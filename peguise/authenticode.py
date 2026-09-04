"""Offline Authenticode inspection.

WHAT THIS MODULE DOES
  * detects presence/absence of an embedded Authenticode signature
  * extracts the signer certificate's Subject CN (and O, for context)
  * recomputes the Authenticode digest ("authentihash") from the PE layout and
    compares it against the digest embedded in the PKCS#7
    SpcIndirectDataContent

WHAT THIS MODULE DELIBERATELY DOES NOT DO
  * chain-of-trust validation (no root store is consulted)
  * revocation checking (no CRL, no OCSP)
  * timestamp / countersignature validity
  * any network access whatsoever

A file can therefore pass every check here and still be signed with a stolen,
revoked, expired or self-issued certificate. Treat a "signature present, digest
matches, CN plausible" result as *absence of one class of evidence*, never as
proof of authenticity.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    from signify.authenticode.signed_file.pe import SignedPEFile
    SIGNIFY_AVAILABLE = True
    SIGNIFY_IMPORT_ERROR = ""
except Exception as exc:  # pragma: no cover - depends on environment
    SignedPEFile = None  # type: ignore[assignment]
    SIGNIFY_AVAILABLE = False
    SIGNIFY_IMPORT_ERROR = str(exc)

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:  # pragma: no cover
    pefile = None  # type: ignore[assignment]
    PEFILE_AVAILABLE = False


# Offset of the CheckSum field within the optional header. Identical for PE32
# and PE32+ (the wider ImageBase is offset by the missing BaseOfData field).
_CHECKSUM_OFFSET_IN_OPTIONAL_HEADER = 64
_SECURITY_DIRECTORY_INDEX = 4


@dataclass
class SignatureInfo:
    """Result of the Authenticode inspection for one file."""

    status: str = "ok"                  # ok | unavailable | error
    status_reason: str = ""
    signed: bool = False
    signature_count: int = 0
    signer_common_name: str | None = None
    signer_organization: str | None = None
    signer_subject_dn: str | None = None
    signer_issuer_dn: str | None = None
    # False when no certificate in the blob matched the SignerInfo issuer and
    # serial, so the signer fields above describe a best-effort candidate.
    signer_certificate_matched: bool = True
    digest_algorithm: str | None = None
    embedded_digest: str | None = None      # hex, from SpcIndirectDataContent
    computed_digest: str | None = None      # hex, recomputed from the PE
    digest_status: str = "not_checked"      # match | mismatch | indeterminate | not_checked
    digest_status_reason: str = ""
    warnings: list[str] = field(default_factory=list)

    # Explicit record of what was NOT verified, surfaced in every report.
    not_verified: tuple[str, ...] = (
        "certificate chain of trust",
        "certificate revocation (CRL/OCSP)",
        "timestamp / countersignature validity",
        "certificate validity period",
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "status_reason": self.status_reason,
            "signed": self.signed,
            "signature_count": self.signature_count,
            "signer_common_name": self.signer_common_name,
            "signer_organization": self.signer_organization,
            "signer_subject_dn": self.signer_subject_dn,
            "signer_issuer_dn": self.signer_issuer_dn,
            "signer_certificate_matched": self.signer_certificate_matched,
            "digest_algorithm": self.digest_algorithm,
            "embedded_digest": self.embedded_digest,
            "computed_digest": self.computed_digest,
            "digest_status": self.digest_status,
            "digest_status_reason": self.digest_status_reason,
            "warnings": list(self.warnings),
            "not_verified": list(self.not_verified),
        }


# ---------------------------------------------------------------------------
# Authentihash recomputation (independent of signify)
# ---------------------------------------------------------------------------

def compute_authentihash(path: str | Path, algorithm: str = "sha256") -> str:
    """Recompute the Authenticode digest of a PE per the PE/COFF specification.

    The digest covers the whole file except three regions: the optional-header
    CheckSum field, the security data-directory entry, and the attribute
    certificate table itself.

    Raises ValueError / OSError on unparsable input; callers must handle it.
    """
    if not PEFILE_AVAILABLE:
        raise ValueError("pefile is not installed")

    file_path = Path(path)
    pe = pefile.PE(str(file_path), fast_load=True)
    try:
        optional_header_offset = pe.OPTIONAL_HEADER.get_file_offset()
        checksum_offset = optional_header_offset + _CHECKSUM_OFFSET_IN_OPTIONAL_HEADER

        directories = pe.OPTIONAL_HEADER.DATA_DIRECTORY
        if len(directories) <= _SECURITY_DIRECTORY_INDEX:
            raise ValueError("PE has no security data directory entry")
        security_entry = directories[_SECURITY_DIRECTORY_INDEX]
        security_entry_offset = security_entry.get_file_offset()
        certificate_table_size = int(security_entry.Size)

        size_of_headers = int(pe.OPTIONAL_HEADER.SizeOfHeaders)
        sections = sorted(pe.sections, key=lambda s: int(s.PointerToRawData))
    finally:
        pe.close()

    try:
        digest = hashlib.new(algorithm)
    except ValueError as exc:
        raise ValueError(f"unsupported digest algorithm {algorithm!r}") from exc

    file_size = file_path.stat().st_size

    with file_path.open("rb") as handle:
        def consume(start: int, end: int) -> None:
            """Hash bytes [start, end); tolerant of ranges past EOF."""
            if end <= start:
                return
            handle.seek(start)
            remaining = end - start
            while remaining > 0:
                chunk = handle.read(min(remaining, 1 << 20))
                if not chunk:
                    return
                digest.update(chunk)
                remaining -= len(chunk)

        # 1. start of file -> CheckSum, skipping the 4-byte CheckSum
        consume(0, checksum_offset)
        # 2. after CheckSum -> security data directory entry, skipping its 8 bytes
        consume(checksum_offset + 4, security_entry_offset)
        # 3. after that entry -> end of headers
        consume(security_entry_offset + 8, size_of_headers)

        # 4. every section's raw data, in file order.
        #
        # PointerToRawData is not guaranteed to fall after everything hashed so
        # far: UPX in particular emits a zero-size UPX0 section and points UPX1
        # at a file offset *inside* the nominal header region (observed at
        # offset 1024, with SizeOfHeaders reporting 4096). Hashing
        # [raw_pointer, raw_pointer+raw_size) unconditionally there re-hashes
        # already-consumed header bytes and produces a digest that never
        # matches -- confirmed by cross-checking against signify's fingerprint
        # on a real UPX-packed, Authenticode-signed sample, where signify's
        # result matched the embedded digest and this method's earlier,
        # unclamped version did not. Clamping the start to the high-water mark
        # is what the Authenticode spec's "no double-hashing" requirement
        # actually calls for.
        bytes_hashed = size_of_headers
        for section in sections:
            raw_pointer = int(section.PointerToRawData)
            raw_size = int(section.SizeOfRawData)
            if raw_size <= 0:
                continue
            section_end = raw_pointer + raw_size
            consume(max(raw_pointer, bytes_hashed), section_end)
            bytes_hashed = max(bytes_hashed, section_end)

        # 5. trailing data, excluding the attribute certificate table
        trailing_end = file_size - certificate_table_size
        if trailing_end > bytes_hashed:
            consume(bytes_hashed, trailing_end)

    return digest.hexdigest()


# ---------------------------------------------------------------------------
# Signature parsing via signify
# ---------------------------------------------------------------------------

def _certificate_name_component(name: Any, component: str) -> str | None:
    """Pull one RDN (e.g. "CN") out of a signify CertificateName."""
    if name is None:
        return None
    try:
        values = list(name.get_components(component))
        if values:
            return str(values[0])
    except Exception:
        pass
    # Fallback: scrape the printed DN.
    try:
        dn = str(name.dn)
    except Exception:
        return None
    for part in dn.split(","):
        part = part.strip()
        if part.upper().startswith(f"{component.upper()}="):
            return part.split("=", 1)[1].strip()
    return None


def _dn_string(name: Any) -> str | None:
    try:
        return str(name.dn)
    except Exception:
        return None


def _find_signer_certificate(signature: Any) -> tuple[Any | None, bool]:
    """Locate the certificate matching the SignerInfo issuer + serial.

    Returns ``(certificate, exact)``. ``exact`` is False when nothing matched
    and a best-effort candidate was chosen instead; the caller records that as
    a warning and the scorer declines to score the signer CN.
    """
    certificates = list(getattr(signature, "certificates", None) or [])
    if not certificates:
        return None, False

    signer_info = getattr(signature, "signer_info", None)
    if signer_info is not None:
        wanted_serial = getattr(signer_info, "serial_number", None)
        wanted_issuer_dn = _dn_string(getattr(signer_info, "issuer", None))
        for certificate in certificates:
            if getattr(certificate, "serial_number", None) != wanted_serial:
                continue
            if wanted_issuer_dn and \
                    _dn_string(getattr(certificate, "issuer", None)) != wanted_issuer_dn:
                continue
            return certificate, True

    # Nothing matches the SignerInfo -- the blob is malformed, but an analyst
    # still wants to see *some* subject. Prefer a certificate that issued no
    # other certificate in the set (a leaf, in chain terms) over the first one
    # listed, which is frequently an intermediate CA whose CN would otherwise
    # be compared against the vendor claim.
    issuers = {_dn_string(getattr(c, "issuer", None)) for c in certificates}
    leaves = [c for c in certificates
              if _dn_string(getattr(c, "subject", None)) not in issuers]
    return (leaves[0] if leaves else certificates[0]), False


def inspect(path: str | Path, *, algorithm_override: str | None = None) -> SignatureInfo:
    """Inspect a PE's Authenticode signature. Never raises; degrades to status."""
    info = SignatureInfo()
    file_path = Path(path)

    if not SIGNIFY_AVAILABLE:
        info.status = "unavailable"
        info.status_reason = (
            f"signify is not installed ({SIGNIFY_IMPORT_ERROR}); signature presence, "
            "signer CN and digest comparison were all skipped"
        )
        return info

    try:
        with file_path.open("rb") as handle:
            signed_file = SignedPEFile(handle)
            try:
                signatures = list(signed_file.iter_embedded_signatures())
            except Exception as exc:
                info.status = "error"
                info.status_reason = f"signature blob unparsable: {type(exc).__name__}: {exc}"
                return info

            info.signature_count = len(signatures)
            info.signed = bool(signatures)
            if not signatures:
                return info

            signature = signatures[0]
            if len(signatures) > 1:
                info.warnings.append(
                    f"{len(signatures)} embedded signatures present; reporting the first"
                )

            _extract_signer(signature, info)
            _compare_digest(signed_file, signature, file_path, info,
                            algorithm_override=algorithm_override)

    except FileNotFoundError as exc:
        info.status = "error"
        info.status_reason = str(exc)
    except Exception as exc:
        info.status = "error"
        info.status_reason = f"authenticode inspection failed: {type(exc).__name__}: {exc}"

    return info


def _extract_signer(signature: Any, info: SignatureInfo) -> None:
    try:
        certificate, exact = _find_signer_certificate(signature)
        if certificate is None:
            info.warnings.append("no certificate found in the signature blob")
            return
        if not exact:
            info.signer_certificate_matched = False
            info.warnings.append(
                "no certificate in the signature blob matches the SignerInfo issuer and "
                "serial number; the signer CN below is a best-effort candidate and may not "
                "be the actual signing identity"
            )
        subject = getattr(certificate, "subject", None)
        info.signer_common_name = _certificate_name_component(subject, "CN")
        info.signer_organization = _certificate_name_component(subject, "O")
        info.signer_subject_dn = _dn_string(subject)
        info.signer_issuer_dn = _dn_string(getattr(certificate, "issuer", None))
        if info.signer_common_name is None and info.signer_organization:
            info.warnings.append("certificate has no CN; falling back to O for comparison")
    except Exception as exc:
        info.warnings.append(f"signer certificate unreadable: {type(exc).__name__}: {exc}")


def _compare_digest(signed_file: Any, signature: Any, file_path: Path,
                    info: SignatureInfo, *, algorithm_override: str | None) -> None:
    """Recompute the authentihash and compare it to the embedded digest."""
    try:
        indirect_data = getattr(signature, "indirect_data", None)
        if indirect_data is None:
            info.digest_status = "indeterminate"
            info.digest_status_reason = "signature carries no SpcIndirectDataContent"
            return

        embedded = getattr(indirect_data, "digest", None)
        algorithm_fn = getattr(indirect_data, "digest_algorithm", None)
        if embedded is None or algorithm_fn is None:
            info.digest_status = "indeterminate"
            info.digest_status_reason = "embedded digest or its algorithm is missing"
            return

        algorithm_name = algorithm_override or _algorithm_name(algorithm_fn)
        info.digest_algorithm = algorithm_name
        info.embedded_digest = embedded.hex()
    except Exception as exc:
        info.digest_status = "indeterminate"
        info.digest_status_reason = f"embedded digest unreadable: {type(exc).__name__}: {exc}"
        return

    # Primary: our own recomputation, so the comparison does not depend on
    # library internals. Secondary: signify's fingerprinter, as a cross-check.
    own_digest: str | None = None
    own_error = ""
    try:
        own_digest = compute_authentihash(file_path, algorithm_name)
    except Exception as exc:
        own_error = f"{type(exc).__name__}: {exc}"

    library_digest: str | None = None
    try:
        library_digest = signed_file.get_fingerprint(algorithm_fn).hex()
    except Exception:
        library_digest = None

    if own_digest is None and library_digest is None:
        info.digest_status = "indeterminate"
        info.digest_status_reason = f"could not recompute the authentihash ({own_error})"
        return

    if own_digest and library_digest and own_digest != library_digest:
        # Two independent implementations disagree about the file's own hash.
        # Refuse to fire a very-high-weight finding on an ambiguous computation.
        info.computed_digest = own_digest
        info.digest_status = "indeterminate"
        info.digest_status_reason = (
            "internal and signify authentihash computations disagree "
            f"({own_digest} vs {library_digest}); the PE layout is likely malformed"
        )
        info.warnings.append("authentihash computations disagree; digest check inconclusive")
        return

    computed = own_digest or library_digest
    info.computed_digest = computed
    if computed == info.embedded_digest:
        info.digest_status = "match"
        info.digest_status_reason = "recomputed authentihash equals the embedded digest"
    else:
        info.digest_status = "mismatch"
        info.digest_status_reason = (
            "recomputed authentihash does not equal the digest inside the signature"
        )


def _algorithm_name(algorithm_fn: Any) -> str:
    """Turn signify's HashFunction (a hashlib constructor) into its name."""
    try:
        return str(algorithm_fn().name)
    except Exception:
        name = getattr(algorithm_fn, "__name__", "sha256")
        return str(name).lower()
