"""Build genuinely parsable Authenticode signatures for test fixtures.

This exists so the test suite can exercise the real code path -- signify's
PKCS#7 parsing, signer-certificate extraction, and the authentihash comparison
-- without committing third-party binaries to the repository or downloading
anything.

The certificates it mints are self-signed throwaways generated at test time.
That is fine here precisely because PEguise never validates chains: a
self-signed certificate parses exactly like a commercially issued one for the
purposes of "what is the Subject CN, and does the embedded digest match the
file?".

Requires ``asn1crypto`` and ``oscrypto``, both of which arrive as signify
dependencies. If either is missing the tests that use this module skip.
"""

from __future__ import annotations

import datetime
import hashlib
import secrets
from typing import Any

try:
    from asn1crypto import algos, cms, core, keys, x509
    from oscrypto import asymmetric
    from signify.asn1 import spc
    SIGNING_AVAILABLE = True
    SIGNING_IMPORT_ERROR = ""
except Exception as exc:  # pragma: no cover - depends on environment
    SIGNING_AVAILABLE = False
    SIGNING_IMPORT_ERROR = str(exc)

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pebuilder

SPC_INDIRECT_DATA_OID = "1.3.6.1.4.1.311.2.1.4"
SPC_PE_IMAGE_DATA_OID = "1.3.6.1.4.1.311.2.1.15"


def _self_signed_certificate(common_name: str, organization: str | None,
                             private_key: Any, public_key: Any) -> x509.Certificate:
    """Mint a throwaway self-signed code-signing certificate."""
    name_parts: dict[str, str] = {"common_name": common_name, "country_name": "US"}
    if organization:
        name_parts["organization_name"] = organization
    name = x509.Name.build(name_parts)

    now = datetime.datetime.now(datetime.UTC).replace(microsecond=0)
    spki = keys.PublicKeyInfo.load(asymmetric.dump_public_key(public_key, encoding="der"))

    tbs = x509.TbsCertificate({
        "version": "v3",
        "serial_number": secrets.randbelow(1 << 63) + 1,
        "signature": algos.SignedDigestAlgorithm({"algorithm": "sha256_rsa"}),
        "issuer": name,
        "validity": x509.Validity({
            "not_before": x509.Time({"utc_time": now - datetime.timedelta(days=1)}),
            "not_after": x509.Time({"utc_time": now + datetime.timedelta(days=365)}),
        }),
        "subject": name,
        "subject_public_key_info": spki,
        "extensions": [
            x509.Extension({
                "extn_id": "extended_key_usage",
                "critical": False,
                "extn_value": x509.ExtKeyUsageSyntax(["code_signing"]),
            }),
        ],
    })
    signature = asymmetric.rsa_pkcs1v15_sign(private_key, tbs.dump(), "sha256")
    return x509.Certificate({
        "tbs_certificate": tbs,
        "signature_algorithm": algos.SignedDigestAlgorithm({"algorithm": "sha256_rsa"}),
        "signature_value": signature,
    })


def _indirect_data(authentihash: bytes) -> spc.SpcIndirectDataContent:
    """SpcIndirectDataContent binding a PE image to ``authentihash``."""
    image_data = spc.SpcPeImageData({
        "flags": set(),
        "file": spc.SpcLink(name="file", value=spc.SpcString(
            name="unicode", value="<<<Obsolete>>>")),
    })
    return spc.SpcIndirectDataContent({
        "data": spc.SpcAttributeTypeAndOptionalValue({
            "type": SPC_PE_IMAGE_DATA_OID,
            "value": image_data,
        }),
        "message_digest": spc.DigestInfo({
            "digest_algorithm": algos.DigestAlgorithm({"algorithm": "sha256"}),
            "digest": authentihash,
        }),
    })


def build_signature_blob(authentihash: bytes, *, common_name: str,
                         organization: str | None = None) -> bytes:
    """Return a DER PKCS#7 SignedData asserting ``authentihash`` for a PE."""
    public_key, private_key = asymmetric.generate_pair("rsa", bit_size=2048)
    certificate = _self_signed_certificate(common_name, organization,
                                           private_key, public_key)

    indirect = _indirect_data(authentihash)
    indirect_der = indirect.dump()

    signed_attributes = cms.CMSAttributes([
        cms.CMSAttribute({
            "type": "content_type",
            "values": [cms.ContentType(SPC_INDIRECT_DATA_OID)],
        }),
        cms.CMSAttribute({
            "type": "message_digest",
            "values": [core.OctetString(hashlib.sha256(indirect_der).digest())],
        }),
    ])
    signature = asymmetric.rsa_pkcs1v15_sign(
        private_key, signed_attributes.dump(), "sha256")

    signer_info = cms.SignerInfo({
        "version": "v1",
        "sid": cms.SignerIdentifier({
            "issuer_and_serial_number": cms.IssuerAndSerialNumber({
                "issuer": certificate.issuer,
                "serial_number": certificate.serial_number,
            }),
        }),
        "digest_algorithm": algos.DigestAlgorithm({"algorithm": "sha256"}),
        "signed_attrs": signed_attributes,
        "signature_algorithm": algos.SignedDigestAlgorithm({"algorithm": "rsassa_pkcs1v15"}),
        "signature": signature,
    })

    signed_data = cms.SignedData({
        "version": "v1",
        "digest_algorithms": [algos.DigestAlgorithm({"algorithm": "sha256"})],
        # signify registers SpcIndirectDataContent against this OID, so the
        # content is set as the parsed object rather than an opaque octet string.
        "encap_content_info": {
            "content_type": SPC_INDIRECT_DATA_OID,
            "content": indirect,
        },
        "certificates": [certificate],
        "signer_infos": [signer_info],
    })

    return cms.ContentInfo({
        "content_type": "signed_data",
        "content": signed_data,
    }).dump()


def sign_image(image: bytes, *, common_name: str, organization: str | None = None,
               corrupt_digest: bool = False) -> bytes:
    """Attach a real Authenticode signature to a PE image built by pebuilder.

    The authentihash is computed over the padded, still-unsigned image, which is
    byte-for-byte what the digest of the finished signed file will be (the
    certificate table and the security data-directory entry are both excluded
    from the Authenticode digest).

    ``corrupt_digest`` flips the embedded digest so the resulting file is a
    valid-but-wrong signature -- a signature that does not match its file.
    """
    padded = image + b"\x00" * ((8 - len(image) % 8) % 8)
    authentihash = _authentihash_of_unsigned_image(padded)
    if corrupt_digest:
        authentihash = bytes((authentihash[0] ^ 0xFF,)) + authentihash[1:]

    blob = build_signature_blob(authentihash, common_name=common_name,
                                organization=organization)
    return pebuilder.attach_fake_certificate_table(image, blob)


def _authentihash_of_unsigned_image(padded_image: bytes) -> bytes:
    """SHA-256 authentihash of an unsigned, 8-byte-aligned PE image."""
    import tempfile
    from pathlib import Path

    from peguise.authenticode import compute_authentihash

    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "unsigned.tmp"
        path.write_bytes(padded_image)
        return bytes.fromhex(compute_authentihash(path, "sha256"))


def signed_pe(*, common_name: str, organization: str | None = None,
              corrupt_digest: bool = False, **build_kwargs: Any) -> bytes:
    """Convenience: build a PE with pebuilder and sign it in one call."""
    return sign_image(pebuilder.build_pe(**build_kwargs),
                      common_name=common_name, organization=organization,
                      corrupt_digest=corrupt_digest)
