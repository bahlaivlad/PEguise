"""Weighted scoring and evidence assembly.

Every weight, threshold and band boundary is read from the configuration
(``data/weights.yaml`` by default) -- this module contains the *logic* for when
a check fires, never the numbers.

Design rule that shapes almost everything here: with the single exception of the
Authenticode digest comparison, no check fires unless a SPECIFIC vendor claim
has been detected. Blank, sloppy or unprofessional metadata on a file that
claims nothing is not evidence of impersonation, and PEguise does not score it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import util
from .authenticode import SignatureInfo
from .icon_fingerprint import IconReport
from .pe_metadata import PEMetadata
from .vendor_db import DEFAULT_SEVERITY_THRESHOLDS, ReferenceData, Vendor

# Fields searched for a vendor identity claim, in priority order.
_CLAIM_FIELDS = ("CompanyName", "ProductName")
# Fields searched for the vendor's own product identity.
_NAME_FIELDS = ("InternalName", "OriginalFilename")


def _severity_for(weight: float, data: ReferenceData) -> str:
    """Informational label for a finding, from ``severity_thresholds`` in the config."""
    thresholds = data.config.get("severity_thresholds") or DEFAULT_SEVERITY_THRESHOLDS
    for label in ("critical", "high", "medium"):
        try:
            if weight >= float(thresholds[label]):
                return label
        except (KeyError, TypeError, ValueError):
            continue
    return "low"


@dataclass
class Finding:
    """One check's outcome, fired or not."""

    check: str
    title: str
    status: str            # fired | clear | not_applicable | unavailable | suppressed
    weight: float = 0.0
    severity: str = "info"
    detail: str = ""
    observed: dict[str, Any] = field(default_factory=dict)
    expected: dict[str, Any] = field(default_factory=dict)

    @property
    def fired(self) -> bool:
        return self.status == "fired"

    def to_dict(self) -> dict[str, Any]:
        return {
            "check": self.check,
            "title": self.title,
            "status": self.status,
            "weight": self.weight if self.fired else 0.0,
            "max_weight": self.weight,
            "severity": self.severity,
            "detail": self.detail,
            "observed": self.observed,
            "expected": self.expected,
        }


@dataclass
class VendorClaim:
    """The vendor identity a file asserts through its VERSIONINFO."""

    vendor: Vendor
    field_name: str
    claimed_value: str
    matched_alias: str
    confidence: float
    method: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "vendor_id": self.vendor.id,
            "vendor_name": self.vendor.display_name,
            "claim_field": self.field_name,
            "claimed_value": self.claimed_value,
            "matched_alias": self.matched_alias,
            "confidence": round(self.confidence, 3),
            "match_method": self.method,
            "vendor_almost_always_signed": self.vendor.almost_always_signed,
            "vendor_internal_name_check": self.vendor.internal_name_check,
        }


@dataclass
class AnalysisResult:
    """The complete triage result for one file."""

    metadata: PEMetadata
    signature: SignatureInfo
    icons: IconReport
    claim: VendorClaim | None
    findings: list[Finding]
    score: float
    band: str
    score_cap: float = 100.0

    @property
    def fired(self) -> list[Finding]:
        return [f for f in self.findings if f.fired]

    @property
    def unavailable(self) -> list[Finding]:
        return [f for f in self.findings if f.status == "unavailable"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.metadata.path,
            "sha256": self.metadata.sha256,
            "size": self.metadata.size,
            "score": round(self.score, 1),
            "score_cap": self.score_cap,
            "band": self.band,
            "vendor_claim": self.claim.to_dict() if self.claim else None,
            "pe": self.metadata.to_dict(),
            "signature": self.signature.to_dict(),
            "icons": self.icons.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "disclaimer": DISCLAIMER,
        }


DISCLAIMER = (
    "PEguise reports weighted suspicion, not a verdict. It performs static, "
    "offline analysis only and never validates certificate chains, revocation "
    "status, timestamps or certificate validity periods. A low score is not a "
    "clean bill of health, and a high score is not proof of malice."
)


# ---------------------------------------------------------------------------
# Vendor claim detection
# ---------------------------------------------------------------------------

def detect_vendor_claim(meta: PEMetadata, data: ReferenceData) -> VendorClaim | None:
    """Find the vendor a file claims to be, if any.

    CompanyName is authoritative; ProductName is consulted only when CompanyName
    yields nothing, and it is additionally matched against each vendor's product
    names (ProductName "Firefox" is a Mozilla claim).
    """
    threshold = data.matching("vendor_claim_threshold", 0.86)
    min_token_length = int(data.matching("min_token_length", 3))

    for field_name in _CLAIM_FIELDS:
        value = meta.field(field_name)
        if not value:
            continue
        for vendor in data.vendors:
            # Company and brand names first. These are distinctive tokens, so
            # containment applies everywhere: a ProductName of "Intel Core"
            # genuinely claims Intel, and CompanyName "Mozilla Corporation"
            # genuinely claims Mozilla.
            matched, confidence, method = util.best_match(
                value, vendor.all_names(), threshold=threshold,
                min_token_length=min_token_length,
            )
            if not matched and field_name == "ProductName" and vendor.product_names:
                # Product brand names are different. A one-word product brand is
                # usually also an ordinary word -- "Windows", "Chrome", "Java" --
                # so containment reads "Quicken for Windows" as a Microsoft
                # claim. One-word brands must match the whole ProductName;
                # multi-word ones keep containment.
                matched, confidence, method = util.best_match(
                    value, vendor.product_names, threshold=threshold,
                    min_token_length=min_token_length,
                    single_token_exact_only=True,
                )
            if matched:
                return VendorClaim(
                    vendor=vendor,
                    field_name=field_name,
                    claimed_value=value,
                    matched_alias=matched,
                    confidence=confidence,
                    method=method,
                )
    return None


def signer_matches_vendor(signature: SignatureInfo, claim: VendorClaim,
                          data: ReferenceData) -> tuple[bool, str, str]:
    """Decide whether the signing entity is plausibly the claimed vendor.

    Deliberately permissive. Real code-signing subjects routinely differ from
    CompanyName: subsidiaries, legal entities, renamed companies, and localized
    spellings all produce a strict-string mismatch on a genuine file. Anything
    short of "no plausible relationship" is treated as a match.

    Returns ``(matched, reason, method)``. ``method`` is ``substring``,
    ``containment``, ``fuzzy`` or ``none``; the caller uses it to distinguish a
    genuine entity variant ("Mozilla Corporation") from a near-miss that only
    the fuzzy pass accepted ("Ozilla Corporation"), which is the signature of a
    typosquatted signing identity.
    """
    vendor = claim.vendor
    threshold = data.matching("signer_cn_threshold", 0.72)
    min_token_length = int(data.matching("min_token_length", 3))

    subjects = [s for s in (signature.signer_common_name, signature.signer_organization) if s]
    if not subjects:
        return False, "signature carries no usable Subject CN or O", "none"

    # 1. Curated signer-CN substrings for this vendor -- the strongest signal.
    for subject in subjects:
        normalized = util.normalize(subject)
        for substring in vendor.signer_cn_substrings:
            if util.normalize(substring) and util.normalize(substring) in normalized:
                return (True,
                        f"signer {subject!r} contains known signer substring {substring!r}",
                        "substring")

    # 2. Token containment either way, which is what makes
    #    "Mozilla Corporation" match a "Mozilla" claim.
    for subject in subjects:
        if util.contains_name(subject, claim.claimed_value, min_token_length=min_token_length):
            return (True,
                    f"signer {subject!r} contains the claimed name {claim.claimed_value!r}",
                    "containment")
        if util.contains_name(claim.claimed_value, subject, min_token_length=min_token_length):
            return (True,
                    f"claimed name {claim.claimed_value!r} contains signer {subject!r}",
                    "containment")

    # 3. Fuzzy match against the vendor's full alias set.
    for subject in subjects:
        matched, confidence, method = util.best_match(
            subject, vendor.all_names(), threshold=threshold, min_token_length=min_token_length
        )
        if matched:
            return (True,
                    f"signer {subject!r} matches vendor alias {matched!r} "
                    f"({method}, confidence {confidence:.2f})",
                    "fuzzy" if method == "fuzzy" else method)

    return (False,
            f"signer {subjects[0]!r} has no plausible relationship to the claimed "
            f"vendor {vendor.display_name!r}",
            "none")


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def _check_digest(signature: SignatureInfo, data: ReferenceData) -> Finding:
    weight = data.weight("authenticode_digest_mismatch")
    check = "authenticode_digest_mismatch"
    title = "Authenticode digest does not match the file"

    if signature.status != "ok":
        return Finding(check, title, "unavailable", weight, _severity_for(weight, data),
                       f"signature inspection unavailable: {signature.status_reason}")
    if not signature.signed:
        return Finding(check, title, "not_applicable", weight, _severity_for(weight, data),
                       "file carries no embedded Authenticode signature")
    if signature.digest_status == "mismatch":
        return Finding(
            check, title, "fired", weight, _severity_for(weight, data),
            "The digest embedded in the SpcIndirectDataContent does not equal the "
            "authentihash recomputed from this file. The signature was produced over "
            "different bytes: the file has been modified after signing, or a signature "
            "was copied onto it from another binary.",
            observed={"computed_authentihash": signature.computed_digest,
                      "digest_algorithm": signature.digest_algorithm},
            expected={"embedded_digest": signature.embedded_digest},
        )
    if signature.digest_status == "indeterminate":
        return Finding(check, title, "unavailable", weight, _severity_for(weight, data),
                       f"digest could not be compared: {signature.digest_status_reason}")
    return Finding(check, title, "clear", weight, "info",
                   "recomputed authentihash equals the digest inside the signature")


def _check_generic_tool(meta: PEMetadata, claim: VendorClaim,
                        data: ReferenceData) -> Finding:
    weight = data.weight("generic_tool_identity")
    check = "generic_tool_identity"
    title = "Vendor claim coexists with a packer/installer self-identity"

    for tool in data.generic_tools:
        if claim.vendor.id in tool.benign_for_vendors:
            continue
        hit = tool.match(meta.version_fields)
        if hit is None:
            continue
        field_name, value = hit
        return Finding(
            check, title, "fired", weight, _severity_for(weight, data),
            f"The file claims to be {claim.vendor.display_name} but its {field_name} "
            f"is the self-identifying string of {tool.name}. Genuine "
            f"{claim.vendor.display_name} binaries do not ship with an unedited "
            f"{tool.name} identity."
            + (f" {tool.note}" if tool.note else ""),
            observed={"field": field_name, "value": value,
                      "matched_tool": tool.id, "tool_name": tool.name},
            expected={"vendor": claim.vendor.display_name,
                      "one_of_patterns": claim.vendor.product_patterns},
        )

    return Finding(check, title, "clear", weight, "info",
                   "no packer/installer self-identity found in the VERSIONINFO fields")


def _check_unsigned(signature: SignatureInfo, claim: VendorClaim,
                    data: ReferenceData) -> Finding:
    weight = data.weight("unsigned_but_vendor_signs")
    check = "unsigned_but_vendor_signs"
    title = "Vendor that almost always signs, but the file is unsigned"

    if not claim.vendor.almost_always_signed:
        return Finding(check, title, "not_applicable", weight, _severity_for(weight, data),
                       f"{claim.vendor.display_name} is not marked as almost-always-signed "
                       "in the vendor database")
    if signature.status != "ok":
        return Finding(check, title, "unavailable", weight, _severity_for(weight, data),
                       f"signature inspection unavailable: {signature.status_reason}")
    if signature.signed:
        return Finding(check, title, "clear", weight, "info",
                       "an embedded Authenticode signature is present")
    return Finding(
        check, title, "fired", weight, _severity_for(weight, data),
        f"The file claims to be {claim.vendor.display_name}, which Authenticode-signs "
        "essentially every shipped binary, yet it carries no embedded signature at all.",
        observed={"embedded_signatures": 0,
                  "certificate_table_present": False},
        expected={"vendor": claim.vendor.display_name,
                  "expected_signature": "present"},
    )


def _check_signer_cn(signature: SignatureInfo, claim: VendorClaim,
                     data: ReferenceData) -> Finding:
    weight = data.weight("signer_cn_mismatch")
    check = "signer_cn_mismatch"
    title = "Signer certificate does not belong to the claimed vendor"

    if signature.status != "ok":
        return Finding(check, title, "unavailable", weight, _severity_for(weight, data),
                       f"signature inspection unavailable: {signature.status_reason}")
    if not signature.signed:
        return Finding(check, title, "not_applicable", weight, _severity_for(weight, data),
                       "file carries no embedded Authenticode signature")
    if not signature.signer_certificate_matched:
        return Finding(check, title, "unavailable", weight, _severity_for(weight, data),
                       "no certificate in the signature blob matches the SignerInfo issuer "
                       "and serial, so the reported signer CN is a best effort and is not "
                       "scored; inspect the certificate set manually")

    matched, reason, method = signer_matches_vendor(signature, claim, data)
    observed = {
        "signer_common_name": signature.signer_common_name,
        "signer_organization": signature.signer_organization,
        "signer_subject_dn": signature.signer_subject_dn,
    }
    expected = {
        "claimed_vendor": claim.vendor.display_name,
        "claimed_value": claim.claimed_value,
        "known_signer_substrings": claim.vendor.signer_cn_substrings,
    }
    if matched:
        return Finding(check, title, "clear", weight, "info", reason,
                       observed={**observed, "match_method": method}, expected=expected)
    return Finding(
        check, title, "fired", weight, _severity_for(weight, data),
        f"The VERSIONINFO claims {claim.vendor.display_name}, but the signing "
        f"certificate belongs to an unrelated subject. {reason}. Note that chain "
        "trust and revocation were NOT checked, so this says nothing about whether "
        "the certificate itself is valid.",
        observed=observed, expected=expected,
    )


def _check_signer_cn_near_miss(signature: SignatureInfo, claim: VendorClaim,
                               data: ReferenceData) -> Finding:
    """Signer CN that is *almost* the vendor name but is not that entity.

    The signer-CN comparison is deliberately loose so that legitimate
    subsidiaries and legal entities are not flagged. That looseness has a cost:
    a deliberately misspelled signing identity ("Ozilla Corporation" against a
    "Mozilla" claim) clears the fuzzy pass. This check recovers that case by
    firing precisely when the ONLY thing that accepted the signer was the fuzzy
    ratio -- a genuine entity variant is caught earlier by the exact, curated
    substring, or token-containment passes, so reaching the fuzzy pass at all
    is itself the anomaly.
    """
    weight = data.weight("signer_cn_near_miss")
    check = "signer_cn_near_miss"
    title = "Signer certificate name is a near-miss for the claimed vendor"

    if signature.status != "ok" or not signature.signed:
        return Finding(check, title, "not_applicable", weight, _severity_for(weight, data),
                       "no parsable embedded signature to compare")
    if not signature.signer_certificate_matched:
        return Finding(check, title, "unavailable", weight, _severity_for(weight, data),
                       "signer certificate could not be matched to the SignerInfo; "
                       "not scored")

    matched, reason, method = signer_matches_vendor(signature, claim, data)
    if not matched:
        return Finding(check, title, "not_applicable", weight, _severity_for(weight, data),
                       "signer does not match the vendor at all; scored by "
                       "signer_cn_mismatch instead")
    if method != "fuzzy":
        return Finding(check, title, "clear", weight, "info",
                       f"signer matched the claimed vendor exactly or by containment "
                       f"({method}), not by approximate similarity")

    return Finding(
        check, title, "fired", weight, _severity_for(weight, data),
        f"The signing identity is close to {claim.vendor.display_name!r} without "
        f"being it: {reason}. No token of the claimed name appears in the signer "
        "subject, and the signer matches none of the curated signer substrings for "
        "this vendor. That combination is characteristic of a deliberately "
        "look-alike signing identity rather than a subsidiary or renamed entity.",
        observed={"signer_common_name": signature.signer_common_name,
                  "signer_organization": signature.signer_organization,
                  "match_method": method},
        expected={"claimed_vendor": claim.vendor.display_name,
                  "known_signer_substrings": claim.vendor.signer_cn_substrings},
    )


def _check_packer_sections(meta: PEMetadata, claim: VendorClaim, data: ReferenceData,
                           *, generic_tool_id: str | None) -> Finding:
    """Vendor claim sitting on a PE whose section names belong to a packer.

    Structural evidence rather than metadata evidence, which matters for two
    reasons. It is independent of VERSIONINFO, so it still fires on a sample
    whose strings were rewritten wholesale; and it lives in the mapped image, so
    it survives memory dumping -- unlike the signature checks, which a sandbox
    dump silently invalidates by discarding the certificate table.
    """
    check = "packer_section_names"
    title = "Vendor claim on a PE with packer section names"
    max_weight = max(data.weight("packer_section_compressor"),
                     data.weight("packer_section_protector"))

    if meta.status != "ok" or not meta.sections:
        return Finding(check, title, "not_applicable", max_weight, _severity_for(max_weight, data),
                       "no section table available to inspect")

    names = meta.section_names
    for tool in data.generic_tools:
        if claim.vendor.id in tool.benign_for_vendors:
            continue
        matched = tool.match_sections(names)
        if not matched:
            continue

        if tool.id == generic_tool_id:
            return Finding(
                check, title, "suppressed", max_weight, _severity_for(max_weight, data),
                f"not scored separately: the generic_tool_identity check already "
                f"reported {tool.name} for this file",
            )

        weight = data.weight(tool.section_weight_key)
        caveat = (
            " Commercial protectors have a real legitimate user base -- security "
            "vendors protect their own agents with them and licensed software uses "
            "them for DRM -- which is why this is weighted well below a compressor "
            "match. Verify the vendor before acting on it."
            if tool.category == "protector" else
            f" Runtime compressors are essentially absent from "
            f"{claim.vendor.display_name}'s shipping builds."
        )
        return Finding(
            check, title, "fired", weight, _severity_for(weight, data),
            f"The file claims to be {claim.vendor.display_name} but carries "
            + ", ".join(repr(n) for n in matched)
            + f" -- the section names of {tool.name} ({tool.category})." + caveat,
            observed={"matched_sections": matched, "matched_tool": tool.id,
                      "tool_name": tool.name, "category": tool.category,
                      "all_sections": names},
            expected={"vendor": claim.vendor.display_name,
                      "expected_sections": "ordinary compiler output, not a packer"},
        )

    return Finding(check, title, "clear", max_weight, "info",
                   f"none of the {len(names)} section names belongs to a known packer")


def _check_anomalous_sections(meta: PEMetadata, claim: VendorClaim,
                              data: ReferenceData) -> Finding:
    """Vendor claim on a PE whose section names are structurally implausible.

    Catches packers that randomise their section names instead of leaving a
    fixed fingerprint. Heuristic, and weighted so it can never reach a band on
    its own; every feature that fired is named in the evidence so an analyst can
    judge it rather than trust it.
    """
    check = "anomalous_section_names"
    title = "Vendor claim on a PE with implausible section names"
    weight = data.weight("anomalous_section_names")
    minimum = int(data.matching("section_anomaly_min_features", 2))

    if meta.status != "ok" or not meta.sections:
        return Finding(check, title, "not_applicable", weight, _severity_for(weight, data),
                       "no section table available to inspect")

    known = data.known_section_names
    counts: dict[str, int] = {}
    for section in meta.sections:
        counts[section.name] = counts.get(section.name, 0) + 1

    flagged: list[tuple[str, list[str]]] = []
    for section in meta.sections:
        features = util.section_name_anomalies(
            section.name,
            known=known,
            has_raw_data=section.raw_size > 0,
            duplicated=counts.get(section.name, 0) > 1,
            printable=section.name_is_printable,
            interior_nul=section.has_interior_nul,
        )
        if len(features) >= minimum:
            flagged.append((section.name or "<empty>", features))

    if not flagged:
        return Finding(check, title, "clear", weight, "info",
                       f"all {len(meta.sections)} section names look like ordinary "
                       "toolchain or known packer output")

    explanations = [
        f"{name!r} ("
        + "; ".join(util.ANOMALY_FEATURE_DESCRIPTIONS.get(f, f) for f in features)
        + ")"
        for name, features in flagged
    ]
    return Finding(
        check, title, "fired", weight, _severity_for(weight, data),
        f"The file claims to be {claim.vendor.display_name}, but "
        + ("a section name is" if len(flagged) == 1 else f"{len(flagged)} section names are")
        + " structurally unlike anything a real toolchain emits: "
        + "; ".join(explanations)
        + f". At least {minimum} independent oddities were required to report this.",
        observed={"flagged_sections": {n: f for n, f in flagged},
                  "all_sections": meta.section_names},
        expected={"vendor": claim.vendor.display_name,
                  "expected_sections": "recognisable toolchain section names"},
    )


def _check_default_icon(icons: IconReport, claim: VendorClaim,
                        data: ReferenceData) -> Finding:
    weight = data.weight("default_packer_icon")
    check = "default_packer_icon"
    title = "Vendor claim combined with a packer's stock default icon"

    if icons.status in ("unavailable", "error"):
        return Finding(check, title, "unavailable", weight, _severity_for(weight, data),
                       f"icon fingerprinting unavailable: {icons.status_reason}")
    if icons.status == "no_reference_data":
        return Finding(check, title, "unavailable", weight, _severity_for(weight, data),
                       icons.status_reason)
    if icons.status == "no_icons":
        return Finding(check, title, "not_applicable", weight, _severity_for(weight, data),
                       "file has no icon resources to fingerprint")
    if not icons.matches:
        return Finding(check, title, "clear", weight, "info",
                       f"none of the {len(icons.icons)} icon resources matched a known "
                       "packer default icon")

    match = icons.matches[0]
    return Finding(
        check, title, "fired", weight, _severity_for(weight, data),
        f"The file claims to be {claim.vendor.display_name} but carries the untouched "
        f"default icon of {match.icon_name}. Real vendors brand their binaries."
        + (f" {match.note}" if match.note else ""),
        observed={"icon_sha256": match.sha256,
                  "resource_id": match.matched_resource_id,
                  "matched_default_icon": match.icon_id,
                  "tool": match.tool},
        expected={"vendor": claim.vendor.display_name,
                  "expected_icon": "vendor-branded, not a packer default"},
    )


def _check_internal_name(meta: PEMetadata, claim: VendorClaim,
                         data: ReferenceData, *, suppressed: bool) -> Finding:
    strict = claim.vendor.is_strict
    check = "internal_name_mismatch_strict" if strict else "internal_name_mismatch_lenient"
    weight = data.weight(check)
    title = "InternalName/OriginalFilename match no known product of the claimed vendor"

    if suppressed:
        return Finding(check, title, "suppressed", weight, _severity_for(weight, data),
                       "not scored separately: the generic_tool_identity check already "
                       "accounts for this name mismatch")

    values = {name: meta.field(name) for name in _NAME_FIELDS}
    present = {k: v for k, v in values.items() if v}
    if not present:
        return Finding(check, title, "not_applicable", weight, _severity_for(weight, data),
                       "neither InternalName nor OriginalFilename is set")

    hits = {name: claim.vendor.matches_product_name(value) for name, value in present.items()}
    if any(hits.values()):
        matched_field = next(k for k, v in hits.items() if v)
        return Finding(check, title, "clear", weight, "info",
                       f"{matched_field} {present[matched_field]!r} matches the expected "
                       f"pattern {hits[matched_field]!r}",
                       observed=present)

    tier = "strict" if strict else "lenient"
    qualifier = (
        f"{claim.vendor.display_name} ships a small, enumerable set of binaries, so a "
        "name outside that set is meaningful evidence."
        if strict else
        f"{claim.vendor.display_name} ships a very large catalogue, so this is weak "
        "evidence on its own and is scored accordingly."
    )
    return Finding(
        check, title, "fired", weight, _severity_for(weight, data),
        f"The file claims to be {claim.vendor.display_name}, but "
        + " and ".join(f"{k}={v!r}" for k, v in present.items())
        + f" matches none of the {len(claim.vendor.product_patterns)} known product "
          f"patterns for that vendor ({tier} tier). " + qualifier,
        observed=present,
        expected={"vendor": claim.vendor.display_name,
                  "one_of_patterns": claim.vendor.product_patterns},
    )


def _check_copyright(meta: PEMetadata, claim: VendorClaim, data: ReferenceData) -> Finding:
    weight = data.weight("copyright_vendor_mismatch")
    check = "copyright_vendor_mismatch"
    title = "LegalCopyright does not mention the claimed vendor"

    copyright_text = meta.field("LegalCopyright")
    if not copyright_text:
        return Finding(check, title, "not_applicable", weight, _severity_for(weight, data),
                       "LegalCopyright is not set")
    if not claim.vendor.copyright_tokens:
        return Finding(check, title, "not_applicable", weight, _severity_for(weight, data),
                       f"no copyright_tokens configured for {claim.vendor.display_name}")

    normalized = util.normalize(copyright_text)
    if any(util.normalize(token) in normalized for token in claim.vendor.copyright_tokens):
        return Finding(check, title, "clear", weight, "info",
                       "LegalCopyright references the claimed vendor")
    return Finding(
        check, title, "fired", weight, _severity_for(weight, data),
        f"CompanyName/ProductName claims {claim.vendor.display_name}, but LegalCopyright "
        "names a different party. Genuine binaries are internally consistent.",
        observed={"LegalCopyright": copyright_text},
        expected={"contains_one_of": claim.vendor.copyright_tokens},
    )


def _check_missing_names(meta: PEMetadata, claim: VendorClaim, data: ReferenceData) -> Finding:
    weight = data.weight("vendor_claim_without_names")
    check = "vendor_claim_without_names"
    title = "Vendor claimed with no InternalName and no OriginalFilename"

    if any(meta.field(name) for name in _NAME_FIELDS):
        return Finding(check, title, "clear", weight, "info",
                       "at least one of InternalName / OriginalFilename is set")
    return Finding(
        check, title, "fired", weight, _severity_for(weight, data),
        f"The file asserts the {claim.vendor.display_name} identity but omits both "
        "InternalName and OriginalFilename. Shipping binaries from major vendors "
        "almost always set at least one.",
        observed={"InternalName": None, "OriginalFilename": None},
        expected={"at_least_one_of": list(_NAME_FIELDS)},
    )


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def band_for(score: float, data: ReferenceData) -> str:
    """Map a numeric score to its configured label."""
    bands = data.config.get("bands") or [[0, "low"]]
    parsed: list[tuple[float, str]] = []
    for entry in bands:
        try:
            lower, label = entry[0], entry[1]
            parsed.append((float(lower), str(label)))
        except (TypeError, IndexError, ValueError):
            continue
    if not parsed:
        return "unknown"
    parsed.sort(key=lambda item: item[0])
    label = parsed[0][1]
    for lower, name in parsed:
        if score >= lower:
            label = name
    return label


def score_file(meta: PEMetadata, signature: SignatureInfo, icons: IconReport,
               data: ReferenceData) -> AnalysisResult:
    """Run every check and assemble the weighted result."""
    findings: list[Finding] = []

    # The digest check is the one signal that stands on its own: a signature
    # that does not match its file is anomalous whatever the file claims to be.
    findings.append(_check_digest(signature, data))

    claim = detect_vendor_claim(meta, data) if meta.status == "ok" else None

    if claim is None:
        reason = (
            "no vendor claim detected in CompanyName/ProductName; impersonation "
            "checks are not applicable"
            if meta.status == "ok"
            else f"PE metadata unavailable: {meta.status_reason}"
        )
        for check, title in (
            ("generic_tool_identity", "Vendor claim coexists with a packer/installer self-identity"),
            ("unsigned_but_vendor_signs", "Vendor that almost always signs, but the file is unsigned"),
            ("signer_cn_mismatch", "Signer certificate does not belong to the claimed vendor"),
            ("signer_cn_near_miss", "Signer certificate name is a near-miss for the claimed vendor"),
            ("default_packer_icon", "Vendor claim combined with a packer's stock default icon"),
            ("packer_section_names", "Vendor claim on a PE with packer section names"),
            ("anomalous_section_names", "Vendor claim on a PE with implausible section names"),
            ("internal_name_mismatch_strict", "InternalName/OriginalFilename match no known product of the claimed vendor"),
            ("copyright_vendor_mismatch", "LegalCopyright does not mention the claimed vendor"),
            ("vendor_claim_without_names", "Vendor claimed with no InternalName and no OriginalFilename"),
        ):
            status = "unavailable" if meta.status != "ok" else "not_applicable"
            findings.append(Finding(check, title, status, data.weight(check),
                                    _severity_for(data.weight(check), data), reason))
    else:
        generic = _check_generic_tool(meta, claim, data)
        findings.append(generic)
        findings.append(_check_unsigned(signature, claim, data))
        findings.append(_check_signer_cn(signature, claim, data))
        findings.append(_check_signer_cn_near_miss(signature, claim, data))
        findings.append(_check_default_icon(icons, claim, data))
        findings.append(_check_packer_sections(
            meta, claim, data,
            generic_tool_id=generic.observed.get("matched_tool") if generic.fired else None,
        ))
        findings.append(_check_anomalous_sections(meta, claim, data))
        findings.append(_check_internal_name(meta, claim, data, suppressed=generic.fired))
        findings.append(_check_copyright(meta, claim, data))
        findings.append(_check_missing_names(meta, claim, data))

    cap = float(data.config.get("score_cap", 100))
    total = min(sum(f.weight for f in findings if f.fired), cap)

    # Report highest-impact evidence first, then everything else.
    findings.sort(key=lambda f: (not f.fired, -f.weight, f.check))

    return AnalysisResult(
        metadata=meta,
        signature=signature,
        icons=icons,
        claim=claim,
        findings=findings,
        score=total,
        band=band_for(total, data),
        score_cap=cap,
    )
