"""PEguise test harness.

Covers the four scenarios required by the brief plus regression tests for the
scoring gate, the Authenticode digest computation and graceful degradation.

Signed-file scenarios are driven by injecting a :class:`SignatureInfo` into the
scorer rather than by fabricating PKCS#7 blobs: forging a structurally valid
Authenticode signature in a fixture would be both fragile and beside the point.
Real end-to-end signature parsing is covered by the opt-in test at the bottom of
this file, which runs against a genuine signed binary supplied by the analyst.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import make_fixtures
import pebuilder
import pesigner
from peguise import icon_fingerprint, pe_metadata, scoring, util
from peguise.analyzer import analyze_file, analyze_path
from peguise.authenticode import SignatureInfo, compute_authentihash

ROOT = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def signed_as(common_name: str, *, organization: str | None = None,
              digest_status: str = "match") -> SignatureInfo:
    """A SignatureInfo describing a present, parsable signature."""
    return SignatureInfo(
        status="ok",
        signed=True,
        signature_count=1,
        signer_common_name=common_name,
        signer_organization=organization,
        signer_subject_dn=f"CN={common_name}" + (f", O={organization}" if organization else ""),
        signer_issuer_dn="CN=Some Public CA, O=Some CA Inc.",
        digest_algorithm="sha256",
        embedded_digest="aa" * 32,
        computed_digest=("aa" * 32) if digest_status == "match" else ("bb" * 32),
        digest_status=digest_status,
        digest_status_reason=f"test-injected {digest_status}",
    )


UNSIGNED = SignatureInfo(status="ok", signed=False)


def score_with(path: Path, data, signature: SignatureInfo) -> scoring.AnalysisResult:
    """Run the full pipeline but substitute a known signature result."""
    meta = pe_metadata.extract(path)
    icons = icon_fingerprint.fingerprint(path, data.icon_hash_index)
    return scoring.score_file(meta, signature, icons, data)


def fired_checks(result: scoring.AnalysisResult) -> set[str]:
    return {finding.check for finding in result.fired}


# ---------------------------------------------------------------------------
# Case 1 -- positive control: a genuine, signed major-vendor binary
# ---------------------------------------------------------------------------

def test_case1_genuine_signed_microsoft_binary_scores_low(fixtures, reference_data):
    """A signed Microsoft system binary with consistent metadata must score 0."""
    result = score_with(
        fixtures["case1_microsoft_system_binary.exe"],
        reference_data,
        signed_as("Microsoft Windows", organization="Microsoft Corporation"),
    )

    assert result.claim is not None
    assert result.claim.vendor.id == "microsoft"
    assert fired_checks(result) == set()
    assert result.score == 0
    assert result.band == "low"


def test_case1_signer_cn_check_accepts_microsofts_own_cn(fixtures, reference_data):
    """Microsoft signs as "Microsoft Windows", not "Microsoft Corporation"."""
    result = score_with(
        fixtures["case1_microsoft_system_binary.exe"],
        reference_data,
        signed_as("Microsoft Windows"),
    )
    assert "signer_cn_mismatch" not in fired_checks(result)


# ---------------------------------------------------------------------------
# Case 2 -- known-bad pattern: vendor claim + packer identity + unsigned
# ---------------------------------------------------------------------------

def test_case2_mozilla_claim_with_7zsfx_identity_scores_high(fixtures, reference_data):
    result = score_with(
        fixtures["case2_mozilla_claim_7zsfx.exe"], reference_data, UNSIGNED
    )

    assert result.claim is not None and result.claim.vendor.id == "mozilla"
    fired = fired_checks(result)
    assert "generic_tool_identity" in fired
    assert "unsigned_but_vendor_signs" in fired
    assert result.band == "high", f"expected high, got {result.band} at {result.score}"


def test_case2_evidence_names_what_was_found_and_expected(fixtures, reference_data):
    """The report must explain WHY, not just produce a number."""
    result = score_with(
        fixtures["case2_mozilla_claim_7zsfx.exe"], reference_data, UNSIGNED
    )
    finding = next(f for f in result.fired if f.check == "generic_tool_identity")

    assert finding.observed["value"] == "7zS.sfx"
    assert finding.observed["matched_tool"] == "7zip_sfx"
    assert finding.expected["vendor"] == "Mozilla"
    assert finding.expected["one_of_patterns"]
    assert "Mozilla" in finding.detail and "7-Zip" in finding.detail


def test_case2_internal_name_check_is_suppressed_not_double_counted(
    fixtures, reference_data
):
    result = score_with(
        fixtures["case2_mozilla_claim_7zsfx.exe"], reference_data, UNSIGNED
    )
    finding = next(f for f in result.findings
                   if f.check == "internal_name_mismatch_strict")
    assert finding.status == "suppressed"


def test_case2_with_the_packer_default_icon_also_fires_the_icon_check(
    fixtures, reference_data_with_icons
):
    result = score_with(
        fixtures["case2_mozilla_claim_7zsfx.exe"], reference_data_with_icons, UNSIGNED
    )
    assert "default_packer_icon" in fired_checks(result)


# ---------------------------------------------------------------------------
# Case 3 -- honest freeware with sloppy metadata and no vendor claim
# ---------------------------------------------------------------------------

def test_case3_honest_unsigned_freeware_scores_low(fixtures, reference_data):
    """Unprofessional metadata is not impersonation and must not be punished."""
    result = score_with(fixtures["case3_honest_freeware.exe"], reference_data, UNSIGNED)

    assert result.claim is None
    assert fired_checks(result) == set()
    assert result.score == 0
    assert result.band == "low"


def test_case3_all_impersonation_checks_report_not_applicable(fixtures, reference_data):
    result = score_with(fixtures["case3_honest_freeware.exe"], reference_data, UNSIGNED)
    gated = [f for f in result.findings if f.check != "authenticode_digest_mismatch"]
    assert gated, "expected the gated checks to still be reported"
    assert all(f.status == "not_applicable" for f in gated)
    assert all("no vendor claim" in f.detail for f in gated)


def test_file_with_no_version_resource_scores_low(fixtures, reference_data):
    result = score_with(fixtures["extra_no_version_resource.exe"], reference_data, UNSIGNED)
    assert result.claim is None
    assert result.score == 0


def test_genuine_7zip_sfx_is_not_flagged_for_its_own_identity(fixtures, reference_data):
    """benign_for_vendors must stop 7-Zip being flagged for shipping 7zS.sfx."""
    result = score_with(fixtures["extra_genuine_7zip_sfx.exe"], reference_data, UNSIGNED)

    assert result.claim is not None and result.claim.vendor.id == "7zip"
    assert "generic_tool_identity" not in fired_checks(result)
    # 7-Zip is not marked almost_always_signed, so being unsigned is fine too.
    assert "unsigned_but_vendor_signs" not in fired_checks(result)
    assert result.score == 0


# ---------------------------------------------------------------------------
# Case 4 -- signer CN is a legitimately different legal entity
# ---------------------------------------------------------------------------

def test_case4_subsidiary_signer_cn_does_not_over_flag(fixtures, reference_data):
    """CompanyName "Mozilla" signed by "Mozilla Corporation" is genuine."""
    result = score_with(
        fixtures["case4_mozilla_genuine_layout.exe"],
        reference_data,
        signed_as("Mozilla Corporation"),
    )

    assert result.claim is not None and result.claim.vendor.id == "mozilla"
    assert "signer_cn_mismatch" not in fired_checks(result)
    assert result.score == 0
    assert result.band == "low"


@pytest.mark.parametrize("common_name", [
    "Mozilla Corporation",
    "Mozilla Foundation",
    "MOZILLA CORPORATION",
    "Mozilla Corp.",
])
def test_case4_signer_cn_variants_all_accepted(fixtures, reference_data, common_name):
    result = score_with(
        fixtures["case4_mozilla_genuine_layout.exe"], reference_data, signed_as(common_name)
    )
    assert "signer_cn_mismatch" not in fired_checks(result), common_name


@pytest.mark.parametrize("common_name", [
    "Shenzhen Yuanchuang Network Technology Co., Ltd.",
    "Bright Future Software LLC",
    "Contoso Media Group",
])
def test_unrelated_signer_cn_does_fire(fixtures, reference_data, common_name):
    result = score_with(
        fixtures["case4_mozilla_genuine_layout.exe"], reference_data, signed_as(common_name)
    )
    assert "signer_cn_mismatch" in fired_checks(result), common_name
    assert result.band in ("elevated", "high")


@pytest.mark.parametrize("common_name", [
    "Ozilla Corporation",
    "Mozila Corporation",
    "Mozzilla Corporation",
])
def test_typosquatted_signer_cn_fires_the_near_miss_check(
    fixtures, reference_data, common_name
):
    """The permissive fuzzy pass accepts look-alikes; the near-miss check
    is what recovers them, so they are still surfaced as evidence."""
    result = score_with(
        fixtures["case4_mozilla_genuine_layout.exe"], reference_data, signed_as(common_name)
    )
    fired = fired_checks(result)
    assert "signer_cn_near_miss" in fired, common_name
    assert "signer_cn_mismatch" not in fired, "the two checks must be mutually exclusive"
    assert result.band in ("elevated", "high")


def test_near_miss_check_stays_quiet_for_genuine_entity_variants(
    fixtures, reference_data
):
    for common_name in ("Mozilla Corporation", "Mozilla Foundation", "Mozilla"):
        result = score_with(
            fixtures["case4_mozilla_genuine_layout.exe"], reference_data,
            signed_as(common_name),
        )
        assert "signer_cn_near_miss" not in fired_checks(result), common_name


# ---------------------------------------------------------------------------
# Authenticode digest mismatch -- the near-independent verdict
# ---------------------------------------------------------------------------

def test_digest_mismatch_reaches_high_on_its_own(fixtures, reference_data):
    """A signature that does not match its file is decisive without any claim."""
    result = score_with(
        fixtures["case3_honest_freeware.exe"],   # no vendor claim at all
        reference_data,
        signed_as("Anybody At All", digest_status="mismatch"),
    )

    assert result.claim is None
    assert fired_checks(result) == {"authenticode_digest_mismatch"}
    assert result.band == "high"


def test_digest_indeterminate_is_reported_unavailable_not_fired(fixtures, reference_data):
    signature = signed_as("Mozilla Corporation")
    signature.digest_status = "indeterminate"
    signature.digest_status_reason = "PE layout malformed"

    result = score_with(fixtures["case4_mozilla_genuine_layout.exe"],
                        reference_data, signature)
    finding = next(f for f in result.findings
                   if f.check == "authenticode_digest_mismatch")
    assert finding.status == "unavailable"
    assert not finding.fired


# ---------------------------------------------------------------------------
# Authentihash computation
# ---------------------------------------------------------------------------

def test_authentihash_is_deterministic(fixtures, tmp_path):
    path = fixtures["case1_microsoft_system_binary.exe"]
    assert compute_authentihash(path) == compute_authentihash(path)


def test_authentihash_changes_when_section_content_changes(tmp_path):
    first = tmp_path / "a.exe"
    second = tmp_path / "b.exe"
    first.write_bytes(pebuilder.build_pe(version_fields={"CompanyName": "Acme"}))
    second.write_bytes(pebuilder.build_pe(version_fields={"CompanyName": "Acme Two"}))
    assert compute_authentihash(first) != compute_authentihash(second)


def test_authentihash_excludes_the_certificate_table(tmp_path):
    """Attaching a certificate table must not change the file's authentihash."""
    image = pebuilder.build_pe(version_fields={"CompanyName": "Acme"})
    padded = image + b"\x00" * ((8 - len(image) % 8) % 8)

    unsigned = tmp_path / "unsigned.exe"
    unsigned.write_bytes(padded)

    signed = tmp_path / "signed.exe"
    signed.write_bytes(pebuilder.attach_fake_certificate_table(image, b"\xAA" * 137))

    assert compute_authentihash(unsigned) == compute_authentihash(signed)


def test_authentihash_handles_a_section_pointing_inside_the_header_region(tmp_path):
    """Regression for a real bug found via a live VT sample.

    UPX emits a zero-size UPX0 section and points UPX1's PointerToRawData at an
    offset *inside* the file's own SizeOfHeaders region (observed: raw_pointer
    1024 against SizeOfHeaders 4096, in an Adobe-signed, UPX-packed sample
    pulled from `tag:upx signature:"Adobe" positives:0`). The original
    implementation hashed [raw_pointer, raw_pointer+raw_size) unconditionally
    for every section, re-hashing the already-consumed header bytes and
    producing a digest that never matched signify's -- confirmed by comparing
    against signify's own fingerprint on that real file, which DID match the
    embedded digest. The fix clamps each section's start to the running
    high-water mark.

    Reproduces the same UPX0(size=0) + UPX1(pointer inside headers) shape
    synthetically, with exactly two sections and nothing after them, so the
    ground truth reduces cleanly to "the whole file, minus the checksum field
    and the security-directory entry, hashed once with no gaps and no
    overlap" -- computed by plain byte slicing, not by any section-iteration
    logic, so it cannot share the bug being tested for.
    """
    import hashlib
    import struct

    import pefile

    image = bytearray(pebuilder.build_pe(section_names=["UPX0", "UPX1"]))
    pe = pefile.PE(data=bytes(image), fast_load=True)
    try:
        optional_header_offset = pe.OPTIONAL_HEADER.get_file_offset()
        checksum_offset = optional_header_offset + 64
        security_entry_offset = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].get_file_offset()
        size_of_headers = pe.OPTIONAL_HEADER.SizeOfHeaders
        assert len(pe.sections) == 2
        upx0, upx1 = pe.sections
        upx0_size_field_offset = upx0.get_file_offset() + 16       # SizeOfRawData
        upx1_pointer_field_offset = upx1.get_file_offset() + 20    # PointerToRawData
        assert upx0.PointerToRawData == size_of_headers, "fixture assumption changed"
        assert upx1.PointerToRawData > size_of_headers, "fixture assumption changed"
    finally:
        pe.close()

    struct.pack_into("<I", image, upx0_size_field_offset, 0)                        # UPX0: raw_size=0
    struct.pack_into("<I", image, upx1_pointer_field_offset, size_of_headers // 2)   # UPX1: inside headers

    path = tmp_path / "overlap.exe"
    path.write_bytes(bytes(image))

    data = path.read_bytes()
    expected = hashlib.sha256(
        data[:checksum_offset]
        + data[checksum_offset + 4:security_entry_offset]
        + data[security_entry_offset + 8:]
    ).hexdigest()

    assert compute_authentihash(path, "sha256") == expected


def test_authentihash_supports_sha1_and_sha256(fixtures):
    path = fixtures["case1_microsoft_system_binary.exe"]
    assert len(compute_authentihash(path, "sha1")) == 40
    assert len(compute_authentihash(path, "sha256")) == 64


# ---------------------------------------------------------------------------
# Isolated checks
# ---------------------------------------------------------------------------

def test_strict_internal_name_mismatch_fires_without_a_packer_identity(
    fixtures, reference_data
):
    result = score_with(
        fixtures["extra_mozilla_claim_odd_name.exe"],
        reference_data,
        signed_as("Mozilla Corporation"),
    )
    assert fired_checks(result) == {"internal_name_mismatch_strict"}
    # Weak evidence on its own: a correctly signed vendor binary with a helper
    # name outside the curated pattern list must not be pushed up a band.
    assert result.score == reference_data.weight("internal_name_mismatch_strict")
    assert result.band == "low"


def test_lenient_vendors_score_name_mismatches_lower(fixtures, reference_data, tmp_path):
    """Microsoft ships thousands of binaries; an unknown name is weak evidence."""
    path = tmp_path / "ms_odd.exe"
    path.write_bytes(pebuilder.build_pe(version_fields={
        "CompanyName": "Microsoft Corporation",
        "ProductName": "Microsoft Windows",
        "InternalName": "zzz_unlikely_name",
        "OriginalFilename": "zzz_unlikely_name",
        "LegalCopyright": "© Microsoft Corporation",
    }))
    result = score_with(path, reference_data, signed_as("Microsoft Windows"))

    assert fired_checks(result) == {"internal_name_mismatch_lenient"}
    assert result.score == reference_data.weight("internal_name_mismatch_lenient")
    assert result.band == "low"


def test_default_packer_icon_alone_fires_only_with_a_vendor_claim(
    fixtures, reference_data_with_icons
):
    flagged = score_with(
        fixtures["extra_adobe_claim_default_icon.exe"],
        reference_data_with_icons,
        signed_as("Adobe Inc."),
    )
    assert "default_packer_icon" in fired_checks(flagged)

    # Same stock icon, but nobody is being impersonated.
    honest = score_with(
        fixtures["case3_honest_freeware.exe"], reference_data_with_icons, UNSIGNED
    )
    assert "default_packer_icon" not in fired_checks(honest)


def test_icon_check_reports_unavailable_when_no_reference_hashes(
    fixtures, reference_data
):
    """The shipped default_icons.yaml is empty; that must degrade, not crash."""
    result = score_with(
        fixtures["extra_adobe_claim_default_icon.exe"], reference_data,
        signed_as("Adobe Inc."),
    )
    finding = next(f for f in result.findings if f.check == "default_packer_icon")
    assert finding.status == "unavailable"
    assert "default_icons.yaml" in finding.detail


def test_icon_hashes_are_stable_across_identical_builds(tmp_path):
    first = tmp_path / "one.exe"
    second = tmp_path / "two.exe"
    kwargs = dict(version_fields={"CompanyName": "Acme"},
                  icon_seeds=[make_fixtures.PACKER_DEFAULT_ICON_SEED])
    first.write_bytes(pebuilder.build_pe(**kwargs))
    second.write_bytes(pebuilder.build_pe(**kwargs))

    hashes_first = {i.sha256 for i in icon_fingerprint.fingerprint(first).icons}
    hashes_second = {i.sha256 for i in icon_fingerprint.fingerprint(second).icons}
    assert hashes_first == hashes_second
    assert make_fixtures.packer_default_icon_sha256() in hashes_first


# ---------------------------------------------------------------------------
# Graceful degradation
# ---------------------------------------------------------------------------

def test_non_pe_file_degrades_without_crashing(fixtures, reference_data):
    result = analyze_file(fixtures["extra_not_a_pe.bin"], reference_data)

    assert result.metadata.status == "error"
    assert not result.metadata.is_pe
    assert result.score == 0
    assert result.signature.status == "unavailable"
    assert result.icons.status == "unavailable"
    assert all(f.status == "unavailable" for f in result.findings)


def test_truncated_pe_degrades_without_crashing(tmp_path, reference_data):
    image = pebuilder.build_pe(version_fields={"CompanyName": "Mozilla",
                                               "InternalName": "7zS.sfx"})
    truncated = tmp_path / "truncated.exe"
    truncated.write_bytes(image[: len(image) // 3])

    result = analyze_file(truncated, reference_data)   # must not raise
    assert result.score >= 0
    assert isinstance(result.band, str)


def test_empty_file_degrades_without_crashing(tmp_path, reference_data):
    empty = tmp_path / "empty.exe"
    empty.write_bytes(b"")
    result = analyze_file(empty, reference_data)
    assert result.metadata.status == "error"
    assert result.score == 0


def test_missing_signify_reports_check_unavailable(fixtures, reference_data, monkeypatch):
    """If signify cannot be imported, signature checks report unavailable."""
    from peguise import authenticode

    monkeypatch.setattr(authenticode, "SIGNIFY_AVAILABLE", False)
    monkeypatch.setattr(authenticode, "SIGNIFY_IMPORT_ERROR", "simulated absence")

    signature = authenticode.inspect(fixtures["case2_mozilla_claim_7zsfx.exe"])
    assert signature.status == "unavailable"
    assert "signify" in signature.status_reason

    result = score_with(fixtures["case2_mozilla_claim_7zsfx.exe"],
                        reference_data, signature)
    statuses = {f.check: f.status for f in result.findings}
    assert statuses["authenticode_digest_mismatch"] == "unavailable"
    assert statuses["unsigned_but_vendor_signs"] == "unavailable"
    assert statuses["signer_cn_mismatch"] == "unavailable"
    # The signature-independent evidence must still be scored.
    assert "generic_tool_identity" in fired_checks(result)


def test_malformed_reference_data_raises_a_clear_error(tmp_path):
    from peguise import vendor_db

    (tmp_path / "vendors.yaml").write_text("not_a_vendors_key: []\n")
    with pytest.raises(vendor_db.ReferenceDataError, match="vendors"):
        vendor_db.load_vendors(tmp_path / "vendors.yaml")


# ---------------------------------------------------------------------------
# Matching primitives
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("a,b", [
    ("Mozilla Corporation", "Mozilla"),
    ("Microsoft(R) Corporation", "Microsoft Corporation"),
    ("Adobe Systems Incorporated", "Adobe Systems"),
    ("Google LLC", "Google"),
])
def test_containment_matches_legal_entity_variants(a, b):
    assert util.contains_name(a, b) or util.contains_name(b, a)


@pytest.mark.parametrize("a,b", [
    ("Mozilla", "Microsoft"),
    ("Google LLC", "Goggle Software"),
    ("Adobe", "Nvidia"),
])
def test_containment_rejects_unrelated_names(a, b):
    assert not (util.contains_name(a, b) or util.contains_name(b, a))


def test_normalization_strips_trademark_noise():
    assert util.normalize("Microsoft® Windows®") == "microsoft windows"
    assert util.core_name("Mozilla Corporation") == "mozilla"
    assert util.normalize("Notepad++").endswith("++")


def test_vendor_claim_detection_prefers_company_name(reference_data, tmp_path):
    path = tmp_path / "claim.exe"
    path.write_bytes(pebuilder.build_pe(version_fields={
        "CompanyName": "Adobe Inc.", "ProductName": "Firefox",
    }))
    meta = pe_metadata.extract(path)
    claim = scoring.detect_vendor_claim(meta, reference_data)
    assert claim is not None
    assert claim.vendor.id == "adobe"
    assert claim.field_name == "CompanyName"


def test_vendor_claim_falls_back_to_product_name(reference_data, tmp_path):
    path = tmp_path / "product_claim.exe"
    path.write_bytes(pebuilder.build_pe(version_fields={
        "ProductName": "Mozilla Firefox", "InternalName": "stub",
    }))
    meta = pe_metadata.extract(path)
    claim = scoring.detect_vendor_claim(meta, reference_data)
    assert claim is not None and claim.vendor.id == "mozilla"
    assert claim.field_name == "ProductName"


# ---------------------------------------------------------------------------
# Reference data integrity
#
# The vendor and packer databases are meant to be extended by analysts. These
# tests are the guard rail: they catch the mistakes that extension actually
# produces -- a regex typo, an alias that collides with another vendor, a
# benign_for_vendors id that does not exist, or a packer identity that a vendor
# legitimately ships and would therefore self-trip on.
# ---------------------------------------------------------------------------

def _claim_for(company_name: str, data, field: str = "CompanyName"):
    """Detect the vendor claim for a bare VERSIONINFO value, without a PE."""
    meta = pe_metadata.PEMetadata(path="<synthetic>", size=0, sha256="")
    meta.version_fields = {name: None for name in pe_metadata.VERSION_FIELDS}
    meta.version_fields[field] = company_name
    return scoring.detect_vendor_claim(meta, data)


def test_every_vendor_entry_is_well_formed(reference_data):
    import re

    assert len(reference_data.vendors) >= 12
    seen_ids = set()
    for vendor in reference_data.vendors:
        assert vendor.id not in seen_ids, f"duplicate vendor id {vendor.id}"
        seen_ids.add(vendor.id)
        assert vendor.display_name, vendor.id
        assert vendor.aliases, f"{vendor.id} has no aliases"
        assert vendor.product_patterns, f"{vendor.id} has no product_patterns"
        assert vendor.internal_name_check in ("strict", "lenient"), vendor.id
        assert all(s == s.lower() for s in vendor.signer_cn_substrings), vendor.id
        for pattern in vendor.product_patterns:
            re.compile(pattern)   # raises re.error on a malformed pattern
        # compile_patterns raises on a bad regex; make sure every pattern compiled.
        assert len(vendor._compiled) == len(vendor.product_patterns), vendor.id


def test_every_generic_tool_entry_is_well_formed(reference_data):
    import re

    seen_ids = set()
    for tool in reference_data.generic_tools:
        assert tool.id not in seen_ids, f"duplicate tool id {tool.id}"
        seen_ids.add(tool.id)
        assert tool.patterns or tool.section_names, \
            f"{tool.id} has neither patterns nor section_names"
        assert tool.fields, f"{tool.id} has no fields"
        assert tool.category in ("compressor", "protector", "other"), \
            f"{tool.id} has unknown category {tool.category!r}"
        for field_name in tool.fields:
            assert field_name in pe_metadata.VERSION_FIELDS, \
                f"{tool.id} references unknown VERSIONINFO field {field_name}"
        for pattern in tool.patterns:
            re.compile(pattern)
        assert len(tool._compiled) == len(tool.patterns), tool.id


def test_benign_for_vendors_references_real_vendor_ids(reference_data):
    """A typo here silently disables the exemption and creates a false positive."""
    known = {vendor.id for vendor in reference_data.vendors}
    for tool in reference_data.generic_tools:
        for vendor_id in tool.benign_for_vendors:
            assert vendor_id in known, \
                f"{tool.id}.benign_for_vendors references unknown vendor {vendor_id!r}"


def test_no_two_vendors_claim_the_same_alias(reference_data):
    """An alias owned by two vendors makes attribution order-dependent."""
    owners: dict[str, str] = {}
    for vendor in reference_data.vendors:
        for name in vendor.all_names():
            key = util.normalize(name)
            assert key not in owners or owners[key] == vendor.id, (
                f"alias {name!r} is claimed by both {owners.get(key)} and {vendor.id}"
            )
            owners[key] = vendor.id


def test_every_vendor_alias_resolves_to_its_own_vendor(reference_data):
    """No alias may be captured by an earlier vendor in the file."""
    for vendor in reference_data.vendors:
        for name in vendor.all_names():
            claim = _claim_for(name, reference_data)
            assert claim is not None, f"{vendor.id}: alias {name!r} matches nothing"
            assert claim.vendor.id == vendor.id, (
                f"alias {name!r} of {vendor.id} was captured by {claim.vendor.id}"
            )


def test_every_vendor_product_name_resolves_to_its_own_vendor(reference_data):
    for vendor in reference_data.vendors:
        for name in vendor.product_names:
            claim = _claim_for(name, reference_data, field="ProductName")
            assert claim is not None, f"{vendor.id}: product {name!r} matches nothing"
            assert claim.vendor.id == vendor.id, (
                f"product name {name!r} of {vendor.id} was captured by {claim.vendor.id}"
            )


def test_no_vendor_self_trips_on_a_generic_tool_identity(reference_data):
    """A vendor whose own product names look like a packer identity must be
    exempted via benign_for_vendors, or every genuine copy scores 45."""
    offenders = []
    for vendor in reference_data.vendors:
        for pattern in vendor.product_patterns:
            # Use the pattern's own literal alternatives as stand-in filenames.
            for candidate in _literal_candidates(pattern):
                for tool in reference_data.generic_tools:
                    if vendor.id in tool.benign_for_vendors:
                        continue
                    if not vendor.matches_product_name(candidate):
                        continue
                    if tool.match({"InternalName": candidate,
                                   "OriginalFilename": candidate}):
                        offenders.append((vendor.id, candidate, tool.id))
    assert not offenders, (
        "these vendors ship a name that a generic-tool entry also claims; add the "
        f"vendor id to that entry's benign_for_vendors: {sorted(set(offenders))}"
    )


def _literal_candidates(pattern: str) -> list[str]:
    r"""Pull plain-literal alternatives out of a product pattern, e.g.
    '(?i)(winrar|rar|unrar)(\.exe)?' -> ['winrar', 'rar', 'unrar']."""
    import re as _re

    body = pattern.replace("(?i)", "")
    candidates: list[str] = []
    for group in _re.findall(r"\(([^()]*)\)", body):
        for alternative in group.split("|"):
            alternative = alternative.replace("\\.", ".").strip()
            if alternative and _re.fullmatch(r"[A-Za-z0-9 ._+-]+", alternative):
                candidates.append(alternative)
                candidates.append(alternative + ".exe")
    return candidates


# ---------------------------------------------------------------------------
# Section-name reference data
# ---------------------------------------------------------------------------

def test_no_packer_section_name_collides_with_a_standard_one(reference_data):
    """A standard toolchain name in a packer entry fires on every clean build.

    This is the guard that keeps `.ndata` and `.wixburn` out: Firefox Setup is
    an NSIS installer, so a Mozilla claim beside `.ndata` is entirely normal.
    """
    for tool in reference_data.generic_tools:
        for name in tool.section_names:
            assert name.strip().lower() not in util.STANDARD_SECTION_NAMES, (
                f"{tool.id} claims {name!r}, which is a standard toolchain section"
            )


def test_section_names_fit_the_pe_field(reference_data):
    """The PE section name field is 8 bytes; anything longer can never match."""
    for tool in reference_data.generic_tools:
        for name in tool.section_names:
            assert len(name) <= 8, f"{tool.id}: {name!r} exceeds the 8-byte field"


def test_no_section_name_is_claimed_by_two_tools(reference_data):
    owners: dict[str, str] = {}
    for tool in reference_data.generic_tools:
        for name in tool.section_names:
            key = name.strip().lower()
            assert key not in owners, (
                f"{name!r} is claimed by both {owners[key]} and {tool.id}"
            )
            owners[key] = tool.id


def test_no_known_section_name_trips_the_anomaly_heuristic(reference_data):
    """Every allowlisted name must survive the heuristic.

    `.msvcjmc`, `.00cfg`, `.ndr64` and `.wpp_sf` are all legitimate and all trip
    two lexical features apiece; they are only quiet because they are listed.
    """
    minimum = int(reference_data.matching("section_anomaly_min_features", 2))
    for name in sorted(reference_data.known_section_names):
        features = util.section_name_anomalies(name, known=reference_data.known_section_names)
        assert len(features) < minimum, f"{name!r} would be flagged: {features}"


# ---------------------------------------------------------------------------
# Packer section names
# ---------------------------------------------------------------------------

def _pe_with_sections(tmp_path, names, **version_fields):
    path = tmp_path / "sections.exe"
    path.write_bytes(pebuilder.build_pe(
        version_fields=version_fields or None, section_names=names))
    return path


MOZILLA_CLEAN = dict(
    CompanyName="Mozilla", ProductName="Firefox", InternalName="firefox",
    OriginalFilename="firefox.exe", LegalCopyright="Mozilla", FileVersion="115.0.0.0",
)


def test_compressor_sections_fire_on_a_vendor_claim(reference_data, tmp_path):
    path = _pe_with_sections(tmp_path, ["UPX0", "UPX1", ".rdata"], **MOZILLA_CLEAN)
    result = score_with(path, reference_data, signed_as("Mozilla Corporation"))

    assert fired_checks(result) == {"packer_section_names"}
    finding = next(f for f in result.fired if f.check == "packer_section_names")
    assert finding.observed["matched_tool"] == "upx"
    assert finding.observed["matched_sections"] == ["UPX0", "UPX1"]
    assert finding.weight == reference_data.weight("packer_section_compressor")


def test_valleyrat_shape_dot_prefixed_upx(reference_data, tmp_path):
    """The corpus case: a complete, self-consistent NVIDIA identity whose only
    contradiction is its section names."""
    path = _pe_with_sections(
        tmp_path, [".text", ".upx0", ".upx1", ".upx2", ".rdata", ".gfids"],
        CompanyName="NVIDIA Corporation",
        ProductName="NVIDIA Smart Maximise Helper Host version 100.03",
        InternalName="NvSmartMaxapp", OriginalFilename="NvSmartMaxapp.dll",
        LegalCopyright="(C) NVIDIA Corporation. All rights reserved.",
        FileVersion="6.14.10.100.03",
    )
    result = score_with(path, reference_data, UNSIGNED)

    assert result.claim is not None and result.claim.vendor.id == "nvidia"
    assert "packer_section_names" in fired_checks(result)
    assert result.score == 50 and result.band == "elevated"


def test_protector_sections_score_lower_than_compressors(reference_data, tmp_path):
    """Security vendors legitimately protect their own agents."""
    path = _pe_with_sections(tmp_path, [".text", ".vmp0", ".vmp1"], **MOZILLA_CLEAN)
    result = score_with(path, reference_data, signed_as("Mozilla Corporation"))

    finding = next(f for f in result.fired if f.check == "packer_section_names")
    assert finding.observed["category"] == "protector"
    assert finding.weight == reference_data.weight("packer_section_protector")
    assert finding.weight < reference_data.weight("packer_section_compressor")
    assert result.band == "low", "a protector match alone must not reach a band"
    assert "legitimate user base" in finding.detail


def test_packer_sections_do_not_fire_without_a_vendor_claim(reference_data, tmp_path):
    """Ordinary UPX-packed freeware impersonates nobody."""
    path = _pe_with_sections(
        tmp_path, ["UPX0", "UPX1"],
        CompanyName="Jane's Tiny Tools", ProductName="PortSniffer",
        InternalName="main", FileVersion="0.9.1.0",
    )
    result = score_with(path, reference_data, UNSIGNED)

    assert result.claim is None
    assert result.score == 0
    finding = next(f for f in result.findings if f.check == "packer_section_names")
    assert finding.status == "not_applicable"


def test_standard_sections_leave_the_check_clear(reference_data, tmp_path):
    path = _pe_with_sections(
        tmp_path, [".text", ".rdata", ".data", ".pdata", ".gfids", ".reloc"],
        **MOZILLA_CLEAN)
    result = score_with(path, reference_data, signed_as("Mozilla Corporation"))

    assert fired_checks(result) == set()
    for check in ("packer_section_names", "anomalous_section_names"):
        assert next(f for f in result.findings if f.check == check).status == "clear"


def test_installer_sections_are_not_treated_as_packer_evidence(reference_data, tmp_path):
    """Firefox Setup is an NSIS installer -- `.ndata` beside a Mozilla claim is
    normal, and the corpus contains legitimate `.wixburn` binaries."""
    for name in (".ndata", ".wixburn"):
        path = _pe_with_sections(tmp_path, [".text", name, ".rsrc"], **MOZILLA_CLEAN)
        result = score_with(path, reference_data, signed_as("Mozilla Corporation"))
        assert fired_checks(result) == set(), f"{name} fired: {sorted(fired_checks(result))}"


def test_benign_for_vendors_exempts_section_matches(reference_data, tmp_path):
    path = _pe_with_sections(tmp_path, [".text", "UPX0"], **MOZILLA_CLEAN)
    tool = next(t for t in reference_data.generic_tools if t.id == "upx")
    tool.benign_for_vendors.append("mozilla")
    try:
        result = score_with(path, reference_data, signed_as("Mozilla Corporation"))
        assert "packer_section_names" not in fired_checks(result)
    finally:
        tool.benign_for_vendors.remove("mozilla")


def test_metadata_and_section_evidence_are_independent(reference_data, tmp_path):
    """7-Zip SFX metadata plus UPX sections is two facts, not one."""
    path = _pe_with_sections(
        tmp_path, ["UPX0", "UPX1"],
        CompanyName="Mozilla", ProductName="Thunderbird",
        InternalName="7zS.sfx", OriginalFilename="7zS.sfx.exe",
        LegalCopyright="Mozilla", FileVersion="18.05",
    )
    result = score_with(path, reference_data, UNSIGNED)

    fired = fired_checks(result)
    assert "generic_tool_identity" in fired
    assert "packer_section_names" in fired
    assert result.band == "high"


def test_same_tool_is_not_counted_twice(reference_data, tmp_path):
    """When one entry matches both ways, only the metadata finding scores."""
    tool = next(t for t in reference_data.generic_tools if t.id == "7zip_sfx")
    tool.section_names.append("SFXSEG")
    tool._section_set = frozenset({"sfxseg"})
    try:
        path = _pe_with_sections(
            tmp_path, [".text", "SFXSEG"],
            CompanyName="Mozilla", InternalName="7zS.sfx", FileVersion="1.0.0.0")
        result = score_with(path, reference_data, UNSIGNED)
        assert "generic_tool_identity" in fired_checks(result)
        finding = next(f for f in result.findings if f.check == "packer_section_names")
        assert finding.status == "suppressed"
    finally:
        tool.section_names.remove("SFXSEG")
        tool._section_set = frozenset()


# ---------------------------------------------------------------------------
# Anomalous section names
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name,expected_feature", [
    ("xk3jf9", "no_vowels"),
    ("wRfGh2", "case_alternation"),
    (".a3vTz", "digit_before_letter"),
    (".asdf454", "digit_run"),
])
def test_random_looking_section_names_are_flagged(reference_data, tmp_path,
                                                  name, expected_feature):
    path = _pe_with_sections(tmp_path, [".text", name], **MOZILLA_CLEAN)
    result = score_with(path, reference_data, signed_as("Mozilla Corporation"))

    assert "anomalous_section_names" in fired_checks(result), name
    finding = next(f for f in result.fired if f.check == "anomalous_section_names")
    assert expected_feature in finding.observed["flagged_sections"][name]


@pytest.mark.parametrize("name", [
    "ulcbptgt", "sacknfts", "xufkzpzn", "kxefbggn", "wrjdxasy",
    "skhjdruu", "cxelpskf", "hmmghgit", "bctwrsll", "zvzqjrbm",
])
def test_real_themida_randomized_names_are_flagged(reference_data, tmp_path, name):
    """Regression corpus from a live VT batch (50 files matching
    `tag:themida tag:signed positives:0`). Modern Themida builds do not leave a
    `.themida` section at all -- they randomize eight lowercase letters instead,
    with no digits and no case variation, so the digit- and case-based features
    never fire on them. Before adding `consonant_run`, only 15/30 real samples
    from that batch cleared the 2-feature threshold; these ten are drawn from
    the 8 that only clear it because of that feature.
    """
    path = _pe_with_sections(tmp_path, [".text", name], **MOZILLA_CLEAN)
    result = score_with(path, reference_data, signed_as("Mozilla Corporation"))
    assert "anomalous_section_names" in fired_checks(result), name
    finding = next(f for f in result.fired if f.check == "anomalous_section_names")
    assert "consonant_run" in finding.observed["flagged_sections"][name]


def test_consonant_run_recall_on_real_random_names(reference_data):
    """Measured, not assumed: recall of the full feature set against all 30
    section names from that same live batch. 15/30 before `consonant_run` was
    added, 23/30 after -- both numbers come from running the checker against
    the actual samples, not from a synthetic corpus."""
    names = ["ulcbptgt", "iezhiqxn", "sacknfts", "xufkzpzn", "kxefbggn",
             "phozinag", "wrjdxasy", "reuthhzf", "whrvlaxr", "skhjdruu",
             "difeuqgw", "tpjolsla", "tmwpphiq", "pmcmjdti", "dbnuwmpy",
             "cxelpskf", "hmmghgit", "qyrweoqr", "rpopcoji", "bctwrsll",
             "vircqnue", "ikohesjq", "rataiiba", "rptrjeca", "dqoanwov",
             "eolsbizt", "zvzqjrbm", "uapfcsvb", "dboecnco", "tltrjyno"]
    known = reference_data.known_section_names
    hits = sum(1 for n in names if len(util.section_name_anomalies(n, known=known)) >= 2)
    assert hits == 23


def test_malformed_section_names_are_flagged(reference_data, tmp_path):
    """Both shapes come from the real corpus: an all-NUL name, and a name with
    an interior NUL followed by more data."""
    for raw in (b"\x00\x00\x00\x00 \x00\x00`", b".pdata\x00I"):
        path = _pe_with_sections(tmp_path, [".text", raw], **MOZILLA_CLEAN)
        result = score_with(path, reference_data, signed_as("Mozilla Corporation"))
        assert "anomalous_section_names" in fired_checks(result), raw
        finding = next(f for f in result.fired if f.check == "anomalous_section_names")
        assert any("non_printable" in feats
                   for feats in finding.observed["flagged_sections"].values())


@pytest.mark.parametrize("name", [
    ".text", ".rdata", ".gfids", ".giats", ".msvcjmc", ".00cfg", ".bss", ".tls",
    ".ndr64", ".wpp_sf", "_RDATA", "/19", ".CRT", ".debug_info", "CODE", "INIT",
    ".wixburn", ".vmp0", "UPX0",
])
def test_real_section_names_are_not_flagged_as_anomalous(reference_data, tmp_path, name):
    """Regression corpus. `.ndr64` and `.wpp_sf` are the two false positives a
    survey of 1,076 real PEs surfaced -- both genuine Windows system sections."""
    path = _pe_with_sections(tmp_path, [".text", name], **MOZILLA_CLEAN)
    result = score_with(path, reference_data, signed_as("Mozilla Corporation"))
    assert "anomalous_section_names" not in fired_checks(result), name


def test_anomaly_check_cannot_reach_a_band_alone(reference_data, tmp_path):
    path = _pe_with_sections(tmp_path, [".text", "xk3jf9"], **MOZILLA_CLEAN)
    result = score_with(path, reference_data, signed_as("Mozilla Corporation"))
    assert result.score == reference_data.weight("anomalous_section_names")
    assert result.band == "low"


def test_section_checks_degrade_on_a_non_pe(fixtures, reference_data):
    result = analyze_file(fixtures["extra_not_a_pe.bin"], reference_data)
    assert result.metadata.sections == []
    statuses = {f.check: f.status for f in result.findings}
    assert statuses["packer_section_names"] == "unavailable"
    assert statuses["anomalous_section_names"] == "unavailable"


# ---------------------------------------------------------------------------
# ProductName containment fix
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("product_name", [
    "Quicken for Windows",
    "Acme Backup for Windows",
    "SomeTool Chrome Extension Host",
    "Acme Java Runtime Helper",
])
def test_generic_product_token_is_not_a_vendor_claim(reference_data, product_name):
    """A one-word product name must match the whole ProductName or not at all.

    "Windows", "Chrome" and "Java" are all single-token product_names; token
    containment previously made any phrase containing them a vendor claim, which
    misattributed a real Quicken binary to Microsoft.
    """
    assert _claim_for(product_name, reference_data, field="ProductName") is None


@pytest.mark.parametrize("product_name,vendor_id", [
    ("Windows", "microsoft"),
    ("Java", "oracle"),
    ("Chrome", "google"),
    ("Mozilla Firefox", "mozilla"),
    ("Microsoft Windows Operating System", "microsoft"),
    ("Adobe Acrobat Reader", "adobe"),
])
def test_real_product_names_still_resolve(reference_data, product_name, vendor_id):
    claim = _claim_for(product_name, reference_data, field="ProductName")
    assert claim is not None and claim.vendor.id == vendor_id


@pytest.mark.parametrize("product_name,vendor_id", [
    ("Intel Core", "intel"),
    ("Intel SONAR Boutique Utility", "intel"),
])
def test_distinctive_brand_tokens_keep_containment(reference_data, product_name, vendor_id):
    """Regression: the exact-only rule must not swallow real impersonation.

    GravityRAT ships ProductName "Intel Core" with copyright "Copyright (c) Intel
    Corporation" and NO CompanyName at all -- ProductName is the only place the
    claim is made. A blanket exact-only rule lost it. One-word COMPANY names are
    distinctive and keep containment; only one-word PRODUCT brands ("Windows",
    "Chrome", "Java"), which are ordinary words, are restricted.
    """
    claim = _claim_for(product_name, reference_data, field="ProductName")
    assert claim is not None and claim.vendor.id == vendor_id


def test_gravityrat_shape_is_still_detected(reference_data, tmp_path):
    """Full pipeline on the corpus shape: an Intel claim carried only by
    ProductName, contradicted by a misspelled copyright and no signature."""
    path = tmp_path / "gravityrat.exe"
    path.write_bytes(pebuilder.build_pe(version_fields={
        "ProductName": "Intel Core", "FileDescription": "Intel Core",
        "InternalName": "Intel Core.exe", "OriginalFilename": "Intel Core.exe",
        "LegalCopyright": "Copyright \u00a9 Intel Corporation. All right reseved",
        "FileVersion": "1.8.28.8",
    }))
    result = score_with(path, reference_data, UNSIGNED)

    assert result.claim is not None and result.claim.vendor.id == "intel"
    assert "unsigned_but_vendor_signs" in fired_checks(result)


def test_company_name_keeps_containment_matching(reference_data):
    """The fix must not touch CompanyName, which is not phrase-shaped."""
    for company in ("Mozilla Corporation", "Google LLC", "Adobe Systems Incorporated"):
        assert _claim_for(company, reference_data) is not None


# ---------------------------------------------------------------------------
# Newly added vendors: genuine binaries stay quiet, impersonation is caught
# ---------------------------------------------------------------------------

GENUINE_BINARIES = [
    # (CompanyName, ProductName, InternalName, OriginalFilename, LegalCopyright, signer CN)
    ("RARLAB", "WinRAR", "WinRAR", "WinRAR.exe",
     "Copyright (c) Alexander Roshal 1993-2024", "win.rar GmbH"),
    ("win.rar GmbH", "WinRAR", "WinRAR SFX", "WinRAR.exe",
     "Copyright (c) Alexander Roshal", "win.rar GmbH"),
    ("TeamViewer Germany GmbH", "TeamViewer", "TeamViewer", "TeamViewer.exe",
     "Copyright TeamViewer Germany GmbH", "TeamViewer Germany GmbH"),
    ("Realtek Semiconductor Corp.", "Realtek Audio Console", "RtkAudUService64",
     "RtkAudUService64.exe", "Copyright (C) Realtek Semiconductor Corp.",
     "Realtek Semiconductor Corp"),
    ("Python Software Foundation", "Python", "python", "python.exe",
     "Copyright (c) Python Software Foundation. All rights reserved.",
     "Python Software Foundation"),
    ("VideoLAN", "VLC media player", "VLC", "vlc.exe",
     "Copyright (C) 1996-2024 VideoLAN and VLC Authors", "VideoLAN"),
    ("Malwarebytes", "Malwarebytes", "MBAMService", "MBAMService.exe",
     "Copyright (C) Malwarebytes", "Malwarebytes Inc."),
    ("Zoom Video Communications, Inc.", "Zoom", "Zoom", "Zoom.exe",
     "Copyright Zoom Video Communications, Inc.", "Zoom Video Communications, Inc."),
    ("Advanced Micro Devices, Inc.", "AMD Radeon Software", "RadeonSoftware",
     "RadeonSoftware.exe", "Copyright Advanced Micro Devices, Inc.",
     "Advanced Micro Devices, Inc."),
]


@pytest.mark.parametrize(
    "company,product,internal,original,copyright_text,signer", GENUINE_BINARIES,
    ids=[row[0] for row in GENUINE_BINARIES],
)
def test_plausible_genuine_binary_from_a_new_vendor_scores_zero(
    reference_data, tmp_path, company, product, internal, original,
    copyright_text, signer,
):
    path = tmp_path / "genuine.exe"
    path.write_bytes(pebuilder.build_pe(version_fields={
        "CompanyName": company, "ProductName": product,
        "InternalName": internal, "OriginalFilename": original,
        "LegalCopyright": copyright_text, "FileVersion": "1.0.0.0",
    }))

    result = score_with(path, reference_data, signed_as(signer))
    assert result.claim is not None, f"{company} was not recognised as a vendor claim"
    assert fired_checks(result) == set(), (
        f"{company}/{internal} fired {sorted(fired_checks(result))}: "
        + " | ".join(f.detail for f in result.fired)
    )


@pytest.mark.parametrize("company,vendor_id", [
    ("TeamViewer GmbH", "teamviewer"),
    ("AnyDesk Software GmbH", "anydesk"),
    ("Realtek Semiconductor Corp.", "realtek"),
    ("Kaspersky Lab", "kaspersky"),
    ("ESET, spol. s r.o.", "eset"),
    ("Zoom Video Communications, Inc.", "zoom"),
    ("Cisco Systems, Inc.", "cisco"),
    ("Discord Inc.", "discord"),
    ("VideoLAN", "videolan"),
    ("Python Software Foundation", "python"),
])
def test_impersonating_a_new_vendor_with_a_packer_identity_is_caught(
    reference_data, tmp_path, company, vendor_id,
):
    """The core pattern, applied to each newly added vendor."""
    path = tmp_path / "impersonation.exe"
    path.write_bytes(pebuilder.build_pe(version_fields={
        "CompanyName": company, "ProductName": "Setup",
        "InternalName": "7zS.sfx", "OriginalFilename": "7zS.sfx",
        "FileVersion": "1.0.0.0",
    }))

    result = score_with(path, reference_data, UNSIGNED)
    assert result.claim is not None and result.claim.vendor.id == vendor_id
    assert "generic_tool_identity" in fired_checks(result)
    assert "unsigned_but_vendor_signs" in fired_checks(result)
    assert result.band == "high"


# ---------------------------------------------------------------------------
# Configurability
# ---------------------------------------------------------------------------

def test_weights_come_from_config_not_code(fixtures, reference_data):
    reference_data.config["weights"]["generic_tool_identity"] = 1
    reference_data.config["weights"]["unsigned_but_vendor_signs"] = 1
    reference_data.config["weights"]["copyright_vendor_mismatch"] = 1
    try:
        result = score_with(fixtures["case2_mozilla_claim_7zsfx.exe"],
                            reference_data, UNSIGNED)
        assert result.score == 3
        assert result.band == "low"
    finally:
        reference_data.config["weights"].update(
            generic_tool_identity=50, unsigned_but_vendor_signs=20,
            copyright_vendor_mismatch=5,
        )


def test_score_is_capped(fixtures, reference_data):
    result = score_with(
        fixtures["case2_mozilla_claim_7zsfx.exe"],
        reference_data,
        signed_as("Totally Unrelated Signer Ltd", digest_status="mismatch"),
    )
    assert result.score == reference_data.config["score_cap"]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(ROOT / "analyze.py"), *args],
        capture_output=True, text=True, cwd=str(ROOT), check=False,
    )


def test_cli_json_output_is_valid_and_complete(fixtures):
    completed = _run_cli(str(fixtures["case2_mozilla_claim_7zsfx.exe"]), "--json")
    assert completed.returncode == 0, completed.stderr

    payload = json.loads(completed.stdout)
    assert payload["analysis_type"] == "static-offline"
    assert "chain" in payload["disclaimer"]

    result = payload["results"][0]
    assert result["vendor_claim"]["vendor_id"] == "mozilla"
    assert result["band"] == "high"
    assert any(f["check"] == "generic_tool_identity" and f["status"] == "fired"
               for f in result["findings"])
    assert "certificate chain of trust" in result["signature"]["not_verified"]


def test_cli_directory_scan_finds_only_pe_files(fixtures):
    directory = fixtures["case2_mozilla_claim_7zsfx.exe"].parent
    completed = _run_cli(str(directory), "--json")
    assert completed.returncode == 0, completed.stderr

    payload = json.loads(completed.stdout)
    names = {Path(r["file"]).name for r in payload["results"]}
    assert "case2_mozilla_claim_7zsfx.exe" in names
    assert "extra_not_a_pe.bin" not in names        # filtered by the MZ sniff
    assert "test_default_icons.yaml" not in names


def test_cli_text_output_shows_evidence(fixtures):
    completed = _run_cli(str(fixtures["case2_mozilla_claim_7zsfx.exe"]))
    assert completed.returncode == 0, completed.stderr
    for expected in ("VENDOR CLAIM", "EVIDENCE", "generic_tool_identity",
                     "NOT VERIFIED", "7zS.sfx"):
        assert expected in completed.stdout


def test_cli_min_score_filters(fixtures):
    directory = fixtures["case2_mozilla_claim_7zsfx.exe"].parent
    completed = _run_cli(str(directory), "--json", "--min-score", "40")
    payload = json.loads(completed.stdout)
    assert payload["results"]
    assert all(r["score"] >= 40 for r in payload["results"])


def test_cli_fail_band_exit_code(fixtures):
    high = _run_cli(str(fixtures["case2_mozilla_claim_7zsfx.exe"]),
                    "--json", "--fail-band", "high")
    assert high.returncode == 1

    low = _run_cli(str(fixtures["case3_honest_freeware.exe"]),
                   "--json", "--fail-band", "high")
    assert low.returncode == 0


def test_cli_missing_target_is_a_usage_error(tmp_path):
    completed = _run_cli(str(tmp_path / "nope.exe"))
    assert completed.returncode == 2
    assert "no such file" in completed.stderr


def test_analyze_path_is_non_recursive_by_default(fixtures, reference_data, tmp_path):
    nested = tmp_path / "sub"
    nested.mkdir()
    (nested / "x.exe").write_bytes(pebuilder.build_pe(version_fields={"CompanyName": "X"}))
    (tmp_path / "top.exe").write_bytes(pebuilder.build_pe(version_fields={"CompanyName": "Y"}))

    assert len(analyze_path(tmp_path, reference_data)) == 1
    assert len(analyze_path(tmp_path, reference_data, recursive=True)) == 2


# ---------------------------------------------------------------------------
# End-to-end against REAL, parsable Authenticode signatures
#
# These run the whole pipeline -- signify PKCS#7 parsing, signer-certificate
# extraction, independent authentihash recomputation -- against fixtures signed
# at generation time with a throwaway self-signed certificate. Chain trust is
# never consulted by PEguise, so a self-signed certificate exercises exactly the
# same code path as a commercially issued one.
# ---------------------------------------------------------------------------

requires_signing = pytest.mark.skipif(
    not pesigner.SIGNING_AVAILABLE,
    reason=f"asn1crypto/oscrypto unavailable: {pesigner.SIGNING_IMPORT_ERROR}",
)


@requires_signing
def test_e2e_correctly_signed_vendor_binary_scores_low(fixtures, reference_data):
    """Case 1, end to end: real signature, matching digest, matching signer."""
    result = analyze_file(fixtures["signed_case1_mozilla_correct.exe"], reference_data)

    assert result.signature.status == "ok"
    assert result.signature.signed
    assert result.signature.signer_common_name == "Mozilla Corporation"
    assert result.signature.digest_status == "match", \
        result.signature.digest_status_reason
    assert result.claim is not None and result.claim.vendor.id == "mozilla"
    assert fired_checks(result) == set()
    assert result.score == 0
    assert result.band == "low"


@requires_signing
def test_e2e_subsidiary_signer_cn_scores_low(fixtures, reference_data):
    """Case 4, end to end: CompanyName "Mozilla", signer CN "Mozilla Foundation"."""
    result = analyze_file(fixtures["signed_case4_subsidiary_cn.exe"], reference_data)

    assert result.signature.signer_common_name == "Mozilla Foundation"
    assert result.signature.digest_status == "match"
    assert "signer_cn_mismatch" not in fired_checks(result)
    assert "signer_cn_near_miss" not in fired_checks(result)
    assert result.band == "low"


@requires_signing
def test_e2e_unrelated_signer_is_flagged(fixtures, reference_data):
    result = analyze_file(fixtures["signed_unrelated_signer.exe"], reference_data)

    assert result.signature.digest_status == "match"
    assert "signer_cn_mismatch" in fired_checks(result)
    assert "unsigned_but_vendor_signs" not in fired_checks(result)
    assert result.band in ("elevated", "high")


@requires_signing
def test_e2e_digest_mismatch_is_detected_from_a_real_signature(fixtures, reference_data):
    """The signature parses and the signer is right, but it covers other bytes."""
    result = analyze_file(fixtures["signed_digest_mismatch.exe"], reference_data)

    assert result.signature.status == "ok"
    assert result.signature.signed
    assert result.signature.digest_status == "mismatch", \
        result.signature.digest_status_reason
    assert result.signature.embedded_digest != result.signature.computed_digest
    assert "authenticode_digest_mismatch" in fired_checks(result)
    assert result.band == "high"


@requires_signing
def test_e2e_digest_mismatch_fires_without_any_vendor_claim(fixtures, reference_data):
    """The digest check is the one signal not gated on impersonation."""
    result = analyze_file(fixtures["signed_digest_mismatch_no_claim.exe"], reference_data)

    assert result.claim is None
    assert fired_checks(result) == {"authenticode_digest_mismatch"}
    assert result.band == "high"


@requires_signing
def test_e2e_signature_survives_appended_data(fixtures, reference_data, tmp_path):
    """Appending bytes after the certificate table changes the authentihash.

    Overlay-appended data is a classic way to smuggle a payload into an
    otherwise-signed binary, and it must show up as a digest mismatch.
    """
    original = fixtures["signed_case1_mozilla_correct.exe"].read_bytes()
    tampered = tmp_path / "tampered.exe"
    tampered.write_bytes(original[:0x420] + b"\x90" * 32 + original[0x440:])

    result = analyze_file(tampered, reference_data)
    assert result.signature.digest_status == "mismatch"
    assert "authenticode_digest_mismatch" in fired_checks(result)


@requires_signing
def test_e2e_our_authentihash_agrees_with_signify(fixtures):
    """Cross-check: if the two implementations disagreed we would report
    "indeterminate" rather than a mismatch, so agreement matters."""
    from signify.authenticode.signed_file.pe import SignedPEFile

    path = fixtures["signed_case1_mozilla_correct.exe"]
    with path.open("rb") as handle:
        signature = next(SignedPEFile(handle).iter_embedded_signatures())
        library = SignedPEFile(handle).get_fingerprint(
            signature.indirect_data.digest_algorithm).hex()

    assert compute_authentihash(path, "sha256") == library


@requires_signing
def test_e2e_cli_on_a_signed_fixture(fixtures):
    completed = _run_cli(str(fixtures["signed_digest_mismatch.exe"]), "--json")
    assert completed.returncode == 0, completed.stderr

    result = json.loads(completed.stdout)["results"][0]
    assert result["signature"]["digest_status"] == "mismatch"
    assert result["band"] == "high"


# ---------------------------------------------------------------------------
# Offline guarantee
# ---------------------------------------------------------------------------

def test_no_network_access_during_a_full_scan(fixtures, reference_data, monkeypatch):
    """The whole pipeline must run with every outbound connection blocked.

    signify is used strictly as a PKCS#7 parser here; if a future change ever
    reached for chain validation, revocation checking or a timestamp authority,
    this test fails rather than silently making the tool non-offline.
    """
    import socket
    import ssl

    class NetworkAccess(Exception):
        pass

    def blocked(*args, **kwargs):
        raise NetworkAccess("network access attempted")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket.socket, "connect_ex", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    monkeypatch.setattr(ssl.SSLContext, "wrap_socket", blocked)

    directory = fixtures["case2_mozilla_claim_7zsfx.exe"].parent
    results = analyze_path(directory, reference_data, recursive=True)

    assert results
    # Not merely "did not raise": the signature checks must still have worked.
    assert all(r.signature.status == "ok" for r in results)
    assert any(r.signature.digest_status == "match" for r in results)
    assert any(r.signature.digest_status == "mismatch" for r in results)


# ---------------------------------------------------------------------------
# Opt-in: real signed binary supplied by the analyst
# ---------------------------------------------------------------------------

REAL_SIGNED_PE = os.environ.get("PEGUISE_TEST_SIGNED_PE")


@pytest.mark.skipif(
    not REAL_SIGNED_PE,
    reason="set PEGUISE_TEST_SIGNED_PE to a genuine signed vendor binary "
           "(e.g. a copy of C:\\Windows\\System32\\notepad.exe or a Firefox "
           "installer) to run the real positive control",
)
def test_real_signed_vendor_binary_scores_low(reference_data):
    """End-to-end positive control against a real, genuinely signed binary.

    This is the only test that exercises signify's PKCS#7 parsing and the
    authentihash comparison against a real signature.
    """
    result = analyze_file(Path(REAL_SIGNED_PE), reference_data)

    assert result.metadata.is_pe
    assert result.signature.status == "ok"
    assert result.signature.signed, "supplied binary is not Authenticode-signed"
    assert result.signature.digest_status == "match", result.signature.digest_status_reason
    assert result.signature.signer_common_name

    assert "signer_cn_mismatch" not in fired_checks(result)
    assert "authenticode_digest_mismatch" not in fired_checks(result)
    assert result.band in ("low", "moderate"), (
        f"genuine signed binary scored {result.score} ({result.band}); "
        f"fired: {sorted(fired_checks(result))}"
    )


# ---------------------------------------------------------------------------
# Audit regressions
# ---------------------------------------------------------------------------

def test_text_report_escapes_terminal_control_characters(reference_data, tmp_path):
    """VERSIONINFO strings are attacker-controlled and the text report is read in a terminal.

    An ESC sequence in CompanyName could clear lines and repaint the SCORE line;
    a bidi override could reorder what the analyst sees. Every such character
    must reach the terminal escaped, while the JSON output keeps the raw value.
    """
    import io

    from peguise import report

    evil = "Mozilla\x1b[2K\r  SCORE  : 0 / 100  ->  \x1b[32mLOW\x1b[0m\u202e"
    path = tmp_path / "evil.exe"
    path.write_bytes(pebuilder.build_pe(version_fields={
        "CompanyName": evil, "ProductName": "Firefox", "InternalName": "7zS.sfx",
        "OriginalFilename": "7zS.sfx", "FileVersion": "1.0.0.0",
    }))
    result = analyze_file(path, reference_data)
    assert result.claim is not None and result.claim.vendor.id == "mozilla"
    result.metadata.path = "samples/\x1b[2Kevil.exe"          # paths are untrusted too
    result.signature.warnings.append("issuer said \x9b31m hello")  # C1 control

    text = io.StringIO()
    report.render_text(result, text, verbose=True)
    report.render_summary([result, result], text)
    rendered = text.getvalue()
    for raw in ("\x1b", "\r", "\u202e", "\x9b"):
        assert raw not in rendered
    assert "\\x1b[2K" in rendered          # escaped, and still visible to the analyst
    assert "\\u202e" in rendered
    assert "\\x9b" in rendered

    payload = io.StringIO()
    report.render_json([result], payload)
    decoded = json.loads(payload.getvalue())
    assert decoded["results"][0]["pe"]["version_fields"]["CompanyName"] == evil


def test_cli_json_emits_an_empty_document_when_nothing_is_found(tmp_path):
    completed = _run_cli(str(tmp_path), "--json")
    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout)
    assert payload["results"] == []
    assert "no PE files found" in completed.stderr


def test_signer_certificate_fallback_prefers_a_leaf_and_is_flagged():
    """When no certificate matches the SignerInfo, do not silently report the first one."""
    from types import SimpleNamespace as NS

    from peguise import authenticode

    def name(dn: str) -> NS:
        return NS(dn=dn)

    root = NS(serial_number=1, issuer=name("CN=Root"), subject=name("CN=Root"))
    intermediate = NS(serial_number=2, issuer=name("CN=Root"),
                      subject=name("CN=Intermediate CA"))
    leaf = NS(serial_number=3, issuer=name("CN=Intermediate CA"),
              subject=name("CN=Leaf Signer"))
    certificates = [root, intermediate, leaf]     # a CA listed first, as often happens

    # SignerInfo references a serial that no certificate carries.
    orphan = NS(signer_info=NS(serial_number=99, issuer=name("CN=Intermediate CA")),
                certificates=certificates)
    certificate, exact = authenticode._find_signer_certificate(orphan)
    assert certificate is leaf and exact is False

    info = authenticode.SignatureInfo(signed=True, signature_count=1)
    authenticode._extract_signer(orphan, info)
    assert info.signer_common_name == "Leaf Signer"
    assert info.signer_certificate_matched is False
    assert any("best-effort" in warning for warning in info.warnings)
    assert info.to_dict()["signer_certificate_matched"] is False

    # An exact issuer + serial match is unaffected and raises no warning.
    matched = NS(signer_info=NS(serial_number=3, issuer=name("CN=Intermediate CA")),
                 certificates=certificates)
    certificate, exact = authenticode._find_signer_certificate(matched)
    assert certificate is leaf and exact is True
    info = authenticode.SignatureInfo(signed=True, signature_count=1)
    authenticode._extract_signer(matched, info)
    assert info.signer_certificate_matched is True and not info.warnings


def test_unmatched_signer_certificate_is_not_scored(fixtures, reference_data):
    """A best-effort CN (often an intermediate CA) must not drive a 40-point finding."""
    signature = signed_as("DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1")
    signature.signer_certificate_matched = False
    result = score_with(fixtures["case4_mozilla_genuine_layout.exe"], reference_data, signature)

    by_check = {f.check: f for f in result.findings}
    assert by_check["signer_cn_mismatch"].status == "unavailable"
    assert by_check["signer_cn_near_miss"].status == "unavailable"
    assert result.score == 0

    # The same CN with a matched certificate is scored as usual.
    signature.signer_certificate_matched = True
    result = score_with(fixtures["case4_mozilla_genuine_layout.exe"], reference_data, signature)
    assert "signer_cn_mismatch" in fired_checks(result)


def test_fuzzy_matching_is_bounded_on_oversized_strings(reference_data):
    """difflib is quadratic; a 15,000-character CompanyName must not take seconds."""
    import time

    names = [n for v in reference_data.vendors for n in v.all_names()]
    value = "Mozilla" + "x" * 15000
    started = time.perf_counter()
    matched, _confidence, method = util.best_match(value, names, threshold=0.86)
    elapsed = time.perf_counter() - started
    assert elapsed < 0.5, f"best_match took {elapsed:.2f}s"
    assert matched is None and method == "none"
    # Ordinary near-misses still score as before.
    assert util.ratio("Mozilla Corporation", "Mozila Corporation") > 0.9


def test_bad_regex_in_reference_data_is_a_clear_error(tmp_path):
    from peguise import vendor_db

    (tmp_path / "vendors.yaml").write_text(
        "vendors:\n  - id: acme\n    product_patterns: ['(unclosed']\n", encoding="utf-8")
    with pytest.raises(vendor_db.ReferenceDataError, match="acme") as excinfo:
        vendor_db.load_vendors(tmp_path / "vendors.yaml")
    assert "(unclosed" in str(excinfo.value)

    (tmp_path / "packer_identities.yaml").write_text(
        "generic_tools:\n  - id: badtool\n    patterns: ['[']\n", encoding="utf-8")
    with pytest.raises(vendor_db.ReferenceDataError, match="badtool"):
        vendor_db.load_generic_tools(tmp_path / "packer_identities.yaml")


def test_missing_weight_in_config_is_a_clear_error(tmp_path):
    """A misspelled weight key must not silently disable a check."""
    from peguise import vendor_db

    good = {key: 1 for key in vendor_db.REQUIRED_WEIGHT_KEYS}
    good["generic_tool_identiy"] = good.pop("generic_tool_identity")     # typo
    (tmp_path / "weights.yaml").write_text(
        "weights:\n" + "".join(f"  {k}: {v}\n" for k, v in good.items())
        + "bands: [[0, low]]\n", encoding="utf-8")
    with pytest.raises(vendor_db.ReferenceDataError) as excinfo:
        vendor_db.load_config(tmp_path / "weights.yaml")
    message = str(excinfo.value)
    assert "generic_tool_identity" in message          # the missing key
    assert "generic_tool_identiy" in message           # the typo, offered as a hint

    (tmp_path / "weights.yaml").write_text(
        "weights:\n  generic_tool_identity: fifty\n", encoding="utf-8")
    with pytest.raises(vendor_db.ReferenceDataError, match="must be a number"):
        vendor_db.load_config(tmp_path / "weights.yaml")


def test_shipped_config_defines_every_required_weight(reference_data):
    from peguise import vendor_db

    for key in vendor_db.REQUIRED_WEIGHT_KEYS:
        assert key in reference_data.config["weights"], key
    assert reference_data.config["severity_thresholds"] == {"critical": 50, "high": 30, "medium": 15}


def test_severity_labels_come_from_config(fixtures, reference_data):
    result = score_with(fixtures["case2_mozilla_claim_7zsfx.exe"], reference_data, UNSIGNED)
    generic = next(f for f in result.findings if f.check == "generic_tool_identity")
    assert generic.severity == "critical"

    original = reference_data.config["severity_thresholds"]
    reference_data.config["severity_thresholds"] = {"critical": 1000, "high": 1000, "medium": 1000}
    try:
        result = score_with(fixtures["case2_mozilla_claim_7zsfx.exe"], reference_data, UNSIGNED)
        generic = next(f for f in result.findings if f.check == "generic_tool_identity")
        assert generic.severity == "low"
    finally:
        reference_data.config["severity_thresholds"] = original


def test_icon_walk_skips_malformed_resource_nodes():
    """A name node without a language directory must not abort the whole icon walk."""
    from types import SimpleNamespace as NS

    good_data = NS(struct=NS(OffsetToData=0, Size=0))
    type_entry = NS(directory=NS(entries=[
        NS(id=1, name=None, directory=None),                                  # no language dir
        NS(id=2, name=None, directory=NS(entries=[NS(id=0x409, data=None)])),  # no data
        NS(id=3, name=None, directory=NS(entries=[NS(id=0x409, data=good_data)])),
    ]))
    leaves = list(icon_fingerprint._iter_leaves(type_entry))
    assert [(identifier, lang) for identifier, lang, _data in leaves] == [(3, 0x409)]
    assert list(icon_fingerprint._iter_leaves(NS(directory=None))) == []
