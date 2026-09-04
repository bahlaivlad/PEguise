"""Generate the synthetic PE fixtures used by the test suite.

Every fixture is built from scratch by ``pebuilder`` -- no third-party binaries
are committed to the repository and nothing is downloaded. The fixtures are
inert: structurally valid PE containers whose only interesting content is their
resource directory. They are never executed.

Run directly to (re)write tests/fixtures/:

    python tests/make_fixtures.py
"""

from __future__ import annotations

import hashlib
from pathlib import Path

try:
    from . import pebuilder, pesigner  # type: ignore[attr-defined]
except ImportError:  # executed as a script
    import pebuilder  # type: ignore[no-redef]
    import pesigner  # type: ignore[no-redef]

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"

# Seed used for the icon that the test-only default-icon database claims is a
# packer's stock icon. Fixtures sharing this seed produce identical RT_ICON
# bytes, which is exactly the condition the real check looks for.
PACKER_DEFAULT_ICON_SEED = 42
CUSTOM_ICON_SEED = 7


def packer_default_icon_sha256() -> str:
    """Hash of the RT_ICON bytes produced by PACKER_DEFAULT_ICON_SEED."""
    return hashlib.sha256(
        pebuilder.build_icon_image(PACKER_DEFAULT_ICON_SEED)
    ).hexdigest()


# ---------------------------------------------------------------------------
# Fixture definitions. Each entry is (filename, kwargs for build_pe).
# ---------------------------------------------------------------------------

FIXTURES: dict[str, dict] = {
    # Case 2 -- the known-bad pattern from the brief: a big-vendor claim wearing
    # a 7-Zip SFX identity, unsigned, with the packer's stock icon.
    "case2_mozilla_claim_7zsfx.exe": dict(
        version_fields={
            "CompanyName": "Mozilla",
            "ProductName": "Firefox",
            "FileDescription": "Firefox Setup",
            "InternalName": "7zS.sfx",
            "OriginalFilename": "7zS.sfx",
            "LegalCopyright": "Copyright (c) 1999-2023 Igor Pavlov",
            "FileVersion": "115.0.2.0",
            "ProductVersion": "115.0.2",
        },
        icon_seeds=[PACKER_DEFAULT_ICON_SEED],
        file_version=(115, 0, 2, 0),
        product_version=(115, 0, 2, 0),
    ),

    # Case 3 -- honest small freeware. Slightly unprofessional metadata
    # (InternalName does not match OriginalFilename, no copyright), unsigned,
    # but it impersonates nobody. Must score zero.
    "case3_honest_freeware.exe": dict(
        version_fields={
            "CompanyName": "Jane's Tiny Tools",
            "ProductName": "PortSniffer",
            "FileDescription": "quick port scanner",
            "InternalName": "main",
            "OriginalFilename": "portsniff_v2_FINAL.exe",
            "FileVersion": "0.9.1.0",
        },
        icon_seeds=[CUSTOM_ICON_SEED],
        file_version=(0, 9, 1, 0),
        product_version=(0, 9, 1, 0),
    ),

    # Case 4 (unsigned half) -- a genuine-looking Mozilla file. The signed half
    # of this case is exercised in the tests by injecting a SignatureInfo whose
    # signer CN is "Mozilla Corporation"; this fixture supplies the VERSIONINFO.
    "case4_mozilla_genuine_layout.exe": dict(
        version_fields={
            "CompanyName": "Mozilla",
            "ProductName": "Firefox",
            "FileDescription": "Firefox",
            "InternalName": "firefox",
            "OriginalFilename": "firefox.exe",
            "LegalCopyright": "© Mozilla and Mozilla contributors",
            "FileVersion": "115.0.2.8432",
            "ProductVersion": "115.0.2",
        },
        icon_seeds=[CUSTOM_ICON_SEED],
        file_version=(115, 0, 2, 8432),
        product_version=(115, 0, 2, 0),
    ),

    # Case 1 (offline stand-in) -- a plausible genuine Microsoft system binary.
    # Real positive-control coverage requires an actually-signed binary; see
    # PEGUISE_TEST_SIGNED_PE in test_peguise.py.
    "case1_microsoft_system_binary.exe": dict(
        version_fields={
            "CompanyName": "Microsoft Corporation",
            "ProductName": "Microsoft® Windows® Operating System",
            "FileDescription": "Windows Command Processor",
            "InternalName": "cmd",
            "OriginalFilename": "Cmd.Exe",
            "LegalCopyright": "© Microsoft Corporation. All rights reserved.",
            "FileVersion": "10.0.19041.1 (WinBuild.160101.0800)",
            "ProductVersion": "10.0.19041.1",
        },
        icon_seeds=[CUSTOM_ICON_SEED],
        file_version=(10, 0, 19041, 1),
        product_version=(10, 0, 19041, 1),
    ),

    # Supporting fixtures -------------------------------------------------

    # Vendor claim + stock packer icon, but an otherwise plausible name --
    # isolates the default-icon check.
    "extra_adobe_claim_default_icon.exe": dict(
        version_fields={
            "CompanyName": "Adobe Systems Incorporated",
            "ProductName": "Adobe Acrobat Reader",
            "FileDescription": "Adobe Acrobat Reader DC",
            "InternalName": "AcroRd32",
            "OriginalFilename": "AcroRd32.exe",
            "LegalCopyright": "Copyright 2023 Adobe",
            "FileVersion": "23.1.0.0",
        },
        icon_seeds=[PACKER_DEFAULT_ICON_SEED],
    ),

    # Vendor claim with a name outside the vendor's catalogue, but no packer
    # identity -- isolates the strict internal-name check.
    "extra_mozilla_claim_odd_name.exe": dict(
        version_fields={
            "CompanyName": "Mozilla",
            "ProductName": "Firefox",
            "InternalName": "svc_helper",
            "OriginalFilename": "svc_helper.exe",
            "LegalCopyright": "Copyright Mozilla",
            "FileVersion": "115.0.0.0",
        },
        icon_seeds=[CUSTOM_ICON_SEED],
    ),

    # No version resource at all. Must score zero: nothing is claimed.
    "extra_no_version_resource.exe": dict(
        version_fields=None,
        icon_seeds=[CUSTOM_ICON_SEED],
    ),

    # Genuine 7-Zip SFX: the packer identity is the vendor's own. Must score
    # zero thanks to benign_for_vendors in packer_identities.yaml.
    "extra_genuine_7zip_sfx.exe": dict(
        version_fields={
            "CompanyName": "Igor Pavlov",
            "ProductName": "7-Zip",
            "FileDescription": "7z SFX",
            "InternalName": "7zS.sfx",
            "OriginalFilename": "7zS.sfx",
            "LegalCopyright": "Copyright (c) 1999-2023 Igor Pavlov",
            "FileVersion": "23.1.0.0",
        },
        icon_seeds=[CUSTOM_ICON_SEED],
    ),

    # Not a PE at all -- exercises graceful degradation.
    "extra_not_a_pe.bin": None,
}


# ---------------------------------------------------------------------------
# Signed fixtures. These carry a real, parsable Authenticode signature made with
# a throwaway self-signed certificate minted at generation time -- see
# pesigner.py for why a self-signed certificate is adequate here. They exist so
# the test suite exercises signify's PKCS#7 parsing and the real authentihash
# comparison rather than only injected SignatureInfo objects.
#
# Skipped silently when asn1crypto/oscrypto are unavailable; the tests that need
# them skip too.
# ---------------------------------------------------------------------------

MOZILLA_VERSION_FIELDS = {
    "CompanyName": "Mozilla",
    "ProductName": "Firefox",
    "FileDescription": "Firefox",
    "InternalName": "firefox",
    "OriginalFilename": "firefox.exe",
    "LegalCopyright": "\u00a9 Mozilla and Mozilla contributors",
    "FileVersion": "115.0.2.8432",
    "ProductVersion": "115.0.2",
}

SIGNED_FIXTURES: dict[str, dict] = {
    # Case 1 (real) -- genuine-looking, correctly signed by the vendor's own
    # legal entity. The end-to-end positive control.
    "signed_case1_mozilla_correct.exe": dict(
        common_name="Mozilla Corporation",
        organization="Mozilla Corporation",
        version_fields=MOZILLA_VERSION_FIELDS,
        icon_seeds=[CUSTOM_ICON_SEED],
    ),
    # Case 4 (real) -- signer CN is a subsidiary/legal-entity spelling that
    # differs from CompanyName. Must not over-flag.
    "signed_case4_subsidiary_cn.exe": dict(
        common_name="Mozilla Foundation",
        organization="Mozilla Corporation",
        version_fields=MOZILLA_VERSION_FIELDS,
        icon_seeds=[CUSTOM_ICON_SEED],
    ),
    # Signer is an entirely unrelated entity.
    "signed_unrelated_signer.exe": dict(
        common_name="Shenzhen Yuanchuang Network Technology Co., Ltd.",
        organization="Shenzhen Yuanchuang Network Technology Co., Ltd.",
        version_fields=MOZILLA_VERSION_FIELDS,
        icon_seeds=[CUSTOM_ICON_SEED],
    ),
    # Valid signature structure whose embedded digest is for different bytes.
    "signed_digest_mismatch.exe": dict(
        common_name="Mozilla Corporation",
        organization="Mozilla Corporation",
        corrupt_digest=True,
        version_fields=MOZILLA_VERSION_FIELDS,
        icon_seeds=[CUSTOM_ICON_SEED],
    ),
    # Digest mismatch on a file that impersonates nobody -- proves the digest
    # check is independent of the vendor-claim gate.
    "signed_digest_mismatch_no_claim.exe": dict(
        common_name="Jane's Tiny Tools",
        organization="Jane's Tiny Tools",
        corrupt_digest=True,
        version_fields={
            "CompanyName": "Jane's Tiny Tools",
            "ProductName": "PortSniffer",
            "InternalName": "main",
            "OriginalFilename": "portsniff.exe",
            "FileVersion": "0.9.1.0",
        },
        icon_seeds=[CUSTOM_ICON_SEED],
    ),
}


def build_all(destination: Path = FIXTURE_DIR) -> dict[str, Path]:
    """Write every fixture and return {name: path}."""
    destination.mkdir(parents=True, exist_ok=True)
    written: dict[str, Path] = {}

    for name, kwargs in FIXTURES.items():
        path = destination / name
        if kwargs is None:
            path.write_bytes(b"This is not a PE file.\n" + bytes(range(256)) * 4)
        else:
            path.write_bytes(pebuilder.build_pe(**kwargs))
        written[name] = path

    if pesigner.SIGNING_AVAILABLE:
        for name, kwargs in SIGNED_FIXTURES.items():
            path = destination / name
            path.write_bytes(pesigner.signed_pe(**kwargs))
            written[name] = path

    # A test-only default-icon database, so the icon check can be exercised
    # without shipping hashes of third-party binaries in data/default_icons.yaml.
    (destination / "test_default_icons.yaml").write_text(
        "# Generated by tests/make_fixtures.py -- do not edit by hand.\n"
        "# Test-only stand-in for data/default_icons.yaml.\n"
        "default_icons:\n"
        "  - id: synthetic_packer_default\n"
        "    name: Synthetic packer default icon\n"
        "    tool: 7zip_sfx\n"
        "    note: generated fixture icon, not a real packer icon\n"
        "    sha256:\n"
        f"      - {packer_default_icon_sha256()}\n",
        encoding="utf-8",
    )
    written["test_default_icons.yaml"] = destination / "test_default_icons.yaml"
    return written


if __name__ == "__main__":
    for name, path in build_all().items():
        print(f"{path.stat().st_size:>8} bytes  {name}")
