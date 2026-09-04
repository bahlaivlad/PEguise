"""Shared fixtures. Regenerates the synthetic PE corpus before every session."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import make_fixtures  # noqa: E402
from peguise import vendor_db  # noqa: E402


@pytest.fixture(scope="session")
def fixtures() -> dict[str, Path]:
    return make_fixtures.build_all()


@pytest.fixture(scope="session")
def reference_data():
    """The shipped reference data, exactly as an analyst would get it."""
    return vendor_db.load()


@pytest.fixture(scope="session")
def reference_data_with_icons(fixtures):
    """Shipped reference data plus the test-only default-icon hashes.

    data/default_icons.yaml ships empty on purpose (see its header), so the
    icon check is exercised against a generated fixture icon instead of
    hashes of third-party binaries.
    """
    data = vendor_db.load()
    data.default_icons = vendor_db.load_default_icons(
        fixtures["test_default_icons.yaml"]
    )
    return data
