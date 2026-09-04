"""Loading of the reference data files (vendors, generic tools, default icons).

All reference data lives in ``data/*.yaml`` and is loaded at runtime. Nothing in
this module encodes vendor knowledge -- see the header comments in each YAML
file for the schema and extension instructions.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import util
from .util import STANDARD_SECTION_NAMES  # re-exported for callers and tests

DEFAULT_DATA_DIR = Path(__file__).resolve().parent.parent / "data"

DEFAULT_GENERIC_TOOL_FIELDS = ("InternalName", "OriginalFilename")

# Every check weight the scoring module reads. weights.yaml must define all of
# them: ReferenceData.weight() returns 0 for an unknown key, so a misspelled or
# missing entry would otherwise disable a check silently.
REQUIRED_WEIGHT_KEYS = (
    "authenticode_digest_mismatch",
    "generic_tool_identity",
    "signer_cn_mismatch",
    "signer_cn_near_miss",
    "unsigned_but_vendor_signs",
    "default_packer_icon",
    "packer_section_compressor",
    "packer_section_protector",
    "anomalous_section_names",
    "internal_name_mismatch_strict",
    "internal_name_mismatch_lenient",
    "copyright_vendor_mismatch",
    "vendor_claim_without_names",
)

# Finding severity labels by weight, used when weights.yaml does not override
# them. Informational only; they never affect the score.
DEFAULT_SEVERITY_THRESHOLDS: dict[str, float] = {"critical": 50, "high": 30, "medium": 15}


class ReferenceDataError(RuntimeError):
    """Raised when a reference data file is missing or structurally invalid."""


def _load_structured(path: Path) -> Any:
    """Load a YAML file, falling back to JSON when PyYAML is unavailable.

    A ``.json`` sibling is accepted so the tool still runs in environments where
    PyYAML cannot be installed.
    """
    json_sibling = path.with_suffix(".json")
    if not path.exists() and json_sibling.exists():
        path = json_sibling

    if not path.exists():
        raise ReferenceDataError(f"reference data file not found: {path}")

    text = path.read_text(encoding="utf-8")
    if path.suffix == ".json":
        return json.loads(text)

    try:
        import yaml  # type: ignore[import-untyped]  # PyYAML ships no stubs
    except ImportError as exc:  # pragma: no cover - depends on environment
        raise ReferenceDataError(
            f"PyYAML is required to read {path.name}; install pyyaml or provide "
            f"{json_sibling.name} instead"
        ) from exc
    return yaml.safe_load(text)


@dataclass
class Vendor:
    """One entry from vendors.yaml, with regexes pre-compiled."""

    id: str
    display_name: str
    aliases: list[str]
    product_names: list[str]
    internal_name_check: str
    almost_always_signed: bool
    signer_cn_substrings: list[str]
    copyright_tokens: list[str]
    product_patterns: list[str]
    _compiled: list[re.Pattern[str]] = field(default_factory=list, repr=False)

    @property
    def is_strict(self) -> bool:
        return self.internal_name_check == "strict"

    def matches_product_name(self, value: str | None) -> str | None:
        """Return the pattern string that accepts ``value``, else None."""
        hit = util.any_fullmatch(self._compiled, value)
        return hit.pattern if hit else None

    def all_names(self) -> list[str]:
        """Display name plus aliases, for claim matching."""
        names = [self.display_name, *self.aliases]
        seen, unique = set(), []
        for name in names:
            key = util.normalize(name)
            if key and key not in seen:
                seen.add(key)
                unique.append(name)
        return unique


@dataclass
class GenericTool:
    """One entry from packer_identities.yaml."""

    id: str
    name: str
    fields: list[str]
    patterns: list[str]
    benign_for_vendors: list[str]
    note: str
    section_names: list[str] = field(default_factory=list)
    category: str = "other"
    _compiled: list[re.Pattern[str]] = field(default_factory=list, repr=False)
    _section_set: frozenset[str] = field(default_factory=frozenset, repr=False)

    def match(self, version_fields: dict[str, str | None]) -> tuple[str, str] | None:
        """Return ``(field_name, value)`` for the first field that matches."""
        for field_name in self.fields:
            value = version_fields.get(field_name)
            if util.any_fullmatch(self._compiled, value):
                return field_name, (value or "")
        return None

    def match_sections(self, names: list[str]) -> list[str]:
        """Return the section names of this file that this tool claims."""
        if not self._section_set:
            return []
        return [n for n in names if n.strip().lower() in self._section_set]

    @property
    def section_weight_key(self) -> str:
        """Config key for scoring a section-name match from this entry."""
        if self.category == "protector":
            return "packer_section_protector"
        return "packer_section_compressor"


@dataclass
class DefaultIcon:
    """One entry from default_icons.yaml."""

    id: str
    name: str
    tool: str | None
    note: str
    sha256: set[str]


@dataclass
class ReferenceData:
    """The complete loaded reference set."""

    vendors: list[Vendor]
    generic_tools: list[GenericTool]
    default_icons: list[DefaultIcon]
    config: dict[str, Any]
    data_dir: Path

    # -- convenience accessors ------------------------------------------------

    def vendor_by_id(self, vendor_id: str) -> Vendor | None:
        return next((v for v in self.vendors if v.id == vendor_id), None)

    @property
    def known_section_names(self) -> frozenset[str]:
        """Toolchain names plus every packer name the reference data knows.

        Packer names count as "known" for the anomaly heuristic: ``.vmp0`` is a
        recognised name, not a random one, and it is already reported by the
        packer-section check. Including them here stops the same section being
        reported twice under two different explanations.
        """
        packer = {n.strip().lower() for tool in self.generic_tools for n in tool.section_names}
        return frozenset(STANDARD_SECTION_NAMES | packer)

    @property
    def icon_hash_index(self) -> dict[str, DefaultIcon]:
        index: dict[str, DefaultIcon] = {}
        for icon in self.default_icons:
            for digest in icon.sha256:
                index[digest.lower()] = icon
        return index

    def weight(self, check_id: str) -> float:
        return float(self.config.get("weights", {}).get(check_id, 0.0))

    def matching(self, key: str, default: float) -> float:
        return float(self.config.get("matching", {}).get(key, default))


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return [str(v) for v in value]


def _compile(patterns: list[str], *, path: Path, kind: str, entry_id: str) -> list[re.Pattern[str]]:
    """Compile an entry's regexes, converting a bad one into a ReferenceDataError."""
    try:
        return util.compile_patterns(patterns)
    except ValueError as exc:
        raise ReferenceDataError(f"{path.name}: {kind} {entry_id!r} has an {exc}") from exc


def load_vendors(path: Path) -> list[Vendor]:
    raw = _load_structured(path) or {}
    entries = raw.get("vendors")
    if not isinstance(entries, list):
        raise ReferenceDataError(f"{path.name}: expected a top-level 'vendors' list")

    vendors: list[Vendor] = []
    for entry in entries:
        if not isinstance(entry, dict) or "id" not in entry:
            raise ReferenceDataError(f"{path.name}: vendor entry missing 'id': {entry!r}")
        check_mode = str(entry.get("internal_name_check", "lenient")).lower()
        if check_mode not in ("strict", "lenient"):
            check_mode = "lenient"
        vendor = Vendor(
            id=str(entry["id"]),
            display_name=str(entry.get("display_name", entry["id"])),
            aliases=_as_list(entry.get("aliases")),
            product_names=_as_list(entry.get("product_names")),
            internal_name_check=check_mode,
            almost_always_signed=bool(entry.get("almost_always_signed", False)),
            signer_cn_substrings=[s.lower() for s in _as_list(entry.get("signer_cn_substrings"))],
            copyright_tokens=[s.lower() for s in _as_list(entry.get("copyright_tokens"))],
            product_patterns=_as_list(entry.get("product_patterns")),
        )
        vendor._compiled = _compile(vendor.product_patterns, path=path,
                                    kind="vendor", entry_id=vendor.id)
        vendors.append(vendor)
    return vendors


def load_generic_tools(path: Path) -> list[GenericTool]:
    raw = _load_structured(path) or {}
    entries = raw.get("generic_tools")
    if not isinstance(entries, list):
        raise ReferenceDataError(f"{path.name}: expected a top-level 'generic_tools' list")

    tools: list[GenericTool] = []
    for entry in entries:
        if not isinstance(entry, dict) or "id" not in entry:
            raise ReferenceDataError(f"{path.name}: generic_tool entry missing 'id': {entry!r}")
        tool = GenericTool(
            id=str(entry["id"]),
            name=str(entry.get("name", entry["id"])),
            fields=_as_list(entry.get("fields")) or list(DEFAULT_GENERIC_TOOL_FIELDS),
            patterns=_as_list(entry.get("patterns")),
            benign_for_vendors=_as_list(entry.get("benign_for_vendors")),
            note=str(entry.get("note", "")).strip(),
            section_names=_as_list(entry.get("section_names")),
            category=str(entry.get("category", "other")).lower(),
        )
        if not tool.patterns and not tool.section_names:
            raise ReferenceDataError(
                f"{path.name}: generic_tool {tool.id!r} has neither 'patterns' nor "
                "'section_names'; it can never match anything"
            )
        tool._compiled = _compile(tool.patterns, path=path,
                                  kind="generic_tool", entry_id=tool.id)
        tool._section_set = frozenset(n.strip().lower() for n in tool.section_names)
        tools.append(tool)
    return tools


def load_default_icons(path: Path) -> list[DefaultIcon]:
    raw = _load_structured(path) or {}
    entries = raw.get("default_icons")
    if entries is None:
        entries = []
    if not isinstance(entries, list):
        raise ReferenceDataError(f"{path.name}: expected a top-level 'default_icons' list")

    icons: list[DefaultIcon] = []
    for entry in entries:
        if not isinstance(entry, dict) or "id" not in entry:
            raise ReferenceDataError(f"{path.name}: default_icon entry missing 'id': {entry!r}")
        icons.append(
            DefaultIcon(
                id=str(entry["id"]),
                name=str(entry.get("name", entry["id"])),
                tool=entry.get("tool"),
                note=str(entry.get("note", "")).strip(),
                sha256={str(h).strip().lower() for h in _as_list(entry.get("sha256"))},
            )
        )
    return icons


def load_config(path: Path) -> dict[str, Any]:
    raw = _load_structured(path) or {}
    if not isinstance(raw, dict):
        raise ReferenceDataError(f"{path.name}: expected a mapping at the top level")
    raw.setdefault("weights", {})
    raw.setdefault("matching", {})
    raw.setdefault("score_cap", 100)
    raw.setdefault("bands", [[0, "low"]])
    raw.setdefault("severity_thresholds", dict(DEFAULT_SEVERITY_THRESHOLDS))

    weights = raw["weights"]
    if not isinstance(weights, dict):
        raise ReferenceDataError(f"{path.name}: 'weights' must be a mapping of check id to number")
    for key, value in weights.items():
        try:
            float(value)
        except (TypeError, ValueError):
            raise ReferenceDataError(
                f"{path.name}: weight {key!r} must be a number, got {value!r}"
            ) from None
    missing = [key for key in REQUIRED_WEIGHT_KEYS if key not in weights]
    if missing:
        unknown = sorted(set(weights) - set(REQUIRED_WEIGHT_KEYS))
        hint = f"; unknown keys present, possibly misspelled: {unknown}" if unknown else ""
        raise ReferenceDataError(
            f"{path.name}: 'weights' is missing {missing}{hint}. Every check needs a "
            "weight; an absent key would silently disable that check."
        )
    return raw


def load(data_dir: str | os.PathLike[str] | None = None,
         config_path: str | os.PathLike[str] | None = None) -> ReferenceData:
    """Load every reference file. Raises ReferenceDataError on bad input."""
    directory = Path(data_dir) if data_dir else DEFAULT_DATA_DIR
    config_file = Path(config_path) if config_path else directory / "weights.yaml"
    return ReferenceData(
        vendors=load_vendors(directory / "vendors.yaml"),
        generic_tools=load_generic_tools(directory / "packer_identities.yaml"),
        default_icons=load_default_icons(directory / "default_icons.yaml"),
        config=load_config(config_file),
        data_dir=directory,
    )
