"""Icon resource fingerprinting.

Extracts RT_GROUP_ICON / RT_ICON resources and hashes the raw RT_ICON bytes so
they can be compared against the bundled list of packer/SFX stock default icons
(``data/default_icons.yaml``).

A vendor claim combined with a packer's untouched default icon is meaningful:
real vendors brand their installers. The reverse is not true -- a custom icon
proves nothing, so a non-match contributes zero.

Read-only: resource bytes are hashed, never decoded into an image or written
anywhere.
"""

from __future__ import annotations

import contextlib
import hashlib
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import pefile
    PEFILE_AVAILABLE = True
    PEFILE_IMPORT_ERROR = ""
except ImportError as exc:  # pragma: no cover
    pefile = None  # type: ignore[assignment]
    PEFILE_AVAILABLE = False
    PEFILE_IMPORT_ERROR = str(exc)

RT_ICON = 3
RT_GROUP_ICON = 14

_GRPICONDIR_HEADER = struct.Struct("<HHH")     # reserved, type, count
_GRPICONDIRENTRY = struct.Struct("<BBBBHHIH")  # w,h,colors,rsvd,planes,bpp,size,id


@dataclass
class IconEntry:
    """One RT_ICON resource."""

    resource_id: int | str
    language: int
    size: int
    sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "resource_id": self.resource_id,
            "language": self.language,
            "size": self.size,
            "sha256": self.sha256,
        }


@dataclass
class IconGroup:
    """One RT_GROUP_ICON resource and the RT_ICON ids it references."""

    resource_id: int | str
    language: int
    member_ids: list[int]
    sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "resource_id": self.resource_id,
            "language": self.language,
            "member_ids": list(self.member_ids),
            "sha256": self.sha256,
        }


@dataclass
class IconMatch:
    """A hashed icon that matched a known default-icon fingerprint."""

    icon_id: str
    icon_name: str
    tool: str | None
    note: str
    sha256: str
    matched_resource_id: int | str

    def to_dict(self) -> dict[str, Any]:
        return {
            "icon_id": self.icon_id,
            "icon_name": self.icon_name,
            "tool": self.tool,
            "note": self.note,
            "sha256": self.sha256,
            "matched_resource_id": self.matched_resource_id,
        }


@dataclass
class IconReport:
    """Result of icon fingerprinting for one file."""

    status: str = "ok"  # ok | unavailable | error | no_icons | no_reference_data
    status_reason: str = ""
    icons: list[IconEntry] = field(default_factory=list)
    groups: list[IconGroup] = field(default_factory=list)
    matches: list[IconMatch] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def has_icons(self) -> bool:
        return bool(self.icons)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "status_reason": self.status_reason,
            "icon_count": len(self.icons),
            "icons": [i.to_dict() for i in self.icons],
            "groups": [g.to_dict() for g in self.groups],
            "matches": [m.to_dict() for m in self.matches],
            "warnings": list(self.warnings),
        }


def _resource_id(entry: Any) -> int | str:
    name = getattr(entry, "name", None)
    if name is not None:
        return str(name)
    return int(getattr(entry, "id", -1))


def _iter_leaves(type_entry: Any):
    """Yield (resource_id, language, data_entry) for one resource type.

    Tolerates malformed trees: a name node without a language directory, or a
    language node without data, is skipped instead of aborting the whole walk
    with an AttributeError.
    """
    name_directory = getattr(type_entry, "directory", None)
    for name_entry in getattr(name_directory, "entries", None) or []:
        identifier = _resource_id(name_entry)
        language_directory = getattr(name_entry, "directory", None)
        for language_entry in getattr(language_directory, "entries", None) or []:
            data = getattr(language_entry, "data", None)
            if data is None:
                continue
            yield identifier, int(getattr(language_entry, "id", 0) or 0), data


def _parse_group_members(blob: bytes) -> list[int]:
    """Read the RT_ICON ids referenced by a GRPICONDIR structure."""
    if len(blob) < _GRPICONDIR_HEADER.size:
        return []
    _reserved, _type, count = _GRPICONDIR_HEADER.unpack_from(blob, 0)
    members: list[int] = []
    offset = _GRPICONDIR_HEADER.size
    for _ in range(count):
        if offset + _GRPICONDIRENTRY.size > len(blob):
            break
        fields = _GRPICONDIRENTRY.unpack_from(blob, offset)
        members.append(int(fields[-1]))
        offset += _GRPICONDIRENTRY.size
    return members


def fingerprint(path: str | Path, known_icons: dict[str, Any] | None = None) -> IconReport:
    """Hash every RT_ICON in the file and match against ``known_icons``.

    ``known_icons`` maps lowercase sha256 hex -> a DefaultIcon-like object with
    ``id``, ``name``, ``tool`` and ``note`` attributes.
    """
    report = IconReport()
    known_icons = known_icons or {}

    if not PEFILE_AVAILABLE:
        report.status = "unavailable"
        report.status_reason = f"pefile not installed ({PEFILE_IMPORT_ERROR})"
        return report

    pe = None
    try:
        pe = pefile.PE(str(path), fast_load=True)
        try:
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]]
            )
        except Exception as exc:
            report.status = "error"
            report.status_reason = f"resource directory unparsable: {type(exc).__name__}: {exc}"
            return report

        resource_root = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
        if resource_root is None:
            report.status = "no_icons"
            report.status_reason = "PE has no resource directory"
            return report

        for type_entry in resource_root.entries or []:
            type_id = getattr(type_entry, "id", None)
            if type_id not in (RT_ICON, RT_GROUP_ICON):
                continue
            if getattr(type_entry, "directory", None) is None:
                continue

            for identifier, language, data_entry in _iter_leaves(type_entry):
                try:
                    blob = pe.get_data(data_entry.struct.OffsetToData, data_entry.struct.Size)
                except Exception as exc:
                    report.warnings.append(
                        f"resource {type_id}/{identifier} unreadable: {exc}"
                    )
                    continue

                digest = hashlib.sha256(blob).hexdigest()
                if type_id == RT_ICON:
                    report.icons.append(
                        IconEntry(identifier, language, len(blob), digest)
                    )
                else:
                    report.groups.append(
                        IconGroup(identifier, language, _parse_group_members(blob), digest)
                    )

    except Exception as exc:
        report.status = "error"
        report.status_reason = f"icon extraction failed: {type(exc).__name__}: {exc}"
        return report
    finally:
        if pe is not None:
            with contextlib.suppress(Exception):
                pe.close()

    if not report.icons and not report.groups:
        report.status = "no_icons"
        report.status_reason = "PE contains no RT_ICON or RT_GROUP_ICON resources"
        return report

    if not known_icons:
        report.status = "no_reference_data"
        report.status_reason = (
            "no default-icon hashes are configured in data/default_icons.yaml; "
            "see tools/hash_icons.py to populate it"
        )
        return report

    for icon in report.icons:
        known = known_icons.get(icon.sha256)
        if known is not None:
            report.matches.append(
                IconMatch(
                    icon_id=getattr(known, "id", "unknown"),
                    icon_name=getattr(known, "name", "unknown"),
                    tool=getattr(known, "tool", None),
                    note=getattr(known, "note", ""),
                    sha256=icon.sha256,
                    matched_resource_id=icon.resource_id,
                )
            )

    return report
