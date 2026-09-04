"""VERSIONINFO extraction and basic PE facts, via pefile.

Read-only. The file is opened, parsed and closed; nothing is executed, unpacked
or written back.
"""

from __future__ import annotations

import contextlib
import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import pefile
    PEFILE_AVAILABLE = True
    PEFILE_IMPORT_ERROR = ""
except ImportError as exc:  # pragma: no cover - depends on environment
    pefile = None  # type: ignore[assignment]
    PEFILE_AVAILABLE = False
    PEFILE_IMPORT_ERROR = str(exc)


# The VERSIONINFO string fields PEguise reasons about, in report order.
VERSION_FIELDS = (
    "CompanyName",
    "ProductName",
    "FileDescription",
    "InternalName",
    "OriginalFilename",
    "LegalCopyright",
    "FileVersion",
    "ProductVersion",
)


@dataclass
class SectionInfo:
    """One PE section header, as far as PEguise cares about it."""

    name: str                  # trailing NULs stripped, otherwise verbatim
    raw_name_hex: str          # the original 8 bytes, for unprintable names
    virtual_size: int
    raw_size: int
    characteristics: int
    name_is_printable: bool
    has_interior_nul: bool     # a NUL with more data after it -- malformed

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "raw_name_hex": self.raw_name_hex,
            "virtual_size": self.virtual_size,
            "raw_size": self.raw_size,
            "characteristics": self.characteristics,
            "name_is_printable": self.name_is_printable,
            "has_interior_nul": self.has_interior_nul,
        }


@dataclass
class PEMetadata:
    """Everything the rest of the pipeline needs from the PE itself."""

    path: str
    size: int
    sha256: str
    status: str = "ok"              # ok | unavailable | error
    status_reason: str = ""
    is_pe: bool = False
    machine: str | None = None
    is_dll: bool = False
    timestamp: int | None = None
    has_version_resource: bool = False
    version_fields: dict[str, str | None] = field(default_factory=dict)
    extra_version_fields: dict[str, str] = field(default_factory=dict)
    fixed_file_version: str | None = None
    fixed_product_version: str | None = None
    has_certificate_table: bool = False
    certificate_table_size: int = 0
    sections: list[SectionInfo] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def field(self, name: str) -> str | None:
        return self.version_fields.get(name)

    @property
    def any_version_strings(self) -> bool:
        return any(v for v in self.version_fields.values())

    @property
    def section_names(self) -> list[str]:
        return [s.name for s in self.sections]

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "size": self.size,
            "sha256": self.sha256,
            "status": self.status,
            "status_reason": self.status_reason,
            "is_pe": self.is_pe,
            "machine": self.machine,
            "is_dll": self.is_dll,
            "timestamp": self.timestamp,
            "has_version_resource": self.has_version_resource,
            "version_fields": dict(self.version_fields),
            "extra_version_fields": dict(self.extra_version_fields),
            "fixed_file_version": self.fixed_file_version,
            "fixed_product_version": self.fixed_product_version,
            "has_certificate_table": self.has_certificate_table,
            "certificate_table_size": self.certificate_table_size,
            "sections": [s.to_dict() for s in self.sections],
            "warnings": list(self.warnings),
        }


def sha256_file(path: Path, chunk_size: int = 1 << 20) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def looks_like_pe(path: Path) -> bool:
    """Cheap MZ/PE sniff so directory scans do not depend on file extensions."""
    try:
        with path.open("rb") as handle:
            if handle.read(2) != b"MZ":
                return False
            handle.seek(0x3C)
            raw = handle.read(4)
            if len(raw) != 4:
                return False
            offset = int.from_bytes(raw, "little")
            if offset <= 0 or offset > (1 << 20):
                return False
            handle.seek(offset)
            return handle.read(4) == b"PE\x00\x00"
    except OSError:
        return False


def _decode(value: Any) -> str | None:
    """VERSIONINFO values arrive as bytes from pefile; decode leniently."""
    if value is None:
        return None
    if isinstance(value, bytes):
        for encoding in ("utf-8", "utf-16-le", "latin-1"):
            try:
                decoded = value.decode(encoding)
                break
            except UnicodeDecodeError:
                continue
        else:  # pragma: no cover - latin-1 never fails
            decoded = value.decode("utf-8", "replace")
    else:
        decoded = str(value)
    decoded = decoded.replace("\x00", "").strip()
    return decoded or None


def _format_version(ms: int, ls: int) -> str:
    return f"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}"


def _machine_name(pe: pefile.PE) -> str | None:
    try:
        return pefile.MACHINE_TYPE.get(pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine))
    except Exception:
        return None


def extract(path: str | Path) -> PEMetadata:
    """Parse a file and return its metadata, degrading gracefully on failure."""
    file_path = Path(path)

    try:
        size = file_path.stat().st_size
        digest = sha256_file(file_path)
    except OSError as exc:
        return PEMetadata(
            path=str(file_path), size=0, sha256="",
            status="error", status_reason=f"cannot read file: {exc}",
        )

    meta = PEMetadata(path=str(file_path), size=size, sha256=digest)
    meta.version_fields = {name: None for name in VERSION_FIELDS}

    if not PEFILE_AVAILABLE:
        meta.status = "unavailable"
        meta.status_reason = f"pefile not installed ({PEFILE_IMPORT_ERROR})"
        return meta

    pe = None
    try:
        # fast_load skips directory parsing; we then load only what we need.
        pe = pefile.PE(str(file_path), fast_load=True)
        meta.is_pe = True
        meta.machine = _machine_name(pe)
        meta.is_dll = bool(pe.FILE_HEADER.Characteristics & 0x2000)
        meta.timestamp = int(pe.FILE_HEADER.TimeDateStamp)

        _read_certificate_table(pe, meta)
        _read_sections(pe, meta)

        try:
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]]
            )
        except Exception as exc:
            meta.warnings.append(f"resource directory unparsable: {exc}")
        else:
            _read_version_info(pe, meta)

    except Exception as exc:  # pefile raises PEFormatError and assorted others
        meta.status = "error"
        meta.status_reason = f"PE parse failed: {type(exc).__name__}: {exc}"
    finally:
        if pe is not None:
            with contextlib.suppress(Exception):
                pe.close()

    return meta


def _read_certificate_table(pe: pefile.PE, meta: PEMetadata) -> None:
    """Record whether the security data directory points at a signature blob."""
    try:
        directories = pe.OPTIONAL_HEADER.DATA_DIRECTORY
        index = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        if index < len(directories):
            entry = directories[index]
            meta.certificate_table_size = int(entry.Size)
            meta.has_certificate_table = bool(entry.VirtualAddress and entry.Size)
    except Exception as exc:
        meta.warnings.append(f"certificate table unreadable: {exc}")


def _read_sections(pe: pefile.PE, meta: PEMetadata) -> None:
    """Record the section table.

    ``pe.sections`` is already populated under ``fast_load=True``, so this costs
    no extra parsing and no second read of the file.

    Section names are 8 bytes, NUL-padded. Trailing NULs are stripped, but a NUL
    with data after it is preserved and flagged: real toolchains never emit that,
    and the malformed shape is itself evidence.
    """
    try:
        for section in pe.sections:
            raw = bytes(section.Name)
            stripped = raw.rstrip(b"\x00")
            meta.sections.append(
                SectionInfo(
                    name=stripped.decode("latin-1"),
                    raw_name_hex=raw.hex(),
                    virtual_size=int(section.Misc_VirtualSize),
                    raw_size=int(section.SizeOfRawData),
                    characteristics=int(section.Characteristics),
                    name_is_printable=all(0x20 <= b <= 0x7E for b in stripped),
                    has_interior_nul=b"\x00" in stripped,
                )
            )
    except Exception as exc:
        meta.warnings.append(f"section table unreadable: {exc}")


def _read_version_info(pe: pefile.PE, meta: PEMetadata) -> None:
    """Pull VS_FIXEDFILEINFO and every StringTable entry out of RT_VERSION."""
    # pefile populates VS_FIXEDFILEINFO / FileInfo as a side effect of parsing
    # the resource directory, which the caller has already done.
    fixed = getattr(pe, "VS_FIXEDFILEINFO", None) or []
    if fixed:
        try:
            info = fixed[0]
            meta.fixed_file_version = _format_version(info.FileVersionMS, info.FileVersionLS)
            meta.fixed_product_version = _format_version(info.ProductVersionMS, info.ProductVersionLS)
            meta.has_version_resource = True
        except Exception as exc:
            meta.warnings.append(f"VS_FIXEDFILEINFO unreadable: {exc}")

    string_tables = getattr(pe, "FileInfo", None) or []
    collected: dict[str, str] = {}

    for file_info_list in string_tables:
        # pefile nests this differently across versions; tolerate both shapes.
        entries = file_info_list if isinstance(file_info_list, list) else [file_info_list]
        for entry in entries:
            if getattr(entry, "Key", None) != b"StringFileInfo":
                continue
            meta.has_version_resource = True
            for string_table in getattr(entry, "StringTable", []) or []:
                for key, value in (getattr(string_table, "entries", {}) or {}).items():
                    name = _decode(key)
                    text = _decode(value)
                    if not name:
                        continue
                    # First occurrence wins; later language blocks are extras.
                    collected.setdefault(name, text or "")

    for name in VERSION_FIELDS:
        meta.version_fields[name] = collected.pop(name, None) or None
    # Anything the vendor added beyond the standard set, kept for the report.
    meta.extra_version_fields = {k: v for k, v in collected.items() if v}
