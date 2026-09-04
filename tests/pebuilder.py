"""Minimal PE32 writer used to generate deterministic test fixtures.

Builds structurally valid PE files carrying a real VS_VERSIONINFO resource and
real RT_ICON / RT_GROUP_ICON resources, so the analysis pipeline is exercised
end to end against actual parsed resources rather than mocks.

The generated files contain no executable code path -- the ".text" section is
int3 filler and the entry point is never intended to be run. Fixtures exist to
be *parsed*, never executed.
"""

from __future__ import annotations

import struct
from collections.abc import Iterable, Mapping

# --- constants ------------------------------------------------------------

RT_ICON = 3
RT_GROUP_ICON = 14
RT_VERSION = 16

FILE_ALIGNMENT = 0x200
SECTION_ALIGNMENT = 0x1000
IMAGE_BASE = 0x00400000

_DOS_HEADER_SIZE = 0x80
_COFF_HEADER_SIZE = 20
_OPTIONAL_HEADER_SIZE = 0xE0
_SECTION_HEADER_SIZE = 40


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def _pad_to(data: bytes, alignment: int) -> bytes:
    return data + b"\x00" * (_align(len(data), alignment) - len(data))


# --- VS_VERSIONINFO -------------------------------------------------------

def _wide(text: str) -> bytes:
    return text.encode("utf-16-le") + b"\x00\x00"


def _pad4(data: bytes) -> bytes:
    return data + b"\x00" * ((4 - len(data) % 4) % 4)


def _node(key: str, *, value: bytes = b"", value_length: int = 0,
          value_type: int = 1, children: Iterable[bytes] = ()) -> bytes:
    """Build one version-resource node (the shared VS_* struct shape).

    Layout: wLength, wValueLength, wType, szKey, padding, Value, padding,
    Children. wLength covers everything except padding that follows the node
    itself, which is why children are padded individually and the last one is
    left unpadded.
    """
    body = struct.pack("<HHH", 0, value_length, value_type) + _wide(key)
    body = _pad4(body)
    if value:
        body += value

    child_list = list(children)
    if child_list:
        body = _pad4(body)
        for index, child in enumerate(child_list):
            body += child if index == len(child_list) - 1 else _pad4(child)

    return struct.pack("<H", len(body)) + body[2:]


def _fixed_file_info(file_version: tuple[int, int, int, int],
                     product_version: tuple[int, int, int, int],
                     *, file_type: int = 1) -> bytes:
    def pack_version(version: tuple[int, int, int, int]) -> tuple[int, int]:
        return (version[0] << 16) | version[1], (version[2] << 16) | version[3]

    file_ms, file_ls = pack_version(file_version)
    product_ms, product_ls = pack_version(product_version)
    return struct.pack(
        "<13I",
        0xFEEF04BD,   # dwSignature
        0x00010000,   # dwStrucVersion
        file_ms, file_ls,
        product_ms, product_ls,
        0x0000003F,   # dwFileFlagsMask
        0x00000000,   # dwFileFlags
        0x00040004,   # dwFileOS = VOS_NT_WINDOWS32
        file_type,    # dwFileType = VFT_APP
        0x00000000,   # dwFileSubtype
        0x00000000, 0x00000000,  # dwFileDate
    )


def build_version_resource(fields: Mapping[str, str], *,
                           file_version: tuple[int, int, int, int] = (1, 0, 0, 0),
                           product_version: tuple[int, int, int, int] = (1, 0, 0, 0),
                           lang_codepage: str = "040904B0") -> bytes:
    """Serialize a VS_VERSIONINFO resource from a field mapping."""
    strings = [
        _node(name, value=_wide(text), value_length=len(text) + 1, value_type=1)
        for name, text in fields.items()
        if text
    ]
    string_table = _node(lang_codepage, value_type=1, children=strings)
    string_file_info = _node("StringFileInfo", value_type=1, children=[string_table])

    language = int(lang_codepage[:4], 16)
    codepage = int(lang_codepage[4:], 16)
    var = _node("Translation", value=struct.pack("<HH", language, codepage),
                value_length=4, value_type=0)
    var_file_info = _node("VarFileInfo", value_type=1, children=[var])

    return _node(
        "VS_VERSION_INFO",
        value=_fixed_file_info(file_version, product_version),
        value_length=52,
        value_type=0,
        children=[string_file_info, var_file_info],
    )


# --- icon resources -------------------------------------------------------

def build_icon_image(seed: int = 0, *, width: int = 16, height: int = 16,
                     bit_count: int = 4) -> bytes:
    """A minimal, valid 4bpp DIB icon image. ``seed`` varies the pixel bytes.

    Two fixtures built with the same seed produce byte-identical RT_ICON
    resources, which is what lets the default-icon hash check be tested.
    """
    palette_entries = 1 << bit_count
    row_bytes = ((width * bit_count + 31) // 32) * 4
    mask_row_bytes = ((width + 31) // 32) * 4

    header = struct.pack(
        "<IiiHHIIiiII",
        40,                 # biSize
        width, height * 2,  # biWidth, biHeight (doubled: XOR + AND masks)
        1, bit_count,       # biPlanes, biBitCount
        0, 0,               # biCompression, biSizeImage
        0, 0,               # biXPelsPerMeter, biYPelsPerMeter
        palette_entries, 0,  # biClrUsed, biClrImportant
    )
    palette = b"".join(
        struct.pack("<4B", (i * 16 + seed) & 0xFF, (i * 8 + seed) & 0xFF,
                    (i * 4 + seed) & 0xFF, 0)
        for i in range(palette_entries)
    )
    xor_mask = bytes(((y * width + x + seed) & 0xFF)
                     for y in range(height) for x in range(row_bytes))
    and_mask = b"\x00" * (mask_row_bytes * height)
    return header + palette + xor_mask + and_mask


def build_group_icon(members: list[tuple[int, int]], *, width: int = 16,
                     height: int = 16, bit_count: int = 4) -> bytes:
    """GRPICONDIR referencing ``members`` as (resource_id, byte_size) pairs."""
    blob = struct.pack("<HHH", 0, 1, len(members))
    for resource_id, byte_size in members:
        blob += struct.pack(
            "<BBBBHHIH",
            width & 0xFF, height & 0xFF, 1 << bit_count if bit_count < 8 else 0, 0,
            1, bit_count, byte_size, resource_id,
        )
    return blob


# --- resource section -----------------------------------------------------

ResourceTree = Mapping[int, Mapping[int, Mapping[int, bytes]]]


def build_resource_section(tree: ResourceTree, base_rva: int) -> bytes:
    """Serialize a three-level IMAGE_RESOURCE_DIRECTORY (type/name/language)."""
    types = sorted(tree)

    offset = 16 + 8 * len(types)
    type_dir_offsets: dict[int, int] = {}
    for type_id in types:
        type_dir_offsets[type_id] = offset
        offset += 16 + 8 * len(tree[type_id])

    name_dir_offsets: dict[tuple[int, int], int] = {}
    for type_id in types:
        for name_id in sorted(tree[type_id]):
            name_dir_offsets[(type_id, name_id)] = offset
            offset += 16 + 8 * len(tree[type_id][name_id])

    data_entry_offsets: dict[tuple[int, int, int], int] = {}
    for type_id in types:
        for name_id in sorted(tree[type_id]):
            for lang_id in sorted(tree[type_id][name_id]):
                data_entry_offsets[(type_id, name_id, lang_id)] = offset
                offset += 16

    offset = _align(offset, 8)
    blob_offsets: dict[tuple[int, int, int], int] = {}
    for type_id in types:
        for name_id in sorted(tree[type_id]):
            for lang_id in sorted(tree[type_id][name_id]):
                blob_offsets[(type_id, name_id, lang_id)] = offset
                offset = _align(offset + len(tree[type_id][name_id][lang_id]), 8)

    buffer = bytearray(offset)

    def write_directory(at: int, entries: list[tuple[int, int, bool]]) -> None:
        struct.pack_into("<IIHHHH", buffer, at, 0, 0, 0, 0, 0, len(entries))
        cursor = at + 16
        for identifier, target, is_directory in entries:
            struct.pack_into("<II", buffer, cursor, identifier,
                             target | (0x80000000 if is_directory else 0))
            cursor += 8

    write_directory(0, [(t, type_dir_offsets[t], True) for t in types])
    for type_id in types:
        write_directory(
            type_dir_offsets[type_id],
            [(n, name_dir_offsets[(type_id, n)], True) for n in sorted(tree[type_id])],
        )
        for name_id in sorted(tree[type_id]):
            write_directory(
                name_dir_offsets[(type_id, name_id)],
                [(lang, data_entry_offsets[(type_id, name_id, lang)], False)
                 for lang in sorted(tree[type_id][name_id])],
            )

    for key, entry_offset in data_entry_offsets.items():
        type_id, name_id, lang_id = key
        blob = tree[type_id][name_id][lang_id]
        struct.pack_into("<IIII", buffer, entry_offset,
                         base_rva + blob_offsets[key], len(blob), 0, 0)
        buffer[blob_offsets[key]:blob_offsets[key] + len(blob)] = blob

    return bytes(buffer)


# --- PE assembly ----------------------------------------------------------

def _dos_header() -> bytes:
    """IMAGE_DOS_HEADER + stub. e_lfanew must land exactly at offset 0x3C."""
    header = struct.pack(
        "<2s13H",
        b"MZ",
        0x90, 0x0003, 0x0000, 0x0004, 0x0000, 0xFFFF, 0x0000,
        0x00B8, 0x0000, 0x0000, 0x0000, 0x0040, 0x0000,
    )                       # 28 bytes: e_magic .. e_lfarlc, e_ovno
    header += b"\x00" * 8   # e_res[4]
    header += struct.pack("<HH", 0, 0)   # e_oemid, e_oeminfo
    header += b"\x00" * 20  # e_res2[10]
    assert len(header) == 0x3C, len(header)
    header += struct.pack("<I", _DOS_HEADER_SIZE)   # e_lfanew
    header += (b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21"
               b"This program cannot be run in DOS mode.\r\r\n$")
    return header.ljust(_DOS_HEADER_SIZE, b"\x00")


_DOS_STUB = _dos_header()


def build_pe(*, version_fields: Mapping[str, str] | None = None,
             icon_seeds: list[int] | None = None,
             section_names: list[str | bytes] | None = None,
             text_size: int = 0x200,
             is_dll: bool = False,
             file_version: tuple[int, int, int, int] = (1, 0, 0, 0),
             product_version: tuple[int, int, int, int] = (1, 0, 0, 0),
             trailing_bytes: bytes = b"") -> bytes:
    """Assemble a complete PE32 image.

    ``version_fields`` becomes the VS_VERSIONINFO string table (omit or pass an
    empty mapping for a file with no version resource). ``icon_seeds`` adds one
    RT_ICON per seed plus a matching RT_GROUP_ICON.

    ``section_names`` replaces the single default ``.text`` section with one
    section per name, for exercising the packer-section and anomalous-name
    checks. Pass ``bytes`` to build a deliberately malformed name (non-printable
    bytes, an interior NUL); names are truncated to the PE's 8-byte field.
    """
    sections: list[tuple[bytes, bytes, int]] = []  # (name, raw data, characteristics)

    for raw_name in (section_names or [".text"]):
        encoded = raw_name if isinstance(raw_name, bytes) else raw_name.encode("latin-1")
        sections.append((encoded[:8], b"\xcc" * text_size, 0x60000020))

    resource_tree: dict[int, dict[int, dict[int, bytes]]] = {}
    if version_fields:
        resource_tree[RT_VERSION] = {
            1: {0x0409: build_version_resource(
                version_fields,
                file_version=file_version,
                product_version=product_version,
            )}
        }
    if icon_seeds:
        images = {index + 1: build_icon_image(seed) for index, seed in enumerate(icon_seeds)}
        resource_tree[RT_ICON] = {i: {0x0409: blob} for i, blob in images.items()}
        resource_tree[RT_GROUP_ICON] = {
            1: {0x0409: build_group_icon([(i, len(b)) for i, b in images.items()])}
        }

    header_size = (_DOS_HEADER_SIZE + 4 + _COFF_HEADER_SIZE + _OPTIONAL_HEADER_SIZE
                   + _SECTION_HEADER_SIZE * (len(sections) + (1 if resource_tree else 0)))
    size_of_headers = _align(header_size, FILE_ALIGNMENT)

    if resource_tree:
        # The resource section's RVA must be known before serializing it,
        # because data entries store absolute RVAs. It sits after every section
        # built so far -- which is more than one when section_names is used.
        preceding = sum(_align(len(data), SECTION_ALIGNMENT) for _name, data, _c in sections)
        rsrc_rva = _align(size_of_headers, SECTION_ALIGNMENT) + preceding
        sections.append((b".rsrc", build_resource_section(resource_tree, rsrc_rva), 0x40000040))

    # Lay out sections in both address space and file space.
    laid_out = []
    virtual_address = _align(size_of_headers, SECTION_ALIGNMENT)
    raw_pointer = size_of_headers
    for name, data, characteristics in sections:
        raw_size = _align(len(data), FILE_ALIGNMENT)
        laid_out.append({
            "name": name, "data": data, "characteristics": characteristics,
            "virtual_size": len(data), "virtual_address": virtual_address,
            "raw_size": raw_size, "raw_pointer": raw_pointer,
        })
        virtual_address += _align(len(data), SECTION_ALIGNMENT)
        raw_pointer += raw_size

    size_of_image = virtual_address
    text = laid_out[0]
    resource_section = next((s for s in laid_out if s["name"] == b".rsrc"), None)

    data_directories = [(0, 0)] * 16
    if resource_section is not None:
        data_directories[2] = (resource_section["virtual_address"],
                               resource_section["virtual_size"])

    coff = struct.pack(
        "<HHIIIHH",
        0x014C,                          # Machine = i386
        len(laid_out),                   # NumberOfSections
        0x5F000000,                      # TimeDateStamp (fixed, for reproducibility)
        0, 0,                            # symbol table (none)
        _OPTIONAL_HEADER_SIZE,
        0x0102 | (0x2000 if is_dll else 0),  # EXECUTABLE_IMAGE | 32BIT_MACHINE [| DLL]
    )

    optional = struct.pack(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        0x010B,                          # Magic = PE32
        14, 0,                           # linker version
        text["raw_size"],                # SizeOfCode
        resource_section["raw_size"] if resource_section else 0,
        0,                               # SizeOfUninitializedData
        text["virtual_address"],         # AddressOfEntryPoint
        text["virtual_address"],         # BaseOfCode
        text["virtual_address"] + _align(text_size, SECTION_ALIGNMENT),  # BaseOfData
        IMAGE_BASE,
        SECTION_ALIGNMENT, FILE_ALIGNMENT,
        6, 0, 0, 0, 6, 0,                # OS / image / subsystem versions
        0,                               # Win32VersionValue
        size_of_image, size_of_headers,
        0,                               # CheckSum (left zero, as many real files do)
        3,                               # Subsystem = CUI
        0x8140,                          # DllCharacteristics
        0x100000, 0x1000, 0x100000, 0x1000,
        0, 16,                           # LoaderFlags, NumberOfRvaAndSizes
    ) + b"".join(struct.pack("<II", rva, size) for rva, size in data_directories)

    section_headers = b"".join(
        struct.pack("<8sIIIIIIHHI",
                    section["name"].ljust(8, b"\x00"),
                    section["virtual_size"], section["virtual_address"],
                    section["raw_size"], section["raw_pointer"],
                    0, 0, 0, 0, section["characteristics"])
        for section in laid_out
    )

    image = bytearray(_pad_to(
        _DOS_STUB + b"PE\x00\x00" + coff + optional + section_headers, FILE_ALIGNMENT))
    for section in laid_out:
        image[section["raw_pointer"]:section["raw_pointer"] + section["raw_size"]] = \
            _pad_to(section["data"], FILE_ALIGNMENT)

    return bytes(image) + trailing_bytes


def attach_fake_certificate_table(image: bytes, certificate_blob: bytes) -> bytes:
    """Append a WIN_CERTIFICATE-shaped blob and point data directory 4 at it.

    The blob is NOT a valid PKCS#7 -- it exists purely to prove that the
    authentihash computation excludes the attribute certificate table and the
    security data-directory entry.
    """
    padded = image + b"\x00" * ((8 - len(image) % 8) % 8)

    length = 8 + len(certificate_blob)
    certificate = struct.pack("<IHH", length, 0x0200, 0x0002) + certificate_blob
    certificate = certificate.ljust(_align(length, 8), b"\x00")

    out = bytearray(padded + certificate)
    e_lfanew = struct.unpack_from("<I", out, 0x3C)[0]
    optional_header = e_lfanew + 4 + _COFF_HEADER_SIZE
    security_entry = optional_header + 96 + 4 * 8   # data directory index 4
    struct.pack_into("<II", out, security_entry, len(padded), len(certificate))
    return bytes(out)
