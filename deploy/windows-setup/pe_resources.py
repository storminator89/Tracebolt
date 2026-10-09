"""Deterministic, dependency-free PE resource objects and read-only verification.

The tiny COFF object contains only RT_VERSION and RT_MANIFEST. It is generated
inside the build workspace, never checked in or executed. Format references:
https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
https://learn.microsoft.com/en-us/windows/win32/menurc/versioninfo-resource
"""
from __future__ import annotations

import re
import struct
from xml.etree import ElementTree

MACHINES = {"amd64": 0x8664, "arm64": 0xAA64}
RELOCATIONS = {"amd64": 0x0003, "arm64": 0x0002}  # ADDR32NB
VERSION = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?\Z", re.ASCII)
COMMIT = re.compile(r"[0-9a-f]{40}\Z", re.ASCII)


class Rejected(ValueError):
    """A bounded build input or PE contract was rejected."""


def require(ok: bool, message: str) -> None:
    if not ok:
        raise Rejected(message)


def version_parts(version: str) -> tuple[int, int, int, int]:
    require(isinstance(version, str) and len(version) <= 80, "Version is not a bounded v-prefixed SemVer.")
    match = VERSION.fullmatch(version)
    require(match is not None, "Version is not a bounded v-prefixed SemVer.")
    assert match is not None
    if match[4]:
        require(all(not (part.isdigit() and len(part) > 1 and part[0] == "0") for part in match[4].split(".")), "Numeric prerelease components must not have leading zeroes.")
    parts = tuple(int(match[i]) for i in range(1, 4)) + (0,)
    require(all(part <= 65535 for part in parts), "Version components exceed Windows resource limits.")
    return parts


def pad4(raw: bytes) -> bytes:
    return raw + b"\0" * (-len(raw) % 4)


def utf16(text: str) -> bytes:
    require("\0" not in text, "Resource string contains NUL.")
    return text.encode("utf-16le") + b"\0\0"


def version_block(key: str, value: bytes = b"", children: tuple[bytes, ...] = (), *, text: bool = False) -> bytes:
    prefix = pad4(b"\0" * 6 + utf16(key))
    body = prefix + value
    for child in children:
        body = pad4(body) + child
    require(len(body) <= 65535, "Resource block is too large.")
    value_length = len(value) // 2 if text else len(value)
    return struct.pack("<HHH", len(body), value_length, int(text)) + body[6:]


def version_resource(version: str, source: str, *, setup: bool) -> bytes:
    major, minor, patch, revision = version_parts(version)
    require(COMMIT.fullmatch(source) is not None, "Source revision must be a lowercase full Git SHA.")
    flags = 2 if "-" in version else 0  # VS_FF_PRERELEASE
    fixed = struct.pack("<13I", 0xFEEF04BD, 0x00010000, (major << 16) | minor,
                        (patch << 16) | revision, (major << 16) | minor,
                        (patch << 16) | revision, 0x3F, flags, 0x00040004, 1, 0, 0, 0)
    description = "Tracebolt Windows Setup candidate" if setup else "Tracebolt Windows Agent candidate"
    original = "Tracebolt-Setup.exe" if setup else "tracebolt-windows-service.exe"
    values = {"CompanyName": "Tracebolt", "FileDescription": description,
              "FileVersion": version, "InternalName": original.removesuffix(".exe"),
              "OriginalFilename": original, "ProductName": "Tracebolt",
              "ProductVersion": version, "Comments": "Source revision: " + source}
    strings = tuple(version_block(k, utf16(v), text=True) for k, v in sorted(values.items()))
    string_table = version_block("040904B0", children=strings, text=True)
    string_info = version_block("StringFileInfo", children=(string_table,), text=True)
    translation = version_block("Translation", struct.pack("<HH", 0x0409, 1200))
    var_info = version_block("VarFileInfo", children=(translation,), text=True)
    return version_block("VS_VERSION_INFO", fixed, (string_info, var_info))


def application_manifest(version: str, arch: str, *, setup: bool) -> bytes:
    parts = version_parts(version)
    require(arch in MACHINES, "Unsupported architecture.")
    level = "requireAdministrator" if setup else "asInvoker"
    role = "Setup" if setup else "WindowsAgent"
    # No autoElevate, uiAccess, compatibility lies, or long-path opt-in. The
    # controller's stricter supported-path and Windows-version checks still apply.
    return (f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            f'<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">\n'
            f'  <assemblyIdentity type="win32" name="Tracebolt.{role}" version="{".".join(map(str, parts))}" processorArchitecture="{arch}"/>\n'
            f'  <description>Tracebolt {role} candidate</description>\n'
            f'  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3"><security><requestedPrivileges>'
            f'<requestedExecutionLevel level="{level}" uiAccess="false"/>'
            f'</requestedPrivileges></security></trustInfo>\n'
            f'  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1"><application>'
            f'<supportedOS Id="{{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}}"/>'
            f'</application></compatibility>\n'
            f'  <dependency><dependentAssembly><assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*"/></dependentAssembly></dependency>\n'
            f'</assembly>\n').encode("utf-8")


def resource_section(resources: dict[int, bytes]) -> tuple[bytes, list[int]]:
    """ID-only type/name=1/language=0x409 tree with image-relative data offsets."""
    require(0 < len(resources) <= 8 and all(0 < k < 65536 for k in resources), "Resource identifiers rejected.")
    kinds = sorted(resources)
    root_size = 16 + 8 * len(kinds)
    name_start = root_size
    language_start = name_start + 24 * len(kinds)
    entries_start = language_start + 24 * len(kinds)
    raw = bytearray(entries_start + 16 * len(kinds))

    def directory(offset: int, entries: list[tuple[int, int]]) -> None:
        struct.pack_into("<IIHHHH", raw, offset, 0, 0, 0, 0, 0, len(entries))
        for i, pair in enumerate(entries):
            struct.pack_into("<II", raw, offset + 16 + 8 * i, *pair)

    directory(0, [(kind, 0x80000000 | (name_start + 24 * i)) for i, kind in enumerate(kinds)])
    relocations = []
    for i, kind in enumerate(kinds):
        directory(name_start + 24 * i, [(1, 0x80000000 | (language_start + 24 * i))])
        directory(language_start + 24 * i, [(0x0409, entries_start + 16 * i)])
        raw.extend(b"\0" * (-len(raw) % 4))
        data_offset = len(raw)
        payload = resources[kind]
        require(0 < len(payload) < 65536, "Resource payload bounds rejected.")
        entry = entries_start + 16 * i
        struct.pack_into("<IIII", raw, entry, data_offset, len(payload), 0, 0)
        raw.extend(payload)
        relocations.append(entry)
    return bytes(raw), relocations


def coff_resources(version: str, source: str, arch: str, *, setup: bool) -> bytes:
    require(arch in MACHINES, "Unsupported architecture.")
    section, relocations = resource_section({16: version_resource(version, source, setup=setup),
                                             24: application_manifest(version, arch, setup=setup)})
    raw_offset = 60  # IMAGE_FILE_HEADER + one IMAGE_SECTION_HEADER
    relocation_offset = raw_offset + len(section)
    symbols_offset = relocation_offset + 10 * len(relocations)
    header = struct.pack("<HHIIIHH", MACHINES[arch], 1, 0, symbols_offset, 1, 0, 0)
    section_header = struct.pack("<8sIIIIIIHHI", b".rsrc\0\0\0", 0, 0, len(section), raw_offset,
                                 relocation_offset, 0, len(relocations), 0, 0x40300040)
    records = b"".join(struct.pack("<IIH", offset, 0, RELOCATIONS[arch]) for offset in relocations)
    symbol = struct.pack("<8sIhHBB", b".rsrc\0\0\0", 0, 1, 0, 3, 0)
    return header + section_header + section + records + symbol + struct.pack("<I", 4)


def inspect_pe(raw: bytes) -> dict:
    """Read only, bounded PE64 and its resources; never load or execute an image."""
    require(256 <= len(raw) <= 256 << 20 and raw[:2] == b"MZ", "PE image bounds/header rejected.")
    pe = struct.unpack_from("<I", raw, 0x3C)[0]
    require(0x40 <= pe <= len(raw) - 24 and raw[pe:pe + 4] == b"PE\0\0", "PE signature rejected.")
    machine, count, timestamp, _, _, optional_size, _ = struct.unpack_from("<HHIIIHH", raw, pe + 4)
    require(machine in MACHINES.values() and 1 <= count <= 96, "PE architecture or section count rejected.")
    optional = pe + 24
    require(optional_size >= 152 and optional + optional_size + count * 40 <= len(raw), "PE optional header bounds rejected.")
    require(struct.unpack_from("<H", raw, optional)[0] == 0x20B, "Only PE64 is supported.")
    subsystem = struct.unpack_from("<H", raw, optional + 68)[0]
    directory_count = struct.unpack_from("<I", raw, optional + 108)[0]
    require(5 <= directory_count <= (optional_size - 112) // 8, "PE data directories rejected.")
    resource_rva, resource_size = struct.unpack_from("<II", raw, optional + 112 + 2 * 8)
    certificate_offset, certificate_size = struct.unpack_from("<II", raw, optional + 112 + 4 * 8)
    sections = []
    for i in range(count):
        item = struct.unpack_from("<8sIIIIIIHHI", raw, optional + optional_size + 40 * i)
        _, virtual_size, virtual_address, size, offset, _, _, _, _, _ = item
        require(offset + size <= len(raw), "PE section extends past image.")
        sections.append((virtual_address, virtual_size, offset, size))

    def map_rva(rva: int, size: int) -> int:
        matches = []
        for address, _, offset, length in sections:
            if address <= rva and rva - address + size <= length:
                matches.append(offset + rva - address)
        require(len(matches) == 1, "PE resource RVA is missing or ambiguous.")
        return matches[0]

    require(16 <= resource_size <= 1 << 20, "PE resource directory bounds rejected.")
    base = map_rva(resource_rva, resource_size)
    end = base + resource_size
    resources = {}

    def directory(offset: int, depth: int, ids: tuple[int, ...]) -> None:
        require(depth <= 2 and 0 <= offset <= resource_size - 16, "PE resource nesting rejected.")
        at = base + offset
        _, _, _, _, named, count = struct.unpack_from("<IIHHHH", raw, at)
        require(named == 0 and 1 <= count <= 8 and at + 16 + 8 * count <= end, "PE resource identifiers rejected.")
        last = -1
        for i in range(count):
            identity, target = struct.unpack_from("<II", raw, at + 16 + i * 8)
            require(last < identity < 65536, "PE resource identifiers are not canonical.")
            last = identity
            path = ids + (identity,)
            if depth < 2:
                require(target & 0x80000000 != 0, "PE resource directory expected.")
                directory(target & 0x7FFFFFFF, depth + 1, path)
            else:
                require(not target & 0x80000000 and target <= resource_size - 16, "PE resource leaf expected.")
                rva, size, code_page, reserved = struct.unpack_from("<IIII", raw, base + target)
                require(0 < size < 65536 and code_page == 0 and reserved == 0, "PE resource leaf bounds rejected.")
                item = map_rva(rva, size)
                require(base <= item and item + size <= end, "PE resource data is outside resource section.")
                resources[path] = raw[item:item + size]
    directory(0, 0, ())
    return {"architecture": next(k for k, value in MACHINES.items() if value == machine),
            "timestamp": timestamp, "subsystem": subsystem,
            "certificateOffset": certificate_offset, "certificateSize": certificate_size,
            "resources": resources}


def verify_pe(raw: bytes, version: str, source: str, arch: str, *, setup: bool) -> dict:
    result = inspect_pe(raw)
    require(result["architecture"] == arch, "Built PE architecture mismatch.")
    require(result["timestamp"] == 0, "Built PE timestamp is not deterministic.")
    require(result["subsystem"] == (2 if setup else 3), "Built PE subsystem mismatch.")
    require(result["certificateOffset"] == result["certificateSize"] == 0, "Candidate must be explicitly unsigned.")
    require(result["resources"] == {(16, 1, 0x0409): version_resource(version, source, setup=setup),
                                    (24, 1, 0x0409): application_manifest(version, arch, setup=setup)},
            "Built PE UAC/version resources differ from the exact build contract.")
    # Parse the exact bytes too so malformed XML fails before artifact delivery.
    tree = ElementTree.fromstring(result["resources"][(24, 1, 0x0409)])
    level = tree.find(".//{urn:schemas-microsoft-com:asm.v3}requestedExecutionLevel")
    require(level is not None and level.attrib == {"level": "requireAdministrator" if setup else "asInvoker", "uiAccess": "false"}, "Built PE UAC level rejected.")
    return {"architecture": arch, "subsystem": "windows-gui" if setup else "windows-console", "uac": level.attrib["level"], "authenticode": "unsigned", "resourcesVerified": True}
