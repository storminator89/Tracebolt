"""Read-only, bounded provenance for the single inert CI test image.

These checks never load an image or establish installer/native acceptance.
Only the reviewed build and its source binding authorize the separate driver.
"""
import re
import struct

TAGS = "tracebolt_setup_rust,tracebolt_setup_gui_fixture,tracebolt_setup_gui_ci_fixture"
PROJECT_DEPENDENCIES = (
    "localrmm/internal/windowssetupui",
    "localrmm/internal/windowssetupui [localrmm/internal/windowssetupui.test]",
    "localrmm/internal/windowssetupui.test",
)
SYSTEM_DLLS = frozenset({
    "kernel32.dll", "msvcrt.dll", "ntdll.dll", "userenv.dll", "ws2_32.dll",
    "api-ms-win-core-synch-l1-2-0.dll", "bcryptprimitives.dll", "gdi32.dll",
    "user32.dll", "dbghelp.dll", "ucrtbase.dll",
})
MAX_IMAGE = 128 * 1024 * 1024
MAX_BUILD_INFO = 64 * 1024
_SOURCE = re.compile(r"[0-9a-f]{40}\Z")
_SETTING = re.compile(r"[A-Za-z0-9_.-]{1,64}\Z")


def _need(value):
    if not value:
        raise ValueError("provenance")


def inspect_pe(raw):
    """Inspect actual AMD64 console PE/import bytes; never invoke a loader."""
    _need(type(raw) is bytes and 512 <= len(raw) <= MAX_IMAGE and raw[:2] == b"MZ")

    def unpack(fmt, offset):
        size = struct.calcsize(fmt)
        _need(0 <= offset <= len(raw) - size)
        return struct.unpack_from(fmt, raw, offset)

    pe, = unpack("<I", 0x3C)
    _need(0x40 <= pe <= len(raw) - 24 and raw[pe:pe + 4] == b"PE\0\0")
    machine, count, stamp, _, _, opt_size, characteristics = unpack("<HHIIIHH", pe + 4)
    _need(machine == 0x8664 and stamp == 0 and 1 <= count <= 96
          and characteristics & 2 and not characteristics & 0x2000)
    optional = pe + 24
    headers_end = optional + opt_size + count * 40
    _need(224 <= opt_size <= 4096 and headers_end <= len(raw))
    _need(unpack("<H", optional)[0] == 0x20B and unpack("<H", optional + 68)[0] == 3)
    image_size, header_size = unpack("<II", optional + 56)
    _need(headers_end <= header_size <= len(raw) and header_size < image_size)
    directories, = unpack("<I", optional + 108)
    _need(14 <= directories <= 16 and 112 + directories * 8 <= opt_size)

    def directory(index):
        return unpack("<II", optional + 112 + index * 8)

    # Signature, bound imports and delay imports are not part of this static
    # test-image contract. Reject them rather than overlook another DLL list.
    _need(directory(4) == (0, 0) and directory(11) == (0, 0) and directory(13) == (0, 0))
    if directories > 14:
        _need(directory(14) == (0, 0))  # No managed executable/runtime route.
    sections, virtual_ranges, file_ranges = [], [], []
    for index in range(count):
        row = unpack("<8sIIIIIIHHI", optional + opt_size + index * 40)
        _, virtual_size, address, size, offset, _, _, _, _, _ = row
        span = max(virtual_size, size)
        _need(span > 0 and header_size <= address < address + span <= image_size)
        virtual_ranges.append((address, address + span))
        if size:
            _need(header_size <= offset < offset + size <= len(raw))
            file_ranges.append((offset, offset + size))
        sections.append((address, offset, size))
    for ranges in (virtual_ranges, file_ranges):
        ordered = sorted(ranges)
        _need(all(left[1] <= right[0] for left, right in zip(ordered, ordered[1:])))

    def map_rva(rva, size):
        _need(0 < size and 0 < rva <= 0xFFFFFFFF - size + 1)
        matches = [offset + rva - address for address, offset, length in sections
                   if address <= rva and rva - address + size <= length]
        _need(len(matches) == 1)
        return matches[0]

    def dll_name(rva):
        # The complete bounded NUL-terminated name must occupy one unique,
        # file-backed section; virtual zero-fill is not a valid import name.
        for length in range(1, 82):
            at = map_rva(rva, length)
            if raw[at + length - 1] == 0:
                name = raw[at:at + length - 1]
                _need(name and name.isascii())
                value = name.decode("ascii").lower()
                _need(value in SYSTEM_DLLS)
                return value
        raise ValueError("provenance")

    imports_rva, imports_size = directory(1)
    _need(40 <= imports_size <= 1024 * 1024)
    imports_at = map_rva(imports_rva, imports_size)
    imported = set()
    for index in range(33):  # At most 32 descriptors plus a mandatory terminator.
        _need((index + 1) * 20 <= imports_size)
        original, timestamp, forwarder, name_rva, first = unpack("<IIIII", imports_at + index * 20)
        if not (original or timestamp or forwarder or name_rva or first):
            _need(imported)
            return {"architecture": "amd64", "subsystem": "console", "timestamp": 0,
                    "authenticode": "unsigned", "imports": sorted(imported)}
        _need(index < 32 and timestamp == 0 and forwarder == 0 and first != 0)
        map_rva(first, 8)
        if original:
            map_rva(original, 8)
        imported.add(dll_name(name_rva))
    raise ValueError("provenance")


def inspect_go_build_info(raw, source):
    """Project finite settings from `go version -m`; never echo its image path."""
    _need(type(raw) is bytes and 0 < len(raw) <= MAX_BUILD_INFO
          and type(source) is str and _SOURCE.fullmatch(source) is not None)
    try:
        text = raw.decode("utf-8")
    except UnicodeError:
        raise ValueError("provenance") from None
    text = text.replace("\r\n", "\n")
    _need(text.endswith("\n") and "\r" not in text and "\0" not in text)
    lines = text[:-1].split("\n")
    _need(2 <= len(lines) <= 512 and 14 < len(lines[0]) <= 4096
          and lines[0].endswith(": go1.27.1")
          and all(ord(char) >= 32 for char in lines[0]))
    path, settings = None, {}
    for line in lines[1:]:
        _need(line.startswith("\t") and len(line) <= 8192
              and all(char == "\t" or 32 <= ord(char) < 127 for char in line))
        fields = line.split("\t")
        _need(len(fields) >= 3 and fields[0] == "")
        kind = fields[1]
        if kind == "path":
            _need(path is None and len(fields) == 3)
            path = fields[2]
        elif kind == "build":
            _need(len(fields) == 3 and "=" in fields[2])
            key, value = fields[2].split("=", 1)
            _need(_SETTING.fullmatch(key) is not None and key not in settings)
            settings[key] = value
        else:
            # Module/dependency rows are not a source-authority claim. The
            # builder independently checks the exact project dependency roots.
            _need(kind in {"mod", "dep", "=>"} and 3 <= len(fields) <= 5)
    _need(path == "localrmm/internal/windowssetupui.test")
    required = {"-tags": TAGS, "-trimpath": "true", "GOOS": "windows",
                "GOARCH": "amd64", "CGO_ENABLED": "1"}
    _need(all(settings.get(key) == value for key, value in required.items()))
    # Go deliberately omits ldflags with -trimpath (cmd/go/internal/load/pkg.go,
    # go.dev/issue/52372). Do not invent a source-binding claim from build info.
    # The reviewed source build, image hash and child's separate acknowledgement
    # must establish that binding; a plain tag match is not enough to launch.
    _need("-ldflags" not in settings)
    return {"goVersion": "go1.27.1", "path": path, "tags": TAGS.split(","),
            "goos": "windows", "goarch": "amd64", "cgo": True, "embeddedSourceProven": False}
