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
# Inert PR201 test-image policy only. Observed on the hash-bound Windows2025
# build in run 41390825514; never a prefix rule or production installer policy.
EVIDENCED_CRT_DLLS = frozenset({
    "api-ms-win-crt-environment-l1-1-0.dll",
    "api-ms-win-crt-heap-l1-1-0.dll",
    "api-ms-win-crt-locale-l1-1-0.dll",
    "api-ms-win-crt-math-l1-1-0.dll",
    "api-ms-win-crt-private-l1-1-0.dll",
    "api-ms-win-crt-runtime-l1-1-0.dll",
    "api-ms-win-crt-stdio-l1-1-0.dll",
    "api-ms-win-crt-string-l1-1-0.dll",
})
ALLOWED_DLLS = SYSTEM_DLLS | EVIDENCED_CRT_DLLS
MAX_IMAGE = 128 * 1024 * 1024
MAX_BUILD_INFO = 64 * 1024
_SOURCE = re.compile(r"[0-9a-f]{40}\Z")
_SETTING = re.compile(r"[A-Za-z0-9_.-]{1,64}\Z")
PE_CHECKS = ("pe-headers", "pe-sections", "pe-import-directory", "pe-import-descriptors", "pe-import-name", "pe-import-allowlist",
    "pe-import-rejected-known-crt-contract", "pe-import-rejected-declared-system-link",
    "pe-import-rejected-compiler-runtime-shaped", "pe-import-rejected-api-set-shaped", "pe-import-rejected-other")
GO_INFO_CHECKS = ("go-info-input", "go-info-rows", "go-info-path", "go-info-required", "go-info-source-claim")


def _need(value):
    if not value:
        raise ValueError("provenance")


def inspect_pe(raw, checkpoint=None):
    """Inspect actual AMD64 console PE/import bytes; never invoke a loader."""
    if checkpoint is not None:
        checkpoint("pe-headers")
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
    if checkpoint is not None:
        checkpoint("pe-sections")
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
        if checkpoint is not None:
            checkpoint("pe-import-name")
        # The complete bounded NUL-terminated name must occupy one unique,
        # file-backed section; virtual zero-fill is not a valid import name.
        for length in range(1, 82):
            at = map_rva(rva, length)
            if raw[at + length - 1] == 0:
                name = raw[at:at + length - 1]
                _need(name and name.isascii())
                value = name.decode("ascii").lower()
                if checkpoint is not None:
                    checkpoint("pe-import-allowlist")
                    if value not in ALLOWED_DLLS:
                        # Diagnostic only. These public source-defined names or
                        # syntactic shapes do not attest availability/identity
                        # and never enter the admission set. Stop at this first
                        # rejected import; never export its name or a hash.
                        crt_families = ("conio", "convert", "environment", "filesystem", "heap", "locale", "math",
                            "multibyte", "private", "process", "runtime", "stdio", "string", "time", "utility")
                        if value in {"api-ms-win-crt-" + family + "-l1-1-0.dll" for family in crt_families}:
                            checkpoint("pe-import-rejected-known-crt-contract")
                        elif value in {"comdlg32.dll", "bcrypt.dll"}:
                            checkpoint("pe-import-rejected-declared-system-link")
                        elif value in {"libgcc_s_seh-1.dll", "libgcc_s_dw2-1.dll", "libgcc_s_sjlj-1.dll", "libwinpthread-1.dll",
                                       "libstdc++-6.dll", "libssp-0.dll", "libgomp-1.dll", "libatomic-1.dll"}:
                            checkpoint("pe-import-rejected-compiler-runtime-shaped")
                        elif re.fullmatch(r"(?:api|ext)-[a-z0-9-]{1,64}-l[0-9]+-[0-9]+-[0-9]+\.dll", value):
                            checkpoint("pe-import-rejected-api-set-shaped")
                        else:
                            checkpoint("pe-import-rejected-other")
                _need(value in ALLOWED_DLLS)
                return value
        raise ValueError("provenance")

    if checkpoint is not None:
        checkpoint("pe-import-directory")
    imports_rva, imports_size = directory(1)
    _need(40 <= imports_size <= 1024 * 1024)
    imports_at = map_rva(imports_rva, imports_size)
    imported = set()
    for index in range(33):  # At most 32 descriptors plus a mandatory terminator.
        if checkpoint is not None:
            checkpoint("pe-import-descriptors")
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


def inspect_go_build_info(raw, source, checkpoint=None):
    """Project finite settings from `go version -m`; never echo its image path."""
    if checkpoint is not None:
        checkpoint("go-info-input")
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
    if checkpoint is not None:
        checkpoint("go-info-rows")
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
    if checkpoint is not None:
        checkpoint("go-info-path")
    _need(path == "localrmm/internal/windowssetupui.test")
    required = {"-tags": TAGS, "-trimpath": "true", "GOOS": "windows",
                "GOARCH": "amd64", "CGO_ENABLED": "1"}
    if checkpoint is not None:
        checkpoint("go-info-required")
    _need(all(settings.get(key) == value for key, value in required.items()))
    # Go deliberately omits ldflags with -trimpath (cmd/go/internal/load/pkg.go,
    # go.dev/issue/52372). Do not invent a source-binding claim from build info.
    # The reviewed source build, image hash and child's separate acknowledgement
    # must establish that binding; a plain tag match is not enough to launch.
    if checkpoint is not None:
        checkpoint("go-info-source-claim")
    _need("-ldflags" not in settings)
    return {"goVersion": "go1.27.1", "path": path, "tags": TAGS.split(","),
            "goos": "windows", "goarch": "amd64", "cgo": True, "embeddedSourceProven": False}
