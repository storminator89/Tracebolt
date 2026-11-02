"""Read-only CRT diagnostics, never admission or candidate execution.

Only the fixed 15-contract catalogue is projected. Unknowns discard all vectors.
Importing this module makes no native calls and starts no process.
"""
import ctypes as C
import hashlib
import os
from pathlib import Path, PureWindowsPath
import re
import subprocess
import threading

CATALOG = "mingw-ucrt-15-l1-1-0-v1"
FAMILIES = ("conio", "convert", "environment", "filesystem", "heap", "locale", "math", "multibyte",
            "private", "process", "runtime", "stdio", "string", "time", "utility")
CONTRACTS = tuple("api-ms-win-crt-" + family + "-l1-1-0" for family in FAMILIES)
NAMES = tuple(name + ".dll" for name in CONTRACTS)
MAX_OUTPUT = 8 * 1024 * 1024
BASELINE = frozenset({"kernel32.dll", "msvcrt.dll", "ntdll.dll", "userenv.dll", "ws2_32.dll",
    "api-ms-win-core-synch-l1-2-0.dll", "bcryptprimitives.dll", "gdi32.dll", "user32.dll", "dbghelp.dll", "ucrtbase.dll"})


def need(value, *_):
    if not value:
        raise ValueError("crt-evidence-unavailable")


def projection(required, available):
    for vector in (required, available):
        need(type(vector) is list and len(vector) == 15 and all(type(item) is bool for item in vector))
    need(any(required))
    return {"catalog": CATALOG, "status": "observed_read_only", "requiredCRT": required[:],
            "schemaPresent": available[:], "candidateExecuted": False, "admissionChanged": False}


def unavailable():
    return {"catalog": CATALOG, "status": "unavailable", "requiredCRT": None,
            "schemaPresent": None, "candidateExecuted": False, "admissionChanged": False}



def public_report(value):
    """Validate again at the log boundary; corruption never exports raw values."""
    try:
        need(type(value) is dict)
        if value == unavailable():
            return unavailable()
        base = projection(value["requiredCRT"], value["schemaPresent"])
        need(set(value) == set(base) | {"sourceCommit", "sourceTree", "sourceInputsSHA256", "imageSHA256", "imageSize"})
        need(all(value[key] == item for key, item in base.items()))
        for key, width in (("sourceCommit", 40), ("sourceTree", 40), ("sourceInputsSHA256", 64), ("imageSHA256", 64)):
            need(type(value[key]) is str and re.fullmatch("[0-9a-f]{" + str(width) + "}", value[key]) is not None)
        need(type(value["imageSize"]) is int and 512 <= value["imageSize"] <= 128 * 1024 * 1024)
        return {**base, **{key: value[key] for key in ("sourceCommit", "sourceTree", "sourceInputsSHA256", "imageSHA256", "imageSize")}}
    except Exception:
        return unavailable()


def inspect_objdump(raw, image):
    """Independent GNU-tool text only; never admit or export an arbitrary DLL."""
    need(type(raw) is bytes and 64 <= len(raw) <= MAX_OUTPUT and raw.endswith(b"\n") and b"\0" not in raw)
    text = raw.decode("ascii")
    rows = text.splitlines()
    need(len(rows) <= 150000 and all(len(row) <= 4096 for row in rows))
    content = [row for row in rows if row.strip()]
    need(content and content[0] == str(image) + ":     file format pei-x86-64")
    caption = "The Import Tables (interpreted .idata section contents)"
    need(rows.count(caption) == 1)
    position = rows.index(caption) + 1
    need(rows[position:position + 2] == [
        " vma:            Hint    Time      Forward  DLL       First",
        "                 Table   Stamp     Chain    Name      Thunk"])
    position += 2
    descriptor = re.compile(r"[ \t]+" + r"([0-9a-fA-F]{8})[ \t]+" * 5 + r"([0-9a-fA-F]{8})")
    dll = re.compile(r"[ \t]+DLL Name: ([A-Za-z0-9_.-]{1,80}\.dll)", flags=re.ASCII | re.IGNORECASE)
    names, previous = [], None
    while True:
        while position < len(rows) and not rows[position].strip():
            position += 1
        need(position < len(rows))
        match = descriptor.fullmatch(rows[position])
        need(match is not None)
        location, lookup, stamp, chain, name_rva, thunk = (int(item, 16) for item in match.groups())
        need(previous is None or location == previous + 20)
        previous, position = location, position + 1
        if not any((lookup, stamp, chain, name_rva, thunk)):
            break  # A complete, aligned zero descriptor is mandatory, not EOF/newline.
        need(lookup > 0 and name_rva > 0 and thunk > 0 and stamp == 0 and chain == 0 and len(names) < 32)
        while position < len(rows) and not rows[position].strip():
            position += 1
        need(position < len(rows))
        match = dll.fullmatch(rows[position])
        need(match is not None)
        name, position = match[1].lower(), position + 1
        need(name in BASELINE or name in NAMES)
        names.append(name)
        need(position < len(rows) and rows[position] == "\tvma:     Ordinal  Hint  Member-Name  Bound-To")
        position += 1
        while position < len(rows):
            row = rows[position]
            if descriptor.fullmatch(row):
                break
            # Function rows cannot impersonate the next aligned six-column descriptor.
            need(not row.strip() or re.fullmatch(r"\t[0-9a-fA-F]{8}[ \t]+[^\r\n]{1,512}", row) is not None)
            position += 1
    # No orphan, malformed or later DLL row may hide beyond the completed table.
    need(1 <= len(names) <= 32 and sum("DLL Name" in row for row in rows) == len(names))
    required = [name in names for name in NAMES]
    need(any(required))
    return required


def run_bounded(argv, cwd, env, *, limit=20):
    """Drain privately while running; retain only bounded bytes; own child only."""
    process, threads = None, []
    buffers, bad = [bytearray(), bytearray()], [False, False]
    settled, result = True, None
    try:
        process = subprocess.Popen(argv, cwd=cwd, env=env, shell=False, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        def drain(index, stream):
            try:
                while True:
                    chunk = stream.read(4096)
                    if not chunk:
                        break
                    if len(buffers[index]) + len(chunk) > MAX_OUTPUT:
                        bad[index] = True
                    else:
                        buffers[index].extend(chunk)
            except Exception:
                bad[index] = True
        for index, stream in enumerate((process.stdout, process.stderr)):
            thread = threading.Thread(target=drain, args=(index, stream), daemon=True)
            thread.start(); threads.append(thread)
        need(process.wait(timeout=limit) == 0)
        for thread in threads:
            thread.join(timeout=2)
        need(not any(thread.is_alive() for thread in threads) and not any(bad) and not buffers[1])
        result = bytes(buffers[0])
    finally:
        if process is not None:
            try:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=5)
            except Exception:
                settled = False
            for thread in threads:
                try: thread.join(timeout=2)
                except Exception: settled = False
            if any(thread.is_alive() for thread in threads):
                settled = False
            else:
                for stream in (process.stdout, process.stderr):
                    try: stream.close()
                    except Exception: settled = False
        need(settled)
    return result


U32, I32, HANDLE = C.c_uint32, C.c_int32, C.c_void_p

class FileInfo(C.Structure):
    _fields_ = [(k, U32) for k in ("attributes", "creationLow", "creationHigh", "accessLow",
        "accessHigh", "writeLow", "writeHigh", "volume", "sizeHigh", "sizeLow", "links", "indexHigh", "indexLow")]

def path_chain(value):
    need(type(value) is str and 4 <= len(value) <= 240 and "/" not in value and re.match(r"^[A-Za-z]:\\", value) is not None, "image-path")
    p = PureWindowsPath(value)
    need(p.is_absolute() and p.root == "\\" and len(p.parts) >= 2 and p.suffix.lower() == ".exe", "image-path")
    for part in p.parts[1:]:
        need(part not in {".", ".."} and not part.endswith((" ", "."))
             and not any(ord(c) < 32 or c in '<>:"/|?*' for c in part), "image-path")
        need(part.split(".", 1)[0].upper() not in {"CON", "PRN", "AUX", "NUL", *[f"COM{i}" for i in range(10)], *[f"LPT{i}" for i in range(10)]}, "image-path")
    need(value == str(p), "image-path")
    return [str(PureWindowsPath(*p.parts[:n])) for n in range(1, len(p.parts) + 1)]


class Native:
    """Kernel-only reader. No window/DPI/session/SCM/trust/network actions."""
    def __init__(self):
        need(os.name == "nt" and C.sizeof(HANDLE) == 8)
        # Explicit System32-only binding, never a candidate/import-derived name.
        self.k = C.WinDLL("kernel32.dll", use_last_error=True, winmode=0x800)
        signatures = [
            ("CreateFileW", [C.c_wchar_p, U32, U32, HANDLE, U32, U32, HANDLE], HANDLE),
            ("GetFileInformationByHandle", [HANDLE, C.POINTER(FileInfo)], I32),
            ("GetFileType", [HANDLE], U32), ("CloseHandle", [HANDLE], I32),
            ("ReadFile", [HANDLE, HANDLE, U32, C.POINTER(U32), HANDLE], I32),
            ("GetDriveTypeW", [C.c_wchar_p], U32),
        ]
        for name, args, result in signatures:
            function = getattr(self.k, name); function.argtypes, function.restype = args, result

    def schema(self):
        # Fixed documented system query API, never a PE-derived DLL or host guess.
        api = C.WinDLL("api-ms-win-core-apiquery-l2-1-0.dll", use_last_error=True, winmode=0x800)
        query = api.IsApiSetImplemented
        query.argtypes, query.restype = [C.c_char_p], I32
        values = []
        for name in CONTRACTS:  # No DLL suffix, input-derived name, alias or wildcard.
            result = query(name.encode("ascii"))
            need(type(result) is int and result in (0, 1))
            values.append(bool(result))
        return values

    def lease(self, image, digest):
        return Lease(self.k, str(image), digest)


class Lease:
    def __init__(self, kernel, image, digest):
        need(type(digest) is str and re.fullmatch(r"[0-9a-f]{64}", digest) is not None)
        self.k, self.image, self.digest, self.handles = kernel, image, digest, []

    def __enter__(self):
        try:
            self._lease_image()
            return self
        except Exception:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *_):
        settled = True
        for handle in reversed(self.handles):
            try: settled = bool(self.k.CloseHandle(handle)) and settled
            except Exception: settled = False
        self.handles.clear()
        need(settled)

    def _lease_image(self):
        chain = path_chain(self.image)
        need(self.k.GetDriveTypeW(chain[0]) == 3, "image-path")  # Existing fixed local disk only.
        for i, path in enumerate(chain):
            directory = i < len(chain) - 1
            # OPEN_EXISTING, read-only access and read sharing only. No creation,
            # ACL/owner change, privilege enable, fallback or delete-on-close.
            h = self.k.CreateFileW(path, 0x80 if directory else 0x80000000, 1, None, 3,
                                  0x00200000 | (0x02000000 if directory else 0), None)
            need(h not in (None, C.c_void_p(-1).value), "image-lease")
            self.handles.append(h)
            info = FileInfo()
            need(self.k.GetFileInformationByHandle(h, C.byref(info)) != 0
                 and self.k.GetFileType(h) == 1 and not info.attributes & 0x400
                 and bool(info.attributes & 0x10) == directory, "image-lease")
            if not directory:
                size = (info.sizeHigh << 32) | info.sizeLow
                need(512 <= size <= 128 * 1024 * 1024 and info.links == 1, "image-lease")
                hasher, total = hashlib.sha256(), 0
                while True:
                    buf, count = C.create_string_buffer(65536), U32()
                    need(self.k.ReadFile(h, buf, len(buf), C.byref(count), None) != 0, "image-lease")
                    if count.value == 0:
                        break
                    total += count.value
                    need(total <= size, "image-lease")
                    hasher.update(buf.raw[:count.value])
                need(total == size and hasher.hexdigest() == self.digest, "image-digest")
