"""Manual adapter for the harness's own child only. No SCM/trust/network APIs."""
import ctypes as C
import hashlib
import os
from pathlib import PureWindowsPath
import re
import subprocess
import threading
from rust_gui_contract import Failure, need, eventually, parse_font_probe, parse_fixture, drain_bounded

U32, I32, UPTR, IPTR, HANDLE = C.c_uint32, C.c_int32, C.c_size_t, C.c_ssize_t, C.c_void_p

class Rect(C.Structure):
    _fields_ = [(k, I32) for k in ("left", "top", "right", "bottom")]
class Point(C.Structure):
    _fields_ = [("x", I32), ("y", I32)]
class MonitorInfo(C.Structure):
    _fields_ = [("size", U32), ("monitor", Rect), ("work", Rect), ("flags", U32)]
class FileInfo(C.Structure):
    _fields_ = [(k, U32) for k in ("attributes", "creationLow", "creationHigh", "accessLow",
        "accessHigh", "writeLow", "writeHigh", "volume", "sizeHigh", "sizeLow", "links", "indexHigh", "indexLow")]
class UserObjectFlags(C.Structure):
    _fields_ = [("inherit", I32), ("reserved", I32), ("flags", U32)]

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

class Session:
    def __init__(self, image, digest, which):
        need(os.name == "nt" and C.sizeof(HANDLE) == 8, "platform")
        self.image, self.digest, self.which = image, digest, which
        self.handles, self.process, self.root = [], None, 0
        self.previous_dpi = None
        self.font_probes = 0
        self.buffers, self.threads, self.overflow = [bytearray(), bytearray()], [], [False, False]
        self.u = C.WinDLL("user32", use_last_error=True)
        self.k = C.WinDLL("kernel32", use_last_error=True)
        self.callback_type = C.WINFUNCTYPE(I32, HANDLE, IPTR)
        self._configure()

    def _configure(self):
        signatures = {
            "GetWindowThreadProcessId": ([HANDLE, C.POINTER(U32)], U32),
            "GetClassNameW": ([HANDLE, C.c_wchar_p, I32], I32),
            "EnumWindows": ([self.callback_type, IPTR], I32),
            "GetDlgItem": ([HANDLE, I32], HANDLE), "IsChild": ([HANDLE, HANDLE], I32),
            "GetDlgCtrlID": ([HANDLE], I32),
            "IsWindow": ([HANDLE], I32), "IsWindowEnabled": ([HANDLE], I32),
            "IsWindowVisible": ([HANDLE], I32),
            "GetWindow": ([HANDLE, U32], HANDLE),
            "GetWindowLongPtrW": ([HANDLE, I32], IPTR),
            "SendMessageTimeoutW": ([HANDLE, U32, UPTR, IPTR, U32, U32, C.POINTER(UPTR)], IPTR),
            "PostMessageW": ([HANDLE, U32, UPTR, IPTR], I32),
            "GetWindowRect": ([HANDLE, C.POINTER(Rect)], I32),
            "GetClientRect": ([HANDLE, C.POINTER(Rect)], I32),
            "ClientToScreen": ([HANDLE, C.POINTER(Point)], I32),
            "SetWindowPos": ([HANDLE, HANDLE, I32, I32, I32, I32, U32], I32),
            "GetDpiForWindow": ([HANDLE], U32),
            "SetThreadDpiAwarenessContext": ([HANDLE], HANDLE),
            "AdjustWindowRectExForDpi": ([C.POINTER(Rect), U32, I32, U32, U32], I32),
            "ShowWindowAsync": ([HANDLE, I32], I32), "IsZoomed": ([HANDLE], I32),
            "GetProcessWindowStation": ([], HANDLE),
            "GetUserObjectInformationW": ([HANDLE, I32, HANDLE, U32, C.POINTER(U32)], I32),
            "OpenInputDesktop": ([U32, I32, U32], HANDLE), "CloseDesktop": ([HANDLE], I32),
        }
        for name, (args, result) in signatures.items():
            f = getattr(self.u, name); f.argtypes, f.restype = args, result
        for name, args, result in [
            ("CreateFileW", [C.c_wchar_p, U32, U32, HANDLE, U32, U32, HANDLE], HANDLE),
            ("GetFileInformationByHandle", [HANDLE, C.POINTER(FileInfo)], I32),
            ("GetFileType", [HANDLE], U32), ("CloseHandle", [HANDLE], I32),
            ("ReadFile", [HANDLE, HANDLE, U32, C.POINTER(U32), HANDLE], I32),
            ("GetDriveTypeW", [C.c_wchar_p], U32),
        ]:
            f = getattr(self.k, name); f.argtypes, f.restype = args, result

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

    def __enter__(self):
        try:
            self.previous_dpi = self.u.SetThreadDpiAwarenessContext(C.c_void_p(-4))
            need(self.previous_dpi, "layout")
            flags, required = UserObjectFlags(), U32()
            station = self.u.GetProcessWindowStation()
            need(station and self.u.GetUserObjectInformationW(station, 1, C.byref(flags), C.sizeof(flags), C.byref(required))
                 and flags.flags & 1, "desktop")
            desktop = self.u.OpenInputDesktop(0, 0, 1)  # Read objects only; no desktop switch.
            need(desktop, "desktop")
            need(self.u.CloseDesktop(desktop) != 0, "desktop")
            self._lease_image()
            env = dict(os.environ)
            env.update(TRACEBOLT_RUST_GUI_FIXTURE_EXECUTE="synthetic-window-only-v1", TRACEBOLT_RUST_GUI_FIXTURE_CASE=self.which)
            self.process = subprocess.Popen(self._command(),
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, shell=False)
            for i, stream in enumerate((self.process.stdout, self.process.stderr)):
                def drain(index=i, source=stream):
                    try:
                        self.overflow[index] = drain_bounded(source, self.buffers[index])
                    except Exception:
                        self.overflow[index] = True
                thread = threading.Thread(target=drain, daemon=True)
                thread.start(); self.threads.append(thread)
            return self
        except Exception:
            self.__exit__(None, None, None)
            raise

    def _command(self):
        return [self.image, "-test.run=^TestRustNativeGUIFixture$", "-test.count=1", "-test.timeout=80s"]

    def __exit__(self, *_):
        settled = True
        try:
            if self.process is not None:
                try:
                    self._close_input()
                    if self.process.poll() is None:
                        # Retained own-child handle only, never a foreign PID or installer.
                        self.process.kill()
                    self.process.wait(timeout=5)
                except Exception:
                    settled = False
                for thread in self.threads:
                    try: thread.join(timeout=2)
                    except Exception: settled = False
                threads_done = not any(t.is_alive() for t in self.threads)
                settled = settled and threads_done
                if threads_done:
                    for stream in (self.process.stdout, self.process.stderr):
                        try: stream.close()
                        except Exception: settled = False
        finally:
            # Independent best-effort cleanup even if kill/wait/pipe handling throws.
            for h in reversed(self.handles):
                try: settled = bool(self.k.CloseHandle(h)) and settled
                except Exception: settled = False
            self.handles.clear()
            if self.previous_dpi is not None:
                try: settled = bool(self.u.SetThreadDpiAwarenessContext(self.previous_dpi)) and settled
                except Exception: settled = False
                self.previous_dpi = None
        need(settled, "cleanup")

    def _close_input(self):
        stream = getattr(self.process, "stdin", None)
        if stream is not None and not stream.closed:
            stream.close()  # EOF lets the child join its bounded, public-only font reader.

    def finish(self):
        self._close_input()
        try:
            need(self.process.wait(timeout=5) == 0, "fixture-report")
        except subprocess.TimeoutExpired:
            raise Failure("cleanup") from None
        for thread in self.threads:
            thread.join(timeout=2)
        need(not any(t.is_alive() for t in self.threads) and not any(self.overflow), "fixture-report")
        raw = bytes(self.buffers[0])
        value = parse_fixture(raw, self.which)
        need(value["fontProbeCount"] == self.font_probes, "fixture-report")
        return raw

    def _pid(self, hwnd):
        pid = U32(); self.u.GetWindowThreadProcessId(hwnd, C.byref(pid)); return pid.value

    def _class(self, hwnd):
        buf = C.create_unicode_buffer(256)
        need(self.u.GetClassNameW(hwnd, buf, len(buf)) > 0, "window-identity")
        return buf.value

    def _owned(self, hwnd, kind):
        need(hwnd and self.u.IsWindow(hwnd) and self.process is not None
             and self.process.poll() is None and self._pid(hwnd) == self.process.pid
             and self._class(hwnd).casefold() == kind.casefold(), "window-identity")
        return hwnd

    def _root(self):
        root = self._owned(self.root, "TraceboltRustFreshSetupWizard")
        need(self.u.IsWindowVisible(root) != 0, "window-identity")
        return root

    def _find(self, kind):
        need(self.process is not None and self.process.poll() is None, "window-identity")
        found, errors = [], []
        def visit(hwnd, _):
            try:
                need(self.process.poll() is None, "window-identity")
                if self._pid(hwnd) == self.process.pid and self._class(hwnd).casefold() == kind.casefold():
                    found.append(hwnd)
                return 1
            except Exception:
                errors.append(True)
                return 0
        callback = self.callback_type(visit)
        need(self.u.EnumWindows(callback, 0) != 0 and not errors and len(found) <= 1, "window-identity")
        return found[0] if found else 0

    def wait_root(self, budget):
        self.budget = budget
        def found():
            need(self.process.poll() is None, "window")
            self.root = self._find("TraceboltRustFreshSetupWizard")
            return bool(self.root and self.u.IsWindowVisible(self.root))
        eventually(found, budget, "window")

    def _control(self, identifier, owner=None, optional=False):
        parent = self._root() if owner is None else self._owned(owner, "#32770")
        h = self.u.GetDlgItem(parent, identifier)
        if not h and optional:
            return 0
        expected = "button" if identifier in {1, 2, 6, 7, 101, 102, 103, 104, 105, 106, 107, 108, 110, 111} else (
            "edit" if identifier in {201, 203, 204, 205, 206} else "static")
        self._owned(h, expected)
        need(self.u.IsChild(parent, h) != 0 and self.u.GetDlgCtrlID(h) == identifier, "control-identity")
        return h

    def _send(self, h, message, wp=0, lp=0):
        need(self.process is not None and self.process.poll() is None
             and self._pid(h) == self.process.pid and self.u.IsWindow(h), "window-identity")
        result = UPTR()
        need(self.u.SendMessageTimeoutW(h, message, wp, lp, 2, 1000, C.byref(result)) != 0, "message")
        return result.value

    def text(self, identifier):
        h = self._control(identifier)
        count = self._send(h, 0x000e)
        need(count <= 65536, "privacy")
        buf = C.create_unicode_buffer(count + 1)
        self._send(h, 0x000d, len(buf), C.addressof(buf))
        return buf.value

    def present(self, identifier):
        return bool(self._control(identifier, optional=True))
    def enabled(self, identifier):
        return bool(self.u.IsWindowEnabled(self._control(identifier)))
    def checked(self, identifier):
        return self._send(self._control(identifier), 0x00f0) == 1
    def click(self, identifier):
        h = self._control(identifier)
        need(self.u.IsWindowEnabled(h) != 0, "consent")
        if identifier == 103:
            # Uninstall opens a synchronous modal Go dialog. Queue the click so
            # the driver can inspect/default-No/cancel it without blocking.
            need(self.u.PostMessageW(h, 0x00f5, 0, 0) != 0, "message")
        else:
            self._send(h, 0x00f5)
    def repeat_submit(self):
        self._send(self._root(), 0x0111, 1)
    def close(self):
        self._send(self._root(), 0x0010)
    def root_alive(self):
        return bool(self._root())

    def _rect(self, h, client=False):
        r = Rect(); need((self.u.GetClientRect if client else self.u.GetWindowRect)(h, C.byref(r)) != 0, "layout"); return r

    def check_layout(self):
        root = self._root(); dpi = self.u.GetDpiForWindow(root)
        need(96 <= dpi <= 768, "layout")
        area = self._rect(root, True); origin = Point()
        need(self.u.ClientToScreen(root, C.byref(origin)) != 0, "layout")
        need(area.right >= (600 * dpi + 95) // 96 and area.bottom >= (440 * dpi + 95) // 96, "layout")
        style = self.u.GetWindowLongPtrW(root, -16)
        need(style & 0x00010000 and style & 0x00040000, "layout")
        ids = [1, 2, 201] + ([104, 105, 106, 107] if self.present(104) else [])
        for identifier in ids:
            h = self._control(identifier); rect = self._rect(h)
            need(origin.x <= rect.left < rect.right <= origin.x + area.right and origin.y <= rect.top < rect.bottom <= origin.y + area.bottom, "layout")
            need(self.u.IsWindowVisible(h) != 0, "layout")
        self._font_probe()

    def _font_probe(self):
        self.font_probes += 1
        need(self.font_probes <= 16 and self.process.poll() is None, "font")
        try:
            self.process.stdin.write(b"FONT_CHECK\n")
            self.process.stdin.flush()
        except Exception:
            raise Failure("font") from None
        def acknowledged():
            need(not any(self.overflow), "fixture-report")
            return parse_font_probe(bytes(self.buffers[0]), self.font_probes) is True
        eventually(acknowledged, self.budget, "font")

    def resize_client(self, width, height):
        root = self._root(); dpi = self.u.GetDpiForWindow(root)
        r = Rect(0, 0, (width * dpi + 95) // 96, (height * dpi + 95) // 96)
        need(self.u.AdjustWindowRectExForDpi(C.byref(r), self.u.GetWindowLongPtrW(root, -16) & 0xffffffff,
             0, self.u.GetWindowLongPtrW(root, -20) & 0xffffffff, dpi) != 0, "layout")
        before = self._rect(root)
        self._move(before.left, before.top, r.right-r.left, r.bottom-r.top)

    def _move(self, x, y, width, height):
        root = self._root()
        # Asynchronous cross-thread positioning avoids a synchronous WM_SIZE
        # wait on an unresponsive fixture thread. No desktop setting changes.
        need(self.u.SetWindowPos(root, None, x, y, width, height, 0x4000 | 0x0010 | 0x0004) != 0, "layout")
        def placed():
            r = self._rect(self._root())
            return (r.left, r.top, r.right-r.left, r.bottom-r.top) == (x, y, width, height)
        eventually(placed, self.budget, "layout")

    def exercise_geometry(self):
        root = self._root(); original = self._rect(root)
        self.resize_client(600, 440); self.check_layout()
        self._move(original.left, original.top, original.right-original.left, original.bottom-original.top)
        need(self.u.ShowWindowAsync(root, 3) != 0, "layout")
        eventually(lambda: self.u.IsZoomed(self._root()) != 0, self.budget, "layout")
        need(self.u.ShowWindowAsync(root, 9) != 0, "layout")
        eventually(lambda: self.u.IsZoomed(self._root()) == 0, self.budget, "layout")
        before = self._rect(root)
        for message in (0x001a, 0x007e):  # Messages to own window; no OS setting is changed.
            self._send(root, message)
            after = self._rect(root)
            need(bytes(after) == bytes(before), "layout")

    def dialog_present(self):
        dialog = self._find("#32770")
        if dialog:
            need(self.u.GetWindow(dialog, 4) == self._root(), "uninstall")
        return bool(dialog)
    def wait_dialog(self, budget):
        eventually(self.dialog_present, budget, "uninstall")
    def default_no(self):
        dialog = self._find("#32770")
        need(dialog and self.u.GetWindow(dialog, 4) == self._root(), "uninstall")
        return bool(self.u.GetWindowLongPtrW(self._control(7, dialog), -16) & 1)
    def dialog_click(self, identifier):
        need(identifier in {6, 7}, "uninstall")
        dialog = self._find("#32770")
        need(dialog and self.u.GetWindow(dialog, 4) == self._root(), "uninstall")
        self._send(self._control(identifier, dialog), 0x00f5)
