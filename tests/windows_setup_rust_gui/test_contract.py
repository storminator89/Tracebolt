"""Portable orchestration/negative tests, not Windows execution or UI proof."""
import ctypes
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
def source(name):
    spec = importlib.util.spec_from_file_location("rust_gui_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module
c = source("contract")
w = source("windows")

class Clock:
    now = 0
    def time(self): return self.now
    def sleep(self, seconds): self.now += seconds

class FakeUI:
    def __init__(self, which):
        self.which, self.page, self.dialog, self.alive = which, "input", False, True
        self.hooks, self.checks, self.events = 0, set(), []
        self.default, self.clear_back = True, True
        self.private_error, self.early_close, self.cancelled = False, False, False
        self.ids = {104, 105, 106, 107} | ({108} if which == "http" else {111} if which == "renewal" else set())
    def wait_root(self, budget): self.events.append("root")
    def text(self, identifier):
        if identifier == 201: return "INERT_GUI_FIXTURE_NO_HOST_ACTION"
        if self.page != "operation": return ""
        if self.which == "cancel" and not self.cancelled: return "INERT GUI fixture hook entered"
        terminal = "The operation did not complete" if self.which in {"failure", "cancel"} else "Service removal completed" if self.which in {"uninstall", "modal-resize"} else "Service start requested"
        return terminal + (" SYNTHETIC_PRIVATE_ERROR_MUST_NOT_REACH_VIEW" if self.private_error else "")
    def check_layout(self): self.events.append("layout-font")
    def exercise_geometry(self): self.events.append("geometry")
    def present(self, identifier):
        return (identifier == 104 and self.page == "review") or (identifier in {102, 103} and self.page == "input") or (identifier == 205 and self.page == "operation")
    def enabled(self, identifier): return self.page == "review" and self.ids <= self.checks
    def checked(self, identifier): return identifier in self.checks
    def click(self, identifier):
        self.events.append(identifier)
        if identifier == 103: self.dialog = True
        elif identifier == 101:
            self.page = "input"
            if self.clear_back: self.checks.clear()
        elif identifier == 1:
            if self.page == "input": self.page = "review"
            else:
                if not self.enabled(1): raise c.Failure("consent")
                self.page = "operation"; self.hooks += 1
        elif identifier == 2: self.alive = False
        else: self.checks.symmetric_difference_update({identifier})
    def repeat_submit(self): self.events.append("duplicate-queued")
    def close(self):
        if self.page == "operation" and not self.early_close: self.cancelled = True
        else: self.alive = False
    def root_alive(self): return self.alive
    def resize_client(self, width, height):
        self.events.append((width, height))
        if width == 40: self.cancelled = True
    def wait_dialog(self, budget):
        if not self.dialog: raise c.Failure("uninstall")
    def default_no(self): return self.default
    def dialog_present(self): return self.dialog
    def dialog_click(self, identifier):
        self.events.append(("dialog", identifier)); self.dialog = False
        if identifier == 6: self.page = "operation"; self.hooks += 1

def fixture_report(which, **updates):
    close = which == "close-input"
    value = {"schema": "tracebolt.rust-gui-inert-hook-result.v1", "case": which,
        "hook": "" if close else "uninstall" if which in {"uninstall", "modal-resize"} else "renewable-read-admin" if which == "renewal" else "read-admin",
        "hookCount": 0 if close else 1, "cancelled": which == "cancel",
        "cleanupJoined": not close, "exactHookSelection": True, "layoutAtHookAdmission": not close,
        "uiReturned": True, "installerHostActionsAttempted": False, "installerAcceptance": False,
        "fontProbeCount": 1, "fontProbesValid": True, "probeReaderJoined": True}
    value.update(updates)
    return b"RUST_GUI_FIXTURE_RESULT " + json.dumps(value).encode() + b"\nPASS\n"

class ContractTests(unittest.TestCase):
    def budget(self):
        clock = Clock(); return c.Deadline(2, clock.time, clock.sleep)
    def test_all_cases_use_only_bounded_synthetic_driver_protocol(self):
        for which in c.CASES:
            with self.subTest(which=which):
                ui = FakeUI(which); checks = c.drive(ui, which, self.budget())
                self.assertFalse(ui.alive)
                self.assertEqual(ui.hooks, 0 if which == "close-input" else 1)
                self.assertTrue(checks["nativeWindow"])
                c.parse_fixture(fixture_report(which), which)
    def test_back_cannot_reuse_consent(self):
        ui = FakeUI("tls"); ui.clear_back = False
        with self.assertRaisesRegex(c.Failure, "back"): c.drive(ui, "tls", self.budget())
        self.assertEqual(ui.hooks, 0)
    def test_default_yes_or_early_close_or_raw_error_cannot_pass(self):
        ui = FakeUI("uninstall"); ui.default = False
        with self.assertRaisesRegex(c.Failure, "uninstall"): c.drive(ui, ui.which, self.budget())
        ui = FakeUI("cancel"); ui.early_close = True
        with self.assertRaisesRegex(c.Failure, "cancel"): c.drive(ui, ui.which, self.budget())
        ui = FakeUI("failure"); ui.private_error = True
        with self.assertRaisesRegex(c.Failure, "privacy"): c.drive(ui, ui.which, self.budget())
    def test_duplicate_hooks_fake_acceptance_and_unknown_fields_are_rejected(self):
        for update in [{"hookCount": 2}, {"hookCount": True}, {"installerAcceptance": True},
                       {"installerHostActionsAttempted": True}, {"private": "invented-secret"}, {"uiReturned": False},
                       {"fontProbeCount": 17}, {"fontProbeCount": True}, {"probeReaderJoined": False}]:
            with self.subTest(update=update), self.assertRaises(c.Failure):
                c.parse_fixture(fixture_report("tls", **update), "tls")
        with self.assertRaises(c.Failure): c.parse_fixture(fixture_report("tls") * 2, "tls")
    def test_no_approval_wrong_platform_and_ci_are_inert(self):
        for platform, ack, env, stage in [("nt", False, {}, "approval"), ("posix", True, {}, "platform"), ("nt", True, {"ci": "false"}, "ci")]:
            with self.assertRaisesRegex(c.Failure, stage): c.authorization(platform, ack, "tls", "a"*40, "b"*64, env)
        with tempfile.TemporaryDirectory() as tmp:
            command = [sys.executable, "-I", "-B", str(HERE / "run.py"), "--image", str(Path(tmp)/"not-read.exe")]
            result = subprocess.run(command, cwd=tmp, capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 2)
            report = json.loads(result.stdout)
            self.assertEqual(report["stage"], "approval")
            self.assertFalse(any(report["coverage"].values()))
            self.assertEqual(list(Path(tmp).iterdir()), [])
    def test_deadline_is_a_failure_not_a_partial_pass(self):
        with self.assertRaisesRegex(c.Failure, "deadline"): c.eventually(lambda: False, self.budget(), "window")

    def test_invalid_cli_never_echoes_supplied_private_values(self):
        marker = 'invented-private-argument-value'
        result = subprocess.run([sys.executable,'-I','-B',str(HERE/'run.py'),'--unknown',marker],capture_output=True,timeout=5)
        self.assertEqual(result.returncode,2)
        self.assertNotIn(marker.encode(),result.stdout+result.stderr)
    def test_source_fixture_has_no_host_backend_import_and_requires_unique_build_tag(self):
        text = (HERE.parents[1] / "internal/windowssetupui/rust_gui_fixture_windows_test.go").read_text()
        self.assertIn("windows && cgo && tracebolt_setup_rust && tracebolt_setup_gui_fixture", text)
        for forbidden in ['"localrmm/internal/windowsservice"', '"localrmm/internal/windowspackage"', '"localrmm/internal/enrollmentclient"', '"net"', '"net/http"', '"os/exec"']:
            self.assertNotIn(forbidden, text)
        self.assertIn('"installerAcceptance"', text)
        self.assertIn('NewScanner(os.Stdin)', text)
        self.assertIn('GetObjectW', text)
        self.assertNotIn('GetObjectW', (HERE / 'windows.py').read_text())

    def test_font_probe_is_bounded_public_boolean_protocol_not_a_gdi_handle(self):
        row = b'RUST_GUI_FIXTURE_FONT {"ordinal":1,"matchesOriginal":true}\n'
        self.assertIs(c.parse_font_probe(row, 1), True)
        self.assertIsNone(c.parse_font_probe(row[:-1], 1))
        for raw in [row * 2, row.replace(b'true', b'false'), row.replace(b'"ordinal":1', b'"ordinal":true'),
                    row.replace(b'"matchesOriginal":true', b'"matchesOriginal":true,"handle":42')]:
            with self.assertRaises(c.Failure): c.parse_font_probe(raw, 1)

    def test_short_probe_drain_does_not_wait_for_4096_bytes_and_caps_overflow(self):
        class Stream:
            def __init__(self, chunks): self.chunks = iter(chunks)
            def read1(self, count): return next(self.chunks, b'')
            def read(self, count): raise AssertionError('full-buffer read can deadlock probe')
        buffer = bytearray()
        self.assertFalse(c.drain_bounded(Stream([b'probe\n']), buffer))
        self.assertEqual(buffer, b'probe\n')
        buffer = bytearray()
        self.assertTrue(c.drain_bounded(Stream([b'x' * 70000]), buffer))
        self.assertEqual(len(buffer), 65536)

    def test_unavailable_native_layout_case_is_not_exposed(self):
        self.assertNotIn('layout-cancel', c.CASES)
        with self.assertRaises(c.Failure): c.authorization('nt', True, 'layout-cancel', 'a'*40, 'b'*64, {})

class NativeAdapterSourceTests(unittest.TestCase):
    def test_64bit_windows_abi_is_explicit_even_on_linux(self):
        self.assertEqual(ctypes.sizeof(w.Rect), 16)
        self.assertEqual(ctypes.sizeof(w.MonitorInfo), 40)
        self.assertEqual(ctypes.sizeof(w.FileInfo), 52)
        self.assertEqual(ctypes.sizeof(w.UserObjectFlags), 12)
    def test_only_simple_fixed_local_image_paths_are_accepted(self):
        self.assertEqual(w.path_chain(r"C:\fixture\gui.test.exe"), ["C:\\", r"C:\fixture", r"C:\fixture\gui.test.exe"])
        for path in [r"\\server\share\a.exe", r"\\?\C:\a.exe", r"C:\a\..\b.exe", r"C:\a.exe:stream", r"C:\NUL.exe", r"C:\a.\b.exe", "C:/a.exe", r"C:\a.dll"]:
            with self.subTest(path=path), self.assertRaises(c.Failure): w.path_chain(path)
    def test_null_thread_dpi_is_distinct_and_refuses_before_child_start(self):
        calls = []
        session = object.__new__(w.Session)
        session.process, session.threads, session.handles, session.previous_dpi = None, [], [], None
        session.u = type("U", (), {"SetThreadDpiAwarenessContext": lambda self, context: calls.append("dpi")})()
        with patch.object(w.subprocess, "Popen") as launch:
            with self.assertRaisesRegex(c.Failure, "^thread-dpi$"):
                session.__enter__()
        launch.assert_not_called()
        self.assertEqual(calls, ["dpi"])
        self.assertIsNone(session.process)
        self.assertIsNone(session.previous_dpi)

    def test_foreign_pid_is_rejected_before_class_read_or_action(self):
        session = object.__new__(w.Session)
        session.process = type("Process", (), {"pid": 7, "poll": lambda self: None})()
        session.u = type("U", (), {"IsWindow": lambda self, h: 1})()
        session._pid = lambda h: 99
        session._class = lambda h: self.fail("foreign class must not be read")
        with self.assertRaisesRegex(c.Failure, "window-identity"): session._owned(123, "button")

    def lease_session(self, reparse=False):
        data = b"MZ" + b"x" * 510
        class Kernel:
            def __init__(self): self.calls, self.paths, self.reads = [], [], 0
            def GetDriveTypeW(self, path): return 3
            def CreateFileW(self, path, access, share, security, disposition, flags, template):
                self.calls.append((access, share, disposition, flags))
                self.paths.append(path)
                return len(self.paths)
            def GetFileInformationByHandle(self, handle, pointer):
                info = pointer._obj
                directory = handle < 3
                info.attributes = 0x10 if directory else 0x80
                if reparse and handle == 2: info.attributes |= 0x400
                info.links, info.sizeLow = 1, len(data)
                return 1
            def GetFileType(self, handle): return 1
            def ReadFile(self, handle, buffer, size, pointer, overlapped):
                self.reads += 1
                chunk = data if self.reads == 1 else b""
                ctypes.memmove(buffer, chunk, len(chunk))
                pointer._obj.value = len(chunk)
                return 1
        session = object.__new__(w.Session)
        session.image, session.digest = r"C:\fixture\gui.test.exe", hashlib.sha256(data).hexdigest()
        session.handles, session.k = [], Kernel()
        return session

    def test_image_lease_is_existing_read_only_and_hashes_the_held_handle(self):
        session = self.lease_session(); session._lease_image()
        self.assertEqual(len(session.handles), 3)
        self.assertTrue(all(share == 1 and disposition == 3 for _, share, disposition, _ in session.k.calls))
        self.assertEqual([x[0] for x in session.k.calls], [0x80, 0x80, 0x80000000])
        self.assertTrue(all(flags & 0x00200000 for _, _, _, flags in session.k.calls))
        self.assertEqual(session.k.reads, 2)

    def test_reparse_and_wrong_image_digest_refuse_without_launch(self):
        session = self.lease_session(True)
        with self.assertRaisesRegex(c.Failure, "image-lease"): session._lease_image()
        self.assertEqual(session.k.reads, 0)
        session = self.lease_session(); session.digest = "0" * 64
        with self.assertRaisesRegex(c.Failure, "image-digest"): session._lease_image()

    def test_uncertain_child_cleanup_never_blocks_on_live_pipe_close(self):
        class Pipe:
            def close(self): raise AssertionError("live pipe must not be synchronously closed")
        class Process:
            stdout, stderr = Pipe(), Pipe()
            killed = False
            def poll(self): return None
            def kill(self): self.killed = True
            def wait(self, timeout): raise subprocess.TimeoutExpired("fixture-only", timeout)
        class Thread:
            def join(self, timeout): pass
            def is_alive(self): return True
        session = object.__new__(w.Session)
        session.process, session.threads, session.handles, session.previous_dpi = Process(), [Thread()], [], None
        with self.assertRaisesRegex(c.Failure, "cleanup"): session.__exit__(None, None, None)
        self.assertTrue(session.process.killed)

    def test_kill_error_still_releases_all_handles_and_restores_thread_dpi(self):
        events = []
        class Pipe:
            def close(self): events.append('pipe-close')
        class Process:
            stdout, stderr = Pipe(), Pipe()
            def poll(self): return None
            def kill(self): raise OSError('invented-kill-error')
        session = object.__new__(w.Session)
        session.process, session.threads, session.handles, session.previous_dpi = Process(), [], [11, 12], 99
        session.k = type('K', (), {'CloseHandle': lambda self,h: events.append(('close',h)) or 1})()
        session.u = type('U', (), {'SetThreadDpiAwarenessContext': lambda self,h: events.append(('dpi',h)) or 1})()
        with self.assertRaisesRegex(c.Failure, 'cleanup'): session.__exit__(None,None,None)
        self.assertIn(('close',12),events);self.assertIn(('close',11),events);self.assertIn(('dpi',99),events)
        self.assertEqual(session.handles,[]);self.assertIsNone(session.previous_dpi)

    def test_parent_closes_probe_write_end_before_waiting_for_child(self):
        class Pipe:
            closed = False
            def close(self): self.closed = True
        pipe = Pipe()
        class Process:
            stdin = pipe
            def wait(self, timeout):
                if not pipe.closed: raise AssertionError('child probe reader still waiting for EOF')
                return 0
        session = object.__new__(w.Session)
        session.process,session.threads,session.overflow = Process(),[],[False,False]
        session.buffers,session.font_probes,session.which = [bytearray(fixture_report('tls')),bytearray()],1,'tls'
        self.assertEqual(session.finish(),fixture_report('tls'))

    def test_missing_probe_ack_is_a_bounded_failure(self):
        class Pipe:
            data = b''
            def write(self, data): self.data += data
            def flush(self): pass
        pipe=Pipe()
        session = object.__new__(w.Session)
        session.process=type('P',(),{'stdin':pipe,'poll':lambda self:None})()
        session.font_probes,session.buffers,session.overflow=0,[bytearray(),bytearray()],[False,False]
        clock=Clock();session.budget=c.Deadline(1,clock.time,clock.sleep)
        with self.assertRaisesRegex(c.Failure,'deadline'): session._font_probe()
        self.assertEqual(pipe.data,b'FONT_CHECK\n')

if __name__ == "__main__": unittest.main()
