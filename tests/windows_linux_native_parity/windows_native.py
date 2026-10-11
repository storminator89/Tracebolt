"""Windows-only OS adapter. No host calls occur at import time."""
from __future__ import annotations
import ctypes
import base64
from contextlib import contextmanager
import threading
from ctypes import wintypes as W
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import ssl
import time
import tempfile
from contract import Rejected, need, digest, read_regular, verify_artifact, synthetic_message, strict_json, no_links, canonical, write_new, trusted_path, check_time, require_current_setup_gate, is_current, CURRENT_PROFILE, private_directory

SERVICE = "TraceboltWindowsAgent"
GRANTS = {
    "event-enable": ("event-content-enable", "selected-application-system-event-messages", True, "windows-selected-application-system-event-content-v1"),
    "event-disable": ("event-content-disable", None, False, "windows-selected-application-system-event-content-v1"),
    "updates-enable": ("updates-enable", "cached-windows-updates", True, "windows-cached-update-inspection-v1"),
    "updates-disable": ("updates-disable", None, False, "windows-cached-update-inspection-v1"),
}

# Production WindowsReadAdminScopesV14 order, never a promotion of older receipts.
# Each row names the fixed sibling containing public consent, its production
# schema suffix and (where implemented) its existing nonmutating CLI preview.
CURRENT_GRANTS = (
    ("windows-application-system-event-headers-v1", "event-metadata", "event-metadata", "events"),
    ("windows-visible-volumes-v1", "visible-volumes", "volumes", "volumes"),
    ("windows-process-metrics-v1", "process-metrics", "process-metrics", "process-metrics"),
    ("windows-network-endpoints-v1", "network", "network", "network"),
    ("windows-service-startup-v1", "service-startup", "service-startup", "service-startup"),
    ("windows-complete-services-v1", "full-services", "complete-services", "full-services"),
    ("windows-complete-machine-software-v1", "full-software", "complete-machine-software", "full-software"),
    ("windows-adapter-context-v1", "adapter-context", "adapter-context", "adapter-context"),
    ("windows-patch-context-v1", "patch-context", "patch-context", "patch-context"),
    ("windows-security-posture-v1", "security-posture", "security-posture", "security-posture"),
    ("windows-session-context-v1", "session-context", "session-context", "session-context"),
    ("windows-hardware-context-v1", "hardware-context", "hardware-context", None),
    ("windows-storage-context-v1", "storage-context", "storage-context", None),
    ("windows-security-coverage-v1", "security-coverage", "security-coverage", None),
    ("windows-complete-processes-v1", "full-processes", "complete-processes", "full-processes"),
    ("windows-network-context-v1", "network-context", "network-context", "network-context"),
    ("windows-resource-context-v1", "resource-context", "resource-context", None),
    ("windows-storage-io-v1", "storage-io", "storage-io", None),
    ("windows-machine-software-history-v1", "full-software", "complete-machine-software", "software-history"),
    ("windows-application-system-event-history-v1", "event-history", "event-history", "event-history"),
)
CURRENT_SCOPES = ("windows-inventory-v1",) + tuple(row[0] for row in CURRENT_GRANTS)

def go_json(value):
    """Compact production JSON field order; only public bounded DTOs use this."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e").encode("utf-8")

def match_hex(value, size=64):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{%d}" % size, value) is not None

def libraries():
    need(os.name == "nt", "target_mismatch")
    return ctypes.WinDLL("advapi32", use_last_error=True), ctypes.WinDLL("kernel32", use_last_error=True)

@contextmanager
def target_lock():
    _, kernel = libraries()
    kernel.CreateMutexW.argtypes = [W.LPVOID, W.BOOL, W.LPCWSTR]; kernel.CreateMutexW.restype = W.HANDLE
    kernel.ReleaseMutex.argtypes = [W.HANDLE]; kernel.CloseHandle.argtypes = [W.HANDLE]
    handle = kernel.CreateMutexW(None, True, r"Global\TraceboltNativeParityHarness-v1")
    existed = ctypes.get_last_error() == 183
    if not handle or existed:
        if handle: kernel.CloseHandle(handle)
        raise Rejected("phase_replay")
    try:
        yield
    finally:
        kernel.ReleaseMutex(handle); kernel.CloseHandle(handle)

def current_sid():
    adv, kernel = libraries(); token = W.HANDLE()
    kernel.GetCurrentProcess.restype = W.HANDLE
    adv.OpenProcessToken.argtypes = [W.HANDLE, W.DWORD, ctypes.POINTER(W.HANDLE)]
    adv.GetTokenInformation.argtypes = [W.HANDLE, ctypes.c_int, W.LPVOID, W.DWORD, ctypes.POINTER(W.DWORD)]
    need(adv.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)), "private_path_rejected")
    try:
        size = W.DWORD(); adv.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
        need(0 < size.value <= 65536, "private_path_rejected")
        buf = ctypes.create_string_buffer(size.value)
        need(adv.GetTokenInformation(token, 1, buf, size, ctypes.byref(size)), "private_path_rejected")
        return sid_string(ctypes.cast(buf, ctypes.POINTER(W.LPVOID))[0])
    finally:
        kernel.CloseHandle(token)

def sid_string(sid):
    adv, kernel = libraries(); text = W.LPWSTR()
    adv.ConvertSidToStringSidW.argtypes = [W.LPVOID, ctypes.POINTER(W.LPWSTR)]
    kernel.LocalFree.argtypes = [W.LPVOID]
    need(adv.ConvertSidToStringSidW(sid, ctypes.byref(text)), "private_path_rejected")
    try:
        return text.value
    finally:
        kernel.LocalFree(text)

def acl_grant_safe(sid, mask, trusted, private=False, ancestor=False):
    if sid in trusted:
        return True
    if private:
        return False
    # Ancestors must not permit replacing this protected child via DELETE_CHILD,
    # ownership/DACL modification or generic write/all. Child creation alone in
    # ProgramData does not permit replacing an existing protected directory.
    unsafe = 0x10000000 | 0x40000000 | 0x40000 | 0x80000 | 0x10000 | 0x40
    if not ancestor:
        unsafe |= 0x2 | 0x4 | 0x10 | 0x100
    return mask & unsafe == 0

def require_private_acl(path):
    require_safe_acl(path, private=True)
    for parent in Path(path).parents:
        require_safe_acl(parent, ancestor=True)

def require_safe_acl(path, private=False, ancestor=False, trusted_sids=()):
    adv, kernel = libraries(); sd = W.LPVOID(); owner = W.LPVOID(); dacl = W.LPVOID()
    adv.GetNamedSecurityInfoW.argtypes = [W.LPWSTR, ctypes.c_int, W.DWORD, ctypes.POINTER(W.LPVOID), W.LPVOID, ctypes.POINTER(W.LPVOID), W.LPVOID, ctypes.POINTER(W.LPVOID)]
    adv.GetAce.argtypes = [W.LPVOID, W.DWORD, ctypes.POINTER(W.LPVOID)]
    kernel.LocalFree.argtypes = [W.LPVOID]
    need(adv.GetNamedSecurityInfoW(str(path), 1, 5, ctypes.byref(owner), None, ctypes.byref(dacl), None, ctypes.byref(sd)) == 0, "private_path_rejected")
    try:
        trusted = {current_sid(), "S-1-5-18", "S-1-5-32-544", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", *trusted_sids}
        need(owner and sid_string(owner) in trusted and dacl, "private_path_rejected")
        # ACL header: revision, reserved, ACL size, ACE count, reserved.
        count = ctypes.cast(dacl, ctypes.POINTER(ctypes.c_ushort))[2]
        need(1 <= count <= 64, "private_path_rejected")
        for i in range(count):
            ace = W.LPVOID(); need(adv.GetAce(dacl, i, ctypes.byref(ace)), "private_path_rejected")
            header = ctypes.string_at(ace, 4)
            need(header[0] in {0, 1}, "private_path_rejected")  # reject unfamiliar/object/callback ACEs
            if header[1] & 0x08 and not private:  # private parents also protect inherited child ACLs
                continue
            if header[0] == 0:
                mask = ctypes.cast(ace.value + 4, ctypes.POINTER(W.DWORD))[0]
                need(acl_grant_safe(sid_string(ace.value + 8), mask, trusted, private, ancestor), "private_path_rejected")
    finally:
        if sd:
            kernel.LocalFree(sd)

def windows_directory():
    _, kernel = libraries(); buf = ctypes.create_unicode_buffer(32768)
    kernel.GetWindowsDirectoryW.argtypes = [W.LPWSTR, W.UINT]
    n = kernel.GetWindowsDirectoryW(buf, len(buf)); need(0 < n < len(buf), "target_mismatch")
    return buf.value

def known_folder(guid):
    import uuid
    shell = ctypes.WinDLL("shell32", use_last_error=True); ole = ctypes.WinDLL("ole32")
    raw = (ctypes.c_ubyte * 16).from_buffer_copy(uuid.UUID(guid).bytes_le); out = W.LPWSTR()
    shell.SHGetKnownFolderPath.argtypes = [W.LPVOID, W.DWORD, W.HANDLE, ctypes.POINTER(W.LPWSTR)]
    ole.CoTaskMemFree.argtypes = [W.LPVOID]
    need(shell.SHGetKnownFolderPath(ctypes.byref(raw), 0, None, ctypes.byref(out)) == 0, "target_mismatch")
    try:
        return Path(out.value)
    finally:
        ole.CoTaskMemFree(out)

def layout():
    return (known_folder("905e63b6-c1bf-494e-b29c-65b732d3d21a") / "Tracebolt",
            known_folder("62ab5d82-fdc1-4dc3-a9dd-070d1d495d97") / "Tracebolt")

def native_os_version():
    # RtlGetVersion is not affected by an executable's compatibility manifest.
    class OSVERSIONINFOEXW(ctypes.Structure):
        _fields_ = [("size", W.DWORD), ("major", W.DWORD), ("minor", W.DWORD),
                    ("build", W.DWORD), ("platform", W.DWORD), ("servicePack", W.WCHAR * 128),
                    ("servicePackMajor", W.WORD), ("servicePackMinor", W.WORD),
                    ("suiteMask", W.WORD), ("productType", W.BYTE), ("reserved", W.BYTE)]
    version = OSVERSIONINFOEXW(); version.size = ctypes.sizeof(version)
    ntdll = ctypes.WinDLL("ntdll")
    ntdll.RtlGetVersion.argtypes = [ctypes.POINTER(OSVERSIONINFOEXW)]
    ntdll.RtlGetVersion.restype = W.LONG
    need(ntdll.RtlGetVersion(ctypes.byref(version)) == 0, "target_mismatch")
    return version.major, version.minor, version.build, version.productType

def validate_os_selection(target, observed):
    major, minor, build, product_type = observed
    need(type(build) is int and str(build) == target["osBuild"] and (major, minor) == (10, 0), "target_mismatch")
    selected = target.get("platform", "windows-server-2025-x64")
    if selected == "windows-11-x64":
        need(product_type == 1 and build >= 22000, "target_mismatch")
    elif selected == "windows-server-2025-x64":
        # Both Server and Domain Controller are server product types. A later
        # server release is not silently admitted under the Server 2025 label.
        need(product_type in {2, 3} and build == 26100, "target_mismatch")
    else:
        raise Rejected("target_mismatch")

def verify_target(t):
    need(ctypes.sizeof(ctypes.c_void_p) == 8 and os.name == "nt" and platform.machine().lower() in {"amd64", "x86_64"}, "target_mismatch")
    import winreg
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography", 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
        guid = winreg.QueryValueEx(key, "MachineGuid")[0]
    need(digest(guid.strip().lower().encode()) == t["machineIdSHA256"], "target_mismatch")
    validate_os_selection(t, native_os_version())
    need(ctypes.windll.shell32.IsUserAnAdmin() != 0, "secure_handoff_required")
    # Visible interactive desktop is required; do not bypass UAC or a locked session.
    user = ctypes.WinDLL("user32", use_last_error=True)
    user.OpenInputDesktop.argtypes = [W.DWORD, W.BOOL, W.DWORD]; user.OpenInputDesktop.restype = W.HANDLE
    user.CloseDesktop.argtypes = [W.HANDLE]
    desktop = user.OpenInputDesktop(0, False, 0x100)
    need(desktop, "secure_handoff_required"); user.CloseDesktop(desktop)

def command(executable, args, expires, limit=64 << 10, expected_sha256=None, preserve_process=False, observation_directory=None):
    need(expected_sha256 is not None, "artifact_mismatch")
    trusted_path(executable)
    need(digest(read_regular(executable, 128 << 20)) == expected_sha256, "artifact_mismatch")
    remaining = min(55 if preserve_process else 45, check_time(expires))
    if preserve_process:
        need(observation_directory is not None, "private_path_rejected")
        private_directory(observation_directory)
        # An inherited anonymous regular-file handle survives parent closure.
        # Never close a live child's output pipe, kill it, or wait indefinitely
        # on a synchronous native lifecycle call. No output enters evidence.
        with tempfile.TemporaryFile(mode="w+b", dir=observation_directory) as output:
            p = subprocess.Popen([str(executable), *args], stdin=subprocess.DEVNULL, stdout=output,
                                 stderr=subprocess.DEVNULL, env={"SystemRoot": windows_directory()}, shell=False)
            end = time.monotonic() + remaining
            try:
                while p.poll() is None:
                    check_time(expires)
                    need(time.monotonic() < end and os.fstat(output.fileno()).st_size <= limit, "native_observation_unavailable")
                    time.sleep(0.01)
                check_time(expires)
                need(p.returncode == 0, "native_operation_failed")
                need(os.fstat(output.fileno()).st_size <= limit, "native_observation_unavailable")
                output.seek(0); raw = output.read(limit + 1)
                need(len(raw) <= limit, "native_observation_unavailable")
            finally:
                if p.poll() is None:
                    print("SECURE HANDOFF: the owned lifecycle controller may still be active. Its process was not killed. Preserve state and inspect it manually; do not repeat the operation or infer rollback.", flush=True)
                    raise Rejected("secure_handoff_required")
        rows = [line for line in raw.splitlines() if line.startswith(b"{")]
        need(len(rows) == 1, "native_observation_unavailable")
        return strict_json(rows[0], limit)
    # Exact supported CLI, no shell. Never inherit ambient credentials or dump output.
    p = subprocess.Popen([str(executable), *args], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL, env={"SystemRoot": windows_directory()}, shell=False)
    # Python >=3.12 supports nonblocking Windows pipes: no unbounded
    # communicate buffer or blocked reader thread/inherited-handle join.
    collected = bytearray(); end = time.monotonic() + remaining; exited_at = None
    try:
        os.set_blocking(p.stdout.fileno(), False)
        while True:
            check_time(expires)
            need(time.monotonic() < end, "native_observation_unavailable")
            try:
                chunk = os.read(p.stdout.fileno(), min(4096, limit + 1 - len(collected)))
            except BlockingIOError:
                chunk = None
            if chunk:
                collected.extend(chunk)
                need(len(collected) <= limit, "native_observation_unavailable")
            if p.poll() is not None:
                exited_at = exited_at or time.monotonic()
                if chunk == b"": break
                need(time.monotonic() - exited_at < 1, "native_observation_unavailable")
            time.sleep(0.01)
        need(p.returncode == 0, "native_operation_failed")
        raw = bytes(collected)
    finally:
        if p.poll() is None:
            p.kill(); p.wait(timeout=10)
        p.stdout.close()
    rows = [line for line in raw.splitlines() if line.startswith(b"{")]
    need(len(rows) == 1, "native_observation_unavailable")
    return strict_json(rows[0], limit)

def inspect(exe, expires, expected_hash=None, expected_state=None, binary_hash=None):
    s = command(exe, ["--inspect"], expires, expected_sha256=expected_hash or binary_hash)
    need(type(s) is dict and type(s.get("exists")) is bool, "native_observation_unavailable")
    if expected_hash:
        need(s["exists"], "native_observation_unavailable")
        files, _ = layout(); installed = files / "tracebolt-windows-service.exe"
        need(digest(read_regular(installed, 128 << 20)) == expected_hash, "artifact_mismatch")
        cfg = s.get("configuration", {})
        need(cfg.get("name") == SERVICE and cfg.get("account") == r"NT AUTHORITY\LocalService"
             and cfg.get("binaryPath") == '"' + str(installed) + '" "--run-service"'
             and cfg.get("serviceType") == 16 and cfg.get("startType") == 2
             and cfg.get("sidType") == 1 and cfg.get("requiredPrivileges") == ["SeChangeNotifyPrivilege"], "native_observation_unavailable")
    if expected_state is not None:
        need(s.get("state") == expected_state, "native_observation_unavailable")
    return s

def wait_state(exe, expires, expected_hash, state):
    end = time.monotonic() + min(45, check_time(expires))
    while time.monotonic() < end:
        check_time(expires)
        s = inspect(exe, expires, expected_hash)
        if s.get("state") == state:
            return s
        time.sleep(0.5)
    raise Rejected("native_observation_unavailable")

def verify_package(p):
    a = p["artifacts"]
    setup = verify_artifact(a["setup"], 128 << 20); service = verify_artifact(a["service"], 128 << 20)
    manifest_raw = verify_artifact(a["setupManifest"], 2048)
    m = strict_json(manifest_raw, 2048)
    need(set(m) == {"schemaVersion", "version", "sourceCommit", "architecture", "sha256"}, "artifact_mismatch")
    need(m["schemaVersion"] == "tracebolt.windows-setup-package.v1" and m["sourceCommit"] == p["source"]["commit"] and m["architecture"] == "amd64" and m["sha256"] == a["service"]["sha256"], "artifact_mismatch")
    need(service in setup and manifest_raw in setup, "artifact_mismatch")
    inputs = strict_json(verify_artifact(a["setupSourceInputs"], 4 << 20), 4 << 20)
    source = Path(p["targets"]["windows"]["sourceRoot"])
    validate_setup_inputs(inputs, source)
    # Reuse the existing read-only PE verifier, not its native fixture runner.
    import importlib.util
    spec = importlib.util.spec_from_file_location("parity_pe", source / "deploy/windows-setup/pe_resources.py")
    pe = importlib.util.module_from_spec(spec); spec.loader.exec_module(pe)
    pe.verify_pe(setup, m["version"], m["sourceCommit"], "amd64", setup=True)
    pe.verify_pe(service, m["version"], m["sourceCommit"], "amd64", setup=False)

def validate_setup_inputs(document, source):
    need(type(document) is dict and set(document) == {"schemaVersion", "files"}
         and document["schemaVersion"] == "tracebolt.windows-setup-source-inputs.v1", "artifact_mismatch")
    import importlib.util
    spec = importlib.util.spec_from_file_location("parity_setup_build", source / "deploy/windows-setup/build-setup.py")
    build = importlib.util.module_from_spec(spec); spec.loader.exec_module(build)
    expected, _ = build.source_inputs(source)
    # Exact complete builder inventory, not a caller-selected matching subset.
    need(document["files"] == expected, "artifact_mismatch")

def verify_synthetic_format(resource, event_id, text, expires):
    check_time(expires)
    _, kernel = libraries()
    kernel.LoadLibraryExW.argtypes = [W.LPCWSTR, W.HANDLE, W.DWORD]; kernel.LoadLibraryExW.restype = W.HMODULE
    kernel.FreeLibrary.argtypes = [W.HMODULE]
    kernel.FormatMessageW.argtypes = [W.DWORD, W.LPVOID, W.DWORD, W.DWORD, W.LPWSTR, W.DWORD, W.LPVOID]
    module = kernel.LoadLibraryExW(resource, None, 0x22)  # data/image resource; never execute DLL entry code
    need(module, "native_observation_unavailable")
    try:
        insertion = ctypes.create_unicode_buffer(text)
        args = (ctypes.c_void_p * 1)(ctypes.cast(insertion, ctypes.c_void_p).value)
        output = ctypes.create_unicode_buffer(4096)
        count = kernel.FormatMessageW(0x2800, module, event_id, 0, output, len(output), ctypes.cast(args, W.LPVOID))
        need(0 < count < len(output) and output.value == text, "native_observation_unavailable")
        check_time(expires)
    finally:
        kernel.FreeLibrary(module)

def write_synthetic_event(p):
    import winreg
    e = p["syntheticEvent"]
    # Event-source registration is NOT performed here. Its exact source and
    # message-resource preparation need separate, explicit runtime permission.
    key_name = "SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\" + e["source"]
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_name, 0, winreg.KEY_READ) as key:
        resource = winreg.QueryValueEx(key, "EventMessageFile")[0]
        need(type(resource) is str and resource, "native_observation_unavailable")
        resource = resource.replace("%SystemRoot%", windows_directory())
        need(resource.casefold() == e["messageResourcePath"].casefold(), "artifact_mismatch")
        trusted_path(e["messageResourcePath"])
        need(digest(read_regular(e["messageResourcePath"], 32 << 20)) == e["messageResourceSHA256"], "artifact_mismatch")
    verify_synthetic_format(e["messageResourcePath"], e["eventId"], synthetic_message(p["runId"]), p["expiresUnix"])
    check_time(p["expiresUnix"])
    adv, _ = libraries()
    adv.RegisterEventSourceW.argtypes = [W.LPCWSTR, W.LPCWSTR]; adv.RegisterEventSourceW.restype = W.HANDLE
    adv.ReportEventW.argtypes = [W.HANDLE, W.WORD, W.WORD, W.DWORD, W.LPVOID, W.WORD, W.DWORD, ctypes.POINTER(W.LPCWSTR), W.LPVOID]
    adv.DeregisterEventSource.argtypes = [W.HANDLE]
    handle = adv.RegisterEventSourceW(None, e["source"])
    need(handle, "native_operation_failed")
    try:
        texts = (W.LPCWSTR * 1)(synthetic_message(p["runId"]))
        check_time(p["expiresUnix"])
        if is_current(p):
            need(p["historyQuery"]["startUnix"] <= time.time() < p["historyQuery"]["endUnix"], "deadline")
        need(adv.ReportEventW(handle, 4, 0, e["eventId"], None, 1, 0, texts, None), "native_operation_failed")
    finally:
        adv.DeregisterEventSource(handle)

def bootstrap_bytes(raw, p):
    b = strict_json(raw, 64 << 10)
    current = is_current(p)
    fields = {"schemaVersion", "managerInstanceId", "profile", "enrollmentOrigin", "agentOrigin", "collectionProfile", "invitationId", "serverCaPem", "issuerRootPem", "issuerPem"}
    if current:
        fields.add("renewalPolicy")
        need(p.get("currentProfile") == CURRENT_PROFILE, "artifact_mismatch")
    need(type(b) is dict and set(b) == fields, "artifact_mismatch")
    t = p["tls"]
    schema = "tracebolt.enrollment-bootstrap.renewable.v1" if current else "tracebolt.enrollment-bootstrap.v2"
    need(b["schemaVersion"] == schema and (not current or b["renewalPolicy"] == "same-key-v1") and b["profile"] == "tls"
         and b["collectionProfile"] == "windows-inventory-v1" and b["managerInstanceId"] == t["managerInstanceId"]
         and b["enrollmentOrigin"] == t["operatorOrigin"] and b["agentOrigin"] == t["agentOrigin"]
         and re.fullmatch(r"invite_[a-f0-9]{32}", b["invitationId"]), "artifact_mismatch")
    need(digest(b["serverCaPem"].encode()) == t["bootstrapServerCASHA256"]
         and digest(b["issuerRootPem"].encode()) == t["bootstrapIssuerRootSHA256"]
         and digest(ssl.PEM_cert_to_DER_cert(b["issuerPem"])) == t["issuerFingerprint"], "artifact_mismatch")
    return b

def read_runtime_file(path, bound, sid):
    trusted_path(path, trusted_sids=(sid,))
    return read_regular(path, bound)

def endpoint_binding(p, plan_hash, snapshot, allow_running=False, verify_live=True):
    need(snapshot.get("state") == 1 or allow_running and is_current(p) and snapshot.get("state") == 4, "native_observation_unavailable")
    sid = snapshot.get("serviceSID")
    need(type(sid) is str and re.fullmatch(r"S-1-5-80(?:-[0-9]{1,10}){5}", sid), "native_observation_unavailable")
    _, data = layout(); root = data / "windows-agent"; enrollment = root / "enrollment"
    # Read only immutable public artifacts while the owned sender is stopped.
    # Never inspect ledger, private key, sender state, cookies or raw telemetry.
    raw = read_runtime_file(root / "bootstrap.json", 64 << 10, sid); bootstrap = bootstrap_bytes(raw, p)
    bootstrap_raw = raw
    trusted_path(p["targets"]["windows"]["publicBootstrap"])
    supplied = read_regular(p["targets"]["windows"]["publicBootstrap"], 64 << 10)
    need(raw == supplied, "artifact_mismatch")
    cfg_raw = read_runtime_file(enrollment / "agent.json", 64 << 10, sid); cfg = strict_json(cfg_raw, 64 << 10)
    ready_raw = read_runtime_file(enrollment / "ready.json", 2048, sid); ready = strict_json(ready_raw, 2048)
    cert_raw = read_runtime_file(enrollment / "agent-cert.pem", 32768, sid); cert = cert_raw.decode("ascii")
    first = re.search(r"-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----", cert)
    need(first is not None, "native_observation_unavailable")
    certificate_hash = digest(ssl.PEM_cert_to_DER_cert(first.group()))
    need(ready.get("serverAuthenticated") is True and ready == {"version": "tracebolt.enrollment-ready.v2", "configHash": digest(cfg_raw), "certificateHash": certificate_hash, "serverAuthenticated": True}, "native_observation_unavailable")
    need(cfg.get("collectionProfile") == "windows-inventory-v1" and cfg.get("profile") == "tls"
         and cfg.get("managerOrigin") == p["tls"]["agentOrigin"] and not cfg.get("insecureHTTPAcknowledged")
         and re.fullmatch(r"agent_[a-f0-9]{32}", cfg.get("agentId", "")), "native_observation_unavailable")
    binding = {"schema": "tracebolt.windows-linux-native-parity.endpoint-binding.v1", "runId": p["runId"], "planSHA256": plan_hash,
            "source": p["source"], "windowsTargetId": p["targets"]["windows"]["id"], "windowsMachineIdSHA256": p["targets"]["windows"]["machineIdSHA256"],
            "setupSHA256": p["artifacts"]["setup"]["sha256"], "serviceSHA256": p["artifacts"]["service"]["sha256"], "deviceId": cfg["agentId"],
            "certificateHash": certificate_hash, "invitationIdSHA256": digest(bootstrap["invitationId"].encode()), "bootstrapSHA256": digest(supplied)}
    if is_current(p):
        binding.update(current_public_proof(p, snapshot, root, sid, cfg, certificate_hash, verify_live))
        binding.update(schema="tracebolt.windows-linux-native-parity.endpoint-binding.v2",
                       currentProfile=p["currentProfile"], windowsPlatform=p["targets"]["windows"]["platform"])
        immutable = {"bootstrap": bootstrap_raw, "config": cfg_raw, "ready": ready_raw, "certificate": cert_raw}
        binding["publicIdentitySHA256"] = digest(canonical({key: digest(value) for key, value in immutable.items()}))
        for name, old, bound in ((root / "bootstrap.json", bootstrap_raw, 64 << 10), (enrollment / "agent.json", cfg_raw, 64 << 10),
                                 (enrollment / "ready.json", ready_raw, 2048), (enrollment / "agent-cert.pem", cert_raw, 32768)):
            need(read_runtime_file(name, bound, sid) == old, "native_observation_unavailable")
    return binding

def current_consent():
    return {"schemaVersion": "tracebolt.windows-capability-consent.v14", "collectionProfile": "windows-inventory-v1",
            "scopes": list(CURRENT_SCOPES), "acknowledged": True, "insecureHTTPAcknowledged": False}

def expected_configuration(files, installation_id, executable_hash):
    return {"name": SERVICE, "displayName": "Tracebolt Windows Agent",
            "binaryPath": '"' + str(files / "tracebolt-windows-service.exe") + '" "--run-service"',
            "account": r"NT AUTHORITY\LocalService", "serviceType": 16, "startType": 2, "errorControl": 1,
            "sidType": 1, "requiredPrivileges": ["SeChangeNotifyPrivilege"], "dependencies": [], "loadOrderGroup": "",
            "delayedAutoStart": False, "failureActions": False, "triggers": False,
            "description": "Tracebolt Windows agent candidate; installation=" + installation_id + "; executable-sha256=" + executable_hash}

def validate_current_receipt(raw, p, snapshot, cfg, anchor_hash, files, data):
    """Validate exact completed receipt 12 and immutable anchor sender binding."""
    r = strict_json(raw, 64 << 10)
    need(type(r) is dict and set(r) == {"version", "service", "prepared", "readSetup"}
         and type(r["version"]) is int and r["version"] == 12 and r["prepared"] is True, "native_observation_unavailable")
    service = r["service"]
    need(type(service) is dict and set(service) == {"version", "installationID", "layout", "configurationSHA256", "executableSHA256", "serviceSID", "complete"}, "native_observation_unavailable")
    need(type(service["version"]) is int and service["version"] == 1 and service["complete"] is True
         and match_hex(service["installationID"], 32) and service["serviceSID"] == snapshot["serviceSID"]
         and service["executableSHA256"] == p["artifacts"]["service"]["sha256"], "native_observation_unavailable")
    root = data / "windows-agent"; enrollment = root / "enrollment"
    expected_layout = {"programFiles": str(files.parent), "programData": str(data.parent),
                       "executable": str(files / "tracebolt-windows-service.exe"), "stateRoot": str(root),
                       "enrollmentRoot": str(enrollment), "senderRoot": str(enrollment / "telemetry")}
    expected_cfg = expected_configuration(files, service["installationID"], service["executableSHA256"])
    need(service["layout"] == expected_layout and canonical(snapshot.get("configuration")) == canonical(expected_cfg)
         and service["configurationSHA256"] == digest(go_json(expected_cfg)), "native_observation_unavailable")
    progress = r["readSetup"]
    sender = digest(("tracebolt.sender-binding.windows.v1\nwindows-inventory-v1\ntls\n" + p["tls"]["agentOrigin"] + "\n" + anchor_hash + "\n" + cfg["agentId"]).encode())
    need(type(progress) is dict and set(progress) == {"consent", "phase", "senderBinding", "grants", "grantDigests"}
         and progress["phase"] == "configured" and progress["senderBinding"] == sender
         and canonical(progress["consent"]) == canonical(current_consent())
         and canonical(progress["grants"]) == canonical({"metadataScopeVerified": True, "appliedScopes": list(CURRENT_SCOPES[1:])}), "native_observation_unavailable")
    grants = progress["grantDigests"]
    need(type(grants) is list and len(grants) == 20, "native_observation_unavailable")
    for row, scope in zip(grants, CURRENT_SCOPES[1:]):
        need(type(row) is dict and set(row) == {"scope", "sha256"} and row["scope"] == scope and match_hex(row["sha256"]), "native_observation_unavailable")
    need(grants[6]["sha256"] == grants[18]["sha256"], "native_observation_unavailable")
    return {"senderBinding": sender, "receiptSHA256": digest(raw), "consentSHA256": digest(go_json(current_consent())),
            "scopes": list(CURRENT_SCOPES), "grantDigests": grants}

def validate_public_grant(raw, row, sender, expected_digest):
    scope, suffix, schema, _ = row
    c = strict_json(raw, 2048)
    fields = ["schemaVersion", "scope", "senderBinding", "grantId", "enabled"]
    if suffix in {"full-services", "full-software", "full-processes", "network-context"}:
        fields = fields[:4] + ["revision", "enabled", "changedAt"]
        if suffix == "full-software":
            fields.append("historyScope")
    elif suffix == "event-history":
        fields = fields[:4] + ["profile", "enabled", "historyAcknowledged", "contentAcknowledged", "httpPlaintextAcknowledged"]
    need(type(c) is dict and list(c) == fields and raw == go_json(c)
         and digest(raw) == expected_digest and c["senderBinding"] == sender and c["enabled"] is True
         and match_hex(c["grantId"], 32) and c["schemaVersion"] == "tracebolt.windows-" + schema + "-consent.v1", "native_observation_unavailable")
    base_scope = "windows-complete-machine-software-v1" if suffix == "full-software" else scope
    need(c["scope"] == base_scope, "native_observation_unavailable")
    if "revision" in c:
        need(type(c["revision"]) is int and 0 < c["revision"] <= (1 << 63) - 1
             and type(c["changedAt"]) is str and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z", c["changedAt"]), "native_observation_unavailable")
    if suffix == "full-software":
        need(c["historyScope"] == "windows-machine-software-history-v1", "native_observation_unavailable")
    if suffix == "event-history":
        need(c["profile"] == "tls" and c["historyAcknowledged"] is True and c["contentAcknowledged"] is True
             and c["httpPlaintextAcknowledged"] is False, "native_observation_unavailable")
    return {"scope": scope, "grantId": c["grantId"]}

def validate_current_manifest(raw, p, cfg, anchor_hash, now):
    m = strict_json(raw, 64 << 10)
    fields = {"version", "managerInstanceId", "enrollmentOrigin", "agentOrigin", "collectionProfile", "deviceId", "identityGeneration", "keyFingerprint", "anchorHash", "issuerFingerprint", "authorityExpiresAt", "credentialGeneration", "revision", "certificateDer", "anchorIntent", "intent", "lastServerNow"}
    need(type(m) is dict and set(m) == fields and m["version"] == "tracebolt.renewable-identity.v1"
         and m["managerInstanceId"] == p["tls"]["managerInstanceId"] and m["enrollmentOrigin"] == p["tls"]["operatorOrigin"]
         and m["agentOrigin"] == p["tls"]["agentOrigin"] and m["deviceId"] == cfg["agentId"]
         and m["collectionProfile"] == "windows-inventory-v1" and m["anchorHash"] == anchor_hash
         and m["issuerFingerprint"] == p["tls"]["issuerFingerprint"] and match_hex(m["keyFingerprint"])
         and type(m["identityGeneration"]) is str and re.fullmatch(r"identity_[0-9a-f]{32}", m["identityGeneration"]), "native_observation_unavailable")
    for key in ("credentialGeneration", "revision", "authorityExpiresAt", "lastServerNow"):
        need(type(m[key]) is int and 0 < m[key] <= (1 << 63) - 1, "native_observation_unavailable")
    need(m["lastServerNow"] <= now < m["authorityExpiresAt"], "native_observation_unavailable")
    anchor, current = m["anchorIntent"], m["intent"]
    intent_fields = {"managerInstanceId", "profile", "origin", "collectionProfile", "invitationId", "claimId", "requestId", "deviceId", "intentId", "keyFingerprint", "publicKeyDerBase64", "csrHash", "claimHash", "issuerFingerprint", "serialHex", "templateVersion", "keyGeneration", "notBefore", "notAfter"}
    need(type(anchor) is dict and type(current) is dict and set(anchor) == intent_fields and set(current) == intent_fields, "native_observation_unavailable")
    for key in ("managerInstanceId", "origin", "collectionProfile", "invitationId", "claimId", "deviceId", "keyFingerprint", "publicKeyDerBase64", "csrHash", "claimHash", "issuerFingerprint", "keyGeneration", "profile"):
        need(key in anchor and anchor[key] == current[key], "native_observation_unavailable")
    need(current["deviceId"] == cfg["agentId"] and current["keyFingerprint"] == m["keyFingerprint"]
         and current["profile"] == "tls" and current["managerInstanceId"] == m["managerInstanceId"]
         and current["origin"] == m["enrollmentOrigin"] and current["collectionProfile"] == m["collectionProfile"]
         and current["issuerFingerprint"] == m["issuerFingerprint"], "native_observation_unavailable")
    identity_fields = ["Tracebolt renewable identity generation v1", anchor["managerInstanceId"], anchor["invitationId"], anchor["claimId"], anchor["intentId"], anchor["deviceId"], anchor["keyFingerprint"]]
    need(all(type(value) is str for value in identity_fields), "native_observation_unavailable")
    transcript = b"".join(len(value.encode()).to_bytes(4, "big") + value.encode() for value in identity_fields)
    need(m["identityGeneration"] == "identity_" + digest(transcript)[:32], "native_observation_unavailable")
    need(type(current.get("notBefore")) is int and type(current.get("notAfter")) is int
         and current["notBefore"] <= now < current["notAfter"] <= m["authorityExpiresAt"], "native_observation_unavailable")
    try:
        der = base64.b64decode(m["certificateDer"], validate=True)
    except (ValueError, TypeError):
        raise Rejected("native_observation_unavailable") from None
    need(0 < len(der) <= 32768, "native_observation_unavailable")
    current_hash = digest(der)
    if m["credentialGeneration"] == 1:
        need(current == anchor and current_hash == anchor_hash, "native_observation_unavailable")
    else:
        need(current_hash != anchor_hash and current.get("intentId") != anchor.get("intentId")
             and current.get("serialHex") != anchor.get("serialHex") and current["notAfter"] > anchor.get("notAfter", 0), "native_observation_unavailable")
    # Cryptographic/current-leaf validation is additionally performed by the
    # production stopped-service preview; no private key is read by this harness.
    return {"identityGeneration": m["identityGeneration"], "credentialGeneration": m["credentialGeneration"],
            "credentialRevision": m["revision"], "currentCertificateHash": current_hash, "keyFingerprint": m["keyFingerprint"],
            "authorityExpiresUnix": m["authorityExpiresAt"], "currentCertificateExpiresUnix": current["notAfter"]}

def current_public_proof(p, snapshot, root, sid, cfg, anchor_hash, verify_live=True):
    files, data = layout(); enrollment = root / "enrollment"
    expected_cfg = {"collectionProfile": "windows-inventory-v1", "schemaVersion": "tracebolt.lan-agent.windows.v2",
                    "profile": "tls", "managerOrigin": p["tls"]["agentOrigin"], "agentId": cfg["agentId"],
                    "certificateFile": str(enrollment / "agent-cert.pem"), "privateKeyFile": str(enrollment / "agent-key.pem"),
                    "serverCAFile": str(enrollment / "server-ca.pem"), "stateDirectory": str(enrollment / "telemetry"),
                    "insecureHTTPAcknowledged": False, "renewalManifestFile": str(enrollment / "renewal-manifest.json")}
    need(cfg == expected_cfg, "native_observation_unavailable")
    paths = {}
    def public(path, bound, installer=False):
        if installer:
            trusted_path(path); raw = read_regular(path, bound)
        else:
            raw = read_runtime_file(path, bound, sid)
        paths[path] = (raw, bound, installer)
        return raw
    receipt_raw = public(Path(str(root) + "-installer") / "receipt.json", 64 << 10, installer=True)
    proof = validate_current_receipt(receipt_raw, p, snapshot, cfg, anchor_hash, files, data)
    proof["grantIds"] = []
    for row, expected in zip(CURRENT_GRANTS, proof["grantDigests"]):
        raw = public(Path(str(root) + "-" + row[1]) / "consent.json", 2048)
        proof["grantIds"].append(validate_public_grant(raw, row, proof["senderBinding"], expected["sha256"]))
    manifest_raw = public(enrollment / "renewal-manifest.json", 64 << 10)
    proof.update(validate_current_manifest(manifest_raw, p, cfg, anchor_hash, time.time()))
    proof["credentialManifestSHA256"] = digest(manifest_raw)
    if verify_live and snapshot["state"] == 1:
        installed = files / "tracebolt-windows-service.exe"
        for row in CURRENT_GRANTS:
            if row[3] is None:
                continue
            result = command(installed, ["--" + row[3] + "-preview"], p["expiresUnix"], expected_sha256=p["artifacts"]["service"]["sha256"])
            need(result == {"scope": row[0], "enabled": True, "existingStatePreserved": True}, "native_observation_unavailable")
        for preview, scope in (("event-content", "windows-selected-application-system-event-content-v1"), ("updates", "windows-cached-update-inspection-v1")):
            result = command(installed, ["--" + preview + "-preview"], p["expiresUnix"], expected_sha256=p["artifacts"]["service"]["sha256"])
            need(result == {"scope": scope, "enabled": False, "existingStatePreserved": True}, "native_observation_unavailable")
    # A renewal/grant/receipt race is a visible failure, never mixed evidence.
    for path, (raw, bound, installer) in paths.items():
        if installer:
            trusted_path(path); reread = read_regular(path, bound)
        else:
            reread = read_runtime_file(path, bound, sid)
        need(reread == raw, "native_observation_unavailable")
    return proof

def current_binding_file(p):
    return Path(p["targets"]["windows"]["workspace"]) / (p["runId"] + "-windows-binding.json")

def confirm_current_binding(p, plan_hash, snapshot, checks, verify_live=True):
    path = current_binding_file(p)
    trusted_path(path)
    original = strict_json(read_regular(path, 32 << 10), 32 << 10)
    binding = endpoint_binding(p, plan_hash, snapshot, allow_running=True, verify_live=verify_live)
    need(binding == original, "native_observation_unavailable")
    checks.update(endpoint_binding=True, current_receipt=True, current_grants=True, current_credential=True)
    return binding

def validate_restart_result(result):
    need(type(result) is dict and set(result) == {"outcome", "phase", "stopAttempted", "stopRequested", "stoppedObserved", "startAttempted", "startRequested", "runningObserved", "lastObservedState", "observations", "stateRetained"}, "native_observation_unavailable")
    need(result["outcome"] == "running-observed" and result["phase"] == "complete"
         and all(result[k] is True for k in ("stopAttempted", "stopRequested", "stoppedObserved", "startAttempted", "startRequested", "runningObserved", "stateRetained"))
         and type(result["lastObservedState"]) is int and result["lastObservedState"] == 4
         and type(result["observations"]) is int and 1 <= result["observations"] <= 184, "native_observation_unavailable")

def current_operate(p, phase, checks, plan_hash):
    require_current_setup_gate(p)
    need(phase in {"setup", "event-fixture", "own-restart", "remove"} and match_hex(plan_hash))
    if phase == "remove":
        # Set only by run.previous_phase after validating transferred exact
        # browser evidence. A path, operator assertion or hash alone is not proof.
        need(checks.get("browser_evidence_verified") is True, "browser_incomplete")
    expires = p["expiresUnix"]; expected_hash = p["artifacts"]["service"]["sha256"]
    files, data = layout(); installed = files / "tracebolt-windows-service.exe"
    if phase == "setup":
        need(not files.exists() and not data.exists(), "native_observation_unavailable")
        checks["native_actions_attempted"] = True
        need(not inspect(Path(p["artifacts"]["service"]["path"]), expires, binary_hash=expected_hash)["exists"], "native_observation_unavailable")
        checks["fresh_host"] = True
        bootstrap_path = p["targets"]["windows"]["publicBootstrap"]
        trusted_path(bootstrap_path); bootstrap_bytes(read_regular(bootstrap_path, 64 << 10), p)
        verify_artifact(p["artifacts"]["setup"], 128 << 20)
        print("SECURE HANDOFF: The human must launch this harness from an approved elevated interactive console and handle UAC personally. In real Setup select the exact approved public bootstrap, review Read admin's twenty-one scopes, separately acknowledge automatic same-key certificate renewal, persistent identity and service installation, and leave optional service control off. Enter the invitation only in Setup's hidden prompt; independently compare and approve the public identity in the real manager dashboard. This harness does not supply invitation secrets or approve trust.", flush=True)
        check_time(expires)
        proc = subprocess.Popen([p["artifacts"]["setup"]["path"]], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, env={"SystemRoot": windows_directory()}, shell=False)
        checks["setup_launched"] = True
        try:
            proc.wait(timeout=check_time(expires))
        except subprocess.TimeoutExpired:
            # A partially completed human handoff must never be killed or retried.
            raise Rejected("secure_handoff_required") from None
        need(proc.returncode == 0, "native_operation_failed")
        wait_state(installed, expires, expected_hash, 4)
        checks.update(installed_hash=True, scm_running=True)
        command(installed, ["--stop", "--apply"], expires, expected_sha256=expected_hash, preserve_process=True, observation_directory=p["targets"]["windows"]["workspace"])
        snapshot = wait_state(installed, expires, expected_hash, 1); checks["scm_stopped"] = True
        binding = endpoint_binding(p, plan_hash, snapshot)
        write_new(current_binding_file(p), binding)
        checks.update(endpoint_binding=True, current_receipt=True, current_grants=True, current_credential=True)
        print("PUBLIC ENDPOINT BINDING SHA256=" + digest(canonical(binding)), flush=True)
        print("SECURE HANDOFF: transfer only the generated public endpoint binding unchanged to the approved Linux private workspace and compare its digest. Consent/receipt proof is not provider coverage or a renewal-cycle result.", flush=True)
        command(installed, ["--start", "--apply"], expires, expected_sha256=expected_hash, preserve_process=True, observation_directory=p["targets"]["windows"]["workspace"])
        wait_state(installed, expires, expected_hash, 4)
        return
    checks["native_actions_attempted"] = True
    snapshot = inspect(installed, expires, expected_hash, 4)
    checks.update(installed_hash=True, scm_running=True)
    binding = confirm_current_binding(p, plan_hash, snapshot, checks)
    if phase == "event-fixture":
        need(p["historyQuery"]["startUnix"] <= time.time() < p["historyQuery"]["endUnix"], "deadline")
        write_synthetic_event(p); checks["synthetic_event_written"] = True
        return
    if phase == "own-restart":
        result = command(installed, ["--restart", "--apply"], expires, expected_sha256=expected_hash, preserve_process=True, observation_directory=p["targets"]["windows"]["workspace"])
        validate_restart_result(result)
        checks.update(scm_stopped=True, own_restart=True)
        after = inspect(installed, expires, expected_hash, 4)
        need(confirm_current_binding(p, plan_hash, after, checks) == binding, "native_observation_unavailable")
        checks["same_identity"] = True
        observed = {"schema": "tracebolt.windows-linux-native-parity.restart-binding.v1", "runId": p["runId"],
                    "planSHA256": plan_hash, "endpointBindingSHA256": digest(canonical(binding)),
                    "observedUnix": int(time.time()), "ownRestartObserved": True}
        check_time(expires)
        write_new(Path(p["targets"]["windows"]["workspace"]) / (p["runId"] + "-windows-restart.json"), observed)
        print("PUBLIC RESTART BINDING SHA256=" + digest(canonical(observed)), flush=True)
        print("SECURE HANDOFF: transfer the generated public restart binding unchanged to the approved Linux observer; compare its digest before observing a genuinely newer accepted sample.", flush=True)
        return
    command(installed, ["--stop", "--apply"], expires, expected_sha256=expected_hash, preserve_process=True, observation_directory=p["targets"]["windows"]["workspace"])
    stopped = wait_state(installed, expires, expected_hash, 1); checks["scm_stopped"] = True
    binding = confirm_current_binding(p, plan_hash, stopped, checks)
    result = command(installed, ["--uninstall", "--apply"], expires, expected_sha256=expected_hash, preserve_process=True, observation_directory=p["targets"]["windows"]["workspace"])
    need(type(result) is dict and set(result) == {"snapshot", "requested", "deletePending", "stateRetained"}
         and result["requested"] is True and result["deletePending"] is True and result["stateRetained"] is True
         and result["snapshot"] == stopped, "native_observation_unavailable")
    checks["receipt_owned_removal"] = True
    end = time.monotonic() + min(45, check_time(expires))
    while True:
        check_time(expires)
        need(time.monotonic() < end, "native_observation_unavailable")
        if not inspect(installed, expires, binary_hash=expected_hash)["exists"]:
            break
        time.sleep(0.5)
    checks["scm_absent"] = True
    need(confirm_current_binding(p, plan_hash, stopped, checks, verify_live=False) == binding, "native_observation_unavailable")
    # CLI deletion intentionally retains installed binary, enrollment, grants,
    # receipt and all used state. Only public files are inspected here; no claim
    # of byte-identical private counters, key erasure or full removal is made.
    need(digest(read_regular(installed, 128 << 20)) == expected_hash, "artifact_mismatch")
    checks["retained_state_preserved"] = True

def operate(p, phase, checks, plan_hash=None):
    if is_current(p):
        return current_operate(p, phase, checks, plan_hash)
    if phase == "setup":
        require_current_setup_gate()  # Before layout/SCM/installer access.
    expires = p["expiresUnix"]; artifact = Path(p["artifacts"]["service"]["path"])
    expected_hash = p["artifacts"]["service"]["sha256"]
    files, data = layout(); installed = files / "tracebolt-windows-service.exe"
    if phase == "setup":
        need(not files.exists() and not data.exists(), "native_observation_unavailable")
        checks["native_actions_attempted"] = True
        need(not inspect(artifact, expires, binary_hash=expected_hash)["exists"], "native_observation_unavailable")
        checks["fresh_host"] = True
        trusted_path(p["targets"]["windows"]["publicBootstrap"])
        bootstrap_bytes(read_regular(p["targets"]["windows"]["publicBootstrap"], 64 << 10), p)
        print("SECURE HANDOFF: Use the real manager dashboard to create the Windows invitation and download its public bootstrap. Historical five-scope Setup only: review TLS origins/fingerprints and separate scope, persistent identity and service consent. Current twelve-scope Read admin Setup is blocked pending a matching native gate; old consent cannot cover it. Enter the invitation ONLY in Setup's hidden console, then independently approve the fingerprint in the real dashboard. No invitation or credential is read by this harness.", flush=True)
        check_time(expires)
        proc = subprocess.Popen([p["artifacts"]["setup"]["path"]], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, env={"SystemRoot": windows_directory()}, shell=False)
        checks["setup_launched"] = True
        try:
            proc.wait(timeout=check_time(expires))
        except subprocess.TimeoutExpired:
            # Never kill an in-progress identity/install handoff to fake rollback.
            raise Rejected("secure_handoff_required") from None
        need(proc.returncode == 0, "native_operation_failed")
        wait_state(installed, expires, expected_hash, 4)
        checks.update(installed_hash=True, scm_running=True)
        command(installed, ["--stop", "--apply"], expires, expected_sha256=expected_hash)
        snapshot = wait_state(installed, expires, expected_hash, 1); checks["scm_stopped"] = True
        binding = endpoint_binding(p, plan_hash, snapshot)
        target = Path(p["targets"]["windows"]["workspace"]) / (p["runId"] + "-windows-binding.json")
        write_new(target, binding)
        print("PUBLIC ENDPOINT BINDING SHA256=" + digest(canonical(binding)), flush=True)
        print("SECURE HANDOFF: transfer only this tool-generated public identity binding unchanged to the approved Linux private workspace and compare its digest. This is identity correlation, not a manual acceptance report.", flush=True)
        checks["endpoint_binding"] = True
        command(installed, ["--start", "--apply"], expires, expected_sha256=expected_hash)
        wait_state(installed, expires, expected_hash, 4)
        return
    checks["native_actions_attempted"] = True
    inspect(installed, expires, expected_hash, 4)
    checks.update(installed_hash=True, scm_running=True)
    if phase == "event-fixture":
        write_synthetic_event(p); checks["synthetic_event_written"] = True
        return
    need(phase in GRANTS)
    mode, flag, enabled, scope = GRANTS[phase]
    if enabled:
        relative = "internal/windowseventrequest/request.go" if phase == "event-enable" else "internal/windowsupdates/contract.go"
        source = read_regular(Path(p["targets"]["windows"]["sourceRoot"]) / relative, 128 << 10).decode()
        disclosure = re.search(r'\bPrivacy\s*=\s*("[^"\n]+")', source)
        need(disclosure is not None, "source_mismatch")
        print(json.loads(disclosure.group(1)), flush=True)
    command(installed, ["--stop", "--apply"], expires, expected_sha256=expected_hash)
    snapshot = wait_state(installed, expires, expected_hash, 1); checks["scm_stopped"] = True
    if plan_hash is not None:
        binding = endpoint_binding(p, plan_hash, snapshot)
        original = strict_json(read_regular(Path(p["targets"]["windows"]["workspace"]) / (p["runId"] + "-windows-binding.json"), 8192), 8192)
        need(binding == original, "native_observation_unavailable"); checks["endpoint_binding"] = True
    before = {"event-enable": (False, False), "updates-enable": (True, False), "event-disable": (True, True), "updates-disable": (False, True)}[phase]
    scopes = ("windows-selected-application-system-event-content-v1", "windows-cached-update-inspection-v1")
    previews = ("event-content-preview", "updates-preview")
    for preview, expected, expected_scope in zip(previews, before, scopes):
        need(command(installed, ["--" + preview], expires, expected_sha256=expected_hash) == {"scope": expected_scope, "enabled": expected, "existingStatePreserved": True}, "native_observation_unavailable")
    args = ["--" + mode, "--apply"]
    if flag:
        args.append("--" + flag)
    # Every command below independently verifies the protected owned stopped
    # receipt. No sidecar edit, floor reset, service permission or WUA workaround.
    result = command(installed, args, expires, expected_sha256=expected_hash)
    need(result == {"scope": scope, "enabled": enabled, "existingStatePreserved": True}, "native_observation_unavailable")
    checks["grant_enabled" if enabled else "grant_disabled"] = True
    after = list(before); after[0 if phase.startswith("event-") else 1] = enabled
    for preview, expected, expected_scope in zip(previews, after, scopes):
        need(command(installed, ["--" + preview], expires, expected_sha256=expected_hash) == {"scope": expected_scope, "enabled": expected, "existingStatePreserved": True}, "native_observation_unavailable")
    checks["grant_independence"] = True
    command(installed, ["--start", "--apply"], expires, expected_sha256=expected_hash)
    wait_state(installed, expires, expected_hash, 4)
