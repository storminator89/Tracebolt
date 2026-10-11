"""Windows-only OS adapter. No host calls occur at import time."""
from __future__ import annotations
import ctypes
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
from contract import Rejected, need, digest, read_regular, verify_artifact, synthetic_message, strict_json, no_links, canonical, write_new, trusted_path, check_time

SERVICE = "TraceboltWindowsAgent"
GRANTS = {
    "event-enable": ("event-content-enable", "selected-application-system-event-messages", True, "windows-selected-application-system-event-content-v1"),
    "event-disable": ("event-content-disable", None, False, "windows-selected-application-system-event-content-v1"),
    "updates-enable": ("updates-enable", "cached-windows-updates", True, "windows-cached-update-inspection-v1"),
    "updates-disable": ("updates-disable", None, False, "windows-cached-update-inspection-v1"),
}

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

def verify_target(t):
    need(ctypes.sizeof(ctypes.c_void_p) == 8 and os.name == "nt" and platform.machine().lower() in {"amd64", "x86_64"}, "target_mismatch")
    import winreg
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography", 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
        guid = winreg.QueryValueEx(key, "MachineGuid")[0]
    need(digest(guid.strip().lower().encode()) == t["machineIdSHA256"], "target_mismatch")
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
        product = winreg.QueryValueEx(key, "ProductName")[0]
        build = winreg.QueryValueEx(key, "CurrentBuildNumber")[0]
    need("Windows Server 2025" in product and build == t["osBuild"] and int(build) >= 26100, "target_mismatch")
    need(ctypes.windll.shell32.IsUserAnAdmin() != 0, "secure_handoff_required")
    # Visible interactive desktop is required; do not bypass UAC or a locked session.
    user = ctypes.WinDLL("user32", use_last_error=True)
    user.OpenInputDesktop.argtypes = [W.DWORD, W.BOOL, W.DWORD]; user.OpenInputDesktop.restype = W.HANDLE
    user.CloseDesktop.argtypes = [W.HANDLE]
    desktop = user.OpenInputDesktop(0, False, 0x100)
    need(desktop, "secure_handoff_required"); user.CloseDesktop(desktop)

def command(executable, args, expires, limit=64 << 10, expected_sha256=None):
    need(expected_sha256 is not None, "artifact_mismatch")
    trusted_path(executable)
    need(digest(read_regular(executable, 128 << 20)) == expected_sha256, "artifact_mismatch")
    remaining = min(45, check_time(expires))
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
        need(adv.ReportEventW(handle, 4, 0, e["eventId"], None, 1, 0, texts, None), "native_operation_failed")
    finally:
        adv.DeregisterEventSource(handle)

def bootstrap_bytes(raw, p):
    b = strict_json(raw, 64 << 10)
    need(type(b) is dict and set(b) == {"schemaVersion", "managerInstanceId", "profile", "enrollmentOrigin", "agentOrigin", "collectionProfile", "invitationId", "serverCaPem", "issuerRootPem", "issuerPem"}, "artifact_mismatch")
    t = p["tls"]
    need(b["schemaVersion"] == "tracebolt.enrollment-bootstrap.v2" and b["profile"] == "tls"
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

def endpoint_binding(p, plan_hash, snapshot):
    need(snapshot.get("state") == 1, "native_observation_unavailable")
    sid = snapshot.get("serviceSID")
    need(type(sid) is str and re.fullmatch(r"S-1-5-80(?:-[0-9]{1,10}){5}", sid), "native_observation_unavailable")
    _, data = layout(); root = data / "windows-agent"; enrollment = root / "enrollment"
    # Read only immutable public artifacts while the owned sender is stopped.
    # Never inspect ledger, private key, sender state, cookies or raw telemetry.
    raw = read_runtime_file(root / "bootstrap.json", 64 << 10, sid); bootstrap = bootstrap_bytes(raw, p)
    trusted_path(p["targets"]["windows"]["publicBootstrap"])
    supplied = read_regular(p["targets"]["windows"]["publicBootstrap"], 64 << 10)
    need(raw == supplied, "artifact_mismatch")
    cfg_raw = read_runtime_file(enrollment / "agent.json", 64 << 10, sid); cfg = strict_json(cfg_raw, 64 << 10)
    ready = strict_json(read_runtime_file(enrollment / "ready.json", 2048, sid), 2048)
    cert = read_runtime_file(enrollment / "agent-cert.pem", 32768, sid).decode("ascii")
    first = re.search(r"-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----", cert)
    need(first is not None, "native_observation_unavailable")
    certificate_hash = digest(ssl.PEM_cert_to_DER_cert(first.group()))
    need(ready.get("serverAuthenticated") is True and ready == {"version": "tracebolt.enrollment-ready.v2", "configHash": digest(cfg_raw), "certificateHash": certificate_hash, "serverAuthenticated": True}, "native_observation_unavailable")
    need(cfg.get("collectionProfile") == "windows-inventory-v1" and cfg.get("profile") == "tls"
         and cfg.get("managerOrigin") == p["tls"]["agentOrigin"] and not cfg.get("insecureHTTPAcknowledged")
         and re.fullmatch(r"agent_[a-f0-9]{32}", cfg.get("agentId", "")), "native_observation_unavailable")
    return {"schema": "tracebolt.windows-linux-native-parity.endpoint-binding.v1", "runId": p["runId"], "planSHA256": plan_hash,
            "source": p["source"], "windowsTargetId": p["targets"]["windows"]["id"], "windowsMachineIdSHA256": p["targets"]["windows"]["machineIdSHA256"],
            "setupSHA256": p["artifacts"]["setup"]["sha256"], "serviceSHA256": p["artifacts"]["service"]["sha256"], "deviceId": cfg["agentId"],
            "certificateHash": certificate_hash, "invitationIdSHA256": digest(bootstrap["invitationId"].encode()), "bootstrapSHA256": digest(supplied)}

def operate(p, phase, checks, plan_hash=None):
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
        print("SECURE HANDOFF: Use the real manager dashboard to create the Windows invitation and download its public bootstrap. In Setup, review TLS origins/fingerprints, five scopes and identity/service consent. Enter the invitation ONLY in Setup's hidden console, then independently approve the fingerprint in the real dashboard. No invitation or credential is read by this harness.", flush=True)
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
