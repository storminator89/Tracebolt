"""Real production Linux manager/browser adapter; never creates TLS credentials."""
from __future__ import annotations
import ipaddress
from contextlib import contextmanager
import os
from pathlib import Path
import platform
import re
import socket
import ssl
import subprocess
import time
from urllib.parse import urlsplit
from contract import Rejected, need, read_regular, strict_json, digest, verify_artifact, verify_inventory, private_directory, no_links, canonical, trusted_path, check_time, exact, verify_executable_header

MARKERS = frozenset(("PARITY_BROWSER_BASELINE_OBSERVED", "PARITY_BROWSER_EVENT_ENABLE_READY", "PARITY_BROWSER_UPDATES_ENABLE_READY", "PARITY_BROWSER_EVENT_DISABLE_READY", "PARITY_BROWSER_UPDATES_DISABLE_READY", "PARITY_BROWSER_SECURE_LOGIN_HANDOFF", "PARITY_BROWSER_EVENT_REQUEST_HANDOFF"))

@contextmanager
def target_lock():
    # Kernel-local abstract UNIX name, no listener/network/credential or file.
    lock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        try:
            lock.bind("\0tracebolt-native-parity-harness-v1")
        except OSError:
            raise Rejected("phase_replay") from None
        yield
    finally:
        lock.close()

def verify_target(t):
    need(platform.system() == "Linux" and platform.machine() == "x86_64", "target_mismatch")
    machine = read_regular("/etc/machine-id", 256).decode("ascii").strip().lower()
    need(digest(machine.encode()) == t["machineIdSHA256"], "target_mismatch")
    need(platform.release() == t["osBuild"], "target_mismatch")
    need(os.geteuid() != 0, "target_mismatch")

def protected_file(path, secret=False):
    p = trusted_path(path, secret=secret)
    info = p.stat()
    need(info.st_nlink == 1 and 0 < info.st_size <= 32768, "private_path_rejected")
    if secret:
        # Only production reads keys/auth material. The harness checks metadata.
        need(p.is_file(), "private_path_rejected")
        return None
    return read_regular(p, 32768)

def resolve_private(hostname, port, expires):
    # libc DNS may outlive socket timeouts. Bound preflight without launching a
    # helper process; the daemon can only resolve, never mutate or start a host.
    import queue
    import threading
    result = queue.Queue(maxsize=1)
    def lookup():
        try:
            rows = socket.getaddrinfo(hostname, port, socket.AF_INET, socket.SOCK_STREAM)
            result.put((True, {r[4][0] for r in rows}))
        except Exception:
            result.put((False, None))
    timeout = min(5, check_time(expires))
    threading.Thread(target=lookup, daemon=True).start()
    try:
        ok, addresses = result.get(timeout=timeout)
    except queue.Empty:
        raise Rejected("native_observation_unavailable") from None
    check_time(expires)
    need(ok, "native_observation_unavailable")
    return addresses

def check_listener(value, expected_origin, expires):
    need(type(value) is str and value.count(":") == 1)
    host, port = value.rsplit(":", 1)
    try:
        address = ipaddress.IPv4Address(host)
        need(address.is_private and not address.is_loopback and not address.is_unspecified and not address.is_link_local)
        u = urlsplit(expected_origin); need(int(port) == u.port)
        resolved = resolve_private(u.hostname, u.port, expires)
        need(resolved == {host})  # no public relay, DNS ambiguity, or implicit network expansion
    except (ValueError, OSError):
        raise Rejected("contract_rejected") from None

def verify_config(p):
    t = p["targets"]["linux"]
    c = strict_json(protected_file(t["lanConfig"]), 16384)
    need(set(c) == {"schemaVersion", "profile", "windowsInventoryEnabled", "operatorListen", "agentListen", "operatorOrigin", "agentOrigin", "tlsCertificateFile", "tlsPrivateKeyFile", "agentClientCAFile", "operatorAuthFile", "stateDirectory", "webDirectory"})
    need(c["schemaVersion"] == "tracebolt.lan-config.v1" and c["profile"] == "tls" and c["windowsInventoryEnabled"] is True)
    need(c["operatorOrigin"] == p["tls"]["operatorOrigin"] and c["agentOrigin"] == p["tls"]["agentOrigin"] and c["webDirectory"] == t["webRoot"])
    check_listener(c["operatorListen"], c["operatorOrigin"], p["expiresUnix"]); check_listener(c["agentListen"], c["agentOrigin"], p["expiresUnix"])
    certificate = protected_file(c["tlsCertificateFile"])
    need(digest(certificate) == p["tls"]["serverCertificateSHA256"], "artifact_mismatch")
    # Production performs its complete key, certificate, role and custody checks.
    # We verify private-file boundaries without decoding or copying secrets.
    for key in ("tlsPrivateKeyFile", "operatorAuthFile"):
        protected_file(c[key], secret=True)
    protected_file(c["agentClientCAFile"])
    state = private_directory(c["stateDirectory"])
    workspace = private_directory(t["workspace"])
    need(state != workspace and not list(state.iterdir()), "native_observation_unavailable")
    e = strict_json(protected_file(t["enrollmentConfig"]), 16384)
    need(set(e) <= {"schemaVersion", "profile", "collectionProfile", "instanceId", "issuerCertificateFile", "issuerPrivateKeyFile", "issuerRootFile", "expectedIssuerFingerprint", "bootstrapServerCAFile"})
    need(e.get("schemaVersion") == "tracebolt.enrollment-config.v2" and e.get("profile") == "tls")
    need(e.get("collectionProfile", "basic-readonly-v1") in {"basic-readonly-v1", "managed-operations-v3"})
    for key in ("issuerCertificateFile", "issuerRootFile", "bootstrapServerCAFile"):
        protected_file(e[key])
    protected_file(e["issuerPrivateKeyFile"], secret=True)
    need(e["instanceId"] == p["tls"]["managerInstanceId"] and e["expectedIssuerFingerprint"] == p["tls"]["issuerFingerprint"])
    need(digest(protected_file(e["bootstrapServerCAFile"])) == p["tls"]["bootstrapServerCASHA256"]
         and digest(protected_file(e["issuerRootFile"])) == p["tls"]["bootstrapIssuerRootSHA256"])
    return c

def stop_owned(proc, grace=45):
    if proc is None:
        return True
    if proc.poll() is not None:
        proc.wait(timeout=1)
        return proc.returncode >= 0
    # Browser handler closes via pinned Playwright's supported 30-second
    # close-or-kill path. Never infer detached Chromium cleanup from Node exit.
    proc.terminate()
    try:
        proc.wait(timeout=grace)
        return proc.returncode >= 0
    except subprocess.TimeoutExpired:
        proc.kill(); proc.wait(timeout=10)
        return False  # manual cleanup needed; no native acceptance inference

def await_tls(manager, p, config):
    u = urlsplit(p["tls"]["operatorOrigin"])
    # Existing machine trust only. No custom CA import, ignore-errors or HTTP.
    context = ssl.create_default_context()
    pem = protected_file(config["tlsCertificateFile"]).decode("ascii")
    leaf = re.search(r"-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----", pem)
    need(leaf is not None, "artifact_mismatch")
    expected_leaf = ssl.PEM_cert_to_DER_cert(leaf.group())
    deadline = time.monotonic() + min(45, check_time(p["expiresUnix"]))
    while time.monotonic() < deadline:
        check_time(p["expiresUnix"])
        need(manager.poll() is None, "manager_exited")
        try:
            with socket.create_connection((config["operatorListen"].rsplit(":", 1)[0], u.port), timeout=min(2, check_time(p["expiresUnix"]))) as sock:
                with context.wrap_socket(sock, server_hostname=u.hostname) as tls:
                    need(tls.version() in {"TLSv1.2", "TLSv1.3"})
                    need(tls.getpeercert(binary_form=True) == expected_leaf, "artifact_mismatch")
                    need(manager.poll() is None, "manager_exited")
                    return
        except ssl.SSLCertVerificationError:
            raise Rejected("secure_handoff_required") from None
        except OSError:
            time.sleep(0.5)
    raise Rejected("native_observation_unavailable")

def browser_spec(p, plan_hash):
    t = p["targets"]["linux"]
    output = str(Path(t["workspace"]) / (p["runId"] + "-browser.json"))
    return {"schema": "tracebolt.windows-linux-native-parity.browser.v1", "runId": p["runId"], "planSHA256": plan_hash,
                "source": p["source"], "expiresUnix": p["expiresUnix"], "operatorOrigin": p["tls"]["operatorOrigin"],
                "chromium": p["artifacts"]["chromium"], "browserRoot": t["browserRoot"],
                "syntheticEvent": {k: p["syntheticEvent"][k] for k in ("source", "eventId", "messageSHA256")},
                "outputPath": output, "workspace": t["workspace"],
                **{k: p["tls"][k] for k in ("agentOrigin", "managerInstanceId", "issuerFingerprint", "bootstrapServerCASHA256", "bootstrapIssuerRootSHA256")},
                "windowsBindingPath": str(Path(t["workspace"]) / (p["runId"] + "-windows-binding.json")),
                "windowsTargetId": p["targets"]["windows"]["id"], "windowsMachineIdSHA256": p["targets"]["windows"]["machineIdSHA256"],
                "setupSHA256": p["artifacts"]["setup"]["sha256"], "serviceSHA256": p["artifacts"]["service"]["sha256"]}

BROWSER_CHECKS = {"publicBootstrapSaved", "endpointBindingObserved", "singleFreshWindowsIdentity", "baselineDefaultOff", "syntheticHeaderObserved", "eventRequestObserved", "eventResultObserved", "eventMessageRendered", "updatesObserved", "updatesRendered", "eventDisabledObserved", "updatesDisabledObserved", "browserClosed"}
BROWSER_REASONS = {"complete", "contract_rejected", "deadline", "clock_changed", "wrong_origin", "artifact_mismatch", "private_path_rejected", "dependency_unavailable", "browser_unavailable", "session_lost", "identity_mismatch", "invalid_response", "stale_capture", "request_conflict", "event_unknown", "updates_unknown", "ui_unavailable", "cleanup_unverified"}
BROWSER_OMISSIONS = ["baseline_source_completeness", "health_policy_lifecycle", "worker_faults_and_replay", "online_updates", "update_installation", "service_actions", "reboot", "upgrade_repair"]

def validate_browser_result(r, p, plan_hash, passed=False):
    exact(r, ("schema", "runId", "planSHA256", "source", "status", "reason", "fullAcceptance", "nativeExecution", "checks", "observations", "omissions"))
    need(r["schema"] == "tracebolt.windows-linux-native-parity.browser-result.v1" and r["runId"] == p["runId"]
         and r["planSHA256"] == plan_hash and r["source"] == p["source"] and r["fullAcceptance"] is False
         and type(r["nativeExecution"]) is bool and r["status"] in {"passed", "blocked"} and r["reason"] in BROWSER_REASONS
         and r["omissions"] == BROWSER_OMISSIONS, "browser_incomplete")
    exact(r["checks"], BROWSER_CHECKS); need(all(type(v) is bool for v in r["checks"].values()), "browser_incomplete")
    o = r["observations"]
    exact(o, ("eventQuality", "updatesQuality", "updatesRows", "updatesCountExact", "updatesTruncated", "updatesRendering", "cacheFreshness", "patchCoverage"))
    need(o["eventQuality"] in {"not_observed", "observed", "bounded", "partial", "unavailable"}
         and o["updatesQuality"] in {"not_observed", "observed", "partial", "denied", "unavailable"}
         and type(o["updatesRows"]) is int and 0 <= o["updatesRows"] <= 64
         and type(o["updatesCountExact"]) is bool and type(o["updatesTruncated"]) is bool
         and o["updatesRendering"] in {"not_observed", "empty_state_only", "rows_observed"}
         and o["cacheFreshness"] == "unknown" and o["patchCoverage"] == "not_assessed", "browser_incomplete")
    need(o["updatesRendering"] != "empty_state_only" or o["updatesRows"] == 0, "browser_incomplete")
    need(o["updatesRendering"] != "rows_observed" or o["updatesRows"] > 0, "browser_incomplete")
    if r["status"] == "passed" or passed:
        need(r["status"] == "passed" and r["nativeExecution"] and r["reason"] == "complete" and all(r["checks"].values())
             and o["eventQuality"] == "observed" and (o["updatesQuality"] == "observed" or o["updatesQuality"] == "partial" and o["updatesRows"] > 0)
             and o["updatesRendering"] != "not_observed", "browser_incomplete")
    else:
        need(r["reason"] != "complete", "browser_incomplete")
    return r

def operate(p, plan_hash, checks):
    t = p["targets"]["linux"]
    for name in ("manager", "node", "chromium"):
        raw = verify_artifact(p["artifacts"][name], 64 << 20) if name == "manager" else verify_executable_header(p["artifacts"][name])
        need(raw[:6] == b"\x7fELF\x02\x01" and raw[18:20] == b"\x3e\x00", "artifact_mismatch")
        if name == "manager":
            need(b"path\tlocalrmm/cmd/lan-manager\n" in raw
                 and ("build\tvcs.revision=" + p["source"]["commit"] + "\n").encode() in raw
                 and b"build\tvcs.modified=false\n" in raw, "artifact_mismatch")
    verify_inventory(t["webRoot"], t["webInventory"], p["artifacts"]["webInventory"]["sha256"], trusted=True)
    verify_inventory(t["browserRoot"], t["browserInventory"], p["artifacts"]["browserInventory"]["sha256"], dependencies=True, trusted=True)
    config = verify_config(p)
    need(Path(t["webRoot"], "index.html").is_file(), "artifact_mismatch")
    manager = browser = None
    try:
        # Real command, isolated state/config. Logs may include paths; discard them.
        check_time(p["expiresUnix"])
        checks["native_actions_attempted"] = True
        manager = subprocess.Popen([p["artifacts"]["manager"]["path"], "--lan-config", t["lanConfig"], "--enrollment-config", t["enrollmentConfig"]],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   env={"HOME": t["workspace"], "TMPDIR": t["workspace"], "LANG": "C.UTF-8"}, shell=False, start_new_session=True)
        await_tls(manager, p, config); checks["real_manager_started"] = True
        output = str(Path(t["workspace"]) / (p["runId"] + "-browser.json"))
        need(not Path(output).exists(), "phase_replay")
        spec = browser_spec(p, plan_hash)
        # Preserve only GUI session selectors, never ambient tokens/proxy/Node flags.
        env = {"HOME": t["workspace"], "TMPDIR": t["workspace"], "LANG": "C.UTF-8"}
        for k in ("DISPLAY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"):
            if os.environ.get(k):
                env[k] = os.environ[k]
        need("DISPLAY" in env or "WAYLAND_DISPLAY" in env, "secure_handoff_required")
        check_time(p["expiresUnix"])
        browser = subprocess.Popen([p["artifacts"]["node"]["path"], str(Path(t["sourceRoot"]) / "tests/windows_linux_native_parity/browser.mjs")],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env, shell=False, start_new_session=True)
        browser.stdin.write(canonical(spec)); browser.stdin.close()
        # Read bounded fixed markers without printing raw browser/OS diagnostics.
        import queue, threading
        queue_out = queue.Queue(maxsize=64)
        def read_markers():
            try:
                for _ in range(64):
                    line = browser.stdout.readline(128)
                    if not line:
                        break
                    queue_out.put_nowait(line)
            except Exception:
                pass
        reader = threading.Thread(target=read_markers, daemon=True); reader.start()
        seen = set()
        while browser.poll() is None:
            need(manager.poll() is None, "manager_exited")
            check_time(p["expiresUnix"])
            try:
                line = queue_out.get(timeout=0.25).decode("ascii").strip()
                need(line in MARKERS and line not in seen, "browser_incomplete")
                seen.add(line); print(line, flush=True)
            except queue.Empty:
                pass
        need(browser.returncode == 0, "browser_incomplete")
        result = strict_json(read_regular(output, 32 << 10), 32 << 10)
        validate_browser_result(result, p, plan_hash, passed=True)
        # The browser adapter owns strict observation validation, never a supplied
        # report or manual PASS. This fresh output can only be created by this child.
        checks["real_browser_finished"] = True
    finally:
        browser_graceful = manager_graceful = False
        try:
            browser_graceful = stop_owned(browser, 45)
        finally:
            manager_graceful = stop_owned(manager, 15)
        checks["manager_cleanup"] = manager_graceful
        browser_closed = browser is None
        if browser is not None:
            try:
                final = validate_browser_result(strict_json(read_regular(output, 32 << 10), 32 << 10), p, plan_hash)
                browser_closed = final["checks"]["browserClosed"] or not final["nativeExecution"]
            except Exception:
                browser_closed = False
        checks["browser_cleanup"] = browser_graceful and browser_closed
        if not checks["browser_cleanup"] or not manager_graceful:
            raise Rejected("cleanup_unverified")
