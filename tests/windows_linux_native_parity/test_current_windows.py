"""Inert current-profile adapter fixtures. No OS API, child or host is run."""
from __future__ import annotations
import base64
import copy
import contextlib
import io
import json
import re
from pathlib import Path
import ssl
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
sys.path.insert(0, str(Path(__file__).resolve().parent))
import contract as c
import windows_native as w
from test_contract import plan, h, ROOT


def current_plan():
    p = plan(); p["schema"] = c.CURRENT_SCHEMA; p["currentProfile"] = copy.deepcopy(c.CURRENT_PROFILE)
    p["targets"]["windows"]["platform"] = "windows-11-x64"
    p["phases"] = {phase: {"approvalRef": "inert-" + phase, "targetId": p["targets"]["linux" if phase == "manager-browser" else "windows"]["id"]} for phase in c.CURRENT_PHASES}
    p["historyQuery"] = {"approvalRef": "fixture-search", "messagesApprovalRef": "fixture-messages", "channel": "Application", "eventId": 42, "startUnix": 1020, "endUnix": 1980, "maxRows": 100, "maxMessages": 1}
    return p


def public_fixture():
    p = current_plan(); files = Path("/fixture/ProgramFiles/Tracebolt"); data = Path("/fixture/ProgramData/Tracebolt")
    root = data / "windows-agent"; enrollment = root / "enrollment"
    anchor_der = b"INERT PUBLIC CERTIFICATE FIXTURE, NOT A TLS CERTIFICATE"
    anchor_hash = c.digest(anchor_der)
    cfg = {"collectionProfile": "windows-inventory-v1", "schemaVersion": "tracebolt.lan-agent.windows.v2", "profile": "tls",
           "managerOrigin": p["tls"]["agentOrigin"], "agentId": "agent_" + h("agent")[:32],
           "certificateFile": str(enrollment / "agent-cert.pem"), "privateKeyFile": str(enrollment / "agent-key.pem"),
           "serverCAFile": str(enrollment / "server-ca.pem"), "stateDirectory": str(enrollment / "telemetry"),
           "insecureHTTPAcknowledged": False, "renewalManifestFile": str(enrollment / "renewal-manifest.json")}
    sender = c.digest(("tracebolt.sender-binding.windows.v1\nwindows-inventory-v1\ntls\n" + p["tls"]["agentOrigin"] + "\n" + anchor_hash + "\n" + cfg["agentId"]).encode())
    public = {}; grants = []
    for scope, suffix, schema, _ in w.CURRENT_GRANTS:
        consent = {"schemaVersion": "tracebolt.windows-" + schema + "-consent.v1", "scope": scope,
                   "senderBinding": sender, "grantId": h(suffix)[:32]}
        if suffix in {"full-services", "full-software", "full-processes", "network-context"}:
            consent.update(revision=1, enabled=True, changedAt="2026-10-11T20:00:00Z")
            if suffix == "full-software":
                consent["scope"] = "windows-complete-machine-software-v1"; consent["historyScope"] = "windows-machine-software-history-v1"
        elif suffix == "event-history":
            consent.update(profile="tls", enabled=True, historyAcknowledged=True, contentAcknowledged=True, httpPlaintextAcknowledged=False)
        else:
            consent["enabled"] = True
        raw = w.go_json(consent); public[Path(str(root) + "-" + suffix) / "consent.json"] = raw
        grants.append({"scope": scope, "sha256": c.digest(raw)})
    installed_hash = p["artifacts"]["service"]["sha256"]; installation = h("installation")[:32]
    configuration = w.expected_configuration(files, installation, installed_hash)
    sid = "S-1-5-80-111-222-333-444-555"
    snapshot = {"exists": True, "configuration": configuration, "state": 1, "serviceSID": sid}
    receipt = {"version": 12, "service": {"version": 1, "installationID": installation,
        "layout": {"programFiles": str(files.parent), "programData": str(data.parent), "executable": str(files / "tracebolt-windows-service.exe"),
                   "stateRoot": str(root), "enrollmentRoot": str(enrollment), "senderRoot": str(enrollment / "telemetry")},
        "configurationSHA256": c.digest(w.go_json(configuration)), "executableSHA256": installed_hash, "serviceSID": sid, "complete": True},
        "prepared": True, "readSetup": {"consent": w.current_consent(), "phase": "configured", "senderBinding": sender,
        "grants": {"metadataScopeVerified": True, "appliedScopes": list(w.CURRENT_SCOPES[1:])}, "grantDigests": grants}}
    public[Path(str(root) + "-installer") / "receipt.json"] = w.go_json(receipt)
    intent = {"managerInstanceId": p["tls"]["managerInstanceId"], "profile": "tls", "origin": p["tls"]["operatorOrigin"],
              "collectionProfile": "windows-inventory-v1", "invitationId": "invite_" + h("invite")[:32], "claimId": "claim_" + h("claim")[:32],
              "requestId": "request_" + h("request")[:32], "deviceId": cfg["agentId"], "intentId": "intent_" + h("intent")[:32],
              "keyFingerprint": h("public-key"), "publicKeyDerBase64": base64.b64encode(b"public-key").decode().rstrip("="),
              "csrHash": h("csr"), "claimHash": h("claim"), "issuerFingerprint": p["tls"]["issuerFingerprint"], "serialHex": h("serial")[:32],
              "templateVersion": "tracebolt.enrollment.client.v2", "keyGeneration": 1, "notBefore": 1000, "notAfter": 9000}
    identity_fields = ["Tracebolt renewable identity generation v1", intent["managerInstanceId"], intent["invitationId"], intent["claimId"], intent["intentId"], intent["deviceId"], intent["keyFingerprint"]]
    identity = "identity_" + c.digest(b"".join(len(s.encode()).to_bytes(4, "big") + s.encode() for s in identity_fields))[:32]
    manifest = {"version": "tracebolt.renewable-identity.v1", "managerInstanceId": p["tls"]["managerInstanceId"], "enrollmentOrigin": p["tls"]["operatorOrigin"],
                "agentOrigin": p["tls"]["agentOrigin"], "collectionProfile": "windows-inventory-v1", "deviceId": cfg["agentId"],
                "identityGeneration": identity, "keyFingerprint": h("public-key"), "anchorHash": anchor_hash, "issuerFingerprint": p["tls"]["issuerFingerprint"],
                "authorityExpiresAt": 99000, "credentialGeneration": 1, "revision": 1, "certificateDer": base64.b64encode(anchor_der).decode(),
                "anchorIntent": intent, "intent": copy.deepcopy(intent), "lastServerNow": 1100}
    public[enrollment / "renewal-manifest.json"] = w.go_json(manifest)
    return p, files, data, cfg, anchor_hash, receipt, snapshot, public, manifest


class CurrentWindowsProofTests(unittest.TestCase):
    def test_renewable_bootstrap_is_exact_and_never_adopts_v2(self):
        p = current_plan()
        b = {"schemaVersion": "tracebolt.enrollment-bootstrap.renewable.v1", "managerInstanceId": p["tls"]["managerInstanceId"],
             "profile": "tls", "enrollmentOrigin": p["tls"]["operatorOrigin"], "agentOrigin": p["tls"]["agentOrigin"],
             "collectionProfile": "windows-inventory-v1", "invitationId": "invite_" + h("invite")[:32],
             "serverCaPem": "serverca", "issuerRootPem": "issuerroot", "issuerPem": ssl.DER_cert_to_PEM_cert(b"issuer"), "renewalPolicy": "same-key-v1"}
        self.assertEqual(w.bootstrap_bytes(w.go_json(b), p), b)
        for key, value in (("schemaVersion", "tracebolt.enrollment-bootstrap.v2"), ("renewalPolicy", ""), ("profile", "http-test"),
                           ("agentOrigin", "https://other.internal:8444"), ("collectionProfile", "inventory-v1"), ("unexpected", True)):
            with self.subTest(key=key), self.assertRaises(c.Rejected): w.bootstrap_bytes(w.go_json({**b, key: value}), p)
        del b["renewalPolicy"]
        with self.assertRaises(c.Rejected): w.bootstrap_bytes(w.go_json(b), p)

    def test_exact_scope_and_production_schema_literals(self):
        self.assertEqual(len(w.CURRENT_SCOPES), 21); self.assertEqual(len(set(w.CURRENT_SCOPES)), 21)
        source = (ROOT / "internal/lanclient/windows_read_admin_profile.go").read_text()
        self.assertIn('"tracebolt.windows-capability-consent.v14"', source)
        for scope, _, schema, _ in w.CURRENT_GRANTS:
            combined = "\n".join(path.read_text() for path in (ROOT / "internal").glob("windows*/*.go") if not path.name.endswith("_test.go"))
            self.assertIn('"' + scope + '"', combined)
            self.assertIn('"tracebolt.windows-' + schema + '-consent.v1"', combined)

    def test_os_product_type_is_authoritative_not_product_name(self):
        for selected, version in (("windows-11-x64", (10, 0, 26100, 1)), ("windows-server-2025-x64", (10, 0, 26100, 3)), ("windows-server-2025-x64", (10, 0, 26100, 2))):
            w.validate_os_selection({"platform": selected, "osBuild": "26100"}, version)
        for selected, version in (("windows-11-x64", (10, 0, 26100, 3)), ("windows-11-x64", (10, 0, 19045, 1)), ("windows-server-2025-x64", (10, 0, 26100, 1)), ("windows-server-2025-x64", (10, 0, 26200, 3)), ("unknown", (10, 0, 26100, 1))):
            with self.subTest(selected=selected, version=version), self.assertRaises(c.Rejected):
                w.validate_os_selection({"platform": selected, "osBuild": str(version[2])}, version)

    def test_exact_receipt_grants_and_anchor_sender_binding(self):
        p, files, data, cfg, anchor, receipt, snapshot, public, _ = public_fixture()
        proof = w.validate_current_receipt(w.go_json(receipt), p, snapshot, cfg, anchor, files, data)
        self.assertEqual(proof["scopes"], list(w.CURRENT_SCOPES)); self.assertEqual(len(proof["grantDigests"]), 20)
        for edit in (lambda r: r.update(version=11), lambda r: r.update(prepared=1), lambda r: r["readSetup"].update(phase="grants-started"),
                     lambda r: r["readSetup"]["consent"].update(acknowledged=1), lambda r: r["readSetup"]["consent"]["scopes"].pop(),
                     lambda r: r["readSetup"].update(senderBinding=h("foreign")), lambda r: r["readSetup"]["grantDigests"].pop(),
                     lambda r: r["readSetup"]["grantDigests"].reverse(), lambda r: r["readSetup"]["grantDigests"][18].update(sha256=h("other-software")),
                     lambda r: r["service"].update(configurationSHA256=h("another config")), lambda r: r["service"].update(complete=False)):
            changed = copy.deepcopy(receipt); edit(changed)
            with self.subTest(receipt=changed), self.assertRaises(c.Rejected):
                w.validate_current_receipt(w.go_json(changed), p, snapshot, cfg, anchor, files, data)
        with self.assertRaises(c.Rejected):
            w.validate_current_receipt(w.go_json(receipt), p, snapshot, cfg, h("current-leaf-is-not-anchor"), files, data)

    def test_every_public_consent_is_exact_enabled_digest_and_sender_bound(self):
        p, files, data, cfg, anchor, receipt, snapshot, public, _ = public_fixture()
        sender = receipt["readSetup"]["senderBinding"]
        for row, grant in zip(w.CURRENT_GRANTS, receipt["readSetup"]["grantDigests"]):
            raw = public[Path(str(data / "windows-agent") + "-" + row[1]) / "consent.json"]
            result = w.validate_public_grant(raw, row, sender, grant["sha256"])
            self.assertEqual(result["scope"], row[0])
            for key, value in (("enabled", False), ("enabled", 1), ("senderBinding", h("foreign")), ("grantId", "bad"), ("unexpected", True)):
                changed = json.loads(raw); changed[key] = value; mutated = w.go_json(changed)
                with self.subTest(scope=row[0], key=key), self.assertRaises(c.Rejected):
                    w.validate_public_grant(mutated, row, sender, c.digest(mutated))
            with self.assertRaises(c.Rejected): w.validate_public_grant(raw + b"\n", row, sender, c.digest(raw + b"\n"))
            with self.assertRaises(c.Rejected): w.validate_public_grant(raw, row, sender, h("wrong-digest"))

    def test_manifest_distinguishes_stable_anchor_from_current_leaf(self):
        p, _, _, cfg, anchor, _, _, _, manifest = public_fixture()
        first = w.validate_current_manifest(w.go_json(manifest), p, cfg, anchor, 1500)
        self.assertEqual(first["currentCertificateHash"], anchor)
        renewed = copy.deepcopy(manifest); renewed.update(credentialGeneration=2, revision=2, certificateDer=base64.b64encode(b"different current public leaf").decode())
        renewed["intent"].update(intentId="intent_" + h("second")[:32], serialHex=h("second-serial")[:32], notAfter=16000)
        second = w.validate_current_manifest(w.go_json(renewed), p, cfg, anchor, 1500)
        self.assertEqual(second["identityGeneration"], first["identityGeneration"])
        self.assertNotEqual(second["currentCertificateHash"], anchor)
        for edit in (lambda m: m.update(anchorHash=h("wrong")), lambda m: m.update(identityGeneration="identity_" + h("wrong")[:32]),
                     lambda m: m.update(credentialGeneration=True), lambda m: m.update(lastServerNow=1501), lambda m: m.update(authorityExpiresAt=1499),
                     lambda m: m["intent"].update(notAfter=1500), lambda m: m["intent"].update(keyFingerprint=h("rotated")),
                     lambda m: m.update(certificateDer="not-base64"), lambda m: m["intent"].update(unexpected=True)):
            changed = copy.deepcopy(manifest); edit(changed)
            with self.subTest(manifest=changed), self.assertRaises(c.Rejected): w.validate_current_manifest(w.go_json(changed), p, cfg, anchor, 1500)

    def test_current_agent_config_keys_match_production_json_declarations(self):
        # Do not duplicate field spelling in both harness and fixture: derive
        # the exact public Config keys from the production Go declaration.
        production = (ROOT / "internal/lanclient/config.go").read_text()
        declaration = re.search(r"type Config struct \{(.*?)\n\}", production, re.S)
        self.assertIsNotNone(declaration)
        fields = re.findall(r'`json:"([^",]+)(?:,[^"]+)?"`', declaration[1])
        p, files, data, cfg, anchor, _, snapshot, _, _ = public_fixture()
        self.assertEqual(set(cfg), set(fields), "Fresh native Config contract needs explicit review")
        wrong = dict(cfg); wrong["serverCaFile"] = wrong.pop("serverCAFile")
        with patch.object(w, "layout", return_value=(files, data)), patch.object(w, "read_runtime_file") as read, patch.object(w, "command") as command:
            with self.assertRaises(c.Rejected):
                w.current_public_proof(p, snapshot, data / "windows-agent", snapshot["serviceSID"], wrong, anchor)
        read.assert_not_called(); command.assert_not_called()

    def test_current_public_proof_uses_fixed_public_files_and_real_preview_interfaces(self):
        p, files, data, cfg, anchor, receipt, snapshot, public, _ = public_fixture()
        paths = []
        def read(path, *unused):
            paths.append(Path(path)); return public[Path(path)]
        def preview(exe, args, *unused, **kw):
            mode = args[0][2:-8]
            scope = next((r[0] for r in w.CURRENT_GRANTS if r[3] == mode), None)
            return {"scope": scope or {"event-content": "windows-selected-application-system-event-content-v1", "updates": "windows-cached-update-inspection-v1"}[mode], "enabled": scope is not None, "existingStatePreserved": True}
        with patch.object(w, "layout", return_value=(files, data)), patch.object(w, "trusted_path"), patch.object(w, "read_regular", side_effect=read), patch.object(w, "read_runtime_file", side_effect=read), patch.object(w, "command", side_effect=preview) as commands, patch.object(w.time, "time", return_value=1500):
            result = w.current_public_proof(p, snapshot, data / "windows-agent", snapshot["serviceSID"], cfg, anchor)
        self.assertEqual(len(result["grantIds"]), 20)
        self.assertEqual(len(commands.call_args_list), 17)
        self.assertTrue(all(path.name in {"receipt.json", "consent.json", "renewal-manifest.json"} for path in paths))
        self.assertEqual(result["grantIds"][6]["grantId"], result["grantIds"][18]["grantId"])

    def test_restart_result_no_partial_success_promotion(self):
        r = restart_result(); w.validate_restart_result(r)
        for key, value in (("outcome", "intervention-required"), ("phase", "lease-release"), ("stopRequested", False), ("startRequested", 1), ("observations", 185), ("lastObservedState", 1), ("rawError", "private")):
            with self.subTest(key=key), self.assertRaises(c.Rejected): w.validate_restart_result({**r, key: value})

    def test_endpoint_binding_exports_only_digest_bound_public_proof_and_rejects_races(self):
        p, files, data, cfg, anchor, receipt, snapshot, public, manifest = public_fixture()
        root = data / "windows-agent"; enrollment = root / "enrollment"
        b = {"schemaVersion": "tracebolt.enrollment-bootstrap.renewable.v1", "managerInstanceId": p["tls"]["managerInstanceId"],
             "profile": "tls", "enrollmentOrigin": p["tls"]["operatorOrigin"], "agentOrigin": p["tls"]["agentOrigin"],
             "collectionProfile": "windows-inventory-v1", "invitationId": "invite_" + h("invite")[:32],
             "serverCaPem": "serverca", "issuerRootPem": "issuerroot", "issuerPem": ssl.DER_cert_to_PEM_cert(b"issuer"), "renewalPolicy": "same-key-v1"}
        public[root / "bootstrap.json"] = w.go_json(b); public[Path(p["targets"]["windows"]["publicBootstrap"])] = w.go_json(b)
        public[enrollment / "agent.json"] = w.go_json(cfg)
        public[enrollment / "agent-cert.pem"] = ssl.DER_cert_to_PEM_cert(base64.b64decode(manifest["certificateDer"])).encode()
        public[enrollment / "ready.json"] = w.go_json({"version": "tracebolt.enrollment-ready.v2", "configHash": c.digest(w.go_json(cfg)), "certificateHash": anchor, "serverAuthenticated": True})
        def read(path, *unused): return public[Path(path)]
        # Running proof is compared against the stopped, production-validated
        # initial binding by the actual caller. Here only codec/race seams run.
        snapshot["state"] = 4
        with patch.object(w, "layout", return_value=(files, data)), patch.object(w, "trusted_path"), patch.object(w, "read_regular", side_effect=read), patch.object(w, "read_runtime_file", side_effect=read), patch.object(w.time, "time", return_value=1500), patch.object(w, "command") as command:
            binding = w.endpoint_binding(p, h("plan"), snapshot, allow_running=True)
            command.assert_not_called()
            self.assertEqual(binding["schema"], "tracebolt.windows-linux-native-parity.endpoint-binding.v2")
            self.assertEqual(binding["certificateHash"], anchor); self.assertEqual(len(binding["grantDigests"]), 20)
            self.assertEqual(binding["credentialManifestSHA256"], c.digest(public[enrollment / "renewal-manifest.json"]))
            encoded = c.canonical(binding)
            for secret in (b"privateKeyFile", b"certificateDer", b"serverCaPem", b"/fixture/"):
                self.assertNotIn(secret, encoded)
            counter = {}
            def racing(path, *unused):
                path = Path(path); counter[path] = counter.get(path, 0) + 1
                raw = public[path]
                return raw + b" " if path.name == "renewal-manifest.json" and counter[path] > 1 else raw
            with patch.object(w, "read_runtime_file", side_effect=racing), self.assertRaises(c.Rejected):
                w.endpoint_binding(p, h("plan"), snapshot, allow_running=True)


def restart_result():
    return {"outcome": "running-observed", "phase": "complete", "stopAttempted": True, "stopRequested": True,
            "stoppedObserved": True, "startAttempted": True, "startRequested": True, "runningObserved": True,
            "lastObservedState": 4, "observations": 7, "stateRetained": True}


class CurrentWindowsPhaseTests(unittest.TestCase):
    def test_event_outside_authorized_query_window_never_writes(self):
        p = current_plan()
        with patch.object(w, "layout", return_value=(Path("/inert/files"), Path("/inert/data"))), patch.object(w, "inspect", return_value={"state": 4}), patch.object(w, "confirm_current_binding"), patch.object(w.time, "time", return_value=p["historyQuery"]["endUnix"]), patch.object(w, "write_synthetic_event") as event:
            with self.assertRaises(c.Rejected): w.operate(p, "event-fixture", {}, h("plan"))
            event.assert_not_called()

    def test_remove_refuses_before_layout_without_verified_browser_evidence(self):
        with patch.object(w, "layout") as layout, patch.object(w, "command") as command:
            with self.assertRaises(c.Rejected) as err: w.operate(current_plan(), "remove", {}, h("plan"))
            self.assertEqual(err.exception.reason, "browser_incomplete"); layout.assert_not_called(); command.assert_not_called()

    def test_mutation_timeout_retains_child_and_has_no_output_pipe(self):
        child = Mock(); child.poll.return_value = None
        with tempfile.TemporaryDirectory() as private:
            exe = Path(private) / "fixture.exe"; exe.write_bytes(b"INERT")
            with patch.object(w, "windows_directory", return_value=r"C:\Windows"), patch.object(w.subprocess, "Popen", return_value=child) as launch, patch.object(w, "check_time", side_effect=[30, c.Rejected("deadline")]), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(c.Rejected) as err:
                    w.command(exe, ["--restart", "--apply"], 2000, expected_sha256=c.digest(b"INERT"), preserve_process=True, observation_directory=private)
            self.assertEqual(err.exception.reason, "secure_handoff_required")
            child.kill.assert_not_called(); child.terminate.assert_not_called(); child.wait.assert_not_called()
            self.assertNotEqual(launch.call_args.kwargs["stdout"], w.subprocess.PIPE)

    def test_restart_event_and_removal_emit_exact_contract_checks(self):
        p = current_plan(); files = Path("/inert/files"); data = Path("/inert/data")
        stopped = {"exists": True, "state": 1, "serviceSID": "fixture"}; running = {**stopped, "state": 4}
        binding = {"schema": "inert-fixture"}; calls = []
        def confirm(p, plan_hash, snapshot, checks, verify_live=True):
            checks.update(endpoint_binding=True, current_receipt=True, current_grants=True, current_credential=True)
            return binding
        def command(exe, args, *unused, **kwargs):
            calls.append(args)
            self.assertTrue(kwargs["preserve_process"])
            if args == ["--restart", "--apply"]: return restart_result()
            if args == ["--uninstall", "--apply"]: return {"snapshot": stopped, "requested": True, "deletePending": True, "stateRetained": True}
            return {}
        for phase in ("event-fixture", "own-restart", "remove"):
            checks = {"browser_evidence_verified": True} if phase == "remove" else {}; calls.clear()
            results = [running, {"exists": False}] if phase == "remove" else [running, running]
            with patch.object(w, "layout", return_value=(files, data)), patch.object(w, "inspect", side_effect=results), patch.object(w, "confirm_current_binding", side_effect=confirm), patch.object(w, "command", side_effect=command), patch.object(w, "wait_state", return_value=stopped), patch.object(w, "write_synthetic_event"), patch.object(w, "write_new") as output, patch.object(w, "check_time", return_value=100), patch.object(w, "read_regular", return_value=b"service"), patch.object(w.time, "time", return_value=1500), contextlib.redirect_stdout(io.StringIO()):
                p["artifacts"]["service"]["sha256"] = c.digest(b"service")
                w.operate(p, phase, checks, h("plan"))
            c.report(p, h("plan"), phase, checks, "observed_phase", "complete", 1)
            if phase == "own-restart":
                self.assertEqual(calls, [["--restart", "--apply"]]); self.assertTrue(output.call_args.args[1]["ownRestartObserved"])
            if phase == "remove": self.assertEqual(calls, [["--stop", "--apply"], ["--uninstall", "--apply"]])

    def test_current_setup_reaches_real_launch_seam_with_all_mutations_mocked(self):
        p = current_plan(); child = Mock(); child.returncode = 0; child.wait.return_value = 0
        files = Mock(); files.exists.return_value = False; files.__truediv__ = Mock(return_value=Path("/fixture/service.exe"))
        data = Mock(); data.exists.return_value = False
        with patch.object(w, "layout", return_value=(files, data)), patch.object(w, "inspect", return_value={"exists": False}), patch.object(w, "trusted_path"), patch.object(w, "read_regular", return_value=b"public-bootstrap"), patch.object(w, "bootstrap_bytes"), patch.object(w, "verify_artifact"), patch.object(w, "windows_directory", return_value=r"C:\Windows"), patch.object(w, "check_time", return_value=100), patch.object(w.subprocess, "Popen", return_value=child) as launch, patch.object(w, "wait_state", return_value={"state": 1}), patch.object(w, "command") as command, patch.object(w, "endpoint_binding", return_value={"public": "fixture"}), patch.object(w, "write_new"), contextlib.redirect_stdout(io.StringIO()):
            checks = {}; w.operate(p, "setup", checks, h("plan"))
        self.assertEqual(launch.call_count, 1)
        self.assertEqual([call.args[1] for call in command.call_args_list], [["--stop", "--apply"], ["--start", "--apply"]])
        c.report(p, h("plan"), "setup", checks, "observed_phase", "complete", 1)


if __name__ == "__main__":
    unittest.main()
