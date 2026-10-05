"""Inert fixtures: no systemd, host private paths, source commands or network."""
import contextlib
import copy
import importlib.util
import json
from pathlib import Path
import shlex
import sys
import stat
import types
import unittest
from unittest import mock

HERE = Path(__file__).parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


g = load("inventory_guide_test", HERE / "guide.py")
c = load("inventory_command_test", HERE / "prepare-guide-command.py")
f = load("inventory_ownership_fixture", HERE.parent / "journal" / "test_setup.py")
s = f.s
REVISION = "a" * 40


class Fixture(f.Fixture):
    def __init__(self, profile="tls", active=True):
        super().__init__(profile, active)
        self.help = b"\n".join(("  -" + x + " string").encode() for x in
            ["config", "service-identity", "validate-guided"] + [flag for spec in g.SCOPES.values()
                for flag in (spec["flag"] + "-consent", "ack-" + spec["flag"])])
        self.config = dict(schemaVersion="tracebolt.lan-agent.v5", profile=profile,
            managerOrigin=json.loads(self.files[s.BOOTSTRAP])["agentOrigin"], agentId="agent_" + "d" * 32,
            certificateFile="/unused/public-cert", privateKeyFile="/never-read/key", serverCAFile="/unused/public-ca",
            stateDirectory=g.TELEMETRY, insecureHTTPAcknowledged=profile == "http-test", collectionProfile=s.PROFILE)
        self.enabled = {key: False for key in g.SCOPES}
        self.shapes = {key: dict(consentPresent=False, markersPresent=False,
                                spoolsPresent=[False] * len(spec["spools"])) for key, spec in g.SCOPES.items()}
        self.calls = []
        self.events = []
        self.failure = None
        self.mutate_after_confirm = None
        self.prompts = []
        self.output = []
        self.confirmed = False
        self.confirm_result = True
        self.bad_result = None
        self.files["/etc/tracebolt/journal-activation.json"] = b"synthetic unresolved journal pending marker"
        self.files["/etc/tracebolt/.journal-content-policy.json.amend.tmp"] = b"synthetic pending policy"
        self.journal_before = {k: v for k, v in self.files.items() if k.startswith("/etc/tracebolt/")}

    def agent_config(self, uid, gid):
        self.assert_identity(uid, gid)
        return s.canonical(self.config)

    def scope_shape(self, uid, gid, key):
        self.assert_identity(uid, gid)
        return copy.deepcopy(self.shapes[key])

    def assert_identity(self, uid, gid):
        g.require(uid == 200 and gid == 201, "fixture-service-identity")

    @contextlib.contextmanager
    def lock(self):
        g.require(self.confirmed, "fixture-lock-before-confirmation")
        self.events.append("lock")
        with super().lock():
            yield

    def command(self, args, uid=None, gid=None, **kwargs):
        self.calls.append(tuple(args))
        if args == [s.BINARY, "--help"]:
            self.assert_identity(uid, gid)
            self.events.append("help")
            return self.help
        g.require(self.confirmed and self.locked, "fixture-effect-before-confirmation")
        if args[0] == s.BINARY:
            self.assert_identity(uid, gid)
            g.require(self.units[s.AGENT_UNIT]["ActiveState"] == "inactive", "fixture-running-consent")
            if args[-1] == "--validate-guided":
                self.events.append("validate-baseline")
                if self.failure == "baseline":
                    raise g.Rejected("resume-protected-state-unverified")
                return b"Validated locally."
            matches = [(key, mode) for key in g.SCOPES for mode in ("preview", "enable")
                       if args == g.consent_args(s, dict(uid=uid, gid=gid), key, mode)]
            g.require(len(matches) == 1, "fixture-fixed-consent")
            key, mode = matches[0]
            self.events.append(key + ":" + mode)
            if self.failure == (key, mode):
                raise g.Rejected("fixture-" + key + "-" + mode + "-failed")
            if mode == "enable":
                self.enabled[key] = True
                self.shapes[key]["consentPresent"] = True
                self.shapes[key]["spoolsPresent"] = [True] * len(g.SCOPES[key]["spools"])
            p = self.result(key, mode)
            if self.bad_result == (key, mode):
                p["scope"] = "foreign-scope"
            return s.canonical(p)
        if args == ["/usr/bin/systemctl", "stop", s.AGENT_UNIT]:
            self.events.append("stop")
            self.units[s.AGENT_UNIT]["ActiveState"], self.units[s.AGENT_UNIT]["MainPID"] = "inactive", "0"
            if self.failure == "lost-stop":
                raise g.Rejected("agent-stop-failed")
            return b""
        if args == ["/usr/bin/systemctl", "start", s.AGENT_UNIT]:
            self.events.append("start")
            if self.failure == "start":
                raise g.Rejected("agent-resume-failed")
            self.units[s.AGENT_UNIT]["ActiveState"], self.units[s.AGENT_UNIT]["MainPID"] = "active", "123"
            return b""
        raise AssertionError("Unexpected fixture command")

    def result(self, key, mode):
        spec = g.SCOPES[key]
        p = dict(schemaVersion=spec["schema"], mode=mode, extensionVersion=spec["extension"],
                 scope=spec["scope"], enabled=self.enabled[key], existingStatePreserved=True)
        if key != "identity":
            p.update(disclosure=spec["disclosure"], captureIntervalSeconds=spec["cadence"])
        return p

    def confirm(self, phrase):
        self.events.append("confirm")
        self.prompts.append(phrase)
        self.confirmed = self.confirm_result
        if self.mutate_after_confirm:
            self.mutate_after_confirm(self)
        return self.confirm_result

    def run(self, include_identity=False):
        result = g.run(s, self, self.templates, include_identity, self.confirm, self.output.append)
        self.assert_journal_unchanged()
        return result

    def assert_journal_unchanged(self):
        assert {k: v for k, v in self.files.items() if k.startswith("/etc/tracebolt/")} == self.journal_before

    def grant(self, key):
        self.enabled[key] = True
        self.shapes[key] = dict(consentPresent=True, markersPresent=False,
                               spoolsPresent=[True] * len(g.SCOPES[key]["spools"]))


class WorkflowTests(unittest.TestCase):
    def test_cancel_no_stop_lock_preview_or_validation(self):
        x = Fixture()
        x.confirm_result = False
        result = x.run()
        self.assertTrue(result["canceled"])
        self.assertEqual(x.events, ["help", "confirm"])
        self.assertEqual(result["activity"], "unchanged")
        self.assertIn("unknown until stopped-agent validation", x.output[0])
        self.assertIn("not selected", x.output[0])

    def test_success_all_previews_before_any_write_then_restore(self):
        x = Fixture()
        result = x.run()
        self.assertTrue(result["completed"])
        self.assertEqual(result["activity"], "restored_active")
        self.assertEqual(x.events, ["help", "confirm", "lock", "help", "stop", "overview:preview", "apt:preview",
            "overview:enable", "overview:preview", "apt:enable", "apt:preview", "validate-baseline", "start"])
        self.assertEqual([r["outcome"] for r in result["scopes"].values()], ["enabled_confirmed"] * 2)
        self.assertFalse(x.enabled["identity"])
        self.assertFalse(result["collectionPerformed"])

    def test_optional_identity_must_be_explicitly_selected(self):
        x = Fixture("http-test")
        result = x.run(True)
        self.assertTrue(result["completed"])
        self.assertTrue(x.enabled["identity"])
        self.assertEqual(x.prompts, ["ENABLE INVENTORY OVER HTTP"])
        self.assertIn("Hostname and interface addresses (separate optional scope)", x.output[0])
        self.assertIn("plaintext", x.output[0])
        self.assertLess(x.events.index("identity:preview"), x.events.index("overview:enable"))

    def test_installed_older_agent_flags_block_before_confirmation(self):
        for missing in ("complete-overview-consent", "complete-cached-updates-consent", "ack-complete-cached-updates"):
            x = Fixture()
            x.help = x.help.replace(("  -" + missing + " string").encode(), b"")
            with self.subTest(missing=missing), self.assertRaisesRegex(g.Rejected, "installed-agent-upgrade-required"):
                x.run()
            self.assertEqual(x.events, ["help"])

    def test_default_does_not_require_optional_identity_flag(self):
        x = Fixture()
        x.help = b"\n".join(row for row in x.help.splitlines() if b"endpoint-identity" not in row)
        self.assertTrue(x.run()["completed"])

    def test_already_enabled_scopes_skipped(self):
        x = Fixture()
        x.grant("overview")
        x.grant("apt")
        result = x.run()
        self.assertTrue(result["completed"])
        self.assertEqual([r["outcome"] for r in result["scopes"].values()], ["already_enabled"] * 2)
        self.assertFalse(any(":enable" in event for event in x.events))

    def test_originally_inactive_agent_remains_inactive(self):
        x = Fixture(active=False)
        result = x.run()
        self.assertTrue(result["completed"])
        self.assertNotIn("stop", x.events)
        self.assertNotIn("start", x.events)
        self.assertEqual(x.units[s.AGENT_UNIT]["ActiveState"], "inactive")

    def test_known_preview_failure_restores_without_any_enable(self):
        x = Fixture()
        x.failure = ("apt", "preview")
        result = x.run()
        self.assertFalse(result["completed"])
        self.assertEqual(result["activity"], "restored_active")
        self.assertFalse(any(":enable" in event for event in x.events))
        self.assertEqual(x.events[-2:], ["validate-baseline", "start"])

    def test_ambiguous_present_sidecars_fail_before_first_enable(self):
        for key in g.SCOPES:
            x = Fixture()
            x.shapes[key]["consentPresent"] = True
            result = x.run(True)
            with self.subTest(key=key):
                self.assertEqual(result["failureStage"], "ambiguous-" + key + "-consent")
                self.assertFalse(any(":enable" in event for event in x.events))
                self.assertEqual(result["activity"], "restored_active")

    def test_markers_partial_and_missing_spools_retained(self):
        cases = [("apt", dict(markersPresent=True), False, "uncertain-apt-initialization"),
                 ("overview", dict(spoolsPresent=[True, False]), False, "partial-overview-spools"),
                 ("apt", dict(consentPresent=True), True, "missing-apt-spools")]
        for key, shape, enabled, stage in cases:
            x = Fixture()
            x.shapes[key].update(shape)
            x.enabled[key] = enabled
            before = copy.deepcopy(x.shapes)
            result = x.run()
            with self.subTest(stage=stage):
                self.assertEqual(result["failureStage"], stage)
                self.assertEqual(x.shapes, before)
                self.assertFalse(any(":enable" in event for event in x.events))

    def test_dormant_complete_spools_reuse_existing_enable_validator(self):
        x = Fixture()
        x.shapes["overview"]["spoolsPresent"] = [True, True]
        self.assertTrue(x.run()["completed"])
        self.assertEqual(x.events.count("overview:enable"), 1)

    def test_partial_second_enable_uncertain_stays_stopped(self):
        x = Fixture()
        x.failure = ("apt", "enable")
        result = x.run(True)
        self.assertFalse(result["completed"])
        self.assertEqual(result["scopes"]["overview"]["outcome"], "enabled_confirmed")
        self.assertEqual(result["scopes"]["apt"]["outcome"], "uncertain")
        self.assertEqual(result["scopes"]["identity"]["outcome"], "not_attempted")
        self.assertEqual(result["activity"], "left_stopped_uncertain_consent")
        self.assertNotIn("start", x.events)
        self.assertTrue(x.enabled["overview"])
        self.assertEqual(result["resumeAfterInspection"], g.RESUME)
        self.assertIn("Do not remove", result["retry"])

    def test_bad_enable_response_keeps_real_committed_scope_uncertain(self):
        x = Fixture()
        x.bad_result = ("overview", "enable")
        result = x.run()
        self.assertTrue(x.enabled["overview"])
        self.assertEqual(result["scopes"]["overview"]["outcome"], "uncertain")
        self.assertNotIn("start", x.events)

    def test_prewrite_baseline_invalid_does_not_resume(self):
        x = Fixture()
        x.shapes["overview"]["markersPresent"] = True
        x.failure = "baseline"
        result = x.run()
        self.assertEqual(result["activity"], "resume_not_confirmed")
        self.assertEqual(result["resumeFailureStage"], "resume-protected-state-unverified")
        self.assertNotIn("start", x.events)

    def test_lost_stop_ack_attempts_safe_restore(self):
        x = Fixture()
        x.failure = "lost-stop"
        result = x.run()
        self.assertEqual(result["failureStage"], "agent-stop-failed")
        self.assertEqual(result["activity"], "restored_active")
        self.assertFalse(any(":enable" in event for event in x.events))

    def test_changed_config_or_activity_after_confirmation_no_stop(self):
        for mutate in (lambda x: x.config.update(agentId="agent_" + "e" * 32),
                       lambda x: x.units[s.AGENT_UNIT].update(ActiveState="inactive", MainPID="0")):
            x = Fixture()
            x.mutate_after_confirm = mutate
            result = x.run()
            self.assertEqual(result["failureStage"], "reviewed-installation-changed")
            self.assertNotIn("stop", x.events)
            self.assertNotIn("start", x.events)

    def test_committed_grants_survive_resume_failure(self):
        x = Fixture()
        x.failure = "start"
        result = x.run()
        self.assertTrue(result["completed"])
        self.assertEqual(result["activity"], "resume_not_confirmed")
        self.assertTrue(all(x.enabled[key] for key in ("overview", "apt")))
        self.assertEqual(result["resumeFailureStage"], "agent-resume-failed")

    def test_retry_skips_already_confirmed_scope(self):
        x = Fixture()
        x.grant("overview")
        self.assertTrue(x.run()["completed"])
        self.assertNotIn("overview:enable", x.events)
        self.assertIn("apt:enable", x.events)

    def test_contract_rejects_duplicate_scope_boolean_cadence_unknown_members(self):
        x = Fixture()
        raw = s.canonical(x.result("overview", "preview"))
        cases = [b'{"mode":"preview",' + raw[1:]]
        for field, value in (("captureIntervalSeconds", True), ("disclosure", "weakened scope"),
                             ("enabled", 1), ("unexpected", "field")):
            p = x.result("overview", "preview")
            p[field] = value
            cases.append(s.canonical(p))
        for raw in cases:
            with self.assertRaises(g.Rejected):
                g.consent_result(raw, "overview", "preview")


class SourceTests(unittest.TestCase):
    def files(self):
        root = HERE.resolve().parents[1]
        return {path: (root / path).read_bytes() for path in (g.GUIDE_FILE, g.MANIFEST_FILE, *g.CORE_FILES)}

    def test_generated_command_verifies_all_public_bytes_without_execution(self):
        files = self.files()
        downloads = []
        def download(url, limit):
            downloads.append(url)
            return files[url.split(REVISION + "/", 1)[1]]
        cmd = c.command(REVISION, files.__getitem__, download)
        parts = shlex.split(cmd)
        self.assertEqual(parts[:2], ["/usr/bin/env", "-i"])
        self.assertIn("-I", parts)
        self.assertEqual(parts[-1], "default")
        self.assertEqual(len(downloads), 4)
        self.assertNotIn("\n", cmd)
        self.assertIn("NoRedirect", c.BOOTSTRAP)
        self.assertIn("hashlib.sha256(b).hexdigest()!=h", c.BOOTSTRAP)
        self.assertNotIn("tempfile", c.BOOTSTRAP)
        self.assertIn("network-identity", c.command(REVISION, files.__getitem__, download, True))

    def test_public_byte_mismatch_refuses_command(self):
        files = self.files()
        with self.assertRaisesRegex(c.g.Rejected, "public-source-differs"):
            c.command(REVISION, files.__getitem__, lambda *_: b"different")

    def test_load_sources_hashes_before_compile_no_host_access(self):
        files = self.files()
        def download(url, limit):
            return files[url.split(REVISION + "/", 1)[1]]
        with mock.patch.object(g.subprocess, "Popen", side_effect=AssertionError("No host command")), \
                mock.patch.object(g.os, "open", side_effect=AssertionError("No host file")):
            adapter, templates = g.load_sources(REVISION, g.digest(files[g.MANIFEST_FILE]), download)
        self.assertEqual(adapter.AGENT_UNIT, s.AGENT_UNIT)
        self.assertEqual(set(templates), {"tracebolt-agent.service.in"})
        files[g.CORE_FILES[0]] += b"tamper"
        with self.assertRaisesRegex(g.Rejected, "source-hash"):
            g.load_sources(REVISION, g.digest(files[g.MANIFEST_FILE]), download)

    def test_manifest_exact_paths_sizes_hashes(self):
        files = self.files()
        self.assertEqual(g.manifest(files[g.MANIFEST_FILE]), c.make_manifest(files.__getitem__))
        raw = g.manifest(files[g.MANIFEST_FILE])
        raw["files"]["../../unexpected"] = raw["files"][g.CORE_FILES[0]]
        with self.assertRaises(g.Rejected):
            g.manifest(s.canonical(raw))

    def test_real_adapter_rejects_unlisted_effect_before_process_or_file(self):
        effect = g.real_effects(s)
        with mock.patch.object(effect, "read", side_effect=AssertionError("No read")), \
                mock.patch.object(g.subprocess, "Popen", side_effect=AssertionError("No process")):
            for args in (["/usr/sbin/useradd", "name"], ["/usr/bin/systemctl", "restart", s.AGENT_UNIT],
                         [s.BINARY, "--journal-content-consent", "initialize"], [s.BINARY, "--foreground"],
                         ["/usr/bin/systemctl", "start", s.SERVICE]):
                with self.subTest(args=args), self.assertRaises(g.Rejected):
                    effect.command(args)


class AdapterTests(unittest.TestCase):
    def test_existing_identity_and_clean_environment_for_help_and_consent(self):
        effect = g.real_effects(s)
        facts = dict(uid=200, gid=201)
        for args in ([s.BINARY, "--help"], g.consent_args(s, facts, "apt", "enable"),
                     [s.BINARY, "--config", s.CONFIG, "--validate-guided"]):
            with self.subTest(args=args), mock.patch.object(effect, "read", return_value=b"fixture owned executable"), \
                    mock.patch.object(g.subprocess, "Popen", side_effect=RuntimeError("fixture launch stopped")) as popen:
                with self.assertRaisesRegex(RuntimeError, "fixture launch stopped"):
                    effect.command(args, uid=200, gid=201)
                options = popen.call_args.kwargs
                self.assertEqual((options["user"], options["group"], options["extra_groups"]), (200, 201, []))
                self.assertEqual(options["env"], s.ENV)
                self.assertEqual(options["cwd"], "/")
                self.assertTrue(options["close_fds"])
                self.assertTrue(options["start_new_session"])
                self.assertEqual(options["stdin"], g.subprocess.DEVNULL)
                self.assertEqual(options["stderr"], g.subprocess.STDOUT if args[-1] == "--help" else g.subprocess.DEVNULL)

    def test_scope_shape_never_follows_links_or_reads_content(self):
        effect = g.real_effects(s)
        @contextlib.contextmanager
        def directory(*args, **kwargs):
            yield 77
        entries = {"complete-overview-consent.json": types.SimpleNamespace(st_mode=stat.S_IFREG | 0o600,
                    st_uid=200, st_gid=201, st_nlink=1, st_size=250),
                   "overview-processes": types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=200, st_gid=201),
                   "overview-volumes": types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=200, st_gid=201)}
        def status(name, **kwargs):
            self.assertEqual(kwargs, dict(dir_fd=77, follow_symlinks=False))
            if name not in entries:
                raise FileNotFoundError()
            return entries[name]
        with mock.patch.object(effect, "agent_directory", directory), mock.patch.object(g.os, "stat", status), \
                mock.patch.object(g.os, "read", side_effect=AssertionError("no state content")):
            self.assertEqual(effect.scope_shape(200, 201, "overview"),
                dict(consentPresent=True, markersPresent=False, spoolsPresent=[True, True]))
            entries["complete-overview-consent.json"].st_mode = stat.S_IFLNK | 0o777
            with self.assertRaisesRegex(g.Rejected, "protected-overview-state"):
                effect.scope_shape(200, 201, "overview")
            entries["complete-overview-consent.json"].st_mode = stat.S_IFREG | 0o600
            entries[".complete-overview-initialization"] = types.SimpleNamespace(st_mode=stat.S_IFLNK | 0o777)
            self.assertTrue(effect.scope_shape(200, 201, "overview")["markersPresent"])

    def test_confirmation_eof_and_enter_cancel_without_effect(self):
        @contextlib.contextmanager
        def terminal():
            yield 99
        for answer in (b"", b"\n", b"ENABLE INVENTORY\n"):
            source = iter(bytes((b,)) for b in answer)
            with self.subTest(answer=answer), mock.patch.object(g, "terminal", terminal), \
                    mock.patch.object(g.os, "write", side_effect=lambda fd, raw: len(raw)), \
                    mock.patch.object(g.os, "read", side_effect=lambda *_: next(source, b"")):
                self.assertEqual(g.confirm_terminal("ENABLE INVENTORY"), answer == b"ENABLE INVENTORY\n")


if __name__ == "__main__":
    unittest.main()
