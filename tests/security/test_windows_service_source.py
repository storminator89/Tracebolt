import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
spec=importlib.util.spec_from_file_location("source_gate",Path(__file__).with_name("run_windows_service_source.py"))
gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)
class GateTests(unittest.TestCase):
    def test_startup_digest_fixture_stays_canonical_under_autocrlf_checkout(self):
        root = Path(__file__).resolve().parents[2]
        name = "web/src/windows-service-startup-go-fixture.json"
        expected = (root / name).read_bytes()
        self.assertNotIn(b"\r", expected)
        git = shutil.which("git")
        self.assertIsNotNone(git, "Git is required to verify the checkout contract")
        env = os.environ.copy()
        for key in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT"):
            env.pop(key, None)
        env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_ATTR_NOSYSTEM="1")
        with tempfile.TemporaryDirectory(prefix="startup-checkout-") as folder:
            checkout = Path(folder)
            fixture = checkout / name
            fixture.parent.mkdir(parents=True)
            fixture.write_bytes(expected)
            def run(*args):
                return subprocess.run([git, *args], cwd=checkout, env=env,
                                      check=True, capture_output=True, timeout=20)
            run("init", "--quiet")
            run("config", "core.autocrlf", "true")
            run("add", "--", name)
            fixture.unlink()
            run("checkout-index", "--", name)
            # Negative control: Git's Windows-style conversion really changes
            # raw bytes while leaving the JSON data and embedded digests equal.
            converted = fixture.read_bytes()
            self.assertEqual(converted, expected.replace(b"\n", b"\r\n"))
            self.assertNotEqual(converted, expected)
            self.assertEqual(json.loads(converted), json.loads(expected))
            (checkout / ".gitattributes").write_bytes((root / ".gitattributes").read_bytes())
            run("add", "--", ".gitattributes")
            fixture.unlink()
            run("checkout-index", "--", name)
            self.assertEqual(fixture.read_bytes(), expected)
            # Pin only this fixture. Unrelated text keeps the checkout's policy.
            other = checkout / "ordinary.txt"
            other.write_bytes(b"ordinary\ntext\n")
            run("add", "--", "ordinary.txt")
            other.unlink()
            run("checkout-index", "--", "ordinary.txt")
            self.assertEqual(other.read_bytes(), b"ordinary\r\ntext\r\n")
    def test_exact_required_cases(self):
        records=[dict(Package=p,Test=t,Action="pass") for p,t in gate.REQUIRED]
        raw=lambda rows:b"\n".join(json.dumps(x).encode() for x in rows)
        gate.check_events(raw(records))
        for rows in (records[:-1],records+[dict(records[0],Action="skip")]):
            with self.assertRaises(ValueError):gate.check_events(raw(rows))
    def test_volume_mocks_are_mandatory_without_native_scope(self):
        self.assertIn("./internal/windowsvolumes",gate.PACKAGES)
        for name in ("TestNativeInjectedEnumeration","TestNativeRejectMalformedRoots"):
            required=("localrmm/internal/windowsvolumes",name)
            self.assertIn(required,gate.REQUIRED)
            rows=[dict(Package=p,Test=t,Action="pass") for p,t in gate.REQUIRED if (p,t)!=required]
            with self.assertRaises(ValueError):gate.check_events(b"\n".join(json.dumps(x).encode() for x in rows))
        source=Path(gate.__file__).read_text()
        self.assertIn('env.pop("TRACEBOLT_WINDOWS_READONLY_NATIVE", None)',source)
        self.assertNotIn("run_windows_readonly.py",source)
        self.assertNotIn("run_acceptance.py",source)
    def test_process_metric_mock_is_mandatory(self):
        self.assertIn("./internal/windowsprocessmetrics",gate.PACKAGES)
        required=("localrmm/internal/windowsprocessmetrics","TestNativeMinimalRightsCloseAndCancel")
        self.assertIn(required,gate.REQUIRED)
        rows=[dict(Package=p,Test=t,Action="pass") for p,t in gate.REQUIRED if (p,t)!=required]
        with self.assertRaises(ValueError):gate.check_events(b"\n".join(json.dumps(x).encode() for x in rows))
    def test_startup_mock_and_explicit_cli_boundaries_are_mandatory(self):
        self.assertIn("./internal/windowsmanaged", gate.PACKAGES)
        cases = [
            ("localrmm/internal/windowsmanaged", "TestServiceStartupNativeRightsAndHandleLifetime"),
            ("localrmm/internal/windowsmanaged", "TestServiceStartupNativeBufferClearedAndNoPointersFollowed"),
            ("localrmm/internal/windowsmanaged", "TestServiceStartupNativeModesAndUnknownDoNotQueryDelayed"),
            ("localrmm/internal/windowsmanaged", "TestServiceStartupNativeFailuresBoundsAndBOOL"),
            ("localrmm/internal/windowsmanaged", "TestServiceStartupNativeCancellationClosesOwnedHandles"),
            ("localrmm/internal/windowsmanaged", "TestServiceStartupNativeInvalidInputsNeverOpen"),
            ("localrmm/internal/windowsmanaged", "TestServiceStartupGoGeneratedDigestFixture"),
            ("localrmm/cmd/windows-service", "TestServiceStartupRequiresOwnedStoppedService"),
            ("localrmm/cmd/windows-service", "TestServiceStartupDisclosureMustCompleteBeforeDispatch"),
            ("localrmm/cmd/windows-service", "TestServiceStartupFlagsDoNotAuthorizeAnotherScope"),
        ]
        for required in cases:
            self.assertIn(required, gate.REQUIRED)
            rows = [dict(Package=p, Test=t, Action="pass") for p, t in gate.REQUIRED if (p, t) != required]
            with self.assertRaises(ValueError):
                gate.check_events(b"\n".join(json.dumps(x).encode() for x in rows))
        source = Path(gate.__file__).read_text()
        self.assertIn('env.pop("TRACEBOLT_WINDOWS_READONLY_NATIVE", None)', source)
        self.assertIn('env.pop("TRACEBOLT_UPDATE_SERVICE_STARTUP_FIXTURE", None)', source)
        self.assertNotIn('TRACEBOLT_WINDOWS_READONLY_NATIVE"] =', source)
    def test_startup_vectors_survive_restricted_docker_web_inputs(self):
        root = Path(__file__).resolve().parents[2]
        docker = (root / "Dockerfile").read_text()
        ignore = (root / ".dockerignore").read_text().splitlines()
        web_stage = docker.split("FROM --platform=$BUILDPLATFORM golang:")[0]
        runtime_stage = docker.split("FROM scratch AS runtime")[1]
        # This fixture stays inside the already allowed/copied web tree. No new
        # tests directory, secret source, runtime COPY or ignore exception is needed.
        self.assertIn("!web/**", ignore)
        self.assertNotIn("web/src/windows-service-startup-go-fixture.json", ignore)
        self.assertLess(web_stage.index("COPY web/ ./"), web_stage.index("RUN npm run build"))
        path = root / "web/src/windows-service-startup-go-fixture.json"
        self.assertGreater(len(json.loads(path.read_text())), 0)
        source = (root / "web/src/windows-service-startup-types.test.ts").read_text()
        self.assertIn("'./windows-service-startup-go-fixture.json'", source)
        self.assertIn("COPY --from=web /src/web/dist /tracebolt/web", runtime_stage)
        self.assertNotIn("/src/web/src", runtime_stage)
        self.assertNotIn("windows-service-startup-vectors", runtime_stage)
    def test_network_mocks_are_mandatory_without_native_reads(self):
        self.assertIn("./internal/windowsnetwork", gate.PACKAGES)
        for name in ("TestNativeNetworkInjectedFourTables", "TestNativeNetworkReturnCodesAndBounds", "TestNativeNetworkDWORDLayouts", "TestFourTablesAndNetworkByteOrder", "TestMalformedAndTrailingNativeTables", "TestBufferGrowthBoundAndCancellation", "TestBoundedCountsStableRowsAndBudget", "TestShrinkingTableIgnoresSurplusAllocation", "TestTCPListenerHasNoRemotePeer"):
            required = ("localrmm/internal/windowsnetwork", name)
            self.assertIn(required, gate.REQUIRED)
            rows = [dict(Package=p, Test=t, Action="pass") for p, t in gate.REQUIRED if (p, t) != required]
            with self.assertRaises(ValueError):
                gate.check_events(b"\n".join(json.dumps(x).encode() for x in rows))
        source = Path(gate.__file__).read_text()
        self.assertIn('env.pop("TRACEBOLT_WINDOWS_READONLY_NATIVE", None)', source)
        self.assertNotIn('TRACEBOLT_WINDOWS_READONLY_NATIVE"] =', source)
    def test_fresh_setup_remains_inert_source_and_required(self):
        names = {
            "TestFreshReadSetupStaysDisabledAndOrdinaryLifecycleRejectsReceipt",
            "TestFreshReadSetupIndeterminateTransitionOnlyReadOnlyReconciliation",
            "TestFreshReadSetupOneConsentBeforeFirstStart",
            "TestFreshReadSetupPartialGrantOutcomeRetained",
            "TestFreshReadSetupHasNoPublicCommand",
        }
        self.assertTrue(names.issubset({name for _, name in gate.REQUIRED}))
        root = Path(__file__).resolve().parents[2]
        cli = (root / "cmd/windows-service/main.go").read_text()
        dispatch = (root / "cmd/windows-service/operation_windows.go").read_text()
        self.assertNotIn("installReadObservation(", dispatch)
        self.assertNotIn('flags.Bool("read-setup"', cli)
    def test_malformed_stream(self):
        for raw in (b"[]",b"not json",b"",b" "*(32*1024*1024+1)):
            with self.assertRaises(ValueError):gate.check_events(raw)
if __name__=="__main__":unittest.main()
