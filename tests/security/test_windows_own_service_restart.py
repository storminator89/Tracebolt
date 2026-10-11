"""Source-only own-agent lifecycle boundary guards; never invoke native SCM."""
from pathlib import Path
import re
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]


def source(name):
    return (ROOT / name).read_text()


class OwnServiceRestartSourceTests(unittest.TestCase):
    def test_restart_has_fixed_one_handle_and_one_control_each(self):
        text = source("internal/windowsservice/restart.go")
        self.assertEqual(text.count("b.Open("), 1)
        self.assertIn("b.Open(restartAccess)", text)
        self.assertEqual(text.count("s.Stop()"), 1)
        self.assertEqual(text.count("s.Start()"), 1)
        self.assertEqual(text.count("s.Close()"), 1)
        for forbidden in ("s.Delete(", "b.Create(", "exec.Command", "go func", "ApplyStart(", "ApplyStop(", "time.Sleep", "SetAutomatic", "Write("):
            self.assertNotIn(forbidden, text)
        self.assertIn("snapshot.State == Running && snapshot.ProcessID == 0", text)
        self.assertIn("snapshot.ServiceSID != r.ServiceSID", text)
        self.assertIn("!reflect.DeepEqual(snapshot.Configuration, expected)", text)
        self.assertIn("hash != r.ExecutableSHA256", text)

    def test_native_access_does_not_broaden_security(self):
        text = source("internal/windowsservice/native_windows.go")
        rights = text[text.index("func serviceAccessRights"):text.index("func (windowsBackend) Open")]
        base = re.search(r"rights := uint32\(([^)]+)\)", rights).group(1)
        self.assertEqual(base.strip(), "windows.SERVICE_QUERY_CONFIG | windows.SERVICE_QUERY_STATUS")
        restart = re.search(r"case restartAccess:\s*(.*?)\s*case deleteAccess:", rights, re.S).group(1)
        self.assertEqual(restart.strip(), "rights |= windows.SERVICE_START | windows.SERVICE_STOP")
        opened = text[text.index("func (windowsBackend) Open"):text.index("func (windowsBackend) Create")]
        self.assertIn("openSCM(windows.SC_MANAGER_CONNECT)", opened)
        self.assertIn("windows.StringToUTF16Ptr(Name)", opened)
        self.assertIn("windows.CloseServiceHandle(scm)", opened)
        self.assertIn("err = errors.Join(err, closeErr)", opened)
        for forbidden in ("ALL_ACCESS", "LockServiceDatabase", "ChangeService", "AdjustToken", "SetSecurity", "CreateFile", "TerminateProcess"):
            self.assertNotIn(forbidden, opened + rights)

    def test_native_rights_guard_rejects_privilege_broadening(self):
        original = source("internal/windowsservice/native_windows.go")
        for old, new in (
            ("rights := uint32(windows.SERVICE_QUERY_CONFIG | windows.SERVICE_QUERY_STATUS)",
             "rights := uint32(windows.SERVICE_QUERY_CONFIG | windows.SERVICE_QUERY_STATUS | windows.SERVICE_ENUMERATE_DEPENDENTS)"),
            ("rights |= windows.SERVICE_START | windows.SERVICE_STOP", "rights |= windows.SERVICE_START | windows.SERVICE_STOP | windows.SERVICE_CHANGE_CONFIG"),
            ("openSCM(windows.SC_MANAGER_CONNECT)", "openSCM(windows.SC_MANAGER_ALL_ACCESS)"),
        ):
            self.assertIn(old, original)
            with mock.patch(__name__ + ".source", return_value=original.replace(old, new, 1)):
                with self.assertRaises(AssertionError):
                    self.test_native_access_does_not_broaden_security()

    def test_cli_receipt_paths_share_existing_lease(self):
        text = source("cmd/windows-service/operation_windows.go")
        self.assertNotIn("loadReceipt", text)
        self.assertIn("return withReceiptLease(ctx, openReceiptStore", text)
        self.assertIn("nativeReceiptOperation(ctx, r, receipt, lease, out, stderr)", text)
        self.assertIn('case "start", "stop", "restart", "uninstall":', text)
        self.assertIn("restart: windowsservice.ApplyRestart", text)
        opener = text[text.index("func openReceiptStore"):text.index("func install(")]
        self.assertIn("windowsstate.Open(installerPath(layout), windowsagentconfig.Installer(false))", opener)
        self.assertNotIn("Close()", opener)
        lease = source("cmd/windows-service/lifecycle_lease.go")
        for forbidden in ("windowsstate.Open", "Write(", "Create(", "sync.Mutex", "LockFile", "os."):
            self.assertNotIn(forbidden, lease)
        self.assertLess(lease.index('store.Read("receipt.json")'), lease.index("result, err = perform(receipt, store)"))
        self.assertIn("releaseErr := joinLifecycleErrors(receiptLeaseFailure(store.Close()), lifecycleContextError(ctx))", lease)
        self.assertIn("verifyErr := joinLifecycleErrors(receiptLeaseFailure(store.Verify()), lifecycleContextError(ctx))", lease)

    def test_gui_removal_lease_outlives_observation_and_completion(self):
        native = source("cmd/windows-service/entry_setup_windows.go")
        self.assertIn("setupWizardUninstallWithLease(ctx, openReceiptStore", native)
        self.assertNotIn("loadReceipt", native)
        text = source("cmd/windows-service/setup_wizard.go")
        wrapper = text[text.index("func setupWizardUninstallWithLease"):text.index("func setupWizardUninstall(ctx")]
        self.assertIn("withReceiptLease(ctx, open", wrapper)
        self.assertIn("return retained.Service, nil", wrapper)
        self.assertIn("return nil, setupWizardUninstall", wrapper)
        self.assertIn("if err == nil && complete", wrapper)

    def test_setup_retains_original_journal_without_nested_open(self):
        text = source("cmd/windows-service/setup.go")
        self.assertEqual(text.count("admin.Close()"), 1)
        self.assertIn("if closeErr := joinLifecycleErrors(admin.Close(), lifecycleContextError(ctx)); closeErr != nil", text)
        self.assertEqual(text.count("admin.Verify()"), 2)
        self.assertIn('setupFailed("journal_close"', text)
        native = source("cmd/windows-service/read_setup_windows.go")
        update = native[native.index("updateReceipt: func"):native.index("ensureFreshScopes:")]
        self.assertIn('journal.Read("receipt.json")', update)
        self.assertIn('journal.Write("receipt.json", next)', update)
        self.assertIn("return journal.Verify()", update)
        self.assertNotIn("windowsstate.Open", update)
        self.assertNotIn("Close()", update)

    def test_only_explicit_cli_restart_and_finite_partial_output(self):
        text = source("cmd/windows-service/main.go")
        self.assertIn('mode == "restart"', text)
        self.assertLess(text.index("context.WithTimeout(ctx, windowsservice.RestartTimeout)"), text.index("result, err := perform(ctx,"))
        self.assertIn("result.(windowsservice.RestartResult)", text)
        self.assertIn("writeLifecycleResult(out, partial)", text)
        self.assertIn("--restart --apply", text)
        setup = source("cmd/windows-service/entry_setup_windows.go")
        self.assertNotIn("ApplyRestart", setup)
        for file in ("cmd/windows-service/read_setup.go", "cmd/windows-service/pending.go", "internal/windowsservice/runtime.go"):
            self.assertNotIn("ApplyRestart", source(file))

    def test_restart_observation_and_clock_budgets_are_fixed(self):
        text = source("internal/windowsservice/restart.go")
        for pattern in (r"restartBudget\s*= 45 \* time.Second", r"restartPoll\s*= 250 \* time.Millisecond", r"restartMaxObservations\s*= 184"):
            self.assertRegex(text, pattern)
        self.assertIn("!now.Before(deadline)", text)
        self.assertIn("result.Observations >= restartMaxObservations", text)
        self.assertIn("clock.wait(ctx, delay)", text)
        self.assertIn("err = errors.Join(err, checkErr)", text)


if __name__ == "__main__":
    unittest.main()
