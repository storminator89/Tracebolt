"""Bounded source regression only; never probes the host or runs Go/Windows."""
from pathlib import Path, PureWindowsPath
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "cmd/windows-service/current_setup_acceptance_native_windows_test.go"


class OptionalAbsenceSource(unittest.TestCase):
    def test_exact_implemented_namespace_tables_and_source_bindings(self):
        source = SOURCE.read_text()
        body = source.split("func currentSetupOptionalPaths(", 1)[1].split("func currentSetupOptionalServices", 1)[0]
        groups = re.findall(r'for _, (?:name|suffix) := range \[\]string\{([^}]+)\}', body)
        groups = [re.findall(r'"([^"\n]+)"', group) for group in groups]
        self.assertEqual(groups, [
            ["Tracebolt-action-broker", "Tracebolt-action-broker-setup"],
            ["windows-update-executor", "windows-software-executor", "windows-software-package", "windows-managed-msi-service", "windows-managed-msi-package", "windows-mutation-fence", "windows-update-service"],
            ["tracebolt-windows-action-broker.exe", "tracebolt-windows-update-executor.exe", "tracebolt-windows-software-executor.exe", "tracebolt-windows-managed-msi-service.exe", "tracebolt-windows-update-service.exe"],
            ["event-content", "updates", "update-job-relay", "action-relay", "user-software", "software-job-relay", "managed-msi-relay", "background-update-job-relay"]])
        for binding in ('filepath.Join(l.ProgramData, name)', 'filepath.Join(filepath.Dir(l.StateRoot), name)',
                        'filepath.Join(l.ProgramFiles, "Tracebolt", name)', 'l.StateRoot+"-"+suffix'):
            self.assertIn(binding, body)
        # Independent source checks prevent a guessed path from satisfying the
        # table regression. Reusable v3 retains the existing managed namespace.
        contracts = {
            "internal/windowsmanagedmsiipc/config.go": ("windows-managed-msi-service", "TraceboltWindowsDeployment"),
            "internal/windowspackage/managed_msi.go": ("windows-managed-msi-package",),
            "internal/windowspackage/managed_msi_service_image.go": ("tracebolt-windows-managed-msi-service.exe",),
            "internal/windowssoftwaresetup/setup.go": ("windows-software-executor", "software-job-relay", "tracebolt-windows-software-executor.exe"),
            "internal/windowspackage/prepared_msi.go": ("windows-software-package",),
            "internal/windowsmutationfence/fence.go": ("windows-mutation-fence",),
            "internal/lanclient/windows_managed_msi_job_grant.go": ("-managed-msi-relay",),
            "internal/windowsaction/contract.go": ("TraceboltWindowsActionBroker",),
            "internal/windowsupdateipc/config.go": ("windows-update-service", "TraceboltWindowsCachedUpdate"),
            "internal/windowsupdatesetup/setup.go": ("windows-update-service", "-background-update-job-relay", "UpdateServiceImageName"),
            "internal/windowspackage/update_executor_image.go": ("tracebolt-windows-update-service.exe",),
            "internal/lanclient/windows_update_job_grant.go": ("-background-update-job-relay",),
        }
        for path, names in contracts.items():
            text = (ROOT / path).read_text()
            for name in names:
                self.assertIn(name, text, path)
        data, program = PureWindowsPath("C:/ProgramData"), PureWindowsPath("C:/Program Files")
        state = data / "Tracebolt/windows-agent"
        paths = ([data / n for n in groups[0]] + [state.parent / n for n in groups[1]] +
                 [program / "Tracebolt" / n for n in groups[2]] + [PureWindowsPath(str(state) + "-" + n) for n in groups[3]])
        self.assertEqual(len(paths), len(set(paths)))
        self.assertIn(data / "Tracebolt/windows-managed-msi-service", paths)
        self.assertIn(data / "Tracebolt/windows-software-package", paths)
        self.assertIn(data / "Tracebolt/windows-update-service", paths)
        self.assertIn(PureWindowsPath(str(state) + "-background-update-job-relay"), paths)
        services = source.split("func currentSetupOptionalServices()", 1)[1].split("func currentSetupOptionalsOffWith", 1)[0]
        self.assertIn('return []string{"TraceboltWindowsActionBroker", "TraceboltWindowsDeployment", "TraceboltWindowsCachedUpdate"}', services)

    def test_read_only_fail_closed_probes_and_each_injected_presence_rejection_exist(self):
        source = SOURCE.read_text()
        guard = source.split("func currentSetupOptionalsOffWith", 1)[1].split("func (g *setupGUI) currentConsentObserved", 1)[0]
        for required in ('if !pathAbsent(path)', 'if !serviceAbsent(name)', 'return setupgate.ErrGuard',
                         'os.Lstat(path)', 'errors.Is(e, os.ErrNotExist)', 'windows.SC_MANAGER_CONNECT',
                         'windows.OpenService(scm, setupUTF(name), windows.SERVICE_QUERY_STATUS)',
                         'errors.Is(e, windows.ERROR_SERVICE_DOES_NOT_EXIST)',
                         'func TestCurrentSetupOptionalsRejectEveryPresence',
                         'func(p string) bool { return p != path }', 'func(n string) bool { return n != name }'):
            self.assertIn(required, guard)
        for forbidden in ('CreateService', 'StartService', 'ControlService', 'DeleteService', 'MsiInstall', 'exec.Command', 'os.Remove'):
            self.assertNotIn(forbidden, guard)
        self.assertEqual(source.count('currentSetupOptionalsOff(l) != nil'), 2)


if __name__ == "__main__":
    unittest.main()
