"""Pure source boundary checks. Never builds or runs a native test."""
from pathlib import Path
import unittest
ROOT = Path(__file__).resolve().parents[2]
class FreshConPTYSourceBoundary(unittest.TestCase):
    def test_native_entries_require_windows_and_nondefault_tag(self):
        for name in ('fresh_native_windows_test.go', 'fresh_pty_windows_test.go'):
            raw = (ROOT / 'cmd/windows-service' / name).read_text()
            self.assertTrue(raw.startswith('//go:build windows && tracebolt_fresh_native\n'))
        helper=(ROOT/'internal/windowsacceptance/native/fresh_support_windows.go').read_text()
        self.assertTrue(helper.startswith('//go:build windows && tracebolt_fresh_native\n'))
    def test_ordinary_workflows_and_cli_have_no_native_entry(self):
        for p in (ROOT/'.github/workflows').glob('*.yml'):
            if p.name != 'windows-fresh-conpty-acceptance.yml':
                self.assertNotIn('tracebolt_fresh_native', p.read_text())
        for name in ('main.go', 'operation_windows.go'):
            self.assertNotIn('freshChildMain', (ROOT/'cmd/windows-service'/name).read_text())
    def test_real_coordinator_and_distinct_disposal_contract(self):
        raw=(ROOT/'cmd/windows-service/fresh_native_windows_test.go').read_text()
        self.assertIn('installReadObservation(ctx,',raw)
        self.assertIn('yes("SYNTHETIC_CONSOLE")',raw)
        self.assertIn('yes("STOP_OWNED_SERVICE")',raw)
        self.assertIn('yes("RETAIN_FOR_VM_DISPOSAL")',raw)
        self.assertNotIn('d.Prepare(',raw)
        self.assertNotIn('d.Claim(',raw)
        self.assertNotIn('d.ConfigureCapabilities(',raw)
    def test_bootstrap_test_store_accepts_public_bootstrap_only(self):
        raw=(ROOT/'cmd/windows-service/fresh_native_windows_test.go').read_text()
        self.assertIn('Names: []string{"bootstrap.json"}',raw)
        self.assertNotIn('Write("invitation',raw)
    def test_child_launch_uses_owned_job_and_no_shell(self):
        raw=(ROOT/'cmd/windows-service/fresh_pty_windows_test.go').read_text()
        self.assertIn('windows.CREATE_SUSPENDED',raw)
        self.assertLess(raw.index('windows.AssignProcessToJobObject'),raw.index('windows.ResumeThread'))
        self.assertNotIn('exec.Command(',raw)
        self.assertIn('sort.Slice(entries',raw)
    def test_production_hidden_input_remains_console_only(self):
        raw=(ROOT/'internal/windowsconsole/native_windows.go').read_text()
        self.assertIn('"CONIN$"',raw)
        self.assertIn('ReadConsoleInputExW',raw)
        self.assertNotIn('TRACEBOLT_FRESH',raw)

    def test_diagnostics_observe_before_cleanup_without_native_calls(self):
        harness=(ROOT/'cmd/windows-service/fresh_native_windows_test.go').read_text()
        self.assertLess(harness.index('r.NaturalChildExit = child.naturalExit()'),harness.index('reaped, closed := child.Close()'))
        raw=(ROOT/'cmd/windows-service/fresh_pty_windows_test.go').read_text()
        observation=raw.split('func (p *freshPTY) naturalExit() string {',1)[1].split('func (p *freshPTY) Close()',1)[0]
        self.assertIn('case <-p.processDone:',observation)
        self.assertIn('p.closed',observation)
        for forbidden in ('windows.', 'time.', 'processErr.Error', 'strconv.', 'fmt.'):
            self.assertNotIn(forbidden,observation)
        self.assertEqual(harness.count('freshReadReceipt(layout)'),3)
        self.assertIn('r.SessionOutcome, e = child.Run(',harness)
