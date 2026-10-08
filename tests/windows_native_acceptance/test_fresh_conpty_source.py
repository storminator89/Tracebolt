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
        self.assertIn('sort.Slice(entries',(ROOT/'cmd/windows-service/fresh_environment_test.go').read_text())
    def test_production_hidden_input_remains_console_only(self):
        raw=(ROOT/'internal/windowsconsole/native_windows.go').read_text()
        self.assertIn('"CONIN$"',raw)
        self.assertIn('ReadConsoleInputExW',raw)
        self.assertNotIn('TRACEBOLT_FRESH',raw)

    def test_diagnostics_observe_before_cleanup_without_native_calls(self):
        harness=(ROOT/'cmd/windows-service/fresh_native_windows_test.go').read_text()
        self.assertLess(harness.index('r.NaturalChildExit, r.ChildFailureStage, r.ChildFailureCategory = child.naturalDiagnostic()'),harness.index('reaped, closed := child.Close()'))
        raw=(ROOT/'cmd/windows-service/fresh_pty_windows_test.go').read_text()
        observation=raw.split('func (p *freshPTY) naturalDiagnostic() (exit, stage, category string) {',1)[1].split('func (p *freshPTY) Close()',1)[0]
        self.assertIn('case <-p.processDone:',observation)
        self.assertIn('p.closed',observation)
        for forbidden in ('windows.', 'time.', 'processErr.Error', 'strconv.', 'fmt.'):
            self.assertNotIn(forbidden,observation)
        self.assertEqual(harness.count('freshReadReceipt(layout)'),3)
        self.assertIn('r.SessionOutcome, e = child.Run(',harness)
        self.assertIn('r.OutputRejection = guard.RejectionReason()',harness)

    def test_output_rejection_allowlist_matches_go(self):
        raw=(ROOT/'internal/windowsacceptance/freshgate/output_rejection.go').read_text()
        import re
        values=set(re.findall(r'OutputRejection\s*=\s*"([a-z_]+)"',raw))
        runner=(ROOT/'tests/windows_native_acceptance/run_fresh_conpty.py').read_text()
        field=runner.split('"outputRejection":{',1)[1].split('}',1)[0]
        self.assertEqual(values,set(re.findall(r'"([a-z_]+)"',field)))

    def test_child_diagnostic_vocab_covers_all_location_labels(self):
        import re
        runner=(ROOT/'tests/windows_native_acceptance/fresh_child_diagnostics.py').read_text()
        known=set(re.findall(r"\('([a-z_]+)', '[a-z_]+'\)",runner))
        for name in ('setup.go','read_setup.go','read_setup_windows.go','operation_windows.go','fresh_native_windows_test.go'):
            raw=(ROOT/'cmd/windows-service'/name).read_text()
            observed=set(re.findall(r'(?:stage\s*:?=\s*|setupFailed(?:Category)?\()"([a-z_]+)"',raw))
            self.assertTrue(observed<=known,(name,observed-known))

    def test_authorization_environment_and_child_argv_are_unchanged(self):
        import re
        harness=(ROOT/'cmd/windows-service/fresh_native_windows_test.go').read_text()
        child=(ROOT/'cmd/windows-service/fresh_pty_windows_test.go').read_text()
        authorization=harness.split('func freshAuthorization()',1)[1].split('func freshConsent()',1)[0]
        builder=(ROOT/'cmd/windows-service/fresh_environment_test.go').read_text()
        forwarded=set(re.findall(r'"([A-Z][A-Z_]+)"',builder.split('entries :=',1)[0]))
        required=set(re.findall(r'get\("([A-Z][A-Z_]+)"\)',authorization))
        required.update('TRACEBOLT_FRESH_APPROVE_'+x for x in re.findall(r'yes\("([A-Z_]+)"\)',authorization))
        self.assertTrue(required<=forwarded,required-forwarded)
        for arg in ('-test.run=^TestFreshReadConPTYNative$','-test.count=1','-test.timeout=14m'):
            self.assertIn(arg,harness);self.assertIn(arg,child)
        self.assertIn('len(os.Args) != 4',harness)
        self.assertIn('syscall.EscapeArg(exe)',child)
        self.assertIn('TRACEBOLT_FRESH_BOOTSTRAP=',builder)
        self.assertIn('windows.CreateProcess(app, command, nil, nil, false,',child)

    def test_systemdrive_is_derived_once_from_os_api_without_inherited_override(self):
        child=(ROOT/'cmd/windows-service/fresh_pty_windows_test.go').read_text()
        builder=(ROOT/'cmd/windows-service/fresh_environment_test.go').read_text().split('func Test',1)[0]
        self.assertIn('freshChildEnvironmentEntries(bootstrap, windows.GetSystemWindowsDirectory, os.Getenv)',child)
        self.assertIn('windowsservice.SystemDriveFromWindowsDirectory(directory)',builder)
        self.assertEqual(builder.count('"SystemDrive=" + drive'),1)
        self.assertIn('return nil, freshgate.ErrGuard',builder)
        keys=builder.split('keys := []string{',1)[1].split('}',1)[0]
        for forbidden in ('"SystemDrive"','"ProgramData"','"ProgramFiles"','"PATH"','"GITHUB_TOKEN"'):
            self.assertNotIn(forbidden,keys)
        for forbidden in ('os.Environ(','.Error()', 'fmt.', 'log.'):
            self.assertNotIn(forbidden,builder)

    def test_failure_decode_is_snapshot_only_and_before_teardown(self):
        harness=(ROOT/'cmd/windows-service/fresh_native_windows_test.go').read_text()
        self.assertLess(harness.index('child.naturalDiagnostic()'),harness.index('reaped, closed := child.Close()'))
        child=(ROOT/'cmd/windows-service/fresh_pty_windows_test.go').read_text()
        block=child.split('func (p *freshPTY) naturalDiagnostic()',1)[1].split('func (p *freshPTY) Close()',1)[0]
        self.assertIn('case <-p.processDone:',block)
        self.assertIn('p.closed',block)
        self.assertIn('p.processErr != nil',block)
        for forbidden in ('windows.','time.','.Error(', 'fmt.', 'os.'):
            self.assertNotIn(forbidden,block)
        self.assertIn('freshgate.DecodeChildFailureExit(p.processExit)',block)

    def test_write_failures_use_fixed_reviewed_category(self):
        setup=(ROOT/'cmd/windows-service/read_setup_windows.go').read_text()
        child=(ROOT/'cmd/windows-service/fresh_native_windows_test.go').read_text()
        self.assertIn('setupFailedCategory("fresh_disclosure", "failed", err)',setup)
        self.assertIn('setupFailedCategory("success_write", "failed", e)',child)
