"""Pure finite-output/source checks; never launch a Windows executable."""
import io
import contextlib
import json
import subprocess
from unittest import mock
from pathlib import Path
import unittest
import run_knownfolder_probe as probe

ROOT = Path(__file__).resolve().parents[2]


def events(summary=None):
    if summary is None:
        summary = ('baseline_pf=valid baseline_pd=unsafe_root baseline_pf_equal=true '
                   'baseline_pd_equal=false systemdrive_pf=valid systemdrive_pd=valid '
                   'systemdrive_pf_equal=true systemdrive_pd_equal=true')
    package, test = probe.PACKAGE, probe.TEST
    return [dict(Action='start', Package=package), dict(Action='run', Package=package, Test=test),
            dict(Action='output', Package=package, Test=test,
                 Output='    knownfolder_probe_windows_test.go:99: ' + summary + '\n'),
            dict(Action='pass', Package=package, Test=test), dict(Action='pass', Package=package)]


def encode(items):
    return b''.join(json.dumps(item).encode() + b'\n' for item in items)


class KnownFolderProjection(unittest.TestCase):
    def test_finite_observation(self):
        result = probe.project(encode(events()))
        self.assertEqual(result['baseline_pd'], 'unsafe_root')
        self.assertEqual(result['systemdrive_pd_equal'], 'true')

    def test_baseline_can_succeed_without_claiming_reproduction(self):
        raw = encode(events()).replace(b'unsafe_root', b'valid').replace(b'baseline_pd_equal=false', b'baseline_pd_equal=true')
        self.assertEqual(probe.project(raw)['baseline_pd'], 'valid')

    def test_failure_and_malformed_events_are_withheld(self):
        valid = encode(events())
        bad = [b'', valid[:-1], valid + b'private path', valid.replace(b'unsafe_root',b'C:\\\\private'),
               valid.replace(b'baseline_pd_equal=false',b'baseline_pd_equal=true'),
               valid.replace(b'systemdrive_pd_equal=true',b'systemdrive_pd_equal=1'),
               valid.replace(b'"start"', b'"skip"'), valid.replace(probe.PACKAGE.encode(),b'other'),
               valid.replace(b'"Action": "start"',b'"Action": "start", "Action": "start"'),
               encode(events()[:-1]), encode(events()[:3]+events()[4:]), valid.replace(probe.TEST.encode(),b"OtherTest"), encode(events()[:3]+events()[2:]),
               encode(events()+[dict(Action='fail',Package=probe.PACKAGE)]),
               b'x' * (probe.MAX_OUTPUT+1)]
        for raw in bad:
            with self.subTest(raw=raw[:40]):
                with self.assertRaises((ValueError, TypeError, KeyError)):
                    probe.project(raw)

    def test_arbitrary_test_output_is_rejected(self):
        items = events()
        items.insert(2,dict(Action='output',Package=probe.PACKAGE,Test=probe.TEST,Output='private path\n'))
        with self.assertRaises(ValueError):
            probe.project(encode(items))

    def test_build_environment_is_normalized(self):
        with mock.patch.dict(probe.os.environ, {"TRACEBOLT_FRESH_APPROVE_SERVICES": "1", "GOFLAGS": "-race", "GOEXPERIMENT": "unknown", "GOENV": "private", "GOWORK": "private"}, clear=True):
            env = probe.probe_environment()
        self.assertNotIn("TRACEBOLT_FRESH_APPROVE_SERVICES", env)
        self.assertNotIn("GOFLAGS", env)
        self.assertNotIn("GOEXPERIMENT", env)
        self.assertEqual(env["GOENV"], "off")
        self.assertEqual(env["GOWORK"], "off")
        self.assertEqual(env["CGO_ENABLED"], "0")

    def test_capture_overflow_and_timeout(self):
        for overflow in (False, True):
            process = mock.Mock()
            process.stdout = io.BytesIO(b'x' * (probe.MAX_OUTPUT + 1) if overflow else b'')
            process.wait.side_effect = [0] if overflow else [subprocess.TimeoutExpired('fixed', 120), 0]
            with mock.patch.object(probe.subprocess, 'Popen', return_value=process):
                with self.assertRaises(ValueError):
                    probe.capture({})
            self.assertEqual(process.kill.called, not overflow)

    def test_main_withholds_deep_json_and_other_errors(self):
        for failure in (RecursionError('private path'), ValueError('private path')):
            out = io.StringIO()
            with mock.patch.object(probe.sys, 'platform', 'win32'), mock.patch.object(probe, 'capture', side_effect=failure), contextlib.redirect_stdout(out):
                self.assertEqual(probe.main(), 1)
            self.assertNotIn('private path', out.getvalue())
            self.assertTrue(out.getvalue().startswith('FAIL: KnownFolder'))

    def test_probe_has_separate_bounded_ordinary_workflow_step(self):
        raw = (ROOT/'.github/workflows/windows-service-source.yml').read_text()
        self.assertIn('python -I -B tests/security/run_knownfolder_probe.py', raw)
        step = raw.split('- name: Observe read-only KnownFolder',1)[1]
        self.assertIn('timeout-minutes: 3',step)
        self.assertNotIn('tracebolt_fresh_native',raw)
        self.assertNotIn('windows-native-acceptance',raw)

    def test_native_gate_is_not_reachable(self):
        raw = (ROOT/'internal/windowsservice/knownfolder_probe_windows_test.go').read_text()
        self.assertTrue(raw.startswith('//go:build windows\n'))
        self.assertEqual(raw.count('windows.KnownFolderPath('),4)
        self.assertEqual(raw.count('windows.KF_FLAG_DONT_VERIFY'),4)
        for forbidden in ('ResolveLayout(', 'OpenSCManager', 'CreateService', 'KF_FLAG_CREATE',
                          'TRACEBOLT_FRESH_', 'os.Environ(', 'os.Setenv(', 'fmt.Print', 'log.Print'):
            self.assertNotIn(forbidden,raw)
        self.assertIn('[]string{"SystemRoot", "WINDIR", "COMPUTERNAME"}',raw)
        self.assertIn('windows.GetSystemWindowsDirectory()',raw)
        harness = (ROOT/'cmd/windows-service/fresh_pty_windows_test.go').read_text()
        keys = harness.split('keys := []string{',1)[1].split('}',1)[0]
        self.assertTrue(keys.startswith('"SystemRoot", "WINDIR", "COMPUTERNAME", "GITHUB_SHA"'))
        for name in ('"SystemDrive"','"ProgramData"','"ProgramFiles"'):
            self.assertNotIn(name,keys)


if __name__ == '__main__':
    unittest.main()
