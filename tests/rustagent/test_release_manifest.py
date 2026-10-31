"""Inert source-artifact tests; these never publish, enroll, or install."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ReleaseManifestTests(unittest.TestCase):
    def test_exact_components_contract_and_unchanged_artifact_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            names = ['windows-rust.zip', 'tracebolt-windows-agent.exe', 'manager-linux-amd64.tar.gz']
            fixtures = {name: ('inert synthetic ' + name).encode() for name in names}
            for name, raw in fixtures.items():
                (directory / name).write_bytes(raw)
            commit = 'a' * 40
            subprocess.run([sys.executable, '-B', str(ROOT / 'deploy/windows-rust/write-release-manifest.py'),
                            str(directory), commit, '123'], check=True, capture_output=True)
            value = json.loads((directory / 'release-manifest.json').read_text())
            self.assertEqual(value['components'], {'managerSourceCommit': commit, 'frontendSourceCommit': commit,
                                                   'agentSourceCommit': commit, 'agentProfile': 'rust-windows-basic-v1'})
            self.assertEqual(value['compatibility'], {
                'path': '/v1/windows/rust-basic-capabilities',
                'schemaVersion': 'tracebolt.rust-basic-manager-capabilities.v1',
                'enrollmentProtocol': 'tracebolt.enrollment.v2',
                'telemetryFrame': 'tracebolt.agent-telemetry.windows.v1',
                'receiptSchema': 'tracebolt.agent-receipt.v1',
                'requiredAutomaticRegistration': True, 'checkBeforePersistentInitialization': True})
            self.assertEqual(value['profile'], 'windows-inventory-v1')
            for artifact in value['artifacts']:
                raw = fixtures[artifact['name']]
                self.assertEqual(artifact['sha256'], hashlib.sha256(raw).hexdigest())
                self.assertEqual(artifact['bytes'], len(raw))
                self.assertEqual((directory / artifact['name']).read_bytes(), raw)


if __name__ == '__main__':
    unittest.main()
