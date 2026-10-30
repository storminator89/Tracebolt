"""Bind the candidate's unchanged package bytes to one source and CI run."""
import hashlib
import json
import pathlib
import sys

release = pathlib.Path(sys.argv[1])
commit, run = sys.argv[2:4]
if len(commit) != 40 or any(c not in '0123456789abcdef' for c in commit) or not run.isdigit():
    raise SystemExit('invalid source or workflow identity')
artifacts = []
for name, platform in [('windows-rust.zip', 'windows-amd64'),
                       ('tracebolt-windows-agent.exe', 'windows-amd64'),
                       ('manager-linux-amd64.tar.gz', 'linux-amd64')]:
    raw = (release / name).read_bytes()
    artifacts.append({'name': name, 'platform': platform, 'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)})
manifest = {
    'schemaVersion': 'tracebolt.integrated-rust-test-release.v1',
    'sourceCommit': commit,
    'components': {'managerSourceCommit': commit, 'frontendSourceCommit': commit,
                   'agentSourceCommit': commit, 'agentProfile': 'rust-windows-basic-v1'},
    'compatibility': {
        'path': '/v1/windows/rust-basic-capabilities',
        'schemaVersion': 'tracebolt.rust-basic-manager-capabilities.v1',
        'enrollmentProtocol': 'tracebolt.enrollment.v2',
        'telemetryFrame': 'tracebolt.agent-telemetry.windows.v1',
        'receiptSchema': 'tracebolt.agent-receipt.v1',
        'requiredAutomaticRegistration': True,
        'checkBeforePersistentInitialization': True,
    },
    'workflowRun': f'https://github.com/storminator89/Tracebolt/actions/runs/{run}',
    'artifacts': artifacts,
    'profile': 'windows-inventory-v1',
    'collectorSubset': ['cpu', 'physical-memory', 'system-volume-capacity', 'uptime'],
    'enrollment': {'mode': 'automatic-pending-operator-approval', 'transport': 'tls', 'renewal': False},
    'evidence': ['rust-contract-tests', 'go-enrollment-api-tests', 'linux-manager-frontend-build',
                 'windows-server-2025-installed-service-protocol-fixture'],
    'openGates': ['real-linux-manager-browser-end-to-end', 'windows-11-native', 'os-reboot',
                  'certificate-renewal', 'upgrade-repair', 'authenticode-signing'],
}
(release / 'release-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
