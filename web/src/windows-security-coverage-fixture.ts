import { windowsView } from './windows-inventory-fixture';
import type { WindowsSecurityCoverage } from './windows-security-coverage-types';
export function windowsSecurityCoverage(): WindowsSecurityCoverage {
    const snapshot = windowsView().snapshot!;
    return { schemaVersion: 'tracebolt.windows-security-coverage.v1', scope: 'windows-security-coverage-v1', grantId: 'd5'.repeat(16), generationId: snapshot.generationId, collectedAt: snapshot.collectedAt,
        antivirus: { quality: 'observed', reason: '', reportedCount: 2, rows: [{ index: 0, name: 'Example Antivirus', state: 'on', signatureStatus: 'up-to-date' }, { index: 1, name: 'Example Secondary Antivirus', state: 'snoozed', signatureStatus: 'out-of-date' }], truncated: false },
        tpm: { quality: 'observed', reason: '', presence: 'present', version: '2.0' },
    };
}
export const windowsSecurityCoverageView = () => ({ ...windowsView(), securityCoverage: windowsSecurityCoverage() });
