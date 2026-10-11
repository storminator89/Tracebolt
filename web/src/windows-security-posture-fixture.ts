import { windowsView } from './windows-inventory-fixture';
import type { WindowsSecurityPosture } from './windows-security-posture-types';
export function windowsSecurityPosture(): WindowsSecurityPosture {
    const snapshot = windowsView().snapshot!;
    return { schemaVersion: 'tracebolt.windows-security-posture.v1', scope: 'windows-security-posture-v1', grantId: '6'.repeat(32), generationId: snapshot.generationId, collectedAt: snapshot.collectedAt,
        defender: { quality: 'observed', reason: '', mode: 'normal', serviceEnabled: 'on', antivirusEnabled: 'on', realTimeProtectionEnabled: 'on', signatureVersion: '1.437.1234.0', signatureAgeDays: 1 },
        firewall: { quality: 'partial', reason: 'windows_security_posture_partial_result', profiles: [{ profile: 'domain', active: 'off', enabled: 'on' }, { profile: 'private', active: 'on', enabled: 'on' }, { profile: 'public', active: 'unknown', enabled: 'unknown' }] },
    };
}
export const windowsSecurityPostureView = () => ({ ...windowsView(), securityPosture: windowsSecurityPosture() });
