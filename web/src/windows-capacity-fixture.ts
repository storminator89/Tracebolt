/** Invented manager policy/evaluation records only; no endpoint or native data. */
import { windowsContactDevice } from './windows-contact-fixture';
import { windowsDeviceId, windowsNow } from './windows-inventory-fixture';
import type { WindowsCapacityIncident, WindowsCapacityView } from './windows-capacity-types';
export const windowsCapacitySession = '2026-10-07T13:00:00Z';
export const windowsCapacityDevice = windowsContactDevice;
export function windowsCapacityIncident(closed: 'open' | 'recovered' | 'policy-changed' = 'open'): WindowsCapacityIncident { return {
    id: 'wcapacity_0000000000000001', policyRevision: 1, thresholdPercent: 90,
    openedAt: '2026-10-07T11:55:00Z', lastConfirmedAt: '2026-10-07T11:57:00Z',
    openingObservation: { value: 94, collectedAt: '2026-10-07T11:54:00Z', receivedAt: '2026-10-07T11:54:01Z', sequence: 2 },
    lastHighObservation: { value: 92, collectedAt: '2026-10-07T11:56:00Z', receivedAt: '2026-10-07T11:56:01Z', sequence: 4 },
    resolvedAt: closed === 'open' ? null : '2026-10-07T11:58:30Z',
    recoveryObservation: closed === 'recovered' ? { value: 85, collectedAt: '2026-10-07T11:57:30Z', receivedAt: '2026-10-07T11:57:31Z', sequence: 5 } : null,
    closedReason: closed === 'open' ? '' : closed === 'recovered' ? 'within-policy' : 'policy-changed',
}; }
export function windowsCapacityView(status: WindowsCapacityView['status'] = 'disabled'): WindowsCapacityView { return {
    schemaVersion: 'tracebolt.windows-capacity-view.v1', deviceId: windowsDeviceId, serverNow: windowsNow, certificateExpiresAt: '2026-11-07T12:00:00Z',
    policy: { enabled: status !== 'disabled', thresholdPercent: 90, revision: status === 'disabled' ? 0 : 1 }, status,
    evaluatedAt: status === 'disabled' ? null : windowsNow,
    observation: status === 'unknown' || status === 'disabled' ? null : { value: status === 'within-policy' ? 61 : 94, collectedAt: '2026-10-07T12:00:00Z', receivedAt: '2026-10-07T12:00:01Z', sequence: 7 },
    incidents: status === 'pressure' ? [windowsCapacityIncident()] : status === 'within-policy' ? [windowsCapacityIncident('recovered')] : [],
}; }
