/** Invented manager acceptance/evaluation records only. No endpoint or native data. */
import { windowsDevice, windowsDeviceId, windowsNow } from './windows-inventory-fixture';
import type { WindowsContactIncident, WindowsContactView } from './windows-contact-types';
export const windowsContactSession = '2026-10-07T13:00:00Z';
export function windowsContactDevice() { return { ...windowsDevice(), capabilities: [{ id: 'agent_identity', name: 'Enrolled agent identity', status: 'supported' as const, detail: 'Invented current manager authority; no native acceptance' }] }; }
export function windowsContactIncident(recovered = false): WindowsContactIncident { return {
    id: 'wcontact_0000000000000001', kind: 'overdue-report', openedAt: '2026-10-07T11:55:00Z', lastConfirmedAt: '2026-10-07T11:57:00Z', lastAcceptedAt: '2026-10-07T11:51:59Z', sequence: 1,
    resolvedAt: recovered ? '2026-10-07T11:58:01Z' : null, recoveryAcceptedAt: recovered ? '2026-10-07T11:57:01Z' : null, recoverySequence: recovered ? 2 : 0, ...(recovered ? { closedReason: 'reports-resumed' as const } : {}),
}; }
export function windowsContactView(status: WindowsContactView['status'] = 'recent'): WindowsContactView { return {
    schemaVersion: 'tracebolt.windows-contact-view.v1', deviceId: windowsDeviceId, serverNow: windowsNow, certificateExpiresAt: '2026-11-07T12:00:00Z', status,
    evaluatedAt: windowsNow, lastAcceptedAt: status === 'pending' || status === 'overdue' ? '2026-10-07T11:57:59Z' : '2026-10-07T12:00:01Z', sequence: 3,
    incidents: status === 'overdue' ? [{ ...windowsContactIncident(), lastConfirmedAt: windowsNow }] : [windowsContactIncident(true)],
}; }
