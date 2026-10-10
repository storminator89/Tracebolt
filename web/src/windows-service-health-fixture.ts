/** Invented operator-only service policies, source samples and episodes. No native data. */
import { windowsDeviceId, windowsNow } from './windows-inventory-fixture';
import type { WindowsServiceHealthIncident, WindowsServiceHealthInventory, WindowsServiceHealthStatus, WindowsServiceHealthView } from './windows-service-health-types';
export function windowsServiceHealthInventory(): WindowsServiceHealthInventory { return {
    collectedAt: '2026-10-07T12:00:00Z', receivedAt: '2026-10-07T12:00:01Z', sequence: 7, quality: 'healthy', complete: true, truncated: false, countExact: true, observedCount: 3,
    services: [{ name: 'FixtureService', displayName: 'Fixture Background Service', state: 'running' }, { name: 'Spooler', displayName: 'Print Spooler', state: 'stopped' }, { name: 'spooler', displayName: 'Separate case-sensitive selector', state: 'paused' }],
}; }
export function windowsServiceHealthIncident(closed: 'open' | 'running' | 'policy-changed' = 'open'): WindowsServiceHealthIncident { return {
    id: 'wservice_0000000000000001', name: 'FixtureService', policyRevision: 1,
    openedAt: '2026-10-07T11:55:00Z', lastConfirmedAt: '2026-10-07T11:57:00Z',
    openingObservation: { state: 'stopped', collectedAt: '2026-10-07T11:54:00Z', receivedAt: '2026-10-07T11:54:01Z', sequence: 2 },
    lastBadObservation: { state: 'paused', collectedAt: '2026-10-07T11:56:00Z', receivedAt: '2026-10-07T11:56:01Z', sequence: 4 },
    resolvedAt: closed === 'open' ? null : '2026-10-07T11:58:30Z',
    recoveryObservation: closed === 'running' ? { state: 'running', collectedAt: '2026-10-07T11:57:30Z', receivedAt: '2026-10-07T11:57:31Z', sequence: 5 } : null,
    closedReason: closed === 'open' ? '' : closed,
}; }
export function windowsServiceHealthView(status: WindowsServiceHealthStatus = 'disabled'): WindowsServiceHealthView { const value: WindowsServiceHealthView = {
    schemaVersion: 'tracebolt.windows-service-view.v1', deviceId: windowsDeviceId, serverNow: windowsNow, certificateExpiresAt: '2026-11-07T12:00:00Z',
    policy: { enabled: status !== 'disabled', services: status === 'disabled' ? [] : ['FixtureService'], revision: status === 'disabled' ? 0 : 1 }, status,
    evaluatedAt: status === 'disabled' ? null : windowsNow,
    checks: status === 'disabled' ? [] : [{ name: 'FixtureService', status, observation: status === 'unknown' ? null : { state: status === 'running' ? 'running' : 'stopped', collectedAt: '2026-10-07T12:00:00Z', receivedAt: '2026-10-07T12:00:01Z', sequence: 7 } }],
    incidents: status === 'attention' ? [windowsServiceHealthIncident()] : status === 'running' ? [windowsServiceHealthIncident('running')] : [], inventory: windowsServiceHealthInventory(),
}; if (status === 'pending' || status === 'attention') value.inventory!.services[0].state = 'stopped'; return value; }
