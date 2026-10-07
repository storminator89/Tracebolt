import type { WindowsInventorySection, WindowsInventorySnapshot, WindowsInventoryView } from './windows-inventory-types';
import type { Device } from './types';
export const windowsDeviceId = `agent_${'7'.repeat(32)}`;
export const windowsNow = '2026-10-07T12:00:10Z';
export function windowsSection<T>(rows: T[]): WindowsInventorySection<T> { return { source: 'Synthetic Windows API fixture', scope: 'Synthetic caller-visible scope; no native collection', quality: 'healthy', observedCount: rows.length, countExact: true, complete: true, truncated: false, rows }; }
export function windowsSnapshot(): WindowsInventorySnapshot { return {
    schemaVersion: 'tracebolt.windows-inventory.v1', collectionProfile: 'windows-inventory-v1', generationId: `sample_${'a'.repeat(32)}`, collectedAt: '2026-10-07T12:00:00Z',
    hostname: windowsSection([{ value: 'fixture-windows' }]), processes: windowsSection([{ pid: 44, parentPid: 4, name: 'fixture.exe', threads: 3 }]),
    services: windowsSection([{ name: 'FixtureService', displayName: 'Fixture Service', state: 'running', pid: 44 }]), software: windowsSection([{ name: 'Synthetic Application', version: '1.2.3', publisher: 'Fixture Publisher', registryView: '64' }]),
    network: windowsSection([{ index: 4, name: 'Fixture Ethernet', address: '192.0.2.40', prefixLength: 24 }, { index: 4, name: 'Fixture Ethernet', address: '2001:db8::40', prefixLength: 64 }]),
}; }
export function windowsView(): WindowsInventoryView { return { schemaVersion: 'tracebolt.windows-inventory-view.v1', deviceId: windowsDeviceId, collectionProfile: 'windows-inventory-v1', serverNow: windowsNow, maxAgeSeconds: 120, status: 'fresh', sequence: 1, receivedAt: '2026-10-07T12:00:01Z', snapshot: windowsSnapshot() }; }
export function windowsDevice(): Device { const metric = { value: 24, unit: '%', quality: 'healthy' as const, source: 'Synthetic Windows metric', collectedAt: '2026-10-07T12:00:00Z' }; return { id: windowsDeviceId, name: windowsDeviceId, platform: 'windows', os: 'Windows fixture', source: 'lan', synthetic: false, status: 'healthy', site: '', group: '', ip: null, lastSeen: metric.collectedAt, agentVersion: 'source-fixture', cpu: metric, memory: { ...metric, value: 51 }, disk: { ...metric, value: 61 }, uptime: '3h', tags: [], capabilities: [], evidence: [], trend: [], caseIds: [], agentCertificate: { source: 'guided-enrollment', expiresAt: '2026-11-07T12:00:00Z', checkedAt: windowsNow } }; }
