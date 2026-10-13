/** Synthetic, public-safe metadata only; no native provider or endpoint reads. */
import type { MacInventoryPage, MacInventoryQuery, MacInventorySource, MacHardware } from './macos-inventory-types';
import { macInventorySources } from './macos-inventory-types';
import type { Device } from './types';
export const macInventoryDeviceId = `agent_${'9'.repeat(32)}`;
export const macInventoryNow = '2026-10-13T10:00:10Z';
export const macInventoryGeneration = `sample_${'a'.repeat(32)}`;
const source = (key: keyof typeof macInventorySources): MacInventorySource => ({ source: macInventorySources[key], quality: 'observed', reason: '' });
export const macInventoryQuery = (section: MacInventoryQuery['section'] = 'summary', offset = 0): MacInventoryQuery => ({ section, generationId: section === 'summary' ? '' : macInventoryGeneration, offset, limit: 50 });
export function macInventoryFixture(query: MacInventoryQuery = macInventoryQuery()): MacInventoryPage {
 const hardware: MacHardware = { ...source('hardware'), modelIdentifier: 'Mac14,12', physicalCPUs: 8, logicalCPUs: 8, memoryCapacityBytes: 17179869184 };
 const receipts = ['com.example.fixture.editor', 'com.example.fixture.helper', 'com.example.fixture.runtime'];
 const processes = [{ pid: 1, parentPid: 0, accountingName: 'fixture-init', nameQuality: 'observed' as const }, { pid: 42, parentPid: 1, accountingName: 'fixture-agent', nameQuality: 'observed' as const }];
 const interfaces = [{ name: 'en0', mtu: 1500, up: true, running: true, addresses: [{ ip: query.section === 'ipv6' ? '2001:db8::42' : '192.0.2.42', prefixBits: query.section === 'ipv6' ? 64 : 24 }] }];
 const total = query.section === 'receipts' ? receipts.length : query.section === 'processes' ? processes.length : query.section === 'ipv4' || query.section === 'ipv6' ? interfaces.length : 0;
 const end = Math.min(query.offset + query.limit, total);
 return { schemaVersion: 'tracebolt.macos-read-inventory-page.v1', deviceId: macInventoryDeviceId, section: query.section, status: 'fresh', serverNow: macInventoryNow, authorityUntil: '2026-10-13T10:30:00Z', generationId: macInventoryGeneration, sourceQuality: 'full', collectedAt: '2026-10-13T10:00:00Z', expiresAt: '2026-10-14T10:00:00Z', sources: { hardware: source('hardware'), receipts: source('receipts'), processes: source('processes'), ipv4: source('ipv4'), ipv6: source('ipv6') }, hardware: query.section === 'hardware' ? hardware : null, receiptIds: query.section === 'receipts' ? receipts.slice(query.offset, end) : [], processes: query.section === 'processes' ? processes.slice(query.offset, end) : [], interfaces: query.section === 'ipv4' || query.section === 'ipv6' ? interfaces.slice(query.offset, end) : [], offset: query.offset, total, nextOffset: end < total ? end : null };
}
export function macInventoryDevice(configured = true): Device {
 const metric = { value: null, unit: '%', quality: 'unknown' as const, source: 'Synthetic Mac fixture', collectedAt: '2026-10-13T10:00:00Z' };
 return { id: macInventoryDeviceId, name: 'Synthetic Mac', platform: 'macos', os: 'macOS fixture', site: '', group: '', ip: null, status: 'unknown', source: 'lan', synthetic: false, lastSeen: macInventoryNow, agentVersion: 'source-fixture', cpu: metric, memory: metric, disk: { ...metric, value: 34, quality: 'healthy' }, uptime: '2h', tags: [], capabilities: configured ? [{ id: 'macos_inventory', name: 'macOS inventory', status: 'scope', detail: 'Fresh explicit inventory profile' }] : [], evidence: [], trend: [], caseIds: [], agentCertificate: { source: 'guided-enrollment', expiresAt: '2026-10-14T10:00:00Z', checkedAt: macInventoryNow } };
}
