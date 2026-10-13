/** Synthetic, public-safe metadata only; no native provider or endpoint reads. */
import type { MacInventoryPage, MacInventoryQuery, MacInventorySource, MacHardware, MacInventoryLookupQuery } from './macos-inventory-types';
import { macInventorySources, macProcessMatches } from './macos-inventory-types';
import type { Device } from './types';
export const macInventoryDeviceId = `agent_${'9'.repeat(32)}`;
export const macInventoryNow = '2026-10-13T10:00:10Z';
export const macInventoryGeneration = `sample_${'a'.repeat(32)}`;
const source = (key: keyof typeof macInventorySources): MacInventorySource => ({ source: macInventorySources[key], quality: 'observed', reason: '' });
export const macInventoryQuery = (section: MacInventoryQuery['section'] = 'summary', offset = 0): MacInventoryQuery => ({ section, generationId: section === 'summary' ? '' : macInventoryGeneration, offset, limit: 50 });
export const macInventoryLookupQuery = (section: MacInventoryLookupQuery['section'] = 'receipts', search = '', offset = 0): MacInventoryLookupQuery => ({ schemaVersion: 'tracebolt.macos-read-inventory-query.v2', section, generationId: macInventoryGeneration, offset, limit: 50, search });
export function macInventoryFixture(query: MacInventoryQuery = macInventoryQuery()): MacInventoryPage {
 const hardware: MacHardware = { ...source('hardware'), modelIdentifier: 'Mac14,12', physicalCPUs: 8, logicalCPUs: 8, memoryCapacityBytes: 17179869184 };
 const receipts = ['com.example.fixture.editor', 'com.example.fixture.helper', 'com.example.fixture.runtime'];
 const processes = [{ pid: 1, parentPid: 0, accountingName: 'fixture-init', nameQuality: 'observed' as const }, { pid: 42, parentPid: 1, accountingName: 'fixture-agent', nameQuality: 'observed' as const }];
 const interfaces = [{ name: 'en0', mtu: 1500, up: true, running: true, addresses: [{ ip: query.section === 'ipv6' ? '2001:db8::42' : '192.0.2.42', prefixBits: query.section === 'ipv6' ? 64 : 24 }] }];
 const total = query.section === 'receipts' ? receipts.length : query.section === 'processes' ? processes.length : query.section === 'ipv4' || query.section === 'ipv6' ? interfaces.length : 0;
 const search = 'search' in query ? query.search : '', matchedReceipts = receipts.filter(row => row.toLowerCase().includes(search)), matchedProcesses = processes.filter(row => macProcessMatches(row, search));
 const matchingCount = query.section === 'receipts' ? matchedReceipts.length : query.section === 'processes' ? matchedProcesses.length : total;
 const end = Math.min(query.offset + query.limit, matchingCount);
 return { ...('search' in query ? { schemaVersion: 'tracebolt.macos-read-inventory-page.v2' as const, search, matchingCount } : { schemaVersion: 'tracebolt.macos-read-inventory-page.v1' as const }), deviceId: macInventoryDeviceId, section: query.section, status: 'fresh', serverNow: macInventoryNow, authorityUntil: '2026-10-13T10:30:00Z', generationId: macInventoryGeneration, sourceQuality: 'full', collectedAt: '2026-10-13T10:00:00Z', expiresAt: '2026-10-14T10:00:00Z', sources: { hardware: source('hardware'), receipts: source('receipts'), processes: source('processes'), ipv4: source('ipv4'), ipv6: source('ipv6') }, hardware: query.section === 'hardware' ? hardware : null, receiptIds: query.section === 'receipts' ? matchedReceipts.slice(query.offset, end) : [], processes: query.section === 'processes' ? matchedProcesses.slice(query.offset, end) : [], interfaces: query.section === 'ipv4' || query.section === 'ipv6' ? interfaces.slice(query.offset, end) : [], offset: query.offset, total, nextOffset: end < matchingCount ? end : null };
}
export function macInventoryDevice(configured = true): Device {
 const metric = { value: null, unit: '%', quality: 'unknown' as const, source: 'Synthetic Mac fixture', collectedAt: '2026-10-13T10:00:00Z' };
 return { id: macInventoryDeviceId, name: 'Synthetic Mac', platform: 'macos', os: 'macOS fixture', site: '', group: '', ip: null, status: 'unknown', source: 'lan', synthetic: false, lastSeen: macInventoryNow, agentVersion: 'source-fixture', cpu: metric, memory: metric, disk: { ...metric, value: 34, quality: 'healthy' }, uptime: '2h', tags: [], capabilities: configured ? [{ id: 'macos_inventory', name: 'macOS inventory', status: 'scope', detail: 'Fresh explicit inventory profile' }] : [], evidence: [], trend: [], caseIds: [], agentCertificate: { source: 'guided-enrollment', expiresAt: '2026-10-14T10:00:00Z', checkedAt: macInventoryNow } };
}

/** Advancing synthetic server time for interaction tests, without refreshing capture age.
 * Bind before clock spies so long/repeated interactions remain realistic. */
export function macInventoryFixtureClock() {
 const now = performance.now.bind(performance), started = now();
 return (query: MacInventoryQuery = macInventoryQuery()): MacInventoryPage => {
  const page = macInventoryFixture(query), elapsed = Math.max(0, Math.floor(now() - started));
  return { ...page, serverNow: new Date(Date.parse(page.serverNow) + elapsed).toISOString(), status: elapsed < 50000 ? 'fresh' : 'stale' };
 };
}
