import { numericWindowsAddress } from './windows-numeric-address';
export const MAC_INVENTORY_PAGE_BYTES = 32768;
export const MAC_INVENTORY_PAGE_ROWS = 50;
export const macInventorySections = ['hardware', 'receipts', 'processes', 'ipv4', 'ipv6'] as const;
export type MacInventorySection = typeof macInventorySections[number];
export const macInventorySources = {
 hardware: 'sysctl: hw.model,hw.physicalcpu,hw.logicalcpu,hw.memsize',
 receipts: 'pkgutil --pkgs-plist: Installer receipt identifiers only',
 processes: 'ps -A -o ucomm=,pid=,ppid=: caller-visible kernel accounting labels',
 ipv4: 'ifconfig -a inet: passive local IPv4 interface context',
 ipv6: 'ifconfig -a inet6: passive local IPv6 interface context',
} as const;
export const macInventoryReasons = ['macos_inventory_access_denied', 'macos_inventory_unavailable', 'macos_inventory_unsupported_platform', 'macos_inventory_invalid_metadata', 'macos_inventory_bounds', 'macos_inventory_budget_exhausted'] as const;
export interface MacInventorySource { source: string; quality: 'observed' | 'denied' | 'unavailable'; reason: '' | typeof macInventoryReasons[number] }
export interface MacHardware extends MacInventorySource { modelIdentifier: string; physicalCPUs: number; logicalCPUs: number; memoryCapacityBytes: number }
export interface MacProcess { pid: number; parentPid: number; accountingName: string; nameQuality: 'observed' | 'unavailable' }
export interface MacInterface { name: string; mtu: number; up: boolean; running: boolean; addresses: { ip: string; prefixBits: number }[] }
export interface MacInventoryQuery { section: 'summary' | MacInventorySection; generationId: string; offset: number; limit: number }
export interface MacInventoryPage {
 schemaVersion: 'tracebolt.macos-read-inventory-page.v1'; deviceId: string; section: MacInventoryQuery['section'];
 status: 'not-enabled' | 'unavailable' | 'disabled' | 'expired' | 'fresh' | 'stale'; serverNow: string; authorityUntil: string;
 generationId: string; sourceQuality: 'full' | 'partial' | 'unknown'; collectedAt: string | null; expiresAt: string | null;
 sources: Record<MacInventorySection, MacInventorySource> | null; hardware: MacHardware | null;
 receiptIds: string[]; processes: MacProcess[]; interfaces: MacInterface[]; offset: number; total: number; nextOffset: number | null;
}
const exact = (v: unknown, keys: string[]): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === keys.length && keys.every(key => Object.hasOwn(v, key));
const integer = (v: unknown, max = Number.MAX_SAFE_INTEGER): v is number => typeof v === 'number' && Number.isSafeInteger(v) && !Object.is(v, -0) && v >= 0 && v <= max;
const text = (v: unknown, pattern: RegExp): v is string => typeof v === 'string' && pattern.test(v);
const timestamp = (v: unknown): v is string => typeof v === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(v) && Number.isFinite(Date.parse(v)) && Number(v.slice(0, 4)) >= 1970 && new Date(Date.parse(v)).toISOString().slice(0, 19) === v.slice(0, 19);
export const validMacDeviceId = (v: unknown): v is string => text(v, /^agent_[a-f0-9]{32}$/) && v !== `agent_${'0'.repeat(32)}`;
export const validMacGenerationId = (v: unknown): v is string => text(v, /^sample_[a-f0-9]{32}$/) && v !== `sample_${'0'.repeat(32)}`;
const statusKeys = ['source', 'quality', 'reason'];
function source(v: unknown, key: MacInventorySection, hardware = false): v is MacInventorySource {
 if (!exact(v, hardware ? [...statusKeys, 'modelIdentifier', 'physicalCPUs', 'logicalCPUs', 'memoryCapacityBytes'] : statusKeys) || v.source !== macInventorySources[key]) return false;
 return v.quality === 'observed' ? v.reason === '' : v.quality === 'denied' ? v.reason === 'macos_inventory_access_denied' : v.quality === 'unavailable' && macInventoryReasons.slice(1).includes(v.reason as typeof macInventoryReasons[1]);
}
export function validMacHardware(v: unknown): v is MacHardware {
 if (!source(v, 'hardware', true)) return false;
 const h = v as MacHardware;
 if (h.quality !== 'observed') return h.modelIdentifier === '' && h.physicalCPUs === 0 && h.logicalCPUs === 0 && h.memoryCapacityBytes === 0;
 return text(h.modelIdentifier, /^[A-Za-z0-9,._-]{1,64}$/) && integer(h.physicalCPUs, 4096) && h.physicalCPUs > 0 && integer(h.logicalCPUs, 4096) && h.logicalCPUs >= h.physicalCPUs && integer(h.memoryCapacityBytes) && h.memoryCapacityBytes > 0;
}
export function validMacProcess(v: unknown): v is MacProcess {
 return exact(v, ['pid', 'parentPid', 'accountingName', 'nameQuality']) && integer(v.pid, 2147483647) && integer(v.parentPid, 2147483647) && (v.nameQuality === 'unavailable' ? v.accountingName === '' : v.nameQuality === 'observed' && text(v.accountingName, /^[\x20-\x7e]{1,16}$/) && v.accountingName.trim() === v.accountingName && !/[\\/]/.test(v.accountingName));
}
export function validMacInterface(v: unknown, family: 'ipv4' | 'ipv6'): v is MacInterface {
 if (!exact(v, ['name', 'mtu', 'up', 'running', 'addresses']) || !text(v.name, /^[A-Za-z0-9._-]{1,15}$/) || !integer(v.mtu, 1048576) || v.mtu === 0 || typeof v.up !== 'boolean' || typeof v.running !== 'boolean' || !Array.isArray(v.addresses) || v.addresses.length > 16) return false;
 const keys: string[] = [];
 return v.addresses.every(a => {
  if (!exact(a, ['ip', 'prefixBits']) || typeof a.ip !== 'string' || a.ip.includes('%') || !integer(a.prefixBits, family === 'ipv4' ? 32 : 128)) return false;
  const bytes = numericWindowsAddress(a.ip, family);
  if (!bytes || family === 'ipv6' && bytes.slice(0, 10).every(n => n === 0) && bytes[10] === 255 && bytes[11] === 255) return false;
  const key = `${a.ip}/${String.fromCharCode(a.prefixBits)}`; if (keys.length && key <= keys[keys.length - 1]) return false; keys.push(key); return true;
 });
}
export function validMacInventoryPage(v: unknown, deviceId: string, query: MacInventoryQuery): v is MacInventoryPage {
 if (!integer(query.limit, 100) || query.limit < 1 || !integer(query.offset, 4096) || !['summary', ...macInventorySections].includes(query.section) || (query.section === 'summary' ? query.generationId !== '' || query.offset !== 0 : !validMacGenerationId(query.generationId) || query.section === 'hardware' && query.offset !== 0)) return false;
 if (!exact(v, ['schemaVersion', 'deviceId', 'section', 'status', 'serverNow', 'authorityUntil', 'generationId', 'sourceQuality', 'collectedAt', 'expiresAt', 'sources', 'hardware', 'receiptIds', 'processes', 'interfaces', 'offset', 'total', 'nextOffset']) || v.schemaVersion !== 'tracebolt.macos-read-inventory-page.v1' || !validMacDeviceId(deviceId) || v.deviceId !== deviceId || v.section !== query.section || !timestamp(v.serverNow) || !timestamp(v.authorityUntil) || Date.parse(v.authorityUntil) <= Date.parse(v.serverNow) || !['not-enabled', 'unavailable', 'disabled', 'expired', 'fresh', 'stale'].includes(String(v.status)) || !['full', 'partial', 'unknown'].includes(String(v.sourceQuality)) || !integer(v.offset, 4096) || v.offset !== query.offset || !integer(v.total, 4096) || !Array.isArray(v.receiptIds) || !Array.isArray(v.processes) || !Array.isArray(v.interfaces)) return false;
 const page = v as unknown as MacInventoryPage;
 const ready = page.status === 'fresh' || page.status === 'stale';
 if (page.sources === null) {
  if (page.generationId !== '' || page.collectedAt !== null || page.expiresAt !== null || page.sourceQuality !== 'unknown' || ready || page.status === 'expired') return false;
 } else {
  if (!exact(page.sources, [...macInventorySections]) || !macInventorySections.every(key => source(page.sources![key], key)) || !validMacGenerationId(page.generationId) || !timestamp(page.collectedAt) || !timestamp(page.expiresAt) || Date.parse(page.expiresAt) - Date.parse(page.collectedAt) !== 86400000 || Date.parse(page.serverNow) < Date.parse(page.collectedAt)) return false;
  const observed = macInventorySections.filter(key => page.sources![key].quality === 'observed').length;
  if (observed === 0 && page.sourceQuality !== 'unknown' || observed > 0 && page.sourceQuality === 'unknown' || page.sourceQuality === 'full' && observed !== 5) return false;
  const age = Date.parse(page.serverNow) - Date.parse(page.collectedAt);
  if (page.status === 'fresh' && age >= 60000 || page.status === 'stale' && (age < 60000 || age >= 86400000) || page.status === 'expired' && age < 86400000 || ready && Date.parse(page.authorityUntil) > Date.parse(page.expiresAt)) return false;
 }
 if (query.section === 'summary' || !ready) return query.section === 'summary' && page.hardware === null && page.receiptIds.length + page.processes.length + page.interfaces.length === 0 && page.offset === 0 && page.total === 0 && page.nextOffset === null;
 if (query.generationId !== page.generationId || !page.sources) return false;
 const section = query.section, selected = page.sources[section], rows = section === 'receipts' ? page.receiptIds : section === 'processes' ? page.processes : section === 'ipv4' || section === 'ipv6' ? page.interfaces : [];
 if (section !== 'hardware' && page.hardware !== null || section !== 'receipts' && page.receiptIds.length || section !== 'processes' && page.processes.length || section !== 'ipv4' && section !== 'ipv6' && page.interfaces.length) return false;
 if (section === 'hardware') return validMacHardware(page.hardware) && statusKeys.every(key => page.hardware![key as keyof MacInventorySource] === selected[key as keyof MacInventorySource]) && page.total === 0 && page.offset === 0 && page.nextOffset === null;
 if (page.total > (section === 'receipts' ? 2048 : section === 'processes' ? 4096 : 128) || page.offset > page.total || rows.length > query.limit || page.offset + rows.length > page.total || rows.length === 0 && page.offset < page.total || (page.nextOffset === null ? page.offset + rows.length !== page.total : page.nextOffset !== page.offset + rows.length || page.nextOffset <= page.offset || page.nextOffset >= page.total)) return false;
 if (selected.quality !== 'observed' && (page.total !== 0 || rows.length !== 0)) return false;
 if (section === 'receipts') return page.receiptIds.every((row, i) => text(row, /^[A-Za-z0-9._+-]{1,256}$/) && (i === 0 || row > page.receiptIds[i - 1]));
 if (selected.quality === 'observed' && page.total === 0) return false;
 if (section === 'processes' && page.sourceQuality === 'full' && page.processes.some(row => row.nameQuality !== 'observed')) return false;
 if (section === 'processes') return page.processes.every((row, i) => validMacProcess(row) && (i === 0 || row.pid > page.processes[i - 1].pid));
 return page.interfaces.every((row, i) => validMacInterface(row, section) && (i === 0 || row.name > page.interfaces[i - 1].name));
}
export function sameMacInventoryGeneration(a: MacInventoryPage, b: MacInventoryPage): boolean {
 return a.deviceId === b.deviceId && a.generationId === b.generationId && a.collectedAt === b.collectedAt && a.expiresAt === b.expiresAt && a.sourceQuality === b.sourceQuality && JSON.stringify(a.sources) === JSON.stringify(b.sources);
}
export function macInventoryVisible(page: MacInventoryPage, elapsed: number): boolean {
 return Number.isFinite(elapsed) && elapsed >= 0 && Date.parse(page.authorityUntil) - Date.parse(page.serverNow) > elapsed && (page.status !== 'fresh' && page.status !== 'stale' || page.expiresAt !== null && Date.parse(page.expiresAt) - Date.parse(page.serverNow) > elapsed);
}
