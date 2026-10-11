import { inventoryAge } from './complete-packages-types';
import type { WindowsInventorySnapshot } from './windows-inventory-types';

/** Independent source context; never a utilization sampler or health-policy input. */
export const WINDOWS_RESOURCE_CONTEXT_BYTES = 5 * 1024;
export const WINDOWS_RESOURCE_CONTEXT_REASONS = ['', 'windows_resource_context_access_denied', 'windows_resource_context_unavailable', 'windows_resource_context_unsupported_platform', 'windows_resource_context_invalid_metadata', 'windows_resource_context_bounds', 'windows_resource_context_partial_result', 'windows_resource_context_budget_exhausted'] as const;
interface Source { quality: 'observed' | 'denied' | 'unavailable'; reason: typeof WINDOWS_RESOURCE_CONTEXT_REASONS[number] }
export interface WindowsResourceLabel { value: string | null; quality: 'observed' | 'empty' | 'denied' | 'unavailable' }
export interface WindowsResourceCount { value: number | null; quality: 'observed' | 'denied' | 'unavailable' }
export interface WindowsProcessor { name: WindowsResourceLabel; architecture: { value: string | null; quality: WindowsResourceCount['quality'] }; cores: WindowsResourceCount; logicalProcessors: WindowsResourceCount }
export interface WindowsResourceContext {
    schemaVersion: 'tracebolt.windows-resource-context.v1'; scope: 'windows-resource-context-v1'; grantId: string; generationId: string; collectedAt: string;
    processors: Omit<Source, 'quality'> & { quality: Source['quality'] | 'partial'; source: 'Win32_Processor'; rows: WindowsProcessor[]; totalCores: number | null; totalLogicalProcessors: number | null };
    installedMemory: Source & { source: 'GetPhysicallyInstalledSystemMemory'; installedBytes: string | null };
    memory: Source & { source: 'K32GetPerformanceInfo'; commitTotalBytes: string | null; commitLimitBytes: string | null; physicalTotalBytes: string | null; physicalAvailableBytes: string | null; pageSizeBytes: string | null };
    pagefiles: Source & { source: 'EnumPageFilesW'; count: number | null; totalBytes: string | null; totalInUseBytes: string | null };
}
const exact = (v: unknown, keys: readonly string[]): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v, k));
const integer = (v: unknown, max: number): v is number => typeof v === 'number' && Number.isSafeInteger(v) && !Object.is(v, -0) && v >= 0 && v <= max;
const timestamp = (v: unknown): v is string => typeof v === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(v) && Number(v.slice(0, 4)) >= 1970 && Number.isFinite(Date.parse(v)) && new Date(Date.parse(v)).toISOString().slice(0, 19) === v.slice(0, 19);
const label = (v: unknown): v is string => typeof v === 'string' && v.length > 0 && v.length <= 128 && !/[\p{Cc}\uFFFD\uD800-\uDFFF]/u.test(v);
export const windowsResourceUint64 = (v: unknown): v is string => typeof v === 'string' && /^(?:0|[1-9]\d{0,19})$/.test(v) && BigInt(v) <= 18446744073709551615n;
const field = (v: unknown, text: boolean): boolean => exact(v, ['value', 'quality']) && (v.quality === 'observed' ? text ? label(v.value) : integer(v.value, 65535) && v.value > 0 : v.value === null && (text ? ['empty', 'denied', 'unavailable'] : ['denied', 'unavailable']).includes(v.quality as string));
const reason = (v: unknown): boolean => WINDOWS_RESOURCE_CONTEXT_REASONS.includes(v as Source['reason']);
const unavailable = (v: Record<string, unknown>): boolean => (v.quality === 'denied' || v.quality === 'unavailable') && v.reason !== '' && (v.quality === 'denied') === (v.reason === 'windows_resource_context_access_denied');
function processors(v: unknown): boolean {
    if (!exact(v, ['quality', 'reason', 'source', 'rows', 'totalCores', 'totalLogicalProcessors']) || !reason(v.reason) || v.source !== 'Win32_Processor' || !Array.isArray(v.rows) || v.rows.length > 4) return false;
    if (v.quality === 'denied' || v.quality === 'unavailable') return unavailable(v) && v.rows.length === 0 && v.totalCores === null && v.totalLogicalProcessors === null;
    if (!v.rows.length || !v.rows.every(row => exact(row, ['name', 'architecture', 'cores', 'logicalProcessors']) && field(row.name, true) && field(row.architecture, true) && (row.architecture as WindowsResourceLabel).quality !== 'empty' && ((row.architecture as WindowsResourceLabel).value === null || ['x86', 'MIPS', 'Alpha', 'PowerPC', 'ARM', 'ia64', 'x64', 'ARM64'].includes((row.architecture as WindowsResourceLabel).value!)) && field(row.cores, false) && field(row.logicalProcessors, false))) return false;
    const rows = v.rows as WindowsProcessor[];
    const completeCounts = rows.every(row => row.cores.value !== null && row.logicalProcessors.value !== null);
    const total = (key: 'cores' | 'logicalProcessors') => completeCounts ? rows.reduce((n, row) => n + row[key].value!, 0) : null;
    if (v.totalCores !== total('cores') || v.totalLogicalProcessors !== total('logicalProcessors') || Object.is(v.totalCores, -0) || Object.is(v.totalLogicalProcessors, -0)) return false;
    const missing = rows.some(row => Object.values(row).some(f => f.quality === 'denied' || f.quality === 'unavailable'));
    return v.quality === 'observed' && !missing && v.reason === '' || v.quality === 'partial' && missing && v.reason === 'windows_resource_context_partial_result';
}
function bytesSource(v: unknown, source: string, keys: string[]): v is Record<string, string | number> {
    if (!exact(v, ['quality', 'reason', 'source', ...keys]) || !reason(v.reason) || v.source !== source) return false;
    if (v.quality === 'denied' || v.quality === 'unavailable') return unavailable(v) && keys.every(key => v[key] === null);
    return v.quality === 'observed' && v.reason === '' && keys.every(key => key === 'count' ? integer(v[key], 32) : windowsResourceUint64(v[key]));
}
export function validWindowsResourceContext(v: unknown, snapshot: WindowsInventorySnapshot, serverNow: string): v is WindowsResourceContext {
    if (!exact(v, ['schemaVersion', 'scope', 'grantId', 'generationId', 'collectedAt', 'processors', 'installedMemory', 'memory', 'pagefiles']) || v.schemaVersion !== 'tracebolt.windows-resource-context.v1' || v.scope !== 'windows-resource-context-v1' || typeof v.grantId !== 'string' || !/^[a-f0-9]{32}$/.test(v.grantId) || typeof v.generationId !== 'string' || !/^sample_[a-f0-9]{32}$/.test(v.generationId) || v.generationId !== snapshot.generationId || !timestamp(v.collectedAt) || !timestamp(snapshot.collectedAt) || !timestamp(serverNow) || inventoryAge(v.collectedAt, snapshot.collectedAt) !== 0 || inventoryAge(v.collectedAt, serverNow) > 30000 || inventoryAge(serverNow, v.collectedAt) >= 86400000 || !processors(v.processors) || !bytesSource(v.installedMemory, 'GetPhysicallyInstalledSystemMemory', ['installedBytes']) || !bytesSource(v.memory, 'K32GetPerformanceInfo', ['commitTotalBytes', 'commitLimitBytes', 'physicalTotalBytes', 'physicalAvailableBytes', 'pageSizeBytes']) || !bytesSource(v.pagefiles, 'EnumPageFilesW', ['count', 'totalBytes', 'totalInUseBytes'])) return false;
    if (v.installedMemory.quality === 'observed' && (BigInt(v.installedMemory.installedBytes) === 0n || BigInt(v.installedMemory.installedBytes) % 1024n !== 0n)) return false;
    if (v.memory.quality === 'observed') {
        const memory = v.memory, pageSize = BigInt(memory.pageSizeBytes);
        if (pageSize < 1024n || pageSize > 1073741824n || (pageSize & (pageSize - 1n)) !== 0n || BigInt(v.memory.physicalTotalBytes) === 0n || BigInt(v.memory.commitLimitBytes) === 0n || BigInt(v.memory.physicalAvailableBytes) > BigInt(v.memory.physicalTotalBytes) || BigInt(v.memory.commitTotalBytes) > BigInt(v.memory.commitLimitBytes) || ['commitTotalBytes', 'commitLimitBytes', 'physicalTotalBytes', 'physicalAvailableBytes'].some(key => BigInt(memory[key]) % pageSize !== 0n)) return false;
    }
    if (v.pagefiles.quality === 'observed' && (BigInt(v.pagefiles.totalInUseBytes) > BigInt(v.pagefiles.totalBytes) || v.pagefiles.count === 0 && (v.pagefiles.totalBytes !== '0' || v.pagefiles.totalInUseBytes !== '0') || v.pagefiles.count !== 0 && v.pagefiles.totalBytes === '0')) return false;
    const encoded = JSON.stringify(v).replace(/[<>&\u2028\u2029]/g, ch => `\\u${ch.charCodeAt(0).toString(16).padStart(4, '0')}`);
    return new TextEncoder().encode(encoded).byteLength <= WINDOWS_RESOURCE_CONTEXT_BYTES;
}
export function usefulWindowsResourceContext(v: WindowsResourceContext): boolean {
    return v.processors.rows.some(row => Object.values(row).some(field => field.value !== null)) || [v.installedMemory, v.memory, v.pagefiles].some(source => source.quality === 'observed');
}
/** Calculate only current-limit capacity; do not infer pressure or future limits. */
export function windowsCommitRemaining(memory: WindowsResourceContext['memory']): string | null {
    return windowsResourceUint64(memory.commitLimitBytes) && windowsResourceUint64(memory.commitTotalBytes) && BigInt(memory.commitLimitBytes) >= BigInt(memory.commitTotalBytes) ? (BigInt(memory.commitLimitBytes) - BigInt(memory.commitTotalBytes)).toString() : null;
}
/** BigInt-only display rounding; exact source bytes remain available in details. */
export function windowsResourceBytes(value: string, locale: 'en' | 'de'): string {
    const bytes = BigInt(value), units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB'];
    let unit = 0, scale = 1n;
    while (unit < units.length - 1 && bytes >= scale * 1024n) { unit++; scale *= 1024n; }
    if (!unit) return `${bytes.toLocaleString(locale)} B`;
    const rounded = (bytes * 10n + scale / 2n) / scale;
    return `${(rounded / 10n).toLocaleString(locale)}${locale === 'de' ? ',' : '.'}${rounded % 10n} ${units[unit]}`;
}
