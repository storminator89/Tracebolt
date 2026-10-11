import type { WindowsInventorySnapshot } from './windows-inventory-types';

/** Independent provider aggregate; never a physical-disk identity or health input. */
export const WINDOWS_STORAGE_IO_BYTES = 2048;
export const WINDOWS_STORAGE_IO_REASONS = ['', 'windows_storage_io_access_denied', 'windows_storage_io_unavailable', 'windows_storage_io_unsupported_platform', 'windows_storage_io_invalid_metadata', 'windows_storage_io_bounds', 'windows_storage_io_partial_result', 'windows_storage_io_budget_exhausted', 'windows_storage_io_counter_missing', 'windows_storage_io_counter_reset', 'windows_storage_io_invalid_timebase', 'windows_storage_io_idle'] as const;
export type WindowsStorageIOReason = typeof WINDOWS_STORAGE_IO_REASONS[number];
export interface WindowsStorageIOMetric { value: number | null; quality: 'observed' | 'denied' | 'unavailable'; reason: WindowsStorageIOReason }
export const windowsStorageIOMetricKeys = ['readBytesPerSecond', 'writeBytesPerSecond', 'readOperationsPerSecond', 'writeOperationsPerSecond', 'readLatencySeconds', 'writeLatencySeconds', 'averageQueueLength', 'currentQueueLength'] as const;
export type WindowsStorageIOMetricKey = typeof windowsStorageIOMetricKeys[number];
export interface WindowsStorageIO {
    schemaVersion: 'tracebolt.windows-storage-io.v1'; scope: 'windows-storage-io-v1'; grantId: string; generationId: string; collectedAt: string;
    perfDisk: Record<WindowsStorageIOMetricKey, WindowsStorageIOMetric> & { source: 'PDH PhysicalDisk(_Total)'; quality: 'observed' | 'partial' | 'denied' | 'unavailable'; reason: WindowsStorageIOReason; sampleStartedAt: string | null; sampleEndedAt: string | null; intervalMilliseconds: number | null };
}
const exact = (v: unknown, keys: readonly string[]): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v, k));
const timestamp = (v: unknown): v is string => typeof v === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(v) && Number(v.slice(0, 4)) >= 1970 && Number.isFinite(Date.parse(v)) && new Date(Date.parse(v)).toISOString().slice(0, 19) === v.slice(0, 19);
// Go retains nanoseconds. Subtract before flooring; independently truncated
// JavaScript endpoints (or floating-point fractions) can change the interval.
const nanoseconds = (v: string): bigint => BigInt(Date.parse(v.slice(0, 19) + 'Z')) * 1000000n + BigInt((v.includes('.') ? v.slice(20, -1) : '').padEnd(9, '0'));
const validReason = (v: unknown): v is WindowsStorageIOReason => WINDOWS_STORAGE_IO_REASONS.includes(v as WindowsStorageIOReason);
function metric(v: unknown): v is WindowsStorageIOMetric {
    if (!exact(v, ['value', 'quality', 'reason']) || !validReason(v.reason)) return false;
    if (v.quality === 'observed') return v.reason === '' && typeof v.value === 'number' && Number.isFinite(v.value) && v.value >= 0 && !Object.is(v.value, -0);
    return v.value === null && ['denied', 'unavailable'].includes(v.quality as string) && v.reason !== '' && v.reason !== 'windows_storage_io_partial_result' && (v.quality === 'denied') === (v.reason === 'windows_storage_io_access_denied');
}
export function validWindowsStorageIO(v: unknown, snapshot: WindowsInventorySnapshot, serverNow: string): v is WindowsStorageIO {
    if (!exact(v, ['schemaVersion', 'scope', 'grantId', 'generationId', 'collectedAt', 'perfDisk']) || v.schemaVersion !== 'tracebolt.windows-storage-io.v1' || v.scope !== 'windows-storage-io-v1' || typeof v.grantId !== 'string' || !/^[a-f0-9]{32}$/.test(v.grantId) || typeof v.generationId !== 'string' || !/^sample_[a-f0-9]{32}$/.test(v.generationId) || v.generationId !== snapshot.generationId || !timestamp(v.collectedAt) || !timestamp(snapshot.collectedAt) || !timestamp(serverNow)) return false;
    const collected = nanoseconds(v.collectedAt), now = nanoseconds(serverNow);
    if (collected !== nanoseconds(snapshot.collectedAt) || collected - now > 30000000000n || now - collected >= 86400000000000n) return false;
    const p = v.perfDisk;
    if (!exact(p, ['quality', 'reason', 'source', 'sampleStartedAt', 'sampleEndedAt', 'intervalMilliseconds', ...windowsStorageIOMetricKeys]) || p.source !== 'PDH PhysicalDisk(_Total)' || !validReason(p.reason) || !windowsStorageIOMetricKeys.every(k => metric(p[k]))) return false;
    const values = windowsStorageIOMetricKeys.map(k => p[k] as WindowsStorageIOMetric), observed = values.filter(m => m.quality === 'observed').length;
    if (p.sampleStartedAt === null || p.sampleEndedAt === null || p.intervalMilliseconds === null) {
        if (p.sampleStartedAt !== null || p.sampleEndedAt !== null || p.intervalMilliseconds !== null || observed !== 0) return false;
    } else {
        if (!timestamp(p.sampleStartedAt) || !timestamp(p.sampleEndedAt) || typeof p.intervalMilliseconds !== 'number' || !Number.isSafeInteger(p.intervalMilliseconds) || Object.is(p.intervalMilliseconds, -0)) return false;
        const start = nanoseconds(p.sampleStartedAt), end = nanoseconds(p.sampleEndedAt), duration = end - start;
        if (duration < 1000000000n || duration > 2000000000n || duration / 1000000n !== BigInt(p.intervalMilliseconds) || start < collected || end - now > 30000000000n) return false;
    }
    for (const k of windowsStorageIOMetricKeys) {
        const m = p[k] as WindowsStorageIOMetric;
        if (m.reason === 'windows_storage_io_idle' && (!['readLatencySeconds', 'writeLatencySeconds'].includes(k) || (p[k === 'readLatencySeconds' ? 'readOperationsPerSecond' : 'writeOperationsPerSecond'] as WindowsStorageIOMetric).value !== 0)) return false;
    }
    for (const side of ['read', 'write']) {
        const latency = p[`${side}LatencySeconds`] as WindowsStorageIOMetric, ops = p[`${side}OperationsPerSecond`] as WindowsStorageIOMetric;
        if (latency.quality === 'observed' && (ops.value === null || ops.value <= 0) || ops.value === 0 && latency.reason !== 'windows_storage_io_idle') return false;
    }
    const same = values.every(m => m.quality === values[0].quality && m.reason === values[0].reason);
    if (same ? p.quality !== values[0].quality || p.reason !== values[0].reason : p.quality !== 'partial' || p.reason !== 'windows_storage_io_partial_result') return false;
    return new TextEncoder().encode(JSON.stringify(v).replace(/[<>&\u2028\u2029]/g, ch => `\\u${ch.charCodeAt(0).toString(16).padStart(4, '0')}`)).byteLength <= WINDOWS_STORAGE_IO_BYTES;
}
export const usefulWindowsStorageIO = (v: WindowsStorageIO): boolean => windowsStorageIOMetricKeys.some(k => v.perfDisk[k].quality === 'observed');
