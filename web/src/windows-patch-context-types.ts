import { inventoryAge } from './complete-packages-types';
import type { WindowsInventorySnapshot } from './windows-inventory-types';

/** Private, read-only observations. Retained history is not installed inventory. */
export const WINDOWS_PATCH_CONTEXT_BYTES = 24 * 1024;
export const WINDOWS_PATCH_CONTEXT_ROWS = 64;
export const WINDOWS_PATCH_CONTEXT_REASONS = ['', 'windows_patch_context_access_denied', 'windows_patch_context_unavailable', 'windows_patch_context_unsupported_platform', 'windows_patch_context_invalid_metadata', 'windows_patch_context_bounds', 'windows_patch_context_offline_not_verified', 'windows_patch_context_partial_result', 'windows_patch_context_budget_exhausted'] as const;
export interface WindowsPatchOSField { value: string | null; quality: 'observed' | 'absent' | 'denied' | 'unavailable' }
export type WindowsPatchRebootState = 'pending' | 'clear' | 'denied' | 'unavailable';
export interface WindowsPatchHistoryRow {
    index: number; updateId: string; revision: number; title: string; occurredAt: string;
    operation: 'installation' | 'uninstallation'; result: 'not-started' | 'in-progress' | 'succeeded' | 'succeeded-with-errors' | 'failed' | 'aborted';
    hresult: string; metadataTruncated: boolean;
}
export interface WindowsPatchContext {
    schemaVersion: 'tracebolt.windows-patch-context.v1'; scope: 'windows-patch-context-v1'; grantId: string; generationId: string; collectedAt: string;
    os: { edition: WindowsPatchOSField; release: WindowsPatchOSField; build: WindowsPatchOSField; revision: WindowsPatchOSField };
    reboot: { windowsUpdate: WindowsPatchRebootState; servicing: WindowsPatchRebootState; fileOperations: WindowsPatchRebootState };
    history: { quality: 'observed' | 'partial' | 'denied' | 'unavailable'; reason: typeof WINDOWS_PATCH_CONTEXT_REASONS[number]; countExact: boolean; totalCount: number; truncated: boolean; rows: WindowsPatchHistoryRow[] };
}
const exact = (v: unknown, keys: readonly string[]): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v, k));
const integer = (v: unknown, max = 4294967295): v is number => typeof v === 'number' && Number.isSafeInteger(v) && !Object.is(v, -0) && v >= 0 && v <= max;
const timestamp = (v: unknown): v is string => typeof v === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(v) && Number(v.slice(0, 4)) >= 1970 && Number.isFinite(Date.parse(v)) && new Date(Date.parse(v)).toISOString().slice(0, 19) === v.slice(0, 19);
const title = (v: unknown): v is string => typeof v === 'string' && v.length > 0 && v.trim() === v && !v.includes('  ') && new TextEncoder().encode(v).byteLength <= 256 && !/[\p{Cc}\p{Cf}\uD800-\uDFFF]/u.test(v) && !/[^\S ]/u.test(v);
function field(v: unknown, max: number, decimal = false): v is WindowsPatchOSField {
    if (!exact(v, ['value', 'quality'])) return false;
    if (v.quality !== 'observed') return ['absent', 'denied', 'unavailable'].includes(v.quality as string) && v.value === null;
    return typeof v.value === 'string' && (decimal ? /^(0|[1-9][0-9]{0,9})$/.test(v.value) && integer(Number(v.value)) : v.value.length > 0 && v.value.length <= max && /^[A-Za-z0-9 ._-]+$/.test(v.value) && v.value.trim() === v.value && !v.value.includes('  '));
}
function row(v: unknown, capture: string): v is WindowsPatchHistoryRow {
    return exact(v, ['index', 'updateId', 'revision', 'title', 'occurredAt', 'operation', 'result', 'hresult', 'metadataTruncated']) && integer(v.index, WINDOWS_PATCH_CONTEXT_ROWS - 1) && typeof v.updateId === 'string' && /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(v.updateId) && v.updateId !== '00000000-0000-0000-0000-000000000000' && integer(v.revision, 2147483647) && title(v.title) && timestamp(v.occurredAt) && inventoryAge(v.occurredAt, capture) <= 120000 && ['installation', 'uninstallation'].includes(v.operation as string) && ['not-started', 'in-progress', 'succeeded', 'succeeded-with-errors', 'failed', 'aborted'].includes(v.result as string) && typeof v.hresult === 'string' && /^[a-f0-9]{8}$/.test(v.hresult) && typeof v.metadataTruncated === 'boolean';
}
export function validWindowsPatchContext(v: unknown, snapshot: WindowsInventorySnapshot, serverNow: string): v is WindowsPatchContext {
    if (!exact(v, ['schemaVersion', 'scope', 'grantId', 'generationId', 'collectedAt', 'os', 'reboot', 'history']) || v.schemaVersion !== 'tracebolt.windows-patch-context.v1' || v.scope !== 'windows-patch-context-v1' || typeof v.grantId !== 'string' || !/^[a-f0-9]{32}$/.test(v.grantId) || typeof v.generationId !== 'string' || !/^sample_[a-f0-9]{32}$/.test(v.generationId) || v.generationId !== snapshot.generationId || !timestamp(v.collectedAt) || !timestamp(snapshot.collectedAt) || !timestamp(serverNow) || inventoryAge(v.collectedAt, snapshot.collectedAt) !== 0 || inventoryAge(v.collectedAt, serverNow) > 30000 || inventoryAge(serverNow, v.collectedAt) >= 86400000 || !exact(v.os, ['edition', 'release', 'build', 'revision']) || !field(v.os.edition, 64) || !field(v.os.release, 32) || !field(v.os.build, 10, true) || !field(v.os.revision, 10, true) || !exact(v.reboot, ['windowsUpdate', 'servicing', 'fileOperations']) || !Object.values(v.reboot).every(state => ['pending', 'clear', 'denied', 'unavailable'].includes(state as string))) return false;
    const h = v.history;
    if (!exact(h, ['quality', 'reason', 'countExact', 'totalCount', 'truncated', 'rows']) || !WINDOWS_PATCH_CONTEXT_REASONS.includes(h.reason as WindowsPatchContext['history']['reason']) || typeof h.countExact !== 'boolean' || !integer(h.totalCount, 2147483647) || typeof h.truncated !== 'boolean' || !Array.isArray(h.rows) || h.rows.length > WINDOWS_PATCH_CONTEXT_ROWS || !h.rows.every(item => row(item, v.collectedAt as string)) || h.totalCount < h.rows.length || h.truncated !== (h.totalCount > h.rows.length)) return false;
    if (h.quality === 'observed') { if (!h.countExact || h.reason !== '') return false; }
    else if (h.quality === 'partial') { if (h.reason === '') return false; }
    else if (h.quality === 'denied' || h.quality === 'unavailable') { if (h.countExact || h.totalCount !== 0 || h.rows.length !== 0 || h.reason === '' || (h.quality === 'denied') !== (h.reason === 'windows_patch_context_access_denied')) return false; }
    else return false;
    if (h.rows.some((item, i, rows) => item.index >= (h.totalCount as number) || i > 0 && (rows[i - 1].index >= item.index || inventoryAge(rows[i - 1].occurredAt, item.occurredAt) < 0))) return false;
    const encoded = JSON.stringify(v).replace(/[<>&\u2028\u2029]/g, c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
    return new TextEncoder().encode(encoded).byteLength <= WINDOWS_PATCH_CONTEXT_BYTES;
}
