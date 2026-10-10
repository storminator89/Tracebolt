import { inventoryAge } from './complete-packages-types';
import type { WindowsInventorySnapshot } from './windows-inventory-types';

/** Cached observations only. Never an update action, online scan or AI input. */
export const WINDOWS_UPDATES_BYTES = 24 * 1024;
export const WINDOWS_UPDATES_MAX_ROWS = 64;
export const WINDOWS_UPDATES_SEVERITIES = ['unspecified', 'critical', 'important', 'moderate', 'low'] as const;
export const WINDOWS_UPDATES_REASONS = ['', 'windows_updates_access_denied', 'windows_updates_unavailable', 'windows_updates_unsupported_platform', 'windows_updates_invalid_metadata', 'windows_updates_bounds', 'windows_updates_offline_not_verified', 'windows_updates_partial_result', 'windows_updates_budget_exhausted'] as const;
export interface WindowsUpdate {
    updateId: string; revision: number; title: string; kbArticleIds: string[];
    severity: typeof WINDOWS_UPDATES_SEVERITIES[number]; downloaded: boolean; metadataTruncated: boolean;
}
export interface WindowsUpdates {
    schemaVersion: 'tracebolt.windows-update-inspection.v1'; scope: 'windows-cached-update-inspection-v1';
    grantId: string; generationId: string; collectedAt: string; source: 'wua-cache'; cacheFreshness: 'unknown';
    quality: 'observed' | 'partial' | 'denied' | 'unavailable'; reason: typeof WINDOWS_UPDATES_REASONS[number];
    countExact: boolean; observedCount: number; truncated: boolean; rows: WindowsUpdate[];
}
const exact = (v: unknown, keys: readonly string[]): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v, k));
const integer = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && !Object.is(v, -0) && v >= 0 && v <= 2147483647;
const timestamp = (v: unknown): v is string => typeof v === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(v) && Number(v.slice(0, 4)) >= 1970 && Number.isFinite(Date.parse(v)) && new Date(Date.parse(v)).toISOString().slice(0, 19) === v.slice(0, 19);
const title = (v: unknown): v is string => typeof v === 'string' && v.length > 0 && v.trim() === v && !v.includes('  ') && new TextEncoder().encode(v).byteLength <= 256 && !/[\p{Cc}\p{Cf}\uD800-\uDFFF]/u.test(v) && !/[^\S ]/u.test(v);
function update(v: unknown): v is WindowsUpdate {
    return exact(v, ['updateId', 'revision', 'title', 'kbArticleIds', 'severity', 'downloaded', 'metadataTruncated']) && typeof v.updateId === 'string' && /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(v.updateId) && v.updateId !== '00000000-0000-0000-0000-000000000000' && integer(v.revision) && title(v.title) && Array.isArray(v.kbArticleIds) && v.kbArticleIds.length <= 8 && v.kbArticleIds.every((kb, i, all) => typeof kb === 'string' && /^KB[1-9][0-9]{0,9}$/.test(kb) && (i === 0 || all[i - 1] < kb)) && WINDOWS_UPDATES_SEVERITIES.includes(v.severity as WindowsUpdate['severity']) && typeof v.downloaded === 'boolean' && typeof v.metadataTruncated === 'boolean';
}
/** Defense in depth for the private operator projection; server authorization
 * remains authoritative. The original capture must equal its exact base sample.
 * The existing 30-second skew allowance does not make future update rows visible. */
export function validWindowsUpdates(v: unknown, snapshot: WindowsInventorySnapshot, serverNow: string): v is WindowsUpdates {
    if (!exact(v, ['schemaVersion', 'scope', 'grantId', 'generationId', 'collectedAt', 'source', 'cacheFreshness', 'quality', 'reason', 'countExact', 'observedCount', 'truncated', 'rows']) || v.schemaVersion !== 'tracebolt.windows-update-inspection.v1' || v.scope !== 'windows-cached-update-inspection-v1' || typeof v.grantId !== 'string' || !/^[a-f0-9]{32}$/.test(v.grantId) || typeof v.generationId !== 'string' || !/^sample_[a-f0-9]{32}$/.test(v.generationId) || v.generationId !== snapshot.generationId || !timestamp(v.collectedAt) || !timestamp(snapshot.collectedAt) || !timestamp(serverNow) || inventoryAge(v.collectedAt, snapshot.collectedAt) !== 0 || inventoryAge(v.collectedAt, serverNow) > 30000 || inventoryAge(serverNow, v.collectedAt) >= 86400000 || v.source !== 'wua-cache' || v.cacheFreshness !== 'unknown' || !WINDOWS_UPDATES_REASONS.includes(v.reason as WindowsUpdates['reason']) || typeof v.countExact !== 'boolean' || !integer(v.observedCount) || typeof v.truncated !== 'boolean' || !Array.isArray(v.rows) || v.rows.length > WINDOWS_UPDATES_MAX_ROWS || v.observedCount < v.rows.length || v.truncated !== (v.observedCount > v.rows.length) || !v.rows.every(update)) return false;
    if (v.quality === 'observed') { if (!v.countExact || v.reason !== '') return false; }
    else if (v.quality === 'partial') { if (v.reason === '') return false; }
    else if (v.quality === 'denied' || v.quality === 'unavailable') { if (v.countExact || v.observedCount !== 0 || v.rows.length !== 0 || v.reason === '' || (v.quality === 'denied') !== (v.reason === 'windows_updates_access_denied')) return false; }
    else return false;
    if (v.rows.some((row, i, rows) => i > 0 && !(rows[i - 1].updateId < row.updateId || rows[i - 1].updateId === row.updateId && rows[i - 1].revision < row.revision))) return false;
    // Go encoding/json escapes HTML characters; count those bytes as the source
    // does. Text remains literal in React and never becomes a link or markup.
    const encoded = JSON.stringify(v).replace(/[<>&\u2028\u2029]/g, c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
    return new TextEncoder().encode(encoded).byteLength <= WINDOWS_UPDATES_BYTES;
}
