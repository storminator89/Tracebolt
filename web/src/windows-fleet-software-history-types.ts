import { inventoryAge } from './complete-packages-types';
import { validFullSoftwareCursor, validFullSoftwareSearch } from './windows-full-software-types';
import { sameSoftwareHistory, validSoftwareHistoryProjection } from './windows-software-history-types';
import type { SoftwareHistoryProjection } from './windows-software-history-types';
import { validWindowsDeviceId } from './windows-inventory-types';

export const FLEET_HISTORY_PAGE_BYTES = 256 * 1024;
export interface FleetHistoryQuery { view: 'history'; name: string; version: ''; cursor: string }
export interface FleetHistoryItem { deviceId: string; identity: string; authorityUntil: string; history: SoftwareHistoryProjection; detailCursor: string }
export interface FleetHistoryPage { schemaVersion: 'tracebolt.windows-fleet-software-history-page.v1'; serverNow: string; status: 'ready' | 'not_configured'; search: string; mode: 'fleet' | 'device'; totalDevices: number; offset: number; items: FleetHistoryItem[]; nextCursor: string; cursorExpiresAt: string | null }
export type FleetHistoryExpected = { mode: 'fleet' | 'device'; offset: number; device?: FleetHistoryItem; totalDevices?: number; deadline?: string };
const exact = (v: unknown, keys: readonly string[]): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === keys.length && keys.every(key => Object.hasOwn(v, key));
const integer = (v: unknown, max: number): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 && v <= max;
const timestamp = (v: unknown): v is string => typeof v === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(v) && Number.isFinite(Date.parse(v)) && Number(v.slice(0, 4)) >= 2020 && new Date(Date.parse(v)).toISOString().slice(0, 19) === v.slice(0, 19);
export const validFleetHistoryQuery = (q: FleetHistoryQuery) => q.view === 'history' && q.version === '' && validFullSoftwareSearch(q.name) && validFullSoftwareCursor(q.cursor);
export function validFleetHistoryPage(v: unknown, q: FleetHistoryQuery, expected: FleetHistoryExpected): v is FleetHistoryPage {
    if (!validFleetHistoryQuery(q) || !exact(v, ['schemaVersion', 'serverNow', 'status', 'search', 'mode', 'totalDevices', 'offset', 'items', 'nextCursor', 'cursorExpiresAt']) || v.schemaVersion !== 'tracebolt.windows-fleet-software-history-page.v1' || !timestamp(v.serverNow) || !['ready', 'not_configured'].includes(v.status as string) || v.search !== q.name || v.mode !== expected.mode || !integer(v.totalDevices, 25) || !integer(v.offset, v.mode === 'fleet' ? 25 : 1024) || v.offset !== expected.offset || !Array.isArray(v.items) || v.items.length > (v.mode === 'fleet' ? 5 : 1) || !validFullSoftwareCursor(v.nextCursor) || v.nextCursor !== '' && v.nextCursor === q.cursor) return false;
    if (v.status === 'not_configured') return expected.mode === 'fleet' && q.cursor === '' && v.offset === 0 && v.totalDevices === 0 && v.items.length === 0 && v.nextCursor === '' && v.cursorExpiresAt === null;
    if (!timestamp(v.cursorExpiresAt) || inventoryAge(v.cursorExpiresAt, v.serverNow) <= 0 || inventoryAge(v.cursorExpiresAt, v.serverNow) > 300000 || expected.deadline !== undefined && v.cursorExpiresAt !== expected.deadline || expected.totalDevices !== undefined && v.totalDevices !== expected.totalDevices) return false;
    const p = v as unknown as FleetHistoryPage;
    for (const item of p.items) {
        if (!exact(item, ['deviceId', 'identity', 'authorityUntil', 'history', 'detailCursor']) || !validWindowsDeviceId(item.deviceId) || !/^[a-f0-9]{64}$/.test(item.identity) || !timestamp(item.authorityUntil) || inventoryAge(item.authorityUntil, p.cursorExpiresAt!) < 0 || !validFullSoftwareCursor(item.detailCursor)) return false;
        const h = item.history;
        if (!validSoftwareHistoryProjection(h, item.deviceId, { search: q.name, sort: 'observed-desc', limit: p.mode === 'fleet' ? 3 : 20, cursor: '' }, p.mode === 'fleet' ? 0 : p.offset) || inventoryAge(p.serverNow, h.serverNow) < 0 || h.authorityUntil !== null && h.authorityUntil !== item.authorityUntil || h.cursorExpiresAt !== null && h.cursorExpiresAt !== p.cursorExpiresAt) return false;
        if (p.mode === 'fleet' ? (item.detailCursor !== '') !== (h.status === 'ready') : item.detailCursor !== '' || h.status !== 'ready') return false;
    }
    if (new Set(p.items.map(item => item.deviceId)).size !== p.items.length || new Set(p.items.map(item => item.identity)).size !== p.items.length) return false;
    if (p.mode === 'fleet') return p.items.every((item, i) => i === 0 || p.items[i - 1].deviceId < item.deviceId) && p.offset <= p.totalDevices && p.items.length <= p.totalDevices - p.offset && (p.items.length > 0 || p.totalDevices === 0 && p.offset === 0) && (p.nextCursor !== '') === (p.offset + p.items.length < p.totalDevices);
    const item = p.items[0], old = expected.device;
    return p.totalDevices > 0 && p.items.length === 1 && !!old && item.deviceId === old.deviceId && item.identity === old.identity && item.authorityUntil === old.authorityUntil && item.history.status === old.history.status && sameSoftwareHistory(item.history, old.history) && item.history.matchingCount === old.history.matchingCount && (p.nextCursor !== '') === (p.offset + item.history.rows.length < item.history.matchingCount);
}
export function fleetHistoryVisible(p: FleetHistoryPage, elapsed: number): boolean {
    return p.status === 'ready' && p.cursorExpiresAt !== null && Number.isFinite(elapsed) && elapsed >= 0 && [p.cursorExpiresAt, ...p.items.flatMap(item => [item.authorityUntil, ...(item.history.comparison ? [item.history.comparison.expiresAt] : []), ...item.history.rows.map(row => row.expiresAt)])].every(expiry => inventoryAge(expiry, p.serverNow) > elapsed);
}
