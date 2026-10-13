import { inventoryAge } from './complete-packages-types';
import { fullSoftwareReasons, sameFullSoftwareComplete, validFullSoftwareComplete, validFullSoftwareCursor, validFullSoftwareRow, validFullSoftwareSearch } from './windows-full-software-types';
import type { FullSoftwareAttempt, FullSoftwareComplete, FullSoftwareRow } from './windows-full-software-types';
import { validWindowsDeviceId } from './windows-inventory-types';

export const FLEET_SOFTWARE_PAGE_BYTES = 256 * 1024;
export const FLEET_SOFTWARE_MAX_DEVICES = 25;
export const FLEET_SOFTWARE_PAGE_DEVICES = 5;
export const FLEET_SOFTWARE_PREVIEW_ROWS = 3;
export const FLEET_SOFTWARE_DETAIL_ROWS = 20;
export const FLEET_SOFTWARE_LIFETIME_MS = 300000;
export interface FleetSoftwareQuery { name: string; version: string; cursor: string }
export interface FleetSoftwareItem {
    deviceId: string; identity: string; status: 'not_configured' | 'disabled' | 'awaiting' | 'ready' | 'unavailable'; authorityUntil: string;
    complete: FullSoftwareComplete | null; latestAttempt: FullSoftwareAttempt | null;
    matchingCount: number; unknownCount: number; rows: FullSoftwareRow[]; detailCursor: string;
}
export interface FleetSoftwarePage {
    schemaVersion: 'tracebolt.windows-fleet-software-page.v1'; serverNow: string; status: 'ready' | 'not_configured';
    name: string; version: string; mode: 'fleet' | 'device'; totalDevices: number; offset: number;
    items: FleetSoftwareItem[]; nextCursor: string; cursorExpiresAt: string | null;
}
export type FleetSoftwareExpected = { mode: 'fleet' | 'device'; offset: number; device?: FleetSoftwareItem; totalDevices?: number; deadline?: string };
const exact = (v: unknown, keys: readonly string[]): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === keys.length && keys.every(key => Object.hasOwn(v, key));
const integer = (v: unknown, max = Number.MAX_SAFE_INTEGER): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 && v <= max;
const timestamp = (v: unknown): v is string => typeof v === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(v) && Number.isFinite(Date.parse(v)) && Number(v.slice(0, 4)) >= 2020 && new Date(Date.parse(v)).toISOString().slice(0, 19) === v.slice(0, 19);
export const validFleetSoftwareQuery = (v: FleetSoftwareQuery): boolean => validFullSoftwareSearch(v.name) && validFullSoftwareSearch(v.version) && (v.name !== '' || v.version !== '') && validFullSoftwareCursor(v.cursor);
function validAttempt(v: unknown, now: string): v is FullSoftwareAttempt {
    return exact(v, ['sequence', 'attemptedAt', 'status', 'reason']) && integer(v.sequence) && v.sequence > 0 && timestamp(v.attemptedAt) && inventoryAge(now, v.attemptedAt) >= 0 && ['pending', 'complete', 'source_failed', 'expired'].includes(v.status as string) && (v.status === 'source_failed' ? fullSoftwareReasons.includes(v.reason as typeof fullSoftwareReasons[number]) : v.reason === '');
}
/** Literal matching uses the server's Unicode simple-fold contract. Do not
 * approximate it with JavaScript locale-dependent or full lowercase mapping. */
function validItem(v: unknown, page: FleetSoftwarePage): v is FleetSoftwareItem {
    if (!exact(v, ['deviceId', 'identity', 'status', 'authorityUntil', 'complete', 'latestAttempt', 'matchingCount', 'unknownCount', 'rows', 'detailCursor']) || typeof v.deviceId !== 'string' || !validWindowsDeviceId(v.deviceId) || typeof v.identity !== 'string' || !/^[a-f0-9]{64}$/.test(v.identity) || !['not_configured', 'disabled', 'awaiting', 'ready', 'unavailable'].includes(v.status as string) || !timestamp(v.authorityUntil) || inventoryAge(v.authorityUntil, page.serverNow) <= 0 || !integer(v.matchingCount, 32768) || !integer(v.unknownCount, 32768) || !Array.isArray(v.rows) || v.rows.length > (page.mode === 'fleet' ? FLEET_SOFTWARE_PREVIEW_ROWS : FLEET_SOFTWARE_DETAIL_ROWS) || !v.rows.every(validFullSoftwareRow) || !validFullSoftwareCursor(v.detailCursor) || v.latestAttempt !== null && !validAttempt(v.latestAttempt, page.serverNow)) return false;
    if (!page.cursorExpiresAt || inventoryAge(v.authorityUntil, page.cursorExpiresAt) < 0) return false;
    if (v.status !== 'ready') return v.complete === null && v.matchingCount === 0 && v.unknownCount === 0 && v.rows.length === 0 && v.detailCursor === '' && (v.status !== 'not_configured' || v.latestAttempt === null);
    if (!validFullSoftwareComplete(v.complete, v.deviceId, page.serverNow) || inventoryAge(v.complete.manifest.expiresAt, page.cursorExpiresAt) < 0 || v.matchingCount + v.unknownCount > v.complete.manifest.rowCount || !validAttempt(v.latestAttempt, page.serverNow) || v.latestAttempt.sequence < v.complete.manifest.sequence) return false;
    const a = v.latestAttempt, m = v.complete.manifest;
    if (a.sequence === m.sequence && (a.status !== 'complete' || a.attemptedAt !== m.captureStartedAt)) return false;
    const offset = page.mode === 'fleet' ? 0 : page.offset, limit = page.mode === 'fleet' ? FLEET_SOFTWARE_PREVIEW_ROWS : FLEET_SOFTWARE_DETAIL_ROWS;
    if (offset > v.matchingCount || v.rows.length !== Math.min(limit, v.matchingCount - offset) || (page.mode === 'fleet' ? v.detailCursor === '' : v.detailCursor !== '')) return false;
    const rows = v.rows as FullSoftwareRow[];
    return rows.every((row, i) => (i === 0 || rows[i - 1].registrationId < row.registrationId) && (page.name === '' || row.nameQuality === 'observed') && (page.version === '' || row.versionQuality === 'observed'));
}
export function sameFleetSoftwareSource(a: FleetSoftwareItem, b: FleetSoftwareItem): boolean {
    return a.deviceId === b.deviceId && a.identity === b.identity && a.status === b.status && a.authorityUntil === b.authorityUntil && a.matchingCount === b.matchingCount && a.unknownCount === b.unknownCount && (a.complete === null ? b.complete === null : b.complete !== null && sameFullSoftwareComplete(a.complete, b.complete));
}
export function validFleetSoftwarePage(v: unknown, query: FleetSoftwareQuery, expected: FleetSoftwareExpected): v is FleetSoftwarePage {
    if (!validFleetSoftwareQuery(query) || !exact(v, ['schemaVersion', 'serverNow', 'status', 'name', 'version', 'mode', 'totalDevices', 'offset', 'items', 'nextCursor', 'cursorExpiresAt']) || v.schemaVersion !== 'tracebolt.windows-fleet-software-page.v1' || !timestamp(v.serverNow) || !['ready', 'not_configured'].includes(v.status as string) || v.name !== query.name || v.version !== query.version || v.mode !== expected.mode || !integer(v.totalDevices, FLEET_SOFTWARE_MAX_DEVICES) || !integer(v.offset, 32768) || v.offset !== expected.offset || !Array.isArray(v.items) || v.items.length > (v.mode === 'fleet' ? FLEET_SOFTWARE_PAGE_DEVICES : 1) || !validFullSoftwareCursor(v.nextCursor) || v.nextCursor !== '' && v.nextCursor === query.cursor) return false;
    if (v.status === 'not_configured') return expected.mode === 'fleet' && query.cursor === '' && v.offset === 0 && v.totalDevices === 0 && v.items.length === 0 && v.nextCursor === '' && v.cursorExpiresAt === null;
    if (!timestamp(v.cursorExpiresAt) || inventoryAge(v.cursorExpiresAt, v.serverNow) <= 0 || inventoryAge(v.cursorExpiresAt, v.serverNow) > FLEET_SOFTWARE_LIFETIME_MS || expected.deadline !== undefined && v.cursorExpiresAt !== expected.deadline || expected.totalDevices !== undefined && v.totalDevices !== expected.totalDevices) return false;
    const page = v as unknown as FleetSoftwarePage;
    if (!page.items.every(item => validItem(item, page)) || new Set(page.items.map(item => item.deviceId)).size !== page.items.length || new Set(page.items.map(item => item.identity)).size !== page.items.length) return false;
    if (page.mode === 'fleet') return page.items.every((item, i) => i === 0 || page.items[i - 1].deviceId < item.deviceId) && page.offset <= page.totalDevices && page.items.length === Math.min(FLEET_SOFTWARE_PAGE_DEVICES, page.totalDevices - page.offset) && (page.nextCursor !== '') === (page.offset + page.items.length < page.totalDevices);
    return page.totalDevices > 0 && page.items.length === 1 && page.items[0].status === 'ready' && !!expected.device && sameFleetSoftwareSource(expected.device, page.items[0]) && (page.nextCursor !== '') === (page.offset + page.items[0].rows.length < page.items[0].matchingCount);
}
export function fleetSoftwareVisible(page: FleetSoftwarePage, elapsed: number): boolean {
    return page.status === 'ready' && page.cursorExpiresAt !== null && Number.isFinite(elapsed) && elapsed >= 0 && [page.cursorExpiresAt, ...page.items.flatMap(item => [item.authorityUntil, ...(item.complete ? [item.complete.manifest.expiresAt] : [])])].every(expiry => inventoryAge(expiry, page.serverNow) > elapsed);
}
export function fleetSoftwareFresh(item: FleetSoftwareItem, serverNow: string, elapsed: number): boolean {
    if (!item.complete || !Number.isFinite(elapsed) || elapsed < 0) return false;
    const age = inventoryAge(serverNow, item.complete.manifest.captureStartedAt) + elapsed;
    return age >= 0 && age <= 120000;
}
