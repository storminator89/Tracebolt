import vectors from './windows-full-services-go-fixture.json';
import { sha256Bytes } from './sha256';
import { compareFullServiceRows, fullServicesGenerationId, fullServicesManifestHash } from './windows-full-services-types';
import type { FullServiceRow, FullServicesComplete, FullServicesPage, FullServicesQuery } from './windows-full-services-types';
export const fullServicesDevice = vectors[0].complete.manifest.deviceId;
export const fullServicesNow = '2026-10-11T06:00:10Z';
export const fullServicesQuery: FullServicesQuery = { search: '', sort: 'name-asc', limit: 100, cursor: '' };
export function fullServiceRows(): FullServiceRow[] { return structuredClone(vectors[0].rows) as FullServiceRow[]; }
export function fullServicesComplete(empty = false): FullServicesComplete { return structuredClone(vectors[empty ? 1 : 0].complete) as FullServicesComplete; }
export function replaceFullServicesGeneration(complete: FullServicesComplete, rows: FullServiceRow[], sequence = complete.manifest.sequence + 1) {
    const m = complete.manifest;
    const raw = JSON.stringify(rows).replace(/[<>&\u2028\u2029]/g, c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
    m.rowCount = rows.length; m.rowsBytes = new TextEncoder().encode(raw).byteLength; m.rowsSha256 = sha256Bytes(new TextEncoder().encode(`tracebolt.windows-complete-services.rows.v1\0${raw}`)); m.chunkCount = Math.max(1, Math.ceil(rows.length / 128)); m.sequence = sequence; m.generationId = fullServicesGenerationId(m.deviceId, m.grantId, sequence); complete.manifestSha256 = fullServicesManifestHash(m);
}
export function fullServicesPage(query: FullServicesQuery = fullServicesQuery, rows = fullServiceRows(), complete = fullServicesComplete(), offset = 0): FullServicesPage {
    // Fixture scan/sort intentionally happens only in this synthetic server.
    const search = query.search.toLowerCase();
    const matching = rows.filter(row => [row.name, row.displayName ?? '', row.state ?? '', row.pid === null ? '' : String(row.pid)].some(value => value.toLowerCase().includes(search))).sort((a, b) => compareFullServiceRows(a, b, query.sort));
    const selected = matching.slice(offset, offset + query.limit);
    return { schemaVersion: 'tracebolt.windows-full-services-page.v1', deviceId: fullServicesDevice, serverNow: fullServicesNow, status: 'ready', authorityUntil: '2026-10-12T05:00:00Z', grantId: complete.manifest.grantId, grantRevision: complete.manifest.grantRevision, complete, latestAttempt: { sequence: complete.manifest.sequence, attemptedAt: complete.manifest.captureStartedAt, status: 'complete', reason: '' }, search: query.search, sort: query.sort, limit: query.limit, offset, matchingCount: matching.length, rows: selected, nextCursor: offset + selected.length < matching.length ? `cursor_${offset + selected.length}.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA` : '', cursorExpiresAt: '2026-10-11T06:15:10Z' };
}
export function fullServicesUnavailable(status: Exclude<FullServicesPage['status'], 'ready'>): FullServicesPage {
    return { ...fullServicesPage(), status, complete: null, latestAttempt: null, offset: 0, matchingCount: 0, rows: [], nextCursor: '', cursorExpiresAt: null, ...(status === 'not_configured' ? { authorityUntil: null, grantId: null, grantRevision: null } : {}) };
}
