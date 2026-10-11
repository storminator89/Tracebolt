import vectors from './windows-full-software-go-fixture.json';
import { sha256Bytes } from './sha256';
import { compareFullSoftwareRows, fullSoftwareGenerationId, fullSoftwareManifestHash } from './windows-full-software-types';
import type { FullSoftwareRow, FullSoftwareComplete, FullSoftwarePage, FullSoftwareQuery } from './windows-full-software-types';
export const fullSoftwareDevice = vectors[0].complete.manifest.deviceId;
export const fullSoftwareNow = '2026-10-11T06:00:10Z';
export const fullSoftwareQuery: FullSoftwareQuery = { search: '', sort: 'name-asc', limit: 100, cursor: '' };
export function fullSoftwareRows(): FullSoftwareRow[] { return structuredClone(vectors[0].rows) as FullSoftwareRow[]; }
export function fullSoftwareComplete(empty = false): FullSoftwareComplete { return structuredClone(vectors[empty ? 1 : 0].complete) as FullSoftwareComplete; }
export function replaceFullSoftwareGeneration(complete: FullSoftwareComplete, rows: FullSoftwareRow[], sequence = complete.manifest.sequence + 1) {
    const m = complete.manifest;
    const raw = JSON.stringify(rows).replace(/[<>&\u2028\u2029]/g, c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
    m.rowCount = rows.length; m.rowsBytes = new TextEncoder().encode(raw).byteLength; m.rowsSha256 = sha256Bytes(new TextEncoder().encode(`tracebolt.windows-complete-machine-software.rows.v1\0${raw}`)); m.chunkCount = Math.max(1, Math.ceil(rows.length / 128)); m.sequence = sequence; m.generationId = fullSoftwareGenerationId(m.deviceId, m.grantId, sequence); complete.manifestSha256 = fullSoftwareManifestHash(m);
}
export function fullSoftwarePage(query: FullSoftwareQuery = fullSoftwareQuery, rows = fullSoftwareRows(), complete = fullSoftwareComplete(), offset = 0): FullSoftwarePage {
    // Fixture scan/sort intentionally happens only in this synthetic server.
    const search = query.search.toLowerCase();
    const matching = rows.filter(row => [row.name ?? '', row.version ?? '', row.publisher ?? '', row.registryView].some(value => value.toLowerCase().includes(search))).sort((a, b) => compareFullSoftwareRows(a, b, query.sort));
    const selected = matching.slice(offset, offset + query.limit);
    return { schemaVersion: 'tracebolt.windows-full-software-page.v1', deviceId: fullSoftwareDevice, serverNow: fullSoftwareNow, status: 'ready', authorityUntil: '2026-10-12T05:00:00Z', grantId: complete.manifest.grantId, grantRevision: complete.manifest.grantRevision, complete, latestAttempt: { sequence: complete.manifest.sequence, attemptedAt: complete.manifest.captureStartedAt, status: 'complete', reason: '' }, search: query.search, sort: query.sort, limit: query.limit, offset, matchingCount: matching.length, rows: selected, nextCursor: offset + selected.length < matching.length ? `cursor_${offset + selected.length}.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA` : '', cursorExpiresAt: '2026-10-11T06:15:10Z' };
}
export function fullSoftwareUnavailable(status: Exclude<FullSoftwarePage['status'], 'ready'>): FullSoftwarePage {
    return { ...fullSoftwarePage(), status, complete: null, latestAttempt: null, offset: 0, matchingCount: 0, rows: [], nextCursor: '', cursorExpiresAt: null, ...(status === 'not_configured' ? { authorityUntil: null, grantId: null, grantRevision: null } : {}) };
}
