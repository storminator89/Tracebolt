import { sha256Bytes } from './sha256';
import { compareFullProcessesRows, fullProcessesGenerationId, fullProcessesManifestHash } from './windows-full-processes-types';
import type { FullProcessesRow, FullProcessesComplete, FullProcessesPage, FullProcessesQuery } from './windows-full-processes-types';
export const fullProcessesDevice = `agent_${'1'.repeat(32)}`;
export const fullProcessesNow = '2026-10-11T06:00:10Z';
export const fullProcessesQuery: FullProcessesQuery = { search: '', sort: 'pid-asc', limit: 100, cursor: '' };
/** Invented rows only. PID zero is a real valid identifier in this contract. */
export function fullProcessesRows(count = 617): FullProcessesRow[] {
    return Array.from({ length: count }, (_, pid) => ({ pid, parentPid: pid > 0 ? Math.floor(pid / 2) : 0, name: `Fixture Process ${String(pid).padStart(4, '0')}`, nameQuality: 'observed', threads: pid % 13 }));
}
export function fullProcessesComplete(empty = false): FullProcessesComplete {
    const complete: FullProcessesComplete = { manifest: { schemaVersion: 'tracebolt.windows-complete-processes-manifest.v1', scope: 'windows-complete-processes-v1', source: 'toolhelp-process-snapshot', coverage: 'caller_visible_process_snapshot_complete', deviceId: fullProcessesDevice, senderBinding: '2'.repeat(64), grantId: '3'.repeat(32), grantRevision: 1, sequence: 1, generationId: '', captureStartedAt: '2026-10-11T06:00:00Z', captureFinishedAt: '2026-10-11T06:00:01Z', expiresAt: '2026-10-12T06:00:00Z', rowCount: 0, rowsBytes: 0, rowsSha256: '', chunkCount: 1 }, manifestSha256: '', receivedAt: '2026-10-11T06:00:02Z' };
    replaceFullProcessesGeneration(complete, empty ? [] : fullProcessesRows(), 1); return complete;
}
export function replaceFullProcessesGeneration(complete: FullProcessesComplete, rows: FullProcessesRow[], sequence = complete.manifest.sequence + 1) {
    const m = complete.manifest;
    const raw = JSON.stringify(rows).replace(/[<>&\u2028\u2029]/g, c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
    m.rowCount = rows.length; m.rowsBytes = new TextEncoder().encode(raw).byteLength; m.rowsSha256 = sha256Bytes(new TextEncoder().encode(`tracebolt.windows-complete-processes.rows.v1\0${raw}`)); m.chunkCount = Math.max(1, Math.ceil(rows.length / 128)); m.sequence = sequence; m.generationId = fullProcessesGenerationId(m.deviceId, m.grantId, sequence); complete.manifestSha256 = fullProcessesManifestHash(m);
}
export function fullProcessesPage(query: FullProcessesQuery = fullProcessesQuery, rows = fullProcessesRows(), complete = fullProcessesComplete(), offset = 0): FullProcessesPage {
    // Entire-generation search/sort belongs to this synthetic server, never the client.
    const search = query.search.toLowerCase();
    const matching = rows.filter(row => [row.name ?? '', String(row.pid), String(row.parentPid), String(row.threads)].some(value => value.toLowerCase().includes(search))).sort((a, b) => compareFullProcessesRows(a, b, query.sort));
    const selected = matching.slice(offset, offset + query.limit);
    return { schemaVersion: 'tracebolt.windows-full-processes-page.v1', deviceId: fullProcessesDevice, serverNow: fullProcessesNow, status: 'ready', authorityUntil: '2026-10-12T05:00:00Z', grantId: complete.manifest.grantId, grantRevision: complete.manifest.grantRevision, complete, latestAttempt: { sequence: complete.manifest.sequence, attemptedAt: complete.manifest.captureStartedAt, status: 'complete', reason: '' }, search: query.search, sort: query.sort, limit: query.limit, offset, matchingCount: matching.length, rows: selected, nextCursor: offset + selected.length < matching.length ? `cursor_${offset + selected.length}.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA` : '', cursorExpiresAt: '2026-10-11T06:15:10Z' };
}
export function fullProcessesUnavailable(status: Exclude<FullProcessesPage['status'], 'ready'>): FullProcessesPage {
    return { ...fullProcessesPage(), status, complete: null, latestAttempt: null, offset: 0, matchingCount: 0, rows: [], nextCursor: '', cursorExpiresAt: null, ...(status === 'not_configured' ? { authorityUntil: null, grantId: null, grantRevision: null } : {}) };
}
