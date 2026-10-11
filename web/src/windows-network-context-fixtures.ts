import { sha256Bytes } from './sha256';
import { compareNetworkContextRows, networkContextGenerationId, networkContextManifestHash } from './windows-network-context-types';
import type { NetworkContextComplete, NetworkContextPage, NetworkContextQuery, NetworkContextRow } from './windows-network-context-types';
export const networkContextDevice = `agent_${'1'.repeat(32)}`;
export const networkContextNow = '2026-10-11T06:00:10Z';
export const networkContextQuery: NetworkContextQuery = { kind: 'route', search: '', sort: 'source-asc', limit: 100, cursor: '' };
/** Invented source-local rows only; matching indices never imply a join. */
export function networkContextRows(): NetworkContextRow[] {
    return [...Array.from({ length: 205 }, (_, i): NetworkContextRow => ({ id: i + 1, kind: 'route', interfaceIndex: i % 3 + 1, route: { destinationScopeId: 0, destination: `192.0.${i}.0/24`, nextHop: '192.0.2.1', metric: i, protocol: 3, origin: 0 } })),
        { id: 206, kind: 'route', interfaceIndex: 7, route: { destinationScopeId: 7, destination: '2001:db8::/32', nextHop: 'fe80::1%7', metric: 0xffffffff, protocol: 3, origin: 2 } },
        { id: 207, kind: 'interface', interfaceIndex: 7, counters: { alias: 'Fixture <adapter> [.*]', aliasQuality: 'observed', inOctets: '18446744073709551615', outOctets: '9007199254740993', inErrors: '0', outErrors: '18446744073709551615', inDiscards: '0', outDiscards: '1' } },
        { id: 208, kind: 'interface', interfaceIndex: 1, counters: { alias: null, aliasQuality: 'unavailable', inOctets: '0', outOctets: '0', inErrors: '0', outErrors: '0', inDiscards: '0', outDiscards: '0' } }];
}
export function replaceNetworkContextGeneration(complete: NetworkContextComplete, rows: NetworkContextRow[], sequence = complete.manifest.sequence + 1) {
    const m = complete.manifest;
    const raw = JSON.stringify(rows).replace(/[<>&\u2028\u2029]/g, c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
    m.rowCount = rows.length; m.rowsBytes = new TextEncoder().encode(raw).byteLength; m.rowsSha256 = sha256Bytes(new TextEncoder().encode(`tracebolt.windows-network-context.rows.v1\0${raw}`)); m.chunkCount = Math.max(1, Math.ceil(rows.length / 128)); m.sequence = sequence; m.generationId = networkContextGenerationId(m.deviceId, m.grantId, sequence); complete.manifestSha256 = networkContextManifestHash(m);
}
export function networkContextComplete(empty = false): NetworkContextComplete {
    const complete: NetworkContextComplete = { manifest: { schemaVersion: 'tracebolt.windows-network-context-manifest.v1', scope: 'windows-network-context-v1', source: 'ip-helper-routes-and-raw-interface-counters', coverage: 'caller_visible_tables_complete_nonatomic', deviceId: networkContextDevice, senderBinding: '2'.repeat(64), grantId: '3'.repeat(32), grantRevision: 1, sequence: 1, generationId: '', captureStartedAt: '2026-10-11T06:00:00Z', captureFinishedAt: '2026-10-11T06:00:01Z', expiresAt: '2026-10-12T06:00:00Z', rowCount: 0, rowsBytes: 0, rowsSha256: '', chunkCount: 1 }, manifestSha256: '', receivedAt: '2026-10-11T06:00:02Z' };
    replaceNetworkContextGeneration(complete, empty ? [] : networkContextRows(), 1); return complete;
}
export function networkContextPage(query: NetworkContextQuery = networkContextQuery, rows = networkContextRows(), complete = networkContextComplete(), offset = 0): NetworkContextPage {
    const search = query.search.toLowerCase();
    // This synthetic server alone filters the whole generation. The browser holds one page.
    const matching = rows.filter(row => (query.kind === 'all' || row.kind === query.kind) && [String(row.id), String(row.interfaceIndex), ...(row.kind === 'route' ? Object.values(row.route).map(String) : Object.values(row.counters).map(v => v ?? ''))].some(value => value.toLowerCase().includes(search))).sort((a, b) => compareNetworkContextRows(a, b, query.sort));
    const selected = matching.slice(offset, offset + query.limit);
    return { kind: query.kind, schemaVersion: 'tracebolt.windows-network-context-page.v1', deviceId: networkContextDevice, serverNow: networkContextNow, status: 'ready', authorityUntil: '2026-10-12T05:00:00Z', grantId: complete.manifest.grantId, grantRevision: complete.manifest.grantRevision, complete, latestAttempt: { sequence: complete.manifest.sequence, attemptedAt: complete.manifest.captureStartedAt, status: 'complete', reason: '' }, search: query.search, sort: query.sort, limit: query.limit, offset, matchingCount: matching.length, rows: selected, nextCursor: offset + selected.length < matching.length ? `cursor_${offset + selected.length}.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA` : '', cursorExpiresAt: '2026-10-11T06:15:10Z' };
}
export function networkContextUnavailable(status: Exclude<NetworkContextPage['status'], 'ready'>, query = networkContextQuery): NetworkContextPage {
    return { ...networkContextPage(query), status, complete: null, latestAttempt: null, offset: 0, matchingCount: 0, rows: [], nextCursor: '', cursorExpiresAt: null, ...(status === 'not_configured' ? { authorityUntil: null, grantId: null, grantRevision: null } : {}) };
}
