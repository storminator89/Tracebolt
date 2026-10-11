import { describe, expect, it } from 'vitest';
import { compareNetworkContextRows, networkContextKinds, networkContextManifestHash, networkContextSorts, networkContextVisible, validNetworkContextCounter, validNetworkContextPage, validNetworkContextRow, validNetworkContextSearch } from './windows-network-context-types';
import { networkContextComplete, networkContextDevice, networkContextPage, networkContextQuery, networkContextRows, networkContextUnavailable } from './windows-network-context-fixtures';

describe('independent Windows route and raw counter contract', () => {
    it('validates every source kind and sort and complete empty', () => {
        for (const kind of networkContextKinds) for (const sort of networkContextSorts) { const q = { ...networkContextQuery, kind, sort }; expect(validNetworkContextPage(networkContextPage(q), networkContextDevice, q, 0)).toBe(true); }
        expect(validNetworkContextPage(networkContextPage(networkContextQuery, [], networkContextComplete(true)), networkContextDevice, networkContextQuery, 0)).toBe(true);
    });
    it.each(['not_configured', 'disabled', 'awaiting', 'unavailable'] as const)('keeps %s different from complete empty', status => {
        const page = networkContextUnavailable(status); expect(validNetworkContextPage(page, networkContextDevice, networkContextQuery, 0)).toBe(true); page.rows = networkContextRows().slice(0, 1); expect(validNetworkContextPage(page, networkContextDevice, networkContextQuery, 0)).toBe(false);
    });
    it('accepts only exact unsigned64 strings without rounding max, unsafe integers or zero', () => {
        for (const value of ['0', '1', '9007199254740993', '18446744073709551615']) expect(validNetworkContextCounter(value)).toBe(true);
        for (const value of [0, 18446744073709551615, '', '00', '01', '-1', '+1', ' 1', '1 ', '1e2', '1.0', '18446744073709551616', '999999999999999999999', null]) expect(validNetworkContextCounter(value)).toBe(false);
        const row = networkContextRows().find(row => row.kind === 'interface')!; expect(validNetworkContextRow(row)).toBe(true);
        if (row.kind === 'interface') for (const key of ['inOctets', 'outOctets', 'inErrors', 'outErrors', 'inDiscards', 'outDiscards']) expect(validNetworkContextRow({ ...row, counters: { ...row.counters, [key]: '18446744073709551616' } })).toBe(false);
    });
    it('strictly validates canonical masked numeric routes, uint32 values and numeric scopes', () => {
        const row = networkContextRows()[0]; if (row.kind !== 'route') throw new Error('fixture');
        for (const [destination, nextHop] of [['0.0.0.0/0','0.0.0.0'],['192.0.2.255/32','192.0.2.1'],['::/0','::'],['2001:db8::/32','fe80::1%4294967295'],['2001:db8::1/128','::']]) expect(validNetworkContextRow({ ...row, route: { ...row.route, destination, nextHop } })).toBe(true);
        for (const [destination, nextHop] of [['192.0.2.1/24','192.0.2.1'],['192.0.2.0/33','192.0.2.1'],['192.0.2.0/024','192.0.2.1'],['192.0.2.0/24','example.test'],['192.0.2.0/24','::'],['192.0.2.0/24','192.0.2.1%1'],['2001:db8::1/32','::'],['2001:DB8::/32','::'],['::ffff:192.0.2.0/120','::ffff:192.0.2.1'],['::/0','fe80::1%0'],['::/0','fe80::1%01'],['::/0','fe80::1%name'],['::/0','fe80::1%4294967296'],['::/0','fe80::1%1%2']]) expect(validNetworkContextRow({ ...row, route: { ...row.route, destination, nextHop } })).toBe(false);
        expect(validNetworkContextRow({ ...row, route: { ...row.route, destinationScopeId: 1 } })).toBe(false);
        for (const value of [-1, -0, 0.5, 0x100000000, '1', null]) expect(validNetworkContextRow({ ...row, route: { ...row.route, destination: '::/0', nextHop: '::', destinationScopeId: value } })).toBe(false);
        for (const key of ['metric', 'protocol', 'origin']) for (const value of [-1, -0, 0.5, 0x100000000, '1', null]) expect(validNetworkContextRow({ ...row, route: { ...row.route, [key]: value } })).toBe(false);
        for (const key of ['id', 'interfaceIndex']) for (const value of [0, -1, 0.5, 0x100000000, '1']) expect(validNetworkContextRow({ ...row, [key]: value })).toBe(false);
        expect(validNetworkContextRow({ ...row, counters: {} })).toBe(false);
    });
    it('preserves unavailable aliases, literal markup and bounded valid UTF-16', () => {
        const row = networkContextRows()[207]; if (row.kind !== 'interface') throw new Error('fixture');
        expect(validNetworkContextRow(row)).toBe(true);
        for (const alias of ['<script> [.*] & 🛠', '😀'.repeat(128)]) expect(validNetworkContextRow({ ...row, counters: { ...row.counters, alias, aliasQuality: 'observed' } })).toBe(true);
        for (const alias of ['', '\ud800', '\0', 'a'.repeat(257), '😀'.repeat(129)]) expect(validNetworkContextRow({ ...row, counters: { ...row.counters, alias, aliasQuality: 'observed' } })).toBe(false);
        expect(validNetworkContextRow({ ...row, counters: { ...row.counters, aliasQuality: 'observed' } })).toBe(false);
        expect(validNetworkContextSearch('😀'.repeat(64))).toBe(true); expect(validNetworkContextSearch('😀'.repeat(65))).toBe(false); expect(validNetworkContextSearch('\ud800')).toBe(false);
    });
    it.each([
        (v: ReturnType<typeof networkContextPage>) => { (v as unknown as Record<string, unknown>).extra = true; },
        v => { v.kind = 'interface'; }, v => { v.search = 'private'; }, v => { v.sort = 'interface-desc'; }, v => { v.limit = 99; }, v => { v.offset = 1; }, v => { v.matchingCount = 0; },
        v => { v.rows = []; }, v => { v.rows.reverse(); }, v => { v.rows[0].id = v.rows[1].id; }, v => { v.rows[0] = networkContextRows()[207]; },
        v => { v.nextCursor = ''; }, v => { v.nextCursor = 'bad cursor'; }, v => { v.nextCursor = 'a'.repeat(4097); },
        v => { v.grantId = 'd'.repeat(32); }, v => { v.authorityUntil = null; }, v => { v.grantRevision = 0; },
        v => { v.complete!.manifest.rowCount = 4353; }, v => { v.complete!.manifestSha256 = 'a'.repeat(64); },
        v => { v.complete!.manifest.captureFinishedAt = '2026-10-11T06:00:06Z'; v.complete!.manifestSha256 = networkContextManifestHash(v.complete!.manifest); },
        v => { v.complete!.manifest.expiresAt = '2026-10-13T06:00:00Z'; v.complete!.manifestSha256 = networkContextManifestHash(v.complete!.manifest); },
        v => { v.complete!.receivedAt = '2026-10-11T06:00:00Z'; }, v => { v.cursorExpiresAt = v.serverNow; }, v => { v.cursorExpiresAt = '2026-10-11T06:15:10.000000001Z'; },
        v => { v.latestAttempt = null; }, v => { v.latestAttempt!.status = 'pending'; }, v => { v.latestAttempt!.reason = 'access_denied'; }, v => { v.latestAttempt!.attemptedAt = '2026-10-11T06:00:01Z'; },
    ] as ((v: ReturnType<typeof networkContextPage>) => void)[])('rejects inconsistent private envelope %#', mutate => {
        const page = networkContextPage(); mutate(page); expect(validNetworkContextPage(page, networkContextDevice, networkContextQuery, 0)).toBe(false);
    });
    it('accepts short byte-bounded nonterminal pages and distinct latest failed attempt', () => {
        const page = networkContextPage(); page.rows = page.rows.slice(0, 71); page.latestAttempt = { sequence: 2, attemptedAt: '2026-10-11T06:00:09Z', status: 'source_failed', reason: 'resource_limit' }; expect(validNetworkContextPage(page, networkContextDevice, networkContextQuery, 0)).toBe(true);
    });
    it('matches Go source order and numeric interface order with stable row IDs', () => {
        const route = networkContextRows()[0], counter = networkContextRows()[207];
        expect(compareNetworkContextRows(route, counter, 'source-asc')).toBeGreaterThan(0); expect(compareNetworkContextRows(route, counter, 'source-desc')).toBeLessThan(0);
        expect(compareNetworkContextRows(route, counter, 'interface-desc')).toBeGreaterThan(0);
        const other = { ...route, id: 9, interfaceIndex: 10 }; expect(compareNetworkContextRows(route, other, 'interface-asc')).toBeLessThan(0); expect(compareNetworkContextRows(route, other, 'interface-desc')).toBeGreaterThan(0);
        expect(compareNetworkContextRows(route, { ...route, id: 9 }, 'source-desc')).toBeLessThan(0);
    });
    it('honors original source/authority/cursor submillisecond expiry', () => {
        const page = networkContextPage(); expect(networkContextVisible(page, 899999.999)).toBe(true); expect(networkContextVisible(page, 900000)).toBe(false); expect(networkContextVisible(page, Infinity)).toBe(false);
        page.authorityUntil = '2026-10-11T06:00:10.000000001Z'; expect(networkContextVisible(page, 0)).toBe(true); expect(networkContextVisible(page, 0.000001)).toBe(false);
    });
});
