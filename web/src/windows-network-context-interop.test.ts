import { describe, expect, it } from 'vitest';
import vectors from './windows-network-context-store-fixture.json';
import { validNetworkContextPage } from './windows-network-context-types';
import type { NetworkContextQuery } from './windows-network-context-types';

describe('actual Go SQLite route and raw counter private page interoperability', () => {
    it.each(vectors)('validates $name without adapting retained metadata or decimal counters', vector => {
        expect(validNetworkContextPage(vector.page, vector.page.deviceId, vector.query as NetworkContextQuery, vector.page.offset)).toBe(true);
    });
    it('retains all ten source vectors, exact max uint64, scoped IPv6 and kind-bound continuations', () => {
        expect(vectors.map(vector => vector.name)).toEqual(['schemaAbsent', 'unavailable', 'first257', 'second100', 'lateSearch', 'retainedLatestFailed', 'scopedRoutes', 'exactCounters', 'allByInterface', 'completeEmpty']);
        const counters = vectors.find(v => v.name === 'exactCounters')!;
        expect(JSON.stringify(counters.page.rows)).toContain('18446744073709551615');
        const routes = vectors.find(v => v.name === 'scopedRoutes')!;
        expect(routes.page.rows.some(row => row.route && row.route.destinationScopeId > 0)).toBe(true);
        const first = vectors.find(v => v.name === 'first257')!, second = vectors.find(v => v.name === 'second100')!;
        expect(first.page.nextCursor).toBe(second.query.cursor); expect(second.page.offset).toBe(100);
        expect(validNetworkContextPage(second.page, second.page.deviceId, { ...second.query, kind: 'interface' } as NetworkContextQuery, 100)).toBe(false);
    });
});
