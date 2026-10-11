import interop from './windows-full-services-interop-fixtures.json';
import type { FullServicesQuery } from './windows-full-services-types';
import storeFixture from './windows-full-services-store-fixture.json';
import { describe, expect, it } from 'vitest';
import { compareFullServiceRows, fullServicesManifestHash, fullServicesVisible, validFullServiceRow, validFullServicesPage, validFullServicesSearch } from './windows-full-services-types';
import { fullServiceRows, fullServicesComplete, fullServicesDevice, fullServicesPage, fullServicesQuery, fullServicesUnavailable } from './windows-full-services-fixtures';

describe('complete Windows services exact Go contract', () => {
    it('admits actual Go Build vectors with 617 services and positively complete zero', () => {
        expect(validFullServicesPage(fullServicesPage(), fullServicesDevice, fullServicesQuery, 0)).toBe(true);
        expect(validFullServicesPage(fullServicesPage(fullServicesQuery, [], fullServicesComplete(true)), fullServicesDevice, fullServicesQuery, 0)).toBe(true);
    });
    it.each(interop)('admits real ledger vector $name including 2051 rows, Unicode and byte-short continuation', vector => { expect(validFullServicesPage(vector.page, vector.page.deviceId, vector.query as FullServicesQuery, vector.page.offset)).toBe(true); });
    it('accepts an exact Page exported by the real SQLite-backed Go store', () => { expect(validFullServicesPage(storeFixture, storeFixture.deviceId, fullServicesQuery, 0)).toBe(true); });
    it('accepts a byte-limited short nonterminal page without treating it as the end', () => { const page = fullServicesPage(); page.rows = page.rows.slice(0, 71); expect(validFullServicesPage(page, fullServicesDevice, fullServicesQuery, 0)).toBe(true); });
    it.each(['not_configured', 'disabled', 'awaiting', 'unavailable'] as const)('keeps %s distinct from a successful empty generation', status => {
        expect(validFullServicesPage(fullServicesUnavailable(status), fullServicesDevice, fullServicesQuery, 0)).toBe(true);
        const bad = fullServicesUnavailable(status); bad.rows = fullServiceRows().slice(0, 1);
        expect(validFullServicesPage(bad, fullServicesDevice, fullServicesQuery, 0)).toBe(false);
    });
    it('validates empty final search pages and generation-bound later pages', () => {
        const query = { ...fullServicesQuery, search: 'not-present' };
        expect(validFullServicesPage(fullServicesPage(query), fullServicesDevice, query, 0)).toBe(true);
        const later = { ...fullServicesQuery, cursor: 'cursor_600.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
        expect(validFullServicesPage(fullServicesPage(later, fullServiceRows(), fullServicesComplete(), 600), fullServicesDevice, later, 600)).toBe(true);
    });
    it.each([
        (v: ReturnType<typeof fullServicesPage>) => { (v as unknown as Record<string, unknown>).extra = 'private'; },
        v => { v.search = 'different'; }, v => { v.sort = 'name-desc'; }, v => { v.limit = 99; }, v => { v.offset = 1; }, v => { v.matchingCount = 0; },
        v => { v.rows = []; }, v => { v.rows.push(v.rows[0]); }, v => { v.rows[0].name = v.rows[1].name; }, v => { v.rows.reverse(); },
        v => { v.nextCursor = ''; }, v => { v.nextCursor = 'bad cursor'; }, v => { v.nextCursor = 'a'.repeat(4097); },
        v => { v.rows[0].pid = 1; }, v => { v.rows[0].displayNameQuality = 'unavailable'; }, v => { v.rows[0].state = null; },
        v => { v.rows[0].name = '\u0000'; }, v => { v.rows[0].displayName = 'a'.repeat(257); }, v => { v.rows[0].pid = 4294967296; },
        v => { v.grantId = 'd'.repeat(32); }, v => { v.authorityUntil = null; }, v => { v.grantRevision = 0; },
        v => { v.complete!.manifest.rowCount = 618; }, v => { v.complete!.manifestSha256 = 'a'.repeat(64); },
        v => { v.complete!.manifest.generationId = `sample_${'a'.repeat(32)}`; v.complete!.manifestSha256 = fullServicesManifestHash(v.complete!.manifest); },
        v => { v.complete!.manifest.expiresAt = '2026-10-13T06:00:00Z'; v.complete!.manifestSha256 = fullServicesManifestHash(v.complete!.manifest); },
        v => { v.complete!.receivedAt = '2026-10-11T06:00:00Z'; }, v => { v.cursorExpiresAt = v.serverNow; },
        v => { v.cursorExpiresAt = '2026-10-11T06:15:10.000000001Z'; }, v => { v.latestAttempt = null; }, v => { v.latestAttempt!.status = 'pending'; },
        v => { v.latestAttempt!.reason = 'access_denied'; }, v => { v.latestAttempt!.attemptedAt = '2026-10-11T06:00:01Z'; },
    ] as ((v: ReturnType<typeof fullServicesPage>) => void)[])('rejects malformed/inconsistent contract case %#', mutate => {
        const page = fullServicesPage(); mutate(page); expect(validFullServicesPage(page, fullServicesDevice, fullServicesQuery, 0)).toBe(false);
    });
    it('accepts independently failed latest attempts without changing prior capture metadata', () => {
        const page = fullServicesPage(); page.latestAttempt = { sequence: 2, attemptedAt: '2026-10-11T06:00:09Z', status: 'source_failed', reason: 'access_denied' };
        expect(validFullServicesPage(page, fullServicesDevice, fullServicesQuery, 0)).toBe(true);
    });
    it('keeps text literal, accepts valid UTF-16 pairs and enforces byte/code-unit limits', () => {
        expect(validFullServicesSearch('[.*] Ä <script>')).toBe(true); expect(validFullServicesSearch('😀'.repeat(64))).toBe(true); expect(validFullServicesSearch('😀'.repeat(65))).toBe(false); expect(validFullServicesSearch('\ud800')).toBe(false);
        const row = fullServiceRows()[616]; expect(validFullServiceRow(row)).toBe(true); row.displayName = '😀'.repeat(128); expect(validFullServiceRow(row)).toBe(true); row.displayName += 'a'; expect(validFullServiceRow(row)).toBe(false);
    });
    it.each(['stopped', 'start_pending', 'stop_pending', null] as const)('rejects a claimed observed PID for state %s', state => {
        const row = fullServiceRows()[1]; row.state = state; row.stateQuality = state === null ? 'unavailable' : 'observed'; expect(validFullServiceRow(row)).toBe(false); row.pid = null; row.pidQuality = 'unavailable'; expect(validFullServiceRow(row)).toBe(true);
    });
    it('uses UTF-8 scalar name order and keeps unavailable values last in both directions', () => {
        const [a, b] = fullServiceRows(); a.name = '\uE000'; b.name = '😀'; expect(compareFullServiceRows(a, b, 'name-asc')).toBeLessThan(0); a.pid = null; expect(compareFullServiceRows(a, b, 'pid-desc')).toBeGreaterThan(0); a.state = null; expect(compareFullServiceRows(a, b, 'state-asc')).toBeGreaterThan(0);
    });
    it('respects original source, authority and cursor expiry at submillisecond boundaries', () => {
        const page = fullServicesPage(); expect(fullServicesVisible(page, 899999.999)).toBe(true); expect(fullServicesVisible(page, 900000)).toBe(false); expect(fullServicesVisible(page, Infinity)).toBe(false);
        page.authorityUntil = '2026-10-11T06:00:10.000000001Z'; expect(fullServicesVisible(page, 0)).toBe(true); expect(fullServicesVisible(page, 0.000001)).toBe(false);
    });
});
