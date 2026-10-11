import vectors from './windows-full-processes-store-fixture.json';
import type { FullProcessesQuery } from './windows-full-processes-types';
import { describe, expect, it } from 'vitest';
import { compareFullProcessesRows, fullProcessesManifestHash, fullProcessesVisible, validFullProcessesRow, validFullProcessesPage, validFullProcessesSearch } from './windows-full-processes-types';
import { fullProcessesRows, fullProcessesComplete, fullProcessesDevice, fullProcessesPage, fullProcessesQuery, fullProcessesUnavailable } from './windows-full-processes-fixtures';

describe('complete Windows machine software bounded page contract', () => {
    it.each(vectors)('admits actual SQLite page vector $name', vector => { expect(validFullProcessesPage(vector.page, vector.page.deviceId, vector.query as FullProcessesQuery, vector.page.offset)).toBe(true); });
    it('admits synthetic vectors with 617 processes and positively complete zero', () => {
        expect(validFullProcessesPage(fullProcessesPage(), fullProcessesDevice, fullProcessesQuery, 0)).toBe(true);
        expect(validFullProcessesPage(fullProcessesPage(fullProcessesQuery, [], fullProcessesComplete(true)), fullProcessesDevice, fullProcessesQuery, 0)).toBe(true);
    });
    it('accepts a byte-limited short nonterminal page without treating it as the end', () => { const page = fullProcessesPage(); page.rows = page.rows.slice(0, 71); expect(validFullProcessesPage(page, fullProcessesDevice, fullProcessesQuery, 0)).toBe(true); });
    it.each(['not_configured', 'disabled', 'awaiting', 'unavailable'] as const)('keeps %s distinct from a successful empty generation', status => {
        expect(validFullProcessesPage(fullProcessesUnavailable(status), fullProcessesDevice, fullProcessesQuery, 0)).toBe(true);
        const bad = fullProcessesUnavailable(status); bad.rows = fullProcessesRows().slice(0, 1);
        expect(validFullProcessesPage(bad, fullProcessesDevice, fullProcessesQuery, 0)).toBe(false);
    });
    it('validates empty final search pages and generation-bound later pages', () => {
        const query = { ...fullProcessesQuery, search: 'not-present' };
        expect(validFullProcessesPage(fullProcessesPage(query), fullProcessesDevice, query, 0)).toBe(true);
        const later = { ...fullProcessesQuery, cursor: 'cursor_600.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
        expect(validFullProcessesPage(fullProcessesPage(later, fullProcessesRows(), fullProcessesComplete(), 600), fullProcessesDevice, later, 600)).toBe(true);
    });
    it.each([
        (v: ReturnType<typeof fullProcessesPage>) => { (v as unknown as Record<string, unknown>).extra = 'private'; },
        v => { v.search = 'different'; }, v => { v.sort = 'name-desc'; }, v => { v.limit = 99; }, v => { v.offset = 1; }, v => { v.matchingCount = 0; },
        v => { v.rows = []; }, v => { v.rows.push(v.rows[0]); }, v => { v.rows[0].pid = v.rows[1].pid; }, v => { v.rows.reverse(); },
        v => { v.nextCursor = ''; }, v => { v.nextCursor = 'bad cursor'; }, v => { v.nextCursor = 'a'.repeat(4097); },
        v => { v.rows[0].pid = -1; }, v => { v.rows[0].nameQuality = 'unavailable'; }, v => { v.rows[0].name = null; },
        v => { v.rows[0].name = '\u0000'; }, v => { v.rows[0].name = 'a'.repeat(260); }, v => { v.rows[0].threads = 0x100000000; },
        v => { v.grantId = 'd'.repeat(32); }, v => { v.authorityUntil = null; }, v => { v.grantRevision = 0; },
        v => { v.complete!.manifest.rowCount = 618; }, v => { v.complete!.manifestSha256 = 'a'.repeat(64); },
        v => { v.complete!.manifest.generationId = `sample_${'a'.repeat(32)}`; v.complete!.manifestSha256 = fullProcessesManifestHash(v.complete!.manifest); },
        v => { v.complete!.manifest.expiresAt = '2026-10-13T06:00:00Z'; v.complete!.manifestSha256 = fullProcessesManifestHash(v.complete!.manifest); },
        v => { v.complete!.receivedAt = '2026-10-11T06:00:00Z'; }, v => { v.cursorExpiresAt = v.serverNow; },
        v => { v.cursorExpiresAt = '2026-10-11T06:15:10.000000001Z'; }, v => { v.latestAttempt = null; }, v => { v.latestAttempt!.status = 'pending'; },
        v => { v.latestAttempt!.reason = 'access_denied'; }, v => { v.latestAttempt!.attemptedAt = '2026-10-11T06:00:01Z'; },
    ] as ((v: ReturnType<typeof fullProcessesPage>) => void)[])('rejects malformed/inconsistent contract case %#', mutate => {
        const page = fullProcessesPage(); mutate(page); expect(validFullProcessesPage(page, fullProcessesDevice, fullProcessesQuery, 0)).toBe(false);
    });
    it('accepts independently failed latest attempts without changing prior capture metadata', () => {
        const page = fullProcessesPage(); page.latestAttempt = { sequence: 2, attemptedAt: '2026-10-11T06:00:09Z', status: 'source_failed', reason: 'access_denied' };
        expect(validFullProcessesPage(page, fullProcessesDevice, fullProcessesQuery, 0)).toBe(true);
    });
    it('keeps text literal, accepts valid UTF-16 pairs and enforces byte/code-unit limits', () => {
        expect(validFullProcessesSearch('[.*] Ä <script>')).toBe(true); expect(validFullProcessesSearch('😀'.repeat(64))).toBe(true); expect(validFullProcessesSearch('😀'.repeat(65))).toBe(false); expect(validFullProcessesSearch('\ud800')).toBe(false);
        const row = fullProcessesRows()[616]; expect(validFullProcessesRow(row)).toBe(true); row.name = '😀'.repeat(129) + 'a'; expect(validFullProcessesRow(row)).toBe(true); row.name += 'a'; expect(validFullProcessesRow(row)).toBe(false);
    });
    it('preserves PID zero, duplicate names, missing names, and maximum uint32 fields', () => {
        const rows = fullProcessesRows(3); rows[0].name = rows[1].name; rows[1].parentPid = 0xffffffff; rows[1].threads = 0xffffffff; rows[2].name = null; rows[2].nameQuality = 'unavailable';
        expect(rows.every(validFullProcessesRow)).toBe(true); expect(rows[0].pid).toBe(0);
    });
    it('rejects paths, empty observed names, malformed names, fractional and out-of-range numeric fields', () => {
        const row = fullProcessesRows(1)[0];
        for (const name of ['', 'C:\\Windows\\bad.exe', 'path/bad.exe', '\ud800', '\u0000', 'x'.repeat(260)]) expect(validFullProcessesRow({ ...row, name })).toBe(false);
        for (const field of ['pid', 'parentPid', 'threads']) for (const value of [-1, 0.5, 0x100000000, Infinity, '1', null]) expect(validFullProcessesRow({ ...row, [field]: value })).toBe(false);
        expect(validFullProcessesRow({ ...row, cpuPercent: 5 })).toBe(false);
    });
    it('uses numeric PID/parent/thread sorting, Unicode scalar name order and stable PID ties', () => {
        const [a, b] = fullProcessesRows(2); a.pid = 2; b.pid = 10; a.parentPid = 2; b.parentPid = 10; a.threads = 2; b.threads = 10;
        for (const field of ['pid', 'parentPid', 'threads'] as const) { expect(compareFullProcessesRows(a, b, `${field}-asc`)).toBeLessThan(0); expect(compareFullProcessesRows(a, b, `${field}-desc`)).toBeGreaterThan(0); }
        a.name = '\uE000'; b.name = '😀'; expect(compareFullProcessesRows(a, b, 'name-asc')).toBeLessThan(0);
        a.name = null; expect(compareFullProcessesRows(a, b, 'name-desc')).toBeGreaterThan(0); expect(compareFullProcessesRows(a, b, 'name-asc')).toBeGreaterThan(0);
        a.name = b.name; expect(compareFullProcessesRows(a, b, 'name-desc')).toBeLessThan(0); a.threads = b.threads; expect(compareFullProcessesRows(a, b, 'threads-desc')).toBeLessThan(0);
    });
    it('respects original source, authority and cursor expiry at submillisecond boundaries', () => {
        const page = fullProcessesPage(); expect(fullProcessesVisible(page, 899999.999)).toBe(true); expect(fullProcessesVisible(page, 900000)).toBe(false); expect(fullProcessesVisible(page, Infinity)).toBe(false);
        page.authorityUntil = '2026-10-11T06:00:10.000000001Z'; expect(fullProcessesVisible(page, 0)).toBe(true); expect(fullProcessesVisible(page, 0.000001)).toBe(false);
    });
});
