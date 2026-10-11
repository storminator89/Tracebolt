import storeFixture from './windows-full-software-store-fixture.json';
import type { FullSoftwareQuery } from './windows-full-software-types';
import { describe, expect, it } from 'vitest';
import { compareFullSoftwareRows, fullSoftwareManifestHash, fullSoftwareVisible, validFullSoftwareRow, validFullSoftwarePage, validFullSoftwareSearch } from './windows-full-software-types';
import { fullSoftwareRows, fullSoftwareComplete, fullSoftwareDevice, fullSoftwarePage, fullSoftwareQuery, fullSoftwareUnavailable } from './windows-full-software-fixtures';

describe('complete Windows machine software exact Go contract', () => {
    it.each(storeFixture)('admits actual SQLite vector $name', vector => { expect(validFullSoftwarePage(vector.page, vector.page.deviceId, vector.query as FullSoftwareQuery, vector.page.offset)).toBe(true); });
    it('admits actual Go Build vectors with 617 registrations and positively complete zero', () => {
        expect(validFullSoftwarePage(fullSoftwarePage(), fullSoftwareDevice, fullSoftwareQuery, 0)).toBe(true);
        expect(validFullSoftwarePage(fullSoftwarePage(fullSoftwareQuery, [], fullSoftwareComplete(true)), fullSoftwareDevice, fullSoftwareQuery, 0)).toBe(true);
    });
    it('accepts a byte-limited short nonterminal page without treating it as the end', () => { const page = fullSoftwarePage(); page.rows = page.rows.slice(0, 71); expect(validFullSoftwarePage(page, fullSoftwareDevice, fullSoftwareQuery, 0)).toBe(true); });
    it.each(['not_configured', 'disabled', 'awaiting', 'unavailable'] as const)('keeps %s distinct from a successful empty generation', status => {
        expect(validFullSoftwarePage(fullSoftwareUnavailable(status), fullSoftwareDevice, fullSoftwareQuery, 0)).toBe(true);
        const bad = fullSoftwareUnavailable(status); bad.rows = fullSoftwareRows().slice(0, 1);
        expect(validFullSoftwarePage(bad, fullSoftwareDevice, fullSoftwareQuery, 0)).toBe(false);
    });
    it('validates empty final search pages and generation-bound later pages', () => {
        const query = { ...fullSoftwareQuery, search: 'not-present' };
        expect(validFullSoftwarePage(fullSoftwarePage(query), fullSoftwareDevice, query, 0)).toBe(true);
        const later = { ...fullSoftwareQuery, cursor: 'cursor_600.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
        expect(validFullSoftwarePage(fullSoftwarePage(later, fullSoftwareRows(), fullSoftwareComplete(), 600), fullSoftwareDevice, later, 600)).toBe(true);
    });
    it.each([
        (v: ReturnType<typeof fullSoftwarePage>) => { (v as unknown as Record<string, unknown>).extra = 'private'; },
        v => { v.search = 'different'; }, v => { v.sort = 'name-desc'; }, v => { v.limit = 99; }, v => { v.offset = 1; }, v => { v.matchingCount = 0; },
        v => { v.rows = []; }, v => { v.rows.push(v.rows[0]); }, v => { v.rows[0].registrationId = v.rows[1].registrationId; }, v => { v.rows.reverse(); },
        v => { v.nextCursor = ''; }, v => { v.nextCursor = 'bad cursor'; }, v => { v.nextCursor = 'a'.repeat(4097); },
        v => { v.rows[0].registryView = '16' as '32'; }, v => { v.rows[0].nameQuality = 'unavailable'; }, v => { v.rows[0].name = null; },
        v => { v.rows[0].name = '\u0000'; }, v => { v.rows[0].publisher = 'a'.repeat(513); }, v => { v.rows[0].registrationId = 'A'.repeat(64); },
        v => { v.grantId = 'd'.repeat(32); }, v => { v.authorityUntil = null; }, v => { v.grantRevision = 0; },
        v => { v.complete!.manifest.rowCount = 618; }, v => { v.complete!.manifestSha256 = 'a'.repeat(64); },
        v => { v.complete!.manifest.generationId = `sample_${'a'.repeat(32)}`; v.complete!.manifestSha256 = fullSoftwareManifestHash(v.complete!.manifest); },
        v => { v.complete!.manifest.expiresAt = '2026-10-13T06:00:00Z'; v.complete!.manifestSha256 = fullSoftwareManifestHash(v.complete!.manifest); },
        v => { v.complete!.receivedAt = '2026-10-11T06:00:00Z'; }, v => { v.cursorExpiresAt = v.serverNow; },
        v => { v.cursorExpiresAt = '2026-10-11T06:15:10.000000001Z'; }, v => { v.latestAttempt = null; }, v => { v.latestAttempt!.status = 'pending'; },
        v => { v.latestAttempt!.reason = 'access_denied'; }, v => { v.latestAttempt!.attemptedAt = '2026-10-11T06:00:01Z'; },
    ] as ((v: ReturnType<typeof fullSoftwarePage>) => void)[])('rejects malformed/inconsistent contract case %#', mutate => {
        const page = fullSoftwarePage(); mutate(page); expect(validFullSoftwarePage(page, fullSoftwareDevice, fullSoftwareQuery, 0)).toBe(false);
    });
    it('accepts independently failed latest attempts without changing prior capture metadata', () => {
        const page = fullSoftwarePage(); page.latestAttempt = { sequence: 2, attemptedAt: '2026-10-11T06:00:09Z', status: 'source_failed', reason: 'access_denied' };
        expect(validFullSoftwarePage(page, fullSoftwareDevice, fullSoftwareQuery, 0)).toBe(true);
    });
    it('keeps text literal, accepts valid UTF-16 pairs and enforces byte/code-unit limits', () => {
        expect(validFullSoftwareSearch('[.*] Ä <script>')).toBe(true); expect(validFullSoftwareSearch('😀'.repeat(64))).toBe(true); expect(validFullSoftwareSearch('😀'.repeat(65))).toBe(false); expect(validFullSoftwareSearch('\ud800')).toBe(false);
        const row = fullSoftwareRows()[616]; expect(validFullSoftwareRow(row)).toBe(true); row.publisher = '😀'.repeat(256); expect(validFullSoftwareRow(row)).toBe(true); row.publisher += 'a'; expect(validFullSoftwareRow(row)).toBe(false);
    });
    it('preserves duplicate names across views, observed empty values and unavailable fields', () => {
        const rows = fullSoftwareRows().slice(0, 3); rows[0].name = rows[1].name; rows[1].publisher = ''; rows[2].name = null; rows[2].nameQuality = 'unavailable';
        expect(rows.every(validFullSoftwareRow)).toBe(true);
        const page = fullSoftwarePage(fullSoftwareQuery, rows); page.complete!.manifest.rowCount = 3; page.complete!.manifest.chunkCount = 1; page.complete!.manifestSha256 = fullSoftwareManifestHash(page.complete!.manifest);
        expect(validFullSoftwarePage(page, fullSoftwareDevice, fullSoftwareQuery, 0)).toBe(true);
    });
    it('uses Unicode scalar order, registration-ID ties, and unavailable values last in both directions', () => {
        const [a, b] = fullSoftwareRows(); a.name = '\uE000'; b.name = '😀'; expect(compareFullSoftwareRows(a, b, 'name-asc')).toBeLessThan(0);
        for (const field of ['name', 'version', 'publisher'] as const) {
            a[field] = null; expect(compareFullSoftwareRows(a, b, `${field}-desc`)).toBeGreaterThan(0); expect(compareFullSoftwareRows(a, b, `${field}-asc`)).toBeGreaterThan(0);
            a[field] = b[field]; expect(compareFullSoftwareRows(a, b, `${field}-desc`)).toBeLessThan(0);
        }
        a.registryView = b.registryView; expect(compareFullSoftwareRows(a, b, 'view-desc')).toBeLessThan(0);
    });
    it('respects original source, authority and cursor expiry at submillisecond boundaries', () => {
        const page = fullSoftwarePage(); expect(fullSoftwareVisible(page, 899999.999)).toBe(true); expect(fullSoftwareVisible(page, 900000)).toBe(false); expect(fullSoftwareVisible(page, Infinity)).toBe(false);
        page.authorityUntil = '2026-10-11T06:00:10.000000001Z'; expect(fullSoftwareVisible(page, 0)).toBe(true); expect(fullSoftwareVisible(page, 0.000001)).toBe(false);
    });
});
