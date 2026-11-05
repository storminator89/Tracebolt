import { describe, expect, it } from 'vitest';
import { journalPage } from './journal-fixtures';
import type { JournalRow } from './journal-types';
import { compareJournalTimestamp, journalMessageGroups, journalPageRows, journalTriageBinding } from './journal-triage-model';

const row = (timestamp: string, message = 'failure', priority = 3, unit = 'fixture.service'): JournalRow => ({ timestamp, message, priority, unit });
describe('journal display-page triage model', () => {
    it.each([
        ['2026-10-04T11:59:00Z', '2026-10-04T11:59:00.000000000Z', 0],
        ['2026-10-04T11:59:00.1Z', '2026-10-04T11:59:00.10Z', 0],
        ['2026-10-04T11:59:00.000000001Z', '2026-10-04T11:59:00.000000002Z', -1],
        ['2026-10-04T11:59:00.100000001Z', '2026-10-04T11:59:00.1Z', 1],
        ['2026-10-04T11:59:00.999999999Z', '2026-10-04T11:59:01Z', -1],
        ['2026-11-01T00:00:00Z', '2026-10-31T23:59:59.999999999Z', 1],
    ])('compares exact UTC timestamps %s and %s', (a, b, result) => {
        expect(compareJournalTimestamp(a, b)).toBe(result);
        expect(compareJournalTimestamp(b, a)).toBe(result === 0 ? 0 : -result);
    });
    it('preserves duplicate rows and stable source identity without mutating accepted rows', () => {
        const rows = [row('2026-10-04T11:59:00.000000003Z'), row('2026-10-04T11:59:00.000000001Z'), row('2026-10-04T11:59:00.000000001Z'), row('2026-10-04T11:59:00.000000002Z', 'notice', 5)];
        const original = structuredClone(rows);
        expect(journalPageRows(rows, null, 'source').map(value => value.index)).toEqual([0, 1, 2, 3]);
        expect(journalPageRows(rows, null, 'oldest').map(value => value.index)).toEqual([1, 2, 3, 0]);
        expect(journalPageRows(rows, null, 'newest').map(value => value.index)).toEqual([0, 3, 1, 2]);
        expect(journalPageRows(rows, 3, 'oldest').map(value => value.index)).toEqual([1, 2, 0]);
        expect(journalPageRows(rows, 0, 'source')).toEqual([]);
        expect(rows).toEqual(original);
    });
    it('groups only exact displayed message, severity and service and keeps all duplicate occurrences', () => {
        const rows = [row('2026-10-04T11:59:01Z', 'masked [redacted]'), row('2026-10-04T11:59:00Z', 'masked [redacted]'), row('2026-10-04T11:59:00Z', 'masked [redacted]'), row('2026-10-04T11:59:02Z', 'MASKED [redacted]'), row('2026-10-04T11:59:03Z', 'masked [redacted]', 4), row('2026-10-04T11:59:04Z', 'masked [redacted]', 3, 'other.service')];
        const groups = journalMessageGroups(journalPageRows(rows, null, 'source'));
        expect(groups).toHaveLength(4);
        expect(groups[0].rows.map(value => value.index)).toEqual([0, 1, 2]);
        expect(groups[0].first.index).toBe(1);
        expect(groups[0].last.index).toBe(0);
        expect(groups.reduce((count, group) => count + group.rows.length, 0)).toBe(rows.length);
        expect(journalMessageGroups(journalPageRows(rows, null, 'newest')).map(group => group.rows[0].index)).toEqual([5, 4, 3, 0]);
    });
    it('does not collide on separators or normalize Unicode, whitespace or source markup', () => {
        const values = ['a\u0000b', 'a', 'é', 'e\u0301', 'a ', '<img src=x>', 'a|3|fixture.service'];
        const groups = journalMessageGroups(journalPageRows(values.map(message => row('2026-10-04T11:59:00Z', message)), null, 'source'));
        expect(groups).toHaveLength(values.length);
        expect(new Set(groups.map(group => group.key)).size).toBe(values.length);
    });
    it('binds controls to every content authority and page boundary but not refreshing server time', () => {
        const page = journalPage(['one']);
        const baseline = journalTriageBinding(page, 'session');
        expect(journalTriageBinding({ ...page, serverNow: '2026-10-04T12:00:01Z' }, 'session')).toBe(baseline);
        expect(journalTriageBinding(page, 'other-session')).not.toBe(baseline);
        for (const change of [{ deviceId: 'other' }, { schemaVersion: 'tracebolt.journal-page.v2' as const }, { snapshotDigest: 'other' }, { offset: 100 }, { search: 'other' }]) expect(journalTriageBinding({ ...page, ...change }, 'session')).not.toBe(baseline);
        for (const field of ['id', 'sequence', 'queryDigest'] as const) expect(journalTriageBinding({ ...page, identity: { ...page.identity, [field]: 'other' } }, 'session')).not.toBe(baseline);
    });
    it('bounds results to the supplied display page without deriving counts from retained totals', () => {
        const page = journalPage(Array.from({ length: 100 }, () => 'same'));
        page.totalCapturedRows = page.matchedRows = 500;
        const groups = journalMessageGroups(journalPageRows(page.rows, null, 'source'));
        expect(groups).toHaveLength(1);
        expect(groups[0].rows).toHaveLength(100);
    });
});
