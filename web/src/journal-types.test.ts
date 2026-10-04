import { describe, expect, it } from 'vitest';
import { journalDevice, journalNow, journalPage, journalView } from './journal-fixtures';
import { journalFold, validJournalPage, validJournalQuery, validJournalUnit, validJournalView } from './journal-types';
describe('strict bounded journal contract', () => {
    it('accepts documented lifecycle and complete empty capture', () => {
        for (const state of ['awaiting', 'pending', 'claimed', 'accepted', 'expired', 'canceled'] as const) expect(validJournalView(journalView(state), journalDevice)).toBe(true);
        expect(validJournalPage(journalPage([]), journalView(), '', 0)).toBe(true);
    });
    it.each(['*.service', 'foo.service;id', 'a..b.service', '-foo.service', 'foo@.service', 'foo@@bar.service', '/etc/foo.service', 'foo.socket', 'x'.repeat(250) + '.service'])('rejects noncanonical service %s', unit => expect(validJournalUnit(unit)).toBe(false));
    it('accepts exact instantiated names without aliases or expression parsing', () => expect(validJournalUnit('fixture@blue.service')).toBe(true));
    it('enforces UTC, lookback, span, finite priority and microsecond alignment', () => {
        const q = journalView().request!.description.query;
        expect(validJournalQuery(q, journalNow)).toBe(true);
        for (const change of [{ start: '2026-10-04T10:59:59Z' }, { end: '2026-10-04T12:00:01Z' }, { start: q.end }, { start: '2026-10-04T11:45:00+00:00' }, { start: '2026-10-04T11:45:00.000000001Z' }, { maxPriority: 8 }, { maxPriority: -1 }, { maxPriority: 2.5 }]) expect(validJournalQuery({ ...q, ...change }, journalNow)).toBe(false);
    });
    it('rejects mismatched device, floor, request binding, budgets and sliding expiry', () => {
        const changes = [(v: ReturnType<typeof journalView>) => { v.deviceId = 'agent_other'; }, (v: ReturnType<typeof journalView>) => { v.expectedFloor = '2'; }, (v: ReturnType<typeof journalView>) => { v.request!.receipt!.identity.sequence = '2'; }, (v: ReturnType<typeof journalView>) => { v.request!.description.budgets.maxRows = 501; }, (v: ReturnType<typeof journalView>) => { v.request!.description.expiresAt = '2026-10-04T12:16:00Z'; }];
        for (const change of changes) { const v = journalView(); change(v); expect(validJournalView(v, journalDevice)).toBe(false); }
    });
    it('rejects contradictory states and unknown fields', () => {
        const v = journalView('pending'); v.contentStatus = 'available'; expect(validJournalView(v, journalDevice)).toBe(false);
        expect(validJournalView({ ...journalView(), surprise: true }, journalDevice)).toBe(false);
        const p = journalPage(); p.coverage = 'failed'; p.countExact = false; p.reason = 'read_failed'; expect(validJournalPage(p, journalView(), '', 0)).toBe(false);
    });
    it('pins every page to the original request, digest, search, offset and expiry', () => {
        for (const change of [{ identity: { ...journalPage().identity, sequence: '2' } }, { snapshotDigest: `sha256:${'0'.repeat(64)}` }, { offset: 1 }, { search: 'different' }, { expiresAt: '2026-10-04T12:16:00Z' }, { nextOffset: 0 }, { serverNow: '2026-10-04T11:59:59Z' }]) expect(validJournalPage({ ...journalPage(), ...change }, journalView(), '', 0)).toBe(false);
    });
    it('rejects over-cap rows, invalid row provenance, wrong counts and messages over 4KiB', () => {
        const p = journalPage();
        for (const change of [{ totalCapturedRows: 501 }, { matchedRows: 2 }, { rows: Array(101).fill(p.rows[0]) }, { rows: [{ ...p.rows[0], unit: 'another.service' }] }, { rows: [{ ...p.rows[0], timestamp: '2026-10-04T11:00:00Z' }] }, { rows: [{ ...p.rows[0], priority: 7 }] }, { rows: [{ ...p.rows[0], message: 'x'.repeat(4097) }] }]) expect(validJournalPage({ ...p, ...change }, journalView(), '', 0)).toBe(false);
    });
    it('permits truthful partial zero retained rows without calling it complete', () => {
        const p = journalPage([]); p.coverage = 'partial'; p.reason = 'visibility_restricted'; p.countExact = false;
        expect(validJournalPage(p, journalView(), '', 0)).toBe(true);
    });
    it('uses literal simple lowercase mapping for highlight compatibility', () => {
        expect(journalFold('İΣΣ [.*]')).toBe('iσσ [.*]');
    });
});

import goFixture from './journal-go-fixture.json';
it('accepts final Go request/cache JSON including case-insensitive snapshot search', () => {
    const status: unknown = goFixture.status;
    expect(validJournalView(status, goFixture.status.deviceId)).toBe(true);
    if (validJournalView(status, goFixture.status.deviceId)) expect(validJournalPage(goFixture.page, status, 'needle', 0)).toBe(true);
});
