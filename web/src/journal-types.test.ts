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

import type { JournalGenerationView } from './journal-types';
export function generationFixture(): JournalGenerationView {
    return { schemaVersion: 'tracebolt.journal-generation-view.v1', policyGeneration: { revision: '1', generation: 'a'.repeat(64), policyDigest: `sha256:${'d'.repeat(64)}` }, sequence: '1', observedAt: journalNow, receivedAt: journalNow, expiresAt: '2026-10-04T12:05:00Z', fresh: true };
}
describe('generation-bound journal views', () => {
    it('requires explicit view/request versions and exact bounded tuples', () => {
        const v = journalView('pending'); v.schemaVersion = 'tracebolt.journal-view.v2'; v.generation = generationFixture();
        expect(validJournalView(v, journalDevice)).toBe(false);
        v.request!.description.schemaVersion = 'tracebolt.journal-request.v2'; v.request!.description.policyGeneration = { ...v.generation.policyGeneration };
        expect(validJournalView(v, journalDevice)).toBe(true);
        for (const tuple of [{ ...v.generation.policyGeneration, revision: '01' }, { ...v.generation.policyGeneration, revision: '18446744073709551616' }, { ...v.generation.policyGeneration, generation: '0'.repeat(64) }, { ...v.generation.policyGeneration, extra: true }]) {
            expect(validJournalView({ ...v, generation: { ...v.generation, policyGeneration: tuple } }, journalDevice)).toBe(false);
        }
        expect(validJournalView({ ...v, schemaVersion: 'tracebolt.journal-view.v1' }, journalDevice)).toBe(false);
        expect(validJournalView({ ...v, generation: undefined }, journalDevice)).toBe(false);
        expect(validJournalView({ ...v, generation: { ...v.generation, policyGeneration: { ...v.generation.policyGeneration, revision: '2' } } }, journalDevice)).toBe(false);
    });
    it('accepts stale floor metadata without upgrading freshness and retains old accepted content', () => {
        const v = journalView(); v.schemaVersion = 'tracebolt.journal-view.v2'; v.generation = generationFixture();
        expect(validJournalView(v, journalDevice)).toBe(true);
        v.serverNow = '2026-10-04T12:05:00Z'; expect(validJournalView(v, journalDevice)).toBe(false);
        v.generation.fresh = false; expect(validJournalView(v, journalDevice)).toBe(true);
        v.generation.expiresAt = '2026-10-04T12:06:00Z'; expect(validJournalView(v, journalDevice)).toBe(false);
    });
});

it('requires a canonical explicit scope for v2 permission summaries and keeps old reports unknown', () => {
    const v = journalView('awaiting'); v.schemaVersion = 'tracebolt.journal-view.v2';
    v.generation = { ...generationFixture(), schemaVersion: 'tracebolt.journal-generation-view.v2', policyEnabled: true, serviceAuthorization: 'all-system-services', allowedUnits: [] };
    expect(validJournalView(v, journalDevice)).toBe(true);
    const summary = v.generation;
    for (const change of [{ allowedUnits: null }, { allowedUnits: ['a.service'] }, { allowedUnits: undefined }, { policyEnabled: undefined }, { serviceAuthorization: undefined }, { serviceAuthorization: 'all' }, { schemaVersion: 'tracebolt.journal-generation-view.v1' }]) expect(validJournalView({ ...v, generation: { ...summary, ...change } }, journalDevice)).toBe(false);
    v.generation = { ...summary, serviceAuthorization: 'exact-units', allowedUnits: ['a.service', 'z@instance.service'] };
    expect(validJournalView(v, journalDevice)).toBe(true);
    for (const units of [[], ['b.service', 'a.service'], ['a.service', 'a.service'], ['*.service'], Array(33).fill('a.service')]) expect(validJournalView({ ...v, generation: { ...v.generation, allowedUnits: units } }, journalDevice)).toBe(false);
    v.generation = generationFixture(); expect(validJournalView(v, journalDevice)).toBe(true);
});
