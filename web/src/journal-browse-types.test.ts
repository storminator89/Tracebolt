import { describe, expect, it } from 'vitest';
import { journalDevice, journalNow, journalPage, journalView } from './journal-fixtures';
import { JOURNAL_BROWSE_CONTRACT, sameJournalAuthorization, sameJournalQuery, validJournalGenerationView, validJournalPage, validJournalQuery, validJournalView } from './journal-types';
import type { JournalPage, JournalQuery, JournalView } from './journal-types';

const query: JournalQuery = { unit: 'fixture.service', start: '1970-01-01T00:00:00Z', end: journalNow, maxPriority: 6, browseMode: 'retained-v1' };
function browsingView(): JournalView {
    const view = journalView();
    view.schemaVersion = 'tracebolt.journal-view.v2';
    view.generation = { schemaVersion: 'tracebolt.journal-generation-view.v3', browsingContract: JOURNAL_BROWSE_CONTRACT, policyEnabled: true, serviceAuthorization: 'exact-units', allowedUnits: ['fixture.service'], policyGeneration: { revision: '1', generation: 'a'.repeat(64), policyDigest: view.request!.receipt!.policyDigest }, sequence: '1', observedAt: journalNow, receivedAt: journalNow, expiresAt: '2026-10-04T12:05:00Z', fresh: true };
    view.request!.description = { ...view.request!.description, schemaVersion: 'tracebolt.journal-request.v3', policyGeneration: view.generation.policyGeneration, query: { ...query } };
    return view;
}
function browsingPage(): JournalPage {
    return { ...journalPage(), schemaVersion: 'tracebolt.journal-page.v2', searchScope: 'retained_source_page', query: { ...query }, exhausted: true };
}

describe('retained journal browsing contract', () => {
    it('permits retained history only under the explicit query mode and request schema', () => {
        expect(validJournalQuery(query, journalNow)).toBe(true);
        expect(validJournalQuery({ ...query, browseMode: undefined }, journalNow)).toBe(false);
        expect(validJournalQuery({ ...query, browseMode: 'future' }, journalNow)).toBe(false);
        const view = browsingView();
        expect(validJournalView(view, journalDevice)).toBe(true);
        view.request!.description.schemaVersion = 'tracebolt.journal-request.v2';
        expect(validJournalView(view, journalDevice)).toBe(false);
    });
    it('checks byte limits, controls, UTC precision and a pinned nonfuture end', () => {
        expect(validJournalQuery({ ...query, search: 'ü'.repeat(100), cursor: 's=' + 'x'.repeat(1022) }, journalNow)).toBe(true);
        for (const extra of [{ search: 'ü'.repeat(101) }, { cursor: 'x'.repeat(1025) }, { search: 'a\nb' }, { cursor: 'a\0b' }, { end: '2026-10-04T12:00:01Z' }, { start: '1969-12-31T23:59:59Z' }, { start: '1970-01-01T00:00:00.0000001Z' }]) expect(validJournalQuery({ ...query, ...extra }, journalNow)).toBe(false);
    });
    it('requires exact v3 grant metadata and treats its contract as authorization identity', () => {
        const grant = browsingView().generation!;
        expect(validJournalGenerationView(grant, journalNow)).toBe(true);
        expect(validJournalGenerationView({ ...grant, browsingContract: undefined }, journalNow)).toBe(false);
        expect(validJournalGenerationView({ ...grant, schemaVersion: 'tracebolt.journal-generation-view.v2' }, journalNow)).toBe(false);
        expect(sameJournalAuthorization(grant, { ...grant, browsingContract: undefined })).toBe(false);
        expect(sameJournalQuery(query, { ...query, cursor: 'different' })).toBe(false);
        expect(sameJournalQuery(query, { ...query, search: 'different' })).toBe(false);
    });
    it('binds cursor pages to their query and accepts omitted false exhaustion only with a continuation', () => {
        const view = browsingView(), page = browsingPage();
        expect(validJournalPage(page, view, '', 0)).toBe(true);
        const continuing = { ...page, coverage: 'partial', reason: 'item_limit', countExact: false, nextCursor: 's=fixture;i=1', exhausted: undefined };
        delete continuing.exhausted;
        expect(validJournalPage(continuing, view, '', 0)).toBe(true);
        for (const changed of [{ ...page, nextCursor: 's=fixture;i=1' }, { ...page, exhausted: 'true' }, { ...page, query: { ...query, cursor: 'another-page' } }, { ...page, schemaVersion: 'tracebolt.journal-page.v1' }, { ...continuing, nextCursor: 'x'.repeat(1025) }]) expect(validJournalPage(changed, view, '', 0)).toBe(false);
        expect(validJournalPage(page, view, 'local search', 0)).toBe(false);
    });
});

it.each(['read_failed','timeout'] as const)('accepts zero-row partial continuation after %s cleanup and rejects failed-with-cursor',reason=>{
 const view=browsingView(),page=browsingPage();
 const continuing:JournalPage={...page,coverage:'partial',reason,rows:[],observedCount:0,countExact:false,redactionApplied:false,totalCapturedRows:0,matchedRows:0,nextCursor:'s=fixture;i=1'};
 delete continuing.exhausted;
 expect(validJournalPage(continuing,view,'',0)).toBe(true);
 expect(validJournalPage({...continuing,coverage:'failed'},view,'',0)).toBe(false);
});
