import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { filterSavedUpdateJobs, updateJobResultKey, WindowsUpdateJobHistoryReview } from './windows-update-job-history-review';
import { validUpdateJobHistory, type UpdateJobSummary, type UpdateResult } from './windows-update-jobs-types';

const selection = { updateId: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee', revision: 17 };
const job = (id: string, state: string, outcome?: UpdateResult['outcome'], download = false): UpdateJobSummary => ({
    id: `update_${id.repeat(32)}`, selection, state, reason: state === 'scheduled' ? 'schedule_waiting' : 'ready', requestedAt: 100, approvedAt: state === 'scheduled' ? 0 : 110, claimedAt: state === 'claimed' || outcome ? 120 : 0,
    ...(download ? { purpose: 'download' as const } : {}),
    ...(state === 'scheduled' ? { schedule: { version: 'tracebolt.windows-selected-update-schedule.v1' as const, digest: `sha256:${'2'.repeat(64)}`, approvedAt: 110, startAt: 200, endAt: 300, permitIssuedAt: 0, revoked: false } } : {}),
    result: outcome ? { jobId: `update_${id.repeat(32)}`, envelopeDigest: `sha256:${'1'.repeat(64)}`, attempted: outcome !== 'not_attempted', outcome, operationResult: outcome === 'succeeded' ? 2 : outcome === 'not_attempted' ? 0 : 4, hresult: 0, rebootRequired: 'unknown', completedAt: 130,
        ...(download ? { purpose: 'download' as const, nativeReturned: true, cleanupSucceeded: true, aggregateResultKnown: true, aggregateHresultKnown: true, updateResultKnown: true, updateHresultKnown: true, aggregateOperationResult: 2, downloadedAfter: 'yes' as const } : {}),
    } : null,
});
const jobs = [job('6', 'claimed'), job('5', 'complete', 'uncertain'), job('4', 'complete', 'failed'), job('3', 'complete', 'succeeded', true), job('2', 'complete', 'not_attempted'), job('1', 'scheduled')];
const draw = (source: readonly UpdateJobSummary[] = jobs, locale: 'en' | 'de' = 'en', busy = false) => <WindowsUpdateJobHistoryReview jobs={source} locale={locale} busy={busy}>{row => <span data-testid="saved-job">{row.id}</span>}</WindowsUpdateJobHistoryReview>;
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

it('keeps claim, saved outcomes and schedule states distinct without inferring execution or success', () => {
    const device = `agent_${'1'.repeat(32)}`;
    expect(validUpdateJobHistory({ version: 'tracebolt.windows-selected-update-history.v1', deviceId: device, serverNow: 130, available: true, reason: 'ready', remainingCapacity: 27, jobs }, device, `operator_${'2'.repeat(32)}`)).toBe(true);
    expect(jobs.map(updateJobResultKey)).toEqual(['state:claimed', 'result:uncertain', 'result:failed', 'result:succeeded', 'result:not_attempted', 'state:scheduled']);
    for (const state of ['requested', 'blocked', 'preview', 'approved', 'expired', 'schedule_canceled', 'schedule_blocked', 'schedule_expired']) {
        expect(updateJobResultKey(job('7', state))).toBe(`state:${state}`);
    }
});

it('combines literal ID/revision, purpose and exact result filters while preserving source order and objects', () => {
    const before = JSON.stringify(jobs);
    expect(filterSavedUpdateJobs(jobs, '  AAAA-BBBB  ', 'all', 'all')).toEqual(jobs);
    expect(filterSavedUpdateJobs(jobs, '17', 'download', 'result:succeeded')).toEqual([jobs[3]]);
    expect(filterSavedUpdateJobs(jobs, '17', 'install', 'result:succeeded')).toEqual([]);
    expect(filterSavedUpdateJobs(jobs, 'update_4444', 'install', 'result:failed')).toEqual([jobs[2]]);
    expect(filterSavedUpdateJobs(jobs, '.*', 'all', 'all')).toEqual([]);
    expect(filterSavedUpdateJobs(jobs, '', 'install', 'all')).toEqual([jobs[0], jobs[1], jobs[2], jobs[4], jobs[5]]);
    expect(filterSavedUpdateJobs(jobs, '', 'all', 'all')[0]).toBe(jobs[0]);
    expect(JSON.stringify(jobs)).toBe(before);
});

it.each(['en', 'de'] as const)('offers labelled local filters, accurate counts and a focused reset in %s', locale => {
    render(draw(jobs, locale)); const de = locale === 'de';
    const search = screen.getByRole('searchbox', { name: de ? 'Auftrags-ID, Update-ID oder Revision' : 'Job ID, update ID or revision' });
    const purpose = screen.getByRole('combobox', { name: de ? 'Auftragszweck' : 'Job purpose' });
    const result = screen.getByRole('combobox', { name: de ? 'Gespeicherter Status oder Ergebnis' : 'Saved status or result' });
    const clear = screen.getByRole('button', { name: de ? 'Auftragsfilter leeren' : 'Clear job filters' });
    expect(clear).toBeDisabled(); expect(screen.getAllByTestId('saved-job')).toHaveLength(6);
    fireEvent.change(purpose, { target: { value: 'download' } });
    expect(screen.getAllByTestId('saved-job')).toHaveLength(1); expect(screen.getByRole('option', { name: de ? 'Erfolg gemeldet (1)' : 'Reported success (1)' })).toBeInTheDocument();
    fireEvent.change(result, { target: { value: 'result:succeeded' } }); fireEvent.change(search, { target: { value: 'not-present' } });
    expect(screen.queryByTestId('saved-job')).toBeNull();
    expect(screen.getByText(de ? 'Angezeigt: 0 von 6 gespeicherten Aufträgen' : 'Showing 0 of 6 saved jobs')).toBeInTheDocument();
    expect(screen.getByText(de ? 'Keine gespeicherten Aufträge passen zu diesen Filtern.' : 'No saved jobs match these filters.')).toBeInTheDocument();
    expect(result).toHaveValue('result:succeeded'); expect(screen.getByRole('option', { name: de ? 'Erfolg gemeldet (0)' : 'Reported success (0)' })).toBeInTheDocument();
    fireEvent.click(clear); expect(search).toHaveValue(''); expect(purpose).toHaveValue('all'); expect(result).toHaveValue('all'); expect(search).toHaveFocus();
    expect(screen.getAllByTestId('saved-job').map(row => row.textContent)).toEqual(jobs.map(row => row.id));
});

it('resets filters when the loaded history snapshot is replaced and after remount', () => {
    const ui = render(draw()); fireEvent.change(screen.getByRole('searchbox'), { target: { value: 'update_4444' } });
    expect(screen.getAllByTestId('saved-job')).toHaveLength(1);
    ui.rerender(draw([...jobs])); expect(screen.getByRole('searchbox')).toHaveValue(''); expect(screen.getAllByTestId('saved-job')).toHaveLength(6);
    fireEvent.change(screen.getByRole('searchbox'), { target: { value: 'private-query' } }); ui.unmount(); render(draw()); expect(screen.getByRole('searchbox')).toHaveValue('');
});

it('disables controls during the existing read and makes no network or storage calls', () => {
    const fetch = vi.spyOn(globalThis, 'fetch'), storage = vi.spyOn(Storage.prototype, 'setItem');
    const ui = render(draw()); fireEvent.change(screen.getByRole('searchbox'), { target: { value: '4444' } });
    ui.rerender(draw(jobs, 'en', true)); expect(screen.getByRole('searchbox')).toBeDisabled();
    for (const field of screen.getAllByRole('combobox')) expect(field).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Clear job filters' })).toBeDisabled(); expect(fetch).not.toHaveBeenCalled(); expect(storage).not.toHaveBeenCalled();
});
