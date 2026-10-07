import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { APIError, AUTH_REQUIRED_EVENT, mutateRaw, request } from './api';
import { CompleteUpdatesPanel } from './complete-updates';
import { updateDevice, updatePage, updateRows, updateView } from './complete-updates-fixtures';
import { setLocale } from './i18n';
import type { CompleteUpdatePage } from './complete-updates-types';
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutateRaw: vi.fn() }));
vi.mock('./auth', () => ({ useOperator: () => ({ mode: 'lan', authenticated: true, expiresAt: '2026-10-05T06:00:00Z' }) }));
let view = updateView(), rows = updateRows();
async function open() { render(<CompleteUpdatesPanel deviceId={updateDevice}/>); await screen.findByRole('table'); }
beforeEach(() => { setLocale('en', false); view = updateView(); rows = updateRows(); vi.mocked(request).mockReset().mockImplementation(async () => view); vi.mocked(mutateRaw).mockReset().mockImplementation(async (_path, raw) => updatePage(view, rows, raw)); });
afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.useRealTimers(); });
describe('complete known cached update rows', () => {
    it('traverses all 1,213 candidates in at-most-100-row DOM pages without a preview prefix', async () => {
        render(<CompleteUpdatesPanel deviceId={updateDevice}/>); const seen: string[] = [];
        for (let page = 0; page < 13; page++) {
            await screen.findByText(`fixture-update-${String(page * 100).padStart(6, '0')}`, { selector: 'th' });
            const displayed = [...document.querySelectorAll('tbody th[scope="row"]')]; expect(displayed.length).toBeLessThanOrEqual(100); seen.push(...displayed.map(row => row.textContent!));
            if (page < 12) fireEvent.click(screen.getByRole('button', { name: 'Next 100 candidates' }));
        }
        expect(seen).toEqual(rows.map(row => row.name)); expect(new Set(seen).size).toBe(1213); expect(screen.getByText('The entire selected generation has been scanned.')).toBeVisible(); expect(mutateRaw).toHaveBeenCalledTimes(13);
        for (const [path, raw, , , limit] of vi.mocked(mutateRaw).mock.calls) { expect(path).toBe(`/devices/${updateDevice}/inventory/complete-updates/query`); expect(JSON.parse(raw)).toMatchObject({ generationId: view.complete!.binding.generationId, limit: 100 }); expect(limit).toBe(262144); }
    });
    it('reveals provenance and scope through native disclosure without querying or clearing the search draft', async () => {
        await open();
        const search = screen.getByRole('searchbox', { name: 'Search all candidate rows' });
        fireEvent.change(search, { target: { value: 'fixture-update-0012' } });
        const reads = vi.mocked(request).mock.calls.length, queries = vi.mocked(mutateRaw).mock.calls.length;
        const capture = screen.getByText('Capture details', { selector: 'summary' });
        expect(capture.parentElement).not.toHaveAttribute('open');
        expect(screen.getByText('Installed packages')).not.toBeVisible();
        expect(screen.getByText(view.complete!.manifest.collectedAt)).toBeVisible();
        expect(screen.getByText(view.complete!.retainedUntil)).toBeVisible();
        capture.focus();
        fireEvent.click(capture);
        expect(screen.getByText('Installed packages')).toBeVisible();
        fireEvent.click(capture);
        expect(capture.parentElement).not.toHaveAttribute('open');
        expect(capture).toHaveFocus();
        const scope = screen.getByText('Scope & limits', { selector: 'summary' });
        scope.focus();
        fireEvent.click(scope);
        expect(screen.getByText(/No CVE or installability assessment/)).toBeVisible();
        expect(screen.getByText(/Search checks up to 2,048 rows/)).toBeVisible();
        expect(screen.getByText(/Rows expire 24 hours/)).toBeVisible();
        expect(search).toHaveValue('fixture-update-0012');
        act(() => setLocale('de', false));
        expect(screen.getByText('Umfang & Grenzen', { selector: 'summary' })).toBe(scope);
        expect(scope.parentElement).toHaveAttribute('open');
        expect(search).toHaveValue('fixture-update-0012');
        expect(request).toHaveBeenCalledTimes(reads);
        expect(mutateRaw).toHaveBeenCalledTimes(queries);
    });
    it('keeps unknown freshness visible with provenance collapsed', async () => {
        view.complete!.manifest.metadata = { ...view.complete!.manifest.metadata, freshness: 'unknown', oldestIndexModifiedAt: '2026-10-05T03:00:00Z', ageSeconds: 3600 };
        await open();
        expect(screen.getByText(/Source freshness unknown/)).toBeVisible();
        expect(screen.getByText('Capture details', { selector: 'summary' }).parentElement).not.toHaveAttribute('open');
    });
    it('keeps revocation visible and hides rows even with details collapsed', async () => {
        view.status = 'revoked';
        render(<CompleteUpdatesPanel deviceId={updateDevice}/>);
        await screen.findAllByText('Device identity revoked');
        for (const warning of screen.getAllByText('Device identity revoked')) expect(warning).toBeVisible();
        expect(screen.queryByRole('table')).not.toBeInTheDocument();
        expect(mutateRaw).not.toHaveBeenCalled();
        expect(screen.getByText('Capture details', { selector: 'summary' }).parentElement).not.toHaveAttribute('open');
    });
    it('keeps an expired generation warning visible while source details stay collapsed', async () => {
        view.complete!.state = 'expired'; view.serverNow = view.complete!.retainedUntil;
        render(<CompleteUpdatesPanel deviceId={updateDevice}/>);
        expect(await screen.findByText('This generation has expired. Its rows are no longer available.')).toBeVisible();
        expect(screen.queryByRole('table')).not.toBeInTheDocument();
        expect(screen.getByText('Capture details', { selector: 'summary' }).parentElement).not.toHaveAttribute('open');
        expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('searches past an empty 2,048-row window without claiming no matches early', async () => {
        view = updateView(2300); rows = updateRows(2300); await open(); fireEvent.change(screen.getByLabelText('Search all candidate rows'), { target: { value: 'fixture-update-002299' } }); fireEvent.click(screen.getByRole('button', { name: 'Search' })); await screen.findByText('No matches in this scan window. Continue to check remaining rows.'); expect(screen.queryByText('No matches in the complete known-candidate generation.')).not.toBeInTheDocument(); fireEvent.click(screen.getByRole('button', { name: 'Continue search' })); await screen.findByText('fixture-update-002299', { selector: 'th' }); expect(screen.getByText('2,300 / 2,300')).toBeVisible();
    });
    it('keeps metadata stale and unknown comparisons partial despite complete known rows', async () => { view.complete!.manifest.checkedCount--; view.complete!.manifest.unknownCount = 1; view.complete!.manifest.comparisonCoverage = 'partial'; view.complete!.manifest.comparisonReason = 'candidate_unknown'; await open(); expect(screen.getByText(/metadata is stale/)).toBeVisible(); expect(screen.getByText(/lower bound/)).toBeVisible(); expect(screen.getByText('Cached candidates do not establish security or patch status.')).toBeVisible(); expect(screen.getByText(/No CVE or installability assessment/)).not.toBeVisible(); });
    it('does not show a zero candidate claim for absent complete data', async () => { view = { ...view, status: 'awaiting', complete: null }; render(<CompleteUpdatesPanel deviceId={updateDevice}/>); await screen.findByText('Awaiting a complete update generation'); expect(mutateRaw).not.toHaveBeenCalled(); expect(screen.queryByText(/No newer candidates in/)).not.toBeInTheDocument(); expect(screen.getByText(/preview consent does not enable/)).toBeVisible(); });
    it('retains prior complete rows and timestamps after a failed newer capture', async () => { view.failure = { sequence: '9223372036854775807', generationId: `sample_${'d'.repeat(32)}`, attemptedAt: '2026-10-05T04:00:06Z', receivedAt: '2026-10-05T04:00:07Z', reason: 'source_missing' }; await open(); expect(screen.getByText('Latest capture failed')).toBeVisible(); expect(screen.getByText('2026-10-05T04:00:00Z')).toBeVisible(); expect(screen.getByText('fixture-update-000000', { selector: 'th' })).toBeVisible(); });
    it.each(['close', 'pagehide', 'blur', 'auth', 'session', 'device'] as const)('aborts and hides a delayed page after %s', async transition => {
        let finish!: (value: CompleteUpdatePage) => void, signal!: AbortSignal; const rendered = render(<CompleteUpdatesPanel deviceId={updateDevice} sessionKey="first"/>); await screen.findByRole('table');
        vi.mocked(mutateRaw).mockImplementation(async (_path, _raw, _headers, supplied) => { signal = supplied!; return new Promise<CompleteUpdatePage>(resolve => { finish = resolve; }); }); fireEvent.click(screen.getByRole('button', { name: 'Next 100 candidates' })); await waitFor(() => expect(signal).toBeDefined());
        if (transition === 'close') rendered.unmount(); if (transition === 'pagehide') act(() => window.dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true }))); if (transition === 'blur') act(() => window.dispatchEvent(new Event('blur'))); if (transition === 'auth') act(() => window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT))); if (transition === 'session') rendered.rerender(<CompleteUpdatesPanel deviceId={updateDevice} sessionKey="replacement"/>); if (transition === 'device') rendered.rerender(<CompleteUpdatesPanel deviceId="agent_other" sessionKey="first"/>);
        expect(signal.aborted).toBe(true); await act(async () => finish(updatePage(view, rows, JSON.stringify({ cursor: 'cursor_100', search: '', limit: 100 })))); expect(document.body.textContent).not.toContain('fixture-update-000100');
    });
    it('requires explicit restart after generation conflict', async () => { await open(); vi.mocked(mutateRaw).mockRejectedValueOnce(new APIError('expired', 409)); fireEvent.click(screen.getByRole('button', { name: 'Next 100 candidates' })); await screen.findByText(/generation or paging session expired or changed/); expect(screen.queryByRole('table')).not.toBeInTheDocument(); expect(request).toHaveBeenCalledTimes(1); fireEvent.click(screen.getByRole('button', { name: 'Refresh complete update inventory' })); await screen.findByRole('table'); expect(JSON.parse(vi.mocked(mutateRaw).mock.calls.at(-1)![1]).cursor).toBe(''); });
    it('locks after session failure and never restores on focus', async () => { await open(); vi.mocked(mutateRaw).mockRejectedValueOnce(new APIError('session', 401)); fireEvent.click(screen.getByRole('button', { name: 'Next 100 candidates' })); await screen.findByText('Your session has ended. Sign in again.'); act(() => window.dispatchEvent(new Event('focus'))); expect(screen.queryByRole('table')).not.toBeInTheDocument(); expect(screen.getByRole('button', { name: 'Refresh complete update inventory' })).toBeDisabled(); });
    it('rejects repeated page order rather than silently missing tail rows', async () => { await open(); vi.mocked(mutateRaw).mockResolvedValueOnce(updatePage(view, rows)); fireEvent.click(screen.getByRole('button', { name: 'Next 100 candidates' })); await screen.findByText(/Inconsistent or unsupported update data/); expect(screen.queryByRole('table')).not.toBeInTheDocument(); });
    it.each(['staging lease', 'capture retention'] as const)('expires a pending transfer at its %s without renewing facts or querying', async deadline => {
        vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] });
        const mono = vi.spyOn(performance, 'now').mockReturnValue(1000), wall = vi.spyOn(Date, 'now').mockReturnValue(100000);
        view.complete!.binding.sequence = '1';
        view.transfer = { binding: { ...view.complete!.binding, sequence: '2', generationId: `sample_${'d'.repeat(32)}` }, state: 'pending', declaredRows: 1213, acceptedRows: 128, expectedChunks: 10, acceptedChunks: 1, collectedAt: deadline === 'staging lease' ? '2026-10-05T04:00:06Z' : '2026-10-04T04:00:12Z', startedAt: '2026-10-05T04:00:07Z', expiresAt: '2026-10-05T04:15:07Z' };
        if (deadline === 'capture retention') view = { ...view, status: 'awaiting', complete: null };
        const original = JSON.stringify(view), milliseconds = deadline === 'staging lease' ? 897000 : 2000;
        render(<CompleteUpdatesPanel deviceId={updateDevice}/>);
        await screen.findByText('Transfer pending');
        if (view.complete) await screen.findByRole('table');
        const reads = vi.mocked(request).mock.calls.length, pages = vi.mocked(mutateRaw).mock.calls.length;
        mono.mockReturnValue(1000 + milliseconds - 1); wall.mockReturnValue(100000 + milliseconds - 1);
        act(() => vi.advanceTimersByTime(1000)); expect(screen.getByText('Transfer pending')).toBeVisible();
        mono.mockReturnValue(1000 + milliseconds); wall.mockReturnValue(100000 + milliseconds);
        act(() => vi.advanceTimersByTime(1000));
        expect(screen.getByText('Transfer expired')).toBeVisible(); expect(screen.queryByText('Transfer pending')).not.toBeInTheDocument();
        expect(screen.getByText('128 / 1,213')).toBeVisible(); expect(screen.getByText('1 / 10')).not.toBeVisible(); fireEvent.click(screen.getByText('Transfer details', { selector: 'summary' })); expect(screen.getByText('1 / 10')).toBeVisible();
        if (view.complete) { expect(screen.getByRole('table')).toBeVisible(); expect(screen.getByText(view.complete.manifest.collectedAt)).toBeVisible(); }
        expect(request).toHaveBeenCalledTimes(reads + (deadline === 'staging lease' ? 1 : 0)); expect(mutateRaw).toHaveBeenCalledTimes(pages); expect(JSON.stringify(view)).toBe(original);
    });
    it('renders German state and hold labels', async () => { setLocale('de', false); await open(); expect(screen.getByText('Bekannte neuere Kandidaten')).toBeVisible(); expect(screen.getAllByText('Von dpkg zurückgehalten').length).toBeGreaterThan(0); });
});
