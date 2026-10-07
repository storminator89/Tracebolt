import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { APIError, AUTH_REQUIRED_EVENT, mutateRaw, request } from './api';
import { CompletePackagesPanel } from './complete-packages';
import { completeDevice, completePage, completeRows, completeView } from './complete-packages-fixtures';
import { setLocale } from './i18n';
import type { CompletePackagePage } from './complete-packages-types';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutateRaw: vi.fn() }));
vi.mock('./auth', () => ({ useOperator: () => ({ mode: 'lan', authenticated: true, expiresAt: '2026-10-04T01:00:00Z' }) }));
let view = completeView(), rows = completeRows();
async function open() { render(<CompletePackagesPanel deviceId={completeDevice}/>); fireEvent.click(screen.getByRole('button', { name: 'Complete dpkg inventory' })); await screen.findByRole('table'); }
beforeEach(() => {
    setLocale('en', false); view = completeView(); rows = completeRows();
    vi.mocked(request).mockReset().mockImplementation(async () => view);
    vi.mocked(mutateRaw).mockReset().mockImplementation(async (_path, raw) => completePage(view, rows, raw));
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.useRealTimers(); });

describe('complete dpkg inventory browsing', () => {
    it('is lazy and enumerates all 350 rows with a bounded 100-row DOM page rather than a global 128/256 prefix', async () => {
        render(<CompletePackagesPanel deviceId={completeDevice}/>); expect(request).not.toHaveBeenCalled();
        fireEvent.click(screen.getByRole('button', { name: 'Complete dpkg inventory' }));
        const seen: string[] = [];
        for (let page = 0; page < 4; page++) {
            await screen.findByText(`fixture-${String(page * 100).padStart(6, '0')}`, { selector: 'th' });
            const displayed = within(screen.getByRole('table')).getAllByRole('rowheader');
            expect(displayed.length).toBeLessThanOrEqual(100); seen.push(...displayed.map(row => row.textContent!));
            if (page < 3) fireEvent.click(screen.getByRole('button', { name: 'Next 100 rows' }));
        }
        expect(seen).toEqual(rows.map(row => row.name)); expect(new Set(seen).size).toBe(350);
        expect(screen.getByText('The entire generation has been scanned.')).toBeVisible(); expect(screen.queryByRole('button', { name: 'Next 100 rows' })).not.toBeInTheDocument();
        expect(mutateRaw).toHaveBeenCalledTimes(4);
        for (const [path, raw, , , maximum] of vi.mocked(mutateRaw).mock.calls) { expect(path).toBe(`/devices/${completeDevice}/inventory/packages/query`); expect(JSON.parse(raw)).toMatchObject({ generationId: view.complete!.binding.generationId, limit: 100, search: '' }); expect(maximum).toBe(262144); }
    });
    it.each(['en', 'de'] as const)('keeps six scan columns and exact mapping evidence in collapsed per-package details in %s', async locale => {
        setLocale(locale, false); view = completeView(2); rows = completeRows(2);
        Object.assign(rows[1], { sourcePackage: 'fixture-source', sourceVersion: '1.0', sourceMapping: 'source-field' });
        render(<CompletePackagesPanel deviceId={completeDevice} inline/>);
        const table = await screen.findByRole('table'), rowElements = within(table).getAllByRole('row').slice(1);
        const headers = locale === 'de' ? ['Binärpaket', 'Binärversion', 'Architektur', 'Quellpaket', 'Quellversion', 'Installationszustand'] : ['Binary package', 'Binary version', 'Architecture', 'Source package', 'Source version', 'Install state'];
        expect(within(table).getAllByRole('columnheader').map(header => header.textContent)).toEqual(headers);
        const labels = locale === 'de' ? ['Source-Feld fehlt: Binärvorgabe', 'Ausdrückliches Source-Feld'] : ['Absent Source field: binary default', 'Explicit Source field'];
        for (const [index, rowElement] of rowElements.entries()) {
            const summary = rowElement.querySelector('summary')!, details = summary.closest('details')!;
            expect(summary).toHaveTextContent(rows[index].sourcePackage);
            expect(summary).toHaveTextContent(`${locale === 'de' ? 'Paketdetails' : 'Package details'}: ${rows[index].name} (${rows[index].architecture})`);
            expect(details).not.toHaveAttribute('open'); expect(within(rowElement).getByText(labels[index])).not.toBeVisible();
            summary.focus(); expect(summary).toHaveFocus();
            fireEvent.click(summary); expect(details).toHaveAttribute('open'); expect(within(rowElement).getByText(labels[index])).toBeVisible();
            fireEvent.click(summary); expect(details).not.toHaveAttribute('open'); expect(within(rowElement).getByText(labels[index])).not.toBeVisible();
        }
        expect(within(rowElements[1]).getByText('1.0')).toBeVisible(); expect(within(rowElements[1]).getByText('1.0+b1')).toBeVisible();
        expect(request).toHaveBeenCalledTimes(1); expect(mutateRaw).toHaveBeenCalledTimes(1);
    });
    it('still searches mapping evidence while it is collapsed and clears expanded details when search changes', async () => {
        view = completeView(2); rows = completeRows(2);
        Object.assign(rows[1], { sourcePackage: 'fixture-source', sourceVersion: '1.0', sourceMapping: 'source-field' });
        await open(); const firstSummary = screen.getByRole('table').querySelector('summary')!; fireEvent.click(firstSummary);
        expect(firstSummary.closest('details')).toHaveAttribute('open');
        for (const [search, name, evidence] of [['source-field', rows[1].name, 'Explicit Source field'], ['binary-default', rows[0].name, 'Absent Source field: binary default']]) {
            fireEvent.change(screen.getByLabelText('Search packages'), { target: { value: search } });
            expect(screen.queryByRole('table')).not.toBeInTheDocument(); fireEvent.click(screen.getByRole('button', { name: 'Search' }));
            await screen.findByText(name, { selector: 'th' }); expect(within(screen.getByRole('table')).getAllByRole('rowheader')).toHaveLength(1);
            expect(screen.getByText(evidence)).not.toBeVisible(); expect(screen.getByRole('table').querySelector('details')).not.toHaveAttribute('open');
            expect(JSON.parse(vi.mocked(mutateRaw).mock.calls.at(-1)![1])).toMatchObject({ search, cursor: '', limit: 100 });
        }
        expect(screen.getByText('2026-10-04T00:00:00Z')).toBeVisible(); expect(request).toHaveBeenCalledTimes(1);
    });
    it('continues an empty 2048-row search window and finds a match beyond row 2299', async () => {
        view = completeView(2300); rows = completeRows(2300); await open();
        fireEvent.change(screen.getByLabelText('Search packages'), { target: { value: 'fixture-002299' } });
        expect(screen.queryByRole('table')).not.toBeInTheDocument(); fireEvent.click(screen.getByRole('button', { name: 'Search' }));
        await screen.findByText('No matches in this scan window. More rows remain; continue the search.'); expect(screen.queryByText('No matches in the complete generation.')).not.toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', { name: 'Continue search' })); await screen.findByText('fixture-002299', { selector: 'th' }); expect(screen.getByText('2,300 / 2,300')).toBeVisible();
    });
    it('only reports no matches after exhausting the complete generation', async () => {
        await open(); fireEvent.change(screen.getByLabelText('Search packages'), { target: { value: 'absent-fixture' } }); fireEvent.click(screen.getByRole('button', { name: 'Search' })); await screen.findByText('No matches in the complete generation.');
    });
    it('keeps prior complete rows and original age when a newer transfer is pending or a collection attempt failed', async () => {
        view.complete!.binding.sequence = '1'; view.transfer = { binding: { sequence: '2', generationId: `sample_${'d'.repeat(32)}`, manifestHash: 'e'.repeat(64) }, state: 'pending', declaredRows: 500, acceptedRows: 128, expectedChunks: 4, acceptedChunks: 1, collectedAt: '2026-10-04T00:00:06Z', startedAt: '2026-10-04T00:00:07Z', expiresAt: '2026-10-04T00:15:07Z' };
        view.failure = { sequence: '3', generationId: `sample_${'f'.repeat(32)}`, attemptedAt: '2026-10-04T00:00:08Z', receivedAt: '2026-10-04T00:00:09Z', reason: 'collection_failed' }; await open();
        expect(screen.getByText('Transfer pending')).toBeVisible(); expect(screen.getByText('Latest collection attempt failed')).toBeVisible(); expect(screen.getByText('2026-10-04T00:00:00Z')).toBeVisible(); expect(screen.getByText('128 / 500')).toBeVisible();
    });
    it('preserves expired zero-row metadata without reporting successful empty inventory', async () => {
        view = completeView(0); view.complete!.state = 'expired'; view.serverNow = '2026-10-05T00:00:00Z'; render(<CompletePackagesPanel deviceId={completeDevice}/>); fireEvent.click(screen.getByRole('button', { name: 'Complete dpkg inventory' })); await screen.findByText(/The retained generation has expired/); expect(mutateRaw).not.toHaveBeenCalled(); expect(screen.queryByText(/completed generation contains zero/)).not.toBeInTheDocument();
    });
    it.each(['close', 'pagehide', 'blur', 'auth', 'session', 'device'] as const)('aborts in-flight pages and rejects late completion on %s', async transition => {
        let resolve!: (value: CompletePackagePage) => void, signal!: AbortSignal;
        const rendered = render(<CompletePackagesPanel deviceId={completeDevice} sessionKey="first"/>); fireEvent.click(screen.getByRole('button', { name: 'Complete dpkg inventory' })); await screen.findByRole('table');
        vi.mocked(mutateRaw).mockImplementation(async (_path, _raw, _headers, supplied) => { signal = supplied!; return new Promise<CompletePackagePage>(done => { resolve = done; }); });
        fireEvent.click(screen.getByRole('button', { name: 'Next 100 rows' })); await waitFor(() => expect(signal).toBeDefined());
        if (transition === 'close') fireEvent.click(screen.getByRole('button', { name: 'Complete dpkg inventory' }));
        if (transition === 'pagehide') act(() => window.dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true })));
        if (transition === 'blur') act(() => window.dispatchEvent(new Event('blur')));
        if (transition === 'auth') act(() => window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT)));
        if (transition === 'session') rendered.rerender(<CompletePackagesPanel deviceId={completeDevice} sessionKey="replacement"/>);
        if (transition === 'device') rendered.rerender(<CompletePackagesPanel deviceId="agent_other" sessionKey="first"/>);
        expect(signal.aborted).toBe(true); await act(async () => resolve(completePage(view, rows, JSON.stringify({ cursor: 'cursor_100', search: '', limit: 100 }))));
        expect(screen.queryByRole('table')).not.toBeInTheDocument(); expect(document.body.textContent).not.toContain('fixture-000100');
    });
    it('query edits cancel old results and start with an empty cursor', async () => {
        await open(); let resolve!: (value: CompletePackagePage) => void, signal!: AbortSignal;
        vi.mocked(mutateRaw).mockImplementationOnce(async (_path, _raw, _headers, supplied) => { signal = supplied!; return new Promise<CompletePackagePage>(done => { resolve = done; }); });
        fireEvent.click(screen.getByRole('button', { name: 'Next 100 rows' })); await waitFor(() => expect(signal).toBeDefined()); fireEvent.change(screen.getByLabelText('Search packages'), { target: { value: 'fixture-000349' } }); expect(signal.aborted).toBe(true);
        fireEvent.click(screen.getByRole('button', { name: 'Search' })); await screen.findByText('fixture-000349', { selector: 'th' });
        await act(async () => resolve(completePage(view, rows, JSON.stringify({ cursor: 'cursor_100', search: '', limit: 100 })))); expect(screen.queryByText('fixture-000100')).not.toBeInTheDocument(); expect(JSON.parse(vi.mocked(mutateRaw).mock.calls.at(-1)![1]).cursor).toBe('');
    });
    it('409 clears all pages and requires an explicit restart against a new generation', async () => {
        await open(); vi.mocked(mutateRaw).mockRejectedValueOnce(new APIError('expired', 409)); fireEvent.click(screen.getByRole('button', { name: 'Next 100 rows' })); await screen.findByText(/generation or paging session expired or changed/); expect(screen.queryByRole('table')).not.toBeInTheDocument(); expect(request).toHaveBeenCalledTimes(1);
        view = completeView(); view.complete!.binding.generationId = view.complete!.manifest.generationId = `sample_${'d'.repeat(32)}`; fireEvent.click(screen.getByRole('button', { name: 'Refresh inventory and restart' })); await screen.findByRole('table'); expect(request).toHaveBeenCalledTimes(2); expect(JSON.parse(vi.mocked(mutateRaw).mock.calls.at(-1)![1]).cursor).toBe('');
    });
    it('429 is bounded and offers an explicit retry without looping or changing the cursor', async () => {
        await open(); vi.mocked(mutateRaw).mockRejectedValueOnce(new APIError('busy', 429)); fireEvent.click(screen.getByRole('button', { name: 'Next 100 rows' })); await screen.findByText('The manager is busy. Retry in a moment.'); expect(mutateRaw).toHaveBeenCalledTimes(2); fireEvent.click(screen.getByRole('button', { name: 'Retry request' })); await screen.findByText('fixture-000100', { selector: 'th' }); expect(screen.getByText('200 / 350')).toBeVisible();
    });
    it('401 clears private data and focus cannot restart locked requests', async () => {
        await open(); vi.mocked(mutateRaw).mockRejectedValueOnce(new APIError('session', 401)); fireEvent.click(screen.getByRole('button', { name: 'Next 100 rows' })); await screen.findByText('Your session has ended. Sign in again.'); act(() => window.dispatchEvent(new Event('focus'))); expect(screen.queryByRole('table')).not.toBeInTheDocument(); expect(mutateRaw).toHaveBeenCalledTimes(2); expect(screen.getByRole('button', { name: 'Refresh inventory and restart' })).toBeDisabled();
    });
    it('BFCache/focus restore refreshes and starts from row zero instead of retaining cursor pages', async () => {
        await open(); fireEvent.click(screen.getByRole('button', { name: 'Next 100 rows' })); await screen.findByText('fixture-000100', { selector: 'th' }); act(() => window.dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true }))); expect(screen.queryByRole('table')).not.toBeInTheDocument(); act(() => window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true }))); await screen.findByText('fixture-000000', { selector: 'th' }); expect(JSON.parse(vi.mocked(mutateRaw).mock.calls.at(-1)![1]).cursor).toBe('');
    });
    it('fails closed on mixed generations and repeat page order', async () => {
        await open(); vi.mocked(mutateRaw).mockResolvedValueOnce(completePage(view, rows)); fireEvent.click(screen.getByRole('button', { name: 'Next 100 rows' })); await screen.findByText(/inconsistent or unsupported inventory/); expect(screen.queryByRole('table')).not.toBeInTheDocument();
    });
    it('provides German inventory labels without invented update or CVE counts', async () => {
        setLocale('de', false); render(<CompletePackagesPanel deviceId={completeDevice}/>); fireEvent.click(screen.getByRole('button', { name: 'Vollständiges dpkg-Inventar' })); await screen.findByRole('table'); expect(screen.getByText('Installierte Zeilen')).toBeVisible(); expect(screen.getByText(/Snap, Flatpak und andere Quellen/)).toBeVisible(); expect(document.body.textContent).not.toMatch(/0 CVEs|0 Updates/);
    });
    it.each(['rollback', 'forward', 'backward'] as const)('invalidates clock confidence on %s instead of extending observation age', async kind => {
        vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] });
        const mono = vi.spyOn(performance, 'now').mockReturnValue(1000), wall = vi.spyOn(Date, 'now').mockReturnValue(100000);
        await open(); if (kind === 'rollback') mono.mockReturnValue(500); else wall.mockReturnValue(kind === 'forward' ? 3700000 : -3500000);
        act(() => vi.advanceTimersByTime(1000)); expect(screen.queryByRole('table')).not.toBeInTheDocument(); expect(screen.getByRole('alert')).toHaveTextContent('time anchor is no longer reliable');
    });
    it('expires a cursor locally using monotonic server age and requires explicit restart', async () => {
        vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] });
        const mono = vi.spyOn(performance, 'now').mockReturnValue(1000), wall = vi.spyOn(Date, 'now').mockReturnValue(100000);
        await open(); mono.mockReturnValue(901000); wall.mockReturnValue(1000000); act(() => vi.advanceTimersByTime(1000));
        expect(screen.queryByRole('table')).not.toBeInTheDocument(); expect(screen.getByRole('alert')).toHaveTextContent('paging session expired or changed'); expect(mutateRaw).toHaveBeenCalledTimes(1);
    });
    it('rejects unsupported search text without sending it and preserves the ability to correct it', async () => {
        await open(); fireEvent.change(screen.getByLabelText('Search packages'), { target: { value: 'ä' } }); fireEvent.click(screen.getByRole('button', { name: 'Search' })); expect(screen.getByRole('alert')).toHaveTextContent('128 printable ASCII'); expect(mutateRaw).toHaveBeenCalledTimes(1);
        fireEvent.change(screen.getByLabelText('Search packages'), { target: { value: 'fixture-000349' } }); fireEvent.click(screen.getByRole('button', { name: 'Search' })); await screen.findByText('fixture-000349', { selector: 'th' });
    });
});
