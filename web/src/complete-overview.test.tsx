import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { APIError, AUTH_REQUIRED_EVENT, mutateRaw, request } from './api';
import { CompleteOverviewPanel } from './complete-overview';
import { overviewDevice, overviewGolden, overviewPage, overviewView, processRows, volumeRows } from './complete-overview-fixtures';
import type { OverviewPage, OverviewSection, OverviewView } from './complete-overview-types';
import { setLocale } from './i18n';
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutateRaw: vi.fn() }));
const operator = vi.hoisted(() => ({ mode: 'lan', authenticated: true, expiresAt: '2026-10-04T20:00:00Z' }));
vi.mock('./auth', () => ({ useOperator: () => operator }));
let view: OverviewView;
const open = (section: OverviewSection = 'processes') => render(<CompleteOverviewPanel deviceId={overviewDevice} section={section} sessionKey="first"/>);
const query = (section: OverviewSection = 'processes', cursor = '', search = '') => JSON.stringify({ section, cursor, search, limit: 100 });
beforeEach(() => { setLocale('en', false); operator.authenticated = true; view = overviewView(); vi.mocked(request).mockReset().mockImplementation(async () => view); vi.mocked(mutateRaw).mockReset().mockImplementation(async (_path, raw) => overviewPage(view, processRows(), volumeRows(), raw)); });
afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.useRealTimers(); });

describe('complete process and mount panels', () => {
    it('pages all 350 processes instead of a 64-row capture sample', async () => {
        open(); await screen.findByText('fixture-process-000099'); expect(screen.queryByText('fixture-process-000100')).not.toBeInTheDocument();
        expect(screen.getByText('Complete enumeration rows').nextElementSibling).toHaveTextContent('350');
        for (const last of ['000199', '000299', '000349']) { fireEvent.click(screen.getByRole('button', { name: 'Next page' })); await screen.findByText(`fixture-process-${last}`); }
        expect(screen.getByText('Rows scanned so far').nextElementSibling).toHaveTextContent('350 / 350'); expect(screen.getByText('Rows on this page').nextElementSibling).toHaveTextContent('50'); expect(screen.queryByRole('button', { name: 'Next page' })).not.toBeInTheDocument();
        expect(vi.mocked(mutateRaw).mock.calls).toHaveLength(4); for (const [path, raw, , signal, limit] of vi.mocked(mutateRaw).mock.calls) { expect(path).toBe(`/devices/${overviewDevice}/inventory/overview/query`); expect(JSON.parse(raw)).toMatchObject({ generationId: view.processes.complete!.binding.generationId, section: 'processes', limit: 100 }); expect(signal).toBeInstanceOf(AbortSignal); expect(limit).toBe(262144); }
    });
    it('shows all 85 mounts with measured local grouping and namespace/sum limitations', async () => {
        open('volumes'); await screen.findByText('/fixture-000084'); expect(screen.getByText('Complete enumeration rows').nextElementSibling).toHaveTextContent('85'); expect(screen.getByText('Rows on this page').nextElementSibling).toHaveTextContent('85');
        expect(screen.getByText(/not a physical-host disk inventory/)).toHaveTextContent('do not sum capacities'); expect(screen.getByText('Measured local filesystems')).toHaveTextContent('on this page'); expect(screen.getAllByText('N/A · zero capacity')).toHaveLength(85);
    });
    it('renders actual Go process zero values, missing outcomes, latest failure, and original independent ages', async () => {
        const f = overviewGolden(); view = f.view; vi.mocked(mutateRaw).mockResolvedValue(f.processPage); open(); await screen.findByRole('table');
        expect(screen.getByText('kworker/0:0')).toBeVisible(); expect(screen.getByText('fixture\\worker')).toBeVisible();
        expect(screen.getByText('Latest collection attempt failed')).toBeVisible(); expect(screen.getByText('Collection timed out', { exact: false })).toBeVisible(); expect(screen.getByText('Original observation age (minutes)').nextElementSibling).toHaveTextContent('5');
        expect(screen.getByText(/Mixed captures:/)).toHaveTextContent('2026-10-04T18:15:00Z'); expect(screen.getByText('Denied').nextElementSibling).toHaveTextContent('1'); expect(screen.getByText('Exited').nextElementSibling).toHaveTextContent('1');
        const observed = f.processPage.items.find(row => row.process!.observation.status === 'observed')!.process!;
        const row = screen.getByRole('rowheader', { name: String(observed.pid) }).closest('tr')!; expect(within(row).getByText('0 B')).toBeVisible(); expect(within(row).getAllByText('0')).toHaveLength(2);
        expect(screen.getByRole('columnheader', { name: 'CPU time (s), cumulative' })).toBeVisible(); expect(screen.getAllByText('Exited during capture').length).toBeGreaterThan(0);
    });
    it('renders path-like process labels as inert text', async () => {
        const rows = processRows(2); rows[0].process!.name = '../label'; rows[1].process!.name = '<img/onerror=alert(1)>';
        view = overviewView(2, 0); vi.mocked(mutateRaw).mockImplementation(async (_path, raw) => overviewPage(view, rows, [], raw));
        open(); await screen.findByText('../label'); expect(screen.getByText('<img/onerror=alert(1)>')).toBeVisible();
        expect(screen.queryByRole('img')).not.toBeInTheDocument();
    });
    it('renders actual Go volume classes and N/A separately from denied and unsupported capacities', async () => {
        const f = overviewGolden(); view = f.view; vi.mocked(mutateRaw).mockResolvedValue(f.volumePage); open('volumes'); await screen.findByRole('table');
        for (const label of ['Measured local filesystems', 'Local filesystems · capacity unavailable', 'Memory-backed filesystems', 'Remote filesystems', 'Unclassified filesystems', 'Virtual and pseudo filesystems']) expect(screen.getByText(label)).toBeVisible();
        expect(screen.getAllByText('N/A').length).toBeGreaterThan(0); expect(screen.getAllByText('Denied').length).toBeGreaterThan(0); expect(screen.getByText('Remote filesystem not measured')).toBeVisible(); expect(screen.getAllByText('0 B').length).toBeGreaterThan(0);
    });
    it('searches across scan windows rather than filtering only the visible page', async () => {
        view = overviewView(2200); vi.mocked(mutateRaw).mockImplementation(async (_path, raw) => overviewPage(view, processRows(2200), volumeRows(), raw)); open(); await screen.findByRole('table');
        fireEvent.change(screen.getByLabelText('Search this complete section'), { target: { value: 'fixture-process-002199' } }); expect(screen.queryByRole('table')).not.toBeInTheDocument(); fireEvent.click(screen.getByRole('button', { name: 'Search from first page' }));
        await screen.findByText('No matches in this scan window. More rows remain; continue searching.'); expect(screen.getByText('Rows scanned so far').nextElementSibling).toHaveTextContent('2,048 / 2,200'); fireEvent.click(screen.getByRole('button', { name: 'Continue search' })); await screen.findByText('fixture-process-002199'); expect(screen.getByText('Rows scanned so far').nextElementSibling).toHaveTextContent('2,200 / 2,200');
        expect(screen.getByText('Matches found so far').nextElementSibling).toHaveTextContent('1');
    });
    it('distinguishes successful zero from awaiting or expired observations', async () => {
        view = overviewView(0); vi.mocked(mutateRaw).mockImplementation(async (_path, raw) => overviewPage(view, [], volumeRows(), raw)); const rendered = open(); await screen.findByText('Successful complete enumeration contained zero rows.'); rendered.unmount();
        view.processes = { status: 'awaiting', complete: null, transfer: null, failure: null }; vi.mocked(mutateRaw).mockClear(); open(); await screen.findByText('No complete generation is available. Missing or failed collection is not a successful zero-row capture.'); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('retains independent pending transfer counts without using them as complete row counts', async () => {
        const c = structuredClone(view.processes.complete!); c.binding.sequence = '5'; c.binding.generationId = c.manifest.generationId = 'sample_' + 'e'.repeat(32);
        view.processes.transfer = { ...c, state: 'pending', declaredRows: 350, acceptedRows: 128, expectedChunks: c.manifest.chunkCount, acceptedChunks: 1, collectedAt: c.manifest.collectedAt, startedAt: c.completedAt, expiresAt: '2026-10-04T18:40:00Z' };
        // Transfer has its own exact DTO fields, with no completion metadata.
        delete (view.processes.transfer as unknown as Record<string, unknown>).completedAt; delete (view.processes.transfer as unknown as Record<string, unknown>).retainedUntil;
        open(); await screen.findByRole('table'); expect(screen.getByText('Latest transfer', { exact: false })).toHaveTextContent('pending'); expect(screen.getByText(/128 \/ 350 rows received/)).toBeVisible(); expect(screen.getByText('Complete enumeration rows').nextElementSibling).toHaveTextContent('350');
    });
    it.each(['auth', 'pagehide', 'blur', 'hashchange'] as const)('aborts and suppresses late pages after %s', async transition => {
        let finish!: (v: OverviewPage) => void, signal!: AbortSignal;
        vi.mocked(mutateRaw).mockImplementation(async (_p, _r, _h, s) => { signal = s!; return new Promise<OverviewPage>(resolve => { finish = resolve; }); }); open(); await waitFor(() => expect(finish).toBeDefined());
        act(() => window.dispatchEvent(new Event(transition === 'auth' ? AUTH_REQUIRED_EVENT : transition))); expect(signal.aborted).toBe(true);
        await act(async () => finish(overviewPage(view, processRows(), volumeRows(), query()))); expect(screen.queryByRole('table')).not.toBeInTheDocument();
        if (transition === 'auth') expect(screen.getByRole('button', { name: 'Refresh section and restart' })).toBeDisabled();
    });
    it.each(['section', 'device', 'session'] as const)('clears rows and cancels old requests when %s changes', async transition => {
        let finish!: (v: OverviewPage) => void, signal!: AbortSignal; vi.mocked(mutateRaw).mockImplementationOnce(async (_p, _r, _h, s) => { signal = s!; return new Promise<OverviewPage>(resolve => { finish = resolve; }); }); const rendered = open(); await waitFor(() => expect(finish).toBeDefined());
        rendered.rerender(<CompleteOverviewPanel deviceId={transition === 'device' ? 'agent_' + 'b'.repeat(32) : overviewDevice} section={transition === 'section' ? 'volumes' : 'processes'} sessionKey={transition === 'session' ? 'second' : 'first'}/>); expect(signal.aborted).toBe(true); await act(async () => finish(overviewPage(view, processRows(), volumeRows(), query())));
        if (transition === 'section') { await screen.findByText('/fixture-000084'); expect(screen.queryByText('fixture-process-000000')).not.toBeInTheDocument(); } else if (transition === 'device') expect(screen.queryByRole('table')).not.toBeInTheDocument(); else { await screen.findByRole('table'); expect(mutateRaw).toHaveBeenCalledTimes(2); }
    });
    it.each([409, 429, 503] as const)('clears rows and renders bounded error for HTTP %s', async status => {
        open(); await screen.findByRole('table'); vi.mocked(mutateRaw).mockRejectedValueOnce(new APIError('private diagnostics', status)); fireEvent.click(screen.getByRole('button', { name: 'Next page' })); const alert = await screen.findByRole('alert'); expect(alert).not.toHaveTextContent('private diagnostics'); expect(screen.queryByRole('table')).not.toBeInTheDocument();
        if (status !== 409) { fireEvent.click(screen.getByRole('button', { name: 'Retry request' })); await screen.findByText('fixture-process-000199'); expect(screen.getByText('Rows scanned so far').nextElementSibling).toHaveTextContent('200 / 350'); }
    });
    it('rejects a repeated cursor or a renewed cursor deadline rather than mixing pages', async () => {
        open(); await screen.findByRole('table'); const second = overviewPage(view, processRows(), volumeRows(), query('processes', 'cursor_100')); second.cursorExpiresAt = '2026-10-04T18:49:59Z'; vi.mocked(mutateRaw).mockResolvedValueOnce(second); fireEvent.click(screen.getByRole('button', { name: 'Next page' })); await screen.findByRole('alert'); expect(screen.queryByRole('table')).not.toBeInTheDocument();
    });
    it.each(['rollback', 'forward', 'backward'] as const)('invalidates a %s clock jump without extending capture age', async kind => {
        vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] }); const mono = vi.spyOn(performance, 'now').mockReturnValue(1000), wall = vi.spyOn(Date, 'now').mockReturnValue(100000);
        open(); await screen.findByRole('table'); if (kind === 'rollback') mono.mockReturnValue(500); else wall.mockReturnValue(kind === 'forward' ? 3700000 : -3500000);
        act(() => vi.advanceTimersByTime(1000)); expect(screen.queryByRole('table')).not.toBeInTheDocument(); expect(screen.getByRole('alert')).toHaveTextContent('time anchor is no longer reliable');
    });
    it('expires the original cursor locally and does not silently renew it', async () => {
        vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] }); const mono = vi.spyOn(performance, 'now').mockReturnValue(1000), wall = vi.spyOn(Date, 'now').mockReturnValue(100000);
        open(); await screen.findByRole('table'); mono.mockReturnValue(901000); wall.mockReturnValue(1000000); act(() => vi.advanceTimersByTime(1000));
        expect(screen.queryByRole('table')).not.toBeInTheDocument(); expect(screen.getByRole('alert')).toHaveTextContent('generation or cursor changed or expired'); expect(mutateRaw).toHaveBeenCalledTimes(1);
        fireEvent.click(screen.getByRole('button', { name: 'Refresh section and restart' })); await screen.findByText('fixture-process-000000'); expect(JSON.parse(vi.mocked(mutateRaw).mock.calls.at(-1)![1]).cursor).toBe('');
    });
    it('clears expired retained rows while preserving historical metadata and original count', async () => {
        view.serverNow = '2026-10-05T18:30:00Z'; view.processes.status = view.volumes.status = view.status = 'expired'; view.processes.complete!.state = view.volumes.complete!.state = 'expired';
        open(); await screen.findByText('Retained metadata only. Original observations have expired; no rows are shown.'); expect(mutateRaw).not.toHaveBeenCalled(); expect(screen.getByText('Complete enumeration rows').nextElementSibling).toHaveTextContent('350'); expect(screen.queryByRole('table')).not.toBeInTheDocument();
    });
    it('rejects authoritative server-time regression on refresh', async () => {
        open(); await screen.findByRole('table'); view = structuredClone(view); view.serverNow = '2026-10-04T18:34:59Z'; fireEvent.click(screen.getByRole('button', { name: 'Refresh section and restart' }));
        await screen.findByRole('alert'); expect(screen.getByRole('alert')).toHaveTextContent('time anchor'); expect(screen.queryByRole('table')).not.toBeInTheDocument();
    });
    it('restarts from the first page after BFCache or visibility suspension', async () => {
        open(); await screen.findByRole('table'); fireEvent.click(screen.getByRole('button', { name: 'Next page' })); await screen.findByText('fixture-process-000199');
        act(() => window.dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true }))); expect(screen.queryByRole('table')).not.toBeInTheDocument(); act(() => window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true }))); await screen.findByText('fixture-process-000000'); expect(JSON.parse(vi.mocked(mutateRaw).mock.calls.at(-1)![1]).cursor).toBe('');
        const visibility = vi.spyOn(document, 'visibilityState', 'get'); visibility.mockReturnValue('hidden'); act(() => document.dispatchEvent(new Event('visibilitychange'))); expect(screen.queryByRole('table')).not.toBeInTheDocument(); visibility.mockReturnValue('visible'); act(() => document.dispatchEvent(new Event('visibilitychange'))); await screen.findByText('fixture-process-000000');
    });
    it('search changes cancel an in-flight page and unsupported search is never sent', async () => {
        open(); await screen.findByRole('table'); let finish!: (value: OverviewPage) => void, signal!: AbortSignal;
        vi.mocked(mutateRaw).mockImplementationOnce(async (_p, _r, _h, s) => { signal = s!; return new Promise<OverviewPage>(resolve => { finish = resolve; }); }); fireEvent.click(screen.getByRole('button', { name: 'Next page' })); await waitFor(() => expect(finish).toBeDefined());
        fireEvent.change(screen.getByLabelText('Search this complete section'), { target: { value: 'ä' } }); expect(signal.aborted).toBe(true); fireEvent.click(screen.getByRole('button', { name: 'Search from first page' })); expect(screen.getByRole('alert')).toHaveTextContent('128 printable ASCII'); await act(async () => finish(overviewPage(view, processRows(), volumeRows(), query('processes', 'cursor_100')))); expect(screen.queryByRole('table')).not.toBeInTheDocument(); expect(mutateRaw).toHaveBeenCalledTimes(2);
    });
    it('does not request private rows for an unauthenticated operator and retains German UI', async () => {
        operator.authenticated = false; const r = open(); expect(screen.getByText('Authenticated LAN operator access is required.')).toBeVisible(); expect(request).not.toHaveBeenCalled(); r.unmount(); operator.authenticated = true; setLocale('de', false); open(); await screen.findByRole('table'); expect(screen.getByRole('heading', { name: 'Prozesse · vollständige sichtbare Aufzählung' })).toBeVisible(); expect(screen.getByRole('button', { name: 'Nächste Seite' })).toBeVisible();
    });
});
