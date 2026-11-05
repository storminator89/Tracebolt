import { useCompleteOverview } from './complete-overview-resource';
import userEvent from '@testing-library/user-event';
import { act, cleanup, fireEvent, render, renderHook, screen, waitFor, within } from '@testing-library/react';
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
    it.each([['en', 'processes'], ['de', 'processes'], ['en', 'volumes'], ['de', 'volumes']] as const)('retains %s %s search while refresh replaces the generation and resets later-page progress', async (locale, section) => {
        setLocale(locale, false); view = overviewView(220, 220);
        vi.mocked(mutateRaw).mockImplementation(async (_path, raw) => overviewPage(view, processRows(220), volumeRows(220), raw));
        open(section); await screen.findByRole('table');
        const needle = section === 'processes' ? 'fixture-process-' : 'ext4';
        const searchLabel = locale === 'de' ? 'Abschnitt durchsuchen' : 'Search this section';
        fireEvent.change(screen.getByLabelText(searchLabel), { target: { value: needle } });
        fireEvent.click(screen.getByRole('button', { name: locale === 'de' ? 'Suchen' : 'Search' })); await screen.findByRole('table');
        fireEvent.click(screen.getByRole('button', { name: locale === 'de' ? 'Suche fortsetzen' : 'Continue search' })); await screen.findByRole('table');
        expect(screen.getByText(locale === 'de' ? 'Bisher geprüfte Zeilen' : 'Rows scanned so far').nextElementSibling).toHaveTextContent('200 / 220');
        const original = structuredClone(view[section].complete!);
        view = structuredClone(view);
        const next = view[section].complete!;
        next.binding.generationId = next.manifest.generationId = `sample_${'e'.repeat(32)}`; next.binding.sequence = '5';
        let finish!: (value: OverviewView) => void;
        vi.mocked(request).mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
        fireEvent.click(screen.getByRole('button', { name: locale === 'de' ? 'Abschnitt aktualisieren und neu beginnen' : 'Refresh section and restart' }));
        expect(screen.queryByRole('table')).toBeNull();
        expect(screen.getByText(needle, { selector: 'code' })).toBeVisible();
        await act(async () => finish(view)); await screen.findByRole('table');
        expect(screen.getByLabelText(searchLabel)).toHaveValue(needle);
        expect(JSON.parse(vi.mocked(mutateRaw).mock.calls.at(-1)![1])).toEqual({ section, generationId: next.binding.generationId, cursor: '', search: needle, limit: 100 });
        expect(screen.getByText(locale === 'de' ? 'Bisher geprüfte Zeilen' : 'Rows scanned so far').nextElementSibling).toHaveTextContent('100 / 220');
        expect(screen.getByText(locale === 'de' ? 'Bisher gefundene Treffer' : 'Matches found so far').nextElementSibling).toHaveTextContent('100');
        expect(screen.getByText(locale === 'de' ? 'Ursprüngliche Aufbewahrungsfrist' : 'Original retention deadline').nextElementSibling).toHaveTextContent(original.retainedUntil);
        expect(screen.getByText(locale === 'de' ? 'Erfassung begonnen' : 'Capture started').nextElementSibling).toHaveTextContent(original.manifest.captureStartedAt);
        expect(request).toHaveBeenCalledTimes(2); expect(mutateRaw).toHaveBeenCalledTimes(4);
    });
    it.each(['processes', 'volumes'] as const)('explicitly applies a valid unsubmitted %s draft when refreshing', async section => {
        open(section); await screen.findByRole('table');
        const needle = section === 'processes' ? 'fixture-process-000219' : '/fixture-000084';
        fireEvent.change(screen.getByLabelText('Search this section'), { target: { value: needle } });
        expect(mutateRaw).toHaveBeenCalledTimes(1);
        fireEvent.click(screen.getByRole('button', { name: 'Refresh section and restart' })); await screen.findByRole('table');
        expect(screen.getByLabelText('Search this section')).toHaveValue(needle);
        expect(JSON.parse(vi.mocked(mutateRaw).mock.calls.at(-1)![1])).toMatchObject({ section, cursor: '', search: needle });
        expect(within(screen.getByRole('table')).getByText(needle)).toBeVisible();
    });
    it.each(['en', 'de'] as const)('allows explicit recovery from an invalid search after focus loss (%s)', async locale => {
        setLocale(locale, false); open(); await screen.findByRole('table');
        const label = locale === 'de' ? 'Abschnitt durchsuchen' : 'Search this section';
        fireEvent.change(screen.getByLabelText(label), { target: { value: 'ä' } });
        act(() => window.dispatchEvent(new Event('blur'))); act(() => window.dispatchEvent(new Event('focus')));
        expect(screen.queryByLabelText(label)).toBeNull();
        expect(screen.getByRole('alert')).toHaveTextContent('128');
        expect(screen.getByText('ä', { selector: 'code' })).toBeVisible();
        expect(request).toHaveBeenCalledTimes(1); expect(mutateRaw).toHaveBeenCalledTimes(1);
        fireEvent.click(screen.getByRole('button', { name: locale === 'de' ? 'Suche leeren und aktualisieren' : 'Clear search and refresh' }));
        await screen.findByRole('table'); expect(screen.getByLabelText(label)).toHaveValue('');
        expect(vi.mocked(mutateRaw).mock.calls.every(([, raw]) => JSON.parse(raw).search !== 'ä')).toBe(true);
        expect(request).toHaveBeenCalledTimes(2);
    });
    it('keeps a valid query after a failed refresh and reuses it on explicit retry', async () => {
        open(); await screen.findByRole('table');
        fireEvent.change(screen.getByLabelText('Search this section'), { target: { value: 'fixture-process-000219' } });
        vi.mocked(request).mockRejectedValueOnce(new APIError('Synthetic read failed', 503));
        fireEvent.click(screen.getByRole('button', { name: 'Refresh section and restart' })); await screen.findByRole('alert');
        expect(screen.queryByRole('table')).toBeNull(); expect(screen.getByText('fixture-process-000219', { selector: 'code' })).toBeVisible();
        expect(mutateRaw).toHaveBeenCalledTimes(1);
        fireEvent.click(screen.getByRole('button', { name: 'Retry request' })); await screen.findByRole('table');
        expect(screen.getByLabelText('Search this section')).toHaveValue('fixture-process-000219');
        expect(JSON.parse(vi.mocked(mutateRaw).mock.calls.at(-1)![1])).toMatchObject({ cursor: '', search: 'fixture-process-000219' });
        expect(request).toHaveBeenCalledTimes(3); expect(mutateRaw).toHaveBeenCalledTimes(2);
    });
    it.each(['section', 'device', 'session', 'auth'] as const)('does not retain a private query across %s changes', async boundary => {
        const mounted = open(); await screen.findByRole('table');
        fireEvent.change(screen.getByLabelText('Search this section'), { target: { value: 'private-query-fixture' } });
        if (boundary === 'auth') {
            act(() => window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT)));
            expect(screen.queryByDisplayValue('private-query-fixture')).toBeNull();
            expect(screen.queryByText('private-query-fixture', { selector: 'code' })).toBeNull();
            expect(screen.queryByRole('button', { name: 'Clear search and refresh' })).toBeNull();
        } else {
            const id = boundary === 'device' ? `agent_${'b'.repeat(32)}` : overviewDevice;
            view = structuredClone(view); view.deviceId = id;
            mounted.rerender(<CompleteOverviewPanel deviceId={id} section={boundary === 'section' ? 'volumes' : 'processes'} sessionKey={boundary === 'session' ? 'second' : 'first'}/>);
            await screen.findByRole('table'); expect(screen.getByLabelText('Search this section')).toHaveValue('');
            expect(JSON.parse(vi.mocked(mutateRaw).mock.calls.at(-1)![1]).search).toBe('');
        }
    });
    it.each([['en', 'processes'], ['de', 'processes'], ['en', 'volumes'], ['de', 'volumes']] as const)('keeps %s %s coverage, age and search ahead of the capture disclosure, directly before rows', async (locale, section) => {
        setLocale(locale, false); open(section);
        const table = await screen.findByRole('table'), disclosure = document.querySelector('.overview-provenance')!, summary = disclosure.querySelector('summary')!;
        expect(document.querySelectorAll('.complete-overview > details')).toHaveLength(1);
        const search = screen.getByLabelText(locale === 'de' ? 'Abschnitt durchsuchen' : 'Search this section');
        expect(search.compareDocumentPosition(table) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
        expect(search.compareDocumentPosition(disclosure) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
        expect(disclosure.compareDocumentPosition(table) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
        expect(disclosure.previousElementSibling?.tagName).toBe('DL');
        expect(disclosure.nextElementSibling).toContainElement(table);
        expect(disclosure).not.toHaveAttribute('open'); expect(summary).toHaveTextContent(locale === 'de' ? 'Erfassungsdetails' : 'Capture details');
        expect(document.querySelector('.overview-coverage')).toBeVisible(); expect(document.querySelector('.overview-coverage')).not.toContainElement(disclosure as HTMLElement);
        expect(screen.getByText(locale === 'de' ? 'Ursprüngliches Beobachtungsalter (Minuten)' : 'Original observation age (minutes)').nextElementSibling).toHaveTextContent(section === 'processes' ? '5' : '20');
        const original = view[section].complete!, facts = within(disclosure as HTMLElement);
        expect(facts.getByText(original.binding.generationId)).not.toBeVisible();
        summary.focus(); expect(summary).toHaveFocus(); fireEvent.click(summary);
        for (const [label, value] of [
            [locale === 'de' ? 'Abschnittsgeneration' : 'Section generation', original.binding.generationId],
            [locale === 'de' ? 'Sequenz' : 'Sequence', original.binding.sequence],
            [locale === 'de' ? 'Erfassung begonnen' : 'Capture started', original.manifest.captureStartedAt],
            [locale === 'de' ? 'Erfassung beendet' : 'Capture finished', original.manifest.captureFinishedAt],
            [locale === 'de' ? 'Ursprüngliche Aufbewahrungsfrist' : 'Original retention deadline', original.retainedUntil],
        ]) { expect(facts.getByText(label).nextElementSibling).toHaveTextContent(value); expect(facts.getByText(label).nextElementSibling).toBeVisible(); }
        fireEvent.click(summary); expect(disclosure).not.toHaveAttribute('open'); expect(screen.getByRole('table')).toBe(table);
        expect(request).toHaveBeenCalledTimes(1); expect(mutateRaw).toHaveBeenCalledTimes(1);
        expect(JSON.parse(vi.mocked(mutateRaw).mock.calls[0][1])).toMatchObject({ section, generationId: original.binding.generationId, cursor: '', search: '', limit: 100 });
    });
    it('pages all 350 processes instead of a 64-row capture sample', async () => {
        open(); await screen.findByText('fixture-process-000099'); expect(screen.queryByText('fixture-process-000100')).not.toBeInTheDocument();
        expect(screen.getByText('Complete enumeration rows').nextElementSibling).toHaveTextContent('350');
        for (const last of ['000199', '000299', '000349']) { fireEvent.click(screen.getByRole('button', { name: 'Next page' })); await screen.findByText(`fixture-process-${last}`); }
        expect(screen.getByText('Rows scanned so far').nextElementSibling).toHaveTextContent('350 / 350'); expect(screen.getByText('Rows on this page').nextElementSibling).toHaveTextContent('50'); expect(screen.queryByRole('button', { name: 'Next page' })).not.toBeInTheDocument();
        expect(vi.mocked(mutateRaw).mock.calls).toHaveLength(4); for (const [path, raw, , signal, limit] of vi.mocked(mutateRaw).mock.calls) { expect(path).toBe(`/devices/${overviewDevice}/inventory/overview/query`); expect(JSON.parse(raw)).toMatchObject({ generationId: view.processes.complete!.binding.generationId, section: 'processes', limit: 100 }); expect(signal).toBeInstanceOf(AbortSignal); expect(limit).toBe(262144); }
    });
    it('shows all 85 mounts with measured local grouping and namespace/sum limitations', async () => {
        open('volumes'); await screen.findByText('/fixture-000084'); expect(screen.getByText('Complete enumeration rows').nextElementSibling).toHaveTextContent('85'); expect(screen.getByText('Rows on this page').nextElementSibling).toHaveTextContent('85');
        expect(screen.getByText(/not physical disks/)).toHaveTextContent('do not sum capacities'); expect(screen.getByText('Measured local filesystems')).toHaveTextContent('on this page'); expect(screen.getAllByText('N/A · zero capacity')).toHaveLength(85);
    });
    it('renders actual Go process zero values, missing outcomes, latest failure, and original independent ages', async () => {
        const f = overviewGolden(); view = f.view; vi.mocked(mutateRaw).mockResolvedValue(f.processPage); open(); await screen.findByRole('table');
        expect(screen.getByText('kworker/0:0')).toBeVisible(); expect(screen.getByText('fixture\\worker')).toBeVisible();
        expect(screen.getByText('Latest collection attempt failed', { selector: 'strong' })).toBeVisible(); expect(screen.getByText('Collection timed out', { exact: false })).toBeVisible(); expect(screen.getByText('Original observation age (minutes)').nextElementSibling).toHaveTextContent('5');
        expect(screen.getByText(/Mixed captures\./)).toBeVisible(); expect(screen.getByText(/Mixed captures\./)).not.toHaveTextContent('2026-10-04T18:15:00Z'); expect(within(document.querySelector('.overview-provenance')! as HTMLElement).getByText('Mounts · original capture started').nextElementSibling).toHaveTextContent('2026-10-04T18:15:00Z'); expect(screen.getByText('Denied').nextElementSibling).toHaveTextContent('1'); expect(screen.getByText('Exited').nextElementSibling).toHaveTextContent('1');
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
        fireEvent.change(screen.getByLabelText('Search this section'), { target: { value: 'fixture-process-002199' } }); expect(screen.queryByRole('table')).not.toBeInTheDocument(); fireEvent.click(screen.getByRole('button', { name: 'Search' }));
        await screen.findByText('No matches in this scan window. More rows remain; continue searching.'); expect(screen.getByText('Rows scanned so far').nextElementSibling).toHaveTextContent('2,048 / 2,200'); fireEvent.click(screen.getByRole('button', { name: 'Continue search' })); await screen.findByText('fixture-process-002199'); expect(screen.getByText('Rows scanned so far').nextElementSibling).toHaveTextContent('2,200 / 2,200');
        expect(screen.getByText('Matches found so far').nextElementSibling).toHaveTextContent('1');
        expect(JSON.parse(vi.mocked(mutateRaw).mock.calls.at(-1)![1])).toEqual({ section: 'processes', generationId: view.processes.complete!.binding.generationId, cursor: 'cursor_2048', search: 'fixture-process-002199', limit: 100 });
        fireEvent.click(screen.getByText('Capture details')); expect(screen.getByText('Capture started').nextElementSibling).toHaveTextContent(view.processes.complete!.manifest.captureStartedAt); expect(screen.getByText('Original retention deadline').nextElementSibling).toHaveTextContent(view.processes.complete!.retainedUntil); expect(request).toHaveBeenCalledTimes(1);
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
        open(); await screen.findByRole('table'); expect(screen.getByText('Latest transfer', { exact: false, selector: 'strong' })).toHaveTextContent('Transfer pending'); expect(screen.getByText(/128 \/ 350 rows received/)).not.toBeVisible(); fireEvent.click(screen.getByText('Capture details')); expect(screen.getByText(/128 \/ 350 rows received/)).toBeVisible(); expect(screen.getByText('Complete enumeration rows').nextElementSibling).toHaveTextContent('350');
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
        open(); await screen.findByText('Retained metadata only. Original observations have expired; no rows are shown.'); expect(screen.queryByText('Search changed. Choose Search to read the saved capture.')).toBeNull(); expect(screen.queryByRole('button', {name:'Clear search'})).toBeNull(); expect(mutateRaw).not.toHaveBeenCalled(); expect(screen.getByText('Complete enumeration rows').nextElementSibling).toHaveTextContent('350'); expect(screen.queryByRole('table')).not.toBeInTheDocument();
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
        fireEvent.change(screen.getByLabelText('Search this section'), { target: { value: 'ä' } }); expect(signal.aborted).toBe(true); fireEvent.click(screen.getByRole('button', { name: 'Search' })); expect(screen.getByRole('alert')).toHaveTextContent('128 printable ASCII'); await act(async () => finish(overviewPage(view, processRows(), volumeRows(), query('processes', 'cursor_100')))); expect(screen.queryByRole('table')).not.toBeInTheDocument(); expect(mutateRaw).toHaveBeenCalledTimes(2);
    });
    it('does not request private rows for an unauthenticated operator and retains German UI', async () => {
        operator.authenticated = false; const r = open(); expect(screen.getByText('Authenticated LAN operator access is required.')).toBeVisible(); expect(request).not.toHaveBeenCalled(); r.unmount(); operator.authenticated = true; setLocale('de', false); open(); await screen.findByRole('table'); expect(screen.getByRole('heading', { name: 'Prozesse' })).toBeVisible(); expect(screen.getByRole('button', { name: 'Nächste Seite' })).toBeVisible();
    });
});


describe('overview search draft feedback', () => {
    it.each([['en','processes'],['de','processes'],['en','volumes'],['de','volumes']] as const)('explains and clears only the draft without querying (%s, %s)', async (locale, section) => {
        setLocale(locale,false); const user=userEvent.setup(); open(section); await screen.findByRole('table');
        const input=screen.getByRole('searchbox'), before=vi.mocked(mutateRaw).mock.calls.length;
        const hint=locale==='de'?'Suche geändert. Mit „Suchen“ die gespeicherte Erfassung durchsuchen.':'Search changed. Choose Search to read the saved capture.';
        expect(screen.queryByText(hint)).toBeNull();
        fireEvent.change(input,{target:{value:'fixture'}});
        expect(screen.queryByRole('table')).toBeNull(); expect(screen.getByText(hint)).toHaveAttribute('role','status'); expect(input).toHaveAccessibleDescription(hint);
        expect(mutateRaw).toHaveBeenCalledTimes(before);
        const clear=screen.getByRole('button',{name:locale==='de'?'Suche leeren':'Clear search'}); clear.focus(); await user.keyboard(' ');
        expect(input).toHaveFocus(); expect(input).toHaveValue(''); expect(screen.getByText(hint)).toBeVisible(); expect(mutateRaw).toHaveBeenCalledTimes(before);
        fireEvent.click(screen.getByRole('button',{name:locale==='de'?'Suchen':'Search'})); await screen.findByRole('table');
        expect(screen.queryByText(hint)).toBeNull(); expect(input).not.toHaveAttribute('aria-describedby');
        expect(JSON.parse(vi.mocked(mutateRaw).mock.calls.at(-1)![1])).toMatchObject({section,search:'',cursor:'',limit:100});
        expect(mutateRaw).toHaveBeenCalledTimes(before+1);
    });
    it('does not substitute draft guidance for loading, failures or ended access', async () => {
        open(); await screen.findByRole('table'); fireEvent.change(screen.getByRole('searchbox'),{target:{value:'fixture'}});
        let reject!:(error:Error)=>void;
        vi.mocked(mutateRaw).mockImplementationOnce(()=>new Promise((_resolve,no)=>{reject=no;}));
        fireEvent.click(screen.getByRole('button',{name:'Search'}));
        expect(screen.queryByText('Search changed. Choose Search to read the saved capture.')).toBeNull();
        await act(async()=>reject(new APIError('Synthetic failure',503)));
        expect(screen.queryByText('Search changed. Choose Search to read the saved capture.')).toBeNull();
        expect(screen.getByRole('alert')).toBeVisible();
        act(()=>window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT)));
        expect(screen.queryByRole('searchbox')).toBeNull(); expect(screen.queryByRole('button',{name:'Clear search'})).toBeNull();
    });
});

describe('bounded Overview page navigation',()=>{
    it.each([['en','processes'],['de','processes'],['en','volumes'],['de','volumes']] as const)('supports keyboard Previous and First with original counters (%s/%s)',async(locale,section)=>{
        setLocale(locale,false);const user=userEvent.setup();view=overviewView(220,220);vi.mocked(mutateRaw).mockImplementation(async(_path,raw)=>overviewPage(view,processRows(220),volumeRows(220),raw));open(section);await screen.findByRole('table');
        const label=(en:string,de:string)=>locale==='en'?en:de, next=()=>screen.getByRole('button',{name:label('Next page','Nächste Seite')}),previous=()=>screen.getByRole('button',{name:label('Previous page','Vorherige Seite')}),first=()=>screen.getByRole('button',{name:label('First page','Erste Seite')});
        expect(first()).toBeDisabled();expect(previous()).toBeDisabled();fireEvent.click(next());await screen.findByText('200 / 220');fireEvent.click(next());await screen.findByText('220 / 220');
        previous().focus();await user.keyboard(' ');await screen.findByText('200 / 220');expect(previous()).toHaveFocus();first().focus();await user.keyboard('{Enter}');await screen.findByText('100 / 220');expect(first()).toHaveFocus();expect(previous()).toBeDisabled();
        fireEvent.click(next());await screen.findByText('200 / 220');expect(vi.mocked(mutateRaw).mock.calls.map(([,raw])=>JSON.parse(raw).cursor)).toEqual(['','cursor_100','cursor_200','cursor_100','','cursor_100']);
        expect(vi.mocked(mutateRaw).mock.calls.every(([path,raw])=>path===`/devices/${overviewDevice}/inventory/overview/query`&&JSON.parse(raw).section===section)).toBe(true);expect(request).toHaveBeenCalledTimes(1);
    });
    it('retains the first token and earliest lease when First receives a renewed token',async()=>{
        const mono=vi.spyOn(performance,'now').mockReturnValue(1000),wall=vi.spyOn(Date,'now').mockReturnValue(100000);open();await screen.findByRole('table');fireEvent.click(screen.getByRole('button',{name:'Next page'}));await screen.findByText('200 / 350');
        const deadline=overviewPage(view,processRows(),volumeRows(),query()).cursorExpiresAt;
        vi.mocked(mutateRaw).mockImplementationOnce(async(_path,raw)=>({...overviewPage(view,processRows(),volumeRows(),raw),serverNow:new Date(Date.parse(view.serverNow)+1000).toISOString(),cursorExpiresAt:new Date(Date.parse(deadline)+1000).toISOString(),nextCursor:'renewed_100'}));
        fireEvent.click(screen.getByRole('button',{name:'First page'}));await screen.findByText('100 / 350');expect(screen.getByText(`Paging deadline: ${deadline}`)).toBeVisible();
        vi.mocked(mutateRaw).mockImplementationOnce(async(_path,raw)=>({...overviewPage(view,processRows(),volumeRows(),raw),serverNow:new Date(Date.parse(view.serverNow)+1000).toISOString()}));fireEvent.click(screen.getByRole('button',{name:'Next page'}));await screen.findByText('200 / 350');expect(JSON.parse(vi.mocked(mutateRaw).mock.calls.at(-1)![1]).cursor).toBe('cursor_100');
        mono.mockReturnValue(901000);wall.mockReturnValue(1000000);const count=vi.mocked(mutateRaw).mock.calls.length;fireEvent.click(screen.getByRole('button',{name:'Previous page'}));expect(mutateRaw).toHaveBeenCalledTimes(count);expect(screen.queryByRole('table')).toBeNull();expect(screen.getByRole('alert')).toHaveTextContent('expired');
    });
    it.each(['processes','volumes'] as const)('clears terminal %s rows at the original non-null cursor deadline before a navigation request',async section=>{
        const mono=vi.spyOn(performance,'now').mockReturnValue(1000),wall=vi.spyOn(Date,'now').mockReturnValue(100000);view=overviewView(101,101);vi.mocked(mutateRaw).mockImplementation(async(_path,raw)=>overviewPage(view,processRows(101),volumeRows(101),raw));open(section);await screen.findByRole('table');fireEvent.click(screen.getByRole('button',{name:'Next page'}));await screen.findByText('101 / 101');mono.mockReturnValue(901000);wall.mockReturnValue(1000000);fireEvent.click(screen.getByRole('button',{name:'First page'}));expect(mutateRaw).toHaveBeenCalledTimes(2);expect(screen.queryByRole('table')).toBeNull();expect(screen.getByRole('alert')).toHaveTextContent('expired');
    });
    it.each(['deadline','boundary','count','token'] as const)('rejects altered replay %s evidence',async kind=>{
        open();await screen.findByRole('table');fireEvent.click(screen.getByRole('button',{name:'Next page'}));await screen.findByText('200 / 350');fireEvent.click(screen.getByRole('button',{name:'Next page'}));await screen.findByText('300 / 350');
        vi.mocked(mutateRaw).mockImplementationOnce(async(_path,raw)=>{const p=overviewPage(view,processRows(),volumeRows(),raw);if(kind==='deadline')p.cursorExpiresAt=new Date(Date.parse(p.cursorExpiresAt)-1000).toISOString();else if(kind==='boundary')p.items=p.items.slice(1);else if(kind==='count')p.scannedRows++;else p.nextCursor='another_token';return p;});
        fireEvent.click(screen.getByRole('button',{name:'Previous page'}));await screen.findByRole('alert');expect(screen.queryByRole('table')).toBeNull();expect(screen.queryByRole('group',{name:'Page navigation'})).toBeNull();
    });
    it('does not silently restart First after a generation replacement',async()=>{open();await screen.findByRole('table');fireEvent.click(screen.getByRole('button',{name:'Next page'}));await screen.findByText('200 / 350');vi.mocked(mutateRaw).mockRejectedValueOnce(new APIError('changed',409));fireEvent.click(screen.getByRole('button',{name:'First page'}));await screen.findByRole('alert');expect(screen.queryByRole('table')).toBeNull();expect(request).toHaveBeenCalledTimes(1);expect(mutateRaw).toHaveBeenCalledTimes(3);});
    it('rejects a late previous page after its original lease expires',async()=>{const mono=vi.spyOn(performance,'now').mockReturnValue(1000),wall=vi.spyOn(Date,'now').mockReturnValue(100000);open();await screen.findByRole('table');fireEvent.click(screen.getByRole('button',{name:'Next page'}));await screen.findByText('200 / 350');mono.mockReturnValue(900500);wall.mockReturnValue(999500);let done!:(v:unknown)=>void;vi.mocked(mutateRaw).mockReturnValueOnce(new Promise(resolve=>done=resolve));fireEvent.click(screen.getByRole('button',{name:'Previous page'}));mono.mockReturnValue(901000);wall.mockReturnValue(1000000);await act(async()=>done(overviewPage(view,processRows(),volumeRows(),query())));expect(screen.queryByRole('table')).toBeNull();expect(screen.getByRole('alert')).toHaveTextContent('expired');});
});

describe('Overview checkpoint retention and replay boundaries',()=>{
    it('bounds the backward trail to128 checkpoints and reuses known signatures beyond eviction',async()=>{
        view=overviewView(13000,1);const processes=processRows(13000),volumes=volumeRows(1);vi.mocked(mutateRaw).mockImplementation(async(_path,raw)=>overviewPage(view,processes,volumes,raw));const {result}=renderHook(()=>useCompleteOverview(overviewDevice,'processes'));await waitFor(()=>expect(result.current.pageNumber).toBe(1));
        for(let i=2;i<=130;i++){await act(async()=>result.current.next());expect(result.current.pageNumber).toBe(i);}
        for(let i=129;i>=3;i--){await act(async()=>result.current.previous());expect(result.current.pageNumber).toBe(i);}
        expect(result.current.canPrevious).toBe(false);expect(result.current.limitedBack).toBe(true);expect(result.current.canFirst).toBe(true);await act(async()=>result.current.first());expect(result.current.pageNumber).toBe(1);expect(result.current.scanned).toBe(100);
        await act(async()=>result.current.next());expect(result.current.pageNumber).toBe(2);expect(result.current.scanned).toBe(200);expect(result.current.error).toBeNull();expect(request).toHaveBeenCalledTimes(1);
    },20000);
    it.each(['processes','volumes'] as const)('replays empty scan windows with correct %s progress',async section=>{
        view=overviewView(2200,2200);const processes=processRows(2200),volumes=volumeRows(2200);vi.mocked(mutateRaw).mockImplementation(async(_path,raw)=>overviewPage(view,processes,volumes,raw));const {result}=renderHook(()=>useCompleteOverview(overviewDevice,section));await waitFor(()=>expect(result.current.page).not.toBeNull());act(()=>result.current.changeSearch('002199'));await act(async()=>result.current.startSearch());expect(result.current.page?.items).toHaveLength(0);expect(result.current.scanned).toBe(2048);await act(async()=>result.current.next());expect(result.current.matches).toBe(1);await act(async()=>result.current.previous());expect(result.current.matches).toBe(0);expect(result.current.scanned).toBe(2048);await act(async()=>result.current.next());expect(result.current.matches).toBe(1);expect(result.current.scanned).toBe(2200);expect(result.current.error).toBeNull();
    });
    it('keeps numeric PID and mount root/UTF8 ordering during replay',async()=>{
        for(const section of ['processes','volumes'] as const){cleanup();view=overviewView(102,102);const processes=processRows(102),volumes=volumeRows(102);volumes[100].volume!.mountPoint='/ä';volumes[101].volume!.mountPoint='/z';vi.mocked(mutateRaw).mockImplementation(async(_path,raw)=>overviewPage(view,processes,volumes,raw));const {result}=renderHook(()=>useCompleteOverview(overviewDevice,section));await waitFor(()=>expect(result.current.page).not.toBeNull());await act(async()=>result.current.next());const tail=result.current.page!.items;expect(section==='processes'?tail[0].process!.pid:tail[0].volume!.mountPoint).toBe(section==='processes'?101:'/z');await act(async()=>result.current.previous());expect(section==='processes'?result.current.page!.items[0].process!.pid:result.current.page!.items[0].volume!.mountPoint).toBe(section==='processes'?1:'/');await act(async()=>result.current.next());expect(result.current.error).toBeNull();}
    });
    it.each(['blur','pagehide','hashchange','auth','section','device'] as const)('clears checkpoints and rejects late Previous on %s',async loss=>{
        const {result,rerender}=renderHook(({device,section}:{device:string;section:OverviewSection})=>useCompleteOverview(device,section),{initialProps:{device:overviewDevice,section:'processes' as OverviewSection}});await waitFor(()=>expect(result.current.page).not.toBeNull());await act(async()=>result.current.next());let done!:(p:unknown)=>void;vi.mocked(mutateRaw).mockReturnValueOnce(new Promise(resolve=>done=resolve));act(()=>result.current.previous());
        if(loss==='section'||loss==='device'){vi.mocked(request).mockReturnValue(new Promise(()=>{}));rerender({device:loss==='device'?'agent_other':overviewDevice,section:loss==='section'?'volumes':'processes'});}else act(()=>window.dispatchEvent(new Event(loss==='auth'?AUTH_REQUIRED_EVENT:loss)));
        await act(async()=>done(overviewPage(view,processRows(),volumeRows(),query())));expect(result.current.page).toBeNull();expect(result.current.hasNavigation).toBe(false);expect(result.current.canFirst).toBe(false);expect(result.current.canPrevious).toBe(false);
    });
});

it('preserves mount group ordering and rejects a changed replay boundary',async()=>{
    view=overviewView(1,101);const volumes=volumeRows(101);volumes[0].volume!.kind='memory';volumes[0].volume!.filesystem='tmpfs';
    vi.mocked(mutateRaw).mockImplementation(async(_path,raw)=>overviewPage(view,processRows(1),volumes,raw));const {result}=renderHook(()=>useCompleteOverview(overviewDevice,'volumes'));await waitFor(()=>expect(result.current.page).not.toBeNull());expect(result.current.page!.items[0].volume!.mountPoint).toBe('/fixture-000001');await act(async()=>result.current.next());expect(result.current.page!.items[0].volume!.mountPoint).toBe('/');await act(async()=>result.current.previous());expect(result.current.error).toBeNull();
    vi.mocked(mutateRaw).mockImplementationOnce(async(_path,raw)=>{const p=overviewPage(view,processRows(1),volumes,raw);p.items=structuredClone(p.items);p.items[0].volume!.mountPoint='/changed';return p;});await act(async()=>result.current.next());expect(result.current.error).toBe('invalid');expect(result.current.page).toBeNull();
});
it('keeps Previous mounted and focused while its reread is pending',async()=>{
    open();await screen.findByRole('table');fireEvent.click(screen.getByRole('button',{name:'Next page'}));await screen.findByText('200 / 350');let done!:(p:unknown)=>void;vi.mocked(mutateRaw).mockReturnValueOnce(new Promise(resolve=>done=resolve));const previous=screen.getByRole('button',{name:'Previous page'});previous.focus();fireEvent.click(previous);expect(previous).toBeInTheDocument();expect(previous).toBeDisabled();expect(previous).toHaveFocus();expect(screen.queryByRole('table')).toBeNull();await act(async()=>done(overviewPage(view,processRows(),volumeRows(),query())));expect(previous).toBeInTheDocument();expect(previous).toHaveFocus();expect(previous).toBeDisabled();
});

describe('Overview replay retry and terminal focus regressions',()=>{
    it.each([['previous','503'],['first','503'],['previous','timeout'],['first','timeout']] as const)('retries %s after %s at the original checkpoint and lease',async(action,failure)=>{
        const mono=vi.spyOn(performance,'now').mockReturnValue(1000),wall=vi.spyOn(Date,'now').mockReturnValue(100000);const {result}=renderHook(()=>useCompleteOverview(overviewDevice,'processes'));await waitFor(()=>expect(result.current.page).not.toBeNull());await act(async()=>result.current.next());await act(async()=>result.current.next());const deadline=result.current.pagingExpiresAt;
        if(failure==='503')vi.mocked(mutateRaw).mockRejectedValueOnce(new APIError('failed',503));else{vi.useFakeTimers({toFake:['setTimeout','clearTimeout']});vi.mocked(mutateRaw).mockReturnValueOnce(new Promise(()=>{}));}
        await act(async()=>result.current[action]());if(failure==='timeout'){mono.mockReturnValue(11000);wall.mockReturnValue(110000);await act(async()=>vi.advanceTimersByTimeAsync(10000));}
        expect(result.current.page).toBeNull();expect(result.current.error).toBe(failure==='503'?'loadError':'timeout');expect(mutateRaw).toHaveBeenCalledTimes(4);
        await act(async()=>result.current.retry());expect(result.current.error).toBeNull();expect(result.current.pageNumber).toBe(action==='first'?1:2);expect(result.current.scanned).toBe(action==='first'?100:200);expect(result.current.matches).toBe(action==='first'?100:200);expect(result.current.pagingExpiresAt).toBe(deadline);
        const bodies=vi.mocked(mutateRaw).mock.calls.slice(-2).map(([,raw])=>JSON.parse(raw));expect(bodies[0]).toEqual(bodies[1]);expect(bodies[1]).toMatchObject({cursor:action==='first'?'':'cursor_100',search:'',limit:100,generationId:view.processes.complete!.binding.generationId});expect(request).toHaveBeenCalledTimes(1);
    });
    it.each(['previous','first'] as const)('does not retry an expired %s checkpoint',async action=>{
        const mono=vi.spyOn(performance,'now').mockReturnValue(1000),wall=vi.spyOn(Date,'now').mockReturnValue(100000);const {result}=renderHook(()=>useCompleteOverview(overviewDevice,'processes'));await waitFor(()=>expect(result.current.page).not.toBeNull());await act(async()=>result.current.next());vi.mocked(mutateRaw).mockRejectedValueOnce(new APIError('failed',503));await act(async()=>result.current[action]());mono.mockReturnValue(901000);wall.mockReturnValue(1000000);const count=vi.mocked(mutateRaw).mock.calls.length;await act(async()=>result.current.retry());expect(mutateRaw).toHaveBeenCalledTimes(count);expect(result.current.page).toBeNull();expect(result.current.hasNavigation).toBe(false);expect(result.current.error).toBe('restart');
    });
    it.each(['processes','volumes'] as const)('preserves %s checkpoints across same-generation background status after rewinding',async section=>{
        vi.useFakeTimers({toFake:['setInterval','clearInterval']});const mono=vi.spyOn(performance,'now').mockReturnValue(1000),wall=vi.spyOn(Date,'now').mockReturnValue(100000);view=overviewView(220,220);const deadline=overviewPage(view,processRows(220),volumeRows(220),query(section)).cursorExpiresAt;
        vi.mocked(mutateRaw).mockImplementation(async(_path,raw)=>({...overviewPage(view,processRows(220),volumeRows(220),raw),cursorExpiresAt:deadline}));const {result}=renderHook(()=>useCompleteOverview(overviewDevice,section));await act(async()=>{});await waitFor(()=>{expect(request).toHaveBeenCalled();expect(result.current.view).not.toBeNull();expect(mutateRaw).toHaveBeenCalled();expect(result.current.error).toBeNull();expect(result.current.page).not.toBeNull();});await act(async()=>result.current.next());await act(async()=>result.current.next());await act(async()=>result.current.previous());await act(async()=>result.current.previous());expect(result.current.pageNumber).toBe(1);const calls=vi.mocked(mutateRaw).mock.calls.length;
        view=structuredClone(view);view.serverNow=new Date(Date.parse(view.serverNow)+15000).toISOString();mono.mockReturnValue(16000);wall.mockReturnValue(115000);await act(async()=>vi.advanceTimersByTime(15000));expect(request).toHaveBeenCalledTimes(2);expect(mutateRaw).toHaveBeenCalledTimes(calls);expect(result.current.pageNumber).toBe(1);expect(result.current.scanned).toBe(100);expect(result.current.pagingExpiresAt).toBe(deadline);
        await act(async()=>result.current.next());expect(result.current.pageNumber).toBe(2);expect(result.current.scanned).toBe(200);expect(result.current.canPrevious).toBe(true);expect(result.current.canFirst).toBe(true);expect(result.current.pagingExpiresAt).toBe(deadline);mono.mockReturnValue(901000);wall.mockReturnValue(1000000);act(()=>vi.advanceTimersByTime(1000));expect(result.current.page).toBeNull();expect(result.current.hasNavigation).toBe(false);
    });
    it.each(['en','de'] as const)('moves keyboard focus to Previous after the final forward page (%s)',async locale=>{
        setLocale(locale,false);const user=userEvent.setup();view=overviewView(101,101);vi.mocked(mutateRaw).mockImplementation(async(_path,raw)=>overviewPage(view,processRows(101),volumeRows(101),raw));open();await screen.findByRole('table');const next=screen.getByRole('button',{name:locale==='en'?'Next page':'Nächste Seite'});next.focus();await user.keyboard(locale==='en'?'{Enter}':' ');await screen.findByText('101 / 101');expect(next).not.toBeInTheDocument();expect(screen.getByRole('button',{name:locale==='en'?'Previous page':'Vorherige Seite'})).toHaveFocus();
    });
    it.each(['moved','body','blur','auth','expired','session','device','section'] as const)('does not reclaim terminal focus after %s',async loss=>{
        const mono=vi.spyOn(performance,'now').mockReturnValue(1000),wall=vi.spyOn(Date,'now').mockReturnValue(100000);view=overviewView(101,101);vi.mocked(mutateRaw).mockImplementation(async(_path,raw)=>overviewPage(view,processRows(101),volumeRows(101),raw));const mounted=render(<><button>Outside</button><CompleteOverviewPanel deviceId={overviewDevice} section="processes" sessionKey="first"/></>);await screen.findByRole('table');let done!:(p:unknown)=>void;vi.mocked(mutateRaw).mockReturnValueOnce(new Promise(resolve=>done=resolve));const next=screen.getByRole('button',{name:'Next page'});next.focus();fireEvent.click(next);
        if(loss==='blur'||loss==='auth')act(()=>window.dispatchEvent(new Event(loss==='auth'?AUTH_REQUIRED_EVENT:'blur')));else if(loss==='expired'){mono.mockReturnValue(901000);wall.mockReturnValue(1000000);}else if(loss==='session'||loss==='device'||loss==='section'){vi.mocked(request).mockReturnValue(new Promise(()=>{}));mounted.rerender(<><button>Outside</button><CompleteOverviewPanel deviceId={loss==='device'?'agent_other':overviewDevice} section={loss==='section'?'volumes':'processes'} sessionKey={loss==='session'?'second':'first'}/></>);}
        const outside=screen.getByRole('button',{name:'Outside'});if(loss==='body'){fireEvent.pointerDown(document.body);next.blur();}else outside.focus();await act(async()=>done(overviewPage(view,processRows(101),volumeRows(101),query('processes','cursor_100'))));expect(loss==='body'?document.body:outside).toHaveFocus();if(loss!=='moved'&&loss!=='body')expect(screen.queryByRole('table')).toBeNull();expect(mutateRaw).toHaveBeenCalledTimes(2);
    });
});

it.each(['blur', 'auth', 'expired', 'session', 'device', 'section', 'hidden', 'pagehide'] as const)('does not hand off terminal focus after isolated %s without a focus move', async loss => {
    const mono = vi.spyOn(performance, 'now').mockReturnValue(1000), wall = vi.spyOn(Date, 'now').mockReturnValue(100000);
    view = overviewView(101, 101);
    vi.mocked(mutateRaw).mockImplementation(async (_path, raw) => overviewPage(view, processRows(101), volumeRows(101), raw));
    const mounted = open();
    await screen.findByRole('table');
    let finish!: (page: unknown) => void;
    vi.mocked(mutateRaw).mockReturnValueOnce(new Promise(resolve => { finish = resolve; }));
    const next = screen.getByRole('button', { name: 'Next page' });
    next.focus(); fireEvent.click(next);
    expect(next).toHaveFocus(); expect(next).toBeDisabled();
    // Observe automatic handoffs without moving focus to another element ourselves.
    const focus = vi.spyOn(HTMLElement.prototype, 'focus');
    if (loss === 'hidden') {
        vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden');
        act(() => document.dispatchEvent(new Event('visibilitychange')));
    } else if (loss === 'blur' || loss === 'auth' || loss === 'pagehide') {
        act(() => window.dispatchEvent(new Event(loss === 'auth' ? AUTH_REQUIRED_EVENT : loss)));
    } else if (loss === 'expired') {
        mono.mockReturnValue(901000); wall.mockReturnValue(1000000);
    } else {
        vi.mocked(request).mockReturnValue(new Promise(() => {}));
        mounted.rerender(<CompleteOverviewPanel deviceId={loss === 'device' ? 'agent_other' : overviewDevice} section={loss === 'section' ? 'volumes' : 'processes'} sessionKey={loss === 'session' ? 'second' : 'first'}/>);
    }
    await act(async () => finish(overviewPage(view, processRows(101), volumeRows(101), query('processes', 'cursor_100'))));
    expect(focus).not.toHaveBeenCalled();
    expect(screen.queryByRole('table')).toBeNull();
    const previous = screen.queryByRole('button', { name: 'Previous page' });
    if (loss === 'expired' && previous) { expect(previous).toBeDisabled(); expect(previous).not.toHaveFocus(); }
    else expect(previous).toBeNull();
    expect(mutateRaw).toHaveBeenCalledTimes(2);
});
