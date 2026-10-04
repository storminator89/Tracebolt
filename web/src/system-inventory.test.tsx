import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { APIError, AUTH_REQUIRED_EVENT, mutateRaw, request } from './api';
import { SystemInventoryPanel } from './system-inventory';
import { serviceRows, socketRows, systemDevice, systemPage, systemView } from './system-inventory-fixtures';
import { setLocale } from './i18n';
import type { SystemPage, SystemSection } from './system-inventory-types';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutateRaw: vi.fn() }));
vi.mock('./auth', () => ({ useOperator: () => ({ mode: 'lan', authenticated: true, expiresAt: '2026-10-04T01:00:00Z' }) }));
let view = systemView(), services = serviceRows(), sockets = socketRows();
const panel = (section: SystemSection = 'services', sessionKey = 'first') => <SystemInventoryPanel deviceId={systemDevice} section={section} sessionKey={sessionKey}/>;
async function open(section: SystemSection = 'services') { const result = render(panel(section)); await screen.findByRole('table'); return result; }
beforeEach(() => {
    setLocale('en', false); view = systemView(); services = serviceRows(); sockets = socketRows();
    vi.mocked(request).mockReset().mockImplementation(async () => view);
    vi.mocked(mutateRaw).mockReset().mockImplementation(async (_path, raw) => systemPage(view, services, sockets, raw));
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.useRealTimers(); });

describe('system inventory bounded service/socket browsing', () => {
    it('enumerates every one of 350 services in 100-row pages without a global prefix limit', async () => {
        const rendered = await open(), queries = within(rendered.container), seen: string[] = [];
        for (let i = 0; i < 4; i++) {
            const name = `fixture-${String(i * 100).padStart(6, '0')}.service`;
            // Wait for the exact semantic cell without recomputing accessible names
            // for every row on every poll. Keep role/visibility assertions below.
            const first = await queries.findByText(name, { selector: 'th[scope="row"]' });
            expect(first).toHaveRole('rowheader'); expect(first).toHaveAccessibleName(name); expect(first).toBeVisible();
            const rows = within(queries.getByRole('table')).getAllByRole('rowheader'); expect(rows.length).toBeLessThanOrEqual(100); seen.push(...rows.map(row => row.textContent!));
            if (i < 3) fireEvent.click(queries.getByRole('button', { name: 'Next page' }));
        }
        expect(seen).toEqual(services.map(row => row.name)); expect(queries.getByText('350 / 350')).toBeVisible(); expect(queries.getByText('The entire retained section has been scanned.')).toBeVisible();
        for (const [path, raw, , , maximum] of vi.mocked(mutateRaw).mock.calls) { expect(path).toBe(`/devices/${systemDevice}/inventory/system/query`); expect(JSON.parse(raw)).toMatchObject({ section: 'services', limit: 100, filter: 'all' }); expect(maximum).toBe(262144); }
    });
    it('enumerates sockets in 25-row pages and retains numeric endpoints and attribution', async () => {
        const rendered = await open('sockets'), queries = within(rendered.container), seen: string[] = [], owners: string[] = [];
        for (let i = 0; i < 3; i++) {
            // Scope the entire traversal to its own render so a canceled/timed-out
            // test cannot find or click a subsequent test's pagination controls.
            await queries.findByText(`127.0.0.1:${10000 + i * 25}`, { selector: 'td' });
            const rows = within(queries.getByRole('table')).getAllByRole('row').slice(1); expect(rows.length).toBe(25);
            seen.push(...rows.map(row => row.querySelectorAll('td')[0].textContent!)); owners.push(...rows.map(row => row.querySelectorAll('td')[4].textContent!));
            if (i < 2) fireEvent.click(queries.getByRole('button', { name: 'Next page' }));
        }
        expect(new Set(seen).size).toBe(75); expect(seen).toEqual(sockets.map(row => `${row.local.address}:${row.local.port}`)); expect(owners).toEqual(sockets.map(row => `${row.owners[0].pid} / ${row.owners[0].processName}`));
        expect(queries.getByText('75 / 75')).toBeVisible(); expect(queries.getByText(/does not establish external reachability/)).toBeVisible(); expect(JSON.parse(vi.mocked(mutateRaw).mock.calls[0][1]).limit).toBe(25);
    });
    it.each(['active', 'failed', 'enabled'] as const)('uses the fixed %s service filter and starts from a new cursor', async filter => {
        await open(); fireEvent.change(screen.getByLabelText('Section filter'), { target: { value: filter } }); expect(screen.queryByRole('table')).not.toBeInTheDocument(); fireEvent.click(screen.getByRole('button', { name: 'Apply search and filter' })); await screen.findByRole('table');
        expect(JSON.parse(vi.mocked(mutateRaw).mock.calls.at(-1)![1])).toMatchObject({ cursor: '', filter }); const names = within(screen.getByRole('table')).getAllByRole('rowheader').map(row => row.textContent); const expected = services.filter(row => filter === 'active' ? row.runtime!.activeState === 'active' : filter === 'failed' ? row.runtime!.activeState === 'failed' : row.enablement === 'enabled').slice(0, 100).map(row => row.name); expect(names).toEqual(expected);
    });
    it.each(['tcp-listeners', 'udp', 'connections'] as const)('uses the fixed %s socket filter', async filter => {
        await open('sockets'); fireEvent.change(screen.getByLabelText('Section filter'), { target: { value: filter } }); fireEvent.click(screen.getByRole('button', { name: 'Apply search and filter' })); await screen.findByRole('table'); expect(JSON.parse(vi.mocked(mutateRaw).mock.calls.at(-1)![1])).toMatchObject({ cursor: '', section: 'sockets', filter, limit: 25 });
        expect(within(screen.getByRole('table')).getAllByRole('row').length - 1).toBe(25);
    });
    it('continues an empty 2048-row scan window to the only matching service', async () => {
        view = systemView(2300); services = serviceRows(2300); await open(); fireEvent.change(screen.getByLabelText('Search this complete section'), { target: { value: 'fixture-002299' } }); fireEvent.click(screen.getByRole('button', { name: 'Apply search and filter' }));
        await screen.findByText('No matches in this scan window. More rows remain; continue.'); expect(screen.queryByText('No matches in the complete section.')).not.toBeInTheDocument(); fireEvent.click(screen.getByRole('button', { name: 'Continue search or filter' })); await screen.findByRole('rowheader', { name: 'fixture-002299.service' }); expect(screen.getByText('2,300 / 2,300')).toBeVisible();
    });
    it('shows failed latest and independently stale prior complete without renewing original time', async () => {
        view.serverNow = '2026-10-04T00:05:10Z'; view.receivedAt = '2026-10-04T00:05:05Z'; view.sequence = '9007199254740994'; view.latest!.generationId = `sample_${'b'.repeat(32)}`; view.latest!.collectedAt = '2026-10-04T00:05:00Z';
        for (const section of ['services', 'sockets'] as const) { view.latest![section] = { generationId: view.latest!.generationId, observedAt: view.latest!.collectedAt, coverage: 'failed', reason: 'timeout', observedCount: null, countExact: false }; view.lastComplete[section]!.status = 'stale'; }
        await open(); expect(screen.getByText(/Latest section collection failed/)).toBeVisible(); expect(screen.getByText(/Showing the last complete section/)).toBeVisible(); expect(screen.getByText('2026-10-04T00:00:00Z')).toBeVisible(); expect(screen.getByText('Stale / historical observations')).toBeVisible();
    });
    it('keeps null process names and unavailable attribution distinct from no running process', async () => {
        sockets[0] = { ...sockets[0], owners: [{ pid: 100, processName: null, nameReason: 'process_gone' }], attribution: { coverage: 'partial', reason: 'process_gone' } }; sockets[1] = { ...sockets[1], owners: [], attribution: { coverage: 'unavailable', reason: 'permission_denied' } };
        await open('sockets'); expect(screen.getByText(/100 \/ Process name unknown/)).toBeVisible(); expect(screen.getByText('Owner unknown')).toBeVisible(); expect(screen.getByText('Unavailable · Permission denied')).toBeVisible();
    });
    it('never converts expired or failed metadata into a successful empty section', async () => {
        view = { ...systemView(), status: 'expired', serverNow: '2026-10-05T00:00:00Z', latest: null, lastComplete: { services: null, sockets: null } }; render(panel()); await screen.findByText('No retained complete section is available. Missing or failed data is not a successful zero-row observation.'); expect(mutateRaw).not.toHaveBeenCalled(); expect(screen.queryByText('Successful complete enumeration contained zero rows in this section.')).not.toBeInTheDocument();
    });
    it.each(['unmount', 'section', 'session', 'auth', 'pagehide', 'blur', 'search', 'filter'] as const)('cancels delayed pages and rejects late rows after %s', async transition => {
        const rendered = await open(); let finish!: (value: SystemPage) => void, signal!: AbortSignal;
        vi.mocked(mutateRaw).mockImplementationOnce(async (_path, _raw, _headers, supplied) => { signal = supplied!; return new Promise<SystemPage>(resolve => { finish = resolve; }); }); fireEvent.click(screen.getByRole('button', { name: 'Next page' })); await waitFor(() => expect(signal).toBeDefined());
        if (transition === 'unmount') rendered.unmount(); if (transition === 'section') rendered.rerender(panel('sockets')); if (transition === 'session') rendered.rerender(panel('services', 'replacement'));
        if (transition === 'auth') act(() => window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT))); if (transition === 'pagehide') act(() => window.dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true }))); if (transition === 'blur') act(() => window.dispatchEvent(new Event('blur')));
        if (transition === 'search') fireEvent.change(screen.getByLabelText('Search this complete section'), { target: { value: 'replacement' } }); if (transition === 'filter') fireEvent.change(screen.getByLabelText('Section filter'), { target: { value: 'failed' } });
        expect(signal.aborted).toBe(true); await act(async () => finish(systemPage(view, services, sockets, JSON.stringify({ section: 'services', cursor: 'cursor_100', search: '', filter: 'all', limit: 100 })))); expect(screen.queryByRole('rowheader', { name: 'fixture-000100.service' })).not.toBeInTheDocument();
    });
    it('409 clears previous pages and requires an explicit refreshed generation', async () => {
        await open(); vi.mocked(mutateRaw).mockRejectedValueOnce(new APIError('changed', 409)); fireEvent.click(screen.getByRole('button', { name: 'Next page' })); await screen.findByText(/section generation or paging session changed or expired/); expect(screen.queryByRole('table')).not.toBeInTheDocument(); expect(request).toHaveBeenCalledTimes(1); fireEvent.click(screen.getByRole('button', { name: 'Refresh section and restart' })); await screen.findByRole('table'); expect(JSON.parse(vi.mocked(mutateRaw).mock.calls.at(-1)![1]).cursor).toBe('');
    });
    it('429 retries only on request, and 401 locks future focus refresh', async () => {
        await open(); vi.mocked(mutateRaw).mockRejectedValueOnce(new APIError('busy', 429)); fireEvent.click(screen.getByRole('button', { name: 'Next page' })); await screen.findByText('The manager is busy. Retry in a moment.'); expect(mutateRaw).toHaveBeenCalledTimes(2); fireEvent.click(screen.getByRole('button', { name: 'Retry request' })); await screen.findByRole('rowheader', { name: 'fixture-000100.service' });
        vi.mocked(mutateRaw).mockRejectedValueOnce(new APIError('session', 401)); fireEvent.click(screen.getByRole('button', { name: 'Next page' })); await screen.findByText('Your session has ended. Sign in again.'); act(() => window.dispatchEvent(new Event('focus'))); expect(mutateRaw).toHaveBeenCalledTimes(4); expect(screen.queryByRole('table')).not.toBeInTheDocument(); expect(screen.getByRole('button', { name: 'Refresh section and restart' })).toBeDisabled();
    });
    it('restores BFCache with a new first page instead of reusing a cursor', async () => {
        await open(); fireEvent.click(screen.getByRole('button', { name: 'Next page' })); await screen.findByRole('rowheader', { name: 'fixture-000100.service' }); act(() => window.dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true }))); expect(screen.queryByRole('table')).not.toBeInTheDocument(); act(() => window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true }))); await screen.findByRole('rowheader', { name: 'fixture-000000.service' }); expect(JSON.parse(vi.mocked(mutateRaw).mock.calls.at(-1)![1]).cursor).toBe('');
    });
    it('invalidates a wall/monotonic clock jump and an authoritative server-time regression', async () => {
        vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] }); const mono = vi.spyOn(performance, 'now').mockReturnValue(1000), wall = vi.spyOn(Date, 'now').mockReturnValue(100000); await open(); wall.mockReturnValue(200000); act(() => vi.advanceTimersByTime(1000)); expect(screen.queryByRole('table')).not.toBeInTheDocument(); expect(screen.getByRole('alert')).toHaveTextContent('time anchor');
        mono.mockReturnValue(2000); wall.mockReturnValue(101000); view.serverNow = '2026-10-04T00:00:09Z'; fireEvent.click(screen.getByRole('button', { name: 'Refresh section and restart' })); await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('time anchor')); expect(screen.queryByRole('table')).not.toBeInTheDocument();
    });
    it('renders German source/attribution limits without invented health counts', async () => {
        setLocale('de', false); render(panel('sockets')); await screen.findByRole('table'); expect(screen.getByText(/keine Erreichbarkeit von außen/)).toBeVisible(); expect(screen.getByRole('columnheader', { name: 'PID / Prozessname' })).toBeVisible(); expect(document.body.textContent).not.toMatch(/0 CVEs|0 Updates/);
    });
});
