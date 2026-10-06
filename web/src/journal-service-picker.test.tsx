import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { APIError, AUTH_REQUIRED_EVENT, mutateRaw, request } from './api';
import { JournalServicePicker } from './journal-service-picker';
import { JournalContent } from './journal';
import { journalView } from './journal-fixtures';
import type { JournalResource } from './journal-resource';
import { serviceRows, systemDevice, systemGeneration, systemPage, systemView } from './system-inventory-fixtures';
import { setLocale } from './i18n';
import type { SystemPage } from './system-inventory-types';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutateRaw: vi.fn() }));
const auth = vi.hoisted(() => ({ mode: 'lan', authenticated: true, expiresAt: '2026-10-04T01:00:00Z' }));
vi.mock('./auth', () => ({ useOperator: () => auth }));
let view = systemView(), services = serviceRows();
const select = vi.fn(), close = vi.fn();
const picker = (deviceId = systemDevice, sessionKey: string | null = 'first') => <JournalServicePicker deviceId={deviceId} sessionKey={sessionKey} onSelect={select} onClose={close}/>;
async function open() { const rendered = render(picker()); await screen.findByText(services[0].name); return rendered; }
const queryFor = (cursor: string, search = '') => JSON.stringify({ section: 'services', generationId: systemGeneration, cursor, search, filter: 'all', limit: 100 });
beforeEach(() => {
    setLocale('en', false); view = systemView(); services = serviceRows(); auth.mode = 'lan'; auth.authenticated = true;
    select.mockReset(); close.mockReset();
    vi.mocked(request).mockReset().mockImplementation(async () => view);
    vi.mocked(mutateRaw).mockReset().mockImplementation(async (_path, raw) => systemPage(view, services, [], raw));
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.useRealTimers(); });

describe('observed-service picker uses only bounded protected inventory reads', () => {
    it('integrates lazily with the capture form and preserves acknowledgement and manual-entry boundaries', async () => {
        const resource: JournalResource = {
            view: { ...journalView('awaiting'), deviceId: systemDevice }, page: null, busy: false, paused: false, failure: null, uncertain: false, reset: 0,
            refresh: vi.fn(), create: vi.fn(async () => undefined), cancelRequest: vi.fn(), search: vi.fn(), next: vi.fn(), previous: vi.fn(), canPrevious: false,
        };
        render(<JournalContent resource={resource} insecureTestMode sessionKey="picker-integration"/>);
        expect(request).not.toHaveBeenCalled(); expect(mutateRaw).not.toHaveBeenCalled();
        openAdvanced(); fireEvent.change(screen.getByLabelText('Exact service unit'), { target: { value: 'manual.service' } });
        fireEvent.click(screen.getByRole('button', { name: 'Choose observed service' })); await within(screen.getByRole('region', { name: 'Observed services' })).findByText(services[0].name); expect(screen.getByRole('dialog')).toBeVisible();
        expect(screen.getByLabelText('Exact service unit')).toHaveValue('manual.service');
        fireEvent.click(screen.getByRole('button', { name: `Use ${services[0].name}` }));
        expect(screen.queryByRole('region', { name: 'Observed services' })).not.toBeInTheDocument();
        expect(screen.getByLabelText('Exact service unit')).toHaveValue(services[0].name); expect(screen.getByRole('button', { name: 'Choose observed service' })).toHaveFocus();
        expect(screen.queryByRole('checkbox')).not.toBeInTheDocument(); fireEvent.click(screen.getByRole('button', { name: 'Fetch logs' }));
        for (const checkbox of screen.getAllByRole('checkbox')) expect(checkbox).not.toBeChecked();
        expect(screen.getByRole('button', { name: 'Capture logs' })).toBeDisabled(); expect(resource.create).not.toHaveBeenCalled(); expect(resource.cancelRequest).not.toHaveBeenCalled(); fireEvent.click(screen.getByRole('button', { name: 'Back' }));
        fireEvent.click(screen.getByRole('button', { name: 'Choose observed service' })); await within(screen.getByRole('region', { name: 'Observed services' })).findByText(services[0].name);
        expect(request).toHaveBeenCalledTimes(2); fireEvent.keyDown(document.activeElement!, { key: 'Escape' });
        expect(screen.queryByRole('region', { name: 'Observed services' })).not.toBeInTheDocument(); expect(screen.getByRole('button', { name: 'Choose observed service' })).toHaveFocus();
        expect(screen.getByLabelText('Exact service unit')).toHaveValue(services[0].name); expect(resource.create).not.toHaveBeenCalled();
    });

    it('traverses all services in pinned 100-row pages and selection only reports the exact unit', async () => {
        const rendered = await open(), ui = within(rendered.container), seen: string[] = [];
        for (let page = 0; page < 4; page++) {
            await ui.findByText(`fixture-${String(page * 100).padStart(6, '0')}.service`);
            const rows = ui.getAllByRole('listitem'); expect(rows.length).toBeLessThanOrEqual(100);
            seen.push(...rows.map(row => row.querySelector('.journal-picker-unit')!.textContent!));
            if (page < 3) fireEvent.click(ui.getByRole('button', { name: 'Next service page' }));
        }
        expect(seen).toEqual(services.map(row => row.name));
        expect(ui.queryByText('fixture-000000.service')).not.toBeInTheDocument();
        expect(ui.getByText('50 shown · 350 / 350 scanned · 350 matches so far')).toBeVisible();
        const before = vi.mocked(mutateRaw).mock.calls.length;
        fireEvent.click(ui.getByRole('button', { name: 'Use fixture-000349.service' }));
        expect(select).toHaveBeenCalledExactlyOnceWith('fixture-000349.service'); expect(close).not.toHaveBeenCalled();
        expect(mutateRaw).toHaveBeenCalledTimes(before);
        expect(request).toHaveBeenCalledWith(`/devices/${systemDevice}/inventory/system`, expect.objectContaining({ signal: expect.any(AbortSignal) }), 16384);
        for (const [path, raw, headers, signal, maximum] of vi.mocked(mutateRaw).mock.calls) {
            expect(path).toBe(`/devices/${systemDevice}/inventory/system/query`); expect(headers).toEqual({}); expect(signal).toBeInstanceOf(AbortSignal); expect(maximum).toBe(262144);
            expect(JSON.parse(raw)).toMatchObject({ section: 'services', generationId: systemGeneration, limit: 100, filter: 'all' });
        }
        fireEvent.click(ui.getByText('Selection & permission', { selector: 'summary' }));
        expect(ui.getByText(/does not confirm local journal allowlist membership or grant access/)).toBeVisible();
        expect(ui.getByText(/enter an exact service unit manually/)).toBeVisible();
    });

    it('continues an empty bounded search window and keeps whole-inventory and match counts distinct', async () => {
        view = systemView(2300); services = serviceRows(2300); await open();
        fireEvent.change(screen.getByLabelText('Search observed services'), { target: { value: 'fixture-002299' } });
        expect(screen.queryByRole('list')).not.toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', { name: 'Search services' }));
        await screen.findByText('No matches in this scan window. More rows remain; continue searching.');
        expect(screen.queryByText('No matches in the complete service inventory.')).not.toBeInTheDocument();
        fireEvent.click(screen.getByText('Inventory details', { selector: 'summary' }));
        expect(screen.getByText('Whole retained service inventory').nextElementSibling).toHaveTextContent('2,300');
        expect(screen.getByText('0 shown · 2,048 / 2,300 scanned · 0 matches so far')).toBeVisible();
        expect(JSON.parse(vi.mocked(mutateRaw).mock.calls.at(-1)![1])).toMatchObject({ cursor: '', search: 'fixture-002299', generationId: systemGeneration });
        fireEvent.click(screen.getByRole('button', { name: 'Continue search' }));
        await screen.findByText('fixture-002299.service');
        expect(screen.getByText('1 shown · 2,300 / 2,300 scanned · 1 matches so far')).toBeVisible();
        expect(screen.queryByRole('button', { name: 'Continue search' })).not.toBeInTheDocument();
    });

    it('disables observed names that the exact journal-unit contract rejects without rewriting them', async () => {
        const names = ['-leading.service', 'colon:name.service', 'double..dot.service', 'escaped\\x2dname.service', 'instance@one.service', 'many@at@name.service', 'template@.service'];
        services = names.map(name => ({ ...serviceRows(1)[0], name })); view = systemView(names.length); await open();
        for (const name of names) {
            const button = screen.getByRole('button', { name: `Use ${name}` });
            if (name === 'instance@one.service') { expect(button).toBeEnabled(); fireEvent.click(button); }
            else { expect(button).toBeDisabled(); expect(button).toHaveAccessibleDescription('This observed name is not supported by the exact service-unit syntax for log capture.'); fireEvent.click(button); }
        }
        expect(select).toHaveBeenCalledExactlyOnceWith('instance@one.service');
    });

    it('never nests a form or submits the capture form and Escape only closes the picker', async () => {
        const submit = vi.fn((event: React.FormEvent) => event.preventDefault()), parentKeys = vi.fn(), documentKeys = vi.fn();
        document.addEventListener('keydown', documentKeys);
        try {
            const rendered = render(<form onSubmit={submit} onKeyDown={parentKeys}>{picker()}<button type="submit">Capture logs</button></form>);
            await screen.findByText(services[0].name);
            expect(rendered.container.querySelectorAll('form')).toHaveLength(1);
            expect(screen.getByRole('button', { name: 'Close service picker' })).toHaveFocus();
            const region = screen.getByRole('region', { name: 'Observed services' });
            for (const button of within(region).getAllByRole('button')) expect(button).toHaveAttribute('type', 'button');
            fireEvent.change(screen.getByLabelText('Search observed services'), { target: { value: 'fixture-000010' } });
            const enter = new KeyboardEvent('keydown', { key: 'Enter', bubbles: true, cancelable: true });
            fireEvent(screen.getByLabelText('Search observed services'), enter);
            await screen.findByText('fixture-000010.service');
            expect(enter.defaultPrevented).toBe(true); expect(submit).not.toHaveBeenCalled(); expect(parentKeys).not.toHaveBeenCalled();
            expect(JSON.parse(vi.mocked(mutateRaw).mock.calls.at(-1)![1]).search).toBe('fixture-000010');
            fireEvent.keyDown(screen.getByLabelText('Search observed services'), { key: 'Escape' });
            expect(close).toHaveBeenCalledTimes(1); expect(parentKeys).not.toHaveBeenCalled(); expect(documentKeys).not.toHaveBeenCalled(); expect(submit).not.toHaveBeenCalled();
            fireEvent.click(screen.getByRole('button', { name: 'Close service picker' })); expect(close).toHaveBeenCalledTimes(2); expect(submit).not.toHaveBeenCalled();
        } finally { document.removeEventListener('keydown', documentKeys); }
    });

    it.each(['😀'.repeat(33), 'forbidden\u200b'])('prevents an invalid UTF-8 or formatting-character search from reaching the API', async value => {
        await open(); fireEvent.change(screen.getByLabelText('Search observed services'), { target: { value } });
        expect(screen.getByRole('button', { name: 'Search services' })).toBeDisabled(); expect(screen.getByLabelText('Search observed services')).toHaveAttribute('aria-invalid', 'true');
        expect(screen.getByRole('alert')).toHaveTextContent('128 UTF-8 bytes');
        fireEvent.keyDown(screen.getByLabelText('Search observed services'), { key: 'Enter' }); expect(mutateRaw).toHaveBeenCalledTimes(1);
    });

    it('preserves the stale original observation when a newer inventory attempt failed', async () => {
        view.serverNow = '2026-10-04T00:05:10Z'; view.receivedAt = '2026-10-04T00:05:05Z'; view.sequence = '9007199254740994';
        view.latest!.generationId = `sample_${'b'.repeat(32)}`; view.latest!.collectedAt = '2026-10-04T00:05:00Z';
        for (const section of ['services', 'sockets'] as const) {
            view.latest![section] = { generationId: view.latest!.generationId, observedAt: view.latest!.collectedAt, coverage: 'failed', reason: 'timeout', observedCount: null, countExact: false };
            view.lastComplete[section]!.status = 'stale';
        }
        await open(); expect(screen.getByText('Stale / historical service observations')).toBeVisible();
        expect(screen.getByText(/newer failed attempt does not refresh its original observation time/)).toBeVisible();
        expect(screen.getByText('Original observation time').nextElementSibling).toHaveTextContent('2026-10-04T00:00:00Z');
        expect(JSON.parse(vi.mocked(mutateRaw).mock.calls[0][1]).generationId).toBe(systemGeneration);
    });

    it.each(['awaiting', 'revoked', 'expired'] as const)('does not turn %s inventory into a successful empty list', async status => {
        view = { ...systemView(), status, latest: null, lastComplete: { services: null, sockets: null } };
        render(picker()); await screen.findByText(/No retained complete service inventory is available/);
        expect(mutateRaw).not.toHaveBeenCalled(); expect(screen.queryByRole('list')).not.toBeInTheDocument(); expect(screen.queryByText('The complete service inventory contained zero services.')).not.toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Close service picker' })).toBeEnabled();
    });

    it('distinguishes a successful zero-row inventory from an exhausted search with no matches', async () => {
        view = systemView(0); services = []; const rendered = render(picker()); await screen.findByText('The complete service inventory contained zero services.');
        view = systemView(1); services = serviceRows(1); rendered.rerender(picker(systemDevice, 'replacement')); await screen.findByText(services[0].name);
        fireEvent.change(screen.getByLabelText('Search observed services'), { target: { value: 'missing' } }); fireEvent.click(screen.getByRole('button', { name: 'Search services' }));
        await screen.findByText('No matches in the complete service inventory.'); expect(screen.queryByText('The complete service inventory contained zero services.')).not.toBeInTheDocument();
    });

    it.each(['unmount', 'device', 'session', 'auth', 'gate', 'pagehide', 'blur', 'hashchange', 'search'] as const)('aborts a pending read and ignores late rows after %s', async transition => {
        const rendered = await open(); let finish!: (value: SystemPage) => void, signal!: AbortSignal;
        const oldPage = systemPage(view, services, [], queryFor('cursor_100'));
        vi.mocked(mutateRaw).mockImplementationOnce(async (_path, _raw, _headers, supplied) => { signal = supplied!; return new Promise<SystemPage>(resolve => { finish = resolve; }); });
        fireEvent.click(screen.getByRole('button', { name: 'Next service page' })); await waitFor(() => expect(signal).toBeDefined());
        if (transition === 'unmount') rendered.unmount();
        if (transition === 'device') { view = { ...view, deviceId: 'agent_replacement' }; rendered.rerender(picker(view.deviceId)); }
        if (transition === 'session') rendered.rerender(picker(systemDevice, 'replacement'));
        if (transition === 'gate') { auth.authenticated = false; rendered.rerender(picker()); }
        if (transition === 'auth') act(() => window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT)));
        if (transition === 'pagehide') act(() => window.dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true })));
        if (transition === 'blur' || transition === 'hashchange') act(() => window.dispatchEvent(new Event(transition)));
        if (transition === 'search') fireEvent.change(screen.getByLabelText('Search observed services'), { target: { value: 'replacement' } });
        expect(signal.aborted).toBe(true); await act(async () => finish(oldPage));
        expect(screen.queryByText('fixture-000100.service')).not.toBeInTheDocument(); expect(select).not.toHaveBeenCalled();
    });

    it('requires an explicit generation restart after a 409 and never retries automatically', async () => {
        await open(); vi.mocked(mutateRaw).mockRejectedValueOnce(new APIError('changed', 409)); fireEvent.click(screen.getByRole('button', { name: 'Next service page' }));
        await screen.findByText(/service generation or paging session changed or expired/); expect(screen.queryByRole('list')).not.toBeInTheDocument(); expect(request).toHaveBeenCalledTimes(1);
        fireEvent.click(screen.getByRole('button', { name: 'Refresh service list' })); await screen.findByText(services[0].name);
        expect(request).toHaveBeenCalledTimes(2); expect(JSON.parse(vi.mocked(mutateRaw).mock.calls.at(-1)![1]).cursor).toBe('');
    });

    it('inherits session locking so focus cannot resurrect inventory after a 401', async () => {
        await open(); vi.mocked(mutateRaw).mockRejectedValueOnce(new APIError('session', 401)); fireEvent.click(screen.getByRole('button', { name: 'Next service page' }));
        await screen.findByText('Your session has ended. Sign in again.'); expect(screen.queryByRole('list')).not.toBeInTheDocument();
        act(() => window.dispatchEvent(new Event('focus'))); expect(mutateRaw).toHaveBeenCalledTimes(2); expect(screen.getByRole('button', { name: 'Refresh service list' })).toBeDisabled();
    });

    it('clears hidden inventory and restores a fresh first-page read instead of reusing rows or a cursor', async () => {
        await open(); fireEvent.click(screen.getByRole('button', { name: 'Next service page' })); await screen.findByText('fixture-000100.service');
        const visibility = vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden');
        act(() => document.dispatchEvent(new Event('visibilitychange'))); expect(screen.queryByRole('list')).not.toBeInTheDocument();
        const count = vi.mocked(request).mock.calls.length; fireEvent.click(screen.getByRole('button', { name: 'Refresh service list' })); expect(request).toHaveBeenCalledTimes(count);
        visibility.mockReturnValue('visible'); act(() => document.dispatchEvent(new Event('visibilitychange'))); await screen.findByText('fixture-000000.service');
        expect(request).toHaveBeenCalledTimes(count + 1); expect(JSON.parse(vi.mocked(mutateRaw).mock.calls.at(-1)![1]).cursor).toBe('');
    });

    it('inherits the ten-second request deadline and discards a late response', async () => {
        await open(); let finish!: (value: SystemPage) => void, signal!: AbortSignal;
        const oldPage = systemPage(view, services, [], queryFor('cursor_100'));
        vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
        vi.mocked(mutateRaw).mockImplementationOnce(async (_path, _raw, _headers, supplied) => { signal = supplied!; return new Promise<SystemPage>(resolve => { finish = resolve; }); });
        fireEvent.click(screen.getByRole('button', { name: 'Next service page' })); expect(signal).toBeDefined();
        act(() => vi.advanceTimersByTime(10000)); expect(signal.aborted).toBe(true);
        expect(screen.getByRole('alert')).toHaveTextContent('service read timed out');
        await act(async () => finish(oldPage)); expect(screen.queryByRole('list')).not.toBeInTheDocument();
        expect(mutateRaw).toHaveBeenCalledTimes(2); expect(select).not.toHaveBeenCalled();
    });

    it('clears selectable rows at the original cursor deadline and after a clock discontinuity', async () => {
        vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] });
        const mono = vi.spyOn(performance, 'now').mockReturnValue(1000), wall = vi.spyOn(Date, 'now').mockReturnValue(100000);
        await open(); mono.mockReturnValue(901000); wall.mockReturnValue(1000000); act(() => vi.advanceTimersByTime(1000));
        expect(screen.queryByRole('list')).not.toBeInTheDocument(); expect(screen.getByRole('alert')).toHaveTextContent('paging session changed or expired');
        fireEvent.click(screen.getByRole('button', { name: 'Refresh service list' })); await screen.findByText(services[0].name);
        wall.mockReturnValue(1100000); act(() => vi.advanceTimersByTime(1000));
        expect(screen.queryByRole('list')).not.toBeInTheDocument(); expect(screen.getByRole('alert')).toHaveTextContent('time anchor');
    });

    it.each(['anonymous', 'development'] as const)('does not mount protected inventory reads for %s access', async access => {
        if (access === 'anonymous') auth.authenticated = false; else auth.mode = 'development';
        render(picker()); expect(screen.getByText('Authenticated LAN operator access is required.')).toBeVisible(); expect(request).not.toHaveBeenCalled(); expect(mutateRaw).not.toHaveBeenCalled();
    });

    it('provides German picker labels and permission limitations', async () => {
        setLocale('de', false); await open(); expect(screen.getByRole('region', { name: 'Beobachtete Dienste' })).toBeVisible();
        expect(screen.getByRole('button', { name: 'Dienstliste aktualisieren' })).toBeEnabled();
        expect(screen.getByLabelText('Beobachtete Dienste durchsuchen')).toBeVisible(); fireEvent.click(screen.getByText('Auswahl & Freigabe', { selector: 'summary' })); expect(screen.getByText(/bestätigt weder die lokale Journal-Freigabeliste/)).toBeVisible();
        fireEvent.click(screen.getByRole('button', { name: 'Übernehmen fixture-000000.service' })); expect(select).toHaveBeenCalledExactlyOnceWith('fixture-000000.service');
    });
});

function openAdvanced() {
    const summary = screen.getByText(/^(Advanced|Erweitert)$/, { selector: 'summary' });
    if (!summary.closest('details')!.open) fireEvent.click(summary);
}
