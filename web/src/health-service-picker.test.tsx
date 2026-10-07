import { Profiler, useState } from 'react';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { APIError, AUTH_REQUIRED_EVENT, mutate, mutateRaw, request } from './api';
import { HealthServicePicker } from './health-service-picker';
import { HealthPanel } from './health';
import { setLocale } from './i18n';
import { serviceRows, systemDevice, systemGeneration, systemPage, systemView } from './system-inventory-fixtures';
import type { HealthView } from './health-types';
import type { SystemPage } from './system-inventory-types';
import healthFixture from './health-go-fixture.json';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutateRaw: vi.fn(), mutate: vi.fn() }));
const auth = vi.hoisted(() => ({ mode: 'lan', authenticated: true, expiresAt: '2026-10-04T01:00:00Z' }));
vi.mock('./auth', () => ({ useOperator: () => auth, hasLogoutIntent: () => false }));
let view = systemView(), rows = serviceRows();
const change = vi.fn(), submit = vi.fn();
function Harness({ deviceId = systemDevice, sessionKey = 'first', initial = [], disabled = false }: { deviceId?: string; sessionKey?: string; initial?: string[]; disabled?: boolean }) {
    const [selected, setSelected] = useState(initial);
    return <form onSubmit={event => { event.preventDefault(); submit(); }}>
        <HealthServicePicker deviceId={deviceId} sessionKey={sessionKey} selected={selected} disabled={disabled} onChange={services => { change(services); setSelected(services); }}/>
        <button type="submit">Save test selection</button>
    </form>;
}
const open = async (initial: string[] = []) => { const rendered = render(<Harness initial={initial}/>); await screen.findByRole('checkbox', { name: rows[0].name }); return rendered; };
const unavailable = (status: 'awaiting' | 'unknown' | 'not_configured' | 'expired' | 'revoked' = 'awaiting') => { view = { ...systemView(), status, latest: null, lastComplete: { services: null, sockets: null } }; };
beforeEach(() => {
    setLocale('en', false); view = systemView(); rows = serviceRows(); auth.mode = 'lan'; auth.authenticated = true;
    change.mockReset(); submit.mockReset(); vi.mocked(mutate).mockReset();
    vi.mocked(request).mockReset().mockImplementation(async () => view);
    vi.mocked(mutateRaw).mockReset().mockImplementation(async (_path, raw) => systemPage(view, rows, [], raw));
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.useRealTimers(); });

describe('health service selection', () => {
    it('selects, caps at eight and removes chips without saving or requesting content', async () => {
        view = systemView(9); rows = serviceRows(9);
        await open(); expect(screen.queryByRole('textbox')).not.toBeInTheDocument();
        for (const row of rows.slice(0, 8)) fireEvent.click(screen.getByRole('checkbox', { name: row.name }));
        expect(screen.getByText(/8 of 8 services selected/)).toBeVisible();
        const ninth = screen.getByRole('checkbox', { name: rows[8].name }); expect(ninth).toBeDisabled(); fireEvent.click(ninth);
        expect(change).toHaveBeenCalledTimes(8); expect(change).toHaveBeenLastCalledWith(rows.slice(0, 8).map(row => row.name));
        fireEvent.click(screen.getByRole('button', { name: `Remove service: ${rows[0].name}` }));
        expect(ninth).toBeEnabled(); expect(screen.getByRole('checkbox', { name: rows[0].name })).not.toBeChecked(); fireEvent.click(ninth);
        fireEvent.click(screen.getByRole('checkbox', { name: rows[1].name }));
        expect(screen.getByRole('list', { name: 'Selected services' })).not.toHaveTextContent(rows[1].name);
        expect(mutate).not.toHaveBeenCalled(); expect(submit).not.toHaveBeenCalled(); expect(mutateRaw).toHaveBeenCalledTimes(1);
        expect(request).toHaveBeenCalledWith(`/devices/${systemDevice}/inventory/system`, expect.objectContaining({ signal: expect.any(AbortSignal) }), 16384);
        const [path, raw, headers, signal, limit] = vi.mocked(mutateRaw).mock.calls[0];
        expect(path).toBe(`/devices/${systemDevice}/inventory/system/query`); expect(JSON.parse(raw)).toMatchObject({ section: 'services', generationId: systemGeneration, cursor: '', search: '', limit: 100, filter: 'all' }); expect(headers).toEqual({}); expect(signal).toBeInstanceOf(AbortSignal); expect(limit).toBe(262144);
        expect(screen.getByText(/No additional collection or logs/)).toBeVisible();
    });

    it('uses native keyboard checkboxes and keeps Enter search separate from Save', async () => {
        const user = userEvent.setup(), rendered = await open();
        const checkbox = screen.getByRole('checkbox', { name: rows[0].name }); checkbox.focus(); await user.keyboard(' '); expect(checkbox).toBeChecked();
        await user.keyboard(' '); expect(checkbox).not.toBeChecked();
        const search = screen.getByRole('searchbox'); fireEvent.change(search, { target: { value: '000349' } });
        const event = new KeyboardEvent('keydown', { key: 'Enter', bubbles: true, cancelable: true }); fireEvent(search, event);
        expect(event.defaultPrevented).toBe(true); await screen.findByRole('checkbox', { name: rows[349].name });
        expect(submit).not.toHaveBeenCalled(); expect(mutate).not.toHaveBeenCalled(); expect(rendered.container.querySelectorAll('form')).toHaveLength(1);
        for (const button of screen.getAllByRole('button').filter(button => button.textContent !== 'Save test selection')) expect(button).toHaveAttribute('type', 'button');
        fireEvent.change(search, { target: { value: 'composing' } }); fireEvent.keyDown(search, { key: 'Enter', isComposing: true }); expect(mutateRaw).toHaveBeenCalledTimes(2);
    });

    it('preserves selected names across pages and search even when no longer in the current page', async () => {
        await open(['missing-from-inventory.service']); fireEvent.click(screen.getByRole('checkbox', { name: rows[0].name }));
        fireEvent.click(screen.getByRole('button', { name: 'Next service page' })); await screen.findByRole('checkbox', { name: rows[100].name });
        const selected = screen.getByRole('list', { name: 'Selected services' }); expect(selected).toHaveTextContent(rows[0].name); expect(selected).toHaveTextContent('missing-from-inventory.service');
        fireEvent.change(screen.getByRole('searchbox'), { target: { value: '000000' } }); fireEvent.click(screen.getByRole('button', { name: 'Search services' }));
        expect(await screen.findByRole('checkbox', { name: rows[0].name })).toBeChecked(); expect(selected).toHaveTextContent('missing-from-inventory.service');
        expect(screen.queryByRole('textbox')).not.toBeInTheDocument();
    });

    it('does not mislabel an empty scan window or an exhausted search as zero inventory', async () => {
        view = systemView(2300); rows = serviceRows(2300); await open();
        fireEvent.change(screen.getByRole('searchbox'), { target: { value: '002299' } }); fireEvent.click(screen.getByRole('button', { name: 'Search services' }));
        await screen.findByText('No matches in this scan window. More rows remain.'); expect(screen.getByText('Scanned: 2,048 / 2,300 · Matches so far: 0')).toBeVisible();
        expect(screen.queryByRole('textbox')).not.toBeInTheDocument(); fireEvent.click(screen.getByRole('button', { name: 'Continue service search' }));
        await screen.findByRole('checkbox', { name: rows[2299].name }); expect(screen.getByText('Scanned: 2,300 / 2,300 · Matches so far: 1')).toBeVisible();
        fireEvent.change(screen.getByRole('searchbox'), { target: { value: 'absent' } }); fireEvent.click(screen.getByRole('button', { name: 'Search services' }));
        await screen.findByText('No matches in this scan window. More rows remain.'); fireEvent.click(screen.getByRole('button', { name: 'Continue service search' }));
        await screen.findByText('No matches in the complete service inventory.'); expect(screen.queryByText('The complete service inventory contained zero services.')).not.toBeInTheDocument();
    });

    it('shows a confirmed empty inventory without offering manual fallback', async () => {
        view = systemView(0); rows = []; render(<Harness/>); await screen.findByText('The complete service inventory contained zero services.'); expect(screen.queryByRole('textbox')).not.toBeInTheDocument(); expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();
    });

    it.each(['awaiting', 'unknown', 'not_configured', 'expired', 'revoked'] as const)('offers an unknown manual fallback only when %s inventory is unavailable', async status => {
        rows = serviceRows(2);
        unavailable(status); render(<Harness/>); const manual = await screen.findByRole('textbox', { name: 'Add service manually' });
        expect(screen.getByText(/Service inventory unavailable; service count unknown/)).toBeVisible(); expect(screen.queryByText('The complete service inventory contained zero services.')).not.toBeInTheDocument(); expect(mutateRaw).not.toHaveBeenCalled();
        fireEvent.change(manual, { target: { value: '*.service' } }); expect(screen.getByRole('button', { name: 'Add service' })).toBeDisabled(); expect(manual).toHaveAttribute('aria-invalid', 'true');
        fireEvent.change(manual, { target: { value: 'manual.service' } }); fireEvent.keyDown(manual, { key: 'Enter' });
        expect(change).toHaveBeenCalledExactlyOnceWith(['manual.service']); expect(submit).not.toHaveBeenCalled(); expect(mutate).not.toHaveBeenCalled();
        fireEvent.change(manual, { target: { value: 'manual.service' } }); expect(screen.getByRole('button', { name: 'Add service' })).toBeDisabled();
        view = systemView(rows.length); fireEvent.click(screen.getByRole('button', { name: 'Refresh service list' })); await screen.findByRole('checkbox', { name: rows[0].name });
        expect(screen.queryByRole('textbox')).not.toBeInTheDocument(); expect(screen.getByRole('list', { name: 'Selected services' })).toHaveTextContent('manual.service');
    });

    it.each([
        ['en', 'Service inventory unavailable; service count unknown. Manual selections stay unknown until observed.'],
        ['de', 'Dienstinventar nicht verfügbar; Dienstanzahl unbekannt. Manuelle Auswahl bleibt bis zur Beobachtung unbekannt.'],
    ] as const)('keeps an unavailable service count explicitly unknown in %s', async (locale, note) => {
        setLocale(locale, false); unavailable(); render(<Harness/>);
        expect(await screen.findByText(note)).toBeVisible();
        expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();
        expect(screen.queryByText(/complete service inventory contained zero services|vollständige Dienstinventar enthielt keine Dienste/)).not.toBeInTheDocument();
        expect(change).not.toHaveBeenCalled(); expect(submit).not.toHaveBeenCalled(); expect(mutate).not.toHaveBeenCalled(); expect(mutateRaw).not.toHaveBeenCalled();
    });

    it('keeps manual addition bounded and clearing selection explicit', async () => {
        unavailable(); render(<Harness initial={rows.slice(0, 8).map(row => row.name)}/>);
        expect(await screen.findByRole('textbox')).toBeDisabled(); fireEvent.click(screen.getByRole('button', { name: `Remove service: ${rows[0].name}` })); expect(screen.getByRole('textbox')).toBeEnabled();
        for (const row of rows.slice(1, 8)) fireEvent.click(screen.getByRole('button', { name: `Remove service: ${row.name}` }));
        expect(screen.getByText('No selection. Saving stops existing service checks.')).toBeVisible(); expect(change).toHaveBeenLastCalledWith([]); expect(submit).not.toHaveBeenCalled();
    });

    it('accepts the full backend service-name length in the manual fallback', async () => {
        unavailable(); render(<Harness/>); const manual = await screen.findByRole('textbox');
        const unit = `${'a'.repeat(119)}.service`; expect(unit).toHaveLength(127); expect(manual).toHaveAttribute('maxlength', '127');
        fireEvent.change(manual, { target: { value: unit } }); fireEvent.click(screen.getByRole('button', { name: 'Add service' })); expect(change).toHaveBeenCalledExactlyOnceWith([unit]);
    });

    it('leaves unsupported observed names intact but unselectable', async () => {
        rows = ['-leading.service', 'escaped\\x2dname.service', 'instance@one.service'].map(name => ({ ...serviceRows(1)[0], name })); view = systemView(rows.length); await open();
        for (const row of rows.slice(0, 2)) { const box = screen.getByRole('checkbox', { name: row.name }); expect(box).toBeDisabled(); expect(box).toHaveAccessibleDescription('This observed name is not supported by health checks.'); }
        fireEvent.click(screen.getByRole('checkbox', { name: rows[2].name })); expect(change).toHaveBeenCalledExactlyOnceWith([rows[2].name]);
    });

    it.each(['😀'.repeat(33), 'forbidden\u200b'])('rejects invalid search without submitting the parent form', async query => {
        view = systemView(2); rows = serviceRows(2);
        await open(); fireEvent.change(screen.getByRole('searchbox'), { target: { value: query } }); fireEvent.keyDown(screen.getByRole('searchbox'), { key: 'Enter' });
        expect(screen.getByRole('button', { name: 'Search services' })).toBeDisabled(); expect(screen.getByRole('alert')).toHaveTextContent('128 UTF-8 bytes'); expect(mutateRaw).toHaveBeenCalledTimes(1); expect(submit).not.toHaveBeenCalled();
    });

    it('labels stale observations and retains their original time after a newer failed attempt', async () => {
        view = systemView(2); rows = serviceRows(2);
        view.serverNow = '2026-10-04T00:05:10Z'; view.receivedAt = '2026-10-04T00:05:05Z'; view.sequence = '9007199254740994';
        view.latest!.generationId = `sample_${'b'.repeat(32)}`; view.latest!.collectedAt = '2026-10-04T00:05:00Z';
        for (const section of ['services', 'sockets'] as const) {
            view.latest![section] = { generationId: view.latest!.generationId, observedAt: view.latest!.collectedAt, coverage: 'failed', reason: 'timeout', observedCount: null, countExact: false }; view.lastComplete[section]!.status = 'stale';
        }
        await open(); expect(screen.getByText(/Stale \/ historical service observations/)).toBeVisible(); expect(screen.getByText(/original observation time is unchanged/)).toBeVisible(); expect(document.querySelector('time')).toHaveAttribute('datetime', '2026-10-04T00:00:00Z');
        fireEvent.click(screen.getByRole('checkbox', { name: rows[0].name })); expect(change).toHaveBeenCalledWith([rows[0].name]); expect(mutate).not.toHaveBeenCalled();
    });
});

describe('health picker inventory lifecycle', () => {
    it.each(['unmount', 'device', 'session', 'auth', 'gate', 'pagehide', 'blur', 'hashchange', 'search'] as const)('aborts and ignores late rows after %s', async transition => {
        const rendered = await open(); let finish!: (value: SystemPage) => void, signal!: AbortSignal;
        const raw = JSON.stringify({ section: 'services', generationId: systemGeneration, cursor: 'cursor_100', search: '', filter: 'all', limit: 100 }), oldPage = systemPage(view, rows, [], raw);
        vi.mocked(mutateRaw).mockImplementationOnce(async (_path, _raw, _headers, supplied) => { signal = supplied!; return new Promise<SystemPage>(resolve => { finish = resolve; }); });
        fireEvent.click(screen.getByRole('button', { name: 'Next service page' })); await waitFor(() => expect(signal).toBeDefined());
        if (transition === 'unmount') rendered.unmount();
        if (transition === 'device') { view = { ...view, deviceId: 'agent_replacement' }; rendered.rerender(<Harness deviceId={view.deviceId}/>); }
        if (transition === 'session') rendered.rerender(<Harness sessionKey="second"/>);
        if (transition === 'gate') { auth.authenticated = false; rendered.rerender(<Harness/>); }
        if (transition === 'auth') act(() => window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT)));
        if (['pagehide', 'blur', 'hashchange'].includes(transition)) act(() => window.dispatchEvent(new Event(transition)));
        if (transition === 'search') fireEvent.change(screen.getByRole('searchbox'), { target: { value: 'replacement' } });
        expect(signal.aborted).toBe(true); await act(async () => finish(oldPage)); expect(screen.queryByRole('checkbox', { name: rows[100].name })).not.toBeInTheDocument(); expect(change).not.toHaveBeenCalled();
    });

    it.each(['anonymous', 'development'] as const)('does not read protected inventory for %s access', access => {
        if (access === 'anonymous') auth.authenticated = false; else auth.mode = 'development'; render(<Harness/>);
        expect(screen.getByText('Authenticated LAN operator access is required.')).toBeVisible(); expect(request).not.toHaveBeenCalled(); expect(mutateRaw).not.toHaveBeenCalled();
    });

    it('fails closed on session loss and does not resurrect rows on focus', async () => {
        await open(); vi.mocked(mutateRaw).mockRejectedValueOnce(new APIError('private server text', 401)); fireEvent.click(screen.getByRole('button', { name: 'Next service page' }));
        await screen.findByRole('alert'); expect(screen.getByRole('alert')).toHaveTextContent('session expired'); expect(screen.queryByRole('checkbox')).not.toBeInTheDocument(); expect(screen.queryByRole('textbox')).not.toBeInTheDocument();
        act(() => window.dispatchEvent(new Event('focus'))); expect(mutateRaw).toHaveBeenCalledTimes(2); expect(document.body).not.toHaveTextContent('private server text');
    });

    it('requires an explicit inventory restart after a generation conflict', async () => {
        await open(); vi.mocked(mutateRaw).mockRejectedValueOnce(new APIError('changed', 409)); fireEvent.click(screen.getByRole('button', { name: 'Next service page' }));
        await screen.findByText(/generation or paging session changed or expired/); expect(screen.queryByRole('checkbox')).not.toBeInTheDocument(); expect(request).toHaveBeenCalledTimes(1);
        fireEvent.click(screen.getByRole('button', { name: 'Refresh service list' })); await screen.findByRole('checkbox', { name: rows[0].name }); expect(JSON.parse(vi.mocked(mutateRaw).mock.calls.at(-1)![1]).cursor).toBe('');
    });

    it('does not show manual fallback while inventory is still loading', async () => {
        view = systemView(2); rows = serviceRows(2);
        let finish!: (value: typeof view) => void; vi.mocked(request).mockImplementationOnce(async () => new Promise(resolve => { finish = resolve; })); render(<Harness/>);
        expect(screen.queryByRole('textbox')).not.toBeInTheDocument(); expect(screen.getByText('Reading observed services…')).toBeVisible();
        await act(async () => finish(view)); await screen.findByRole('checkbox', { name: rows[0].name });
    });

    it('clears hidden inventory and reloads page one on return', async () => {
        await open(); fireEvent.click(screen.getByRole('button', { name: 'Next service page' })); await screen.findByRole('checkbox', { name: rows[100].name });
        const visibility = vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden'); act(() => document.dispatchEvent(new Event('visibilitychange')));
        expect(screen.queryByRole('checkbox')).not.toBeInTheDocument(); expect(screen.queryByRole('textbox')).not.toBeInTheDocument();
        visibility.mockReturnValue('visible'); act(() => document.dispatchEvent(new Event('visibilitychange'))); await screen.findByRole('checkbox', { name: rows[0].name });
        expect(request).toHaveBeenCalledTimes(2); expect(JSON.parse(vi.mocked(mutateRaw).mock.calls.at(-1)![1]).cursor).toBe('');
    });

    it('clears stale cursors and unreliable time anchors without implying zero services', async () => {
        vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] }); const mono = vi.spyOn(performance, 'now').mockReturnValue(1000), wall = vi.spyOn(Date, 'now').mockReturnValue(100000);
        await open(); mono.mockReturnValue(901000); wall.mockReturnValue(1000000); act(() => vi.advanceTimersByTime(1000));
        expect(screen.queryByRole('checkbox')).not.toBeInTheDocument(); expect(screen.getByRole('alert')).toHaveTextContent('paging session changed or expired');
        fireEvent.click(screen.getByRole('button', { name: 'Refresh service list' })); await screen.findByRole('checkbox', { name: rows[0].name });
        wall.mockReturnValue(1100000); act(() => vi.advanceTimersByTime(1000)); expect(screen.queryByRole('checkbox')).not.toBeInTheDocument(); expect(screen.getByRole('alert')).toHaveTextContent('time reference changed');
        expect(screen.queryByText('The complete service inventory contained zero services.')).not.toBeInTheDocument();
    });

    it('provides German controls and keeps disabled selection immutable', async () => {
        view = systemView(2); rows = serviceRows(2);
        setLocale('de', false); render(<Harness initial={[rows[0].name]} disabled/>); await screen.findByRole('checkbox', { name: rows[0].name });
        expect(screen.getByLabelText('Beobachtete Dienste durchsuchen')).toBeDisabled(); expect(screen.getByRole('button', { name: `Dienst entfernen: ${rows[0].name}` })).toBeDisabled(); expect(screen.getAllByRole('checkbox').every(box => (box as HTMLInputElement).disabled)).toBe(true); expect(change).not.toHaveBeenCalled();
    });
});

describe('real health form integration', () => {
    function health(): HealthView { return { ...structuredClone(healthFixture) as HealthView, deviceId: systemDevice }; }
    it('persists only on explicit Save, sends sorted names, and explicitly saves deselection', async () => {
        view = systemView(2); rows = serviceRows(2);
        let saved = health();
        vi.mocked(request).mockImplementation(async path => path.endsWith('/health') ? saved : view);
        vi.mocked(mutate).mockImplementation(async (_path, body) => {
            const services = (body as { services: string[] }).services;
            saved = { ...saved, monitoredServices: services, checks: [...saved.checks.filter(check => check.kind !== 'service'), ...services.map(unit => ({ key: `service:${unit}`, kind: 'service' as const, target: unit, state: 'unknown' as const, observedAt: null, value: null }))] }; return saved;
        });
        render(<HealthPanel deviceId={systemDevice} sessionKey="first"/>); await screen.findByRole('checkbox', { name: rows[0].name });
        expect(screen.getByRole('button', { name: 'Save selection' })).toBeDisabled(); fireEvent.click(screen.getByRole('checkbox', { name: rows[0].name }));
        expect(screen.getByRole('list', { name: 'Current checks' })).not.toHaveTextContent(rows[0].name);
        fireEvent.change(screen.getByRole('searchbox'), { target: { value: '000001' } }); fireEvent.keyDown(screen.getByRole('searchbox'), { key: 'Enter' }); await screen.findByRole('checkbox', { name: rows[1].name });
        expect(mutate).not.toHaveBeenCalled(); fireEvent.click(screen.getByRole('button', { name: 'Save selection' }));
        await waitFor(() => expect(screen.getByRole('button', { name: 'Save selection' })).toBeDisabled());
        expect(mutate).toHaveBeenCalledExactlyOnceWith(`/devices/${systemDevice}/health/services`, { services: [rows[0].name, 'sshd.service'] }, expect.any(AbortSignal));
        expect(screen.getByRole('list', { name: 'Current checks' })).toHaveTextContent('Unknown');
        fireEvent.click(screen.getByRole('button', { name: `Remove service: ${rows[0].name}` })); fireEvent.click(screen.getByRole('button', { name: 'Remove service: sshd.service' }));
        expect(mutate).toHaveBeenCalledTimes(1); fireEvent.click(screen.getByRole('button', { name: 'Save selection' }));
        await waitFor(() => expect(mutate).toHaveBeenCalledTimes(2)); expect(vi.mocked(mutate).mock.calls[1][1]).toEqual({ services: [] });
        await waitFor(() => expect(screen.getByRole('button', { name: 'Save selection' })).toBeDisabled());
        expect(vi.mocked(mutateRaw).mock.calls.every(([path]) => path.endsWith('/inventory/system/query'))).toBe(true);
    });

    it('preserves an immediate removal when a deferred Save response commits', async () => {
        view = systemView(2); rows = serviceRows(2);
        let saved = health(), release!: () => void;
        const response = new Promise<void>(resolve => { release = resolve; });
        vi.mocked(request).mockImplementation(async path => path.endsWith('/health') ? saved : view);
        vi.mocked(mutate).mockImplementation(async (_path, body) => {
            await response;
            const services = (body as { services: string[] }).services;
            saved = { ...saved, monitoredServices: services, checks: [...saved.checks.filter(check => check.kind !== 'service'), ...services.map(unit => ({ key: `service:${unit}`, kind: 'service' as const, target: unit, state: 'unknown' as const, observedAt: null, value: null }))] }; return saved;
        });
        let armed = false, removed = false;
        render(<Profiler id="save-response" onRender={() => {
            const remove = screen.queryByRole('button', { name: `Remove service: ${rows[0].name}` });
            if (armed && remove && !removed) {
                removed = true; expect(remove).toBeEnabled();
                // Exercise the response-commit / passive-effect boundary without a timing delay.
                // The outer async act owns this native event and all queued updates.
                (remove as HTMLButtonElement).click();
            }
        }}><HealthPanel deviceId={systemDevice} sessionKey="first"/></Profiler>);
        await screen.findByRole('checkbox', { name: rows[0].name });
        fireEvent.click(screen.getByRole('checkbox', { name: rows[0].name }));
        fireEvent.click(screen.getByRole('button', { name: 'Save selection' }));
        expect(mutate).toHaveBeenCalledExactlyOnceWith(`/devices/${systemDevice}/health/services`, { services: [rows[0].name, 'sshd.service'] }, expect.any(AbortSignal));
        expect(screen.queryByRole('button', { name: `Remove service: ${rows[0].name}` })).not.toBeInTheDocument();
        armed = true; await act(async () => { release(); });
        expect(removed).toBe(true);
        expect(screen.getByRole('list', { name: 'Selected services' })).not.toHaveTextContent(rows[0].name);
        expect(screen.getByRole('list', { name: 'Selected services' })).toHaveTextContent('sshd.service');
        expect(screen.getByRole('button', { name: 'Save selection' })).toBeEnabled();
        expect(saved.monitoredServices).toEqual([rows[0].name, 'sshd.service']);
        fireEvent.click(screen.getByRole('button', { name: 'Remove service: sshd.service' }));
        expect(screen.getByText('No selection. Saving stops existing service checks.')).toBeVisible();
        await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Save selection' })); });
        expect(mutate).toHaveBeenCalledTimes(2); expect(vi.mocked(mutate).mock.calls[1][1]).toEqual({ services: [] });
        expect(saved.monitoredServices).toEqual([]); expect(screen.getByRole('button', { name: 'Save selection' })).toBeDisabled();
    });

    it.each(['rejected', 'invalid'] as const)('retains the unsaved selection after a %s Save response and refresh', async failure => {
        view = systemView(2); rows = serviceRows(2);
        vi.mocked(request).mockImplementation(async path => path.endsWith('/health') ? health() : view);
        if (failure === 'rejected') vi.mocked(mutate).mockRejectedValueOnce(new Error('fixture failure'));
        else vi.mocked(mutate).mockResolvedValueOnce({});
        render(<HealthPanel deviceId={systemDevice} sessionKey="first"/>);
        await screen.findByRole('checkbox', { name: rows[0].name });
        fireEvent.click(screen.getByRole('checkbox', { name: rows[0].name }));
        await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Save selection' })); });
        expect(screen.getByRole('alert')).toHaveTextContent('Change not confirmed');
        await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Refresh' })); });
        expect(screen.getByRole('list', { name: 'Selected services' })).toHaveTextContent(rows[0].name);
        expect(screen.getByRole('button', { name: 'Save selection' })).toBeEnabled();
        expect(screen.getByRole('list', { name: 'Current checks' })).not.toHaveTextContent(rows[0].name);
        expect(mutate).toHaveBeenCalledTimes(1);
    });

    it.each(['device', 'session'] as const)('ignores an old Save response after a new %s selection', async transition => {
        view = systemView(2); rows = serviceRows(2);
        let current = health(), finish!: (value: HealthView) => void;
        vi.mocked(request).mockImplementation(async path => path.endsWith('/health') ? current : view);
        vi.mocked(mutate).mockImplementationOnce(() => new Promise<HealthView>(resolve => { finish = resolve; }));
        const rendered = render(<HealthPanel deviceId={systemDevice} sessionKey="first"/>);
        await screen.findByRole('checkbox', { name: rows[0].name });
        fireEvent.click(screen.getByRole('checkbox', { name: rows[0].name }));
        fireEvent.click(screen.getByRole('button', { name: 'Save selection' }));
        expect(mutate).toHaveBeenCalledTimes(1);
        const signal = vi.mocked(mutate).mock.calls[0][2]!;
        const oldResponse: HealthView = { ...current, monitoredServices: [rows[0].name, 'sshd.service'], checks: [...current.checks, { key: `service:${rows[0].name}`, kind: 'service', target: rows[0].name, state: 'unknown', observedAt: null, value: null }] };
        if (transition === 'device') { current = { ...health(), deviceId: 'agent_replacement' }; view = { ...view, deviceId: current.deviceId }; }
        rendered.rerender(<HealthPanel deviceId={current.deviceId} sessionKey={transition === 'session' ? 'second' : 'first'}/>);
        await screen.findByRole('checkbox', { name: rows[1].name });
        expect(signal.aborted).toBe(true);
        fireEvent.click(screen.getByRole('checkbox', { name: rows[1].name }));
        await act(async () => { finish(oldResponse); });
        expect(screen.getByRole('list', { name: 'Selected services' })).toHaveTextContent(rows[1].name);
        expect(screen.getByRole('list', { name: 'Selected services' })).not.toHaveTextContent(rows[0].name);
        expect(screen.getByRole('button', { name: 'Save selection' })).toBeEnabled();
        expect(mutate).toHaveBeenCalledTimes(1);
    });

    it('preserves focus and draft selection while the ordinary health poll is pending', async () => {
        view = systemView(2); rows = serviceRows(2);
        vi.useFakeTimers(); const wall = Date.now(); vi.spyOn(performance, 'now').mockImplementation(() => Date.now() - wall);
        const current = health(); let finish!: (value: HealthView) => void;
        vi.mocked(request).mockImplementation(async path => path.endsWith('/health') ? current : view);
        render(<HealthPanel deviceId={systemDevice}/>); await act(async () => {});
        fireEvent.click(screen.getByRole('checkbox', { name: rows[0].name }));
        const search = screen.getByRole('searchbox'); fireEvent.change(search, { target: { value: 'partly typed' } }); search.focus();
        vi.mocked(request).mockImplementation(async path => path.endsWith('/health') ? new Promise(resolve => { finish = resolve; }) : view);
        await act(async () => { vi.advanceTimersByTime(30000); });
        expect(search).toHaveFocus(); expect(search).toBeEnabled(); expect(search).toHaveValue('partly typed');
        expect(screen.getByRole('button', { name: 'Save selection' })).toBeDisabled(); expect(screen.getByRole('button', { name: `Remove service: ${rows[0].name}` })).toBeEnabled();
        fireEvent.change(search, { target: { value: 'still typing' } });
        await act(async () => finish(current)); expect(search).toHaveFocus(); expect(search).toHaveValue('still typing');
        expect(screen.getByRole('list', { name: 'Selected services' })).toHaveTextContent(rows[0].name); expect(screen.getByRole('button', { name: 'Save selection' })).toBeEnabled();
        expect(mutate).not.toHaveBeenCalled();
    });

    it('clears an unsaved selection on device/session switch', async () => {
        view = systemView(2); rows = serviceRows(2);
        let current = health(); vi.mocked(request).mockImplementation(async path => path.endsWith('/health') ? current : view);
        const rendered = render(<HealthPanel deviceId={systemDevice} sessionKey="first"/>); await screen.findByRole('checkbox', { name: rows[0].name }); fireEvent.click(screen.getByRole('checkbox', { name: rows[0].name }));
        rendered.rerender(<HealthPanel deviceId={systemDevice} sessionKey="second"/>); await screen.findByRole('checkbox', { name: rows[0].name });
        expect(screen.getByRole('checkbox', { name: rows[0].name })).not.toBeChecked(); expect(screen.getByRole('button', { name: 'Save selection' })).toBeDisabled();
        fireEvent.click(screen.getByRole('checkbox', { name: rows[0].name })); current = { ...health(), deviceId: 'agent_replacement' }; view = { ...view, deviceId: current.deviceId };
        rendered.rerender(<HealthPanel deviceId={current.deviceId} sessionKey="second"/>); await screen.findByRole('checkbox', { name: rows[0].name }); expect(screen.getByRole('checkbox', { name: rows[0].name })).not.toBeChecked();
        rendered.unmount(); expect(mutate).not.toHaveBeenCalled();
    });
    it('aborts a pending service inventory page on unmount', async () => {
        vi.mocked(request).mockImplementation(async path => path.endsWith('/health') ? health() : view);
        const rendered = render(<HealthPanel deviceId={systemDevice} sessionKey="first"/>);
        await screen.findByRole('checkbox', { name: rows[0].name });
        let signal!: AbortSignal; vi.mocked(mutateRaw).mockImplementationOnce(async (_path, _raw, _headers, supplied) => { signal = supplied!; return new Promise(() => {}); });
        fireEvent.click(screen.getByRole('button', { name: 'Next service page' })); await waitFor(() => expect(signal).toBeDefined()); rendered.unmount(); expect(signal.aborted).toBe(true); expect(mutate).not.toHaveBeenCalled();
    });
});
