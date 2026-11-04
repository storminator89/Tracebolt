import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { APIError, AUTH_REQUIRED_EVENT, request } from './api';
import { setLocale } from './i18n';
import { NetworkInterval } from './network-interval';
import { networkObservation } from './network-interval-model';
import { networkRow, networkView } from './network-interval-fixture';
import { OperationalInventoryPanel } from './operational';
import type { OperationalView } from './operational-types';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn() }));
const title = 'Network counter interval';
const setName = 'Use current network observation as baseline';
const region = () => screen.getByRole('region', { name: title });
const baseline = () => networkObservation(networkView(), 0)!;
const current = () => networkObservation(networkView(2, '2026-10-03T12:01:00Z', [networkRow('fixture0', 1600, 3200)]), 0)!;
function defer<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(done => { resolve = done; }); return { promise, resolve }; }
async function open() {
    render(<OperationalInventoryPanel deviceId="agent_fixture"/>);
    await waitFor(() => expect(screen.getByRole('button', { name: 'Refresh observations' })).toBeEnabled());
    fireEvent.click(screen.getByRole('button', { name: /^Network ·/ }));
    return region();
}
async function selectBaseline() { const panel = await open(); fireEvent.click(within(panel).getByRole('button', { name: setName })); return panel; }
const refresh = () => fireEvent.click(screen.getByRole('button', { name: 'Refresh observations' }));
beforeEach(() => { vi.mocked(request).mockReset(); vi.mocked(request).mockResolvedValue(networkView()); setLocale('en', false); });
afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); });

describe('read-only network interval component', () => {
    it('renders original source references, partial coverage, zero deltas and arithmetic rates', () => {
        render(<NetworkInterval baseline={baseline()} current={current()} pending={false} cleared={false} onSet={vi.fn()} onClear={vi.fn()}/>);
        const panel = region();
        expect(within(panel).getAllByText('Partial coverage')).toHaveLength(2); expect(within(panel).getAllByText('not_implemented')).toHaveLength(2);
        expect(within(panel).getByText('600')).toBeVisible(); expect(within(panel).getByText('1,200')).toBeVisible(); expect(within(panel).getByText('10')).toBeVisible(); expect(within(panel).getByText('20')).toBeVisible();
        expect(within(panel).getByText('Original counter values')).toBeVisible();
        const endpoints = within(panel).getByText('Original counter values').closest('details')!;
        expect(within(endpoints).getByText('1,000')).toBeInTheDocument(); expect(within(endpoints).getByText('1,600')).toBeInTheDocument();
        fireEvent.click(within(endpoints).getByText('Original counter values')); expect(endpoints).toHaveAttribute('open');
        expect(within(panel).getByText('Name matched; identity continuity unverified')).toBeVisible(); expect(within(panel).getByText(/not verified traffic throughput/)).toBeVisible();
        expect(within(panel).getAllByText('2026-10-03T12:00:00Z')).toHaveLength(2); expect(request).not.toHaveBeenCalled();
    });
    it('renders names as inert text and uses bounded literal filtering without any request', () => {
        const first = baseline(), second = current(), hostile = '<img src=x onerror=alert(1)>';
        first.rows = [networkRow(hostile), networkRow('[literal]')]; second.rows = [networkRow(hostile, 1100), networkRow('[literal]', 1200)];
        const { container } = render(<NetworkInterval baseline={first} current={second} pending={false} cleared={false} onSet={vi.fn()} onClear={vi.fn()}/>);
        expect(screen.getByText(hostile)).toBeVisible(); expect(container.querySelector('img,script')).toBeNull();
        fireEvent.change(screen.getByRole('searchbox'), { target: { value: '[LITERAL]' } }); expect(screen.queryByText(hostile)).toBeNull(); expect(screen.getByText('[literal]')).toBeVisible();
        fireEvent.change(screen.getByRole('searchbox'), { target: { value: '.*' } }); expect(screen.getByText('No interface names match this filter.')).toBeVisible(); expect(request).not.toHaveBeenCalled();
    });
    it('keeps one-sided names and reset/MTU discontinuities unknown without zero substitution', () => {
        const first = baseline(), second = current(); first.rows.push(networkRow('before')); second.rows.push(networkRow('after')); second.rows[0].rxBytes = 1;
        render(<NetworkInterval baseline={first} current={second} pending={false} cleared={false} onSet={vi.fn()} onClear={vi.fn()}/>);
        expect(screen.getByText('Only in baseline observation; not proof of removal')).toBeVisible(); expect(screen.getByText('Only in current observation; not proof of addition')).toBeVisible();
        const row = screen.getByRole('rowheader', { name: 'fixture0' }).closest('tr')!; expect(within(row).getByText(/all differences withheld/)).toBeVisible(); expect(within(row).getAllByText('Unknown')).toHaveLength(6);
    });
    it('supports German original timestamps and explicit replace/clear without side effects', () => {
        setLocale('de', false); const set = vi.fn(), clear = vi.fn();
        render(<NetworkInterval baseline={baseline()} current={current()} pending={false} cleared={false} onSet={set} onClear={clear}/>);
        expect(screen.getByText(/kein verifizierter Datendurchsatz/)).toBeVisible(); expect(screen.getByText('Änderung empfangener Bytes')).toBeVisible();
        fireEvent.click(screen.getByRole('button', { name: 'Netzwerk-Ausgangsstand ersetzen' })); fireEvent.click(screen.getByRole('button', { name: 'Netzwerk-Ausgangsstand löschen' })); expect(set).toHaveBeenCalledOnce(); expect(clear).toHaveBeenCalledOnce(); expect(request).not.toHaveBeenCalled();
    });
});

describe('existing operational reader network investigation integration', () => {
    it('selects baseline, waits for unchanged evidence, compares one ordinary refresh, replaces and clears locally', async () => {
        const storage = vi.spyOn(Storage.prototype, 'setItem'); await selectBaseline();
        expect(within(region()).getByText(/Waiting for a different original observation/)).toBeVisible(); expect(request).toHaveBeenCalledOnce();
        vi.mocked(request).mockResolvedValue(networkView(2, '2026-10-03T12:01:00Z', [networkRow('fixture0', 1600, 3200)])); refresh();
        await waitFor(() => expect(within(region()).getByText('600')).toBeVisible()); expect(request).toHaveBeenCalledTimes(2);
        fireEvent.change(within(region()).getByRole('searchbox'), { target: { value: 'no match' } });
        fireEvent.click(within(region()).getByRole('button', { name: 'Replace network baseline' })); expect(within(region()).queryByRole('searchbox')).toBeNull(); expect(within(region()).getByText(/Waiting for a different/)).toBeVisible();
        fireEvent.click(within(region()).getByRole('button', { name: 'Clear network baseline' })); expect(within(region()).getByText('No network baseline selected.')).toBeVisible();
        expect(request).toHaveBeenCalledTimes(2); expect(storage).not.toHaveBeenCalled();
    });
    it('keeps the selected baseline across an in-flight refresh but withholds comparison and ignores interrupted results', async () => {
        await selectBaseline(); const pending = defer<OperationalView>(); vi.mocked(request).mockReturnValue(pending.promise); refresh();
        expect(within(region()).getByText(/Reading the existing source/)).toBeVisible(); expect(within(region()).getByText('Baseline original observation')).toBeVisible(); expect(within(region()).getByRole('button', { name: 'Replace network baseline' })).toBeDisabled();
        act(() => window.dispatchEvent(new Event('blur'))); expect(within(region()).queryByText('Baseline original observation')).toBeNull();
        await act(async () => pending.resolve(networkView(2, '2026-10-03T12:01:00Z'))); expect(within(region()).queryByText('Current original observation')).toBeNull(); expect(request).toHaveBeenCalledTimes(2);
    });
    it.each(['auth', 'pagehide', 'hashchange', 'hidden'] as const)('clears selected private baseline on %s', async event => {
        await selectBaseline();
        act(() => {
            if (event === 'hidden') { vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden'); document.dispatchEvent(new Event('visibilitychange')); }
            else window.dispatchEvent(new Event(event === 'auth' ? AUTH_REQUIRED_EVENT : event));
        });
        expect(within(region()).queryByText('Baseline original observation')).toBeNull(); expect(request).toHaveBeenCalledOnce();
    });
    it.each(['failure', 'invalid', 'denied', 'duplicate', 'regression'] as const)('clears baseline after %s without retained fallback or automatic retry', async failure => {
        await selectBaseline();
        const next = networkView(2, '2026-10-03T12:01:00Z');
        if (failure === 'failure') vi.mocked(request).mockRejectedValue(new APIError('PRIVATE_DO_NOT_RENDER', 500));
        else if (failure === 'invalid') vi.mocked(request).mockResolvedValue({ ...next, extra: 'PRIVATE_DO_NOT_RENDER' });
        else {
            if (failure === 'denied') { next.lastGood.network = structuredClone(next.snapshot!.sections.network); Object.assign(next.snapshot!.sections.network.meta, { quality: 'denied', reason: 'permission_denied', observedCount: 0 }); next.snapshot!.sections.network.items = []; }
            if (failure === 'duplicate') { next.snapshot!.sections.network.items.push(networkRow()); next.snapshot!.sections.network.meta.observedCount = 2; }
            if (failure === 'regression') next.sequence = 1;
            vi.mocked(request).mockResolvedValue(next);
        }
        refresh(); await waitFor(() => expect(screen.getByRole('button', { name: 'Refresh observations' })).toBeEnabled());
        expect(within(region()).queryByText('Baseline original observation')).toBeNull(); expect(screen.queryByText('PRIVATE_DO_NOT_RENDER')).toBeNull(); expect(request).toHaveBeenCalledTimes(2);
    });
    it('rejects regression against the latest source, even when both sequences exceed the selected baseline', async () => {
        await selectBaseline(); vi.mocked(request).mockResolvedValue(networkView(3, '2026-10-03T12:01:00Z')); refresh();
        await waitFor(() => expect(within(region()).getByText('Matched names')).toBeVisible());
        vi.mocked(request).mockResolvedValue(networkView(2, '2026-10-03T12:00:30Z')); refresh();
        await waitFor(() => expect(screen.getByRole('button', { name: 'Refresh observations' })).toBeEnabled());
        expect(within(region()).queryByText('Baseline original observation')).toBeNull(); expect(within(region()).getByRole('button', { name: setName })).toBeDisabled();
    });
    it.each(['counter', 'mtu'] as const)('clears on a latest-pair %s discontinuity even if baseline arithmetic looks positive', async kind => {
        await selectBaseline();
        const middle = networkView(2, '2026-10-03T12:00:30Z', [networkRow('fixture0', 2000)]);
        if (kind === 'mtu') middle.snapshot!.sections.network.items[0].mtu = 9000;
        vi.mocked(request).mockResolvedValue(middle); refresh();
        await waitFor(() => expect(screen.getByRole('button', { name: 'Refresh observations' })).toBeEnabled());
        if (kind === 'mtu') expect(within(region()).queryByText('Baseline original observation')).toBeNull();
        // Re-select to prove the second transition also clears a new baseline.
        fireEvent.click(within(region()).getByRole('button', { name: kind === 'mtu' ? setName : 'Replace network baseline' }));
        vi.mocked(request).mockResolvedValue(networkView(3, '2026-10-03T12:01:00Z', [networkRow('fixture0', 1500)])); refresh();
        await waitFor(() => expect(screen.getByRole('button', { name: 'Refresh observations' })).toBeEnabled());
        expect(within(region()).queryByText('Baseline original observation')).toBeNull(); expect(within(region()).getByRole('button', { name: setName })).toBeEnabled();
        fireEvent.click(within(region()).getByRole('button', { name: setName })); expect(within(region()).getByText(/Waiting for a different/)).toBeVisible();
    });
    it('never presents a positive baseline difference after an intervening higher counter', async () => {
        await selectBaseline(); vi.mocked(request).mockResolvedValue(networkView(2, '2026-10-03T12:00:30Z', [networkRow('fixture0', 2000)])); refresh();
        await waitFor(() => expect(within(region()).getByRole('cell', { name: '1,000' })).toBeVisible());
        vi.mocked(request).mockResolvedValue(networkView(3, '2026-10-03T12:01:00Z', [networkRow('fixture0', 1500)])); refresh();
        await waitFor(() => expect(screen.getByRole('button', { name: 'Refresh observations' })).toBeEnabled());
        expect(within(region()).queryByText('500')).toBeNull(); expect(within(region()).queryByText('Baseline original observation')).toBeNull();
    });
    it('does not renew freshness through repeated unchanged successful reads before the timer fires', async () => {
        let now = 0; vi.spyOn(performance, 'now').mockImplementation(() => now); await selectBaseline();
        now = 60000; refresh(); await waitFor(() => expect(screen.getByRole('button', { name: 'Refresh observations' })).toBeEnabled());
        expect(within(region()).getByText('Baseline original observation')).toBeVisible();
        now = 121000; refresh(); await waitFor(() => expect(screen.getByRole('button', { name: 'Refresh observations' })).toBeEnabled());
        expect(within(region()).queryByText('Baseline original observation')).toBeNull(); expect(within(region()).getByRole('button', { name: setName })).toBeDisabled();
    });
    it('rechecks actual selection time between timer ticks instead of selecting an expired rendered sample', async () => {
        let now = 0; vi.spyOn(performance, 'now').mockImplementation(() => now); await open();
        expect(within(region()).getByRole('button', { name: setName })).toBeEnabled();
        now = 120001; fireEvent.click(within(region()).getByRole('button', { name: setName }));
        expect(within(region()).queryByText('Baseline original observation')).toBeNull(); expect(within(region()).getByRole('button', { name: setName })).toBeDisabled();
    });
    it('does not allow a slow response at the freshness boundary to become a fresh baseline', async () => {
        let now = 0; vi.spyOn(performance, 'now').mockImplementation(() => now);
        const pending = defer<OperationalView>(); vi.mocked(request).mockReturnValue(pending.promise); const opened = open();
        const response = networkView(); response.serverNow = '2026-10-03T12:01:59Z'; now = 2000; await act(async () => pending.resolve(response)); await opened;
        expect(within(region()).getByRole('button', { name: setName })).toBeDisabled(); expect(request).toHaveBeenCalledOnce();
    });
    it('clears when current evidence ages out and cannot refresh frozen server times back into eligibility', async () => {
        vi.useFakeTimers(); let now = 0; vi.spyOn(performance, 'now').mockImplementation(() => now);
        render(<OperationalInventoryPanel deviceId="agent_fixture"/>); await act(async () => {});
        fireEvent.click(screen.getByRole('button', { name: /^Network ·/ })); fireEvent.click(within(region()).getByRole('button', { name: setName }));
        now = 121000; act(() => vi.advanceTimersByTime(121000));
        expect(within(region()).queryByText('Baseline original observation')).toBeNull(); expect(within(region()).getByRole('button', { name: setName })).toBeDisabled();
        refresh(); await act(async () => {}); expect(within(region()).getByRole('button', { name: setName })).toBeDisabled(); expect(request).toHaveBeenCalledTimes(2);
    });
    it('clears private baseline on same-device session change and device change', async () => {
        const instance = render(<OperationalInventoryPanel deviceId="agent_fixture" sessionKey="first"/>); await waitFor(() => expect(screen.getByRole('button', { name: 'Refresh observations' })).toBeEnabled());
        fireEvent.click(screen.getByRole('button', { name: /^Network ·/ })); fireEvent.click(within(region()).getByRole('button', { name: setName }));
        instance.rerender(<OperationalInventoryPanel deviceId="agent_fixture" sessionKey="second"/>); expect(screen.queryByText('Baseline original observation')).toBeNull(); await act(async () => {});
        const next = networkView(); next.deviceId = 'agent_other'; vi.mocked(request).mockResolvedValue(next); instance.rerender(<OperationalInventoryPanel deviceId="agent_other" sessionKey="second"/>); await act(async () => {}); expect(screen.queryByText('Baseline original observation')).toBeNull();
    });
});
