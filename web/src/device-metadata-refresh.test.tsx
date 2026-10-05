import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, APIError, AUTH_REQUIRED_EVENT, mutateRaw, request } from './api';
import { LOGOUT_INTENT_KEY, useOperator } from './auth';
import { DeviceDetail } from './details';
import { emptyEndpointView } from './endpoint-identity-fixtures';
import { completeView } from './complete-packages-fixtures';
import { journalDevice as id, journalNow, journalSession, journalSessionExpiry, journalView, journalPage } from './journal-fixtures';
import { setLocale } from './i18n';
import type { Device, Metric } from './types';
import { fullDate, relativeTime } from './utils';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutateRaw: vi.fn() }));
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
const secondID = `agent_${'8'.repeat(32)}`;
const oldContact = '2026-10-04T11:00:00Z', newContact = '2026-10-04T11:59:00Z';
const operator = { mode: 'lan' as const, authenticated: true, expiresAt: journalSessionExpiry, insecureTestMode: false, logout: vi.fn(), theme: 'light' as const, setTheme: vi.fn() };
function device(deviceID = id, fresh = false): Device {
    const metric: Metric = { value: fresh ? 42 : 11, unit: '%', quality: 'healthy', source: 'Synthetic metadata fixture', collectedAt: fresh ? newContact : oldContact };
    return { id: deviceID, name: deviceID === id ? 'Synthetic metadata fixture' : 'Synthetic second device', platform: 'linux', os: fresh ? 'Refreshed Linux fixture' : 'Linux fixture', site: 'Fixture', group: 'Fixture', ip: null, status: 'unknown', source: 'lan', synthetic: false, lastSeen: fresh ? newContact : oldContact, agentVersion: 'fixture', cpu: metric, memory: metric, disk: metric, uptime: '', tags: [], capabilities: [], evidence: [], trend: [], caseIds: [] };
}
function answer(path: string) {
    if (path === `/devices/${id}`) return device();
    if (path === `/devices/${secondID}`) return device(secondID);
    if (path.endsWith('/inventory/endpoint-identity')) return { ...emptyEndpointView(), deviceId: path.split('/')[2] };
    if (path.endsWith('/inventory/packages')) return { ...completeView(), deviceId: path.split('/')[2] };
    if (path === '/auth/session') return journalSession;
    if (path === `/devices/${id}/journal`) return journalView('awaiting');
    throw new Error('Unconfigured synthetic resource');
}
function deferred<T>() { let resolve!: (value: T) => void, reject!: (error: unknown) => void; const promise = new Promise<T>((ok, fail) => { resolve = ok; reject = fail; }); return { promise, resolve, reject }; }
const flush = () => act(async () => {});
const advance = (ms: number) => act(async () => { await vi.advanceTimersByTimeAsync(ms); });
const refresh = () => screen.getByRole('button', { name: 'Refresh device metadata' });
const metadataCalls = () => vi.mocked(request).mock.calls.filter(([path]) => path === `/devices/${id}`);
const panel = (deviceID = id) => <DeviceDetail id={deviceID} onClose={vi.fn()} onCase={vi.fn()}/>;
async function start() { const mounted = render(panel()); await flush(); return mounted; }
function holdRefresh() {
    const held = deferred<Device>();
    vi.mocked(request).mockImplementation(path => path === `/devices/${id}` ? held.promise : Promise.resolve(answer(path)));
    fireEvent.click(refresh()); return held;
}
beforeEach(() => {
    vi.useFakeTimers(); vi.setSystemTime(journalNow); localStorage.clear(); sessionStorage.clear(); setLocale('en', false);
    vi.mocked(useOperator).mockReturnValue(operator);
    vi.mocked(request).mockReset().mockImplementation(async path => answer(path)); vi.mocked(mutateRaw).mockReset();
});
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.restoreAllMocks(); });

describe('explicit device metadata refresh', () => {
    it('refreshes only the read-only certificate check and never treats new contact as renewal', async () => {
        const expiresAt = '2026-10-04T12:01:00Z';
        vi.mocked(request).mockImplementation(async path => path === `/devices/${id}` ? { ...device(), agentCertificate: { source: 'guided-enrollment', expiresAt, checkedAt: journalNow } } : answer(path));
        await start();
        fireEvent.click(screen.getByRole('tab', { name: 'Details' })); await flush();
        const region = screen.getByRole('region', { name: 'Agent certificate' });
        expect(within(region).getByText('Expires within 48 hours')).toBeVisible();
        const calls = vi.mocked(request).mock.calls.length, held = holdRefresh();
        await act(async () => held.resolve({ ...device(id, true), agentCertificate: { source: 'guided-enrollment', expiresAt, checkedAt: expiresAt } }));
        expect(within(region).getByText('Expired')).toBeVisible();
        expect(region.querySelector('time')).toHaveAttribute('datetime', expiresAt);
        expect(region.querySelector('button')).toBeNull();
        expect(request).toHaveBeenCalledTimes(calls + 1); expect(mutateRaw).not.toHaveBeenCalled();
        expect(document.querySelector('.detail-time')).toHaveTextContent(relativeTime(newContact));
        act(() => window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT)));
        expect(screen.queryByRole('region', { name: 'Agent certificate' })).not.toBeInTheDocument();
    });

    it('updates metrics and contact from one bounded GET without remounting Details or collapsing its disclosure', async () => {
        await start();
        fireEvent.click(screen.getByRole('tab', { name: 'Details' })); await flush();
        const metrics = document.querySelector('.device-metrics')!, technical = screen.getByText('Device profile & technical details').closest('details')!;
        fireEvent.click(within(technical).getByText('Device profile & technical details'));
        expect(technical).toHaveAttribute('open'); expect(metrics.textContent).toContain('11%');
        const lastCheck = document.querySelector('#device-metadata-status time')!.getAttribute('datetime');
        await advance(1000); const held = holdRefresh();
        expect(refresh()).toBeDisabled(); expect(refresh()).toHaveAccessibleDescription(/Checking device metadata/);
        fireEvent.click(refresh()); fireEvent.click(refresh()); expect(metadataCalls()).toHaveLength(2);
        expect(metadataCalls()[1][1]).toEqual({ signal: expect.any(AbortSignal) }); expect(metadataCalls()[1][2]).toBe(262144);
        expect(document.querySelector('.device-metrics')).toBe(metrics); expect(technical).toHaveAttribute('open');
        await act(async () => held.resolve(device(id, true)));
        expect(metrics.textContent).toContain('42%'); expect(metrics.textContent).not.toContain('11%');
        expect(document.querySelector('.detail-time')).toHaveTextContent(relativeTime(newContact));
        expect(within(technical).getByText(fullDate(newContact))).toBeVisible(); expect(technical).toHaveAttribute('open');
        expect(document.querySelector('#device-metadata-status time')!.getAttribute('datetime')).not.toBe(lastCheck);
        expect(refresh()).toBeEnabled(); expect(screen.getByRole('tab', { name: 'Details' })).toHaveAttribute('aria-selected', 'true');
        await advance(30000); expect(metadataCalls()).toHaveLength(2); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('preserves the actual Logs form instance, unit/window/severity/consent and active tab through metadata refresh', async () => {
        await start(); fireEvent.click(screen.getByRole('tab', { name: 'Logs' })); await flush();
        const unit = screen.getByLabelText('Exact service unit');
        fireEvent.change(unit, { target: { value: 'draft.service' } });
        fireEvent.change(screen.getByLabelText('From (UTC)'), { target: { value: '2026-10-04T11:42' } });
        fireEvent.change(screen.getByLabelText('To (UTC)'), { target: { value: '2026-10-04T11:58' } });
        fireEvent.change(screen.getByLabelText('Include severity through'), { target: { value: '3' } }); fireEvent.click(screen.getByRole('checkbox'));
        const calls = vi.mocked(request).mock.calls.length, held = holdRefresh();
        expect(screen.getByLabelText('Exact service unit')).toBe(unit); expect(unit).toHaveValue('draft.service');
        await act(async () => held.resolve(device(id, true)));
        expect(screen.getByLabelText('Exact service unit')).toBe(unit); expect(unit).toHaveValue('draft.service');
        expect(screen.getByLabelText('From (UTC)')).toHaveValue('2026-10-04T11:42'); expect(screen.getByLabelText('To (UTC)')).toHaveValue('2026-10-04T11:58');
        expect(screen.getByLabelText('Include severity through')).toHaveValue('3'); expect(screen.getByRole('checkbox')).toBeChecked();
        expect(screen.getByRole('tab', { name: 'Logs' })).toHaveAttribute('aria-selected', 'true');
        expect(screen.getByText('Refreshed Linux fixture')).toBeVisible(); expect(document.querySelector('.detail-time')).toHaveTextContent(relativeTime(newContact));
        expect(request).toHaveBeenCalledTimes(calls + 1); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('does not renew the original Logs retention deadline or requery rows while refreshing metadata', async () => {
        vi.mocked(request).mockImplementation(async path => path === `/devices/${id}/journal` ? journalView() : answer(path));
        vi.mocked(mutateRaw).mockResolvedValue(journalPage(['Synthetic retained row']));
        await start(); fireEvent.click(screen.getByRole('tab', { name: 'Logs' })); await flush();
        expect(screen.getByText('Synthetic retained row')).toBeVisible(); expect(mutateRaw).toHaveBeenCalledTimes(1);
        await advance(14 * 60000); const held = holdRefresh(); await act(async () => held.resolve(device(id, true)));
        expect(screen.getByText('Synthetic retained row')).toBeVisible(); expect(mutateRaw).toHaveBeenCalledTimes(1);
        await advance(59999); expect(screen.getByText('Synthetic retained row')).toBeVisible();
        await advance(1); expect(screen.queryByText('Synthetic retained row')).not.toBeInTheDocument(); expect(mutateRaw).toHaveBeenCalledTimes(1);
        expect(metadataCalls()).toHaveLength(2);
    });
    it('keeps the actual nested inventory selection and instance without rerunning child requests', async () => {
        await start(); fireEvent.click(screen.getByRole('tab', { name: 'Inventory' })); await flush();
        fireEvent.click(screen.getByRole('tab', { name: 'Mounts' })); await flush();
        const inventory = document.querySelector('.inventory-workspace'), mounts = screen.getByRole('tab', { name: 'Mounts' }), calls = vi.mocked(request).mock.calls.length;
        const held = holdRefresh(); await act(async () => held.resolve(device(id, true)));
        expect(document.querySelector('.inventory-workspace')).toBe(inventory); expect(screen.getByRole('tab', { name: 'Mounts' })).toBe(mounts);
        expect(mounts).toHaveAttribute('aria-selected', 'true'); expect(screen.getByRole('tab', { name: 'Inventory' })).toHaveAttribute('aria-selected', 'true');
        expect(request).toHaveBeenCalledTimes(calls + 1); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('retains the previous snapshot and successful-check time honestly on an ordinary refresh failure, then permits a fresh click', async () => {
        await start(); const time = document.querySelector('#device-metadata-status time')!.getAttribute('datetime');
        const held = holdRefresh(); await act(async () => held.reject(new APIError('Synthetic unavailable', 503)));
        expect(screen.getByRole('alert')).toHaveTextContent('Refresh failed. Displayed device metadata is unchanged.');
        expect(document.querySelector('.device-metrics')).toHaveTextContent('11%'); expect(document.querySelector('#device-metadata-status time')).toHaveAttribute('datetime', time);
        await advance(30000); expect(metadataCalls()).toHaveLength(2); expect(refresh()).toBeEnabled();
        vi.mocked(request).mockImplementation(async path => path === `/devices/${id}` ? device(id, true) : answer(path)); fireEvent.click(refresh()); await flush();
        expect(screen.queryByRole('alert')).not.toBeInTheDocument(); expect(document.querySelector('.device-metrics')).toHaveTextContent('42%'); expect(metadataCalls()).toHaveLength(3);
    });
    it('aborts at ten seconds, unlocks explicit retry and rejects a late reply without polling', async () => {
        await start(); const held = holdRefresh(), signal = metadataCalls()[1][1]!.signal as AbortSignal;
        await advance(9999); expect(signal.aborted).toBe(false); expect(refresh()).toBeDisabled();
        await advance(1); expect(signal.aborted).toBe(true); expect(refresh()).toBeEnabled(); expect(screen.getByRole('alert')).toHaveTextContent(/not responding/i);
        await act(async () => held.resolve(device(id, true))); expect(document.querySelector('.device-metrics')).toHaveTextContent('11%');
        await advance(30000); expect(metadataCalls()).toHaveLength(2);
    });
    it.each(['wall', 'monotonic', 'elapsed'] as const)('rejects a late reply after a %s clock/deadline discontinuity', async kind => {
        await start(); const held = holdRefresh();
        if (kind === 'wall') vi.spyOn(Date, 'now').mockReturnValue(Date.now() + 5000);
        else vi.spyOn(performance, 'now').mockReturnValue(kind === 'monotonic' ? -1 : performance.now() + 10000);
        await act(async () => held.resolve(device(id, true)));
        expect(screen.getByRole('alert')).toHaveTextContent(/not responding/i); expect(document.querySelector('.device-metrics')).toHaveTextContent('11%');
        expect(refresh()).toBeEnabled(); expect(metadataCalls()).toHaveLength(2);
    });
    it.each([403, 404, 410])('clears existing metadata and child drafts on HTTP %s', async status => {
        await start(); fireEvent.click(screen.getByRole('tab', { name: 'Logs' })); await flush(); fireEvent.change(screen.getByLabelText('Exact service unit'), { target: { value: 'private-draft.service' } });
        const held = holdRefresh(); await act(async () => held.reject(new APIError('Unavailable', status)));
        expect(screen.queryByRole('heading', { name: 'Synthetic metadata fixture' })).not.toBeInTheDocument(); expect(screen.queryByLabelText('Exact service unit')).not.toBeInTheDocument();
        expect(screen.getByRole('alert')).toHaveTextContent('Device unavailable');
    });
    it.each(['response401', 'event', 'epoch', 'logout'] as const)('clears and locks old session metadata after %s', async transition => {
        await start(); const held = holdRefresh(), signal = metadataCalls()[1][1]!.signal as AbortSignal;
        if (transition === 'response401') await act(async () => held.reject(new APIError('Ended', 401)));
        else {
            if (transition === 'event') act(() => window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT)));
            if (transition === 'epoch') act(() => abortProtectedRequests());
            if (transition === 'logout') localStorage.setItem(LOGOUT_INTENT_KEY, '1');
            await act(async () => held.resolve(device(id, true)));
        }
        expect(signal.aborted).toBe(true); expect(screen.queryByRole('heading', { name: 'Synthetic metadata fixture' })).not.toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Try again' })).toBeDisabled(); expect(screen.getByRole('alert')).toHaveTextContent(/session.*expired/i);
    });
    it('resets a changed device to Overview and rejects the old late metadata', async () => {
        const mounted = await start(); fireEvent.click(screen.getByRole('tab', { name: 'Inventory' })); await flush();
        const held = holdRefresh(), signal = metadataCalls()[1][1]!.signal as AbortSignal;
        mounted.rerender(panel(secondID)); await flush(); expect(signal.aborted).toBe(true);
        expect(screen.getByRole('heading', { name: 'Synthetic second device' })).toBeVisible(); expect(screen.getByRole('tab', { name: 'Overview' })).toHaveAttribute('aria-selected', 'true');
        await act(async () => held.resolve(device(id, true))); expect(screen.queryByText('Refreshed Linux fixture')).not.toBeInTheDocument();
    });
    it('discards a pending response and private draft when the operator session changes', async () => {
        const mounted = await start(); fireEvent.click(screen.getByRole('tab', { name: 'Logs' })); await flush(); fireEvent.change(screen.getByLabelText('Exact service unit'), { target: { value: 'private-draft.service' } });
        const held = holdRefresh(), signal = metadataCalls()[1][1]!.signal as AbortSignal;
        vi.mocked(useOperator).mockReturnValue({ ...operator, expiresAt: '2026-10-04T14:00:00Z' }); vi.mocked(request).mockImplementation(async path => answer(path));
        mounted.rerender(panel()); await flush(); expect(signal.aborted).toBe(true); expect(screen.queryByLabelText('Exact service unit')).not.toBeInTheDocument();
        await act(async () => held.resolve(device(id, true))); expect(screen.queryByText('Refreshed Linux fixture')).not.toBeInTheDocument();
    });
    it.each(['hidden', 'pagehide', 'unmount'] as const)('cancels a pending refresh on %s and never installs its late response', async transition => {
        const mounted = await start(), held = holdRefresh(), signal = metadataCalls()[1][1]!.signal as AbortSignal;
        if (transition === 'unmount') mounted.unmount();
        else if (transition === 'hidden') { vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden'); act(() => document.dispatchEvent(new Event('visibilitychange'))); }
        else act(() => window.dispatchEvent(new Event('pagehide')));
        expect(signal.aborted).toBe(true); await act(async () => held.resolve(device(id, true))); expect(screen.queryByText('Refreshed Linux fixture')).not.toBeInTheDocument();
        await advance(30000); expect(metadataCalls()).toHaveLength(2);
    });
    it('does not reload or reset selection for ordinary blur, focus or locale changes', async () => {
        await start(); fireEvent.click(screen.getByRole('tab', { name: 'Inventory' })); await flush(); fireEvent.click(screen.getByRole('tab', { name: 'Mounts' })); await flush();
        const inventory = document.querySelector('.inventory-workspace'); act(() => { window.dispatchEvent(new Event('blur')); window.dispatchEvent(new Event('focus')); }); await flush();
        expect(document.querySelector('.inventory-workspace')).toBe(inventory); expect(screen.getByRole('tab', { name: 'Mounts' })).toHaveAttribute('aria-selected', 'true'); expect(metadataCalls()).toHaveLength(1);
        act(() => setLocale('de', false)); expect(screen.getByRole('button', { name: 'Gerätedaten aktualisieren' })).toBeEnabled(); expect(screen.getByRole('tab', { name: 'Mounts' })).toHaveAttribute('aria-selected', 'true'); expect(metadataCalls()).toHaveLength(1);
    });
    it('rejects a mismatched device reply without marking it as a successful refresh', async () => {
        await start(); const time = document.querySelector('#device-metadata-status time')!.getAttribute('datetime'), held = holdRefresh();
        await act(async () => held.resolve(device(secondID, true)));
        expect(screen.queryByText('Synthetic second device')).not.toBeInTheDocument(); expect(screen.getByRole('alert')).toHaveTextContent(/valid JSON/i);
        expect(document.querySelector('#device-metadata-status time')).toHaveAttribute('datetime', time);
    });
});
