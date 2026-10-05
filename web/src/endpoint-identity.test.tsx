import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AUTH_REQUIRED_EVENT, APIError, request } from './api';
import { useOperator } from './auth';
import { DeviceDetail } from './details';
import { EndpointIdentityPanel } from './endpoint-identity';
import { useEndpointIdentity } from './endpoint-identity-resource';
import { emptyEndpointView, endpointComplete, endpointDevice, endpointFailed, endpointView } from './endpoint-identity-fixtures';
import type { EndpointIdentityView } from './endpoint-identity-types';
import type { Device } from './types';
import { setLocale } from './i18n';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn() }));
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
const operator = { mode: 'lan' as const, authenticated: true, expiresAt: '2026-10-04T13:00:00Z', insecureTestMode: false, logout: vi.fn(), theme: 'light' as const, setTheme: vi.fn() };
function Harness({ id = endpointDevice, enabled = true, session = 'fixture-session' }: { id?: string; enabled?: boolean; session?: string }) { const resource = useEndpointIdentity(id, enabled, session); return <EndpointIdentityPanel resource={resource}/>; }
function device(id = endpointDevice): Device {
    const metric = { value: null, unit: '%', quality: 'unknown' as const, source: 'fixture', collectedAt: '0001-01-01T00:00:00Z' };
    return { id, name: id, platform: 'linux', os: 'Linux', source: 'lan', synthetic: false, status: 'unknown', site: '', group: '', ip: '198.51.100.250', lastSeen: '0001-01-01T00:00:00Z', agentVersion: 'fixture', cpu: metric, memory: metric, disk: metric, uptime: '', tags: [], capabilities: [], evidence: [], trend: [], caseIds: [] };
}
beforeEach(() => { setLocale('en', false); vi.mocked(request).mockReset().mockResolvedValue(endpointView()); vi.mocked(useOperator).mockReturnValue(operator); });
afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); });

describe('endpoint identity operator view', () => {
    it('shows independent interface families, numeric addresses, scopes and explicit flags without links', async () => {
        render(<Harness/>); await screen.findByText('fixture-linux');
        expect(screen.getByText('Recent observation')).toBeVisible();
        expect(screen.getByRole('article', { name: 'Interface lo' })).toHaveTextContent('Up · Loopback');
        const eth = screen.getByRole('article', { name: 'Interface eth0' }); expect(within(eth).getByRole('region', { name: 'IPv4' })).toHaveTextContent('192.0.2.19'); expect(within(eth).getByRole('region', { name: 'IPv6' })).toHaveTextContent('2001:db8::19'); expect(eth).toHaveTextContent('fe80::19'); expect(eth).toHaveTextContent('Hardware kind unknown');
        expect(screen.queryByRole('link')).not.toBeInTheDocument(); expect(screen.getByText('2026-10-04T12:00:00Z')).toBeVisible(); expect(screen.getByText('2026-10-04T12:00:01Z')).toBeVisible();
        fireEvent.click(screen.getByText('Source, permission & retention')); expect(screen.getByText(/Sources: local uname/)).toBeVisible(); expect(screen.getByText(/cannot remotely verify/)).toBeVisible();
        expect(vi.mocked(request)).toHaveBeenCalledWith(`/devices/${endpointDevice}/inventory/endpoint-identity`, expect.objectContaining({ signal: expect.any(AbortSignal) }), 16384);
    });
    it('renders hostname markup inertly without creating an element', async () => {
        const v = endpointView(); v.latest!.reportedHostname.value = '<img src=x onerror=alert(1)>'; vi.mocked(request).mockResolvedValue(v); const { container } = render(<Harness/>);
        expect(await screen.findByText('<img src=x onerror=alert(1)>')).toBeVisible(); expect(container.querySelector('img')).toBeNull(); expect(container.querySelector('a')).toBeNull();
    });
    it('preserves other observations on a hostname/family failure and distinguishes successful emptiness', async () => {
        const v = endpointView(); v.latest!.reportedHostname = { coverage: 'failed', reason: 'permission_denied', value: null }; v.latest!.interfaces.meta = { ...endpointComplete(2), coverage: 'partial', reason: 'address_unavailable' }; v.latest!.interfaces.items[1].up = false; v.latest!.interfaces.items[1].addresses.ipv6 = { meta: endpointFailed('not_supported'), items: [] }; v.latest!.interfaces.items[0].addresses.ipv6 = { meta: endpointComplete(0), items: [] }; vi.mocked(request).mockResolvedValue(v);
        render(<Harness/>); await screen.findByText('192.0.2.19'); expect(screen.getByText('Collection failed: Permission denied')).toBeVisible(); expect(screen.getByText('Partial address coverage: One or more address families could not be read')).toBeVisible(); expect(screen.getByText('Collection failed: Not supported')).toBeVisible(); expect(screen.getByText('Complete: no assigned addresses observed for this family.')).toBeVisible(); expect(screen.getByRole('article', { name: 'Interface eth0' })).toHaveTextContent('Down · Not loopback');
    });
    it.each(['not_collected', 'expired', 'revoked', 'unknown'] as const)('clears previous observations when the manager reports %s', async status => {
        vi.mocked(request).mockResolvedValueOnce(endpointView()).mockResolvedValueOnce(emptyEndpointView(status)); render(<Harness/>); await screen.findByText('fixture-linux'); fireEvent.click(screen.getByRole('button', { name: 'Refresh reported identity' })); await screen.findByText('No hostname or address values are shown in this state.'); expect(screen.queryByText('fixture-linux')).not.toBeInTheDocument(); expect(screen.queryByText('192.0.2.19')).not.toBeInTheDocument();
    });
    it('rejects invalid responses, including raw errors, with fixed failure text', async () => {
        vi.mocked(request).mockResolvedValue({ ...endpointView(), secret: 'raw-sensitive-value' }); render(<Harness/>); await screen.findByRole('alert'); expect(screen.getByRole('alert')).toHaveTextContent('inconsistent or unsupported'); expect(document.body).not.toHaveTextContent('raw-sensitive-value');
        vi.mocked(request).mockRejectedValue(new Error('raw-sensitive-value')); fireEvent.click(screen.getByRole('button', { name: 'Refresh reported identity' })); await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('could not be read')); expect(document.body).not.toHaveTextContent('raw-sensitive-value');
    });
    it('shows German source/permission/failure states', async () => {
        setLocale('de', false); const v = endpointView(); v.latest!.interfaces = { meta: endpointFailed(), items: [] }; vi.mocked(request).mockResolvedValue(v); render(<Harness/>); await screen.findByText('fixture-linux'); expect(screen.getByText('Erfassung fehlgeschlagen: Berechtigung verweigert')).toBeVisible(); fireEvent.click(screen.getByText('Quelle, Freigabe & Aufbewahrung')); expect(screen.getByText(/standardmäßig aus/)).toBeVisible();
    });
});

describe('endpoint identity lifecycle', () => {
    it('does not request while disabled or initially hidden', async () => {
        const { rerender } = render(<Harness enabled={false}/>); expect(request).not.toHaveBeenCalled();
        vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden'); rerender(<Harness/>); expect(request).not.toHaveBeenCalled();
    });
    it.each(['pagehide', 'blur', 'hashchange'] as const)('clears on %s and aborts a pending request with late results ignored', async event => {
        let finish!: (v: EndpointIdentityView) => void; let signal!: AbortSignal;
        vi.mocked(request).mockImplementation((_path, options) => { signal = options!.signal as AbortSignal; return new Promise(resolve => { finish = resolve; }); }); render(<Harness/>); expect(signal.aborted).toBe(false);
        act(() => window.dispatchEvent(new Event(event))); expect(signal.aborted).toBe(true); await act(async () => finish(endpointView())); expect(screen.queryByText('fixture-linux')).not.toBeInTheDocument();
    });
    it('hides on visibility change and reads again only on return', async () => {
        let visibility: DocumentVisibilityState = 'visible'; vi.spyOn(document, 'visibilityState', 'get').mockImplementation(() => visibility); render(<Harness/>); await screen.findByText('fixture-linux');
        act(() => { visibility = 'hidden'; document.dispatchEvent(new Event('visibilitychange')); }); expect(screen.queryByText('fixture-linux')).not.toBeInTheDocument(); expect(request).toHaveBeenCalledTimes(1);
        act(() => { visibility = 'visible'; document.dispatchEvent(new Event('visibilitychange')); }); await screen.findByText('fixture-linux'); expect(request).toHaveBeenCalledTimes(2);
    });
    it('locks on authentication loss and does not refetch on pageshow/focus or refresh', async () => {
        render(<Harness/>); await screen.findByText('fixture-linux'); act(() => window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT))); expect(screen.queryByText('fixture-linux')).not.toBeInTheDocument(); expect(screen.getByRole('alert')).toHaveTextContent('Your session has ended.');
        act(() => { window.dispatchEvent(new Event('focus')); const show = new Event('pageshow'); Object.defineProperty(show, 'persisted', { value: true }); window.dispatchEvent(show); }); expect(request).toHaveBeenCalledTimes(1); expect(screen.getByRole('button', { name: 'Refresh reported identity' })).toBeDisabled();
    });
    it('binds in-flight responses to device and session; unmount aborts', async () => {
        let finish!: (v: EndpointIdentityView) => void; let signal!: AbortSignal; vi.mocked(request).mockImplementationOnce((_path, options) => { signal = options!.signal as AbortSignal; return new Promise(resolve => { finish = resolve; }); });
        const { rerender, unmount } = render(<Harness/>); const second = 'agent_second'; vi.mocked(request).mockResolvedValue({ ...emptyEndpointView(), deviceId: second }); rerender(<Harness id={second}/>); expect(signal.aborted).toBe(true); await act(async () => finish(endpointView())); expect(screen.queryByText('fixture-linux')).not.toBeInTheDocument();
        let lastSignal!: AbortSignal; vi.mocked(request).mockImplementation((_path, options) => { lastSignal = options!.signal as AbortSignal; return new Promise(() => {}); }); rerender(<Harness id={second} session="new-session"/>); expect(lastSignal.aborted).toBe(false); unmount(); expect(lastSignal.aborted).toBe(true);
    });
    it('fails closed on manager clock rollback across refresh', async () => {
        vi.mocked(request).mockResolvedValueOnce(endpointView()).mockResolvedValueOnce({ ...endpointView(), serverNow: '2026-10-04T12:00:09Z' }); render(<Harness/>); await screen.findByText('fixture-linux'); fireEvent.click(screen.getByRole('button', { name: 'Refresh reported identity' })); await screen.findByRole('alert'); expect(screen.getByRole('alert')).toHaveTextContent('time anchor'); expect(screen.queryByText('fixture-linux')).not.toBeInTheDocument();
    });
    it('ages fresh data to stale then removes it at original expiry without polling or refreshing age', async () => {
        vi.useFakeTimers(); const wall = Date.now(); vi.spyOn(performance, 'now').mockImplementation(() => Date.now() - wall); const v = endpointView(); v.serverNow = '2026-10-04T12:01:59Z'; vi.mocked(request).mockResolvedValue(v); render(<Harness/>); await act(async () => {}); expect(screen.getByText('Recent observation')).toBeVisible();
        await act(async () => { vi.advanceTimersByTime(2000); }); expect(screen.getByText('Stale / historical observation')).toBeVisible();
        const remaining = 86400000 - 121000; await act(async () => { vi.advanceTimersByTime(remaining); }); expect(screen.queryByText('fixture-linux')).not.toBeInTheDocument(); expect(screen.getByText('Observation or device identity expired')).toBeVisible(); expect(request).toHaveBeenCalledTimes(1);
    });
    it('clears immediately on a wall-clock jump', async () => {
        vi.useFakeTimers(); let mono = 0; vi.spyOn(performance, 'now').mockImplementation(() => mono); render(<Harness/>); await act(async () => {}); expect(screen.getByText('fixture-linux')).toBeVisible();
        act(() => { vi.setSystemTime(Date.now() + 100000); mono += 1000; vi.advanceTimersByTime(1000); }); expect(screen.getByRole('alert')).toHaveTextContent('time anchor'); expect(screen.queryByText('fixture-linux')).not.toBeInTheDocument();
    });
    it('times out and cannot install a late response', async () => {
        vi.useFakeTimers(); const wall = Date.now(); vi.spyOn(performance, 'now').mockImplementation(() => Date.now() - wall); let finish!: (v: EndpointIdentityView) => void, signal!: AbortSignal;
        vi.mocked(request).mockImplementation((_path, options) => { signal = options!.signal as AbortSignal; return new Promise(resolve => { finish = resolve; }); }); render(<Harness/>);
        await act(async () => { vi.advanceTimersByTime(10000); }); expect(signal.aborted).toBe(true); expect(screen.getByRole('alert')).toHaveTextContent('timed out'); await act(async () => finish(endpointView())); expect(screen.queryByText('fixture-linux')).not.toBeInTheDocument();
    });
    it('handles 401 and busy errors without leaking server messages', async () => {
        vi.mocked(request).mockRejectedValue(new APIError('sensitive', 429)); render(<Harness/>); await screen.findByRole('alert'); expect(screen.getByRole('alert')).toHaveTextContent('manager is busy'); vi.mocked(request).mockRejectedValue(new APIError('sensitive', 401)); fireEvent.click(screen.getByRole('button', { name: 'Refresh reported identity' })); await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('session has ended')); expect(document.body).not.toHaveTextContent('sensitive');
    });
});

describe('roomy device page identity integration', () => {
    it('uses a reported hostname in the header while keeping stable cryptographic ID and suppressing legacy single-IP', async () => {
        vi.mocked(request).mockImplementation(async path => path.endsWith('/inventory/endpoint-identity') ? endpointView() : device()); render(<DeviceDetail id={endpointDevice} onClose={vi.fn()} onCase={vi.fn()}/>);
        await screen.findByRole('heading', { name: 'fixture-linux', level: 1 }); fireEvent.click(screen.getByRole('tab', { name: 'Details' })); expect(screen.getByText('Stable cryptographic device ID')).toBeVisible(); expect(screen.getAllByText(endpointDevice).length).toBeGreaterThan(0); expect(document.body).not.toHaveTextContent('198.51.100.250'); expect(screen.queryByText('IP address')).not.toBeInTheDocument();
        act(() => window.dispatchEvent(new Event('blur'))); expect(screen.queryByRole('heading', { name: 'fixture-linux', level: 1 })).not.toBeInTheDocument(); expect(screen.getByRole('heading', { name: endpointDevice, level: 1 })).toBeVisible();
    });
    it.each(['unauthenticated', 'development', 'synthetic', 'non-linux'] as const)('does not acquire the extension for %s pages', async state => {
        const d = device(); if (state === 'unauthenticated') vi.mocked(useOperator).mockReturnValue({ ...operator, authenticated: false }); if (state === 'development') vi.mocked(useOperator).mockReturnValue({ ...operator, mode: 'development' }); if (state === 'synthetic') d.synthetic = true; if (state === 'non-linux') d.platform = 'windows'; vi.mocked(request).mockResolvedValue(d); render(<DeviceDetail id={endpointDevice} onClose={vi.fn()} onCase={vi.fn()}/>); await screen.findByRole('heading', { name: endpointDevice, level: 1 }); expect(request).toHaveBeenCalledTimes(1); expect(screen.queryByRole('heading', { name: 'Hostname & interface addresses' })).not.toBeInTheDocument();
    });
});
