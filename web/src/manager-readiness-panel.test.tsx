import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, AUTH_REQUIRED_EVENT, getProtectedRequestEpoch } from './api';
import { LOGOUT_INTENT_KEY } from './auth';
import { setLocale } from './i18n';
import { MANAGER_READINESS_COMPONENTS, MANAGER_READINESS_UNASSESSED } from './manager-readiness-model';
import type { ManagerReadinessView } from './manager-readiness-model';
import { ManagerReadinessPanel } from './manager-readiness-panel';
import { readManagerReadiness } from './manager-readiness-resource';

const NOW = '2026-11-04T00:00:00Z', SESSION = '2026-11-04T01:00:00Z';
function fixture(): ManagerReadinessView {
    return { schemaVersion: 'tracebolt.manager-readiness.v1', scope: 'core_reads_and_last_worker_steps', status: 'ready', serverNow: NOW,
        components: MANAGER_READINESS_COMPONENTS.map(component => ({ component, state: component.endsWith('_step') ? 'succeeded' : 'ready', checkedAt: NOW })), unassessed: [...MANAGER_READINESS_UNASSESSED],
        certificateLifetimes: ['server_chain', 'enrollment_issuer', 'enrollment_root'].map(role => ({ role, state: 'valid', validFrom: '2026-01-01T00:00:00Z', validUntil: '2027-01-01T00:00:00Z' })) as ManagerReadinessView['certificateLifetimes'] };
}
function response(value: unknown = fixture(), status = 200, headers: Record<string, string> = {}): Response {
    return new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json; charset=utf-8', ...headers } });
}
const open = () => fireEvent.click(screen.getByRole('button', { name: 'Inspect manager checks and certificate dates' }));
async function flush() { await act(async () => { for (let i = 0; i < 25; i++) await Promise.resolve(); }); }
async function advance(ms: number) { await act(async () => { await vi.advanceTimersByTimeAsync(ms); }); }
beforeEach(() => {
    vi.useFakeTimers({ toFake: ['Date', 'performance', 'setTimeout', 'clearTimeout', 'setInterval', 'clearInterval'] });
    vi.setSystemTime(Date.parse(NOW)); setLocale('en', false); abortProtectedRequests();
    localStorage.clear(); sessionStorage.clear();
    Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' });
    vi.stubGlobal('fetch', vi.fn(async () => response()));
});
afterEach(() => { cleanup(); abortProtectedRequests(); vi.unstubAllGlobals(); vi.restoreAllMocks(); vi.useRealTimers(); });

describe('bounded manager readiness transport', () => {
    it('reads only the exact same-origin GET with no-store and no redirects', async () => {
        const controller = new AbortController();
        expect(await readManagerReadiness(controller.signal)).toEqual(fixture());
        expect(fetch).toHaveBeenCalledExactlyOnceWith('/api/manager/readiness', { method: 'GET', credentials: 'same-origin', cache: 'no-store', redirect: 'error', headers: { Accept: 'application/json' }, signal: controller.signal });
    });
    it('preserves validated unavailable evidence from 503, including certificate dates', async () => {
        const view = fixture(); view.status = 'unavailable'; view.components[0].state = 'failed';
        vi.mocked(fetch).mockResolvedValueOnce(response(view, 503));
        expect(await readManagerReadiness(new AbortController().signal)).toEqual(view);
    });
    it.each([400, 403, 404, 500])('does not retain or surface raw error responses (%s)', async status => {
        vi.mocked(fetch).mockResolvedValueOnce(response({ error: { message: 'private filesystem path or secret' } }, status));
        await expect(readManagerReadiness(new AbortController().signal)).rejects.toThrow('Manager evidence unavailable');
    });
    it('rejects mismatched status, invalid JSON, type, oversized declared and streamed bodies', async () => {
        const cases = [response(fixture(), 503), response({ ...fixture(), secret: 'must not render' }), new Response('{', { headers: { 'Content-Type': 'application/json' } }), response(fixture(), 200, { 'Content-Type': 'text/html' }), response(fixture(), 200, { 'Content-Length': '32769' }), response({ padding: 'ü'.repeat(20000) })];
        for (const value of cases) {
            vi.mocked(fetch).mockResolvedValueOnce(value);
            await expect(readManagerReadiness(new AbortController().signal)).rejects.toThrow();
        }
    });
    it('invalidates protected access on a current 401, without reading its error body', async () => {
        const before = getProtectedRequestEpoch(), event = vi.fn(); window.addEventListener(AUTH_REQUIRED_EVENT, event);
        vi.mocked(fetch).mockResolvedValueOnce(response({ private: 'no display' }, 401));
        await expect(readManagerReadiness(new AbortController().signal)).rejects.toThrow('Inactive manager read');
        expect(getProtectedRequestEpoch()).toBe(before + 1); expect(event).toHaveBeenCalledOnce();
        window.removeEventListener(AUTH_REQUIRED_EVENT, event);
    });
    it('does not let an obsolete 401 invalidate a newer access epoch', async () => {
        let finish!: (value: Response) => void;
        vi.mocked(fetch).mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
        const pending = readManagerReadiness(new AbortController().signal); abortProtectedRequests(); const current = getProtectedRequestEpoch();
        finish(response({}, 401)); await expect(pending).rejects.toThrow('Inactive manager read');
        expect(getProtectedRequestEpoch()).toBe(current);
    });
    it('withholds a delayed response after request abortion or logout intent', async () => {
        for (const reason of ['abort', 'logout']) {
            let finish!: (value: Response) => void;
            vi.mocked(fetch).mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
            const controller = new AbortController(), pending = readManagerReadiness(controller.signal);
            if (reason === 'abort') controller.abort(); else localStorage.setItem(LOGOUT_INTENT_KEY, '1');
            finish(response()); await expect(pending).rejects.toThrow('Inactive manager read'); localStorage.clear();
        }
    });
    it('rejects streamed JSON when access changes during its body read', async () => {
        let stream!: ReadableStreamDefaultController<Uint8Array>;
        const body = new ReadableStream<Uint8Array>({ start(controller) { stream = controller; } });
        vi.mocked(fetch).mockResolvedValueOnce(new Response(body, { headers: { 'Content-Type': 'application/json' } }));
        const pending = readManagerReadiness(new AbortController().signal);
        stream.enqueue(new TextEncoder().encode('{')); await flush(); abortProtectedRequests();
        stream.enqueue(new TextEncoder().encode(JSON.stringify(fixture()).slice(1))); stream.close();
        await expect(pending).rejects.toThrow('Inactive manager read');
    });
});

describe('private on-demand manager status panel', () => {
    it('starts collapsed, then shows all exact checks, limits and certificate dates without mutations', async () => {
        render(<ManagerReadinessPanel sessionKey={SESSION}/>); expect(fetch).not.toHaveBeenCalled();
        open(); await flush();
        expect(screen.getByText('Recorded checks passed')).toHaveAttribute('data-manager-state', 'ready');
        expect(screen.getByRole('table')).toHaveAccessibleName('Core checks and last worker evidence');
        expect(screen.getAllByRole('row')).toHaveLength(15);
        expect(screen.getAllByText('One step succeeded')).toHaveLength(3);
        expect(screen.getAllByText('More than 30 days remaining')).toHaveLength(3);
        expect(screen.getByText('Full store integrity')).toBeInTheDocument();
        const original = screen.getByText('Original manager read:').querySelector('time'); expect(original).toHaveAttribute('datetime', NOW);
        expect(fetch).toHaveBeenCalledTimes(1); expect(vi.mocked(fetch).mock.calls.every(([, options]) => options?.method === 'GET')).toBe(true);
    });
    it('displays the 503 source failure rather than an empty success or transport error', async () => {
        const view = fixture(); view.status = 'unavailable'; view.components.find(row => row.component === 'windows_health_worker')!.state = 'failed';
        vi.mocked(fetch).mockResolvedValueOnce(response(view, 503)); render(<ManagerReadinessPanel sessionKey={SESSION}/>); open(); await flush();
        expect(screen.getByText('Configured checks unavailable')).toBeInTheDocument(); expect(screen.getByText('Failed')).toBeInTheDocument();
        expect(screen.getAllByText('More than 30 days remaining')).toHaveLength(3); expect(screen.queryByText(/could not be read/)).not.toBeInTheDocument();
    });
    it('keeps omitted certificate evidence unknown in a valid busy fallback', async () => {
        const view: ManagerReadinessView = { ...fixture(), status: 'unavailable', components: [{ component: 'probe', state: 'busy' }] }; delete view.certificateLifetimes;
        vi.mocked(fetch).mockResolvedValueOnce(response(view, 503)); render(<ManagerReadinessPanel sessionKey={SESSION}/>); open(); await flush();
        expect(screen.getByText('Busy')).toBeInTheDocument(); expect(screen.getAllByText('Current validity unknown')).toHaveLength(3); expect(screen.queryByText('Not configured')).not.toBeInTheDocument();
    });
    it('ages the original evidence without polling or restamping any time', async () => {
        render(<ManagerReadinessPanel sessionKey={SESSION}/>); open(); await flush(); await advance(5250);
        expect(screen.getByText('Snapshot is stale')).toBeInTheDocument(); expect(screen.getAllByText('Stale evidence')).toHaveLength(14);
        expect(screen.getAllByText('Current validity unknown')).toHaveLength(3); expect(fetch).toHaveBeenCalledTimes(1);
        expect(screen.getAllByTitle(NOW).length).toBe(15);
    });
    it('does not renew a stalled manager clock on manual refresh or close/reopen', async () => {
        render(<ManagerReadinessPanel sessionKey={SESSION}/>); open(); await flush(); await advance(6000);
        fireEvent.click(screen.getByRole('button', { name: 'Refresh manager status' })); await flush();
        expect(screen.getByText('Snapshot is stale')).toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', { name: 'Close manager status' })); open(); await flush();
        expect(screen.getByText('Snapshot is stale')).toBeInTheDocument(); expect(fetch).toHaveBeenCalledTimes(3);
    });
    it('fails closed on manager rollback and session expiry', async () => {
        const mounted = render(<ManagerReadinessPanel sessionKey={SESSION}/>); open(); await flush();
        const backwards = fixture(); backwards.serverNow = '2026-11-03T23:59:59Z'; backwards.components.forEach(row => { row.checkedAt = backwards.serverNow; });
        vi.mocked(fetch).mockResolvedValueOnce(response(backwards)); fireEvent.click(screen.getByRole('button', { name: 'Refresh manager status' })); await flush();
        expect(screen.queryByRole('table')).not.toBeInTheDocument(); expect(screen.getByText(/could not be read or validated/)).toBeInTheDocument();
        mounted.unmount(); abortProtectedRequests();
        render(<ManagerReadinessPanel sessionKey="2026-11-04T00:00:02Z"/>); open(); await flush(); await advance(2000);
        expect(screen.queryByRole('table')).not.toBeInTheDocument(); expect(screen.getByText(/snapshot or session expired/)).toBeInTheDocument();
    });
    it('clears private evidence on a browser wall/monotonic clock disagreement', async () => {
        render(<ManagerReadinessPanel sessionKey={SESSION}/>); open(); await flush();
        vi.setSystemTime(Date.parse(NOW) + 10000); await advance(250);
        expect(screen.queryByRole('table')).not.toBeInTheDocument(); expect(screen.getByText(/snapshot or session expired/)).toBeInTheDocument(); expect(fetch).toHaveBeenCalledTimes(1);
    });
    it('removes the retained snapshot after two minutes without a background refresh', async () => {
        render(<ManagerReadinessPanel sessionKey={SESSION}/>); open(); await flush(); await advance(119750);
        expect(screen.getByRole('table')).toBeInTheDocument(); expect(screen.getByText('Snapshot is stale')).toBeInTheDocument();
        await advance(250); expect(screen.queryByRole('table')).not.toBeInTheDocument(); expect(screen.getByText(/snapshot or session expired/)).toBeInTheDocument(); expect(fetch).toHaveBeenCalledTimes(1);
    });
    it('accepts genuinely advancing manager checks on deliberate refresh', async () => {
        render(<ManagerReadinessPanel sessionKey={SESSION}/>); open(); await flush(); await advance(6000);
        const next = fixture(); next.serverNow = '2026-11-04T00:00:06Z'; next.components.forEach(row => { row.checkedAt = next.serverNow; });
        vi.mocked(fetch).mockResolvedValueOnce(response(next)); fireEvent.click(screen.getByRole('button', { name: 'Refresh manager status' })); await flush();
        expect(screen.getByText('Recorded checks passed')).toBeInTheDocument(); expect(screen.getAllByTitle(next.serverNow)).toHaveLength(15); expect(fetch).toHaveBeenCalledTimes(2);
    });
    it('clears on blur/hidden and requires deliberate refresh on focus, with no background reads', async () => {
        render(<ManagerReadinessPanel sessionKey={SESSION}/>); open(); await flush(); fireEvent(window, new Event('blur'));
        expect(screen.queryByRole('table')).not.toBeInTheDocument(); expect(screen.getByText(/cleared while this view was inactive/)).toBeInTheDocument();
        fireEvent(window, new Event('focus')); await advance(1000); expect(fetch).toHaveBeenCalledTimes(1);
        fireEvent.click(screen.getByRole('button', { name: 'Refresh manager status' })); await flush(); expect(screen.getByRole('table')).toBeInTheDocument();
        Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'hidden' }); fireEvent(document, new Event('visibilitychange'));
        expect(screen.queryByRole('table')).not.toBeInTheDocument(); expect(fetch).toHaveBeenCalledTimes(2);
    });
    it('allows explicit refresh after pagehide/pageshow without automatically reading', async () => {
        render(<ManagerReadinessPanel sessionKey={SESSION}/>); open(); await flush();
        fireEvent(window, new Event('pagehide')); expect(screen.queryByRole('table')).not.toBeInTheDocument();
        fireEvent(window, new Event('pageshow')); await flush(); expect(fetch).toHaveBeenCalledTimes(1);
        fireEvent.click(screen.getByRole('button', { name: 'Refresh manager status' })); await flush(); expect(screen.getByRole('table')).toBeInTheDocument(); expect(fetch).toHaveBeenCalledTimes(2);
    });
    it.each(['authentication', 'logout', 'navigation'])('ends private evidence on %s loss', async reason => {
        render(<ManagerReadinessPanel sessionKey={SESSION}/>); open(); await flush();
        if (reason === 'authentication') fireEvent(window, new Event(AUTH_REQUIRED_EVENT));
        else if (reason === 'logout') { localStorage.setItem(LOGOUT_INTENT_KEY, '1'); await advance(250); }
        else fireEvent(window, new Event('popstate'));
        expect(screen.queryByRole('table')).not.toBeInTheDocument(); expect(screen.getByRole('button', { name: 'Refresh manager status' })).toBeDisabled();
        expect(fetch).toHaveBeenCalledTimes(1);
    });
    it('aborts collapsed and obsolete session reads and never resurrects late private data', async () => {
        let finish!: (value: Response) => void, signal!: AbortSignal;
        vi.mocked(fetch).mockImplementationOnce((_, options) => { signal = options!.signal as AbortSignal; return new Promise(resolve => { finish = resolve; }); });
        const mounted = render(<ManagerReadinessPanel sessionKey={SESSION}/>); open(); await flush();
        fireEvent.click(screen.getByRole('button', { name: 'Close manager status' })); expect(signal.aborted).toBe(true);
        finish(response()); await flush(); expect(screen.queryByRole('table')).not.toBeInTheDocument();
        open(); await flush(); expect(screen.getByRole('table')).toBeInTheDocument();
        mounted.rerender(<ManagerReadinessPanel sessionKey={null}/>); await flush(); expect(screen.queryByRole('table')).not.toBeInTheDocument();
    });
    it('bounds a stalled request and does not automatically retry', async () => {
        vi.mocked(fetch).mockImplementationOnce(() => new Promise(() => {})); render(<ManagerReadinessPanel sessionKey={SESSION}/>); open(); await flush();
        expect(screen.getByRole('button', { name: 'Refresh manager status' })).toBeDisabled(); fireEvent.click(screen.getByRole('button', { name: 'Refresh manager status' })); expect(fetch).toHaveBeenCalledTimes(1); await advance(10000);
        expect(screen.getByText(/could not be read or validated/)).toBeInTheDocument(); expect(screen.getByRole('button', { name: 'Refresh manager status' })).toBeEnabled();
        await advance(30000); expect(fetch).toHaveBeenCalledTimes(1);
    });
    it('renders German labels and does not read without a valid session', async () => {
        setLocale('de', false); render(<ManagerReadinessPanel sessionKey={null}/>);
        fireEvent.click(screen.getByRole('button', { name: 'Managerprüfungen und Zertifikatsdaten ansehen' })); await flush();
        expect(fetch).not.toHaveBeenCalled(); expect(screen.getByText(/Zugriff beendet/)).toBeInTheDocument();
    });
});
