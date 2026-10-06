import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, APIError, AUTH_REQUIRED_EVENT, hasPendingAPIRequests, request } from './api';
import { LOGOUT_INTENT_KEY, useOperator } from './auth';
import { ApplicationChecksPanel } from './application-checks';
import { applicationNow, applicationView } from './application-checks-fixtures';
import { applicationDNSRow, applicationHTTPRow, applicationTCPRow, applicationViewV2, disabledApplicationViewV2 } from './application-checks-v2-fixtures';
import { APPLICATION_CHECKS_BYTES } from './application-checks-types';
import type { ApplicationChecksViewV2 } from './application-checks-types';
import { setLocale } from './i18n';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), hasPendingAPIRequests: vi.fn(), request: vi.fn() }));
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
const operator = { mode: 'lan' as const, authenticated: true, expiresAt: '2026-10-06T14:00:00Z', insecureTestMode: false, logout: vi.fn(), theme: 'light' as const, setTheme: vi.fn() };
const flush = () => act(async () => {}), advance = (ms: number) => act(async () => { await vi.advanceTimersByTimeAsync(ms); });
const refresh = () => screen.getByRole('button', { name: 'Reload application status' });
const panel = () => screen.getByRole('region', { name: 'Application checks' });
const successful = () => document.querySelectorAll('.application-ok, .application-tls-valid, .application-tls-expiring, .application-tls-expired');
const row = (id: string) => screen.getByText(id).closest('tr')!;
function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(done => { resolve = done; }); return { resolve, promise }; }
async function start() { const mounted = render(<ApplicationChecksPanel/>); await flush(); return mounted; }
beforeEach(() => {
    vi.useFakeTimers(); vi.setSystemTime(applicationNow); localStorage.clear(); sessionStorage.clear(); setLocale('en', false);
    vi.spyOn(document, 'hasFocus').mockReturnValue(true); vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('visible');
    vi.mocked(useOperator).mockReturnValue(operator); vi.mocked(hasPendingAPIRequests).mockReset().mockReturnValue(false); vi.mocked(request).mockReset().mockResolvedValue(applicationViewV2());
});
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.restoreAllMocks(); });

describe('compact mixed-kind retained observations', () => {
    it('separates HTTP/HTTPS, DNS resolution and TCP connection with neutral certificate cells', async () => {
        vi.mocked(request).mockResolvedValue(applicationViewV2([...applicationViewV2().items, applicationHTTPRow({ id: 'fixture-plain', targetScheme: 'http', tls: { state: 'not_applicable', expiresAt: null } })]));
        await start(); const content = panel();
        expect(content.querySelectorAll('tbody tr')).toHaveLength(4);
        expect(within(content).getByRole('columnheader', { name: 'Result' })).toBeInTheDocument();
        expect(content).toHaveTextContent('HTTP/TLS, DNS and TCP observations from the management server.');
        expect(row('fixture-app')).toHaveTextContent('HTTPS'); expect(row('fixture-app')).toHaveTextContent('204 · 2xx'); expect(row('fixture-app')).toHaveTextContent('Expiring soon');
        expect(row('fixture-plain')).toHaveTextContent('HTTP · plaintext'); expect(row('fixture-plain')).toHaveTextContent('No TLS');
        for (const [id, kind, result] of [['fixture-dns', 'DNS', 'Resolved'], ['fixture-tcp', 'TCP', 'Connected']]) {
            const check = row(id);
            expect(check.querySelector('th small')).toHaveTextContent(kind); expect(check).toHaveTextContent(result);
            expect(within(check).getByRole('img', { name: 'Certificate is not part of this check' })).toHaveTextContent('—');
            expect(check.querySelectorAll('time')).toHaveLength(1); expect(check.querySelector('.application-expiry')).toBeNull(); expect(check).not.toHaveTextContent('No TLS');
            expect(check.querySelector('td:last-child time')).toHaveAttribute('datetime', applicationNow);
        }
        expect(content).toHaveTextContent('system hostname resolution'); expect(content).toHaveTextContent('hosts file, cache or search domains');
        expect(content).toHaveTextContent('All returned addresses must be approved'); expect(content).toHaveTextContent('not an authoritative or complete DNS record set');
        expect(content).toHaveTextContent('one connection to a numeric address and close, without data or TLS'); expect(content).toHaveTextContent('does not establish application health');
        expect(content.querySelector('a,input,select')).toBeNull(); expect(within(content).getAllByRole('button')).toHaveLength(1);
        expect(vi.mocked(request).mock.calls[0]).toEqual(['/application-checks/status', { signal: expect.any(AbortSignal), cache: 'no-store' }, APPLICATION_CHECKS_BYTES]);
    });

    it('renders German success, failure and scope labels without another read', async () => {
        vi.mocked(request).mockResolvedValue(applicationViewV2([applicationDNSRow(), applicationTCPRow(), { ...applicationTCPRow(), id: 'fixture-failed', state: 'network_error', reason: 'tcp_failed' }]));
        await start(); act(() => setLocale('de', false)); const content = screen.getByRole('region', { name: 'Anwendungsprüfungen' });
        expect(content).toHaveTextContent('Aufgelöst'); expect(content).toHaveTextContent('Verbunden'); expect(content).toHaveTextContent('TCP-Verbindung fehlgeschlagen');
        expect(within(content).getByRole('columnheader', { name: 'Prüfergebnis' })).toBeInTheDocument();
        expect(within(content).getAllByLabelText('Zertifikat nicht Teil dieser Prüfung')).toHaveLength(3);
        expect(content).toHaveTextContent('System-Namensauflösung'); expect(content).toHaveTextContent('kein autoritativer oder vollständiger DNS-Datensatz');
        expect(content).toHaveTextContent('keine Anwendungsfunktion'); expect(content).toHaveTextContent('vor 0 s'); expect(request).toHaveBeenCalledTimes(1);
    });

    it.each([
        ['dns_failed', 'DNS failed', 'DNS fehlgeschlagen'], ['timeout', 'Timed out', 'Zeitüberschreitung'],
        ['tcp_failed', 'TCP connection failed', 'TCP-Verbindung fehlgeschlagen'], ['destination_blocked', 'Destination blocked', 'Ziel gesperrt'],
        ['cancelled', 'Canceled', 'Abgebrochen'], ['invalid_configuration', 'Invalid configuration', 'Ungültige Konfiguration'],
    ] as const)('labels %s precisely in English and German', async (reason, english, german) => {
        const state = ['dns_failed', 'timeout', 'tcp_failed'].includes(reason) ? 'network_error' : 'unknown';
        // Validate the actual JSON path, including its per-kind state/reason checks.
        vi.mocked(request).mockResolvedValue({ ...applicationViewV2(), items: [{ ...applicationTCPRow(), state, reason }], maxAgeSeconds: 70 });
        await start(); expect(row('fixture-tcp')).toHaveTextContent(english); expect(successful()).toHaveLength(0);
        act(() => setLocale('de', false)); expect(row('fixture-tcp')).toHaveTextContent(german); expect(request).toHaveBeenCalledTimes(1);
    });

    it.each(['unchecked', 'stale', 'future'] as const)('keeps %s DNS/TCP unknown without fabricating HTTP or TLS', async kind => {
        const items = [applicationDNSRow(), applicationTCPRow()].map(value => kind === 'unchecked' ? { ...value, observedAt: null, state: 'unknown', reason: 'not_checked' } : { ...value, observedAt: kind === 'future' ? '2026-10-06T12:00:00.000000001Z' : '2026-10-06T11:00:00Z' });
        vi.mocked(request).mockResolvedValue({ ...applicationViewV2(), items, maxAgeSeconds: 75 });
        await start(); expect(successful()).toHaveLength(0); expect(panel().querySelector('.application-expiry')).toBeNull();
        expect(panel()).not.toHaveTextContent('Resolved'); expect(panel()).not.toHaveTextContent('Connected'); expect(panel()).not.toHaveTextContent('No TLS');
        expect(within(panel()).getAllByLabelText('Certificate is not part of this check')).toHaveLength(2);
        await advance(5000); expect(successful()).toHaveLength(0);
    });

    it('rejects one malformed mixed row and clears the entire prior generation', async () => {
        await start(); expect(successful()).toHaveLength(4);
        for (const patch of [{ httpStatus: null }, { tls: { state: 'not_applicable', expiresAt: null } }, { hostname: 'must-not-render.invalid' }, { state: 'ok', reason: 'tcp_connected' }]) {
            vi.mocked(request).mockResolvedValueOnce({ ...applicationViewV2(), items: [applicationHTTPRow(), { ...applicationDNSRow(), ...patch }, applicationTCPRow()] });
            fireEvent.click(refresh()); await flush(); expect(screen.getByRole('alert')).toHaveTextContent('Application status unavailable');
            expect(successful()).toHaveLength(0); expect(panel()).not.toHaveTextContent('fixture-'); expect(panel()).not.toHaveTextContent('must-not-render');
        }
    });
});

describe('v2 retained-status lifecycle regressions', () => {
    it('reads only the retained status route and does not overlap repeated reloads', async () => {
        await start(); const held = deferred<ApplicationChecksViewV2>(); vi.mocked(request).mockReturnValueOnce(held.promise);
        await advance(14999); expect(request).toHaveBeenCalledTimes(1); await advance(1); expect(request).toHaveBeenCalledTimes(2);
        fireEvent.click(refresh()); fireEvent.click(refresh()); expect(request).toHaveBeenCalledTimes(2); expect(refresh()).toBeDisabled();
        await act(async () => held.resolve(applicationViewV2())); fireEvent.click(refresh()); fireEvent.click(refresh()); await flush(); expect(request).toHaveBeenCalledTimes(3);
        expect(vi.mocked(request).mock.calls.every(([path]) => path === '/application-checks/status')).toBe(true);
    });

    it('retains age and clock watermarks across a v1/v2 upgrade and downgrade', async () => {
        vi.mocked(request).mockResolvedValue(applicationView()); await start(); await advance(60000);
        vi.mocked(request).mockResolvedValue(applicationViewV2()); fireEvent.click(refresh()); await flush(); expect(panel()).toHaveTextContent('Resolved');
        await advance(21000); expect(successful()).toHaveLength(0); expect(panel()).toHaveTextContent('Unknown · stale');
        vi.mocked(request).mockResolvedValue(applicationView()); fireEvent.click(refresh()); await flush(); expect(successful()).toHaveLength(0);
        expect(panel()).toHaveTextContent('Unknown · stale'); expect(panel().querySelector('td:last-child time')).toHaveAttribute('datetime', applicationNow);
    });

    it('ages all kinds between polls while yielding new reads to foreground API work', async () => {
        await start(); vi.mocked(hasPendingAPIRequests).mockReturnValue(true); await advance(81000);
        expect(request).toHaveBeenCalledTimes(1); expect(successful()).toHaveLength(0); expect(panel()).toHaveTextContent('Unknown · stale');
        fireEvent.click(refresh()); expect(request).toHaveBeenCalledTimes(1);
    });

    it('keeps the watermark through failed reads and rejects regressed server time', async () => {
        await start(); vi.mocked(request).mockRejectedValue(new Error('fixture-only')); await advance(81000);
        vi.mocked(request).mockResolvedValue({ ...applicationViewV2(), serverNow: '2026-10-06T11:59:59Z' }); fireEvent.click(refresh()); await flush();
        expect(screen.getByRole('alert')).toHaveTextContent('Application status unavailable'); expect(successful()).toHaveLength(0);
        vi.mocked(request).mockResolvedValue(applicationViewV2()); fireEvent.click(refresh()); await flush(); expect(successful()).toHaveLength(0); expect(panel()).toHaveTextContent('Unknown · stale');
    });

    it.each(['blur', 'pagehide', 'visibility'] as const)('aborts on %s and cannot rejuvenate evidence after resume', async event => {
        await start(); const held = deferred<ApplicationChecksViewV2>(); vi.mocked(request).mockReturnValueOnce(held.promise); fireEvent.click(refresh());
        const signal = vi.mocked(request).mock.calls[1][1]!.signal!;
        if (event === 'visibility') { vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden'); act(() => document.dispatchEvent(new Event('visibilitychange'))); }
        else act(() => window.dispatchEvent(new Event(event)));
        expect(signal.aborted).toBe(true); expect(successful()).toHaveLength(0); expect(panel()).not.toHaveTextContent('fixture-dns');
        await advance(81000); expect(request).toHaveBeenCalledTimes(2); await act(async () => held.resolve(applicationViewV2())); expect(successful()).toHaveLength(0);
        if (event === 'visibility') { vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('visible'); act(() => document.dispatchEvent(new Event('visibilitychange'))); }
        else act(() => window.dispatchEvent(new Event(event === 'pagehide' ? 'pageshow' : 'focus')));
        await advance(0); expect(request).toHaveBeenCalledTimes(3); expect(successful()).toHaveLength(0); expect(panel()).toHaveTextContent('Unknown · stale');
    });

    it.each(['event', 'epoch', 'logout'] as const)('clears all kinds and late reads on %s invalidation', async kind => {
        await start(); const held = deferred<ApplicationChecksViewV2>(); vi.mocked(request).mockReturnValueOnce(held.promise); fireEvent.click(refresh());
        act(() => { if (kind === 'event') window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT)); else if (kind === 'epoch') abortProtectedRequests(); else localStorage.setItem(LOGOUT_INTENT_KEY, '1'); });
        await advance(1000); await act(async () => held.resolve(applicationViewV2())); expect(successful()).toHaveLength(0); expect(panel()).not.toHaveTextContent('fixture-');
        await advance(60000); expect(request).toHaveBeenCalledTimes(2); expect(refresh()).toBeDisabled();
    });

    it('drops a timed-out reply after v2 disabled state wins and polls disabled slowly', async () => {
        await start(); const held = deferred<ApplicationChecksViewV2>(); vi.mocked(request).mockReturnValueOnce(held.promise); fireEvent.click(refresh());
        const signal = vi.mocked(request).mock.calls[1][1]!.signal!; await advance(10000); expect(signal.aborted).toBe(true); expect(successful()).toHaveLength(0);
        vi.mocked(request).mockResolvedValue(disabledApplicationViewV2()); fireEvent.click(refresh()); await flush(); await act(async () => held.resolve(applicationViewV2()));
        expect(panel()).toHaveTextContent('Disabled'); expect(screen.queryByRole('table')).not.toBeInTheDocument();
        await advance(59999); expect(request).toHaveBeenCalledTimes(3); await advance(1); expect(request).toHaveBeenCalledTimes(4);
    });

    it('clears mixed evidence after a local clock discontinuity', async () => {
        await start(); vi.setSystemTime('2026-10-06T11:00:00Z'); await advance(1000);
        expect(successful()).toHaveLength(0); expect(panel()).toHaveTextContent('Unknown · stale'); expect(panel().querySelector('.application-expiry')).toBeNull();
    });

    it('binds mixed evidence to the operator session and discards unmounted reads', async () => {
        await start(); const held = deferred<ApplicationChecksViewV2>(); vi.mocked(request).mockReturnValueOnce(held.promise); fireEvent.click(refresh());
        const signal = vi.mocked(request).mock.calls[1][1]!.signal!;
        cleanup(); expect(signal.aborted).toBe(true); await act(async () => held.resolve(applicationViewV2())); expect(screen.queryByRole('region')).not.toBeInTheDocument();
        vi.mocked(useOperator).mockReturnValue({ ...operator, actorId: 'operator_next', expiresAt: '2026-10-06T15:00:00Z' });
        vi.mocked(request).mockResolvedValue(disabledApplicationViewV2()); await start(); expect(panel()).toHaveTextContent('Disabled'); expect(successful()).toHaveLength(0);
    });

    it.each([401, 403, 404, 410])('treats denied status %i as terminal for mixed observations', async status => {
        await start(); vi.mocked(request).mockRejectedValue(new APIError('do-not-render', status)); fireEvent.click(refresh()); await flush();
        expect(refresh()).toBeDisabled(); expect(panel()).not.toHaveTextContent('fixture-'); expect(panel()).not.toHaveTextContent('do-not-render');
        await advance(200000); expect(request).toHaveBeenCalledTimes(2); expect(successful()).toHaveLength(0);
    });
});
