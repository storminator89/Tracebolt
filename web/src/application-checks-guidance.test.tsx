import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, APIError, hasPendingAPIRequests, request } from './api';
import { useOperator } from './auth';
import { ApplicationChecksPanel } from './application-checks';
import { applicationNow, applicationRow, applicationView, disabledApplicationView } from './application-checks-fixtures';
import { applicationDNSRow, applicationTCPRow, applicationViewV2, disabledApplicationViewV2 } from './application-checks-v2-fixtures';
import { setLocale } from './i18n';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), hasPendingAPIRequests: vi.fn(), request: vi.fn() }));
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
const operator = { mode: 'lan' as const, authenticated: true, expiresAt: '2026-10-06T14:00:00Z', insecureTestMode: false, logout: vi.fn(), theme: 'light' as const, setTheme: vi.fn() };
const guide = 'https://github.com/storminator89/Tracebolt/blob/bb76d6a6b7000b244b8075d5644562ad0da94c91/docs/application-checks.md';
const panel = () => screen.getByRole('region', { name: 'Application checks' });
const flush = () => act(async () => {});
async function start() { const mounted = render(<ApplicationChecksPanel/>); await flush(); return mounted; }
beforeEach(() => {
    vi.useFakeTimers(); vi.setSystemTime(applicationNow); localStorage.clear(); sessionStorage.clear(); setLocale('en', false);
    vi.spyOn(document, 'hasFocus').mockReturnValue(true); vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('visible');
    vi.mocked(useOperator).mockReturnValue(operator); vi.mocked(hasPendingAPIRequests).mockReset().mockReturnValue(false); vi.mocked(request).mockReset().mockResolvedValue(applicationView());
});
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.restoreAllMocks(); });

describe('read-only application-check setup guidance', () => {
    it.each([disabledApplicationView, disabledApplicationViewV2])('explains all supported kinds without inferring whether a disabled file exists (%#)', async fixture => {
        vi.mocked(request).mockResolvedValue(fixture()); await start();
        expect(panel()).toHaveTextContent('Disabled · no application checks running.');
        expect(panel()).not.toHaveTextContent('no application checks configured');
        expect(panel()).toHaveTextContent('Checks from the manager: HTTP/TLS, DNS, TCP.');
        expect(panel()).toHaveTextContent('Configure up to 8 HTTP/HTTPS, DNS or TCP targets on the manager.');
        const details = panel().querySelector('details')!;
        expect(details).not.toHaveAttribute('open');
        expect(details.querySelector('summary')).toHaveTextContent('Setup and approvals');
        expect(within(panel()).getByRole('link', { name: 'Add check' })).toBeVisible();
        expect(details).toHaveTextContent('Saving starts no checks');
        expect(details).not.toHaveTextContent('explicitly restart the manager');
        expect(details).toHaveTextContent('exact targets and IPs');
        expect(details).toHaveTextContent('private LAN and plaintext HTTP need separate approval');
        expect(details).toHaveTextContent('Side-effect-free targets without credentials');
        expect(details).toHaveTextContent('no alarms');
        expect(panel().querySelector('input,select,textarea,form,table,dl')).toBeNull();
        expect(within(panel()).getAllByRole('button')).toHaveLength(1);
        fireEvent.click(details.querySelector('summary')!); fireEvent.click(details.querySelector('summary')!);
        expect(request).toHaveBeenCalledTimes(1);
    });

    it.each([disabledApplicationView, applicationView])('links only fixed source guidance without sending the operator referrer (%#)', async fixture => {
        vi.mocked(request).mockResolvedValue(fixture()); await start();
        const links = panel().querySelectorAll('a[target="_blank"]'); expect(links).toHaveLength(1);
        if (!fixture().enabled) expect(within(panel()).getByRole('link', { name: 'Add check' })).toHaveAttribute('href', '#/settings/application-checks');
        expect(links[0]).toHaveTextContent('Startup-file guide (GitHub)'); expect(links[0]).toHaveAttribute('href', guide);
        expect(links[0]).toHaveAttribute('target', '_blank'); expect(links[0]).toHaveAttribute('rel', 'noopener noreferrer'); expect(links[0]).toHaveAttribute('referrerpolicy', 'no-referrer');
        expect(request).toHaveBeenCalledTimes(1);
    });

    it('gives named readers an administrator hint without exposing a settings editor', async () => {
        vi.mocked(useOperator).mockReturnValue({ ...operator, loginMode: 'named', actorId: `operator_${'a'.repeat(32)}`, capabilities: ['read'] });
        vi.mocked(request).mockResolvedValue(disabledApplicationView()); await start();
        expect(panel()).toHaveTextContent('An administrator can set up targets.');
        expect(within(panel()).queryByRole('link', { name: 'Add check' })).toBeNull();
        expect(vi.mocked(request).mock.calls.every(([path]) => path === '/application-checks/status')).toBe(true);
    });

    it.each([401, 403])('removes the direct entry after an authorization failure %i', async status => {
        vi.mocked(request).mockRejectedValue(new APIError('fixture', status)); await start();
        expect(within(panel()).queryByRole('link', { name: 'Add check' })).toBeNull();
        expect(screen.getByRole('button', { name: 'Reload application status' })).toBeDisabled();
    });

    it('localizes setup guidance without another request or storing approvals', async () => {
        vi.mocked(request).mockResolvedValue(disabledApplicationView()); await start();
        const previousStorage = { local: { ...localStorage }, session: { ...sessionStorage } };
        act(() => setLocale('de', false));
        const content = screen.getByRole('region', { name: 'Anwendungsprüfungen' });
        expect(content).toHaveTextContent('Deaktiviert · keine Anwendungsprüfungen aktiv.');
        expect(content).toHaveTextContent('Einrichtung und Freigaben'); expect(content).toHaveTextContent('LAN und unverschlüsseltes HTTP');
        expect(content.querySelector('a[target="_blank"]')).toHaveTextContent('Anleitung zur Startdatei (GitHub)');
        expect(request).toHaveBeenCalledTimes(1); expect({ local: { ...localStorage }, session: { ...sessionStorage } }).toEqual(previousStorage);
    });
});

describe('retained cadence, freshness and reason explanations', () => {
    it.each([60, 75, 3600])('shows exact completion-based cadence and freshness at %i seconds', async intervalSeconds => {
        const view = applicationViewV2([applicationDNSRow(), applicationTCPRow()]);
        vi.mocked(request).mockResolvedValue({ ...view, intervalSeconds, maxAgeSeconds: intervalSeconds + 15 }); await start();
        const timing = panel().querySelector('dl')!;
        expect(timing).toHaveTextContent(`Check interval${intervalSeconds}s after each round`);
        expect(timing).toHaveTextContent(`Freshness limit${intervalSeconds + 15}s`);
        expect(panel()).toHaveTextContent('Interval starts after each round');
        expect(panel()).toHaveTextContent('original times are preserved');
        expect(panel().querySelector('.application-checks-help')).toBeNull();
    });

    it('explains blocked destinations once without exposing destination data or adding controls', async () => {
        const row = { ...applicationTCPRow(), state: 'unknown' as const, reason: 'destination_blocked' as const };
        vi.mocked(request).mockResolvedValue(applicationViewV2([row, { ...row, id: 'second-blocked' }])); await start();
        const hints = panel().querySelectorAll('.application-checks-help li'); expect(hints).toHaveLength(1);
        expect(hints[0]).toHaveTextContent('all resolved IP addresses must match the exact allowlist and LAN approval');
        expect(panel().querySelector('input,select,textarea,form')).toBeNull();
        expect(within(panel()).getAllByRole('button')).toHaveLength(1);
        expect(vi.mocked(request).mock.calls.every(([path, init]) => path === '/application-checks/status' && !init?.method && !init?.body)).toBe(true);
    });

    it('updates stale explanation locally without rejuvenating original results', async () => {
        await start(); vi.mocked(hasPendingAPIRequests).mockReturnValue(true);
        expect(panel().querySelector('.application-checks-help')).toBeNull();
        await act(async () => { await vi.advanceTimersByTimeAsync(71000); });
        expect(panel()).toHaveTextContent('Stale or inconsistent observation times remain unknown. Reload does not start a check.');
        expect(panel().querySelector('td:last-child time')).toHaveAttribute('datetime', applicationNow);
        expect(panel().querySelector('.application-ok,.application-expiry')).toBeNull(); expect(request).toHaveBeenCalledTimes(1);
    });

    it('explains existing TLS verification rather than offering a bypass', async () => {
        vi.mocked(request).mockResolvedValue(applicationView([applicationRow({ state: 'tls_error', reason: 'tls_verification_failed', httpStatus: null, tls: { state: 'unknown', expiresAt: null } })])); await start();
        expect(panel().querySelector('.application-checks-help')).toHaveTextContent('review the hostname, certificate validity and existing manager trust store');
        expect(panel()).not.toHaveTextContent('disable verification');
    });

    it('clears cadence and reason help when a read fails or the session ends', async () => {
        vi.mocked(request).mockResolvedValue(applicationViewV2([{ ...applicationTCPRow(), state: 'network_error', reason: 'tcp_failed' }]));
        const mounted = await start(); expect(panel().querySelector('dl')).not.toBeNull(); expect(panel().querySelector('.application-checks-help')).not.toBeNull();
        vi.mocked(request).mockRejectedValueOnce(new Error('fixture'));
        fireEvent.click(screen.getByRole('button', { name: 'Reload application status' })); await flush();
        expect(panel().querySelector('dl,.application-checks-help,.application-checks-details')).toBeNull();
        expect(within(panel()).getByRole('link', { name: 'Add check' })).toHaveAttribute('href', '#/settings/application-checks');
        vi.mocked(useOperator).mockReturnValue({ ...operator, authenticated: false }); mounted.rerender(<ApplicationChecksPanel/>);
        expect(screen.queryByRole('region')).toBeNull();
    });
});
