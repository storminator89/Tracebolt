import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, APIError, AUTH_REQUIRED_EVENT, mutateRaw, request } from './api';
import { LOGOUT_INTENT_KEY, useOperator } from './auth';
import { setLocale } from './i18n';
import { AlarmSettingsPanel } from './alarm-settings';
import { AlarmStatusPanel } from './alarm-status';
import { ALARM_ENDPOINT_MAX, ALARM_SETTINGS_BYTES, createAlarmTestRequestId, validAlarmEndpoint, validAlarmSettings } from './alarm-settings-types';
import type { AlarmSettings } from './alarm-settings-types';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutateRaw: vi.fn() }));
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
const operator = { mode: 'lan' as const, authenticated: true, expiresAt: '2026-10-06T14:00:00Z', insecureTestMode: false, logout: vi.fn(), theme: 'light' as const, setTheme: vi.fn() };
const revision = 'a'.repeat(32), nextRevision = 'b'.repeat(32), eventId = 'c'.repeat(64);
const empty = (): AlarmSettings => ({ schemaVersion: 'tracebolt.alarm-settings.v1', mode: 'managed', revision, configured: false, enabled: false, destinationHost: '', test: null, blocked: false });
const configured = (): AlarmSettings => ({ ...empty(), configured: true, enabled: true, destinationHost: 'hooks.example.com' });
const queued = (): AlarmSettings => ({ ...configured(), test: { eventId, state: 'queued', createdAt: '2026-10-06T12:00:00Z' } });
const destination = 'https://hooks.example.com/private-secret?key=private-token';
const flush = () => act(async () => {}), advance = (ms: number) => act(async () => { await vi.advanceTimersByTimeAsync(ms); });
const button = (name: string) => screen.getByRole('button', { name });
const panel = () => screen.getByRole('region', { name: 'Alarm setup' });
const refresh = () => button('Refresh alarm setup');
const open = () => fireEvent.click(button('Alarm setup'));
const input = () => screen.getByLabelText('New webhook URL (write-only)');
const acknowledgePayload = () => fireEvent.click(screen.getByRole('checkbox', { name: /I allow future alarm payloads/ }));
function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(done => { resolve = done; }); return { resolve, promise }; }
async function start(value: unknown = configured()) { vi.mocked(request).mockResolvedValue(value); const mounted = render(<AlarmSettingsPanel/>); await flush(); return mounted; }
async function replace(value: unknown = configured()) { const mounted = await start(value); open(); fireEvent.click(button((value as AlarmSettings).configured ? 'Replace destination' : 'Add destination')); fireEvent.change(input(), { target: { value: destination } }); acknowledgePayload(); return mounted; }
function mutation() { return JSON.parse(vi.mocked(mutateRaw).mock.calls.at(-1)![1]) as Record<string, unknown>; }
beforeEach(() => {
    vi.useFakeTimers(); vi.setSystemTime('2026-10-06T12:00:00Z'); localStorage.clear(); sessionStorage.clear(); setLocale('en', false);
    vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('visible'); vi.mocked(useOperator).mockReturnValue(operator); vi.mocked(request).mockReset(); vi.mocked(mutateRaw).mockReset();
});
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });

describe('strict sanitized settings contract', () => {
    it('accepts settings, public host/IP readbacks and all test states', () => {
        expect(validAlarmSettings(empty())).toBe(true); expect(validAlarmSettings(configured())).toBe(true);
        for (const host of ['hooks.example.com', '8.8.8.8', '2606:4700:4700::1111', '[2606:4700:4700::1111]']) expect(validAlarmSettings({ ...configured(), destinationHost: host })).toBe(true);
        for (const mode of ['external', 'unavailable']) expect(validAlarmSettings({ ...empty(), mode, revision: '' })).toBe(true);
        for (const state of ['queued', 'in_flight', 'provider_accepted', 'failed', 'uncertain', 'suppressed']) expect(validAlarmSettings({ ...queued(), test: { ...queued().test, state } })).toBe(true);
    });
    it.each([null, [], {}, { ...empty(), revision: '' }, { ...empty(), revision: 'A'.repeat(32) }, { ...empty(), mode: 'external' }, { ...empty(), schemaVersion: 'v2' }, { ...empty(), enabled: true }, { ...configured(), configured: false }, { ...configured(), destinationHost: '' }, { ...configured(), endpoint: destination }, { ...configured(), token: 'private' }, { ...configured(), destinationHost: destination }, { ...configured(), destinationHost: 'hooks.example.com:443' }, { ...configured(), destinationHost: 'secret@hooks.example.com' }, { ...configured(), destinationHost: 'x'.repeat(254) }, { ...configured(), blocked: 'false' }, { ...configured(), blocked: true }, { ...configured(), mode: 'unavailable', revision: '' }, { ...empty(), mode: 'unavailable', revision: '', blocked: true }, { ...empty(), test: queued().test }, { ...queued(), test: { ...queued().test, endpoint: destination } }, { ...queued(), test: { ...queued().test, eventId: 'bad' } }, { ...queued(), test: { ...queued().test, createdAt: 'today' } }, { ...queued(), test: { ...queued().test, state: 'delivered' } }])('rejects malformed or secret-bearing responses %j', value => expect(validAlarmSettings(value)).toBe(false));
    it.each(['', 'http://example.com/a', 'https://example.com:8443/a', 'https://user:pass@example.com/a', 'https://example.com/#fragment', 'https://example.com/#', 'https://example.com/ä', 'https://@example.com/', 'https://EXAMPLE.com/', ' https://example.com', 'https://example.com/with space', 'https://example.com\\other', 'https://example.com/\nprivate', 'https://example.com/' + 'a'.repeat(ALARM_ENDPOINT_MAX)])('rejects invalid replacement URL %s', value => expect(validAlarmEndpoint(value)).toBe(false));
    it('accepts a complete HTTPS 443 URL with an embedded path/query secret and generates bounded random test IDs', () => {
        expect(validAlarmEndpoint(destination)).toBe(true); expect(validAlarmEndpoint('https://example.com:443/hook')).toBe(true);
        const one = createAlarmTestRequestId(), two = createAlarmTestRequestId(); expect(one).toMatch(/^[0-9a-f]{32}$/); expect(two).not.toBe(one);
    });
});

describe('quiet rendering and permission boundaries', () => {
    it('starts collapsed with only sanitized host/status and a bounded GET', async () => {
        await start(); expect(button('Alarm setup')).toHaveAttribute('aria-expanded', 'false'); expect(panel()).toHaveTextContent('hooks.example.com · On');
        expect(panel().querySelector('input,form')).toBeNull(); expect(panel()).not.toHaveTextContent('Slack');
        expect(request).toHaveBeenCalledExactlyOnceWith('/alerts/settings', { signal: expect.any(AbortSignal), cache: 'no-store' }, ALARM_SETTINGS_BYTES); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('shows an unconfigured state and explicit add flow', async () => {
        await start(empty()); expect(panel()).toHaveTextContent('No destination'); open(); expect(button('Add destination')).toBeEnabled();
        expect(screen.queryByRole('button', { name: 'Enable alarms' })).toBeNull(); expect(screen.queryByRole('button', { name: 'Test destination' })).toBeNull();
    });
    it.each([null, { ...operator, mode: 'development' as const }, { ...operator, authenticated: false }])('neither renders nor requests outside authenticated LAN access', async value => {
        vi.mocked(useOperator).mockReturnValue(value); await start(); expect(screen.queryByRole('region')).toBeNull(); expect(request).not.toHaveBeenCalled();
    });
    it('lets named readers see host/status but no mutation form', async () => {
        vi.mocked(useOperator).mockReturnValue({ ...operator, loginMode: 'named', actorId: `operator_${revision}`, capabilities: ['read'] });
        await start(); open(); expect(panel()).toHaveTextContent('requires alarm-management permission'); expect(screen.queryByRole('button', { name: 'Replace destination' })).toBeNull(); expect(panel().querySelector('input')).toBeNull();
    });
    it('allows named alarm managers independently of other operational capabilities', async () => {
        vi.mocked(useOperator).mockReturnValue({ ...operator, loginMode: 'named', actorId: `operator_${revision}`, capabilities: ['read', 'manage_alarms'] });
        await start(); open(); expect(button('Replace destination')).toBeEnabled();
    });
    it.each(['external', 'unavailable'] as const)('keeps %s configuration read-only even for a manager', async mode => {
        await start({ ...(mode === 'external' ? configured() : empty()), mode, revision: '' }); open(); expect(screen.queryByRole('button', { name: 'Replace destination' })).toBeNull();
        expect(panel()).toHaveTextContent(mode === 'external' ? 'settings file' : 'unavailable on this manager'); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('blocks mutable controls when storage/configuration is blocked', async () => {
        await start({ ...configured(), enabled: false, blocked: true }); open(); expect(screen.getByRole('alert')).toHaveTextContent('blocked alarm changes'); expect(screen.queryByRole('button', { name: 'Replace destination' })).toBeNull();
    });
    it('changes visible copy to German without another request or resetting the entered URL', async () => {
        await replace(); act(() => setLocale('de', false)); expect(screen.getByRole('region', { name: 'Alarme einrichten' })).toHaveTextContent('Keine Logs, Hostnamen');
        expect(screen.getByLabelText('Neue Webhook-URL (nur Eingabe)')).toHaveValue(destination); expect(button('Speichern und aktivieren')).toBeEnabled(); expect(request).toHaveBeenCalledTimes(1);
    });
});

describe('explicit bounded mutations', () => {
    it('requires a new secret and payload acknowledgement, then saves the exact replacement once without testing', async () => {
        await start(); open(); fireEvent.click(button('Replace destination')); expect(input()).toHaveAttribute('type', 'password'); expect(input()).toHaveAttribute('autocomplete', 'off'); expect(input()).toHaveValue(''); expect(button('Save and enable')).toBeDisabled();
        acknowledgePayload(); expect(button('Save and enable')).toBeDisabled(); fireEvent.change(input(), { target: { value: destination } }); expect(button('Save and enable')).toBeEnabled();
        const held = deferred<AlarmSettings>(); vi.mocked(mutateRaw).mockReturnValue(held.promise); const save = button('Save and enable'); fireEvent.click(save); fireEvent.click(save);
        expect(mutateRaw).toHaveBeenCalledTimes(1); expect(mutation()).toEqual({ expectedRevision: revision, operation: 'replace', endpoint: destination, payloadSharingAcknowledged: true, plaintextAcknowledged: false });
        expect(vi.mocked(mutateRaw).mock.calls[0]).toEqual(['/alerts/settings', expect.any(String), {}, expect.any(AbortSignal), ALARM_SETTINGS_BYTES]);
        expect(panel().querySelector('input')).toBeNull(); expect(panel()).not.toHaveTextContent('private-secret'); expect(refresh()).toBeDisabled();
        await act(async () => held.resolve({ ...configured(), revision: nextRevision })); expect(panel()).toHaveTextContent('Settings saved. No test was sent.');
        fireEvent.click(button('Replace destination')); expect(input()).toHaveValue(''); await advance(120000); expect(mutateRaw).toHaveBeenCalledTimes(1); expect(request).toHaveBeenCalledTimes(1);
    });
    it('keeps invalid URL values disabled without echoing them into errors', async () => {
        await replace(); fireEvent.change(input(), { target: { value: 'http://example.com/private-secret' } }); expect(button('Save and enable')).toBeDisabled(); expect(screen.getByRole('alert')).not.toHaveTextContent('private-secret');
    });
    it('requires the additional plaintext risk acknowledgement only in HTTP-test mode', async () => {
        vi.mocked(useOperator).mockReturnValue({ ...operator, insecureTestMode: true }); await replace(); expect(button('Save and enable')).toBeDisabled();
        fireEvent.click(screen.getByRole('checkbox', { name: /I understand this isolated HTTP-test/ })); vi.mocked(mutateRaw).mockResolvedValue(configured()); fireEvent.click(button('Save and enable')); await flush(); expect(mutation().plaintextAcknowledged).toBe(true);
    });
    it('enables a retained destination with an empty endpoint and fresh payload acknowledgement', async () => {
        await start({ ...configured(), enabled: false }); open(); fireEvent.click(button('Enable alarms')); expect(panel().querySelector('input[type=password]')).toBeNull(); expect(button('Confirm enable')).toBeDisabled();
        acknowledgePayload(); vi.mocked(mutateRaw).mockResolvedValue({ ...configured(), revision: nextRevision }); fireEvent.click(button('Confirm enable')); await flush();
        expect(mutation()).toEqual({ expectedRevision: revision, operation: 'enable', endpoint: '', payloadSharingAcknowledged: true, plaintextAcknowledged: false });
    });
    it('disables only after explicit confirmation and retains the destination', async () => {
        await start(); open(); fireEvent.click(button('Disable alarms')); expect(mutateRaw).not.toHaveBeenCalled(); expect(panel()).toHaveTextContent('retain the saved destination'); expect(panel().querySelector('input')).toBeNull();
        vi.mocked(mutateRaw).mockResolvedValue({ ...configured(), enabled: false, revision: nextRevision }); fireEvent.click(button('Confirm disable')); await flush();
        expect(mutation()).toEqual({ expectedRevision: revision, operation: 'disable', endpoint: '', payloadSharingAcknowledged: false, plaintextAcknowledged: false }); expect(panel()).toHaveTextContent('hooks.example.com · Off'); expect(button('Enable alarms')).toBeEnabled();
    });
    it('sends only an acknowledged synthetic test with a unique ID, and requires explicit refresh for its result', async () => {
        await start(); open(); fireEvent.click(button('Test destination')); expect(mutateRaw).not.toHaveBeenCalled(); expect(panel()).toHaveTextContent('no live device information'); expect(button('Confirm and send test')).toBeDisabled();
        fireEvent.click(screen.getByRole('checkbox', { name: 'Send this synthetic test to the saved destination now.' })); vi.mocked(mutateRaw).mockResolvedValue(queued()); fireEvent.click(button('Confirm and send test')); await flush();
        expect(mutation()).toEqual({ expectedRevision: revision, requestId: expect.stringMatching(/^[0-9a-f]{32}$/), testAcknowledged: true }); expect(vi.mocked(mutateRaw).mock.calls[0][0]).toBe('/alerts/test'); expect(button('Test destination')).toBeDisabled();
        expect(panel()).toHaveTextContent('Test request recorded'); await advance(120000); expect(request).toHaveBeenCalledTimes(1); expect(mutateRaw).toHaveBeenCalledTimes(1);
        vi.mocked(request).mockResolvedValue({ ...queued(), test: { ...queued().test, state: 'provider_accepted' } }); fireEvent.click(refresh()); await flush(); expect(panel()).toHaveTextContent('Provider accepted'); expect(panel()).toHaveTextContent('does not confirm receipt by a person'); expect(button('Test destination')).toBeEnabled();
    });
    it('withholds a second test until the one-minute limit and a fresh explicit read', async () => {
        await start({ ...queued(), test: { ...queued().test, state: 'failed' } }); open(); expect(button('Test destination')).toBeDisabled(); expect(panel()).toHaveTextContent('Wait at least one minute');
        await advance(60001); expect(button('Test destination')).toBeDisabled(); fireEvent.click(refresh()); await flush(); expect(button('Test destination')).toBeEnabled();
    });
    it('never automatically replays uncertain tests', async () => {
        await start({ ...queued(), test: { ...queued().test, state: 'uncertain' } }); open(); expect(panel()).toHaveTextContent('Uncertain tests are never automatically replayed'); await advance(180000); expect(mutateRaw).not.toHaveBeenCalled(); expect(request).toHaveBeenCalledTimes(1);
    });
    it('clears the form and stops if secure random ID generation fails', async () => {
        await start(); open(); fireEvent.click(button('Test destination')); fireEvent.click(screen.getByRole('checkbox')); vi.spyOn(crypto, 'getRandomValues').mockImplementation(() => { throw new Error('private error'); }); fireEvent.click(button('Confirm and send test'));
        expect(screen.getByRole('alert')).toHaveTextContent('secure test ID'); expect(mutateRaw).not.toHaveBeenCalled(); expect(panel().querySelector('input')).toBeNull();
    });
    it('closes and clears on Escape, returning focus to the compact heading', async () => {
        await replace(); input().focus(); fireEvent.keyDown(input(), { key: 'Escape' }); expect(button('Alarm setup')).toHaveFocus(); expect(button('Alarm setup')).toHaveAttribute('aria-expanded', 'false');
        open(); fireEvent.click(button('Replace destination')); expect(input()).toHaveValue(''); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it.each(['Reset form', 'Cancel', 'Close', 'Alarm setup'])('clears secrets and acknowledgements on %s', async action => {
        await replace(); fireEvent.click(button(action)); if (action === 'Close' || action === 'Alarm setup') open(); if (action !== 'Reset form') fireEvent.click(button('Replace destination'));
        expect(input()).toHaveValue(''); expect(screen.getByRole('checkbox')).not.toBeChecked(); expect(mutateRaw).not.toHaveBeenCalled();
    });
});

describe('interruption, uncertainty and lifecycle safety', () => {
    it.each([409, 429, 500, 400] as const)('requires refresh after HTTP %s and does not expose raw server text', async status => {
        await replace(); vi.mocked(mutateRaw).mockRejectedValue(new APIError('https://private.invalid/SECRET', status)); fireEvent.click(button('Save and enable')); await flush();
        expect(screen.getByRole('alert')).toBeInTheDocument(); expect(panel()).not.toHaveTextContent('SECRET'); expect(panel().querySelector('input')).toBeNull(); expect(screen.queryByRole('button', { name: 'Replace destination' })).toBeNull();
        await advance(180000); expect(mutateRaw).toHaveBeenCalledTimes(1); expect(request).toHaveBeenCalledTimes(1);
        vi.mocked(request).mockResolvedValue({ ...configured(), revision: nextRevision }); fireEvent.click(refresh()); await flush(); fireEvent.click(button('Replace destination')); expect(input()).toHaveValue('');
        fireEvent.change(input(), { target: { value: destination } }); acknowledgePayload(); vi.mocked(mutateRaw).mockResolvedValue(configured()); fireEvent.click(button('Save and enable')); await flush(); expect(mutation().expectedRevision).toBe(nextRevision);
    });
    it.each(['timeout', 'invalid', 'clock'] as const)('treats a %s write outcome as uncertain and never replays it', async kind => {
        await replace(); const held = deferred<unknown>(); vi.mocked(mutateRaw).mockReturnValue(held.promise); fireEvent.click(button('Save and enable'));
        if (kind === 'timeout') await advance(10000);
        if (kind === 'invalid') await act(async () => held.resolve({ ...configured(), endpoint: destination }));
        if (kind === 'clock') { vi.setSystemTime('2026-10-06T15:00:00Z'); await act(async () => held.resolve(configured())); }
        expect(screen.getByRole('alert')).toHaveTextContent('may have taken effect'); expect(vi.mocked(mutateRaw).mock.calls[0][3]!.aborted).toBe(true); expect(panel()).not.toHaveTextContent('private-secret');
        await advance(120000); expect(mutateRaw).toHaveBeenCalledTimes(1);
    });
    it.each(['pagehide', 'visibility', 'hashchange', 'popstate', 'close', 'unmount'] as const)('cancels a write and rejects late results after %s', async kind => {
        const mounted = await replace(); const held = deferred<AlarmSettings>(); vi.mocked(mutateRaw).mockReturnValue(held.promise); fireEvent.click(button('Save and enable')); const signal = vi.mocked(mutateRaw).mock.calls[0][3]!;
        if (kind === 'unmount') mounted.unmount(); else if (kind === 'close') fireEvent.click(button('Close')); else if (kind === 'visibility') { vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden'); act(() => document.dispatchEvent(new Event('visibilitychange'))); } else act(() => window.dispatchEvent(new Event(kind)));
        expect(signal.aborted).toBe(true); await act(async () => held.resolve({ ...configured(), revision: nextRevision })); expect(document.querySelector('input')).toBeNull(); expect(document.body).not.toHaveTextContent('Settings saved');
        if (kind !== 'unmount') { expect(screen.getByRole('alert')).toHaveTextContent('may have taken effect'); expect(button('Alarm setup')).toHaveAttribute('aria-expanded', 'false'); }
        await advance(120000); expect(mutateRaw).toHaveBeenCalledTimes(1);
    });
    it.each(['event', 'epoch', 'storage', 'logout', '401', '403'] as const)('clears secrets and locks the panel after %s access loss', async kind => {
        await replace(); const held = deferred<AlarmSettings>();
        if (kind === '401' || kind === '403') { vi.mocked(mutateRaw).mockRejectedValue(new APIError('private auth error', Number(kind))); fireEvent.click(button('Save and enable')); }
        else { vi.mocked(request).mockReturnValue(held.promise); act(() => { if (kind === 'event') window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT)); if (kind === 'epoch') abortProtectedRequests(); if (kind === 'storage' || kind === 'logout') { localStorage.setItem(LOGOUT_INTENT_KEY, '1'); if (kind === 'storage') window.dispatchEvent(new StorageEvent('storage', { key: LOGOUT_INTENT_KEY, newValue: '1' })); } }); }
        await advance(1000); await act(async () => held.resolve(configured())); expect(panel().querySelector('input')).toBeNull(); expect(refresh()).toBeDisabled(); expect(panel()).not.toHaveTextContent('hooks.example.com'); expect(screen.getByRole('alert')).toHaveTextContent('Sign in again');
    });
    it('cancels an old session and drops the form on capability removal', async () => {
        const mounted = await replace(); const held = deferred<AlarmSettings>(); vi.mocked(mutateRaw).mockReturnValue(held.promise); fireEvent.click(button('Save and enable')); const signal = vi.mocked(mutateRaw).mock.calls[0][3]!;
        vi.mocked(useOperator).mockReturnValue({ ...operator, loginMode: 'named', actorId: `operator_${revision}`, capabilities: ['read'] }); mounted.rerender(<AlarmSettingsPanel/>); await flush(); expect(signal.aborted).toBe(true); await act(async () => held.resolve(configured()));
        expect(button('Alarm setup')).toHaveAttribute('aria-expanded', 'false'); open(); expect(screen.queryByRole('button', { name: 'Replace destination' })).toBeNull(); expect(panel()).not.toHaveTextContent('Settings saved');
    });
    it('never polls or overlaps refresh and clears edits when explicitly refreshing', async () => {
        await replace(); await advance(180000); expect(request).toHaveBeenCalledTimes(1); const held = deferred<AlarmSettings>(); vi.mocked(request).mockReturnValueOnce(held.promise); fireEvent.click(refresh()); fireEvent.click(refresh());
        expect(request).toHaveBeenCalledTimes(2); expect(refresh()).toBeDisabled(); expect(panel().querySelector('input')).toBeNull(); await act(async () => held.resolve(configured())); expect(refresh()).toBeEnabled();
    });
    it('resumes after page restore only through an explicit refresh', async () => {
        await replace(); act(() => window.dispatchEvent(new Event('pagehide'))); act(() => window.dispatchEvent(new Event('pageshow'))); await advance(60000); expect(request).toHaveBeenCalledTimes(1); expect(panel().querySelector('input')).toBeNull();
        fireEvent.click(refresh()); await flush(); expect(request).toHaveBeenCalledTimes(2); expect(button('Alarm setup')).toHaveAttribute('aria-expanded', 'false');
    });
    it('rejects late timed-out read/write replies after a newer refresh', async () => {
        await replace(); const held = deferred<AlarmSettings>(); vi.mocked(mutateRaw).mockReturnValueOnce(held.promise); fireEvent.click(button('Save and enable')); await advance(10000);
        vi.mocked(request).mockResolvedValue({ ...configured(), destinationHost: 'new.example.com', revision: nextRevision }); fireEvent.click(refresh()); await flush(); await act(async () => held.resolve(configured()));
        expect(panel()).toHaveTextContent('new.example.com'); expect(panel()).not.toHaveTextContent('hooks.example.com');
    });
    it('fails closed on a malformed settings response without showing its URL', async () => {
        await start({ ...configured(), destinationHost: destination }); expect(screen.getByRole('alert')).toHaveTextContent('unsupported alarm settings'); open(); expect(panel()).not.toHaveTextContent('private-secret'); expect(panel().querySelector('input')).toBeNull();
    });
    it('allows manual recovery from a failed GET without auto-retry', async () => {
        vi.mocked(request).mockRejectedValue(new Error('private')); render(<AlarmSettingsPanel/>); await flush(); await advance(30000); expect(request).toHaveBeenCalledTimes(1); expect(screen.getByRole('alert')).toHaveTextContent('could not be confirmed');
        vi.mocked(request).mockResolvedValue(empty()); fireEvent.click(refresh()); await flush(); expect(panel()).toHaveTextContent('No destination');
    });
});

describe('real same-origin API transport', () => {
    it('uses a bounded same-origin GET and never requests the destination', async () => {
        const real = await vi.importActual<typeof import('./api')>('./api'); vi.mocked(request).mockImplementation(real.request); const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify(configured()), { status: 200 })); vi.stubGlobal('fetch', fetch);
        render(<AlarmSettingsPanel/>); await flush(); expect(panel()).toHaveTextContent('hooks.example.com'); expect(fetch).toHaveBeenCalledExactlyOnceWith('/api/alerts/settings', expect.objectContaining({ credentials: 'same-origin', cache: 'no-store', headers: { Accept: 'application/json' } }));
    });
    it('rejects oversized actual settings bodies before rendering them', async () => {
        const real = await vi.importActual<typeof import('./api')>('./api'); vi.mocked(request).mockImplementation(real.request); vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ ...configured(), secret: 'PRIVATE'.repeat(1000) }), { status: 200 })));
        render(<AlarmSettingsPanel/>); await flush(); expect(screen.getByRole('alert')).toBeInTheDocument(); expect(panel()).not.toHaveTextContent('PRIVATE');
    });
    it('uses same-origin CSRF plus one bounded fixed-path POST without provider contact', async () => {
        await replace(); const real = await vi.importActual<typeof import('./api')>('./api'); vi.mocked(mutateRaw).mockImplementation(real.mutateRaw);
        const fetch = vi.fn().mockResolvedValueOnce(new Response(JSON.stringify({ csrfToken: 'fixture-csrf' }), { status: 200 })).mockResolvedValueOnce(new Response(JSON.stringify({ ...configured(), revision: nextRevision }), { status: 200 })); vi.stubGlobal('fetch', fetch);
        fireEvent.click(button('Save and enable')); await flush(); expect(fetch.mock.calls.map(call => call[0])).toEqual(['/api/session', '/api/alerts/settings']);
        expect(fetch.mock.calls[1][1]).toEqual(expect.objectContaining({ method: 'POST', credentials: 'same-origin', headers: { Accept: 'application/json', 'Content-Type': 'application/json', 'X-CSRF-Token': 'fixture-csrf' } })); expect(panel()).toHaveTextContent('Settings saved');
    });
    it('does not POST if session access is revoked between CSRF and mutation', async () => {
        await replace(); const real = await vi.importActual<typeof import('./api')>('./api'); vi.mocked(mutateRaw).mockImplementation(real.mutateRaw); const held = deferred<Response>(); const fetch = vi.fn().mockReturnValue(held.promise); vi.stubGlobal('fetch', fetch);
        fireEvent.click(button('Save and enable')); act(() => abortProtectedRequests()); await act(async () => held.resolve(new Response(JSON.stringify({ csrfToken: 'fixture-csrf' }), { status: 200 }))); await advance(1000);
        expect(fetch).toHaveBeenCalledTimes(1); expect(refresh()).toBeDisabled(); expect(panel()).not.toHaveTextContent('Settings saved');
    });
});


describe('composed alarm panels after confirmed local mutations', () => {
    const status = (enabled = false, queuedCount = 0, accepted = 0) => ({ schemaVersion: 'tracebolt.alarm-status.v1', enabled, queued: queuedCount, inFlight: 0, providerAccepted: accepted, failed: 0, uncertain: 0, suppressed: 0, dropped: 0 });
    const delivery = () => screen.getByRole('region', { name: 'Alarm delivery' });
    const mode = () => delivery().querySelector('.alarm-mode');
    const statusReads = () => vi.mocked(request).mock.calls.filter(call => call[0] === '/alerts/status');
    const compose = async () => { render(<><AlarmStatusPanel/><AlarmSettingsPanel/></>); await flush(); };
    const fillNew = () => { open(); fireEvent.click(button('Add destination')); fireEvent.change(input(), { target: { value: destination } }); acknowledgePayload(); };
    it('reads actual status after a confirmed save, shows no optimistic On, and never replays the write', async () => {
        const fresh = deferred<unknown>(), saved = deferred<AlarmSettings>(); let reads = 0;
        vi.mocked(request).mockImplementation(async path => path === '/alerts/settings' ? empty() : ++reads === 1 ? status() : fresh.promise);
        vi.mocked(mutateRaw).mockReturnValue(saved.promise); await compose(); expect(mode()).toHaveTextContent('Off'); fillNew();
        fireEvent.click(button('Save and enable')); await flush(); expect(statusReads()).toHaveLength(1); expect(mode()).toHaveTextContent('Off'); expect(mutateRaw).toHaveBeenCalledTimes(1);
        await act(async () => saved.resolve({ ...configured(), revision: nextRevision })); expect(statusReads()).toHaveLength(2); expect(mode()).toHaveTextContent('Unknown'); expect(delivery()).toHaveTextContent('Previous snapshot');
        expect(mutateRaw).toHaveBeenCalledTimes(1); expect(vi.mocked(mutateRaw).mock.calls[0][0]).toBe('/alerts/settings');
        await act(async () => fresh.resolve(status(true, 2))); expect(mode()).toHaveTextContent('On'); expect(delivery().querySelector('.alarm-counts div:nth-child(2) dd')).toHaveTextContent('2');
        await advance(1000); expect(statusReads()).toHaveLength(2); expect(mutateRaw).toHaveBeenCalledTimes(1); expect(panel().querySelector('input')).toBeNull();
    });
    it('keeps previous counts and unknown current status when the follow-up read fails, with read-only explicit recovery', async () => {
        let reads = 0;
        vi.mocked(request).mockImplementation(async path => { if (path === '/alerts/settings') return empty(); reads++; if (reads === 2) throw new APIError('Synthetic status failure', 503); return status(reads > 1, 0, 7); });
        vi.mocked(mutateRaw).mockResolvedValue({ ...configured(), revision: nextRevision }); await compose(); fillNew(); fireEvent.click(button('Save and enable')); await flush();
        expect(mode()).toHaveTextContent('Unknown'); expect(delivery()).toHaveTextContent('Previous snapshot'); expect(delivery()).toHaveTextContent('Alarm status could not be confirmed'); expect(delivery().querySelector('.alarm-counts dd')).toHaveTextContent('7');
        await advance(1000); expect(statusReads()).toHaveLength(2); expect(mutateRaw).toHaveBeenCalledTimes(1);
        fireEvent.click(button('Refresh alarm status')); await flush(); expect(statusReads()).toHaveLength(3); expect(mode()).toHaveTextContent('On'); expect(mutateRaw).toHaveBeenCalledTimes(1);
    });
    it('cancels a pre-change read so its late result cannot overwrite the confirmed mutation status', async () => {
        const old = deferred<unknown>(); let reads = 0;
        vi.mocked(request).mockImplementation(async path => path === '/alerts/settings' ? empty() : ++reads === 1 ? old.promise : status(true, 1));
        vi.mocked(mutateRaw).mockResolvedValue({ ...configured(), revision: nextRevision }); await compose(); const oldSignal = statusReads()[0][1]?.signal;
        fillNew(); fireEvent.click(button('Save and enable')); await flush(); expect(oldSignal?.aborted).toBe(true); expect(statusReads()).toHaveLength(2); expect(mode()).toHaveTextContent('On');
        await act(async () => old.resolve(status(false))); expect(mode()).toHaveTextContent('On'); expect(delivery().querySelector('.alarm-counts div:nth-child(2) dd')).toHaveTextContent('1'); expect(mutateRaw).toHaveBeenCalledTimes(1);
    });
    it('refreshes counts only after the explicit test mutation is confirmed and does not send another test', async () => {
        let reads = 0; vi.mocked(request).mockImplementation(async path => path === '/alerts/settings' ? configured() : status(true, ++reads > 1 ? 1 : 0));
        vi.mocked(mutateRaw).mockResolvedValue(queued()); await compose(); open(); fireEvent.click(button('Test destination')); expect(statusReads()).toHaveLength(1); expect(mutateRaw).not.toHaveBeenCalled();
        fireEvent.click(screen.getByRole('checkbox', { name: 'Send this synthetic test to the saved destination now.' })); fireEvent.click(button('Confirm and send test')); await flush();
        expect(statusReads()).toHaveLength(2); expect(delivery().querySelector('.alarm-counts div:nth-child(2) dd')).toHaveTextContent('1'); expect(mutateRaw).toHaveBeenCalledTimes(1); expect(vi.mocked(mutateRaw).mock.calls[0][0]).toBe('/alerts/test');
        await advance(1000); expect(statusReads()).toHaveLength(2); expect(mutateRaw).toHaveBeenCalledTimes(1);
    });
});
