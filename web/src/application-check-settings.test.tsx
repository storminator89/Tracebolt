import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, APIError, AUTH_REQUIRED_EVENT, mutateRaw, request } from './api';
import { LOGOUT_INTENT_KEY, useOperator, validOperatorSession } from './auth';
import { setLocale } from './i18n';
import { ApplicationCheckSettingsPanel } from './application-check-settings';
import { APPLICATION_CHECK_SETTINGS_BYTES, exactApplicationIP, validApplicationCheckSettings, validApplicationTarget, validApplicationURL } from './application-check-settings-types';
import type { ApplicationCheckSettings, ApplicationTarget } from './application-check-settings-types';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutateRaw: vi.fn() }));
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
const operator = { mode: 'lan' as const, authenticated: true, expiresAt: '2026-10-07T14:00:00Z', insecureTestMode: false, logout: vi.fn(), theme: 'light' as const, setTheme: vi.fn() };
const revision = 'a'.repeat(32), nextRevision = 'b'.repeat(32);
const http = (): ApplicationTarget => ({ kind: 'http', id: 'web', url: 'https://fixture.example.test/health', allowedAddresses: ['8.8.8.8'], allowPrivateLAN: false, plaintextHTTPAcknowledged: false });
const dns = (): ApplicationTarget => ({ kind: 'dns', id: 'dns', host: 'fixture.example.test', allowedAddresses: ['8.8.8.8'], allowPrivateLAN: false });
const tcp = (): ApplicationTarget => ({ kind: 'tcp', id: 'port', host: 'fixture.example.test', port: 443, allowedAddresses: ['8.8.8.8'], allowPrivateLAN: false });
const empty = (): ApplicationCheckSettings => ({ schemaVersion: 'tracebolt.application-check-settings.v1', mode: 'managed', revision, configured: false, enabled: false, blocked: false, intervalSeconds: 60, targets: [] });
const configured = (): ApplicationCheckSettings => ({ ...empty(), configured: true, targets: [http()] });
const on = (): ApplicationCheckSettings => ({ ...configured(), enabled: true });
const flush = () => act(async () => {}), advance = (ms: number) => act(async () => { await vi.advanceTimersByTimeAsync(ms); });
const button = (name: string) => screen.getByRole('button', { name });
const panel = () => screen.getByRole('region', { name: 'Application check setup' });
const refresh = () => button('Refresh application check setup');
const open = () => fireEvent.click(button('Application check setup'));
const input = (label: string) => screen.getByLabelText(label, { exact: true });
const fill = (label: string, value: string) => fireEvent.change(input(label), { target: { value } });
const manager = () => screen.getByRole('checkbox', { name: /^I understand these checks run/ });
const destinations = () => screen.getByRole('checkbox', { name: /^I approve recurring checks/ });
function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(done => { resolve = done; }); return { resolve, promise }; }
async function start(value: unknown = configured()) { vi.mocked(request).mockResolvedValue(value); const mounted = render(<ApplicationCheckSettingsPanel/>); await flush(); return mounted; }
async function edit(value: ApplicationCheckSettings = configured()) { const mounted = await start(value); open(); fireEvent.click(button(value.configured ? 'Edit targets' : 'Add targets')); return mounted; }
async function enable(value = configured()) { const mounted = await start(value); open(); fireEvent.click(button('Enable checks')); fireEvent.click(manager()); fireEvent.click(destinations()); return mounted; }
function mutation() { return JSON.parse(vi.mocked(mutateRaw).mock.calls.at(-1)![1]) as Record<string, unknown>; }
beforeEach(() => {
    vi.useFakeTimers(); vi.setSystemTime('2026-10-07T12:00:00Z'); localStorage.clear(); sessionStorage.clear(); setLocale('en', false);
    vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('visible'); vi.mocked(useOperator).mockReturnValue(operator); vi.mocked(request).mockReset(); vi.mocked(mutateRaw).mockReset();
});
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });

describe('strict bounded settings contract', () => {
    it('accepts all target kinds, canonical IPv6 and managed/external/unavailable states', () => {
        expect(validApplicationCheckSettings(empty())).toBe(true); expect(validApplicationCheckSettings(configured())).toBe(true); expect(validApplicationCheckSettings(on())).toBe(true);
        expect(validApplicationCheckSettings({ ...configured(), targets: [http(), dns(), tcp()] })).toBe(true);
        expect(validApplicationCheckSettings({ ...configured(), mode: 'external', revision: '' })).toBe(true);
        expect(validApplicationCheckSettings({ ...empty(), mode: 'unavailable', revision: '' })).toBe(true);
        expect(validApplicationTarget({ ...tcp(), host: '2606:4700:4700::1111', allowedAddresses: ['2606:4700:4700::1111'] })).toBe(true);
    });
    it.each([null, [], {}, { ...empty(), revision: '' }, { ...empty(), revision: 'A'.repeat(32) }, { ...empty(), schemaVersion: 'v2' }, { ...empty(), enabled: true }, { ...empty(), intervalSeconds: 75 }, { ...configured(), configured: false }, { ...configured(), targets: [] }, { ...configured(), secret: 'PRIVATE' }, { ...configured(), blocked: 'false' }, { ...on(), blocked: true }, { ...configured(), mode: 'unavailable', revision: '' }, { ...empty(), mode: 'unavailable', revision: '', blocked: true }, { ...configured(), intervalSeconds: 59 }, { ...configured(), intervalSeconds: 3601 }, { ...configured(), intervalSeconds: 60.5 }, { ...configured(), targets: [http(), http()] }, { ...configured(), targets: Array.from({ length: 9 }, (_, i) => ({ ...http(), id: `web${i}` })) }])('rejects malformed/contradictory responses %#', value => expect(validApplicationCheckSettings(value)).toBe(false));
    it.each([{ ...http(), headers: {} }, { ...http(), host: 'fixture.example.test' }, { ...dns(), port: 443 }, { ...tcp(), url: 'https://fixture.example.test' }, { ...dns(), plaintextHTTPAcknowledged: false }, { ...dns(), kind: 'udp' }, { ...tcp(), port: '443' }, { ...tcp(), port: 0 }, { ...tcp(), port: 65536 }, { ...http(), id: 'UPPER' }, { ...http(), allowedAddresses: [] }, { ...http(), allowedAddresses: ['8.8.8.8', '8.8.8.8'] }, { ...http(), allowedAddresses: ['10.0.0.1'] }, { ...http(), allowedAddresses: ['8.8.8.8/32'] }, { ...http(), url: 'https://8.8.4.4/' }, { ...dns(), host: '8.8.8.8' }, { ...http(), plaintextHTTPAcknowledged: true }, { ...http(), url: 'http://fixture.example.test' }, { ...http(), allowedAddresses: Array.from({ length: 17 }, (_, i) => `8.8.8.${i + 1}`) }])('rejects cross-kind, invalid and unsafe targets %#', value => expect(validApplicationTarget(value)).toBe(false));
    it.each(['127.0.0.1', '169.254.169.254', '0.0.0.0', '100.64.0.1', '168.63.129.16', '224.0.0.1', '192.0.2.1', '::1', 'fe80::1', 'fd00:ec2::254', 'fd20:ce::254', '2001:db8::1', '2002::1', '3fff::1'])('rejects excluded address %s even with private consent', ip => expect(validApplicationTarget({ ...dns(), allowedAddresses: [ip], allowPrivateLAN: true })).toBe(false));
    it.each(['8.8.8.08', '8.8.8.256', '8.8.8.8:443', '8.8.8.8/32', '[2606:4700:4700::1111]', '2606:4700:4700:0:0:0:0:1111', '::ffff:8.8.8.8', '::ffff:808:808', 'fe80::1%eth0', 'fixture.example.test'])('rejects nonexact address %s', value => expect(exactApplicationIP(value)).toBe(false));
    it.each(['https://user:pass@fixture.example.test/', 'https://fixture.example.test/?key=secret', 'https://fixture.example.test/#fragment', 'https://fixture.example.test/%61', 'https://fixture.example.test/a//b', 'https://fixture.example.test/a/../b', 'https://fixture.example.test:000443', 'https://FIXTURE.example.test', ' https://fixture.example.test', 'https://fixture.example.test/with space', 'https://fixture.example.test\\x', 'ftp://fixture.example.test'])('rejects unsupported URL %s', value => expect(validApplicationURL(value, false)).toBe(false));
    it.each(['<', '>', '"', '`', '{', '}', '|', '^'])('rejects noncanonical URL path character %s before sending', character => {
        const url = `https://fixture.example.test/x${character}y`;
        expect(validApplicationURL(url, false)).toBe(false); expect(validApplicationTarget({ ...http(), url })).toBe(false);
    });
    it.each(['123', '8.8.8.999'])('preserves valid server numeric-looking hostname %s without WHATWG rewriting', host => {
        expect(validApplicationTarget({ ...http(), url: `https://${host}/health` })).toBe(true);
    });
    it('supports only explicit private LAN and plaintext target approvals', () => {
        expect(validApplicationTarget({ ...http(), url: 'http://fixture.example.test/health', plaintextHTTPAcknowledged: true, allowedAddresses: ['10.2.3.4', 'fd00:1234::1'], allowPrivateLAN: true })).toBe(true);
    });
    it('accepts the new named capability without relaxing the strict auth allowlist', () => {
        const session = { mode: 'lan', transport: 'https', insecureTestMode: false, transportWarning: null, authenticationRequired: true, authenticated: true, csrfToken: 'fixture-csrf', serverNow: '2026-10-07T12:00:00Z', expiresAt: '2026-10-07T14:00:00Z', expiresInSeconds: 7200, loginMode: 'named', actorId: `operator_${revision}`, capabilities: ['read', 'plan_updates', 'execute_updates', 'restart_service', 'manage_alarms', 'manage_application_checks'] };
        expect(validOperatorSession(session)).toBe(true); expect(validOperatorSession({ ...session, capabilities: [...session.capabilities, 'admin'] })).toBe(false); expect(validOperatorSession({ ...session, capabilities: ['read', 'manage_application_checks', 'manage_application_checks'] })).toBe(false);
    });
});

describe('administrator-only settings', () => {
    it('starts collapsed with one bounded no-store GET and no polling or destination display', async () => {
        await start(); expect(button('Application check setup')).toHaveAttribute('aria-expanded', 'false'); expect(panel()).toHaveTextContent('1 · Off'); expect(panel()).not.toHaveTextContent('fixture.example.test'); expect(panel().querySelector('input,form')).toBeNull();
        expect(request).toHaveBeenCalledExactlyOnceWith('/application-checks/settings', { signal: expect.any(AbortSignal), cache: 'no-store' }, APPLICATION_CHECK_SETTINGS_BYTES); await advance(180000); expect(request).toHaveBeenCalledTimes(1); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it.each([null, { ...operator, mode: 'development' as const }, { ...operator, authenticated: false }])('does not mount/read without authenticated LAN access %#', async value => { vi.mocked(useOperator).mockReturnValue(value); await start(); expect(screen.queryByRole('region')).toBeNull(); expect(request).not.toHaveBeenCalled(); });
    it('does not request or expose admin destinations for named read-only or alarm-only operators', async () => {
        vi.mocked(useOperator).mockReturnValue({ ...operator, loginMode: 'named', actorId: `operator_${revision}`, capabilities: ['read', 'manage_alarms'] }); await start(); expect(panel()).toHaveTextContent('requires administrator permission'); expect(request).not.toHaveBeenCalled(); expect(panel().querySelector('button,input,form')).toBeNull(); expect(panel()).not.toHaveTextContent('fixture.example.test');
    });
    it('admits specifically authorized named operators', async () => { vi.mocked(useOperator).mockReturnValue({ ...operator, loginMode: 'named', actorId: `operator_${revision}`, capabilities: ['read', 'manage_application_checks'] }); await start(); open(); expect(button('Edit targets')).toBeEnabled(); });
    it.each(['external', 'unavailable'] as const)('keeps %s settings immutable', async mode => { await start({ ...(mode === 'external' ? configured() : empty()), mode, revision: '' }); open(); expect(panel()).toHaveTextContent(mode === 'external' ? 'startup file' : 'unavailable'); expect(panel().querySelector('form,input')).toBeNull(); expect(screen.queryByRole('button', { name: 'Edit targets' })).toBeNull(); if (mode === 'external') expect(panel()).toHaveTextContent('https://fixture.example.test/health'); });
    it('blocks controls on manager storage/configuration failure', async () => { await start({ ...configured(), blocked: true }); open(); expect(screen.getByRole('alert')).toHaveTextContent('blocked changes'); expect(screen.queryByRole('button', { name: 'Edit targets' })).toBeNull(); });
    it('localizes the editor without another request or losing its draft', async () => { await edit(); fill('Target ID', 'new-id'); act(() => setLocale('de', false)); expect(screen.getByRole('region', { name: 'Anwendungsprüfungen einrichten' })).toBeInTheDocument(); expect(input('Ziel-ID')).toHaveValue('new-id'); expect(button('Entwurf speichern')).toBeEnabled(); expect(request).toHaveBeenCalledTimes(1); });
});

describe('inert saved drafts and exact consent', () => {
    it('saves exact targets once, leaves checks off and never sends a probe', async () => {
        await edit(on()); fill('Interval (seconds)', '75'); const held = deferred<ApplicationCheckSettings>(); vi.mocked(mutateRaw).mockReturnValue(held.promise); const save = button('Save draft'); fireEvent.click(save); fireEvent.click(save);
        expect(mutation()).toEqual({ expectedRevision: revision, operation: 'save', intervalSeconds: 75, targets: [http()] }); expect(mutateRaw).toHaveBeenCalledTimes(1); expect(vi.mocked(mutateRaw).mock.calls[0][0]).toBe('/application-checks/settings');
        await act(async () => held.resolve({ ...configured(), intervalSeconds: 75, revision: nextRevision })); expect(panel()).toHaveTextContent('Draft saved. Checks are off.'); expect(button('Enable checks')).toBeEnabled(); expect(screen.queryByRole('button', { name: /test|probe/i })).toBeNull(); expect(request).toHaveBeenCalledTimes(1);
    });
    it('validates an empty form, unique IDs, exact ports and interval before any write', async () => {
        await edit(empty()); fireEvent.click(button('Save draft')); expect(screen.getByRole('alert')).toHaveTextContent('invalid'); expect(mutateRaw).not.toHaveBeenCalled(); fill('Target ID', 'port'); fill('Type', 'tcp'); fill('Hostname or IP address', 'fixture.example.test'); fill('Allowed IP addresses', '8.8.8.8'); fill('Port', '4e2'); fireEvent.click(button('Save draft')); expect(mutateRaw).not.toHaveBeenCalled(); fill('Port', '443'); fill('Interval (seconds)', '59'); fireEvent.click(button('Save draft')); expect(mutateRaw).not.toHaveBeenCalled(); fill('Interval (seconds)', '60'); vi.mocked(mutateRaw).mockResolvedValue({ ...configured(), targets: [tcp()], revision: nextRevision }); fireEvent.click(button('Save draft')); await flush(); expect(mutation()).toEqual({ expectedRevision: revision, operation: 'save', intervalSeconds: 60, targets: [tcp()] });
    });
    it('caps targets at eight and clears incompatible fields/approvals on kind changes', async () => {
        await edit(); fill('URL', 'http://fixture.example.test/health'); fill('Allowed IP addresses', '10.2.3.4'); for (const box of screen.getAllByRole('checkbox')) fireEvent.click(box);
        fill('Type', 'tcp'); expect(screen.queryByLabelText('URL', { exact: true })).toBeNull(); expect(input('Hostname or IP address')).toHaveValue(''); expect(input('Port')).toHaveValue(''); expect(input('Allowed IP addresses')).toHaveValue(''); expect(screen.getByRole('checkbox')).not.toBeChecked();
        for (let i = 0; i < 10; i++) fireEvent.click(button('Add target')); expect(screen.getAllByRole('group')).toHaveLength(8); expect(button('Add target')).toBeDisabled(); fireEvent.click(button('Remove target 8')); expect(screen.getAllByRole('group')).toHaveLength(7); expect(button('Add target')).toBeEnabled();
    });
    it.each(['URL', 'Allowed IP addresses', 'Target ID'])('clears private and HTTP approvals after editing %s', async field => {
        await edit(); fill('URL', 'http://fixture.example.test/health'); fill('Allowed IP addresses', '10.2.3.4'); for (const box of screen.getAllByRole('checkbox')) fireEvent.click(box); expect(screen.getAllByRole('checkbox').every(box => (box as HTMLInputElement).checked)).toBe(true);
        fill(field, field === 'URL' ? 'http://other.example.test/health' : field === 'Target ID' ? 'other' : '10.2.3.5'); expect(screen.getAllByRole('checkbox').every(box => !(box as HTMLInputElement).checked)).toBe(true);
    });
    it('requires fresh private/HTTP consent when reopening a saved draft', async () => {
        await edit({ ...configured(), targets: [{ ...http(), kind: 'http', url: 'http://fixture.example.test/health', allowedAddresses: ['10.2.3.4'], allowPrivateLAN: true, plaintextHTTPAcknowledged: true }] });
        expect(screen.getAllByRole('checkbox').every(box => !(box as HTMLInputElement).checked)).toBe(true); fireEvent.click(button('Save draft')); expect(mutateRaw).not.toHaveBeenCalled();
        for (const box of screen.getAllByRole('checkbox')) fireEvent.click(box); vi.mocked(mutateRaw).mockReturnValue(new Promise(() => {})); fireEvent.click(button('Save draft')); expect((mutation().targets as ApplicationTarget[])[0]).toMatchObject({ allowPrivateLAN: true, plaintextHTTPAcknowledged: true });
    });
    it('normalizes only surrounding field/IP whitespace and preserves exact allowlist order', async () => {
        await edit(); fill('Allowed IP addresses', ' 8.8.8.8,\n 8.8.4.4 '); fill('URL', ' https://fixture.example.test/health '); vi.mocked(mutateRaw).mockReturnValue(new Promise(() => {})); fireEvent.click(button('Save draft')); expect((mutation().targets as ApplicationTarget[])[0]).toEqual({ ...http(), allowedAddresses: ['8.8.8.8', '8.8.4.4'] });
    });
    it('reviews saved exact targets and interval, then requires both fresh enable approvals', async () => {
        await start({ ...configured(), intervalSeconds: 75, targets: [http(), dns(), tcp()] }); open(); fireEvent.click(button('Enable checks'));
        expect(panel()).toHaveTextContent('Review saved targets'); expect(panel()).toHaveTextContent('75'); expect(panel()).toHaveTextContent('https://fixture.example.test/health'); expect(panel()).toHaveTextContent('fixture.example.test:443'); expect(panel()).toHaveTextContent('Allowed IPs: 8.8.8.8'); expect(button('Confirm enable')).toBeDisabled();
        fireEvent.click(manager()); expect(button('Confirm enable')).toBeDisabled(); fireEvent.click(destinations()); expect(button('Confirm enable')).toBeEnabled(); vi.mocked(mutateRaw).mockResolvedValue({ ...configured(), enabled: true, revision: nextRevision, intervalSeconds: 75, targets: [http(), dns(), tcp()] }); fireEvent.click(button('Confirm enable')); await flush(); expect(mutation()).toEqual({ expectedRevision: revision, operation: 'enable', checksFromManagerAcknowledged: true, destinationsAcknowledged: true }); expect(panel()).toHaveTextContent('Checks enabled');
    });
    it('requires the additional HTTP operator-transport acknowledgement', async () => {
        vi.mocked(useOperator).mockReturnValue({ ...operator, insecureTestMode: true }); await enable(); expect(button('Confirm enable')).toBeDisabled(); expect(panel()).toHaveTextContent('read or changed on the network'); fireEvent.click(screen.getByRole('checkbox', { name: /^I understand this HTTP-test/ })); vi.mocked(mutateRaw).mockResolvedValue({ ...on(), revision: nextRevision }); fireEvent.click(button('Confirm enable')); await flush(); expect(mutation()).toEqual({ expectedRevision: revision, operation: 'enable', checksFromManagerAcknowledged: true, destinationsAcknowledged: true, plaintextAcknowledged: true });
    });
    it('never enables an unsaved edited destination, and cancellation resets approvals', async () => {
        await edit(); fill('URL', 'https://unsaved.example.test/other'); fireEvent.click(button('Cancel')); fireEvent.click(button('Enable checks')); expect(panel()).not.toHaveTextContent('unsaved.example.test'); expect(panel()).toHaveTextContent('https://fixture.example.test/health'); fireEvent.click(manager()); fireEvent.click(destinations()); fireEvent.click(button('Cancel')); fireEvent.click(button('Enable checks')); expect(manager()).not.toBeChecked(); expect(destinations()).not.toBeChecked(); expect(button('Confirm enable')).toBeDisabled(); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('requires explicit disable confirmation and retains the exact targets', async () => {
        await start(on()); open(); fireEvent.click(button('Disable checks')); expect(mutateRaw).not.toHaveBeenCalled(); vi.mocked(mutateRaw).mockResolvedValue({ ...configured(), revision: nextRevision }); fireEvent.click(button('Confirm disable')); await flush(); expect(mutation()).toEqual({ expectedRevision: revision, operation: 'disable' }); expect(panel()).toHaveTextContent('Saved targets retained'); expect(panel()).toHaveTextContent('https://fixture.example.test/health');
    });
    it('stores no draft or consent in local/session storage and loses drafts on reload/remount', async () => {
        const mounted = await edit(); const before = JSON.stringify({ ...localStorage }); fill('URL', 'https://unsaved.example.test/path'); fireEvent.click(screen.getByRole('checkbox')); expect(JSON.stringify({ ...localStorage })).toBe(before); expect(sessionStorage.length).toBe(0); mounted.unmount(); await start(); open(); fireEvent.click(button('Edit targets')); expect(input('URL')).toHaveValue('https://fixture.example.test/health'); expect(screen.getByRole('checkbox')).not.toBeChecked();
    });
});

describe('interruptions, auth and uncertain writes', () => {
    it.each(['Close', 'Escape', 'toggle'])('clears approvals on %s', async action => { await enable(); if (action === 'Escape') fireEvent.keyDown(manager(), { key: 'Escape' }); else fireEvent.click(button(action === 'toggle' ? 'Application check setup' : 'Close')); expect(button('Application check setup')).toHaveAttribute('aria-expanded', 'false'); open(); fireEvent.click(button('Enable checks')); expect(manager()).not.toBeChecked(); expect(button('Confirm enable')).toBeDisabled(); });
    it.each(['hashchange', 'popstate', 'pagehide', 'visibilitychange'])('discards draft/snapshot on %s and needs an explicit fresh GET', async eventName => {
        await enable(); if (eventName === 'visibilitychange') vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden'); act(() => (eventName === 'visibilitychange' ? document : window).dispatchEvent(new Event(eventName))); expect(panel()).not.toHaveTextContent('fixture.example.test'); expect(panel().querySelector('input')).toBeNull(); expect(request).toHaveBeenCalledTimes(1);
        vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('visible'); act(() => { document.dispatchEvent(new Event('visibilitychange')); window.dispatchEvent(new Event('pageshow')); }); await advance(60000); expect(request).toHaveBeenCalledTimes(1); fireEvent.click(refresh()); await flush(); open(); fireEvent.click(button('Enable checks')); expect(manager()).not.toBeChecked(); expect(request).toHaveBeenCalledTimes(2);
    });
    it('does not read while initially hidden and requires refresh after restoration', async () => { vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden'); await start(); expect(request).not.toHaveBeenCalled(); vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('visible'); act(() => document.dispatchEvent(new Event('visibilitychange'))); expect(request).not.toHaveBeenCalled(); fireEvent.click(refresh()); await flush(); expect(request).toHaveBeenCalledTimes(1); });
    it.each(['cancel', 'hidden', 'navigation', 'unmount'])('aborts an in-flight write on %s and ignores its late result', async action => {
        const mounted = await enable(), held = deferred<ApplicationCheckSettings>(); vi.mocked(mutateRaw).mockReturnValue(held.promise); fireEvent.click(button('Confirm enable')); const signal = vi.mocked(mutateRaw).mock.calls[0][3]!;
        if (action === 'cancel') fireEvent.click(button('Cancel')); else if (action === 'hidden') { vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden'); act(() => document.dispatchEvent(new Event('visibilitychange'))); } else if (action === 'navigation') act(() => window.dispatchEvent(new Event('popstate'))); else mounted.unmount();
        expect(signal.aborted).toBe(true); await act(async () => held.resolve({ ...on(), revision: nextRevision })); expect(screen.queryByText('Checks enabled for the reviewed targets.')).toBeNull(); if (action !== 'unmount') { expect(screen.getByRole('alert')).toHaveTextContent('may have taken effect'); expect(panel()).not.toHaveTextContent('fixture.example.test'); } expect(mutateRaw).toHaveBeenCalledTimes(1);
    });
    it('retains write uncertainty across repeated suspension and a failed fresh read', async () => {
        await enable(); vi.mocked(mutateRaw).mockReturnValue(new Promise(() => {})); fireEvent.click(button('Confirm enable'));
        act(() => { window.dispatchEvent(new Event('popstate')); window.dispatchEvent(new Event('pagehide')); window.dispatchEvent(new Event('pageshow')); });
        expect(screen.getByRole('alert')).toHaveTextContent('may have taken effect'); vi.mocked(request).mockRejectedValueOnce(new Error('PRIVATE')); fireEvent.click(refresh()); await flush(); expect(screen.getByRole('alert')).toHaveTextContent('may have taken effect');
        fireEvent.click(refresh()); await flush(); expect(screen.queryByRole('alert')).toBeNull(); expect(mutateRaw).toHaveBeenCalledTimes(1);
    });
    it('cancels pending reads on dismiss and does not allow old snapshots to return', async () => {
        const held = deferred<ApplicationCheckSettings>(); vi.mocked(request).mockReturnValue(held.promise); render(<ApplicationCheckSettingsPanel/>); open(); fireEvent.click(button('Cancel')); expect(vi.mocked(request).mock.calls[0][1]!.signal!.aborted).toBe(true); await act(async () => held.resolve(configured())); expect(panel()).not.toHaveTextContent('fixture.example.test'); expect(panel()).toHaveTextContent('Status unknown');
    });
    it('locks on authorization events, access loss and cross-tab logout', async () => {
        await enable(); act(() => window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT))); expect(refresh()).toBeDisabled(); expect(panel()).not.toHaveTextContent('fixture.example.test'); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('aborts writes and removes destinations when a named capability is revoked', async () => {
        const mounted = await enable(), held = deferred<ApplicationCheckSettings>(); vi.mocked(mutateRaw).mockReturnValue(held.promise); fireEvent.click(button('Confirm enable')); const signal = vi.mocked(mutateRaw).mock.calls[0][3]!;
        vi.mocked(useOperator).mockReturnValue({ ...operator, loginMode: 'named', actorId: `operator_${revision}`, capabilities: ['read'] }); mounted.rerender(<ApplicationCheckSettingsPanel/>); await flush(); expect(signal.aborted).toBe(true); await act(async () => held.resolve({ ...on(), revision: nextRevision })); expect(panel()).toHaveTextContent('administrator permission'); expect(panel()).not.toHaveTextContent('fixture.example.test'); expect(request).toHaveBeenCalledTimes(1);
    });
    it.each(['epoch', 'storage'])('invalidates snapshot and consent after %s loss', async kind => { await enable(); act(() => { if (kind === 'epoch') abortProtectedRequests(); else { localStorage.setItem(LOGOUT_INTENT_KEY, '1'); window.dispatchEvent(new StorageEvent('storage', { key: LOGOUT_INTENT_KEY })); } }); await advance(1000); expect(refresh()).toBeDisabled(); expect(panel().querySelector('input')).toBeNull(); expect(panel()).not.toHaveTextContent('fixture.example.test'); });
    it('serializes explicit refreshes and clears approval when the revision changes', async () => {
        await enable(); const held = deferred<ApplicationCheckSettings>(); vi.mocked(request).mockReturnValueOnce(held.promise); const refreshButton = refresh(); fireEvent.click(refreshButton); fireEvent.click(refreshButton); expect(request).toHaveBeenCalledTimes(2); expect(panel().querySelector('input')).toBeNull(); await act(async () => held.resolve({ ...configured(), revision: nextRevision })); fireEvent.click(button('Enable checks')); expect(manager()).not.toBeChecked(); expect(button('Confirm enable')).toBeDisabled();
    });
    it.each([new APIError('PRIVATE', 409), new APIError('PRIVATE', 500), new Error('PRIVATE')])('never replays a failed/uncertain write and clears target authority %#', async error => {
        await enable(); vi.mocked(mutateRaw).mockRejectedValue(error); fireEvent.click(button('Confirm enable')); await flush(); expect(screen.getByRole('alert')).toHaveTextContent(error instanceof APIError && error.status === 409 ? 'settings changed' : 'may have taken effect'); expect(panel()).not.toHaveTextContent('PRIVATE'); expect(panel()).not.toHaveTextContent('fixture.example.test'); await advance(60000); expect(mutateRaw).toHaveBeenCalledTimes(1); expect(request).toHaveBeenCalledTimes(1); vi.mocked(request).mockResolvedValue({ ...configured(), revision: nextRevision }); fireEvent.click(refresh()); await flush(); fireEvent.click(button('Enable checks')); expect(manager()).not.toBeChecked(); expect(button('Confirm enable')).toBeDisabled();
    });
    it.each([401, 403])('locks on settings API authorization failure %i', async status => { vi.mocked(request).mockRejectedValue(new APIError('PRIVATE', status)); render(<ApplicationCheckSettingsPanel/>); await flush(); expect(refresh()).toBeDisabled(); expect(screen.getByRole('alert')).toHaveTextContent('session or permissions changed'); });
    it('times out a write without replay and ignores its eventual successful response', async () => {
        await enable(); const held = deferred<ApplicationCheckSettings>(); vi.mocked(mutateRaw).mockReturnValue(held.promise); fireEvent.click(button('Confirm enable')); await advance(10000); expect(screen.getByRole('alert')).toHaveTextContent('may have taken effect'); await act(async () => held.resolve({ ...on(), revision: nextRevision })); expect(panel()).not.toHaveTextContent('Checks enabled'); expect(mutateRaw).toHaveBeenCalledTimes(1); expect(request).toHaveBeenCalledTimes(1);
    });
    it('rejects same-revision, mismatched-target or wrongly enabled save responses as uncertain', async () => {
        await edit(); vi.mocked(mutateRaw).mockResolvedValue({ ...on(), revision: nextRevision }); fireEvent.click(button('Save draft')); await flush(); expect(screen.getByRole('alert')).toHaveTextContent('may have taken effect'); expect(panel()).not.toHaveTextContent('fixture.example.test');
        for (const value of [{ ...on(), revision }, { ...on(), revision: nextRevision, targets: [dns()] }]) { fireEvent.click(refresh()); await flush(); fireEvent.click(button('Enable checks')); fireEvent.click(manager()); fireEvent.click(destinations()); vi.mocked(mutateRaw).mockResolvedValue(value); fireEvent.click(button('Confirm enable')); await flush(); expect(screen.getByRole('alert')).toHaveTextContent('may have taken effect'); }
    });
    it('failed refresh removes saved destinations and permits only an explicit retry', async () => { await enable(); vi.mocked(request).mockRejectedValue(new Error('PRIVATE')); fireEvent.click(refresh()); await flush(); expect(screen.getByRole('alert')).toHaveTextContent('could not be confirmed'); expect(panel()).not.toHaveTextContent('fixture.example.test'); expect(panel().querySelector('input')).toBeNull(); await advance(60000); expect(request).toHaveBeenCalledTimes(2); });
});

describe('bounded same-origin transport and source layout', () => {
    it('uses the real bounded GET transport, never any target URL', async () => {
        const real = await vi.importActual<typeof import('./api')>('./api'); vi.mocked(request).mockImplementation(real.request); const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify(configured()), { status: 200 })); vi.stubGlobal('fetch', fetch); render(<ApplicationCheckSettingsPanel/>); await flush(); open(); expect(panel()).toHaveTextContent('https://fixture.example.test/health'); expect(fetch).toHaveBeenCalledExactlyOnceWith('/api/application-checks/settings', expect.objectContaining({ credentials: 'same-origin', cache: 'no-store', headers: { Accept: 'application/json' } }));
    });
    it('drops oversized or unknown-field response bodies before rendering their contents', async () => {
        const real = await vi.importActual<typeof import('./api')>('./api'); vi.mocked(request).mockImplementation(real.request); vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ ...configured(), secret: 'PRIVATE'.repeat(APPLICATION_CHECK_SETTINGS_BYTES) }), { status: 200 }))); render(<ApplicationCheckSettingsPanel/>); await flush(); expect(screen.getByRole('alert')).toBeInTheDocument(); expect(panel()).not.toHaveTextContent('PRIVATE'); expect(panel()).not.toHaveTextContent('fixture.example.test');
    });
    it('uses real same-origin CSRF and operation-specific JSON exactly once', async () => {
        await enable(); const real = await vi.importActual<typeof import('./api')>('./api'); vi.mocked(mutateRaw).mockImplementation(real.mutateRaw); const fetch = vi.fn().mockResolvedValueOnce(new Response(JSON.stringify({ csrfToken: 'fixture-csrf' }), { status: 200 })).mockResolvedValueOnce(new Response(JSON.stringify({ ...on(), revision: nextRevision }), { status: 200 })); vi.stubGlobal('fetch', fetch); fireEvent.click(button('Confirm enable')); await flush(); expect(fetch).toHaveBeenCalledTimes(2); expect(fetch.mock.calls[1][0]).toBe('/api/application-checks/settings'); expect(fetch.mock.calls[1][1]).toMatchObject({ method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': 'fixture-csrf' } }); expect(panel()).toHaveTextContent('Checks enabled');
    });
    it('provides labelled fieldsets and responsive source rules, without claiming browser geometry', async () => {
        await edit(); expect(screen.getByRole('group', { name: 'Target 1' })).toBeInTheDocument(); expect(within(screen.getByRole('group')).getByLabelText('Allowed IP addresses')).toHaveAccessibleDescription(/1–16 exact IPs/);
        const { readFileSync } = await vi.importActual<{ readFileSync(path: string, encoding: 'utf8'): string }>('node:fs'); const style = readFileSync('src/application-check-settings.css', 'utf8'); expect(style).toContain('@media(max-width:760px)'); expect(style).toContain('grid-template-columns:minmax(0,1fr)'); expect(style).toContain('overflow-wrap:anywhere'); expect(style).toContain('min-height:44px');
    });
});
