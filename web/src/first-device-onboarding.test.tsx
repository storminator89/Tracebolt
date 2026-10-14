import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import App from './App';
import { abortProtectedRequests } from './api';
import { setLocale } from './i18n';
import { journalNow, journalSession } from './journal-fixtures';
import type { Device, Overview } from './types';

const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status });
const metric = { value: null, unit: '%', quality: 'unknown' as const, source: 'lan', collectedAt: journalNow };
const device: Device = { id: `agent_${'a'.repeat(32)}`, name: 'Fixture device', platform: 'linux', os: 'Linux', site: '', group: '', ip: null, status: 'unknown', source: 'lan', synthetic: false, lastSeen: journalNow, agentVersion: '', cpu: metric, memory: metric, disk: metric, uptime: '', tags: [], capabilities: [], evidence: [], trend: [], caseIds: [] };
const overview = (devices: Device[] = []): Overview => ({ product: 'Tracebolt', mode: 'lan', generatedAt: journalNow, stats: { totalDevices: devices.length, healthyDevices: 0, attentionDevices: 0, unknownDevices: devices.length, openCases: 0, criticalCases: 0 }, devices, cases: [], activity: [] });
const enrollment = (enabled = true) => ({ schemaVersion: 'tracebolt.enrollment-operator.v2', serverNow: journalNow, enabled, platforms: enabled ? ['linux'] : [], recordLimit: 25, items: [], ...(enabled ? { collectionProfile: 'managed-operations-v3', collectionPrivacy: 'complete_system_inventory_metadata_may_be_sensitive' } : {}) });
const labels = {
    en: { empty: 'No devices yet', setup: 'Review device setup', panel: 'Add devices', add: 'Add device', systems: 'Operating system', consent: /I acknowledge operational metadata/, unavailable: 'Device list unavailable', refresh: 'Refresh', refreshing: 'Refreshing device data…', noMatches: 'No matching devices', reset: 'Reset filters', search: 'Search devices', approval: 'Create invitation' },
    de: { empty: 'Noch keine Geräte', setup: 'Geräteeinrichtung prüfen', panel: 'Geräte hinzufügen', add: 'Gerät hinzufügen', systems: 'Betriebssystem', consent: /Ich bestätige die Erfassung/, unavailable: 'Geräteliste nicht verfügbar', refresh: 'Aktualisieren', refreshing: 'Gerätedaten werden aktualisiert …', noMatches: 'Keine passenden Geräte', reset: 'Filter zurücksetzen', search: 'Geräte durchsuchen', approval: 'Einladung erstellen' },
} as const;
function server({ access = 'shared', enabled = true, devices = [] }: { access?: 'shared' | 'named' | 'legacy' | 'development'; enabled?: boolean; devices?: Device[] } = {}) {
    let readOverview = async () => json(overview(devices));
    let readEnrollment = async () => json(enrollment(enabled));
    const session = access === 'development' ? { ...journalSession, mode: 'development', authenticationRequired: false, authenticated: false, loginMode: 'shared', actorId: null, capabilities: [] } : { ...journalSession, ...(access === 'legacy' ? {} : { loginMode: access, actorId: access === 'named' ? `operator_${'b'.repeat(32)}` : null, capabilities: ['read'] }) };
    const fetch = vi.fn(async (url: string, init?: RequestInit) => {
        if (init?.method && init.method !== 'GET') throw new Error('This navigation must never mutate');
        if (url === '/api/auth/session') return json(session);
        if (url === '/api/overview') return readOverview();
        if (url === '/api/enrollment') return readEnrollment();
        if (url === '/api/windows/enrollment') return json(enrollment(false));
        return json({}, 503);
    });
    vi.stubGlobal('fetch', fetch);
    return { fetch, setOverview: (next: typeof readOverview) => { readOverview = next; }, setEnrollment: (next: typeof readEnrollment) => { readEnrollment = next; } };
}
function route(view: string) { act(() => { window.history.replaceState({}, '', `/#/${view}`); window.dispatchEvent(new Event('hashchange')); }); }
async function travel(direction: 'back' | 'forward') {
    await act(async () => {
        const changed = new Promise<void>(resolve => window.addEventListener('hashchange', () => resolve(), { once: true }));
        window.history[direction](); await changed;
    });
}
function expectReadOnly(fetch: ReturnType<typeof server>['fetch']) { expect(fetch.mock.calls.every(([, init]) => !init?.method || init.method === 'GET')).toBe(true); }
beforeEach(() => { localStorage.clear(); sessionStorage.clear(); setLocale('en', false); window.history.replaceState({}, '', '/#/overview'); vi.spyOn(document, 'hasFocus').mockReturnValue(true); });
afterEach(() => { cleanup(); abortProtectedRequests(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe('first device guidance', () => {
    it.each(['en', 'de'] as const)('uses the keyboard to enter existing setup without creating or consenting (%s)', async locale => {
        setLocale(locale, false); const c = labels[locale], { fetch } = server(), user = userEvent.setup(); render(<App/>);
        const entry = await screen.findByRole('button', { name: c.setup });
        expect(screen.getByRole('heading', { name: c.empty })).toBeVisible(); expect(entry).toBeEnabled();
        expect(document.querySelector('.summary-strip')).toBeNull();
        expect(fetch.mock.calls.some(([path]) => path === '/api/enrollment')).toBe(false);
        entry.focus(); await user.keyboard('{Enter}');
        const panel = await screen.findByRole('region', { name: c.panel });
        await waitFor(() => expect(panel).toHaveFocus());
        expect(window.location.hash).toBe('#/devices'); expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
        await waitFor(() => expect(within(panel).getByRole('button', { name: c.add })).toBeEnabled());
        await user.tab(); expect(within(panel).getByRole('combobox', { name: c.systems })).toHaveFocus();
        await user.click(within(panel).getByRole('button', { name: c.add }));
        const dialog = screen.getByRole('dialog', { name: c.add });
        expect(within(dialog).getByRole('checkbox', { name: c.consent })).not.toBeChecked();
        expect(within(dialog).getByRole('button', { name: c.approval })).toBeDisabled();
        await user.keyboard('{Escape}'); expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
        expect(within(panel).getByRole('button', { name: c.add })).toHaveFocus();
        await travel('back'); await screen.findByRole('button', { name: c.setup });
        await travel('forward'); const ordinaryPanel = await screen.findByRole('region', { name: c.panel });
        expect(ordinaryPanel).not.toHaveFocus(); expect(screen.queryByRole('dialog')).not.toBeInTheDocument(); expectReadOnly(fetch);
    });

    it('cancels an interrupted setup focus request before later ordinary navigation', async () => {
        const { fetch } = server(); render(<App/>);
        const entry = await screen.findByRole('button', { name: labels.en.setup });
        act(() => { fireEvent.click(entry); window.history.replaceState({}, '', '/#/overview'); window.dispatchEvent(new Event('hashchange')); });
        await waitFor(() => expect(screen.getByRole('button', { name: labels.en.setup })).toBeVisible());
        route('devices');
        const panel = await screen.findByRole('region', { name: labels.en.panel });
        expect(panel).not.toHaveFocus(); expect(screen.queryByRole('dialog')).not.toBeInTheDocument(); expectReadOnly(fetch);
    });

    it.each(['en', 'de'] as const)('keeps disabled and different platform domains authoritative (%s)', async locale => {
        setLocale(locale, false); const c = labels[locale], { fetch } = server({ enabled: false }); render(<App/>);
        fireEvent.click(await screen.findByRole('button', { name: c.setup }));
        const panel = await screen.findByRole('region', { name: c.panel });
        await within(panel).findByText(locale === 'de' ? 'Enrollment ist auf diesem Manager nicht eingerichtet.' : 'Enrollment is not configured on this manager.');
        expect(within(panel).getByRole('button', { name: c.add })).toBeDisabled();
        fireEvent.change(within(panel).getByRole('combobox', { name: c.systems }), { target: { value: 'windows' } });
        await waitFor(() => expect(fetch.mock.calls.some(([path]) => path === '/api/windows/enrollment')).toBe(true));
        expect(within(screen.getByRole('region', { name: c.panel })).getByRole('button', { name: c.add })).toBeDisabled();
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument(); expectReadOnly(fetch);
    });

    it.each([['en', 'named'], ['en', 'legacy'], ['de', 'named'], ['de', 'legacy']] as const)('does not infer setup authority from read access (%s, %s)', async (locale, access) => {
        setLocale(locale, false); const { fetch } = server({ access }); render(<App/>);
        expect(await screen.findByRole('button', { name: labels[locale].setup })).toBeDisabled();
        expect(screen.getByText(locale === 'de' ? access === 'named' ? /Nur der gemeinsame Administrator/ : /Einrichtungsberechtigung dieser Sitzung ist nicht bestätigt/ : access === 'named' ? /Adding devices requires the shared administrator/ : /Setup permissions are not confirmed/)).toBeVisible();
        expect(fetch.mock.calls.some(([path]) => path === '/api/enrollment')).toBe(false); expectReadOnly(fetch);
    });

    it('does not add a LAN setup action to the development fleet', async () => {
        server({ access: 'development' }); render(<App/>);
        await screen.findByRole('button', { name: /Total devices/ });
        expect(screen.queryByRole('button', { name: labels.en.setup })).not.toBeInTheDocument();
        route('devices'); expect(await screen.findByRole('heading', { name: 'No devices available' })).toBeVisible();
        expect(screen.queryByRole('heading', { name: labels.en.noMatches })).not.toBeInTheDocument();
    });

    it.each(['en', 'de'] as const)('distinguishes an empty source from no filter matches (%s)', async locale => {
        setLocale(locale, false); const c = labels[locale], s = server(); route('devices'); render(<App/>);
        expect(await screen.findByRole('heading', { name: c.empty })).toBeVisible();
        fireEvent.change(screen.getByRole('textbox', { name: c.search }), { target: { value: 'no-match' } });
        expect(screen.getByRole('heading', { name: c.empty })).toBeVisible();
        expect(screen.queryByRole('heading', { name: c.noMatches })).not.toBeInTheDocument();
        expect(screen.queryByRole('button', { name: c.reset })).not.toBeInTheDocument();
        s.setOverview(async () => json(overview([device])));
        fireEvent.click(screen.getByRole('button', { name: c.refresh }));
        expect(await screen.findByRole('heading', { name: c.noMatches })).toBeVisible();
        expect(screen.queryByRole('heading', { name: c.empty })).not.toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', { name: c.reset }));
        await waitFor(() => expect(document.querySelectorAll('.device-table tbody tr')).toHaveLength(1));
        expect(document.querySelector('.device-table')).toBeVisible(); expectReadOnly(s.fetch);
    });

    it.each(['overview', 'devices'])('does not treat retained empty data during refresh or failure as a fresh empty fleet (%s)', async view => {
        const s = server(); route(view); render(<App/>); await screen.findByRole('heading', { name: labels.en.empty });
        let release!: (value: Response) => void;
        s.setOverview(() => new Promise(resolve => { release = resolve; }));
        fireEvent.click(screen.getByRole('button', { name: labels.en.refresh }));
        expect(await screen.findByText(labels.en.refreshing)).toBeVisible();
        expect(screen.queryByRole('heading', { name: labels.en.empty })).not.toBeInTheDocument();
        expect(screen.queryByRole('button', { name: labels.en.setup })).not.toBeInTheDocument();
        await act(async () => { release(json({}, 503)); });
        expect(await screen.findByRole('heading', { name: labels.en.unavailable })).toBeVisible();
        expect(screen.queryByRole('heading', { name: labels.en.empty })).not.toBeInTheDocument();
        expect(screen.queryByRole('heading', { name: labels.en.noMatches })).not.toBeInTheDocument();
        s.setOverview(async () => json(overview())); fireEvent.click(screen.getByRole('button', { name: 'Try again' }));
        expect(await screen.findByRole('heading', { name: labels.en.empty })).toBeVisible(); expectReadOnly(s.fetch);
    });

    it('does not show setup guidance during initial loading or failure', async () => {
        const s = server(); let release!: (value: Response) => void;
        s.setOverview(() => new Promise(resolve => { release = resolve; })); render(<App/>);
        await waitFor(() => expect(s.fetch.mock.calls.some(([path]) => path === '/api/overview')).toBe(true));
        expect(screen.queryByRole('heading', { name: labels.en.empty })).not.toBeInTheDocument();
        expect(screen.queryByRole('button', { name: labels.en.setup })).not.toBeInTheDocument();
        await act(async () => { release(json({}, 503)); });
        expect(await screen.findByRole('heading', { name: 'No data available' })).toBeVisible();
        expect(screen.queryByRole('button', { name: labels.en.setup })).not.toBeInTheDocument(); expectReadOnly(s.fetch);
    });
});

it.each(['en', 'de'] as const)('manual enrollment status reloads newly accepted report evidence with unchanged invitation revision (%s)', async locale => {
    setLocale(locale, false); const seconds = Date.parse(journalNow) / 1000, invitation = `invite_${'1'.repeat(32)}`;
    const pendingDevice: Device = { ...device, lastSeen: '0001-01-01T00:00:00Z', capabilities: [{ id: 'agent_identity', name: 'Enrolled agent identity', status: 'supported', detail: 'Synthetic activated identity' }], agentCertificate: { source: 'guided-enrollment', checkedAt: journalNow, expiresAt: new Date((seconds + 86400) * 1000).toISOString() } };
    const item = { version: 'tracebolt.enrollment-state.v2', binding: { instanceID: `manager_${'2'.repeat(32)}`, origin: window.location.origin, profile: 'tls', collectionProfile: 'managed-operations-v3', issuerFingerprint: 'a'.repeat(64) }, invitationID: invitation, createRequestID: `request_${'3'.repeat(32)}`, platform: 'linux', revision: 6, state: 'activated', createdAt: seconds - 300, deadlineAt: seconds + 600, updatedAt: seconds, claim: { claimID: `claim_${'4'.repeat(32)}`, keyFingerprint: 'ab'.repeat(32), comparisonCode: '12ab'.repeat(8) }, approval: { deviceID: device.id }, intent: { deviceID: device.id, notAfter: seconds + 86400 }, issuance: {}, activation: {}, termination: {} };
    const s = server({ devices: [pendingDevice] }), timers = vi.spyOn(window, 'setInterval');
    s.setEnrollment(async () => json({ ...enrollment(), items: [item] })); route('devices'); render(<App/>);
    const panel = await screen.findByRole('region', { name: labels[locale].panel });
    fireEvent.click(await within(panel).findByRole('button', { name: locale === 'de' ? /^Einladungen/ : /^Invitations/ }));
    fireEvent.click(within(panel).getByRole('button', { name: locale === 'de' ? `Einladung ${invitation} prüfen` : `Review invitation ${invitation}` }));
    const waiting = locale === 'de' ? 'Warte auf erste Meldung' : 'Waiting for first report', check = locale === 'de' ? 'Status prüfen' : 'Check status';
    expect(await screen.findByText(waiting)).toBeVisible();
    const count = (path: string) => s.fetch.mock.calls.filter(([url]) => url === path).length;
    expect(count('/api/overview')).toBe(1); expect(count('/api/enrollment')).toBe(1);
    const poll = timers.mock.calls.find(([, delay]) => delay === 10000)?.[0]; expect(typeof poll).toBe('function');
    await act(async () => { (poll as () => void)(); });
    expect(count('/api/enrollment')).toBe(2); expect(count('/api/overview')).toBe(1);
    const unrelatedReads = () => s.fetch.mock.calls.filter(([path]) => path !== '/api/enrollment' && path !== '/api/overview').length;
    const beforeManual = unrelatedReads();
    let release!: (value: Response) => void;
    s.setOverview(() => new Promise(resolve => { release = resolve; }));
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: check }));
    await waitFor(() => expect(count('/api/overview')).toBe(2));
    expect(within(screen.getByRole('dialog')).getByRole('button', { name: check })).toBeDisabled();
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: check }));
    await act(async () => { (poll as () => void)(); });
    expect(count('/api/enrollment')).toBe(3); expect(count('/api/overview')).toBe(2);
    const reported = { ...pendingDevice, lastSeen: new Date((seconds - 30) * 1000).toISOString() };
    await act(async () => { release(json(overview([reported]))); });
    const report = within(screen.getByRole('dialog')).getByRole('status', { name: locale === 'de' ? 'Meldung' : 'Report' });
    expect(report.querySelector('time')).toHaveAttribute('datetime', reported.lastSeen); expect(screen.queryByText(waiting)).not.toBeInTheDocument(); expect(item.revision).toBe(6);
    expect(count('/api/enrollment')).toBe(3); expect(count('/api/overview')).toBe(2); expect(unrelatedReads()).toBe(beforeManual);
    s.setOverview(async () => json({ error: { message: 'Synthetic overview unavailable' } }, 503));
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: check }));
    await within(report).findByText(locale === 'de' ? 'Meldungsstatus nicht verfügbar' : 'Report status unavailable');
    expect(report.querySelector('time')).toHaveAttribute('datetime', reported.lastSeen);
    expect(screen.queryByText(waiting)).not.toBeInTheDocument();
    expect(count('/api/enrollment')).toBe(4); expect(count('/api/overview')).toBe(3); expectReadOnly(s.fetch);
});
