import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import App from './App';
import { abortProtectedRequests } from './api';
import { setLocale } from './i18n';
import type { FleetGroupsView } from './fleet-groups-types';
import type { Overview } from './types';
import { windowsCapacityDevice, windowsCapacitySession } from './windows-capacity-fixture';
import { windowsNow } from './windows-inventory-fixture';

// Invented observations through the real auth/request/resource/App path.
const groupId = `group_${'4'.repeat(32)}`, secondId = `agent_${'2'.repeat(32)}`;
const devices = [{ ...windowsCapacityDevice(), name: 'Fixture member' }, { ...windowsCapacityDevice(), id: secondId, name: 'Fixture outside group' }];
const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status });
const overview: Overview = { product: 'Tracebolt', mode: 'lan', generatedAt: windowsNow, devices, cases: [], activity: [], stats: { totalDevices: 2, healthyDevices: 0, attentionDevices: 0, unknownDevices: 2, openCases: 0, criticalCases: 0 } };
const session = { mode: 'lan', transport: 'https', insecureTestMode: false, transportWarning: null, authenticationRequired: true, authenticated: true, csrfToken: 'fixture-csrf', serverNow: windowsNow, expiresAt: windowsCapacitySession, expiresInSeconds: 3590, loginMode: 'shared', actorId: null, capabilities: ['read'] };
const groups = (memberIds = [devices[0].id], unavailableMembers = 0): FleetGroupsView => ({ schemaVersion: 'tracebolt.fleet-groups.v1', serverNow: new Date().toISOString(), groups: [{ id: groupId, name: 'Fixture group', revision: 1, memberIds, unavailableMembers }], devices: devices.map(({ id, name }) => ({ id, name, platform: 'windows' })) });
const labels = {
    en: { groups: 'Fleet groups', checking: 'Checking group membership…', unavailable: 'Group membership unavailable', missing: 'Selected group unavailable', empty: 'No visible group members', retry: 'Refresh group membership', overview: 'Refresh overview', clear: 'Clear group filter', export: 'Export CSV', search: 'Search devices', sort: 'Sort devices', platform: 'Filter by operating system', noMatches: 'No matching devices', refresh: 'Refresh' },
    de: { groups: 'Flottengruppen', checking: 'Gruppenmitgliedschaft wird geprüft …', unavailable: 'Gruppenmitgliedschaft nicht verfügbar', missing: 'Gewählte Gruppe nicht verfügbar', empty: 'Keine sichtbaren Gruppenmitglieder', retry: 'Gruppenmitgliedschaft aktualisieren', overview: 'Übersicht aktualisieren', clear: 'Gruppenfilter entfernen', export: 'CSV exportieren', search: 'Geräte durchsuchen', sort: 'Geräte sortieren', platform: 'Nach Betriebssystem filtern', noMatches: 'Keine passenden Geräte', refresh: 'Aktualisieren' },
} as const;
function server() {
    let readGroups = async () => json(groups()), readOverview = async () => json(overview);
    const fetch = vi.fn(async (path: string, init?: RequestInit) => {
        if (init?.method && init.method !== 'GET') throw new Error('Group inventory must remain read-only');
        if (path === '/api/auth/session') return json(session);
        if (path === '/api/overview') return readOverview();
        if (path === '/api/fleet/groups') return readGroups();
        return json({}, 503);
    });
    vi.stubGlobal('fetch', fetch);
    return { fetch, setGroups: (read: typeof readGroups) => { readGroups = read; }, setOverview: (read: typeof readOverview) => { readOverview = read; } };
}
const flush = () => act(async () => {});
const panel = () => document.querySelector<HTMLElement>('.inventory-panel')!;
const state = () => panel().querySelector<HTMLElement>('.fleet-group-inventory-state')!;
const rows = () => panel().querySelectorAll('tbody tr');
const noWrites = (s: ReturnType<typeof server>) => expect(s.fetch.mock.calls.every(([, init]) => !init?.method || init.method === 'GET')).toBe(true);
async function openGroup(locale: keyof typeof labels = 'en') {
    setLocale(locale, false); render(<App/>); await flush();
    fireEvent.click(screen.getByRole('button', { name: labels[locale].groups })); await flush();
    fireEvent.change(screen.getByRole('combobox', { name: labels[locale].groups }), { target: { value: groupId } });
    expect(rows()).toHaveLength(1);
}
function expectUnknown(locale: keyof typeof labels) {
    expect(rows()).toHaveLength(0);
    expect(panel().querySelector('.inventory-meta')).toHaveTextContent('—');
    expect(panel().querySelector('.table-footer')).toBeNull();
    expect(within(panel()).queryByRole('heading', { name: labels[locale].noMatches })).toBeNull();
    expect(screen.getByRole('button', { name: labels[locale].export })).toBeDisabled();
    expect(state()).toHaveTextContent(groupId);
}
beforeEach(() => {
    abortProtectedRequests(); localStorage.clear(); sessionStorage.clear(); vi.useFakeTimers(); vi.setSystemTime(windowsNow);
    window.history.replaceState({}, '', '/#/devices'); vi.spyOn(document, 'hasFocus').mockReturnValue(true);
});
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

it.each(['en', 'de'] as const)('distinguishes unchecked membership from zero matches and recovers the same selection (%s)', async locale => {
    const s = server(), c = labels[locale]; await openGroup(locale);
    let finish!: (value: Response) => void;
    s.setGroups(() => new Promise(resolve => { finish = resolve; }));
    fireEvent.click(screen.getByRole('button', { name: locale === 'de' ? 'Gruppen aktualisieren' : 'Refresh groups' }));
    expect(within(state()).getByRole('heading', { name: c.checking })).toBeVisible(); expectUnknown(locale);
    expect(within(state()).getByRole('button', { name: c.retry })).toBeDisabled();
    await act(async () => { finish(json({}, 503)); });
    expect(within(state()).getByRole('heading', { name: c.unavailable })).toBeVisible(); expectUnknown(locale);
    expect(state()).toHaveTextContent(locale === 'de' ? 'Die Gerätezahl ist unbekannt.' : 'The device count is unknown.');
    s.setGroups(async () => json(groups([secondId])));
    fireEvent.click(within(state()).getByRole('button', { name: c.retry })); await flush();
    expect(state()).toBeNull(); expect(rows()).toHaveLength(1); expect(rows()[0]).toHaveTextContent(secondId);
    expect(screen.getByRole('combobox', { name: c.groups })).toHaveValue(groupId);
    expect(screen.getByRole('button', { name: c.export })).toBeEnabled(); noWrites(s);
});

it.each(['en', 'de'] as const)('keeps the selected filter recoverable when overview failure hides group controls (%s)', async locale => {
    const s = server(), c = labels[locale]; await openGroup(locale);
    s.setOverview(async () => json({}, 503)); fireEvent.click(screen.getByRole('button', { name: c.refresh })); await flush();
    expect(within(state()).getByRole('heading', { name: c.unavailable })).toBeVisible(); expectUnknown(locale);
    expect(screen.queryByRole('combobox', { name: c.groups })).toBeNull();
    s.setOverview(async () => json(overview));
    fireEvent.click(within(state()).getByRole('button', { name: c.overview })); await flush();
    expect(state()).toBeNull(); expect(rows()).toHaveLength(1);
    expect(screen.getByRole('combobox', { name: c.groups })).toHaveValue(groupId);
    expect(s.fetch.mock.calls.filter(([path]) => path === '/api/overview')).toHaveLength(3); noWrites(s);
});

it.each(['en', 'de'] as const)('shows a missing selected group only after a valid current roster (%s)', async locale => {
    const s = server(), c = labels[locale]; await openGroup(locale);
    s.setGroups(async () => json({ ...groups(), groups: [] }));
    fireEvent.click(screen.getByRole('button', { name: locale === 'de' ? 'Gruppen aktualisieren' : 'Refresh groups' })); await flush();
    expect(state()).toHaveAttribute('data-state', 'missing');
    expect(within(state()).getByRole('heading', { name: c.missing })).toBeVisible(); expectUnknown(locale);
    fireEvent.click(within(state()).getByRole('button', { name: c.clear }));
    expect(rows()).toHaveLength(2); expect(state()).toBeNull(); noWrites(s);
});

it.each([['en', 0], ['en', 3], ['de', 0], ['de', 3]] as const)('distinguishes a confirmed empty/partly unavailable group (%s, %i)', async (locale, unavailable) => {
    const s = server(), c = labels[locale]; await openGroup(locale);
    s.setGroups(async () => json(groups([], unavailable)));
    fireEvent.click(screen.getByRole('button', { name: locale === 'de' ? 'Gruppen aktualisieren' : 'Refresh groups' })); await flush();
    expect(state()).toHaveAttribute('data-state', 'empty');
    expect(within(state()).getByRole('heading', { name: c.empty })).toBeVisible();
    expect(state()).toHaveTextContent(locale === 'de'
        ? unavailable ? '3 Gruppenmitglieder sind derzeit nicht verfügbar.' : 'Die gewählte Gruppe hat keine Mitglieder.'
        : unavailable ? '3 group members are currently unavailable.' : 'The selected group has no members.');
    expect(panel().querySelector('.inventory-meta')).toHaveTextContent(locale === 'de' ? '0 Geräte' : '0 Devices');
    expect(panel().querySelector('.table-footer')).toHaveTextContent(locale === 'de' ? '0 von 2 Geräten' : '0 of 2 devices');
    expect(screen.getByRole('button', { name: c.export })).toBeDisabled(); noWrites(s);
});

it('keeps a verified search with no matches distinct from unavailable membership', async () => {
    const s = server(); await openGroup();
    fireEvent.change(screen.getByRole('textbox', { name: labels.en.search }), { target: { value: 'no such fixture' } });
    expect(within(panel()).getByRole('heading', { name: labels.en.noMatches })).toBeVisible();
    expect(state()).toBeNull(); expect(panel().querySelector('.inventory-meta')).toHaveTextContent('0 Devices'); noWrites(s);
});

it('clears only the group filter, preserves search/platform/sort, and ignores a late response as selection authority', async () => {
    const s = server(); await openGroup();
    fireEvent.change(screen.getByRole('textbox', { name: labels.en.search }), { target: { value: 'outside' } });
    fireEvent.change(screen.getByRole('combobox', { name: labels.en.platform }), { target: { value: 'windows' } });
    fireEvent.change(screen.getByRole('combobox', { name: labels.en.sort }), { target: { value: 'name' } });
    let finish!: (value: Response) => void;
    s.setGroups(() => new Promise(resolve => { finish = resolve; }));
    fireEvent.click(screen.getByRole('button', { name: 'Refresh groups' }));
    fireEvent.click(within(state()).getByRole('button', { name: labels.en.clear }));
    await act(async () => { finish(json(groups())); });
    expect(screen.getByRole('textbox', { name: labels.en.search })).toHaveValue('outside');
    expect(screen.getByRole('combobox', { name: labels.en.platform })).toHaveValue('windows');
    expect(screen.getByRole('combobox', { name: labels.en.sort })).toHaveValue('name');
    expect(screen.getByRole('combobox', { name: labels.en.groups })).toHaveValue('');
    expect(state()).toBeNull(); expect(rows()).toHaveLength(1); expect(rows()[0]).toHaveTextContent(secondId); noWrites(s);
});

it('uses the same unknown state during the automatic membership poll', async () => {
    const s = server(); await openGroup();
    s.setGroups(() => new Promise(() => {}));
    await act(async () => { await vi.advanceTimersByTimeAsync(15000); });
    expect(within(state()).getByRole('heading', { name: labels.en.checking })).toBeVisible(); expectUnknown('en'); noWrites(s);
});

it('rejects malformed membership instead of presenting a confirmed empty group', async () => {
    const s = server(); await openGroup();
    s.setGroups(async () => json({ ...groups([]), unexpected: true }));
    fireEvent.click(screen.getByRole('button', { name: 'Refresh groups' })); await flush();
    expect(state()).toHaveAttribute('data-state', 'unavailable'); expectUnknown('en'); noWrites(s);
});
