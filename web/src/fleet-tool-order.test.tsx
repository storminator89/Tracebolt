import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import App from './App';
import { abortProtectedRequests } from './api';
import { setLocale } from './i18n';
import { windowsCapacityDevice, windowsCapacitySession } from './windows-capacity-fixture';
import { windowsDeviceId, windowsNow } from './windows-inventory-fixture';
import { windowsIncidentItem, windowsIncidentView } from './windows-incident-inbox-fixture';
import type { FleetGroupsView } from './fleet-groups-types';
import type { Device } from './types';

// Actual App and tools; only the HTTP boundary is replaced with invented DTOs.
const second = `agent_${'2'.repeat(32)}`, linux = `agent_${'3'.repeat(32)}`;
const office = `group_${'4'.repeat(32)}`, other = `group_${'5'.repeat(32)}`;
const devices: Device[] = [
    { ...windowsCapacityDevice(), name: 'Desk One' },
    { ...windowsCapacityDevice(), id: second, name: 'Desk Two' },
    { ...windowsCapacityDevice(), id: linux, name: 'Linux fixture', platform: 'linux', os: 'Linux' },
];
const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status });
const flush = () => act(async () => {});
const toolClasses = ['windows-incident-inbox', 'windows-fleet-software', 'windows-fleet-update-worklist', 'windows-fleet-managed-msi', 'windows-maintenance', 'windows-notifications'];
const panel = () => document.querySelector<HTMLElement>('.inventory-panel')!;
const toolsPanel = () => document.querySelector<HTMLElement>('.devices-tools-section')!;
const tools = () => toolClasses.map(name => toolsPanel().querySelector<HTMLElement>(`:scope > .${name}`)!);
const expectSameTools = (original: HTMLElement[]) => tools().forEach((tool, index) => expect(tool).toBe(original[index]));
function server(named = false, fleet = devices) {
    const session = { mode: 'lan', transport: 'https', insecureTestMode: false, transportWarning: null, authenticationRequired: true, authenticated: true, csrfToken: 'fixture-csrf', serverNow: windowsNow, expiresAt: windowsCapacitySession, expiresInSeconds: 3590, loginMode: named ? 'named' : 'shared', actorId: named ? `operator_${'6'.repeat(32)}` : null, capabilities: named ? ['read', 'windows_update_install', 'windows_managed_msi_deliver', 'windows_managed_msi_install'] : ['read'] };
    let groups: FleetGroupsView = { schemaVersion: 'tracebolt.fleet-groups.v1', serverNow: windowsNow, groups: [
        { id: office, name: 'Office', revision: 2, memberIds: [windowsDeviceId], unavailableMembers: 0 },
        { id: other, name: 'Other', revision: 7, memberIds: [second], unavailableMembers: 0 },
    ], devices: fleet.map(({ id, name, platform }) => ({ id, name, platform: platform as 'linux' | 'windows' })) };
    let rows = [windowsIncidentItem()];
    let acknowledge = async () => { rows = rows.map(row => ({ ...row, acknowledgedAt: windowsNow })); return json({ schemaVersion: 'tracebolt.windows-incident-ack.v1', serverNow: windowsNow, key: rows[0].key, acknowledgedAt: windowsNow }); };
    const digest = (letter: string) => `sha256:${letter.repeat(64)}`;
    const selection = { sha256: digest('a'), size: 1024, productCode: '{11111111-2222-3333-4444-555555555555}', packageCode: '{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}', version: '1.2.3', architecture: 'amd64', name: 'Inert fixture', termsReviewDigest: digest('b'), reviewReference: 'Synthetic package review' };
    const artifact = { version: 'tracebolt.windows-managed-msi-artifact.v2', serverNow: Date.parse(windowsNow) / 1000, state: 'uploaded', artifactId: digest('c'), package: selection, nativeAcceptanceDigest: digest('d'), uploadOffset: 1024, uploadPendingDigest: '', targets: [{ deviceId: windowsDeviceId, bindingDigest: digest('1') }, { deviceId: second, bindingDigest: digest('2') }] };
    const fetch = vi.fn(async (url: string, init?: RequestInit) => {
        if (init?.method === 'POST') {
            if (url === '/api/fleet/windows-incidents/acknowledge') return acknowledge();
            throw new Error('Unexpected synthetic POST');
        }
        if (url === '/api/auth/session') return json(session);
        if (url === '/api/overview') return json({ generatedAt: windowsNow, stats: { totalDevices: fleet.length, healthyDevices: 0, attentionDevices: 0, unknownDevices: fleet.length, openCases: 0, criticalCases: 0 }, devices: fleet, cases: [], activity: [] });
        if (url === '/api/fleet/identities') return json({ schemaVersion: 'tracebolt.fleet-identities.v2', serverNow: windowsNow, items: [] });
        if (url === '/api/fleet/groups') return json(groups);
        if (url.startsWith('/api/fleet/windows-incidents?')) return json(windowsIncidentView(rows));
        if (url === '/api/windows-managed-msi/catalogue') return json({ version: 'tracebolt.windows-managed-msi-catalogue.v1', enabled: false, serverNow: artifact.serverNow, revision: '0', maxEntries: 4, maxRetainedPayloadBytes: 134217728, reservedBytes: 0, entries: [] });
        if (url === '/api/windows-managed-msi/artifact') return json(artifact);
        return json({}, 503);
    });
    vi.stubGlobal('fetch', fetch);
    return { fetch, posts: () => fetch.mock.calls.filter(([, init]) => init?.method === 'POST'), loseGroups: () => { groups = { ...groups, groups: [] }; }, setAcknowledge: (next: typeof acknowledge) => { acknowledge = next; } };
}
async function chooseGroup(id: string) {
    if (screen.queryByRole('button', { name: 'Fleet groups' })) { fireEvent.click(screen.getByRole('button', { name: 'Fleet groups' })); await flush(); }
    fireEvent.change(screen.getByRole('combobox', { name: 'Fleet groups' }), { target: { value: id } }); await flush();
}
function localJumps() {
    const before = window.location.hash, length = window.history.length;
    const index = document.querySelector<HTMLElement>('.devices-workspace-index')!;
    for (const name of ['Setup', 'Inventory', 'Fleet tools']) {
        const button = within(index).getByRole('button', { name });
        fireEvent.click(button);
        expect(document.getElementById(button.getAttribute('aria-controls')!)).toHaveFocus();
    }
    expect(window.location.hash).toBe(before); expect(window.history.length).toBe(length);
}
function changeFilters() {
    fireEvent.change(screen.getByRole('textbox', { name: 'Search devices' }), { target: { value: 'no-match' } });
    fireEvent.change(screen.getByRole('combobox', { name: 'Sort devices' }), { target: { value: 'name' } });
    fireEvent.change(screen.getByRole('combobox', { name: 'Filter by operating system' }), { target: { value: 'linux' } });
}
beforeEach(() => { abortProtectedRequests(); localStorage.clear(); sessionStorage.clear(); vi.useFakeTimers(); vi.setSystemTime(windowsNow); setLocale('en', false); window.history.replaceState({}, '', '/#/devices'); vi.spyOn(document, 'hasFocus').mockReturnValue(true); });
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe('device list before the existing fleet tools', () => {
    it.each(['en', 'de'] as const)('uses real DOM order and leaves every tool collapsed without a tool request (%s)', async locale => {
        setLocale(locale, false); const s = server(); render(<App/>); await flush();
        const parts = [panel().querySelector('.filter-toolbar'), panel().querySelector('.fleet-groups'), panel().querySelector('.inventory-meta'), panel().querySelector('.fleet-identity-notice'), panel().querySelector('.device-table'), panel().querySelector('.table-footer'), ...tools()];
        parts.forEach(node => expect(node).not.toBeNull());
        for (let i = 1; i < parts.length; i++) expect(parts[i - 1]!.compareDocumentPosition(parts[i]!) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
        expect(tools()).toHaveLength(6);
        for (const tool of tools()) { expect(tool.parentElement).toBe(toolsPanel()); expect(tool.querySelector('button[aria-expanded]')).toHaveAttribute('aria-expanded', 'false'); }
        expect(panel().querySelectorAll('.device-table tbody tr')).toHaveLength(3);
        expect(s.fetch.mock.calls.some(([url]) => /windows-incidents|windows-software|windows-update|windows-managed-msi|windows-maintenance|windows-notifications/.test(url))).toBe(false);
        expect(s.posts()).toHaveLength(0);
    });

    it('preserves a pending exact acknowledgement and all tool instances through filter, sort, platform and group changes', async () => {
        const s = server(); render(<App/>); await flush(); await chooseGroup(office);
        const original = tools(), inbox = original[0];
        fireEvent.click(within(inbox).getByRole('button', { name: 'Windows incidents' })); await flush();
        let reject!: (error: Error) => void;
        s.setAcknowledge(() => new Promise((_resolve, fail) => { reject = fail; }));
        fireEvent.click(within(inbox).getByRole('button', { name: /^Mark seen:/ })); await flush();
        expect(s.posts()).toHaveLength(1);
        const [path, init] = s.posts()[0];
        expect(path).toBe('/api/fleet/windows-incidents/acknowledge'); expect(JSON.parse(init!.body as string)).toEqual({ key: windowsIncidentItem().key });
        const pending = within(inbox).getByRole('button', { name: /^Mark seen:/ }); expect(pending).toBeDisabled();
        localJumps(); changeFilters(); await chooseGroup(other); localJumps();
        expect(screen.getByRole('heading', { name: 'No matching devices' })).toBeVisible();
        expectSameTools(original); expect(within(inbox).getByRole('button', { name: /^Mark seen:/ })).toBe(pending);
        expect(pending).toBeDisabled(); expect(init!.signal?.aborted).toBe(false);
        expect(within(inbox).getByRole('link', { name: 'Desk One · Health details' })).toHaveAttribute('href', `#/devices/${windowsDeviceId}/health`);
        expect(within(inbox).getByText(/Fleet-wide; the device table/)).toBeInTheDocument();
        await act(async () => reject(new Error('Synthetic lost acknowledgement response')));
        expect(within(inbox).getByText(/Acknowledgement could not be confirmed/)).toBeVisible();
        fireEvent.click(screen.getByRole('button', { name: 'Reset filters' })); await chooseGroup(other);
        s.loseGroups(); fireEvent.click(screen.getByRole('button', { name: 'Refresh groups' })); await flush();
        expect(screen.getByRole('combobox', { name: 'Fleet groups' })).toHaveValue(other);
        expect(panel().querySelector('.device-table')).toBeNull(); expect(screen.getByRole('heading', { name: 'Selected group unavailable' })).toBeVisible();
        expect(screen.queryByRole('heading', { name: 'No matching devices' })).toBeNull();
        expectSameTools(original); expect(within(inbox).getByRole('button', { name: /^Mark seen:/ })).toBeDisabled();
        expect(s.posts()).toHaveLength(1);
    });

    it('keeps both frozen worklists and exact targets when the table no longer includes them', async () => {
        const s = server(true); render(<App/>); await flush(); await chooseGroup(office);
        const original = tools(), updates = original[2], msi = original[3];
        for (const [region, title] of [[updates, 'Windows update worklist'], [msi, 'Windows MSI worklist']] as const) {
            fireEvent.click(within(region).getByRole('button', { name: title })); await flush();
            const choices = within(region).getByRole('group', { name: 'Select devices' });
            expect(within(choices).getAllByRole('checkbox')).toHaveLength(1);
            fireEvent.click(within(choices).getByRole('checkbox', { name: /Desk One/ }));
            fireEvent.click(within(region).getByRole('button', { name: 'Freeze device selection' })); await flush();
            expect(within(region).getByText('Office · Group revision 2')).toBeVisible();
        }
        const frozen = [updates, msi].map(region => within(region).getByRole('button', { name: 'Open device: Desk One' }));
        localJumps(); changeFilters(); await chooseGroup(other); localJumps();
        expectSameTools(original); expect(screen.getByRole('heading', { name: 'No matching devices' })).toBeVisible();
        for (const [index, region] of [updates, msi].entries()) {
            expect(within(region).getByText('Office · Group revision 2')).toBeVisible();
            const open = within(region).getByRole('button', { name: 'Open device: Desk One' });
            expect(open).toBe(frozen[index]); expect(open).toBeEnabled();
            expect(within(region).queryByRole('button', { name: 'Open device: Desk Two' })).not.toBeInTheDocument();
            fireEvent.click(open); await flush();
        }
        expect(s.fetch.mock.calls.some(([url]) => url === `/api/devices/${windowsDeviceId}/windows-update-jobs`)).toBe(true);
        expect(s.fetch.mock.calls.some(([url]) => url === `/api/devices/${windowsDeviceId}/windows-managed-msi`)).toBe(true);
        expect(s.fetch.mock.calls.some(([url]) => url.startsWith(`/api/devices/${second}/`) || url.startsWith(`/api/devices/${linux}/`))).toBe(false);
        expect(s.posts()).toHaveLength(0);
    });

    it('retains saved view, search, sort and group context across local jumps without reads', async () => {
        const s = server(); render(<App/>); await flush(); await chooseGroup(office);
        fireEvent.change(screen.getByRole('textbox', { name: 'Search devices' }), { target: { value: 'Desk' } });
        fireEvent.change(screen.getByRole('combobox', { name: 'Sort devices' }), { target: { value: 'name' } });
        fireEvent.click(screen.getByRole('button', { name: 'Save view' }));
        const saved = localStorage.getItem('local-rmm-saved-view'), original = tools(), reads = s.fetch.mock.calls.length;
        localJumps();
        expect(s.fetch.mock.calls).toHaveLength(reads); expectSameTools(original);
        expect(screen.getByRole('textbox', { name: 'Search devices' })).toHaveValue('Desk');
        expect(screen.getByRole('combobox', { name: 'Sort devices' })).toHaveValue('name');
        expect(screen.getByRole('combobox', { name: 'Fleet groups' })).toHaveValue(office);
        expect(localStorage.getItem('local-rmm-saved-view')).toBe(saved);
        fireEvent.change(screen.getByRole('textbox', { name: 'Search devices' }), { target: { value: 'no-match' } });
        fireEvent.click(screen.getByRole('button', { name: 'Saved view' }));
        expect(screen.getByRole('textbox', { name: 'Search devices' })).toHaveValue('Desk'); expect(s.posts()).toHaveLength(0);
    });

    it('retains collapsed tools below a truly empty fleet', async () => {
        const s = server(false, []); render(<App/>); await flush();
        const empty = screen.getByRole('heading', { name: 'No devices yet' });
        expect(tools().every(tool => Boolean(empty.compareDocumentPosition(tool) & Node.DOCUMENT_POSITION_FOLLOWING))).toBe(true);
        expect(tools()).toHaveLength(6); expect(s.posts()).toHaveLength(0);
    });
});
