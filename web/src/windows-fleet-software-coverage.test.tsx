import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, AUTH_REQUIRED_EVENT } from './api';
import { LOGOUT_INTENT_KEY, useOperator } from './auth';
import { setLocale } from './i18n';
import { WindowsFleetSoftwareLookup } from './windows-fleet-software';
import { WindowsFleetSoftwareCoverage } from './windows-fleet-software-coverage';
import { fleetSoftwareDevice, fleetSoftwareNow, fleetSoftwarePage, fleetSoftwareSession } from './windows-fleet-software-fixtures';
import type { FleetSoftwarePage, FleetSoftwareQuery } from './windows-fleet-software-types';

vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
const response = (value: unknown) => new Response(JSON.stringify(value));
const flush = async () => act(async () => { for (let i = 0; i < 30; i++) await Promise.resolve(); });
const operator = () => ({ mode: 'lan' as const, authenticated: true, expiresAt: fleetSoftwareSession, insecureTestMode: false, loginMode: 'named' as const, actorId: `operator_${'a'.repeat(32)}`, capabilities: ['read' as const], hasExplicitMetadata: true, logout: vi.fn(), theme: 'light' as const, setTheme: vi.fn() });
function mixed(page: FleetSoftwarePage) {
    if (page.mode !== 'fleet' || page.offset !== 0) return;
    // Distinct full-generation outcomes; the existing parser still admits every page.
    for (const index of [1, 2]) Object.assign(page.items[index], { matchingCount: 0, unknownCount: index === 1 ? 4 : 0, rows: [] });
    Object.assign(page.items[3], { status: 'disabled', complete: null, latestAttempt: null, matchingCount: 0, unknownCount: 0, rows: [], detailCursor: '' });
}
function server() {
    const requests: FleetSoftwareQuery[] = [];
    const fetch = vi.fn(async (path: string, options?: RequestInit) => {
        if (path === '/api/session') return response({ csrfToken: 'fixture-csrf' });
        const query = JSON.parse(options!.body as string) as FleetSoftwareQuery; requests.push(query);
        const page = fleetSoftwarePage(query); mixed(page); page.serverNow = new Date().toISOString(); return response(page);
    });
    vi.stubGlobal('fetch', fetch); return { requests, fetch };
}
async function open() {
    const ui = render(<WindowsFleetSoftwareLookup/>);
    fireEvent.click(screen.getByRole('button', { name: 'Find software across Windows devices' }));
    fireEvent.change(screen.getByRole('searchbox', { name: 'Application name' }), { target: { value: 'Fixture' } });
    fireEvent.click(screen.getByRole('button', { name: 'Search reported software' })); await flush(); return ui;
}
const group = () => screen.getByRole('group', { name: 'Search coverage' });
const choose = (label: string) => fireEvent.click(within(group()).getByRole('button', { name: new RegExp(`^${label} `) }));
const cards = () => document.querySelectorAll('.windows-fleet-software-results > li');
const summary = (page: FleetSoftwarePage) => <WindowsFleetSoftwareCoverage page={page}>{items => <ul aria-label="Device cards">{items.map(item => <li key={item.identity}>{item.deviceId}</li>)}</ul>}</WindowsFleetSoftwareCoverage>;

beforeEach(() => {
    vi.useFakeTimers(); vi.setSystemTime(fleetSoftwareNow); vi.mocked(useOperator).mockReturnValue(operator()); setLocale('en', false);
    localStorage.removeItem(LOGOUT_INTENT_KEY); sessionStorage.removeItem(LOGOUT_INTENT_KEY);
});
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.unstubAllGlobals(); vi.restoreAllMocks(); localStorage.removeItem(LOGOUT_INTENT_KEY); sessionStorage.removeItem(LOGOUT_INTENT_KEY); });

describe('loaded fleet software coverage', () => {
    it.each(['en', 'de'] as const)('counts devices, not preview rows, with exclusive groups and visible scope (%s)', locale => {
        setLocale(locale, false); const page = fleetSoftwarePage(); mixed(page); const original = JSON.stringify(page);
        const fetch = vi.fn(); vi.stubGlobal('fetch', fetch); const local = vi.spyOn(Storage.prototype, 'setItem'); render(summary(page));
        const labels = locale === 'en' ? ['All', 'With matches', 'Unclear', 'No reported match', 'No complete capture'] : ['Alle', 'Mit Treffern', 'Unklar', 'Kein gemeldeter Treffer', 'Keine vollständige Erfassung'];
        const toolbar = screen.getByRole('group', { name: locale === 'en' ? 'Search coverage' : 'Suchabdeckung' });
        labels.forEach((label, i) => expect(within(toolbar).getByRole('button', { name: `${label} ${[5, 2, 1, 1, 1][i]}` })).toHaveAttribute('aria-pressed', i === 0 ? 'true' : 'false'));
        expect(screen.getByText(locale === 'en' ? 'Devices on this page only. No match does not prove absence.' : 'Nur Geräte dieser Seite. Kein Treffer belegt nicht, dass Software fehlt.')).toBeVisible();
        const unclear = within(toolbar).getByRole('button', { name: `${labels[2]} 1` }); unclear.focus(); fireEvent.click(unclear);
        expect(unclear).toHaveFocus(); expect(unclear).toHaveAttribute('aria-pressed', 'true');
        expect(within(screen.getByRole('list', { name: 'Device cards' })).getAllByRole('listitem')).toHaveLength(1);
        expect(screen.getByRole('list', { name: 'Device cards' })).toHaveTextContent(fleetSoftwareDevice(1));
        fireEvent.click(within(toolbar).getByRole('button', { name: `${labels[0]} 5` }));
        expect(within(screen.getByRole('list', { name: 'Device cards' })).getAllByRole('listitem').map(node => node.textContent)).toEqual(page.items.map(item => item.deviceId));
        expect(JSON.stringify(page)).toBe(original); expect(fetch).not.toHaveBeenCalled(); expect(local).not.toHaveBeenCalled();
        expect(toolbar.querySelectorAll('svg[aria-hidden="true"]')).toHaveLength(5);
    });
    it.each(['not_configured', 'disabled', 'awaiting', 'unavailable'] as const)('keeps %s separate from negative evidence', status => {
        const page = fleetSoftwarePage(undefined, 1); Object.assign(page.items[0], { status, complete: null, matchingCount: 0, unknownCount: 0, rows: [] });
        render(summary(page)); expect(within(group()).getByRole('button', { name: 'No complete capture 1' })).toBeVisible();
        expect(within(group()).getByRole('button', { name: 'No reported match 0' })).toBeVisible();
    });
    it.each(['query', 'page', 'generation', 'identity'] as const)('starts with all devices after %s replacement', change => {
        const page = fleetSoftwarePage(); mixed(page); const ui = render(summary(page)); choose('Unclear');
        const next = structuredClone(page);
        if (change === 'query') next.name = 'Other';
        if (change === 'page') next.offset = 5;
        if (change === 'generation') next.items[0].complete!.manifest.generationId = 'a'.repeat(64);
        if (change === 'identity') next.items[0].identity = 'b'.repeat(64);
        ui.rerender(summary(next)); expect(within(group()).getByRole('button', { name: 'All 5' })).toHaveAttribute('aria-pressed', 'true');
        expect(within(screen.getByRole('list', { name: 'Device cards' })).getAllByRole('listitem')).toHaveLength(5);
    });
    it('never presents device-detail rows or an empty roster as fleet coverage', () => {
        const page = fleetSoftwarePage(undefined, 1); page.mode = 'device'; const ui = render(summary(page)); expect(screen.queryByRole('group')).toBeNull();
        ui.rerender(summary(fleetSoftwarePage(undefined, 0))); expect(screen.queryByRole('group')).toBeNull();
    });
});

describe('coverage integration and privacy', () => {
    it('filters without another read; retains evidence, source controls, paging and detail behavior', async () => {
        const api = server(); await open(); expect(cards()).toHaveLength(5); const calls = api.fetch.mock.calls.length;
        choose('Unclear'); expect(cards()).toHaveLength(1); expect(cards()[0]).toHaveTextContent(fleetSoftwareDevice(1));
        expect(cards()[0]).toHaveTextContent('Registrations with unavailable queried fields: 4');
        expect(within(cards()[0] as HTMLElement).getByText('Scope and original capture')).toBeVisible();
        expect(screen.getByText('Devices: 1–5 of 6')).toBeVisible(); expect(api.fetch).toHaveBeenCalledTimes(calls);
        choose('No complete capture'); expect(cards()[0]).toHaveTextContent('Collection disabled');
        choose('With matches'); expect(cards()).toHaveLength(2); expect(cards()[0]).toHaveTextContent('Reported matches: 23');
        fireEvent.click(screen.getByRole('button', { name: `View all matching registrations: ${fleetSoftwareDevice(0)}` })); await flush();
        expect(screen.queryByRole('group', { name: 'Search coverage' })).toBeNull(); expect(document.querySelectorAll('tbody tr')).toHaveLength(20);
        fireEvent.click(screen.getByRole('button', { name: 'Back to search' })); await flush();
        // Back clears private results; a new deliberate search is required by the original reader.
        expect(screen.queryByRole('group', { name: 'Search coverage' })).toBeNull();
        fireEvent.click(screen.getByRole('button', { name: 'Search reported software' })); await flush();
        expect(within(group()).getByRole('button', { name: 'All 5' })).toHaveAttribute('aria-pressed', 'true');
        choose('Unclear'); fireEvent.click(screen.getByRole('button', { name: 'Next devices' })); await flush();
        expect(cards()).toHaveLength(1); expect(within(group()).getByRole('button', { name: 'All 1' })).toHaveAttribute('aria-pressed', 'true');
        choose('Unclear'); expect(cards()).toHaveLength(0); expect(screen.getByText('No devices in this group on this page.')).toBeVisible();
    });
    it('keeps next-page navigation accessible when a selected category is empty', async () => {
        const api = server(); api.fetch.mockImplementation(async (path, options) => path === '/api/session' ? response({ csrfToken: 'fixture-csrf' }) : response(fleetSoftwarePage(JSON.parse(options!.body as string))));
        await open(); choose('Unclear'); expect(cards()).toHaveLength(0);
        const next = screen.getByRole('button', { name: 'Next devices' }); expect(next).toBeEnabled(); fireEvent.click(next); await flush(); expect(cards()).toHaveLength(1);
    });
    it('does not turn retained matches into fresh or successful latest captures', async () => {
        const api = server(); api.fetch.mockImplementation(async (path, options) => {
            if (path === '/api/session') return response({ csrfToken: 'fixture-csrf' });
            const page = fleetSoftwarePage(JSON.parse(options!.body as string), 1);
            page.items[0].latestAttempt = { sequence: 2, attemptedAt: fleetSoftwareNow, status: 'source_failed', reason: 'unavailable' }; return response(page);
        });
        await open(); choose('With matches'); act(() => vi.advanceTimersByTime(111000));
        expect(cards()).toHaveLength(1); expect(cards()[0]).toHaveTextContent('Stale capture'); expect(cards()[0]).toHaveTextContent('Latest capture failed');
        expect(cards()[0]).toHaveTextContent('Showing the earlier complete capture with its original age.');
        expect(within(group()).getByRole('button', { name: 'With matches 1' })).toHaveAttribute('aria-pressed', 'true');
    });
    it.each(['blur', 'pagehide', 'hidden', 'close', 'clear', 'auth', 'actor', 'expiry'] as const)('clears coverage and filtered evidence on %s', async event => {
        const api = server(), ui = await open(); choose('Unclear'); expect(cards()).toHaveLength(1);
        act(() => {
            if (event === 'close') fireEvent.click(screen.getByRole('button', { name: 'Close software lookup' }));
            else if (event === 'clear') fireEvent.click(screen.getByRole('button', { name: 'Clear search' }));
            else if (event === 'hidden') { vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden'); document.dispatchEvent(new Event('visibilitychange')); }
            else if (event === 'actor') { vi.mocked(useOperator).mockReturnValue({ ...operator(), actorId: `operator_${'b'.repeat(32)}` }); ui.rerender(<WindowsFleetSoftwareLookup/>); }
            else if (event === 'expiry') vi.advanceTimersByTime(300000);
            else window.dispatchEvent(new Event(event === 'auth' ? AUTH_REQUIRED_EVENT : event));
        });
        expect(screen.queryByRole('group', { name: 'Search coverage' })).toBeNull(); expect(cards()).toHaveLength(0);
        expect(document.body).not.toHaveTextContent(fleetSoftwareDevice(1)); expect(api.requests).toHaveLength(1);
    });
    it('does not restore a selected group from a late response after focus loss', async () => {
        const api = server(); await open(); choose('Unclear');
        let resolve!: (value: Response) => void;
        api.fetch.mockImplementation(async () => new Promise(done => { resolve = done; }));
        fireEvent.click(screen.getByRole('button', { name: 'Next devices' })); await flush();
        act(() => window.dispatchEvent(new Event('blur')));
        await act(async () => resolve(response(fleetSoftwarePage())));
        expect(screen.queryByRole('group', { name: 'Search coverage' })).toBeNull(); expect(cards()).toHaveLength(0);
    });
});
