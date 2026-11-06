import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, AUTH_REQUIRED_EVENT } from './api';
import { useOperator } from './auth';
import { setLocale } from './i18n';
import { WindowsSoftwareHistoryPanel } from './windows-software-history';
import { softwareHistoryDevice, softwareHistoryNow, softwareHistoryPage, softwareHistoryQuery, softwareHistoryRows } from './windows-software-history-fixtures';
import { validSoftwareHistoryPage } from './windows-software-history-types';
import type { SoftwareHistoryChange, SoftwareHistoryPage, SoftwareHistoryQuery } from './windows-software-history-types';
import { WindowsSoftwareRegistrationTrails } from './windows-software-registration-trails';

vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
function trailRows(): SoftwareHistoryChange[] {
    const old = { ...softwareHistoryRows(1)[0].after!, name: 'Original name', version: '1.0' };
    const next = { ...old, name: 'Renamed registration', version: '2.0', publisher: null, publisherQuality: 'unavailable' as const };
    const base = { registrationId: old.registrationId, registryView: old.registryView };
    const early: SoftwareHistoryChange = { ...base, id: '1'.repeat(64), kind: 'registration_added', before: null, after: old, changedFields: [], beforeObservedAt: '2026-10-11T03:00:01Z', afterObservedAt: '2026-10-11T04:00:01Z', expiresAt: '2026-10-18T03:00:00Z' };
    const middle: SoftwareHistoryChange = { ...base, id: '2'.repeat(64), kind: 'metadata_changed', before: old, after: next, changedFields: ['name', 'version'], beforeObservedAt: early.afterObservedAt, afterObservedAt: '2026-10-11T05:00:01Z', expiresAt: '2026-10-18T04:00:00Z' };
    const late: SoftwareHistoryChange = { ...base, id: '3'.repeat(64), kind: 'registration_removed', before: next, after: null, changedFields: [], beforeObservedAt: middle.afterObservedAt, afterObservedAt: '2026-10-11T06:00:01Z', expiresAt: '2026-10-18T05:00:00Z' };
    return [late, middle, early];
}
function page(): SoftwareHistoryPage { return softwareHistoryPage(softwareHistoryQuery, trailRows()); }
const outer = () => document.querySelector('details.windows-registration-trails') as HTMLDetailsElement;
const group = () => document.querySelector('details.windows-registration-trail') as HTMLDetailsElement;
function expand() { fireEvent.click(outer().querySelector('summary')!); fireEvent.click(group().querySelector('summary')!); }
const ids = () => Array.from(document.querySelectorAll('[data-trail-change]')).map(node => node.getAttribute('data-trail-change'));
const flush = () => act(async () => { for (let i = 0; i < 12; i++) await Promise.resolve(); });
beforeEach(() => {
    setLocale('en', false);
    vi.mocked(useOperator).mockReturnValue({ mode: 'lan', authenticated: true, expiresAt: 'synthetic-session', insecureTestMode: false, logout: vi.fn(), theme: 'light', setTheme: vi.fn() });
});
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe('exact-registration observation trails', () => {
    it.each(['en', 'de'] as const)('follows renamed/removed registrations with original paired evidence in %s', locale => {
        const p = page(), original = JSON.stringify(p);
        expect(validSoftwareHistoryPage(p, softwareHistoryDevice, softwareHistoryQuery, 0)).toBe(true);
        render(<WindowsSoftwareRegistrationTrails page={p} locale={locale}/>); expand();
        expect(outer()).toHaveAttribute('open'); expect(group()).toHaveAttribute('open');
        expect(group().querySelector('summary')).toHaveTextContent('Renamed registration');
        expect(ids()).toEqual([...p.rows].reverse().map(row => row.id));
        const values = screen.getByRole('table', { name: locale === 'en' ? 'First and last shown observations' : 'Erste und letzte angezeigte Beobachtung' });
        expect(within(values).getAllByText(locale === 'en' ? 'Not in this capture' : 'Nicht in dieser Erfassung')).toHaveLength(6);
        const observation = group().querySelector('.windows-registration-observations')!;
        expect(observation.querySelectorAll('time')[0]).toHaveAttribute('dateTime', p.rows[2].beforeObservedAt);
        expect(observation.querySelectorAll('time')[1]).toHaveAttribute('dateTime', p.rows[0].afterObservedAt);
        const middle = document.querySelector(`[data-trail-change="${p.rows[1].id}"]`)!;
        fireEvent.click(middle.querySelector('summary')!);
        expect(within(middle as HTMLElement).getByText('Original name')).toBeVisible();
        expect(within(middle as HTMLElement).getByText('Renamed registration')).toBeVisible();
        expect(within(middle as HTMLElement).getByText(locale === 'en' ? 'Unavailable' : 'Nicht verfügbar')).toBeVisible();
        expect(middle.querySelector('p')).toHaveTextContent(locale === 'en' ? 'Observed changed fields: Name, Version' : 'Beobachtete geänderte Felder: Name, Version');
        expect(middle.querySelector('p')).not.toHaveTextContent(locale === 'en' ? 'Publisher' : 'Herausgeber');
        expect(outer()).toHaveTextContent(locale === 'en' ? 'not a complete lifetime' : 'weder ein vollständiger Lebenslauf');
        expect(JSON.stringify(p)).toBe(original);
    });
    it('does not join equal display names, registry views, or single occurrences', () => {
        const p = page(), other = structuredClone(p.rows);
        for (const row of other) { row.registrationId = 'd'.repeat(64); row.id = `d${row.id.slice(1)}`; for (const value of [row.before, row.after]) if (value) value.registrationId = row.registrationId; }
        const differentView = structuredClone(p.rows);
        for (const row of differentView) { row.registryView = '64'; row.id = `e${row.id.slice(1)}`; for (const value of [row.before, row.after]) if (value) value.registryView = '64'; }
        const singleton = structuredClone(p.rows[0]); singleton.registrationId = 'f'.repeat(64); singleton.id = 'f'.repeat(64);
        p.rows = [...p.rows, ...other, ...differentView, singleton];
        render(<WindowsSoftwareRegistrationTrails page={p} locale="en"/>);
        const groups = document.querySelectorAll('[data-registration-trail]');
        expect(groups).toHaveLength(3); expect(new Set(Array.from(groups).map(node => node.getAttribute('data-registration-trail'))).size).toBe(3);
        expect(document.querySelector(`[data-trail-change="${singleton.id}"]`)).toBeNull();
        expect(ids()).toHaveLength(9);
    });
    it('orders sub-millisecond observations correctly and preserves response ties', () => {
        const p = page();
        p.rows[0].afterObservedAt = '2026-10-11T06:00:01.000000003Z';
        p.rows[1].afterObservedAt = '2026-10-11T06:00:01.000000001Z';
        p.rows[2].afterObservedAt = p.rows[1].afterObservedAt;
        const original = JSON.stringify(p.rows);
        render(<WindowsSoftwareRegistrationTrails page={p} locale="en"/>);
        expect(ids()).toEqual([p.rows[1].id, p.rows[2].id, p.rows[0].id]); expect(JSON.stringify(p.rows)).toBe(original);
        expand(); const time = group().querySelector(`time[datetime="${p.rows[1].afterObservedAt}"]`)!;
        expect(time.querySelector('small')).toHaveTextContent(p.rows[1].afterObservedAt); expect(time.querySelector('small')).toBeVisible();
    });
    it('distinguishes empty and unavailable values and renders hostile text literally', () => {
        const p = page(); p.rows = p.rows.slice(1); p.rows[1].before = { ...p.rows[1].after!, name: '', version: null, versionQuality: 'unavailable' };
        p.rows[0].after!.name = '<img src=x onerror=alert(1)>'; p.rows[0].after!.publisher = '';
        render(<WindowsSoftwareRegistrationTrails page={p} locale="en"/>); expand();
        const values = screen.getByRole('table', { name: 'First and last shown observations' });
        expect(values).toHaveTextContent('Empty value'); expect(values).toHaveTextContent('Unavailable'); expect(values).toHaveTextContent('<img src=x onerror=alert(1)>');
        expect(document.querySelector('img,script')).toBeNull();
    });
    it('does not claim completeness or duplicate the singleton change table', () => {
        const p = page(); p.search = 'Renamed'; p.matchingCount = 150; p.retainedCount = 200; p.offset = 100;
        const view = render(<WindowsSoftwareRegistrationTrails page={p} locale="en"/>);
        expect(outer()).toHaveTextContent('Search and other pages may hide earlier, later or intervening evidence');
        view.rerender(<WindowsSoftwareRegistrationTrails page={softwareHistoryPage()} locale="en"/>); expect(outer()).toBeNull();
    });
    it.each(['deviceId', 'grantId', 'grantRevision', 'historyDigest', 'search', 'offset'] as const)('closes native disclosures when %s changes', field => {
        const p = page(), view = render(<WindowsSoftwareRegistrationTrails page={p} locale="en"/>); expand();
        const next = { ...p, [field]: typeof p[field] === 'number' ? Number(p[field]) + 1 : `${p[field]}-different` };
        view.rerender(<WindowsSoftwareRegistrationTrails page={next} locale="en"/>);
        expect(outer()).not.toHaveAttribute('open'); expect(group()).not.toHaveAttribute('open');
    });
});

function server(rows = trailRows()) {
    const started = Date.now(), requests: SoftwareHistoryQuery[] = [], state = { hold: null as Promise<void> | null, lifetime: 900000 };
    vi.stubGlobal('fetch', vi.fn(async (path: string, options?: RequestInit) => {
        if (path === '/api/session') return new Response(JSON.stringify({ csrfToken: 'synthetic-csrf' }));
        if (!/^\/api\/devices\/agent_[a-f0-9]{32}\/windows-software-history\/query$/.test(path)) throw new Error('Unexpected request');
        const query = JSON.parse(options!.body as string) as SoftwareHistoryQuery; requests.push(query);
        const offset = query.cursor ? Number(query.cursor.match(/^history_(\d+)\./)?.[1]) : 0;
        const p = softwareHistoryPage(query, rows, offset); p.deviceId = path.split('/')[3];
        p.serverNow = new Date(Date.parse(softwareHistoryNow) + Date.now() - started).toISOString();
        p.cursorExpiresAt = new Date(Date.parse(softwareHistoryNow) + state.lifetime).toISOString();
        if (state.hold) await state.hold;
        return new Response(JSON.stringify(p));
    }));
    return { requests, state };
}
const open = () => render(<WindowsSoftwareHistoryPanel deviceId={softwareHistoryDevice} sessionKey="session-a"/>);
describe('registration trails inside the original private reader', () => {
    it('does not accumulate evidence across pages or search changes', async () => {
        const singletons = softwareHistoryRows(101).map((row, index) => {
            const next = structuredClone(row); next.id = (index + 10).toString(16).padStart(64, '0'); next.registrationId = (index + 1000).toString(16).padStart(64, '0');
            for (const value of [next.before, next.after]) if (value) value.registrationId = next.registrationId;
            next.beforeObservedAt = '2026-10-11T01:00:01Z'; next.afterObservedAt = '2026-10-11T02:00:01Z'; next.expiresAt = '2026-10-18T01:00:00Z';
            return next;
        });
        const s = server([...trailRows(), ...singletons]); open(); await screen.findByRole('table', { name: 'Change history' }); expand();
        fireEvent.click(screen.getByRole('button', { name: 'Next history page' })); expect(outer()).toBeNull();
        await waitFor(() => expect(document.querySelectorAll('[data-history-id]')).toHaveLength(4));
        expect(outer()).toBeNull(); expect(ids()).toHaveLength(0);
        fireEvent.click(screen.getByRole('button', { name: 'Previous history page' }));
        await waitFor(() => expect(outer()).not.toBeNull()); expect(outer()).not.toHaveAttribute('open');
        expand(); fireEvent.change(screen.getByRole('searchbox'), { target: { value: 'Renamed registration' } });
        expect(outer()).toBeNull(); expect(s.requests).toHaveLength(3);
        fireEvent.click(screen.getByRole('button', { name: 'Apply' }));
        await waitFor(() => expect(outer()).not.toBeNull()); expect(outer()).not.toHaveAttribute('open'); expect(ids()).toHaveLength(2);
        expect(s.requests).toHaveLength(4); expect(s.requests[3]).toEqual({ ...softwareHistoryQuery, search: 'Renamed registration' });
    });
    it('adds no I/O or storage and leaves source counters and table unchanged', async () => {
        const s = server(); open(); await screen.findByRole('table', { name: 'Change history' });
        const counts = document.querySelector('.windows-history-counts')!.textContent, storage = vi.spyOn(Storage.prototype, 'setItem');
        expand(); fireEvent.click(group().querySelector('li summary')!);
        expect(s.requests).toEqual([softwareHistoryQuery]); expect(storage).not.toHaveBeenCalled();
        expect(document.querySelector('.windows-history-counts')!.textContent).toBe(counts);
        expect(document.querySelectorAll('[data-history-id]')).toHaveLength(3);
        expect(screen.getByRole('searchbox')).toHaveValue('');
    });
    it.each(['blur', 'auth', 'hidden'])('immediately removes an open idle trail on %s', async event => {
        const s = server(); open(); await screen.findByRole('table', { name: 'Change history' }); expand();
        expect(group()).toHaveAttribute('open'); expect(ids()).toHaveLength(3);
        if (event === 'hidden') { vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden'); fireEvent(document, new Event('visibilitychange')); }
        else fireEvent(window, new Event(event === 'auth' ? AUTH_REQUIRED_EVENT : event));
        expect(outer()).toBeNull(); expect(ids()).toHaveLength(0); expect(s.requests).toHaveLength(1);
    });
    it.each(['blur', 'pagehide', 'hashchange', 'auth', 'hidden'])('clears trails after %s and suppresses a late response', async event => {
        const s = server(); open(); await screen.findByRole('table', { name: 'Change history' }); expand();
        let release!: () => void; s.state.hold = new Promise(resolve => { release = resolve; });
        fireEvent.click(screen.getByRole('button', { name: 'Refresh software history' }));
        await waitFor(() => expect(s.requests).toHaveLength(2)); expect(outer()).toBeNull();
        if (event === 'hidden') { vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden'); fireEvent(document, new Event('visibilitychange')); }
        else fireEvent(window, new Event(event === 'auth' ? AUTH_REQUIRED_EVENT : event));
        release(); await flush(); expect(outer()).toBeNull(); expect(ids()).toHaveLength(0); expect(s.requests).toHaveLength(2);
    });
    it.each(['device', 'session', 'disabled'])('clears all trail content across %s transitions', async context => {
        const s = server(), view = open(); await screen.findByRole('table', { name: 'Change history' }); expand();
        view.rerender(<WindowsSoftwareHistoryPanel deviceId={context === 'device' ? `agent_${'b'.repeat(32)}` : softwareHistoryDevice} sessionKey={context === 'session' ? 'session-b' : 'session-a'} enabled={context !== 'disabled'}/>);
        expect(outer()).toBeNull(); expect(ids()).toHaveLength(0);
        if (context !== 'disabled') { await screen.findByRole('table', { name: 'Change history' }); expect(outer()).not.toHaveAttribute('open'); expect(s.requests).toHaveLength(2); }
        else expect(s.requests).toHaveLength(1);
    });
    it('drops the open trail at the original expiry without extending the lease', async () => {
        vi.useFakeTimers(); const s = server(); s.state.lifetime = 1000; open(); await flush(); expand();
        await act(async () => vi.advanceTimersByTimeAsync(600)); fireEvent.click(group().querySelector('li summary')!);
        await act(async () => vi.advanceTimersByTimeAsync(400)); expect(outer()).toBeNull(); expect(ids()).toHaveLength(0); expect(s.requests).toHaveLength(1);
    });
});
