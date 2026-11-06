import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, AUTH_REQUIRED_EVENT } from './api';
import { useOperator } from './auth';
import { setLocale } from './i18n';
import { WindowsFullProcessesPanel } from './windows-full-processes';
import { fullProcessesComplete, fullProcessesDevice, fullProcessesNow, fullProcessesPage, fullProcessesQuery, fullProcessesRows, replaceFullProcessesGeneration } from './windows-full-processes-fixtures';
import type { FullProcessesQuery, FullProcessesRow } from './windows-full-processes-types';
import { sharedParentReferences, WindowsProcessParentReferences } from './windows-process-parent-references';

vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
const title = 'Shared parent PID references';
const row = (pid: number, parentPid: number, name: string | null = `Process ${pid}`, threads = 3): FullProcessesRow => ({ pid, parentPid, name, nameQuality: name === null ? 'unavailable' : 'observed', threads });
function pageFor(rows: FullProcessesRow[]) {
    const complete = fullProcessesComplete(); replaceFullProcessesGeneration(complete, rows, 1);
    return fullProcessesPage(fullProcessesQuery, rows, complete);
}
const summary = (name = title) => screen.getByText(name, { selector: 'strong' }).closest('summary')!;
function toggle(target: HTMLElement, open = true) {
    const details = target.closest('details')!;
    act(() => { details.open = open; fireEvent(details, new Event('toggle')); });
    return details;
}
const groupSummaries = () => Array.from(document.querySelectorAll<HTMLElement>('.windows-process-parent-group>summary'));
const visibleNames = () => Array.from(document.querySelectorAll('.windows-process-parent-name')).map(e => e.textContent);
const flush = async () => { await act(async () => { for (let i = 0; i < 12; i++) await Promise.resolve(); }); };
beforeEach(() => {
    setLocale('en', false);
    vi.mocked(useOperator).mockReturnValue({ mode: 'lan', authenticated: true, expiresAt: 'synthetic-session', insecureTestMode: false, logout: vi.fn(), theme: 'light', setTheme: vi.fn() });
});
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe('shared captured parent PID references', () => {
    it('groups exact numeric references in first-member order without sorting or mutating rows', () => {
        const rows = [row(7, 20), row(9, 3), row(1, 20), row(5, 3), row(2, 9)];
        rows.forEach(Object.freeze); Object.freeze(rows);
        const groups = sharedParentReferences(rows);
        expect(groups.map(([pid, members]) => [pid, members.map(r => r.pid)])).toEqual([[20, [7, 1]], [3, [9, 5]]]);
        expect(groups[0][1][0]).toBe(rows[0]); expect(rows.map(r => r.pid)).toEqual([7, 9, 1, 5, 2]);
    });
    it('preserves zero, self references, cycles, absent parent rows and maximum uint32 literally', () => {
        const rows = [row(0, 0), row(1, 0), row(4, 5), row(5, 4), row(6, 5), row(8, 0xffffffff), row(9, 0xffffffff)];
        expect(sharedParentReferences(rows).map(([pid, members]) => [pid, members.map(r => r.pid)])).toEqual([[0, [0, 1]], [5, [4, 6]], [0xffffffff, [8, 9]]]);
    });
    it.each(['en', 'de'] as const)('starts compact and exposes bounded truthful labels with native disclosures (%s)', locale => {
        render(<WindowsProcessParentReferences page={pageFor([row(1, 8), row(2, 8), row(3, 7)])} locale={locale}/>);
        const name = locale === 'en' ? title : 'Gemeinsame Eltern-PID-Verweise';
        expect(summary(name).parentElement).not.toHaveAttribute('open'); expect(groupSummaries()).toHaveLength(0);
        const icon = summary(name).querySelector('svg')!; expect(icon).toHaveAttribute('aria-hidden', 'true'); expect(icon).toHaveAttribute('focusable', 'false');
        toggle(summary(name)); expect(groupSummaries()).toHaveLength(1);
        expect(groupSummaries()[0]).toHaveTextContent(locale === 'en' ? 'Reported parent PID: 8Rows on page: 2' : 'Gemeldete Eltern-PID: 8Zeilen auf Seite: 2');
        expect(screen.getByText(locale === 'en' ? /not a verified process tree/ : /kein bestätigter Prozessbaum/)).toBeVisible();
        expect(screen.getByText(locale === 'en' ? /Search and paging may split groups/ : /Suche und Seitenwechsel/)).toBeVisible();
        expect(groupSummaries()[0].parentElement).not.toHaveAttribute('open'); toggle(groupSummaries()[0]);
        expect(visibleNames()).toEqual(['Process 1', 'Process 2']); expect(screen.queryByText('Process 3')).toBeNull();
        expect(document.querySelectorAll('.windows-process-parent-rows dl')).toHaveLength(2);
    });
    it('keeps hostile and unavailable names literal with original PID and thread values', () => {
        const page = pageFor([row(1, 9, '<img onerror=alert(1)>', 0), row(2, 9, null, 0xffffffff), row(3, 9, '  Mixed CASE  ')]);
        render(<WindowsProcessParentReferences page={page} locale="en"/>); toggle(summary()); toggle(groupSummaries()[0]);
        expect(visibleNames()).toEqual(['<img onerror=alert(1)>', 'Name unavailable', '  Mixed CASE  ']); expect(document.querySelector('img')).toBeNull();
        const values = Array.from(document.querySelectorAll('.windows-process-parent-rows dd')).map(e => e.textContent);
        expect(values).toEqual(['1', '0', '2', '4294967295', '3', '3']);
    });
    it('does not look up a matching parent row or call matching names a family', () => {
        const page = pageFor([row(2, 0, 'Potential parent'), row(3, 2, 'same.exe'), row(4, 2, 'same.exe')]);
        render(<WindowsProcessParentReferences page={page} locale="en"/>); toggle(summary());
        expect(visibleNames()).toEqual(['same.exe', 'same.exe']); expect(screen.queryByText('Potential parent')).toBeNull();
        expect(document.body.textContent).not.toMatch(/family|children|root process|CPU|RAM|healthy/i);
    });
    it('shows a local empty result without inferring missing endpoint relationships', () => {
        render(<WindowsProcessParentReferences page={pageFor([row(1, 3), row(2, 4)])} locale="en"/>); toggle(summary());
        expect(screen.getByText('No shared parent PID on this page.')).toBeVisible(); expect(groupSummaries()).toHaveLength(0);
    });
    it('bounds one expanded group to the original 100 current rows without extrapolating counts', () => {
        const rows = fullProcessesRows(150).map(r => ({ ...r, parentPid: 12345 })), page = pageFor(rows);
        render(<WindowsProcessParentReferences page={page} locale="en"/>); toggle(summary()); toggle(groupSummaries()[0]);
        expect(groupSummaries()[0]).toHaveTextContent('Rows on page: 100'); expect(visibleNames()).toHaveLength(100);
        expect(screen.queryByText('Fixture Process 0100')).toBeNull(); expect(document.body.textContent).not.toContain('150');
    });
    it('renders at most 50 repeated-reference groups for a 100-row page', () => {
        render(<WindowsProcessParentReferences page={fullProcessesPage()} locale="en"/>); toggle(summary());
        expect(groupSummaries()).toHaveLength(50); expect(visibleNames()).toHaveLength(100);
    });
    it.each(['not_configured', 'disabled', 'awaiting', 'unavailable'] as const)('does not expose retained rows under %s', status => {
        render(<WindowsProcessParentReferences page={{ ...fullProcessesPage(), status }} locale="en"/>); expect(screen.queryByText(title)).toBeNull();
    });
    it.each(['empty', 'no complete source', 'oversized'] as const)('does not render an %s page', variant => {
        const page = fullProcessesPage(); if (variant === 'empty') page.rows = []; else if (variant === 'oversized') page.rows = fullProcessesRows(101); else page.complete = null;
        render(<WindowsProcessParentReferences page={page} locale="en"/>); expect(screen.queryByText(title)).toBeNull();
    });
    it.each(['source', 'authority', 'cursor expiry', 'query', 'sort', 'page', 'rows', 'device'] as const)('closes disclosure when %s changes without retaining a private selection', change => {
        const page = fullProcessesPage(), view = render(<WindowsProcessParentReferences page={page} locale="en"/>); toggle(summary()); toggle(groupSummaries()[0]);
        const next = structuredClone(page);
        if (change === 'source') next.complete!.manifest.sequence++;
        if (change === 'authority') next.authorityUntil = '2026-10-12T04:00:00Z';
        if (change === 'cursor expiry') next.cursorExpiresAt = '2026-10-11T06:12:00Z';
        if (change === 'query') next.search = 'Process';
        if (change === 'sort') next.sort = 'name-desc';
        if (change === 'page') next.offset = 100;
        if (change === 'rows') next.rows[0].name = 'Changed row';
        if (change === 'device') next.deviceId = `agent_${'a'.repeat(32)}`;
        view.rerender(<WindowsProcessParentReferences page={next} locale="en"/>);
        expect(summary().parentElement).not.toHaveAttribute('open'); expect(groupSummaries()).toHaveLength(0); expect(visibleNames()).toHaveLength(0);
    });
    it('keeps same-page language changes local and closes inner groups after outer close/reopen', () => {
        const page = fullProcessesPage(), view = render(<WindowsProcessParentReferences page={page} locale="en"/>); toggle(summary()); toggle(groupSummaries()[0]);
        view.rerender(<WindowsProcessParentReferences page={page} locale="de"/>); const deSummary = summary('Gemeinsame Eltern-PID-Verweise');
        expect(deSummary.parentElement).toHaveAttribute('open'); expect(groupSummaries()[0]).toHaveTextContent('Gemeldete Eltern-PID');
        toggle(deSummary, false); expect(groupSummaries()).toHaveLength(0); toggle(deSummary); expect(groupSummaries()[0].parentElement).not.toHaveAttribute('open');
    });
    it('never issues a read, storage write, navigation, timer or action during repeated local toggles', () => {
        const fetch = vi.fn(); vi.stubGlobal('fetch', fetch);
        const local = vi.spyOn(Storage.prototype, 'setItem'), push = vi.spyOn(history, 'pushState'), interval = vi.spyOn(window, 'setInterval');
        render(<WindowsProcessParentReferences page={fullProcessesPage()} locale="en"/>);
        for (let i = 0; i < 3; i++) { toggle(summary()); toggle(groupSummaries()[0]); toggle(summary(), false); }
        expect(fetch).not.toHaveBeenCalled(); expect(local).not.toHaveBeenCalled(); expect(push).not.toHaveBeenCalled(); expect(interval).not.toHaveBeenCalled(); expect(screen.queryByRole('button')).toBeNull();
    });
});

function server() {
    const rows = fullProcessesRows(), complete = fullProcessesComplete(), began = Date.now();
    const state = { failure: 0, expire: false, delay: null as Promise<Response> | null, queries: [] as FullProcessesQuery[] };
    const fetch = vi.fn(async (path: string, options?: RequestInit) => {
        if (path === '/api/session') return new Response(JSON.stringify({ csrfToken: 'synthetic-csrf' }));
        if (path !== `/api/devices/${fullProcessesDevice}/windows-full-processes/query`) return new Response('{}', { status: 404 });
        const query = JSON.parse(options!.body as string) as FullProcessesQuery; state.queries.push(query);
        if (state.delay) return state.delay;
        if (state.failure) return new Response('{}', { status: state.failure });
        const offset = query.cursor ? Number(query.cursor.split('.')[0].slice(7)) : 0;
        const page = fullProcessesPage(query, rows, complete, offset);
        page.serverNow = new Date(Date.parse(fullProcessesNow) + Date.now() - began).toISOString();
        if (state.expire) page.authorityUntil = page.cursorExpiresAt = '2026-10-11T06:00:11Z';
        return new Response(JSON.stringify(page));
    });
    vi.stubGlobal('fetch', fetch); return { state, fetch };
}
const panel = (sessionKey = 'session-a', enabled = true) => <WindowsFullProcessesPanel deviceId={fullProcessesDevice} sessionKey={sessionKey} enabled={enabled}/>;

describe('parent reference integration with existing complete-process ownership', () => {
    it('opens locally without changing source order, capture times, watch choices or requests', async () => {
        const s = server(); render(panel()); await screen.findByRole('table'); const originalRows = screen.getByRole('table').textContent;
        const times = Array.from(document.querySelectorAll('time')).map(t => t.dateTime), requests = s.fetch.mock.calls.length;
        toggle(summary()); toggle(groupSummaries()[0]);
        expect(screen.getByRole('table').textContent).toBe(originalRows); expect(Array.from(document.querySelectorAll('time')).map(t => t.dateTime)).toEqual(times);
        expect(s.fetch).toHaveBeenCalledTimes(requests); expect(screen.queryByRole('checkbox')).toBeNull();
    });
    it('removes groups on a draft edit and resets them after explicit apply', async () => {
        const s = server(); render(panel()); await screen.findByRole('table'); toggle(summary());
        fireEvent.change(screen.getByRole('searchbox'), { target: { value: 'Fixture Process 000' } });
        expect(screen.queryByText(title)).toBeNull(); expect(visibleNames()).toHaveLength(0); expect(s.state.queries).toHaveLength(1);
        fireEvent.click(screen.getByRole('button', { name: 'Apply' })); await screen.findByRole('table'); expect(summary().parentElement).not.toHaveAttribute('open'); toggle(summary());
        expect(visibleNames()).toHaveLength(10); expect(s.state.queries).toHaveLength(2);
    });
    it('replaces the loaded page without accumulating or reopening groups on later/backward pages', async () => {
        const s = server(); render(panel()); await screen.findByRole('table'); toggle(summary());
        fireEvent.click(screen.getByRole('button', { name: 'Next process page' })); await waitFor(() => expect(screen.getByRole('table')).toHaveTextContent('Fixture Process 0100'));
        expect(summary().parentElement).not.toHaveAttribute('open'); toggle(summary()); expect(visibleNames()).toHaveLength(100); expect(visibleNames()[0]).toBe('Fixture Process 0100'); expect(visibleNames()).not.toContain('Fixture Process 0000');
        fireEvent.click(screen.getByRole('button', { name: 'Previous process page' })); await waitFor(() => expect(screen.getByRole('table')).toHaveTextContent('Fixture Process 0000'));
        expect(summary().parentElement).not.toHaveAttribute('open'); expect(s.state.queries).toHaveLength(3);
    });
    it('hides groups during a same-source reread and cannot restore a late result after privacy loss', async () => {
        const s = server(); render(panel()); await screen.findByRole('table'); toggle(summary()); let resolve!: (response: Response) => void;
        s.state.delay = new Promise<Response>(done => { resolve = done; }); fireEvent.click(screen.getByRole('button', { name: 'Refresh process inventory' })); await flush();
        expect(screen.queryByText(title)).toBeNull(); expect(visibleNames()).toHaveLength(0);
        act(() => window.dispatchEvent(new Event('blur'))); await act(async () => resolve(new Response(JSON.stringify(fullProcessesPage())))); await flush();
        expect(screen.queryByText(title)).toBeNull(); expect(s.state.queries).toHaveLength(2);
    });
    it.each(['blur', 'pagehide', 'hashchange', AUTH_REQUIRED_EVENT])('clears expanded private groups on %s without another request', async event => {
        const s = server(); render(panel()); await screen.findByRole('table'); toggle(summary()); toggle(groupSummaries()[0]); const count = s.fetch.mock.calls.length;
        act(() => window.dispatchEvent(new Event(event))); expect(screen.queryByText(title)).toBeNull(); expect(visibleNames()).toHaveLength(0); expect(s.fetch).toHaveBeenCalledTimes(count);
    });
    it('clears groups on hidden visibility and restores only collapsed after the existing refresh', async () => {
        server(); render(panel()); await screen.findByRole('table'); toggle(summary());
        const visibility = vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden'); act(() => document.dispatchEvent(new Event('visibilitychange')));
        expect(screen.queryByText(title)).toBeNull(); visibility.mockReturnValue('visible'); act(() => document.dispatchEvent(new Event('visibilitychange'))); await screen.findByRole('table');
        expect(summary().parentElement).not.toHaveAttribute('open');
    });
    it('does not preserve expanded groups across tab disable/reentry or operator session replacement', async () => {
        server(); const view = render(panel()); await screen.findByRole('table'); toggle(summary()); view.rerender(panel('session-a', false));
        expect(screen.queryByText(title)).toBeNull(); view.rerender(panel('session-a', true)); await screen.findByRole('table'); expect(summary().parentElement).not.toHaveAttribute('open'); toggle(summary());
        view.rerender(panel('session-b')); await screen.findByRole('table'); expect(summary().parentElement).not.toHaveAttribute('open');
    });
    it('clears grouped evidence when the existing read fails', async () => {
        const s = server(); render(panel()); await screen.findByRole('table'); toggle(summary()); s.state.failure = 403;
        fireEvent.click(screen.getByRole('button', { name: 'Refresh process inventory' })); await screen.findByRole('alert');
        expect(screen.queryByText(title)).toBeNull(); expect(visibleNames()).toHaveLength(0); expect(s.state.queries).toHaveLength(2);
    });
    it('preserves the original authority expiry while groups are open', async () => {
        vi.useFakeTimers(); const s = server(); s.state.expire = true; render(panel()); await flush(); toggle(summary()); toggle(groupSummaries()[0]);
        await act(async () => vi.advanceTimersByTimeAsync(1000)); expect(screen.queryByText(title)).toBeNull(); expect(screen.getByRole('alert')).toHaveTextContent('expired'); expect(s.state.queries).toHaveLength(1);
    });
});
