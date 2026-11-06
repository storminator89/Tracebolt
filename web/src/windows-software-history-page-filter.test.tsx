import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, AUTH_REQUIRED_EVENT } from './api';
import { useOperator } from './auth';
import { setLocale } from './i18n';
import { WindowsSoftwareHistoryPanel, WindowsSoftwareHistoryTable } from './windows-software-history';
import { softwareHistoryDevice, softwareHistoryNow, softwareHistoryPage, softwareHistoryQuery } from './windows-software-history-fixtures';
import { validSoftwareHistoryPage } from './windows-software-history-types';
import type { SoftwareHistoryPage, SoftwareHistoryQuery } from './windows-software-history-types';

vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
const labels = {
    en: { filter: 'Change type on this page', reset: 'Show all change types', next: 'Next history page', previous: 'Previous history page', empty: 'No changes of this type on the loaded page. Other pages may contain matches.' },
    de: { filter: 'Änderungsart auf dieser Seite', reset: 'Alle Änderungsarten anzeigen', next: 'Nächste Verlaufsseite', previous: 'Vorherige Verlaufsseite', empty: 'Keine Änderungen dieser Art auf der geladenen Seite. Andere Seiten können Treffer enthalten.' },
};
const renderedIds = () => Array.from(document.querySelectorAll('tbody tr')).map(row => row.getAttribute('data-history-id'));
function server() {
    const started = Date.now(), requests: SoftwareHistoryQuery[] = [];
    const state = { hold: null as Promise<void> | null, lifetime: 900000 };
    vi.stubGlobal('fetch', vi.fn(async (path: string, options?: RequestInit) => {
        if (path === '/api/session') return new Response(JSON.stringify({ csrfToken: 'synthetic-csrf' }));
        if (!/^\/api\/devices\/agent_[a-f0-9]{32}\/windows-software-history\/query$/.test(path)) throw new Error('Unexpected request');
        const query = JSON.parse(options!.body as string) as SoftwareHistoryQuery;
        requests.push(query);
        const offset = query.cursor ? Number(query.cursor.match(/^history_(\d+)\./)?.[1]) : 0;
        const page = softwareHistoryPage(query, undefined, offset);
        page.deviceId = path.split('/')[3];
        page.serverNow = new Date(Date.parse(softwareHistoryNow) + Date.now() - started).toISOString();
        page.cursorExpiresAt = new Date(Date.parse(softwareHistoryNow) + state.lifetime).toISOString();
        if (state.hold) await state.hold;
        return new Response(JSON.stringify(page));
    }));
    return { requests, state };
}
const open = () => render(<WindowsSoftwareHistoryPanel deviceId={softwareHistoryDevice} sessionKey="session-a"/>);
const flush = () => act(async () => { for (let i = 0; i < 12; i++) await Promise.resolve(); });
beforeEach(() => {
    setLocale('en', false);
    vi.mocked(useOperator).mockReturnValue({ mode: 'lan', authenticated: true, expiresAt: 'synthetic-session', insecureTestMode: false, logout: vi.fn(), theme: 'light', setTheme: vi.fn() });
});
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe('loaded-page software history filtering', () => {
    it.each(['en', 'de'] as const)('filters exact observed kinds without modifying rows, order or evidence (%s)', locale => {
        const page = softwareHistoryPage(), original = JSON.stringify(page), c = labels[locale];
        render(<WindowsSoftwareHistoryTable page={page} locale={locale}/>);
        const filter = screen.getByRole('combobox', { name: c.filter });
        expect(filter).toHaveAccessibleDescription(locale === 'en'
            ? 'Filters only the loaded page. Search totals and other pages are unchanged. Each new page starts with all change types.'
            : 'Filtert nur die geladene Seite. Suchtrefferzahl und andere Seiten bleiben unverändert. Jede neue Seite beginnt mit allen Änderungsarten.');
        expect(renderedIds()).toEqual(page.rows.map(row => row.id));
        for (const kind of ['registration_added', 'registration_removed', 'metadata_changed']) {
            fireEvent.change(filter, { target: { value: kind } });
            expect(renderedIds()).toEqual(page.rows.filter(row => row.kind === kind).map(row => row.id));
        }
        expect(screen.getByText(locale === 'en' ? '98 of 100 changes on this page shown' : '98 von 100 Änderungen auf dieser Seite angezeigt')).toBeVisible();
        // The unavailable old version remains unavailable, not an inferred version change.
        const unknown = document.querySelector(`[data-history-id="${page.rows[3].id}"]`)!;
        expect(unknown.querySelector('td:nth-child(2)')).toHaveTextContent('Name');
        expect(unknown.querySelector('td:nth-child(2)')).not.toHaveTextContent('Version');
        fireEvent.click(screen.getByRole('button', { name: c.reset }));
        expect(filter).toHaveValue('all'); expect(filter).toHaveFocus();
        expect(renderedIds()).toEqual(page.rows.map(row => row.id));
        expect(JSON.stringify(page)).toBe(original);
        expect(validSoftwareHistoryPage(page, softwareHistoryDevice, softwareHistoryQuery, 0)).toBe(true);
    });
    it.each(['deviceId', 'grantId', 'grantRevision', 'historyDigest', 'search', 'offset'] as const)('resets the local filter when %s changes', field => {
        const page = softwareHistoryPage(), view = render(<WindowsSoftwareHistoryTable page={page} locale="en"/>);
        fireEvent.change(screen.getByRole('combobox'), { target: { value: 'registration_removed' } });
        const next: SoftwareHistoryPage = { ...page, [field]: typeof page[field] === 'number' ? Number(page[field]) + 1 : `${page[field]}-different` };
        view.rerender(<WindowsSoftwareHistoryTable page={next} locale="en"/>);
        expect(screen.getByRole('combobox')).toHaveValue('all'); expect(renderedIds()).toHaveLength(100);
    });
    it.each(['en', 'de'] as const)('keeps server totals, search and navigation independent of local filtering (%s)', async locale => {
        setLocale(locale, false); const c = labels[locale], s = server(); open(); await screen.findByRole('table');
        const counts = document.querySelector('.windows-history-counts')!.textContent;
        const writes = vi.spyOn(Storage.prototype, 'setItem');
        fireEvent.change(screen.getByRole('combobox', { name: c.filter }), { target: { value: 'registration_removed' } });
        expect(renderedIds()).toHaveLength(1); expect(s.requests).toEqual([softwareHistoryQuery]);
        expect(document.querySelector('.windows-history-counts')!.textContent).toBe(counts);
        expect(screen.getByRole('searchbox')).toHaveValue('');
        expect(screen.getByRole('button', { name: c.next })).toBeEnabled();
        fireEvent.click(screen.getByRole('button', { name: c.next }));
        await waitFor(() => expect(document.querySelector('tbody tr')).toHaveTextContent('Fixture Software 0101'));
        expect(screen.getByRole('combobox')).toHaveValue('all'); expect(renderedIds()).toHaveLength(100);
        fireEvent.change(screen.getByRole('combobox'), { target: { value: 'registration_removed' } });
        expect(renderedIds()).toHaveLength(0); expect(screen.getByText(c.empty)).toBeVisible();
        expect(screen.getByRole('button', { name: c.next })).toBeEnabled();
        expect(screen.getByRole('button', { name: c.previous })).toBeEnabled();
        expect(s.requests).toHaveLength(2); expect(writes).not.toHaveBeenCalled();
        fireEvent.click(screen.getByRole('button', { name: c.previous }));
        await screen.findByRole('table'); expect(screen.getByRole('combobox')).toHaveValue('all');
        expect(s.requests).toHaveLength(3); expect(s.requests.at(-1)).toEqual(softwareHistoryQuery);
    });
    it.each(['blur', 'pagehide', 'auth', 'hidden'])('cannot retain filter or private rows after %s, including a late response', async event => {
        const s = server(); open(); await screen.findByRole('table');
        fireEvent.change(screen.getByRole('combobox'), { target: { value: 'registration_removed' } });
        let release!: () => void; s.state.hold = new Promise(resolve => { release = resolve; });
        fireEvent.click(screen.getByRole('button', { name: labels.en.next }));
        await waitFor(() => expect(s.requests).toHaveLength(2));
        if (event === 'hidden') { vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden'); fireEvent(document, new Event('visibilitychange')); }
        else fireEvent(window, new Event(event === 'auth' ? AUTH_REQUIRED_EVENT : event));
        release(); await flush();
        expect(screen.queryByRole('combobox')).toBeNull(); expect(renderedIds()).toHaveLength(0);
        expect(screen.queryByText(/changes on this page shown/)).toBeNull(); expect(s.requests).toHaveLength(2);
    });
    it.each(['device', 'session', 'disabled'])('clears the active local filter across %s context changes', async context => {
        const s = server(), view = open(); await screen.findByRole('table');
        fireEvent.change(screen.getByRole('combobox'), { target: { value: 'registration_removed' } });
        view.rerender(<WindowsSoftwareHistoryPanel deviceId={context === 'device' ? `agent_${'b'.repeat(32)}` : softwareHistoryDevice} sessionKey={context === 'session' ? 'session-b' : 'session-a'} enabled={context !== 'disabled'}/>);
        expect(screen.queryByRole('combobox')).toBeNull(); expect(renderedIds()).toHaveLength(0);
        if (context === 'disabled') {
            expect(s.requests).toHaveLength(1);
            view.rerender(<WindowsSoftwareHistoryPanel deviceId={softwareHistoryDevice} sessionKey="session-a"/>);
        }
        await screen.findByRole('table'); expect(screen.getByRole('combobox')).toHaveValue('all');
        expect(s.requests).toHaveLength(2); expect(s.requests.at(-1)).toEqual(softwareHistoryQuery);
    });
    it('does not extend original history expiry by repeatedly filtering or clearing', async () => {
        vi.useFakeTimers(); const s = server(); s.state.lifetime = 1000; open(); await flush();
        fireEvent.change(screen.getByRole('combobox'), { target: { value: 'registration_removed' } });
        await act(async () => vi.advanceTimersByTimeAsync(600));
        fireEvent.click(screen.getByRole('button', { name: labels.en.reset }));
        fireEvent.change(screen.getByRole('combobox'), { target: { value: 'metadata_changed' } });
        await act(async () => vi.advanceTimersByTimeAsync(400));
        expect(screen.queryByRole('combobox')).toBeNull(); expect(renderedIds()).toHaveLength(0);
        expect(screen.getByRole('alert')).toHaveTextContent('expired'); expect(s.requests).toHaveLength(1);
    });
    it('does not turn an empty loaded page into a claim about all retained history', () => {
        const page = softwareHistoryPage(softwareHistoryQuery, undefined, 200);
        render(<WindowsSoftwareHistoryTable page={page} locale="en"/>);
        fireEvent.change(screen.getByRole('combobox'), { target: { value: 'registration_added' } });
        expect(screen.getByText(labels.en.empty)).toBeVisible();
        expect(screen.getByText('0 of 5 changes on this page shown')).toBeVisible();
        expect(screen.queryByText('No retained observed changes.')).toBeNull();
        fireEvent.click(screen.getByRole('button', { name: labels.en.reset }));
        expect(renderedIds()).toEqual(page.rows.map(row => row.id));
        const last = document.querySelector('tbody tr:last-child') as HTMLElement;
        fireEvent.click(within(last).getByText('Details'));
        expect(screen.getByText(/<img src=x onerror=alert\(1\)>/)).toBeVisible(); expect(document.querySelector('img,script:not([src])')).toBeNull();
    });
});
