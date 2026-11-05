import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { JournalContent } from './journal';
import { JournalPageTriage } from './journal-triage';
import { journalNow, journalPage, journalView } from './journal-fixtures';
import type { JournalResource } from './journal-resource';
import type { JournalPage, JournalView } from './journal-types';
import { setLocale } from './i18n';

function page(): JournalPage {
    const p = journalPage(['same failure', 'notice', 'same failure', 'another failure']);
    p.rows[0] = { ...p.rows[0], priority: 3, timestamp: '2026-10-04T11:59:00.000000003Z' };
    p.rows[1] = { ...p.rows[1], priority: 5, timestamp: '2026-10-04T11:59:00.000000002Z' };
    p.rows[2] = { ...p.rows[2], priority: 3, timestamp: '2026-10-04T11:59:00.000000001Z' };
    p.rows[3] = { ...p.rows[3], priority: 3, timestamp: '2026-10-04T11:59:00.000000001Z' };
    return p;
}
function retained(p: JournalPage): JournalView {
    const v = journalView();
    v.schemaVersion = 'tracebolt.journal-view.v2';
    v.generation = { schemaVersion: 'tracebolt.journal-generation-view.v3', browsingContract: 'tracebolt.journal-browse.v1', policyGeneration: { revision: '1', generation: 'a'.repeat(64), policyDigest: `sha256:${'b'.repeat(64)}` }, sequence: '1', observedAt: journalNow, receivedAt: journalNow, expiresAt: '2026-10-04T12:05:00Z', fresh: true, policyEnabled: true, serviceAuthorization: 'all-system-services', allowedUnits: [] };
    v.request!.description = { ...v.request!.description, schemaVersion: 'tracebolt.journal-request.v3', policyGeneration: v.generation.policyGeneration, query: { ...p.query, maxPriority: 7, browseMode: 'retained-v1' } };
    p.schemaVersion = 'tracebolt.journal-page.v2'; p.query = v.request!.description.query; p.searchScope = 'retained_source_page';
    return v;
}
function resource(extra: Partial<JournalResource> = {}): JournalResource {
    return { view: journalView(), page: page(), busy: false, paused: false, failure: null, uncertain: false, reset: 0, refresh: vi.fn(), refreshWindow: vi.fn(async () => journalNow), create: vi.fn(async () => {}), cancelRequest: vi.fn(), search: vi.fn(), next: vi.fn(), previous: vi.fn(), canPrevious: false, ...extra };
}
function messages() { return within(screen.getByRole('table')).getAllByRole('row').slice(1).map(row => within(row).getAllByRole('cell')[2].textContent); }
beforeEach(() => setLocale('en', false));
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });
describe('read-only journal display-page triage', () => {
    it('counts exactly the display page, filters exact severities and restores all rows', () => {
        const p = page(); p.totalCapturedRows = p.matchedRows = 500;
        render(<JournalPageTriage page={p}/>);
        expect(screen.getByRole('button', { name: 'All severities (4)' })).toHaveAttribute('aria-pressed', 'true');
        expect(screen.getByRole('button', { name: '0 · Emergency (0)' })).toBeDisabled();
        expect(screen.getByText(/Only the loaded display page/)).toBeVisible();
        fireEvent.click(screen.getByRole('button', { name: '5 · Notice (1)' }));
        expect(messages()).toEqual(['notice']);
        expect(screen.getByRole('status')).toHaveTextContent('1 messages shown of 4 loaded on this page');
        fireEvent.click(screen.getByRole('button', { name: 'All severities (4)' }));
        expect(messages()).toEqual(['same failure', 'notice', 'same failure', 'another failure']);
    });
    it('sorts nanosecond times and keeps duplicate order without changing original timestamps', () => {
        const p = page(); render(<JournalPageTriage page={p}/>);
        fireEvent.change(screen.getByLabelText('Page order'), { target: { value: 'oldest' } });
        expect(messages()).toEqual(['same failure', 'another failure', 'notice', 'same failure']);
        expect(screen.getByRole('table').querySelector('tbody time')).toHaveAttribute('datetime', p.rows[2].timestamp);
        fireEvent.change(screen.getByLabelText('Page order'), { target: { value: 'newest' } });
        expect(messages()).toEqual(['same failure', 'notice', 'same failure', 'another failure']);
        fireEvent.change(screen.getByLabelText('Page order'), { target: { value: 'source' } });
        expect(messages()).toEqual(p.rows.map(row => row.message));
    });
    it('shows grouped repeated messages with exact first/last and all source-row occurrences', () => {
        const p = page(); p.offset = 100; render(<JournalPageTriage page={p}/>);
        fireEvent.change(screen.getByLabelText('Display'), { target: { value: 'groups' } });
        expect(screen.queryByRole('table')).not.toBeInTheDocument();
        expect(screen.getByRole('status')).toHaveTextContent('3 displayed message groups');
        expect(screen.getByText(/Masking may make different original messages/)).toBeVisible();
        const group = screen.getByText('same failure').closest('li')!;
        expect(within(group).getByText('2 occurrences on this page')).toBeVisible();
        const times = group.querySelectorAll('dl time');
        expect(times[0]).toHaveAttribute('datetime', p.rows[2].timestamp);
        expect(times[1]).toHaveAttribute('datetime', p.rows[0].timestamp);
        const disclosure = within(group).getByText('Show occurrences (2)'); fireEvent.click(disclosure);
        expect(disclosure.closest('details')).toHaveAttribute('open');
        expect(within(group).getByText('Result row 101')).toBeVisible();
        expect(within(group).getByText('Result row 103')).toBeVisible();
        fireEvent.change(screen.getByLabelText('Page order'), { target: { value: 'oldest' } });
        expect(Array.from(group.querySelectorAll('ol time')).map(time => time.getAttribute('datetime'))).toEqual([p.rows[2].timestamp, p.rows[0].timestamp]);
        fireEvent.click(screen.getByRole('button', { name: 'Reset page view' }));
        expect(screen.getByRole('table')).toBeVisible();
        expect(screen.getByLabelText('Page order')).toHaveValue('source');
        expect(screen.getByRole('button', { name: 'Reset page view' })).toBeDisabled();
    });
    it.each(['session', 'device', 'request', 'sequence', 'query', 'digest', 'offset', 'search'] as const)('resets filters, sort, grouping and disclosures synchronously at the %s boundary', boundary => {
        const p = page(), mounted = render(<JournalPageTriage page={p} sessionKey="one"/>);
        fireEvent.click(screen.getByRole('button', { name: '3 · Error (3)' }));
        fireEvent.change(screen.getByLabelText('Page order'), { target: { value: 'oldest' } });
        fireEvent.change(screen.getByLabelText('Display'), { target: { value: 'groups' } });
        fireEvent.click(screen.getByText('Show occurrences (2)'));
        const changed = structuredClone(p);
        if (boundary === 'device') changed.deviceId = 'other';
        if (boundary === 'request') changed.identity.id = 'other';
        if (boundary === 'sequence') changed.identity.sequence = '2';
        if (boundary === 'query') changed.identity.queryDigest = 'other';
        if (boundary === 'digest') changed.snapshotDigest = 'other';
        if (boundary === 'offset') changed.offset = 100;
        if (boundary === 'search') changed.search = 'failure';
        mounted.rerender(<JournalPageTriage page={changed} sessionKey={boundary === 'session' ? 'two' : 'one'}/>);
        expect(screen.getByRole('button', { name: 'All severities (4)' })).toHaveAttribute('aria-pressed', 'true');
        expect(screen.getByLabelText('Page order')).toHaveValue('source');
        expect(screen.getByLabelText('Display')).toHaveValue('rows');
        expect(screen.getByRole('table')).toBeVisible();
        fireEvent.change(screen.getByLabelText('Display'), { target: { value: 'groups' } });
        expect(screen.getByText('Show occurrences (2)').closest('details')).not.toHaveAttribute('open');
    });
    it('keeps controls on a same-page status refresh without retaining removed message content', () => {
        const p = page(), mounted = render(<JournalPageTriage page={p}/>);
        fireEvent.click(screen.getByRole('button', { name: '5 · Notice (1)' }));
        mounted.rerender(<JournalPageTriage page={{ ...p, serverNow: '2026-10-04T12:00:01Z' }}/>);
        expect(messages()).toEqual(['notice']);
        mounted.rerender(<p>Content unavailable</p>);
        expect(screen.queryByText('notice')).not.toBeInTheDocument();
        mounted.rerender(<JournalPageTriage page={p}/>);
        expect(screen.getByRole('button', { name: 'All severities (4)' })).toHaveAttribute('aria-pressed', 'true');
    });
    it.each(['en', 'de'] as const)('renders all triage controls and scope in %s without mutating source search', locale => {
        setLocale(locale, false); render(<JournalPageTriage page={page()}/>);
        expect(screen.getByRole('heading', { name: locale === 'de' ? 'Diese Seite prüfen' : 'Review this page' })).toBeVisible();
        fireEvent.click(screen.getByRole('button', { name: locale === 'de' ? '3 · Fehler (3)' : '3 · Error (3)' }));
        fireEvent.change(screen.getByLabelText(locale === 'de' ? 'Anzeige' : 'Display'), { target: { value: 'groups' } });
        expect(screen.getByText(locale === 'de' ? /Maskierung kann unterschiedliche/ : /Masking may make different/)).toBeVisible();
        expect(screen.getByText(locale === 'de' ? 'Vorkommen anzeigen (2)' : 'Show occurrences (2)')).toBeVisible();
    });
    it('renders hostile messages as inert text and highlights literal searches in both views', () => {
        const p = page(); p.rows = [{ ...p.rows[0], message: '<img src=x onerror=alert(1)> https://example.invalid [.*]' }]; p.search = '[.*]';
        const mounted = render(<JournalPageTriage page={p}/>);
        expect(screen.getByText('[.*]', { selector: 'mark' })).toBeVisible();
        fireEvent.change(screen.getByLabelText('Display'), { target: { value: 'groups' } });
        expect(screen.getByText('[.*]', { selector: 'mark' })).toBeVisible();
        expect(mounted.container.querySelector('img,a,script')).toBeNull();
    });
    it.each(['legacy', 'retained'] as const)('integrates into %s logs with zero additional reads or actions and clears with resource loss', mode => {
        const fetch = vi.fn(); vi.stubGlobal('fetch', fetch);
        const p = page(), v = mode === 'retained' ? retained(p) : journalView(), r = resource({ page: p, view: v });
        const mounted = render(<JournalContent resource={r} insecureTestMode={false} sessionKey="one"/>);
        fireEvent.click(screen.getByRole('button', { name: '3 · Error (3)' }));
        fireEvent.change(screen.getByLabelText('Display'), { target: { value: 'groups' } });
        fireEvent.change(screen.getByLabelText('Page order'), { target: { value: 'oldest' } });
        fireEvent.click(screen.getByText('Show occurrences (2)'));
        for (const method of ['refresh', 'refreshWindow', 'create', 'cancelRequest', 'search', 'next', 'previous'] as const) expect(r[method]).not.toHaveBeenCalled();
        expect(fetch).not.toHaveBeenCalled();
        mounted.rerender(<JournalContent resource={{ ...r, page: null, view: null, paused: true, reset: 1 }} insecureTestMode={false} sessionKey="one"/>);
        expect(screen.queryByText('same failure')).not.toBeInTheDocument();
        expect(screen.queryByRole('heading', { name: 'Review this page' })).not.toBeInTheDocument();
        mounted.rerender(<JournalContent resource={r} insecureTestMode={false} sessionKey="one"/>);
        expect(screen.getByRole('button', { name: 'All severities (4)' })).toHaveAttribute('aria-pressed', 'true');
        expect(screen.getByLabelText('Display')).toHaveValue('rows');
    });
});
