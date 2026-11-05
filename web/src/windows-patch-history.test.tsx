import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AUTH_REQUIRED_EVENT, request } from './api';
import { setLocale } from './i18n';
import { WindowsPatchHistory } from './windows-patch-history';
import { WindowsInventoryWorkspace } from './windows-inventory';
import { useWindowsInventory } from './windows-inventory-resource';
import { windowsDeviceId, windowsNow, windowsView } from './windows-inventory-fixture';
import { windowsPatchContextView } from './windows-patch-context-fixture';
import type { WindowsPatchHistoryRow } from './windows-patch-context-types';
import { initialPatchHistoryFilters, patchHistoryPage } from './windows-patch-history-model';
import type { PatchHistoryFilters } from './windows-patch-history-model';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn() }));
const flush = () => act(async () => {});
const outcomes: WindowsPatchHistoryRow['result'][] = ['failed', 'succeeded-with-errors', 'aborted', 'succeeded', 'in-progress', 'not-started'];
function historyRows(count = 64): WindowsPatchHistoryRow[] {
    return Array.from({ length: count }, (_, index) => ({
        index, updateId: `${(index + 1).toString(16).padStart(8, '0')}-0000-0000-0000-000000000001`, revision: index + 1,
        title: `Synthetic event ${String(index).padStart(2, '0')}`, occurredAt: new Date(Date.parse('2026-10-06T23:59:59Z') - index * 3600000).toISOString(),
        operation: index % 2 ? 'uninstallation' : 'installation', result: outcomes[index % outcomes.length], hresult: index % 2 ? '80240022' : '00000000', metadataTruncated: index === 1,
    }));
}
function historyView() {
    const view = windowsPatchContextView();
    view.patchContext.history = { quality: 'partial', reason: 'windows_patch_context_partial_result', countExact: false, totalCount: 90, truncated: true, rows: historyRows() };
    return view;
}
function Harness({ session = 'fixture', device = windowsDeviceId, enabled = true }: { session?: string; device?: string; enabled?: boolean }) {
    return <WindowsInventoryWorkspace resource={useWindowsInventory(device, enabled, session)}/>;
}
const details = () => document.querySelector<HTMLDetailsElement>('.windows-patch-details')!;
const openHistory = async () => { await flush(); fireEvent.click(screen.getByRole('tab', { name: 'Updates' })); fireEvent.click(details().querySelector('summary')!); };
const table = () => screen.getByRole('table', { name: 'Retained update history' });
const query = (value: string) => fireEvent.change(screen.getByRole('searchbox', { name: 'Search retained events' }), { target: { value } });
const choose = (label: string, value: string) => fireEvent.change(screen.getByLabelText(label), { target: { value } });
const page = (patch: Partial<PatchHistoryFilters> = {}, rows = historyRows()) => patchHistoryPage(rows, { ...initialPatchHistoryFilters(), ...patch });

beforeEach(() => { setLocale('en', false); vi.mocked(request).mockReset().mockResolvedValue(historyView()); });
afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); });

describe('Bounded retained-update-history filtering', () => {
    it.each(outcomes)('matches only the original %s result', result => {
        const found = page({ result });
        expect(found.total).toBe(historyRows().filter(row => row.result === result).length);
        expect(found.rows.every(row => row.result === result)).toBe(true);
    });
    it('combines literal case-insensitive title, exact result and exact operation', () => {
        expect(page({ query: '  SYNTHETIC event 0', result: 'failed', operation: 'installation' }).rows.map(row => row.index)).toEqual([0, 6]);
        expect(page({ query: 'Synthetic.*' }).total).toBe(0);
        expect(page({ query: '%' }).total).toBe(0);
        expect(page({ result: 'failed', operation: 'uninstallation' }).total).toBe(0);
    });
    it('searches exact ID text and HRESULT with optional full 0x notation', () => {
        expect(page({ query: '0000000A-0000-0000-0000-000000000001' }).rows.map(row => row.index)).toEqual([9]);
        expect(page({ query: '0X80240022' }).total).toBe(32);
        expect(page({ query: '80240022' }).total).toBe(32);
        expect(page({ query: '0x8024' }).total).toBe(0);
    });
    it('keeps duplicate update IDs, revisions and source events distinct', () => {
        const rows = historyRows(3); rows[1].updateId = rows[0].updateId; rows[1].revision = rows[0].revision; rows[1].occurredAt = rows[0].occurredAt;
        expect(page({}, rows).rows.map(row => row.index)).toEqual([0, 1, 2]);
        expect(page({ order: 'oldest' }, rows).rows.map(row => row.index)).toEqual([2, 1, 0]);
    });
    it('includes both entire UTC endpoint dates without local timezone conversion', () => {
        expect(page({ from: '2026-10-05', through: '2026-10-05' }).total).toBe(24);
        expect(page({ from: '2026-10-06', through: '2026-10-06' }).total).toBe(24);
        expect(page({ from: '2026-10-07' }).total).toBe(0);
        expect(page({ through: '2026-10-04' }).total).toBe(16);
    });
    it.each(['2026-02-29', '2026-02-31', '2026-13-01', '1969-12-31', '2026-1-01', 'bad'])('rejects invalid UTC date %s without false empty-success semantics', from => {
        expect(page({ from }).invalidDates).toBe(true); expect(page({ from }).rows).toEqual([]);
    });
    it('accepts Gregorian leap days and rejects a reversed range', () => {
        expect(page({ from: '2024-02-29' }).invalidDates).toBe(false);
        expect(page({ from: '2026-10-06', through: '2026-10-05' }).invalidDates).toBe(true);
    });
    it('pages at 20 rows, bounds invalid positions and never mutates source order', () => {
        const rows = historyRows(), original = structuredClone(rows);
        expect(page({}, rows).rows).toHaveLength(20);
        expect(page({ page: 3 }).rows.map(row => row.index)).toEqual([60, 61, 62, 63]);
        expect(page({ page: 1000 }).page).toBe(3); expect(page({ page: -5 }).page).toBe(0); expect(page({ page: NaN }).page).toBe(0);
        expect(page({ order: 'oldest' }, rows).rows[0].index).toBe(63); expect(rows).toEqual(original);
    });
});

describe('Private on-device update-history review', () => {
    it.each(['en', 'de'] as const)('renders accessible compact controls and separates source counts from matches in %s', async locale => {
        setLocale(locale, false); render(<Harness/>); await openHistory(); const de = locale === 'de';
        expect(screen.getByRole('group', { name: de ? 'Gespeicherte Updateereignisse prüfen' : 'Review retained update events' })).toBeVisible();
        expect(screen.getByRole('searchbox', { name: de ? 'Gespeicherte Ereignisse durchsuchen' : 'Search retained events' })).toHaveAttribute('maxlength', '256');
        expect(screen.getByText(de ? '64 passende von 64 gespeicherten Zeilen' : '64 matching of 64 retained rows')).toBeVisible();
        expect(details().querySelector('summary')).toHaveTextContent(de ? '64 gespeicherte Zeilen · mindestens 90 Quellereignisse' : '64 retained rows · at least 90 source events');
        const t = screen.getByRole('table', { name: de ? 'Gespeicherter Updateverlauf' : 'Retained update history' }); expect(within(t).getAllByRole('row')).toHaveLength(21);
        const headers = within(t).getAllByRole('columnheader').map(cell => cell.textContent);
        for (const row of within(t).getAllByRole('row').slice(1)) expect(within(row).getAllByRole('cell').map(cell => cell.dataset.label)).toEqual(headers);
        expect(screen.getByText(de ? /Ausgelassener oder gelöschter Verlauf/ : /Omitted or cleared history/)).toBeVisible();
        expect(screen.getByRole('button', { name: de ? 'Vorherige Ereignisse' : 'Previous events' })).toBeDisabled();
    });
    it('filters locally, resets paging after changes and clears every control in one action', async () => {
        render(<Harness/>); await openHistory(); const pageStatus = screen.getByText('Page 1 of 4 · rows 1–20'); expect(pageStatus).toHaveAttribute('role', 'status'); expect(pageStatus).toHaveAttribute('aria-live', 'polite'); expect(pageStatus).toHaveAttribute('aria-atomic', 'true');
        fireEvent.click(screen.getByRole('button', { name: 'Next events' })); expect(within(table()).getByText('Synthetic event 20')).toBeVisible(); expect(pageStatus).toHaveTextContent('Page 2 of 4 · rows 21–40');
        choose('Event result', 'failed'); expect(screen.getByText('11 matching of 64 retained rows')).toBeVisible(); expect(screen.queryByRole('button', { name: 'Next events' })).toBeNull();
        expect(details().querySelector('summary')).toHaveTextContent('64 retained rows · at least 90 source events');
        expect(within(table()).getAllByRole('row')).toHaveLength(12);
        choose('Event operation', 'installation'); choose('From (UTC)', '2026-10-06'); choose('Through (UTC)', '2026-10-06'); choose('Event order', 'oldest'); query('event 0');
        expect(within(table()).getAllByRole('row')).toHaveLength(3); expect(within(table()).getAllByRole('row')[1]).toHaveTextContent('Synthetic event 06');
        expect(vi.mocked(request)).toHaveBeenCalledTimes(1);
        fireEvent.click(screen.getByRole('button', { name: 'Clear filters' })); expect(screen.getByRole('searchbox')).toHaveValue('');
        expect(screen.getByLabelText('Event result')).toHaveValue('all'); expect(screen.getByLabelText('Event operation')).toHaveValue('all'); expect(screen.getByLabelText('From (UTC)')).toHaveValue(''); expect(screen.getByLabelText('Through (UTC)')).toHaveValue(''); expect(screen.getByLabelText('Event order')).toHaveValue('newest');
        expect(within(table()).getAllByRole('row')[1]).toHaveTextContent('Synthetic event 00'); expect(vi.mocked(request)).toHaveBeenCalledTimes(1);
    });
    it.each(['en', 'de'] as const)('associates date-range errors with both fields and clears them after repair (%s)', locale => {
        const de = locale === 'de';
        render(<WindowsPatchHistory rows={historyRows()} locale={locale}/>);
        const from = screen.getByLabelText(de ? 'Von (UTC)' : 'From (UTC)');
        const through = screen.getByLabelText(de ? 'Bis einschließlich (UTC)' : 'Through (UTC)');
        const hint = de ? 'Die Datumsfilter gelten' : 'Dates filter recorded';
        expect(from).toHaveAttribute('aria-invalid', 'false');
        expect(through).toHaveAttribute('aria-invalid', 'false');
        fireEvent.change(from, { target: { value: '2026-10-06' } });
        fireEvent.change(through, { target: { value: '2026-10-05' } });
        const error = screen.getByRole('alert');
        for (const field of [from, through]) {
            expect(field).toHaveAttribute('aria-invalid', 'true');
            expect(field.getAttribute('aria-describedby')!.split(' ')).toContain(error.id);
            expect(field).toHaveAccessibleDescription(new RegExp(hint));
            expect(field).toHaveAccessibleDescription(new RegExp(de ? 'der Beginn darf nicht nach dem Ende liegen' : 'start on or before the end'));
        }
        expect(screen.queryByRole('table')).toBeNull();
        through.focus();
        fireEvent.change(through, { target: { value: '2026-10-06' } });
        expect(through).toHaveFocus();
        expect(screen.queryByRole('alert')).toBeNull();
        for (const field of [from, through]) {
            expect(field).toHaveAttribute('aria-invalid', 'false');
            expect(field.getAttribute('aria-describedby')!.split(' ')).toHaveLength(1);
        }
        expect(screen.getByRole('table')).toBeVisible();
        fireEvent.change(through, { target: { value: '2026-10-05' } });
        fireEvent.click(screen.getByRole('button', { name: de ? 'Filter leeren' : 'Clear filters' }));
        expect(from).toHaveValue(''); expect(through).toHaveValue('');
        expect(from).toHaveAttribute('aria-invalid', 'false'); expect(through).toHaveAttribute('aria-invalid', 'false');
        expect(request).not.toHaveBeenCalled();
    });
    it('distinguishes invalid dates from no matching retained events and retains source warnings', async () => {
        render(<Harness/>); await openHistory(); choose('From (UTC)', '2026-10-06'); choose('Through (UTC)', '2026-10-05');
        expect(screen.getByRole('alert')).toHaveTextContent('Choose valid UTC dates'); expect(screen.queryByRole('table')).toBeNull(); expect(screen.queryByText(/matching of/)).toBeNull();
        fireEvent.click(screen.getByRole('button', { name: 'Clear filters' })); query('missing update');
        expect(screen.getByText(/No retained rows match these filters/)).toBeVisible(); expect(screen.getByText(/does not prove that an update is absent or succeeded/)).toBeVisible();
        expect(screen.getByText('Partial history result.')).toBeVisible(); expect(screen.getByText('Some history rows were omitted.')).toBeVisible();
    });
    it('retains each exact outcome, HRESULT, truncated title and event details without adding actions', async () => {
        render(<Harness/>); await openHistory(); query('0x80240022'); expect(screen.getByText('32 matching of 64 retained rows')).toBeVisible();
        const first = within(table()).getAllByRole('row')[1]; expect(first).toHaveTextContent('Succeeded with errors'); expect(first).toHaveTextContent('HRESULT: 80240022'); expect(first).toHaveTextContent('Title shortened');
        fireEvent.click(within(first).getByText('Details')); expect(within(first).getByText(/00000002-0000-0000-0000-000000000001 · Revision 2/)).toBeVisible();
        expect(screen.queryByRole('button', { name: /scan|install|reboot|export|enable|apply/i })).toBeNull(); expect(vi.mocked(request)).toHaveBeenCalledTimes(1);
    });
    it('renders hostile titles and filter text inertly, without storing queries', async () => {
        const view = historyView(), title = '<img src=x onerror=alert(1)>'; view.patchContext.history.rows[0].title = title;
        vi.mocked(request).mockResolvedValue(view); const storage = vi.spyOn(Storage.prototype, 'setItem'); render(<Harness/>); await openHistory(); query(title);
        expect(within(table()).getByText(title)).toBeVisible(); expect(document.querySelector('img, script, iframe')).toBeNull(); expect(storage).not.toHaveBeenCalled();
    });
    it('restarts controls on tab navigation and source reread, without changing the existing request', async () => {
        render(<Harness/>); await openHistory(); query('private query'); fireEvent.click(screen.getByRole('tab', { name: 'Hostname' })); fireEvent.click(screen.getByRole('tab', { name: 'Updates' }));
        expect(details().open).toBe(false); fireEvent.click(details().querySelector('summary')!); expect(screen.getByRole('searchbox')).toHaveValue('');
        query('private query'); fireEvent.click(screen.getByRole('button', { name: 'Refresh Windows inventory' })); await flush(); fireEvent.click(details().querySelector('summary')!); expect(screen.getByRole('searchbox')).toHaveValue('');
        expect(vi.mocked(request)).toHaveBeenCalledTimes(2); expect(vi.mocked(request).mock.calls.every(call => call[0] === `/devices/${windowsDeviceId}/windows-inventory`)).toBe(true);
    });
    it.each(['blur', 'pagehide', 'hashchange', AUTH_REQUIRED_EVENT])('discards private filters and rows on %s', async event => {
        render(<Harness/>); await openHistory(); query('private query'); act(() => window.dispatchEvent(new Event(event)));
        expect(screen.queryByRole('searchbox')).toBeNull(); expect(document.body).not.toHaveTextContent('Synthetic event'); expect(document.body.innerHTML).not.toContain('private query');
    });
    it('clears private filters on hidden visibility and never restores them on return', async () => {
        render(<Harness/>); await openHistory(); query('private query'); const visibility = vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden');
        act(() => document.dispatchEvent(new Event('visibilitychange'))); expect(screen.queryByRole('searchbox')).toBeNull(); visibility.mockReturnValue('visible'); act(() => document.dispatchEvent(new Event('visibilitychange'))); await flush();
        fireEvent.click(details().querySelector('summary')!); expect(screen.getByRole('searchbox')).toHaveValue('');
    });
    it('clears controls on scope loss, failed refresh and session replacement with a late response', async () => {
        const rendered = render(<Harness/>); await openHistory(); query('private query'); vi.mocked(request).mockResolvedValue(windowsView()); fireEvent.click(screen.getByRole('button', { name: 'Refresh Windows inventory' })); await flush(); expect(screen.queryByRole('searchbox')).toBeNull();
        vi.mocked(request).mockResolvedValue(historyView()); fireEvent.click(screen.getByRole('button', { name: 'Refresh Windows inventory' })); await flush(); fireEvent.click(details().querySelector('summary')!); expect(screen.getByRole('searchbox')).toHaveValue(''); query('private query');
        let resolve!: (v: ReturnType<typeof historyView>) => void; vi.mocked(request).mockReturnValueOnce(new Promise(done => { resolve = done; })); fireEvent.click(screen.getByRole('button', { name: 'Refresh Windows inventory' }));
        vi.mocked(request).mockResolvedValue(windowsView()); rendered.rerender(<Harness session="replacement"/>); await act(async () => resolve(historyView())); expect(screen.queryByRole('searchbox')).toBeNull(); expect(document.body).not.toHaveTextContent('Synthetic event');
        vi.mocked(request).mockRejectedValue(new Error('unavailable')); fireEvent.click(screen.getByRole('button', { name: 'Refresh Windows inventory' })); await flush(); expect(screen.queryByRole('searchbox')).toBeNull();
    });
    it('expires filters with original source age rather than event time or filtering time', async () => {
        vi.useFakeTimers(); vi.setSystemTime(windowsNow); const view = historyView(); view.snapshot!.collectedAt = view.patchContext.collectedAt = '2026-10-06T12:00:11Z'; view.status = 'stale'; view.patchContext.history.rows.forEach(row => { row.occurredAt = '2026-10-05T10:00:00Z'; });
        vi.mocked(request).mockResolvedValue(view); render(<Harness/>); await openHistory(); query('private query'); await act(async () => vi.advanceTimersByTimeAsync(1000));
        expect(screen.queryByRole('searchbox')).toBeNull(); expect(screen.getByText(/Patch context expired/)).toBeVisible(); expect(document.body.innerHTML).not.toContain('private query');
    });
    it('keeps current and retained earlier captures and their filters separate', async () => {
        const view = historyView(), old = structuredClone(view.patchContext);
        old.generationId = `sample_${'c'.repeat(32)}`; old.collectedAt = '2026-10-07T11:00:00Z'; old.history.rows[0].title = 'Earlier capture event';
        vi.mocked(request).mockResolvedValue({ ...view, retainedContext: { patchContext: old } }); render(<Harness/>); await openHistory();
        fireEvent.click(screen.getByText('Show previous capture'));
        const panels = screen.getAllByRole('region', { name: 'Patch context' }); expect(panels).toHaveLength(2);
        const previousDetails = panels[1].querySelector<HTMLDetailsElement>('.windows-patch-details')!; fireEvent.click(previousDetails.querySelector('summary')!);
        fireEvent.change(within(panels[0]).getByRole('searchbox'), { target: { value: 'Synthetic event 00' } });
        fireEvent.change(within(panels[1]).getByRole('searchbox'), { target: { value: 'Earlier capture' } });
        expect(within(panels[0]).getByRole('table')).toHaveTextContent('Synthetic event 00'); expect(within(panels[0]).getByRole('table')).not.toHaveTextContent('Earlier capture');
        expect(within(panels[1]).getByRole('table')).toHaveTextContent('Earlier capture event'); expect(within(panels[1]).getByRole('table')).not.toHaveTextContent('Synthetic event 00');
        expect(panels[0].querySelector('time')?.dateTime).toBe('2026-10-07T12:00:00Z'); expect(panels[1].querySelector('time')?.dateTime).toBe('2026-10-07T11:00:00Z');
        expect(vi.mocked(request)).toHaveBeenCalledTimes(1);
        act(() => window.dispatchEvent(new Event('blur'))); expect(screen.queryByRole('searchbox')).toBeNull(); expect(screen.queryByText('Earlier capture event')).toBeNull();
    });
});
