import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { APIError, mutateRaw, request } from './api';
import { useOperator } from './auth';
import { JournalContent, JournalPanel } from './journal';
import type { JournalResource } from './journal-resource';
import { journalDevice, journalNow, journalPage, journalSession, journalSessionExpiry, journalView } from './journal-fixtures';
import { serviceRows, systemPage, systemView } from './system-inventory-fixtures';
import type { SystemPage } from './system-inventory-types';
import { setLocale } from './i18n';
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutateRaw: vi.fn() }));
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
function resource(change: Partial<JournalResource> = {}): JournalResource {
    return { view: journalView('awaiting'), page: null, busy: false, paused: false, failure: null, uncertain: false, reset: 0, refresh: vi.fn(), refreshWindow: vi.fn(async () => null), create: vi.fn(async () => undefined), cancelRequest: vi.fn(), search: vi.fn(), next: vi.fn(), previous: vi.fn(), canPrevious: false, ...change };
}
function servicesView() { return { ...systemView(250), deviceId: journalDevice }; }
const ui = (r: JournalResource, plaintext = false) => <JournalContent resource={r} insecureTestMode={plaintext} sessionKey={journalSessionExpiry}/>;
beforeEach(() => {
    setLocale('en', false); vi.mocked(useOperator).mockReturnValue({ mode: 'lan', authenticated: true, expiresAt: journalSessionExpiry, insecureTestMode: false, logout: vi.fn(), theme: 'light', setTheme: vi.fn() });
    vi.mocked(request).mockReset().mockImplementation(async () => servicesView());
    vi.mocked(mutateRaw).mockReset().mockImplementation(async (_path, raw) => systemPage(servicesView(), serviceRows(250), [], raw));
});
afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); });

describe('journal parent form integration and trusted time presets', () => {
    it.each([[5, '5 minutes ending at reference time', '11:55'], [15, '15 minutes ending at reference time', '11:45'], [30, '30 minutes ending at reference time', '11:30'], [60, '1 hour ending at reference time', '11:00']] as const)('selects a%d-minute window from trusted serverNow, never local time or automatic capture', (minutes, label, start) => {
        vi.spyOn(Date, 'now').mockReturnValue(Date.parse('2030-01-01T01:02:03Z')); const r = resource(); render(ui(r)); openAdvanced(); fireEvent.change(screen.getByLabelText('Exact service unit'), { target: { value: 'fixture.service' } });
        const button = screen.getByRole('button', { name: label }); expect(button).toHaveAttribute('type', 'button'); fireEvent.click(button);
        expect(screen.getByLabelText('From (UTC)')).toHaveValue(`2026-10-04T${start}`); expect(screen.getByLabelText('To (UTC)')).toHaveValue(journalNow.slice(0, 16)); expect(button).toHaveAttribute('aria-pressed', 'true'); expect(button).toHaveAccessibleDescription(`Last checked manager time (UTC): ${journalNow}`); expect(screen.getByText(/Reference time may be old/)).toBeVisible();
        expect(r.create).not.toHaveBeenCalled(); expect(r.cancelRequest).not.toHaveBeenCalled(); expect(request).not.toHaveBeenCalled(); expect(mutateRaw).not.toHaveBeenCalled();
        fireEvent.click(screen.getByRole('button', { name: 'Fetch logs' })); fireEvent.click(screen.getByRole('checkbox')); fireEvent.click(screen.getByRole('button', { name: 'Capture logs' })); expect(r.create).toHaveBeenCalledExactlyOnceWith({ unit: 'fixture.service', start: `2026-10-04T${start}:00Z`, end: '2026-10-04T12:00:00Z', maxPriority: 6 }, true, false); expect(minutes).toBeLessThanOrEqual(60);
    });
    it('keeps unit, custom UTC window, severity and retained results stable through ordinary status renders', () => {
        const view = journalView(), page = journalPage(['Retained synthetic message']), r = resource({ view, page }); const rendered = render(ui(r));
        openAdvanced(); fireEvent.change(screen.getByLabelText('Exact service unit'), { target: { value: 'draft.service' } }); fireEvent.change(screen.getByLabelText('From (UTC)'), { target: { value: '2026-10-04T11:42:12' } }); fireEvent.change(screen.getByLabelText('To (UTC)'), { target: { value: '2026-10-04T11:58:34' } }); fireEvent.change(screen.getByLabelText('Include severity through'), { target: { value: '3' } });
        const enteredStart = (screen.getByLabelText('From (UTC)') as HTMLInputElement).value, enteredEnd = (screen.getByLabelText('To (UTC)') as HTMLInputElement).value;
        for (const busy of [true, false, true, false]) {
            rendered.rerender(ui({ ...r, busy, view: { ...view, serverNow: '2026-10-04T12:04:00Z' } })); expect(screen.getByLabelText('Exact service unit')).toHaveValue('draft.service'); expect(screen.getByLabelText('From (UTC)')).toHaveValue(enteredStart); expect(screen.getByLabelText('To (UTC)')).toHaveValue(enteredEnd); expect(screen.getByLabelText('Include severity through')).toHaveValue('3'); expect(screen.getByText('Retained synthetic message')).toBeVisible();
        }
        expect(screen.queryAllByRole('button', { pressed: true })).toHaveLength(0); expect(r.create).not.toHaveBeenCalled(); expect(r.cancelRequest).not.toHaveBeenCalled();
    });
    it('accepts browser-normalized fractional-zero seconds while retaining explicit UTC', () => {
        const r = resource(); render(ui(r)); openAdvanced(); fireEvent.change(screen.getByLabelText('Exact service unit'), { target: { value: 'fixture.service' } }); fireEvent.change(screen.getByLabelText('From (UTC)'), { target: { value: '2026-10-04T11:42:12' } }); fireEvent.change(screen.getByLabelText('To (UTC)'), { target: { value: '2026-10-04T11:58:34' } }); fireEvent.click(screen.getByRole('button', { name: 'Fetch logs' })); fireEvent.click(screen.getByRole('checkbox'));
        expect(screen.getByRole('button', { name: 'Capture logs' })).toBeEnabled(); fireEvent.click(screen.getByRole('button', { name: 'Capture logs' })); const query = vi.mocked(r.create).mock.calls[0][0]; expect(Date.parse(query.start)).toBe(Date.parse('2026-10-04T11:42:12Z')); expect(Date.parse(query.end)).toBe(Date.parse('2026-10-04T11:58:34Z')); expect(query.start).toMatch(/Z$/); expect(query.end).toMatch(/Z$/);
    });
    it('retains the entered window during refresh; a new preset alone chooses the newly checked manager time', () => {
        const r = resource(); const rendered = render(ui(r)); fireEvent.click(screen.getByRole('button', { name: '5 minutes ending at reference time' })); openAdvanced(); fireEvent.change(screen.getByLabelText('Exact service unit'), { target: { value: 'draft.service' } }); fireEvent.change(screen.getByLabelText('Include severity through'), { target: { value: '2' } });
        fireEvent.click(screen.getByRole('button', { name: 'Refresh status and reference time' })); expect(r.refresh).toHaveBeenCalledOnce(); expect(screen.getByLabelText('To (UTC)')).toHaveValue('2026-10-04T12:00');
        rendered.rerender(ui({ ...r, view: null, busy: true, reset: 1 })); expect(screen.getByLabelText('From (UTC)')).toHaveValue('2026-10-04T11:55'); expect(screen.getByLabelText('Exact service unit')).toBeDisabled();
        rendered.rerender(ui({ ...r, view: { ...journalView('awaiting'), serverNow: '2026-10-04T12:03:00Z' }, reset: 1 })); expect(screen.getByLabelText('To (UTC)')).toHaveValue('2026-10-04T12:00'); expect(screen.getByLabelText('Exact service unit')).toHaveValue('draft.service'); expect(screen.getByLabelText('Include severity through')).toHaveValue('2'); expect(screen.queryAllByRole('button', { pressed: true })).toHaveLength(0);
        fireEvent.click(screen.getByRole('button', { name: '5 minutes ending at reference time' })); expect(screen.getByLabelText('From (UTC)')).toHaveValue('2026-10-04T11:58'); expect(screen.getByLabelText('To (UTC)')).toHaveValue('2026-10-04T12:03'); expect(r.create).not.toHaveBeenCalled();
    });
    it('keeps the manual exact-unit fallback available when observed inventory is unavailable', async () => {
        vi.mocked(request).mockRejectedValue(new APIError('private source error', 503)); const r = resource(); render(ui(r)); fireEvent.click(screen.getByRole('button', { name: 'Choose observed service' })); await screen.findByRole('alert'); expect(screen.getByRole('alert')).not.toHaveTextContent('private source error');
        fireEvent.click(screen.getByRole('button', { name: 'Close service picker' })); openAdvanced(); fireEvent.change(screen.getByLabelText('Exact service unit'), { target: { value: 'manual.service' } }); expect(screen.getByLabelText('Exact service unit')).toHaveValue('manual.service'); expect(screen.queryByRole('checkbox')).not.toBeInTheDocument(); expect(r.create).not.toHaveBeenCalled();
    });
    it('search Enter cannot submit an otherwise ready capture form or change its selected service', async () => {
        const r = resource(); render(ui(r)); openAdvanced(); fireEvent.change(screen.getByLabelText('Exact service unit'), { target: { value: 'manual.service' } }); expect(screen.getByRole('button', { name: 'Fetch logs' })).toBeEnabled();
        fireEvent.click(screen.getByRole('button', { name: 'Choose observed service' })); await screen.findByText('fixture-000000.service'); const search = screen.getByLabelText('Search observed services'); fireEvent.change(search, { target: { value: 'fixture-000249' } }); fireEvent.keyDown(search, { key: 'Enter' }); await screen.findByText('fixture-000249.service'); expect(screen.getByLabelText('Exact service unit')).toHaveValue('manual.service'); expect(r.create).not.toHaveBeenCalled(); expect(r.cancelRequest).not.toHaveBeenCalled();
        expect(vi.mocked(mutateRaw).mock.calls.every(([path]) => path.endsWith('/inventory/system/query'))).toBe(true);
    });
    it('pause closes the picker and suppresses an old service page while retaining draft controls', async () => {
        const r = resource(); const rendered = render(ui(r)); openAdvanced(); fireEvent.change(screen.getByLabelText('Exact service unit'), { target: { value: 'draft.service' } }); fireEvent.click(screen.getByRole('button', { name: '30 minutes ending at reference time' })); fireEvent.change(screen.getByLabelText('Include severity through'), { target: { value: '4' } });
        let finish!: (v: SystemPage) => void, signal!: AbortSignal; vi.mocked(mutateRaw).mockImplementationOnce(async (_path, _raw, _headers, supplied) => { signal = supplied!; return new Promise<SystemPage>(resolve => { finish = resolve; }); }); fireEvent.click(screen.getByRole('button', { name: 'Choose observed service' })); await waitFor(() => expect(finish).toBeDefined());
        rendered.rerender(ui({ ...r, view: null, paused: true, reset: 1 })); expect(signal.aborted).toBe(true); expect(screen.queryByRole('region', { name: 'Observed services' })).not.toBeInTheDocument(); expect(screen.getByLabelText('Exact service unit')).toHaveValue('draft.service'); expect(screen.getByLabelText('From (UTC)')).toHaveValue('2026-10-04T11:30'); expect(screen.getByLabelText('Include severity through')).toHaveValue('4');
        await act(async () => finish(systemPage(servicesView(), serviceRows(250), [], JSON.stringify({ section: 'services', cursor: '', search: '', filter: 'all', limit: 100 })))); expect(screen.queryByText('fixture-000000.service')).not.toBeInTheDocument(); expect(r.create).not.toHaveBeenCalled();
    });
    it('does not precheck either content acknowledgement after picker selection or time presets', async () => {
        const r = resource(); render(ui(r, true)); fireEvent.click(screen.getByRole('button', { name: 'Choose observed service' })); await screen.findByText('fixture-000000.service'); fireEvent.click(screen.getByRole('button', { name: 'Use fixture-000000.service' })); fireEvent.click(screen.getByRole('button', { name: '1 hour ending at reference time' }));
        expect(screen.queryByRole('checkbox')).not.toBeInTheDocument(); fireEvent.click(screen.getByRole('button', { name: 'Fetch logs' }));
        for (const box of screen.getAllByRole('checkbox')) expect(box).not.toBeChecked(); expect(screen.getByRole('button', { name: 'Capture logs' })).toBeDisabled(); expect(r.create).not.toHaveBeenCalled();
    });
    it('preserves drafts through real quiet status polls and retained results through four minutes of accepted idle', async () => {
        vi.useFakeTimers(); localStorage.clear(); sessionStorage.clear(); let reads = 0, managerNow = journalNow;
        vi.mocked(request).mockImplementation(async path => {
            if (path === '/auth/session') return { ...journalSession, serverNow: managerNow };
            if (path === `/devices/${journalDevice}/journal`) { reads++; managerNow = new Date(Date.parse(journalNow) + (reads - 1) * 3000).toISOString(); const view = journalView(reads < 3 ? 'pending' : 'accepted'); view.serverNow = managerNow; view.localStatus = reads < 3 ? 'checking' : 'unknown'; return view; }
            throw new Error('Unexpected synthetic request');
        });
        vi.mocked(mutateRaw).mockImplementation(async path => { if (!path.endsWith('/journal/query')) throw new Error('Unexpected mutation'); return { ...journalPage(['Quiet-poll retained synthetic row']), serverNow: managerNow }; });
        render(<JournalPanel deviceId={journalDevice} insecureTestMode={false} sessionKey={journalSessionExpiry}/>); await act(async () => {}); expect(screen.getByText('Pending', { selector: 'strong' })).toBeVisible();
        openAdvanced(); fireEvent.change(screen.getByLabelText('Exact service unit'), { target: { value: 'next-draft.service' } }); fireEvent.change(screen.getByLabelText('From (UTC)'), { target: { value: '2026-10-04T11:30' } }); fireEvent.change(screen.getByLabelText('To (UTC)'), { target: { value: '2026-10-04T11:40' } }); fireEvent.change(screen.getByLabelText('Include severity through'), { target: { value: '3' } });
        for (let i = 0; i < 2; i++) { await act(async () => { await vi.advanceTimersByTimeAsync(3000); }); expect(screen.getByLabelText('Exact service unit')).toHaveValue('next-draft.service'); expect(screen.getByLabelText('From (UTC)')).toHaveValue('2026-10-04T11:30'); expect(screen.getByLabelText('To (UTC)')).toHaveValue('2026-10-04T11:40'); expect(screen.getByLabelText('Include severity through')).toHaveValue('3'); }
        expect(screen.getByText('Quiet-poll retained synthetic row')).toBeVisible(); const readCalls = vi.mocked(request).mock.calls.length; await act(async () => { await vi.advanceTimersByTimeAsync(240000); }); expect(screen.getByText('Quiet-poll retained synthetic row')).toBeVisible(); expect(request).toHaveBeenCalledTimes(readCalls); expect(mutateRaw).toHaveBeenCalledTimes(1); expect(vi.mocked(mutateRaw).mock.calls[0][0]).toBe(`/devices/${journalDevice}/journal/query`);
    });
    it('labels a preset against the unchanged reference after fourteen minutes of accepted idle', async () => {
        vi.useFakeTimers(); localStorage.clear(); sessionStorage.clear();
        vi.mocked(request).mockImplementation(async path => {
            if (path === '/auth/session') return journalSession;
            if (path === `/devices/${journalDevice}/journal`) return journalView();
            throw new Error('Unexpected synthetic request');
        });
        vi.mocked(mutateRaw).mockImplementation(async path => { if (!path.endsWith('/journal/query')) throw new Error('Unexpected mutation'); return journalPage(['Reference-time retained synthetic row']); });
        render(<JournalPanel deviceId={journalDevice} insecureTestMode={false} sessionKey={journalSessionExpiry}/>); await act(async () => {});
        expect(screen.getByText('Reference-time retained synthetic row')).toBeVisible();
        openAdvanced(); fireEvent.change(screen.getByLabelText('Exact service unit'), { target: { value: 'next-draft.service' } }); fireEvent.change(screen.getByLabelText('From (UTC)'), { target: { value: '2026-10-04T11:30' } }); fireEvent.change(screen.getByLabelText('To (UTC)'), { target: { value: '2026-10-04T11:40' } }); fireEvent.change(screen.getByLabelText('Include severity through'), { target: { value: '3' } });
        const reads = vi.mocked(request).mock.calls.length; await act(async () => { await vi.advanceTimersByTimeAsync(14 * 60000); });
        expect(screen.getByText('Reference-time retained synthetic row')).toBeVisible(); expect(screen.getByLabelText('From (UTC)')).toHaveValue('2026-10-04T11:30'); expect(screen.getByLabelText('To (UTC)')).toHaveValue('2026-10-04T11:40');
        const group = screen.getByRole('group', { name: 'Windows ending at the displayed reference time' }), button = within(group).getByRole('button', { name: '15 minutes ending at reference time' });
        expect(button).toHaveAccessibleDescription(`Last checked manager time (UTC): ${journalNow}`); expect(screen.getByRole('button', { name: 'Refresh status and reference time' })).toHaveAttribute('type', 'button'); expect(screen.getByRole('button', { name: 'Last 15 min' })).toBeVisible();
        fireEvent.click(button); expect(screen.getByLabelText('From (UTC)')).toHaveValue('2026-10-04T11:45'); expect(screen.getByLabelText('To (UTC)')).toHaveValue('2026-10-04T12:00'); expect(screen.getByLabelText('Exact service unit')).toHaveValue('next-draft.service'); expect(screen.getByLabelText('Include severity through')).toHaveValue('3'); expect(screen.getByText('Reference-time retained synthetic row')).toBeVisible(); expect(button).toHaveAttribute('aria-pressed', 'true'); expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();
        expect(request).toHaveBeenCalledTimes(reads); expect(mutateRaw).toHaveBeenCalledTimes(1); expect(vi.mocked(mutateRaw).mock.calls[0][0]).toBe(`/devices/${journalDevice}/journal/query`);
    });
    it('shows German preset and manual fallback labels', () => {
        setLocale('de', false); const r = resource(); render(ui(r)); openAdvanced(); fireEvent.click(screen.getByRole('button', { name: '30 Minuten bis zur Referenzzeit' })); expect(screen.getByLabelText('Von (UTC)')).toHaveValue('2026-10-04T11:30'); expect(screen.getByText(/Beobachtete Namen bestätigen keine lokale Freigabe/)).toBeVisible(); expect(r.create).not.toHaveBeenCalled();
    });
});

it('uses a valid service handoff only as the initial draft, preserving edits on rerender with no capture or consent', () => {
    const r = resource(), rendered = render(<JournalContent resource={r} insecureTestMode initialUnit="chosen.service"/>); openAdvanced();
    expect(screen.getByLabelText('Exact service unit')).toHaveValue('chosen.service');
    expect(screen.queryByRole('checkbox')).not.toBeInTheDocument(); fireEvent.click(screen.getByRole('button', { name: 'Fetch logs' }));
    for (const checkbox of screen.getAllByRole('checkbox')) expect(checkbox).not.toBeChecked();
    expect(screen.getByRole('button', { name: 'Capture logs' })).toBeDisabled(); fireEvent.click(screen.getByRole('button', { name: 'Back' }));
    openAdvanced(); fireEvent.change(screen.getByLabelText('Exact service unit'), { target: { value: 'edited.service' } });
    rendered.rerender(<JournalContent resource={r} insecureTestMode initialUnit="different.service"/>);
    expect(screen.getByLabelText('Exact service unit')).toHaveValue('edited.service');
    expect(r.create).not.toHaveBeenCalled(); expect(r.cancelRequest).not.toHaveBeenCalled(); expect(mutateRaw).not.toHaveBeenCalled();
});
it.each(['*.service', '../unsafe.service', 'example.socket', '<script>.service'])('rejects unsupported initial log unit %s', initialUnit => {
    const r = resource(); render(<JournalContent resource={r} insecureTestMode={false} initialUnit={initialUnit}/>);
    expect(screen.getByLabelText('Exact service unit')).toHaveValue(''); expect(r.create).not.toHaveBeenCalled();
});

function openAdvanced() {
    const summary = screen.getByText(/^(Advanced|Erweitert)$/, { selector: 'summary' });
    if (!summary.closest('details')!.open) fireEvent.click(summary);
}
