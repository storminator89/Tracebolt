import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { WindowsEventHistoryPanel } from './windows-event-history';
import { historyAccepted, historyRecord, historyResult, historyView } from './windows-event-history-fixture';
import { validEventHistoryResult, validEventHistoryView, validHistorySearch } from './windows-event-history-types';
import type { EventHistoryResult, EventHistoryView, HistorySearch } from './windows-event-history-types';
import { eventContentSession } from './windows-event-content-fixture';
import { windowsDeviceId } from './windows-inventory-fixture';
import { setLocale } from './i18n';
const prefix = `/api/devices/${windowsDeviceId}/windows-event-history`, at = '2026-10-07T12:00:00Z', expires = '2026-10-07T13:00:00Z';
const json = (v: unknown, status = 200) => new Response(JSON.stringify(v), { status, headers: { 'Content-Type': 'application/json' } });
const flush = async () => { await act(async () => { for (let i = 0; i < 70; i++) await Promise.resolve(); }); };
let view: EventHistoryView, result: EventHistoryResult | null, holdMessages: boolean, resolveMessages: ((v: Response) => void) | null;
const calls: { path: string; body: Record<string, unknown> }[] = [];
beforeEach(() => {
    vi.useFakeTimers(); vi.setSystemTime(at); setLocale('en', false); view = historyView(at, expires); result = null; calls.length = 0; holdMessages = false; resolveMessages = null;
    vi.stubGlobal('fetch', vi.fn(async (path: string, options?: RequestInit) => {
        const body = options?.body ? JSON.parse(String(options.body)) : {}; calls.push({ path, body });
        if (path === '/api/session') return json({ csrfToken: 'synthetic-csrf' });
        if (path === '/api/auth/session') return json({ ...eventContentSession(at), expiresAt: expires });
        if (path === prefix) return json(view);
        if (path === prefix + '/create') { const record = historyAccepted(historyRecord(view, body.search as HistorySearch)); view = { ...view, request: record, expectedFloor: record.description.identity.sequence, contentStatus: 'available' }; result = historyResult(record); return json(view); }
        if (path === prefix + '/messages') {
            if (holdMessages) return new Promise<Response>(resolve => { resolveMessages = resolve; });
            const old = view.request!, rows = result!.report.events.filter(row => (body.selections as { recordId: string }[]).some(s => s.recordId === row.event.recordId)).map(row => row.event);
            const record = historyAccepted(historyRecord(view, undefined, old, rows)); view = { ...view, request: record, expectedFloor: record.description.identity.sequence, contentStatus: 'available' }; result = historyResult(record); return json(view);
        }
        if (path === prefix + '/query') return json(result);
        if (path === prefix + '/cancel') { if (view.request && JSON.stringify(body.identity) === JSON.stringify(view.request.description.identity)) { view = { ...view, request: { ...view.request, state: 'canceled', canceledAt: at }, contentStatus: 'canceled' }; result = null; return json(view); } return json({}, 409); }
        return json({}, 404);
    }));
});
afterEach(() => { cleanup(); vi.useRealTimers(); vi.unstubAllGlobals(); });
async function setup() { render(<WindowsEventHistoryPanel deviceId={windowsDeviceId} admin insecure={false} sessionKey={expires}/>); await flush(); }
async function search() { fireEvent.click(screen.getByLabelText('Read this time window for my private session.')); fireEvent.click(screen.getByRole('button', { name: 'Search once' })); await flush(); }
it('validates bounded windows, exact original expiry and empty exhausted results', () => {
    const r = historyAccepted(historyRecord()), p = historyResult(r, 0), v = { ...historyView(), request: r, expectedFloor: '1', contentStatus: 'available' as const };
    expect(validEventHistoryResult(historyResult(r, 23), r, expires), 'nonempty pure result').toBe(true); expect(validEventHistoryView(v, windowsDeviceId, expires)).toBe(true); expect(validEventHistoryResult(p, r, expires)).toBe(true);
    expect(validHistorySearch({ channel: 'Application', start: at, end: '2026-10-15T12:00:00Z' })).toBe(false);
    p.report.quality = 'bounded'; p.report.complete = false; p.report.truncated = true; p.report.reason = 'windows_event_history_result_limit'; expect(validEventHistoryResult(p, r, expires)).toBe(false);
});
it('searches once, pages captured rows locally, and reads only deliberately selected messages', async () => {
    await setup(); expect(calls.filter(c => c.path.endsWith('/create'))).toHaveLength(0); await search(); expect(document.querySelector('.windows-event-history')?.getAttribute('data-failure')).toBeNull(); expect(validEventHistoryView(view, windowsDeviceId, expires), 'accepted view').toBe(true); expect(validEventHistoryResult(result, view.request!, expires), 'accepted result').toBe(true); expect(screen.getByText('Query exhausted · 23 headers')).toBeVisible();
    expect(calls.filter(c => c.path.endsWith('/create'))).toHaveLength(1); const count = calls.length;
    fireEvent.click(screen.getByRole('button', { name: 'Next' })); fireEvent.change(screen.getByRole('searchbox'), { target: { value: 'Synthetic Provider 1' } }); await flush(); expect(calls).toHaveLength(count);
    fireEvent.change(screen.getByRole('searchbox'), { target: { value: '' } }); fireEvent.click(screen.getByRole('checkbox', { name: 'Select Application 18446744073709551615' }));
    expect(calls.filter(c => c.path.endsWith('/messages'))).toHaveLength(0); expect(screen.getByRole('button', { name: 'Read 1 messages' })).toBeDisabled();
    fireEvent.click(screen.getByLabelText('Messages may contain credentials, personal data and other secrets.')); fireEvent.click(screen.getByRole('button', { name: 'Read 1 messages' })); await flush();
    expect(calls.filter(c => c.path.endsWith('/messages'))).toHaveLength(1); expect(document.querySelector('.history-messages pre')?.textContent).toContain('<img src=x onerror=alert(1)>'); expect(document.querySelector('.history-messages img')).toBeNull();
    expect(screen.getByText('1 selected messages · Read')).toBeVisible();
    expect(view.request!.description.expiresAt).toBe('2026-10-07T12:15:00.000Z'); expect(view.request!.description.searchReceipt).toBeDefined();
});
it('clears the accepted predecessor when navigation interrupts message creation', async () => {
    await setup(); await search(); const predecessor = view.request!.description.identity; holdMessages = true;
    fireEvent.click(screen.getByRole('checkbox', { name: 'Select Application 18446744073709551615' })); fireEvent.click(screen.getByLabelText('Messages may contain credentials, personal data and other secrets.')); fireEvent.click(screen.getByRole('button', { name: 'Read 1 messages' })); await flush();
    fireEvent(window, new Event('blur')); await flush();
    expect(calls.some(c => c.path.endsWith('/cancel') && JSON.stringify(c.body.identity) === JSON.stringify(predecessor))).toBe(true); expect(view.request!.state).toBe('canceled'); expect(document.querySelector('tbody')).toBeNull();
    if (resolveMessages) { await act(async () => resolveMessages!(json(view))); await flush(); } expect(document.querySelector('.history-messages pre')).toBeNull();
});

it('uses clear German event counts and localized levels', async () => {
    setLocale('de', false); await setup();
    expect(screen.getByRole('option', { name: 'Kritisch' })).toHaveValue('1');
    expect(screen.getByRole('option', { name: 'Fehler' })).toHaveValue('2');
    expect(screen.getByRole('option', { name: 'Warnung' })).toHaveValue('3');
    fireEvent.click(screen.getByLabelText('Diesen Zeitraum für meine private Sitzung lesen.'));
    fireEvent.click(screen.getByRole('button', { name: 'Einmal suchen' })); await flush();
    expect(screen.getByText('Suche beendet · 23 Ereignisse')).toBeVisible();
    expect(screen.getByLabelText('Erfasste Ereignisse filtern')).toBeVisible();
});
