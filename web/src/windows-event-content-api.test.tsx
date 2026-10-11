import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AUTH_REQUIRED_EVENT } from './api';
import { setLocale } from './i18n';
import { WindowsLogsPanel } from './windows-logs';
import { eventContentAccepted, eventContentRecord, eventContentResult, eventContentSession, eventContentSessionExpires, eventContentView } from './windows-event-content-fixture';
import type { EventContentResult, EventContentView, SelectedEvent } from './windows-event-content-types';
import { windowsEventsView } from './windows-events-fixture';
import { windowsDeviceId, windowsNow } from './windows-inventory-fixture';
import type { WindowsInventoryResource } from './windows-inventory-resource';
const prefix = `/api/devices/${windowsDeviceId}/windows-event-content`;
const json = (v: unknown, status = 200) => new Response(JSON.stringify(v).replace(/[<>&]/g, c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`), { status, headers: { 'Content-Type': 'application/json' } });
const flush = async () => { await act(async () => { for (let i = 0; i < 50; i++) await Promise.resolve(); }); };
const advance = async (ms: number) => { await act(async () => vi.advanceTimersByTimeAsync(ms)); await flush(); };
function inventory(): WindowsInventoryResource { const view = windowsEventsView(); return { view, snapshot: view.snapshot, events: view.events, status: 'fresh', error: null, loading: false, refresh: vi.fn(), elapsedMS: 0, eventsStale: false, volumes: null, volumesStale: false, processMetrics: null, processMetricsStale: false, network: null, networkStale: false, networkExpired: false, adapterContext: null, adapterContextStale: false, adapterContextExpired: false, patchContext: null, patchContextStale: false, patchContextExpired: false, patchContextAhead: false, sessionContext: null, sessionContextStale: false, sessionContextExpired: false, sessionContextAhead: false, securityPosture: null, securityPostureStale: false, securityPostureExpired: false, securityPostureAhead: false, serviceStartup: null, serviceStartupStale: false, updates: null, updatesStale: false, updatesExpired: false, updatesAhead: false }; }
const access = { deviceId: windowsDeviceId, admin: true, insecure: false, sessionKey: eventContentSessionExpires };
let view: EventContentView, accepted: boolean, transform: (v: EventContentResult) => EventContentResult, override: ((path: string, options?: RequestInit) => Promise<Response> | undefined) | null;
const calls: { path: string; options?: RequestInit }[] = [];
const selection = (): SelectedEvent[] => windowsEventsView().events.channels.slice(0, 1).map(c => ({ ...c.rows[0], channel: c.channel }));
const created = () => calls.filter(c => c.path === prefix + '/create');
const queried = () => calls.filter(c => c.path === prefix + '/query');
const select = () => fireEvent.click(screen.getByRole('checkbox', { name: 'Select Application 18446744073709551615' }));
const review = () => fireEvent.click(screen.getByRole('button', { name: 'Review selection' }));
const acknowledge = () => fireEvent.click(screen.getByLabelText('I acknowledge this exact selection and the sensitive-message risks.'));
const submit = () => { review(); acknowledge(); fireEvent.click(screen.getByRole('button', { name: 'Request messages once' })); };
async function setup() { const ui = render(<WindowsLogsPanel resource={inventory()} contentAccess={access}/>); await flush(); return ui; }
beforeEach(() => {
    vi.useFakeTimers(); vi.setSystemTime(windowsNow); setLocale('en', false); localStorage.clear(); sessionStorage.clear(); view = eventContentView(); accepted = true; transform = v => v; override = null; calls.length = 0;
    vi.stubGlobal('fetch', vi.fn(async (path: string, options?: RequestInit) => {
        calls.push({ path, options }); const special = override?.(path, options); if (special) return special;
        const now = new Date(Date.now()).toISOString();
        if (path === '/api/auth/session') return json(eventContentSession(now));
        if (path === '/api/session') return json({ csrfToken: 'synthetic-csrf' });
        if (path === prefix) return json({ ...view, serverNow: now });
        if (path === prefix + '/create') {
            const body = JSON.parse(String(options?.body)), all = windowsEventsView().events.channels.flatMap(c => c.rows.map(e => ({ ...e, channel: c.channel })));
            const events = body.selections.map((e: SelectedEvent) => all.find(r => r.channel === e.channel && r.recordId === e.recordId));
            const pending = eventContentRecord(events, { ...view, serverNow: now }); view = { ...view, serverNow: now, expectedFloor: pending.description.identity.sequence, request: accepted ? eventContentAccepted(pending) : pending, contentStatus: accepted ? 'available' : 'pending' }; return json(view);
        }
        if (path === prefix + '/query') { const value = transform(eventContentResult(view.request!)); value.expiresAt = new Date(Math.min(Date.parse(value.expiresAt), Date.parse(view.sessionExpiresAt), Date.parse(view.headers!.expiresAt))).toISOString(); return json(value); }
        if (path === prefix + '/cancel') { view = { ...view, serverNow: now, contentStatus: 'canceled', request: { ...view.request!, state: 'canceled', canceledAt: now } }; return json(view); }
        throw new Error('Unexpected fixture route');
    }));
});
afterEach(async () => { cleanup(); await flush(); vi.unstubAllGlobals(); vi.restoreAllMocks(); vi.useRealTimers(); });
describe('real event-content hook, API and Logs integration', () => {
    it('requires exact review and sends canonical IDs; renders literal messages with no autolinks or private bytes outbound', async () => {
        await setup(); expect(created()).toHaveLength(0); select(); expect(created()).toHaveLength(0); review(); expect(screen.getByRole('button', { name: 'Request messages once' })).toBeDisabled();
        expect(screen.getByRole('group', { name: 'Confirm this exact selection' })).toHaveTextContent('2026-10-06T10:30:00Z');
        acknowledge(); fireEvent.click(screen.getByRole('button', { name: 'Request messages once' })); await flush();
        expect(created()).toHaveLength(1); expect(JSON.parse(String(created()[0].options?.body))).toEqual({ expectedFloor: '0', expectedHeaderGenerationId: view.headers!.generationId, expectedHeaderSnapshotDigest: view.headers!.snapshotDigest, selections: [{ channel: 'Application', recordId: '18446744073709551615' }], acknowledgeContent: true, acknowledgePlaintext: false });
        expect(created()[0].options?.headers).toMatchObject({ 'X-CSRF-Token': 'synthetic-csrf' }); expect(queried()).toHaveLength(1);
        expect(document.querySelector('.windows-event-message')?.textContent).toContain('<img src=x onerror=alert(1)>'); expect(document.querySelector('.windows-event-content img')).toBeNull(); expect(document.querySelector('.windows-event-content a')).toBeNull();
        const count = calls.length; fireEvent.change(screen.getByLabelText('Search captured selection only'), { target: { value: 'private search' } }); await flush(); expect(screen.getByText('No captured messages match this filter.')).toBeVisible(); expect(calls).toHaveLength(count);
        expect(calls.every(c => !c.path.includes('?') && !String(c.options?.body ?? '').includes('Invented message') && !String(c.options?.body ?? '').includes('private search'))).toBe(true); expect(localStorage.length + sessionStorage.length).toBe(0);
    });
    it('caps selected displayed rows at 16 across pages and never creates from filtering, review or status', async () => {
        await setup(); const boxes = () => screen.getAllByRole('checkbox').filter(e => e.getAttribute('aria-label')?.startsWith('Select ')); boxes().forEach(e => fireEvent.click(e)); fireEvent.click(screen.getByRole('button', { name: 'Next' })); boxes().slice(0, 6).forEach(e => fireEvent.click(e)); expect(screen.getByText('16 of at most 16 headers selected')).toBeVisible(); expect(boxes()[6]).toBeDisabled();
        review(); expect(screen.getByRole('group', { name: 'Confirm this exact selection' }).querySelectorAll('li')).toHaveLength(16); fireEvent.keyDown(screen.getByRole('group', { name: 'Confirm this exact selection' }), { key: 'Escape' }); expect(screen.queryByRole('group', { name: 'Confirm this exact selection' })).toBeNull();
        fireEvent.change(screen.getByLabelText('Provider'), { target: { value: 'Provider A' } }); expect(screen.getByText('Page 1 of 2 · 12 matching headers')).toBeVisible(); fireEvent.click(screen.getByRole('button', { name: 'Check content status' })); await flush(); expect(screen.getByLabelText('Provider')).toHaveValue('Provider A'); expect(created()).toHaveLength(0);
    });
    it('invalidates acknowledgement when selection changes', async () => {
        await setup(); select(); review(); acknowledge(); expect(screen.getByRole('button', { name: 'Request messages once' })).toBeEnabled(); fireEvent.click(screen.getByRole('checkbox', { name: 'Select System 18446744073709551615' })); expect(screen.getByLabelText('I acknowledge this exact selection and the sensitive-message risks.')).not.toBeChecked(); expect(screen.getByRole('button', { name: 'Request messages once' })).toBeDisabled(); expect(created()).toHaveLength(0);
    });
    it('preserves review through same-sample background refresh; clears on original capture or grant change', async () => {
        const ui = await setup(); select(); review(); acknowledge(); ui.rerender(<WindowsLogsPanel resource={{ ...inventory(), loading: true, events: null, snapshot: null, view: null }} contentAccess={access}/>); expect(screen.getByRole('group', { name: 'Confirm this exact selection' })).toBeVisible(); expect(screen.getByRole('button', { name: 'Request messages once' })).toBeDisabled();
        ui.rerender(<WindowsLogsPanel resource={inventory()} contentAccess={access}/>); expect(screen.getByLabelText('I acknowledge this exact selection and the sensitive-message risks.')).toBeChecked();
        view.capability!.grantId = 'b'.repeat(32); fireEvent.click(screen.getByRole('button', { name: 'Check content status' })); await flush(); expect(screen.queryByRole('group', { name: 'Confirm this exact selection' })).toBeNull();
        select(); review(); const newer = inventory(); newer.events!.collectedAt = '2026-10-07T12:00:03Z'; ui.rerender(<WindowsLogsPanel resource={newer} contentAccess={access}/>); await flush(); expect(screen.queryByRole('group', { name: 'Confirm this exact selection' })).toBeNull(); expect(screen.getByText('0 of at most 16 headers selected')).toBeVisible(); expect(created()).toHaveLength(0);
    });
    it('reconciles ambiguous creation via GET without resubmitting', async () => {
        await setup(); override = path => { if (path !== prefix + '/create') return; const r = eventContentAccepted(eventContentRecord(selection())); view = { ...view, request: r, expectedFloor: '1', contentStatus: 'available' }; return Promise.reject(new TypeError('private transport error')); };
        select(); submit(); await flush(); expect(created()).toHaveLength(1); expect(queried()).toHaveLength(1); expect(document.querySelector('.windows-event-message')).not.toBeNull(); await advance(3000); expect(created()).toHaveLength(1); expect(queried()).toHaveLength(1); expect(document.body).not.toHaveTextContent('private transport error');
    });
    it('cancels an in-flight result and rejects its late text', async () => {
        let finish!: (v: Response) => void, late: EventContentResult | null = null; override = path => path === prefix + '/query' ? new Promise(resolve => { finish = resolve; late = eventContentResult(view.request!); }) : undefined;
        await setup(); select(); submit(); await flush(); expect(screen.getByText('Loading bounded result…')).toBeVisible(); const signal = queried()[0].options!.signal!;
        fireEvent.click(screen.getByRole('button', { name: 'Cancel and discard content' })); await flush(); expect(signal.aborted).toBe(true); expect(calls.filter(c => c.path.endsWith('/cancel'))).toHaveLength(1); await act(async () => finish(json(late))); await flush(); expect(document.querySelector('.windows-event-message')).toBeNull(); expect(screen.getByText('Request status: Canceled')).toBeVisible();
    });
    it('cancels an in-flight create using reconciled identity and ignores its late response', async () => {
        let finish!: (v: Response) => void; override = path => { if (path !== prefix + '/create') return; const r = eventContentRecord(selection()); view = { ...view, request: r, expectedFloor: '1', contentStatus: 'pending' }; return new Promise(resolve => { finish = resolve; }); };
        await setup(); select(); submit(); await flush(); fireEvent.click(screen.getByRole('button', { name: 'Cancel and discard content' })); await flush(); await act(async () => finish(json(view))); await flush(); expect(queried()).toHaveLength(0); expect(created()).toHaveLength(1); expect(view.request!.state).toBe('canceled'); expect(screen.getByText('0 of at most 16 headers selected')).toBeVisible();
    });
    it('resolves a lost cancel response from authoritative terminal GET without repeating the mutation', async () => {
        await setup(); select(); submit(); await flush(); override = path => { if (path !== prefix + '/cancel') return; view = { ...view, request: { ...view.request!, state: 'canceled', canceledAt: view.serverNow }, contentStatus: 'canceled' }; return Promise.reject(new TypeError('lost cancel response')); };
        fireEvent.click(screen.getByRole('button', { name: 'Cancel and discard content' })); await flush(); expect(screen.getByText('Request status: Canceled')).toBeVisible(); expect(screen.queryByText(/outcome is uncertain/)).toBeNull(); expect(calls.filter(c => c.path.endsWith('/cancel'))).toHaveLength(1); expect(created()).toHaveLength(1); expect(document.querySelector('.windows-event-message')).toBeNull();
    });
    it('resolves an ambiguous create whose authoritative status is already terminal', async () => {
        await setup(); override = path => { if (path !== prefix + '/create') return; const r = eventContentRecord(selection()); view = { ...view, request: { ...r, state: 'canceled', canceledAt: r.description.createdAt }, expectedFloor: '1', contentStatus: 'canceled' }; return Promise.reject(new TypeError('lost create')); }; select(); submit(); await flush(); expect(screen.getByText('Request status: Canceled')).toBeVisible(); expect(screen.queryByText(/outcome is uncertain/)).toBeNull(); expect(created()).toHaveLength(1); expect(queried()).toHaveLength(0);
    });
    it('cancels the new identity during a second delayed create, never the old terminal request', async () => {
        await setup(); select(); submit(); await flush(); fireEvent.click(screen.getByRole('button', { name: 'Cancel and discard content' })); await flush(); let finish!: (v: Response) => void;
        override = path => { if (path !== prefix + '/create') return; const r = eventContentRecord(selection(), { ...view, serverNow: new Date(Date.now()).toISOString() }); view = { ...view, request: r, expectedFloor: r.description.identity.sequence, contentStatus: 'pending' }; return new Promise(resolve => { finish = resolve; }); };
        select(); submit(); await flush(); fireEvent.click(screen.getByRole('button', { name: 'Cancel and discard content' })); await flush(); expect(view.request!.state).toBe('canceled'); const cancellations = calls.filter(c => c.path.endsWith('/cancel')); expect(cancellations).toHaveLength(2); expect(JSON.parse(String(cancellations[1].options?.body)).identity.sequence).toBe('2'); await act(async () => finish(json(view))); await flush(); expect(created()).toHaveLength(2);
    });
    it.each(['blur', 'unmount'])('best-effort reconciles and cancels committed-but-unreturned create on %s', async event => {
        let finish!: (v: Response) => void; override = path => { if (path !== prefix + '/create') return; const r = eventContentRecord(selection()); view = { ...view, request: r, expectedFloor: '1', contentStatus: 'pending' }; return new Promise(resolve => { finish = resolve; }); };
        const ui = await setup(); select(); submit(); await flush(); if (event === 'unmount') ui.unmount(); else act(() => window.dispatchEvent(new Event('blur'))); await flush(); expect(view.request!.state).toBe('canceled'); expect(calls.filter(c => c.path.endsWith('/cancel'))).toHaveLength(1); await act(async () => finish(json(view))); await flush(); expect(queried()).toHaveLength(0);
    });
    it.each(['blur', 'pagehide', 'hashchange', AUTH_REQUIRED_EVENT])('discards text, selection, review and search on %s', async event => {
        await setup(); select(); submit(); await flush(); fireEvent.change(screen.getByLabelText('Search captured selection only'), { target: { value: 'Invented' } }); act(() => window.dispatchEvent(new Event(event))); await flush(); expect(document.querySelector('.windows-event-message')).toBeNull(); expect(screen.queryByLabelText('Search captured selection only')).toBeNull(); expect(screen.getByText('0 of at most 16 headers selected')).toBeVisible();
    });
    it('discards on hidden document or replacement session and cannot automatically reopen the result', async () => {
        const ui = await setup(); select(); submit(); await flush(); const hidden = vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden'); act(() => document.dispatchEvent(new Event('visibilitychange'))); await flush(); expect(document.querySelector('.windows-event-message')).toBeNull(); hidden.mockReturnValue('visible'); act(() => document.dispatchEvent(new Event('visibilitychange'))); await flush(); expect(queried()).toHaveLength(1); expect(document.querySelector('.windows-event-message')).toBeNull();
        ui.rerender(<WindowsLogsPanel resource={inventory()} contentAccess={{ ...access, sessionKey: '2026-10-09T12:00:00Z' }}/>); await flush(); expect(document.querySelector('.windows-event-message')).toBeNull(); expect(created()).toHaveLength(1);
    });
    it('distinguishes successful empty text and accepted-but-lost result', async () => {
        transform = v => { v.report.events[0].message = ''; return v; }; await setup(); select(); submit(); await flush(); expect(screen.getByText('Successfully formatted empty message.')).toBeVisible(); view = { ...view, contentStatus: 'result_lost' }; fireEvent.click(screen.getByRole('button', { name: 'Check content status' })); await flush(); expect(screen.getByText(/accepted result is no longer available in memory/)).toBeVisible(); expect(screen.queryByText('Successfully formatted empty message.')).toBeNull(); expect(created()).toHaveLength(1);
    });
    it('rejects unknown fields and arbitrary error prose', async () => {
        transform = v => ({ ...v, extra: 'private-field' }); await setup(); select(); submit(); await flush(); expect(screen.getByRole('alert')).toHaveTextContent('inconsistent'); expect(document.body).not.toHaveTextContent('private-field'); expect(document.querySelector('.windows-event-message')).toBeNull();
    });
    it('named read users neither probe nor enqueue content', async () => { render(<WindowsLogsPanel resource={inventory()} contentAccess={{ ...access, admin: false }}/>); await flush(); expect(calls).toHaveLength(0); expect(screen.getByText(/Named read users cannot enqueue/)).toBeVisible(); expect(screen.getByRole('button', { name: 'Review selection' })).toBeDisabled(); });
    it('rejects opaque session replacement and state rollback', async () => {
        await setup(); select(); submit(); await flush(); view = { ...view, sessionBinding: 'a'.repeat(64) }; fireEvent.click(screen.getByRole('button', { name: 'Check content status' })); await flush(); expect(screen.getByRole('alert')).toHaveTextContent('session ended'); expect(document.querySelector('.windows-event-message')).toBeNull();
    });
    it.each(['wall-clock change', 'header expiry', 'grant lease expiry', 'session expiry'])('discards at %s without renewing time', async cause => {
        if (cause === 'header expiry') { view.headers!.collectedAt = new Date(Date.parse(windowsNow) - 86400000 + 1000).toISOString(); view.headers!.expiresAt = new Date(Date.parse(windowsNow) + 1000).toISOString(); }
        if (cause === 'grant lease expiry') { view.capability!.expiresAt = new Date(Date.parse(windowsNow) + 1000).toISOString(); view.capability!.reportedAt = new Date(Date.parse(windowsNow) - 299000).toISOString(); }
        const key = cause === 'session expiry' ? new Date(Date.parse(windowsNow) + 1000).toISOString() : eventContentSessionExpires;
        if (cause === 'session expiry') { view.sessionExpiresAt = key; override = path => path === '/api/auth/session' ? Promise.resolve(json({ ...eventContentSession(new Date(Date.now()).toISOString()), expiresAt: key })) : undefined; }
        const supplied = inventory(); if (cause === 'header expiry') supplied.events!.collectedAt = view.headers!.collectedAt;
        render(<WindowsLogsPanel resource={supplied} contentAccess={{ ...access, sessionKey: key }}/>); await flush(); select(); submit(); await flush(); expect(document.querySelector('.windows-event-message')).not.toBeNull(); if (cause === 'wall-clock change') vi.setSystemTime('2026-10-07T11:00:00Z'); await advance(1250); expect(document.querySelector('.windows-event-message')).toBeNull(); expect(screen.getByText('0 of at most 16 headers selected')).toBeVisible(); expect(created()).toHaveLength(1);
    });
    it('expires the original fifteen-minute window despite fresh capability reports and repeated status checks', async () => {
        await setup(); select(); submit(); await flush(); override = path => { if (path !== prefix) return; const now = new Date(Date.now()).toISOString(); return Promise.resolve(json({ ...view, serverNow: now, capability: { ...view.capability!, reportedAt: now, expiresAt: new Date(Date.now() + 300000).toISOString() } })); };
        await advance(900250); expect(document.querySelector('.windows-event-message')).toBeNull(); expect(screen.getByRole('alert')).toHaveTextContent('original content window expired'); expect(created()).toHaveLength(1); expect(queried()).toHaveLength(1);
    });
    it.each(['pending', 'accepted'])('preserves an owned %s request across newer ordinary headers', async state => {
        accepted = state === 'accepted'; const ui = await setup(); select(); submit(); await flush(); if (accepted) fireEvent.change(screen.getByLabelText('Search captured selection only'), { target: { value: 'Invented' } });
        const original = view.request!.description; const newer = inventory(); newer.events!.generationId = 'sample_' + 'b'.repeat(32); newer.events!.collectedAt = '2026-10-07T12:00:03Z'; view = { ...view, headers: { ...view.headers!, generationId: newer.events!.generationId, collectedAt: newer.events!.collectedAt, expiresAt: '2026-10-08T12:00:03Z', snapshotDigest: 'sha256:' + 'b'.repeat(64) } };
        ui.rerender(<WindowsLogsPanel resource={newer} contentAccess={access}/>); await advance(3000); expect(calls.filter(c => c.path.endsWith('/cancel'))).toHaveLength(0); expect(view.request!.description).toBe(original); expect(created()).toHaveLength(1); if (accepted) { expect(screen.getByLabelText('Search captured selection only')).toHaveValue('Invented'); expect(document.querySelector('.windows-event-message')).not.toBeNull(); } else expect(screen.getByText('Request status: Waiting for endpoint')).toBeVisible();
    });
    it('allows a fresh explicitly reviewed request after a prior capability lease expired', async () => {
        view.capability!.expiresAt = new Date(Date.parse(windowsNow) + 1000).toISOString(); view.capability!.reportedAt = new Date(Date.parse(windowsNow) - 299000).toISOString(); await setup(); select(); submit(); await flush(); await advance(1250); expect(document.querySelector('.windows-event-message')).toBeNull();
        const now = new Date(Date.now()).toISOString(); view = { ...view, capability: { ...view.capability!, reportedAt: now, expiresAt: new Date(Date.now() + 300000).toISOString() } }; fireEvent.click(screen.getByRole('button', { name: 'Check content status' })); await flush(); select(); submit(); await flush(); expect(created()).toHaveLength(2); expect(document.querySelector('.windows-event-message')).not.toBeNull();
    });
    it('honors an earlier server certificate cutoff without changing the request receipt expiry', async () => {
        transform = v => ({ ...v, expiresAt: new Date(Date.parse(windowsNow) + 1000).toISOString() }); await setup(); select(); submit(); await flush(); expect(document.querySelector('.windows-event-message')).not.toBeNull(); expect(view.request!.receipt!.expiresAt).toBe('2026-10-07T12:15:10.000Z'); await advance(1250); expect(document.querySelector('.windows-event-message')).toBeNull(); expect(screen.getByRole('alert')).toHaveTextContent('original content window expired');
    });
    it('accepts the actual escaped result body above 256 KiB while enforcing the 64 KiB text budget', async () => {
        transform = v => { for (const row of v.report.events) row.message = '<'.repeat(16384); return v; }; await setup(); screen.getAllByRole('checkbox').slice(0, 4).forEach(e => fireEvent.click(e)); submit(); await flush(); expect(document.querySelectorAll('.windows-event-message')).toHaveLength(4); expect([...document.querySelectorAll('.windows-event-message')].reduce((n, el) => n + el.textContent!.length, 0)).toBe(65536); expect(queried()).toHaveLength(1);
    });
    it('withholds content and clears review in the same terminal header-loss render', async () => {
        const ui = await setup(); select(); submit(); await flush(); ui.rerender(<WindowsLogsPanel resource={{ ...inventory(), events: null, status: 'revoked' }} contentAccess={access}/>); expect(document.querySelector('.windows-event-message')).toBeNull(); expect(screen.queryByLabelText('Search captured selection only')).toBeNull(); await flush(); expect(screen.getByText('0 of at most 16 headers selected')).toBeVisible(); ui.rerender(<WindowsLogsPanel resource={inventory()} contentAccess={access}/>); await flush(); expect(document.querySelector('.windows-event-message')).toBeNull(); expect(calls.filter(c => c.path.endsWith('/cancel'))).toHaveLength(1);
    });
    it('does not automatically reopen an earlier accepted result', async () => {
        view.request = eventContentAccepted(eventContentRecord(selection())); view.contentStatus = 'available'; view.expectedFloor = '1'; await setup(); expect(screen.getByText(/belongs to an earlier view/)).toBeVisible(); expect(created()).toHaveLength(0); expect(queried()).toHaveLength(0);
    });
});
