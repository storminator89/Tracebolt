import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, AUTH_REQUIRED_EVENT, request } from './api';
import { LOGOUT_INTENT_KEY } from './auth';
import { setLocale } from './i18n';
import { WindowsIncidentInbox } from './windows-incident-inbox';
import legacyWire from '../../tests/fixtures/windows-incident-inbox-view.json';
import { validWindowsCompleteIncidentInboxView } from './windows-complete-incident-inbox-types';
import { completeIncidentFixture } from './windows-complete-incident-inbox-fixture';
import { windowsCapacityDevice } from './windows-capacity-fixture';
import type { WindowsCompleteIncidentInboxView } from './windows-complete-incident-inbox-types';
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn() }));
const now = '2026-10-13T12:00:00.000Z', expires = '2026-10-13T13:00:00.000Z';
const session = { mode: 'lan', transport: 'https', insecureTestMode: false, transportWarning: null, authenticationRequired: true, authenticated: true, csrfToken: 'synthetic-csrf', serverNow: now, expiresAt: expires, expiresInSeconds: 3600, loginMode: 'shared', actorId: null, capabilities: ['read'] };
let view: WindowsCompleteIncidentInboxView;
const posts = () => vi.mocked(request).mock.calls.filter(([, options]) => options?.method === 'POST');
const reads = () => vi.mocked(request).mock.calls.filter(([path]) => path.startsWith('/fleet/windows-incidents/complete?'));
const flush = () => act(async () => {}), advance = (ms: number) => act(async () => vi.advanceTimersByTimeAsync(ms));
function Harness({ admin = true, sessionKey = expires }: { admin?: boolean; sessionKey?: string } = {}) { return <WindowsIncidentInbox complete devices={[{ ...windowsCapacityDevice(), id: view.items[0].deviceId, name: 'Complete device' }]} sessionKey={sessionKey} admin={admin}/>; }
async function open(de = false) { fireEvent.click(screen.getByRole('button', { name: de ? 'Windows-Vorfälle' : 'Windows incidents' })); await flush(); }
function filtered(path: string) {
    const q = new URL(path, 'https://fixture.invalid').searchParams, scope = q.get('scope'), ack = q.get('ack'), offset = Number(q.get('offset'));
    const rows = view.items.filter(row => (scope !== 'resolved' || row.resolvedAt !== null) && (ack === 'all' || (ack === 'acknowledged') === (row.acknowledgedAt !== null)));
    return { ...structuredClone(view), scope, ack, offset, total: rows.length, items: rows.slice(offset, offset + 25), nextOffset: offset + 25 < rows.length ? offset + 25 : null };
}
beforeEach(() => {
    abortProtectedRequests(); vi.useFakeTimers(); vi.setSystemTime(now); setLocale('en', false); vi.mocked(request).mockReset(); view = completeIncidentFixture('active', now);
    vi.mocked(request).mockImplementation(async (path, options) => {
        if (path === '/auth/session') return structuredClone(session);
        if (options?.method === 'POST') {
            expect(path).toBe('/fleet/windows-incidents/complete/acknowledge'); const { key } = JSON.parse(options.body as string); expect(key).toBe(view.items[0].key);
            view = completeIncidentFixture('acknowledged', now); return { schemaVersion: 'tracebolt.windows-incident-ack.v2', serverNow: now, key, acknowledgedAt: now };
        }
        expect(path).toMatch(/^\/fleet\/windows-incidents\/complete\?/); return filtered(path);
    });
});
afterEach(() => { cleanup(); abortProtectedRequests(); localStorage.removeItem(LOGOUT_INTENT_KEY); sessionStorage.removeItem(LOGOUT_INTENT_KEY); vi.useRealTimers(); vi.restoreAllMocks(); });
describe('complete service incident inbox adapter', () => {
    it.each(['en', 'de'] as const)('keeps the resized refresh control read-only with the same label in %s', async locale => {
        const de = locale === 'de'; setLocale(locale, false); render(<Harness/>); await open(de);
        const refresh = screen.getByRole('button', { name: de ? 'Vorfälle aktualisieren' : 'Refresh incidents' });
        expect(refresh.closest('.windows-incident-toolbar')).not.toBeNull();expect(refresh).toHaveClass('text-button');expect(refresh).toBeEnabled();
        fireEvent.click(refresh);await flush();expect(reads()).toHaveLength(2);expect(posts()).toHaveLength(0);
    });
    it.each(['en', 'de'] as const)('renders compact source and expandable native provenance in %s with deliberate review', async locale => {
        const de = locale === 'de'; setLocale(locale, false); render(<Harness/>); expect(request).not.toHaveBeenCalled(); await open(de);
        expect(reads()).toHaveLength(1); expect(reads()[0][2]).toBe(256 * 1024); expect(screen.getByText(view.items[0].serviceName)).toBeVisible();
        expect(screen.getByText(de ? 'Quelle: Vollständiges Dienstinventar' : 'Source: Complete service inventory')).toBeVisible(); expect(screen.getByRole('button', { name: /Review service|Dienst prüfen/ })).toBeEnabled();
        const evidence = document.querySelector('.windows-incident-meta > details')!; expect(evidence).not.toHaveAttribute('open'); fireEvent.click(evidence.querySelector('summary')!);
        const opening = within(evidence as HTMLElement).getByText(de ? 'Quelle bei Eröffnung' : 'Opening source'); fireEvent.click(opening);
        expect(within(opening.parentElement!).getByText(view.items[0].openingSource!.generationId)).toBeVisible(); expect(within(opening.parentElement!).getByText('2051')).toBeVisible();
        expect(screen.getByRole('link', { name: de ? 'Complete device · Health-Details' : 'Complete device · Health details' })).toHaveAttribute('href', `#/devices/${view.items[0].deviceId}/health`);
    });
    it('offers separate review links for tagged v1 and complete rows in the combined inbox', async () => {
        const legacy = legacyWire.active.items.map(item => ({ ...item, status: 'unknown', statusValidUntil: null, sourceKind: 'assessment_v1', openingSource: null, lastBadSource: null, recoverySource: null, currentSource: null }));
        const combined = { ...view, items: [...view.items, ...legacy], total: view.total + legacy.length, counts: { active: view.counts.active + legacyWire.active.counts.active, resolved: 0, acknowledged: legacyWire.active.counts.acknowledged, unacknowledged: view.counts.unacknowledged + legacyWire.active.counts.unacknowledged, total: view.counts.total + legacy.length } };
        if (!validWindowsCompleteIncidentInboxView(combined, 'active', 'all', 0)) throw new Error('Invalid combined Go fixture'); view = combined;
        render(<Harness/>); await open(); expect(screen.getAllByRole('button', { name: /^Review service:/ })).toHaveLength(2);
        const fullRow = screen.getByText(completeIncidentFixture('active', now).items[0].serviceName).closest('li')!; expect(within(fullRow).getByRole('button', { name: /^Review service:/ })).toBeEnabled(); expect(document.querySelectorAll('.windows-incident-row')).toHaveLength(6);
    });
    it('writes exact v2 key with CSRF once and reconciles by GET without closing the episode', async () => {
        render(<Harness/>); await open(); fireEvent.click(screen.getByRole('button', { name: /^Mark seen:/ })); await flush();
        expect(posts()).toHaveLength(1); expect(posts()[0][2]).toBe(1024); expect(JSON.parse(posts()[0][1]!.body as string)).toEqual({ key: view.items[0].key }); expect(posts()[0][1]!.headers).toEqual({ 'Content-Type': 'application/json', 'X-CSRF-Token': session.csrfToken });
        expect(reads()).toHaveLength(2); expect(view.items[0].resolvedAt).toBeNull(); expect(screen.getByText('Marked seen. Incident status unchanged.')).toBeVisible(); expect(document.querySelector('.windows-incident-badges .is-active')).toHaveTextContent('Active'); expect(screen.queryByRole('button', { name: /^Mark seen:/ })).toBeNull();
    });
    it('allows acknowledgement of retained unknown history when current source is absent', async () => {
        view = completeIncidentFixture('unknown', now); view.items[0].acknowledgedAt = null; view.counts.acknowledged = 0; view.counts.unacknowledged = 1;
        render(<Harness/>); await open(); expect(screen.getByText('Source status: Unknown')).toBeVisible(); const details = document.querySelector('.windows-incident-meta > details')!; fireEvent.click(details.querySelector('summary')!); expect(screen.getByText(/No qualified current source/)).toBeVisible();
        expect(screen.getByRole('button', { name: /^Mark seen:/ })).toBeEnabled(); fireEvent.click(screen.getByRole('button', { name: /^Mark seen:/ })); await flush(); expect(posts()).toHaveLength(1);
    });
    it('keeps named access read-only and rechecks shared role before POST', async () => {
        const mounted = render(<Harness admin={false}/>); await open(); expect(screen.queryByRole('button', { name: /^Mark seen:/ })).toBeNull(); mounted.unmount(); render(<Harness/>); await open();
        vi.mocked(request).mockResolvedValueOnce({ ...session, loginMode: 'named', actorId: 'operator_fixture' }); fireEvent.click(screen.getByRole('button', { name: /^Mark seen:/ })); await flush(); expect(posts()).toHaveLength(0);
    });
    it('locks uncertain writes across refresh and reopening with GET-only reconciliation', async () => {
        render(<Harness/>); await open(); const normal = vi.mocked(request).getMockImplementation()!; vi.mocked(request).mockImplementation((path, options, cap) => options?.method === 'POST' ? Promise.reject(new Error('lost response')) : normal(path, options, cap));
        fireEvent.click(screen.getByRole('button', { name: /^Mark seen:/ })); await flush(); expect(posts()).toHaveLength(1); expect(reads()).toHaveLength(2); fireEvent.click(screen.getByRole('button', { name: 'Refresh incidents' })); await flush(); fireEvent.click(screen.getByRole('button', { name: /Windows incidents/ })); await open();
        expect(screen.getByRole('button', { name: /^Mark seen:/ })).toBeDisabled(); expect(posts()).toHaveLength(1); expect(screen.getByText(/Acknowledgement could not be confirmed/)).toBeVisible();
    });
    it('aborts interrupted POST and never replays on focus', async () => {
        render(<Harness/>); await open(); const normal = vi.mocked(request).getMockImplementation()!; let finish!: (value: unknown) => void;
        vi.mocked(request).mockImplementation((path, options, cap) => options?.method === 'POST' ? new Promise(resolve => { finish = resolve; }) : normal(path, options, cap)); fireEvent.click(screen.getByRole('button', { name: /^Mark seen:/ })); await flush();
        act(() => window.dispatchEvent(new Event('blur'))); expect(posts()[0][1]?.signal?.aborted).toBe(true); act(() => window.dispatchEvent(new Event('focus'))); await flush(); await act(async () => finish({ schemaVersion: 'tracebolt.windows-incident-ack.v2', serverNow: now, key: view.items[0].key, acknowledgedAt: now }));
        expect(posts()).toHaveLength(1); expect(screen.getByRole('button', { name: /^Mark seen:/ })).toBeDisabled();
    });
    it.each(['blur', 'hashchange', 'popstate', 'pagehide', AUTH_REQUIRED_EVENT])('rejects late private responses after %s', async event => {
        render(<Harness/>); await open(); let finish!: (value: unknown) => void; vi.mocked(request).mockReturnValueOnce(new Promise(resolve => { finish = resolve; })); fireEvent.click(screen.getByRole('button', { name: 'Refresh incidents' })); const old = reads().at(-1)!;
        act(() => window.dispatchEvent(new Event(event))); expect(old[1]?.signal?.aborted).toBe(true); await act(async () => finish(view)); expect(screen.queryByText(view.items[0].serviceName)).toBeNull();
    });
    it('aborts obsolete filter reads and keeps bounded page selection', async () => {
        render(<Harness/>); await open(); let finish!: (value: unknown) => void; vi.mocked(request).mockReturnValueOnce(new Promise(resolve => { finish = resolve; })); fireEvent.click(screen.getByRole('button', { name: 'Refresh incidents' })); const old = reads().at(-1)!;
        fireEvent.change(screen.getByRole('combobox', { name: 'Status' }), { target: { value: 'resolved' } }); await flush(); expect(old[1]?.signal?.aborted).toBe(true); await act(async () => finish(view)); expect(screen.queryByText(view.items[0].serviceName)).toBeNull(); expect(reads().at(-1)![0]).toContain('scope=resolved&ack=all&offset=0&limit=25');
    });
    it('ages current confidence to unknown without refreshing historical source', async () => {
        view.items[0].statusValidUntil = '2026-10-13T12:00:01.000Z'; render(<Harness/>); await open(); expect(screen.getByText('Source status: Needs attention')).toBeVisible(); await advance(1000);
        expect(screen.getByText('Source status: Unknown')).toBeVisible(); expect(screen.getByRole('button', { name: /^Mark seen:/ })).toBeEnabled(); expect(reads()).toHaveLength(1);
    });
    it.each(['authority', 'session', 'clock', 'epoch', 'logout'])('expires private rows on %s', async kind => {
        if (kind === 'authority') { view.authorityExpiresAt = '2026-10-13T12:00:01.000Z'; view.items[0].statusValidUntil = view.authorityExpiresAt; }
        render(<Harness sessionKey={kind === 'session' ? '2026-10-13T12:00:01.000Z' : expires}/>); await open(); if (kind === 'epoch') abortProtectedRequests(); if (kind === 'logout') localStorage.setItem(LOGOUT_INTENT_KEY, '1');
        await advance(kind === 'clock' ? 120000 : 1000); expect(screen.queryByText(view.items[0].serviceName)).toBeNull(); expect(posts()).toHaveLength(0);
    });
});
