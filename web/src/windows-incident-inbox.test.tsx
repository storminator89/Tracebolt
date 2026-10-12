import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, AUTH_REQUIRED_EVENT, request } from './api';
import { LOGOUT_INTENT_KEY } from './auth';
import { setLocale } from './i18n';
import { WindowsIncidentInbox } from './windows-incident-inbox';
import { windowsIncidentItem, windowsIncidentView } from './windows-incident-inbox-fixture';
import { windowsCapacityDevice, windowsCapacitySession } from './windows-capacity-fixture';
import { windowsDeviceId, windowsNow } from './windows-inventory-fixture';
import type { WindowsIncidentAckFilter, WindowsIncidentItem, WindowsIncidentScope } from './windows-incident-inbox-types';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn() }));
const session = { mode: 'lan', transport: 'https', insecureTestMode: false, transportWarning: null, authenticationRequired: true, authenticated: true, csrfToken: 'fixture-csrf', serverNow: windowsNow, expiresAt: windowsCapacitySession, expiresInSeconds: 3590, loginMode: 'shared', actorId: null, capabilities: ['read'] };
let rows: WindowsIncidentItem[];
const posts = () => vi.mocked(request).mock.calls.filter(([, options]) => options?.method === 'POST');
const reads = () => vi.mocked(request).mock.calls.filter(([path]) => path.startsWith('/fleet/windows-incidents?'));
const flush = () => act(async () => {});
const advance = (ms: number) => act(async () => vi.advanceTimersByTimeAsync(ms));
function Harness({ admin = true, sessionKey = windowsCapacitySession }: { admin?: boolean; sessionKey?: string | null } = {}) {
    return <WindowsIncidentInbox devices={[{ ...windowsCapacityDevice(), name: 'Desk One' }]} admin={admin} sessionKey={sessionKey}/>;
}
async function open() { fireEvent.click(screen.getByRole('button', { name: 'Windows incidents' })); await flush(); }
function response(path: string) {
    const query = new URL(path, 'https://fixture.invalid').searchParams;
    return windowsIncidentView(rows, query.get('scope') as WindowsIncidentScope, query.get('ack') as WindowsIncidentAckFilter, Number(query.get('offset')), Number(query.get('limit')));
}
beforeEach(() => {
    abortProtectedRequests(); vi.useFakeTimers(); vi.setSystemTime(windowsNow); setLocale('en', false); vi.mocked(request).mockReset(); rows = [windowsIncidentItem()];
    vi.mocked(request).mockImplementation(async (path, options) => {
        if (path === '/auth/session') return structuredClone(session);
        if (options?.method === 'POST') {
            const { key } = JSON.parse(options.body as string); rows = rows.map(row => row.key === key ? { ...row, acknowledgedAt: windowsNow } : row);
            return { schemaVersion: 'tracebolt.windows-incident-ack.v1', serverNow: windowsNow, key, acknowledgedAt: windowsNow };
        }
        return response(path);
    });
});
afterEach(() => { cleanup(); abortProtectedRequests(); localStorage.removeItem(LOGOUT_INTENT_KEY); sessionStorage.removeItem(LOGOUT_INTENT_KEY); vi.useRealTimers(); vi.restoreAllMocks(); });

describe('compact Windows incident inbox', () => {
    it('starts collapsed without fetching and shows named Health links with separate original evidence times', async () => {
        render(<Harness/>); await flush(); expect(request).not.toHaveBeenCalled(); await open();
        expect(screen.getByRole('link', { name: 'Desk One · Health details' })).toHaveAttribute('href', `#/devices/${windowsDeviceId}/health`);
        expect(reads()[0][2]).toBe(256 * 1024);
        expect(screen.getByText('Historical source capture')).toBeInTheDocument(); expect(screen.getByText('Historical manager receipt')).toBeInTheDocument(); expect(screen.getByText('Source status evaluated')).toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', { name: /Windows incidents/ })); expect(screen.queryByRole('link', { name: /Desk One/ })).toBeNull();
    });
    it('gives named operators read-only access', async () => {
        render(<Harness admin={false}/>); await open(); expect(screen.getByText(/Your access is read-only/)).toBeVisible();
        expect(screen.queryByRole('button', { name: /^Mark seen:/ })).toBeNull(); expect(posts()).toHaveLength(0);
    });
    it('acknowledges the exact episode with CSRF, then refreshes without closing it', async () => {
        render(<Harness/>); await open(); fireEvent.click(screen.getByRole('button', { name: /^Mark seen:/ })); await flush();
        expect(posts()).toHaveLength(1); expect(posts()[0][0]).toBe('/fleet/windows-incidents/acknowledge'); expect(posts()[0][2]).toBe(1024);
        expect(JSON.parse(posts()[0][1]!.body as string)).toEqual({ key: rows[0].key }); expect(posts()[0][1]!.headers).toEqual({ 'Content-Type': 'application/json', 'X-CSRF-Token': 'fixture-csrf' });
        expect(rows[0].resolvedAt).toBeNull(); expect(screen.getByText(/Marked seen. The incident/)).toBeVisible(); expect(screen.queryByRole('button', { name: /^Mark seen:/ })).toBeNull(); expect(reads()).toHaveLength(2);
    });
    it('uses only GET after an uncertain write, including refresh and collapse/reopen', async () => {
        render(<Harness/>); await open(); const normal = vi.mocked(request).getMockImplementation()!;
        vi.mocked(request).mockImplementation(async (path, options, cap) => options?.method === 'POST' ? Promise.reject(new Error('lost response')) : normal(path, options, cap));
        fireEvent.click(screen.getByRole('button', { name: /^Mark seen:/ })); await flush(); expect(posts()).toHaveLength(1); expect(reads()).toHaveLength(2);
        expect(screen.getByText(/Acknowledgement could not be confirmed/)).toBeVisible(); expect(screen.getByRole('button', { name: /^Mark seen:/ })).toBeDisabled();
        fireEvent.click(screen.getByRole('button', { name: 'Refresh incidents' })); await flush(); fireEvent.click(screen.getByRole('button', { name: /Windows incidents/ })); await open(); expect(posts()).toHaveLength(1); expect(screen.getByRole('button', { name: /^Mark seen:/ })).toBeDisabled();
    });
    it('aborts obsolete scope/filter reads and ignores delayed responses', async () => {
        render(<Harness/>); await open(); let finish!: (value: unknown) => void; const original = response('/fleet/windows-incidents?scope=active&ack=all&offset=0&limit=25');
        vi.mocked(request).mockReturnValueOnce(new Promise(resolve => { finish = resolve; })); fireEvent.click(screen.getByRole('button', { name: 'Refresh incidents' }));
        const old = reads().at(-1)!; fireEvent.change(screen.getByRole('combobox', { name: 'Incident scope' }), { target: { value: 'resolved' } }); await flush(); expect(old[1]?.signal?.aborted).toBe(true);
        await act(async () => finish(original)); expect(screen.queryByRole('link', { name: /Desk One/ })).toBeNull(); expect(screen.getByText(/No retained incidents match/)).toBeVisible();
        fireEvent.change(screen.getByRole('combobox', { name: 'Acknowledgement' }), { target: { value: 'acknowledged' } }); await flush(); expect(reads().at(-1)![0]).toContain('scope=resolved&ack=acknowledged&offset=0');
    });
    it('pages bounded reads and resets page when filters change', async () => {
        rows = Array.from({ length: 26 }, (_, index) => windowsIncidentItem({ key: (index + 1).toString(16).padStart(64, '0') })); render(<Harness/>); await open();
        expect(screen.getAllByRole('link', { name: /Health details/ })).toHaveLength(25); fireEvent.click(screen.getByRole('button', { name: 'Next incidents' })); await flush(); expect(reads().at(-1)![0]).toContain('offset=25&limit=25'); expect(screen.getAllByRole('link', { name: /Health details/ })).toHaveLength(1);
        fireEvent.change(screen.getByRole('combobox', { name: 'Acknowledgement' }), { target: { value: 'unacknowledged' } }); await flush(); expect(reads().at(-1)![0]).toContain('ack=unacknowledged&offset=0');
    });
    it.each(['blur', 'hashchange', 'pagehide', AUTH_REQUIRED_EVENT])('clears private rows and aborts late reads on %s', async event => {
        render(<Harness/>); await open(); let finish!: (value: unknown) => void; vi.mocked(request).mockReturnValueOnce(new Promise(resolve => { finish = resolve; }));
        fireEvent.click(screen.getByRole('button', { name: 'Refresh incidents' })); const old = reads().at(-1)!; act(() => window.dispatchEvent(new Event(event))); expect(old[1]?.signal?.aborted).toBe(true);
        await act(async () => finish(windowsIncidentView())); expect(screen.queryByRole('link', { name: /Desk One/ })).toBeNull();
    });
    it('clears private rows when hidden and reads again on visibility restoration', async () => {
        render(<Harness/>); await open(); const visibility = vi.spyOn(document, 'visibilityState', 'get'); visibility.mockReturnValue('hidden'); act(() => document.dispatchEvent(new Event('visibilitychange'))); expect(screen.queryByRole('link', { name: /Desk One/ })).toBeNull();
        visibility.mockReturnValue('visible'); act(() => document.dispatchEvent(new Event('visibilitychange'))); await flush(); expect(screen.getByRole('link', { name: /Desk One/ })).toBeVisible(); expect(posts()).toHaveLength(0);
    });
    it('does not replay a POST interrupted by blur; focus performs only a current GET', async () => {
        render(<Harness/>); await open(); const normal = vi.mocked(request).getMockImplementation()!; let finish!: (value: unknown) => void;
        vi.mocked(request).mockImplementation(async (path, options, cap) => options?.method === 'POST' ? new Promise(resolve => { finish = resolve; }) : normal(path, options, cap));
        fireEvent.click(screen.getByRole('button', { name: /^Mark seen:/ })); await flush(); expect(posts()).toHaveLength(1);
        act(() => window.dispatchEvent(new Event('blur'))); expect(posts()[0][1]?.signal?.aborted).toBe(true); expect(screen.queryByRole('link', { name: /Desk One/ })).toBeNull();
        act(() => window.dispatchEvent(new Event('focus'))); await flush(); expect(screen.getByRole('button', { name: /^Mark seen:/ })).toBeDisabled();
        await act(async () => finish({ schemaVersion: 'tracebolt.windows-incident-ack.v1', serverNow: windowsNow, key: rows[0].key, acknowledgedAt: windowsNow })); expect(posts()).toHaveLength(1); expect(screen.getByText(/Acknowledgement could not be confirmed/)).toBeVisible();
    });
    it.each(['epoch', 'logout'])('clears on %s without accepting a late protected response', async reason => {
        render(<Harness/>); await open(); let finish!: (value: unknown) => void; vi.mocked(request).mockReturnValueOnce(new Promise(resolve => { finish = resolve; })); fireEvent.click(screen.getByRole('button', { name: 'Refresh incidents' }));
        act(() => { if (reason === 'epoch') abortProtectedRequests(); else localStorage.setItem(LOGOUT_INTENT_KEY, '1'); }); await advance(250);
        await act(async () => finish(windowsIncidentView())); expect(screen.queryByRole('link', { name: /Desk One/ })).toBeNull(); expect(posts()).toHaveLength(0);
    });
    it('does not renew an expired inbox lease with a frozen manager clock', async () => {
        render(<Harness/>); await open(); await advance(120000); expect(screen.queryByRole('link', { name: /Desk One/ })).toBeNull();
        fireEvent.click(screen.getByRole('button', { name: 'Refresh incidents' })); await flush(); expect(screen.queryByRole('link', { name: /Desk One/ })).toBeNull(); expect(screen.getByText(/unavailable or expired/)).toBeVisible();
    });
    it('withholds confidence at current-source expiry without using old incident capture as current evidence', async () => {
        rows = [windowsIncidentItem({ statusValidUntil: new Date(Date.parse(windowsNow) + 1000).toISOString() })]; render(<Harness/>); await open(); expect(screen.getByText('Source status: Above threshold')).toBeVisible();
        await advance(1000); expect(screen.getByText('Source status: Unknown')).toBeVisible(); expect(screen.getByRole('link', { name: /Desk One/ })).toBeVisible(); expect(reads()).toHaveLength(1);
    });
    it('clears at the authority expiry', async () => {
        const normal = vi.mocked(request).getMockImplementation()!; vi.mocked(request).mockImplementation(async (path, options, cap) => { const value = await normal(path, options, cap) as ReturnType<typeof windowsIncidentView>; return { ...value, authorityExpiresAt: new Date(Date.parse(windowsNow) + 1000).toISOString(), items: value.items.map(row => ({ ...row, statusValidUntil: new Date(Date.parse(windowsNow) + 1000).toISOString() })) }; });
        render(<Harness/>); await open(); expect(screen.getByRole('link', { name: /Desk One/ })).toBeVisible(); await advance(1000); expect(screen.queryByRole('link', { name: /Desk One/ })).toBeNull(); expect(screen.getByText(/unavailable or expired/)).toBeVisible();
    });
    it('clears at session expiry before a longer authority lease', async () => {
        render(<Harness sessionKey={new Date(Date.parse(windowsNow) + 1000).toISOString()}/>); await open(); expect(screen.getByRole('link', { name: /Desk One/ })).toBeVisible(); await advance(1000); expect(screen.queryByRole('link', { name: /Desk One/ })).toBeNull();
    });
    it('rechecks the shared administrator session before POST and stops if role changed', async () => {
        render(<Harness/>); await open(); vi.mocked(request).mockResolvedValueOnce({ ...session, loginMode: 'named', actorId: 'operator_fixture' }); fireEvent.click(screen.getByRole('button', { name: /^Mark seen:/ })); await flush(); expect(posts()).toHaveLength(0);
    });
    it('has German labels and distinguishes policy closure from recovery', async () => {
        setLocale('de', false); rows = [windowsIncidentItem({ resolvedAt: '2026-10-07T11:58:00Z', closedReason: 'policy-changed' })]; render(<Harness/>); fireEvent.click(screen.getByRole('button', { name: 'Windows-Vorfälle' })); await flush();
        fireEvent.change(screen.getByRole('combobox', { name: 'Vorfallszeitraum' }), { target: { value: 'resolved' } }); await flush(); expect(screen.getByText('Geschlossen: Richtlinie geändert; keine Erholung belegt')).toBeVisible(); expect(screen.getByText(/Sie schließt keinen Vorfall/)).toBeVisible();
    });
});
