import userEvent from '@testing-library/user-event';
import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, APIError, AUTH_REQUIRED_EVENT, mutate, request } from './api';
import { useOperator } from './auth';
import { DeviceDetail } from './details';
import { setLocale } from './i18n';
import { windowsCapacityView } from './windows-capacity-fixture';
import { windowsResourceView } from './windows-resource-fixture';
import { WindowsContactPanel } from './windows-contact';
import { windowsContactDevice, windowsContactIncident, windowsContactSession, windowsContactView } from './windows-contact-fixture';
import { useWindowsContact } from './windows-contact-resource';
import { validWindowsContactView, windowsContactDeviceEligible } from './windows-contact-types';
import type { WindowsContactView } from './windows-contact-types';
import { windowsDeviceId, windowsNow, windowsView } from './windows-inventory-fixture';
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutate: vi.fn() }));
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
const operator = { mode: 'lan' as const, authenticated: true, expiresAt: windowsContactSession, insecureTestMode: false, logout: vi.fn(), theme: 'light' as const, setTheme: vi.fn() };
function Harness({ device = windowsContactDevice(), session = windowsContactSession, metadataReady = true, enabled = true }: { device?: ReturnType<typeof windowsContactDevice>; session?: string | null; metadataReady?: boolean; enabled?: boolean }) {
    const resource = useWindowsContact(device.id, enabled && metadataReady && windowsContactDeviceEligible(device, device.id), session);
    return <WindowsContactPanel device={device} resource={resource} sessionKey={session} metadataReady={metadataReady}/>;
}
const flush = () => act(async () => {});
const advance = (time: number) => act(async () => vi.advanceTimersByTimeAsync(time));
const history = () => screen.queryByText('wcontact_0000000000000001');
beforeEach(() => { abortProtectedRequests(); vi.useFakeTimers(); vi.setSystemTime(windowsNow); setLocale('en', false); vi.mocked(request).mockReset().mockResolvedValue(windowsContactView()); vi.mocked(mutate).mockReset(); vi.mocked(useOperator).mockReturnValue(operator); });
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.restoreAllMocks(); });
describe('invented Windows contact panel lifecycle', () => {
    it.each(['en', 'de'] as const)('filters retained incidents locally without changing current assessment (%s)', async locale => {
        const value = windowsContactView('overdue'); value.incidents[0] = { ...value.incidents[0], id: 'wcontact_0000000000000002', openedAt: '2026-10-07T11:59:01Z' }; value.incidents.push(windowsContactIncident(true));
        expect(validWindowsContactView(value, windowsDeviceId)).toBe(true); const original = JSON.stringify(value);
        vi.mocked(request).mockResolvedValue(value); setLocale(locale, false); render(<Harness/>); await flush();
        const group = screen.getByRole('group', { name: locale === 'en' ? 'Filter saved contact incidents' : 'Gespeicherte Kontaktvorfälle filtern' });
        const buttons = within(group).getAllByRole('button'); expect(buttons.map(b => b.textContent)).toEqual(locale === 'en' ? ['All (2)', 'Open (1)', 'Recovered (1)'] : ['Alle (2)', 'Offen (1)', 'Erholt (1)']);
        expect(buttons[0]).toHaveAttribute('aria-pressed', 'true'); const calls = vi.mocked(request).mock.calls.length;
        fireEvent.click(buttons[1]); expect(history()).toBeNull(); expect(screen.getByText('wcontact_0000000000000002')).toBeVisible();
        expect(document.getElementById(buttons[1].getAttribute('aria-controls')!)).toBeVisible();
        fireEvent.click(buttons[2]); expect(history()).toBeVisible(); expect(screen.queryByText('wcontact_0000000000000002')).toBeNull();
        expect(screen.getByText(locale === 'en' ? 'Report overdue · incident open' : 'Meldung überfällig · Vorfall offen')).toBeVisible();
        fireEvent.click(buttons[0]); expect(screen.getAllByRole('listitem')).toHaveLength(2); expect(screen.getByRole('list')).toHaveAttribute('role', 'list');
        expect(JSON.stringify(value)).toBe(original); expect(request).toHaveBeenCalledTimes(calls); expect(mutate).not.toHaveBeenCalled();
    });
    it('distinguishes an empty filter and hides all controls while authority is missing', async () => {
        const mounted = render(<Harness/>); await flush(); fireEvent.click(screen.getByRole('button', { name: 'Open (0)' }));
        expect(screen.getByText('No saved incidents match this filter.')).toBeVisible(); expect(screen.queryByText('No retained contact incidents.')).toBeNull();
        mounted.rerender(<Harness metadataReady={false}/>); expect(screen.queryByRole('group', { name: 'Filter saved contact incidents' })).toBeNull(); expect(history()).toBeNull();
        mounted.rerender(<Harness/>); await flush(); expect(screen.getByRole('button', { name: 'Open (0)' })).toHaveAttribute('aria-pressed', 'true'); expect(history()).toBeNull();
        fireEvent.click(screen.getByRole('button', { name: 'All (1)' })); expect(history()).toBeVisible();
    });
    it('preserves a filter across background refresh and resets it for a different session', async () => {
        const mounted = render(<Harness/>); await flush(); fireEvent.click(screen.getByRole('button', { name: 'Open (0)' }));
        const next = windowsContactView(); next.serverNow = '2026-10-07T12:00:25Z'; next.evaluatedAt = next.serverNow;
        vi.mocked(request).mockResolvedValue(next); await advance(15000);
        expect(screen.getByRole('button', { name: 'Open (0)' })).toHaveAttribute('aria-pressed', 'true');
        mounted.rerender(<Harness session="2026-10-07T14:00:00Z"/>); await flush();
        expect(screen.getByRole('button', { name: 'All (1)' })).toHaveAttribute('aria-pressed', 'true'); expect(history()).toBeVisible();
    });
    it('restores filter focus only after the same successful background read', async () => {
        render(<Harness/>); await flush(); const old = screen.getByRole('button', { name: 'Open (0)' }); old.focus();
        let finish!: (value: WindowsContactView) => void;
        vi.mocked(request).mockReturnValueOnce(new Promise(resolve => { finish = resolve; })); await advance(15000);
        expect(screen.queryByRole('group', { name: 'Filter saved contact incidents' })).toBeNull(); expect(document.activeElement).toBe(document.body);
        const next = windowsContactView(); next.serverNow = '2026-10-07T12:00:25Z'; next.evaluatedAt = next.serverNow;
        await act(async () => finish(next)); expect(screen.getByRole('button', { name: 'Open (0)' })).toHaveFocus(); expect(request).toHaveBeenCalledTimes(2);
    });
    it.each(['blur', 'scope', 'certificate', 'outside-focus', 'metadata', 'keyboard'] as const)('does not steal focus after refresh is interrupted by %s', async interrupt => {
        const mounted = render(<><button>Other control</button><Harness/></>); await flush(); screen.getByRole('button', { name: 'Open (0)' }).focus();
        let finish!: (value: WindowsContactView) => void; vi.mocked(request).mockReturnValueOnce(new Promise(resolve => { finish = resolve; })); await advance(15000);
        const next = windowsContactView(); next.serverNow = '2026-10-07T12:00:25Z'; next.evaluatedAt = next.serverNow; vi.mocked(request).mockResolvedValue(next);
        if (interrupt === 'blur') { act(() => window.dispatchEvent(new Event('blur'))); act(() => window.dispatchEvent(new Event('focus'))); }
        if (interrupt === 'scope') mounted.rerender(<><button>Other control</button><Harness session="2026-10-07T14:00:00Z"/></>);
        if (interrupt === 'certificate') { const device = windowsContactDevice(); device.agentCertificate = { ...device.agentCertificate!, expiresAt: '2026-12-07T12:00:00Z' }; mounted.rerender(<><button>Other control</button><Harness device={device}/></>); }
        if (interrupt === 'outside-focus') screen.getByRole('button', { name: 'Other control' }).focus();
        if (interrupt === 'metadata') { mounted.rerender(<><button>Other control</button><Harness metadataReady={false}/></>); mounted.rerender(<><button>Other control</button><Harness/></>); }
        if (interrupt === 'keyboard') fireEvent.keyDown(document.body, { key: 'Tab' });
        await act(async () => finish(next)); await flush();
        expect(screen.getByRole('button', { name: 'Open (0)' })).not.toHaveFocus();
        expect(document.activeElement).toBe(interrupt === 'outside-focus' ? screen.getByRole('button', { name: 'Other control' }) : document.body);
        expect(mutate).not.toHaveBeenCalled();
    });
    it('supports keyboard filter activation without moving focus or fetching again', async () => {
        render(<Harness/>); await flush(); vi.useRealTimers(); const user = userEvent.setup();
        const openFilter = screen.getByRole('button', { name: 'Open (0)' }); openFilter.focus(); await user.keyboard('{Enter}');
        expect(openFilter).toHaveFocus(); expect(openFilter).toHaveAttribute('aria-pressed', 'true');
        await user.tab(); const recovered = screen.getByRole('button', { name: 'Recovered (1)' }); expect(recovered).toHaveFocus(); await user.keyboard(' ');
        expect(recovered).toHaveAttribute('aria-pressed', 'true'); expect(history()).toBeVisible(); expect(request).toHaveBeenCalledTimes(1); expect(mutate).not.toHaveBeenCalled();
    });
    it.each(['en', 'de'] as const)('shows distinct original acceptance/evaluation/history and scoped limits in %s', async locale => { setLocale(locale, false); render(<Harness/>); await flush(); expect(screen.getByText(locale === 'en' ? 'Recent report' : 'Aktuelle Meldung')).toBeVisible(); expect(screen.getByText(locale === 'en' ? 'Recovered' : 'Erholt')).toBeVisible(); expect(document.querySelector('time[datetime="2026-10-07T12:00:01Z"]')).not.toBeNull(); expect(document.querySelector(`time[datetime="${windowsNow}"]`)).not.toBeNull(); fireEvent.click(screen.getByText(locale === 'en' ? 'Contact rules & limits' : 'Kontaktregeln & Grenzen')); expect(screen.getByText(/120 Sekunden|120 seconds/)).toBeVisible(); expect(screen.getByText(/100 Vorfälle|100 incidents/)).toBeVisible(); expect(screen.queryByRole('button', { name: /acknowledge|bestätigen|maintenance|wartung|analyze|analysieren/i })).toBeNull(); expect(mutate).not.toHaveBeenCalled(); });
    it.each(['pending', 'overdue'] as const)('presents manager %s state without invoking action or investigation sources', async status => { vi.mocked(request).mockResolvedValue(windowsContactView(status)); render(<Harness/>); await flush(); expect(screen.getByText(status === 'pending' ? 'Report overdue · confirmation pending' : 'Report overdue · incident open')).toBeVisible(); expect(vi.mocked(request).mock.calls.map(([path]) => path)).toEqual([`/devices/${windowsDeviceId}/windows-contact`]); expect(mutate).not.toHaveBeenCalled(); });
    it('shows unknown when no accepted report exists', async () => { const view = windowsContactView('unknown'); Object.assign(view, { sequence: 0, lastAcceptedAt: null, evaluatedAt: null, incidents: [] }); vi.mocked(request).mockResolvedValue(view); render(<Harness/>); await flush(); expect(screen.getByText('Unknown')).toBeVisible(); expect(screen.getByText('No accepted report recorded.')).toBeVisible(); });
    it('keeps open historical incident when evaluator age expires without claiming recovery', async () => { const view = windowsContactView('overdue'); view.evaluatedAt = '2026-10-07T11:58:11Z'; view.incidents[0].lastConfirmedAt = view.evaluatedAt; vi.mocked(request).mockResolvedValue(view); render(<Harness/>); await flush(); expect(screen.getByText('Report overdue · incident open')).toBeVisible(); await advance(2000); expect(screen.getByText('Unknown')).toBeVisible(); expect(screen.getByText('Open')).toBeVisible(); expect(history()).toBeVisible(); expect(screen.queryByText('Recovered')).toBeNull(); });
    it('includes response delay without refreshing original receipt', async () => { const value = windowsContactView(); value.lastAcceptedAt = '2026-10-07T11:58:11Z'; let finish!: (value: WindowsContactView) => void; vi.mocked(request).mockReturnValueOnce(new Promise(resolve => { finish = resolve; })); render(<Harness/>); await flush(); await advance(2000); await act(async () => finish(value)); expect(screen.getByText('Unknown')).toBeVisible(); expect(history()).toBeVisible(); expect(document.querySelector('time[datetime="2026-10-07T11:58:11Z"]')).not.toBeNull(); });
    it.each([0, 1])('does not renew original receipt after repeated GET/remount with %i ms server progress', async delta => { const value = windowsContactView(); value.lastAcceptedAt = '2026-10-07T11:58:11Z'; vi.mocked(request).mockResolvedValue(value); const first = render(<Harness/>); await flush(); expect(screen.getByText('Recent report')).toBeVisible(); first.unmount(); await advance(2000); vi.mocked(request).mockResolvedValue({ ...value, serverNow: new Date(Date.parse(windowsNow) + delta).toISOString() }); render(<Harness/>); await flush(); expect(screen.getByText('Unknown')).toBeVisible(); expect(history()).toBeVisible(); });
    it('rejects manager rollback across refresh failure and remount', async () => { const first = render(<Harness/>); await flush(); vi.mocked(request).mockRejectedValueOnce(new Error('private-fixture-error')); fireEvent.click(screen.getByRole('button', { name: 'Refresh contact history' })); await flush(); expect(history()).toBeNull(); first.unmount(); const older = windowsContactView(); older.serverNow = '2026-10-07T12:00:09Z'; older.evaluatedAt = older.serverNow; vi.mocked(request).mockResolvedValue(older); render(<Harness/>); await flush(); expect(history()).toBeNull(); expect(screen.getByText('Unknown')).toBeVisible(); expect(document.body).not.toHaveTextContent('private-fixture-error'); });
    it('rejects local rollback while mounted and across remount', async () => { const first = render(<Harness/>); await flush(); first.unmount(); vi.setSystemTime('2026-10-07T11:00:00Z'); render(<Harness/>); await flush(); expect(history()).toBeNull(); expect(screen.getByText('Unknown')).toBeVisible(); });
    it('clears on refresh, abort/blur and session loss, rejecting late replies', async () => { render(<Harness/>); await flush(); let finish!: (value: WindowsContactView) => void; vi.mocked(request).mockReturnValueOnce(new Promise(resolve => { finish = resolve; })); fireEvent.click(screen.getByRole('button', { name: 'Refresh contact history' })); expect(history()).toBeNull(); act(() => window.dispatchEvent(new Event('blur'))); await act(async () => finish(windowsContactView())); expect(history()).toBeNull(); act(() => window.dispatchEvent(new Event('focus'))); await flush(); expect(history()).toBeVisible(); act(() => window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT))); expect(history()).toBeNull(); const count = vi.mocked(request).mock.calls.length; await advance(15000); expect(request).toHaveBeenCalledTimes(count); });
    it.each(['session', 'certificate'] as const)('hides all history at original %s expiry even after remount', async kind => { const value = windowsContactView(); const at = '2026-10-07T12:00:11Z'; if (kind === 'certificate') value.certificateExpiresAt = at; vi.mocked(request).mockResolvedValue(value); const first = render(<Harness session={kind === 'session' ? at : windowsContactSession}/>); await flush(); expect(history()).toBeVisible(); await advance(1000); expect(history()).toBeNull(); first.unmount(); render(<Harness session={kind === 'session' ? at : windowsContactSession}/>); await flush(); expect(history()).toBeNull(); });
    it('hides all history when device metadata is uncertain or identity is revoked', async () => { const view = render(<Harness/>); await flush(); expect(history()).toBeVisible(); view.rerender(<Harness metadataReady={false}/>); expect(history()).toBeNull(); const device = windowsContactDevice(); device.capabilities = []; view.rerender(<Harness device={device}/>); await flush(); expect(history()).toBeNull(); });
    it('hides all history on timeout, rejects its late response and does not expose errors', async () => { let finish!: (value: WindowsContactView) => void; vi.mocked(request).mockReturnValueOnce(new Promise(resolve => { finish = resolve; })); render(<Harness/>); await flush(); await advance(10000); await act(async () => finish(windowsContactView())); expect(history()).toBeNull(); expect(screen.getByText('Contact history unavailable. Current state is unknown.')).toBeVisible(); });
    it('locks after unauthorized read', async () => { vi.mocked(request).mockRejectedValue(new APIError('private-session-error', 401)); render(<Harness/>); await flush(); expect(history()).toBeNull(); expect(screen.getByRole('button', { name: 'Refresh contact history' })).toBeDisabled(); await advance(30000); expect(request).toHaveBeenCalledOnce(); });
    it.each(['deviceId', 'extra'] as const)('rejects malformed response field %s without leaking content', async field => { vi.mocked(request).mockResolvedValue({ ...windowsContactView(), [field]: 'private-fixture-do-not-display' }); render(<Harness/>); await flush(); expect(history()).toBeNull(); expect(document.body).not.toHaveTextContent('private-fixture-do-not-display'); });
    it.each(['disabled', 'no-session', 'synthetic', 'linux', 'manual', 'missing-identity'] as const)('makes no contact read when %s', async reason => { const device = windowsContactDevice(); if (reason === 'synthetic') device.synthetic = true; if (reason === 'linux') device.platform = 'linux'; if (reason === 'manual') delete device.agentCertificate; if (reason === 'missing-identity') device.capabilities = []; render(<Harness device={device} enabled={reason !== 'disabled'} session={reason === 'no-session' ? null : windowsContactSession}/>); await flush(); expect(request).not.toHaveBeenCalled(); });
});
describe('Windows Health page composition with invented accepted reports', () => {
    it('reads isolated contact and capacity endpoints on Health and keeps quota-aware disk/events separate', async () => { vi.mocked(request).mockImplementation(async path => path === `/devices/${windowsDeviceId}` ? windowsContactDevice() : path.endsWith('/windows-inventory') ? windowsView() : path.endsWith('/windows-contact') ? windowsContactView('overdue') : path.endsWith('/windows-capacity') ? windowsCapacityView() : path.endsWith('/windows-resource/cpu') ? windowsResourceView('cpu') : path.endsWith('/windows-resource/memory') ? windowsResourceView('memory') : path.endsWith('/windows-services/complete') ? Promise.reject(new APIError('This policy uses another explicit source version.', 409)) : Promise.reject(new Error('Unexpected fixture request'))); render(<DeviceDetail id={windowsDeviceId} initialTab="health" onClose={vi.fn()} onCase={vi.fn()}/>); await flush(); expect(screen.getByText('Report overdue · incident open')).toBeVisible(); expect(within(screen.getByRole('region', { name: 'System volume' })).getByText('61.0 %')).toBeVisible(); expect(screen.getByRole('region', { name: 'Windows events' })).toBeVisible(); expect(screen.queryByText('Agent contact')).toBeNull(); expect(vi.mocked(request).mock.calls.every(([path]) => [ `/devices/${windowsDeviceId}`, `/devices/${windowsDeviceId}/windows-inventory`, `/devices/${windowsDeviceId}/windows-contact`, `/devices/${windowsDeviceId}/windows-capacity`, `/devices/${windowsDeviceId}/windows-resource/cpu`, `/devices/${windowsDeviceId}/windows-resource/memory`, `/devices/${windowsDeviceId}/windows-services/complete` ].includes(path))).toBe(true); expect(mutate).not.toHaveBeenCalled(); fireEvent.click(screen.getByRole('button', { name: 'Inspect storage' })); expect(screen.getByRole('tab', { name: 'Storage' })).toHaveAttribute('aria-selected', 'true'); expect(screen.queryByText('Accepted-contact history')).toBeNull(); });
    it('does not request contact history on the Windows overview', async () => { vi.mocked(request).mockImplementation(async path => path === `/devices/${windowsDeviceId}` ? windowsContactDevice() : path.endsWith('/windows-inventory') ? windowsView() : Promise.reject(new Error('Unexpected fixture request'))); render(<DeviceDetail id={windowsDeviceId} onClose={vi.fn()} onCase={vi.fn()}/>); await flush(); expect(vi.mocked(request).mock.calls.some(([path]) => path.endsWith('/windows-contact'))).toBe(false); });
});
