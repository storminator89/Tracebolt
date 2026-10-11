import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AUTH_REQUIRED_EVENT, request } from './api';
import { setLocale } from './i18n';
import { WindowsInventoryWorkspace } from './windows-inventory';
import { useWindowsInventory } from './windows-inventory-resource';
import { windowsDeviceId, windowsNow, windowsView } from './windows-inventory-fixture';
import { windowsSecurityPostureView } from './windows-security-posture-fixture';
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn() }));
const flush = () => act(async () => {});
function Harness({ session = 'fixture', device = windowsDeviceId, enabled = true }: { session?: string; device?: string; enabled?: boolean }) { return <WindowsInventoryWorkspace resource={useWindowsInventory(device, enabled, session)}/>; }
const ready = async (locale = 'en') => { await flush(); fireEvent.click(screen.getByRole('tab', { name: locale === 'de' ? 'Sicherheit' : 'Security' })); };
const refresh = () => fireEvent.click(screen.getByRole('button', { name: 'Refresh Windows inventory' }));
const details = () => Array.from(document.querySelectorAll<HTMLDetailsElement>('.windows-security-details'));
beforeEach(() => { setLocale('en', false); vi.mocked(request).mockReset().mockResolvedValue(windowsSecurityPostureView()); });
afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); });

describe('Compact private Security tab', () => {
    it.each(['en', 'de'] as const)('shows capture, source qualities, explicit states and collapsed details in %s', async locale => {
        setLocale(locale, false); render(<Harness/>); await ready(locale); const de = locale === 'de', panel = screen.getByRole('region', { name: de ? 'Sicherheit' : 'Security' });
        expect(within(panel).getByText(de ? 'Normalmodus' : 'Normal mode')).toBeVisible();
        expect(within(panel).getByText(de ? 'Beobachtet' : 'Observed')).toBeVisible(); expect(within(panel).getByText(de ? 'Teilweise' : 'Partial')).toBeVisible();
        expect(panel.querySelector('time')).toHaveAttribute('dateTime', windowsView().snapshot!.collectedAt);
        expect(screen.getByText('1.437.1234.0')).not.toBeVisible(); expect(details().every(d => !d.open)).toBe(true);
        fireEvent.click(details()[0].querySelector('summary')!); expect(screen.getByText('1.437.1234.0')).toBeVisible(); expect(screen.getByText(de ? '1 Tag' : '1 day')).toBeVisible();
        fireEvent.click(details()[1].querySelector('summary')!); expect(screen.getByText(de ? 'Einige Felder waren nicht verfügbar.' : 'Some fields were not available.')).toBeVisible();
        const table = within(panel).getByRole('table'), headers = within(table).getAllByRole('columnheader').map(c => c.textContent);
        expect(within(table).getAllByRole('row')).toHaveLength(4); for (const row of within(table).getAllByRole('row').slice(1)) expect(within(row).getAllByRole('cell').map(c => c.dataset.label)).toEqual(headers);
        expect(panel).toHaveTextContent(de ? 'Andere Antivirusprodukte werden nicht geprüft.' : 'Other antivirus products are not assessed.'); expect(panel).toHaveTextContent(de ? 'Wirksame Richtlinien und Netzwerkerreichbarkeit werden nicht geprüft.' : 'Effective policy and network connectivity are not checked.');
        expect(panel.querySelector('a,img,iframe,button,form,input')).toBeNull(); expect(panel).not.toHaveTextContent(/unprotected|compliant|compliance|ungeschützt|konform/i);
    });
    it.each(['passive', 'edr-block', 'unknown'] as const)('does not infer lack of protection for %s Defender and false flags', async mode => {
        const v = windowsSecurityPostureView(); Object.assign(v.securityPosture.defender, { mode, antivirusEnabled: 'off', realTimeProtectionEnabled: 'off', ...(mode === 'unknown' ? { quality: 'partial', reason: 'windows_security_posture_partial_result' } : {}) }); vi.mocked(request).mockResolvedValue(v);
        render(<Harness/>); await ready(); const panel = screen.getByRole('region', { name: 'Microsoft Defender' }); expect(panel).toHaveTextContent(mode === 'passive' ? 'Passive mode' : mode === 'edr-block' ? 'EDR block mode' : 'Unknown mode'); expect(within(panel).getAllByText('Off')[0]).toBeVisible(); expect(panel).not.toHaveTextContent(/unprotected|protected|healthy|compliant/i);
    });
    it.each(['denied', 'unavailable'] as const)('keeps %s source independent of readable firewall', async quality => {
        const v = windowsSecurityPostureView(); Object.assign(v.securityPosture.defender, { quality, reason: quality === 'denied' ? 'windows_security_posture_access_denied' : 'windows_security_posture_unavailable', mode: 'unknown', serviceEnabled: 'unknown', antivirusEnabled: 'unknown', realTimeProtectionEnabled: 'unknown', signatureVersion: null, signatureAgeDays: null }); vi.mocked(request).mockResolvedValue(v); render(<Harness/>); await ready(); const panel = screen.getByRole('region', { name: 'Microsoft Defender' }); expect(panel).toHaveTextContent(quality === 'denied' ? 'Access denied' : 'Unavailable'); expect(panel).toHaveTextContent('Unknown mode'); expect(screen.getByRole('table', { name: 'Windows Firewall' })).toBeVisible();
    });
    it('resets details after tab navigation and replacement grant/generation', async () => {
        render(<Harness/>); await ready(); fireEvent.click(details()[0].querySelector('summary')!); fireEvent.click(screen.getByRole('tab', { name: 'Hostname' })); fireEvent.click(screen.getByRole('tab', { name: 'Security' })); expect(details()[0].open).toBe(false);
        fireEvent.click(details()[0].querySelector('summary')!); const v = windowsSecurityPostureView(); v.securityPosture.grantId = 'd'.repeat(32); v.securityPosture.defender.signatureVersion = '9.9'; vi.mocked(request).mockResolvedValue(v); refresh(); await flush(); expect(details()[0].open).toBe(false); expect(screen.queryByText('1.437.1234.0')).toBeNull();
    });
    it('shows an honest absent-scope state and rejects untrusted fields without rendering them', async () => {
        vi.mocked(request).mockResolvedValue(windowsView()); render(<Harness/>); await ready(); expect(screen.getByText(/Separate local approval/)).toBeVisible();
        vi.mocked(request).mockResolvedValue({ ...windowsSecurityPostureView(), securityPosture: { ...windowsSecurityPostureView().securityPosture, raw: 'private raw marker' } }); refresh(); await flush(); expect(screen.getByRole('alert')).toHaveTextContent('inconsistent'); expect(document.body).not.toHaveTextContent('private raw marker');
    });
});

describe('Security source authority and original-capture lifetime', () => {
    it('turns stale after two minutes and removes all fields at original 24-hour expiry', async () => {
        vi.useFakeTimers(); vi.setSystemTime(windowsNow); const v = windowsSecurityPostureView(); v.snapshot!.collectedAt = v.securityPosture.collectedAt = '2026-10-07T11:58:10Z'; vi.mocked(request).mockResolvedValue(v); render(<Harness/>); await ready(); expect(screen.queryByText(/Stale observation;/)).toBeNull(); await act(async () => vi.advanceTimersByTimeAsync(1000)); expect(screen.getByText(/Stale observation;/)).toBeVisible(); cleanup();
        vi.setSystemTime(windowsNow); v.snapshot!.collectedAt = v.securityPosture.collectedAt = '2026-10-06T12:00:11Z'; v.status = 'stale'; render(<Harness/>); await ready(); await act(async () => vi.advanceTimersByTimeAsync(1000)); expect(screen.queryByText('1.437.1234.0')).toBeNull(); expect(screen.getByText(/Security observations expired/)).toBeVisible();
    });
    it('hides future data until capture time is reached on the acceptance clock', async () => {
        vi.useFakeTimers(); vi.setSystemTime(windowsNow); const v = windowsSecurityPostureView(); v.snapshot!.collectedAt = v.securityPosture.collectedAt = '2026-10-07T12:00:11Z'; v.status = 'stale'; vi.mocked(request).mockResolvedValue(v); render(<Harness/>); await ready(); expect(screen.queryByText('Normal mode')).toBeNull(); expect(screen.getByText(/until their capture time/)).toBeVisible(); await act(async () => vi.advanceTimersByTimeAsync(1000)); expect(screen.getByText('Normal mode')).toBeVisible();
    });
    it.each(['blur', 'pagehide', 'hashchange', AUTH_REQUIRED_EVENT])('clears visible and collapsed security fields on %s', async event => {
        render(<Harness/>); await ready(); act(() => window.dispatchEvent(new Event(event))); expect(screen.queryByText('Normal mode')).toBeNull(); expect(screen.queryByText('1.437.1234.0')).toBeNull();
    });
    it.each(['revoked', 'unavailable', 'awaiting', 'not_configured', 'absent'] as const)('removes old data when the scope becomes %s', async status => {
        render(<Harness/>); await ready(); vi.mocked(request).mockResolvedValue(status === 'absent' ? windowsView() : { ...windowsView(), status, snapshot: null, ...(['awaiting', 'not_configured'].includes(status) ? { sequence: null, receivedAt: null } : {}) }); refresh(); await flush(); expect(screen.queryByText('Normal mode')).toBeNull(); expect(screen.queryByText('1.437.1234.0')).toBeNull();
    });
    it('clears source fields on hidden visibility and disabled authority', async () => {
        const result = render(<Harness/>); await ready();
        const visibility = vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden');
        act(() => document.dispatchEvent(new Event('visibilitychange'))); expect(screen.queryByText('1.437.1234.0')).toBeNull();
        visibility.mockReturnValue('visible'); act(() => document.dispatchEvent(new Event('visibilitychange'))); await flush(); expect(screen.getByText('Normal mode')).toBeVisible();
        result.rerender(<Harness enabled={false}/>); expect(screen.queryByText('Normal mode')).toBeNull(); expect(screen.queryByText('1.437.1234.0')).toBeNull();
    });
    it('discards source data immediately on device navigation and ignores the old response', async () => {
        let resolve!: (v: ReturnType<typeof windowsSecurityPostureView>) => void;
        const result = render(<Harness/>); await ready(); vi.mocked(request).mockReturnValueOnce(new Promise(done => { resolve = done; })); refresh(); expect(screen.queryByText('1.437.1234.0')).toBeNull();
        const signal = vi.mocked(request).mock.calls.at(-1)![1]?.signal, device = `agent_${'8'.repeat(32)}`;
        vi.mocked(request).mockResolvedValue({ ...windowsView(), deviceId: device }); result.rerender(<Harness device={device}/>); await act(async () => resolve(windowsSecurityPostureView())); expect(signal?.aborted).toBe(true); expect(screen.queryByText('Normal mode')).toBeNull();
    });
    it('rejects frozen manager time and ignores a late response after session replacement', async () => {
        vi.useFakeTimers(); vi.setSystemTime(windowsNow); render(<Harness/>); await ready(); await act(async () => vi.advanceTimersByTimeAsync(15000)); expect(screen.queryByText('Normal mode')).toBeNull(); expect(screen.getByRole('alert')).toHaveTextContent('time reference changed'); cleanup(); vi.useRealTimers();
        let resolve!: (v: ReturnType<typeof windowsSecurityPostureView>) => void; vi.mocked(request).mockReturnValueOnce(new Promise(done => { resolve = done; })); const result = render(<Harness/>); await ready(); const signal = vi.mocked(request).mock.calls.at(-1)![1]?.signal; vi.mocked(request).mockResolvedValue(windowsView()); result.rerender(<Harness session="replacement"/>); await act(async () => resolve(windowsSecurityPostureView())); expect(signal?.aborted).toBe(true); expect(screen.queryByText('1.437.1234.0')).toBeNull();
    });
});
