import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { AUTH_REQUIRED_EVENT, request } from './api';
import { setLocale } from './i18n';
import { WindowsInventoryWorkspace } from './windows-inventory';
import { useWindowsInventory } from './windows-inventory-resource';
import { windowsDeviceId, windowsNow, windowsView } from './windows-inventory-fixture';
import { windowsSecurityCoverage, windowsSecurityCoverageView } from './windows-security-coverage-fixture';
import type { WindowsInventoryView } from './windows-inventory-types';
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn() }));
const flush = () => act(async () => {});
function Harness({ enabled = true, device = windowsDeviceId, session = 'fixture' }: { enabled?: boolean; device?: string; session?: string }) { return <WindowsInventoryWorkspace resource={useWindowsInventory(device, enabled, session)}/>; }
const ready = async (locale = 'en') => { await flush(); fireEvent.click(screen.getByRole('tab', { name: locale === 'de' ? 'Sicherheit' : 'Security' })); };
const refresh = () => fireEvent.click(screen.getByRole('button', { name: 'Refresh Windows inventory' }));
const details = () => Array.from(document.querySelectorAll<HTMLDetailsElement>('.windows-coverage-details'));
function retained(at = '2026-10-07T11:00:00Z'): WindowsInventoryView {
    const v = windowsSecurityCoverageView(), old = windowsSecurityCoverage(); old.collectedAt = at; old.generationId = `sample_${'b'.repeat(32)}`;
    v.securityCoverage.antivirus = { quality: 'unavailable', reason: 'windows_security_coverage_budget_exhausted', reportedCount: null, rows: [], truncated: false };
    v.securityCoverage.tpm = { quality: 'unavailable', reason: 'windows_security_coverage_budget_exhausted', presence: 'unknown', version: 'unknown' };
    return { ...v, retainedContext: { securityCoverage: old } };
}
beforeEach(() => { setLocale('en', false); vi.mocked(request).mockReset().mockResolvedValue(windowsSecurityCoverageView()); });
afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); });
it.each(['en', 'de'] as const)('renders compact source-specific states and truthful scope in %s', async locale => {
    const de = locale === 'de'; setLocale(locale, false); render(<Harness/>); await ready(locale);
    const panel = screen.getByRole('region', { name: 'Antivirus & TPM' }), av = within(panel).getByRole('region', { name: de ? 'Antivirusregistrierung' : 'Antivirus registration' });
    expect(within(av).getByText('Example Antivirus')).toBeVisible(); expect(within(av).getByText(de ? 'Pausiert' : 'Snoozed')).toBeVisible(); expect(within(av).getByText(de ? 'Veraltet' : 'Out of date')).toBeVisible();
    expect(within(panel).getByText('2.0')).toBeVisible(); expect(details()).toHaveLength(2); expect(details().every(d => !d.open)).toBe(true);
    expect(panel).toHaveTextContent(de ? 'In diesem Profil nicht erfasst.' : 'Not collected under this profile.'); expect(panel).not.toHaveTextContent(/healthy|compliant|unprotected|konform|ungeschützt/i);
    const source = screen.getByText(/IWSCProductList/), avNote = screen.getByText(de ? /Registrierung und gemeldeter Status/ : /Registration and reported status/), tpmNote = screen.getByText(de ? /Vorhandensein und Version/ : /Presence and version/);
    expect(source).not.toBeVisible(); expect(avNote).not.toBeVisible(); expect(tpmNote).not.toBeVisible(); fireEvent.click(details()[0].querySelector('summary')!); expect(source).toBeVisible(); expect(avNote).toBeVisible(); fireEvent.click(details()[1].querySelector('summary')!); expect(tpmNote).toBeVisible();
    const headers = within(av).getAllByRole('columnheader').map(h => h.textContent); for (const row of within(av).getAllByRole('row').slice(1)) expect(Array.from(row.querySelectorAll('td')).map(td => td.dataset.label)).toEqual(headers);
    expect(panel.querySelector('a,button,form,input,img,iframe')).toBeNull(); expect(request).toHaveBeenCalledTimes(1);
});
it.each(['en', 'de'] as const)('keeps unsupported WSC and denied TPM explicit in %s', async locale => {
    setLocale(locale, false); const v = windowsSecurityCoverageView();
    v.securityCoverage.antivirus = { quality: 'unavailable', reason: 'windows_security_coverage_unsupported_platform', reportedCount: null, rows: [], truncated: false };
    v.securityCoverage.tpm = { quality: 'denied', reason: 'windows_security_coverage_access_denied', presence: 'unknown', version: 'unknown' }; vi.mocked(request).mockResolvedValue(v);
    render(<Harness/>); await ready(locale); const panel = screen.getByRole('region', { name: 'Antivirus & TPM' });
    expect(within(panel).getByText(locale === 'de' ? /auf dieser Plattform nicht unterstützt/ : /unsupported on this platform/)).toBeVisible(); expect(within(panel).getByText(locale === 'de' ? 'Zugriff verweigert' : 'Access denied')).toBeVisible();
    expect(panel).not.toHaveTextContent(locale === 'de' ? 'Kein unterstütztes TPM gefunden' : 'No supported TPM found'); expect(panel).not.toHaveTextContent('Example Antivirus'); expect(details().every(d => !d.open)).toBe(true);
    for (const note of within(panel).getAllByText(locale === 'de' ? /Nicht gelesene oder nicht verfügbare Werte/ : /Unread or unavailable values/)) expect(note).not.toBeVisible();
    for (const note of panel.querySelectorAll('.windows-security-card > .windows-security-note')) expect(note).not.toHaveTextContent(/remain unknown|bleiben unbekannt|overall protection|umfassenden Schutz/);
});
it('distinguishes observed source-empty and supported-TPM not-found from hardware or protection claims', async () => {
    const v = windowsSecurityCoverageView(); Object.assign(v.securityCoverage.antivirus, { reportedCount: 0, rows: [] }); Object.assign(v.securityCoverage.tpm, { presence: 'not-found', version: 'unknown' }); vi.mocked(request).mockResolvedValue(v);
    render(<Harness/>); await ready(); expect(screen.getByText('No products reported by this source.')).toBeVisible(); expect(screen.getByText('No supported TPM found')).toBeVisible();
    const avNote = screen.getByText(/does not establish that antivirus software is absent/), tpmNote = screen.getByText(/does not establish hardware absence/); expect(avNote).not.toBeVisible(); expect(tpmNote).not.toBeVisible(); for (const detail of details()) fireEvent.click(detail.querySelector('summary')!); expect(avNote).toBeVisible(); expect(tpmNote).toBeVisible();
});
it('shows unknown product fields and omitted rows without inventing a product or count', async () => {
    const v = windowsSecurityCoverageView(); Object.assign(v.securityCoverage.antivirus, { quality: 'partial', reason: 'windows_security_coverage_bounds', reportedCount: 4, rows: [{ index: 0, name: null, state: 'unknown', signatureStatus: 'unknown' }], truncated: true }); vi.mocked(request).mockResolvedValue(v);
    render(<Harness/>); await ready(); expect(screen.getByText(/Some reported products are omitted/)).toBeVisible(); expect(within(screen.getByRole('table', { name: 'Antivirus registration' })).getAllByText('Unknown')).toHaveLength(3);
});
it('retains old useful capture beside latest failure without refreshing its time', async () => {
    vi.mocked(request).mockResolvedValue(retained()); render(<Harness/>); await ready(); expect(screen.getAllByText(/source read timed out/)).toHaveLength(2); expect(screen.getByText('Example Antivirus')).not.toBeVisible();
    fireEvent.click(screen.getByText('Show previous capture')); expect(screen.getByText('Example Antivirus')).toBeVisible(); expect(screen.getByText(/keeps its original capture time/)).toBeVisible(); expect(document.querySelector('time[datetime="2026-10-07T11:00:00Z"]')).not.toBeNull();
});
it('removes retained data at its own 24-hour boundary while the current attempt stays', async () => {
    vi.useFakeTimers(); vi.setSystemTime(windowsNow); vi.mocked(request).mockResolvedValue(retained('2026-10-06T12:00:11Z')); render(<Harness/>); await ready(); await act(async () => vi.advanceTimersByTimeAsync(1000)); expect(screen.queryByText('Show previous capture')).toBeNull(); expect(screen.queryByText('Example Antivirus')).toBeNull(); expect(screen.getAllByText(/source read timed out/)).toHaveLength(2);
});
it('ages current data, expires at the original boundary and hides future captures', async () => {
    vi.useFakeTimers(); vi.setSystemTime(windowsNow); const v = windowsSecurityCoverageView(); v.snapshot!.collectedAt = v.securityCoverage.collectedAt = '2026-10-07T11:58:10Z'; vi.mocked(request).mockResolvedValue(v); render(<Harness/>); await ready(); await act(async () => vi.advanceTimersByTimeAsync(1000)); expect(screen.getByText(/Stale antivirus and TPM observations/)).toBeVisible(); cleanup();
    vi.setSystemTime(windowsNow); v.snapshot!.collectedAt = v.securityCoverage.collectedAt = '2026-10-06T12:00:11Z'; v.status = 'stale'; render(<Harness/>); await ready(); await act(async () => vi.advanceTimersByTimeAsync(1000)); expect(screen.queryByText('Example Antivirus')).toBeNull(); expect(screen.getByText(/Antivirus and TPM observations expired/)).toBeVisible(); cleanup();
    vi.setSystemTime(windowsNow); v.snapshot!.collectedAt = v.securityCoverage.collectedAt = '2026-10-07T12:00:11Z'; render(<Harness/>); await ready(); expect(screen.queryByText('Example Antivirus')).toBeNull(); expect(screen.getByText(/Antivirus and TPM observations are hidden/)).toBeVisible(); await act(async () => vi.advanceTimersByTimeAsync(1000)); expect(screen.getByText('Example Antivirus')).toBeVisible();
});
it.each(['blur', 'pagehide', 'hashchange', AUTH_REQUIRED_EVENT])('clears current and collapsed retained values on %s', async event => {
    vi.mocked(request).mockResolvedValue(retained()); render(<Harness/>); await ready(); expect(screen.getByText('Example Antivirus')).not.toBeVisible(); act(() => window.dispatchEvent(new Event(event))); expect(screen.queryByText('Example Antivirus')).toBeNull(); expect(screen.queryByText('Show previous capture')).toBeNull();
});
it('rejects raw fields, removes missing scope and closes details on replacement generation', async () => {
    render(<Harness/>); await ready(); fireEvent.click(details()[0].querySelector('summary')!); const v = windowsSecurityCoverageView(); v.snapshot!.generationId = v.securityCoverage.generationId = `sample_${'b'.repeat(32)}`; vi.mocked(request).mockResolvedValue(v); refresh(); await flush(); expect(details().every(d => !d.open)).toBe(true);
    vi.mocked(request).mockResolvedValue({ ...v, securityCoverage: { ...v.securityCoverage, rawTPM: 'raw marker' } }); refresh(); await flush(); expect(screen.getByRole('alert')).toHaveTextContent('inconsistent'); expect(document.body).not.toHaveTextContent('raw marker');
    vi.mocked(request).mockResolvedValue(windowsView()); refresh(); await flush(); expect(screen.queryByText('Example Antivirus')).toBeNull(); expect(screen.getByText(/Antivirus and TPM observations are unavailable/)).toBeVisible();
});
it('ignores late old-device replies and clears disabled authority', async () => {
    let resolve!: (v: ReturnType<typeof windowsSecurityCoverageView>) => void; vi.mocked(request).mockReturnValueOnce(new Promise(done => { resolve = done; })); const result = render(<Harness/>); await ready(); const signal = vi.mocked(request).mock.calls.at(-1)![1]?.signal;
    const device = `agent_${'8'.repeat(32)}`; vi.mocked(request).mockResolvedValue({ ...windowsView(), deviceId: device }); result.rerender(<Harness device={device}/>); await act(async () => resolve(windowsSecurityCoverageView())); expect(signal?.aborted).toBe(true); expect(screen.queryByText('Example Antivirus')).toBeNull(); result.rerender(<Harness enabled={false}/>); expect(screen.queryByText('Example Antivirus')).toBeNull();
});
