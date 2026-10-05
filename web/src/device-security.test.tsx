import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { APIError, mutateRaw, request } from './api';
import { DeviceSecurityWorkspace } from './device-security';
import { useOperator } from './auth';
import { setLocale } from './i18n';
import { linuxCVEDeviceId, linuxCVEView, missingLinuxCVEView, staleLinuxCVEView } from './linux-cve-fixtures';
import type { LinuxCVEView } from './linux-cve-types';
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutateRaw: vi.fn() }));
vi.mock('./auth', () => ({ useOperator: vi.fn() }));
const operator = { mode: 'lan' as const, authenticated: true, expiresAt: '2026-10-05T08:00:00Z', insecureTestMode: false, logout: vi.fn(), theme: 'light' as const, setTheme: vi.fn() };
const path = `/devices/${linuxCVEDeviceId}/security/cves`, packages = vi.fn(), updates = vi.fn();
function current() {
    const value = linuxCVEView(true); value.inventory!.rowCount = 1396;
    value.report!.findings = Array.from({ length: 6 }, (_, index) => ({ ...structuredClone(value.report!.findings[0]), cveId: `CVE-2026-99999${index}`, advisoryUrl: `https://security-tracker.debian.org/tracker/CVE-2026-99999${index}` }));
    value.report!.feed!.recordCount = value.feeds.snapshots[0].recordCount = 6;
    return value;
}
const workspace = (sessionKey = 'first') => <DeviceSecurityWorkspace deviceId={linuxCVEDeviceId} sessionKey={sessionKey} onOpenPackages={packages} onOpenUpdates={updates}/>;
beforeEach(() => { setLocale('en', false); vi.mocked(useOperator).mockReturnValue(operator); vi.mocked(request).mockReset().mockImplementation(async target => { if (target === path) return current(); throw new APIError('Unavailable fixture source', 404); }); vi.mocked(mutateRaw).mockReset(); packages.mockClear(); updates.mockClear(); });
afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.useRealTimers(); });
function legacy(source: string) { fireEvent.click(screen.getByText('Legacy diagnostics', { selector: 'summary' })); fireEvent.change(screen.getByLabelText('Diagnostic source'), { target: { value: source } }); }

describe('one current Security source', () => {
    it('shows the complete 1,396-row inventory and six current warnings without the contradictory 222-row legacy summary', async () => {
        render(workspace()); await screen.findByRole('article', { name: 'CVE-2026-999990: fixture' });
        expect(screen.getByText('Received dpkg rows').nextElementSibling).toHaveTextContent('1,396');
        expect(screen.getByText('Package warnings').previousElementSibling).toHaveTextContent('6');
        expect(screen.getByText('Inventory age').nextElementSibling).toHaveTextContent('1 min');
        expect(screen.getByText('Only the loaded records were checked.')).toBeVisible();
        expect(screen.queryByText('222')).not.toBeInTheDocument(); expect(document.body.textContent).not.toMatch(/adapter is not implemented|No package matching/);
        expect(vi.mocked(request).mock.calls.map(([target]) => target)).toEqual([path]); expect(mutateRaw).not.toHaveBeenCalled();
        fireEvent.click(screen.getByRole('button', { name: 'Open Packages' })); expect(packages).toHaveBeenCalledOnce();
        fireEvent.click(screen.getByRole('button', { name: 'Open Updates' })); expect(updates).toHaveBeenCalledOnce();
        expect(request).toHaveBeenCalledOnce();
    });
    it('opens diagnostics without loading them and mounts only the explicitly selected legacy reader', async () => {
        render(workspace()); await screen.findByText('Package warnings');
        fireEvent.click(screen.getByText('Legacy diagnostics', { selector: 'summary' })); expect(request).toHaveBeenCalledOnce();
        fireEvent.change(screen.getByLabelText('Diagnostic source'), { target: { value: 'legacy-coverage' } });
        await screen.findByRole('heading', { name: 'Legacy inventory evidence' });
        expect(screen.queryByText('Package warnings')).not.toBeInTheDocument();
        expect(vi.mocked(request).mock.calls.map(([target]) => target)).toEqual([path, `/devices/${linuxCVEDeviceId}/security`]);
        fireEvent.change(screen.getByLabelText('Diagnostic source'), { target: { value: 'legacy-packages' } });
        expect(screen.queryByRole('heading', { name: 'Legacy inventory evidence' })).not.toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Release and source-package observations' })).toHaveAttribute('aria-expanded', 'false');
        expect(request).toHaveBeenCalledTimes(2); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it.each(['inventory', 'feed', 'failed', 'invalid'] as const)('does not convert %s gaps into zero warnings or healthy inventory', async missing => {
        const value = missingLinuxCVEView();
        if (missing === 'inventory') { value.inventory = null; value.status = 'inventory_unavailable'; }
        if (missing === 'failed') vi.mocked(request).mockRejectedValue(new APIError('private failure', 503));
        else vi.mocked(request).mockResolvedValue(missing === 'invalid' ? { ...value, deviceId: 'agent_other' } : value);
        render(workspace()); if (missing === 'failed' || missing === 'invalid') await screen.findByRole('alert'); else { await screen.findByText('Warnings unavailable'); expect(screen.getByText('Warnings unavailable').previousElementSibling).toHaveTextContent('—'); }
        expect(screen.queryByText('Package warnings')).not.toBeInTheDocument(); expect(document.body.textContent).not.toMatch(/healthy|secure|private failure/i);
        expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('retains explicit stale coverage and original age', async () => {
        vi.mocked(request).mockResolvedValue(staleLinuxCVEView()); render(workspace()); await screen.findByText(/Old data: these matches/);
        expect(screen.getByText('Feed download age').nextElementSibling).toHaveTextContent('3 d · Stale'); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('cancels a current read on a source change and ignores its late private results', async () => {
        let finish!: (value: LinuxCVEView) => void, signal!: AbortSignal;
        vi.mocked(request).mockImplementationOnce(async (_target, options) => { signal = options!.signal!; return new Promise<LinuxCVEView>(resolve => { finish = resolve; }); });
        render(workspace()); await waitFor(() => expect(signal).toBeDefined()); legacy('legacy-packages'); expect(signal.aborted).toBe(true);
        await act(async () => finish(current())); expect(screen.queryByText('1,396')).not.toBeInTheDocument(); expect(screen.queryByText('Package warnings')).not.toBeInTheDocument();
    });
    it('does not add background reads while waiting', async () => {
        vi.useFakeTimers(); render(workspace()); await act(async () => {}); expect(request).toHaveBeenCalledOnce();
        await act(async () => vi.advanceTimersByTimeAsync(120000)); expect(request).toHaveBeenCalledOnce(); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('resets legacy selection for a new operator session and drops it when access ends', async () => {
        const mounted = render(workspace()); await screen.findByText('Package warnings'); legacy('legacy-packages');
        mounted.rerender(workspace('second')); await screen.findByText('Package warnings'); expect(screen.getByLabelText('Diagnostic source')).toHaveValue('current');
        vi.mocked(useOperator).mockReturnValue(null); mounted.rerender(workspace('second')); expect(screen.queryByText('Package warnings')).not.toBeInTheDocument(); expect(screen.queryByRole('button')).not.toBeInTheDocument();
    });
    it('uses German navigation, authoritative counts and coverage labels', async () => {
        setLocale('de', false); render(workspace()); await screen.findByText('Paketwarnungen');
        expect(screen.getByText('Empfangene dpkg-Zeilen').nextElementSibling).toHaveTextContent('1.396');
        expect(screen.getByRole('button', { name: 'Pakete öffnen' })).toBeVisible(); expect(screen.getByRole('button', { name: 'Updates öffnen' })).toBeVisible();
        expect(screen.queryByRole('heading', { name: 'Ältere Inventarbelege' })).not.toBeInTheDocument();
    });
});
