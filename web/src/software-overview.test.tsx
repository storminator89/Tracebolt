import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { APIError, AUTH_REQUIRED_EVENT, mutateRaw, request } from './api';
import { DeviceInventoryWorkspace } from './device-inventory';
import { SoftwareOverview } from './software-overview';
import { completeDevice, completeNow, completePage, completeRows, completeView } from './complete-packages-fixtures';
import type { CompletePackageView } from './complete-packages-types';
import { OPERATIONAL_PROFILE, OPERATIONAL_SCHEMA, SECTION_LIMITS, validOperationalView } from './operational-types';
import type { OperationalMeta, OperationalSectionName, OperationalView } from './operational-types';
import { setLocale } from './i18n';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutateRaw: vi.fn() }));
const operator = vi.hoisted(() => ({ mode: 'lan', authenticated: true, expiresAt: '2026-10-04T01:00:00Z' }));
vi.mock('./auth', () => ({ useOperator: () => operator }));
let view: CompletePackageView;
// Invented regression counts only. Never imported by production or used as a fallback.
function preview(): OperationalView {
    const meta = (name: OperationalSectionName): OperationalMeta => ({ quality: 'healthy', reason: 'none', observedAt: '2026-10-04T00:00:00Z', generationId: `sample_${'a'.repeat(32)}`, complete: true, truncated: false, observedCount: 0, countExact: true, itemLimit: SECTION_LIMITS[name] });
    return { schemaVersion: 'tracebolt.operational-view.v1', deviceId: completeDevice, status: 'fresh', serverNow: completeNow, receivedAt: '2026-10-04T00:00:05Z', sequence: 1, maxAgeSeconds: 120,
        snapshot: { schemaVersion: OPERATIONAL_SCHEMA, collectionProfile: OPERATIONAL_PROFILE, generationId: `sample_${'a'.repeat(32)}`, collectedAt: '2026-10-04T00:00:00Z', durationMs: 10, sections: {
            volumes: { meta: meta('volumes'), items: [] }, network: { meta: meta('network'), items: [] }, services: { meta: meta('services'), items: [] }, processes: { meta: meta('processes'), items: [] }, events: { meta: meta('events'), items: [] },
            software: { meta: { ...meta('software'), observedCount: 1472, complete: false, truncated: true, reason: 'byte_limit' }, items: Array.from({ length: 211 }, (_, i) => ({ name: `invented-preview-${i}`, version: '1.0', architecture: 'all', manager: 'dpkg' })) },
        } }, lastGood: { volumes: null, network: null, services: null, processes: null, software: null, events: null }, assessments: { updates: { quality: 'unknown', reason: 'not_implemented' }, vulnerabilities: { quality: 'unknown', reason: 'not_implemented' } } };
}
function transfer(state: 'pending' | 'failed' = 'pending'): NonNullable<CompletePackageView['transfer']> {
    return { binding: { sequence: '2', generationId: `sample_${'d'.repeat(32)}`, manifestHash: 'e'.repeat(64) }, state, declaredRows: 2000, acceptedRows: 128, expectedChunks: 16, acceptedChunks: 1, collectedAt: '2026-10-04T00:00:06Z', startedAt: '2026-10-04T00:00:07Z', expiresAt: '2026-10-04T00:15:07Z' };
}
function summary() { return <SoftwareOverview deviceId={completeDevice} onOpenPackages={vi.fn()} sessionKey="first"/>; }
function total() { return screen.getByText('Complete dpkg rows').nextElementSibling!; }
beforeEach(() => {
    setLocale('en', false); operator.authenticated = true; view = completeView(1472);
    vi.mocked(request).mockReset().mockImplementation(async path => path.endsWith('/operational') ? preview() : view);
    vi.mocked(mutateRaw).mockReset().mockImplementation(async (_path, raw) => completePage(view, completeRows(1472), raw));
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.useRealTimers(); });

describe('complete software overview', () => {
    it('keeps the legacy 211-row preview separate and opens complete Packages without concurrent metadata reads', async () => {
        expect(validOperationalView(preview(), completeDevice)).toBe(true);
        render(<DeviceInventoryWorkspace deviceId={completeDevice} initialSource="preview"/>);
        const sample = await screen.findByRole('button', { name: /^Software sample/ });
        expect(within(sample).getByText('211')).toBeVisible(); expect(mutateRaw).not.toHaveBeenCalled();
        expect(request).toHaveBeenCalledTimes(1); expect(vi.mocked(request).mock.calls[0][0]).toBe(`/devices/${completeDevice}/operational`);
        expect(screen.queryByText('Complete dpkg rows')).not.toBeInTheDocument();
        fireEvent.click(sample); expect(screen.getByText(/Legacy bounded sample of installed packages/)).toBeVisible();
        fireEvent.click(screen.getByRole('button', { name: 'Open complete Packages' }));
        await screen.findByRole('rowheader', { name: 'fixture-000000' });
        expect(screen.getByRole('tab', { name: 'Packages' })).toHaveAttribute('aria-selected', 'true');
        expect(screen.getByRole('tab', { name: 'Packages' })).toHaveFocus();
        expect(screen.queryByRole('button', { name: /^Software sample/ })).not.toBeInTheDocument();
        expect(JSON.parse(vi.mocked(mutateRaw).mock.calls[0][1]).generationId).toBe(view.complete!.binding.generationId);
        expect(vi.mocked(request).mock.calls.filter(([path]) => path.endsWith('/inventory/packages'))).toHaveLength(1);
    });
    it.each(['pending', 'failed'] as const)('keeps the original complete count, generation and age separate from a newer %s attempt', async state => {
        view.complete!.binding.sequence = '1'; view.transfer = transfer(state); view.serverNow = '2026-10-04T01:00:10Z';
        if (state === 'pending') view.transfer.expiresAt = '2026-10-04T01:15:07Z';
        view.failure = { sequence: '3', generationId: `sample_${'f'.repeat(32)}`, attemptedAt: '2026-10-04T00:00:08Z', receivedAt: '2026-10-04T00:00:09Z', reason: 'collection_failed' };
        render(summary()); await waitFor(() => expect(total()).toHaveTextContent('1,472'));
        expect(screen.getByText('Observation age (minutes)').nextElementSibling).toHaveTextContent('60');
        expect(screen.getByText('2026-10-04T00:00:00Z')).toBeVisible();
        expect(screen.getByText(view.complete!.binding.generationId)).not.toBeVisible();
        fireEvent.click(screen.getByText('Generation details', { selector: 'summary' }));
        expect(screen.getByText(view.complete!.binding.generationId)).toBeVisible();
        expect(screen.getByText(`Transfer ${state}`)).toBeVisible(); expect(screen.getByText('128 / 2,000')).toBeVisible();
        expect(screen.getByText('Latest collection attempt failed')).toBeVisible(); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it.each(['pending', 'failed'] as const)('never promotes a %s transfer declaration into a complete count', async state => {
        view.complete = null; view.status = 'awaiting'; view.transfer = transfer(state);
        render(summary()); await screen.findByText('Awaiting a complete generation'); expect(total()).toHaveTextContent('—');
        expect(screen.getByText('128 / 2,000')).toBeVisible(); expect(screen.queryByText('Installed rows')).not.toBeInTheDocument(); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it.each(['expired', 'revoked', 'unavailable'] as const)('shows %s as unavailable, preserving only explicitly historical generation metadata', async state => {
        if (state === 'expired') { view.complete!.state = 'expired'; view.serverNow = '2026-10-05T00:00:00Z'; } else view.status = state;
        render(summary()); await screen.findByText('Historical generation details'); expect(total()).toHaveTextContent('—');
        const details = screen.getByText('Historical generation details').closest('details')!; expect(details).not.toHaveAttribute('open');
        fireEvent.click(screen.getByText('Historical generation details')); expect(within(details).getByText('2026-10-04T00:00:00Z')).toBeVisible();
        expect(screen.queryByText('Incomplete rows')).not.toBeInTheDocument(); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('preserves zero only for an available completed generation', async () => {
        view = completeView(0); render(summary()); await waitFor(() => expect(total()).toHaveTextContent(/^0$/)); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it.each(['missing', 'invalid', 'not_configured'] as const)('does not invent a total for %s inventory', async state => {
        if (state === 'missing') vi.mocked(request).mockRejectedValue(new APIError('private failure', 404));
        else if (state === 'invalid') vi.mocked(request).mockResolvedValue({ ...view, deviceId: 'agent_wrong' });
        else { view.collectionProfile = 'managed-operations-v2'; view.status = 'not_configured'; view.complete = null; }
        render(summary()); if (state === 'not_configured') await screen.findByText('Complete package collection not configured'); else await screen.findByRole('alert');
        expect(total()).toHaveTextContent('—'); expect(document.body.textContent).not.toContain('private failure'); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it.each(['auth', 'blur', 'pagehide', 'hidden', 'hash', 'device', 'session', 'unmount'] as const)('aborts metadata reads and rejects late old totals after %s', async transition => {
        let finish!: (value: CompletePackageView) => void; let signal!: AbortSignal;
        vi.mocked(request).mockImplementationOnce(async (_path, options) => { signal = options!.signal as AbortSignal; return new Promise<CompletePackageView>(resolve => { finish = resolve; }); });
        const rendered = render(summary()); await waitFor(() => expect(signal).toBeDefined());
        if (transition === 'auth') act(() => window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT)));
        if (transition === 'blur' || transition === 'pagehide') act(() => window.dispatchEvent(new Event(transition)));
        if (transition === 'hidden') { vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden'); act(() => document.dispatchEvent(new Event('visibilitychange'))); }
        if (transition === 'hash') act(() => window.dispatchEvent(new HashChangeEvent('hashchange')));
        if (transition === 'device' || transition === 'session') { vi.mocked(request).mockReturnValue(new Promise(() => {})); rendered.rerender(<SoftwareOverview deviceId={transition === 'device' ? 'agent_other' : completeDevice} onOpenPackages={vi.fn()} sessionKey="replacement"/>); }
        if (transition === 'unmount') rendered.unmount();
        expect(signal.aborted).toBe(true); await act(async () => finish(view)); expect(document.body.textContent).not.toContain('1,472'); expect(mutateRaw).not.toHaveBeenCalled();
        if (transition === 'auth') { act(() => window.dispatchEvent(new Event('focus'))); expect(request).toHaveBeenCalledTimes(1); }
    });
    it('clears loaded metadata on visibility loss and revalidates a changed generation before restoring totals', async () => {
        render(summary()); await waitFor(() => expect(total()).toHaveTextContent('1,472')); act(() => window.dispatchEvent(new Event('blur'))); expect(total()).toHaveTextContent('—');
        view = completeView(1500); view.complete!.binding.generationId = view.complete!.manifest.generationId = `sample_${'d'.repeat(32)}`;
        act(() => window.dispatchEvent(new Event('focus'))); await waitFor(() => expect(total()).toHaveTextContent('1,500')); expect(screen.queryByText(`sample_${'a'.repeat(32)}`)).not.toBeInTheDocument(); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('expires the overview count locally without refreshing the original observation', async () => {
        vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] }); const mono = vi.spyOn(performance, 'now').mockReturnValue(1000), wall = vi.spyOn(Date, 'now').mockReturnValue(100000);
        view.serverNow = '2026-10-04T23:59:59Z'; render(summary()); await waitFor(() => expect(total()).toHaveTextContent('1,472'));
        mono.mockReturnValue(3000); wall.mockReturnValue(102000); act(() => vi.advanceTimersByTime(1000)); expect(total()).toHaveTextContent('—'); expect(screen.getByText('Historical generation metadata')).toBeVisible(); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('marks a pending transfer expired locally while preserving the independent complete count and age', async () => {
        vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] }); const mono = vi.spyOn(performance, 'now').mockReturnValue(1000), wall = vi.spyOn(Date, 'now').mockReturnValue(100000);
        view.complete!.binding.sequence = '1'; view.transfer = transfer(); view.transfer.expiresAt = '2026-10-04T00:00:11Z';
        render(summary()); await screen.findByText('Transfer pending'); mono.mockReturnValue(3000); wall.mockReturnValue(102000); act(() => vi.advanceTimersByTime(1000));
        expect(screen.getByText('Transfer expired')).toBeVisible(); expect(total()).toHaveTextContent('1,472'); expect(screen.getByText('2026-10-04T00:00:00Z')).toBeVisible(); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('fails closed when its clock anchor becomes unreliable', async () => {
        vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] }); const mono = vi.spyOn(performance, 'now').mockReturnValue(1000);
        render(summary()); await waitFor(() => expect(total()).toHaveTextContent('1,472')); mono.mockReturnValue(500); act(() => vi.advanceTimersByTime(1000)); expect(total()).toHaveTextContent('—'); expect(screen.getByRole('alert')).toHaveTextContent('time anchor');
    });
    it('does not read or retain totals without authenticated LAN access', async () => {
        const rendered = render(summary()); await waitFor(() => expect(total()).toHaveTextContent('1,472')); operator.authenticated = false; rendered.rerender(summary());
        expect(screen.queryByText('Complete dpkg rows')).not.toBeInTheDocument(); expect(request).toHaveBeenCalledTimes(1);
    });
    it('uses German complete-count and direct-navigation labels', async () => {
        setLocale('de', false); render(summary()); await screen.findByText('1.472', { selector: '.software-total > div:first-child dd' }); expect(screen.getByRole('button', { name: 'Pakete öffnen' })).toBeVisible();
    });
});
