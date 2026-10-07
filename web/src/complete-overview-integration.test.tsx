import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { mutateRaw, request } from './api';
import { DeviceInventoryWorkspace } from './device-inventory';
import { overviewDevice, overviewPage, overviewView, processRows, volumeRows } from './complete-overview-fixtures';
import type { OverviewPage } from './complete-overview-types';
import { setLocale } from './i18n';
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutateRaw: vi.fn() }));
vi.mock('./auth', () => ({ useOperator: () => ({ mode: 'lan', authenticated: true, expiresAt: '2026-10-04T20:00:00Z' }) }));
beforeEach(() => { setLocale('en', false); vi.mocked(request).mockReset().mockImplementation(async () => overviewView()); vi.mocked(mutateRaw).mockReset().mockImplementation(async (_path, raw) => overviewPage(overviewView(), processRows(), volumeRows(), raw)); });
afterEach(() => { cleanup(); vi.restoreAllMocks(); });
describe('complete inventory source integration', () => {
    it('opens an explicitly selected complete Processes view and lazily mounts a single selected full-generation source', async () => {
        render(<DeviceInventoryWorkspace deviceId={overviewDevice} initialSource="processes"/>); await screen.findByText('fixture-process-000000'); expect(screen.getByRole('tab', { name: 'Processes' })).toHaveAttribute('aria-selected', 'true'); expect(request).toHaveBeenCalledTimes(1);
        fireEvent.click(screen.getByRole('tab', { name: 'Mounts' })); await screen.findByText('/fixture-000084'); expect(screen.queryByText('fixture-process-000000')).not.toBeInTheDocument(); expect(screen.getAllByRole('table')).toHaveLength(1); expect(screen.queryByRole('heading', { name: 'Operational inventory' })).not.toBeInTheDocument();
        expect(vi.mocked(request).mock.calls.every(([path]) => path.endsWith('/inventory/overview'))).toBe(true);
    });
    it('cancels pending private rows on tab switch and never reinstalls them', async () => {
        let finish!: (value: OverviewPage) => void, signal!: AbortSignal;
        vi.mocked(mutateRaw).mockImplementationOnce(async (_p, _r, _h, s) => { signal = s!; return new Promise<OverviewPage>(resolve => { finish = resolve; }); }); render(<DeviceInventoryWorkspace deviceId={overviewDevice} initialSource="processes"/>); await waitFor(() => expect(finish).toBeDefined());
        fireEvent.click(screen.getByRole('tab', { name: 'Mounts' })); expect(signal.aborted).toBe(true); await screen.findByText('/fixture-000084'); await act(async () => finish(overviewPage(overviewView(), processRows(), volumeRows(), JSON.stringify({ section: 'processes', cursor: '', search: '', limit: 100 })))); expect(screen.queryByText('fixture-process-000000')).not.toBeInTheDocument();
    });
    it('keeps keyboard navigation on complete sources and legacy preview out of the primary tablist', async () => {
        render(<DeviceInventoryWorkspace deviceId={overviewDevice} initialSource="processes"/>); await screen.findByRole('table'); const process = screen.getByRole('tab', { name: 'Processes' }); process.focus(); fireEvent.keyDown(process, { key: 'ArrowRight' }); await screen.findByText('/fixture-000084'); expect(screen.getByRole('tab', { name: 'Mounts' })).toHaveFocus();
        fireEvent.keyDown(screen.getByRole('tab', { name: 'Mounts' }), { key: 'End' }); expect(screen.getByRole('tab', { name: 'Connections' })).toHaveFocus();
        expect(screen.queryByRole('tab', { name: 'Bounded preview' })).not.toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Open bounded preview' })).not.toBeVisible();
        fireEvent.click(screen.getByText('Legacy inventory source', { selector: 'summary' })); fireEvent.click(screen.getByRole('button', { name: 'Open bounded preview' }));
        expect(screen.getByRole('tab', { name: 'Legacy bounded preview' })).toHaveAttribute('aria-selected', 'true'); expect(screen.getByRole('tabpanel', { name: 'Legacy bounded preview' })).toHaveAttribute('aria-labelledby', screen.getByRole('tab', { name: 'Legacy bounded preview' }).id); expect(screen.getByText(/Bounded sample, not full inventory totals/)).toBeVisible(); expect(screen.queryByRole('table')).not.toBeInTheDocument();
    });
});
