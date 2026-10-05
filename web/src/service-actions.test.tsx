import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { APIError, AUTH_REQUIRED_EVENT } from './api';
import { approveServiceAction, InvalidServiceActionResponse, previewServiceAction, readServiceActions } from './service-action-api';
import { actionAccess, actionActor, actionDevice, actionJobView, actionNow, actionPreview, actionView } from './service-action-fixtures';
import { useServiceActions } from './service-action-resource';
import { ServiceActionPanel } from './service-actions';
import { setLocale } from './i18n';
import type { ServiceActionView } from './service-action-types';
vi.mock('./service-action-api', async original => ({ ...await original<typeof import('./service-action-api')>(), readServiceActions: vi.fn(), previewServiceAction: vi.fn(), approveServiceAction: vi.fn() }));
function Harness({ deviceId = actionDevice, authorized = true }: { deviceId?: string; authorized?: boolean }) {
    const workflow = useServiceActions(deviceId, authorized ? actionAccess : null);
    return <><button disabled={!workflow.canSelect('fixture.service')} onClick={() => workflow.select('fixture.service')}>Select fixture</button><button disabled={!workflow.canSelect('other.service')} onClick={() => workflow.select('other.service')}>Select other</button><ServiceActionPanel workflow={workflow} authorized={authorized}/></>;
}
const flush = () => act(async () => {});
async function start() { const mounted = render(<Harness/>); await flush(); return mounted; }
async function preview() { fireEvent.click(screen.getByRole('button', { name: 'Select fixture' })); await flush(); }
async function approve() { fireEvent.click(screen.getByRole('checkbox')); fireEvent.click(screen.getByRole('button', { name: 'Approve try-restart' })); await flush(); }
beforeEach(() => {
    vi.useFakeTimers(); vi.setSystemTime(actionNow); setLocale('en', false);
    vi.mocked(readServiceActions).mockReset().mockResolvedValue(actionView());
    vi.mocked(previewServiceAction).mockReset().mockImplementation(async (_device, unit) => ({ ...actionView(), preview: actionPreview(unit) }));
    vi.mocked(approveServiceAction).mockReset().mockResolvedValue(actionJobView());
});
afterEach(() => { act(() => window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT))); cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); });
describe('explicit selected-service action flow', () => {
    it('requires the exact preview and interruption consent, and submits one approval on repeated clicks', async () => {
        await start(); expect(previewServiceAction).not.toHaveBeenCalled(); expect(approveServiceAction).not.toHaveBeenCalled();
        await preview(); const review = screen.getByRole('region', { name: 'Review service action' });
        expect(review).toHaveTextContent(actionDevice); expect(review).toHaveTextContent(actionActor); expect(review).toHaveTextContent('fixture.service'); expect(review).toHaveTextContent('service.try-restart'); expect(review).toHaveTextContent('interrupt the service and its dependents'); expect(review).toHaveFocus();
        const button = screen.getByRole('button', { name: 'Approve try-restart' }); expect(button).toBeDisabled(); fireEvent.click(button); expect(approveServiceAction).not.toHaveBeenCalled();
        fireEvent.click(screen.getByRole('checkbox')); fireEvent.click(button); fireEvent.click(button); await flush();
        expect(approveServiceAction).toHaveBeenCalledTimes(1); expect(approveServiceAction).toHaveBeenCalledWith(actionDevice, actionPreview(), actionAccess, expect.any(AbortSignal));
        expect(screen.getByText(/awaiting agent delivery/)).toBeVisible(); expect(screen.getByRole('button', { name: 'Select fixture' })).toBeDisabled(); expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();
    });
    it('shows shared/missing-capability access unavailable without reading or mutating actions', async () => {
        render(<Harness authorized={false}/>); await flush(); expect(screen.getByText(/named operator/)).toBeVisible(); expect(screen.getByRole('button', { name: 'Select fixture' })).toBeDisabled(); expect(readServiceActions).not.toHaveBeenCalled(); expect(previewServiceAction).not.toHaveBeenCalled();
    });
    it.each(['not_configured', 'helper_unavailable', 'helper_stale', 'helper_disabled'] as const)('keeps %s disabled without synthetic success', async reason => {
        vi.mocked(readServiceActions).mockResolvedValue({ ...actionView(), configured: reason !== 'not_configured', available: false, reason, services: [] });
        await start(); expect(screen.getByRole('button', { name: 'Select fixture' })).toBeDisabled(); expect(screen.queryByRole('button', { name: 'Approve try-restart' })).not.toBeInTheDocument(); expect(previewServiceAction).not.toHaveBeenCalled();
    });
    it.each(['close', 'escape', 'pagehide', 'blur', 'hashchange', 'popstate', 'auth', 'device', 'unmount'] as const)('clears an unapproved preview on %s without executing', async kind => {
        const mounted = await start(); await preview(); fireEvent.click(screen.getByRole('checkbox'));
        if (kind === 'close') fireEvent.click(screen.getByRole('button', { name: 'Close preview' }));
        if (kind === 'escape') fireEvent.keyDown(screen.getByRole('region', { name: 'Review service action' }), { key: 'Escape' });
        if (kind === 'pagehide' || kind === 'blur' || kind === 'hashchange' || kind === 'popstate') act(() => window.dispatchEvent(new Event(kind)));
        if (kind === 'auth') act(() => window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT)));
        if (kind === 'device') { vi.mocked(readServiceActions).mockResolvedValue({ ...actionView(), deviceId: `agent_${'e'.repeat(32)}` }); mounted.rerender(<Harness deviceId={`agent_${'e'.repeat(32)}`}/>); await flush(); }
        if (kind === 'unmount') mounted.unmount();
        expect(screen.queryByRole('button', { name: 'Approve try-restart' })).not.toBeInTheDocument(); expect(approveServiceAction).not.toHaveBeenCalled();
    });
    it('aborts delayed previews on close and ignores their eventual response', async () => {
        let finish!: (value: ServiceActionView) => void, signal!: AbortSignal;
        vi.mocked(previewServiceAction).mockImplementationOnce(async (_device, _unit, _access, supplied) => { signal = supplied; return new Promise(resolve => { finish = resolve; }); });
        await start(); fireEvent.click(screen.getByRole('button', { name: 'Select fixture' })); await flush(); fireEvent.click(screen.getByRole('button', { name: 'Close preview' })); expect(signal.aborted).toBe(true);
        await act(async () => finish({ ...actionView(), preview: actionPreview() })); expect(screen.queryByRole('checkbox')).not.toBeInTheDocument(); expect(approveServiceAction).not.toHaveBeenCalled();
    });
    it('ignores a superseded service response and resets consent for the selected service', async () => {
        let finish!: (value: ServiceActionView) => void;
        vi.mocked(previewServiceAction).mockImplementationOnce(async () => new Promise(resolve => { finish = resolve; }));
        await start(); fireEvent.click(screen.getByRole('button', { name: 'Select fixture' })); fireEvent.click(screen.getByRole('button', { name: 'Select fixture' })); expect(previewServiceAction).toHaveBeenCalledTimes(1);
        fireEvent.click(screen.getByRole('button', { name: 'Select other' })); await flush(); await act(async () => finish({ ...actionView(), preview: actionPreview() }));
        const review = screen.getByRole('region', { name: 'Review service action' }); expect(review).toHaveTextContent('other.service'); expect(review).not.toHaveTextContent('fixture.service'); expect(screen.getByRole('checkbox')).not.toBeChecked();
    });
    it('expires a preview on monotonic time and refuses an approval after a wall-clock jump', async () => {
        await start(); await preview(); fireEvent.click(screen.getByRole('checkbox'));
        await act(async () => { vi.advanceTimersByTime(61000); }); expect(screen.queryByRole('checkbox')).not.toBeInTheDocument(); expect(screen.getByRole('alert')).toHaveTextContent(/expired|time anchor/); expect(approveServiceAction).not.toHaveBeenCalled();
    });
    it('reads saved status after a lost approval response and never resubmits', async () => {
        vi.mocked(approveServiceAction).mockRejectedValueOnce(new Error('lost response'));
        await start(); await preview(); vi.mocked(readServiceActions).mockResolvedValue(actionJobView('claimed')); await approve();
        expect(readServiceActions).toHaveBeenCalledTimes(2); expect(approveServiceAction).toHaveBeenCalledTimes(1); expect(screen.getByText(/Claimed for delivery/)).toBeVisible(); expect(screen.getByRole('button', { name: 'Select other' })).toBeDisabled();
    });
    it('keeps an ambiguous approval locked when GET cannot yet find its job, including after reopen', async () => {
        vi.mocked(approveServiceAction).mockRejectedValueOnce(new InvalidServiceActionResponse());
        const mounted = await start(); await preview(); await approve(); expect(screen.getByRole('alert')).toHaveTextContent('Approval is unconfirmed'); expect(screen.getByRole('button', { name: 'Select fixture' })).toBeDisabled();
        mounted.unmount(); await start(); expect(screen.getByRole('alert')).toHaveTextContent('Approval is unconfirmed'); expect(screen.getByRole('button', { name: 'Select fixture' })).toBeDisabled(); expect(approveServiceAction).toHaveBeenCalledTimes(1);
    });
    it('treats an unavailable 409 after approval as uncertain until its saved job is found', async () => {
        vi.mocked(approveServiceAction).mockRejectedValueOnce(new APIError('execution not confirmed', 409));
        await start(); await preview(); await approve(); expect(screen.getByRole('alert')).toHaveTextContent('Approval is unconfirmed'); expect(screen.getByRole('button', { name: 'Select other' })).toBeDisabled(); expect(approveServiceAction).toHaveBeenCalledTimes(1);
    });
    it('times out an approval with a read-only status check rather than another approval', async () => {
        let signal!: AbortSignal;
        vi.mocked(approveServiceAction).mockImplementationOnce(async (_device, _preview, _access, supplied) => { signal = supplied; return new Promise(() => {}); });
        await start(); await preview(); await approve(); vi.mocked(readServiceActions).mockResolvedValue(actionJobView('claimed'));
        await act(async () => { vi.advanceTimersByTime(10000); }); expect(signal.aborted).toBe(true); expect(readServiceActions).toHaveBeenCalledTimes(2); expect(approveServiceAction).toHaveBeenCalledTimes(1); expect(screen.getByText(/Claimed for delivery/)).toBeVisible();
    });
    it('invalidates a preview on a wall-clock rollback and does not reuse consent on restoration', async () => {
        await start(); await preview(); fireEvent.click(screen.getByRole('checkbox')); vi.setSystemTime('2026-10-05T11:59:00Z');
        fireEvent.click(screen.getByRole('button', { name: 'Approve try-restart' })); await flush(); expect(approveServiceAction).not.toHaveBeenCalled(); expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();
        act(() => window.dispatchEvent(new Event('blur'))); act(() => window.dispatchEvent(new Event('focus'))); await flush(); expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();
    });
    it('reopens the saved job without restoring any saved preview or approval consent', async () => {
        vi.mocked(readServiceActions).mockResolvedValue({ ...actionView(), preview: actionPreview() }); const mounted = await start(); expect(screen.queryByRole('checkbox')).not.toBeInTheDocument(); mounted.unmount();
        vi.mocked(readServiceActions).mockResolvedValue(actionJobView('claimed')); await start(); expect(screen.getByText(/Claimed for delivery/)).toBeVisible(); expect(approveServiceAction).not.toHaveBeenCalled();
    });
    it('labels command completion as agent-reported with no health or restart proof', async () => {
        vi.mocked(readServiceActions).mockResolvedValue(actionJobView('operation_completed')); await start();
        expect(screen.getByText(/does not prove a restart or service health/)).toBeVisible(); expect(screen.getByText(/Agent-reported result: operation_completed/)).toBeVisible(); expect(screen.getByRole('button', { name: 'Select fixture' })).toBeEnabled();
    });
    it('blocks a needs-intervention result and polls only pending status for a bounded window', async () => {
        vi.mocked(readServiceActions).mockResolvedValue(actionJobView('claimed')); await start();
        for (let i = 0; i < 45; i++) await act(async () => { vi.advanceTimersByTime(3000); });
        const reads = vi.mocked(readServiceActions).mock.calls.length; expect(reads).toBeGreaterThan(1); expect(reads).toBeLessThanOrEqual(41);
        await act(async () => { vi.advanceTimersByTime(120000); }); expect(readServiceActions).toHaveBeenCalledTimes(reads); expect(screen.getByRole('button', { name: 'Select fixture' })).toBeDisabled();
        vi.mocked(readServiceActions).mockResolvedValue(actionJobView('needs_intervention')); fireEvent.click(screen.getByRole('button', { name: 'Check action status' })); await flush();
        expect(within(screen.getByRole('region', { name: 'Saved action' })).getByText(/Local investigation is required/)).toBeVisible(); expect(screen.getByRole('button', { name: 'Select fixture' })).toBeDisabled(); expect(approveServiceAction).not.toHaveBeenCalled();
    });
    it('fails closed on malformed status and revoked access', async () => {
        vi.mocked(readServiceActions).mockRejectedValueOnce(new InvalidServiceActionResponse()); await start(); expect(screen.getByRole('alert')).toHaveTextContent('inconsistent'); expect(screen.getByRole('button', { name: 'Select fixture' })).toBeDisabled();
        vi.mocked(readServiceActions).mockRejectedValueOnce(new APIError('revoked', 401)); fireEvent.click(screen.getByRole('button', { name: 'Check action status' })); await flush();
        expect(screen.getByRole('alert')).toHaveTextContent('access ended or changed'); const calls = vi.mocked(readServiceActions).mock.calls.length; act(() => window.dispatchEvent(new Event('focus'))); await flush(); expect(readServiceActions).toHaveBeenCalledTimes(calls);
    });
});
