import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, AUTH_REQUIRED_EVENT } from './api';
import { setLocale } from './i18n';
import { actionAccess, actionDevice, actionNow, actionView } from './service-action-fixtures';
import { actionHistory, completedActionHistory } from './service-action-history-fixtures';
import { readServiceActionHistory } from './service-action-history-api';
import { ServiceActionHistoryPanel } from './service-action-history';
import { ServiceActionPanel } from './service-actions';
import type { useServiceActions } from './service-action-resource';
import type { ServiceActionHistory } from './service-action-history-types';
vi.mock('./service-action-history-api', () => ({ readServiceActionHistory: vi.fn() }));
const flush = () => act(async () => {});
const open = async () => { fireEvent.click(screen.getByRole('button', { name: 'Saved service-action history' })); await flush(); };
function mount() { return render(<ServiceActionHistoryPanel deviceId={actionDevice} access={actionAccess}/>); }
beforeEach(() => { vi.useFakeTimers(); vi.setSystemTime(actionNow); localStorage.clear(); sessionStorage.clear(); setLocale('en', false); vi.mocked(readServiceActionHistory).mockReset().mockResolvedValue(completedActionHistory()); });
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.restoreAllMocks(); });
describe('deliberate retained Linux action investigation', () => {
    it('is integrated only into the authorized Linux service-action workflow and reads on demand', async () => {
        const workflow: ReturnType<typeof useServiceActions> = { historyAccess: { deviceId: actionDevice, access: actionAccess }, view: actionView(), preview: null, selected: null, loading: null, error: null, unresolved: false, canSelect: vi.fn(), select: vi.fn(), approve: vi.fn(), close: vi.fn(), refresh: vi.fn() };
        const mounted = render(<ServiceActionPanel workflow={workflow} authorized={false}/>); expect(screen.queryByRole('button', { name: 'Saved service-action history' })).not.toBeInTheDocument();
        mounted.rerender(<ServiceActionPanel workflow={workflow} authorized/>); expect(readServiceActionHistory).not.toHaveBeenCalled(); await open(); expect(readServiceActionHistory).toHaveBeenCalledTimes(1);
        mounted.rerender(<ServiceActionPanel workflow={{ ...workflow, error: 'session' }} authorized/>); expect(screen.queryByText(/command completion/)).not.toBeInTheDocument(); expect(screen.queryByRole('button', { name: 'Close history' })).not.toBeInTheDocument();
    });
    it('opens one read, investigates exact saved receipts, closes and never polls or performs actions', async () => {
        mount(); expect(readServiceActionHistory).not.toHaveBeenCalled(); await open(); expect(readServiceActionHistory).toHaveBeenCalledTimes(1);
        expect(screen.getByText(/Agent reports command completion/)).toBeVisible(); fireEvent.click(screen.getByRole('button', { name: 'Read receipt #1' }));
        expect(screen.getByText('Delivery claimed:')).toBeVisible(); expect(screen.getAllByText('Manager received agent report:')).toHaveLength(3); expect(screen.getByText(/not native start or completion times/)).toBeVisible();
        expect(screen.queryByRole('checkbox')).not.toBeInTheDocument(); expect(screen.queryByRole('button', { name: /approve|restart|retry/i })).not.toBeInTheDocument();
        await act(async () => { vi.advanceTimersByTime(30000); }); expect(readServiceActionHistory).toHaveBeenCalledTimes(1);
        fireEvent.click(screen.getByRole('button', { name: 'Close receipt #1' })); expect(screen.queryByText('Delivery claimed:')).not.toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', { name: 'Close history' })); expect(screen.queryByText(/command completion/)).not.toBeInTheDocument();
    });
    it('distinguishes no saved approval from missing reports and a pending claim', async () => {
        vi.mocked(readServiceActionHistory).mockResolvedValue({ ...actionHistory(), jobs: [] }); const mounted = mount(); await open(); expect(screen.getByText('No saved service-action approvals.')).toBeVisible(); mounted.unmount();
        vi.mocked(readServiceActionHistory).mockResolvedValue(actionHistory()); mount(); await open(); fireEvent.click(screen.getByRole('button', { name: 'Read receipt #1' })); expect(screen.getByText('No delivery claim recorded.')).toBeVisible(); expect(screen.getByText('No agent result report received.')).toBeVisible();
    });
    it('shows full-capacity history without offering another approval', async () => {
        const h = completedActionHistory(), row = h.jobs[0]; h.jobs = Array.from({ length: 64 }, (_, n) => ({ ...structuredClone(row), sequence: String(64 - n), job: { ...row.job, id: `action_${(n + 1).toString(16).padStart(32, '0')}` } })); vi.mocked(readServiceActionHistory).mockResolvedValue(h); mount(); await open(); expect(screen.getByText(/All 64 retained approval slots/)).toBeVisible(); expect(screen.getAllByRole('button', { name: /Read receipt/ })).toHaveLength(64);
    });
    it.each(['pagehide', 'blur', 'hashchange', 'popstate', AUTH_REQUIRED_EVENT] as const)('clears rows and aborts a delayed read on %s', async event => {
        let finish!: (value: ServiceActionHistory) => void, signal!: AbortSignal;
        vi.mocked(readServiceActionHistory).mockImplementationOnce(async (_device, _access, supplied) => { signal = supplied; return new Promise(resolve => { finish = resolve; }); }); mount(); await open(); act(() => window.dispatchEvent(new Event(event))); expect(signal.aborted).toBe(true);
        await act(async () => finish(completedActionHistory())); expect(screen.queryByText(/command completion/)).not.toBeInTheDocument(); expect(screen.getByRole('alert')).toHaveTextContent(/interrupted/);
    });
    it('requires deliberate refresh after focus returns and never restores old receipts', async () => {
        mount(); await open(); act(() => window.dispatchEvent(new Event('blur'))); expect(screen.queryByText(/command completion/)).not.toBeInTheDocument(); expect(screen.getByRole('button', { name: 'Refresh history' })).toBeDisabled(); act(() => window.dispatchEvent(new Event('focus'))); expect(screen.getByRole('button', { name: 'Refresh history' })).not.toBeDisabled(); expect(readServiceActionHistory).toHaveBeenCalledTimes(1);
        const h = completedActionHistory(); h.serverNow = '2026-10-05T12:00:11Z'; vi.mocked(readServiceActionHistory).mockResolvedValue(h); fireEvent.click(screen.getByRole('button', { name: 'Refresh history' })); await flush(); expect(readServiceActionHistory).toHaveBeenCalledTimes(2); expect(screen.getByText(/Agent reports command completion/)).toBeVisible();
    });
    it('clears synchronously when device or exact session changes', async () => {
        const mounted = mount(); await open(); mounted.rerender(<ServiceActionHistoryPanel deviceId={`agent_${'f'.repeat(32)}`} access={actionAccess}/>); expect(screen.queryByText(/command completion/)).not.toBeInTheDocument(); expect(screen.getByRole('button', { name: 'Saved service-action history' })).toHaveAttribute('aria-expanded', 'false'); expect(readServiceActionHistory).toHaveBeenCalledTimes(1);
        await open(); mounted.rerender(<ServiceActionHistoryPanel deviceId={actionDevice} access={{ ...actionAccess, sessionKey: '2026-10-05T14:00:00Z' }}/>); expect(screen.queryByText(/command completion/)).not.toBeInTheDocument();
    });
    it('expires status after its original snapshot lifetime without another request', async () => {
        mount(); await open(); await act(async () => { vi.advanceTimersByTime(60000); }); expect(screen.queryByText(/command completion/)).not.toBeInTheDocument(); expect(screen.getByRole('alert')).toHaveTextContent(/expired/); expect(readServiceActionHistory).toHaveBeenCalledTimes(1);
    });
    it('bounds display by exact session expiry rather than the full minute', async () => {
        const h = actionHistory(); h.serverNow = '2026-10-05T12:59:59Z'; vi.mocked(readServiceActionHistory).mockResolvedValue(h); mount(); await open(); await act(async () => { vi.advanceTimersByTime(1000); }); expect(screen.queryByText('fixture.service')).not.toBeInTheDocument(); expect(screen.getByRole('alert')).toHaveTextContent(/expired/);
    });
    it.each(['same-time', 'slower-clock', 'identity', 'key', 'clock-rollback'] as const)('rejects %s refresh without renewing retained evidence', async kind => {
        mount(); await open(); await act(async () => { vi.advanceTimersByTime(5000); }); const h = completedActionHistory();
        h.serverNow = kind === 'same-time' ? h.serverNow : '2026-10-05T12:00:11Z';
        if (kind === 'identity') h.incarnationDigest = `sha256:${'f'.repeat(64)}`;
        if (kind === 'key') h.keyId = `sha256:${'f'.repeat(64)}`;
        if (kind === 'clock-rollback') vi.setSystemTime('2026-10-05T11:59:00Z');
        vi.mocked(readServiceActionHistory).mockResolvedValue(h); fireEvent.click(screen.getByRole('button', { name: 'Refresh history' })); await flush(); expect(screen.queryByText(/command completion/)).not.toBeInTheDocument(); expect(screen.getByRole('alert')).toHaveTextContent(/unavailable|expired/);
    });
    it('times out and ignores a response that completes after Close and reopen', async () => {
        let finish!: (value: ServiceActionHistory) => void;
        vi.mocked(readServiceActionHistory).mockImplementationOnce(async () => new Promise(resolve => { finish = resolve; })); mount(); await open(); await act(async () => { vi.advanceTimersByTime(10000); }); expect(screen.getByRole('alert')).toHaveTextContent(/unavailable/); await act(async () => finish(completedActionHistory())); expect(screen.queryByText(/command completion/)).not.toBeInTheDocument();
    });
    it('renders German workflow and inert labels', async () => {
        setLocale('de', false); const h = completedActionHistory(); h.jobs[0].job.unit = '<img src=x onerror=alert(1)>.service'; vi.mocked(readServiceActionHistory).mockResolvedValue(h); const { container } = mount(); fireEvent.click(screen.getByRole('button', { name: 'Gespeicherte Dienstaktionshistorie' })); await flush(); expect(screen.getByText(/Neustart und Dienstzustand unbestätigt/)).toBeVisible(); expect(container.querySelector('img')).toBeNull(); fireEvent.click(screen.getByRole('button', { name: 'Beleg lesen #1' })); expect(screen.getByText(/keine nativen Start- oder Abschlusszeiten/)).toBeVisible();
    });
});
