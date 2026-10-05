import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AUTH_REQUIRED_EVENT, mutateRaw, request } from './api';
import { useOperator } from './auth';
import { actionActor, actionDevice, actionDigest, actionJobView, actionNow, actionPreview, actionSession, actionSessionExpiry, actionView } from './service-action-fixtures';
import { SystemInventoryPanel } from './system-inventory';
import { serviceRows, systemPage, systemView } from './system-inventory-fixtures';
import { setLocale } from './i18n';
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutateRaw: vi.fn() }));
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
const operator = { mode: 'lan' as const, authenticated: true, loginMode: 'named' as const, actorId: actionActor, capabilities: ['read', 'restart_service'] as const, expiresAt: actionSessionExpiry, insecureTestMode: false, logout: vi.fn(), theme: 'light' as const, setTheme: vi.fn() };
const system = { ...systemView(3, 0), deviceId: actionDevice }, rows = serviceRows(3).map((row, n) => ({ ...row, name: ['fixture.service', 'other.service', 'unlisted.service'][n] }));
const flush = () => act(async () => {});
beforeEach(() => {
    vi.useFakeTimers(); vi.setSystemTime(actionNow); setLocale('en', false); localStorage.clear(); sessionStorage.clear(); vi.mocked(useOperator).mockReturnValue(operator);
    vi.mocked(request).mockReset().mockImplementation(async path => {
        if (path === '/auth/session') return actionSession;
        if (path.endsWith('/inventory/system')) return system;
        if (path.endsWith('/service-actions')) return actionView();
        throw new Error(`Unexpected path ${path}`);
    });
    vi.mocked(mutateRaw).mockReset().mockImplementation(async (path, raw) => {
        if (path.endsWith('/inventory/system/query')) return systemPage(system, rows, [], raw);
        if (path.endsWith('/service-actions/preview')) return { ...actionView(), preview: actionPreview(JSON.parse(raw).unit) };
        if (path.endsWith('/service-actions/approve')) return actionJobView();
        throw new Error(`Unexpected mutation ${path}`);
    });
});
afterEach(() => { act(() => window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT))); cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); });
describe('service table action integration', () => {
    it('opens exactly the selected allowlisted row and requires a separate approval', async () => {
        render(<SystemInventoryPanel deviceId={actionDevice} section="services"/>); await flush();
        expect(vi.mocked(mutateRaw).mock.calls.map(([path]) => path)).toEqual([`/devices/${actionDevice}/inventory/system/query`]);
        expect(screen.getByRole('button', { name: 'Preview try-restart: unlisted.service' })).toBeDisabled();
        const row = screen.getByRole('rowheader', { name: 'fixture.service' }).closest('tr')!;
        fireEvent.click(within(row).getByRole('button', { name: 'Preview try-restart: fixture.service' })); await flush();
        expect(vi.mocked(mutateRaw).mock.calls.at(-1)![0]).toBe(`/devices/${actionDevice}/service-actions/preview`); expect(JSON.parse(vi.mocked(mutateRaw).mock.calls.at(-1)![1])).toEqual({ unit: 'fixture.service' });
        expect(screen.getByRole('region', { name: 'Review service action' })).toHaveTextContent('fixture.service'); expect(screen.getByRole('checkbox')).not.toBeChecked();
        fireEvent.click(screen.getByRole('checkbox')); fireEvent.click(screen.getByRole('button', { name: 'Approve try-restart' })); await flush();
        expect(JSON.parse(vi.mocked(mutateRaw).mock.calls.at(-1)![1])).toEqual({ previewId: actionPreview().id, previewDigest: actionDigest }); expect(screen.getByText(/Execution is unconfirmed/)).toBeVisible();
    });
    it('does not add action requests or row controls for a shared operator', async () => {
        vi.mocked(useOperator).mockReturnValue({ ...operator, loginMode: 'shared', actorId: null, capabilities: ['read'] }); render(<SystemInventoryPanel deviceId={actionDevice} section="services"/>); await flush();
        expect(screen.getByText(/Service actions unavailable/)).toBeVisible(); expect(screen.queryByRole('button', { name: /Preview try-restart:/ })).not.toBeInTheDocument(); expect(vi.mocked(request).mock.calls.some(([path]) => path.includes('service-actions'))).toBe(false);
    });
    it('section navigation removes preview and never carries consent back', async () => {
        const mounted = render(<SystemInventoryPanel deviceId={actionDevice} section="services"/>); await flush(); fireEvent.click(screen.getByRole('button', { name: 'Preview try-restart: fixture.service' })); await flush(); fireEvent.click(screen.getByRole('checkbox'));
        mounted.rerender(<SystemInventoryPanel deviceId={actionDevice} section="sockets"/>); await flush(); expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();
        mounted.rerender(<SystemInventoryPanel deviceId={actionDevice} section="services"/>); await flush(); expect(screen.queryByRole('checkbox')).not.toBeInTheDocument(); expect(vi.mocked(mutateRaw).mock.calls.some(([path]) => path.endsWith('/approve'))).toBe(false);
    });
});
