import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, AUTH_REQUIRED_EVENT, mutate, request } from './api';
import { useOperator } from './auth';
import { DeviceDetail } from './details';
import { setLocale } from './i18n';
import { WindowsLogsPanel } from './windows-logs';
import { useWindowsInventory } from './windows-inventory-resource';
import { windowsDevice, windowsDeviceId, windowsNow } from './windows-inventory-fixture';
import { windowsEventsView } from './windows-events-fixture';
import { historyFixture } from './resource-history-fixture';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutate: vi.fn() }));
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
const operator = { mode: 'lan' as const, authenticated: true, expiresAt: '2026-10-07T13:00:00Z', insecureTestMode: false, logout: vi.fn(), theme: 'light' as const, setTheme: vi.fn() };
const flush = () => act(async () => {});
function answer(path: string) {
    const id = path.split('/')[2], device = { ...windowsDevice(), id }, view = { ...windowsEventsView(), deviceId: id };
    if (path === `/devices/${id}`) return device;
    if (path.endsWith('/windows-inventory')) return view;
    if (path.endsWith('/resource-history')) return { ...historyFixture(), deviceId: id };
    throw new Error('Unexpected fixture route');
}
function Harness() { return <WindowsLogsPanel resource={useWindowsInventory(windowsDeviceId, true, 'fixture')}/>; }
beforeEach(() => { abortProtectedRequests(); vi.useFakeTimers(); vi.setSystemTime(windowsNow); setLocale('en', false); vi.mocked(request).mockReset().mockImplementation(async path => answer(path)); vi.mocked(mutate).mockReset(); vi.mocked(useOperator).mockReturnValue(operator); });
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.restoreAllMocks(); });

describe('Windows Logs device navigation and existing read boundaries', () => {
    it('supports initial Logs, repeat selection, stable device metadata refresh and Health navigation without Linux calls', async () => {
        render(<main><DeviceDetail id={windowsDeviceId} onClose={vi.fn()} onCase={vi.fn()} initialTab="logs"/></main>); await flush();
        const logs = screen.getByRole('tab', { name: 'Logs' }); expect(logs).toHaveAttribute('aria-selected', 'true'); expect(screen.getByRole('region', { name: 'Windows logs' })).toBeVisible();
        const input = screen.getByLabelText('Provider'); fireEvent.change(input, { target: { value: 'Fixture' } }); input.focus(); const main = screen.getByRole('main'); main.scrollTop = 215;
        fireEvent.click(screen.getByRole('button', { name: 'Next' })); fireEvent.click(logs); fireEvent.click(logs);
        fireEvent.click(screen.getByRole('button', { name: 'Refresh device metadata' })); await flush();
        expect(screen.getByLabelText('Provider')).toBe(input); expect(input).toHaveValue('Fixture'); expect(input).toHaveFocus(); expect(main.scrollTop).toBe(215); expect(screen.getByText('Page 2 of 3 · 24 matching headers')).toBeVisible();
        fireEvent.keyDown(logs, { key: 'ArrowRight' }); expect(screen.getByRole('tab', { name: /Health/ })).toHaveFocus();
        fireEvent.click(screen.getByRole('button', { name: 'Open event headers in Logs' })); expect(logs).toHaveFocus(); expect(logs).toHaveAttribute('aria-selected', 'true'); expect(screen.getByLabelText('Provider')).toHaveValue('');
        expect(mutate).not.toHaveBeenCalled(); expect(vi.mocked(request).mock.calls.every(([path]) => path === `/devices/${windowsDeviceId}` || path.endsWith('/windows-inventory'))).toBe(true);
    });
    it('drops filters/pages on a different device or operator session', async () => {
        const ui = render(<DeviceDetail id={windowsDeviceId} onClose={vi.fn()} onCase={vi.fn()} initialTab="logs"/>); await flush();
        fireEvent.change(screen.getByLabelText('Provider'), { target: { value: 'Fixture' } }); fireEvent.click(screen.getByRole('button', { name: 'Next' }));
        const next = `agent_${'8'.repeat(32)}`; ui.rerender(<DeviceDetail id={next} onClose={vi.fn()} onCase={vi.fn()} initialTab="logs"/>); await flush();
        expect(screen.getByLabelText('Provider')).toHaveValue(''); expect(screen.getByText('Page 1 of 3 · 24 matching headers')).toBeVisible();
        fireEvent.change(screen.getByLabelText('Provider'), { target: { value: 'Fixture' } }); vi.mocked(useOperator).mockReturnValue({ ...operator, expiresAt: '2026-10-07T14:00:00Z' }); ui.rerender(<DeviceDetail id={next} onClose={vi.fn()} onCase={vi.fn()} initialTab="logs"/>); await flush();
        expect(screen.getByLabelText('Provider')).toHaveValue(''); expect(mutate).not.toHaveBeenCalled();
    });
    it('expires the actual resource at its original event capture age and does not show retained private rows', async () => {
        const value = windowsEventsView(); value.events.collectedAt = '2026-10-06T12:00:11Z'; vi.mocked(request).mockResolvedValue(value);
        render(<Harness/>); await flush(); expect(screen.getByRole('table')).toBeVisible(); fireEvent.change(screen.getByLabelText('Provider'), { target: { value: 'Fixture Provider A' } });
        await act(async () => vi.advanceTimersByTimeAsync(1001)); expect(screen.getByRole('status')).toHaveTextContent('Event sample expired.'); expect(screen.queryByRole('table')).toBeNull(); expect(screen.queryByText('Fixture Provider A')).toBeNull(); expect(screen.getByLabelText('Provider')).toHaveValue('');
        expect(mutate).not.toHaveBeenCalled();
    });
    it('clears rows on blur, ignores an interrupted response, and stays locked after session loss', async () => {
        render(<Harness/>); await flush(); expect(screen.getByRole('table')).toBeVisible();
        let resolve!: (value: ReturnType<typeof windowsEventsView>) => void;
        vi.mocked(request).mockReturnValueOnce(new Promise(done => { resolve = done; }));
        fireEvent.click(screen.getByRole('button', { name: 'Refresh sample' })); await flush();
        act(() => window.dispatchEvent(new Event('blur'))); await act(async () => resolve(windowsEventsView())); expect(screen.queryByRole('table')).toBeNull();
        act(() => window.dispatchEvent(new Event('focus'))); await flush(); expect(screen.getByRole('table')).toBeVisible();
        fireEvent.change(screen.getByLabelText('Provider'), { target: { value: 'Fixture' } }); act(() => window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT)));
        expect(screen.queryByRole('table')).toBeNull(); expect(screen.getByLabelText('Provider')).toHaveValue(''); expect(screen.getByRole('button', { name: 'Refresh sample' })).toBeDisabled();
        const calls = vi.mocked(request).mock.calls.length; act(() => window.dispatchEvent(new Event('focus'))); await flush(); expect(request).toHaveBeenCalledTimes(calls);
    });
    it.each(['message', 'xml', 'eventData', 'userData', 'userId', 'securityId'])('rejects unexpected private field %s before rendering', async field => {
        const value = windowsEventsView(); Object.assign(value.events.channels[0].rows[0], { [field]: 'private-fixture-do-not-display' }); vi.mocked(request).mockResolvedValue(value);
        render(<Harness/>); await flush(); expect(screen.queryByRole('table')).toBeNull(); expect(screen.getByRole('alert')).toHaveTextContent('Event headers unavailable'); expect(document.body).not.toHaveTextContent('private-fixture-do-not-display'); expect(mutate).not.toHaveBeenCalled();
    });
    it('rejects Security channel reuse rather than querying or showing it', async () => {
        const value = windowsEventsView(); Object.assign(value.events.channels[1], { channel: 'Security' }); vi.mocked(request).mockResolvedValue(value);
        render(<Harness/>); await flush(); expect(screen.queryByRole('table')).toBeNull(); expect(screen.getByRole('alert')).toHaveTextContent('Event headers unavailable'); expect(vi.mocked(request).mock.calls.map(([path]) => path)).toEqual([`/devices/${windowsDeviceId}/windows-inventory`]); expect(mutate).not.toHaveBeenCalled();
    });
});
