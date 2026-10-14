import { act, cleanup, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { abortProtectedRequests, hasPendingAPIRequests, request } from './api';
import { useOperator } from './auth';
import { DeviceDetail } from './details';
import { emptyEndpointView } from './endpoint-identity-fixtures';
import { historyFixture, historyDevice, historyNow } from './resource-history-fixture';
import { setLocale } from './i18n';
import type { Device, Metric } from './types';
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), hasPendingAPIRequests: vi.fn(), request: vi.fn() }));
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
const session = '2026-10-07T14:00:00Z';
function device(): Device {
    const metric: Metric = { value: 38, unit: '%', quality: 'healthy', source: 'Synthetic render fixture', collectedAt: historyNow };
    return { id: historyDevice, name: 'Synthetic render fixture', platform: 'linux', os: 'Linux fixture', site: 'Fixture', group: 'Fixture', ip: null, status: 'unknown', source: 'lan', synthetic: false, lastSeen: historyNow, agentVersion: 'fixture', cpu: metric, memory: { ...metric }, disk: { ...metric }, uptime: '', tags: [], capabilities: [], evidence: [], trend: [], caseIds: [], agentCertificate: { source: 'guided-enrollment', checkedAt: historyNow, expiresAt: session } };
}
beforeEach(() => {
    vi.useFakeTimers(); vi.setSystemTime(historyNow); localStorage.clear(); sessionStorage.clear(); setLocale('en', false);
    vi.mocked(useOperator).mockReturnValue({ mode: 'lan', authenticated: true, expiresAt: session, insecureTestMode: false, logout: vi.fn(), theme: 'light', setTheme: vi.fn() });
    vi.mocked(hasPendingAPIRequests).mockReset().mockReturnValue(false);
    vi.mocked(request).mockReset().mockImplementation(async path => {
        if (path === `/devices/${historyDevice}`) return device();
        if (path.endsWith('/inventory/endpoint-identity')) return { ...emptyEndpointView(), deviceId: historyDevice };
        if (path.endsWith('/resource-history')) return historyFixture();
        throw new Error('Unused synthetic overview source');
    });
});
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.restoreAllMocks(); });
it('does not rebuild chart axes during actual device metadata age ticks and still clears on blur', async () => {
    const NativeDateTimeFormat = Intl.DateTimeFormat;
    const formats = vi.spyOn(Intl, 'DateTimeFormat').mockImplementation(function (...args: Parameters<typeof Intl.DateTimeFormat>) { return new NativeDateTimeFormat(...args); } as typeof Intl.DateTimeFormat);
    render(<DeviceDetail id={historyDevice} onClose={vi.fn()} onCase={vi.fn()}/>); await act(async () => {});
    expect(screen.getAllByRole('img')).toHaveLength(3);
    const axisCalls = () => formats.mock.calls.filter(([, options]) => options?.hour === '2-digit' && options.minute === '2-digit' && Object.keys(options).length === 2);
    expect(axisCalls()).toHaveLength(15); formats.mockClear();
    for (let tick = 0; tick < 10; tick++) await act(async () => { await vi.advanceTimersByTimeAsync(1000); });
    expect(axisCalls()).toHaveLength(0); expect(screen.getAllByRole('img')).toHaveLength(3);
    expect(vi.mocked(request).mock.calls.filter(([path]) => path.endsWith('/resource-history'))).toHaveLength(1);
    act(() => window.dispatchEvent(new Event('blur')));
    expect(screen.queryByRole('img')).toBeNull(); expect(document.querySelector('.resource-chart-line')).toBeNull();
});
