import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, AUTH_REQUIRED_EVENT, mutate, request } from './api';
import { useOperator } from './auth';
import { DeviceDetail } from './details';
import { setLocale } from './i18n';
import { fullDate } from './utils';
import type { Quality } from './types';
import { windowsDevice, windowsDeviceId, windowsNow, windowsView } from './windows-inventory-fixture';
import { historyFixture } from './resource-history-fixture';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutate: vi.fn() }));
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
const source = 'ntdll.RtlGetVersion; numeric NT version and build';
const originalAt = '2026-10-07T11:59:59.999Z';
const detail = 'NT major/minor/build only, without inferring a marketing release or edition. Application compatibility can affect RtlGetVersion. nativeVerification: target-acceptance-unverified.';
function device(quality: Quality) {
    const value = windowsDevice();
    value.status = 'unknown';
    value.os = quality === 'unknown' || quality === 'denied' ? 'Windows (version unavailable)' : 'Windows NT 10.0 (build 26100)';
    value.evidence = [{ id: 'local-windows-os', title: 'Windows NT version', source, quality, collectedAt: originalAt, detail, value: value.os, synthetic: false }];
    return value;
}
const operator = { mode: 'lan' as const, authenticated: true, expiresAt: '2026-10-07T13:00:00Z', insecureTestMode: false, logout: vi.fn(), theme: 'light' as const, setTheme: vi.fn() };
let current = device('healthy');
const flush = () => act(async () => {});
beforeEach(() => {
    vi.useFakeTimers(); vi.setSystemTime(windowsNow); localStorage.clear(); sessionStorage.clear(); setLocale('en', false);
    current = device('healthy'); vi.mocked(useOperator).mockReturnValue(operator); vi.mocked(mutate).mockReset();
    const history = historyFixture(); history.deviceId = windowsDeviceId;
    vi.mocked(request).mockReset().mockImplementation(async path => {
        if (path === `/devices/${windowsDeviceId}`) return current;
        if (path === `/devices/${windowsDeviceId}/windows-inventory`) return windowsView();
        if (path === `/devices/${windowsDeviceId}/resource-history`) return history;
        throw new Error('Unexpected fixture route');
    });
});
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.restoreAllMocks(); });

describe('existing Windows OS evidence in the shared device view', () => {
    for (const locale of ['en', 'de'] as const) {
        it.each(['healthy', 'stale', 'unknown', 'denied'] as const)(`retains source, original capture and %s quality in ${locale}`, async quality => {
            setLocale(locale, false); current = device(quality);
            render(<DeviceDetail id={windowsDeviceId} onClose={vi.fn()} onCase={vi.fn()}/>); await flush();
            fireEvent.click(screen.getByRole('tab', { name: locale === 'de' ? /Belege/ : /Evidence/ })); await flush();
            const card = document.querySelector<HTMLElement>('#evidence-local-windows-os')!;
            expect(card).not.toBeNull(); expect(within(card).getByText(source)).toBeVisible();
            expect(card.querySelector(`.quality-${quality}`)).not.toBeNull();
            fireEvent.click(within(card).getByText('Windows NT version'));
            expect(within(card).getByText(current.os)).toBeVisible();
            expect(within(card).getByText(detail)).toBeVisible();
            expect(within(card).getByText(fullDate(originalAt))).toBeVisible();
            expect(screen.queryByRole('tab', { name: /CVE|Security coverage|Sicherheitsabdeckung/ })).toBeNull();
            expect(vi.mocked(request).mock.calls.every(([path]) => path === `/devices/${windowsDeviceId}` || path.endsWith('/windows-inventory') || path.endsWith('/resource-history'))).toBe(true);
            expect(mutate).not.toHaveBeenCalled();
        });
    }
    it('replaces successful OS evidence with denial and clears it when operator access ends', async () => {
        render(<DeviceDetail id={windowsDeviceId} onClose={vi.fn()} onCase={vi.fn()}/>); await flush();
        fireEvent.click(screen.getByRole('tab', { name: /Evidence/ })); await flush();
        current = device('denied');
        fireEvent.click(screen.getByRole('button', { name: 'Refresh device metadata' })); await flush();
        const card = document.querySelector<HTMLElement>('#evidence-local-windows-os')!;
        expect(card.querySelector('.quality-denied')).not.toBeNull();
        expect(card.textContent).not.toContain('Windows NT 10.0 (build 26100)');
        expect(card.textContent).toContain('Windows (version unavailable)');
        expect(card.textContent).toContain(fullDate(originalAt));
        act(() => window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT))); await flush();
        expect(document.querySelector('#evidence-local-windows-os')).toBeNull();
        expect(document.body).not.toHaveTextContent(source);
        expect(mutate).not.toHaveBeenCalled();
    });
});
