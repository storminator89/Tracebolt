import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { abortProtectedRequests, AUTH_REQUIRED_EVENT } from './api';
import { setLocale } from './i18n';
import { fullServicesDevice, fullServicesNow, fullServicesPage } from './windows-full-services-fixtures';
import type { FullServicesQuery } from './windows-full-services-types';
import { completeHealthSession } from './windows-service-health-complete-fixture';
import { WindowsServiceHealthCompletePicker } from './windows-service-health-complete-picker';
import { windowsServiceHealthCompleteCopy } from './windows-service-health-complete-copy';
const flush = () => act(async () => { for (let i = 0; i < 16; i++) await Promise.resolve(); });
const reply = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status });
beforeEach(() => { abortProtectedRequests(); vi.useFakeTimers(); vi.setSystemTime(fullServicesNow); });
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.unstubAllGlobals(); vi.restoreAllMocks(); setLocale('de', false); });
function setup(locale: 'en' | 'de', mode = 'ready') {
    setLocale(locale, false); const queries: FullServicesQuery[] = [];
    vi.stubGlobal('fetch', vi.fn(async (path: string, init?: RequestInit) => {
        if (path === '/api/session') return reply({ csrfToken: 'synthetic-only' });
        if (path.endsWith('/windows-full-services/query')) {
            const query = JSON.parse(String(init?.body)) as FullServicesQuery; queries.push(query);
            if (mode === 'timeout') return new Promise<Response>(() => {});
            if (mode === 'busy') return reply({ error: { code: 'busy' } }, 429);
            if (mode === 'unavailable') throw new Error('PRIVATE-ERROR-DO-NOT-SHOW');
            return reply(fullServicesPage(query));
        }
        throw new Error('Unexpected path');
    }));
    const evidence = vi.fn(), change = vi.fn();
    render(<WindowsServiceHealthCompletePicker deviceId={fullServicesDevice} sessionKey={completeHealthSession} enabled disabled={false} selected={[]} onChange={change} onEvidence={evidence} c={windowsServiceHealthCompleteCopy[locale]}/>);
    return { queries, evidence, change };
}
it.each(['en', 'de'] as const)('associates UTF-8 input errors and clears after correction (%s)', async locale => {
    const s = setup(locale); await flush(); const input = screen.getByRole('searchbox');
    fireEvent.change(input, { target: { value: 'ä'.repeat(129) } }); const count = s.queries.length;
    fireEvent.keyDown(input, { key: 'Enter' }); await flush();
    expect(input).toHaveAttribute('aria-invalid', 'true'); expect(input).toHaveAccessibleDescription(/256 UTF-8/);
    expect(s.queries).toHaveLength(count); expect(s.change).not.toHaveBeenCalled(); expect(s.evidence).toHaveBeenLastCalledWith(null);
    fireEvent.change(input, { target: { value: 'ä'.repeat(128) } }); expect(input).not.toHaveAttribute('aria-invalid');
    fireEvent.keyDown(input, { key: 'Enter' }); await flush(); expect(s.queries).toHaveLength(count + 1); expect(s.queries.at(-1)?.search).toBe('ä'.repeat(128));
});
it.each(['en', 'de'] as const)('distinguishes timeout without rows or selection (%s)', async locale => {
    const s = setup(locale, 'timeout'); await flush(); await act(async () => { vi.advanceTimersByTime(10000); }); await flush();
    expect(screen.getByText(locale === 'en' ? 'The service request timed out. Try again.' : 'Die Dienstanfrage hat das Zeitlimit überschritten. Erneut versuchen.')).toBeVisible();
    expect(screen.getByRole('searchbox')).not.toHaveAttribute('aria-invalid'); expect(document.querySelector('.windows-service-options')).toBeNull(); expect(s.change).not.toHaveBeenCalled(); expect(s.queries).toHaveLength(1);
});
it.each(['en', 'de'] as const)('distinguishes expiry and hides rows (%s)', async locale => {
    const s = setup(locale); await flush(); expect(document.querySelector('.windows-service-options')).not.toBeNull();
    await act(async () => { vi.advanceTimersByTime(16 * 60 * 1000); }); await flush();
    expect(screen.getByText(locale === 'en' ? 'The original source, access or paging deadline expired. Review the latest generation again.' : 'Die ursprüngliche Quellen-, Zugriffs- oder Seitenfrist ist abgelaufen. Neueste Generation erneut prüfen.')).toBeVisible();
    expect(document.querySelector('.windows-service-options')).toBeNull(); expect(s.evidence).toHaveBeenLastCalledWith(null); expect(s.queries).toHaveLength(1);
});
it('preserves privacy on blur without background queries', async () => {
    const s = setup('en'); await flush(); fireEvent(window, new Event('blur')); await flush();
    expect(document.querySelector('.windows-service-options')).toBeNull(); expect(s.evidence).toHaveBeenLastCalledWith(null); expect(s.queries).toHaveLength(1); expect(s.change).not.toHaveBeenCalled();
});
it.each(['busy', 'unavailable'])('does not claim a generation change for %s', async mode => {
    const s = setup('en', mode); await flush(); expect(screen.getByText(mode === 'busy' ? 'The manager is busy. Try again in a moment.' : 'Service rows could not be read. Try again.')).toBeVisible();
    expect(screen.queryByText(/PRIVATE-ERROR/)).toBeNull(); expect(document.querySelector('.windows-service-options')).toBeNull(); expect(s.queries).toHaveLength(1);
});

it.each(['en', 'de'] as const)('describes session invalidation without assuming logout (%s)', async locale => {
    const s = setup(locale); await flush(); fireEvent(window, new Event(AUTH_REQUIRED_EVENT)); await flush();
    expect(screen.getByText(locale === 'en' ? 'The session changed or could not be verified. Sign in again.' : 'Die Sitzung wurde geändert oder konnte nicht bestätigt werden. Erneut anmelden.')).toBeVisible();
    expect(document.querySelector('.windows-service-options')).toBeNull(); expect(s.evidence).toHaveBeenLastCalledWith(null); expect(s.queries).toHaveLength(1);
});
it('handles protected request epoch changes without claiming logout', async () => {
    const s = setup('en'); await flush();
    await act(async () => { abortProtectedRequests(); vi.advanceTimersByTime(250); }); await flush();
    expect(screen.getByText('The session changed or could not be verified. Sign in again.')).toBeVisible();
    expect(document.querySelector('.windows-service-options')).toBeNull(); expect(s.evidence).toHaveBeenLastCalledWith(null); expect(s.queries).toHaveLength(1);
});
