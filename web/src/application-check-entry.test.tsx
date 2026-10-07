import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import App from './App';
import { abortProtectedRequests } from './api';
import { journalNow, journalSession } from './journal-fixtures';
import { disabledApplicationViewV2 } from './application-checks-v2-fixtures';
import { setLocale } from './i18n';
const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status });
const settings = { schemaVersion: 'tracebolt.application-check-settings.v1', mode: 'managed', revision: 'a'.repeat(32), configured: false, enabled: false, blocked: false, intervalSeconds: 60, targets: [] };
function server() {
    const fetch = vi.fn(async (url: string, init?: RequestInit) => {
        if (init?.method && init.method !== 'GET') throw new Error('Entry must never mutate');
        if (url === '/api/auth/session') return json(journalSession);
        if (url === '/api/overview') return json({ generatedAt: journalNow, stats: { totalDevices: 0, healthyDevices: 0, attentionDevices: 0, openCases: 0, criticalCases: 0 }, devices: [], cases: [], activity: [] });
        if (url === '/api/application-checks/status') return json(disabledApplicationViewV2());
        if (url === '/api/application-checks/settings') return json(settings);
        return json({}, 503);
    }); vi.stubGlobal('fetch', fetch); return fetch;
}
beforeEach(() => { localStorage.clear(); sessionStorage.clear(); setLocale('en', false); window.history.replaceState({}, '', '/#/overview'); vi.spyOn(document, 'hasFocus').mockReturnValue(true); });
afterEach(() => { cleanup(); abortProtectedRequests(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });
const route = (hash: string) => act(() => { window.history.replaceState({}, '', `/${hash}`); window.dispatchEvent(new Event('hashchange')); });

it.each(['en', 'de'] as const)('opens actual setup from the %s Overview CTA without any save or activation', async locale => {
    setLocale(locale, false); const fetch = server(); render(<App/>);
    const link = await screen.findByRole('link', { name: locale === 'de' ? 'Prüfung hinzufügen' : 'Add check' });
    expect(link).toHaveAttribute('href', '#/settings/application-checks'); expect(link.closest('section')).toHaveTextContent('https://example.org/health · DNS: example.org · Port: example.org:443');
    expect(fetch.mock.calls.some(([url]) => url === '/api/application-checks/settings')).toBe(false);
    const frame = document.querySelector('.app-shell'); fireEvent.click(link);
    const id = locale === 'de' ? 'Ziel-ID' : 'Target ID', url = await screen.findByRole('textbox', { name: 'URL' });
    expect(window.location.hash).toBe('#/settings/application-checks'); expect(document.querySelector('.app-shell')).toBe(frame);
    expect(url).toHaveValue(''); await waitFor(() => expect(screen.getByRole('textbox', { name: id })).toHaveFocus());
    const panel = document.querySelector('.application-check-settings') as HTMLElement;
    expect(within(panel).getByRole('checkbox')).not.toBeChecked(); expect(within(panel).getByRole('button', { name: locale === 'de' ? 'Anwendungsprüfungen einrichten' : 'Application check setup' })).toHaveAttribute('aria-expanded', 'true');
    expect(fetch.mock.calls.filter(([path]) => path === '/api/application-checks/settings')).toHaveLength(1);
    expect(fetch.mock.calls.every(([, init]) => !init?.method || init.method === 'GET')).toBe(true);
    fireEvent.change(url, { target: { value: 'https://unsaved.example.test/health' } });
    route('#/settings'); await waitFor(() => expect(document.querySelector('.application-check-settings input')).toBeNull());
    expect(screen.getByRole('button', { name: locale === 'de' ? 'Anwendungsprüfungen einrichten' : 'Application check setup' })).toHaveAttribute('aria-expanded', 'false');
    route('#/settings/application-checks'); expect(await screen.findByRole('textbox', { name: 'URL' })).toHaveValue('');
    expect(document.querySelector('.app-shell')).toBe(frame); expect(fetch.mock.calls.filter(([path]) => path === '/api/auth/session')).toHaveLength(1);
    expect(fetch.mock.calls.every(([, init]) => !init?.method || init.method === 'GET')).toBe(true);
});
