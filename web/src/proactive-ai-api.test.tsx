import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { abortProtectedRequests } from './api';
import { useOperator } from './auth';
import { setLocale } from './i18n';
import { ProactiveAISettingsPanel } from './proactive-ai';

vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
const id = 'agent_00000000000000000000000000000001';
const settings = { schemaVersion: 'tracebolt.proactive-ai-settings.v1', revision: 'revision-a', enabled: false, configRevision: 'config-a', providerConfigured: true, baseURL: 'http://127.0.0.1:11434/v1', model: 'fixture-model', deviceIds: [], availableDevices: [{ id }], dataScope: 'health-summary-v1', logsAllowed: false, resetsOnRestart: true, maxAnalysesPerHour: 6, cooldownMinutes: 30, minIntervalSeconds: 60, reason: 'disabled' };
const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status });
beforeEach(() => { setLocale('en', false); localStorage.clear(); sessionStorage.clear(); vi.mocked(useOperator).mockReturnValue({ mode: 'lan', authenticated: true, loginMode: 'shared', expiresAt: null, insecureTestMode: false, logout: vi.fn(), theme: 'light', setTheme: vi.fn() }); });
afterEach(() => { cleanup(); abortProtectedRequests(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });
async function review() { await screen.findByText('Off'); fireEvent.click(screen.getByRole('button', { name: 'Proactive AI diagnostics' })); fireEvent.click(screen.getByRole('checkbox', { name: id })); fireEvent.click(screen.getByRole('checkbox', { name: /I approve future health-summary/ })); }
it('sends only the explicitly approved scope using same-origin CSRF and no provider request', async () => {
    const fetch = vi.fn().mockImplementation((path: string, options: RequestInit) => Promise.resolve(path === '/api/session' ? json({ csrfToken: 'fixture-csrf' }) : options?.method === 'POST' ? json({ ...settings, revision: 'revision-b', enabled: true, deviceIds: [id] }) : json(settings)));
    vi.stubGlobal('fetch', fetch); render(<ProactiveAISettingsPanel/>); await review(); expect(fetch).toHaveBeenCalledTimes(1);
    const button = screen.getByRole('button', { name: 'Approve and enable' }); fireEvent.click(button); fireEvent.click(button); await screen.findByText('Settings saved. No connectivity test was sent.');
    expect(fetch.mock.calls.map(([path]) => path)).toEqual(['/api/ai/proactive', '/api/session', '/api/ai/proactive']);
    const options = fetch.mock.calls[2][1]; expect(options).toMatchObject({ method: 'POST', credentials: 'same-origin', headers: { 'X-CSRF-Token': 'fixture-csrf', 'Content-Type': 'application/json' } });
    expect(JSON.parse(options.body as string)).toEqual({ expectedRevision: 'revision-a', configRevision: 'config-a', enabled: true, deviceIds: [id], approvedBaseURL: settings.baseURL, approvedModel: settings.model, dataScope: 'health-summary-v1', acknowledgeData: true });
});
it('never POSTs when the session changes during the real CSRF read', async () => {
    let finish!: (response: Response) => void;
    const fetch = vi.fn().mockImplementation((path: string) => path === '/api/session' ? new Promise<Response>(resolve => { finish = resolve; }) : Promise.resolve(json(settings)));
    vi.stubGlobal('fetch', fetch); render(<ProactiveAISettingsPanel/>); await review(); fireEvent.click(screen.getByRole('button', { name: 'Approve and enable' })); await waitFor(() => expect(finish).toBeDefined());
    act(() => abortProtectedRequests()); await act(async () => finish(json({ csrfToken: 'stale-csrf' }))); expect(fetch.mock.calls.every(([, options]) => options?.method !== 'POST')).toBe(true); expect(screen.queryByText('Settings saved. No connectivity test was sent.')).not.toBeInTheDocument();
});
it('rejects an oversized settings stream and makes no mutation', async () => {
    let canceled = false;
    const fetch = vi.fn().mockResolvedValue(new Response(new ReadableStream({ start(controller) { controller.enqueue(new TextEncoder().encode(' '.repeat(16385))); }, cancel() { canceled = true; } })));
    vi.stubGlobal('fetch', fetch); render(<ProactiveAISettingsPanel/>); await screen.findByRole('alert'); expect(canceled).toBe(true); expect(fetch).toHaveBeenCalledTimes(1); expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();
});
