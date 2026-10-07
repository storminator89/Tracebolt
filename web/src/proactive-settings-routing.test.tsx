import type { ReactNode } from 'react';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import App from './App';
import { abortProtectedRequests, request } from './api';
import { useOperator } from './auth';
import { setLocale } from './i18n';
import { endpointDevice, endpointView } from './endpoint-identity-fixtures';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn() }));
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn(), AuthBoundary: ({ children }: { children: ReactNode }) => children }));
vi.mock('./ai', () => ({ AIProviderSettings: () => null }));
vi.mock('./alarm-status', () => ({ AlarmStatusPanel: () => null }));
vi.mock('./alarm-settings', () => ({ AlarmSettingsPanel: () => null }));
vi.mock('./application-check-settings', () => ({ ApplicationCheckSettingsPanel: () => null }));
vi.mock('./security-coverage', () => ({ OfflineCatalogPanel: () => null }));
beforeEach(() => {
    localStorage.clear(); sessionStorage.clear(); setLocale('en', false); history.replaceState(null, '', '#/settings');
    vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('visible');
    vi.mocked(useOperator).mockReturnValue({ mode: 'lan', authenticated: true, loginMode: 'shared', expiresAt: null, insecureTestMode: false, logout: vi.fn(), theme: 'light', setTheme: vi.fn() });
    vi.mocked(request).mockReset();
});
afterEach(() => { cleanup(); abortProtectedRequests(); history.replaceState(null, '', '/'); vi.restoreAllMocks(); });
it('reuses the App fleet hook on Settings and preserves metadata without another read after equivalent-hash navigation', async () => {
    vi.mocked(request).mockImplementation(async path => {
        if (path === '/overview') return { devices: [], cases: [], stats: {}, activity: [], generatedAt: endpointView().serverNow };
        if (path === '/capabilities') return { limitations: [] };
        if (path === '/fleet/endpoint-identities') return { schemaVersion: 'tracebolt.fleet-endpoint-identity.v1', serverNow: endpointView().serverNow, items: [endpointView()] };
        if (path === '/ai/proactive') return { schemaVersion: 'tracebolt.proactive-ai-settings.v1', revision: 'revision-a', enabled: false, configRevision: 'config-a', providerConfigured: true, baseURL: 'http://127.0.0.1:11434/v1', model: 'fixture-model', deviceIds: [], availableDevices: [{ id: endpointDevice }], dataScope: 'health-summary-v1', logsAllowed: false, resetsOnRestart: true, maxAnalysesPerHour: 6, cooldownMinutes: 30, minIntervalSeconds: 60, reason: '' };
        throw new Error(`Unexpected fixture request: ${path}`);
    });
    render(<App/>); await screen.findByText('Off'); fireEvent.click(screen.getByRole('button', { name: 'Proactive AI diagnostics' })); await screen.findByText('fixture-linux');
    const identityCalls = () => vi.mocked(request).mock.calls.filter(([path]) => path === '/fleet/endpoint-identities').length;
    expect(identityCalls()).toBe(1);
    for (const hash of ['#settings', '#/settings', '#/settings/']) {
        const shell = document.querySelector('.app-shell');
        await act(async () => { history.replaceState(null, '', hash); window.dispatchEvent(new HashChangeEvent('hashchange')); });
        expect(document.querySelector('.app-shell')).toBe(shell); expect(identityCalls()).toBe(1);
        // Privileged settings still clear their own draft/consent on navigation.
        // Refreshing them reuses the workspace metadata without a duplicate read.
        expect(screen.queryByText('fixture-linux')).not.toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', { name: 'Refresh proactive AI settings' }));
        await screen.findByText('fixture-linux'); expect(identityCalls()).toBe(1); expect(screen.getByRole('checkbox', { name: new RegExp(endpointDevice) })).not.toBeChecked();
    }
});
