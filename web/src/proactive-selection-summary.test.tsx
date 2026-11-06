import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, AUTH_REQUIRED_EVENT, mutateRaw, request } from './api';
import { useOperator } from './auth';
import { setLocale } from './i18n';
import { ProactiveAISettingsPanel } from './proactive-ai';
import type { ProactiveAISettings } from './proactive-ai-types';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutateRaw: vi.fn() }));
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
const id = 'agent_00000000000000000000000000000001', second = 'agent_00000000000000000000000000000002';
const operator = { mode: 'lan' as const, authenticated: true, loginMode: 'shared' as const, expiresAt: '2026-10-06T14:00:00Z', insecureTestMode: false, logout: vi.fn(), theme: 'light' as const, setTheme: vi.fn() };
const fixture = (): ProactiveAISettings => ({ schemaVersion: 'tracebolt.proactive-ai-settings.v1', revision: 'revision-a', enabled: false, configRevision: 'config-a', providerConfigured: true, baseURL: 'http://127.0.0.1:11434/v1', model: 'fixture-model', deviceIds: [], availableDevices: [{ id }, { id: second }], dataScope: 'health-summary-v1', logsAllowed: false, resetsOnRestart: true, maxAnalysesPerHour: 6, cooldownMinutes: 30, minIntervalSeconds: 60, reason: '' });
const flush = () => act(async () => {});
const button = (name: string) => screen.getByRole('button', { name });
const open = () => fireEvent.click(button('Proactive AI diagnostics'));
const consent = () => screen.getByRole('checkbox', { name: /I approve future health-summary/ });
async function start(value: unknown = fixture()) { vi.mocked(request).mockResolvedValue(value); const mounted = render(<ProactiveAISettingsPanel/>); await flush(); return mounted; }
beforeEach(() => { vi.useFakeTimers(); vi.setSystemTime('2026-10-06T12:00:00Z'); localStorage.clear(); sessionStorage.clear(); setLocale('en', false); vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('visible'); vi.mocked(useOperator).mockReturnValue(operator); vi.mocked(request).mockReset(); vi.mocked(mutateRaw).mockReset(); });
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.restoreAllMocks(); });

describe('device selection summary', () => {
    const summary = () => screen.getByText(/^Current device selection:/);
    it('counts draft selections without approving them or starting requests', async () => {
        await start(); open();
        expect(summary()).toHaveTextContent('Current device selection: 0 · Unavailable selections: 0');
        expect(screen.getByRole('group', { name: 'Devices' })).toHaveAccessibleDescription(summary().textContent!);
        fireEvent.click(screen.getByRole('checkbox', { name: new RegExp(id) }));
        expect(summary()).toHaveTextContent('selection: 1'); expect(consent()).not.toBeChecked();
        fireEvent.click(consent()); fireEvent.click(screen.getByRole('checkbox', { name: new RegExp(second) }));
        expect(summary()).toHaveTextContent('selection: 2'); expect(consent()).not.toBeChecked();
        fireEvent.click(screen.getByRole('checkbox', { name: new RegExp(id) }));
        expect(summary()).toHaveTextContent('selection: 1');
        expect(request).toHaveBeenCalledTimes(1); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('includes unavailable selected identities until explicitly removed', async () => {
        await start({ ...fixture(), deviceIds: [id, second], availableDevices: [{ id }] }); open();
        expect(summary()).toHaveTextContent('Current device selection: 2 · Unavailable selections: 1');
        expect(button('Approve and enable')).toBeDisabled();
        fireEvent.click(screen.getByRole('checkbox', { name: new RegExp(second) }));
        expect(summary()).toHaveTextContent('Current device selection: 1 · Unavailable selections: 0');
        expect(consent()).not.toBeChecked(); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('restores saved selection after close and clears summary on access loss', async () => {
        await start(); open(); fireEvent.click(screen.getByRole('checkbox', { name: new RegExp(id) }));
        fireEvent.keyDown(screen.getByRole('group', { name: 'Devices' }), { key: 'Escape' });
        expect(screen.queryByText(/^Current device selection:/)).toBeNull(); open();
        expect(summary()).toHaveTextContent('selection: 0');
        act(() => window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT)));
        expect(screen.queryByText(/^Current device selection:/)).toBeNull(); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('localizes read-only saved selections without enabling editing', async () => {
        vi.mocked(useOperator).mockReturnValue({ ...operator, loginMode: 'named', actorId: 'operator_00000000000000000000000000000001', capabilities: ['read'] });
        await start({ ...fixture(), deviceIds: [id] }); open(); act(() => setLocale('de', false));
        expect(screen.getByText(/^Aktuelle Geräteauswahl:/)).toHaveTextContent('Aktuelle Geräteauswahl: 1 · Nicht verfügbare Auswahlen: 0');
        expect(screen.getByRole('checkbox', { name: new RegExp(id) })).toBeDisabled();
        expect(request).toHaveBeenCalledTimes(1); expect(mutateRaw).not.toHaveBeenCalled();
    });
});
