import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, mutateRaw, request } from './api';
import { useOperator } from './auth';
import { setLocale } from './i18n';
import { JournalAISettingsPanel } from './journal-ai';
import type { JournalAISettings, JournalAISource } from './journal-ai-types';
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutateRaw: vi.fn() }));
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
const id = 'agent_00000000000000000000000000000001';
const operator = { mode: 'lan' as const, authenticated: true, loginMode: 'shared' as const, expiresAt: '2026-10-07T15:00:00Z', insecureTestMode: false, logout: vi.fn(), theme: 'light' as const, setTheme: vi.fn() };
const generation = { revision: '1', generation: 'a'.repeat(64), policyDigest: `sha256:${'b'.repeat(64)}` };
const settings = (): JournalAISettings => ({ schemaVersion: 'tracebolt.journal-ai-settings.v1', revision: 'scope-a', enabled: false, ready: false, configRevision: 'config-a', providerSaved: true, baseURL: 'http://127.0.0.1:11434/v1', model: 'fixture-model', targets: [], lookbackMinutes: 5, approvedAt: '0001-01-01T00:00:00Z', devices: [id], plaintext: false, maxTargets: 8, maxAnalysesPerHour: 2, maxRows: 10, maxMessageBytes: 1024, dataScope: 'service-journal-ai-v1', retention: 'original-capture-expiry-memory-only', blocked: false, cancellationPending: false });
const source = (): JournalAISource => ({ deviceId: id, serverNow: '2026-10-07T14:00:00Z', generation: { schemaVersion: 'tracebolt.journal-generation-view.v2', policyGeneration: generation, sequence: '1', observedAt: '2026-10-07T14:00:00Z', receivedAt: '2026-10-07T14:00:00Z', expiresAt: '2026-10-07T14:05:00Z', fresh: true, policyEnabled: true, serviceAuthorization: 'exact-units', allowedUnits: ['fixture.service'] } });
const flush = () => act(async () => {});
const button = (name: string) => screen.getByRole('button', { name });
async function start(v = settings(), s: unknown = source()) { vi.mocked(request).mockImplementation(async path => path === '/ai/journal' ? v : s); render(<JournalAISettingsPanel/>); fireEvent.click(screen.getByRole('button', { name: /Service-log AI|Dienstlog-KI/ })); await flush(); }
beforeEach(() => { vi.useFakeTimers(); vi.setSystemTime('2026-10-07T14:00:00Z'); localStorage.clear(); sessionStorage.clear(); setLocale('en', false); vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('visible'); vi.mocked(useOperator).mockReturnValue(operator); vi.mocked(request).mockReset(); vi.mocked(mutateRaw).mockReset(); });
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.restoreAllMocks(); });

describe('service-log target add feedback', () => {
    it.each(['en', 'de'] as const)('explains a duplicate without changing source authority or approval (%s)', async locale => {
        setLocale(locale, false); const v = { ...settings(), targets: [{ deviceId: id, unit: 'fixture.service', generation }] };
        await start(v); const unit = screen.getByRole('textbox', { name: locale === 'en' ? 'Service' : 'Dienst' });
        const add = button(locale === 'en' ? 'Add service' : 'Dienst hinzufügen');
        fireEvent.change(unit, { target: { value: 'fixture.service' } });
        expect(add).toBeDisabled(); expect(add).toHaveAccessibleDescription(locale === 'en' ? 'This device and service are already selected.' : 'Dieses Gerät und dieser Dienst sind bereits ausgewählt.');
        expect(screen.getAllByRole('checkbox').every(box => !(box as HTMLInputElement).checked)).toBe(true);
        const reads = vi.mocked(request).mock.calls.length;
        fireEvent.click(add); expect(mutateRaw).not.toHaveBeenCalled(); expect(request).toHaveBeenCalledTimes(reads);
        fireEvent.change(unit, { target: { value: 'other.service' } });
        expect(add).not.toHaveAttribute('aria-describedby'); expect(add).toBeDisabled();
        fireEvent.change(unit, { target: { value: 'fixture.service' } });
        fireEvent.click(button(locale === 'en' ? 'Remove' : 'Entfernen'));
        expect(add).not.toHaveAttribute('aria-describedby'); expect(add).toBeEnabled(); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it.each(['en', 'de'] as const)('explains the eight-target limit and clears it on removal (%s)', async locale => {
        setLocale(locale, false); const targets = Array.from({ length: 8 }, (_, i) => ({ deviceId: id, unit: `fixture${i}.service`, generation }));
        const s = source(); s.generation!.allowedUnits = targets.map(t => t.unit);
        await start({ ...settings(), targets }, s);
        const add = button(locale === 'en' ? 'Add service' : 'Dienst hinzufügen');
        expect(add).toBeDisabled(); expect(add).toHaveAccessibleDescription(locale === 'en' ? 'Eight services selected. Remove one before adding another.' : 'Acht Dienste ausgewählt. Vor dem Hinzufügen einen entfernen.');
        fireEvent.click(screen.getAllByRole('button', { name: locale === 'en' ? 'Remove' : 'Entfernen' })[0]);
        expect(add).not.toHaveAttribute('aria-describedby'); expect(add).toBeDisabled();
        expect(screen.getAllByRole('checkbox').every(box => !(box as HTMLInputElement).checked)).toBe(true); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('removes the helper together with expired authority', async () => {
        await start({ ...settings(), targets: [{ deviceId: id, unit: 'fixture.service', generation }] });
        fireEvent.change(screen.getByRole('textbox', { name: 'Service' }), { target: { value: 'fixture.service' } });
        expect(screen.getByText('This device and service are already selected.')).toBeVisible();
        await act(async () => { await vi.advanceTimersByTimeAsync(60000); });
        expect(screen.queryByText('This device and service are already selected.')).toBeNull(); expect(screen.queryByRole('button', { name: 'Add service' })).toBeNull(); expect(mutateRaw).not.toHaveBeenCalled();
    });
});
