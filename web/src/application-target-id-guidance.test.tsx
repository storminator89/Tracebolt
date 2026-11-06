import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, mutateRaw, request } from './api';
import { useOperator } from './auth';
import { setLocale } from './i18n';
import { ApplicationCheckSettingsPanel } from './application-check-settings';
import { validApplicationTarget } from './application-check-settings-types';
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutateRaw: vi.fn() }));
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
const operator = { mode: 'lan' as const, authenticated: true, expiresAt: '2026-10-07T14:00:00Z', insecureTestMode: false, logout: vi.fn(), theme: 'light' as const, setTheme: vi.fn() };
const target = { kind: 'http' as const, id: 'web', url: 'https://fixture.example.test/health', allowedAddresses: ['8.8.8.8'], allowPrivateLAN: false, plaintextHTTPAcknowledged: false };
const view = { schemaVersion: 'tracebolt.application-check-settings.v1', mode: 'managed', revision: 'a'.repeat(32), configured: true, enabled: false, blocked: false, intervalSeconds: 60, targets: [target] };
beforeEach(() => {
    vi.useFakeTimers(); vi.setSystemTime('2026-10-07T12:00:00Z'); localStorage.clear(); sessionStorage.clear(); setLocale('en', false);
    vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('visible'); vi.mocked(useOperator).mockReturnValue(operator); vi.mocked(request).mockReset().mockResolvedValue(view); vi.mocked(mutateRaw).mockReset();
});
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.restoreAllMocks(); });
async function start() { render(<ApplicationCheckSettingsPanel initialAdd/>); await act(async () => {}); }
describe('target ID guidance', () => {
    it.each(['en', 'de'] as const)('describes each ID separately before validation without filling or approving it (%s)', async locale => {
        setLocale(locale, false); await start();
        const inputs = screen.getAllByRole('textbox', { name: locale === 'en' ? 'Target ID' : 'Ziel-ID' });
        expect(inputs).toHaveLength(2);
        const ids = inputs.map(input => input.getAttribute('aria-describedby'));
        expect(new Set(ids).size).toBe(2);
        for (const input of inputs) {
            expect(input).toHaveAccessibleDescription(locale === 'en' ? '1–48 characters: lowercase a–z, 0–9, _ or -. Use a different ID for each target.' : '1–48 Zeichen: Kleinbuchstaben a–z, 0–9, _ oder -. Für jedes Ziel eine andere ID verwenden.');
            expect(document.getElementById(input.getAttribute('aria-describedby')!)).toBeVisible();
            expect(input).toHaveAttribute('maxlength', '48');
        }
        expect(inputs[0]).toHaveValue('web'); expect(inputs[1]).toHaveValue(''); expect(inputs[1]).toHaveFocus();
        expect(screen.getAllByRole('checkbox').every(box => !(box as HTMLInputElement).checked)).toBe(true);
        expect(request).toHaveBeenCalledTimes(1); expect(mutateRaw).not.toHaveBeenCalled();
        fireEvent.change(inputs[1], { target: { value: 'new-id_2' } });
        act(() => setLocale(locale === 'en' ? 'de' : 'en', false));
        expect(inputs[1]).toHaveValue('new-id_2'); expect(inputs[1]).toHaveAttribute('aria-describedby', ids[1]);
        expect(request).toHaveBeenCalledTimes(1); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it.each(['a', 'a'.repeat(48), 'a-z_09'])('matches accepted ID characters and boundaries: %s', id => expect(validApplicationTarget({ ...target, id })).toBe(true));
    it.each(['', 'a'.repeat(49), 'Upper', 'has space', 'ümlaut', 'dot.id', 'x\x7f'])('does not promise invalid IDs: %s', id => expect(validApplicationTarget({ ...target, id })).toBe(false));
    it('does not expose an editor or initiate reads without permission', async () => {
        vi.mocked(useOperator).mockReturnValue({ ...operator, loginMode: 'named', actorId: `operator_${'a'.repeat(32)}`, capabilities: ['read'] });
        await start(); expect(screen.queryByRole('textbox')).toBeNull(); expect(request).not.toHaveBeenCalled(); expect(mutateRaw).not.toHaveBeenCalled();
    });
});
