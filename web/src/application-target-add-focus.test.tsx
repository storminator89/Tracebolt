import userEvent from '@testing-library/user-event';
import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, mutateRaw, request } from './api';
import { useOperator } from './auth';
import { setLocale } from './i18n';
import { ApplicationCheckSettingsPanel } from './application-check-settings';
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
async function start(count = 3) {
    vi.mocked(request).mockResolvedValue({ ...view, targets: Array.from({ length: count }, (_, i) => ({ ...target, id: `target-${i + 1}` })) });
    render(<ApplicationCheckSettingsPanel/>); await act(async () => {});
    fireEvent.click(screen.getByRole('button', { name: /Application check setup|Anwendungsprüfungen einrichten/ }));
    fireEvent.click(screen.getByRole('button', { name: /Edit targets|Ziele bearbeiten/ }));
}
const groups = () => screen.getAllByRole('group');

describe('explicit add-target keyboard focus', () => {
    it.each(['en', 'de'] as const)('focuses only the new blank ID without editing existing targets (%s)', async locale => {
        setLocale(locale, false); await start(2);
        const add = screen.getByRole('button', { name: locale === 'en' ? 'Add target' : 'Ziel hinzufügen' });
        add.focus(); fireEvent.click(add);
        const ids = screen.getAllByRole('textbox', { name: locale === 'en' ? 'Target ID' : 'Ziel-ID' });
        expect(ids).toHaveLength(3); expect(ids[2]).toHaveFocus(); expect(ids[2]).toHaveValue('');
        expect(ids[0]).toHaveValue('target-1'); expect(ids[1]).toHaveValue('target-2');
        expect(within(groups()[2]).getByLabelText('URL', { exact: true })).toHaveValue('');
        expect(within(groups()[2]).getByRole('checkbox')).not.toBeChecked();
        expect(screen.queryByRole('alert')).toBeNull(); expect(request).toHaveBeenCalledTimes(1); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it.each(['{Enter}', ' '])('supports keyboard activation with %s and keeps focus while typing', async key => {
        vi.useRealTimers(); const user = userEvent.setup(); await start(1);
        screen.getByRole('button', { name: 'Add target' }).focus(); await user.keyboard(key);
        const field = screen.getAllByRole('textbox', { name: 'Target ID' })[1]; expect(field).toHaveFocus();
        await user.keyboard('new-id'); expect(field).toHaveValue('new-id'); expect(field).toHaveFocus();
        await user.tab(); expect(within(groups()[1]).getByRole('combobox')).toHaveFocus(); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('focuses the eighth target but leaves the existing eight-target limit intact', async () => {
        await start(7); const add = screen.getByRole('button', { name: 'Add target' }); add.focus(); fireEvent.click(add);
        expect(groups()).toHaveLength(8); const last = screen.getAllByRole('textbox', { name: 'Target ID' })[7]; expect(last).toHaveFocus();
        expect(add).toBeDisabled(); fireEvent.click(add); expect(groups()).toHaveLength(8); expect(last).toHaveFocus();
        expect(request).toHaveBeenCalledTimes(1); expect(mutateRaw).not.toHaveBeenCalled();
    });
});
