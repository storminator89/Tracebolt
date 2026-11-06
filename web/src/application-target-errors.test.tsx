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
const change = (row: number, label: string, value: string) => fireEvent.change(within(groups()[row]).getByLabelText(label, { exact: true }), { target: { value } });
const save = () => fireEvent.click(screen.getByRole('button', { name: /Save draft|Entwurf speichern/ }));

describe('target-specific editor feedback', () => {
    it.each(['en', 'de'] as const)('marks only invalid targets after a save attempt and links the summary (%s)', async locale => {
        setLocale(locale, false); await start(8);
        change(1, 'URL', 'not a URL'); change(7, 'URL', 'https://fixture.example.test/?secret=x');
        expect(document.querySelectorAll('[aria-invalid=true]')).toHaveLength(0);
        save(); const summary = screen.getByRole('alert');
        expect(within(summary).getAllByRole('button')).toHaveLength(2);
        expect(groups().filter(group => group.getAttribute('aria-invalid') === 'true')).toHaveLength(2);
        expect(groups()[1]).toHaveAccessibleDescription(new RegExp(locale === 'en' ? 'Check this target' : 'dieses Ziels prüfen'));
        fireEvent.click(within(summary).getByRole('button', { name: locale === 'en' ? 'Target 8' : 'Ziel 8' })); expect(groups()[7]).toHaveFocus();
        change(1, 'URL', target.url); expect(groups()[1]).not.toHaveAttribute('aria-invalid');
        expect(within(screen.getByRole('alert')).getAllByRole('button')).toHaveLength(1);
        change(7, 'URL', target.url); expect(screen.queryByRole('alert')).toBeNull();
        expect(groups().every(group => !group.hasAttribute('aria-describedby'))).toBe(true);
        expect(request).toHaveBeenCalledTimes(1); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('marks both duplicate IDs and removes both errors after one is repaired', async () => {
        await start(); change(2, 'Target ID', 'target-1'); save();
        expect(groups()[0]).toHaveAccessibleDescription(/ID is used by another target/);
        expect(groups()[2]).toHaveAccessibleDescription(/ID is used by another target/);
        expect(groups()[1]).not.toHaveAttribute('aria-invalid');
        change(2, 'Target ID', 'unique'); expect(screen.queryByRole('alert')).toBeNull(); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('reports the existing missing private-LAN approval without granting it', async () => {
        await start(); change(1, 'Allowed IP addresses', '10.2.3.4'); save();
        expect(groups()[1]).toHaveAttribute('aria-invalid', 'true');
        const approval = within(groups()[1]).getByRole('checkbox'); expect(approval).not.toBeChecked();
        expect(mutateRaw).not.toHaveBeenCalled(); fireEvent.click(approval); expect(screen.queryByRole('alert')).toBeNull();
        change(1, 'Target ID', 'changed'); expect(approval).not.toBeChecked(); expect(groups()[1]).toHaveAttribute('aria-invalid', 'true');
    });
    it('renumbers invalid entries after removal and clears the feedback on cancel', async () => {
        await start(); change(2, 'URL', 'invalid'); save();
        fireEvent.click(screen.getByRole('button', { name: 'Remove target 1' }));
        expect(within(screen.getByRole('alert')).getByRole('button', { name: 'Target 2' })).toBeVisible();
        fireEvent.click(within(screen.getByRole('alert')).getByRole('button', { name: 'Target 2' })); expect(groups()[1]).toHaveFocus();
        fireEvent.click(screen.getByRole('button', { name: 'Cancel' })); expect(screen.queryByRole('alert')).toBeNull();
        fireEvent.click(screen.getByRole('button', { name: 'Edit targets' })); expect(groups()).toHaveLength(3); expect(document.querySelectorAll('[aria-invalid=true]')).toHaveLength(0); expect(mutateRaw).not.toHaveBeenCalled();
    });
});
