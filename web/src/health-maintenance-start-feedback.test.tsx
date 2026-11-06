import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, mutate, request } from './api';
import { setLocale } from './i18n';
import { HealthMaintenanceSchedule } from './health-maintenance-schedule';
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutate: vi.fn() }));
const id = 'agent_schedule_fixture';
const initial = { schemaVersion: 'tracebolt.linux-maintenance-schedule-view.v1', deviceId: id, serverNow: '2026-11-04T12:00:00Z', revision: '0', canManage: true, remainingSlots: 64, legacyMaintenanceUntil: null, window: null, lastRequest: null };
beforeEach(() => { abortProtectedRequests(); localStorage.clear(); sessionStorage.clear(); setLocale('en', false); vi.mocked(request).mockReset().mockResolvedValue(initial); vi.mocked(mutate).mockReset(); });
afterEach(() => { cleanup(); vi.restoreAllMocks(); });
function draw() { render(<HealthMaintenanceSchedule deviceId={id} sessionKey="2026-11-04T13:00:00Z" enabled onChanged={vi.fn()}/>); }
describe('maintenance start feedback', () => {
    it.each(['en', 'de'] as const)('associates timing and invalid-start feedback, clearing errors after repair (%s)', async locale => {
        setLocale(locale, false); draw();
        fireEvent.click(screen.getByRole('button', { name: locale === 'en' ? 'Plan a one-time maintenance window' : 'Einmaliges Wartungsfenster planen' }));
        const input = await screen.findByLabelText(locale === 'en' ? 'Start (UTC)' : 'Beginn (UTC)');
        const review = screen.getByRole('button', { name: locale === 'en' ? 'Review fixed window' : 'Festes Fenster prüfen' });
        const timing = input.getAttribute('aria-describedby')!;
        expect(input).toHaveAttribute('aria-invalid', 'false'); expect(review).toBeDisabled();
        expect(document.getElementById(timing)).toHaveTextContent(locale === 'en' ? 'One fixed UTC window' : 'Ein festes UTC-Fenster');
        for (const value of ['2026-11-04T12:00', '2026-11-12T12:00']) {
            fireEvent.change(input, { target: { value } });
            expect(input).toHaveAttribute('aria-invalid', 'true'); expect(review).toBeDisabled();
            const descriptions = input.getAttribute('aria-describedby')!.split(' ');
            expect(descriptions).toHaveLength(2); expect(descriptions[0]).toBe(timing);
            expect(document.getElementById(descriptions[1])).toBeVisible();
            expect(input).toHaveAccessibleDescription(new RegExp(locale === 'en' ? 'Choose a valid UTC start' : 'Einen gültigen UTC-Beginn'));
        }
        fireEvent.change(input, { target: { value: '2026-11-04T12:05' } });
        expect(input).toHaveAttribute('aria-invalid', 'false'); expect(input).toHaveAttribute('aria-describedby', timing); expect(review).toBeEnabled();
        fireEvent.change(input, { target: { value: '' } });
        expect(input).toHaveAttribute('aria-invalid', 'false'); expect(input).toHaveAttribute('aria-describedby', timing); expect(review).toBeDisabled();
        expect(request).toHaveBeenCalledTimes(1); expect(mutate).not.toHaveBeenCalled();
    });
    it('drops invalid feedback when closed and requires a fresh unchecked review', async () => {
        draw(); fireEvent.click(screen.getByRole('button', { name: 'Plan a one-time maintenance window' }));
        const input = await screen.findByLabelText('Start (UTC)');
        fireEvent.change(input, { target: { value: '2026-11-04T12:00' } });
        const errorId = input.getAttribute('aria-describedby')!.split(' ')[1];
        fireEvent.click(screen.getByRole('button', { name: 'Close scheduled maintenance' }));
        expect(document.getElementById(errorId)).toBeNull();
        fireEvent.click(screen.getByRole('button', { name: 'Plan a one-time maintenance window' }));
        const fresh = await screen.findByLabelText('Start (UTC)'); expect(fresh).toHaveValue(''); expect(fresh).toHaveAttribute('aria-invalid', 'false');
        fireEvent.change(fresh, { target: { value: '2026-11-04T12:05' } }); fireEvent.click(screen.getByRole('button', { name: 'Review fixed window' }));
        expect(await screen.findByRole('checkbox')).not.toBeChecked(); expect(screen.getByRole('button', { name: 'Save this one-time window' })).toBeDisabled(); expect(mutate).not.toHaveBeenCalled();
    });
    it('does not introduce a form for read-only access', async () => {
        vi.mocked(request).mockResolvedValue({ ...initial, canManage: false }); draw();
        fireEvent.click(screen.getByRole('button', { name: 'Plan a one-time maintenance window' })); await act(async () => {});
        expect(screen.queryByLabelText('Start (UTC)')).toBeNull(); expect(mutate).not.toHaveBeenCalled();
    });
});
