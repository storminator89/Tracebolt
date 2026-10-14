import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { setLocale } from './i18n';
import { useOperator } from './auth';
import { ResourceHistoryCharts } from './resource-history';
import { useResourceHistory } from './resource-history-resource';
import { historyDevice, historyFixture } from './resource-history-fixture';
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
vi.mock('./resource-history-resource', () => ({ useResourceHistory: vi.fn() }));
const panel = () => <ResourceHistoryCharts deviceId={historyDevice} sessionKey="session" ready/>;
beforeEach(() => {
    setLocale('en', false);
    vi.mocked(useOperator).mockReturnValue({ mode: 'lan', authenticated: true, insecureTestMode: false, expiresAt: '2026-10-08T12:00:00Z', theme: 'light', setTheme: vi.fn(), logout: vi.fn() });
    // A full 24-hour minute series, entirely invented. Original timestamps stay fixed.
    const view = historyFixture(Array.from({ length: 1440 }, (_, index) => (index - 1439) * 60));
    view.points.forEach(point => { point.cpu.value = 38; point.memory.value = 48; });
    vi.mocked(useResourceHistory).mockReturnValue({ view, loading: false, error: '', retry: vi.fn() });
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); });
describe('resource history render work', () => {
    it('does not rebuild unchanged chart axes on unrelated parent clock renders', () => {
        const NativeDateTimeFormat = Intl.DateTimeFormat;
        const formats = vi.spyOn(Intl, 'DateTimeFormat').mockImplementation(function (...args: Parameters<typeof Intl.DateTimeFormat>) { return new NativeDateTimeFormat(...args); } as typeof Intl.DateTimeFormat);
        const mounted = render(panel());
        expect(formats).toHaveBeenCalledTimes(15);
        const paths = [...document.querySelectorAll('.resource-chart-line')].map(node => node.getAttribute('d'));
        formats.mockClear();
        for (let tick = 0; tick < 10; tick++) mounted.rerender(panel());
        expect(formats).not.toHaveBeenCalled();
        expect([...document.querySelectorAll('.resource-chart-line')].map(node => node.getAttribute('d'))).toEqual(paths);
    });
    it('updates new history, locale and keyboard inspection without a stale render', () => {
        const mounted = render(panel()), cpu = screen.getByRole('img', { name: /^CPU/ });
        fireEvent.keyDown(cpu, { key: 'End' }); expect(screen.getByText('38%')).toBeVisible();
        const previous = vi.mocked(useResourceHistory).mock.results.at(-1)!.value;
        const view = structuredClone(previous.view); view.points.at(-1)!.cpu.value = 62;
        vi.mocked(useResourceHistory).mockReturnValue({ ...previous, view }); mounted.rerender(panel());
        expect(screen.getByText('62%')).toBeVisible(); expect(screen.queryByText('38%')).toBeNull();
        act(() => setLocale('de', false)); expect(screen.getByRole('img', { name: /^CPU · Letzte 24 Stunden/ })).toBeVisible();
        fireEvent.keyDown(cpu, { key: 'Escape' }); expect(document.querySelector('.resource-chart-inspection.visible')).toBeNull();
    });
    it.each(['cleared', 'revoked', 'session'] as const)('removes chart paths immediately when history is %s', kind => {
        const mounted = render(panel()); expect(screen.getAllByRole('img')).toHaveLength(3);
        const previous = vi.mocked(useResourceHistory).mock.results.at(-1)!.value;
        if (kind === 'session') vi.mocked(useOperator).mockReturnValue(null);
        else vi.mocked(useResourceHistory).mockReturnValue({ ...previous, view: kind === 'cleared' ? null : { ...previous.view, status: 'revoked', points: [] } });
        mounted.rerender(panel()); expect(screen.queryByRole('img')).toBeNull(); expect(document.querySelector('.resource-chart-line')).toBeNull();
    });
});
