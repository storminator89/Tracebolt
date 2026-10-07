import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { setLocale } from './i18n';
import { useOperator } from './auth';
import { ResourceHistoryCharts } from './resource-history';
import { useResourceHistory } from './resource-history-resource';
import { resourceSegments, validResourceHistory } from './resource-history-types';
import { historyDevice, historyFixture } from './resource-history-fixture';
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
vi.mock('./resource-history-resource', () => ({ useResourceHistory: vi.fn() }));
beforeEach(() => { setLocale('en', false); vi.mocked(useOperator).mockReturnValue({ mode: 'lan', authenticated: true, insecureTestMode: false, expiresAt: '2026-10-08T12:00:00Z', theme: 'light', setTheme: vi.fn(), logout: vi.fn() }); vi.mocked(useResourceHistory).mockReturnValue({ view: historyFixture(), loading: false, error: '', retry: vi.fn() }); });
afterEach(cleanup);
describe('24-hour authentic resource charts', () => {
    it('validates identity, finite bounds, ordered sequences, minute uniqueness and exact window', () => {
        const good = historyFixture(); expect(validResourceHistory(good, historyDevice)).toBe(true);
        for (const mutate of [v => { v.deviceId = 'wrong'; }, v => { v.points[0].cpu.value = NaN; }, v => { v.points[0].cpu.value = -1; }, v => { v.points[0].sequence = '9007199254740994'; }, v => { v.points[1].collectedAt = v.points[0].collectedAt; }, v => { v.windowStart = v.serverNow; }, v => { v.status = 'revoked'; }, v => { v.points[0].cpu.quality = 'unknown'; } ] as ((v: typeof good) => void)[]) { const bad = structuredClone(good); mutate(bad); expect(validResourceHistory(bad, historyDevice)).toBe(false); }
    });
    it('keeps real zero, unknown samples, and missing intervals separate', () => {
        const v = historyFixture(); expect(resourceSegments(v, 'cpu').map(segment => segment.length)).toEqual([2, 2]); expect(resourceSegments(v, 'cpu')[0][0].value).toBe(0);
        v.points[2].cpu = { ...v.points[2].cpu, quality: 'unknown', value: null }; expect(resourceSegments(v, 'cpu').map(segment => segment.length)).toEqual([2, 1]);
        v.points[3].cpu.quality = 'stale'; expect(resourceSegments(v, 'cpu').map(segment => segment.length)).toEqual([2]);
    });
    it('renders three compact charts and exact real timestamp/value inspection', () => {
        render(<ResourceHistoryCharts deviceId={historyDevice} sessionKey="session" ready/>); expect(screen.getAllByRole('img')).toHaveLength(3); expect(screen.getByText('Root filesystem')).toBeVisible();
        const cpu = screen.getByRole('img', { name: /^CPU/ }); fireEvent.keyDown(cpu, { key: 'Home' }); expect(screen.getByText('0%')).toBeVisible(); expect(document.querySelector('.resource-chart-inspection.visible time')).toHaveAttribute('datetime', historyFixture().points[0].cpu.collectedAt);
        fireEvent.keyDown(cpu, { key: 'End' }); expect(screen.getByText('38%')).toBeVisible(); fireEvent.keyDown(cpu, { key: 'Escape' }); expect(document.querySelector('.resource-chart-inspection.visible')).toBeNull();
        expect(document.querySelectorAll('.cpu .resource-chart-line')).toHaveLength(2);
    });
    it('does not invent chart values for empty, revoked, or unconfigured history', () => {
        const resource = { view: historyFixture([]), loading: false, error: '' as const, retry: vi.fn() }; vi.mocked(useResourceHistory).mockReturnValue(resource); const result = render(<ResourceHistoryCharts deviceId={historyDevice} sessionKey="session" ready/>);
        expect(screen.getByText('History will appear as reports arrive.')).toBeVisible(); expect(document.querySelector('.resource-chart-line')).toBeNull();
        vi.mocked(useResourceHistory).mockReturnValue({ ...resource, view: { ...resource.view, status: 'revoked' } }); result.rerender(<ResourceHistoryCharts deviceId={historyDevice} sessionKey="session" ready/>); expect(screen.getByText('Device revoked')).toBeVisible(); expect(screen.queryByRole('img')).toBeNull();
    });
    it('hides protected history outside operator LAN sessions and supports German', () => {
        setLocale('de', false); const result = render(<ResourceHistoryCharts deviceId={historyDevice} sessionKey="session" ready/>); expect(screen.getByText('Letzte 24 Stunden')).toBeVisible();
        vi.mocked(useOperator).mockReturnValue(null); result.rerender(<ResourceHistoryCharts deviceId={historyDevice} sessionKey="session" ready/>); expect(screen.queryByRole('img')).toBeNull();
    });
});
