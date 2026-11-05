import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { setLocale } from './i18n';
import { useOperator } from './auth';
import { historyIntervals, summarizeResource } from './resource-history-analysis';
import { ResourceHistoryCharts } from './resource-history';
import { useResourceHistory } from './resource-history-resource';
import { historyDevice, historyFixture } from './resource-history-fixture';

vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
vi.mock('./resource-history-resource', () => ({ useResourceHistory: vi.fn() }));
const retry = vi.fn();
const openStatistics = () => { const summary = screen.getByText(/^(Sample statistics|Messwertstatistik)$/); if (!(summary.closest('details') as HTMLDetailsElement).open) fireEvent.click(summary); };
beforeEach(() => {
    setLocale('en', false);
    vi.mocked(useOperator).mockReturnValue({ mode: 'lan', authenticated: true, insecureTestMode: false, expiresAt: '2026-10-08T12:00:00Z', theme: 'light', setTheme: vi.fn(), logout: vi.fn() });
    vi.mocked(useResourceHistory).mockReturnValue({ view: historyFixture([-7200, -3660, -3600, -60, 0]), loading: false, error: '', retry });
});
afterEach(() => { cleanup(); vi.clearAllMocks(); });

describe('read-only resource interval exploration', () => {
    it.each(['en', 'de'] as const)('aligns original statistics in accessible comparison columns (%s)', locale => {
        setLocale(locale, false); const view = historyFixture([-7200, -3660, -3600, -60, 0]);
        render(<ResourceHistoryCharts deviceId={historyDevice} sessionKey="session" ready/>);
        fireEvent.change(screen.getByRole('combobox'), { target: { value: '1' } }); fireEvent.click(screen.getByRole('checkbox')); openStatistics();
        const table = screen.getByRole('table', { name: locale === 'en' ? 'CPU usage' : 'CPU-Auslastung' });
        const headers = within(table).getAllByRole('columnheader'); expect(headers).toHaveLength(3);
        expect(headers.map(h => h.textContent)).toEqual(locale === 'en' ? ['Statistic', 'Selected interval', 'Previous equal interval'] : ['Kennzahl', 'Ausgewählter Zeitraum', 'Vorheriger gleich langer Zeitraum']);
        for (const header of headers) expect(header).toHaveAttribute('scope', 'col');
        const ranges = historyIntervals(view, 1), current = summarizeResource(view, 'cpu', ranges.current), previous = summarizeResource(view, 'cpu', ranges.previous!);
        const row = within(table).getByRole('rowheader', { name: 'Median' }); expect(row).toHaveAttribute('scope', 'row');
        expect(within(row.closest('tr')!).getAllByRole('cell').map(cell => cell.textContent)).toEqual([`${current.median}%`, `${previous.median}%`]);
        const count = within(table).getByRole('rowheader', { name: locale === 'en' ? 'Usable samples' : 'Verwendbare Messwerte' });
        expect(within(count.closest('tr')!).getAllByRole('cell').map(cell => cell.textContent)).toEqual([String(current.usable), String(previous.usable)]);
        fireEvent.click(screen.getByRole('checkbox')); expect(screen.queryByRole('table')).toBeNull();
        expect(screen.queryByText(locale === 'en' ? 'Previous equal interval' : 'Vorheriger gleich langer Zeitraum')).toBeNull();
        expect(retry).not.toHaveBeenCalled();
    });
    it('keeps missing prior values unknown while showing genuine zero counts', () => {
        vi.mocked(useResourceHistory).mockReturnValue({ view: historyFixture(), loading: false, error: '', retry });
        render(<ResourceHistoryCharts deviceId={historyDevice} sessionKey="session" ready/>);
        fireEvent.change(screen.getByRole('combobox'), { target: { value: '6' } }); fireEvent.click(screen.getByRole('checkbox')); openStatistics();
        const table = screen.getByRole('table', { name: 'CPU usage' });
        expect(within(table).getByRole('columnheader', { name: 'Previous equal interval · No usable samples' })).toBeVisible();
        const median = within(table).getByRole('rowheader', { name: 'Median' }).closest('tr')!;
        expect(within(median).getAllByRole('cell')[1]).toHaveTextContent('—');
        const count = within(table).getByRole('rowheader', { name: 'Usable samples' }).closest('tr')!;
        expect(within(count).getAllByRole('cell')[1]).toHaveTextContent('0');
        expect(screen.queryByText(/percentage points$/)).toBeNull();
    });
    it('selects shorter charts and compares prior samples without any extra read or retry', () => {
        const fetch = vi.spyOn(globalThis, 'fetch');
        render(<ResourceHistoryCharts deviceId={historyDevice} sessionKey="session" ready/>);
        const compare = screen.getByRole('checkbox', { name: 'Compare with previous interval' });
        expect(compare).toBeDisabled();
        fireEvent.change(screen.getByRole('combobox', { name: 'History time window' }), { target: { value: '1' } });
        expect(compare).toBeEnabled(); fireEvent.click(compare);
        expect(screen.getByRole('img', { name: /^CPU · Last hour\. 3 observations/ })).toBeVisible();
        openStatistics();
        const cpu = screen.getByRole('region', { name: 'CPU usage' });
        expect(within(cpu).getByText('Median difference:')).toBeVisible();
        expect(within(cpu).getByText('+20 percentage points')).toBeVisible();
        expect(screen.getByText('2026-10-07T10:00:00Z')).toBeVisible();
        expect(fetch).not.toHaveBeenCalled(); expect(retry).not.toHaveBeenCalled(); fetch.mockRestore();
    });
    it('never compares outside retention and does not invent zero from empty prior data', () => {
        vi.mocked(useResourceHistory).mockReturnValue({ view: historyFixture(), loading: false, error: '', retry });
        render(<ResourceHistoryCharts deviceId={historyDevice} sessionKey="session" ready/>);
        fireEvent.change(screen.getByRole('combobox'), { target: { value: '6' } });
        fireEvent.click(screen.getByRole('checkbox')); openStatistics();
        expect(screen.getAllByText('No usable samples')).toHaveLength(3);
        expect(screen.queryByText(/percentage points$/)).toBeNull();
        fireEvent.change(screen.getByRole('combobox'), { target: { value: '24' } });
        expect(screen.getByRole('checkbox')).toBeDisabled(); expect(screen.getByRole('checkbox')).not.toBeChecked();
        expect(screen.queryByText('Previous equal interval')).toBeNull();
    });
    it('retains original snapshot times through local filters and clears private summaries on source loss', () => {
        const { rerender } = render(<ResourceHistoryCharts deviceId={historyDevice} sessionKey="session" ready/>);
        fireEvent.change(screen.getByRole('combobox'), { target: { value: '12' } });
        openStatistics();
        expect(document.querySelector('.resource-history-snapshot time')).toHaveAttribute('datetime', '2026-10-07T12:00:00Z');
        vi.mocked(useResourceHistory).mockReturnValue({ view: null, loading: false, error: 'unavailable', retry });
        rerender(<ResourceHistoryCharts deviceId={historyDevice} sessionKey="session" ready/>);
        expect(screen.queryByText('Sample statistics')).toBeNull(); expect(screen.queryByRole('img')).toBeNull();
        fireEvent.click(screen.getByRole('button', { name: 'Retry' })); expect(retry).toHaveBeenCalledOnce();
    });
    it('resets investigation controls across device/session scope changes and after unavailable data', () => {
        const { rerender } = render(<ResourceHistoryCharts deviceId={historyDevice} sessionKey="first" ready/>);
        fireEvent.change(screen.getByRole('combobox'), { target: { value: '1' } }); fireEvent.click(screen.getByRole('checkbox'));
        rerender(<ResourceHistoryCharts deviceId={historyDevice} sessionKey="second" ready/>);
        expect(screen.getByRole('combobox')).toHaveValue('24'); expect(screen.getByRole('checkbox')).not.toBeChecked();
        const next = 'agent_22222222222222222222222222222222';
        vi.mocked(useResourceHistory).mockReturnValue({ view: { ...historyFixture(), deviceId: next }, loading: false, error: '', retry });
        rerender(<ResourceHistoryCharts deviceId={next} sessionKey="second" ready/>);
        expect(screen.getByRole('combobox')).toHaveValue('24');
    });
    it('preserves keyboard sample inspection, real zero and repeated compare toggling', () => {
        render(<ResourceHistoryCharts deviceId={historyDevice} sessionKey="session" ready/>);
        fireEvent.change(screen.getByRole('combobox'), { target: { value: '12' } });
        const cpu = screen.getByRole('img', { name: /^CPU/ });
        fireEvent.keyDown(cpu, { key: 'Home' }); expect(screen.getByText('0%')).toBeVisible();
        fireEvent.keyDown(cpu, { key: 'End' }); expect(screen.getByText('39%')).toBeVisible();
        fireEvent.keyDown(cpu, { key: 'Escape' }); expect(document.querySelector('.resource-chart-inspection.visible')).toBeNull();
        for (let i = 0; i < 4; i++) fireEvent.click(screen.getByRole('checkbox'));
        expect(screen.getByRole('checkbox')).not.toBeChecked(); expect(retry).not.toHaveBeenCalled();
    });
    it('uses German text and Windows system-volume meaning without root-filesystem claims', () => {
        setLocale('de', false);
        render(<ResourceHistoryCharts deviceId={historyDevice} sessionKey="session" ready platform="windows"/>);
        fireEvent.change(screen.getByRole('combobox', { name: 'Verlauf-Zeitraum' }), { target: { value: '1' } });
        fireEvent.click(screen.getByRole('checkbox', { name: 'Mit vorherigem Zeitraum vergleichen' }));
        openStatistics();
        expect(screen.getByRole('region', { name: 'Belegung des Systemvolumes' })).toBeVisible();
        expect(screen.queryByText('Belegung des Root-Dateisystems')).toBeNull();
        expect(screen.getByRole('img', { name: /^CPU · Letzte Stunde/ })).toBeVisible();
    });
    it('allows repeated disclosure dismissal and only reopens after deliberate comparison entry', () => {
        const { rerender } = render(<ResourceHistoryCharts deviceId={historyDevice} sessionKey="session" ready/>);
        fireEvent.change(screen.getByRole('combobox'), { target: { value: '1' } }); fireEvent.click(screen.getByRole('checkbox'));
        expect(screen.getByRole('region', { name: 'CPU usage' })).toBeVisible();
        fireEvent.click(screen.getByText('Sample statistics'));
        expect(screen.queryByRole('region', { name: 'CPU usage' })).toBeNull();
        rerender(<ResourceHistoryCharts deviceId={historyDevice} sessionKey="session" ready/>);
        expect(screen.queryByRole('region', { name: 'CPU usage' })).toBeNull();
        fireEvent.click(screen.getByRole('checkbox')); fireEvent.click(screen.getByRole('checkbox'));
        expect(screen.getByRole('region', { name: 'CPU usage' })).toBeVisible();
    });
    it('removes expanded private statistics on authentication loss and resets after a cleared source', () => {
        const { rerender } = render(<ResourceHistoryCharts deviceId={historyDevice} sessionKey="session" ready/>);
        fireEvent.change(screen.getByRole('combobox'), { target: { value: '1' } }); fireEvent.click(screen.getByRole('checkbox'));
        vi.mocked(useResourceHistory).mockReturnValue({ view: null, loading: true, error: '', retry });
        rerender(<ResourceHistoryCharts deviceId={historyDevice} sessionKey="session" ready/>);
        expect(screen.queryByText('Sample statistics')).toBeNull();
        vi.mocked(useResourceHistory).mockReturnValue({ view: historyFixture(), loading: false, error: '', retry });
        rerender(<ResourceHistoryCharts deviceId={historyDevice} sessionKey="session" ready/>);
        expect(screen.getByRole('combobox')).toHaveValue('24'); openStatistics();
        vi.mocked(useOperator).mockReturnValue(null);
        rerender(<ResourceHistoryCharts deviceId={historyDevice} sessionKey="session" ready/>);
        expect(screen.queryByText('Sample statistics')).toBeNull(); expect(screen.queryByRole('region', { name: 'CPU usage' })).toBeNull();
    });
});
