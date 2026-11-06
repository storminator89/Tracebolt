import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AUTH_REQUIRED_EVENT } from './api';
import { DeviceComparison } from './device-comparison';
import { setLocale } from './i18n';
import type { FleetIdentityDisplay } from './fleet-identity-types';
import type { Device, Metric } from './types';

const at = '2026-11-06T09:00:00Z';
const metric: Metric = { value: null, unit: '%', quality: 'unknown', source: 'Synthetic fixture source', collectedAt: '0001-01-01T00:00:00Z' };
function device(id: string, extra: Partial<Device> = {}): Device { return { id, name: id, platform: 'linux', os: 'Synthetic Linux', site: '', group: '', ip: null, status: 'unknown', source: 'lan', synthetic: false, lastSeen: at, agentVersion: 'fixture', cpu: metric, memory: metric, disk: metric, uptime: '', tags: [], capabilities: [], evidence: [], trend: [], caseIds: [], ...extra }; }
const devices = [device('agent_a'), device('agent_b', { platform: 'windows', os: 'Synthetic Windows', lastSeen: '0001-01-01T00:00:00Z' }), device('demo', { name: 'Demonstration', synthetic: true, source: 'synthetic' })];
const identity: FleetIdentityDisplay = { hostname: 'fixture-host', status: 'stale', hostnamePartial: true, hostnameReason: null, addressReason: null, addresses: [], collectedAt: at, coverage: 'partial' };
const open = () => fireEvent.click(screen.getByRole('button', { name: 'Compare devices' }));
const choose = (slot: number, id: string) => fireEvent.change(screen.getByLabelText(`Device ${slot}${slot === 3 ? ' (optional)' : ''}`), { target: { value: id } });
const selectTwo = () => { open(); choose(1, 'agent_a'); choose(2, 'agent_b'); };
beforeEach(() => { setLocale('en', false); localStorage.clear(); sessionStorage.clear(); });
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

describe('read-only loaded device comparison', () => {
    it.each(['en', 'de'] as const)('opens locally with three accessible native selectors in %s', locale => {
        setLocale(locale, false); render(<DeviceComparison devices={devices} available onOpen={vi.fn()}/>);
        const name = locale === 'de' ? 'Geräte vergleichen' : 'Compare devices';
        expect(screen.queryByRole('combobox')).not.toBeInTheDocument();
        const button = screen.getByRole('button', { name }); fireEvent.click(button);
        expect(button).toHaveAttribute('aria-expanded', 'true'); expect(screen.getAllByRole('combobox')).toHaveLength(3);
        expect(screen.getByText(locale === 'de' ? 'Nur geladenes Inventar. Beobachtungen können aus verschiedenen Zeitpunkten stammen.' : 'Loaded inventory only. Observations may come from different times.')).toBeVisible();
        expect(screen.queryByRole('table')).not.toBeInTheDocument();
        for (const select of screen.getAllByRole('combobox')) expect(select).toHaveAccessibleName();
    });
    it('compares two or three current rows without changing report, health, source or missing metric meaning', () => {
        render(<DeviceComparison devices={devices} available onOpen={vi.fn()}/>); selectTwo();
        const table = screen.getByRole('table'); expect(within(table).getAllByRole('columnheader')).toHaveLength(3);
        expect(within(table).getAllByText('Not assessed')).toHaveLength(2); expect(within(table).getByText('No report recorded yet')).toBeVisible();
        expect(within(table).getAllByText('—')).toHaveLength(6); expect(within(table).getAllByText('Unavailable')).toHaveLength(6);
        expect(within(table).getByText('Synthetic Windows')).toBeVisible(); expect(within(table).getByText('Synthetic Linux')).toBeVisible();
        choose(3, 'demo'); expect(within(table).getAllByRole('columnheader')).toHaveLength(4); expect(within(table).getByText('Demo')).toBeVisible();
        expect(within(table).getAllByRole('rowheader')).toHaveLength(7);
    });
    it('shows original metric quality, source and collection time without a calculated comparison score', () => {
        const input = [device('agent_a', { cpu: { ...metric, value: 87.4, quality: 'stale', source: 'First source', collectedAt: at } }), device('agent_b', { cpu: { ...metric, value: 3, quality: 'healthy', source: 'Second source', collectedAt: '2026-11-06T08:00:00Z' } })];
        render(<DeviceComparison devices={input} available onOpen={vi.fn()}/>); selectTwo();
        const cpu = screen.getByRole('rowheader', { name: 'CPU' }).closest('tr')!;
        expect(within(cpu).getByText('Stale')).toBeVisible(); expect(within(cpu).getByText('Current')).toBeVisible();
        fireEvent.click(within(cpu).getAllByText('Measurement source')[0]);
        expect(within(cpu).getByText('First source')).toBeVisible(); expect(cpu.querySelector(`time[datetime="${at}"]`)).toBeVisible();
        expect(cpu.querySelector('time[datetime="2026-11-06T08:00:00Z"]')).toBeInTheDocument();
        expect(screen.queryByText(/faster|difference|healthier|reachable/i)).not.toBeInTheDocument();
    });
    it('prevents duplicate selections, including a repeated synthetic change event', () => {
        render(<DeviceComparison devices={devices} available onOpen={vi.fn()}/>); open(); choose(1, 'agent_a');
        expect(within(screen.getByLabelText('Device 2')).getByRole('option', { name: 'agent_a' })).toBeDisabled();
        choose(2, 'agent_a'); expect(screen.getByLabelText('Device 2')).toHaveValue(''); expect(screen.queryByRole('table')).not.toBeInTheDocument();
        choose(2, 'agent_b'); choose(3, 'agent_a'); expect(screen.getByLabelText('Device 3 (optional)')).toHaveValue('');
        expect(screen.getByRole('table')).toBeVisible();
    });
    it('keeps duplicate hostnames distinguishable by exact IDs and shows existing stale/partial hostname qualifiers', () => {
        const identities = new Map([['agent_a', identity], ['agent_b', identity]]);
        render(<DeviceComparison devices={devices} identities={identities} available onOpen={vi.fn()}/>); selectTwo();
        const table = screen.getByRole('table'); expect(within(table).getAllByText('fixture-host')).toHaveLength(2);
        expect(within(table).getByText('agent_a')).toBeVisible(); expect(within(table).getByText('agent_b')).toBeVisible();
        expect(within(table).getAllByText('Hostname: Stale · partially collected')).toHaveLength(2);
        expect(within(table).getByRole('button', { name: 'Open device: fixture-host · agent_a' })).toBeVisible();
        expect(within(table).getByRole('button', { name: 'Open device: fixture-host · agent_b' })).toBeVisible();
        expect(within(screen.getByLabelText('Device 1')).getByRole('option', { name: 'fixture-host · agent_a' })).toBeInTheDocument();
    });
    it('drops an expired hostname projection without keeping the old name or copying it into device data', () => {
        const props = { devices, available: true, onOpen: vi.fn() };
        const { rerender } = render(<DeviceComparison {...props} identities={new Map([['agent_a', identity]])}/>); selectTwo();
        rerender(<DeviceComparison {...props} identities={new Map()}/>);
        expect(screen.queryByText('fixture-host')).not.toBeInTheDocument(); expect(screen.getByRole('columnheader', { name: /agent_a/ })).toBeVisible();
        expect(devices[0].name).toBe('agent_a');
    });
    it('renders changed row values from props rather than retaining an earlier snapshot', () => {
        const props = { available: true, onOpen: vi.fn() };
        const { rerender } = render(<DeviceComparison {...props} devices={devices}/>); selectTwo();
        rerender(<DeviceComparison {...props} devices={[{ ...devices[0], os: 'Changed OS' }, devices[1]]}/>);
        expect(screen.queryByText('Synthetic Linux', { selector: 'td' })).not.toBeInTheDocument(); expect(screen.getByText('Changed OS', { selector: 'td' })).toBeVisible();
    });
    it('forgets filtered-out selections, including when the same ID later returns', () => {
        const props = { available: true, onOpen: vi.fn() };
        const { rerender } = render(<DeviceComparison {...props} devices={devices}/>); selectTwo();
        rerender(<DeviceComparison {...props} devices={[devices[0], devices[2]]}/>); expect(screen.queryByRole('table')).not.toBeInTheDocument(); expect(screen.getByLabelText('Device 2')).toHaveValue('');
        rerender(<DeviceComparison {...props} devices={devices}/>); expect(screen.getByLabelText('Device 2')).toHaveValue(''); expect(screen.queryByRole('table')).not.toBeInTheDocument();
    });
    it('opens only the chosen existing device and performs no network or persistent storage work', () => {
        const onOpen = vi.fn(), fetch = vi.spyOn(window, 'fetch'), write = vi.spyOn(Storage.prototype, 'setItem');
        render(<DeviceComparison devices={devices} available onOpen={onOpen}/>); selectTwo();
        fireEvent.click(screen.getByRole('button', { name: 'Open device: agent_b' }));
        expect(onOpen).toHaveBeenCalledExactlyOnceWith(devices[1]); expect(fetch).not.toHaveBeenCalled(); expect(write).not.toHaveBeenCalled();
    });
    it('supports keyboard selection and Clear returns focus to the first selector', async () => {
        const user = userEvent.setup(); render(<DeviceComparison devices={devices} available onOpen={vi.fn()}/>);
        screen.getByRole('button', { name: 'Compare devices' }).focus(); await user.keyboard('{Enter}');
        await user.selectOptions(screen.getByLabelText('Device 1'), 'agent_a'); await user.selectOptions(screen.getByLabelText('Device 2'), 'agent_b');
        screen.getByRole('button', { name: 'Clear comparison' }).focus(); await user.keyboard(' ');
        expect(screen.getByLabelText('Device 1')).toHaveFocus(); expect(screen.queryByRole('table')).not.toBeInTheDocument();
        expect(screen.getAllByRole('combobox').every(select => (select as HTMLSelectElement).value === '')).toBe(true);
    });
    it('removing a column returns focus to that selector without changing the other selections', () => {
        render(<DeviceComparison devices={devices} available onOpen={vi.fn()}/>); selectTwo(); choose(3, 'demo');
        fireEvent.click(screen.getByRole('button', { name: 'Remove from comparison: agent_b' }));
        expect(screen.getByLabelText('Device 2')).toHaveFocus(); expect(screen.getByLabelText('Device 1')).toHaveValue('agent_a'); expect(screen.getByLabelText('Device 3 (optional)')).toHaveValue('demo');
        expect(within(screen.getByRole('table')).queryByText('Synthetic Windows')).not.toBeInTheDocument();
    });
    it('closing returns focus and reopening starts without any selected evidence', () => {
        render(<DeviceComparison devices={devices} available onOpen={vi.fn()}/>); selectTwo();
        fireEvent.click(screen.getByRole('button', { name: 'Close comparison' })); expect(screen.getByRole('button', { name: 'Compare devices' })).toHaveFocus();
        expect(screen.queryByRole('table')).not.toBeInTheDocument(); open(); expect(screen.getByLabelText('Device 1')).toHaveValue('');
    });
    it('clears and blocks while inventory is unavailable, then requires a new selection', () => {
        const props = { devices, onOpen: vi.fn() }; const { rerender } = render(<DeviceComparison {...props} available/>); selectTwo();
        rerender(<DeviceComparison {...props} available={false}/>); expect(screen.queryByRole('table')).not.toBeInTheDocument(); expect(screen.getByRole('button', { name: 'Compare devices' })).toBeDisabled();
        rerender(<DeviceComparison {...props} available/>); open(); expect(screen.getByLabelText('Device 1')).toHaveValue('');
    });
    it('hides and discards the comparison on document visibility loss, including a hidden initial mount', () => {
        const hidden = vi.spyOn(document, 'hidden', 'get').mockReturnValue(true);
        const { unmount } = render(<DeviceComparison devices={devices} available onOpen={vi.fn()}/>); expect(screen.getByRole('button', { name: 'Compare devices' })).toBeDisabled(); unmount();
        hidden.mockReturnValue(false); render(<DeviceComparison devices={devices} available onOpen={vi.fn()}/>); selectTwo();
        hidden.mockReturnValue(true); fireEvent(document, new Event('visibilitychange')); expect(screen.queryByRole('table')).not.toBeInTheDocument();
        hidden.mockReturnValue(false); fireEvent(document, new Event('visibilitychange')); open(); expect(screen.getByLabelText('Device 1')).toHaveValue('');
    });
    it.each([AUTH_REQUIRED_EVENT, 'hashchange', 'pagehide'])('discards and blocks old context after %s until its owner remounts it', event => {
        const props = { devices, available: true, onOpen: vi.fn() }; const { rerender } = render(<DeviceComparison key="original" {...props}/>); selectTwo();
        act(() => window.dispatchEvent(new Event(event))); expect(screen.queryByRole('table')).not.toBeInTheDocument(); expect(screen.getByRole('button', { name: 'Compare devices' })).toBeDisabled();
        rerender(<DeviceComparison key="new-context" {...props}/>); open(); expect(screen.getByLabelText('Device 1')).toHaveValue('');
    });
    it('does not open a device while hidden before visibility invalidation runs', () => {
        const onOpen = vi.fn(); render(<DeviceComparison devices={devices} available onOpen={onOpen}/>); selectTwo();
        vi.spyOn(document, 'hidden', 'get').mockReturnValue(true); fireEvent.click(screen.getByRole('button', { name: 'Open device: agent_a' })); expect(onOpen).not.toHaveBeenCalled();
    });
});
