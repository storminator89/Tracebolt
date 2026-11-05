import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AUTH_REQUIRED_EVENT, request } from './api';
import { setLocale } from './i18n';
import { WindowsNetworkPanel } from './windows-network';
import { findNetworkEndpoints, initialNetworkFinderControls, networkQueryError, type NetworkFinderControls, type NetworkSort } from './windows-network-finder-model';
import { windowsNetwork } from './windows-network-fixture';
import { useWindowsInventory } from './windows-inventory-resource';
import { windowsDeviceId, windowsNow, windowsView } from './windows-inventory-fixture';
import type { WindowsNetwork, WindowsNetworkEndpoint } from './windows-network-types';
import type { WindowsInventoryView } from './windows-inventory-types';
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn() }));
const controls = (value: Partial<NetworkFinderControls> = {}): NetworkFinderControls => ({ ...initialNetworkFinderControls(), ...value });
const rows = (network: WindowsNetwork, value: Partial<NetworkFinderControls>) => findNetworkEndpoints(network, controls(value));
const view = (): WindowsInventoryView & { network: WindowsNetwork } => ({ ...windowsView(), network: windowsNetwork() });
const flush = () => act(async () => {});
function Harness({ id = windowsDeviceId, session = 'fixture', enabled = true }: { id?: string; session?: string; enabled?: boolean }) {
    const resource = useWindowsInventory(id, enabled, session);
    return <><button onClick={resource.refresh}>Refresh fixture</button><WindowsNetworkPanel key={`${id}:${session}`} resource={resource}/></>;
}
const query = () => screen.getByRole('searchbox', { name: 'Find captured endpoints' });
const select = (name: string, value: string) => fireEvent.change(screen.getByRole('combobox', { name }), { target: { value } });
const search = (value: string) => fireEvent.change(query(), { target: { value } });
const endpoints = () => within(screen.getByRole('table', { name: 'Network' })).getAllByRole('row').slice(1);
async function ready() { await screen.findByRole('searchbox', { name: 'Find captured endpoints' }); }
beforeEach(() => { setLocale('en', false); vi.mocked(request).mockReset().mockResolvedValue(view()); });
afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); });

describe('Retained network endpoint selection', () => {
    it('uses literal case-insensitive matching with canonical bracketed and scoped IPv6 endpoints', () => {
        const network = windowsNetwork();
        expect(rows(network, { query: 'DB8::80' })).toEqual([network.rows[1]]);
        expect(rows(network, { query: '[fe80::40%4]:5353' })).toEqual([network.rows[3]]);
        expect(rows(network, { query: '.*' })).toEqual([]);
        expect(rows(network, { query: 'established' })).toEqual([network.rows[1]]);
        expect(rows(network, { query: 'IPV6' })).toEqual([network.rows[1], network.rows[3]]);
        expect(rows(network, { field: 'address', query: '443' })).toEqual([]);
    });
    it('matches exact local and remote ports independently, including actual zero, not prefixes', () => {
        const network = windowsNetwork();
        network.rows = [80, 8080, 0, 65535].map(port => ({ ...network.rows[1], localPort: port, remotePort: 80 }));
        expect(rows(network, { field: 'local-port', query: ' 00080 ' })).toEqual([network.rows[0]]);
        expect(rows(network, { field: 'local-port', query: '0' })).toEqual([network.rows[2]]);
        expect(rows(network, { field: 'local-port', query: '65535' })).toEqual([network.rows[3]]);
        expect(rows(network, { field: 'remote-port', query: '80' })).toHaveLength(4);
        expect(rows(windowsNetwork(), { field: 'remote-port', query: '0' })).toEqual([]);
    });
    it('does not turn unavailable UDP attribution into process zero or a placeholder match', () => {
        const network = windowsNetwork();
        network.rows.push({ ...network.rows[0], pid: 0 }, { ...network.rows[0], pid: 4294967295 });
        expect(rows(network, { field: 'pid', query: '0' })).toEqual([network.rows[4]]);
        expect(rows(network, { field: 'pid', query: '4294967295' })).toEqual([network.rows[5]]);
        expect(rows(network, { field: 'pid', query: '4' })).toEqual([network.rows[0]]);
        expect(rows(network, { query: 'unavailable' })).toEqual([]);
        expect(rows(network, { query: 'not applicable' })).toEqual([]);
    });
    it.each(['-1', '-0', '+1', '1.2', '1e2', '0x50', '65536', '99999999999', 'NaN', 'Infinity', '１２'])('rejects invalid exact port %s without claiming no matches', query => {
        expect(networkQueryError(controls({ field: 'local-port', query }))).toBe('port');
        expect(rows(windowsNetwork(), { field: 'local-port', query })).toEqual([]);
    });
    it.each(['-1', '4294967296', '1.2', '+4', '1e2'])('rejects invalid exact PID %s', query => expect(networkQueryError(controls({ field: 'pid', query }))).toBe('pid'));
    it('allows an empty exact-field search to show all retained rows', () => expect(rows(windowsNetwork(), { field: 'pid', query: ' ' })).toHaveLength(4));
    it('combines exact search with protocol, state and family filters', () => {
        const network = windowsNetwork();
        expect(rows(network, { filter: 'listeners' })).toEqual([network.rows[0]]);
        expect(rows(network, { filter: 'established' })).toEqual([network.rows[1]]);
        expect(rows(network, { filter: 'tcp', family: 'ipv4' })).toEqual([network.rows[0]]);
        expect(rows(network, { filter: 'udp', family: 'ipv6', field: 'local-port', query: '5353' })).toEqual([network.rows[3]]);
        expect(rows(network, { filter: 'listeners', family: 'ipv6' })).toEqual([]);
    });
    it.each(['pid-asc', 'pid-desc'] as const)('keeps unavailable PIDs last with %s', sort => {
        const network = windowsNetwork(), selected = rows(network, { sort });
        expect(selected.at(-1)).toEqual(network.rows[3]);
        expect(selected.slice(0, 3).map(row => row.pid)).toEqual(sort === 'pid-asc' ? [4, 42, 44] : [44, 42, 4]);
    });
    it.each(['remote-port-asc', 'remote-port-desc'] as const)('keeps absent peers last with %s', sort => {
        const network = windowsNetwork(); network.rows.push({ ...network.rows[1], remotePort: 80 });
        const selected = rows(network, { sort });
        expect(selected.slice(0, 2).map(row => row.remotePort)).toEqual(sort === 'remote-port-asc' ? [80, 443] : [443, 80]);
        expect(selected.slice(2).map(row => row.remotePort)).toEqual([null, null, null]);
    });
    it.each(['local-port-asc', 'local-port-desc'] as const)('sorts ports numerically with %s and preserves duplicate rows', sort => {
        const network = windowsNetwork(); network.rows = [9, 80, 1000, 80].map(localPort => ({ ...network.rows[0], localPort }));
        const before = JSON.stringify(network), selected = rows(network, { sort });
        expect(selected.map(row => row.localPort)).toEqual(sort === 'local-port-asc' ? [9, 80, 80, 1000] : [1000, 80, 80, 9]);
        expect(selected.filter(row => row.localPort === 80)[0]).toBe(network.rows[1]);
        expect(selected.filter(row => row.localPort === 80)[1]).toBe(network.rows[3]);
        expect(JSON.stringify(network)).toBe(before);
    });
    it('never changes source counts, quality, capture age or order', () => {
        const network = windowsNetwork(); Object.assign(network, { quality: 'partial', countExact: false, observedCount: 100, truncated: true });
        const before = structuredClone(network);
        for (const sort of ['capture', 'pid-desc', 'local-port-desc', 'remote-port-desc'] as NetworkSort[]) rows(network, { query: '443', sort });
        expect(network).toEqual(before);
    });
});

describe('Network finder workflow', () => {
    it('finds an exact port locally, resets every control, and never requests or persists a query', async () => {
        const history = vi.spyOn(window.history, 'pushState'), replace = vi.spyOn(window.history, 'replaceState'), storage = vi.spyOn(Storage.prototype, 'setItem');
        render(<Harness/>); await ready();
        select('Search by', 'local-port'); search('5353'); select('Show endpoints', 'udp'); select('IP version', 'ipv6'); select('Sort endpoints', 'pid-desc');
        expect(endpoints()).toHaveLength(1); expect(endpoints()[0]).toHaveTextContent('[fe80::40%4]:5353');
        expect(screen.getByText('1–1 of 1 matches · 4 retained')).toBeVisible();
        expect(screen.getByText(/No match does not prove a port is free/)).toBeVisible();
        fireEvent.click(screen.getByRole('button', { name: 'Clear endpoint filters' }));
        expect(query()).toHaveValue(''); expect(endpoints()).toHaveLength(4);
        expect(screen.getByRole('combobox', { name: 'Search by' })).toHaveValue('any');
        expect(screen.getByRole('combobox', { name: 'Show endpoints' })).toHaveValue('all');
        expect(screen.getByRole('combobox', { name: 'IP version' })).toHaveValue('all');
        expect(screen.getByRole('combobox', { name: 'Sort endpoints' })).toHaveValue('capture');
        expect(request).toHaveBeenCalledTimes(1); expect(history).not.toHaveBeenCalled(); expect(replace).not.toHaveBeenCalled(); expect(storage).not.toHaveBeenCalled();
    });
    it('shows invalid numeric input separately from a genuine no-match result', async () => {
        render(<Harness/>); await ready(); select('Search by', 'local-port'); search('65536');
        expect(query()).toHaveAttribute('aria-invalid', 'true'); expect(screen.getByRole('alert')).toHaveTextContent('0 to 65535');
        expect(screen.queryByText('No retained endpoints match these filters.')).toBeNull(); expect(screen.queryByRole('table')).toBeNull();
        search('80'); expect(screen.getByText('No retained endpoints match these filters.')).toBeVisible();
        expect(screen.queryByRole('alert')).toBeNull(); expect(query()).not.toHaveAttribute('aria-invalid');
        expect(screen.getByText('0–0 of 0 matches · 4 retained')).toBeVisible();
    });
    it('pages 64 retained rows in capture order, resets to page one on filtering and exposes sort direction', async () => {
        const value = view(); value.network.rows = Array.from({ length: 64 }, (_, index): WindowsNetworkEndpoint => ({ ...value.network.rows[0], localPort: 1000 + index })); value.network.observedCount = 64;
        vi.mocked(request).mockResolvedValue(value); render(<Harness/>); await ready();
        expect(endpoints()).toHaveLength(25); expect(screen.getByText('1–25 of 64 matches · 64 retained')).toBeVisible();
        fireEvent.click(screen.getByRole('button', { name: 'Next endpoint page' })); expect(screen.getByText('26–50 of 64 matches · 64 retained')).toBeVisible();
        fireEvent.click(screen.getByRole('button', { name: 'Next endpoint page' })); expect(endpoints()).toHaveLength(14); expect(screen.getByRole('button', { name: 'Next endpoint page' })).toBeDisabled();
        select('Sort endpoints', 'local-port-desc'); expect(endpoints()[0]).toHaveTextContent('0.0.0.0:1063'); expect(screen.getByRole('columnheader', { name: 'Local endpoint' })).toHaveAttribute('aria-sort', 'descending');
        select('Search by', 'local-port'); search('1001'); expect(endpoints()).toHaveLength(1); expect(screen.queryByRole('navigation')).toBeNull();
        fireEvent.click(screen.getByRole('button', { name: 'Clear endpoint filters' })); expect(endpoints()[0]).toHaveTextContent('0.0.0.0:1000');
    });
    it('retains partial/stale/omitted source truth while filters have no match', async () => {
        const value = view(); Object.assign(value.network, { quality: 'partial', countExact: false, observedCount: 100, truncated: true, collectedAt: '2026-10-07T11:55:00Z' }); value.snapshot!.collectedAt = value.network.collectedAt; value.status = 'stale';
        vi.mocked(request).mockResolvedValue(value); render(<Harness/>); await ready(); search('absent');
        expect(screen.getByText('Partial enumeration')).toBeVisible(); expect(screen.getByText('4 retained · at least 100 observed')).toBeVisible();
        expect(screen.getByText(/Endpoints omitted/)).toBeVisible(); expect(screen.getByText(/Stale network observation/)).toBeVisible();
        expect(document.querySelector('time')).toHaveAttribute('datetime', value.network.collectedAt);
        expect(screen.queryByText(/No endpoints returned/)).toBeNull();
    });
    it('preserves controls across the same-capture reread, but not a new generation or grant', async () => {
        render(<Harness/>); await ready(); search('443'); select('Sort endpoints', 'pid-desc');
        fireEvent.click(screen.getByRole('button', { name: 'Refresh fixture' })); await ready(); expect(query()).toHaveValue('443'); expect(endpoints()).toHaveLength(1);
        const value = view(); value.network.generationId = `sample_${'b'.repeat(32)}`; value.snapshot!.generationId = value.network.generationId;
        vi.mocked(request).mockResolvedValue(value); fireEvent.click(screen.getByRole('button', { name: 'Refresh fixture' })); await ready(); expect(query()).toHaveValue(''); expect(endpoints()).toHaveLength(4);
        search('443'); value.network.grantId = 'e'.repeat(32); vi.mocked(request).mockResolvedValue(structuredClone(value)); fireEvent.click(screen.getByRole('button', { name: 'Refresh fixture' })); await ready(); expect(query()).toHaveValue('');
    });
    it.each(['blur', 'pagehide', 'hashchange', AUTH_REQUIRED_EVENT])('clears private filters and rows on %s and ignores pending replies', async event => {
        render(<Harness/>); await ready(); search('2001:db8::80');
        let resolve!: (value: WindowsInventoryView) => void; vi.mocked(request).mockReturnValue(new Promise(done => { resolve = done; }));
        fireEvent.click(screen.getByRole('button', { name: 'Refresh fixture' }));
        act(() => window.dispatchEvent(new Event(event))); await act(async () => resolve(view()));
        expect(screen.queryByRole('searchbox')).toBeNull(); expect(screen.queryByRole('table')).toBeNull();
        if (event !== AUTH_REQUIRED_EVENT) {
            vi.mocked(request).mockResolvedValue(view()); act(() => window.dispatchEvent(new Event('focus'))); await ready(); expect(query()).toHaveValue(''); expect(endpoints()).toHaveLength(4);
        }
    });
    it('clears private filters on a disabled view, session change, device change and unmount', async () => {
        const result = render(<Harness/>); await ready(); search('443'); result.rerender(<Harness enabled={false}/>); expect(screen.queryByRole('searchbox')).toBeNull();
        result.rerender(<Harness/>); await ready(); expect(query()).toHaveValue(''); search('443');
        result.rerender(<Harness session="second"/>); await ready(); expect(query()).toHaveValue(''); search('443');
        const value = view(); value.deviceId = 'agent_' + 'c'.repeat(32); vi.mocked(request).mockResolvedValue(value); result.rerender(<Harness session="second" id={value.deviceId}/>); await ready(); expect(query()).toHaveValue('');
        result.unmount(); expect(screen.queryByRole('searchbox')).toBeNull();
    });
    it('clears filters after a failed read and never restores them with the next valid response', async () => {
        render(<Harness/>); await ready(); search('443'); vi.mocked(request).mockRejectedValueOnce(new Error('private-error'));
        fireEvent.click(screen.getByRole('button', { name: 'Refresh fixture' })); await flush(); expect(screen.queryByRole('searchbox')).toBeNull();
        vi.mocked(request).mockResolvedValue(view()); fireEvent.click(screen.getByRole('button', { name: 'Refresh fixture' })); await ready(); expect(query()).toHaveValue(''); expect(document.body).not.toHaveTextContent('private-error');
    });
    it('clears filters at original source expiry and after a clock discontinuity', async () => {
        vi.useFakeTimers(); vi.setSystemTime(windowsNow); const value = view(); value.network.collectedAt = '2026-10-06T12:00:11Z'; value.snapshot!.collectedAt = value.network.collectedAt; value.status = 'stale';
        vi.mocked(request).mockResolvedValue(value); render(<Harness/>); await flush(); search('443'); await act(async () => vi.advanceTimersByTimeAsync(1000));
        expect(screen.queryByRole('searchbox')).toBeNull(); expect(screen.queryByRole('table')).toBeNull();
        vi.mocked(request).mockResolvedValue(view()); fireEvent.click(screen.getByRole('button', { name: 'Refresh fixture' })); await flush(); expect(query()).toHaveValue(''); search('443');
        vi.setSystemTime('2026-10-07T11:00:00Z'); await act(async () => vi.advanceTimersByTimeAsync(1000)); expect(screen.queryByRole('searchbox')).toBeNull();
    });
    it('supports German labels and the full passive workflow without links or mutating actions', async () => {
        setLocale('de', false); render(<Harness/>); await screen.findByRole('searchbox', { name: 'Erfasste Endpunkte finden' });
        select('Endpunkte anzeigen', 'listeners'); expect(screen.getByText('1–1 von 1 Treffern · 4 gespeichert')).toBeVisible();
        fireEvent.change(screen.getByRole('searchbox'), { target: { value: '443' } }); expect(screen.getByText('Keine gespeicherten Endpunkte entsprechen diesen Filtern.')).toBeVisible();
        fireEvent.click(screen.getByRole('button', { name: 'Endpunktfilter zurücksetzen' })); expect(screen.getByRole('searchbox')).toHaveValue('');
        expect(screen.queryByRole('link')).toBeNull(); expect(screen.queryByRole('button', { name: /connect|kill|terminate|scan|verbinden|beenden/i })).toBeNull();
        expect(request).toHaveBeenCalledTimes(1);
    });
});
