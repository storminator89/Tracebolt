import type { WindowsNetwork, WindowsNetworkEndpoint } from './windows-network-types';

export type NetworkSearchField = 'any' | 'address' | 'local-port' | 'remote-port' | 'pid';
export type NetworkFilter = 'all' | 'tcp' | 'listeners' | 'established' | 'udp';
export type NetworkFamily = 'all' | 'ipv4' | 'ipv6';
export type NetworkSort = 'capture' | 'local-port-asc' | 'local-port-desc' | 'remote-port-asc' | 'remote-port-desc' | 'pid-asc' | 'pid-desc';
export interface NetworkFinderControls { query: string; field: NetworkSearchField; filter: NetworkFilter; family: NetworkFamily; sort: NetworkSort; page: number }
export const initialNetworkFinderControls = (): NetworkFinderControls => ({ query: '', field: 'any', filter: 'all', family: 'all', sort: 'capture', page: 0 });
export const networkEndpointLabel = (address: string, port: number) => `${address.includes(':') ? `[${address}]` : address}:${port}`;
export const networkPID = (row: WindowsNetworkEndpoint): number | null => row.protocol === 'udp' && row.pid === 0 ? null : row.pid;
export function networkQueryError({ query, field }: Pick<NetworkFinderControls, 'query' | 'field'>): 'port' | 'pid' | null {
    const value = query.trim();
    if (!value || field === 'any' || field === 'address') return null;
    const max = field === 'pid' ? 4294967295 : 65535;
    return /^\d+$/.test(value) && value.length <= 10 && Number(value) <= max ? null : field === 'pid' ? 'pid' : 'port';
}
/** Only accepted retained rows: no requests, joins, inferred identities or source changes. */
export function findNetworkEndpoints(network: WindowsNetwork, controls: NetworkFinderControls): WindowsNetworkEndpoint[] {
    if (networkQueryError(controls)) return [];
    const query = controls.query.trim().toLowerCase();
    const rows = network.rows.map((row, index) => ({ row, index })).filter(({ row }) => {
        if (controls.family !== 'all' && row.family !== controls.family) return false;
        if (controls.filter === 'tcp' && row.protocol !== 'tcp' || controls.filter === 'udp' && row.protocol !== 'udp' || controls.filter === 'listeners' && (row.protocol !== 'tcp' || row.state !== 'listen') || controls.filter === 'established' && (row.protocol !== 'tcp' || row.state !== 'established')) return false;
        if (!query) return true;
        if (controls.field === 'local-port') return row.localPort === Number(query);
        if (controls.field === 'remote-port') return row.remotePort !== null && row.remotePort === Number(query);
        if (controls.field === 'pid') return networkPID(row) !== null && networkPID(row) === Number(query);
        const addresses = [row.localAddress, row.remoteAddress].filter((value): value is string => value !== null);
        if (controls.field === 'address') return addresses.some(value => value.toLowerCase().includes(query));
        const values = [...addresses, networkEndpointLabel(row.localAddress, row.localPort), ...(row.remoteAddress !== null && row.remotePort !== null ? [networkEndpointLabel(row.remoteAddress, row.remotePort)] : []), String(row.localPort), ...(row.remotePort !== null ? [String(row.remotePort)] : []), ...(networkPID(row) !== null ? [String(networkPID(row))] : []), row.protocol, row.family, row.state ?? ''];
        return values.some(value => value.toLowerCase().includes(query));
    });
    if (controls.sort !== 'capture') rows.sort((a, b) => {
        const value = (row: WindowsNetworkEndpoint) => controls.sort.startsWith('local-port') ? row.localPort : controls.sort.startsWith('remote-port') ? row.remotePort : networkPID(row);
        const left = value(a.row), right = value(b.row);
        // Unavailable and inapplicable values stay last in either direction.
        if (left === null || right === null) return left === right ? a.index - b.index : left === null ? 1 : -1;
        return (left - right) * (controls.sort.endsWith('desc') ? -1 : 1) || a.index - b.index;
    });
    return rows.map(({ row }) => row);
}
