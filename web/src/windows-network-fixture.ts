import type { WindowsNetwork } from './windows-network-types';
export function windowsNetwork(): WindowsNetwork {
    return { schemaVersion: 'tracebolt.windows-network-endpoints.v1', scope: 'windows-network-endpoints-v1', grantId: 'f'.repeat(32), generationId: `sample_${'a'.repeat(32)}`, collectedAt: '2026-10-07T12:00:03Z', quality: 'observed', countExact: true, observedCount: 4, truncated: false, rows: [
        { protocol: 'tcp', family: 'ipv4', localAddress: '0.0.0.0', localPort: 135, remoteAddress: null, remotePort: null, state: 'listen', pid: 4 },
        { protocol: 'tcp', family: 'ipv6', localAddress: '2001:db8::40', localPort: 49152, remoteAddress: '2001:db8::80', remotePort: 443, state: 'established', pid: 44 },
        { protocol: 'udp', family: 'ipv4', localAddress: '127.0.0.1', localPort: 5353, remoteAddress: null, remotePort: null, state: null, pid: 42 },
        { protocol: 'udp', family: 'ipv6', localAddress: 'fe80::40%4', localPort: 5353, remoteAddress: null, remotePort: null, state: null, pid: 0 },
    ] };
}
