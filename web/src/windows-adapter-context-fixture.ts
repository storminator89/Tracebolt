import { windowsView } from './windows-inventory-fixture';
import type { WindowsAdapterContext } from './windows-adapter-context-types';
export function windowsAdapterContext(): WindowsAdapterContext {
    return { schemaVersion: 'tracebolt.windows-adapter-context.v1', scope: 'windows-adapter-context-v1', grantId: '8'.repeat(32), generationId: `sample_${'a'.repeat(32)}`, collectedAt: '2026-10-07T12:00:00Z', quality: 'observed', countExact: true, observedCount: 3, truncated: false, rows: [
        { ifIndex: 4, ipv6IfIndex: 4, name: 'Fixture Ethernet', state: 'up', txLinkBps: 1000000000, txQuality: 'observed', rxLinkBps: 2500000000, rxQuality: 'observed', dnsServers: { quality: 'observed', addresses: ['192.0.2.53', '2001:db8::53'] }, gateways: { quality: 'observed', addresses: ['192.0.2.1', 'fe80::1%4'] } },
        { ifIndex: 8, ipv6IfIndex: 8, name: 'Fixture Wi-Fi', state: 'down', txLinkBps: null, txQuality: 'unknown', rxLinkBps: null, rxQuality: 'unavailable', dnsServers: { quality: 'observed', addresses: [] }, gateways: { quality: 'unavailable', addresses: [] } },
        { ifIndex: 12, ipv6IfIndex: 0, name: 'Fixture tunnel', state: 'unknown', txLinkBps: null, txQuality: 'unavailable', rxLinkBps: null, rxQuality: 'unknown', dnsServers: { quality: 'partial', addresses: ['198.51.100.53'] }, gateways: { quality: 'partial', addresses: [] } },
    ] };
}
export function windowsAdapterContextView() { return { ...windowsView(), adapterContext: windowsAdapterContext() }; }
