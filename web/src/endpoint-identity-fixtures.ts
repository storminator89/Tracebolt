import type { EndpointAddress, EndpointIdentityView, EndpointInterface, EndpointMeta, EndpointSnapshot } from './endpoint-identity-types';
// Fixed synthetic observations only. These fixtures never read the host.
export const endpointDevice = `agent_${'7'.repeat(32)}`;
export const endpointComplete = (n: number): EndpointMeta => ({ coverage: 'complete', reason: 'none', observedCount: n, countExact: true });
export const endpointFailed = (reason: EndpointMeta['reason'] = 'permission_denied'): EndpointMeta => ({ coverage: 'failed', reason, observedCount: null, countExact: false });
export function endpointInterface(index = 2, name = 'eth0'): EndpointInterface {
    const ipv4: EndpointAddress[] = [{ family: 'ipv4', address: '192.0.2.19', scope: 'other' }];
    const ipv6: EndpointAddress[] = [{ family: 'ipv6', address: '2001:db8::19', scope: 'other' }, { family: 'ipv6', address: 'fe80::19', scope: 'link-local' }];
    return { index, name, up: true, loopback: false, hardwareKind: 'unknown', addresses: { ipv4: { meta: endpointComplete(ipv4.length), items: ipv4 }, ipv6: { meta: endpointComplete(ipv6.length), items: ipv6 } } };
}
export function endpointSnapshot(): EndpointSnapshot {
    return { schemaVersion: 'tracebolt.endpoint-identity.v1', generationId: `sample_${'a'.repeat(32)}`, collectedAt: '2026-10-04T12:00:00Z', durationMs: 12, scope: 'agent-visible-linux-hostname-and-interface-addresses', reportedHostname: { coverage: 'complete', reason: 'none', value: 'fixture-linux' }, interfaces: { meta: endpointComplete(2), items: [{ index: 1, name: 'lo', up: true, loopback: true, hardwareKind: 'unknown', addresses: { ipv4: { meta: endpointComplete(1), items: [{ family: 'ipv4', address: '127.0.0.1', scope: 'loopback' }] }, ipv6: { meta: endpointComplete(1), items: [{ family: 'ipv6', address: '::1', scope: 'loopback' }] } } }, endpointInterface()] } };
}
export function endpointView(): EndpointIdentityView {
    return { schemaVersion: 'tracebolt.endpoint-identity-view.v1', deviceId: endpointDevice, status: 'fresh', serverNow: '2026-10-04T12:00:10Z', maxAgeSeconds: 120, sequence: '9', receivedAt: '2026-10-04T12:00:01Z', expiresAt: '2026-10-05T12:00:00Z', latest: endpointSnapshot() };
}
export function emptyEndpointView(status: 'not_collected' | 'revoked' | 'expired' | 'unknown' = 'not_collected'): EndpointIdentityView {
    return { ...endpointView(), status, sequence: null, receivedAt: null, expiresAt: null, latest: null };
}
