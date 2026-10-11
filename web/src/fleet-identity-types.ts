import { validWindowsFleetIdentity, windowsFleetStatus, type WindowsFleetIdentityView } from './windows-fleet-identity-types';
import type { EndpointAddress, EndpointIdentityView, EndpointReason, EndpointStatus } from './endpoint-identity-types';
import { endpointAgeStatus, endpointSnapshotVisible, validEndpointView } from './endpoint-identity-types';
export const FLEET_IDENTITY_BYTES = 256 * 1024, FLEET_IDENTITY_LIMIT = 25;
export const FLEET_IDENTITIES_BYTES = 2 * FLEET_IDENTITY_BYTES, FLEET_IDENTITIES_LIMIT = 2 * FLEET_IDENTITY_LIMIT;
export interface FleetIdentityView { schemaVersion: 'tracebolt.fleet-endpoint-identity.v1'; serverNow: string; items: EndpointIdentityView[] }
export type FleetIdentityItem = EndpointIdentityView | WindowsFleetIdentityView;
export interface FleetIdentitiesView { schemaVersion: 'tracebolt.fleet-identities.v2'; serverNow: string; items: FleetIdentityItem[] }
export type AnyFleetIdentityView = FleetIdentityView | FleetIdentitiesView;
export interface FleetAddress { family: EndpointAddress['family']; address: string; scope: EndpointAddress['scope'] | 'unreported'; interfaceName: string; interfaceIndex: number; up: boolean | null; loopback: boolean | null; prefixLength?: number }
export interface FleetIdentityDisplay { status: EndpointStatus; hostname: string | null; hostnameReason: EndpointReason | 'unavailable' | null; addressReason: EndpointReason | 'unavailable' | null; addresses: FleetAddress[]; collectedAt: string | null; coverage: 'complete' | 'partial' | 'failed' | null; source?: 'windows'; hostnamePartial?: boolean; windows?: { hostnameSource: string; hostnameScope: string; networkSource: string; networkScope: string; observedCount: number; countExact: boolean; truncated: boolean } }
export type FleetIdentityMap = ReadonlyMap<string, FleetIdentityDisplay>;
export const emptyFleetIdentity: FleetIdentityMap = new Map();
export function validFleetIdentityView(value: unknown): value is AnyFleetIdentityView {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
    const v = value as Record<string, unknown>;
    if (Object.keys(v).length !== 3 || !['tracebolt.fleet-endpoint-identity.v1', 'tracebolt.fleet-identities.v2'].includes(v.schemaVersion as string) || typeof v.serverNow !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(v.serverNow) || !Number.isFinite(Date.parse(v.serverNow)) || Number(v.serverNow.slice(0, 4)) < 1970 || new Date(Date.parse(v.serverNow)).toISOString().slice(0, 19) !== v.serverNow.slice(0, 19) || !Array.isArray(v.items) || v.items.length > (v.schemaVersion === 'tracebolt.fleet-identities.v2' ? FLEET_IDENTITIES_LIMIT : FLEET_IDENTITY_LIMIT)) return false;
    let previous = '';
    for (const item of v.items) {
        if (!item || typeof item.deviceId !== 'string' || item.deviceId <= previous || item.serverNow !== v.serverNow || !(item.schemaVersion === 'tracebolt.windows-fleet-identity-view.v1' ? v.schemaVersion === 'tracebolt.fleet-identities.v2' && validWindowsFleetIdentity(item) : validEndpointView(item, item.deviceId))) return false;
        previous = item.deviceId;
    }
    return new TextEncoder().encode(JSON.stringify(v)).byteLength < (v.schemaVersion === 'tracebolt.fleet-identities.v2' ? FLEET_IDENTITIES_BYTES : FLEET_IDENTITY_BYTES);
}
/** Ephemeral display/search projection only. Never assign it to Device or export it. */
export function fleetIdentityProjection(view: AnyFleetIdentityView | null, elapsed: number): FleetIdentityMap {
    return new Map<string, FleetIdentityDisplay>(view?.items.map(item => {
        if (item.schemaVersion === 'tracebolt.windows-fleet-identity-view.v1') {
            const status = windowsFleetStatus(item, elapsed), snapshot = status === 'fresh' || status === 'stale' ? item.latest : null;
            const reason = (quality: string | undefined): EndpointReason | 'unavailable' | null => quality === 'denied' ? 'permission_denied' : quality === 'unavailable' ? 'unavailable' : null;
            return [item.deviceId, { source: 'windows', hostnamePartial: snapshot?.hostname.quality === 'partial', status: status === 'awaiting' ? 'not_collected' : status, hostname: snapshot?.hostname.rows[0]?.value ?? null, hostnameReason: reason(snapshot?.hostname.quality), addressReason: reason(snapshot?.network.quality), addresses: snapshot?.network.rows.map(row => ({ family: row.address.includes(':') ? 'ipv6' : 'ipv4', address: row.address, scope: 'unreported', interfaceName: row.name, interfaceIndex: row.index, up: null, loopback: null, prefixLength: row.prefixLength })) ?? [], collectedAt: snapshot?.collectedAt ?? null, coverage: snapshot ? snapshot.network.quality === 'healthy' ? 'complete' : snapshot.network.quality === 'partial' ? 'partial' : 'failed' : null, ...(snapshot ? { windows: { hostnameSource: snapshot.hostname.source, hostnameScope: snapshot.hostname.scope, networkSource: snapshot.network.source, networkScope: snapshot.network.scope, observedCount: snapshot.network.observedCount, countExact: snapshot.network.countExact, truncated: snapshot.network.truncated } } : {}) }];
        }
        const snapshot = endpointSnapshotVisible(item, elapsed) ? item.latest : null;
        const addresses = snapshot?.interfaces.items.flatMap(row => [...row.addresses.ipv4.items, ...row.addresses.ipv6.items].map(address => ({ ...address, interfaceName: row.name, interfaceIndex: row.index, up: row.up, loopback: row.loopback }))) ?? [];
        // Display order only. No address is selected as a primary or connection target.
        addresses.sort((a, b) => Number(a.loopback) - Number(b.loopback) || Number(b.up) - Number(a.up) || a.interfaceIndex - b.interfaceIndex);
        return [item.deviceId, { status: endpointAgeStatus(item, elapsed), hostname: snapshot?.reportedHostname.value ?? null, hostnameReason: snapshot?.reportedHostname.reason ?? null, addressReason: snapshot?.interfaces.meta.reason ?? null, addresses, collectedAt: snapshot?.collectedAt ?? null, coverage: snapshot?.interfaces.meta.coverage ?? null }];
    }) ?? []);
}

export function fleetIdentityVisible(item: FleetIdentityItem, elapsed: number): boolean {
    if (item.schemaVersion === 'tracebolt.windows-fleet-identity-view.v1') return item.latest !== null && ['fresh', 'stale'].includes(windowsFleetStatus(item, elapsed));
    return endpointSnapshotVisible(item, elapsed);
}
