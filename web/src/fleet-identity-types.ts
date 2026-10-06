import type { EndpointAddress, EndpointIdentityView, EndpointReason, EndpointStatus } from './endpoint-identity-types';
import { endpointAgeStatus, endpointSnapshotVisible, validEndpointView } from './endpoint-identity-types';
export const FLEET_IDENTITY_BYTES = 256 * 1024, FLEET_IDENTITY_LIMIT = 25;
export interface FleetIdentityView { schemaVersion: 'tracebolt.fleet-endpoint-identity.v1'; serverNow: string; items: EndpointIdentityView[] }
export interface FleetAddress extends EndpointAddress { interfaceName: string; interfaceIndex: number; up: boolean; loopback: boolean }
export interface FleetIdentityDisplay { status: EndpointStatus; hostname: string | null; hostnameReason: EndpointReason | null; addressReason: EndpointReason | null; addresses: FleetAddress[]; collectedAt: string | null; coverage: 'complete' | 'partial' | 'failed' | null }
export type FleetIdentityMap = ReadonlyMap<string, FleetIdentityDisplay>;
export const emptyFleetIdentity: FleetIdentityMap = new Map();
export function validFleetIdentityView(value: unknown): value is FleetIdentityView {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
    const v = value as Record<string, unknown>;
    if (Object.keys(v).length !== 3 || v.schemaVersion !== 'tracebolt.fleet-endpoint-identity.v1' || typeof v.serverNow !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(v.serverNow) || !Number.isFinite(Date.parse(v.serverNow)) || Number(v.serverNow.slice(0, 4)) < 1970 || new Date(Date.parse(v.serverNow)).toISOString().slice(0, 19) !== v.serverNow.slice(0, 19) || !Array.isArray(v.items) || v.items.length > FLEET_IDENTITY_LIMIT) return false;
    let previous = '';
    for (const item of v.items) {
        if (!item || typeof item.deviceId !== 'string' || item.deviceId <= previous || item.serverNow !== v.serverNow || !validEndpointView(item, item.deviceId)) return false;
        previous = item.deviceId;
    }
    return new TextEncoder().encode(JSON.stringify(v)).byteLength < FLEET_IDENTITY_BYTES;
}
/** Ephemeral display/search projection only. Never assign it to Device or export it. */
export function fleetIdentityProjection(view: FleetIdentityView | null, elapsed: number): FleetIdentityMap {
    return new Map(view?.items.map(item => {
        const snapshot = endpointSnapshotVisible(item, elapsed) ? item.latest : null;
        const addresses = snapshot?.interfaces.items.flatMap(row => [...row.addresses.ipv4.items, ...row.addresses.ipv6.items].map(address => ({ ...address, interfaceName: row.name, interfaceIndex: row.index, up: row.up, loopback: row.loopback }))) ?? [];
        // Display order only. No address is selected as a primary or connection target.
        addresses.sort((a, b) => Number(a.loopback) - Number(b.loopback) || Number(b.up) - Number(a.up) || a.interfaceIndex - b.interfaceIndex);
        return [item.deviceId, { status: endpointAgeStatus(item, elapsed), hostname: snapshot?.reportedHostname.value ?? null, hostnameReason: snapshot?.reportedHostname.reason ?? null, addressReason: snapshot?.interfaces.meta.reason ?? null, addresses, collectedAt: snapshot?.collectedAt ?? null, coverage: snapshot?.interfaces.meta.coverage ?? null }];
    }) ?? []);
}
