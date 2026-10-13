import { validWindowsCapacityDeviceId, validWindowsCapacityTimestamp } from './windows-capacity-types';
export interface FleetGroupDevice { id: string; name: string; platform: 'windows' | 'linux' | 'macos' }
export interface FleetGroup { id: string; name: string; revision: number; memberIds: string[]; unavailableMembers: number }
export interface FleetGroupsView { schemaVersion: 'tracebolt.fleet-groups.v1'; serverNow: string; groups: FleetGroup[]; devices: FleetGroupDevice[] }
const exact = (v: unknown, keys: string[]): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v, k));
export const validFleetGroupName = (v: unknown): v is string => typeof v === 'string' && v === v.trim() && new TextEncoder().encode(v).length > 0 && new TextEncoder().encode(v).length <= 80 && !/[\p{Cc}\p{Cf}]/u.test(v);
export function validFleetGroupsView(v: unknown): v is FleetGroupsView {
    if (!exact(v, ['schemaVersion', 'serverNow', 'groups', 'devices']) || v.schemaVersion !== 'tracebolt.fleet-groups.v1' || !validWindowsCapacityTimestamp(v.serverNow) || !Array.isArray(v.groups) || v.groups.length > 25 || !Array.isArray(v.devices) || v.devices.length > 100) return false;
    if (!v.devices.every(d => exact(d, ['id', 'name', 'platform']) && typeof d.id === 'string' && validWindowsCapacityDeviceId(d.id) && typeof d.name === 'string' && d.name.length > 0 && new TextEncoder().encode(d.name).length <= 256 && (d.platform === 'windows' || d.platform === 'linux' || d.platform === 'macos')) || new Set(v.devices.map(d => d.id)).size !== v.devices.length) return false;
    const ids = new Set(v.devices.map(d => d.id));
    return v.groups.every(g => exact(g, ['id', 'name', 'revision', 'memberIds', 'unavailableMembers']) && typeof g.id === 'string' && /^group_[a-f0-9]{32}$/.test(g.id) && g.id !== `group_${'0'.repeat(32)}` && validFleetGroupName(g.name) && Number.isSafeInteger(g.revision) && Number(g.revision) > 0 && Number.isSafeInteger(g.unavailableMembers) && Number(g.unavailableMembers) >= 0 && Array.isArray(g.memberIds) && g.memberIds.length + Number(g.unavailableMembers) <= 50 && g.memberIds.every(id => typeof id === 'string' && ids.has(id)) && new Set(g.memberIds).size === g.memberIds.length) && new Set(v.groups.map(g => g.id)).size === v.groups.length;
}
