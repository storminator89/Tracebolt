import type { GroupMaintenanceView } from './fleet-group-maintenance-workflow';
import { WINDOWS_MAINTENANCE_DOMAINS } from './windows-maintenance-types';
import { windowsNow, windowsDeviceId } from './windows-inventory-fixture';
export const maintenanceGroupId = `group_${'4'.repeat(32)}`;
export const maintenanceSecondId = `agent_${'2'.repeat(32)}`;
export function groupMaintenanceFixture(): GroupMaintenanceView {
    return { schemaVersion: 'tracebolt.fleet-group-maintenance.v1', serverNow: windowsNow, authorityExpiresAt: new Date(Date.parse(windowsNow) + 120000).toISOString().replace('.000Z', 'Z'), groupId: maintenanceGroupId, groupName: 'Office', groupRevision: 2, excludedLinuxMembers: 1, unavailableMembers: 1, members: [maintenanceSecondId, windowsDeviceId].sort().map((deviceId, i) => ({ deviceId, name: deviceId === windowsDeviceId ? 'Desk One' : 'Desk Two', targets: WINDOWS_MAINTENANCE_DOMAINS.map((domain, j) => ({ key: (i * 6 + j + 1).toString(16).padStart(64, '0'), deviceId, domain, revision: 0, changedAt: null, windows: [] })) })) };
}
