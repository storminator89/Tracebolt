import type { GroupMaintenanceView } from './fleet-group-maintenance-workflow';
import { WINDOWS_MAINTENANCE_DOMAINS } from './windows-maintenance-types';
import { windowsNow, windowsDeviceId } from './windows-inventory-fixture';
export const maintenanceGroupId = `group_${'4'.repeat(32)}`;
export const maintenanceSecondId = `agent_${'2'.repeat(32)}`;
export function groupMaintenanceFixture(): GroupMaintenanceView {
    return { schemaVersion: 'tracebolt.fleet-group-maintenance.v1', serverNow: windowsNow, authorityExpiresAt: new Date(Date.parse(windowsNow) + 120000).toISOString().replace('.000Z', 'Z'), groupId: maintenanceGroupId, groupName: 'Office', groupRevision: 2, excludedLinuxMembers: 1, unavailableMembers: 1, members: [maintenanceSecondId, windowsDeviceId].sort().map((deviceId, i) => ({ deviceId, name: deviceId === windowsDeviceId ? 'Desk One' : 'Desk Two', targets: WINDOWS_MAINTENANCE_DOMAINS.map((domain, j) => ({ key: (i * 6 + j + 1).toString(16).padStart(64, '0'), deviceId, domain, revision: 0, changedAt: null, windows: [] })) })) };
}

/** Three independent active windows, including two scopes on the same identity. */
export function groupMaintenanceEndFixture(): GroupMaintenanceView {
    const view = groupMaintenanceFixture();
    for (const [i, member] of view.members.entries()) {
        for (const target of member.targets.filter(target => i === 0 ? ['cpu', 'disk'].includes(target.domain) : target.domain === 'all')) {
            target.revision = 1; target.changedAt = view.serverNow;
            target.windows = [{ id: 1, startedAt: view.serverNow, endsAt: new Date(Date.parse(view.serverNow) + (i === 0 ? 30 : 60) * 60000).toISOString().replace('.000Z', 'Z'), endedAt: null, intent: 'planned-work' }];
        }
    }
    return view;
}
