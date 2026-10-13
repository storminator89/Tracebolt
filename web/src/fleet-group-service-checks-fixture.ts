import { windowsNow, windowsDeviceId } from './windows-inventory-fixture';
import { windowsServiceHealthInventory } from './windows-service-health-fixture';
import type { GroupServiceChecksView, GroupServiceChoiceView } from './fleet-group-service-checks-workflow';
export const serviceChecksGroupId = `group_${'4'.repeat(32)}`;
/** Invented, existing consented inventory only; these fixtures perform no host reads. */
export function groupServiceChecksFixture(): GroupServiceChecksView {
    return { schemaVersion: 'tracebolt.fleet-group-service-checks.v1', serverNow: windowsNow, authorityExpiresAt: '2026-10-07T12:02:10Z', groupId: serviceChecksGroupId, groupName: 'Office', groupRevision: 2, excludedLinuxMembers: 1, unavailableMembers: 1, members: [`agent_${'2'.repeat(32)}`, windowsDeviceId].map((deviceId, i) => ({ key: (i + 1).toString(16).padStart(64, '0'), deviceId, name: i ? 'Desk Two' : 'Desk One', policy: { enabled: false, services: [], revision: 0 } })) };
}
export function groupServiceChoiceFixture(view: GroupServiceChecksView, key = view.members[0].key): GroupServiceChoiceView {
    const { serverNow, authorityExpiresAt, groupId, groupName, groupRevision } = view;
    return { schemaVersion: 'tracebolt.fleet-group-service-choice.v1', serverNow, authorityExpiresAt, groupId, groupName, groupRevision, member: { ...structuredClone(view.members.find(m => m.key === key)!), inventory: windowsServiceHealthInventory() } };
}
