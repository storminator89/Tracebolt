import { APIError } from './api';
import { inventoryAge } from './complete-packages-types';
import { validFleetGroupName } from './fleet-groups-types';
import { validWindowsCapacityDeviceId, validWindowsCapacityTimestamp } from './windows-capacity-types';
import { sameWindowsServiceNames, validWindowsServiceHealthInventory, validWindowsServiceHealthSelection } from './windows-service-health-types';
import type { WindowsServiceHealthInventory, WindowsServiceHealthPolicy } from './windows-service-health-types';

export const GROUP_SERVICE_CHECKS_BYTES = 262144;
export type GroupServiceMember = { key: string; deviceId: string; name: string; policy: WindowsServiceHealthPolicy };
type GroupServiceMetadata = { serverNow: string; authorityExpiresAt: string; groupId: string; groupName: string; groupRevision: number };
export type GroupServiceChecksView = GroupServiceMetadata & { schemaVersion: 'tracebolt.fleet-group-service-checks.v1'; excludedLinuxMembers: number; unavailableMembers: number; members: GroupServiceMember[] };
export type GroupServiceChoiceView = GroupServiceMetadata & { schemaVersion: 'tracebolt.fleet-group-service-choice.v1'; member: GroupServiceMember & { inventory: WindowsServiceHealthInventory | null } };
export type GroupServiceSetting = { enabled: boolean; services: string[] };
export type GroupServiceBody = GroupServiceSetting & { groupRevision: number; expectedRevision: number; consent: true };
export type GroupServiceChecksIO = { active: () => boolean; get: () => Promise<GroupServiceChecksView>; choice: (key: string) => Promise<GroupServiceChoiceView>; post: (key: string, body: GroupServiceBody) => Promise<GroupServiceChoiceView> };
export type GroupServiceDraft = { choice: GroupServiceChoiceView; desired: GroupServiceSetting };
export type ReviewedServiceMember = GroupServiceMember & { desired: GroupServiceSetting };
export type GroupServiceReview = GroupServiceMetadata & { members: ReviewedServiceMember[] };
export type GroupServiceResult = ReviewedServiceMember & { status: 'changed' | 'currently-matching' | 'conflict' | 'unconfirmed' | 'not-attempted'; matchingAfterUnconfirmed?: boolean };
const exact = (v: unknown, keys: string[]): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v, k));
const integer = (v: unknown, min = 0): v is number => typeof v === 'number' && Number.isSafeInteger(v) && !Object.is(v, -0) && v >= min;
const bounded = (v: unknown) => new TextEncoder().encode(JSON.stringify(v)).byteLength <= GROUP_SERVICE_CHECKS_BYTES;
const metadata = (v: Record<string, unknown>, groupId: string) => /^group_[a-f0-9]{32}$/.test(groupId) && groupId !== `group_${'0'.repeat(32)}` && v.groupId === groupId && validFleetGroupName(v.groupName) && integer(v.groupRevision, 1) && validWindowsCapacityTimestamp(v.serverNow) && validWindowsCapacityTimestamp(v.authorityExpiresAt) && inventoryAge(v.authorityExpiresAt, v.serverNow) > 0 && inventoryAge(v.authorityExpiresAt, v.serverNow) <= 120000;
const policy = (v: unknown): v is WindowsServiceHealthPolicy => exact(v, ['enabled', 'services', 'revision']) && typeof v.enabled === 'boolean' && validWindowsServiceHealthSelection(v.services, v.enabled) && integer(v.revision) && (!v.enabled || v.revision > 0);
const member = (v: Record<string, unknown>) => typeof v.key === 'string' && /^[a-f0-9]{64}$/.test(v.key) && v.key !== '0'.repeat(64) && typeof v.deviceId === 'string' && validWindowsCapacityDeviceId(v.deviceId) && typeof v.name === 'string' && v.name.length > 0 && new TextEncoder().encode(v.name).byteLength <= 256 && policy(v.policy);
export function validGroupServiceChecksView(v: unknown, groupId: string): v is GroupServiceChecksView {
    return exact(v, ['schemaVersion', 'serverNow', 'authorityExpiresAt', 'groupId', 'groupName', 'groupRevision', 'excludedLinuxMembers', 'unavailableMembers', 'members']) && v.schemaVersion === 'tracebolt.fleet-group-service-checks.v1' && metadata(v, groupId) && integer(v.excludedLinuxMembers) && integer(v.unavailableMembers) && Array.isArray(v.members) && v.members.length <= 25 && v.members.length + v.excludedLinuxMembers + v.unavailableMembers <= 50 && v.members.every(m => exact(m, ['key', 'deviceId', 'name', 'policy']) && member(m)) && new Set(v.members.map(m => m.key)).size === v.members.length && new Set(v.members.map(m => m.deviceId)).size === v.members.length && bounded(v);
}
export function validGroupServiceChoiceView(v: unknown, groupId: string, key: string): v is GroupServiceChoiceView {
    return exact(v, ['schemaVersion', 'serverNow', 'authorityExpiresAt', 'groupId', 'groupName', 'groupRevision', 'member']) && v.schemaVersion === 'tracebolt.fleet-group-service-choice.v1' && metadata(v, groupId) && exact(v.member, ['key', 'deviceId', 'name', 'policy', 'inventory']) && v.member.key === key && member(v.member) && (v.member.inventory === null || validWindowsServiceHealthInventory(v.member.inventory, v.serverNow as string)) && bounded(v);
}
export const sameGroupServicePolicy = (a: WindowsServiceHealthPolicy, b: WindowsServiceHealthPolicy) => a.revision === b.revision && a.enabled === b.enabled && sameWindowsServiceNames(a.services, b.services);
const sameMember = (a: GroupServiceMember, b: GroupServiceMember) => a.key === b.key && a.deviceId === b.deviceId && a.name === b.name;
const sameGroup = (a: GroupServiceMetadata, b: GroupServiceMetadata) => a.groupId === b.groupId && a.groupName === b.groupName && a.groupRevision === b.groupRevision;
const matches = (policy: WindowsServiceHealthPolicy, desired: GroupServiceSetting) => policy.enabled === desired.enabled && sameWindowsServiceNames(policy.services, desired.services);
export function groupServiceChoices(view: GroupServiceChoiceView, age: number) {
    const source = view.member.inventory;
    return source && Number.isFinite(age) && age >= 0 && inventoryAge(view.serverNow, source.collectedAt) + age <= 120000 && inventoryAge(view.serverNow, source.receivedAt) + age <= 120000 ? source.services : [];
}
export function groupServiceSettingAllowed(view: GroupServiceChoiceView, desired: GroupServiceSetting, age = 0) {
    return typeof desired.enabled === 'boolean' && validWindowsServiceHealthSelection(desired.services, desired.enabled) && desired.services.every(name => !(desired.enabled && !view.member.policy.enabled || !view.member.policy.services.includes(name)) || groupServiceChoices(view, age).some(row => row.name === name));
}
const cloneMember = (m: ReviewedServiceMember): ReviewedServiceMember => ({ ...m, policy: { ...m.policy, services: [...m.policy.services] }, desired: { ...m.desired, services: [...m.desired.services] } });
const approved = new WeakMap<GroupServiceReview, GroupServiceReview>(), attempted = new WeakSet<GroupServiceReview>();
/** Freeze every input before network awaits; reads never add members or choices. */
export async function reviewGroupServiceChecks(original: GroupServiceChecksView, drafts: GroupServiceDraft[], io: GroupServiceChecksIO): Promise<GroupServiceReview> {
    if (!validGroupServiceChecksView(original, original.groupId) || drafts.length < 1 || drafts.length > 25 || new Set(drafts.map(d => d.choice.member.key)).size !== drafts.length) throw new Error('Invalid service review');
    const base = structuredClone(original), selected = structuredClone(drafts), members: ReviewedServiceMember[] = [];
    let authorityExpiresAt = base.authorityExpiresAt;
    for (const draft of selected) {
        const previous = base.members.find(m => m.key === draft.choice.member.key);
        if (!previous || !validGroupServiceChoiceView(draft.choice, base.groupId, previous.key) || !sameGroup(base, draft.choice) || !sameMember(previous, draft.choice.member) || !sameGroupServicePolicy(previous.policy, draft.choice.member.policy) || !groupServiceSettingAllowed(draft.choice, draft.desired) || !io.active()) throw new Error('Service selection changed');
        const current = await io.choice(previous.key);
        if (!io.active() || !validGroupServiceChoiceView(current, base.groupId, previous.key) || !sameGroup(base, current) || !sameMember(previous, current.member) || !sameGroupServicePolicy(previous.policy, current.member.policy) || inventoryAge(authorityExpiresAt, current.serverNow) <= 0 || !groupServiceSettingAllowed(current, draft.desired)) throw new Error('Service review changed');
        if (inventoryAge(current.authorityExpiresAt, authorityExpiresAt) < 0) authorityExpiresAt = current.authorityExpiresAt;
        members.push(cloneMember({ ...previous, desired: draft.desired }));
    }
    const review = { serverNow: base.serverNow, authorityExpiresAt, groupId: base.groupId, groupName: base.groupName, groupRevision: base.groupRevision, members };
    approved.set(review, { ...review, members: members.map(cloneMember) });
    return review;
}
/** Single-use, sequential, exact-name policy changes. Any ambiguity stops the remainder. */
export async function applyGroupServiceChecks(review: GroupServiceReview, io: GroupServiceChecksIO, update: (rows: GroupServiceResult[]) => void): Promise<GroupServiceResult[]> {
    const frozen = approved.get(review);
    if (!frozen || attempted.has(review)) throw new Error('A fresh service review is required');
    attempted.add(review);
    const rows: GroupServiceResult[] = frozen.members.map(m => ({ ...cloneMember(m), status: 'not-attempted' }));
    const publish = () => update(rows.map(r => ({ ...cloneMember(r), status: r.status, ...(r.matchingAfterUnconfirmed === undefined ? {} : { matchingAfterUnconfirmed: r.matchingAfterUnconfirmed }) })));
    const validCurrent = (v: unknown, row: ReviewedServiceMember): v is GroupServiceChoiceView => validGroupServiceChoiceView(v, frozen.groupId, row.key) && sameGroup(frozen, v) && sameMember(row, v.member) && inventoryAge(frozen.authorityExpiresAt, v.serverNow) > 0;
    publish();
    for (const row of rows) {
        if (!io.active()) break;
        try {
            const current = await io.choice(row.key);
            if (!io.active()) break;
            if (!validCurrent(current, row) || !sameGroupServicePolicy(row.policy, current.member.policy) || !groupServiceSettingAllowed(current, row.desired)) throw new Error('Service review changed');
            if (matches(current.member.policy, row.desired)) { row.status = 'currently-matching'; publish(); continue; }
        } catch { if (io.active()) row.status = 'conflict'; publish(); break; }
        if (!io.active()) break;
        try {
            const result = await io.post(row.key, { groupRevision: frozen.groupRevision, expectedRevision: row.policy.revision, enabled: row.desired.enabled, services: [...row.desired.services], consent: true });
            if (!io.active() || !validCurrent(result, row) || result.member.policy.revision !== row.policy.revision + 1 || !matches(result.member.policy, row.desired)) throw new Error('Service write unconfirmed');
            row.status = 'changed'; publish();
        } catch (error) {
            row.status = error instanceof APIError && [400, 401, 403, 404, 409, 410].includes(error.status ?? 0) ? 'conflict' : 'unconfirmed';
            publish();
            if (io.active()) {
                try { const current = await io.choice(row.key); if (io.active() && validCurrent(current, row)) row.matchingAfterUnconfirmed = matches(current.member.policy, row.desired); } catch { /* GET-only reconciliation cannot confirm who wrote the policy. */ }
                publish();
            }
            break;
        }
    }
    publish(); return rows;
}
