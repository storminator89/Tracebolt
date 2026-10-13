import { APIError } from './api';
import { inventoryAge } from './complete-packages-types';
import { validFleetGroupName } from './fleet-groups-types';
import { validWindowsCapacityDeviceId, validWindowsCapacityTimestamp } from './windows-capacity-types';
import { fullServicesGenerationId } from './windows-full-services-types';
import type { CompleteServiceSelectionEvidence } from './windows-service-health-complete-picker';
import { sameWindowsServiceNames } from './windows-service-health-types';
import { validWindowsServiceHealthCompleteInventory, validWindowsServiceHealthCompletePolicy, validWindowsServiceHealthCompleteSelection, sameWindowsServiceHealthSource, windowsServiceHealthSourceFresh, sourceBindingMatches } from './windows-service-health-complete-types';
import type { WindowsServiceHealthCompleteInventory, WindowsServiceHealthCompletePolicy, WindowsServiceHealthSource } from './windows-service-health-complete-types';

export const GROUP_COMPLETE_SERVICE_CHECKS_BYTES = 262144;
export type GroupCompleteServiceMember = { key: string; deviceId: string; name: string; policy: WindowsServiceHealthCompletePolicy };
type GroupCompleteServiceMetadata = { serverNow: string; authorityExpiresAt: string; groupId: string; groupName: string; groupRevision: number };
export type GroupCompleteServiceChecksView = GroupCompleteServiceMetadata & { schemaVersion: 'tracebolt.fleet-group-service-checks.v2'; excludedLinuxMembers: number; unavailableMembers: number; members: GroupCompleteServiceMember[] };
export type GroupCompleteServiceChoiceView = GroupCompleteServiceMetadata & { schemaVersion: 'tracebolt.fleet-group-service-choice.v2'; member: GroupCompleteServiceMember & { inventory: WindowsServiceHealthCompleteInventory | null } };
export type GroupCompleteServiceSetting = { enabled: boolean; services: string[]; source: WindowsServiceHealthSource | null };
export type GroupCompleteServiceBody = GroupCompleteServiceSetting & { groupRevision: number; expectedRevision: number; consent: true };
export type GroupCompleteServiceChecksIO = { active: () => boolean; get: () => Promise<GroupCompleteServiceChecksView>; choice: (key: string) => Promise<GroupCompleteServiceChoiceView>; post: (key: string, body: GroupCompleteServiceBody) => Promise<GroupCompleteServiceChoiceView> };
export type GroupCompleteServiceDraft = { choice: GroupCompleteServiceChoiceView; desired: GroupCompleteServiceSetting; evidence: CompleteServiceSelectionEvidence | null };
export type ReviewedServiceMember = GroupCompleteServiceMember & { desired: GroupCompleteServiceSetting; evidence: CompleteServiceSelectionEvidence | null };
export type GroupCompleteServiceReview = GroupCompleteServiceMetadata & { members: ReviewedServiceMember[] };
export type GroupCompleteServiceResult = ReviewedServiceMember & { status: 'changed' | 'currently-matching' | 'conflict' | 'unconfirmed' | 'not-attempted'; matchingAfterUnconfirmed?: boolean };
const exact = (v: unknown, keys: string[]): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v, k));
const integer = (v: unknown, min = 0): v is number => typeof v === 'number' && Number.isSafeInteger(v) && !Object.is(v, -0) && v >= min;
const bounded = (v: unknown) => new TextEncoder().encode(JSON.stringify(v)).byteLength <= GROUP_COMPLETE_SERVICE_CHECKS_BYTES;
const metadata = (v: Record<string, unknown>, groupId: string) => /^group_[a-f0-9]{32}$/.test(groupId) && groupId !== `group_${'0'.repeat(32)}` && v.groupId === groupId && validFleetGroupName(v.groupName) && integer(v.groupRevision, 1) && validWindowsCapacityTimestamp(v.serverNow) && validWindowsCapacityTimestamp(v.authorityExpiresAt) && inventoryAge(v.authorityExpiresAt, v.serverNow) > 0 && inventoryAge(v.authorityExpiresAt, v.serverNow) <= 120000;
const policy = validWindowsServiceHealthCompletePolicy;
const member = (v: Record<string, unknown>) => typeof v.key === 'string' && /^[a-f0-9]{64}$/.test(v.key) && v.key !== '0'.repeat(64) && typeof v.deviceId === 'string' && validWindowsCapacityDeviceId(v.deviceId) && typeof v.name === 'string' && v.name.length > 0 && new TextEncoder().encode(v.name).byteLength <= 256 && policy(v.policy);
export function validGroupCompleteServiceChecksView(v: unknown, groupId: string): v is GroupCompleteServiceChecksView {
    return exact(v, ['schemaVersion', 'serverNow', 'authorityExpiresAt', 'groupId', 'groupName', 'groupRevision', 'excludedLinuxMembers', 'unavailableMembers', 'members']) && v.schemaVersion === 'tracebolt.fleet-group-service-checks.v2' && metadata(v, groupId) && integer(v.excludedLinuxMembers) && integer(v.unavailableMembers) && Array.isArray(v.members) && v.members.length <= 25 && v.members.length + v.excludedLinuxMembers + v.unavailableMembers <= 50 && v.members.every(m => exact(m, ['key', 'deviceId', 'name', 'policy']) && member(m)) && new Set(v.members.map(m => m.key)).size === v.members.length && new Set(v.members.map(m => m.deviceId)).size === v.members.length && bounded(v);
}
export function validGroupCompleteServiceChoiceView(v: unknown, groupId: string, key: string): v is GroupCompleteServiceChoiceView {
    return exact(v, ['schemaVersion', 'serverNow', 'authorityExpiresAt', 'groupId', 'groupName', 'groupRevision', 'member']) && v.schemaVersion === 'tracebolt.fleet-group-service-choice.v2' && metadata(v, groupId) && exact(v.member, ['key', 'deviceId', 'name', 'policy', 'inventory']) && v.member.key === key && member(v.member) && (v.member.inventory === null || validWindowsServiceHealthCompleteInventory(v.member.inventory, v.serverNow as string) && v.member.inventory.source.generationId === fullServicesGenerationId(v.member.deviceId as string, v.member.inventory.source.grantId, v.member.inventory.source.sequence) && v.member.inventory.services.every(row => (v.member as unknown as GroupCompleteServiceMember).policy.services.includes(row.name))) && bounded(v);
}
export const sameGroupCompleteServicePolicy = (a: WindowsServiceHealthCompletePolicy, b: WindowsServiceHealthCompletePolicy) => a.revision === b.revision && a.enabled === b.enabled && sameWindowsServiceNames(a.services, b.services) && (a.source === undefined ? b.source === undefined : b.source !== undefined && a.source.kind === b.source.kind && a.source.grantId === b.source.grantId && a.source.grantRevision === b.source.grantRevision);
const sameMember = (a: GroupCompleteServiceMember, b: GroupCompleteServiceMember) => a.key === b.key && a.deviceId === b.deviceId && a.name === b.name;
const sameGroup = (a: GroupCompleteServiceMetadata, b: GroupCompleteServiceMetadata) => a.groupId === b.groupId && a.groupName === b.groupName && a.groupRevision === b.groupRevision;
const matches = (policy: WindowsServiceHealthCompletePolicy, desired: GroupCompleteServiceSetting) => policy.enabled === desired.enabled && sameWindowsServiceNames(policy.services, desired.services) && (!desired.source || sourceBindingMatches(policy.source, desired.source));
/** Retained-name removal/disable remains possible without any source. Additions,
 * re-enablement or a changed grant require the exact freshly pinned generation.
 * The final manager transaction resolves the selected names, never this list DTO. */
export function groupCompleteServiceSettingAllowed(view: GroupCompleteServiceChoiceView, desired: GroupCompleteServiceSetting, age = 0) {
    if (typeof desired.enabled !== 'boolean' || !validWindowsServiceHealthCompleteSelection(desired.services, desired.enabled)) return false;
    const old = view.member.policy;
    const needsSource = desired.enabled && !old.enabled || desired.services.some(name => !old.services.includes(name));
    if (desired.source === null) return !needsSource && (!desired.enabled || old.source !== undefined);
    const current = view.member.inventory?.source;
    return !!current && sameWindowsServiceHealthSource(current, desired.source) && windowsServiceHealthSourceFresh(desired.source, view.serverNow, age);
}
export function groupCompleteServiceEvidenceAllowed(view: GroupCompleteServiceChoiceView, desired: GroupCompleteServiceSetting, evidence: CompleteServiceSelectionEvidence | null) {
    if (desired.source === null) return !desired.enabled || view.member.policy.enabled;
    if (!evidence || !sameWindowsServiceHealthSource(evidence.source, desired.source) || !validWindowsServiceHealthCompleteSelection(evidence.names, false)) return false;
    const old = view.member.policy, changedBinding = !sourceBindingMatches(old.source, desired.source);
    return desired.services.every(name => !(changedBinding || desired.enabled && !old.enabled || !old.services.includes(name)) || evidence.names.includes(name));
}
const cloneMember = (m: ReviewedServiceMember): ReviewedServiceMember => structuredClone(m);
const approved = new WeakMap<GroupCompleteServiceReview, GroupCompleteServiceReview>(), attempted = new WeakSet<GroupCompleteServiceReview>();
/** Freeze every input before network awaits; reads never add members or choices. */
export async function reviewGroupCompleteServiceChecks(original: GroupCompleteServiceChecksView, drafts: GroupCompleteServiceDraft[], io: GroupCompleteServiceChecksIO): Promise<GroupCompleteServiceReview> {
    if (!validGroupCompleteServiceChecksView(original, original.groupId) || drafts.length < 1 || drafts.length > 25 || new Set(drafts.map(d => d.choice.member.key)).size !== drafts.length) throw new Error('Invalid service review');
    const base = structuredClone(original), selected = structuredClone(drafts), members: ReviewedServiceMember[] = [];
    let authorityExpiresAt = base.authorityExpiresAt;
    for (const draft of selected) {
        const previous = base.members.find(m => m.key === draft.choice.member.key);
        if (!previous || !validGroupCompleteServiceChoiceView(draft.choice, base.groupId, previous.key) || !sameGroup(base, draft.choice) || !sameMember(previous, draft.choice.member) || !sameGroupCompleteServicePolicy(previous.policy, draft.choice.member.policy) || !groupCompleteServiceSettingAllowed(draft.choice, draft.desired) || !groupCompleteServiceEvidenceAllowed(draft.choice, draft.desired, draft.evidence) || !io.active()) throw new Error('Service selection changed');
        const current = await io.choice(previous.key);
        if (!io.active() || !validGroupCompleteServiceChoiceView(current, base.groupId, previous.key) || !sameGroup(base, current) || !sameMember(previous, current.member) || !sameGroupCompleteServicePolicy(previous.policy, current.member.policy) || inventoryAge(authorityExpiresAt, current.serverNow) <= 0 || !groupCompleteServiceSettingAllowed(current, draft.desired)) throw new Error('Service review changed');
        if (inventoryAge(current.authorityExpiresAt, authorityExpiresAt) < 0) authorityExpiresAt = current.authorityExpiresAt;
        members.push(cloneMember({ ...previous, desired: draft.desired, evidence: draft.evidence }));
    }
    const review = { serverNow: base.serverNow, authorityExpiresAt, groupId: base.groupId, groupName: base.groupName, groupRevision: base.groupRevision, members };
    approved.set(review, { ...review, members: members.map(cloneMember) });
    return review;
}
/** Single-use, sequential, exact-name policy changes. Any ambiguity stops the remainder. */
export async function applyGroupCompleteServiceChecks(review: GroupCompleteServiceReview, io: GroupCompleteServiceChecksIO, update: (rows: GroupCompleteServiceResult[]) => void): Promise<GroupCompleteServiceResult[]> {
    const frozen = approved.get(review);
    if (!frozen || attempted.has(review)) throw new Error('A fresh service review is required');
    attempted.add(review);
    const rows: GroupCompleteServiceResult[] = frozen.members.map(m => ({ ...cloneMember(m), status: 'not-attempted' }));
    const publish = () => update(rows.map(r => ({ ...cloneMember(r), status: r.status, ...(r.matchingAfterUnconfirmed === undefined ? {} : { matchingAfterUnconfirmed: r.matchingAfterUnconfirmed }) })));
    const validCurrent = (v: unknown, row: ReviewedServiceMember): v is GroupCompleteServiceChoiceView => validGroupCompleteServiceChoiceView(v, frozen.groupId, row.key) && sameGroup(frozen, v) && sameMember(row, v.member) && inventoryAge(frozen.authorityExpiresAt, v.serverNow) > 0;
    publish();
    for (const row of rows) {
        if (!io.active()) break;
        try {
            const current = await io.choice(row.key);
            if (!io.active()) break;
            if (!validCurrent(current, row) || !sameGroupCompleteServicePolicy(row.policy, current.member.policy) || !groupCompleteServiceSettingAllowed(current, row.desired)) throw new Error('Service review changed');
            if (matches(current.member.policy, row.desired)) { row.status = 'currently-matching'; publish(); continue; }
        } catch { if (io.active()) row.status = 'conflict'; publish(); break; }
        if (!io.active()) break;
        try {
            const result = await io.post(row.key, { groupRevision: frozen.groupRevision, expectedRevision: row.policy.revision, enabled: row.desired.enabled, services: [...row.desired.services], source: row.desired.source ? structuredClone(row.desired.source) : null, consent: true });
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
