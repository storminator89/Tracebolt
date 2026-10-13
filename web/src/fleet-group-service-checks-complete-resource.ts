import { AUTH_REQUIRED_EVENT, getProtectedRequestEpoch, request } from './api';
import { hasLogoutIntent, validOperatorSession } from './auth';
import { inventoryAge } from './complete-packages-types';
import type { FleetGroup } from './fleet-groups-types';
import { acceptWindowsHealthClock, windowsHealthElapsed } from './windows-health-clock';
import { validWindowsCapacityTimestamp } from './windows-capacity-types';
import { GROUP_COMPLETE_SERVICE_CHECKS_BYTES, groupCompleteServiceSettingAllowed, sameGroupCompleteServicePolicy, validGroupCompleteServiceChecksView, validGroupCompleteServiceChoiceView } from './fleet-group-service-checks-complete-workflow';
import type { GroupCompleteServiceChecksIO, GroupCompleteServiceChecksView, GroupCompleteServiceChoiceView } from './fleet-group-service-checks-complete-workflow';

type Anchor = { mono: number; wall: number };
const capture = (): Anchor => ({ mono: performance.now(), wall: Date.now() });
export function groupCompleteServiceElapsed(anchor: Anchor): number {
    const mono = performance.now() - anchor.mono, wall = Date.now() - anchor.wall;
    return Number.isFinite(mono) && mono >= 0 && Number.isFinite(wall) && Math.abs(wall - mono) <= 1500 ? mono : Infinity;
}
type Lease = { view: GroupCompleteServiceChecksView | GroupCompleteServiceChoiceView; started: Anchor };
/** Private foreground IO. Parent activity freezes the original group authority;
 * this resource additionally pins the first service lease and exact members.
 * Every asynchronous boundary, including CSRF, rechecks the same authority. */
export function createGroupCompleteServiceChecksIO(group: FleetGroup, sessionKey: string | null, parentActive: () => boolean): GroupCompleteServiceChecksIO & { cancel: () => void; dispose: () => void } {
    const original = structuredClone(group), epoch = getProtectedRequestEpoch();
    const clockKey = JSON.stringify(['fleet-group-service-checks-complete', group.id, sessionKey]);
    let canceled = false, lease: Lease | null = null, roster: GroupCompleteServiceChecksView | null = null;
    const choices = new Map<string, { view: GroupCompleteServiceChoiceView; started: Anchor }>(), pending = new Set<AbortController>();
    const age = (value: Lease) => windowsHealthElapsed(clockKey, epoch, value.view.serverNow, groupCompleteServiceElapsed(value.started));
    const baseActive = () => !canceled && parentActive() && epoch === getProtectedRequestEpoch() && !hasLogoutIntent() && document.visibilityState !== 'hidden' && validWindowsCapacityTimestamp(sessionKey);
    const leaseActive = (value: Lease) => Number.isFinite(age(value)) && age(value) < 120000 && inventoryAge(sessionKey!, value.view.serverNow) > age(value) && inventoryAge(value.view.authorityExpiresAt, value.view.serverNow) > age(value);
    const active = () => baseActive() && (!lease || leaseActive(lease));
    const cancel = () => { canceled = true; for (const controller of pending) controller.abort(); pending.clear(); choices.clear(); roster = null; lease = null; };
    const visibility = () => { if (document.visibilityState === 'hidden') cancel(); };
    for (const event of [AUTH_REQUIRED_EVENT, 'blur', 'pagehide', 'hashchange']) window.addEventListener(event, cancel);
    document.addEventListener('visibilitychange', visibility);
    const dispose = () => { cancel(); for (const event of [AUTH_REQUIRED_EVENT, 'blur', 'pagehide', 'hashchange']) window.removeEventListener(event, cancel); document.removeEventListener('visibilitychange', visibility); };
    const acceptLease = (value: Lease['view'], started: Anchor) => {
        if (!active() || value.groupId !== original.id || value.groupRevision !== original.revision || value.groupName !== original.name || !acceptWindowsHealthClock(clockKey, epoch, value.serverNow, groupCompleteServiceElapsed(started))) throw new Error('Group complete service checks changed');
        const next = { view: structuredClone(value), started };
        if (!leaseActive(next)) throw new Error('Expired complete service checks');
        // Detail and reread responses can tighten, never renew the first deadline.
        if (!lease || inventoryAge(value.authorityExpiresAt, lease.view.authorityExpiresAt) < 0) lease = next;
    };
    const read = async (path: string, permitted = active, body?: unknown) => {
        if (!permitted()) throw new Error('Inactive');
        const controller = new AbortController(), started = capture(); pending.add(controller);
        const timeout = window.setTimeout(() => controller.abort(), 10000);
        const current = () => permitted() && !controller.signal.aborted && groupCompleteServiceElapsed(started) < 10000;
        try {
            let options: RequestInit = { signal: controller.signal };
            if (body !== undefined) {
                const session = await request<unknown>('/auth/session', options, 32768);
                if (!current() || !validOperatorSession(session) || session.mode !== 'lan' || !session.authenticated || session.loginMode !== 'shared' || session.expiresAt !== sessionKey || typeof session.csrfToken !== 'string' || session.csrfToken.length < 1 || session.csrfToken.length > 256 || inventoryAge(sessionKey!, session.serverNow) <= groupCompleteServiceElapsed(started)) throw new Error('Inactive session');
                options = { ...options, method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': session.csrfToken }, body: JSON.stringify(body) };
            }
            if (!current()) throw new Error('Inactive');
            const value = await request<unknown>(path, options, GROUP_COMPLETE_SERVICE_CHECKS_BYTES);
            if (!current()) throw new Error('Inactive');
            return { value, started };
        } finally { window.clearTimeout(timeout); pending.delete(controller); }
    };
    const acceptChoice = (value: unknown, key: string, started: Anchor): GroupCompleteServiceChoiceView => {
        if (!validGroupCompleteServiceChoiceView(value, original.id, key)) throw new Error('Invalid complete service choice');
        const member = roster?.members.find(m => m.key === key), previous = choices.get(key)?.view.member.policy;
        if (!member || member.deviceId !== value.member.deviceId || member.name !== value.member.name || previous && (value.member.policy.revision < previous.revision || value.member.policy.revision === previous.revision && !sameGroupCompleteServicePolicy(value.member.policy, previous))) throw new Error('Complete service member changed');
        acceptLease(value, started); choices.set(key, { view: structuredClone(value), started }); return value;
    };
    const path = `/fleet/groups/${original.id}/service-checks-complete`;
    return {
        active, cancel, dispose,
        get: async () => {
            const response = await read(path);
            if (!validGroupCompleteServiceChecksView(response.value, original.id) || response.value.members.some(m => !original.memberIds.includes(m.deviceId))) throw new Error('Invalid complete service roster');
            acceptLease(response.value, response.started); roster ??= structuredClone(response.value); return response.value;
        },
        choice: async key => {
            if (!roster?.members.some(m => m.key === key)) throw new Error('No exact complete service member');
            const response = await read(`${path}/${key}`); return acceptChoice(response.value, key, response.started);
        },
        post: async (key, input) => {
            const body = structuredClone(input);
            const choice = choices.get(key);
            const permitted = () => active() && !!choice && body.consent === true && body.groupRevision === original.revision && body.expectedRevision === choice.view.member.policy.revision && groupCompleteServiceSettingAllowed(choice.view, body, age(choice));
            if (!permitted()) throw new Error('No reviewed complete service choice');
            const response = await read(`${path}/${key}`, permitted, body); return acceptChoice(response.value, key, response.started);
        },
    };
}
