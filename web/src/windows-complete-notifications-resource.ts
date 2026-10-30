import { useEffect, useRef, useState } from 'react';
import { AUTH_REQUIRED_EVENT, getProtectedRequestEpoch, request } from './api';
import { hasLogoutIntent, validOperatorSession } from './auth';
import { inventoryAge } from './complete-packages-types';
import { validWindowsCapacityTimestamp } from './windows-capacity-types';
import { acceptWindowsHealthClock, windowsHealthElapsed } from './windows-health-clock';
import { validWindowsCompleteNotificationView, WINDOWS_COMPLETE_NOTIFICATIONS_BYTES } from './windows-complete-notifications-types';
import type { WindowsCompleteNotificationChange, WindowsCompleteNotificationTarget, WindowsCompleteNotificationView } from './windows-complete-notifications-types';

type Anchor = { mono: number; wall: number };
const capture = (): Anchor => ({ mono: performance.now(), wall: Date.now() });
function elapsed(anchor: Anchor): number {
    const mono = performance.now() - anchor.mono, wall = Date.now() - anchor.wall;
    return Number.isFinite(mono) && mono >= 0 && Number.isFinite(wall) && Math.abs(wall - mono) <= 1500 ? mono : Infinity;
}
type Snapshot = { key: string; epoch: number; started: Anchor; view: WindowsCompleteNotificationView };
type Commands = { refresh: () => void; save: (body: WindowsCompleteNotificationChange) => Promise<void> };
type Notice = 'changed' | 'uncertain' | null;
const noop: Commands = { refresh: () => {}, save: async () => {} };

/** Explicit, private source admission. No automatic enablement or write retry. */
export function useWindowsCompleteNotifications(enabled: boolean, sessionKey: string | null, admin: boolean) {
    const [snapshot, setSnapshot] = useState<Snapshot | null>(null), [loading, setLoading] = useState(false), [writing, setWriting] = useState(false), [error, setError] = useState(false), [notice, setNotice] = useState<Notice>(null), [generation, setGeneration] = useState(0), [, tick] = useState(0);
    const retained = useRef({ session: sessionKey, uncertain: new Map<string, number>(), revisions: new Map<string, number>() });
    const key = JSON.stringify([enabled, sessionKey, admin]), clockKey = JSON.stringify(['windows-complete-notifications', sessionKey]);
    const live = useRef(key); live.current = key;
    const commands = useRef<Commands>(noop);
    useEffect(() => {
        if (retained.current.session !== sessionKey) { retained.current = { session: sessionKey, uncertain: new Map(), revisions: new Map() }; setNotice(null); }
        let alive = true, locked = false, suspended = document.visibilityState === 'hidden', operation = 0, reading = false;
        let write: { key: string; revision: number } | null = null, accepted: Snapshot | null = null;
        const epoch = getProtectedRequestEpoch(), pending = new Set<AbortController>();
        const abort = () => { operation++; for (const controller of pending) controller.abort(); pending.clear(); };
        const markUncertain = () => { if (write) { retained.current.uncertain.set(write.key, write.revision); if (alive) setNotice('uncertain'); } };
        const clear = (failure = false) => {
            markUncertain(); abort(); accepted = null; reading = false; write = null;
            if (alive) { setSnapshot(null); setLoading(false); setWriting(false); setError(failure); setGeneration(value => value + 1); }
        };
        const baseActive = () => alive && enabled && live.current === key && !locked && !suspended && document.visibilityState !== 'hidden' && !hasLogoutIntent() && epoch === getProtectedRequestEpoch() && validWindowsCapacityTimestamp(sessionKey);
        const viewAge = () => accepted ? windowsHealthElapsed(clockKey, epoch, accepted.view.serverNow, elapsed(accepted.started)) : Infinity;
        const viewActive = () => baseActive() && accepted !== null && viewAge() < 120000 && inventoryAge(sessionKey!, accepted.view.serverNow) > viewAge() && inventoryAge(accepted.view.authorityExpiresAt, accepted.view.serverNow) > viewAge();
        const accept = (value: unknown, started: Anchor): value is WindowsCompleteNotificationView => {
            if (!validWindowsCompleteNotificationView(value) || value.targets.some(target => target.revision < (retained.current.revisions.get(target.key) ?? 0)) || !acceptWindowsHealthClock(clockKey, epoch, value.serverNow, elapsed(started))) return false;
            const age = windowsHealthElapsed(clockKey, epoch, value.serverNow, elapsed(started));
            if (!validWindowsCapacityTimestamp(sessionKey) || age >= 120000 || inventoryAge(sessionKey, value.serverNow) <= age || inventoryAge(value.authorityExpiresAt, value.serverNow) <= age) return false;
            const newKeys = value.targets.filter(target => !retained.current.revisions.has(target.key)).length;
            if (retained.current.revisions.size + newKeys > 1024) return false;
            for (const target of value.targets) {
                retained.current.revisions.set(target.key, target.revision);
                const uncertain = retained.current.uncertain.get(target.key);
                if (uncertain !== undefined && target.revision > uncertain) retained.current.uncertain.delete(target.key);
            }
            return true;
        };
        const fetchValue = async (path: string, active: () => boolean, body?: WindowsCompleteNotificationChange) => {
            if (!active()) throw new Error('Inactive');
            const controller = new AbortController(), started = capture(); pending.add(controller);
            let timer = 0;
            const timeout = new Promise<never>((_, reject) => { timer = window.setTimeout(() => { controller.abort(); reject(new Error('Timeout')); }, 10000); });
            const current = () => active() && !controller.signal.aborted && elapsed(started) < 10000;
            try {
                const fetch = async () => {
                    let options: RequestInit = { signal: controller.signal };
                    if (body) {
                        const session = await request<unknown>('/auth/session', options, 32768);
                        if (!current() || !admin || !validOperatorSession(session) || session.mode !== 'lan' || !session.authenticated || session.loginMode !== 'shared' || session.expiresAt !== sessionKey || typeof session.csrfToken !== 'string' || session.csrfToken.length < 1 || session.csrfToken.length > 256 || inventoryAge(sessionKey!, session.serverNow) <= elapsed(started)) throw new Error('Inactive session');
                        options = { ...options, method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': session.csrfToken }, body: JSON.stringify(body) };
                    }
                    if (!current()) throw new Error('Inactive');
                    const value = await request<unknown>(path, options, WINDOWS_COMPLETE_NOTIFICATIONS_BYTES);
                    if (!current()) throw new Error('Inactive');
                    return { value, started };
                };
                return await Promise.race([fetch(), timeout]);
            } finally { window.clearTimeout(timer); pending.delete(controller); }
        };
        const read = async () => {
            if (!baseActive() || reading || write) return;
            clear(); const run = operation; reading = true; setLoading(true);
            try {
                const { value, started } = await fetchValue('/fleet/windows-notifications/complete', () => baseActive() && run === operation);
                if (!accept(value, started)) throw new Error('Invalid complete notifications');
                accepted = { key, epoch, started, view: value }; setSnapshot(accepted); setError(false);
            } catch { if (alive && run === operation && live.current === key) clear(true); }
            finally { if (alive && run === operation && live.current === key) { reading = false; setLoading(false); } }
        };
        const mutate = async (body: WindowsCompleteNotificationChange) => {
            const target = accepted?.view.targets.find(item => item.key === body.key);
            if (!admin || !viewActive() || reading || write || !target || target.revision !== body.revision || target.revision >= Number.MAX_SAFE_INTEGER || retained.current.uncertain.has(body.key)) return;
            const permitted = () => viewActive() && !!accepted && (body.enabled ? target.actionable && body.payloadAcknowledged && accepted.view.deliveryEnabled && body.destinationBinding === accepted.view.destinationBinding : !body.payloadAcknowledged && body.destinationBinding === '' && target.enabled);
            if (!permitted()) return;
            const run = operation; write = { key: body.key, revision: body.revision }; setWriting(true); setNotice(null);
            try {
                const { value, started } = await fetchValue('/fleet/windows-notifications/complete/policy', () => run === operation && permitted(), body);
                if (!validWindowsCompleteNotificationView(value) || !confirmedChange(value.targets.find(item => item.key === target.key), target, body) || !accept(value, started)) throw new Error('Unconfirmed complete notifications');
                write = null; setNotice('changed');
            } catch { if (alive && run === operation && live.current === key) markUncertain(); }
            finally {
                if (alive && run === operation && live.current === key) { write = null; setWriting(false); void read(); }
            }
        };
        const lock = () => { locked = true; clear(true); }, suspend = () => { suspended = true; clear(true); };
        const restore = () => { if (locked || document.visibilityState === 'hidden') return; suspended = false; void read(); };
        const visibility = () => document.visibilityState === 'hidden' ? suspend() : restore();
        const navigation = () => { locked = true; clear(); };
        commands.current = { refresh: () => { void read(); }, save: body => mutate(body) };
        clear();
        if (!enabled) return () => { alive = false; abort(); commands.current = noop; };
        window.addEventListener(AUTH_REQUIRED_EVENT, lock); window.addEventListener('blur', suspend); window.addEventListener('focus', restore); window.addEventListener('pagehide', suspend); window.addEventListener('hashchange', navigation); window.addEventListener('popstate', navigation); document.addEventListener('visibilitychange', visibility);
        const timer = window.setInterval(() => {
            if (epoch !== getProtectedRequestEpoch() || hasLogoutIntent()) { if (!locked) lock(); }
            else if (accepted && !viewActive()) clear(true);
            else if (accepted) tick(value => value + 1);
        }, 250);
        void read();
        return () => {
            markUncertain(); alive = false; abort(); accepted = null; commands.current = noop; window.clearInterval(timer);
            window.removeEventListener(AUTH_REQUIRED_EVENT, lock); window.removeEventListener('blur', suspend); window.removeEventListener('focus', restore); window.removeEventListener('pagehide', suspend); window.removeEventListener('hashchange', navigation); window.removeEventListener('popstate', navigation); document.removeEventListener('visibilitychange', visibility);
        };
    }, [enabled, key, clockKey, sessionKey, admin]);
    const age = snapshot ? windowsHealthElapsed(clockKey, snapshot.epoch, snapshot.view.serverNow, elapsed(snapshot.started)) : Infinity;
    const available = enabled && snapshot?.key === key && snapshot.epoch === getProtectedRequestEpoch() && !hasLogoutIntent() && document.visibilityState !== 'hidden' && age < 120000 && validWindowsCapacityTimestamp(sessionKey) && inventoryAge(sessionKey, snapshot.view.serverNow) > age && inventoryAge(snapshot.view.authorityExpiresAt, snapshot.view.serverNow) > age;
    return { view: available ? snapshot.view : null, age, loading, writing, error, notice, generation, isUncertain: (target: WindowsCompleteNotificationTarget) => retained.current.uncertain.get(target.key) === target.revision, refresh: () => commands.current.refresh(), save: (body: WindowsCompleteNotificationChange) => commands.current.save(body) };
}

function confirmedChange(next: WindowsCompleteNotificationTarget | undefined, prior: WindowsCompleteNotificationTarget, body: WindowsCompleteNotificationChange): boolean {
    return !!next && next.deviceId === prior.deviceId && next.domain === prior.domain && next.grantId === prior.grantId && next.grantRevision === prior.grantRevision && next.healthPolicyRevision === prior.healthPolicyRevision && next.services.length === prior.services.length && next.services.every((name, i) => name === prior.services[i]) && next.revision === prior.revision + 1 && next.enabled === body.enabled && (!body.enabled || next.effective);
}
