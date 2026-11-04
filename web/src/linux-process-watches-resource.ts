import { useEffect, useRef, useState } from 'react';
import { APIError, AUTH_REQUIRED_EVENT, getProtectedRequestEpoch, mutateRaw, request } from './api';
import { hasLogoutIntent, LOGOUT_INTENT_KEY } from './auth';
import { acceptWindowsHealthClock, windowsHealthElapsed } from './windows-health-clock';
import { PROCESS_WATCH_BYTES, processWatchConfirmed, processWatchDeviceId, processWatchTime, validProcessWatches } from './linux-process-watches-types';
import type { ProcessWatchesView, ProcessWatchRequest } from './linux-process-watches-types';
type Anchor = { mono: number; wall: number };
const anchor = (): Anchor => ({ mono: performance.now(), wall: Date.now() });
const age = (a: Anchor) => { const m = performance.now() - a.mono, w = Date.now() - a.wall; return Number.isFinite(m) && m >= 0 && Number.isFinite(w) && w >= 0 && Math.abs(m - w) <= 1500 ? Math.max(m, w) : Infinity; };
const pending = new Map<string, ProcessWatchRequest>(), prior = new Map<string, ProcessWatchRequest[]>(), revisions = new Map<string, string>();
let retainedEpoch = -1;
export const processWatchCapacity = (p: ReadonlyMap<string, ProcessWatchRequest>, old: ReadonlyMap<string, readonly ProcessWatchRequest[]>) => p.size + [...old.values()].reduce((n, rows) => n + rows.length, 0) < 128;
type Snapshot = { key: string; view: ProcessWatchesView; started: Anchor; lifetime: number; offset: number };
type Failure = 'unavailable' | 'session' | 'interrupted' | 'clock' | null;
type Commands = { read: () => void; write: (body: ProcessWatchRequest) => Promise<boolean> };
const empty: Commands = { read: () => {}, write: async () => false };
/** Saved local assessments only. No polling, inventory request or write replay. */
export function useLinuxProcessWatches(enabled: boolean, deviceId: string, scope: string, sessionEnd: string | null) {
    const epoch = getProtectedRequestEpoch(), key = JSON.stringify([deviceId, scope, epoch]);
    if (retainedEpoch !== epoch) { pending.clear(); prior.clear(); revisions.clear(); retainedEpoch = epoch; }
    const [snapshot, setSnapshot] = useState<Snapshot | null>(null), [busy, setBusy] = useState<'read' | 'write' | null>(null), [failure, setFailure] = useState<Failure>(null), [generation, setGeneration] = useState(0), [confirmed, setConfirmed] = useState(false), [, update] = useState(0);
    const live = useRef(key), commands = useRef<Commands>(empty); live.current = key;
    useEffect(() => {
        let alive = true, locked = false, suspended = document.visibilityState === 'hidden' || !document.hasFocus(), serial = 0;
        let accepted: Snapshot | null = null, operation: { controller: AbortController; timer: number } | null = null;
        const activeScope = () => alive && enabled && processWatchDeviceId(deviceId) && live.current === key && !locked && !suspended && epoch === getProtectedRequestEpoch() && !hasLogoutIntent() && document.visibilityState !== 'hidden' && document.hasFocus();
        const clear = (reason: Failure) => { serial++; operation?.controller.abort(); window.clearTimeout(operation?.timer); operation = null; accepted = null; if (alive) { setSnapshot(null); setBusy(null); setFailure(reason); setConfirmed(false); setGeneration(v => v + 1); } };
        const available = () => activeScope() && accepted !== null && age(accepted.started) < accepted.lifetime;
        const run = async (change?: ProcessWatchRequest): Promise<boolean> => {
            if (!activeScope() || operation || change && (!available() || !accepted?.view.canManage || change.body.expectedRevision !== accepted.view.revision || change.body.sourceToken !== accepted.view.source.token || pending.has(key) || !processWatchCapacity(pending, prior))) return false;
            const reviewed = accepted, controller = new AbortController(), started = anchor(), mine = ++serial, deadline = change ? 15000 : 10000;
            if (change) pending.set(key, change);
            accepted = null; setSnapshot(null); setBusy(change ? 'write' : 'read'); setFailure(null); setConfirmed(false); setGeneration(v => v + 1);
            operation = { controller, timer: window.setTimeout(() => { if (mine === serial) clear('unavailable'); }, deadline) };
            const active = () => activeScope() && mine === serial && !controller.signal.aborted && age(started) < deadline;
            try {
                const base = `/devices/${deviceId}/linux-process-watches`;
                const value = change ? await mutateRaw<unknown>(`${base}/${change.operation === 'policy' ? 'policy' : 'acknowledge'}`, JSON.stringify(change.body), {}, controller.signal, PROCESS_WATCH_BYTES, () => active() && reviewed !== null && age(reviewed.started) < reviewed.lifetime) : await request<unknown>(base, { signal: controller.signal, cache: 'no-store', redirect: 'error' }, PROCESS_WATCH_BYTES);
                if (!active()) return false;
                if (!validProcessWatches(value, deviceId)) throw new Error('Unsupported process-watch data');
                const known = revisions.get(key);
                if (known !== undefined && BigInt(value.revision) < BigInt(known) || known === undefined && revisions.size >= 128) throw new Error('Global revision regressed');
                let offset = 0;
                if (value.clockReliable) {
                    if (!acceptWindowsHealthClock(`linux-process-watches:${key}`, epoch, value.serverNow, age(started))) throw new Error('Manager clock regressed');
                    offset = windowsHealthElapsed(`linux-process-watches:${key}`, epoch, value.serverNow, age(started)) - age(started);
                }
                let lifetime = Number(processWatchTime(value.validUntil)! - processWatchTime(value.serverNow)!) / 1000000 - offset;
                if (sessionEnd !== null) { const end = processWatchTime(sessionEnd); if (end === null) throw new Error('Unknown session expiry'); lifetime = Math.min(lifetime, Number(end - processWatchTime(value.serverNow)!) / 1000000 - offset); }
                lifetime = Math.min(30000, lifetime);
                if (!(age(started) < lifetime)) throw new Error('Expired process-watch data');
                revisions.set(key, value.revision); accepted = { key, view: value, started, lifetime, offset }; setSnapshot(accepted); setGeneration(v => v + 1);
                const attempt = pending.get(key);
                if (attempt && processWatchConfirmed(value, attempt)) { pending.delete(key); setConfirmed(true); }
                else if (!change && attempt && (BigInt(value.revision) > BigInt(attempt.body.expectedRevision) || value.source.token !== attempt.body.sourceToken)) { pending.delete(key); prior.set(key, [...(prior.get(key) ?? []), attempt]); }
                if (change && !processWatchConfirmed(value, change)) { clear('unavailable'); return false; }
                return true;
            } catch (error) {
                if (active()) {
                    // A 409 can be produced by a final clock/source guard after
                    // commit. Status alone cannot prove rejection: retain the
                    // exact request and reconcile through GET, never replay it.
                    if (change && error instanceof APIError && [400, 403].includes(error.status ?? 0)) pending.delete(key);
                    if (error instanceof APIError && error.status === 401) { locked = true; clear('session'); } else clear('unavailable');
                }
                return false;
            } finally { if (alive && mine === serial) { window.clearTimeout(operation?.timer); operation = null; setBusy(null); } }
        };
        const auth = () => { locked = true; clear('session'); }, suspend = () => { suspended = true; clear('interrupted'); };
        const restore = () => { if (!locked && document.visibilityState !== 'hidden' && document.hasFocus()) suspended = false; };
        const visibility = () => document.visibilityState === 'hidden' ? suspend() : restore();
        const storage = (event: StorageEvent) => { if ((event.key === LOGOUT_INTENT_KEY || event.key === null) && hasLogoutIntent()) auth(); };
        commands.current = { read: () => { restore(); void run(); }, write: run }; clear(null);
        if (!enabled) return () => { alive = false; clear(null); commands.current = empty; };
        window.addEventListener(AUTH_REQUIRED_EVENT, auth); for (const event of ['blur', 'pagehide', 'hashchange', 'popstate']) window.addEventListener(event, suspend); for (const event of ['focus', 'pageshow']) window.addEventListener(event, restore); window.addEventListener('storage', storage); document.addEventListener('visibilitychange', visibility);
        const timer = window.setInterval(() => { if (epoch !== getProtectedRequestEpoch() || hasLogoutIntent()) { if (!locked) auth(); } else if (accepted && !available()) clear(Number.isFinite(age(accepted.started)) ? 'interrupted' : 'clock'); else if (accepted) update(v => v + 1); }, 250);
        void run();
        return () => { alive = false; clear(null); commands.current = empty; window.clearInterval(timer); window.removeEventListener(AUTH_REQUIRED_EVENT, auth); for (const event of ['blur', 'pagehide', 'hashchange', 'popstate']) window.removeEventListener(event, suspend); for (const event of ['focus', 'pageshow']) window.removeEventListener(event, restore); window.removeEventListener('storage', storage); document.removeEventListener('visibilitychange', visibility); };
    }, [enabled, deviceId, epoch, key, scope, sessionEnd]);
    const visible = enabled && snapshot?.key === key && epoch === getProtectedRequestEpoch() && !hasLogoutIntent() && document.visibilityState !== 'hidden' && document.hasFocus() && age(snapshot.started) < snapshot.lifetime;
    return { view: visible ? snapshot.view : null, elapsed: visible ? snapshot.offset + age(snapshot.started) : Infinity, busy, failure, generation, confirmed, uncertain: pending.get(key) ?? null, previous: prior.get(key) ?? [], full: !processWatchCapacity(pending, prior), read: () => commands.current.read(), write: (change: ProcessWatchRequest) => commands.current.write(change) };
}
