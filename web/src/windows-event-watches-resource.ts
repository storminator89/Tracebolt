import { inventoryAge } from './complete-packages-types';
import { useEffect, useRef, useState } from 'react';
import { APIError, AUTH_REQUIRED_EVENT, getProtectedRequestEpoch, mutateRaw, request } from './api';
import { hasLogoutIntent, LOGOUT_INTENT_KEY } from './auth';
import { acceptWindowsHealthClock, windowsHealthElapsed } from './windows-health-clock';
import { EVENT_WATCH_BYTES, eventWatchConfirmed, eventWatchDeviceId, eventWatchTime, validEventWatches } from './windows-event-watches-types';
import type { EventWatchRequest, EventWatchesView } from './windows-event-watches-types';
const anchor = () => ({ wall: Date.now(), mono: performance.now() });
export function eventWatchElapsed(start: { wall: number; mono: number }, wall: number, mono: number): number {
    const w = wall - start.wall, m = mono - start.mono;
    return Number.isFinite(w) && Number.isFinite(m) && w >= 0 && m >= 0 && Math.abs(w - m) <= 1500 ? Math.max(w, m) : Infinity;
}
const elapsed = (start: ReturnType<typeof anchor>) => eventWatchElapsed(start, Date.now(), performance.now());
type Snapshot = { key: string; view: EventWatchesView; start: ReturnType<typeof anchor>; lifetime: number };
type Commands = { read: () => void; write: (change: EventWatchRequest) => void };
const empty: Commands = { read: () => {}, write: () => {} };
/** Private foreground-only views. No polling, storage, collector request or POST retry. */
export function useWindowsEventWatches(open: boolean, deviceId: string, scope: string, sessionEnd: string | null) {
    const epoch = getProtectedRequestEpoch(), key = JSON.stringify([deviceId, scope, epoch]);
    const [snapshot, setSnapshot] = useState<Snapshot | null>(null), [busy, setBusy] = useState(false), [failure, setFailure] = useState(false), [uncertain, setUncertain] = useState(false), [, tick] = useState(0);
    const commands = useRef(empty), live = useRef(key); live.current = key;
    useEffect(() => {
        let alive = true, locked = false, suspended = false, serial = 0, accepted: Snapshot | null = null;
        let operation: { controller: AbortController; timer: number } | null = null;
        let pendingRevision: number | null = null, revision = -1;
        let session: { start: ReturnType<typeof anchor>; lifetime: number } | null = null;
        const active = () => alive && open && eventWatchDeviceId(deviceId) && !locked && !suspended && live.current === key && epoch === getProtectedRequestEpoch() && !hasLogoutIntent() && document.visibilityState !== 'hidden' && document.hasFocus() && (!session || elapsed(session.start) < session.lifetime);
        const clear = (failed = false) => { serial++; operation?.controller.abort(); window.clearTimeout(operation?.timer); operation = null; accepted = null; if (alive) { setSnapshot(null); setBusy(false); setFailure(failed); } };
        const available = () => active() && accepted !== null && elapsed(accepted.start) < accepted.lifetime;
        const run = async (change?: EventWatchRequest) => {
            if (!active() || operation || change && (!available() || !accepted!.view.canManage || pendingRevision !== null || change.body.expectedRevision !== accepted!.view.revision || change.body.sourceToken !== accepted!.view.source.token)) return;
            const reviewed = accepted, start = anchor(), mine = ++serial, controller = new AbortController();
            if (change) { pendingRevision = change.body.expectedRevision; setUncertain(true); }
            accepted = null; setSnapshot(null); setBusy(true); setFailure(false);
            operation = { controller, timer: window.setTimeout(() => { if (mine === serial) clear(true); }, 10000) };
            const current = () => active() && mine === serial && !controller.signal.aborted && elapsed(start) < 10000;
            try {
                const path = `/devices/${deviceId}/windows-event-watches`;
                const value = change ? await mutateRaw<unknown>(`${path}/${change.operation}`, JSON.stringify(change.body), {}, controller.signal, EVENT_WATCH_BYTES, () => current() && reviewed !== null && elapsed(reviewed.start) < reviewed.lifetime) : await request<unknown>(path, { signal: controller.signal, cache: 'no-store', redirect: 'error' }, EVENT_WATCH_BYTES);
                if (!current()) return;
                if (!validEventWatches(value, deviceId) || value.revision < revision || !acceptWindowsHealthClock(`windows-event-watches:${key}`, epoch, value.serverNow, elapsed(start))) throw new Error('Invalid view');
                const offset = windowsHealthElapsed(`windows-event-watches:${key}`, epoch, value.serverNow, elapsed(start)) - elapsed(start);
                let lifetime = Math.min(30000, inventoryAge(value.validUntil, value.serverNow)) - offset;
                if (sessionEnd === null || eventWatchTime(sessionEnd) === null) throw new Error('Session expiry unavailable');
                const sessionLifetime = Math.min(inventoryAge(sessionEnd, value.serverNow) - offset, session ? session.lifetime - elapsed(session.start) + elapsed(start) : Infinity);
                session = { start, lifetime: sessionLifetime }; lifetime = Math.min(lifetime, sessionLifetime);
                if (!(elapsed(start) < lifetime)) throw new Error('Expired view');
                if (change && !eventWatchConfirmed(value, change)) throw new Error('Uncertain write');
                revision = value.revision;
                // A changed global revision establishes fresh state. Never replay an
                // uncertain POST, including after timeout, conflict or failed parsing.
                if (pendingRevision !== null && value.revision > pendingRevision) { pendingRevision = null; setUncertain(false); }
                accepted = { key, view: value, start, lifetime }; setSnapshot(accepted);
            } catch (error) { if (current()) { if (error instanceof APIError && [401, 403].includes(error.status ?? 0)) locked = true; clear(true); } }
            finally { if (alive && mine === serial) { window.clearTimeout(operation?.timer); operation = null; setBusy(false); } }
        };
        const auth = () => { locked = true; clear(); }, suspend = () => { suspended = true; clear(); };
        const restore = () => { if (!locked && document.visibilityState !== 'hidden' && document.hasFocus()) suspended = false; };
        const visibility = () => document.visibilityState === 'hidden' ? suspend() : restore();
        const storage = (e: StorageEvent) => { if ((e.key === null || e.key === LOGOUT_INTENT_KEY) && hasLogoutIntent()) auth(); };
        commands.current = { read: () => { restore(); void run(); }, write: change => { void run(change); } };
        clear(); setUncertain(false);
        if (!open) return () => { alive = false; clear(); commands.current = empty; };
        window.addEventListener(AUTH_REQUIRED_EVENT, auth); window.addEventListener('storage', storage);
        for (const event of ['blur', 'pagehide', 'hashchange', 'popstate']) window.addEventListener(event, suspend);
        document.addEventListener('visibilitychange', visibility);
        const timer = window.setInterval(() => { if (epoch !== getProtectedRequestEpoch() || hasLogoutIntent() || session && elapsed(session.start) >= session.lifetime) auth(); else if (accepted && !available()) clear(); else if (accepted) tick(v => v + 1); }, 100);
        void run();
        return () => { alive = false; clear(); commands.current = empty; window.clearInterval(timer); window.removeEventListener(AUTH_REQUIRED_EVENT, auth); window.removeEventListener('storage', storage); for (const event of ['blur', 'pagehide', 'hashchange', 'popstate']) window.removeEventListener(event, suspend); document.removeEventListener('visibilitychange', visibility); };
    }, [open, deviceId, scope, sessionEnd, epoch, key]);
    const visible = open && snapshot?.key === key && epoch === getProtectedRequestEpoch() && !hasLogoutIntent() && typeof document !== 'undefined' && document.visibilityState !== 'hidden' && document.hasFocus() && elapsed(snapshot.start) < snapshot.lifetime;
    return { view: visible ? snapshot.view : null, busy, failure, uncertain, refresh: () => commands.current.read(), write: (change: EventWatchRequest) => commands.current.write(change) };
}
