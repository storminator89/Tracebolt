import { useCallback, useEffect, useRef, useState, useSyncExternalStore } from 'react';
import { APIError, AUTH_REQUIRED_EVENT, getProtectedRequestEpoch, request } from './api';
import { hasLogoutIntent, validOperatorSession } from './auth';
import { updateID, validUpdateJobHistory, type UpdateJobHistory } from './windows-update-jobs-types';

const CONCURRENCY = 4, MAX_DEVICES = 50, READ_MS = 10000, BATCH_MS = 60000, RETENTION_MS = 300000;
// Page-lifetime admission survives closing/remounting the worklist. Only opaque
// leases live here: never identities, credentials, device IDs or history data.
const transports = new Set<symbol>(), listeners = new Set<() => void>();
let batch: symbol | null = null;
const occupancy = () => transports.size + (batch ? 1 : 0);
const subscribe = (listener: () => void) => { listeners.add(listener); return () => { listeners.delete(listener); }; };
const notify = () => { for (const listener of listeners) listener(); };
const releaseBatch = (lease: symbol | null) => { if (lease && batch === lease) { batch = null; notify(); } };
type Clock = { mono: number; wall: number };
const clock = (): Clock => ({ mono: performance.now(), wall: Date.now() });
const elapsed = (start: Clock) => {
    const mono = performance.now() - start.mono, wall = Date.now() - start.wall;
    return Number.isFinite(mono) && mono >= 0 && Number.isFinite(wall) && Math.abs(wall - mono) <= 1500 ? mono : Infinity;
};
export type FleetUpdateHistoryReport = { deviceId: string; history?: UpdateJobHistory };

/** Deliberate, bounded history reads only. These summaries never enter a job
 * session or replace its exact uncertain-write/retirement reconciliation anchor. */
export function useFleetUpdateHistory(ids: string[], actor: string, sessionKey: string, enabled: boolean) {
    const key = JSON.stringify([...ids].sort()), scope = `${actor}:${sessionKey}:${enabled}:${key}`;
    const [data, setData] = useState<{ scope: string; reports: FleetUpdateHistoryReport[] } | null>(null);
    const [loading, setLoading] = useState(false), [error, setError] = useState(false);
    const inFlight = useSyncExternalStore(subscribe, occupancy, occupancy), owner = useRef<symbol | null>(null);
    const alive = useRef(false), reading = useRef(false), locked = useRef(false), version = useRef(0);
    const pending = useRef(new Set<AbortController>()), timers = useRef(new Set<number>());
    const retained = useRef<{ started: Clock; epoch: number; authorityDeadline: number } | null>(null);
    const floors = useRef(new Map<string, { latest: number; first: number; accepted: Clock }>());
    const clear = useCallback(() => {
        version.current++; reading.current = false; retained.current = null;
        for (const controller of pending.current) controller.abort();
        for (const timer of timers.current) window.clearTimeout(timer);
        timers.current.clear();
        releaseBatch(owner.current); owner.current = null;
        if (alive.current) { setData(null); setLoading(false); setError(false); }
    }, []);
    const read = useCallback(async () => {
        if (!enabled || !alive.current || locked.current || reading.current || occupancy() || document.hidden || hasLogoutIntent()) return;
        const targets: unknown = JSON.parse(key), expires = Date.parse(sessionKey);
        if (!Number.isFinite(expires) || Date.now() >= expires || !updateID(actor, 'operator_') || !Array.isArray(targets) || !targets.length || targets.length > MAX_DEVICES || targets.some(id => !updateID(id, 'agent_')) || new Set(targets).size !== targets.length) return;
        clear(); reading.current = true;
        const lease = Symbol(); batch = lease; owner.current = lease; notify();
        const token = version.current, started = clock(), epoch = getProtectedRequestEpoch();
        retained.current = { started, epoch, authorityDeadline: Infinity }; setData({ scope, reports: [] }); setLoading(true);
        const active = () => {
            if (!alive.current || token !== version.current || locked.current) return false;
            if (epoch !== getProtectedRequestEpoch() || hasLogoutIntent() || retained.current && performance.now() >= retained.current.authorityDeadline) { locked.current = true; clear(); return false; }
            if (document.hidden || !Number.isFinite(elapsed(started)) || elapsed(started) >= RETENTION_MS || Date.now() >= expires) { clear(); return false; }
            return true;
        };
        const bounded = async (path: string, bytes: number) => {
            if (batch !== lease || transports.size >= CONCURRENCY) throw new Error('Read capacity unavailable');
            const controller = new AbortController(), slot = Symbol(); pending.current.add(controller); transports.add(slot); notify();
            // A noncooperative transport retains its slot even after cancellation.
            // Only its actual settlement releases capacity, including after unmount.
            const release = () => { pending.current.delete(controller); transports.delete(slot); notify(); };
            let transport: Promise<unknown>;
            try { transport = request<unknown>(path, { signal: controller.signal }, bytes); }
            catch (failure) { release(); throw failure; }
            void transport.then(release, release);
            let timer: number | undefined;
            try {
                return await Promise.race([
                    transport,
                    new Promise<never>((_, reject) => { if (controller.signal.aborted) reject(new Error('Canceled')); else controller.signal.addEventListener('abort', () => reject(new Error('Canceled')), { once: true }); }),
                    new Promise<never>((_, reject) => { timer = window.setTimeout(() => { controller.abort(); reject(new Error('Timeout')); }, READ_MS); timers.current.add(timer); }),
                ]);
            } finally { controller.abort(); if (timer !== undefined) { window.clearTimeout(timer); timers.current.delete(timer); } }
        };
        let authorityTimer: number | undefined;
        const constrainSession = (serverMS: number, requestStarted: Clock) => {
            const value = retained.current; if (!value) return;
            value.authorityDeadline = Math.min(value.authorityDeadline, requestStarted.mono + expires - serverMS);
            if (authorityTimer !== undefined) { window.clearTimeout(authorityTimer); timers.current.delete(authorityTimer); }
            authorityTimer = window.setTimeout(() => { if (alive.current && token === version.current) { locked.current = true; clear(); } }, Math.max(0, value.authorityDeadline - performance.now()));
            timers.current.add(authorityTimer);
        };
        const retentionTimer = window.setTimeout(clear, RETENTION_MS); timers.current.add(retentionTimer);
        const timeout = window.setTimeout(clear, BATCH_MS); timers.current.add(timeout);
        try {
            const session = await bounded('/auth/session', 16384);
            if (!active()) return;
            if (!validOperatorSession(session) || session.mode !== 'lan' || session.transport !== 'https' || session.insecureTestMode || !session.authenticated || session.loginMode !== 'named' || session.actorId !== actor || session.expiresAt !== sessionKey || !session.capabilities?.includes('windows_update_install') || Date.parse(session.serverNow) >= expires) { locked.current = true; clear(); setError(true); return; }
            constrainSession(Date.parse(session.serverNow), started); if (!active()) return;
            let next = 0;
            const worker = async () => {
                while (next < targets.length && active()) {
                    const deviceId = targets[next++] as string, at = clock();
                    try {
                        const value = await bounded(`/devices/${encodeURIComponent(deviceId)}/windows-update-jobs?history=1`, 65536);
                        if (!active()) return;
                        if (!validUpdateJobHistory(value, deviceId, actor) || elapsed(at) >= READ_MS || value.serverNow < Math.floor(Date.parse(session.serverNow) / 1000)) throw new Error('Invalid history');
                        if (value.serverNow * 1000 >= expires) { locked.current = true; clear(); return; }
                        constrainSession(value.serverNow * 1000, at); if (!active()) return;
                        const prior = floors.current.get(deviceId);
                        if (prior && (value.serverNow < prior.latest || (value.serverNow - prior.first) * 1000 + 1500 < elapsed(prior.accepted))) throw new Error('Clock replay');
                        floors.current.set(deviceId, prior ? { ...prior, latest: value.serverNow } : { latest: value.serverNow, first: value.serverNow, accepted: clock() });
                        setData(current => current?.scope === scope ? { scope, reports: [...current.reports, { deviceId, history: value }] } : current);
                    } catch (failure) {
                        if (!active()) return;
                        if (failure instanceof APIError && failure.status === 401) { locked.current = true; clear(); setError(true); return; }
                        setData(current => current?.scope === scope ? { scope, reports: [...current.reports, { deviceId }] } : current);
                        // Do not reuse a timed-out transport's outstanding slot.
                        if (elapsed(at) >= READ_MS) return;
                    }
                }
            };
            await Promise.all(Array.from({ length: Math.min(CONCURRENCY, targets.length) }, worker));
        } catch { if (active()) { clear(); setError(true); } }
        finally { window.clearTimeout(timeout); timers.current.delete(timeout); releaseBatch(lease); if (owner.current === lease) owner.current = null; if (active()) { reading.current = false; setLoading(false); } }
    }, [actor, clear, enabled, key, scope, sessionKey]);
    useEffect(() => {
        alive.current = true; locked.current = false; floors.current.clear(); clear();
        const stop = () => clear(), lock = () => { locked.current = true; clear(); }, visibility = () => { if (document.hidden) clear(); };
        for (const event of ['blur', 'pagehide', 'popstate', 'hashchange']) window.addEventListener(event, stop);
        window.addEventListener(AUTH_REQUIRED_EVENT, lock); document.addEventListener('visibilitychange', visibility);
        const timer = window.setInterval(() => {
            const value = retained.current;
            if (value && (value.epoch !== getProtectedRequestEpoch() || hasLogoutIntent() || performance.now() >= value.authorityDeadline)) { locked.current = true; clear(); }
            else if (value && (elapsed(value.started) >= RETENTION_MS || Date.now() >= Date.parse(sessionKey))) clear();
        }, 500);
        return () => { alive.current = false; clear(); window.clearInterval(timer); for (const event of ['blur', 'pagehide', 'popstate', 'hashchange']) window.removeEventListener(event, stop); window.removeEventListener(AUTH_REQUIRED_EVENT, lock); document.removeEventListener('visibilitychange', visibility); };
    }, [clear, scope, sessionKey]);
    const visible = enabled && data?.scope === scope;
    return { reports: visible ? data.reports : [], hasRead: !!visible, loading: enabled && loading, error: enabled && error, waiting: inFlight > 0, blocked: locked.current || !Number.isFinite(Date.parse(sessionKey)) || Date.now() >= Date.parse(sessionKey), read: () => void read(), clear };
}
