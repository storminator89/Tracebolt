import { useEffect, useRef, useState } from 'react';
import { APIError, AUTH_REQUIRED_EVENT, getProtectedRequestEpoch, mutate, request } from './api';
import { hasLogoutIntent } from './auth';
import { HEALTH_MAINTENANCE_SCHEDULE_BYTES, maintenanceConfirmed, validMaintenanceSchedule } from './health-maintenance-schedule-types';
import type { MaintenanceRequest, MaintenanceScheduleView } from './health-maintenance-schedule-types';

type Anchor = { mono: number; wall: number };
const capture = (): Anchor => ({ mono: performance.now(), wall: Date.now() });
function elapsed(a: Anchor): number {
    const mono = performance.now() - a.mono, wall = Date.now() - a.wall;
    return Number.isFinite(mono) && mono >= 0 && Number.isFinite(wall) && wall >= 0 && Math.abs(mono - wall) <= 1500 ? Math.max(mono, wall) : Infinity;
}
// Retain only the exact uncertain command, never Health data, across closing the
// panel or a parent refresh. An absent GET is not evidence that a POST failed.
let retainedEpoch = -1;
const uncertain = new Map<string, MaintenanceRequest>();
const superseded = new Map<string, MaintenanceRequest[]>();
const revisions = new Map<string, string>();
/** One total budget, including old outcomes on different device/session keys. */
export function canRetainMaintenanceRequest(pending: ReadonlyMap<string, MaintenanceRequest>, history: ReadonlyMap<string, readonly MaintenanceRequest[]>): boolean {
    return pending.size + [...history.values()].reduce((count, rows) => count + rows.length, 0) < 128;
}
type Snapshot = { key: string; epoch: number; started: Anchor; view: MaintenanceScheduleView; now: number; lifetime: number };
type Commands = { refresh: () => void; apply: (body: MaintenanceRequest) => Promise<boolean> };
const empty: Commands = { refresh: () => {}, apply: async () => false };
type Failure = 'unavailable' | 'interrupted' | 'session' | 'clock' | null;

/** Deliberate metadata reads and one exact write. No scheduler or write retries. */
export function useMaintenanceSchedule(enabled: boolean, deviceId: string, sessionKey: string | null) {
    const epoch = getProtectedRequestEpoch(), key = JSON.stringify([deviceId, sessionKey, epoch]);
    if (retainedEpoch !== epoch) { uncertain.clear(); superseded.clear(); revisions.clear(); retainedEpoch = epoch; }
    const [snapshot, setSnapshot] = useState<Snapshot | null>(null), [pending, setPending] = useState(false), [writing, setWriting] = useState(false), [failure, setFailure] = useState<Failure>(null), [generation, setGeneration] = useState(0), [notice, setNotice] = useState(false), [attempt, setAttempt] = useState<MaintenanceRequest | null>(uncertain.get(key) ?? null), [, tick] = useState(0);
    const [previous, setPrevious] = useState<MaintenanceRequest[]>(superseded.get(key) ?? []);
    const commands = useRef<Commands>(empty), live = useRef(key); live.current = key;
    useEffect(() => {
        let alive = true, locked = false, suspended = document.visibilityState === 'hidden', version = 0;
        let operation: { controller: AbortController; timer: number; started: Anchor } | null = null;
        let accepted: Snapshot | null = null, clock: { server: number; started: Anchor } | null = null;
        const scopeActive = () => alive && enabled && live.current === key && !locked && !suspended && document.visibilityState !== 'hidden' && epoch === getProtectedRequestEpoch() && !hasLogoutIntent();
        const clear = (error: Failure) => {
            version++; operation?.controller.abort(); window.clearTimeout(operation?.timer); operation = null; accepted = null;
            if (alive) { setSnapshot(null); setPending(false); setWriting(false); setFailure(error); setGeneration(n => n + 1); setNotice(false); }
        };
        const now = () => accepted ? accepted.now + elapsed(accepted.started) : Infinity;
        const viewActive = () => scopeActive() && accepted !== null && elapsed(accepted.started) < accepted.lifetime;
        const accept = (value: unknown, started: Anchor, reconcile: boolean): MaintenanceScheduleView => {
            if (!validMaintenanceSchedule(value, deviceId)) throw new Error('Invalid maintenance metadata');
            const knownRevision = revisions.get(key);
            if (knownRevision && BigInt(value.revision) < BigInt(knownRevision) || !knownRevision && revisions.size >= 128) throw new Error('Maintenance revision regressed');
            const server = Date.parse(value.serverNow), age = elapsed(started);
            const floor = clock ? clock.server + elapsed(clock.started) : server;
            if (!Number.isFinite(age) || !Number.isFinite(floor) || clock && server + 1500 < floor) throw new Error('Maintenance clock changed');
            clock ??= { server, started };
            const current = Math.max(server, floor);
            let lifetime = Math.min(60000, sessionKey === null ? 60000 : Date.parse(sessionKey) - current);
            const w = value.window;
            if (w?.state === 'pending') lifetime = Math.min(lifetime, Date.parse(w.startsAt) - current);
            if (w?.state === 'active') lifetime = Math.min(lifetime, Date.parse(w.endsAt) - current);
            if (!(lifetime > age)) throw new Error('Maintenance snapshot expired');
            revisions.set(key, value.revision);
            accepted = { key, epoch, view: value, started, now: current, lifetime };
            setSnapshot(accepted); setFailure(null); setGeneration(n => n + 1);
            const prior = uncertain.get(key);
            if (prior && maintenanceConfirmed(value, prior)) { uncertain.delete(key); setAttempt(null); setNotice(true); }
            else if (reconcile && prior && BigInt(value.revision) > BigInt(prior.expectedRevision)) {
                // Verified later CAS revision fences a delayed original write.
                // It does not establish whether that earlier attempt committed.
                uncertain.delete(key); const history = [...(superseded.get(key) ?? []), prior]; superseded.set(key, history); setPrevious(history); setAttempt(null);
            }
            else setAttempt(prior ?? null);
            return value;
        };
        const run = async (body?: MaintenanceRequest): Promise<boolean> => {
            if (!scopeActive() || operation || body && (!viewActive() || !accepted?.view.canManage || uncertain.has(key) || body.expectedRevision !== accepted.view.revision) || !/^agent_[A-Za-z0-9_-]{1,120}$/.test(deviceId)) return false;
            if (body && !canRetainMaintenanceRequest(uncertain, superseded)) { clear('unavailable'); return false; }
            const controller = new AbortController(), started = capture(), serial = ++version, deadline = body ? 15000 : 10000;
            if (body) { uncertain.set(key, body); setAttempt(body); }
            accepted = null; setSnapshot(null); setPending(true); setWriting(Boolean(body)); setFailure(null); setNotice(false); setGeneration(n => n + 1);
            operation = { controller, started, timer: window.setTimeout(() => { if (serial === version) clear('unavailable'); }, deadline) };
            const active = () => scopeActive() && serial === version && !controller.signal.aborted && elapsed(started) < deadline;
            try {
                const path = `/devices/${encodeURIComponent(deviceId)}/health/maintenance-schedule`;
                const value = body ? await mutate<unknown>(path, body, controller.signal) : await request<unknown>(path, { signal: controller.signal }, HEALTH_MAINTENANCE_SCHEDULE_BYTES);
                if (!active()) return false;
                const view = accept(value, started, !body);
                if (body && !maintenanceConfirmed(view, body)) { clear('unavailable'); return false; }
                return true;
            } catch (error) {
                if (active()) {
                    // These are precommit rejections for this one fresh attempt.
                    // Never resend an older uncertain request to infer its result.
                    if (body && error instanceof APIError && [400, 403, 409].includes(error.status ?? 0)) { uncertain.delete(key); setAttempt(null); }
                    if (error instanceof APIError && error.status === 401) { locked = true; clear('session'); } else clear('unavailable');
                }
                return false;
            } finally { if (alive && serial === version) { window.clearTimeout(operation?.timer); operation = null; setPending(false); setWriting(false); } }
        };
        const auth = () => { locked = true; clear('session'); };
        const suspend = () => { suspended = true; clear('interrupted'); };
        const navigate = () => { locked = true; suspend(); };
        const restore = () => { if (!locked && document.visibilityState !== 'hidden') { suspended = false; tick(n => n + 1); } };
        const visibility = () => document.visibilityState === 'hidden' ? suspend() : restore();
        commands.current = { refresh: () => { void run(); }, apply: run };
        setAttempt(uncertain.get(key) ?? null); setPrevious(superseded.get(key) ?? []); clear(null);
        if (!enabled) return () => { alive = false; clear(null); commands.current = empty; };
        window.addEventListener(AUTH_REQUIRED_EVENT, auth); window.addEventListener('blur', suspend); window.addEventListener('pagehide', suspend); window.addEventListener('hashchange', navigate); window.addEventListener('popstate', navigate); window.addEventListener('focus', restore); window.addEventListener('pageshow', restore); document.addEventListener('visibilitychange', visibility);
        const timer = window.setInterval(() => {
            if (epoch !== getProtectedRequestEpoch() || hasLogoutIntent()) { if (!locked) auth(); }
            else if (accepted && !viewActive()) clear(Number.isFinite(now()) ? 'interrupted' : 'clock');
            else if (accepted) tick(n => n + 1);
        }, 250);
        void run();
        return () => {
            alive = false; clear(null); commands.current = empty; window.clearInterval(timer);
            window.removeEventListener(AUTH_REQUIRED_EVENT, auth); window.removeEventListener('blur', suspend); window.removeEventListener('pagehide', suspend); window.removeEventListener('hashchange', navigate); window.removeEventListener('popstate', navigate); window.removeEventListener('focus', restore); window.removeEventListener('pageshow', restore); document.removeEventListener('visibilitychange', visibility);
        };
    }, [enabled, deviceId, sessionKey, key, epoch]);
    const available = enabled && snapshot?.key === key && snapshot.epoch === getProtectedRequestEpoch() && !hasLogoutIntent() && document.visibilityState !== 'hidden' && elapsed(snapshot.started) < snapshot.lifetime;
    return { view: available ? snapshot.view : null, now: available ? snapshot.now + elapsed(snapshot.started) : Infinity, pending, writing, failure, generation, notice, retentionFull: !canRetainMaintenanceRequest(uncertain, superseded), attempt: attempt && uncertain.get(key) === attempt ? attempt : null, previous: superseded.get(key) === previous ? previous : [], refresh: () => commands.current.refresh(), apply: (body: MaintenanceRequest) => commands.current.apply(body) };
}
