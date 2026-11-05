import { useEffect, useRef, useState } from 'react';
import { APIError, AUTH_REQUIRED_EVENT, getProtectedRequestEpoch, mutateRaw, request } from './api';
import { hasLogoutIntent, LOGOUT_INTENT_KEY } from './auth';
import { APPLICATION_INCIDENT_BYTES, incidentRequestConfirmed, incidentTime, validApplicationIncidents } from './application-incidents-types';
import type { ApplicationIncidentsView, IncidentRequest } from './application-incidents-types';
import { acceptWindowsHealthClock, windowsHealthElapsed } from './windows-health-clock';

type Anchor = { mono: number; wall: number };
const capture = (): Anchor => ({ mono: performance.now(), wall: Date.now() });
const age = (a: Anchor) => { const m = performance.now() - a.mono, w = Date.now() - a.wall; return Number.isFinite(m) && m >= 0 && Number.isFinite(w) && w >= 0 && Math.abs(m - w) <= 1500 ? Math.max(m, w) : Infinity; };
const uncertain = new Map<string, IncidentRequest>(), prior = new Map<string, IncidentRequest[]>();
const revisions = new Map<string, { revision: string; token: string }>();
let retainedEpoch = -1;
export const incidentRequestCapacity = (pending: ReadonlyMap<string, IncidentRequest>, history: ReadonlyMap<string, readonly IncidentRequest[]>) => pending.size + [...history.values()].reduce((n, rows) => n + rows.length, 0) < 128;
type Snapshot = { key: string; epoch: number; view: ApplicationIncidentsView; started: Anchor; lifetime: number; offset: number };
type Failure = 'unavailable' | 'session' | 'interrupted' | 'clock' | null;
type Commands = { read: () => void; write: (body: IncidentRequest) => Promise<boolean>; interrupt: () => void };
const empty: Commands = { read: () => {}, write: async () => false, interrupt: () => {} };

/** Reads retained metadata deliberately. No probe, polling or write replay. */
export function useApplicationIncidents(enabled: boolean, scope: string, sessionKey: string | null, readOnly = false, checkingAccess = false) {
    const epoch = getProtectedRequestEpoch(), key = JSON.stringify([scope, epoch]);
    if (retainedEpoch !== epoch) { uncertain.clear(); prior.clear(); revisions.clear(); retainedEpoch = epoch; }
    const [snapshot, setSnapshot] = useState<Snapshot | null>(null), [busy, setBusy] = useState<'read' | 'write' | null>(null), [failure, setFailure] = useState<Failure>(null), [generation, setGeneration] = useState(0), [confirmed, setConfirmed] = useState(false), [, update] = useState(0);
    const commands = useRef<Commands>(empty), live = useRef(key), accessCheck = useRef(checkingAccess); live.current = key; accessCheck.current = checkingAccess;
    useEffect(() => {
        let alive = true, locked = false, suspended = document.visibilityState === 'hidden' || !document.hasFocus(), version = 0;
        let accepted: Snapshot | null = null, operation: { controller: AbortController; timer: number } | null = null;
        const scopeActive = () => alive && enabled && !accessCheck.current && live.current === key && !locked && !suspended && document.visibilityState !== 'hidden' && document.hasFocus() && epoch === getProtectedRequestEpoch() && !hasLogoutIntent();
        const clear = (error: Failure) => { version++; operation?.controller.abort(); window.clearTimeout(operation?.timer); operation = null; accepted = null; if (alive) { setSnapshot(null); setBusy(null); setFailure(error); setConfirmed(false); setGeneration(n => n + 1); } };
        const available = () => scopeActive() && accepted !== null && age(accepted.started) < accepted.lifetime;
        const run = async (body?: IncidentRequest): Promise<boolean> => {
            if (!scopeActive() || operation || body && (readOnly || !available() || !accepted?.view.canManage || uncertain.has(key) || body.expectedRevision !== accepted.view.revision || body.sourceToken !== accepted.view.currentSource.token || !incidentRequestCapacity(uncertain, prior))) return false;
            const reviewed = accepted;
            const controller = new AbortController(), started = capture(), serial = ++version, deadline = body ? 15000 : 10000;
            if (body) uncertain.set(key, body);
            accepted = null; setSnapshot(null); setBusy(body ? 'write' : 'read'); setFailure(null); setConfirmed(false); setGeneration(n => n + 1);
            operation = { controller, timer: window.setTimeout(() => { if (serial === version) clear('unavailable'); }, deadline) };
            const active = () => scopeActive() && serial === version && !controller.signal.aborted && age(started) < deadline;
            try {
                const value = body ? await mutateRaw<unknown>('/application-checks/incidents', JSON.stringify(body), {}, controller.signal, APPLICATION_INCIDENT_BYTES, () => active() && reviewed !== null && age(reviewed.started) < reviewed.lifetime) : await request<unknown>('/application-checks/incidents', { signal: controller.signal, cache: 'no-store', redirect: 'error' }, APPLICATION_INCIDENT_BYTES);
                if (!active()) return false;
                if (!validApplicationIncidents(value)) throw new Error('Unsupported incident view');
                const known = revisions.get(key);
                // The control revision is persisted globally, not per source.
                // A replacement source never permits a known revision rollback.
                if (known && BigInt(value.revision) < BigInt(known.revision) || !known && revisions.size >= 128) throw new Error('Incident revision regressed');
                let offset = 0;
                if (value.clockReliable) {
                    if (!acceptWindowsHealthClock(`application-incidents:${key}`, epoch, value.serverNow, age(started))) throw new Error('Incident clock regressed');
                    offset = windowsHealthElapsed(`application-incidents:${key}`, epoch, value.serverNow, age(started)) - age(started);
                }
                const lifetime = Math.min(60000, sessionKey === null ? 60000 : Number(incidentTime(sessionKey)! - incidentTime(value.serverNow)!) / 1000000 - offset);
                if (!(age(started) < lifetime)) throw new Error('Incident snapshot expired');
                revisions.set(key, { revision: value.revision, token: value.currentSource.token });
                accepted = { key, epoch, view: value, started, lifetime, offset }; setSnapshot(accepted); setGeneration(n => n + 1);
                // The independent reader must not consume an administration
                // surface's pending or prior request-reconciliation evidence.
                if (readOnly) return true;
                const attempt = uncertain.get(key);
                if (attempt && incidentRequestConfirmed(value, attempt)) { uncertain.delete(key); setConfirmed(true); }
                else if (!body && attempt && (BigInt(value.revision) > BigInt(attempt.expectedRevision) || value.currentSource.token !== attempt.sourceToken)) { uncertain.delete(key); prior.set(key, [...(prior.get(key) ?? []), attempt]); }
                if (body && !incidentRequestConfirmed(value, body)) { clear('unavailable'); return false; }
                return true;
            } catch (error) {
                if (active()) {
                    if (body && error instanceof APIError && [400, 403, 409].includes(error.status ?? 0)) uncertain.delete(key);
                    if (error instanceof APIError && error.status === 401) { locked = true; clear('session'); } else clear('unavailable');
                }
                return false;
            } finally { if (alive && serial === version) { window.clearTimeout(operation?.timer); operation = null; setBusy(null); } }
        };
        const auth = () => { locked = true; clear('session'); }, suspend = () => { suspended = true; clear('interrupted'); };
        const restore = () => { if (!locked && document.visibilityState !== 'hidden' && document.hasFocus()) suspended = false; };
        const visibility = () => document.visibilityState === 'hidden' ? suspend() : restore();
        const storage = (e: StorageEvent) => { if ((e.key === LOGOUT_INTENT_KEY || e.key === null) && hasLogoutIntent()) auth(); };
        commands.current = { read: () => { void run(); }, write: run, interrupt: () => clear('interrupted') }; clear(null);
        if (!enabled) return () => { alive = false; clear(null); commands.current = empty; };
        window.addEventListener(AUTH_REQUIRED_EVENT, auth); for (const e of ['blur', 'pagehide', 'hashchange', 'popstate']) window.addEventListener(e, suspend); for (const e of ['focus', 'pageshow']) window.addEventListener(e, restore); window.addEventListener('storage', storage); document.addEventListener('visibilitychange', visibility);
        const timer = window.setInterval(() => { if (epoch !== getProtectedRequestEpoch() || hasLogoutIntent()) { if (!locked) auth(); } else if (accepted && !available()) clear(Number.isFinite(age(accepted.started)) ? 'interrupted' : 'clock'); else if (accepted) update(n => n + 1); }, 250);
        void run();
        return () => { alive = false; clear(null); commands.current = empty; window.clearInterval(timer); window.removeEventListener(AUTH_REQUIRED_EVENT, auth); for (const e of ['blur', 'pagehide', 'hashchange', 'popstate']) window.removeEventListener(e, suspend); for (const e of ['focus', 'pageshow']) window.removeEventListener(e, restore); window.removeEventListener('storage', storage); document.removeEventListener('visibilitychange', visibility); };
    }, [enabled, key, epoch, scope, sessionKey, readOnly]);
    // Access revalidation clears private state without remounting or restarting
    // the reader. Returning to the same session needs an explicit reload.
    useEffect(() => { if (checkingAccess) commands.current.interrupt(); }, [checkingAccess]);
    const visible = enabled && !checkingAccess && snapshot?.key === key && snapshot.epoch === getProtectedRequestEpoch() && !hasLogoutIntent() && document.visibilityState !== 'hidden' && document.hasFocus() && age(snapshot.started) < snapshot.lifetime;
    return { view: visible ? snapshot.view : null, elapsed: visible ? snapshot.offset + age(snapshot.started) : Infinity, busy, failure, generation, confirmed, uncertain: uncertain.get(key) ?? null, previous: prior.get(key) ?? [], full: !incidentRequestCapacity(uncertain, prior), read: () => commands.current.read(), write: (body: IncidentRequest) => commands.current.write(body) };
}
