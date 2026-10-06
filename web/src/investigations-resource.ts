import { useEffect, useRef, useState } from 'react';
import { APIError, AUTH_REQUIRED_EVENT, getProtectedRequestEpoch, request } from './api';
import { hasLogoutIntent } from './auth';
import { ageInvestigations, INVESTIGATIONS_BYTES, validInvestigationsView } from './investigations-types';
import type { InvestigationScope, InvestigationsView } from './investigations-types';
type Failure = 'load' | 'invalid' | 'session' | 'timeout' | 'interrupted' | 'clock';
type Anchor = { mono: number; wall: number };
const capture = (): Anchor => ({ mono: performance.now(), wall: Date.now() });
function elapsed(anchor: Anchor): number {
    const mono = performance.now() - anchor.mono, wall = Date.now() - anchor.wall;
    return Number.isFinite(mono) && mono >= 0 && Math.abs(wall - mono) <= 1500 ? mono : Infinity;
}
export function useInvestigations(enabled: boolean, sessionKey: string | null, route: string, scope: InvestigationScope = 'open', offset = 0) {
    // Navigation is owned by the React route key. Unconditionally suspending on
    // hashchange can deadlock equivalent or rapidly coalesced Back/Forward events.
    const key = JSON.stringify([enabled, sessionKey, route, scope, offset]);
    const [snapshot, setSnapshot] = useState<{ key: string; epoch: number; view: InvestigationsView; anchor: Anchor } | null>(null);
    const [pending, setPending] = useState(false), [failure, setFailure] = useState<Failure | null>(null), [locked, setLocked] = useState(false), [, tick] = useState(0);
    const refresh = useRef(() => {});
    useEffect(() => {
        let alive = true, accessEnded = false, suspended = document.visibilityState === 'hidden', revision = 0;
        let operation: { controller: AbortController; timer: number; started: Anchor } | null = null;
        let observed: Anchor | null = null, latestServer: string | null = null;
        const accessEpoch = getProtectedRequestEpoch();
        const cancel = () => { revision++; operation?.controller.abort(); window.clearTimeout(operation?.timer); operation = null; if (alive) setPending(false); };
        const clear = (error: Failure | null) => { cancel(); observed = null; if (alive) { setSnapshot(null); setFailure(error); } };
        const lock = () => { accessEnded = true; clear('session'); if (alive) setLocked(true); };
        const run = async () => {
            if (!enabled || !alive || accessEnded || suspended || document.visibilityState === 'hidden' || operation) return;
            if (accessEpoch !== getProtectedRequestEpoch() || hasLogoutIntent()) { lock(); return; }
            cancel(); setFailure(null);
            const controller = new AbortController(), started = capture(), serial = ++revision;
            setPending(true);
            operation = { controller, started, timer: window.setTimeout(() => { if (serial === revision) clear('timeout'); }, 10000) };
            const active = () => {
                if (!alive || suspended || accessEnded || serial !== revision || controller.signal.aborted) return false;
                if (accessEpoch !== getProtectedRequestEpoch() || hasLogoutIntent()) { lock(); return false; }
                if (!Number.isFinite(elapsed(started))) { clear('clock'); return false; }
                if (elapsed(started) >= 10000) { clear('timeout'); return false; }
                return true;
            };
            try {
                const value = await request<unknown>(`/investigations?scope=${scope}&offset=${offset}`, { signal: controller.signal }, INVESTIGATIONS_BYTES);
                if (!active()) return;
                if (!validInvestigationsView(value, scope, offset)) { clear('invalid'); return; }
                if (latestServer && Date.parse(value.serverNow) < Date.parse(latestServer)) { clear('clock'); return; }
                latestServer = value.serverNow; observed = started;
                setSnapshot({ key, epoch: accessEpoch, view: value, anchor: started });
            } catch (caught) {
                if (!active()) return;
                if (caught instanceof APIError && caught.status === 401) lock(); else clear('load');
            } finally {
                if (alive && operation?.controller === controller) { window.clearTimeout(operation.timer); operation = null; setPending(false); }
            }
        };
        const suspend = () => { suspended = true; clear('interrupted'); };
        const restore = () => { if (accessEnded || document.visibilityState === 'hidden') return; suspended = false; void run(); };
        const visibility = () => document.visibilityState === 'hidden' ? suspend() : restore();
        const show = (event: PageTransitionEvent) => { if (event.persisted || suspended) restore(); };
        refresh.current = () => { void run(); };
        setLocked(false); setSnapshot(null); setFailure(null); setPending(false);
        if (!enabled) return () => { alive = false; cancel(); refresh.current = () => {}; };
        window.addEventListener(AUTH_REQUIRED_EVENT, lock); window.addEventListener('pagehide', suspend); window.addEventListener('pageshow', show);
        window.addEventListener('blur', suspend); window.addEventListener('focus', restore); document.addEventListener('visibilitychange', visibility);
        const poll = window.setInterval(() => { void run(); }, 30000);
        const timer = window.setInterval(() => {
            if (accessEpoch !== getProtectedRequestEpoch() || hasLogoutIntent()) { if (!accessEnded) lock(); return; }
            const anchor = observed ?? operation?.started;
            if (anchor && !Number.isFinite(elapsed(anchor))) { clear('clock'); return; }
            if (observed && elapsed(observed) > 45000) { clear('load'); return; }
            if (observed) tick(n => n + 1);
        }, 1000);
        void run();
        return () => {
            alive = false; cancel(); refresh.current = () => {}; window.clearInterval(poll); window.clearInterval(timer);
            window.removeEventListener(AUTH_REQUIRED_EVENT, lock); window.removeEventListener('pagehide', suspend); window.removeEventListener('pageshow', show);
            window.removeEventListener('blur', suspend); window.removeEventListener('focus', restore); document.removeEventListener('visibilitychange', visibility);
        };
    }, [enabled, key, scope, offset]);
    const available = enabled && snapshot?.key === key && snapshot.epoch === getProtectedRequestEpoch() && !hasLogoutIntent() && elapsed(snapshot.anchor) <= 45000;
    const view = available ? ageInvestigations(snapshot.view, elapsed(snapshot.anchor)) : null;
    return { view, pending: enabled && pending, failure: enabled ? failure : null, locked, refresh: () => refresh.current() };
}
export type InvestigationsResource = ReturnType<typeof useInvestigations>;
