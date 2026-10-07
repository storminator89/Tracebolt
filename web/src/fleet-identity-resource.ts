import { useCallback, useEffect, useRef, useState } from 'react';
import { APIError, AUTH_REQUIRED_EVENT, getProtectedRequestEpoch, request } from './api';
import { hasLogoutIntent } from './auth';
import { inventoryAge } from './complete-packages-types';
import { endpointSnapshotVisible } from './endpoint-identity-types';
import { FLEET_IDENTITY_BYTES, fleetIdentityProjection, validFleetIdentityView } from './fleet-identity-types';
import type { FleetIdentityView } from './fleet-identity-types';
export type FleetIdentityFailure = 'loadError' | 'invalid' | 'timeout' | 'session' | 'clock' | 'busy';
type Anchor = { mono: number; wall: number };
const capture = (): Anchor => ({ mono: performance.now(), wall: Date.now() });
function elapsed(anchor: Anchor): number {
    const mono = performance.now() - anchor.mono, wall = Date.now() - anchor.wall;
    return Number.isFinite(mono) && mono >= 0 && Number.isFinite(wall) && Math.abs(wall - mono) <= 1500 ? mono : Infinity;
}
export function useFleetIdentity(enabled: boolean, sessionKey: string | null = null, revision = '', retainNavigation = false) {
    const key = retainNavigation ? `${sessionKey ?? ''}` : `${revision}:${sessionKey ?? ''}:${enabled}`;
    const retainedSession = useRef<string | null | undefined>(undefined);
    const workspaceClock = useRef<{ sessionKey: string | null; epoch: number; serverNow: string; anchor: Anchor } | null>(null);
    const retained = useRef<{ key: string; epoch: number; view: FleetIdentityView; anchor: Anchor } | null>(null);
    const [data, setData] = useState<{ key: string; view: FleetIdentityView } | null>(null), [loading, setLoading] = useState(false), [recovering, setRecovering] = useState(false), [error, setError] = useState<FleetIdentityFailure | null>(null), [, tick] = useState(0);
    const alive = useRef(false), locked = useRef(false), suspended = useRef(false), epoch = useRef(0), current = useRef<FleetIdentityView | null>(null);
    const anchor = useRef<Anchor | null>(null), latestServer = useRef<string | null>(null), pending = useRef<{ controller: AbortController; timeout: number; started: Anchor } | null>(null);
    const cancel = useCallback(() => { epoch.current++; pending.current?.controller.abort(); window.clearTimeout(pending.current?.timeout); pending.current = null; if (alive.current) { setLoading(false); setRecovering(false); } }, []);
    const clear = useCallback((failure: FleetIdentityFailure | null = null) => { cancel(); retained.current = null; anchor.current = null; current.current = null; if (alive.current) { setData(null); setError(failure); } }, [cancel]);
    const read = useCallback(async () => {
        if (!enabled || !alive.current || locked.current || suspended.current || document.visibilityState === 'hidden' || retainNavigation && pending.current) return;
        const cached = retained.current;
        if (retainNavigation && cached?.key === key && cached.epoch === getProtectedRequestEpoch() && !hasLogoutIntent() && elapsed(cached.anchor) <= 45000) { cancel(); setError(null); } else clear();
        const revision = epoch.current, controller = new AbortController(), started = capture(), protectedEpoch = getProtectedRequestEpoch();
        setLoading(true); pending.current = { controller, started, timeout: window.setTimeout(() => { if (revision === epoch.current) clear('timeout'); }, 10000) };
        const active = () => {
            if (!alive.current || locked.current || suspended.current || controller.signal.aborted || revision !== epoch.current) return false;
            if (protectedEpoch !== getProtectedRequestEpoch()) { locked.current = true; clear('session'); return false; }
            if (!Number.isFinite(elapsed(started))) { clear('clock'); return false; }
            if (elapsed(started) >= 10000) { clear('timeout'); return false; }
            return true;
        };
        try {
            let response: unknown;
            // Retry only this exact GET once. Keep the original controller,
            // access epoch, capture anchor and total ten-second deadline.
            for (let attempt = 0; attempt < 2; attempt++) {
                try {
                    response = await request<unknown>('/fleet/endpoint-identities', { signal: controller.signal }, FLEET_IDENTITY_BYTES);
                    break;
                } catch (caught) {
                    if (!active()) return;
                    if (attempt !== 0 || !(caught instanceof APIError) || caught.status !== 429 || caught.code !== 'storage_busy') throw caught;
                    setRecovering(true);
                    await new Promise<void>(resolve => {
                        const finish = () => { window.clearTimeout(delay); controller.signal.removeEventListener('abort', finish); resolve(); };
                        const delay = window.setTimeout(finish, 2000);
                        controller.signal.addEventListener('abort', finish, { once: true });
                        if (controller.signal.aborted) finish();
                    });
                    if (!active()) return;
                    setRecovering(false);
                }
            }
            if (!active()) return;
            if (!validFleetIdentityView(response)) { clear('invalid'); return; }
            const clock = retainNavigation && workspaceClock.current?.sessionKey === sessionKey && workspaceClock.current.epoch === protectedEpoch ? workspaceClock.current : null;
            if (latestServer.current && inventoryAge(response.serverNow, latestServer.current) < 0 || clock && inventoryAge(response.serverNow, clock.serverNow) < 0) { clear('clock'); return; }
            // A repeated server timestamp cannot renew the original observation
            // budget, even after navigation, expiry or a manual refresh.
            const advance = clock ? Date.parse(response.serverNow) - Date.parse(clock.serverNow) : 0;
            const previousAge = clock ? Math.max(0, started.mono - clock.anchor.mono, started.wall - clock.anchor.wall) : 0;
            // Retain the elapsed lower bound for tiny advances too (1ms rounding
            // allowance), matching the application-check reader's clock policy.
            const clockOffset = Math.max(0, previousAge - Math.max(0, advance - 1));
            const acceptedAt = { mono: started.mono - clockOffset, wall: started.wall - clockOffset };
            if (retainNavigation && (!Number.isFinite(elapsed(acceptedAt)) || elapsed(acceptedAt) > 45000)) { clear('clock'); return; }
            if (retainNavigation) workspaceClock.current = { sessionKey, epoch: protectedEpoch, serverNow: response.serverNow, anchor: acceptedAt };
            latestServer.current = response.serverNow; anchor.current = acceptedAt; current.current = response;
            if (retainNavigation) retained.current = { key, epoch: protectedEpoch, view: response, anchor: acceptedAt };
            setData({ key, view: response });
        } catch (caught) {
            if (!active()) return;
            if (caught instanceof APIError && caught.status === 401) { locked.current = true; clear('session'); }
            else clear(caught instanceof APIError && caught.status === 429 ? 'busy' : 'loadError');
        } finally {
            if (revision === epoch.current) { window.clearTimeout(pending.current?.timeout); pending.current = null; if (alive.current) { setLoading(false); setRecovering(false); } }
        }
    }, [cancel, clear, enabled, key, retainNavigation]);
    useEffect(() => {
        alive.current = true; if (!retainNavigation || retainedSession.current !== sessionKey) locked.current = false; retainedSession.current = sessionKey; suspended.current = document.visibilityState === 'hidden';
        const cached = retained.current;
        if (retainNavigation && !locked.current && !suspended.current && cached?.key === key && cached.epoch === getProtectedRequestEpoch() && !hasLogoutIntent() && elapsed(cached.anchor) <= 45000) {
            cancel(); anchor.current = cached.anchor; current.current = cached.view; latestServer.current = cached.view.serverNow; setData({ key, view: cached.view }); setError(null);
        } else { latestServer.current = null; clear(locked.current ? 'session' : null); }
        if (!enabled && !retainNavigation) return () => { alive.current = false; clear(); };
        const lock = () => { locked.current = true; clear('session'); };
        const suspend = () => { suspended.current = true; clear(); };
        const restore = () => { if (locked.current || document.visibilityState === 'hidden') return; suspended.current = false; void read(); };
        const visibility = () => document.visibilityState === 'hidden' ? suspend() : restore();
        const show = (event: PageTransitionEvent) => { if (event.persisted || suspended.current) restore(); };
        window.addEventListener(AUTH_REQUIRED_EVENT, lock); window.addEventListener('pagehide', suspend); window.addEventListener('pageshow', show); window.addEventListener('blur', suspend); window.addEventListener('focus', restore); if (!retainNavigation) window.addEventListener('hashchange', suspend); document.addEventListener('visibilitychange', visibility);
        const poll = retainNavigation && enabled ? window.setInterval(() => { void read(); }, 30000) : undefined;
        const timer = window.setInterval(() => {
            if (retainNavigation && retained.current && (retained.current.epoch !== getProtectedRequestEpoch() || hasLogoutIntent())) { lock(); return; }
            const base = anchor.current ?? pending.current?.started;
            if (base && !Number.isFinite(elapsed(base))) { clear('clock'); return; }
            if (retainNavigation && anchor.current && elapsed(anchor.current) > 45000) { clear(); return; }
            const view = current.current;
            if (view && anchor.current) {
                const age = elapsed(anchor.current);
                if (view.items.some(item => item.latest && !endpointSnapshotVisible(item, age))) {
                    current.current = { ...view, items: view.items.map(item => item.latest && !endpointSnapshotVisible(item, age) ? { ...item, status: 'expired', latest: null } : item) }; if (retainNavigation && retained.current) retained.current = { ...retained.current, view: current.current }; setData({ key, view: current.current });
                }
            }
            if (base) tick(n => n + 1);
        }, 1000);
        void read();
        return () => { alive.current = false; if (retainNavigation) cancel(); else clear(); window.clearInterval(timer); window.clearInterval(poll); window.removeEventListener(AUTH_REQUIRED_EVENT, lock); window.removeEventListener('pagehide', suspend); window.removeEventListener('pageshow', show); window.removeEventListener('blur', suspend); window.removeEventListener('focus', restore); window.removeEventListener('hashchange', suspend); document.removeEventListener('visibilitychange', visibility); };
    }, [cancel, clear, enabled, key, read, revision, retainNavigation]);
    const age = anchor.current ? elapsed(anchor.current) : Infinity;
    const allowed = !retainNavigation || retained.current?.epoch === getProtectedRequestEpoch() && !hasLogoutIntent() && age <= 45000;
    const view = enabled && allowed && data?.key === key ? data.view : null;
    return { view, identities: fleetIdentityProjection(view, age), loading: enabled && loading, recovering: enabled && recovering, error: enabled ? error : null, elapsed: age, refresh: () => void read() };
}
export type FleetIdentityResource = ReturnType<typeof useFleetIdentity>;
