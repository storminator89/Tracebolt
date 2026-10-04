import { useCallback, useEffect, useRef, useState } from 'react';
import { APIError, AUTH_REQUIRED_EVENT, getProtectedRequestEpoch, request } from './api';
import { inventoryAge } from './complete-packages-types';
import { ENDPOINT_VIEW_BYTES, endpointSnapshotVisible, validEndpointDeviceId, validEndpointView } from './endpoint-identity-types';
import type { EndpointIdentityView } from './endpoint-identity-types';
export type EndpointFailure = 'loadError' | 'invalid' | 'timeout' | 'session' | 'clock' | 'busy';
type Anchor = { mono: number; wall: number };
const capture = (): Anchor => ({ mono: performance.now(), wall: Date.now() });
function elapsed(anchor: Anchor): number {
    const mono = performance.now() - anchor.mono, wall = Date.now() - anchor.wall;
    return Number.isFinite(mono) && mono >= 0 && Number.isFinite(wall) && Math.abs(wall - mono) <= 1500 ? mono : Infinity;
}
export function useEndpointIdentity(deviceId: string, enabled: boolean, sessionKey: string | null = null) {
    const key = `${deviceId}:${sessionKey ?? ''}:${enabled}`;
    const [data, setData] = useState<{ key: string; view: EndpointIdentityView } | null>(null), [loading, setLoading] = useState(false), [error, setError] = useState<EndpointFailure | null>(null), [, tick] = useState(0);
    const alive = useRef(false), locked = useRef(false), suspended = useRef(false), epoch = useRef(0), current = useRef<EndpointIdentityView | null>(null);
    const anchor = useRef<Anchor | null>(null), latestServer = useRef<string | null>(null), pending = useRef<{ controller: AbortController; timeout: number; started: Anchor } | null>(null);
    const cancel = useCallback(() => { epoch.current++; pending.current?.controller.abort(); window.clearTimeout(pending.current?.timeout); pending.current = null; if (alive.current) setLoading(false); }, []);
    const clear = useCallback((failure: EndpointFailure | null = null) => { cancel(); anchor.current = null; current.current = null; if (alive.current) { setData(null); setError(failure); } }, [cancel]);
    const read = useCallback(async () => {
        if (!enabled || !alive.current || locked.current || suspended.current || document.visibilityState === 'hidden') return;
        clear(); if (!validEndpointDeviceId(deviceId)) { setError('invalid'); return; }
        const revision = epoch.current, controller = new AbortController(), started = capture(), protectedEpoch = getProtectedRequestEpoch();
        setLoading(true); pending.current = { controller, started, timeout: window.setTimeout(() => { if (revision === epoch.current) clear('timeout'); }, 10000) };
        const active = () => {
            if (!alive.current || locked.current || suspended.current || controller.signal.aborted || revision !== epoch.current || protectedEpoch !== getProtectedRequestEpoch()) return false;
            if (!Number.isFinite(elapsed(started))) { clear('clock'); return false; }
            if (elapsed(started) >= 10000) { clear('timeout'); return false; }
            return true;
        };
        try {
            const response = await request<unknown>(`/devices/${encodeURIComponent(deviceId)}/inventory/endpoint-identity`, { signal: controller.signal }, ENDPOINT_VIEW_BYTES);
            if (!active()) return;
            if (!validEndpointView(response, deviceId)) { clear('invalid'); return; }
            if (latestServer.current && inventoryAge(response.serverNow, latestServer.current) < 0) { clear('clock'); return; }
            latestServer.current = response.serverNow; anchor.current = started; current.current = response; setData({ key, view: response });
        } catch (caught) {
            if (!active()) return;
            if (caught instanceof APIError && caught.status === 401) { locked.current = true; clear('session'); }
            else clear(caught instanceof APIError && caught.status === 429 ? 'busy' : 'loadError');
        } finally {
            if (revision === epoch.current) { window.clearTimeout(pending.current?.timeout); pending.current = null; if (alive.current) setLoading(false); }
        }
    }, [clear, deviceId, enabled, key]);
    useEffect(() => {
        alive.current = true; locked.current = false; suspended.current = document.visibilityState === 'hidden'; latestServer.current = null; clear();
        if (!enabled) return () => { alive.current = false; clear(); };
        const lock = () => { locked.current = true; clear('session'); };
        const suspend = () => { suspended.current = true; clear(); };
        const restore = () => { if (locked.current || document.visibilityState === 'hidden') return; suspended.current = false; void read(); };
        const visibility = () => document.visibilityState === 'hidden' ? suspend() : restore();
        const show = (event: PageTransitionEvent) => { if (event.persisted || suspended.current) restore(); };
        window.addEventListener(AUTH_REQUIRED_EVENT, lock); window.addEventListener('pagehide', suspend); window.addEventListener('pageshow', show); window.addEventListener('blur', suspend); window.addEventListener('focus', restore); window.addEventListener('hashchange', suspend); document.addEventListener('visibilitychange', visibility);
        const timer = window.setInterval(() => {
            const base = anchor.current ?? pending.current?.started;
            if (base && !Number.isFinite(elapsed(base))) { clear('clock'); return; }
            const view = current.current;
            if (view?.latest && anchor.current && !endpointSnapshotVisible(view, elapsed(anchor.current))) {
                // Drop observed values once their original retention window closes.
                current.current = { ...view, status: 'expired', latest: null }; setData({ key, view: current.current });
            }
            if (base) tick(n => n + 1);
        }, 1000);
        void read();
        return () => { alive.current = false; clear(); window.clearInterval(timer); window.removeEventListener(AUTH_REQUIRED_EVENT, lock); window.removeEventListener('pagehide', suspend); window.removeEventListener('pageshow', show); window.removeEventListener('blur', suspend); window.removeEventListener('focus', restore); window.removeEventListener('hashchange', suspend); document.removeEventListener('visibilitychange', visibility); };
    }, [clear, enabled, key, read]);
    const view = enabled && data?.key === key ? data.view : null, age = anchor.current ? elapsed(anchor.current) : Infinity;
    return { view, snapshot: view && endpointSnapshotVisible(view, age) ? view.latest : null, loading: enabled && loading, error: enabled ? error : null, elapsed: age, refresh: () => void read() };
}
export type EndpointIdentityResource = ReturnType<typeof useEndpointIdentity>;
