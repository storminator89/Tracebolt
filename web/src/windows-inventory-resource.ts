import { useCallback, useEffect, useRef, useState } from 'react';
import { inventoryAge } from './complete-packages-types';
import { APIError, AUTH_REQUIRED_EVENT, getProtectedRequestEpoch, request } from './api';
import { validWindowsDeviceId, validWindowsInventoryView, WINDOWS_INVENTORY_VIEW_BYTES, windowsInventoryStatus } from './windows-inventory-types';
import type { WindowsInventoryView } from './windows-inventory-types';
export type WindowsInventoryFailure = 'invalid' | 'unavailable' | 'timeout' | 'session' | 'clock';
type Anchor = { mono: number; wall: number };
const capture = (): Anchor => ({ mono: performance.now(), wall: Date.now() });
function elapsed(anchor: Anchor): number {
    const mono = performance.now() - anchor.mono, wall = Date.now() - anchor.wall;
    return Number.isFinite(mono) && mono >= 0 && Number.isFinite(wall) && Math.abs(wall - mono) <= 1500 ? mono : Infinity;
}
/** Same-origin operator read only. Original capture time controls freshness;
 * session, navigation and visibility changes discard all private row data. */
export function useWindowsInventory(deviceId: string, enabled: boolean, sessionKey: string | null = null) {
    const key = `${deviceId}:${sessionKey ?? ''}:${enabled}`;
    const [data, setData] = useState<{ key: string; view: WindowsInventoryView } | null>(null), [loading, setLoading] = useState(false), [error, setError] = useState<WindowsInventoryFailure | null>(null), [, tick] = useState(0);
    const alive = useRef(false), locked = useRef(false), suspended = useRef(false), epoch = useRef(0), anchor = useRef<Anchor | null>(null), latestServer = useRef<{ value: string; floor: string; accepted: Anchor } | null>(null);
    const pending = useRef<{ controller: AbortController; timeout: number; started: Anchor } | null>(null);
    const cancel = useCallback(() => { epoch.current++; pending.current?.controller.abort(); window.clearTimeout(pending.current?.timeout); pending.current = null; if (alive.current) setLoading(false); }, []);
    const clear = useCallback((failure: WindowsInventoryFailure | null = null) => { cancel(); anchor.current = null; if (alive.current) { setData(null); setError(failure); } }, [cancel]);
    const read = useCallback(async () => {
        if (!enabled || !alive.current || locked.current || suspended.current || document.visibilityState === 'hidden') return;
        clear(); if (!validWindowsDeviceId(deviceId)) { setError('invalid'); return; }
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
            const response: unknown = await request(`/devices/${encodeURIComponent(deviceId)}/windows-inventory`, { signal: controller.signal }, WINDOWS_INVENTORY_VIEW_BYTES);
            if (!active()) return;
            if (!validWindowsInventoryView(response, deviceId)) { clear('invalid'); return; }
            const server = response.serverNow;
            // Keep this successful-response anchor across refresh, errors and suspension.
            // A replay or slowly advancing manager clock must not renew retained rows.
            const previous = latestServer.current;
            if (previous !== null && (inventoryAge(server, previous.value) < 0 || inventoryAge(server, previous.floor) + 1500 < elapsed(previous.accepted))) { clear('clock'); return; }
            latestServer.current = previous ? { ...previous, value: server } : { value: server, floor: server, accepted: capture() }; anchor.current = started; setData({ key, view: response });
        } catch (caught) {
            if (!active()) return;
            if (caught instanceof APIError && caught.status === 401) { locked.current = true; clear('session'); }
            else clear('unavailable');
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
        const clockTimer = window.setInterval(() => { const base = anchor.current ?? pending.current?.started; if (base && !Number.isFinite(elapsed(base))) { clear('clock'); return; } if (base) tick(n => n + 1); }, 1000);
        const refreshTimer = window.setInterval(() => { if (!pending.current) void read(); }, 15000);
        void read();
        return () => { alive.current = false; clear(); window.clearInterval(clockTimer); window.clearInterval(refreshTimer); window.removeEventListener(AUTH_REQUIRED_EVENT, lock); window.removeEventListener('pagehide', suspend); window.removeEventListener('pageshow', show); window.removeEventListener('blur', suspend); window.removeEventListener('focus', restore); window.removeEventListener('hashchange', suspend); document.removeEventListener('visibilitychange', visibility); };
    }, [clear, enabled, key, read]);
    const view = enabled && data?.key === key ? data.view : null, age = anchor.current ? elapsed(anchor.current) : Infinity;
    const status = view ? windowsInventoryStatus(view, age) : null;
    const eventAge = view?.events ? inventoryAge(view.serverNow, view.events.collectedAt) + age : Infinity;
    const events = view && (status === 'fresh' || status === 'stale') && eventAge < 86400000 ? view.events ?? null : null;
    const eventsStale = events !== null && (status !== 'fresh' || eventAge < 0 || eventAge > 120000);
    const volumeAge = view?.volumes ? inventoryAge(view.serverNow, view.volumes.collectedAt) + age : Infinity;
    const volumes = view && (status === 'fresh' || status === 'stale') && volumeAge < 86400000 ? view.volumes ?? null : null;
    const volumesStale = volumes !== null && (volumeAge < 0 || volumeAge > 120000 || !view?.receivedAt || inventoryAge(view.serverNow, view.receivedAt) + age > 120000);
    const metricsAge = view?.processMetrics ? inventoryAge(view.serverNow, view.processMetrics.collectedAt) + age : Infinity;
    const processMetrics = view && (status === 'fresh' || status === 'stale') && metricsAge < 86400000 ? view.processMetrics ?? null : null;
    const processMetricsStale = processMetrics !== null && (metricsAge < 0 || metricsAge > 120000 || !view?.receivedAt || inventoryAge(view.serverNow, view.receivedAt) + age > 120000);
    const networkAge = view?.network ? inventoryAge(view.serverNow, view.network.collectedAt) + age : Infinity;
    const network = view && (status === 'fresh' || status === 'stale') && networkAge < 86400000 ? view.network ?? null : null;
    const networkStale = network !== null && (networkAge < 0 || networkAge > 120000 || !view?.receivedAt || inventoryAge(view.serverNow, view.receivedAt) + age > 120000);
    const networkExpired = Boolean(view?.network) && Number.isFinite(networkAge) && networkAge >= 86400000;
    return { elapsedMS: age, network, networkStale, networkExpired, processMetrics, processMetricsStale, volumes, volumesStale, events, eventsStale, view, snapshot: view && (status === 'fresh' || status === 'stale') ? view.snapshot : null, status, loading: enabled && loading, error: enabled ? error : null, refresh: () => void read() };
}
export type WindowsInventoryResource = ReturnType<typeof useWindowsInventory>;
