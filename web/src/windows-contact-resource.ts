import { useEffect, useRef, useState } from 'react';
import { APIError, AUTH_REQUIRED_EVENT, getProtectedRequestEpoch, request } from './api';
import { hasLogoutIntent } from './auth';
import { inventoryAge } from './complete-packages-types';
import { acceptWindowsContactClock, windowsContactElapsed } from './windows-contact-clock';
import { validWindowsContactDeviceId, validWindowsContactTimestamp, validWindowsContactView, WINDOWS_CONTACT_VIEW_BYTES } from './windows-contact-types';
import type { WindowsContactView } from './windows-contact-types';

export type WindowsContactFailure = 'invalid' | 'unavailable' | 'timeout' | 'session' | 'authority' | 'clock';
type Anchor = { mono: number; wall: number };
type Accepted = { key: string; epoch: number; view: WindowsContactView; started: Anchor };
const capture = (): Anchor => ({ mono: performance.now(), wall: Date.now() });
function elapsed(anchor: Anchor): number {
    const mono = performance.now() - anchor.mono, wall = Date.now() - anchor.wall;
    return Number.isFinite(mono) && mono >= 0 && Number.isFinite(wall) && Math.abs(wall - mono) <= 1500 ? mono : Infinity;
}
/** Isolated operator GET. No endpoint collection, shared Linux health input or mutation. */
export function useWindowsContact(deviceId: string, enabled: boolean, sessionKey: string | null) {
    const key = JSON.stringify(['windows-contact', deviceId, sessionKey]);
    const [data, setData] = useState<Accepted | null>(null), [loading, setLoading] = useState(false), [error, setError] = useState<WindowsContactFailure | null>(null), [, tick] = useState(0);
    const refreshRef = useRef<() => void>(() => {});
    useEffect(() => {
        let alive = true, locked = false, suspended = document.visibilityState === 'hidden', revision = 0;
        let accepted: Accepted | null = null, pending: { controller: AbortController; timeout: number; started: Anchor } | null = null;
        const epoch = getProtectedRequestEpoch();
        const cancel = () => { revision++; pending?.controller.abort(); window.clearTimeout(pending?.timeout); pending = null; };
        const clear = (failure: WindowsContactFailure | null = null) => { cancel(); accepted = null; if (alive) { setData(null); setLoading(false); setError(failure); } };
        const lock = () => { locked = true; clear('session'); };
        const permitted = () => enabled && alive && !locked && !suspended && document.visibilityState !== 'hidden';
        const age = (value: Accepted) => windowsContactElapsed(key, value.epoch, value.view.serverNow, elapsed(value.started));
        const authority = (value: Accepted): WindowsContactFailure | null => {
            if (epoch !== getProtectedRequestEpoch() || hasLogoutIntent()) return 'session';
            const offset = age(value);
            if (!Number.isFinite(offset)) return 'clock';
            if (!validWindowsContactTimestamp(sessionKey) || inventoryAge(sessionKey, value.view.serverNow) <= offset) return 'session';
            if (inventoryAge(value.view.certificateExpiresAt, value.view.serverNow) <= offset) return 'authority';
            return null;
        };
        const read = async () => {
            if (!permitted()) return;
            if (epoch !== getProtectedRequestEpoch() || hasLogoutIntent()) { lock(); return; }
            clear();
            if (!validWindowsContactDeviceId(deviceId) || !validWindowsContactTimestamp(sessionKey)) { clear('invalid'); return; }
            const current = revision, controller = new AbortController(), started = capture();
            setLoading(true);
            pending = { controller, started, timeout: window.setTimeout(() => { if (current === revision) clear('timeout'); }, 10000) };
            const active = () => {
                if (!permitted() || controller.signal.aborted || current !== revision) return false;
                if (epoch !== getProtectedRequestEpoch() || hasLogoutIntent()) { lock(); return false; }
                const duration = elapsed(started);
                if (!Number.isFinite(duration)) { clear('clock'); return false; }
                if (duration >= 10000) { clear('timeout'); return false; }
                return true;
            };
            try {
                const response: unknown = await request(`/devices/${encodeURIComponent(deviceId)}/windows-contact`, { signal: controller.signal }, WINDOWS_CONTACT_VIEW_BYTES);
                if (!active()) return;
                if (!validWindowsContactView(response, deviceId)) { clear('invalid'); return; }
                if (!acceptWindowsContactClock(key, epoch, response.serverNow, elapsed(started))) { clear('clock'); return; }
                const next = { key, epoch, view: response, started }, failure = authority(next);
                if (failure) { if (failure === 'session') locked = true; clear(failure); return; }
                accepted = next; setData(next);
            } catch (caught) {
                if (!active()) return;
                if (caught instanceof APIError && caught.status === 401) lock();
                else clear('unavailable');
            } finally {
                if (current === revision) { window.clearTimeout(pending?.timeout); pending = null; if (alive) setLoading(false); }
            }
        };
        const suspend = () => { suspended = true; clear(); };
        const restore = () => { if (!alive || locked || document.visibilityState === 'hidden') return; suspended = false; void read(); };
        const visibility = () => document.visibilityState === 'hidden' ? suspend() : restore();
        const show = (event: PageTransitionEvent) => { if (event.persisted || suspended) restore(); };
        clear(); refreshRef.current = () => { void read(); };
        if (!enabled) return () => { alive = false; cancel(); refreshRef.current = () => {}; };
        window.addEventListener(AUTH_REQUIRED_EVENT, lock); window.addEventListener('blur', suspend); window.addEventListener('focus', restore); window.addEventListener('pagehide', suspend); window.addEventListener('pageshow', show); window.addEventListener('hashchange', suspend); document.addEventListener('visibilitychange', visibility);
        const clockTimer = window.setInterval(() => {
            if (epoch !== getProtectedRequestEpoch() || hasLogoutIntent()) { lock(); return; }
            if (accepted) { const failure = authority(accepted); if (failure) { if (failure === 'session') locked = true; clear(failure); return; } tick(n => n + 1); }
            else if (pending && !Number.isFinite(elapsed(pending.started))) clear('clock');
        }, 1000);
        const refreshTimer = window.setInterval(() => { if (!pending) void read(); }, 15000);
        void read();
        return () => { alive = false; cancel(); accepted = null; refreshRef.current = () => {}; window.clearInterval(clockTimer); window.clearInterval(refreshTimer); window.removeEventListener(AUTH_REQUIRED_EVENT, lock); window.removeEventListener('blur', suspend); window.removeEventListener('focus', restore); window.removeEventListener('pagehide', suspend); window.removeEventListener('pageshow', show); window.removeEventListener('hashchange', suspend); document.removeEventListener('visibilitychange', visibility); };
    }, [deviceId, enabled, key, sessionKey]);
    const candidate = enabled && data?.key === key && data.epoch === getProtectedRequestEpoch() && !hasLogoutIntent() ? data : null;
    const elapsedMS = candidate ? windowsContactElapsed(key, candidate.epoch, candidate.view.serverNow, elapsed(candidate.started)) : Infinity;
    const view = candidate && Number.isFinite(elapsedMS) && validWindowsContactTimestamp(sessionKey) && inventoryAge(sessionKey, candidate.view.serverNow) > elapsedMS && inventoryAge(candidate.view.certificateExpiresAt, candidate.view.serverNow) > elapsedMS ? candidate.view : null;
    return { view, elapsedMS, loading: enabled && loading, error: enabled ? error : null, refresh: () => refreshRef.current() };
}
export type WindowsContactResource = ReturnType<typeof useWindowsContact>;
