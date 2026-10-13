import { useCallback, useEffect, useRef, useState } from 'react';
import { APIError, AUTH_REQUIRED_EVENT, getProtectedRequestEpoch, mutateRaw } from './api';
import { hasLogoutIntent } from './auth';
import { inventoryAge } from './complete-packages-types';
import { FLEET_SOFTWARE_PAGE_BYTES, fleetSoftwareVisible, validFleetSoftwarePage, validFleetSoftwareQuery } from './windows-fleet-software-types';
import type { FleetSoftwareExpected, FleetSoftwareItem, FleetSoftwarePage, FleetSoftwareQuery } from './windows-fleet-software-types';

type Controls = Pick<FleetSoftwareQuery, 'name' | 'version'>;
type Failure = 'invalid' | 'unavailable' | 'timeout' | 'session' | 'clock' | 'busy' | 'restart' | 'unauthorized' | 'expired' | 'queryInvalid';
type Anchor = { mono: number; wall: number };
const capture = (): Anchor => ({ mono: performance.now(), wall: Date.now() });
const elapsed = (a: Anchor) => {
    const mono = performance.now() - a.mono, wall = Date.now() - a.wall;
    return Number.isFinite(mono) && mono >= 0 && Number.isFinite(wall) && Math.abs(wall - mono) <= 1500 ? mono : Infinity;
};
const initial = (): Controls => ({ name: '', version: '' });
/** One explicit read at a time. Only the current bounded page is retained.
 * Search text, rows and opaque cursors never enter storage, URLs or other views. */
export function useWindowsFleetSoftware(enabled: boolean, sessionKey: string | null, actor: string) {
    const key = `${enabled}:${actor}:${sessionKey ?? ''}`;
    const [data, setData] = useState<{ key: string; page: FleetSoftwarePage | null }>({ key, page: null });
    const [controls, setControls] = useState<{ key: string; value: Controls }>({ key, value: initial() });
    const [loading, setLoading] = useState(false), [error, setError] = useState<Failure | null>(null), [, tick] = useState(0);
    const alive = useRef(false), locked = useRef(false), suspended = useRef(false), revision = useRef(0), accessEpoch = useRef(0);
    const query = useRef<Controls>(initial()), current = useRef<FleetSoftwarePage | null>(null), anchor = useRef<Anchor | null>(null);
    const pending = useRef<{ controller: AbortController; timer: number; started: Anchor } | null>(null);
    const latestServer = useRef<{ value: string; floor: string; anchor: Anchor } | null>(null);
    const install = useCallback((page: FleetSoftwarePage | null) => { current.current = page; if (alive.current) setData({ key, page }); }, [key]);
    const cancel = useCallback(() => { revision.current++; pending.current?.controller.abort(); window.clearTimeout(pending.current?.timer); pending.current = null; if (alive.current) setLoading(false); }, []);
    const clear = useCallback((failure: Failure | null = null, keepControls = false) => {
        cancel(); anchor.current = null; install(null);
        if (!keepControls) { query.current = initial(); if (alive.current) setControls({ key, value: initial() }); }
        if (alive.current) setError(failure);
    }, [cancel, install, key]);
    const sessionValid = useCallback(() => !!sessionKey && Number.isFinite(Date.parse(sessionKey)) && Date.now() < Date.parse(sessionKey) && !hasLogoutIntent() && accessEpoch.current === getProtectedRequestEpoch(), [sessionKey]);
    const read = useCallback(async (cursor = '', expected: FleetSoftwareExpected = { mode: 'fleet', offset: 0 }, afterIdentity?: string) => {
        if (!enabled || !alive.current || locked.current || suspended.current || document.visibilityState === 'hidden') return;
        if (!sessionValid()) { locked.current = true; clear('session'); return; }
        const input: FleetSoftwareQuery = { ...query.current, cursor };
        if (!validFleetSoftwareQuery(input)) { clear('queryInvalid', true); return; }
        if (cursor && (!current.current || !anchor.current || !fleetSoftwareVisible(current.current, elapsed(anchor.current)))) { clear('expired'); return; }
        cancel(); install(null); anchor.current = null; setError(null); setLoading(true);
        const token = revision.current, controller = new AbortController(), started = capture();
        pending.current = { controller, started, timer: window.setTimeout(() => { if (token === revision.current) clear('timeout'); }, 10000) };
        const active = () => {
            if (!alive.current || locked.current || suspended.current || document.visibilityState === 'hidden' || token !== revision.current || controller.signal.aborted) return false;
            if (!sessionValid()) { locked.current = true; clear('session'); return false; }
            const duration = elapsed(started);
            if (!Number.isFinite(duration)) { clear('clock'); return false; }
            if (duration >= 10000) { clear('timeout'); return false; }
            return true;
        };
        try {
            const response: unknown = await mutateRaw('/fleet/windows-software/query', JSON.stringify(input), {}, controller.signal, FLEET_SOFTWARE_PAGE_BYTES, active);
            if (!active()) return;
            if (!validFleetSoftwarePage(response, input, expected)) { clear('invalid'); return; }
            if (Date.parse(response.serverNow) >= Date.parse(sessionKey!)) { locked.current = true; clear('session'); return; }
            if (response.cursorExpiresAt && inventoryAge(sessionKey!, response.cursorExpiresAt) < 0) { clear('invalid'); return; }
            const previous = latestServer.current;
            if (previous && (inventoryAge(response.serverNow, previous.value) < 0 || inventoryAge(response.serverNow, previous.floor) + 1500 < elapsed(previous.anchor))) { clear('clock'); return; }
            latestServer.current = previous ? { ...previous, value: response.serverNow } : { value: response.serverNow, floor: response.serverNow, anchor: capture() };
            if (response.status === 'ready' && !fleetSoftwareVisible(response, elapsed(started))) { clear('expired'); return; }
            const firstIdentity = response.mode === 'fleet' ? response.items[0]?.deviceId : response.items[0]?.rows[0]?.registrationId;
            if (afterIdentity && firstIdentity && firstIdentity <= afterIdentity) { clear('invalid'); return; }
            anchor.current = started; install(response);
        } catch (caught) {
            if (!active()) return;
            if (caught instanceof APIError && caught.status === 401) { locked.current = true; clear('session'); }
            else clear(caught instanceof APIError && caught.status === 403 ? 'unauthorized' : caught instanceof APIError && caught.status === 409 ? 'restart' : caught instanceof APIError && caught.status === 429 ? 'busy' : 'unavailable');
        } finally {
            if (token === revision.current) { window.clearTimeout(pending.current?.timer); pending.current = null; if (alive.current) setLoading(false); }
        }
    }, [cancel, clear, enabled, install, sessionKey, sessionValid]);
    useEffect(() => {
        alive.current = true; locked.current = false; suspended.current = document.visibilityState === 'hidden'; accessEpoch.current = getProtectedRequestEpoch(); latestServer.current = null; clear();
        const lock = () => { locked.current = true; clear('session'); };
        const stop = () => { suspended.current = true; clear(); };
        const restore = () => { if (document.visibilityState !== 'hidden') suspended.current = false; };
        const visibility = () => document.visibilityState === 'hidden' ? stop() : restore();
        const storage = () => { if (hasLogoutIntent()) lock(); };
        for (const event of ['blur', 'pagehide', 'popstate', 'hashchange']) window.addEventListener(event, stop);
        for (const event of ['focus', 'pageshow']) window.addEventListener(event, restore);
        window.addEventListener(AUTH_REQUIRED_EVENT, lock); window.addEventListener('storage', storage); document.addEventListener('visibilitychange', visibility);
        // This clock guard never performs a network read, including on focus.
        const timer = window.setInterval(() => {
            if (!enabled || locked.current) return;
            if (!sessionValid()) { lock(); return; }
            const base = anchor.current ?? pending.current?.started;
            if (base && !Number.isFinite(elapsed(base))) { clear('clock'); return; }
            if (current.current?.status === 'ready' && base && !fleetSoftwareVisible(current.current, elapsed(base))) { clear('expired'); return; }
            if (base) tick(n => n + 1);
        }, 250);
        return () => {
            alive.current = false; clear(); window.clearInterval(timer);
            for (const event of ['blur', 'pagehide', 'popstate', 'hashchange']) window.removeEventListener(event, stop);
            for (const event of ['focus', 'pageshow']) window.removeEventListener(event, restore);
            window.removeEventListener(AUTH_REQUIRED_EVENT, lock); window.removeEventListener('storage', storage); document.removeEventListener('visibilitychange', visibility);
        };
    }, [clear, enabled, key, sessionValid]);
    const change = (field: keyof Controls, value: string) => {
        if (!enabled || locked.current || suspended.current) return;
        clear(null, true); query.current = { ...query.current, [field]: value }; setControls({ key, value: query.current });
    };
    const pinned = (item: FleetSoftwareItem): FleetSoftwareItem => ({ ...item, rows: [], detailCursor: '' });
    const next = () => {
        const page = current.current;
        if (!page?.nextCursor || !page.cursorExpiresAt) return;
        const item = page.items[0];
        void read(page.nextCursor, { mode: page.mode, offset: page.offset + (page.mode === 'fleet' ? page.items.length : item.rows.length), totalDevices: page.totalDevices, deadline: page.cursorExpiresAt, ...(page.mode === 'device' ? { device: pinned(item) } : {}) }, page.mode === 'device' ? item.rows.at(-1)?.registrationId : page.items.at(-1)?.deviceId);
    };
    const detail = (item: FleetSoftwareItem) => {
        const page = current.current;
        if (page?.mode !== 'fleet' || !page.cursorExpiresAt || !page.items.includes(item) || !item.detailCursor) return;
        void read(item.detailCursor, { mode: 'device', offset: 0, totalDevices: page.totalDevices, deadline: page.cursorExpiresAt, device: pinned(item) });
    };
    const admitted = enabled && data.key === key;
    return { page: admitted ? data.page : null, controls: enabled && controls.key === key ? controls.value : initial(), loading: admitted && loading, error: admitted ? error : null, elapsed: admitted && anchor.current ? elapsed(anchor.current) : 0,
        changeName: (value: string) => change('name', value), changeVersion: (value: string) => change('version', value), submit: () => void read(), next, detail,
        clear: () => clear(), back: () => clear(null, true),
    };
}
