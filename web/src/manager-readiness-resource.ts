import { useEffect, useRef, useState } from 'react';
import { abortProtectedRequests, AUTH_REQUIRED_EVENT, getProtectedRequestEpoch } from './api';
import { hasLogoutIntent } from './auth';
import { inventoryAge } from './complete-packages-types';
import { validWindowsCapacityTimestamp } from './windows-capacity-types';
import { acceptWindowsHealthClock, windowsHealthElapsed } from './windows-health-clock';
import { validManagerReadinessView } from './manager-readiness-model';
import type { ManagerReadinessView } from './manager-readiness-model';

const RESPONSE_BYTES = 32768;
type Anchor = { mono: number; wall: number };
const capture = (): Anchor => ({ mono: performance.now(), wall: Date.now() });
function elapsed(anchor: Anchor): number {
    const mono = performance.now() - anchor.mono, wall = Date.now() - anchor.wall;
    return Number.isFinite(mono) && mono >= 0 && Number.isFinite(wall) && Math.abs(wall - mono) <= 1500 ? mono : Infinity;
}

/** This endpoint deliberately returns its unavailable evidence with HTTP 503.
 * Keep that bounded body without changing the common API client's error rules.
 * No caller-controlled path, redirects, error prose or external destination. */
export async function readManagerReadiness(signal: AbortSignal): Promise<ManagerReadinessView> {
    const epoch = getProtectedRequestEpoch();
    const active = () => {
        if (signal.aborted || epoch !== getProtectedRequestEpoch() || hasLogoutIntent()) throw new Error('Inactive manager read');
    };
    active();
    const response = await fetch('/api/manager/readiness', { method: 'GET', credentials: 'same-origin', cache: 'no-store', redirect: 'error', headers: { Accept: 'application/json' }, signal });
    active();
    if (response.status === 401) {
        abortProtectedRequests();
        window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT));
    }
    active();
    const length = response.headers.get('Content-Length');
    if (![200, 503].includes(response.status) || !/^application\/json(?:\s*;|$)/i.test(response.headers.get('Content-Type') ?? '') || length !== null && (!/^\d+$/.test(length) || Number(length) > RESPONSE_BYTES) || !response.body) {
        await response.body?.cancel();
        throw new Error('Manager evidence unavailable');
    }
    const reader = response.body.getReader(), chunks: Uint8Array[] = [];
    let count = 0;
    try {
        for (;;) {
            active();
            const chunk = await reader.read();
            active();
            if (chunk.done) break;
            count += chunk.value.byteLength;
            if (count > RESPONSE_BYTES) throw new Error('Manager response too large');
            chunks.push(chunk.value);
        }
    } catch (error) {
        await reader.cancel().catch(() => {});
        throw error;
    } finally { reader.releaseLock(); }
    active();
    const bytes = new Uint8Array(count);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    const value: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    if (!validManagerReadinessView(value, response.status)) throw new Error('Invalid manager evidence');
    active();
    return value;
}

type Snapshot = { key: string; epoch: number; started: Anchor; view: ManagerReadinessView };
export type ManagerReadinessNotice = 'failed' | 'access' | 'paused' | 'expired' | null;

/** Expanded-panel reads only. No polling, storage, grants or recovery action.
 * Retained evidence ends on access, visibility, navigation or session loss. */
export function useManagerReadiness(enabled: boolean, sessionKey: string | null) {
    const [snapshot, setSnapshot] = useState<Snapshot | null>(null), [loading, setLoading] = useState(false), [notice, setNotice] = useState<ManagerReadinessNotice>(null), [, tick] = useState(0);
    const key = JSON.stringify([enabled, sessionKey]), clockKey = `manager-readiness:${sessionKey}`;
    const live = useRef(key); live.current = key;
    const commands = useRef({ refresh: () => {} });
    useEffect(() => {
        let alive = true, locked = false, suspended = document.visibilityState === 'hidden', reading = false, operation = 0;
        let accepted: Snapshot | null = null, controller: AbortController | null = null;
        const epoch = getProtectedRequestEpoch();
        const abort = () => { operation++; controller?.abort(); controller = null; reading = false; };
        const clear = (reason: ManagerReadinessNotice) => {
            abort(); accepted = null;
            if (alive) { setSnapshot(null); setLoading(false); setNotice(reason); }
        };
        const active = () => alive && enabled && live.current === key && !locked && !suspended && document.visibilityState !== 'hidden' && !hasLogoutIntent() && epoch === getProtectedRequestEpoch() && validWindowsCapacityTimestamp(sessionKey);
        const usable = () => {
            if (!active() || !accepted) return false;
            const age = windowsHealthElapsed(clockKey, epoch, accepted.view.serverNow, elapsed(accepted.started));
            return age < 120000 && inventoryAge(sessionKey!, accepted.view.serverNow) > age;
        };
        const read = async () => {
            if (!active() || reading) return;
            clear(null); reading = true; setLoading(true);
            const run = operation, started = capture(), pending = new AbortController(); controller = pending;
            let timer = 0;
            try {
                const timeout = new Promise<never>((_, reject) => { timer = window.setTimeout(() => { pending.abort(); reject(new Error('Manager read timed out')); }, 10000); });
                const view = await Promise.race([readManagerReadiness(pending.signal), timeout]);
                if (!active() || run !== operation || pending.signal.aborted || elapsed(started) >= 10000) return;
                if (!acceptWindowsHealthClock(clockKey, epoch, view.serverNow, elapsed(started))) throw new Error('Manager clock changed');
                accepted = { key, epoch, started, view };
                if (!usable()) throw new Error('Expired manager evidence');
                setSnapshot(accepted); setNotice(null);
            } catch {
                if (alive && run === operation && live.current === key) clear(active() ? 'failed' : 'access');
            } finally {
                window.clearTimeout(timer);
                if (alive && run === operation && live.current === key) { reading = false; controller = null; setLoading(false); }
            }
        };
        const lock = () => { locked = true; clear('access'); };
        const suspend = () => { suspended = true; clear('paused'); };
        const restore = () => { if (!locked && document.visibilityState !== 'hidden') { suspended = false; if (alive) tick(value => value + 1); } };
        const visibility = () => document.visibilityState === 'hidden' ? suspend() : restore();
        commands.current = { refresh: () => { void read(); } };
        clear(null);
        if (!enabled) return () => { alive = false; abort(); commands.current = { refresh: () => {} }; };
        window.addEventListener(AUTH_REQUIRED_EVENT, lock); window.addEventListener('blur', suspend); window.addEventListener('pagehide', suspend); window.addEventListener('pageshow', restore); window.addEventListener('focus', restore); window.addEventListener('hashchange', lock); window.addEventListener('popstate', lock); document.addEventListener('visibilitychange', visibility);
        const timer = window.setInterval(() => {
            if (epoch !== getProtectedRequestEpoch() || hasLogoutIntent()) { if (!locked) lock(); }
            else if (accepted && !usable()) clear('expired');
            else if (accepted) tick(value => value + 1);
        }, 250);
        void read();
        return () => {
            alive = false; abort(); accepted = null; commands.current = { refresh: () => {} }; window.clearInterval(timer);
            window.removeEventListener(AUTH_REQUIRED_EVENT, lock); window.removeEventListener('blur', suspend); window.removeEventListener('pagehide', suspend); window.removeEventListener('pageshow', restore); window.removeEventListener('focus', restore); window.removeEventListener('hashchange', lock); window.removeEventListener('popstate', lock); document.removeEventListener('visibilitychange', visibility);
        };
    }, [enabled, key, clockKey, sessionKey]);
    const age = snapshot ? windowsHealthElapsed(clockKey, snapshot.epoch, snapshot.view.serverNow, elapsed(snapshot.started)) : Infinity;
    const available = enabled && snapshot?.key === key && snapshot.epoch === getProtectedRequestEpoch() && !hasLogoutIntent() && document.visibilityState !== 'hidden' && age < 120000 && validWindowsCapacityTimestamp(sessionKey) && inventoryAge(sessionKey, snapshot.view.serverNow) > age;
    return { view: available ? snapshot.view : null, age, loading, notice, refresh: () => commands.current.refresh() };
}
