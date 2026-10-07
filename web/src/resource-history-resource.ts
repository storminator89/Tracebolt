import { useEffect, useRef, useState } from 'react';
import { APIError, AUTH_REQUIRED_EVENT, getProtectedRequestEpoch, hasPendingAPIRequests, request } from './api';
import { hasLogoutIntent } from './auth';
import { mergeResourceHistoryReply, type ResourceHistory } from './resource-history-types';

type Snapshot = { scope: string; epoch: number; view: ResourceHistory; wall: number; mono: number };
export function useResourceHistory(id: string, sessionKey: string | null, enabled: boolean) {
    const scope = `${id}:${sessionKey ?? ''}`, [snapshot, setSnapshot] = useState<Snapshot | null>(null), [loading, setLoading] = useState(false), [error, setError] = useState<'unavailable' | 'invalid' | 'session' | ''>('');
    const retry = useRef<() => void>(() => {});
    useEffect(() => {
        let alive = true, stopped = false, suspended = document.visibilityState === 'hidden', timer: number | undefined, deadline: number | undefined, controller: AbortController | null = null;
        let current: Snapshot | null = null, failures = 0;
        const epoch = getProtectedRequestEpoch();
        const clearTimer = () => { window.clearTimeout(timer); timer = undefined; };
        const cancel = () => { controller?.abort(); controller = null; window.clearTimeout(deadline); setLoading(false); };
        const clear = () => { current = null; setSnapshot(null); };
        const lock = () => { stopped = true; clearTimer(); cancel(); clear(); setError('session'); };
        const active = () => alive && enabled && !stopped && !suspended && document.visibilityState !== 'hidden';
        const schedule = (delay = Math.min(120000, 60000 * 2 ** failures)) => { clearTimer(); if (active()) timer = window.setTimeout(() => { void read(); }, delay); };
        const authorized = () => { if (epoch !== getProtectedRequestEpoch() || hasLogoutIntent()) { lock(); return false; } return true; };
        const read = async () => {
            if (!active() || controller || !authorized()) return;
            if (hasPendingAPIRequests()) { schedule(500); return; }
            clearTimer(); const requestController = new AbortController(); controller = requestController;
            const baseline = current?.view, after = baseline?.points.at(-1)?.sequence;
            const started = performance.now(); setLoading(true);
            const valid = () => active() && controller === requestController && !requestController.signal.aborted && authorized();
            deadline = window.setTimeout(() => { if (valid()) { cancel(); clear(); setError('unavailable'); failures = Math.min(2, failures + 1); schedule(); } }, 10000);
            try {
                const reply = await request<unknown>(`/devices/${encodeURIComponent(id)}/resource-history${after ? `?afterSequence=${after}` : ''}`, { signal: requestController.signal }, 1536 * 1024);
                if (!valid()) return;
                if (performance.now() - started >= 10000) throw new Error('timeout');
                const value = mergeResourceHistoryReply(reply, id, baseline, after);
                if (!value) { clear(); setError('invalid'); stopped = true; return; }
                if (current) {
                    const elapsed = performance.now() - current.mono, wall = Date.now() - current.wall;
                    // Never let a frozen/rolled-back manager or local clock renew
                    // the visibility of expired retained samples.
                    if (elapsed < 0 || Math.abs(wall - elapsed) > 1500 || Date.parse(value.serverNow) + 1500 < Date.parse(current.view.serverNow) + elapsed) { clear(); setError('invalid'); stopped = true; return; }
                }
                current = { scope, epoch, view: value, wall: Date.now(), mono: performance.now() }; setSnapshot(current); failures = 0; setError('');
                if (['revoked', 'expired', 'not_configured'].includes(value.status)) stopped = true;
            } catch (caught) {
                if (!valid()) return;
                clear();
                if (caught instanceof APIError && caught.status === 401) { lock(); return; }
                if (caught instanceof APIError && [400, 403, 404, 409, 410].includes(caught.status ?? 0)) stopped = true;
                failures = Math.min(2, failures + 1); setError('unavailable');
            } finally {
                if (alive && controller === requestController) { window.clearTimeout(deadline); controller = null; setLoading(false); schedule(); }
            }
        };
        const suspend = () => { suspended = true; clearTimer(); cancel(); clear(); };
        const resume = () => { if (!alive || stopped || document.visibilityState === 'hidden') return; suspended = false; schedule(0); };
        const visibility = () => document.visibilityState === 'hidden' ? suspend() : resume();
        setSnapshot(null); setError(''); setLoading(enabled);
        retry.current = () => { if (!alive || error === 'session') return; stopped = false; schedule(0); };
        window.addEventListener(AUTH_REQUIRED_EVENT, lock); window.addEventListener('blur', suspend); window.addEventListener('focus', resume); window.addEventListener('pagehide', suspend); window.addEventListener('pageshow', resume); document.addEventListener('visibilitychange', visibility);
        // Strip expired points between reads without inventing new timestamps.
        const age = window.setInterval(() => {
            if (!alive || !enabled || !authorized() || !current) return;
            const elapsed = performance.now() - current.mono, wall = Date.now() - current.wall;
            if (elapsed < 0 || Math.abs(wall - elapsed) > 1500) { clear(); setError('invalid'); stopped = true; clearTimer(); return; }
            const cutoff = Date.parse(current.view.windowStart) + elapsed;
            if (current.view.points.some(point => Date.parse(point.collectedAt) < cutoff)) {
                const points = current.view.points.filter(point => Date.parse(point.collectedAt) >= cutoff);
                current = { ...current, view: { ...current.view, points, status: current.view.status === 'available' && !points.length ? 'awaiting' : current.view.status } };
                setSnapshot(current);
            }
        }, 1000);
        void read();
        return () => { alive = false; clearTimer(); controller?.abort(); window.clearTimeout(deadline); window.clearInterval(age); retry.current = () => {}; window.removeEventListener(AUTH_REQUIRED_EVENT, lock); window.removeEventListener('blur', suspend); window.removeEventListener('focus', resume); window.removeEventListener('pagehide', suspend); window.removeEventListener('pageshow', resume); document.removeEventListener('visibilitychange', visibility); };
    // Session scope, rather than each new device metric, owns this single reader.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [id, sessionKey, enabled, scope]);
    const view = enabled && snapshot?.scope === scope && snapshot.epoch === getProtectedRequestEpoch() && !hasLogoutIntent() ? snapshot.view : null;
    return { view, loading, error, retry: () => retry.current() };
}
