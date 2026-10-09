import { useEffect, useRef, useState } from 'react';
import { APIError, AUTH_REQUIRED_EVENT, getProtectedRequestEpoch, mutateRaw, request } from './api';
import { hasLogoutIntent, LOGOUT_INTENT_KEY } from './auth';
import { JOURNAL_AI_SETTINGS_BYTES } from './journal-ai-types';
/** A bounded review lifetime, independent of provider/source freshness. Never retries a write. */
export function useJournalAIReview(clear: () => void) {
    const reset = useRef(clear); reset.current = clear;
    const [busy, setBusy] = useState(false), [error, setError] = useState(''), [locked, setLocked] = useState(false);
    const commands = useRef({ run: async <T,>(_work: (read: <V>(path: string, max?: number) => Promise<V>, write: <V>(path: string, body: unknown, max?: number) => Promise<V>) => Promise<T>, _write = false): Promise<T | undefined> => undefined, fresh: (): boolean => false, invalidate: () => {} });
    useEffect(() => {
        let alive = true, ended = false, suspended = document.visibilityState === 'hidden', generation = 0;
        let pending: { controller: AbortController; timer: number; write: boolean } | null = null;
        let reviewed: { wall: number; mono: number } | null = null;
        const epoch = getProtectedRequestEpoch();
        const authorized = () => alive && !ended && !hasLogoutIntent() && epoch === getProtectedRequestEpoch();
        const fresh = () => !!reviewed && performance.now() - reviewed.mono >= 0 && performance.now() - reviewed.mono < 60000 && Math.abs(Date.now() - reviewed.wall - (performance.now() - reviewed.mono)) <= 1500;
        const invalidate = (message: string) => { generation++; pending?.controller.abort(); window.clearTimeout(pending?.timer); pending = null; reviewed = null; reset.current(); setBusy(false); setError(message); };
        const lock = () => { ended = true; invalidate('session'); setLocked(true); };
        commands.current = { fresh, invalidate: () => invalidate(pending?.write ? 'uncertain' : 'refresh'), run: async (work, write = false) => {
            if (!authorized()) { lock(); return; }
            if (pending || suspended || document.visibilityState === 'hidden') return;
            if (write && !fresh()) { invalidate('refresh'); return; }
            const own = ++generation, started = { wall: Date.now(), mono: performance.now() }, controller = new AbortController();
            const active = () => authorized() && generation === own && !controller.signal.aborted;
            pending = { controller, write, timer: window.setTimeout(() => invalidate(write ? 'uncertain' : 'timeout'), 10000) };
            setBusy(true); setError('');
            try {
                const value = await work(<V,>(path: string, max = JOURNAL_AI_SETTINGS_BYTES) => request<V>(path, { signal: controller.signal, cache: 'no-store' }, max), <V,>(path: string, body: unknown, max = JOURNAL_AI_SETTINGS_BYTES) => mutateRaw<V>(path, JSON.stringify(body), {}, controller.signal, max));
                if (!active()) return;
                const elapsed = performance.now() - started.mono;
                if (elapsed < 0 || elapsed >= 10000 || Math.abs(Date.now() - started.wall - elapsed) > 1500) { invalidate(write ? 'uncertain' : 'refresh'); return; }
                reviewed = started; return value;
            } catch (e) {
                if (!active()) return;
                if (e instanceof APIError && [401, 403].includes(e.status ?? 0)) lock();
                else invalidate(write ? e instanceof APIError && e.status === 409 ? 'conflict' : 'uncertain' : 'unavailable');
            } finally { if (pending?.controller === controller) { window.clearTimeout(pending.timer); pending = null; setBusy(false); } }
        } };
        const hide = () => { suspended = true; invalidate(pending?.write ? 'uncertain' : 'refresh'); };
        const resume = () => { if (authorized() && document.visibilityState !== 'hidden') suspended = false; };
        const changed = () => invalidate(pending?.write ? 'uncertain' : 'refresh');
        const visibility = () => document.visibilityState === 'hidden' ? hide() : resume();
        const storage = (e: StorageEvent) => { if ((e.key === null || e.key === LOGOUT_INTENT_KEY) && hasLogoutIntent()) lock(); };
        window.addEventListener(AUTH_REQUIRED_EVENT, lock); window.addEventListener('tracebolt-ai-config-changed', changed); window.addEventListener('pagehide', hide); window.addEventListener('blur', hide); window.addEventListener('pageshow', resume); window.addEventListener('focus', resume); window.addEventListener('hashchange', changed); window.addEventListener('popstate', changed); window.addEventListener('storage', storage); document.addEventListener('visibilitychange', visibility);
        const timer = window.setInterval(() => { if (!authorized()) lock(); else if (reviewed && !fresh()) invalidate(pending?.write ? 'uncertain' : 'refresh'); }, 1000);
        return () => { alive = false; generation++; pending?.controller.abort(); window.clearTimeout(pending?.timer); window.clearInterval(timer); window.removeEventListener(AUTH_REQUIRED_EVENT, lock); window.removeEventListener('tracebolt-ai-config-changed', changed); window.removeEventListener('pagehide', hide); window.removeEventListener('blur', hide); window.removeEventListener('pageshow', resume); window.removeEventListener('focus', resume); window.removeEventListener('hashchange', changed); window.removeEventListener('popstate', changed); window.removeEventListener('storage', storage); document.removeEventListener('visibilitychange', visibility); };
    }, []);
    return { busy, error, locked, run: <T,>(work: (read: <V>(path: string, max?: number) => Promise<V>, write: <V>(path: string, body: unknown, max?: number) => Promise<V>) => Promise<T>, write = false) => commands.current.run(work, write), fresh: () => commands.current.fresh(), invalidate: () => commands.current.invalidate() };
}
