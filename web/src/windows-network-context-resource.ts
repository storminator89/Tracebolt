import { useCallback, useEffect, useRef, useState } from 'react';
import { APIError, AUTH_REQUIRED_EVENT, getProtectedRequestEpoch, mutateRaw } from './api';
import { inventoryAge } from './complete-packages-types';
import { NETWORK_CONTEXT_PAGE_BYTES, NETWORK_CONTEXT_PAGE_ROWS, networkContextVisible, sameNetworkContextComplete, validNetworkContextPage, validNetworkContextSearch, validNetworkContextSort, validNetworkContextKind } from './windows-network-context-types';
import type { NetworkContextComplete, NetworkContextPage, NetworkContextQuery, NetworkContextSort, NetworkContextKind } from './windows-network-context-types';
import { validWindowsDeviceId } from './windows-inventory-types';

type Failure = 'invalid' | 'unavailable' | 'timeout' | 'session' | 'clock' | 'busy' | 'restart' | 'unauthorized' | 'expired' | 'searchInvalid';
type Anchor = { mono: number; wall: number };
const capture = (): Anchor => ({ mono: performance.now(), wall: Date.now() });
function elapsed(anchor: Anchor): number {
    const mono = performance.now() - anchor.mono, wall = Date.now() - anchor.wall;
    return Number.isFinite(mono) && mono >= 0 && Number.isFinite(wall) && Math.abs(wall - mono) <= 1500 ? mono : Infinity;
}
type Controls = { kind: NetworkContextKind; search: string; sort: NetworkContextSort };
const initial = (kind: NetworkContextKind): Controls => ({ kind, search: '', sort: 'source-asc' });
type Data = { view: NetworkContextPage | null; page: NetworkContextPage | null };
const empty = (): Data => ({ view: null, page: null });
type Position = { cursor: string; offset: number };
/** No persistent browser storage and no collector/grant action. Every page is a
 * fresh protected read. Only the current <=100 rows are held, never accumulated.
 * No background query reruns a full-generation search/sort. */
export function useWindowsNetworkContext(deviceId: string, enabled: boolean, sessionKey: string | null, kind: NetworkContextKind = 'route') {
    const key = `${deviceId}:${kind}:${enabled}:${sessionKey ?? ''}`;
    const [data, setData] = useState<Data & { key: string }>({ ...empty(), key }), [controls, setControls] = useState<Controls>(() => initial(kind)), [loading, setLoading] = useState(false), [error, setError] = useState<Failure | null>(null);
    const alive = useRef(false), locked = useRef(false), suspended = useRef(false), epoch = useRef(0), state = useRef<Data>(empty()), query = useRef<Controls>(initial(kind));
    const selected = useRef<NetworkContextComplete | null>(null), anchor = useRef<Anchor | null>(null), latestServer = useRef<{ value: string; floor: string; anchor: Anchor } | null>(null);
    const positions = useRef<Position[]>([{ cursor: '', offset: 0 }]), index = useRef(0), totalMatches = useRef<number | null>(null), cursorDeadline = useRef<string | null>(null), originalDeadline = useRef<string | null>(null);
    const pending = useRef<{ controller: AbortController; timeout: number; started: Anchor } | null>(null);
    const install = useCallback((value: Data) => { state.current = value; if (alive.current) setData({ ...value, key }); }, [key]);
    const cancel = useCallback(() => { epoch.current++; pending.current?.controller.abort(); window.clearTimeout(pending.current?.timeout); pending.current = null; if (alive.current) setLoading(false); }, []);
    const resetPaging = useCallback(() => { positions.current = [{ cursor: '', offset: 0 }]; index.current = 0; totalMatches.current = null; cursorDeadline.current = null; originalDeadline.current = null; }, []);
    const resetControls = useCallback(() => { query.current = initial(kind); if (alive.current) setControls(initial(kind)); resetPaging(); }, [resetPaging, kind]);
    const clear = useCallback((failure: Failure | null = null) => { cancel(); anchor.current = null; selected.current = null; resetControls(); install(empty()); if (alive.current) setError(failure); }, [cancel, install, resetControls]);
    const read = useCallback(async (position: Position = positions.current[index.current], targetIndex = index.current) => {
        if (!enabled || !alive.current || locked.current || suspended.current || document.visibilityState === 'hidden') return;
        if (!validWindowsDeviceId(deviceId)) { clear('invalid'); return; }
        if (!validNetworkContextKind(query.current.kind) || !validNetworkContextSearch(query.current.search) || !validNetworkContextSort(query.current.sort)) { setError('searchInvalid'); return; }
        const previous = selected.current;
        const input: NetworkContextQuery = { ...query.current, limit: NETWORK_CONTEXT_PAGE_ROWS, cursor: position.cursor };
        cancel(); install(empty()); anchor.current = null; setError(null); setLoading(true);
        const revision = epoch.current, controller = new AbortController(), started = capture(), accessEpoch = getProtectedRequestEpoch();
        pending.current = { controller, started, timeout: window.setTimeout(() => { if (revision === epoch.current) clear('timeout'); }, 10000) };
        const active = () => {
            if (!alive.current || locked.current || suspended.current || controller.signal.aborted || revision !== epoch.current) return false;
            if (accessEpoch !== getProtectedRequestEpoch()) { locked.current = true; clear('session'); return false; }
            if (!Number.isFinite(elapsed(started))) { clear('clock'); return false; }
            if (elapsed(started) >= 10000) { clear('timeout'); return false; }
            return true;
        };
        try {
            const response: unknown = await mutateRaw(`/devices/${encodeURIComponent(deviceId)}/windows-network-context/query`, JSON.stringify(input), {}, controller.signal, NETWORK_CONTEXT_PAGE_BYTES);
            if (!active()) return;
            if (!validNetworkContextPage(response, deviceId, input, position.offset)) { clear('invalid'); return; }
            const clock = latestServer.current;
            if (clock && (inventoryAge(response.serverNow, clock.value) < 0 || inventoryAge(response.serverNow, clock.floor) + 1500 < elapsed(clock.anchor))) { clear('clock'); return; }
            latestServer.current = clock ? { ...clock, value: response.serverNow } : { value: response.serverNow, floor: response.serverNow, anchor: capture() };
            if (response.status !== 'ready' || !response.complete) {
                selected.current = null; resetControls(); anchor.current = started; install({ view: response, page: null }); return;
            }
            if (previous && !sameNetworkContextComplete(previous, response.complete)) {
                const sameGrant = previous.manifest.grantId === response.complete.manifest.grantId && previous.manifest.grantRevision === response.complete.manifest.grantRevision;
                clear(sameGrant && (previous.manifest.generationId === response.complete.manifest.generationId || previous.manifest.sequence >= response.complete.manifest.sequence) ? 'invalid' : 'restart'); return;
            }
            if (totalMatches.current !== null && response.matchingCount !== totalMatches.current || input.cursor && cursorDeadline.current !== response.cursorExpiresAt) { clear('invalid'); return; }
            // Re-reading page one cannot renew the browser's original paging deadline.
            if (originalDeadline.current && inventoryAge(originalDeadline.current, response.serverNow) <= elapsed(started)) { clear('restart'); return; }
            if (!networkContextVisible(response, elapsed(started))) { clear('expired'); return; }
            if (response.nextCursor && positions.current.some((item, i) => item.cursor === response.nextCursor && i !== targetIndex + 1)) { clear('invalid'); return; }
            if (input.cursor === '') { positions.current = [position]; originalDeadline.current ??= response.cursorExpiresAt; }
            if (response.nextCursor) positions.current[targetIndex + 1] = { cursor: response.nextCursor, offset: response.offset + response.rows.length };
            else positions.current.length = targetIndex + 1;
            index.current = targetIndex; totalMatches.current = response.matchingCount; cursorDeadline.current = response.cursorExpiresAt;
            selected.current = response.complete; anchor.current = started;
            const effective = { ...response, cursorExpiresAt: originalDeadline.current && inventoryAge(originalDeadline.current, response.cursorExpiresAt!) < 0 ? originalDeadline.current : response.cursorExpiresAt };
            install({ view: { ...effective, rows: [], nextCursor: '' }, page: effective });
        } catch (caught) {
            if (!active()) return;
            if (caught instanceof APIError && caught.status === 401) { locked.current = true; clear('session'); }
            else clear(caught instanceof APIError && caught.status === 403 ? 'unauthorized' : caught instanceof APIError && caught.status === 409 ? 'restart' : caught instanceof APIError && caught.status === 429 ? 'busy' : 'unavailable');
        } finally {
            if (revision === epoch.current) { window.clearTimeout(pending.current?.timeout); pending.current = null; if (alive.current) setLoading(false); }
        }
    }, [cancel, clear, deviceId, enabled, install, resetControls]);
    const change = useCallback((value: Controls) => { cancel(); query.current = value; setControls(value); resetPaging(); install({ ...state.current, page: null }); setError(null); }, [cancel, install, resetPaging]);
    useEffect(() => {
        alive.current = true; locked.current = false; suspended.current = document.visibilityState === 'hidden'; latestServer.current = null; clear();
        if (!enabled) return () => { alive.current = false; clear(); };
        const accessEpoch = getProtectedRequestEpoch();
        const lock = () => { locked.current = true; clear('session'); };
        const suspend = () => { suspended.current = true; clear(); };
        const restore = () => { if (locked.current || !suspended.current || document.visibilityState === 'hidden') return; suspended.current = false; void read(); };
        const visibility = () => document.visibilityState === 'hidden' ? suspend() : restore();
        window.addEventListener(AUTH_REQUIRED_EVENT, lock); window.addEventListener('pagehide', suspend); window.addEventListener('pageshow', restore); window.addEventListener('blur', suspend); window.addEventListener('focus', restore); window.addEventListener('hashchange', suspend); document.addEventListener('visibilitychange', visibility);
        const timer = window.setInterval(() => {
            if (getProtectedRequestEpoch() !== accessEpoch) { if (!locked.current) lock(); return; }
            const base = anchor.current ?? pending.current?.started;
            if (base && !Number.isFinite(elapsed(base))) { clear('clock'); return; }
            const view = state.current.view;
            if (view?.status === 'ready' && base && !networkContextVisible(view, elapsed(base))) { clear('expired'); return; }
            if (view && base && originalDeadline.current && inventoryAge(originalDeadline.current, view.serverNow) <= elapsed(base)) clear('restart');
        }, 250);
        void read();
        return () => { alive.current = false; clear(); window.clearInterval(timer); window.removeEventListener(AUTH_REQUIRED_EVENT, lock); window.removeEventListener('pagehide', suspend); window.removeEventListener('pageshow', restore); window.removeEventListener('blur', suspend); window.removeEventListener('focus', restore); window.removeEventListener('hashchange', suspend); document.removeEventListener('visibilitychange', visibility); };
    }, [clear, enabled, key, read]);
    const admitted = enabled && data.key === key;
    return { ...(admitted ? data : empty()), controls: admitted ? controls : initial(kind), loading: enabled && loading, error: admitted ? error : null,
        changeSearch: (search: string) => change({ ...query.current, search }), changeSort: (sort: NetworkContextSort) => change({ ...query.current, sort }),
        apply: () => void read(), refresh: () => void read(), restart: () => { clear(); void read(); },
        previous: () => { if (index.current > 0) void read(positions.current[index.current - 1], index.current - 1); },
        next: () => { if (state.current.page?.nextCursor && positions.current[index.current + 1]) void read(positions.current[index.current + 1], index.current + 1); },
    };
}
