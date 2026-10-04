import { useCallback, useEffect, useRef, useState } from 'react';
import { APIError, AUTH_REQUIRED_EVENT, getProtectedRequestEpoch, mutateRaw, request } from './api';
import { SYSTEM_PAGE_BYTES, SYSTEM_STATUS_BYTES, systemPageSize, systemSectionVisible, validSystemSearch, validSystemPage, validSystemView } from './system-inventory-types';
import type { SystemPage, SystemView, SystemSection, SystemFilter } from './system-inventory-types';
import { inventoryAge } from './complete-packages-types';

export type SystemFailure = 'loadError' | 'invalid' | 'timeout' | 'session' | 'clock' | 'busy' | 'restart' | 'searchInvalid';
type Anchor = { mono: number; wall: number };
const capture = (): Anchor => ({ mono: performance.now(), wall: Date.now() });
function elapsed(anchor: Anchor): number {
    const delta = performance.now() - anchor.mono, wall = Date.now() - anchor.wall;
    return Number.isFinite(delta) && delta >= 0 && Number.isFinite(wall) && Math.abs(wall - delta) <= 1500 ? delta : Infinity;
}
type Data = { view: SystemView | null; page: SystemPage | null; scanned: number; matches: number };
const empty = (): Data => ({ view: null, page: null, scanned: 0, matches: 0 });
export function useSystemInventory(deviceId: string, section: SystemSection) {
    const [data, setData] = useState<Data>(empty), [loading, setLoading] = useState(false), [error, setError] = useState<SystemFailure | null>(null), [search, setSearch] = useState(''), [filter, setFilter] = useState<SystemFilter>('all'), [, tick] = useState(0);
    const alive = useRef(false), locked = useRef(false), suspended = useRef(false), epoch = useRef(0), state = useRef<Data>(empty());
    const anchor = useRef<Anchor | null>(null), pageAnchor = useRef<Anchor | null>(null), lastRow = useRef<string | null>(null);
    const filterRef = useRef<SystemFilter>('all'), query = useRef(''), retryCursor = useRef(''), seenCursors = useRef(new Set<string>());
    const latestServerTime = useRef<string | null>(null);
    const pending = useRef<{ controller: AbortController; timeout: number; started: Anchor } | null>(null);
    const install = useCallback((value: Data) => { state.current = value; if (alive.current) setData(value); }, []);
    const cancel = useCallback(() => { epoch.current++; pending.current?.controller.abort(); window.clearTimeout(pending.current?.timeout); pending.current = null; if (alive.current) setLoading(false); }, []);
    const clear = useCallback((failure: SystemFailure | null = null) => {
        cancel(); anchor.current = null; pageAnchor.current = null; lastRow.current = null; seenCursors.current.clear(); install(empty()); if (alive.current) setError(failure);
    }, [cancel, install]);
    const read = useCallback(async (refresh: boolean, cursor = '') => {
        if (!alive.current || locked.current || suspended.current || document.visibilityState === 'hidden') return;
        const currentQuery = query.current;
        if (!validSystemSearch(currentQuery)) { setError('searchInvalid'); return; }
        cancel(); const revision = epoch.current, controller = new AbortController(), started = capture(), protectedEpoch = getProtectedRequestEpoch();
        if (refresh) { anchor.current = null; pageAnchor.current = null; lastRow.current = null; seenCursors.current.clear(); install(empty()); }
        else install({ ...state.current, page: null });
        retryCursor.current = cursor; setLoading(true); setError(null);
        pending.current = { controller, started, timeout: window.setTimeout(() => {
            if (revision === epoch.current) { cancel(); install({ ...state.current, page: null }); setError('timeout'); }
        }, 10000) };
        const active = () => {
            if (!alive.current || locked.current || suspended.current || controller.signal.aborted || revision !== epoch.current || protectedEpoch !== getProtectedRequestEpoch()) return false;
            if (!Number.isFinite(elapsed(started)) || anchor.current && !Number.isFinite(elapsed(anchor.current))) { clear('clock'); return false; }
            if (elapsed(started) >= 10000) { cancel(); install({ ...state.current, page: null }); setError('timeout'); return false; }
            return true;
        };
        try {
            let view = state.current.view;
            if (refresh) {
                const response = await request<unknown>(`/devices/${encodeURIComponent(deviceId)}/inventory/system`, { signal: controller.signal }, SYSTEM_STATUS_BYTES);
                if (!active()) return;
                if (!validSystemView(response, deviceId)) { clear('invalid'); return; }
                if (latestServerTime.current && inventoryAge(response.serverNow, latestServerTime.current) < 0) { clear('clock'); return; }
                latestServerTime.current = response.serverNow;
                view = response; anchor.current = started; install({ ...empty(), view });
            }
            if (!view || !anchor.current || !systemSectionVisible(view, section, elapsed(anchor.current)) || !view.lastComplete[section]) return;
            const selected = view.lastComplete[section]!;
            const response = await mutateRaw<unknown>(`/devices/${encodeURIComponent(deviceId)}/inventory/system/query`, JSON.stringify({ section, generationId: selected.meta.generationId, cursor, search: currentQuery, limit: systemPageSize(section), filter: filterRef.current }), {}, controller.signal, SYSTEM_PAGE_BYTES);
            if (!active()) return;
            if (!validSystemPage(response, deviceId, section, selected, cursor, currentQuery, filterRef.current) || inventoryAge(response.serverNow, view.serverNow) < 0 || !systemSectionVisible(view, section, elapsed(anchor.current))) { clear('invalid'); return; }
            if (latestServerTime.current && inventoryAge(response.serverNow, latestServerTime.current) < 0) { clear('clock'); return; }
            latestServerTime.current = response.serverNow;
            const first = response.services[0]?.name, previous = lastRow.current;
            if (cursor && first && previous && first <= previous || response.nextCursor && seenCursors.current.has(response.nextCursor) || state.current.scanned + response.scannedCount > response.totalRows || response.exhausted && state.current.scanned + response.scannedCount !== response.totalRows) { clear('invalid'); return; }
            if (response.nextCursor) seenCursors.current.add(response.nextCursor);
            if (response.services.length) lastRow.current = response.services[response.services.length - 1].name;
            pageAnchor.current = started;
            install({ view, page: response, scanned: state.current.scanned + response.scannedCount, matches: state.current.matches + response.returnedCount });
        } catch (caught) {
            if (!active()) return;
            if (caught instanceof APIError && caught.status === 401) { locked.current = true; clear('session'); }
            else if (caught instanceof APIError && caught.status === 409) clear('restart');
            else { install({ ...state.current, page: null }); setError(caught instanceof APIError && caught.status === 429 ? 'busy' : 'loadError'); }
        } finally {
            if (revision === epoch.current) { window.clearTimeout(pending.current?.timeout); pending.current = null; if (alive.current) setLoading(false); }
        }
    }, [cancel, clear, deviceId, install, section]);
    const changeSearch = useCallback((value: string) => {
        cancel(); query.current = value; setSearch(value); pageAnchor.current = null; lastRow.current = null; seenCursors.current.clear(); retryCursor.current = '';
        install({ ...state.current, page: null, scanned: 0, matches: 0 }); setError(null);
    }, [cancel, install]);
    const changeFilter = useCallback((value: SystemFilter) => { filterRef.current = value; setFilter(value); changeSearch(query.current); }, [changeSearch]);
    const startSearch = useCallback(() => {
        cancel(); lastRow.current = null; seenCursors.current.clear(); retryCursor.current = ''; install({ ...state.current, page: null, scanned: 0, matches: 0 });
        void read(!state.current.view, '');
    }, [cancel, install, read]);
    useEffect(() => {
        alive.current = true; locked.current = false; suspended.current = document.visibilityState === 'hidden';
        const lock = () => { locked.current = true; clear('session'); query.current = ''; setSearch(''); };
        const suspend = () => { suspended.current = true; clear(); };
        const restore = () => { if (locked.current || document.visibilityState === 'hidden') return; suspended.current = false; void read(true); };
        const visibility = () => document.visibilityState === 'hidden' ? suspend() : restore();
        const show = (event: PageTransitionEvent) => { if (event.persisted || suspended.current) restore(); };
        const navigate = () => { suspended.current = true; clear(); };
        window.addEventListener(AUTH_REQUIRED_EVENT, lock); window.addEventListener('pagehide', suspend); window.addEventListener('pageshow', show); window.addEventListener('blur', suspend); window.addEventListener('focus', restore); window.addEventListener('hashchange', navigate); document.addEventListener('visibilitychange', visibility);
        const timer = window.setInterval(() => {
            const current = anchor.current ?? pending.current?.started;
            if (current && !Number.isFinite(elapsed(current))) { clear('clock'); return; }
            const page = state.current.page;
            if (page && anchor.current && (!systemSectionVisible(state.current.view!, section, elapsed(anchor.current)) || pageAnchor.current && page.cursorExpiresAt && inventoryAge(page.cursorExpiresAt, page.serverNow) <= elapsed(pageAnchor.current))) {
                cancel(); pageAnchor.current = null; install({ ...state.current, page: null }); setError('restart');
            }
            if (current) tick(n => n + 1);
        }, 1000);
        void read(true);
        return () => { alive.current = false; clear(); window.clearInterval(timer); window.removeEventListener(AUTH_REQUIRED_EVENT, lock); window.removeEventListener('pagehide', suspend); window.removeEventListener('pageshow', show); window.removeEventListener('blur', suspend); window.removeEventListener('focus', restore); window.removeEventListener('hashchange', navigate); document.removeEventListener('visibilitychange', visibility); };
    }, [cancel, clear, install, read, section]);
    return { ...data, loading, error, search, filter, changeSearch, changeFilter, startSearch, refresh: () => void read(true), next: () => { if (state.current.page?.nextCursor) void read(false, state.current.page.nextCursor); }, retry: () => void read(!state.current.view, retryCursor.current), elapsed: anchor.current ? elapsed(anchor.current) : Infinity };
}
