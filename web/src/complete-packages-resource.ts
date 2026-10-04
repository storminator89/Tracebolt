import { useCallback, useEffect, useRef, useState } from 'react';
import { APIError, AUTH_REQUIRED_EVENT, getProtectedRequestEpoch, mutateRaw, request } from './api';
import { COMPLETE_PAGE_BYTES, COMPLETE_PAGE_ROWS, COMPLETE_STATUS_BYTES, completeGenerationVisible, inventoryAge, validCompletePackagePage, validCompletePackageView } from './complete-packages-types';
import type { CompletePackagePage, CompletePackageView } from './complete-packages-types';
import type { PackageRow } from './package-observations-types';

export type CompleteFailure = 'loadError' | 'invalid' | 'timeout' | 'session' | 'clock' | 'busy' | 'restart' | 'searchInvalid';
type Anchor = { mono: number; wall: number };
const capture = (): Anchor => ({ mono: performance.now(), wall: Date.now() });
function elapsed(anchor: Anchor): number {
    const delta = performance.now() - anchor.mono, wall = Date.now() - anchor.wall;
    return Number.isFinite(delta) && delta >= 0 && Number.isFinite(wall) && Math.abs(wall - delta) <= 1500 ? delta : Infinity;
}
type Data = { view: CompletePackageView | null; page: CompletePackagePage | null; scanned: number; matches: number };
const empty = (): Data => ({ view: null, page: null, scanned: 0, matches: 0 });
export function useCompletePackages(deviceId: string, metadataOnly = false) {
    const [data, setData] = useState<Data>(empty), [loading, setLoading] = useState(false), [recovering, setRecovering] = useState(false), [error, setError] = useState<CompleteFailure | null>(null), [search, setSearch] = useState(''), [, tick] = useState(0);
    const alive = useRef(false), locked = useRef(false), suspended = useRef(false), epoch = useRef(0), state = useRef<Data>(empty());
    const anchor = useRef<Anchor | null>(null), pageAnchor = useRef<Anchor | null>(null), lastRow = useRef<PackageRow | null>(null);
    const query = useRef(''), retryCursor = useRef(''), seenCursors = useRef(new Set<string>());
    const latestServerTime = useRef<string | null>(null);
    const pending = useRef<{ controller: AbortController; timeout: number; started: Anchor } | null>(null);
    const install = useCallback((value: Data) => { state.current = value; if (alive.current) setData(value); }, []);
    const cancel = useCallback(() => { epoch.current++; pending.current?.controller.abort(); window.clearTimeout(pending.current?.timeout); pending.current = null; if (alive.current) { setLoading(false); setRecovering(false); } }, []);
    const clear = useCallback((failure: CompleteFailure | null = null) => {
        cancel(); anchor.current = null; pageAnchor.current = null; lastRow.current = null; seenCursors.current.clear(); install(empty()); if (alive.current) setError(failure);
    }, [cancel, install]);
    const read = useCallback(async (refresh: boolean, cursor = '') => {
        if (!alive.current || locked.current || suspended.current || document.visibilityState === 'hidden') return;
        const currentQuery = query.current;
        if (new TextEncoder().encode(currentQuery).byteLength > 128 || /[^\x20-\x7e]/.test(currentQuery)) { setError('searchInvalid'); return; }
        cancel(); const revision = epoch.current, controller = new AbortController(), started = capture(), protectedEpoch = getProtectedRequestEpoch();
        if (refresh) { anchor.current = null; pageAnchor.current = null; lastRow.current = null; seenCursors.current.clear(); install(empty()); }
        else install({ ...state.current, page: null });
        retryCursor.current = cursor; setLoading(true); setError(null);
        pending.current = { controller, started, timeout: window.setTimeout(() => {
            if (revision === epoch.current) { cancel(); install({ ...state.current, page: null }); setError('timeout'); }
        }, 10000) };
        const active = () => {
            if (!alive.current || locked.current || suspended.current || controller.signal.aborted || revision !== epoch.current) return false;
            if (protectedEpoch !== getProtectedRequestEpoch()) { locked.current = true; clear('session'); return false; }
            if (!Number.isFinite(elapsed(started)) || anchor.current && !Number.isFinite(elapsed(anchor.current))) { clear('clock'); return false; }
            if (elapsed(started) >= 10000) { cancel(); install({ ...state.current, page: null }); setError('timeout'); return false; }
            return true;
        };
        try {
            let view = state.current.view;
            if (refresh) {
                let response: unknown;
                // Retry only the software summary GET once; full package paging is unchanged. Keep the original controller,
                // access epoch, capture anchor and total ten-second deadline.
                for (let attempt = 0; attempt < 2; attempt++) {
                    try {
                        response = await request<unknown>(`/devices/${encodeURIComponent(deviceId)}/inventory/packages`, { signal: controller.signal }, COMPLETE_STATUS_BYTES);
                        break;
                    } catch (caught) {
                        if (!active()) return;
                        if (!metadataOnly || attempt !== 0 || !(caught instanceof APIError) || caught.status !== 429 || caught.code !== 'storage_busy') throw caught;
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
                if (!validCompletePackageView(response, deviceId)) { clear('invalid'); return; }
                if (latestServerTime.current && inventoryAge(response.serverNow, latestServerTime.current) < 0) { clear('clock'); return; }
                latestServerTime.current = response.serverNow;
                view = response; anchor.current = started; install({ ...empty(), view });
            }
            // Overview reads only the existing status ledger; it never starts a page query.
            if (metadataOnly || !view || !anchor.current || !completeGenerationVisible(view, elapsed(anchor.current)) || !view.complete) return;
            const selected = view.complete;
            const response = await mutateRaw<unknown>(`/devices/${encodeURIComponent(deviceId)}/inventory/packages/query`, JSON.stringify({ generationId: selected.binding.generationId, cursor, search: currentQuery, limit: COMPLETE_PAGE_ROWS }), {}, controller.signal, COMPLETE_PAGE_BYTES);
            if (!active()) return;
            if (!validCompletePackagePage(response, deviceId, selected, currentQuery, cursor) || inventoryAge(response.serverNow, view.serverNow) < 0 || !completeGenerationVisible(view, elapsed(anchor.current))) { clear('invalid'); return; }
            if (latestServerTime.current && inventoryAge(response.serverNow, latestServerTime.current) < 0) { clear('clock'); return; }
            latestServerTime.current = response.serverNow;
            const first = response.items[0], previous = lastRow.current;
            if (cursor && first && previous && (first.name < previous.name || first.name === previous.name && first.architecture <= previous.architecture) || response.nextCursor && seenCursors.current.has(response.nextCursor) || state.current.scanned + response.scannedRows > response.totalRows || response.exhausted && state.current.scanned + response.scannedRows !== response.totalRows) { clear('invalid'); return; }
            if (response.nextCursor) seenCursors.current.add(response.nextCursor);
            if (response.items.length) lastRow.current = response.items[response.items.length - 1];
            pageAnchor.current = started;
            install({ view, page: response, scanned: state.current.scanned + response.scannedRows, matches: state.current.matches + response.items.length });
        } catch (caught) {
            if (!active()) return;
            if (caught instanceof APIError && caught.status === 401) { locked.current = true; clear('session'); }
            else if (caught instanceof APIError && caught.status === 409) clear('restart');
            else { install({ ...state.current, page: null }); setError(caught instanceof APIError && caught.status === 429 ? 'busy' : 'loadError'); }
        } finally {
            if (revision === epoch.current) { window.clearTimeout(pending.current?.timeout); pending.current = null; if (alive.current) { setLoading(false); setRecovering(false); } }
        }
    }, [cancel, clear, deviceId, install, metadataOnly]);
    const changeSearch = useCallback((value: string) => {
        cancel(); query.current = value; setSearch(value); pageAnchor.current = null; lastRow.current = null; seenCursors.current.clear(); retryCursor.current = '';
        install({ ...state.current, page: null, scanned: 0, matches: 0 }); setError(null);
    }, [cancel, install]);
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
            if (page && anchor.current && (!completeGenerationVisible(state.current.view!, elapsed(anchor.current)) || pageAnchor.current && inventoryAge(page.cursorExpiresAt, page.serverNow) <= elapsed(pageAnchor.current))) {
                cancel(); pageAnchor.current = null; install({ ...state.current, page: null }); setError('restart');
            }
            if (current) tick(n => n + 1);
        }, 1000);
        void read(true);
        return () => { alive.current = false; clear(); window.clearInterval(timer); window.removeEventListener(AUTH_REQUIRED_EVENT, lock); window.removeEventListener('pagehide', suspend); window.removeEventListener('pageshow', show); window.removeEventListener('blur', suspend); window.removeEventListener('focus', restore); window.removeEventListener('hashchange', navigate); document.removeEventListener('visibilitychange', visibility); };
    }, [cancel, clear, install, read]);
    return { ...data, loading, recovering, error, search, changeSearch, startSearch, refresh: () => void read(true), next: () => { if (state.current.page?.nextCursor) void read(false, state.current.page.nextCursor); }, retry: () => void read(!state.current.view, retryCursor.current), elapsed: anchor.current ? elapsed(anchor.current) : Infinity };
}
