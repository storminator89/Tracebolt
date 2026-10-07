import { InventoryPollClock, inventoryGenerationChange, preserveInventoryAge } from './inventory-live-refresh';
import { inventoryAge } from './complete-packages-types';
import { useCallback, useEffect, useRef, useState } from 'react';
import { APIError, AUTH_REQUIRED_EVENT, getProtectedRequestEpoch, hasPendingAPIRequests, mutateRaw, request } from './api';
import { COMPLETE_UPDATES_PAGE_BYTES, COMPLETE_UPDATES_PAGE_ROWS, COMPLETE_UPDATES_STATUS_BYTES, completeUpdatesGenerationVisible, validCompleteUpdatePage, validCompleteUpdateView } from './complete-updates-types';
import type { CompleteUpdatePage, CompleteUpdateView } from './complete-updates-types';
import type { CachedUpdateRow } from './cached-updates-types';

export type CompleteFailure = 'loadError' | 'invalid' | 'timeout' | 'session' | 'clock' | 'busy' | 'restart' | 'searchInvalid';
type Anchor = { mono: number; wall: number };
const capture = (): Anchor => ({ mono: performance.now(), wall: Date.now() });
function elapsed(anchor: Anchor): number {
    const delta = performance.now() - anchor.mono, wall = Date.now() - anchor.wall;
    return Number.isFinite(delta) && delta >= 0 && Number.isFinite(wall) && Math.abs(wall - delta) <= 1500 ? delta : Infinity;
}
type Data = { view: CompleteUpdateView | null; page: CompleteUpdatePage | null; scanned: number; matches: number };
const empty = (): Data => ({ view: null, page: null, scanned: 0, matches: 0 });
export function useCompleteUpdates(deviceId: string, metadataOnly = false, autoResume = true) {
    const [data, setData] = useState<Data>(empty), [loading, setLoading] = useState(false), [recovering, setRecovering] = useState(false), [error, setError] = useState<CompleteFailure | null>(null), [search, setSearch] = useState(''), [, tick] = useState(0);
    const alive = useRef(false), locked = useRef(false), suspended = useRef(false), epoch = useRef(0), state = useRef<Data>(empty());
    const anchor = useRef<Anchor | null>(null), pageAnchor = useRef<Anchor | null>(null), lastRow = useRef<CachedUpdateRow | null>(null);
    const query = useRef(''), retryCursor = useRef(''), seenCursors = useRef(new Set<string>());
    const latestServerTime = useRef<string | null>(null);
    const poll = useRef(new InventoryPollClock()), draft = useRef(false);
    const pending = useRef<{ controller: AbortController; timeout: number; started: Anchor } | null>(null);
    const install = useCallback((value: Data) => { state.current = value; if (alive.current) setData(value); }, []);
    const cancel = useCallback(() => { epoch.current++; pending.current?.controller.abort(); window.clearTimeout(pending.current?.timeout); pending.current = null; if (alive.current) { setLoading(false); setRecovering(false); } }, []);
    const clear = useCallback((failure: CompleteFailure | null = null) => {
        poll.current.stop(); cancel(); anchor.current = null; pageAnchor.current = null; lastRow.current = null; seenCursors.current.clear(); install(empty()); if (alive.current) setError(failure);
    }, [cancel, install]);
    const read = useCallback(async (refresh: boolean, cursor = '', background = false) => {
        if (!alive.current || locked.current || suspended.current || document.visibilityState === 'hidden') return;
        if (background && (pending.current || draft.current || retryCursor.current || hasPendingAPIRequests())) return;
        const currentQuery = query.current;
        if (new TextEncoder().encode(currentQuery).byteLength > 128 || /[^\x20-\x7e]/.test(currentQuery)) { setError('searchInvalid'); return; }
        const retainedView = state.current.view, retainedAnchor = anchor.current;
        cancel(); poll.current.begin(); let failed = false; const revision = epoch.current, controller = new AbortController(), started = capture(), protectedEpoch = getProtectedRequestEpoch();
        if (refresh && !background) { anchor.current = null; pageAnchor.current = null; lastRow.current = null; seenCursors.current.clear(); install(empty()); }
        else if (!background) install({ ...state.current, page: null });
        retryCursor.current = cursor; if (!background) setLoading(true); setError(null);
        pending.current = { controller, started, timeout: window.setTimeout(() => {
            if (revision === epoch.current) { cancel(); if (!background) install({ ...state.current, page: null }); setError('timeout'); if (background) poll.current.finish(true); else poll.current.stop(); }
        }, 10000) };
        const active = () => {
            if (!alive.current || locked.current || suspended.current || controller.signal.aborted || revision !== epoch.current) return false;
            if (protectedEpoch !== getProtectedRequestEpoch()) { locked.current = true; clear('session'); return false; }
            if (!Number.isFinite(elapsed(started)) || anchor.current && !Number.isFinite(elapsed(anchor.current))) { clear('clock'); return false; }
            if (elapsed(started) >= 10000) { cancel(); if (!background) install({ ...state.current, page: null }); setError('timeout'); if (background) poll.current.finish(true); else poll.current.stop(); return false; }
            return true;
        };
        try {
            let view = state.current.view, viewAnchor = anchor.current;
            if (refresh) {
                let response: unknown;
                // Retry only the software summary GET once; full package paging is unchanged. Keep the original controller,
                // access epoch, capture anchor and total ten-second deadline.
                for (let attempt = 0; attempt < 2; attempt++) {
                    try {
                        response = await request<unknown>(`/devices/${encodeURIComponent(deviceId)}/inventory/complete-updates`, { signal: controller.signal }, COMPLETE_UPDATES_STATUS_BYTES);
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
                if (!validCompleteUpdateView(response, deviceId)) { clear('invalid'); return; }
                if (latestServerTime.current && inventoryAge(response.serverNow, latestServerTime.current) < 0) { clear('clock'); return; }
                latestServerTime.current = response.serverNow;
                view = response; viewAnchor = preserveInventoryAge(retainedAnchor, retainedView?.serverNow, response.serverNow, started);
                if (!background) { anchor.current = viewAnchor; install({ ...empty(), view }); }
            }
            // Overview reads only the existing status ledger; it never starts a page query.
            if (!view || !viewAnchor) return;
            if (draft.current || metadataOnly || !completeUpdatesGenerationVisible(view, elapsed(viewAnchor)) || !view.complete) {
                if (background) { anchor.current = viewAnchor; pageAnchor.current = null; install({ ...empty(), view }); }
                if (view.status === 'revoked') { poll.current.stop(); cancel(); }
                return;
            }
            const selected = view.complete!;
            if (background) {
                const previous = state.current.view?.complete;
                const change = inventoryGenerationChange(previous ? { id: previous.binding.generationId, sequence: previous.binding.sequence, evidence: previous } : null, { id: selected.binding.generationId, sequence: selected.binding.sequence, evidence: selected });
                if (change === 'invalid') { clear('invalid'); return; }
                // A status read cannot renew a page/cursor deadline or resubmit a query.
                if (change === 'same' && state.current.page) {
                    const page = state.current.page;
                    anchor.current = viewAnchor;
                    if (page.cursorExpiresAt && inventoryAge(page.cursorExpiresAt, view.serverNow) <= elapsed(viewAnchor)) {
                        poll.current.stop(); cancel(); pageAnchor.current = null; install({ ...state.current, view, page: null }); setError('restart'); return;
                    }
                    install({ ...state.current, view }); return;
                }
            }
            const response = await mutateRaw<unknown>(`/devices/${encodeURIComponent(deviceId)}/inventory/complete-updates/query`, JSON.stringify({ generationId: selected.binding.generationId, cursor, search: currentQuery, limit: COMPLETE_UPDATES_PAGE_ROWS }), {}, controller.signal, COMPLETE_UPDATES_PAGE_BYTES);
            if (!active()) return;
            if (!validCompleteUpdatePage(response, deviceId, selected, currentQuery, cursor) || inventoryAge(response.serverNow, view.serverNow) < 0 || !completeUpdatesGenerationVisible(view, elapsed(viewAnchor))) { clear('invalid'); return; }
            if (latestServerTime.current && inventoryAge(response.serverNow, latestServerTime.current) < 0) { clear('clock'); return; }
            latestServerTime.current = response.serverNow;
            const first = response.items[0], previous = lastRow.current;
            if (cursor && first && previous && (first.name < previous.name || first.name === previous.name && first.architecture <= previous.architecture) || !background && response.nextCursor && seenCursors.current.has(response.nextCursor) || (background ? 0 : state.current.scanned) + response.scannedRows > response.totalRows || response.exhausted && (background ? 0 : state.current.scanned) + response.scannedRows !== response.totalRows) { clear('invalid'); return; }
            if (background) { lastRow.current = null; seenCursors.current.clear(); anchor.current = viewAnchor; }
            if (response.nextCursor) seenCursors.current.add(response.nextCursor);
            if (response.items.length) lastRow.current = response.items[response.items.length - 1];
            pageAnchor.current = started;
            install({ view, page: response, scanned: (background ? 0 : state.current.scanned) + response.scannedRows, matches: (background ? 0 : state.current.matches) + response.items.length });
        } catch (caught) {
            if (!active()) return;
            failed = true;
            if (caught instanceof APIError && caught.status === 401) { locked.current = true; clear('session'); }
            else if (caught instanceof APIError && [403, 404, 410].includes(caught.status ?? 0)) clear('loadError');
            else if (caught instanceof APIError && caught.status === 409) clear('restart');
            else { if (!background) install({ ...state.current, page: null }); setError(caught instanceof APIError && caught.status === 429 ? 'busy' : 'loadError'); }
        } finally {
            if (revision === epoch.current) { if (failed && !background) poll.current.stop(); else poll.current.finish(failed); window.clearTimeout(pending.current?.timeout); pending.current = null; if (alive.current) { setLoading(false); setRecovering(false); } }
        }
    }, [cancel, clear, deviceId, install, metadataOnly]);
    const changeSearch = useCallback((value: string) => {
        draft.current = true; cancel(); query.current = value; setSearch(value); pageAnchor.current = null; lastRow.current = null; seenCursors.current.clear(); retryCursor.current = '';
        install({ ...state.current, page: null, scanned: 0, matches: 0 }); setError(null);
    }, [cancel, install]);
    const startSearch = useCallback(() => {
        draft.current = false; cancel(); lastRow.current = null; seenCursors.current.clear(); retryCursor.current = ''; install({ ...state.current, page: null, scanned: 0, matches: 0 });
        void read(!state.current.view, '');
    }, [cancel, install, read]);
    useEffect(() => {
        const accessEpoch = getProtectedRequestEpoch();
        alive.current = true; locked.current = false; suspended.current = document.visibilityState === 'hidden';
        const lock = () => { locked.current = true; clear('session'); query.current = ''; setSearch(''); };
        const suspend = () => { suspended.current = true; clear(); };
        const restore = () => { if (locked.current || document.visibilityState === 'hidden') return; suspended.current = false; if (autoResume) void read(true); };
        const visibility = () => document.visibilityState === 'hidden' ? suspend() : restore();
        const show = (event: PageTransitionEvent) => { if (event.persisted || suspended.current) restore(); };
        const navigate = () => { suspended.current = true; clear(); };
        window.addEventListener(AUTH_REQUIRED_EVENT, lock); window.addEventListener('pagehide', suspend); window.addEventListener('pageshow', show); window.addEventListener('blur', suspend); window.addEventListener('focus', restore); window.addEventListener('hashchange', navigate); document.addEventListener('visibilitychange', visibility);
        const timer = window.setInterval(() => {
            if (accessEpoch !== getProtectedRequestEpoch()) { if (!locked.current) lock(); return; }
            const current = anchor.current ?? pending.current?.started;
            if (current && !Number.isFinite(elapsed(current))) { clear('clock'); return; }
            const page = state.current.page;
            if (page && anchor.current && (!completeUpdatesGenerationVisible(state.current.view!, elapsed(anchor.current)) || pageAnchor.current && inventoryAge(page.cursorExpiresAt, page.serverNow) <= elapsed(pageAnchor.current))) {
                poll.current.stop(); cancel(); pageAnchor.current = null; install({ ...state.current, page: null }); setError('restart');
            }
            if (!metadataOnly && !locked.current && !suspended.current && document.visibilityState !== 'hidden' && !pending.current && !draft.current && !retryCursor.current && poll.current.due() && !hasPendingAPIRequests()) void read(true, '', true);
            if (current) tick(n => n + 1);
        }, 1000);
        void read(true);
        return () => { alive.current = false; clear(); window.clearInterval(timer); window.removeEventListener(AUTH_REQUIRED_EVENT, lock); window.removeEventListener('pagehide', suspend); window.removeEventListener('pageshow', show); window.removeEventListener('blur', suspend); window.removeEventListener('focus', restore); window.removeEventListener('hashchange', navigate); document.removeEventListener('visibilitychange', visibility); };
    }, [autoResume, cancel, clear, install, read]);
    return { ...data, liveState: poll.current.state(draft.current || Boolean(retryCursor.current)), loading, recovering, error, search, changeSearch, startSearch, refresh: () => { draft.current = false; void read(true); }, next: () => { if (state.current.page?.nextCursor) void read(false, state.current.page.nextCursor); }, retry: () => void read(!state.current.view, retryCursor.current), elapsed: anchor.current ? elapsed(anchor.current) : Infinity };
}
