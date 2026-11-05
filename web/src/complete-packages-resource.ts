import { InventoryPollClock, inventoryGenerationChange, preserveInventoryAge } from './inventory-live-refresh';
import { useCallback, useEffect, useRef, useState } from 'react';
import { APIError, AUTH_REQUIRED_EVENT, getProtectedRequestEpoch, hasPendingAPIRequests, mutateRaw, request } from './api';
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
type PackageKey = Pick<PackageRow, 'name' | 'architecture'>;
// Keep navigation tokens and counters only, never previous package rows.
const PAGE_TRAIL_LIMIT = 128;
type PageMark = { cursor: string; scanned: number; matches: number; last: PackageKey | null; scannedRows: number; matchingRows: number; nextCursor: string };
type PageLease = { expiresAt: string; serverNow: string; started: Anchor };
type Data = { view: CompletePackageView | null; page: CompletePackagePage | null; scanned: number; matches: number };
const empty = (): Data => ({ view: null, page: null, scanned: 0, matches: 0 });
export function useCompletePackages(deviceId: string, metadataOnly = false) {
    const [data, setData] = useState<Data>(empty), [loading, setLoading] = useState(false), [recovering, setRecovering] = useState(false), [error, setError] = useState<CompleteFailure | null>(null), [search, setSearch] = useState(''), [, tick] = useState(0);
    const alive = useRef(false), locked = useRef(false), suspended = useRef(false), epoch = useRef(0), state = useRef<Data>(empty());
    const anchor = useRef<Anchor | null>(null), pageAnchor = useRef<Anchor | null>(null), lastRow = useRef<PackageKey | null>(null);
    const trail = useRef<PageMark[]>([]), trailIndex = useRef(-1), firstPage = useRef<PageMark | null>(null), pagingLease = useRef<PageLease | null>(null), retryMark = useRef<PageMark | null>(null);
    const resetNavigation = () => { trail.current = []; trailIndex.current = -1; firstPage.current = null; pagingLease.current = null; retryMark.current = null; };
    const pagingAlive = () => !pagingLease.current || inventoryAge(pagingLease.current.expiresAt, pagingLease.current.serverNow) > elapsed(pagingLease.current.started);
    const constrainPagingLease = (serverNow: string, started: Anchor, expiresAt?: string) => {
        const lease = pagingLease.current;
        if (!lease) { if (expiresAt) pagingLease.current = { expiresAt, serverNow, started }; return; }
        lease.started = preserveInventoryAge(lease.started, lease.serverNow, serverNow, started);
        lease.serverNow = serverNow;
        if (expiresAt && inventoryAge(expiresAt, lease.expiresAt) < 0) lease.expiresAt = expiresAt;
    };
    const query = useRef(''), retryCursor = useRef(''), seenCursors = useRef(new Set<string>());
    const latestServerTime = useRef<string | null>(null);
    const poll = useRef(new InventoryPollClock()), draft = useRef(false);
    const pending = useRef<{ controller: AbortController; timeout: number; started: Anchor } | null>(null);
    const install = useCallback((value: Data) => { state.current = value; if (alive.current) setData(value); }, []);
    const cancel = useCallback(() => { epoch.current++; pending.current?.controller.abort(); window.clearTimeout(pending.current?.timeout); pending.current = null; if (alive.current) { setLoading(false); setRecovering(false); } }, []);
    const clear = useCallback((failure: CompleteFailure | null = null) => {
        poll.current.stop(); cancel(); resetNavigation(); anchor.current = null; pageAnchor.current = null; lastRow.current = null; seenCursors.current.clear(); install(empty()); if (alive.current) setError(failure);
    }, [cancel, install]);
    const read = useCallback(async (refresh: boolean, cursor = '', background = false, revisit: PageMark | null = null) => {
        if (!alive.current || locked.current || suspended.current || document.visibilityState === 'hidden') return;
        if (background && (pending.current || draft.current || retryCursor.current || hasPendingAPIRequests())) return;
        if (!refresh && !pagingAlive()) { clear('restart'); return; }
        const currentQuery = query.current;
        if (new TextEncoder().encode(currentQuery).byteLength > 128 || /[^\x20-\x7e]/.test(currentQuery)) { setError('searchInvalid'); return; }
        const retainedView = state.current.view, retainedAnchor = anchor.current;
        cancel(); poll.current.begin(); let failed = false; const revision = epoch.current, controller = new AbortController(), started = capture(), protectedEpoch = getProtectedRequestEpoch();
        if (refresh && !background) { resetNavigation(); anchor.current = null; pageAnchor.current = null; lastRow.current = null; seenCursors.current.clear(); install(empty()); }
        else if (!background) install({ ...state.current, page: null });
        retryCursor.current = cursor; retryMark.current = revisit; if (!background) setLoading(true); setError(null);
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
                view = response; viewAnchor = preserveInventoryAge(retainedAnchor, retainedView?.serverNow, response.serverNow, started);
                if (!background) { anchor.current = viewAnchor; install({ ...empty(), view }); }
            }
            // Overview reads only the existing status ledger; it never starts a page query.
            if (!view || !viewAnchor) return;
            if (draft.current || metadataOnly || !completeGenerationVisible(view, elapsed(viewAnchor)) || !view.complete) {
                if (background) { resetNavigation(); lastRow.current = null; seenCursors.current.clear(); anchor.current = viewAnchor; pageAnchor.current = null; install({ ...empty(), view }); }
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
                    constrainPagingLease(view.serverNow, started);
                    if (!pagingAlive() || page.cursorExpiresAt && inventoryAge(page.cursorExpiresAt, view.serverNow) <= elapsed(viewAnchor)) {
                        poll.current.stop(); cancel(); resetNavigation(); pageAnchor.current = null; install({ ...state.current, view, page: null }); setError('restart'); return;
                    }
                    install({ ...state.current, view }); return;
                }
            }
            if (background) { resetNavigation(); seenCursors.current.clear(); }
            const prefix = revisit ?? { cursor, scanned: background ? 0 : state.current.scanned, matches: background ? 0 : state.current.matches, last: background ? null : lastRow.current };
            if (!pagingAlive()) { clear('restart'); return; }
            const response = await mutateRaw<unknown>(`/devices/${encodeURIComponent(deviceId)}/inventory/packages/query`, JSON.stringify({ generationId: selected.binding.generationId, cursor, search: currentQuery, limit: COMPLETE_PAGE_ROWS }), {}, controller.signal, COMPLETE_PAGE_BYTES);
            if (!active()) return;
            if (!validCompletePackagePage(response, deviceId, selected, currentQuery, cursor) || inventoryAge(response.serverNow, view.serverNow) < 0 || !completeGenerationVisible(view, elapsed(viewAnchor))) { clear('invalid'); return; }
            if (latestServerTime.current && inventoryAge(response.serverNow, latestServerTime.current) < 0) { clear('clock'); return; }
            latestServerTime.current = response.serverNow;
            constrainPagingLease(response.serverNow, started, response.cursorExpiresAt);
            if (!pagingAlive()) { clear('restart'); return; }
            const first = response.items[0], previous = prefix.last;
            if (cursor && first && previous && (first.name < previous.name || first.name === previous.name && first.architecture <= previous.architecture) || !revisit && response.nextCursor && seenCursors.current.has(response.nextCursor) || prefix.scanned + response.scannedRows > response.totalRows || response.exhausted && prefix.scanned + response.scannedRows !== response.totalRows || revisit && (response.scannedRows !== revisit.scannedRows || response.items.length !== revisit.matchingRows || Boolean(response.nextCursor) !== Boolean(revisit.nextCursor) || cursor !== '' && response.nextCursor !== revisit.nextCursor)) { clear('invalid'); return; }
            // A blank first-page request may issue a newer token. Keep the original
            // navigation token and earliest lease instead of renewing this search.
            const mark: PageMark = revisit ?? { ...prefix, scannedRows: response.scannedRows, matchingRows: response.items.length, nextCursor: response.nextCursor };
            if (revisit) { const index = trail.current.indexOf(revisit); if (index < 0) { clear('invalid'); return; } trailIndex.current = index; }
            else { trail.current = [...trail.current.slice(0, trailIndex.current + 1), mark].slice(-PAGE_TRAIL_LIMIT); trailIndex.current = trail.current.length - 1; if (cursor === '') firstPage.current = mark; }
            if (mark.nextCursor) seenCursors.current.add(mark.nextCursor);
            const last = response.items.at(-1); lastRow.current = last ? { name: last.name, architecture: last.architecture } : prefix.last;
            if (background) anchor.current = viewAnchor;
            pageAnchor.current = started;
            install({ view, page: response, scanned: prefix.scanned + response.scannedRows, matches: prefix.matches + response.items.length });
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
        draft.current = true; cancel(); resetNavigation(); query.current = value; setSearch(value); pageAnchor.current = null; lastRow.current = null; seenCursors.current.clear(); retryCursor.current = '';
        install({ ...state.current, page: null, scanned: 0, matches: 0 }); setError(null);
    }, [cancel, install]);
    const startSearch = useCallback(() => {
        draft.current = false; cancel(); resetNavigation(); lastRow.current = null; seenCursors.current.clear(); retryCursor.current = ''; install({ ...state.current, page: null, scanned: 0, matches: 0 });
        void read(!state.current.view, '');
    }, [cancel, install, read]);
    useEffect(() => {
        const accessEpoch = getProtectedRequestEpoch();
        alive.current = true; locked.current = false; suspended.current = document.visibilityState === 'hidden';
        const lock = () => { locked.current = true; clear('session'); query.current = ''; setSearch(''); };
        const suspend = () => { suspended.current = true; clear(); };
        // A browser return can emit visibility, focus and pageshow together.
        // Resume once so later notifications cannot abort/restart the fresh read.
        const restore = () => { if (locked.current || !suspended.current || document.visibilityState === 'hidden') return; suspended.current = false; void read(true); };
        const visibility = () => document.visibilityState === 'hidden' ? suspend() : restore();
        const show = (event: PageTransitionEvent) => { if (event.persisted || suspended.current) restore(); };
        const navigate = () => { suspended.current = true; clear(); };
        window.addEventListener(AUTH_REQUIRED_EVENT, lock); window.addEventListener('pagehide', suspend); window.addEventListener('pageshow', show); window.addEventListener('blur', suspend); window.addEventListener('focus', restore); window.addEventListener('hashchange', navigate); document.addEventListener('visibilitychange', visibility);
        const timer = window.setInterval(() => {
            if (accessEpoch !== getProtectedRequestEpoch()) { if (!locked.current) lock(); return; }
            const current = anchor.current ?? pending.current?.started;
            if (current && !Number.isFinite(elapsed(current))) { clear('clock'); return; }
            const page = state.current.page;
            if (page && anchor.current && (!pagingAlive() || !completeGenerationVisible(state.current.view!, elapsed(anchor.current)) || pageAnchor.current && inventoryAge(page.cursorExpiresAt, page.serverNow) <= elapsed(pageAnchor.current))) {
                poll.current.stop(); cancel(); resetNavigation(); pageAnchor.current = null; install({ ...state.current, page: null }); setError('restart');
            }
            if (!metadataOnly && !locked.current && !suspended.current && document.visibilityState !== 'hidden' && !pending.current && !draft.current && !retryCursor.current && poll.current.due() && !hasPendingAPIRequests()) void read(true, '', true);
            if (current) tick(n => n + 1);
        }, 1000);
        void read(true);
        return () => { alive.current = false; clear(); window.clearInterval(timer); window.removeEventListener(AUTH_REQUIRED_EVENT, lock); window.removeEventListener('pagehide', suspend); window.removeEventListener('pageshow', show); window.removeEventListener('blur', suspend); window.removeEventListener('focus', restore); window.removeEventListener('hashchange', navigate); document.removeEventListener('visibilitychange', visibility); };
    }, [cancel, clear, install, read]);
    const previous = () => { if (pending.current || !state.current.page || trailIndex.current <= 0) return; const mark = trail.current[trailIndex.current - 1]; void read(false, mark.cursor, false, mark); };
    const first = () => { if (pending.current || !state.current.page || !firstPage.current || state.current.scanned === firstPage.current.scannedRows) return; const mark = firstPage.current; trail.current = [mark]; trailIndex.current = 0; seenCursors.current.clear(); void read(false, '', false, mark); };
    const next = () => { if (pending.current || !state.current.page) return; const mark = trail.current[trailIndex.current], following = trail.current[trailIndex.current + 1]; if (mark?.nextCursor) void read(false, mark.nextCursor, false, following?.cursor === mark.nextCursor ? following : null); };
    return { ...data, previous, first, canPrevious: trailIndex.current > 0, canFirst: !!firstPage.current && data.scanned > firstPage.current.scannedRows, limitedBack: trailIndex.current === 0 && (trail.current[0]?.scanned ?? 0) > 0, liveState: poll.current.state(draft.current || Boolean(retryCursor.current)), loading, recovering, error, search, changeSearch, startSearch, refresh: () => { draft.current = false; void read(true); }, next, retry: () => void read(!state.current.view, retryCursor.current, false, retryMark.current), elapsed: anchor.current ? elapsed(anchor.current) : Infinity };
}
