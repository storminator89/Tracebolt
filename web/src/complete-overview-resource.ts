import { InventoryPollClock, inventoryGenerationChange, preserveInventoryAge } from './inventory-live-refresh';
import { useCallback, useEffect, useRef, useState } from 'react';
import { APIError, AUTH_REQUIRED_EVENT, getProtectedRequestEpoch, hasPendingAPIRequests, mutateRaw, request } from './api';
import { OVERVIEW_PAGE_BYTES, OVERVIEW_STATUS_BYTES, OVERVIEW_PAGE_ROWS, overviewSectionVisible, validOverviewSearch, validOverviewPage, validOverviewView, volumeGroup } from './complete-overview-types';
import type { OverviewPage, OverviewView, OverviewSection, OverviewRow } from './complete-overview-types';
import { inventoryAge } from './complete-packages-types';

export type OverviewFailure = 'loadError' | 'invalid' | 'timeout' | 'session' | 'clock' | 'busy' | 'restart' | 'searchInvalid';
type Anchor = { mono: number; wall: number };
const capture = (): Anchor => ({ mono: performance.now(), wall: Date.now() });
function elapsed(anchor: Anchor): number {
    const delta = performance.now() - anchor.mono, wall = Date.now() - anchor.wall;
    return Number.isFinite(delta) && delta >= 0 && Number.isFinite(wall) && Math.abs(wall - delta) <= 1500 ? delta : Infinity;
}
// Only bounded cursor/checkpoint metadata is retained, never prior row pages.
const PAGE_TRAIL_LIMIT = 128;
type OrderKey = { pid: number } | { group: number; root: boolean; path: string; id: string };
const orderKey = (row: OverviewRow): OrderKey => row.process ? { pid: row.process.pid } : { group: volumeGroup(row.volume!), root: row.volume!.mountPoint === '/', path: row.volume!.mountPoint, id: row.volume!.id };
const byteCompare = (a: string, b: string) => { const x = new TextEncoder().encode(a), y = new TextEncoder().encode(b); for (let i = 0; i < Math.min(x.length, y.length); i++) if (x[i] !== y[i]) return x[i] - y[i]; return x.length - y.length; };
const compareKeys = (a: OrderKey, b: OrderKey) => 'pid' in a && 'pid' in b ? a.pid - b.pid : !('pid' in a) && !('pid' in b) ? a.group - b.group || Number(b.root) - Number(a.root) || byteCompare(a.path, b.path) || byteCompare(a.id, b.id) : 0;
type Signature = { cursor: string; scanned: number; matches: number; count: number; returned: number; exhausted: boolean; nextCursor: string; first: OrderKey | null; last: OrderKey | null; number: number };
type Mark = { signature: Signature; previous: OrderKey | null };
type Lease = { expiresAt: string; serverNow: string; started: Anchor };
type Data = { view: OverviewView | null; page: OverviewPage | null; scanned: number; matches: number };
const empty = (): Data => ({ view: null, page: null, scanned: 0, matches: 0 });
export function useCompleteOverview(deviceId: string, section: OverviewSection) {
    const [data, setData] = useState<Data>(empty), [loading, setLoading] = useState(false), [recovering, setRecovering] = useState(false), [error, setError] = useState<OverviewFailure | null>(null), [search, setSearch] = useState(''), [, tick] = useState(0);
    const alive = useRef(false), locked = useRef(false), suspended = useRef(false), epoch = useRef(0), state = useRef<Data>(empty());
    const anchor = useRef<Anchor | null>(null), pageAnchor = useRef<Anchor | null>(null), lastRow = useRef<OrderKey | null>(null);
    const query = useRef(''), retryCursor = useRef(''), seenCursors = useRef(new Set<string>()), cursorDeadline = useRef<string | null>(null);
    // Registry bounded by validated section total (32768 processes / 16384 mounts)
    // plus one empty terminal window. The backward trail itself is capped at128.
    const signatures = useRef(new Map<string, Signature>()), trail = useRef<Mark[]>([]), trailIndex = useRef(-1), firstPage = useRef<Mark | null>(null), retryMark = useRef<Mark | null>(null), pagingLease = useRef<Lease | null>(null), navigationExpired = useRef(false);
    const resetNavigation = (expired = false) => { signatures.current.clear(); trail.current = []; trailIndex.current = -1; firstPage.current = null; retryMark.current = null; pagingLease.current = null; navigationExpired.current = expired; retryCursor.current = ''; seenCursors.current.clear(); };
    const pagingAlive = () => !navigationExpired.current && (!pagingLease.current || inventoryAge(pagingLease.current.expiresAt, pagingLease.current.serverNow) > elapsed(pagingLease.current.started));
    const constrainLease = (serverNow: string, started: Anchor, expiresAt: string | null) => {
        const lease = pagingLease.current;
        if (!lease) { if (expiresAt) pagingLease.current = { expiresAt, serverNow, started }; return; }
        lease.started = preserveInventoryAge(lease.started, lease.serverNow, serverNow, started); lease.serverNow = serverNow;
        if (expiresAt && inventoryAge(expiresAt, lease.expiresAt) < 0) lease.expiresAt = expiresAt;
    };
    const latestServerTime = useRef<string | null>(null);
    const poll = useRef(new InventoryPollClock()), draft = useRef(false);
    const pending = useRef<{ controller: AbortController; timeout: number; started: Anchor } | null>(null);
    const install = useCallback((value: Data) => { state.current = value; if (alive.current) setData(value); }, []);
    const cancel = useCallback(() => { epoch.current++; pending.current?.controller.abort(); window.clearTimeout(pending.current?.timeout); pending.current = null; if (alive.current) { setLoading(false); setRecovering(false); } }, []);
    const clear = useCallback((failure: OverviewFailure | null = null) => {
        poll.current.stop(); cancel(); resetNavigation(); anchor.current = null; pageAnchor.current = null; lastRow.current = null; cursorDeadline.current = null; seenCursors.current.clear(); install(empty()); if (alive.current) setError(failure);
    }, [cancel, install]);
    const expireNavigation = useCallback(() => { poll.current.stop(); cancel(); resetNavigation(true); pageAnchor.current = null; lastRow.current = null; cursorDeadline.current = null; install({ ...state.current, page: null }); if (alive.current) setError('restart'); }, [cancel, install]);
    const read = useCallback(async (refresh: boolean, cursor = '', background = false, revisit: Mark | null = null) => {
        if (!alive.current || locked.current || suspended.current || document.visibilityState === 'hidden') return;
        if (background && (pending.current || draft.current || retryCursor.current || hasPendingAPIRequests())) return;
        if (!refresh && !pagingAlive()) { expireNavigation(); return; }
        if (revisit && (revisit.signature.cursor !== cursor || signatures.current.get(cursor) !== revisit.signature)) { clear('invalid'); return; }
        const currentQuery = query.current;
        if (!validOverviewSearch(currentQuery)) { setError('searchInvalid'); return; }
        const retainedView = state.current.view, retainedAnchor = anchor.current;
        cancel(); poll.current.begin(); let failed = false; const revision = epoch.current, controller = new AbortController(), started = capture(), protectedEpoch = getProtectedRequestEpoch();
        if (refresh && !background) { resetNavigation(); anchor.current = null; pageAnchor.current = null; lastRow.current = null; cursorDeadline.current = null; seenCursors.current.clear(); install(empty()); }
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
                // Retry only this exact GET once. Keep the original controller,
                // access epoch, capture anchor and total ten-second deadline.
                for (let attempt = 0; attempt < 2; attempt++) {
                    try {
                        response = await request<unknown>(`/devices/${encodeURIComponent(deviceId)}/inventory/overview`, { signal: controller.signal }, OVERVIEW_STATUS_BYTES);
                        break;
                    } catch (caught) {
                        if (!active()) return;
                        if (attempt !== 0 || !(caught instanceof APIError) || caught.status !== 429 || caught.code !== 'storage_busy') throw caught;
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
                if (!validOverviewView(response, deviceId)) { clear('invalid'); return; }
                if (latestServerTime.current && inventoryAge(response.serverNow, latestServerTime.current) < 0) { clear('clock'); return; }
                latestServerTime.current = response.serverNow;
                view = response; viewAnchor = preserveInventoryAge(retainedAnchor, retainedView?.serverNow, response.serverNow, started);
                if (!background) { anchor.current = viewAnchor; install({ ...empty(), view }); }
            }
            if (draft.current || !view || !viewAnchor) return;
            if (!overviewSectionVisible(view, section, elapsed(viewAnchor)) || !view[section].complete) {
                if (background) { resetNavigation(); lastRow.current = null; cursorDeadline.current = null; anchor.current = viewAnchor; pageAnchor.current = null; install({ ...empty(), view }); }
                return;
            }
            const selected = view[section].complete!;
            if (background) {
                const previous = state.current.view?.[section].complete;
                const change = inventoryGenerationChange(previous ? { id: previous.binding.generationId, sequence: previous.binding.sequence, evidence: previous } : null, { id: selected.binding.generationId, sequence: selected.binding.sequence, evidence: selected });
                if (change === 'invalid') { clear('invalid'); return; }
                // A status read cannot renew a page/cursor deadline or resubmit a query.
                if (change === 'same' && state.current.page) {
                    const page = state.current.page;
                    anchor.current = viewAnchor;
                    constrainLease(view.serverNow, started, null); install({ ...state.current, view });
                    if (!pagingAlive() || inventoryAge(page.cursorExpiresAt, view.serverNow) <= elapsed(viewAnchor)) { expireNavigation(); return; }
                    return;
                }
            }
            const prefix = revisit?.signature ?? { scanned: background ? 0 : state.current.scanned, matches: background ? 0 : state.current.matches };
            const previous = background ? null : revisit ? revisit.previous : lastRow.current;
            if (!background && !pagingAlive()) { expireNavigation(); return; }
            const response = await mutateRaw<unknown>(`/devices/${encodeURIComponent(deviceId)}/inventory/overview/query`, JSON.stringify({ section, generationId: selected.binding.generationId, cursor, search: currentQuery, limit: OVERVIEW_PAGE_ROWS }), {}, controller.signal, OVERVIEW_PAGE_BYTES);
            if (!active()) return;
            if (!validOverviewPage(response, deviceId, section, selected, currentQuery, cursor) || inventoryAge(response.serverNow, view.serverNow) < 0 || !overviewSectionVisible(view, section, elapsed(viewAnchor))) { clear('invalid'); return; }
            if (latestServerTime.current && inventoryAge(response.serverNow, latestServerTime.current) < 0) { clear('clock'); return; }
            latestServerTime.current = response.serverNow;
            if (cursor && cursorDeadline.current !== response.cursorExpiresAt) { clear('invalid'); return; }
            if (background) { resetNavigation(); cursorDeadline.current = null; lastRow.current = null; anchor.current = viewAnchor; }
            if (!cursorDeadline.current) cursorDeadline.current = response.cursorExpiresAt;
            constrainLease(response.serverNow, started, response.cursorExpiresAt);
            if (!pagingAlive()) { expireNavigation(); return; }
            const first = response.items[0] ? orderKey(response.items[0]) : null, last = response.items.length ? orderKey(response.items.at(-1)!) : null, expected = revisit?.signature;
            const sameKey = (a: OrderKey | null, b: OrderKey | null) => a === null || b === null ? a === b : compareKeys(a, b) === 0;
            const changed = expected && (response.scannedRows !== expected.count || response.items.length !== expected.returned || response.exhausted !== expected.exhausted || !sameKey(first, expected.first) || !sameKey(last, expected.last) || Boolean(response.nextCursor) !== Boolean(expected.nextCursor) || cursor !== '' && response.nextCursor !== expected.nextCursor);
            if (cursor && first && previous && compareKeys(previous, first) >= 0 || !expected && response.nextCursor && seenCursors.current.has(response.nextCursor) || prefix.scanned + response.scannedRows > response.totalRows || response.exhausted && prefix.scanned + response.scannedRows !== response.totalRows || changed) { clear('invalid'); return; }
            if (!expected && (signatures.current.has(cursor) || signatures.current.size >= response.totalRows + 1 || response.nextCursor && seenCursors.current.size >= response.totalRows)) { clear('invalid'); return; }
            // First may return a freshly signed cursor: do not adopt its renewed
            // token, deadline or trail. Original tokens remain authoritative.
            const signature: Signature = expected ?? { cursor, scanned: prefix.scanned, matches: prefix.matches, count: response.scannedRows, returned: response.items.length, exhausted: response.exhausted, nextCursor: response.nextCursor, first, last, number: signatures.current.size + 1 };
            const mark = revisit ?? { signature, previous };
            if (!expected) signatures.current.set(cursor, signature);
            if (signature.nextCursor) seenCursors.current.add(signature.nextCursor);
            const known = trail.current.findIndex(item => item.signature === signature);
            if (cursor === '') { firstPage.current = mark; trail.current = [mark]; trailIndex.current = 0; }
            else if (known >= 0) trailIndex.current = known;
            else { trail.current = [...trail.current.slice(0, trailIndex.current + 1), mark].slice(-PAGE_TRAIL_LIMIT); trailIndex.current = trail.current.length - 1; }
            lastRow.current = last ?? previous; pageAnchor.current = started;
            install({ view, page: response, scanned: signature.scanned + response.scannedRows, matches: signature.matches + response.items.length });
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
    }, [cancel, clear, deviceId, expireNavigation, install, section]);
    const changeSearch = useCallback((value: string) => {
        draft.current = true; cancel(); resetNavigation(); query.current = value; setSearch(value); pageAnchor.current = null; lastRow.current = null; cursorDeadline.current = null; seenCursors.current.clear(); retryCursor.current = '';
        install({ ...state.current, page: null, scanned: 0, matches: 0 }); setError(null);
    }, [cancel, install]);
    const startSearch = useCallback(() => {
        draft.current = false; cancel(); resetNavigation(); lastRow.current = null; cursorDeadline.current = null; seenCursors.current.clear(); retryCursor.current = ''; install({ ...state.current, page: null, scanned: 0, matches: 0 });
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
            if (pagingLease.current && !pagingAlive() || page && anchor.current && (!overviewSectionVisible(state.current.view!, section, elapsed(anchor.current)) || pageAnchor.current && inventoryAge(page.cursorExpiresAt, page.serverNow) <= elapsed(pageAnchor.current))) expireNavigation();
            if (!locked.current && !suspended.current && document.visibilityState !== 'hidden' && !pending.current && !draft.current && !retryCursor.current && poll.current.due() && !hasPendingAPIRequests()) void read(true, '', true);
            if (current) tick(n => n + 1);
        }, 1000);
        void read(true);
        return () => { alive.current = false; clear(); window.clearInterval(timer); window.removeEventListener(AUTH_REQUIRED_EVENT, lock); window.removeEventListener('pagehide', suspend); window.removeEventListener('pageshow', show); window.removeEventListener('blur', suspend); window.removeEventListener('focus', restore); window.removeEventListener('hashchange', navigate); document.removeEventListener('visibilitychange', visibility); };
    }, [cancel, clear, expireNavigation, install, read, section]);
    const previous = () => { if (pending.current || !state.current.page || trailIndex.current <= 0) return; const mark = trail.current[trailIndex.current - 1]; void read(false, mark.signature.cursor, false, mark); };
    const first = () => { if (pending.current || !state.current.page || !firstPage.current || trail.current[trailIndex.current]?.signature === firstPage.current.signature) return; void read(false, '', false, firstPage.current); };
    const next = () => {
        if (pending.current || !state.current.page) return;
        if (!pagingAlive()) { expireNavigation(); return; }
        const cursor = trail.current[trailIndex.current]?.signature.nextCursor; if (!cursor) return;
        const known = signatures.current.get(cursor);
        if (known && (known.scanned !== state.current.scanned || known.matches !== state.current.matches)) { clear('invalid'); return; }
        void read(false, cursor, false, known ? { signature: known, previous: lastRow.current } : null);
    };
    return { ...data, previous, first, next, hasNavigation: trail.current.length > 0, pageNumber: data.page ? trail.current[trailIndex.current]?.signature.number ?? null : null, pagingExpiresAt: pagingLease.current?.expiresAt ?? data.page?.cursorExpiresAt, canPrevious: !!data.page && trailIndex.current > 0, canFirst: !!data.page && !!firstPage.current && trail.current[trailIndex.current]?.signature !== firstPage.current.signature, hasNext: !!trail.current[trailIndex.current]?.signature.nextCursor, limitedBack: !!data.page && trailIndex.current === 0 && (trail.current[0]?.signature.scanned ?? 0) > 0, liveState: poll.current.state(draft.current || Boolean(retryCursor.current)), loading, recovering, error, search, changeSearch, startSearch, refresh: () => { draft.current = false; void read(true); }, retry: () => { if (!navigationExpired.current) void read(!state.current.view, retryCursor.current, false, retryMark.current); }, elapsed: anchor.current ? elapsed(anchor.current) : Infinity };
}
