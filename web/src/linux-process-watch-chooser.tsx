import { useEffect, useId, useRef, useState } from 'react';
import { APIError, AUTH_REQUIRED_EVENT, getProtectedRequestEpoch, mutateRaw, request } from './api';
import { hasLogoutIntent } from './auth';
import { OVERVIEW_PAGE_BYTES, OVERVIEW_PAGE_ROWS, OVERVIEW_STATUS_BYTES, compareOverviewRows, validOverviewPage, validOverviewSearch, validOverviewView } from './complete-overview-types';
import type { OverviewComplete, OverviewPage, OverviewView } from './complete-overview-types';
import { processWatchCopy } from './linux-process-watches-copy';
import { PROCESS_WATCH_BYTES, processNameOrder, processWatchTime, validProcessWatchName, validProcessWatches } from './linux-process-watches-types';
import type { ProcessWatchesView } from './linux-process-watches-types';

/** Inventory retention is not watch freshness. Bind every page to the exact
 * reviewed watch generation, then recheck the current watch authority after it. */
export function matchingProcessOverview(overview: OverviewView, watch: ProcessWatchesView): OverviewComplete | null {
    const section = overview.processes, c = section.complete, g = watch.source.generation;
    if (!watch.clockReliable || !watch.canManage || watch.source.status !== 'available' || !g || section.status !== 'available' || c?.state !== 'complete') return null;
    const m = c.manifest, now = processWatchTime(overview.serverNow)!;
    if (c.binding.sequence !== g.sequence || c.binding.generationId !== g.generationId || c.binding.manifestHash !== g.manifestHash || m.captureStartedAt !== g.captureStartedAt || m.captureFinishedAt !== g.captureFinishedAt || c.completedAt !== g.receivedAt || m.observedCount !== g.totalRows || m.observedCount - m.processes.fieldCoverage.observed !== g.unidentifiedRows) return null;
    if (now < processWatchTime(watch.serverNow)! || now >= processWatchTime(watch.validUntil)! || now - processWatchTime(g.captureStartedAt)! >= 120000000000n || now - processWatchTime(g.receivedAt)! >= 120000000000n) return null;
    if (section.transfer && (BigInt(section.transfer.binding.sequence) > BigInt(g.sequence) || section.transfer.binding.sequence === g.sequence && section.transfer.state !== 'complete') || section.failure && BigInt(section.failure.sequence) >= BigInt(g.sequence)) return null;
    return c;
}
export function observedProcessNames(page: OverviewPage): string[] {
    return [...new Set(page.items.flatMap(row => row.process?.observation.status === 'observed' && validProcessWatchName(row.process.name) ? [row.process.name] : []))].sort(processNameOrder);
}

// Accessible-name whitespace normalization must not merge literal choices.
// Positions are Unicode character positions, not UTF-16 code-unit offsets.
export function processNameWhitespace(name: string): string {
    return Array.from(name).flatMap((point, index) => /\s/u.test(point) ? [`${index + 1} (U+${point.codePointAt(0)!.toString(16).toUpperCase().padStart(4, '0')})`] : []).join(', ');
}
type Copy = typeof processWatchCopy.en;
type PageState = { page: OverviewPage; query: string; scanned: number; names: string[]; mono: number; wall: number; lifetime: number };
function pageFresh(data: PageState): boolean {
    const m = performance.now() - data.mono, w = Date.now() - data.wall;
    return Number.isFinite(m) && Number.isFinite(w) && m >= 0 && w >= 0 && Math.abs(m - w) <= 1500 && Math.max(m, w) < data.lifetime;
}
export function LinuxProcessWatchChooser({ view, elapsed, selected, onChange, onAuthorityLost, c }: { view: ProcessWatchesView; elapsed: number; selected: string[] | null; onChange: (names: string[]) => void; onAuthorityLost: () => void; c: Copy }) {
    const uid = useId(), [search, setSearch] = useState(''), [data, setData] = useState<PageState | null>(null), [busy, setBusy] = useState(false), [failed, setFailed] = useState(false);
    const revoke = useRef(onAuthorityLost); revoke.current = onAuthorityLost;
    const latestElapsed = useRef(elapsed), isActive = useRef<() => boolean>(() => false); latestElapsed.current = elapsed;
    const commands = useRef({ read: (_query: string, _previous?: PageState) => {}, cancel: () => {} });
    useEffect(() => {
        let alive = true, serial = 0, operation: { controller: AbortController; timer: number } | null = null;
        const epoch = getProtectedRequestEpoch(), cursors = new Set<string>();
        const scoped = () => alive && epoch === getProtectedRequestEpoch() && !hasLogoutIntent() && document.visibilityState !== 'hidden' && document.hasFocus() && Number.isFinite(latestElapsed.current) && latestElapsed.current >= 0 && latestElapsed.current < Number(processWatchTime(view.validUntil)! - processWatchTime(view.serverNow)!) / 1000000;
        isActive.current = scoped;
        const clear = () => { serial++; operation?.controller.abort(); window.clearTimeout(operation?.timer); operation = null; };
        const run = async (query: string, previous?: PageState) => {
            if (!scoped() || !validOverviewSearch(query)) return;
            clear(); if (!previous) cursors.clear(); setData(null); setFailed(false); setBusy(true);
            const mine = serial, controller = new AbortController(), mono = performance.now(), wall = Date.now();
            const age = () => { const m = performance.now() - mono, w = Date.now() - wall; return m >= 0 && w >= 0 && Math.abs(m - w) <= 1500 ? Math.max(m, w) : Infinity; };
            const active = () => scoped() && mine === serial && !controller.signal.aborted && age() < 10000;
            operation = { controller, timer: window.setTimeout(() => { if (alive && mine === serial) { clear(); setData(null); setBusy(false); setFailed(true); } }, 10000) };
            try {
                const base = `/devices/${view.deviceId}`, options = { signal: controller.signal, cache: 'no-store' as const, redirect: 'error' as const };
                const inventory = await request<unknown>(`${base}/inventory/overview`, options, OVERVIEW_STATUS_BYTES);
                if (!active()) return;
                if (!validOverviewView(inventory, view.deviceId)) throw new Error('Invalid inventory');
                const complete = matchingProcessOverview(inventory, view);
                if (!complete) throw new Error('Different or stale generation');
                const cursor = previous?.page.nextCursor ?? '';
                if (previous && (!cursor || previous.query !== query || processWatchTime(inventory.serverNow)! < processWatchTime(previous.page.serverNow)! || processWatchTime(inventory.serverNow)! >= processWatchTime(previous.page.cursorExpiresAt)!)) throw new Error('Expired cursor');
                const page = await mutateRaw<unknown>(`${base}/inventory/overview/query`, JSON.stringify({ section: 'processes', generationId: complete.binding.generationId, cursor, search: query, limit: OVERVIEW_PAGE_ROWS }), {}, controller.signal, OVERVIEW_PAGE_BYTES, active);
                if (!active()) return;
                if (!validOverviewPage(page, view.deviceId, 'processes', complete, query, cursor) || processWatchTime(page.serverNow)! < processWatchTime(inventory.serverNow)!) throw new Error('Invalid page');
                const scanned = (previous?.scanned ?? 0) + page.scannedRows;
                if (scanned > page.totalRows || page.exhausted && scanned !== page.totalRows || previous && page.cursorExpiresAt !== previous.page.cursorExpiresAt || page.nextCursor && cursors.has(page.nextCursor) || previous?.page.items.length && page.items.length && compareOverviewRows(previous.page.items.at(-1)!, page.items[0]) >= 0) throw new Error('Invalid page continuation');
                // A newer incomplete attempt or replacement may arrive during
                // paging. The watch endpoint applies the strict source guards.
                const current = await request<unknown>(`${base}/linux-process-watches`, options, PROCESS_WATCH_BYTES);
                if (!active()) return;
                if (!validProcessWatches(current, view.deviceId)) throw new Error('Invalid source response');
                if (!current.canManage || current.source.token !== view.source.token) { revoke.current(); return; }
                if (current.revision !== view.revision || processWatchTime(current.serverNow)! < processWatchTime(page.serverNow)! || !matchingProcessOverview({ ...inventory, serverNow: current.serverNow }, view) || JSON.stringify(current.source.generation) !== JSON.stringify(view.source.generation) || current.source.status !== 'available') throw new Error('Source changed');
                if (page.nextCursor) cursors.add(page.nextCursor);
                const accepted = { page, query, scanned, names: observedProcessNames(page), mono, wall, lifetime: Number(processWatchTime(current.validUntil)! - processWatchTime(current.serverNow)!) / 1000000 };
                if (!pageFresh(accepted)) throw new Error('Expired page authority');
                setData(accepted);
            } catch (error) {
                if (active()) { setFailed(true); if (error instanceof APIError && error.status === 401) window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT)); }
            } finally { if (alive && mine === serial) { window.clearTimeout(operation?.timer); operation = null; setBusy(false); } }
        };
        commands.current = { read: (query, previous) => { void run(query, previous); }, cancel: () => { clear(); cursors.clear(); setBusy(false); setFailed(false); } };
        void run('');
        return () => { alive = false; isActive.current = () => false; clear(); commands.current = { read: () => {}, cancel: () => {} }; };
    }, [view]);
    const changeSearch = (value: string) => { commands.current.cancel(); setSearch(value); setData(null); };
    // Changing the query hides old results immediately. A response for the prior
    // query cannot expose names or supply a cursor for the new search.
    const visible = data?.query === search && pageFresh(data) && isActive.current() ? data : null;
    return <section className="process-watch-chooser" aria-labelledby={`${uid}-title`}>
        <h4 id={`${uid}-title`}>{c.chooserTitle}</h4><p>{c.chooserScope}</p>
        <label htmlFor={`${uid}-search`}>{c.chooserSearch}</label><input id={`${uid}-search`} value={search} maxLength={128} autoComplete="off" spellCheck={false} aria-describedby={`${uid}-search-help`} onChange={event => changeSearch(event.target.value)} onKeyDown={event => { if (event.key === 'Enter') { event.preventDefault(); event.stopPropagation(); if (validOverviewSearch(search)) commands.current.read(search); } }}/>
        <p id={`${uid}-search-help`}>{c.chooserSearchHelp}</p>
        <button type="button" className="text-button" disabled={!validOverviewSearch(search)} onClick={() => commands.current.read(search)}>{c.chooserSearchGo}</button>
        {!validOverviewSearch(search) && <p role="alert">{c.chooserSearchInvalid}</p>}
        {busy && <p role="status">{c.chooserLoading}</p>}{(failed || data?.query === search && !visible) && <p role="status">{c.chooserUnavailable}</p>}
        {visible && <><ul className="process-watch-options">{visible.names.map(name => { const whitespace = processNameWhitespace(name); return <li key={name}><label><input type="checkbox" aria-label={whitespace ? `${name} (${c.nameWhitespace}: ${whitespace})` : name} checked={selected?.includes(name) ?? false} disabled={selected === null || selected.length >= 8 && !selected.includes(name)} onChange={event => { if (selected === null || !isActive.current() || !pageFresh(visible)) return; onChange(event.target.checked ? [...new Set([...selected, name])].sort(processNameOrder) : selected.filter(value => value !== name)); }}/><bdi className="process-watch-name">{name}</bdi>{whitespace && <small>{c.nameWhitespace}: {whitespace}</small>}</label></li>; })}</ul>
            {visible.names.length === 0 && <p>{c.chooserEmpty}</p>}{!visible.page.exhausted && <button type="button" className="text-button" onClick={() => commands.current.read(search, visible)}>{c.chooserNext}</button>}
        </>}{selected !== null && selected.length >= 8 && <p role="status">{c.chooserLimit}</p>}
    </section>;
}
