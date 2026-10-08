import { useId, useState } from 'react';
import { processMetricCells, processMetricsCopy } from './windows-process-metrics';
import type { WindowsInventoryResource } from './windows-inventory-resource';
import type { WindowsInventorySnapshot } from './windows-inventory-types';
import type { WindowsProcessMetric, WindowsProcessMetrics } from './windows-process-metrics-types';
import './windows-processes.css';

const PAGE_SIZE = 25;
const copy = {
    en: {
        title: 'Processes', name: 'Name', parent: 'Parent PID', threads: 'Threads', search: 'Filter captured processes by name or PID', sort: 'Sort captured processes',
        'pid-asc': 'PID: lowest first', 'pid-desc': 'PID: highest first', 'name-asc': 'Name: A to Z', 'name-desc': 'Name: Z to A',
        'cpu-desc': 'CPU: highest first', 'cpu-asc': 'CPU: lowest first', 'ram-desc': 'Working-set RAM: highest first', 'ram-asc': 'Working-set RAM: lowest first',
        bounded: 'Search, sorting and pages apply only to this bounded snapshot, with at most 128 captured process rows. Other device processes may be omitted. Unavailable measurements sort last.',
        noMatches: 'No captured processes match this filter.', previous: 'Previous page', next: 'Next page', pagination: 'Captured process pages',
        count: (start: number, end: number, matches: number, captured: number) => `Rows ${start}–${end} of ${matches} matching · ${captured} captured`,
        page: (current: number, total: number) => `Page ${current} of ${total}`,
    },
    de: {
        title: 'Prozesse', name: 'Name', parent: 'Übergeordnete PID', threads: 'Threads', search: 'Erfasste Prozesse nach Name oder PID filtern', sort: 'Erfasste Prozesse sortieren',
        'pid-asc': 'PID: niedrigste zuerst', 'pid-desc': 'PID: höchste zuerst', 'name-asc': 'Name: A bis Z', 'name-desc': 'Name: Z bis A',
        'cpu-desc': 'CPU: höchste zuerst', 'cpu-asc': 'CPU: niedrigste zuerst', 'ram-desc': 'RAM-Arbeitssatz: größter zuerst', 'ram-asc': 'RAM-Arbeitssatz: kleinster zuerst',
        bounded: 'Suche, Sortierung und Seiten gelten nur für diesen begrenzten Snapshot mit höchstens 128 erfassten Prozesszeilen. Weitere Prozesse des Geräts können fehlen. Nicht verfügbare Messwerte stehen zuletzt.',
        noMatches: 'Keine erfassten Prozesse entsprechen diesem Filter.', previous: 'Vorherige Seite', next: 'Nächste Seite', pagination: 'Seiten der erfassten Prozesse',
        count: (start: number, end: number, matches: number, captured: number) => `Zeilen ${start}–${end} von ${matches} Treffern · ${captured} erfasst`,
        page: (current: number, total: number) => `Seite ${current} von ${total}`,
    },
};
const sorts = ['pid-asc', 'pid-desc', 'name-asc', 'name-desc', 'cpu-desc', 'cpu-asc', 'ram-desc', 'ram-asc'] as const;
export type WindowsProcessSort = typeof sorts[number];

// Compare source numbers, never their localized display cells. Missing values stay
// last in either direction; uint64 working sets must not round through Number.
function measurementCompare(a: number | bigint | null, b: number | bigint | null, descending: boolean): number {
    if (a === null) return b === null ? 0 : 1;
    if (b === null) return -1;
    const order = a < b ? -1 : a > b ? 1 : 0;
    return descending ? -order : order;
}
const cpu = (metric?: WindowsProcessMetric) => metric?.cpuQuality === 'observed' ? metric.cpuPercent : null;
const ram = (metric?: WindowsProcessMetric) => metric?.memoryQuality === 'observed' && metric.memoryBytes !== null ? BigInt(metric.memoryBytes) : null;
export function capturedProcessRows(snapshot: WindowsInventorySnapshot, metrics: WindowsProcessMetrics | null | undefined, query: string, sort: WindowsProcessSort, locale: 'en' | 'de') {
    const byPid = new Map(metrics?.generationId === snapshot.generationId ? metrics.rows.map(metric => [metric.pid, metric]) : []);
    const filter = query.trim().toLocaleLowerCase(locale), descending = sort.endsWith('-desc');
    return snapshot.processes.rows.filter(row => row.name.toLocaleLowerCase(locale).includes(filter) || String(row.pid).includes(filter))
        .map(process => ({ process, metric: byPid.get(process.pid) }))
        .sort((a, b) => {
            let order: number;
            if (sort.startsWith('cpu-')) order = measurementCompare(cpu(a.metric), cpu(b.metric), descending);
            else if (sort.startsWith('ram-')) order = measurementCompare(ram(a.metric), ram(b.metric), descending);
            else if (sort.startsWith('name-')) order = a.process.name.localeCompare(b.process.name, locale) * (descending ? -1 : 1);
            else order = (a.process.pid - b.process.pid) * (descending ? -1 : 1);
            return order || a.process.pid - b.process.pid;
        });
}

interface ProcessControls { query: string; sort: WindowsProcessSort; page: number }
const initialControls = (): ProcessControls => ({ query: '', sort: 'pid-asc', page: 0 });
/** Retain view controls, never rows, while a same-snapshot reread is loading.
 * The workspace is device/session-keyed by its owner. Any non-loading absence,
 * tab departure or new original snapshot clears potentially private filter text. */
export function useWindowsProcessControls(resource: WindowsInventoryResource, active: boolean) {
    const snapshot = resource.snapshot;
    const scope = active && snapshot ? `${resource.view?.deviceId}:${snapshot.generationId}:${snapshot.collectedAt}` : null;
    const [state, setState] = useState<ProcessControls & { scope: string | null }>(() => ({ ...initialControls(), scope }));
    const reset = scope !== null ? state.scope !== scope : !(active && resource.loading) && state.scope !== null;
    const current = reset ? { ...initialControls(), scope } : state;
    // Reset during render so new-source controls are never committed with old text.
    if (reset) setState(current);
    return [current, (controls: ProcessControls) => setState({ ...controls, scope: current.scope })] as const;
}

/** No requests or persistence: all rows come from the currently admitted resource. */
export function WindowsProcessTable({ snapshot, metrics, locale, controls, onChange }: { snapshot: WindowsInventorySnapshot; metrics: WindowsProcessMetrics | null; locale: 'en' | 'de'; controls: ProcessControls; onChange: (controls: ProcessControls) => void }) {
    const id = useId(), c = copy[locale], { query, sort, page } = controls;
    const rows = capturedProcessRows(snapshot, metrics, query, sort, locale);
    const pageCount = Math.max(1, Math.ceil(rows.length / PAGE_SIZE)), currentPage = Math.min(page, pageCount - 1);
    const start = currentPage * PAGE_SIZE, visible = rows.slice(start, start + PAGE_SIZE);
    const headers = [c.name, 'PID', c.parent, c.threads, processMetricsCopy[locale].cpu, processMetricsCopy[locale].ram];
    return <>
        <p className="windows-inventory-exclusions" id={`${id}-bounds`}>{c.bounded}</p>
        <div className="windows-process-controls">
            <label className="windows-inventory-search" htmlFor={`${id}-search`}>{c.search}<input id={`${id}-search`} type="search" value={query} maxLength={256} aria-describedby={`${id}-bounds`} onChange={event => { onChange({ ...controls, query: event.target.value, page: 0 }); }}/></label>
            <label className="windows-process-sort" htmlFor={`${id}-sort`}>{c.sort}<select id={`${id}-sort`} value={sort} onChange={event => { onChange({ ...controls, sort: event.target.value as WindowsProcessSort, page: 0 }); }}>{sorts.map(value => <option key={value} value={value}>{c[value]}</option>)}</select></label>
        </div>
        <p className="windows-inventory-count" role="status" aria-live="polite" aria-atomic="true">{c.count(visible.length ? start + 1 : 0, start + visible.length, rows.length, snapshot.processes.rows.length)}</p>
        {visible.length ? <div className="windows-inventory-table-wrap"><table className="windows-inventory-table"><caption className="sr-only">{c.title}</caption><thead><tr>{headers.map((header, column) => <th key={header} scope="col" aria-sort={column === 0 && sort.startsWith('name-') || column === 1 && sort.startsWith('pid-') || column === 4 && sort.startsWith('cpu-') || column === 5 && sort.startsWith('ram-') ? sort.endsWith('-desc') ? 'descending' : 'ascending' : undefined}>{header}</th>)}</tr></thead><tbody>{visible.map(({ process, metric }, index) => <tr key={`${process.pid}:${index}`}>{[process.name, String(process.pid), String(process.parentPid), String(process.threads), ...processMetricCells(metric, locale)].map((value, column) => <td key={column} data-label={headers[column]}>{value}</td>)}</tr>)}</tbody></table></div> : <p>{c.noMatches}</p>}
        <nav className="windows-process-pagination" aria-label={c.pagination}>
            <button type="button" className="button small" disabled={currentPage === 0} onClick={() => onChange({ ...controls, page: currentPage - 1 })}>{c.previous}</button>
            <span>{c.page(currentPage + 1, pageCount)}</span>
            <button type="button" className="button small" disabled={currentPage + 1 >= pageCount} onClick={() => onChange({ ...controls, page: currentPage + 1 })}>{c.next}</button>
        </nav>
    </>;
}
