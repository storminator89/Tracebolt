import { useId, useState } from 'react';
import type { WindowsInventoryResource } from './windows-inventory-resource';
import type { WindowsInventorySnapshot } from './windows-inventory-types';
import './windows-inventory-tables.css';

const PAGE_SIZE = 25;
export type WindowsInventoryTableKind = 'services' | 'software';
const sorts = {
    services: ['name-asc', 'name-desc', 'pid-asc', 'pid-desc', 'state-asc', 'state-desc'],
    software: ['name-asc', 'name-desc', 'version-asc', 'version-desc', 'publisher-asc', 'publisher-desc'],
} as const;
export type WindowsInventoryTableSort = typeof sorts[WindowsInventoryTableKind][number];
const copy = {
    en: {
        services: 'Services', software: 'Software', name: 'Name', displayName: 'Display name', state: 'State', version: 'Version', publisher: 'Publisher', registry: 'Registry view', unknown: 'Not reported',
        servicesSearch: 'Filter captured services', softwareSearch: 'Filter captured software', servicesSort: 'Sort captured services', softwareSort: 'Sort captured software',
        'name-asc': 'Name: A to Z', 'name-desc': 'Name: Z to A', 'pid-asc': 'PID: lowest first', 'pid-desc': 'PID: highest first', 'state-asc': 'State: A to Z', 'state-desc': 'State: Z to A',
        'version-asc': 'Version text: A to Z', 'version-desc': 'Version text: Z to A', 'publisher-asc': 'Publisher: A to Z', 'publisher-desc': 'Publisher: Z to A',
        servicesBounded: 'Search, sorting and pages apply only to this bounded snapshot, with at most 128 captured service rows. Other services may be omitted. Startup mode and service configuration are not collected.',
        softwareBounded: 'Search, sorting and pages apply only to this bounded snapshot, with at most 128 captured machine uninstall registrations. Other software may be omitted. Versions are sorted as text, not by update order.',
        noMatches: 'No captured rows match this filter.', previous: 'Previous page', next: 'Next page', servicesPages: 'Captured service pages', softwarePages: 'Captured software pages',
        count: (start: number, end: number, matches: number, captured: number) => `Rows ${start}–${end} of ${matches} matching · ${captured} captured`,
        page: (current: number, total: number) => `Page ${current} of ${total}`,
        stopped: 'Stopped', start_pending: 'Starting', stop_pending: 'Stopping', running: 'Running', continue_pending: 'Resuming', pause_pending: 'Pausing', paused: 'Paused',
    },
    de: {
        services: 'Dienste', software: 'Software', name: 'Name', displayName: 'Anzeigename', state: 'Zustand', version: 'Version', publisher: 'Herausgeber', registry: 'Registrierungsansicht', unknown: 'Nicht gemeldet',
        servicesSearch: 'Erfasste Dienste filtern', softwareSearch: 'Erfasste Software filtern', servicesSort: 'Erfasste Dienste sortieren', softwareSort: 'Erfasste Software sortieren',
        'name-asc': 'Name: A bis Z', 'name-desc': 'Name: Z bis A', 'pid-asc': 'PID: niedrigste zuerst', 'pid-desc': 'PID: höchste zuerst', 'state-asc': 'Zustand: A bis Z', 'state-desc': 'Zustand: Z bis A',
        'version-asc': 'Versionstext: A bis Z', 'version-desc': 'Versionstext: Z bis A', 'publisher-asc': 'Herausgeber: A bis Z', 'publisher-desc': 'Herausgeber: Z bis A',
        servicesBounded: 'Suche, Sortierung und Seiten gelten nur für diesen begrenzten Snapshot mit höchstens 128 erfassten Dienstzeilen. Weitere Dienste können fehlen. Starttyp und Dienstkonfiguration werden nicht erfasst.',
        softwareBounded: 'Suche, Sortierung und Seiten gelten nur für diesen begrenzten Snapshot mit höchstens 128 erfassten maschinenweiten Deinstallationsregistrierungen. Weitere Software kann fehlen. Versionen werden als Text sortiert, nicht nach Updatereihenfolge.',
        noMatches: 'Keine erfassten Zeilen entsprechen diesem Filter.', previous: 'Vorherige Seite', next: 'Nächste Seite', servicesPages: 'Seiten der erfassten Dienste', softwarePages: 'Seiten der erfassten Software',
        count: (start: number, end: number, matches: number, captured: number) => `Zeilen ${start}–${end} von ${matches} Treffern · ${captured} erfasst`,
        page: (current: number, total: number) => `Seite ${current} von ${total}`,
        stopped: 'Gestoppt', start_pending: 'Wird gestartet', stop_pending: 'Wird gestoppt', running: 'Läuft', continue_pending: 'Wird fortgesetzt', pause_pending: 'Wird pausiert', paused: 'Pausiert',
    },
};
type Locale = 'en' | 'de';
type Row = { cells: string[]; order: string | number; tie: string; index: number; search: string[] };
const literalCompare = (a: string, b: string) => a < b ? -1 : a > b ? 1 : 0;

/** Sort source numbers numerically and source text literally. No version parsing,
 * cross-generation cache, backend search, row deduplication or source mutation. */
export function capturedInventoryTableRows(snapshot: WindowsInventorySnapshot, kind: WindowsInventoryTableKind, query: string, sort: WindowsInventoryTableSort, locale: Locale) {
    const c = copy[locale], unknown = (value: string) => value || c.unknown;
    const filter = query.trim().toLocaleLowerCase(locale), descending = sort.endsWith('-desc');
    const rows: Row[] = kind === 'services' ? snapshot.services.rows.map((row, index) => ({
        cells: [row.name, unknown(row.displayName), c[row.state], String(row.pid)],
        order: sort.startsWith('pid-') ? row.pid : sort.startsWith('state-') ? c[row.state] : row.name,
        tie: JSON.stringify([row.name, row.displayName, row.state, row.pid]), index,
        search: [row.name, row.displayName, row.state, c[row.state], String(row.pid)],
    })) : snapshot.software.rows.map((row, index) => ({
        cells: [row.name, unknown(row.version), unknown(row.publisher), `${row.registryView}-bit`],
        order: sort.startsWith('version-') ? row.version : sort.startsWith('publisher-') ? row.publisher : row.name,
        tie: JSON.stringify([row.name, row.version, row.publisher, row.registryView]), index,
        search: [row.name, row.version, row.publisher, row.registryView, `${row.registryView}-bit`],
    }));
    return rows.filter(row => row.search.some(value => value.toLocaleLowerCase(locale).includes(filter))).sort((a, b) => {
        // Empty source fields stay last in either direction; the placeholder is
        // display text and must not be treated as a reported value.
        if (a.order === '' || b.order === '') return a.order === b.order ? literalCompare(a.tie, b.tie) || a.index - b.index : a.order === '' ? 1 : -1;
        const order = typeof a.order === 'number' && typeof b.order === 'number' ? a.order - b.order : String(a.order).localeCompare(String(b.order), locale, { numeric: false });
        return order * (descending ? -1 : 1) || literalCompare(a.tie, b.tie) || a.index - b.index;
    });
}
interface TableControls { query: string; sort: WindowsInventoryTableSort; page: number }
const initialControls = (): TableControls => ({ query: '', sort: 'name-asc', page: 0 });
/** Retain only controls during a same-generation reread, while the resource hides
 * all rows. Tab departure, nonloading absence and a changed identity/capture
 * discard the controls before paint. The owner keys the workspace by session. */
export function useWindowsInventoryTableControls(resource: WindowsInventoryResource, kind: WindowsInventoryTableKind | null) {
    const snapshot = resource.snapshot;
    const scope = kind && snapshot ? `${resource.view?.deviceId}:${snapshot.generationId}:${snapshot.collectedAt}:${kind}` : null;
    const [state, setState] = useState<TableControls & { scope: string | null; kind: WindowsInventoryTableKind | null }>(() => ({ ...initialControls(), scope, kind }));
    const reset = state.kind !== kind || (scope !== null ? state.scope !== scope : !(kind && resource.loading) && state.scope !== null);
    const current = reset ? { ...initialControls(), scope, kind } : state;
    if (reset) setState(current);
    return [current, (controls: TableControls) => setState({ ...controls, scope: current.scope, kind })] as const;
}

/** All data comes from the already validated, admitted current inventory view. */
export function WindowsInventoryTable({ snapshot, kind, locale, controls, onChange }: { snapshot: WindowsInventorySnapshot; kind: WindowsInventoryTableKind; locale: Locale; controls: TableControls; onChange: (controls: TableControls) => void }) {
    const id = useId(), c = copy[locale], { query, sort, page } = controls;
    const rows = capturedInventoryTableRows(snapshot, kind, query, sort, locale);
    const pageCount = Math.max(1, Math.ceil(rows.length / PAGE_SIZE)), currentPage = Math.min(page, pageCount - 1), start = currentPage * PAGE_SIZE, visible = rows.slice(start, start + PAGE_SIZE);
    const headers = kind === 'services' ? [c.name, c.displayName, c.state, 'PID'] : [c.name, c.version, c.publisher, c.registry];
    const sortedColumn = sort.startsWith('name-') ? 0 : sort.startsWith('pid-') ? 3 : sort.startsWith('version-') ? 1 : 2;
    return <>
        <p className="windows-inventory-exclusions" id={`${id}-bounds`}>{c[`${kind}Bounded`]}</p>
        <div className="windows-inventory-table-controls">
            <label className="windows-inventory-search" htmlFor={`${id}-search`}>{c[`${kind}Search`]}<input id={`${id}-search`} type="search" maxLength={256} value={query} aria-describedby={`${id}-bounds`} onChange={event => onChange({ ...controls, query: event.target.value, page: 0 })}/></label>
            <div className="windows-inventory-table-sort"><label htmlFor={`${id}-sort`}>{c[`${kind}Sort`]}</label><select id={`${id}-sort`} value={sort} aria-describedby={`${id}-bounds`} onChange={event => onChange({ ...controls, sort: event.target.value as WindowsInventoryTableSort, page: 0 })}>{sorts[kind].map(value => <option key={value} value={value}>{c[value]}</option>)}</select></div>
        </div>
        <p className="windows-inventory-count" role="status" aria-live="polite" aria-atomic="true">{c.count(visible.length ? start + 1 : 0, start + visible.length, rows.length, snapshot[kind].rows.length)}</p>
        {visible.length ? <div className="windows-inventory-table-wrap"><table className="windows-inventory-table"><caption className="sr-only">{c[kind]}</caption><thead><tr>{headers.map((header, column) => <th key={header} scope="col" aria-sort={column === sortedColumn ? sort.endsWith('-desc') ? 'descending' : 'ascending' : undefined}>{header}</th>)}</tr></thead><tbody>{visible.map(row => <tr key={row.index}>{row.cells.map((value, column) => <td key={column} data-label={headers[column]}>{value}</td>)}</tr>)}</tbody></table></div> : <p>{c.noMatches}</p>}
        <nav className="windows-inventory-table-pagination" aria-label={c[`${kind}Pages`]}>
            <button type="button" className="button small" disabled={currentPage === 0} onClick={() => onChange({ ...controls, page: currentPage - 1 })}>{c.previous}</button>
            <span>{c.page(currentPage + 1, pageCount)}</span>
            <button type="button" className="button small" disabled={currentPage + 1 >= pageCount} onClick={() => onChange({ ...controls, page: currentPage + 1 })}>{c.next}</button>
        </nav>
    </>;
}
