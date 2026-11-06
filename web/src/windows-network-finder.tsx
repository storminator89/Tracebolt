import { useId, useMemo } from 'react';
import type { WindowsNetwork } from './windows-network-types';
import { findNetworkEndpoints, initialNetworkFinderControls, networkEndpointLabel, networkPID, networkQueryError, type NetworkFinderControls } from './windows-network-finder-model';
import './windows-inventory-tables.css';

const copy = {
    en: {
        search: 'Find captured endpoints', placeholder: 'Address, port, PID or TCP state', field: 'Search by', any: 'Any value', address: 'Address', 'local-port': 'Exact local port', 'remote-port': 'Exact remote port', pid: 'Exact API PID',
        filter: 'Show endpoints', all: 'All endpoints', tcp: 'TCP', listeners: 'TCP listeners', established: 'TCP established', udp: 'UDP', family: 'IP version', allFamilies: 'IPv4 and IPv6',
        sort: 'Sort endpoints', capture: 'Capture order', 'local-port-asc': 'Local port · lowest first', 'local-port-desc': 'Local port · highest first', 'remote-port-asc': 'Remote port · lowest first', 'remote-port-desc': 'Remote port · highest first', 'pid-asc': 'API PID · lowest first', 'pid-desc': 'API PID · highest first', clear: 'Clear endpoint filters',
        scope: 'Search only the retained snapshot, not the live device. No match does not prove a port is free or an endpoint absent. Any value and Address use literal, case-insensitive matching; port and PID fields match exact numbers.',
        portError: 'Enter a whole port number from 0 to 65535.', pidError: 'Enter a whole PID from 0 to 4294967295. UDP PID 0 is unavailable and cannot match.',
        noMatches: 'No retained endpoints match these filters.', protocol: 'Protocol', local: 'Local endpoint', remote: 'Remote endpoint', state: 'TCP state', apiPID: 'API owning PID', unavailable: 'Unavailable', notApplicable: 'Not applicable', title: 'Network',
        previous: 'Previous endpoint page', next: 'Next endpoint page', pages: 'Captured endpoint pages',
        count: (start: number, end: number, matches: number, retained: number) => `${start}–${end} of ${matches} matches · ${retained} retained`, page: (current: number, pages: number) => `Page ${current} of ${pages}`,
    },
    de: {
        search: 'Erfasste Endpunkte finden', placeholder: 'Adresse, Port, PID oder TCP-Zustand', field: 'Suchen nach', any: 'Beliebiger Wert', address: 'Adresse', 'local-port': 'Exakter lokaler Port', 'remote-port': 'Exakter entfernter Port', pid: 'Exakte API-PID',
        filter: 'Endpunkte anzeigen', all: 'Alle Endpunkte', tcp: 'TCP', listeners: 'TCP-Listener', established: 'TCP hergestellt', udp: 'UDP', family: 'IP-Version', allFamilies: 'IPv4 und IPv6',
        sort: 'Endpunkte sortieren', capture: 'Erfassungsreihenfolge', 'local-port-asc': 'Lokaler Port · niedrigste zuerst', 'local-port-desc': 'Lokaler Port · höchste zuerst', 'remote-port-asc': 'Entfernter Port · niedrigste zuerst', 'remote-port-desc': 'Entfernter Port · höchste zuerst', 'pid-asc': 'API-PID · niedrigste zuerst', 'pid-desc': 'API-PID · höchste zuerst', clear: 'Endpunktfilter zurücksetzen',
        scope: 'Suche nur im gespeicherten Snapshot, nicht auf dem aktuellen Gerät. Eine Suche ohne Treffer belegt weder einen freien Port noch einen fehlenden Endpunkt. Beliebiger Wert und Adresse suchen wörtlich ohne Beachtung der Groß-/Kleinschreibung; Port und PID suchen exakte Zahlen.',
        portError: 'Eine ganze Portnummer von 0 bis 65535 eingeben.', pidError: 'Eine ganze PID von 0 bis 4294967295 eingeben. UDP-PID 0 ist nicht verfügbar und kann kein Treffer sein.',
        noMatches: 'Keine gespeicherten Endpunkte entsprechen diesen Filtern.', protocol: 'Protokoll', local: 'Lokaler Endpunkt', remote: 'Entfernter Endpunkt', state: 'TCP-Zustand', apiPID: 'Besitzende PID laut API', unavailable: 'Nicht verfügbar', notApplicable: 'Nicht anwendbar', title: 'Netzwerk',
        previous: 'Vorherige Endpunktseite', next: 'Nächste Endpunktseite', pages: 'Seiten der erfassten Endpunkte',
        count: (start: number, end: number, matches: number, retained: number) => `${start}–${end} von ${matches} Treffern · ${retained} gespeichert`, page: (current: number, pages: number) => `Seite ${current} von ${pages}`,
    },
};
export function WindowsNetworkFinder({ network, locale, controls, onChange }: { network: WindowsNetwork; locale: 'en' | 'de'; controls: NetworkFinderControls; onChange: (next: NetworkFinderControls) => void }) {
    const c = copy[locale], id = useId(), rows = useMemo(() => findNetworkEndpoints(network, controls), [network, controls]);
    const error = networkQueryError(controls), pages = Math.max(1, Math.ceil(rows.length / 25)), page = Math.min(controls.page, pages - 1), start = page * 25, visible = rows.slice(start, start + 25);
    const change = (next: Partial<NetworkFinderControls>) => onChange({ ...controls, ...next, page: 0 });
    const headers = [c.protocol, c.family, c.local, c.remote, c.state, c.apiPID], sortedColumn = controls.sort.startsWith('local-port') ? 2 : controls.sort.startsWith('remote-port') ? 3 : controls.sort.startsWith('pid') ? 5 : -1;
    const selection = <K extends 'field' | 'filter' | 'family' | 'sort'>(key: K, label: string, values: readonly NetworkFinderControls[K][]) => <div className="windows-inventory-table-sort"><label htmlFor={`${id}-${key}`}>{label}</label><select id={`${id}-${key}`} value={controls[key]} onChange={event => change({ [key]: event.target.value })}>{values.map(value => <option key={value} value={value}>{key === 'family' ? value === 'all' ? c.allFamilies : value === 'ipv4' ? 'IPv4' : 'IPv6' : c[value as keyof Omit<typeof c, 'count' | 'page'>]}</option>)}</select></div>;
    return <>
        <p className="windows-inventory-exclusions" id={`${id}-scope`}>{c.scope}</p>
        <div className="windows-inventory-table-controls">
            <label className="windows-inventory-search" htmlFor={`${id}-query`}>{c.search}<input id={`${id}-query`} type="search" value={controls.query} autoComplete="off" spellCheck={false} maxLength={256} placeholder={c.placeholder} aria-describedby={`${id}-scope${error ? ` ${id}-error` : ''}`} aria-invalid={error ? true : undefined} onChange={event => change({ query: event.target.value.slice(0, 256) })}/></label>
            {selection('field', c.field, ['any', 'address', 'local-port', 'remote-port', 'pid'])}
            {selection('filter', c.filter, ['all', 'tcp', 'listeners', 'established', 'udp'])}
            {selection('family', c.family, ['all', 'ipv4', 'ipv6'])}
            {selection('sort', c.sort, ['capture', 'local-port-asc', 'local-port-desc', 'remote-port-asc', 'remote-port-desc', 'pid-asc', 'pid-desc'])}
            <button type="button" className="button small" disabled={!controls.query && controls.field === 'any' && controls.filter === 'all' && controls.family === 'all' && controls.sort === 'capture' && controls.page === 0} onClick={() => onChange(initialNetworkFinderControls())}>{c.clear}</button>
        </div>
        {error ? <p role="alert" id={`${id}-error`}>{error === 'port' ? c.portError : c.pidError}</p> : <>
            <p className="windows-inventory-count" role="status" aria-live="polite" aria-atomic="true">{c.count(visible.length ? start + 1 : 0, start + visible.length, rows.length, network.rows.length)}</p>
            {visible.length ? <div className="windows-inventory-table-wrap"><table className="windows-inventory-table"><caption className="sr-only">{c.title}</caption><thead><tr>{headers.map((header, col) => <th key={header} scope="col" aria-sort={col === sortedColumn ? controls.sort.endsWith('desc') ? 'descending' : 'ascending' : undefined}>{header}</th>)}</tr></thead><tbody>{visible.map((row, index) => {
                const cells = [row.protocol.toUpperCase(), row.family === 'ipv4' ? 'IPv4' : 'IPv6', networkEndpointLabel(row.localAddress, row.localPort), row.remoteAddress === null || row.remotePort === null ? c.notApplicable : networkEndpointLabel(row.remoteAddress, row.remotePort), row.state ?? c.notApplicable, networkPID(row) === null ? c.unavailable : String(row.pid)];
                return <tr key={start + index}>{cells.map((cell, col) => <td key={col} data-label={headers[col]}>{cell}</td>)}</tr>;
            })}</tbody></table></div> : <p className="windows-inventory-empty">{c.noMatches}</p>}
            {rows.length > 25 && <nav className="windows-inventory-table-pagination" aria-label={c.pages}><button type="button" className="button small" disabled={page === 0} onClick={() => onChange({ ...controls, page: page - 1 })}>{c.previous}</button><span>{c.page(page + 1, pages)}</span><button type="button" className="button small" disabled={page + 1 >= pages} onClick={() => onChange({ ...controls, page: page + 1 })}>{c.next}</button></nav>}
        </>}
    </>;
}
