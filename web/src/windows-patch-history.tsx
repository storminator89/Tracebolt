import { useId, useState } from 'react';
import { fullDate } from './utils';
import { initialPatchHistoryFilters, patchHistoryPage } from './windows-patch-history-model';
import type { PatchHistoryFilters } from './windows-patch-history-model';
import type { WindowsPatchHistoryRow } from './windows-patch-context-types';

const copy = {
    en: {
        controls: 'Review retained update events', search: 'Search retained events', placeholder: 'Update title, ID or HRESULT', result: 'Event result', operation: 'Event operation',
        allResults: 'All results', allOperations: 'All operations', from: 'From (UTC)', through: 'Through (UTC)', order: 'Event order', newest: 'Newest first', oldest: 'Oldest first', clear: 'Clear filters',
        dates: 'Dates filter recorded event times in UTC, including both selected days.', invalid: 'Choose valid UTC dates with the start on or before the end.',
        matches: (matched: number, retained: number) => `${matched} matching of ${retained} retained rows`,
        bounds: 'Filters cover only these retained rows. Omitted or cleared history is not searched.', empty: 'No retained rows match these filters. This does not prove that an update is absent or succeeded.',
        history: 'Retained update history', rowTitle: 'Update', occurred: 'Recorded at', operationColumn: 'Operation', resultColumn: 'Result', details: 'Details', revision: 'Revision', shortened: 'Title shortened',
        installation: 'Installation', uninstallation: 'Uninstallation', 'not-started': 'Not started', 'in-progress': 'In progress', succeeded: 'Succeeded', 'succeeded-with-errors': 'Succeeded with errors', failed: 'Failed', aborted: 'Aborted',
        previous: 'Previous events', next: 'Next events', page: (page: number, pages: number, start: number, end: number) => `Page ${page} of ${pages} · rows ${start}–${end}`,
    },
    de: {
        controls: 'Gespeicherte Updateereignisse prüfen', search: 'Gespeicherte Ereignisse durchsuchen', placeholder: 'Updatetitel, ID oder HRESULT', result: 'Ereignisergebnis', operation: 'Ereignisvorgang',
        allResults: 'Alle Ergebnisse', allOperations: 'Alle Vorgänge', from: 'Von (UTC)', through: 'Bis einschließlich (UTC)', order: 'Ereignisreihenfolge', newest: 'Neueste zuerst', oldest: 'Älteste zuerst', clear: 'Filter leeren',
        dates: 'Die Datumsfilter gelten für aufgezeichnete Ereigniszeiten in UTC, einschließlich beider gewählter Tage.', invalid: 'Gültige UTC-Daten wählen; der Beginn darf nicht nach dem Ende liegen.',
        matches: (matched: number, retained: number) => `${matched} passende von ${retained} gespeicherten Zeilen`,
        bounds: 'Filter durchsuchen nur diese gespeicherten Zeilen. Ausgelassener oder gelöschter Verlauf wird nicht durchsucht.', empty: 'Keine gespeicherten Zeilen passen zu diesen Filtern. Das belegt weder das Fehlen noch den Erfolg eines Updates.',
        history: 'Gespeicherter Updateverlauf', rowTitle: 'Update', occurred: 'Aufgezeichnet am', operationColumn: 'Vorgang', resultColumn: 'Ergebnis', details: 'Details', revision: 'Revision', shortened: 'Titel gekürzt',
        installation: 'Installation', uninstallation: 'Deinstallation', 'not-started': 'Nicht gestartet', 'in-progress': 'Läuft', succeeded: 'Erfolgreich', 'succeeded-with-errors': 'Mit Fehlern abgeschlossen', failed: 'Fehlgeschlagen', aborted: 'Abgebrochen',
        previous: 'Vorherige Ereignisse', next: 'Weitere Ereignisse', page: (page: number, pages: number, start: number, end: number) => `Seite ${page} von ${pages} · Zeilen ${start}–${end}`,
    },
};
const results = ['failed', 'succeeded-with-errors', 'aborted', 'succeeded', 'in-progress', 'not-started'] as const;

/** Mounted only while its original private source is visible. The parent key
 * separates devices, grants and captures, including retained earlier captures. */
export function WindowsPatchHistory({ rows, locale }: { rows: readonly WindowsPatchHistoryRow[]; locale: 'en' | 'de' }) {
    const c = copy[locale], id = useId(), [filters, setFilters] = useState(initialPatchHistoryFilters);
    const result = patchHistoryPage(rows, filters);
    const change = (patch: Partial<PatchHistoryFilters>) => setFilters(current => ({ ...current, ...patch, page: 0 }));
    const headers = [c.rowTitle, c.occurred, c.operationColumn, c.resultColumn];
    return <div className="windows-patch-history-review">
        <div className="windows-patch-history-controls" role="group" aria-label={c.controls}>
            <label className="windows-patch-history-search" htmlFor={`${id}-search`}>{c.search}<input id={`${id}-search`} type="search" maxLength={256} autoComplete="off" value={filters.query} placeholder={c.placeholder} onChange={event => change({ query: event.target.value })}/></label>
            <label htmlFor={`${id}-result`}>{c.result}<select id={`${id}-result`} value={filters.result} onChange={event => change({ result: event.target.value as PatchHistoryFilters['result'] })}><option value="all">{c.allResults}</option>{results.map(value => <option key={value} value={value}>{c[value]}</option>)}</select></label>
            <label htmlFor={`${id}-operation`}>{c.operation}<select id={`${id}-operation`} value={filters.operation} onChange={event => change({ operation: event.target.value as PatchHistoryFilters['operation'] })}><option value="all">{c.allOperations}</option><option value="installation">{c.installation}</option><option value="uninstallation">{c.uninstallation}</option></select></label>
            <label htmlFor={`${id}-from`}>{c.from}<input id={`${id}-from`} type="date" min="1970-01-01" max="9999-12-31" value={filters.from} aria-describedby={`${id}-dates`} onChange={event => change({ from: event.target.value })}/></label>
            <label htmlFor={`${id}-through`}>{c.through}<input id={`${id}-through`} type="date" min="1970-01-01" max="9999-12-31" value={filters.through} aria-describedby={`${id}-dates`} onChange={event => change({ through: event.target.value })}/></label>
            <label htmlFor={`${id}-order`}>{c.order}<select id={`${id}-order`} value={filters.order} onChange={event => change({ order: event.target.value as PatchHistoryFilters['order'] })}><option value="newest">{c.newest}</option><option value="oldest">{c.oldest}</option></select></label>
            <button type="button" className="button" onClick={() => setFilters(initialPatchHistoryFilters())}>{c.clear}</button>
        </div>
        <p id={`${id}-dates`} className="windows-inventory-exclusions">{c.dates}</p>
        {result.invalidDates ? <p role="alert" className="windows-inventory-caution">{c.invalid}</p> : <>
            <p role="status" className="windows-inventory-count">{c.matches(result.total, rows.length)}</p>
            {result.rows.length ? <>
                <div className="windows-inventory-table-wrap"><table className="windows-inventory-table windows-patch-history-table"><caption className="sr-only">{c.history}</caption><thead><tr>{headers.map(header => <th scope="col" key={header}>{header}</th>)}</tr></thead><tbody>{result.rows.map(row => <tr key={row.index}>
                    <td data-label={c.rowTitle}><div>{row.title}{row.metadataTruncated && <small>{c.shortened}</small>}<details className="windows-patch-row-details"><summary>{c.details}</summary><span>{row.updateId} · {c.revision} {row.revision}</span></details></div></td>
                    <td data-label={c.occurred}><time dateTime={row.occurredAt}>{fullDate(row.occurredAt)}</time></td><td data-label={c.operationColumn}>{c[row.operation]}</td><td data-label={c.resultColumn}><div>{c[row.result]}<small>HRESULT: {row.hresult}</small></div></td>
                </tr>)}</tbody></table></div>
                {result.pages > 1 && <nav className="windows-patch-history-pages" aria-label={c.history}>
                    <button type="button" className="button" disabled={result.page === 0} onClick={() => setFilters(current => ({ ...current, page: result.page - 1 }))}>{c.previous}</button>
                    <span role="status" aria-live="polite" aria-atomic="true">{c.page(result.page + 1, result.pages, result.start + 1, result.start + result.rows.length)}</span>
                    <button type="button" className="button" disabled={result.page + 1 >= result.pages} onClick={() => setFilters(current => ({ ...current, page: result.page + 1 }))}>{c.next}</button>
                </nav>}
            </> : <p className="windows-inventory-empty">{c.empty}</p>}
        </>}
        <p className="windows-inventory-exclusions">{c.bounds}</p>
    </div>;
}
