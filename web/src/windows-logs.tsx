import { useEffect, useId, useState } from 'react';
import { AUTH_REQUIRED_EVENT } from './api';
import { useLocale } from './i18n';
import { fullDate } from './utils';
import type { WindowsInventoryResource } from './windows-inventory-resource';
import type { WindowsEvent, WindowsEventChannel } from './windows-events-types';
import './windows-logs.css';

const PAGE_SIZE = 10;
type Header = WindowsEvent & { channel: WindowsEventChannel['channel'] };
const initialFilters = { channel: '', level: '', provider: '', eventId: '' };
// Preserve full uint64 record IDs and sub-millisecond timestamp order. Record IDs
// only break ties within a channel; they are not a cross-channel source cursor.
function newestFirst(a: Header, b: Header): number {
    const stamp = (value: string) => value.slice(0, 19) + (value.split('.')[1]?.slice(0, -1) ?? '').padEnd(9, '0');
    const left = stamp(a.timestamp), right = stamp(b.timestamp);
    if (left !== right) return left > right ? -1 : 1;
    if (a.channel !== b.channel) return a.channel < b.channel ? -1 : 1;
    return BigInt(a.recordId) > BigInt(b.recordId) ? -1 : BigInt(a.recordId) < BigInt(b.recordId) ? 1 : 0;
}

/** Browse the already accepted header sample only. No source query, retained
 * history, content collection, grant, export or private row cache is added. */
export function WindowsLogsPanel({ resource }: { resource: WindowsInventoryResource }) {
    const [locale] = useLocale(), de = locale === 'de', filterId = useId();
    const [savedFilters, setFilters] = useState(initialFilters);
    const [page, setPage] = useState({ generation: '', index: 0 });
    const clear = () => { setFilters(initialFilters); setPage({ generation: '', index: 0 }); };
    useEffect(() => {
        const hide = () => { if (document.visibilityState === 'hidden') clear(); };
        window.addEventListener(AUTH_REQUIRED_EVENT, clear); window.addEventListener('blur', clear); window.addEventListener('pagehide', clear); window.addEventListener('hashchange', clear); document.addEventListener('visibilitychange', hide);
        return () => { window.removeEventListener(AUTH_REQUIRED_EVENT, clear); window.removeEventListener('blur', clear); window.removeEventListener('pagehide', clear); window.removeEventListener('hashchange', clear); document.removeEventListener('visibilitychange', hide); };
    }, []);
    const events = !resource.error && (resource.status === 'fresh' || resource.status === 'stale') ? resource.events : null;
    // A provider filter can itself contain private header text. Hide it in the
    // same render as terminal sample loss, and discard it after that render.
    const filters = events || resource.loading ? savedFilters : initialFilters;
    useEffect(() => { if (!events && !resource.loading) clear(); }, [events, resource.loading]);
    const expired = !resource.loading && !resource.error && !events && Boolean(resource.view?.events);
    const state = resource.error === 'session' ? (de ? 'Sitzung beendet. Zum Lesen erneut anmelden.' : 'Session ended. Sign in again to read headers.') : resource.error ? (de ? 'Ereignisköpfe nicht verfügbar. Erneut aktualisieren.' : 'Event headers unavailable. Refresh to try again.') : resource.loading ? (de ? 'Ereignisstichprobe wird geprüft …' : 'Checking the event sample…') : resource.status === 'revoked' ? (de ? 'Gerätefreigabe beendet.' : 'Device access ended.') : expired ? (de ? 'Ereignisstichprobe abgelaufen. Auf eine neue Endpunktmeldung warten.' : 'Event sample expired. Wait for a new endpoint report.') : !events ? (de ? 'Keine aktuelle Ereigniskopf-Stichprobe gemeldet.' : 'No current event-header sample reported.') : resource.eventsStale ? (de ? 'Veraltete Stichprobe. Der aktuelle Zustand ist unbekannt.' : 'Stale sample. Current conditions are unknown.') : (de ? 'Neueste gemeldete Stichprobe' : 'Latest reported sample');
    const levels = [de ? 'Unbekannt / reserviert' : 'Unknown / reserved', de ? 'Kritisch' : 'Critical', de ? 'Fehler' : 'Error', de ? 'Warnung' : 'Warning', 'Information', de ? 'Ausführlich' : 'Verbose'];
    const qualities = { observed: de ? 'Erfasst' : 'Observed', bounded: de ? 'Begrenzt' : 'Bounded', partial: de ? 'Unvollständig' : 'Partial', denied: de ? 'Zugriff verweigert' : 'Access denied', unavailable: de ? 'Nicht verfügbar' : 'Unavailable' };
    const validId = filters.eventId === '' || /^\d{1,5}$/.test(filters.eventId) && Number(filters.eventId) <= 65535;
    const rows = (events?.channels.flatMap(channel => channel.rows.map(row => ({ ...row, channel: channel.channel }))) ?? []).filter(row =>
        (!filters.channel || row.channel === filters.channel) &&
        (!filters.level || (filters.level === 'unknown' ? row.level === 0 || row.level > 5 : row.level === Number(filters.level))) &&
        row.provider.toLowerCase().includes(filters.provider.trim().toLowerCase()) &&
        validId && (!filters.eventId || row.eventId === Number(filters.eventId))).sort(newestFirst);
    const pageCount = Math.max(1, Math.ceil(rows.length / PAGE_SIZE));
    const index = events && page.generation === events.generationId ? Math.min(page.index, pageCount - 1) : 0;
    const update = (name: keyof typeof filters, value: string) => { setFilters(current => ({ ...current, [name]: value })); setPage({ generation: '', index: 0 }); };
    const canPrevious = Boolean(events && rows.length > 0 && index > 0 && !resource.loading), canNext = Boolean(events && rows.length > 0 && index + 1 < pageCount && !resource.loading);
    const columns = [de ? 'Ereigniszeit' : 'Event time', de ? 'Kanal' : 'Channel', de ? 'Stufe' : 'Level', 'Provider', de ? 'Ereignis-ID' : 'Event ID', de ? 'Datensatz-ID' : 'Record ID'];
    return <section className="windows-inventory windows-logs" aria-label={de ? 'Windows-Logs' : 'Windows logs'}>
        <div className="windows-inventory-section-header"><h2>{de ? 'Windows-Ereignisköpfe' : 'Windows event headers'}</h2><button type="button" className="button small" disabled={resource.loading || resource.error === 'session' || resource.status === 'revoked'} onClick={resource.refresh}>{de ? 'Stichprobe aktualisieren' : 'Refresh sample'}</button></div>
        <p className="windows-logs-boundary">{de ? 'Nur die gemeldete Stichprobe: bis zu 16 Köpfe je Kanal. Filter und Seiten lesen keine älteren Ereignisse nach.' : 'Reported sample only: up to 16 headers per channel. Filters and pages do not retrieve older events.'}</p>
        <p role={resource.error ? 'alert' : 'status'}>{state}</p>
        {events && <><p className="windows-inventory-count">{de ? 'Erfasst' : 'Captured'}: <time dateTime={events.collectedAt}>{fullDate(events.collectedAt)}</time></p><ul className="windows-logs-channels" aria-label={de ? 'Kanalstatus' : 'Channel status'}>{events.channels.map(channel => <li key={channel.channel}>
            <strong>{channel.channel}</strong><span>{qualities[channel.quality]} · {channel.rows.length} {de ? 'Köpfe in Stichprobe' : 'sample headers'}</span>
            {(channel.quality === 'denied' || channel.quality === 'unavailable') && <span>{de ? 'Keine auswertbare Beobachtung.' : 'No usable observation.'}</span>}
            {channel.truncated && <span>{de ? 'Weitere Ereignisse fehlen.' : 'More events are omitted.'}</span>}
            {channel.quality === 'partial' && <span>{de ? 'Quellabfrage unvollständig.' : 'Source read incomplete.'}</span>}
        </li>)}</ul></>}
        <fieldset className="windows-logs-filters" disabled={resource.error === 'session' || resource.status === 'revoked' || !events && !resource.loading} aria-describedby="windows-logs-filter-scope"><legend>{de ? 'Stichprobe filtern' : 'Filter sample'}</legend>
            <div className="windows-logs-filter"><label htmlFor={`${filterId}-channel`}>{de ? 'Kanal' : 'Channel'}</label><select id={`${filterId}-channel`} value={filters.channel} onChange={event => update('channel', event.target.value)}><option value="">{de ? 'Alle Kanäle' : 'All channels'}</option><option>Application</option><option>System</option></select></div>
            <div className="windows-logs-filter"><label htmlFor={`${filterId}-level`}>{de ? 'Stufe' : 'Level'}</label><select id={`${filterId}-level`} value={filters.level} onChange={event => update('level', event.target.value)}><option value="">{de ? 'Alle Stufen' : 'All levels'}</option>{levels.slice(1).map((label, i) => <option key={i} value={i + 1}>{label}</option>)}<option value="unknown">{levels[0]}</option></select></div>
            <label>Provider<input type="search" autoComplete="off" spellCheck={false} maxLength={256} value={filters.provider} onChange={event => update('provider', event.target.value)}/></label>
            <label>{de ? 'Ereignis-ID' : 'Event ID'}<input type="text" autoComplete="off" inputMode="numeric" maxLength={5} aria-invalid={!validId} aria-describedby={!validId ? 'windows-logs-id-error' : undefined} value={filters.eventId} onChange={event => update('eventId', event.target.value)}/></label>
            <button type="button" className="button small" disabled={!Object.values(filters).some(Boolean)} onClick={clear}>{de ? 'Filter zurücksetzen' : 'Reset filters'}</button>
        </fieldset>
        <p id="windows-logs-filter-scope" className="windows-inventory-count">{de ? 'Provider: wörtlicher Teiltext · Ereignis-ID: exakter Wert · neueste Ereigniszeit zuerst' : 'Provider: literal text match · event ID: exact value · newest event time first'}</p>
        {!validId && <p id="windows-logs-id-error" role="alert">{de ? 'Ereignis-ID von 0 bis 65535 eingeben.' : 'Enter an event ID from 0 to 65535.'}</p>}
        {events && (rows.length === 0 ? <p className="windows-inventory-empty">{events.channels.every(channel => channel.rows.length === 0) ? (de ? 'Keine Ereignisköpfe in dieser Stichprobe. Das belegt keinen fehlerfreien Zustand.' : 'No event headers in this sample. This does not establish a healthy system.') : (de ? 'Keine Köpfe dieser Stichprobe passen zu den Filtern.' : 'No headers in this sample match these filters.')}</p> : <>
            <div className="windows-inventory-table-wrap"><table className="windows-inventory-table"><caption className="sr-only">{de ? 'Gefilterte Ereigniskopf-Stichprobe' : 'Filtered event-header sample'}</caption><thead><tr>{columns.map(label => <th scope="col" key={label}>{label}</th>)}</tr></thead><tbody>{rows.slice(index * PAGE_SIZE, (index + 1) * PAGE_SIZE).map(row => <tr key={`${row.channel}:${row.recordId}`}>
                <td data-label={columns[0]}><time dateTime={row.timestamp}>{fullDate(row.timestamp)}</time></td><td data-label={columns[1]}>{row.channel}</td><td data-label={columns[2]}>{levels[row.level] ?? levels[0]} ({row.level})</td><td data-label={columns[3]}>{row.provider}</td><td data-label={columns[4]}>{row.eventId}</td><td data-label={columns[5]}>{row.recordId}</td>
            </tr>)}</tbody></table></div>
        </>)}
        <nav className="windows-logs-pages" hidden={!resource.loading && (!events || rows.length === 0)} aria-label={de ? 'Stichprobenseiten' : 'Sample pages'}>
            <button type="button" className="button small" disabled={!resource.loading && !canPrevious} aria-disabled={!canPrevious} onClick={() => { if (canPrevious && events) setPage({ generation: events.generationId, index: index - 1 }); }}>{de ? 'Zurück' : 'Previous'}</button>
            <span aria-live="polite">{resource.loading ? (de ? 'Stichprobe wird geprüft …' : 'Checking sample…') : de ? `Seite ${index + 1} von ${pageCount} · ${rows.length} passende Köpfe` : `Page ${index + 1} of ${pageCount} · ${rows.length} matching headers`}</span>
            <button type="button" className="button small" disabled={!resource.loading && !canNext} aria-disabled={!canNext} onClick={() => { if (canNext && events) setPage({ generation: events.generationId, index: index + 1 }); }}>{de ? 'Weiter' : 'Next'}</button>
        </nav>
        <details className="windows-inventory-scope"><summary>{de ? 'Umfang und Grenzen' : 'Scope and limits'}</summary><p>{de ? 'Application-/System-Köpfe aus der vorhandenen lokalen Freigabe. Keine Nachrichten, XML, Security-Logs oder KI-Übertragung. Aktualisieren prüft nur die neueste akzeptierte Meldung. Die Stichprobe ersetzt keine vollständige Ereignishistorie oder Health-Bewertung. Ereignisse können älter als die Erfassung sein.' : 'Application/System headers from the existing local grant. No messages, XML, Security logs or AI export. Refresh checks only the latest accepted report. The sample is not a complete event history or health assessment. Events may be older than the capture time.'}</p></details>
    </section>;
}
