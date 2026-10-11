import { memo, useId } from 'react';
import { useOperator } from './auth';
import { useLocale } from './i18n';
import { fullDate } from './utils';
import { useWindowsFullServices } from './windows-full-services-resource';
import { fullServicesSorts } from './windows-full-services-types';
import type { FullServicesPage, FullServicesSort } from './windows-full-services-types';
import './windows-inventory.css';
import './windows-inventory-tables.css';
import './windows-full-services.css';

const copy = {
    en: {
        title: 'Complete caller-visible services', access: 'Authenticated LAN operator access is required.', refresh: 'Refresh service page', restartButton: 'Restart with latest service generation', loading: 'Reading the protected service page…',
        intro: 'All Win32 services returned to the existing LocalService identity by a completed SCM enumeration. Drivers and services hidden by permissions are excluded; enumeration is not an atomic snapshot or whole-machine coverage.',
        separate: 'This independent local scope is off until explicitly approved. Reading, searching and paging do not collect services or grant access. The bounded preview and selected-service alarms remain separate sources.',
        noComplete: 'No complete service generation is available. Missing or failed data does not establish an empty service inventory.',
        not_configured: 'Complete service collection is not configured.', disabled: 'The last acknowledged local scope is disabled.', awaiting: 'Awaiting a complete service generation.', unavailable: 'Complete service inventory is unavailable.', ready: 'Complete within the caller-visible API scope',
        invalid: 'The manager returned inconsistent or unsupported service inventory. Rows and controls were cleared.', timeout: 'The request timed out. Refresh to try again.', session: 'Your session has ended. Sign in again.', clock: 'The time reference is no longer reliable. Refresh before continuing.', busy: 'The manager is busy. Refresh in a moment.', restart: 'The generation, grant or paging session changed or expired. Restart explicitly; previous rows were cleared.', unauthorized: 'The device identity is no longer authorized or has expired. Service data is hidden.', expired: 'The original source, authority or paging deadline expired. Service data is hidden.', searchInvalid: 'Search allows at most 256 UTF-8 bytes and no null character.',
        rows: 'services', age: 'Captured', priorShort: 'Showing the previous complete capture.', latest: 'Latest collection attempt', pending: 'Transfer pending', complete: 'Complete', source_failed: 'Collection failed', expiredAttempt: 'Attempt expired', prior: 'A newer attempt has not replaced this completed capture. Its original times and expiry are unchanged.',
        access_denied: 'Access denied', unsupported: 'Unsupported source', source_changed: 'Source changed during collection', malformed_source: 'Invalid source data', resource_limit: 'Collection or transfer limit reached', deadline: 'Collection deadline reached', canceled: 'Collection canceled',
        captured: 'Captured rows', matching: 'Matching rows in the whole generation', visible: 'Visible rows on this page', coverage: 'Coverage', start: 'Original capture started', finish: 'Original capture finished', received: 'Original manager receipt', expiry: 'Original source expiry', cursorExpiry: 'Paging deadline', details: 'Generation and source details', generation: 'Generation', sequence: 'Sequence', scope: 'Scope',
        search: 'Search all captured services', sort: 'Sort all captured services', apply: 'Apply search and sort', hint: 'Literal, case-insensitive search across reported names, display names, raw state codes and PIDs. Sort uses source text, independent of display language. Up to 100 rows per server page.',
        'name-asc': 'Name: A to Z', 'name-desc': 'Name: Z to A', 'pid-asc': 'PID: lowest first', 'pid-desc': 'PID: highest first', 'state-asc': 'State code: A to Z', 'state-desc': 'State code: Z to A',
        name: 'Service name', displayName: 'Display name', state: 'State', fieldUnavailable: 'Unavailable in this capture', emptyDisplay: 'Empty reported display name', stopped: 'Stopped', start_pending: 'Starting', stop_pending: 'Stopping', running: 'Running', continue_pending: 'Resuming', pause_pending: 'Pausing', paused: 'Paused',
        healthyEmpty: 'Successful complete enumeration returned zero caller-visible Win32 services.', noMatches: 'No services in the complete captured generation match this search.', previous: 'Previous service page', next: 'Next service page', pages: 'Complete service pages',
        page: (offset: number, count: number, total: number) => `Rows ${count ? offset + 1 : 0}–${offset + count} of ${total} matching`,
        limits: 'Names may be sensitive. Rows are read-only operator data and retain their original 24-hour capture lifetime. No paths, accounts, startup configuration, service actions, installed-program inventory or AI export are included.',
    },
    de: {
        title: 'Vollständige sichtbare Dienste', access: 'Ein authentifizierter LAN-Operator-Zugang ist erforderlich.', refresh: 'Dienstseite aktualisieren', restartButton: 'Mit neuester Dienstgeneration neu beginnen', loading: 'Geschützte Dienstseite wird gelesen …',
        intro: 'Alle Win32-Dienste, die eine abgeschlossene SCM-Aufzählung für die bestehende LocalService-Identität zurückgibt. Treiber und durch Berechtigungen verborgene Dienste sind ausgeschlossen. Dies ist weder eine atomare Momentaufnahme noch eine Abdeckung des gesamten Geräts.',
        separate: 'Dieser unabhängige lokale Umfang bleibt bis zur ausdrücklichen Zustimmung deaktiviert. Lesen, Suchen und Blättern erfassen keine Dienste und erteilen keine Freigabe. Die begrenzte Vorschau und Alarme für ausgewählte Dienste behalten ihre getrennten Quellen.',
        noComplete: 'Keine vollständige Dienstgeneration verfügbar. Fehlende oder fehlgeschlagene Daten belegen kein leeres Dienstinventar.',
        not_configured: 'Die vollständige Diensterfassung ist nicht eingerichtet.', disabled: 'Der zuletzt bestätigte lokale Umfang ist deaktiviert.', awaiting: 'Warten auf eine vollständige Dienstgeneration.', unavailable: 'Das vollständige Dienstinventar ist nicht verfügbar.', ready: 'Vollständig im sichtbaren API-Umfang',
        invalid: 'Der Manager lieferte widersprüchliches oder nicht unterstütztes Dienstinventar. Zeilen und Steuerelemente wurden entfernt.', timeout: 'Die Anfrage hat das Zeitlimit überschritten. Erneut aktualisieren.', session: 'Die Sitzung ist beendet. Erneut anmelden.', clock: 'Die Zeitreferenz ist nicht mehr verlässlich. Vor dem Fortfahren aktualisieren.', busy: 'Der Manager ist ausgelastet. Gleich erneut aktualisieren.', restart: 'Generation, Freigabe oder Seitensitzung wurden geändert oder sind abgelaufen. Ausdrücklich neu beginnen; vorherige Zeilen wurden entfernt.', unauthorized: 'Die Geräteidentität ist nicht mehr autorisiert oder abgelaufen. Dienstdaten sind ausgeblendet.', expired: 'Die ursprüngliche Quellen-, Berechtigungs- oder Seitenfrist ist abgelaufen. Dienstdaten sind ausgeblendet.', searchInvalid: 'Die Suche erlaubt höchstens 256 UTF-8-Bytes und kein Nullzeichen.',
        rows: 'Dienste', age: 'Erfasst', priorShort: 'Die letzte vollständige Erfassung wird angezeigt.', latest: 'Neuester Erfassungsversuch', pending: 'Übertragung ausstehend', complete: 'Vollständig', source_failed: 'Erfassung fehlgeschlagen', expiredAttempt: 'Versuch abgelaufen', prior: 'Ein neuerer Versuch hat diese vollständige Erfassung nicht ersetzt. Ursprüngliche Zeiten und Ablauf bleiben unverändert.',
        access_denied: 'Zugriff verweigert', unsupported: 'Quelle nicht unterstützt', source_changed: 'Quelle während der Erfassung geändert', malformed_source: 'Ungültige Quelldaten', resource_limit: 'Erfassungs- oder Übertragungsgrenze erreicht', deadline: 'Erfassungsfrist erreicht', canceled: 'Erfassung abgebrochen',
        captured: 'Erfasste Zeilen', matching: 'Treffer in der gesamten Generation', visible: 'Sichtbare Zeilen auf dieser Seite', coverage: 'Abdeckung', start: 'Beginn der ursprünglichen Erfassung', finish: 'Ende der ursprünglichen Erfassung', received: 'Ursprünglicher Empfang beim Manager', expiry: 'Ursprünglicher Quellenablauf', cursorExpiry: 'Seitenfrist', details: 'Generation und Quelldetails', generation: 'Generation', sequence: 'Sequenz', scope: 'Umfang',
        search: 'Alle erfassten Dienste durchsuchen', sort: 'Alle erfassten Dienste sortieren', apply: 'Suche und Sortierung anwenden', hint: 'Wörtliche Suche ohne Beachtung der Groß-/Kleinschreibung in gemeldeten Namen, Anzeigenamen, Zustandscodes und PIDs. Sortierung nach Quelltext, unabhängig von der Anzeigesprache. Bis zu 100 Zeilen je Serverseite.',
        'name-asc': 'Name: A bis Z', 'name-desc': 'Name: Z bis A', 'pid-asc': 'PID: niedrigste zuerst', 'pid-desc': 'PID: höchste zuerst', 'state-asc': 'Zustandscode: A bis Z', 'state-desc': 'Zustandscode: Z bis A',
        name: 'Dienstname', displayName: 'Anzeigename', state: 'Zustand', fieldUnavailable: 'In dieser Erfassung nicht verfügbar', emptyDisplay: 'Leerer gemeldeter Anzeigename', stopped: 'Gestoppt', start_pending: 'Wird gestartet', stop_pending: 'Wird gestoppt', running: 'Läuft', continue_pending: 'Wird fortgesetzt', pause_pending: 'Wird pausiert', paused: 'Pausiert',
        healthyEmpty: 'Die erfolgreiche vollständige Aufzählung ergab keine sichtbaren Win32-Dienste.', noMatches: 'Keine Dienste der vollständig erfassten Generation entsprechen dieser Suche.', previous: 'Vorherige Dienstseite', next: 'Nächste Dienstseite', pages: 'Vollständige Dienstseiten',
        page: (offset: number, count: number, total: number) => `Zeilen ${count ? offset + 1 : 0}–${offset + count} von ${total} Treffern`,
        limits: 'Namen können sensible Angaben enthalten. Zeilen sind nur lesbare Operator-Daten und behalten ihre ursprüngliche Erfassungsfrist von 24 Stunden. Pfade, Konten, Startkonfiguration, Dienstaktionen, installierte Programme und KI-Export sind nicht enthalten.',
    },
};
export const WindowsFullServiceTable = memo(function WindowsFullServiceTable({ page, locale }: { page: FullServicesPage; locale: 'en' | 'de' }) {
    const c = copy[locale], headers = [c.name, c.displayName, c.state, 'PID'], sorted = page.sort.startsWith('pid') ? 3 : page.sort.startsWith('state') ? 2 : 0;
    return <div className="windows-inventory-table-wrap"><table className="windows-inventory-table"><caption className="sr-only">{c.title}</caption><thead><tr>{headers.map((header, i) => <th key={header} scope="col" aria-sort={i === sorted ? page.sort.endsWith('desc') ? 'descending' : 'ascending' : undefined}>{header}</th>)}</tr></thead><tbody>{page.rows.map(row => <tr key={row.name}>{[row.name, row.displayName === null ? c.fieldUnavailable : row.displayName || c.emptyDisplay, row.state === null ? c.fieldUnavailable : `${c[row.state]} (${row.state})`, row.pid === null ? c.fieldUnavailable : String(row.pid)].map((value, i) => <td key={i} data-label={headers[i]}>{value}</td>)}</tr>)}</tbody></table></div>;
});
export function WindowsFullServicesPanel({ deviceId, sessionKey, enabled = true }: { deviceId: string; sessionKey: string | null; enabled?: boolean }) {
    const operator = useOperator(), [locale] = useLocale();
    if (!operator || operator.mode !== 'lan' || !operator.authenticated) return <p>{copy[locale].access}</p>;
    return <FullServices key={`${deviceId}:${sessionKey ?? ''}:${operator.expiresAt ?? ''}`} deviceId={deviceId} sessionKey={sessionKey} enabled={enabled}/>;
}
function FullServices({ deviceId, sessionKey, enabled }: { deviceId: string; sessionKey: string | null; enabled: boolean }) {
    const [locale] = useLocale(), c = copy[locale], id = useId(), resource = useWindowsFullServices(deviceId, enabled, sessionKey), { view, page } = resource;
    const complete = view?.complete, attempt = view?.latestAttempt;
    const time = (label: string, value: string) => <div><dt>{label}</dt><dd><time dateTime={value}>{fullDate(value)}</time></dd></div>;
    return <section className="windows-full-services" aria-labelledby={`${id}-title`} aria-busy={resource.loading}>
        <header className="windows-inventory-section-header"><h3 id={`${id}-title`}>{c.title}</h3><button type="button" className="button small" disabled={!enabled || resource.loading || resource.error === 'session'} onClick={resource.error === 'restart' || resource.error === 'expired' ? resource.restart : resource.refresh}>{resource.error === 'restart' || resource.error === 'expired' ? c.restartButton : c.refresh}</button></header>
        {resource.loading && <p role="status">{c.loading}</p>}{resource.error && <p role="alert" className="windows-inventory-caution">{c[resource.error]}</p>}
        {view && !resource.loading && <>
            <p className="windows-inventory-quality windows-full-services-summary" role="status">{c[view.status]}{complete && <> · {complete.manifest.rowCount} {c.rows} · {c.age} <time dateTime={complete.manifest.captureFinishedAt} title={fullDate(complete.manifest.captureFinishedAt)}>{fullDate(complete.manifest.captureFinishedAt)}</time></>}</p>
            {attempt && attempt.status !== 'complete' && <section className="windows-full-services-attempt" aria-label={c.latest}><p>{c[attempt.status === 'expired' ? 'expiredAttempt' : attempt.status]}{attempt.reason && <> · {c[attempt.reason]}</>}{complete && attempt.sequence !== complete.manifest.sequence && <>. {c.priorShort}</>}</p></section>}
            {!complete && <p>{c.noComplete}</p>}
            {complete && <>
                <form onSubmit={event => { event.preventDefault(); resource.apply(); }}><div className="windows-inventory-table-controls"><label className="windows-inventory-search" htmlFor={`${id}-search`}>{c.search}<input id={`${id}-search`} type="search" autoComplete="off" spellCheck={false} maxLength={256} value={resource.controls.search} onChange={event => resource.changeSearch(event.target.value)} aria-describedby={`${id}-hint`}/></label><div className="windows-inventory-table-sort"><label htmlFor={`${id}-sort`}>{c.sort}</label><select id={`${id}-sort`} value={resource.controls.sort} onChange={event => resource.changeSort(event.target.value as FullServicesSort)}>{fullServicesSorts.map(sort => <option key={sort} value={sort}>{c[sort]}</option>)}</select></div><button type="submit" className="button small">{c.apply}</button></div></form>
                {page && <><dl className="windows-full-services-counts" role="status" aria-live="polite" aria-atomic="true"><div><dt>{c.matching}</dt><dd>{page.matchingCount}</dd></div><div><dt>{c.visible}</dt><dd>{page.rows.length}</dd></div></dl>{page.rows.length ? <WindowsFullServiceTable page={page} locale={locale}/> : <p>{complete.manifest.rowCount === 0 ? c.healthyEmpty : c.noMatches}</p>}<nav className="windows-inventory-table-pagination" aria-label={c.pages}><button type="button" className="button small" disabled={page.offset === 0} onClick={resource.previous}>{c.previous}</button><span>{c.page(page.offset, page.rows.length, page.matchingCount)}</span><button type="button" className="button small" disabled={!page.nextCursor} onClick={resource.next}>{c.next}</button></nav></>}
            </>}
        </>}
        <details className="windows-inventory-scope windows-full-services-details"><summary>{c.details}</summary>
            <p className="windows-inventory-exclusions">{c.intro}</p><p className="windows-inventory-exclusions">{c.separate}</p>
            {view && !resource.loading && <>
                {attempt && <dl className="windows-full-services-attempt-details">{time(c.latest, attempt.attemptedAt)}<div><dt>{c.sequence}</dt><dd>{attempt.sequence} · {c[attempt.status === 'expired' ? 'expiredAttempt' : attempt.status]}</dd></div></dl>}
                {complete && <>
                    <dl className="windows-full-services-facts"><div><dt>{c.coverage}</dt><dd>{c.ready}</dd></div><div><dt>{c.captured}</dt><dd>{complete.manifest.rowCount}</dd></div>{time(c.start, complete.manifest.captureStartedAt)}{time(c.finish, complete.manifest.captureFinishedAt)}{time(c.received, complete.receivedAt)}{time(c.expiry, complete.manifest.expiresAt)}{view.cursorExpiresAt && time(c.cursorExpiry, view.cursorExpiresAt)}</dl>
                    <dl className="windows-full-services-facts"><div><dt>{c.generation}</dt><dd>{complete.manifest.generationId}</dd></div><div><dt>{c.sequence}</dt><dd>{complete.manifest.sequence}</dd></div><div><dt>{c.scope}</dt><dd>{complete.manifest.scope} · {complete.manifest.source}</dd></div></dl>
                    {attempt && attempt.sequence !== complete.manifest.sequence && <p>{c.prior}</p>}
                </>}
            </>}
            <p className="windows-inventory-exclusions" id={`${id}-hint`}>{c.hint}</p><p className="windows-inventory-exclusions">{c.limits}</p>
        </details>
    </section>;
}
