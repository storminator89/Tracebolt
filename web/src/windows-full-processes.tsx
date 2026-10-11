import { memo, useId, type ReactNode } from 'react';
import { ChevronLeft, ChevronRight, RefreshCw, Search } from 'lucide-react';
import { useOperator } from './auth';
import { useLocale } from './i18n';
import { fullDate } from './utils';
import { useWindowsFullProcesses } from './windows-full-processes-resource';
import { fullProcessesSorts } from './windows-full-processes-types';
import type { FullProcessesPage, FullProcessesSort } from './windows-full-processes-types';
import './windows-inventory.css';
import './windows-inventory-tables.css';
import './windows-full-processes.css';

const copy = {
    en: {
        title: 'Process inventory', access: 'Sign in as a LAN operator to view processes.', refresh: 'Refresh process inventory', reload: 'Reload latest', restartButton: 'Reload latest process capture', loading: 'Loading processes…',
        ready: 'Complete visible snapshot', not_configured: 'Local consent required', disabled: 'Collection disabled', awaiting: 'Waiting for first complete capture', unavailable: 'Process inventory unavailable',
        invalid: 'Invalid response. Refresh to retry.', timeout: 'Request timed out. Refresh to retry.', session: 'Your session has ended. Sign in again.', clock: 'Time reference changed. Refresh to verify.', busy: 'Manager busy. Try again shortly.', restart: 'Capture or access changed. Reload latest to continue.', unauthorized: 'Device access ended.', expired: 'Capture or paging session expired. Reload latest.', searchInvalid: 'Search is limited to 256 UTF-8 bytes.',
        pending: 'New capture pending', source_failed: 'Latest capture failed', expiredAttempt: 'Latest attempt expired', complete: 'Latest capture complete', prior: 'Showing earlier capture', latest: 'Latest attempt',
        access_denied: 'Access denied', unsupported: 'Unsupported source', source_changed: 'Source changed', malformed_source: 'Invalid source', resource_limit: 'Capture limit reached', deadline: 'Capture timed out', canceled: 'Capture canceled',
        asOf: 'As of', captured: 'Captured', matching: 'Matching', visible: 'On page', start: 'Capture started', finish: 'Capture finished', received: 'Manager received', expiry: 'Capture expires', cursorExpiry: 'Paging expires', details: 'Scope & capture details', generation: 'Generation', sequence: 'Sequence', scope: 'Source',
        search: 'Search captured processes', placeholder: 'Name, PID, parent PID or threads', sort: 'Sort process inventory', apply: 'Apply',
        'pid-asc': 'PID · lowest first', 'pid-desc': 'PID · highest first', 'name-asc': 'Name · A–Z', 'name-desc': 'Name · Z–A', 'parentPid-asc': 'Parent PID · lowest first', 'parentPid-desc': 'Parent PID · highest first', 'threads-asc': 'Threads · lowest first', 'threads-desc': 'Threads · highest first',
        name: 'Name', pid: 'Snapshot PID', parentPid: 'Snapshot parent PID', threads: 'Threads', fieldUnavailable: 'Unavailable', emptyValue: 'Empty value',
        healthyEmpty: 'No caller-visible processes in this complete snapshot.', noMatches: 'No matches in this capture.', previous: 'Previous process page', next: 'Next process page', pages: 'Process inventory pages',
        preview: 'Process preview & metrics · up to 128 rows',
        page: (offset: number, count: number, total: number) => `${count ? offset + 1 : 0}–${offset + count} of ${total}`,
        coverage: 'Complete caller-visible Toolhelp process snapshot. The service’s visibility defines coverage. A source cutoff or failure never becomes a complete prefix.',
        identity: 'PID and parent PID are values from this snapshot, not lasting identities or verified live relationships. Names may be unavailable. Search is literal and case-insensitive; missing names sort last.',
        lifetime: 'Original capture age and 24-hour lifetime are preserved. A failed attempt leaves the earlier complete capture unchanged. This inventory has no CPU or RAM values and grants no metrics access. The separate bounded preview and measurements retain their own capture identity; rows are never joined across these sources. Reading or refreshing grants no consent or host collection. Paths, command lines, owners and AI export are excluded.',
    },
    de: {
        title: 'Prozessinventar', access: 'Zum Anzeigen als LAN-Operator anmelden.', refresh: 'Prozessinventar aktualisieren', reload: 'Neueste laden', restartButton: 'Neueste Prozesserfassung laden', loading: 'Prozesse werden geladen …',
        ready: 'Sichtbarer Snapshot vollständig', not_configured: 'Lokale Zustimmung erforderlich', disabled: 'Erfassung deaktiviert', awaiting: 'Warten auf erste vollständige Erfassung', unavailable: 'Prozessinventar nicht verfügbar',
        invalid: 'Ungültige Antwort. Erneut aktualisieren.', timeout: 'Zeitlimit überschritten. Erneut aktualisieren.', session: 'Die Sitzung ist beendet. Erneut anmelden.', clock: 'Zeitreferenz geändert. Zur Prüfung aktualisieren.', busy: 'Manager ausgelastet. Gleich erneut versuchen.', restart: 'Erfassung oder Zugriff geändert. Neueste laden.', unauthorized: 'Gerätezugriff beendet.', expired: 'Erfassung oder Seitensitzung abgelaufen. Neueste laden.', searchInvalid: 'Suche auf 256 UTF-8-Bytes begrenzt.',
        pending: 'Neue Erfassung ausstehend', source_failed: 'Neueste Erfassung fehlgeschlagen', expiredAttempt: 'Neuester Versuch abgelaufen', complete: 'Neueste Erfassung vollständig', prior: 'Vorherige Erfassung angezeigt', latest: 'Neuester Versuch',
        access_denied: 'Zugriff verweigert', unsupported: 'Quelle nicht unterstützt', source_changed: 'Quelle geändert', malformed_source: 'Ungültige Quelle', resource_limit: 'Erfassungsgrenze erreicht', deadline: 'Erfassungsfrist erreicht', canceled: 'Erfassung abgebrochen',
        asOf: 'Stand', captured: 'Erfasst', matching: 'Treffer', visible: 'Auf Seite', start: 'Erfassung begonnen', finish: 'Erfassung beendet', received: 'Beim Manager empfangen', expiry: 'Erfassung läuft ab', cursorExpiry: 'Seitensitzung läuft ab', details: 'Umfang & Erfassungsdetails', generation: 'Generation', sequence: 'Sequenz', scope: 'Quelle',
        search: 'Erfasste Prozesse durchsuchen', placeholder: 'Name, PID, Eltern-PID oder Threads', sort: 'Prozessinventar sortieren', apply: 'Anwenden',
        'pid-asc': 'PID · niedrigste zuerst', 'pid-desc': 'PID · höchste zuerst', 'name-asc': 'Name · A–Z', 'name-desc': 'Name · Z–A', 'parentPid-asc': 'Eltern-PID · niedrigste zuerst', 'parentPid-desc': 'Eltern-PID · höchste zuerst', 'threads-asc': 'Threads · niedrigste zuerst', 'threads-desc': 'Threads · höchste zuerst',
        name: 'Name', pid: 'Snapshot-PID', parentPid: 'Snapshot-Eltern-PID', threads: 'Threads', fieldUnavailable: 'Nicht verfügbar', emptyValue: 'Leerer Wert',
        healthyEmpty: 'Keine sichtbaren Prozesse in diesem vollständigen Snapshot.', noMatches: 'Keine Treffer in dieser Erfassung.', previous: 'Vorherige Prozessseite', next: 'Nächste Prozessseite', pages: 'Prozessinventarseiten',
        preview: 'Prozessvorschau & Messwerte · bis zu 128 Zeilen',
        page: (offset: number, count: number, total: number) => `${count ? offset + 1 : 0}–${offset + count} von ${total}`,
        coverage: 'Vollständiger, für den Dienst sichtbarer Toolhelp-Prozesssnapshot. Die Sichtbarkeit des Dienstes bestimmt den Umfang. Ein Quellenabbruch oder Fehler gilt niemals als vollständig erfasster Teilbestand.',
        identity: 'PID und Eltern-PID stammen aus diesem Snapshot; sie sind keine dauerhaften Identitäten oder bestätigten aktuellen Beziehungen. Namen können fehlen. Die Suche ist wörtlich und unabhängig von Groß- und Kleinschreibung; fehlende Namen stehen zuletzt.',
        lifetime: 'Ursprüngliches Erfassungsalter und 24 Stunden Gültigkeit bleiben erhalten. Ein fehlgeschlagener Versuch lässt die frühere vollständige Erfassung unverändert. Dieses Inventar enthält keine CPU- oder RAM-Werte und erteilt keinen Messzugriff. Die getrennte begrenzte Vorschau und Messwerte behalten ihre eigene Erfassungsidentität; Zeilen werden nicht zwischen Quellen verknüpft. Lesen oder Aktualisieren erteilt keine Zustimmung und startet keine lokale Erfassung. Pfade, Befehlszeilen, Besitzer und KI-Export sind ausgeschlossen.',
    },
};

export const WindowsFullProcessesTable = memo(function WindowsFullProcessesTable({ page, locale }: { page: FullProcessesPage; locale: 'en' | 'de' }) {
    const c = copy[locale], headers = [c.name, c.pid, c.parentPid, c.threads];
    const sorted = page.sort.startsWith('pid') ? 1 : page.sort.startsWith('parentPid') ? 2 : page.sort.startsWith('threads') ? 3 : 0;
    const value = (field: string | null) => field === null ? <span className="windows-full-processes-missing">{c.fieldUnavailable}</span> : field === '' ? <span className="windows-full-processes-missing">{c.emptyValue}</span> : field;
    return <div className="windows-inventory-table-wrap"><table className="windows-inventory-table"><caption className="sr-only">{c.title}</caption><thead><tr>{headers.map((header, i) => <th key={header} scope="col" aria-sort={i === sorted ? page.sort.endsWith('desc') ? 'descending' : 'ascending' : undefined}>{header}</th>)}</tr></thead><tbody>{page.rows.map(row => <tr key={row.pid} data-snapshot-pid={row.pid}><td data-label={c.name}>{value(row.name)}</td><td data-label={c.pid}>{row.pid}</td><td data-label={c.parentPid}>{row.parentPid}</td><td data-label={c.threads}>{row.threads}</td></tr>)}</tbody></table></div>;
});

export function WindowsFullProcessesPanel({ deviceId, sessionKey, enabled = true, children }: { deviceId: string; sessionKey: string | null; enabled?: boolean; children?: ReactNode }) {
    const operator = useOperator(), [locale] = useLocale();
    if (!operator || operator.mode !== 'lan' || !operator.authenticated) return <p>{copy[locale].access}</p>;
    return <FullProcesses key={`${deviceId}:${sessionKey ?? ''}:${operator.expiresAt ?? ''}`} deviceId={deviceId} sessionKey={sessionKey} enabled={enabled}>{children}</FullProcesses>;
}
function FullProcesses({ deviceId, sessionKey, enabled, children }: { deviceId: string; sessionKey: string | null; enabled: boolean; children?: ReactNode }) {
    const [locale] = useLocale(), c = copy[locale], id = useId(), resource = useWindowsFullProcesses(deviceId, enabled, sessionKey), { view, page } = resource;
    const complete = view?.complete, attempt = view?.latestAttempt, newerAttempt = complete && attempt && attempt.sequence !== complete.manifest.sequence;
    const restart = resource.error === 'restart' || resource.error === 'expired';
    const time = (label: string, value: string) => <div><dt>{label}</dt><dd><time dateTime={value}>{fullDate(value)}</time></dd></div>;
    return <section className="windows-full-processes" aria-labelledby={`${id}-title`} aria-busy={resource.loading}>
        <header className="windows-full-processes-header"><div><h3 id={`${id}-title`}>{c.title}</h3>{complete && <span className="windows-full-processes-complete">{c.ready}</span>}</div><button type="button" className="button small" aria-label={restart ? c.restartButton : c.refresh} disabled={!enabled || resource.loading || resource.error === 'session'} onClick={restart ? resource.restart : resource.refresh}><RefreshCw size={14} aria-hidden="true" className={resource.loading ? 'spin' : undefined}/>{restart ? c.reload : locale === 'de' ? 'Aktualisieren' : 'Refresh'}</button></header>
        {resource.loading && <p className="windows-full-processes-status" role="status">{c.loading}</p>}
        {resource.error && <p role="alert" className="windows-inventory-caution">{c[resource.error]}</p>}
        {view && !resource.loading && <>
            {!complete && <p className="windows-full-processes-status" role="status">{c[view.status]}</p>}
            {attempt && (newerAttempt || !complete && attempt.status !== 'complete') && <p className="windows-full-processes-attempt" role="status">{c[attempt.status === 'expired' ? 'expiredAttempt' : attempt.status]}{attempt.reason && <> · {c[attempt.reason]}</>}{newerAttempt && <> · {c.prior}</>}</p>}
            {complete && <>
                <div className="windows-full-processes-meta"><dl className="windows-full-processes-counts" aria-live="polite" aria-atomic="true"><div><dt>{c.captured}</dt><dd>{complete.manifest.rowCount}</dd></div><div><dt>{c.matching}</dt><dd>{page?.matchingCount ?? '—'}</dd></div><div><dt>{c.visible}</dt><dd>{page?.rows.length ?? '—'}</dd></div></dl><span className="windows-full-processes-age">{c.asOf} <time dateTime={complete.manifest.captureStartedAt}>{fullDate(complete.manifest.captureStartedAt)}</time></span></div>
                <form className="windows-full-processes-controls" onSubmit={event => { event.preventDefault(); resource.apply(); }}><label className="windows-full-processes-search" htmlFor={`${id}-search`}><span className="sr-only">{c.search}</span><Search size={15} aria-hidden="true"/><input id={`${id}-search`} type="search" autoComplete="off" spellCheck={false} maxLength={256} placeholder={c.placeholder} value={resource.controls.search} onChange={event => resource.changeSearch(event.target.value)}/></label><label htmlFor={`${id}-sort`} className="sr-only">{c.sort}</label><select id={`${id}-sort`} value={resource.controls.sort} onChange={event => resource.changeSort(event.target.value as FullProcessesSort)}>{fullProcessesSorts.map(sort => <option key={sort} value={sort}>{c[sort]}</option>)}</select><button type="submit" className="button small">{c.apply}</button></form>
                {page && <>{page.rows.length ? <WindowsFullProcessesTable page={page} locale={locale}/> : <p className="windows-inventory-empty">{complete.manifest.rowCount === 0 ? c.healthyEmpty : c.noMatches}</p>}<nav className="windows-full-processes-pagination" aria-label={c.pages}><span>{c.page(page.offset, page.rows.length, page.matchingCount)}</span><button type="button" className="button small" aria-label={c.previous} disabled={page.offset === 0} onClick={resource.previous}><ChevronLeft size={16} aria-hidden="true"/></button><button type="button" className="button small" aria-label={c.next} disabled={!page.nextCursor} onClick={resource.next}><ChevronRight size={16} aria-hidden="true"/></button></nav></>}
            </>}
        </>}
        <details className="windows-inventory-scope windows-full-processes-details"><summary>{c.details}</summary><p>{c.coverage}</p><p>{c.identity}</p><p>{c.lifetime}</p>{complete && <dl>{time(c.start, complete.manifest.captureStartedAt)}{time(c.finish, complete.manifest.captureFinishedAt)}{time(c.received, complete.receivedAt)}{time(c.expiry, complete.manifest.expiresAt)}{view?.cursorExpiresAt && time(c.cursorExpiry, view.cursorExpiresAt)}<div><dt>{c.generation}</dt><dd>{complete.manifest.generationId}</dd></div><div><dt>{c.sequence}</dt><dd>{complete.manifest.sequence}</dd></div><div><dt>{c.scope}</dt><dd>{complete.manifest.scope} · {complete.manifest.source}</dd></div></dl>}{attempt && <dl>{time(c.latest, attempt.attemptedAt)}<div><dt>{c.sequence}</dt><dd>{attempt.sequence}</dd></div></dl>}</details>
        {children && <details className="windows-inventory-scope windows-full-processes-preview" open={!complete}><summary>{c.preview}</summary>{children}</details>}
    </section>;
}
