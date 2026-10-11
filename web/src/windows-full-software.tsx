import { memo, useId } from 'react';
import { ChevronLeft, ChevronRight, RefreshCw, Search } from 'lucide-react';
import { useOperator } from './auth';
import { useLocale } from './i18n';
import { fullDate } from './utils';
import { useWindowsFullSoftware } from './windows-full-software-resource';
import { fullSoftwareSorts } from './windows-full-software-types';
import type { FullSoftwarePage, FullSoftwareSort } from './windows-full-software-types';
import './windows-inventory.css';
import './windows-inventory-tables.css';
import './windows-full-software.css';

const copy = {
    en: {
        title: 'Machine software', access: 'Sign in as a LAN operator to view software.', refresh: 'Refresh software page', reload: 'Reload latest', restartButton: 'Reload latest software capture', loading: 'Loading software…',
        ready: 'Complete capture', not_configured: 'Local consent required', disabled: 'Collection disabled', awaiting: 'Waiting for first complete capture', unavailable: 'Software unavailable',
        invalid: 'Invalid response. Refresh to retry.', timeout: 'Request timed out. Refresh to retry.', session: 'Your session has ended. Sign in again.', clock: 'Time reference changed. Refresh to verify.', busy: 'Manager busy. Try again shortly.', restart: 'Capture or access changed. Reload latest to continue.', unauthorized: 'Device access ended.', expired: 'Capture or paging session expired. Reload latest.', searchInvalid: 'Search is limited to 256 UTF-8 bytes.',
        pending: 'New capture pending', source_failed: 'Latest capture failed', expiredAttempt: 'Latest attempt expired', complete: 'Latest capture complete', prior: 'Showing earlier capture', latest: 'Latest attempt',
        access_denied: 'Access denied', unsupported: 'Unsupported source', source_changed: 'Source changed', malformed_source: 'Invalid source', resource_limit: 'Capture limit reached', deadline: 'Capture timed out', canceled: 'Capture canceled',
        asOf: 'As of', captured: 'Captured', matching: 'Matching', visible: 'On page', start: 'Capture started', finish: 'Capture finished', received: 'Manager received', expiry: 'Capture expires', cursorExpiry: 'Paging expires', details: 'Scope & capture details', generation: 'Generation', sequence: 'Sequence', scope: 'Source',
        search: 'Search captured software', placeholder: 'Name, version, publisher or view', sort: 'Sort software', apply: 'Apply',
        'name-asc': 'Name · A–Z', 'name-desc': 'Name · Z–A', 'version-asc': 'Version · A–Z', 'version-desc': 'Version · Z–A', 'publisher-asc': 'Publisher · A–Z', 'publisher-desc': 'Publisher · Z–A', 'view-asc': 'View · 32 first', 'view-desc': 'View · 64 first',
        name: 'Name', version: 'Version', publisher: 'Publisher', view: 'Registry view', fieldUnavailable: 'Unavailable', emptyValue: 'Empty value',
        healthyEmpty: 'No machine registrations in this capture.', noMatches: 'No matches in this capture.', previous: 'Previous software page', next: 'Next software page', pages: 'Software pages',
        page: (offset: number, count: number, total: number) => `${count ? offset + 1 : 0}–${offset + count} of ${total}`,
        coverage: 'All caller-visible machine Uninstall registrations in HKLM’s 32-bit and 64-bit views. Per-user, MSIX/Store, portable and unregistered apps are excluded. This is not every installed program or an atomic snapshot.',
        identity: 'Duplicate names remain separate registrations. Unavailable fields could not be read; an empty value was reported as empty. Versions sort as text, not upgrade order. Search is literal and case-insensitive.',
        lifetime: 'Read-only operator data with original capture times and a 24-hour lifetime. A failed attempt never replaces a complete capture. Reading or refreshing does not collect software or grant local consent. Paths, commands and AI export are excluded.',
    },
    de: {
        title: 'Gerätesoftware', access: 'Zum Anzeigen als LAN-Operator anmelden.', refresh: 'Softwareseite aktualisieren', reload: 'Neueste laden', restartButton: 'Neueste Softwareerfassung laden', loading: 'Software wird geladen …',
        ready: 'Vollständig erfasst', not_configured: 'Lokale Zustimmung erforderlich', disabled: 'Erfassung deaktiviert', awaiting: 'Warten auf erste vollständige Erfassung', unavailable: 'Software nicht verfügbar',
        invalid: 'Ungültige Antwort. Erneut aktualisieren.', timeout: 'Zeitlimit überschritten. Erneut aktualisieren.', session: 'Die Sitzung ist beendet. Erneut anmelden.', clock: 'Zeitreferenz geändert. Zur Prüfung aktualisieren.', busy: 'Manager ausgelastet. Gleich erneut versuchen.', restart: 'Erfassung oder Zugriff geändert. Neueste laden.', unauthorized: 'Gerätezugriff beendet.', expired: 'Erfassung oder Seitensitzung abgelaufen. Neueste laden.', searchInvalid: 'Suche auf 256 UTF-8-Bytes begrenzt.',
        pending: 'Neue Erfassung ausstehend', source_failed: 'Neueste Erfassung fehlgeschlagen', expiredAttempt: 'Neuester Versuch abgelaufen', complete: 'Neueste Erfassung vollständig', prior: 'Vorherige Erfassung angezeigt', latest: 'Neuester Versuch',
        access_denied: 'Zugriff verweigert', unsupported: 'Quelle nicht unterstützt', source_changed: 'Quelle geändert', malformed_source: 'Ungültige Quelle', resource_limit: 'Erfassungsgrenze erreicht', deadline: 'Erfassungsfrist erreicht', canceled: 'Erfassung abgebrochen',
        asOf: 'Stand', captured: 'Erfasst', matching: 'Treffer', visible: 'Auf Seite', start: 'Erfassung begonnen', finish: 'Erfassung beendet', received: 'Beim Manager empfangen', expiry: 'Erfassung läuft ab', cursorExpiry: 'Seitensitzung läuft ab', details: 'Umfang & Erfassungsdetails', generation: 'Generation', sequence: 'Sequenz', scope: 'Quelle',
        search: 'Erfasste Software durchsuchen', placeholder: 'Name, Version, Herausgeber oder Ansicht', sort: 'Software sortieren', apply: 'Anwenden',
        'name-asc': 'Name · A–Z', 'name-desc': 'Name · Z–A', 'version-asc': 'Version · A–Z', 'version-desc': 'Version · Z–A', 'publisher-asc': 'Herausgeber · A–Z', 'publisher-desc': 'Herausgeber · Z–A', 'view-asc': 'Ansicht · 32 zuerst', 'view-desc': 'Ansicht · 64 zuerst',
        name: 'Name', version: 'Version', publisher: 'Herausgeber', view: 'Registrierungsansicht', fieldUnavailable: 'Nicht verfügbar', emptyValue: 'Leerer Wert',
        healthyEmpty: 'Keine Geräteregistrierungen in dieser Erfassung.', noMatches: 'Keine Treffer in dieser Erfassung.', previous: 'Vorherige Softwareseite', next: 'Nächste Softwareseite', pages: 'Softwareseiten',
        page: (offset: number, count: number, total: number) => `${count ? offset + 1 : 0}–${offset + count} von ${total}`,
        coverage: 'Alle für den Dienst sichtbaren Uninstall-Geräteregistrierungen in den 32- und 64-Bit-Ansichten von HKLM. Benutzerbezogene, MSIX-/Store-, portable und unregistrierte Apps sind ausgeschlossen. Dies umfasst weder jedes installierte Programm noch eine atomare Momentaufnahme.',
        identity: 'Gleiche Namen bleiben getrennte Registrierungen. Nicht verfügbare Felder konnten nicht gelesen werden; leere Werte wurden leer gemeldet. Versionen werden als Text sortiert, nicht nach Aktualität. Die Suche ist wörtlich und unabhängig von Groß- und Kleinschreibung.',
        lifetime: 'Nur lesbare Operator-Daten mit ursprünglichen Erfassungszeiten und 24 Stunden Gültigkeit. Ein fehlgeschlagener Versuch ersetzt keine vollständige Erfassung. Lesen oder Aktualisieren erfasst keine Software und erteilt keine lokale Zustimmung. Pfade, Befehle und KI-Export sind ausgeschlossen.',
    },
};

export const WindowsFullSoftwareTable = memo(function WindowsFullSoftwareTable({ page, locale }: { page: FullSoftwarePage; locale: 'en' | 'de' }) {
    const c = copy[locale], headers = [c.name, c.version, c.publisher, c.view];
    const sorted = page.sort.startsWith('version') ? 1 : page.sort.startsWith('publisher') ? 2 : page.sort.startsWith('view') ? 3 : 0;
    const value = (field: string | null) => field === null ? <span className="windows-full-software-missing">{c.fieldUnavailable}</span> : field === '' ? <span className="windows-full-software-missing">{c.emptyValue}</span> : field;
    return <div className="windows-inventory-table-wrap"><table className="windows-inventory-table"><caption className="sr-only">{c.title}</caption><thead><tr>{headers.map((header, i) => <th key={header} scope="col" aria-sort={i === sorted ? page.sort.endsWith('desc') ? 'descending' : 'ascending' : undefined}>{header}</th>)}</tr></thead><tbody>{page.rows.map(row => <tr key={row.registrationId} data-registration-id={row.registrationId}><td data-label={c.name}>{value(row.name)}</td><td data-label={c.version}>{value(row.version)}</td><td data-label={c.publisher}>{value(row.publisher)}</td><td data-label={c.view}><span className="windows-full-software-view">HKLM {row.registryView}</span></td></tr>)}</tbody></table></div>;
});

export function WindowsFullSoftwarePanel({ deviceId, sessionKey, enabled = true }: { deviceId: string; sessionKey: string | null; enabled?: boolean }) {
    const operator = useOperator(), [locale] = useLocale();
    if (!operator || operator.mode !== 'lan' || !operator.authenticated) return <p>{copy[locale].access}</p>;
    return <FullSoftware key={`${deviceId}:${sessionKey ?? ''}:${operator.expiresAt ?? ''}`} deviceId={deviceId} sessionKey={sessionKey} enabled={enabled}/>;
}
function FullSoftware({ deviceId, sessionKey, enabled }: { deviceId: string; sessionKey: string | null; enabled: boolean }) {
    const [locale] = useLocale(), c = copy[locale], id = useId(), resource = useWindowsFullSoftware(deviceId, enabled, sessionKey), { view, page } = resource;
    const complete = view?.complete, attempt = view?.latestAttempt, newerAttempt = complete && attempt && attempt.sequence !== complete.manifest.sequence;
    const restart = resource.error === 'restart' || resource.error === 'expired';
    const time = (label: string, value: string) => <div><dt>{label}</dt><dd><time dateTime={value}>{fullDate(value)}</time></dd></div>;
    return <section className="windows-full-software" aria-labelledby={`${id}-title`} aria-busy={resource.loading}>
        <header className="windows-full-software-header"><div><h3 id={`${id}-title`}>{c.title}</h3><span className="windows-full-software-source">HKLM · 32/64</span>{complete && <span className="windows-full-software-complete">{c.ready}</span>}</div><button type="button" className="button small" aria-label={restart ? c.restartButton : c.refresh} disabled={!enabled || resource.loading || resource.error === 'session'} onClick={restart ? resource.restart : resource.refresh}><RefreshCw size={14} aria-hidden="true" className={resource.loading ? 'spin' : undefined}/>{restart ? c.reload : locale === 'de' ? 'Aktualisieren' : 'Refresh'}</button></header>
        {resource.loading && <p className="windows-full-software-status" role="status">{c.loading}</p>}
        {resource.error && <p role="alert" className="windows-inventory-caution">{c[resource.error]}</p>}
        {view && !resource.loading && <>
            {!complete && <p className="windows-full-software-status" role="status">{c[view.status]}</p>}
            {attempt && (newerAttempt || !complete && attempt.status !== 'complete') && <p className="windows-full-software-attempt" role="status">{c[attempt.status === 'expired' ? 'expiredAttempt' : attempt.status]}{attempt.reason && <> · {c[attempt.reason]}</>}{newerAttempt && <> · {c.prior}</>}</p>}
            {complete && <>
                <div className="windows-full-software-meta"><dl className="windows-full-software-counts" aria-live="polite" aria-atomic="true"><div><dt>{c.captured}</dt><dd>{complete.manifest.rowCount}</dd></div><div><dt>{c.matching}</dt><dd>{page?.matchingCount ?? '—'}</dd></div><div><dt>{c.visible}</dt><dd>{page?.rows.length ?? '—'}</dd></div></dl><span className="windows-full-software-age">{c.asOf} <time dateTime={complete.manifest.captureStartedAt}>{fullDate(complete.manifest.captureStartedAt)}</time></span></div>
                <form className="windows-full-software-controls" onSubmit={event => { event.preventDefault(); resource.apply(); }}><label className="windows-full-software-search" htmlFor={`${id}-search`}><span className="sr-only">{c.search}</span><Search size={15} aria-hidden="true"/><input id={`${id}-search`} type="search" autoComplete="off" spellCheck={false} maxLength={256} placeholder={c.placeholder} value={resource.controls.search} onChange={event => resource.changeSearch(event.target.value)}/></label><label htmlFor={`${id}-sort`} className="sr-only">{c.sort}</label><select id={`${id}-sort`} value={resource.controls.sort} onChange={event => resource.changeSort(event.target.value as FullSoftwareSort)}>{fullSoftwareSorts.map(sort => <option key={sort} value={sort}>{c[sort]}</option>)}</select><button type="submit" className="button small">{c.apply}</button></form>
                {page && <>{page.rows.length ? <WindowsFullSoftwareTable page={page} locale={locale}/> : <p className="windows-inventory-empty">{complete.manifest.rowCount === 0 ? c.healthyEmpty : c.noMatches}</p>}<nav className="windows-full-software-pagination" aria-label={c.pages}><span>{c.page(page.offset, page.rows.length, page.matchingCount)}</span><button type="button" className="button small" aria-label={c.previous} disabled={page.offset === 0} onClick={resource.previous}><ChevronLeft size={16} aria-hidden="true"/></button><button type="button" className="button small" aria-label={c.next} disabled={!page.nextCursor} onClick={resource.next}><ChevronRight size={16} aria-hidden="true"/></button></nav></>}
            </>}
        </>}
        <details className="windows-inventory-scope windows-full-software-details"><summary>{c.details}</summary><p>{c.coverage}</p><p>{c.identity}</p><p>{c.lifetime}</p>{complete && <dl>{time(c.start, complete.manifest.captureStartedAt)}{time(c.finish, complete.manifest.captureFinishedAt)}{time(c.received, complete.receivedAt)}{time(c.expiry, complete.manifest.expiresAt)}{view?.cursorExpiresAt && time(c.cursorExpiry, view.cursorExpiresAt)}<div><dt>{c.generation}</dt><dd>{complete.manifest.generationId}</dd></div><div><dt>{c.sequence}</dt><dd>{complete.manifest.sequence}</dd></div><div><dt>{c.scope}</dt><dd>{complete.manifest.scope} · {complete.manifest.source}</dd></div></dl>}{attempt && <dl>{time(c.latest, attempt.attemptedAt)}<div><dt>{c.sequence}</dt><dd>{attempt.sequence}</dd></div></dl>}</details>
    </section>;
}
