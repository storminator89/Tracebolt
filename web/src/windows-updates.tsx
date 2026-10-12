import { useId, useMemo, useState } from 'react';
import { useLocale } from './i18n';
import { fullDate } from './utils';
import type { WindowsInventoryResource } from './windows-inventory-resource';
import type { WindowsUpdate, WindowsUpdates } from './windows-updates-types';
import './windows-inventory-tables.css';
import './windows-updates.css';

const copy = {
    en: {
        title: 'Cached Windows Updates', missing: 'Cached Windows Update inspection is not included in this report. It requires separate local consent.', unavailable: 'No accepted cached update report is available.', expired: 'This cached update report expired. Rows are hidden 24 hours after the original capture.',
        caution: 'Cached data only. Cache freshness is unknown; this is not a current patch assessment. An empty result does not mean the device is fully patched.',
        refreshSummary: 'Refresh reads the saved report only; it does not scan or install.',
        refresh: 'Refresh checks only the latest accepted manager report. It does not start an online scan, refresh the Windows cache, download or install updates.',
        ahead: 'The capture time is ahead of the manager clock or the time reference changed. Update rows are hidden until the timing can be verified.', captured: 'Cache inspected', stale: 'Stale inspection. These values describe the original capture; the cache itself may be older.',
        observed: 'Cached result observed', bounded: 'Bounded cached result', partial: 'Partial cached result', denied: 'Access denied', unavailableQuality: 'Unavailable',
        retained: 'captured', observedCount: 'cached results observed', atLeast: 'at least', omitted: 'Some rows are omitted by collection, metadata-read or transfer limits.',
        empty: 'No non-hidden, not-installed software updates were returned from this caller-visible cache. This does not establish current patch coverage.', failed: 'No update rows are available. This does not establish an empty cache or a fully patched device.',
        search: 'Filter captured updates', sort: 'Sort captured updates', noMatches: 'No captured updates match this filter.',
        'title-asc': 'Title: A to Z', 'title-desc': 'Title: Z to A', 'severity-desc': 'Vendor severity: highest first', 'severity-asc': 'Vendor severity: lowest first', 'downloaded-desc': 'Already downloaded: first', 'downloaded-asc': 'Not downloaded: first',
        rowTitle: 'Title', kb: 'KB articles', severity: 'Vendor severity', downloaded: 'Already downloaded', identity: 'Update ID / revision', revision: 'Revision', yes: 'Yes', no: 'No', unspecified: 'Unspecified', critical: 'Critical', important: 'Important', moderate: 'Moderate', low: 'Low', noKB: 'None reported', shortened: 'Title or KB metadata shortened',
        bounds: 'Scope & limits', source: 'Source: wua-cache · cache freshness: unknown', scope: 'Caller-visible cached Windows Update Agent results for non-hidden, not-installed software updates. Installed, hidden and driver updates are excluded; the configured source and default supersedence behavior are unchanged.',
        counts: 'The observed count describes this cached search, before row validation and retention limits. Exact counts do not guarantee readable metadata or whole-device coverage. Partial counts can be lower bounds, including zero.',
        tableScope: 'Search, sorting and pages cover captured rows only; other updates may be missing.',
        limits: 'At most 128 native entries are examined and 64 rows retained within 24 KiB. Search, sorting and pages use only these accepted rows. They cannot recover omitted updates or prove the highest-severity updates were retained.',
        meaning: 'Vendor severity is a label, not a CVE match or proof of exploitability. “Already downloaded” is the cached WUA flag, not a download request or installation state. Shortened metadata can affect search results.',
        privacy: 'Cached observations are read-only operator data. This observation scope performs no update actions, EULA acceptance, reboot, service changes or AI export.',
        reasons: { windows_updates_access_denied: 'The local caller was denied access.', windows_updates_unavailable: 'The local update source was unavailable.', windows_updates_unsupported_platform: 'This source is unsupported on the reporting platform.', windows_updates_invalid_metadata: 'Some source metadata could not be validated.', windows_updates_bounds: 'A collection or byte limit was reached.', windows_updates_offline_not_verified: 'Offline-only inspection could not be verified; collection stopped.', windows_updates_partial_result: 'The cached search returned a partial result.', windows_updates_budget_exhausted: 'The collection budget was exhausted.' },
        previous: 'Previous page', next: 'Next page', pages: 'Captured update pages', count: (start: number, end: number, matches: number, captured: number) => `Rows ${start}–${end} of ${matches} matching · ${captured} captured`, page: (current: number, total: number) => `Page ${current} of ${total}`,
    },
    de: {
        title: 'Windows-Updates aus dem Cache', missing: 'Die Prüfung des Windows-Update-Caches ist in dieser Meldung nicht enthalten. Sie benötigt eine separate lokale Zustimmung.', unavailable: 'Keine akzeptierte Meldung zum Update-Cache verfügbar.', expired: 'Diese Meldung zum Update-Cache ist abgelaufen. Zeilen werden 24 Stunden nach der ursprünglichen Erfassung ausgeblendet.',
        caution: 'Nur Cache-Daten. Die Aktualität des Caches ist unbekannt; dies ist keine aktuelle Patch-Bewertung. Ein leeres Ergebnis bedeutet nicht, dass das Gerät vollständig gepatcht ist.',
        refreshSummary: 'Aktualisieren liest nur die gespeicherte Meldung; es sucht und installiert keine Updates.',
        refresh: 'Aktualisieren prüft nur die neueste akzeptierte Manager-Meldung. Es startet keine Online-Suche, aktualisiert den Windows-Cache nicht und lädt oder installiert keine Updates.',
        ahead: 'Die Erfassungszeit liegt aus Sicht des Managers in der Zukunft oder die Zeitreferenz hat sich geändert. Updatezeilen bleiben ausgeblendet, bis die Zeit geprüft werden kann.', captured: 'Cache geprüft', stale: 'Veraltete Prüfung. Diese Werte beschreiben die ursprüngliche Erfassung; der Cache selbst kann älter sein.',
        observed: 'Cache-Ergebnis beobachtet', bounded: 'Begrenztes Cache-Ergebnis', partial: 'Teilweises Cache-Ergebnis', denied: 'Zugriff verweigert', unavailableQuality: 'Nicht verfügbar',
        retained: 'erfasst', observedCount: 'Cache-Ergebnisse beobachtet', atLeast: 'mindestens', omitted: 'Einige Zeilen fehlen durch Erfassungs-, Metadatenlese- oder Übertragungsgrenzen.',
        empty: 'Aus diesem für den Aufrufer sichtbaren Cache wurden keine nicht ausgeblendeten, nicht installierten Softwareupdates zurückgegeben. Dies belegt keine aktuelle Patch-Abdeckung.', failed: 'Keine Updatezeilen verfügbar. Dies belegt weder einen leeren Cache noch ein vollständig gepatchtes Gerät.',
        search: 'Erfasste Updates filtern', sort: 'Erfasste Updates sortieren', noMatches: 'Keine erfassten Updates entsprechen diesem Filter.',
        'title-asc': 'Titel: A bis Z', 'title-desc': 'Titel: Z bis A', 'severity-desc': 'Hersteller-Schweregrad: höchste zuerst', 'severity-asc': 'Hersteller-Schweregrad: niedrigste zuerst', 'downloaded-desc': 'Bereits heruntergeladen: zuerst', 'downloaded-asc': 'Nicht heruntergeladen: zuerst',
        rowTitle: 'Titel', kb: 'KB-Artikel', severity: 'Hersteller-Schweregrad', downloaded: 'Bereits heruntergeladen', identity: 'Update-ID / Revision', revision: 'Revision', yes: 'Ja', no: 'Nein', unspecified: 'Nicht angegeben', critical: 'Kritisch', important: 'Wichtig', moderate: 'Mittel', low: 'Niedrig', noKB: 'Keine gemeldet', shortened: 'Titel oder KB-Metadaten gekürzt',
        bounds: 'Umfang & Grenzen', source: 'Quelle: wua-cache · Cache-Aktualität: unbekannt', scope: 'Für den Aufrufer sichtbare Cache-Ergebnisse des Windows Update Agent für nicht ausgeblendete, nicht installierte Softwareupdates. Installierte, ausgeblendete und Treiberupdates sind ausgeschlossen; konfigurierte Quelle und Standardverhalten für ersetzte Updates bleiben unverändert.',
        counts: 'Die beobachtete Zahl beschreibt diese Cache-Suche vor Zeilenvalidierung und Aufbewahrungsgrenzen. Exakte Zahlen garantieren weder lesbare Metadaten noch eine vollständige Geräteabdeckung. Teilweise erfasste Zahlen können Untergrenzen sein, auch bei null.',
        tableScope: 'Suche, Sortierung und Seiten zeigen nur erfasste Zeilen; weitere Updates können fehlen.',
        limits: 'Höchstens 128 native Einträge werden geprüft und 64 Zeilen innerhalb von 24 KiB aufbewahrt. Suche, Sortierung und Seiten nutzen nur diese akzeptierten Zeilen. Fehlende Updates werden dadurch nicht sichtbar; die Auswahl belegt nicht, dass die schwerwiegendsten Updates enthalten sind.',
        meaning: 'Der Hersteller-Schweregrad ist eine Kennzeichnung, kein CVE-Abgleich oder Beleg für Ausnutzbarkeit. „Bereits heruntergeladen“ ist das gespeicherte WUA-Kennzeichen, kein Downloadauftrag oder Installationsstatus. Gekürzte Metadaten können Suchergebnisse beeinflussen.',
        privacy: 'Die Cache-Prüfung liefert rein lesende Operatordaten. Dieser Beobachtungsumfang umfasst keine Updateaktionen, EULA-Zustimmung, Neustarts, Dienständerungen oder KI-Übertragung.',
        reasons: { windows_updates_access_denied: 'Dem lokalen Aufrufer wurde der Zugriff verweigert.', windows_updates_unavailable: 'Die lokale Updatequelle war nicht verfügbar.', windows_updates_unsupported_platform: 'Diese Quelle wird auf der meldenden Plattform nicht unterstützt.', windows_updates_invalid_metadata: 'Einige Quellmetadaten konnten nicht validiert werden.', windows_updates_bounds: 'Eine Erfassungs- oder Bytegrenze wurde erreicht.', windows_updates_offline_not_verified: 'Die reine Offline-Prüfung konnte nicht bestätigt werden; die Erfassung wurde beendet.', windows_updates_partial_result: 'Die Cache-Suche lieferte ein Teilergebnis.', windows_updates_budget_exhausted: 'Das Erfassungsbudget wurde ausgeschöpft.' },
        previous: 'Vorherige Seite', next: 'Nächste Seite', pages: 'Seiten der erfassten Updates', count: (start: number, end: number, matches: number, captured: number) => `Zeilen ${start}–${end} von ${matches} Treffern · ${captured} erfasst`, page: (current: number, total: number) => `Seite ${current} von ${total}`,
    },
};
const sorts = ['title-asc', 'title-desc', 'severity-desc', 'severity-asc', 'downloaded-desc', 'downloaded-asc'] as const;
export type WindowsUpdatesSort = typeof sorts[number];
type Locale = 'en' | 'de';
const severityRank = { unspecified: 0, low: 1, moderate: 2, important: 3, critical: 4 };
const tie = (a: WindowsUpdate, b: WindowsUpdate) => a.updateId < b.updateId ? -1 : a.updateId > b.updateId ? 1 : a.revision - b.revision;
/** Pure local operations over accepted rows, never source lookups or joins. */
export function capturedWindowsUpdateRows(updates: WindowsUpdates, query: string, sort: WindowsUpdatesSort, locale: Locale) {
    const c = copy[locale], filter = query.trim().toLocaleLowerCase(locale), compare = new Intl.Collator(locale).compare;
    return updates.rows.filter(row => [row.title, row.updateId, String(row.revision), ...row.kbArticleIds, row.severity, c[row.severity], row.downloaded ? c.yes : c.no, row.metadataTruncated ? c.shortened : ''].some(value => value.toLocaleLowerCase(locale).includes(filter))).sort((a, b) => {
        // An absent vendor label stays last in either severity direction.
        if (sort.startsWith('severity-') && (a.severity === 'unspecified' || b.severity === 'unspecified')) return a.severity === b.severity ? tie(a, b) : a.severity === 'unspecified' ? 1 : -1;
        const order = sort.startsWith('severity-') ? severityRank[a.severity] - severityRank[b.severity] : sort.startsWith('downloaded-') ? Number(a.downloaded) - Number(b.downloaded) : compare(a.title, b.title);
        return order * (sort.endsWith('-desc') ? -1 : 1) || tie(a, b);
    });
}
interface Controls { query: string; sort: WindowsUpdatesSort; page: number }
const initialControls = (): Controls => ({ query: '', sort: 'title-asc', page: 0 });
function UpdatesTable({ updates, locale, controls, onChange }: { updates: WindowsUpdates; locale: Locale; controls: Controls; onChange: (value: Controls) => void }) {
    const id = useId(), c = copy[locale], { query, sort, page } = controls;
    const rows = useMemo(() => capturedWindowsUpdateRows(updates, query, sort, locale), [updates, query, sort, locale]);
    const pages = Math.max(1, Math.ceil(rows.length / 25)), current = Math.min(page, pages - 1), start = current * 25, visible = rows.slice(start, start + 25);
    const headers = [c.rowTitle, c.kb, c.severity, c.downloaded, c.identity], sortedColumn = sort.startsWith('severity-') ? 2 : sort.startsWith('downloaded-') ? 3 : 0;
    return <>
        <p className="windows-inventory-exclusions" id={`${id}-bounds`}>{c.tableScope}</p>
        <div className="windows-inventory-table-controls">
            <label className="windows-inventory-search" htmlFor={`${id}-search`}>{c.search}<input id={`${id}-search`} type="search" value={query} maxLength={256} aria-describedby={`${id}-bounds`} onChange={event => onChange({ ...controls, query: event.target.value, page: 0 })}/></label>
            <div className="windows-inventory-table-sort"><label htmlFor={`${id}-sort`}>{c.sort}</label><select id={`${id}-sort`} value={sort} aria-describedby={`${id}-bounds`} onChange={event => onChange({ ...controls, sort: event.target.value as WindowsUpdatesSort, page: 0 })}>{sorts.map(value => <option key={value} value={value}>{c[value]}</option>)}</select></div>
        </div>
        <p className="windows-inventory-count" role="status" aria-live="polite" aria-atomic="true">{c.count(visible.length ? start + 1 : 0, start + visible.length, rows.length, updates.rows.length)}</p>
        {visible.length ? <div className="windows-inventory-table-wrap"><table className="windows-inventory-table windows-updates-table"><caption className="sr-only">{c.title}</caption><thead><tr>{headers.map((header, i) => <th scope="col" key={header} aria-sort={i === sortedColumn ? sort.endsWith('-desc') ? 'descending' : 'ascending' : undefined}>{header}</th>)}</tr></thead><tbody>{visible.map(row => <tr key={`${row.updateId}:${row.revision}`}>
            <td data-label={c.rowTitle}><span>{row.title}{row.metadataTruncated && <small className="windows-updates-shortened">{c.shortened}</small>}</span></td>
            <td data-label={c.kb}>{row.kbArticleIds.length ? row.kbArticleIds.join(', ') : c.noKB}</td>
            <td data-label={c.severity}>{c[row.severity]}</td><td data-label={c.downloaded}>{row.downloaded ? c.yes : c.no}</td>
            <td data-label={c.identity}><span>{row.updateId}<small className="windows-updates-revision">{c.revision} {row.revision}</small></span></td>
        </tr>)}</tbody></table></div> : <p>{c.noMatches}</p>}
        <nav className="windows-inventory-table-pagination" aria-label={c.pages}><button type="button" className="button small" disabled={current === 0} onClick={() => onChange({ ...controls, page: current - 1 })}>{c.previous}</button><span>{c.page(current + 1, pages)}</span><button type="button" className="button small" disabled={current + 1 >= pages} onClick={() => onChange({ ...controls, page: current + 1 })}>{c.next}</button></nav>
    </>;
}
export function WindowsUpdatesPanel({ resource }: { resource: WindowsInventoryResource }) {
    const [locale] = useLocale(), c = copy[locale], updates = resource.updates;
    const scope = updates ? `${resource.view?.deviceId}:${updates.generationId}:${updates.collectedAt}:${updates.grantId}` : null;
    const [state, setState] = useState<Controls & { scope: string | null }>(() => ({ ...initialControls(), scope }));
    // Keep controls only during a same-generation reread. Absence, error, expiry,
    // identity/grant/capture replacement and tab unmount remove private filters.
    const reset = scope !== null ? state.scope !== scope : !resource.loading && state.scope !== null;
    const controls = reset ? { ...initialControls(), scope } : state;
    if (reset) setState(controls);
    const quality = updates?.quality === 'unavailable' ? c.unavailableQuality : updates?.quality === 'observed' && updates.truncated ? c.bounded : updates ? c[updates.quality] : null;
    return <section className="windows-updates" aria-label={c.title}>
        <div className="windows-inventory-section-header"><h3>{c.title}</h3>{quality && <span className="windows-inventory-quality">{quality}</span>}</div>
        <p className="windows-inventory-caution">{c.caution}</p><p className="windows-inventory-exclusions">{c.refreshSummary}</p>
        {!updates ? <p role="status" className="windows-inventory-empty">{resource.updatesExpired ? c.expired : resource.updatesAhead ? c.ahead : resource.snapshot ? c.missing : c.unavailable}</p> : <>
            <p className="windows-inventory-times">{c.captured} <time dateTime={updates.collectedAt}>{fullDate(updates.collectedAt)}</time></p>
            {resource.updatesStale && <p role="status" className="windows-inventory-caution">{c.stale}</p>}
            <p className="windows-inventory-exclusions">{c.source}</p>
            {(updates.quality === 'observed' || updates.quality === 'partial') && <p className="windows-inventory-count">{updates.rows.length} {c.retained} · {updates.countExact ? '' : `${c.atLeast} `}{updates.observedCount} {c.observedCount}</p>}
            {updates.reason && <p className="windows-inventory-caution">{c.reasons[updates.reason]}</p>}{updates.truncated && <p className="windows-inventory-caution">{c.omitted}</p>}
            {updates.rows.length ? <UpdatesTable updates={updates} locale={locale} controls={controls} onChange={value => setState({ ...value, scope: controls.scope })}/> : <p className="windows-inventory-empty">{updates.quality === 'observed' && updates.observedCount === 0 ? c.empty : c.failed}</p>}
        </>}
        <details className="windows-inventory-scope"><summary>{c.bounds}</summary><p>{c.scope}</p><p>{c.refresh}</p><p>{c.counts}</p><p>{c.limits}</p><p>{c.meaning}</p><p>{c.privacy}</p></details>
    </section>;
}
