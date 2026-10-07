import { InventoryLiveStatus } from './inventory-live-status';
import { useId, useState } from 'react';
import { ChevronDown, Info, LoaderCircle, RefreshCw, Search, TriangleAlert } from 'lucide-react';
import { useOperator } from './auth';
import { useLocale } from './i18n';
import { completeGenerationVisible, inventoryAge } from './complete-packages-types';
import { useCompletePackages } from './complete-packages-resource';
import './package-observations.css';
import './complete-packages.css';

export const completePackageCopy = {
    en: {
        disclosure: 'Complete dpkg inventory', title: 'Packages · dpkg', access: 'Authenticated LAN operator access is required.',
        intro: 'Installed and incomplete dpkg rows in the agent-visible namespace. Excludes Snap, Flatpak and other sources; no update or CVE assessment.',
        refresh: 'Refresh inventory and restart', loading: 'Reading package inventory…', not_configured: 'Complete package collection not configured', awaiting: 'Awaiting a complete generation', available: 'Complete generation available', revoked: 'Device identity revoked', unavailable: 'Complete package inventory unavailable',
        configure: 'Requires fresh managed-operations-v3 enrollment and explicit consent. Earlier profiles keep their scope.',
        historical: 'Historical generation metadata', expired: 'The retained generation has expired. Its metadata is historical; package rows are unavailable.',
        loadError: 'The manager could not be read. Retry the request or refresh the inventory.', invalid: 'The manager returned inconsistent or unsupported inventory. Rows were cleared.', timeout: 'The request timed out. Retry the request or refresh the inventory.', session: 'Your session has ended. Sign in again.', clock: 'The time anchor is no longer reliable. Refresh the inventory before continuing.', busy: 'The manager is busy. Retry in a moment.', restart: 'The generation or paging session expired or changed. Refresh to explicitly restart; previous pages were cleared.', searchInvalid: 'Use at most 128 printable ASCII characters for search.',
        search: 'Search packages', searchHint: 'Searches all seven fields, up to 2,048 rows per request and 100 matches per page. Continue to scan the full generation.', submit: 'Search', next: 'Next 100 rows', continue: 'Continue search', retry: 'Retry request',
        continuing: 'No matches in this scan window. More rows remain; continue the search.', noMatches: 'No matches in the complete generation.', noPageMatches: 'No further matches. Earlier pages contained matches.', zero: 'The completed generation contains zero installed or incomplete dpkg rows.', finished: 'The entire generation has been scanned.', more: 'More rows remain in this generation.',
        observed: 'Generation rows', installed: 'Installed rows', scanned: 'Rows scanned so far', matches: 'Matches found so far', shown: 'Rows on this page', generation: 'Generation', sequence: 'Sequence', collected: 'Original collection time', completed: 'Completed by manager', retained: 'Rows retained until', age: 'Observation age (minutes)',
        transfer: 'Latest transfer', pending: 'Transfer pending', complete: 'Transfer completed', failed: 'Transfer failed', transferExpired: 'Transfer expired', accepted: 'Accepted / declared rows', chunks: 'Accepted / expected chunks', transferNote: 'Declared counts are not completion. Pending or failed transfers leave the prior generation and its age unchanged.',
        failure: 'Latest collection attempt failed', attempted: 'Attempted at', source_missing: 'Source unavailable', source_invalid: 'Source invalid', source_changed: 'Source changed during collection', resource_limit: 'Resource limit reached', collection_failed: 'Collection failed',
        binary: 'Binary package', version: 'Binary version', architecture: 'Architecture', source: 'Source package', sourceVersion: 'Source version', mapping: 'Mapping basis', state: 'Install state', 'source-field': 'Explicit Source field', 'binary-default': 'Absent Source field: binary default', installedState: 'Installed', incompleteState: 'Incomplete',
        retention: 'Original capture age is preserved when paging or when a newer capture fails.',
    },
    de: {
        disclosure: 'Vollständiges dpkg-Inventar', title: 'Pakete · dpkg', access: 'Ein authentifizierter LAN-Operator-Zugang ist erforderlich.',
        intro: 'Installierte und unvollständige dpkg-Einträge im Agent-Namensraum. Ohne Snap, Flatpak und andere Quellen; keine Update- oder CVE-Bewertung.',
        refresh: 'Inventar aktualisieren und neu beginnen', loading: 'Paketinventar wird gelesen…', not_configured: 'Vollständige Paketerfassung nicht eingerichtet', awaiting: 'Vollständige Generation ausstehend', available: 'Vollständige Generation verfügbar', revoked: 'Geräteidentität widerrufen', unavailable: 'Vollständiges Paketinventar nicht verfügbar',
        configure: 'Benötigt neues managed-operations-v3-Enrollment mit ausdrücklicher Zustimmung. Frühere Profile behalten ihren Umfang.',
        historical: 'Historische Generationsmetadaten', expired: 'Die gespeicherte Generation ist abgelaufen. Ihre Metadaten sind historisch; Paketzeilen sind nicht verfügbar.',
        loadError: 'Der Manager konnte nicht gelesen werden. Anfrage wiederholen oder Inventar aktualisieren.', invalid: 'Der Manager lieferte widersprüchliches oder nicht unterstütztes Inventar. Zeilen wurden entfernt.', timeout: 'Die Anfrage hat das Zeitlimit überschritten. Anfrage wiederholen oder Inventar aktualisieren.', session: 'Die Sitzung ist beendet. Erneut anmelden.', clock: 'Der Zeitanker ist nicht mehr verlässlich. Vor dem Fortfahren Inventar aktualisieren.', busy: 'Der Manager ist ausgelastet. Gleich erneut versuchen.', restart: 'Die Generation oder Seitensitzung ist abgelaufen oder wurde geändert. Zum ausdrücklichen Neubeginn aktualisieren; vorherige Seiten wurden entfernt.', searchInvalid: 'Für die Suche höchstens 128 druckbare ASCII-Zeichen verwenden.',
        search: 'Pakete durchsuchen', searchHint: 'Durchsucht alle sieben Felder: bis zu 2.048 Zeilen je Anfrage und 100 Treffer je Seite. Für die ganze Generation fortsetzen.', submit: 'Suchen', next: 'Nächste 100 Zeilen', continue: 'Suche fortsetzen', retry: 'Anfrage wiederholen',
        continuing: 'Keine Treffer in diesem Suchabschnitt. Weitere Zeilen stehen aus; Suche fortsetzen.', noMatches: 'Keine Treffer in der vollständigen Generation.', noPageMatches: 'Keine weiteren Treffer. Frühere Seiten enthielten Treffer.', zero: 'Die abgeschlossene Generation enthält keine installierten oder unvollständigen dpkg-Einträge.', finished: 'Die gesamte Generation wurde durchsucht.', more: 'Weitere Zeilen dieser Generation stehen aus.',
        observed: 'Zeilen der Generation', installed: 'Installierte Zeilen', scanned: 'Bisher geprüfte Zeilen', matches: 'Bisher gefundene Treffer', shown: 'Zeilen auf dieser Seite', generation: 'Generation', sequence: 'Sequenz', collected: 'Ursprüngliche Erfassungszeit', completed: 'Vom Manager abgeschlossen', retained: 'Zeilen verfügbar bis', age: 'Alter der Beobachtung (Minuten)',
        transfer: 'Neueste Übertragung', pending: 'Übertragung ausstehend', complete: 'Übertragung abgeschlossen', failed: 'Übertragung fehlgeschlagen', transferExpired: 'Übertragung abgelaufen', accepted: 'Akzeptierte / deklarierte Zeilen', chunks: 'Akzeptierte / erwartete Blöcke', transferNote: 'Deklarierte Zahlen belegen keinen Abschluss. Ausstehende oder fehlgeschlagene Übertragungen ändern weder vorherige Generation noch Alter.',
        failure: 'Neuester Erfassungsversuch fehlgeschlagen', attempted: 'Versuch am', source_missing: 'Quelle nicht verfügbar', source_invalid: 'Quelle ungültig', source_changed: 'Quelle während der Erfassung geändert', resource_limit: 'Ressourcengrenze erreicht', collection_failed: 'Erfassung fehlgeschlagen',
        binary: 'Binärpaket', version: 'Binärversion', architecture: 'Architektur', source: 'Quellpaket', sourceVersion: 'Quellversion', mapping: 'Zuordnungsgrundlage', state: 'Installationszustand', 'source-field': 'Ausdrückliches Source-Feld', 'binary-default': 'Source-Feld fehlt: Binärvorgabe', installedState: 'Installiert', incompleteState: 'Unvollständig',
        retention: 'Blättern und neue fehlgeschlagene Erfassungen ändern das ursprüngliche Erfassungsalter nicht.',
    },
};
export function CompletePackagesPanel({ deviceId, sessionKey, inline = false }: { deviceId: string; sessionKey?: string | number; inline?: boolean }) {
    const operator = useOperator(), [locale] = useLocale();
    if (!operator || operator.mode !== 'lan' || !operator.authenticated) return <p>{completePackageCopy[locale].access}</p>;
    // A renewed/replaced private session cannot reuse a disclosure, request or cursor.
    if (inline) return <CompletePackages key={`${deviceId}:${sessionKey ?? operator.expiresAt ?? ''}`} deviceId={deviceId}/>;
    return <CompleteDisclosure key={`${deviceId}:${sessionKey ?? ''}:${operator.expiresAt ?? ''}`} deviceId={deviceId}/>;
}
function CompleteDisclosure({ deviceId }: { deviceId: string }) {
    const [open, setOpen] = useState(false), [locale] = useLocale(), id = useId();
    return <section className="package-disclosure"><button className="package-disclosure-toggle" type="button" aria-expanded={open} aria-controls={id} onClick={() => setOpen(value => !value)}>{completePackageCopy[locale].disclosure}<ChevronDown size={16}/></button><div id={id}>{open && <CompletePackages deviceId={deviceId}/>}</div></section>;
}
function CompletePackages({ deviceId }: { deviceId: string }) {
    const [locale] = useLocale(), labels = completePackageCopy[locale], id = useId(), resource = useCompletePackages(deviceId);
    const { view, page } = resource, selected = view?.complete, visible = view && completeGenerationVisible(view, resource.elapsed);
    const number = (value: number) => new Intl.NumberFormat(locale).format(value);
    const field = (name: string, value: string) => <div><dt>{name}</dt><dd>{value}</dd></div>;
    return <div className="package-observations complete-packages" aria-labelledby={id} aria-busy={resource.loading}>
        <header className="package-heading"><h3 id={id}>{labels.title}</h3><button className="button small" type="button" disabled={resource.loading || resource.error === 'session'} onClick={resource.refresh} aria-label={labels.refresh} title={labels.refresh}><RefreshCw size={14}/>{locale === 'de' ? 'Aktualisieren' : 'Refresh'}</button></header>
        <p className="package-note">{labels.intro}</p>
        <InventoryLiveStatus state={resource.liveState}/>
        {resource.loading && <p role="status"><LoaderCircle size={16} className="spin"/>{labels.loading}</p>}
        {resource.error && <p className="package-error" role="alert"><TriangleAlert size={16}/>{labels[resource.error]}</p>}
        {['busy', 'timeout', 'loadError'].includes(resource.error ?? '') && <button type="button" className="button small" disabled={resource.loading} onClick={resource.retry}>{labels.retry}</button>}
        {view && <>
            <p className="package-status">{view.status === 'available' && !visible ? labels.historical : labels[view.status]}</p>{view.status === 'not_configured' && <p>{labels.configure}</p>}
            {selected && <>
                {!visible && <p role="status" className="package-error">{view.status === 'revoked' ? labels.revoked : labels.expired}</p>}
                <dl className="package-counts">{field(labels.observed, number(selected.manifest.observedCount))}{field(labels.installed, number(selected.manifest.installedCount))}</dl>
                <dl className="package-facts">{field(labels.generation, selected.binding.generationId)}{field(labels.sequence, selected.binding.sequence)}{field(labels.collected, selected.manifest.collectedAt)}{field(labels.completed, selected.completedAt)}{field(labels.retained, selected.retainedUntil)}{Number.isFinite(resource.elapsed) && field(labels.age, number(Math.floor(Math.max(0, inventoryAge(view.serverNow, selected.manifest.collectedAt) + resource.elapsed) / 60000)))}</dl>
            </>}
            {view.transfer && <section aria-label={labels.transfer}><h4>{labels.transfer}</h4><p>{labels[view.transfer.state === 'expired' ? 'transferExpired' : view.transfer.state]}</p><dl className="package-facts">{field(labels.accepted, `${number(view.transfer.acceptedRows)} / ${number(view.transfer.declaredRows)}`)}{field(labels.chunks, `${number(view.transfer.acceptedChunks)} / ${number(view.transfer.expectedChunks)}`)}{field(labels.collected, view.transfer.collectedAt)}</dl><p className="package-note">{labels.transferNote}</p></section>}
            {view.failure && <section aria-label={labels.failure}><h4>{labels.failure}</h4><p>{labels[view.failure.reason]}</p><dl className="package-facts">{field(labels.attempted, view.failure.attemptedAt)}{field(labels.sequence, view.failure.sequence)}</dl></section>}
            {visible && <section>
                <form className="complete-package-search" onSubmit={event => { event.preventDefault(); resource.startSearch(); }}><label htmlFor={`${id}-search`}>{labels.search}</label><div><input id={`${id}-search`} type="search" value={resource.search} maxLength={128} onChange={event => resource.changeSearch(event.target.value)} autoComplete="off" spellCheck={false}/><button type="submit" className="button" disabled={resource.loading}><Search size={15}/>{labels.submit}</button></div><p className="package-note">{labels.searchHint}</p></form>
                {page && <>
                    <dl className="package-counts">{field(labels.scanned, `${number(resource.scanned)} / ${number(page.totalRows)}`)}{field(labels.matches, number(resource.matches))}{field(labels.shown, number(page.items.length))}</dl>
                    {page.items.length > 0 ? <div className="package-table-scroll" role="region" aria-label={labels.disclosure} tabIndex={0}><table><caption className="sr-only">{labels.disclosure}</caption><thead><tr>{[labels.binary, labels.version, labels.architecture, labels.source, labels.sourceVersion, labels.mapping, labels.state].map(label => <th key={label} scope="col">{label}</th>)}</tr></thead><tbody>{page.items.map(row => <tr key={`${row.name}:${row.architecture}`}><th scope="row">{row.name}</th><td>{row.version}</td><td>{row.architecture}</td><td>{row.sourcePackage}</td><td>{row.sourceVersion}</td><td>{labels[row.sourceMapping]}</td><td>{row.installState === 'installed' ? labels.installedState : labels.incompleteState}</td></tr>)}</tbody></table></div> : <p role="status">{!page.exhausted ? labels.continuing : page.totalRows === 0 ? labels.zero : resource.matches === 0 ? labels.noMatches : labels.noPageMatches}</p>}
                    <div className="complete-package-pagination"><p>{page.exhausted ? labels.finished : labels.more}</p>{!page.exhausted && <button className="button" type="button" disabled={resource.loading} onClick={resource.next}>{resource.search.trim() ? labels.continue : labels.next}</button>}</div>
                </>}
            </section>}
        </>}
        <p className="package-note package-retention"><Info size={16}/>{labels.retention}</p>
    </div>;
}
