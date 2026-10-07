import { InventoryLiveStatus } from './inventory-live-status';
import { useId } from 'react';
import { LoaderCircle, RefreshCw, Search, TriangleAlert } from 'lucide-react';
import { useOperator } from './auth';
import { useLocale } from './i18n';
import { completeUpdatesGenerationVisible, completeUpdatesTransferExpired } from './complete-updates-types';
import { useCompleteUpdates } from './complete-updates-resource';
import './complete-packages.css';
import './cached-updates.css';
import './complete-updates.css';
const copy = {
    en: {
        title: 'Updates · all known cached APT candidates', access: 'Authenticated LAN operator access is required.', refresh: 'Refresh complete update inventory', loading: 'Reading complete update inventory…',
        intro: 'Every known newer candidate from one completed Debian 13 / Ubuntu 24.04 cache-only capture is available in bounded pages. Held candidates are included. This does not refresh APT or install updates.',
        not_configured: 'Complete update storage is not configured', awaiting: 'Awaiting a complete update generation', available: 'Complete known-candidate generation available', revoked: 'Device identity revoked', unavailable: 'Complete update inventory unavailable',
        consent: 'All-row collection is off by default. It needs a separate identity-bound local acknowledgement; preview consent does not enable it. An awaiting state does not prove the current local consent setting.',
        candidates: 'Known newer candidates', held: 'Held candidates', unknown: 'Candidate comparisons unknown', installed: 'Installed packages', checked: 'Compared packages',
        stale: 'Local package-index metadata is stale (at least 48 hours old).', freshness: 'Source freshness unknown. A file modification time does not prove a successful repository refresh.', partial: 'Some installed packages could not be compared. The known-candidate total is a lower bound; the complete row set does not make these unknown comparisons current.',
        noSecurity: 'No CVE or installability assessment. No candidates in this cache does not establish that the device is secure or fully patched. Phased rollout, dependencies, source reachability and reboot needs are not evaluated.',
        collected: 'Original capture time', completed: 'Completed by manager', retained: 'Rows retained until', sourceTime: 'Oldest local package-index modification', sourceAge: 'Local metadata age at capture (hours)',
        historical: 'Historical generation metadata', expired: 'This generation has expired. Its rows are no longer available.', transfer: 'Latest transfer', pending: 'Transfer pending', complete: 'Transfer completed', failed: 'Transfer failed', transferExpired: 'Transfer expired', accepted: 'Accepted / declared candidate rows', chunks: 'Accepted / expected chunks',
        transferNote: 'An unfinished or failed newer transfer does not replace the prior complete generation or refresh its source age.', failure: 'Latest capture failed', attempted: 'Attempted at', not_supported: 'OS release or APT configuration is unsupported', source_missing: 'Source unavailable', source_invalid: 'Source invalid or unsupported', source_changed: 'Source changed during capture', resource_limit: 'Resource limit reached', collection_failed: 'Capture failed',
        search: 'Search all candidate rows', hint: 'Search checks up to 2,048 rows per request and returns up to 100 matches. Continue until the entire selected generation has been scanned.', submit: 'Search', next: 'Next 100 candidates', continue: 'Continue search', retry: 'Retry request', scanned: 'Rows scanned', matches: 'Matches found', shown: 'Rows on this page',
        zero: 'No newer candidates in the successfully compared cached scope.', zeroUnknown: 'No known newer candidates; some package comparisons are unknown.', continuing: 'No matches in this scan window. Continue to check remaining rows.', noMatches: 'No matches in the complete known-candidate generation.', noPageMatches: 'No further matches. Earlier pages contained matches.', done: 'The entire selected generation has been scanned.', more: 'More candidate rows remain.',
        package: 'Package', architecture: 'Architecture', installedVersion: 'Installed version', candidateVersion: 'Native candidate', state: 'Candidate state', candidate_only: 'Candidate only', heldState: 'Held by dpkg',
        loadError: 'The manager could not be read. Retry the request or refresh.', invalid: 'Inconsistent or unsupported update data was returned. Rows were cleared.', timeout: 'The request timed out. Retry or refresh.', session: 'Your session has ended. Sign in again.', clock: 'The time anchor is no longer reliable. Refresh before continuing.', busy: 'The manager is busy. Retry shortly.', restart: 'The selected generation or paging session expired or changed. Refresh to restart; prior pages were cleared.', searchInvalid: 'Use at most 128 printable ASCII characters.',
        summary: 'Stored APT candidates. Refresh reads manager data; it does not query APT or install updates.',
        securitySummary: 'Cached candidates do not establish security or patch status.',
        captureDetails: 'Capture details', transferDetails: 'Transfer details', failureDetails: 'Failure details', scopeDetails: 'Scope & limits', generationId: 'Generation ID', sequence: 'Sequence',
        retention: 'Rows expire 24 hours after their original capture. Refresh and pagination only read stored manager data; they never initiate a native query or refresh metadata.',
    },
    de: {
        title: 'Updates · alle bekannten APT-Cache-Kandidaten', access: 'Ein authentifizierter LAN-Operator-Zugang ist erforderlich.', refresh: 'Vollständiges Updateinventar aktualisieren', loading: 'Vollständiges Updateinventar wird gelesen…',
        intro: 'Alle bekannten neueren Kandidaten einer abgeschlossenen Cache-Erfassung unter Debian 13 / Ubuntu 24.04 stehen in begrenzten Seiten bereit. Zurückgehaltene Kandidaten sind enthalten. APT wird weder aktualisiert noch werden Updates installiert.',
        not_configured: 'Speicher für vollständige Updates nicht eingerichtet', awaiting: 'Vollständige Updategeneration ausstehend', available: 'Vollständige Generation bekannter Kandidaten verfügbar', revoked: 'Geräteidentität widerrufen', unavailable: 'Vollständiges Updateinventar nicht verfügbar',
        consent: 'Die vollständige Erfassung ist standardmäßig aus und braucht eine separate identitätsgebundene lokale Bestätigung. Eine Vorschaufreigabe aktiviert sie nicht. Ausstehende Daten belegen keinen aktuellen lokalen Freigabestatus.',
        candidates: 'Bekannte neuere Kandidaten', held: 'Zurückgehaltene Kandidaten', unknown: 'Unbekannte Paketvergleiche', installed: 'Installierte Pakete', checked: 'Verglichene Pakete',
        stale: 'Lokale Paketindex-Metadaten sind veraltet (mindestens 48 Stunden alt).', freshness: 'Quellenaktualität unbekannt. Eine Dateiänderungszeit belegt keine erfolgreiche Repository-Aktualisierung.', partial: 'Einige installierte Pakete konnten nicht verglichen werden. Die Kandidatenzahl ist eine Untergrenze; auch die vollständige Zeilenmenge klärt diese unbekannten Vergleiche nicht.',
        noSecurity: 'Keine CVE- oder Installierbarkeitsbewertung. Keine Kandidaten im Cache belegen weder Sicherheit noch einen vollständigen Patchstand. Gestaffelte Freigabe, Abhängigkeiten, Quellenerreichbarkeit und Neustartbedarf sind nicht geprüft.',
        collected: 'Ursprünglicher Erfassungszeitpunkt', completed: 'Vom Manager abgeschlossen', retained: 'Zeilen verfügbar bis', sourceTime: 'Änderungszeit des ältesten lokalen Paketindex', sourceAge: 'Metadatenalter bei Erfassung (Stunden)',
        historical: 'Historische Generationsmetadaten', expired: 'Die Generation ist abgelaufen. Ihre Zeilen sind nicht mehr verfügbar.', transfer: 'Neueste Übertragung', pending: 'Übertragung ausstehend', complete: 'Übertragung abgeschlossen', failed: 'Übertragung fehlgeschlagen', transferExpired: 'Übertragung abgelaufen', accepted: 'Akzeptierte / deklarierte Kandidatenzeilen', chunks: 'Akzeptierte / erwartete Blöcke',
        transferNote: 'Eine neuere unvollständige oder fehlgeschlagene Übertragung ersetzt keine vorherige vollständige Generation und erneuert nicht ihr Quellenalter.', failure: 'Neueste Erfassung fehlgeschlagen', attempted: 'Versuch am', not_supported: 'Betriebssystemversion oder APT-Konfiguration nicht unterstützt', source_missing: 'Quelle nicht verfügbar', source_invalid: 'Quelle ungültig oder nicht unterstützt', source_changed: 'Quelle während der Erfassung geändert', resource_limit: 'Ressourcengrenze erreicht', collection_failed: 'Erfassung fehlgeschlagen',
        search: 'Alle Kandidatenzeilen durchsuchen', hint: 'Jede Anfrage prüft bis zu 2.048 Zeilen und liefert bis zu 100 Treffer. Fortsetzen, bis die gesamte ausgewählte Generation durchsucht wurde.', submit: 'Suchen', next: 'Nächste 100 Kandidaten', continue: 'Suche fortsetzen', retry: 'Anfrage wiederholen', scanned: 'Geprüfte Zeilen', matches: 'Gefundene Treffer', shown: 'Zeilen auf dieser Seite',
        zero: 'Keine neueren Kandidaten im erfolgreich verglichenen Cache-Umfang.', zeroUnknown: 'Keine bekannten neueren Kandidaten; einige Paketvergleiche sind unbekannt.', continuing: 'Keine Treffer in diesem Abschnitt. Weitere Zeilen prüfen.', noMatches: 'Keine Treffer in der vollständigen Generation bekannter Kandidaten.', noPageMatches: 'Keine weiteren Treffer. Frühere Seiten enthielten Treffer.', done: 'Die gesamte ausgewählte Generation wurde durchsucht.', more: 'Weitere Kandidatenzeilen stehen aus.',
        package: 'Paket', architecture: 'Architektur', installedVersion: 'Installierte Version', candidateVersion: 'Nativer Kandidat', state: 'Kandidatenstatus', candidate_only: 'Nur Kandidat', heldState: 'Von dpkg zurückgehalten',
        loadError: 'Der Manager konnte nicht gelesen werden. Anfrage wiederholen oder aktualisieren.', invalid: 'Widersprüchliche oder nicht unterstützte Updatedaten erhalten. Zeilen wurden entfernt.', timeout: 'Die Anfrage hat das Zeitlimit überschritten. Wiederholen oder aktualisieren.', session: 'Die Sitzung ist beendet. Erneut anmelden.', clock: 'Der Zeitanker ist nicht mehr verlässlich. Vor dem Fortfahren aktualisieren.', busy: 'Der Manager ist ausgelastet. Gleich erneut versuchen.', restart: 'Die ausgewählte Generation oder Seitensitzung ist abgelaufen oder geändert. Zum Neustart aktualisieren; vorherige Seiten wurden entfernt.', searchInvalid: 'Höchstens 128 druckbare ASCII-Zeichen verwenden.',
        summary: 'Gespeicherte APT-Kandidaten. Aktualisieren liest Managerdaten, fragt APT nicht ab und installiert keine Updates.',
        securitySummary: 'Cache-Kandidaten belegen weder Sicherheit noch einen vollständigen Patchstand.',
        captureDetails: 'Erfassungsdetails', transferDetails: 'Übertragungsdetails', failureDetails: 'Fehlerdetails', scopeDetails: 'Umfang & Grenzen', generationId: 'Generations-ID', sequence: 'Sequenz',
        retention: 'Zeilen laufen 24 Stunden nach ihrer ursprünglichen Erfassung ab. Aktualisieren und Blättern lesen nur gespeicherte Managerdaten und starten weder eine native Abfrage noch eine Metadaten-Aktualisierung.',
    },
};
export function CompleteUpdatesPanel({ deviceId, sessionKey }: { deviceId: string; sessionKey?: string }) {
    const operator = useOperator(), [locale] = useLocale();
    if (!operator || operator.mode !== 'lan' || !operator.authenticated) return <p>{copy[locale].access}</p>;
    return <CompleteUpdates key={`${deviceId}:${sessionKey ?? operator.expiresAt ?? ''}`} deviceId={deviceId}/>;
}
function CompleteUpdates({ deviceId }: { deviceId: string }) {
    const [locale] = useLocale(), labels = copy[locale], id = useId(), resource = useCompleteUpdates(deviceId), { view, page } = resource;
    const selected = view?.complete, visible = view && completeUpdatesGenerationVisible(view, resource.elapsed), manifest = selected?.manifest;
    const number = (value: number) => new Intl.NumberFormat(locale).format(value), field = (label: string, value: string | number) => <div><dt>{label}</dt><dd>{value}</dd></div>;
    return <section className="package-observations complete-packages complete-updates" aria-labelledby={id} aria-busy={resource.loading}>
        <header className="package-heading"><h3 id={id}>{labels.title}</h3><button type="button" className="button small" disabled={resource.loading || resource.error === 'session'} onClick={resource.refresh}><RefreshCw size={14}/>{labels.refresh}</button></header>
        <p className="package-note">{labels.summary}</p>
        <InventoryLiveStatus state={resource.liveState}/>
        {resource.loading && <p role="status"><LoaderCircle size={16} className="spin"/>{labels.loading}</p>}
        {resource.error && <p className="package-error" role="alert"><TriangleAlert size={16}/>{labels[resource.error]}</p>}
        {['busy', 'timeout', 'loadError'].includes(resource.error ?? '') && <button type="button" className="button small" disabled={resource.loading} onClick={resource.retry}>{labels.retry}</button>}
        {view && <><p className="package-status">{view.status === 'available' && !visible ? labels.historical : labels[view.status]}</p>{['not_configured', 'awaiting'].includes(view.status) && <p className="package-note">{labels.consent}</p>}
            {manifest && <>
                {!visible && <p className="package-error" role="status">{view.status === 'revoked' ? labels.revoked : labels.expired}</p>}
                <dl className="package-counts">{field(labels.candidates, number(manifest.candidateCount))}{field(labels.held, number(manifest.heldCount))}{field(labels.unknown, number(manifest.unknownCount))}</dl>
                <dl className="package-facts">{field(labels.collected, manifest.collectedAt)}{field(labels.retained, selected!.retainedUntil)}</dl>
                <p className={manifest.metadata.freshness === 'stale' ? 'package-error' : 'package-note'}>{manifest.metadata.freshness === 'stale' ? labels.stale : labels.freshness}</p>{manifest.unknownCount > 0 && <p className="package-note">{labels.partial}</p>}
                <details className="update-details">
                    <summary>{labels.captureDetails}</summary>
                    <dl className="package-facts">
                        {field(labels.generationId, selected!.binding.generationId)}
                        {field(labels.sequence, selected!.binding.sequence)}
                        {field(labels.installed, number(manifest.installedCount))}
                        {field(labels.checked, number(manifest.checkedCount))}
                        {field(labels.completed, selected!.completedAt)}
                        {manifest.metadata.oldestIndexModifiedAt && field(labels.sourceTime, manifest.metadata.oldestIndexModifiedAt)}
                        {manifest.metadata.ageSeconds !== null && field(labels.sourceAge, new Intl.NumberFormat(locale, { maximumFractionDigits: 1 }).format(manifest.metadata.ageSeconds / 3600))}
                    </dl>
                </details>
            </>}
            {view.transfer && <section aria-label={labels.transfer}>
                <h4>{labels.transfer}</h4>
                <p>{labels[view.transfer.state === 'expired' || completeUpdatesTransferExpired(view, resource.elapsed) ? 'transferExpired' : view.transfer.state]}</p>
                <dl className="package-facts">{field(labels.accepted, `${number(view.transfer.acceptedRows)} / ${number(view.transfer.declaredRows)}`)}</dl>
                <details className="update-details">
                    <summary>{labels.transferDetails}</summary>
                    <dl className="package-facts">
                        {field(labels.generationId, view.transfer.binding.generationId)}
                        {field(labels.sequence, view.transfer.binding.sequence)}
                        {field(labels.collected, view.transfer.collectedAt)}
                        {field(labels.chunks, `${number(view.transfer.acceptedChunks)} / ${number(view.transfer.expectedChunks)}`)}
                    </dl>
                    <p className="package-note">{labels.transferNote}</p>
                </details>
            </section>}
            {view.failure && <section aria-label={labels.failure}>
                <h4>{labels.failure}</h4><p>{labels[view.failure.reason]}</p>
                <dl className="package-facts">{field(labels.attempted, view.failure.attemptedAt)}</dl>
                <details className="update-details">
                    <summary>{labels.failureDetails}</summary>
                    <dl className="package-facts">
                        {field(labels.generationId, view.failure.generationId)}
                        {field(labels.sequence, view.failure.sequence)}
                    </dl>
                </details>
            </section>}
            {visible && <section><form className="complete-package-search" onSubmit={event => { event.preventDefault(); resource.startSearch(); }}><label htmlFor={`${id}-search`}>{labels.search}</label><div><input id={`${id}-search`} type="search" value={resource.search} maxLength={128} onChange={event => resource.changeSearch(event.target.value)} autoComplete="off" spellCheck={false}/><button type="submit" className="button" disabled={resource.loading}><Search size={15}/>{labels.submit}</button></div></form>
                {page && <><dl className="package-counts">{field(labels.scanned, `${number(resource.scanned)} / ${number(page.totalRows)}`)}{field(labels.matches, number(resource.matches))}{field(labels.shown, number(page.items.length))}</dl>
                    {page.items.length > 0 ? <div className="package-table-scroll" role="region" aria-label={labels.title} tabIndex={0}><table><caption className="sr-only">{labels.title}</caption><thead><tr>{[labels.package, labels.architecture, labels.installedVersion, labels.candidateVersion, labels.state].map(label => <th key={label} scope="col">{label}</th>)}</tr></thead><tbody>{page.items.map(row => <tr key={`${row.name}:${row.architecture}`}><th scope="row">{row.name}</th><td>{row.architecture}</td><td>{row.installedVersion}</td><td>{row.candidateVersion}</td><td>{row.state === 'held' ? labels.heldState : labels.candidate_only}</td></tr>)}</tbody></table></div> : <p role="status">{!page.exhausted ? labels.continuing : page.totalRows === 0 ? manifest!.unknownCount > 0 ? labels.zeroUnknown : labels.zero : resource.matches === 0 ? labels.noMatches : labels.noPageMatches}</p>}
                    <div className="complete-package-pagination"><p>{page.exhausted ? labels.done : labels.more}</p>{!page.exhausted && <button type="button" className="button" disabled={resource.loading} onClick={resource.next}>{resource.search.trim() ? labels.continue : labels.next}</button>}</div>
                </>}
            </section>}
        </>}
        <p className="package-note">{labels.securitySummary}</p>
        <details className="update-details">
            <summary>{labels.scopeDetails}</summary>
            <p className="package-note">{labels.intro}</p>
            <p className="package-note">{labels.hint}</p>
            <p className="package-note">{labels.noSecurity}</p>
            <p className="package-note">{labels.retention}</p>
        </details>
    </section>;
}
