import { useId } from 'react';
import { Info, LoaderCircle, RefreshCw, TriangleAlert } from 'lucide-react';
import { useLocale } from './i18n';
import { cachedUpdatesAgeStatus } from './cached-updates-types';
import type { CachedUpdatesResource } from './cached-updates-resource';
import { useCachedUpdates } from './cached-updates-resource';
import './cached-updates.css';
const copy = {
    en: {
        title: 'Updates · APT preview', refresh: 'Refresh stored update report', loading: 'Reading stored update report…', recovering: 'Storage is busy. Retrying the read once in 2 seconds.',
        intro: 'Debian 13 / Ubuntu 24.04 cached candidates, including held packages. Dependencies, phased rollout, download availability and installability are unchecked.',
        scope: 'Only the agent-visible package namespace and existing local cache are read. No metadata refresh, package installation or CVE assessment. Zero candidates does not mean the device is secure or fully patched.',
        permission: 'Off by default. A local administrator must explicitly enable this extension for the existing device identity. The manager cannot verify whether local collection is currently enabled.',
        fresh: 'Recent observation', stale: 'Historical observation', expired: 'Observation or identity expired', revoked: 'Device identity revoked', unknown: 'No eligible observation', not_collected: 'No accepted cached-update report', hidden: 'Update counts are unknown in this state.',
        complete: 'Installed package scope checked', partial: 'Partial result / bounded preview', unavailable: 'Cached-update collection unavailable',
        candidates: 'Newer candidates', held: 'Held candidates', installed: 'Installed packages', checked: 'Candidates checked', unknownCount: 'Candidate status unknown',
        zero: 'No newer candidates found in the checked local cache.', truncated: 'Bounded preview: some rows are omitted. Counts cover the completed query.',
        unknownHint: 'Some installed packages could not be compared. Candidate counts are a lower bound for this package scope.',
        metadata: 'Local metadata age', metadataStale: 'Local package indexes are stale (at least 48 hours old).', metadataUnknown: 'Source freshness unknown. File modification time does not prove a successful repository refresh.', age: 'Oldest local package-index age at collection (hours)', observed: 'Original collection time', sourceTime: 'Oldest package-index modification time',
        package: 'Package', architecture: 'Architecture', installedVersion: 'Installed version', candidateVersion: 'Native candidate', state: 'Candidate state', candidate_only: 'Candidate only', heldState: 'Held by dpkg',
        loadError: 'The manager could not be read. Refresh to try again.', invalid: 'The manager returned inconsistent or unsupported update data. Values were cleared.', timeout: 'The request timed out. Refresh to try again.', session: 'Your session has ended. Sign in again.', clock: 'The time anchor is no longer reliable. Refresh before continuing.', busy: 'The manager is busy. Retry in a moment.',
        none: 'No collection failure', not_supported: 'OS release, platform or APT configuration unsupported', source_missing: 'Package database unavailable', cache_missing: 'Existing APT package indexes unavailable', permission_denied: 'Source permission denied', read_failed: 'Native query failed', invalid_source: 'Source or native output invalid', source_changed: 'Source changed during collection', collectionTimeout: 'Collection timed out', collector_busy: 'Collector busy', item_limit: 'Preview row limit reached', byte_limit: 'Preview byte limit reached', work_limit: 'Collection work limit reached', candidate_unknown: 'One or more candidates unknown',
        details: 'Scope, consent & retention', retention: 'The original report expires after 24 hours. A report without this extension does not refresh it. Local disable does not delete previously delivered values. Refresh here only reads the manager.',
    },
    de: {
        title: 'Updates · APT-Vorschau', refresh: 'Gespeicherten Updatebericht aktualisieren', loading: 'Gespeicherter Updatebericht wird gelesen…', recovering: 'Der Speicher ist ausgelastet. Ein weiterer Leseversuch folgt in 2 Sekunden.',
        intro: 'Cache-Kandidaten für Debian 13 / Ubuntu 24.04, einschließlich zurückgehaltener Pakete. Abhängigkeiten, gestaffelte Freigabe, Download und Installierbarkeit ungeprüft.',
        scope: 'Gelesen werden nur der für den Agent sichtbare Paketnamensraum und der vorhandene lokale Cache. Keine Metadaten-Aktualisierung, Paketinstallation oder CVE-Bewertung. Null Kandidaten bedeutet weder sicher noch vollständig gepatcht.',
        permission: 'Standardmäßig aus. Ein lokaler Administrator muss diese Erweiterung für die bestehende Geräteidentität ausdrücklich aktivieren. Der Manager kann den aktuellen lokalen Freigabestatus nicht bestätigen.',
        fresh: 'Aktuelle Beobachtung', stale: 'Historische Beobachtung', expired: 'Beobachtung oder Identität abgelaufen', revoked: 'Geräteidentität widerrufen', unknown: 'Keine berechtigte Beobachtung', not_collected: 'Kein akzeptierter Cache-Updatebericht', hidden: 'Die Updateanzahl ist in diesem Zustand unbekannt.',
        complete: 'Installierter Paketumfang geprüft', partial: 'Teilergebnis / begrenzte Vorschau', unavailable: 'Cache-Updateerfassung nicht verfügbar',
        candidates: 'Neuere Kandidaten', held: 'Zurückgehaltene Kandidaten', installed: 'Installierte Pakete', checked: 'Geprüfte Kandidaten', unknownCount: 'Kandidatenstatus unbekannt',
        zero: 'Keine neueren Kandidaten im geprüften lokalen Cache gefunden.', truncated: 'Begrenzte Vorschau: einige Zeilen fehlen. Zahlen gelten für die abgeschlossene Abfrage.',
        unknownHint: 'Einige installierte Pakete konnten nicht verglichen werden. Die Kandidatenzahl ist eine Untergrenze für diesen Paketumfang.',
        metadata: 'Alter der lokalen Metadaten', metadataStale: 'Die lokalen Paketindizes sind veraltet (mindestens 48 Stunden alt).', metadataUnknown: 'Quellenaktualität unbekannt. Die Dateiänderungszeit belegt keine erfolgreiche Repository-Aktualisierung.', age: 'Alter des ältesten lokalen Paketindex bei Erfassung (Stunden)', observed: 'Ursprünglicher Erfassungszeitpunkt', sourceTime: 'Änderungszeit des ältesten Paketindex',
        package: 'Paket', architecture: 'Architektur', installedVersion: 'Installierte Version', candidateVersion: 'Nativer Kandidat', state: 'Kandidatenstatus', candidate_only: 'Nur Kandidat', heldState: 'Von dpkg zurückgehalten',
        loadError: 'Der Manager konnte nicht gelesen werden. Zum Wiederholen aktualisieren.', invalid: 'Der Manager lieferte widersprüchliche oder nicht unterstützte Updatedaten. Werte wurden entfernt.', timeout: 'Die Anfrage hat das Zeitlimit überschritten. Zum Wiederholen aktualisieren.', session: 'Die Sitzung ist beendet. Erneut anmelden.', clock: 'Der Zeitanker ist nicht mehr verlässlich. Vor dem Fortfahren aktualisieren.', busy: 'Der Manager ist ausgelastet. Gleich erneut versuchen.',
        none: 'Kein Erfassungsfehler', not_supported: 'Betriebssystemversion, Plattform oder APT-Konfiguration nicht unterstützt', source_missing: 'Paketdatenbank nicht verfügbar', cache_missing: 'Vorhandene APT-Paketindizes nicht verfügbar', permission_denied: 'Quellenzugriff verweigert', read_failed: 'Native Abfrage fehlgeschlagen', invalid_source: 'Quelle oder native Ausgabe ungültig', source_changed: 'Quelle während der Erfassung geändert', collectionTimeout: 'Erfassung hat Zeitlimit überschritten', collector_busy: 'Collector ausgelastet', item_limit: 'Zeilengrenze der Vorschau erreicht', byte_limit: 'Bytegrenze der Vorschau erreicht', work_limit: 'Arbeitsgrenze der Erfassung erreicht', candidate_unknown: 'Mindestens ein Kandidat unbekannt',
        details: 'Umfang, Freigabe & Aufbewahrung', retention: 'Der ursprüngliche Bericht läuft nach 24 Stunden ab. Ein Bericht ohne diese Erweiterung erneuert ihn nicht. Lokales Deaktivieren löscht keine bereits übertragenen Werte. Aktualisieren liest hier nur den Manager.',
    },
};
export function DeviceCachedUpdates({ deviceId, sessionKey }: { deviceId: string; sessionKey: string | null }) {
    return <CachedUpdatesPanel resource={useCachedUpdates(deviceId, true, sessionKey)}/>;
}
export function CachedUpdatesPanel({ resource }: { resource: CachedUpdatesResource }) {
    const [locale] = useLocale(), labels = copy[locale], id = useId(), { view, snapshot } = resource;
    const status = view ? cachedUpdatesAgeStatus(view, resource.elapsed) : null;
    const field = (label: string, value: string | number) => <div><dt>{label}</dt><dd>{value}</dd></div>;
    return <section className="cached-updates package-observations" aria-labelledby={id} aria-busy={resource.loading}>
        <header className="package-heading"><h3 id={id}>{labels.title}</h3><button type="button" className="button small" disabled={resource.loading || resource.error === 'session'} onClick={resource.refresh} aria-label={labels.refresh} title={labels.refresh}><RefreshCw size={14}/>{locale === 'de' ? 'Aktualisieren' : 'Refresh'}</button></header>
        <p className="package-note">{labels.intro}</p>
        {resource.loading && <p role="status"><LoaderCircle size={16} className="spin"/>{resource.recovering ? labels.recovering : labels.loading}</p>}
        {resource.error && <p className="package-error" role="alert"><TriangleAlert size={16}/>{labels[resource.error]}</p>}
        {status && <p className="package-status">{labels[status]}</p>}
        {view && !snapshot && <p>{labels.hidden}</p>}
        {(status === 'not_collected' || status === 'unknown') && <p className="package-note">{labels.permission}</p>}
        {snapshot && <>
            <p className={snapshot.coverage === 'complete' ? 'package-note' : 'package-error'}>{labels[snapshot.coverage]}{snapshot.reason !== 'none' && <>: {labels[snapshot.reason === 'timeout' ? 'collectionTimeout' : snapshot.reason]}</>}</p>
            {snapshot.candidateCount !== null && <><dl className="package-counts">{field(labels.candidates, snapshot.candidateCount)}{field(labels.held, snapshot.heldCount!)}{field(labels.unknownCount, snapshot.unknownCount!)}</dl><dl className="package-facts">{field(labels.installed, snapshot.installedCount!)}{field(labels.checked, snapshot.checkedCount!)}</dl></>}
            {snapshot.candidateCount === 0 && snapshot.unknownCount === 0 && <p>{labels.zero}</p>}
            {snapshot.unknownCount !== null && snapshot.unknownCount > 0 && <p className="package-note">{labels.unknownHint}</p>}
            {snapshot.truncated && <p className="package-note">{labels.truncated}</p>}
            <p className={snapshot.metadata.freshness === 'stale' ? 'package-error' : 'package-note'}>{snapshot.metadata.freshness === 'stale' ? labels.metadataStale : labels.metadataUnknown}</p>
            <dl className="package-facts">{field(labels.observed, snapshot.collectedAt)}{snapshot.metadata.oldestIndexModifiedAt && field(labels.sourceTime, snapshot.metadata.oldestIndexModifiedAt)}{snapshot.metadata.ageSeconds !== null && field(labels.age, new Intl.NumberFormat(locale, { maximumFractionDigits: 1 }).format(snapshot.metadata.ageSeconds / 3600))}</dl>
            {snapshot.items.length > 0 && <div className="package-table-scroll" role="region" aria-label={labels.title} tabIndex={0}><table><caption className="sr-only">{labels.title}</caption><thead><tr>{[labels.package, labels.architecture, labels.installedVersion, labels.candidateVersion, labels.state].map(label => <th key={label} scope="col">{label}</th>)}</tr></thead><tbody>{snapshot.items.map(row => <tr key={`${row.name}:${row.architecture}`}><th scope="row">{row.name}</th><td>{row.architecture}</td><td>{row.installedVersion}</td><td>{row.candidateVersion}</td><td>{row.state === 'held' ? labels.heldState : labels.candidate_only}</td></tr>)}</tbody></table></div>}
        </>}
        <details><summary><Info size={14}/>{labels.details}</summary><p>{labels.scope}</p><p>{labels.permission}</p><p>{labels.retention}</p></details>
    </section>;
}
