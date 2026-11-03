import type { ReactNode } from 'react';
import { useLocale } from './i18n';
import { inventoryAge } from './complete-packages-types';
import { completeUpdatesGenerationVisible, completeUpdatesTransferExpired } from './complete-updates-types';
import { useCompleteUpdates } from './complete-updates-resource';
import type { WindowsInventoryResource } from './windows-inventory-resource';
import './patch-evidence.css';

const copy = {
    en: {
        title: 'Patch evidence', intro: 'Saved observations, with each source and original capture kept separate. No current patch-compliance or security verdict.',
        boundary: 'Opening or refreshing this view only reads the manager. It does not refresh a package cache, start a scan, install updates or reboot.',
        linux: 'Linux · complete known APT candidates', windows: 'Windows · cached update results', history: 'Windows · retained history and reboot context',
        source: 'Source / scope', method: 'Method', captured: 'Original capture time', status: 'Observation', recent: 'Recent capture', stale: 'Historical capture',
        missing: 'No eligible accepted observation. Counts are unknown.', expired: 'Original observation expired. Counts are hidden.', awaiting: 'Awaiting a complete generation. Counts are unknown.',
        notConfigured: 'This separate source is not configured. Local consent is not inferred.', revoked: 'Identity revoked or no longer eligible. Counts are hidden.',
        loading: 'Reading saved evidence…', error: 'Saved evidence could not be verified. Counts are hidden; refresh to retry.', session: 'Your session has ended. Sign in again.',
        clock: 'The time reference cannot be verified. Counts are hidden.', refresh: 'Refresh saved patch evidence', open: 'Open source view',
        aptSource: 'Agent-visible dpkg packages and existing local APT indexes; complete known-candidate generation', aptMethod: 'Debian package-version comparison; cached metadata only',
        candidates: 'Known newer candidates', held: 'Held candidates', unknown: 'Unknown package comparisons', compared: 'Compared / installed packages',
        lower: 'Some packages could not be compared. The known-candidate count is a lower bound, including when it is zero.',
        cache: 'Cache freshness', unknownFreshness: 'Unknown; a capture or file timestamp does not prove a successful source refresh.', staleCache: 'Stale at capture (at least 48 hours old).',
        index: 'Oldest package-index modification time', metadataAge: 'Oldest package-index age at capture (hours)',
        aptLimit: 'Candidates include held packages. Installability, dependencies, phased rollout, CVEs and reboot needs are unchecked. Zero candidates is not proof of a fully patched device.',
        transfer: 'Latest transfer', pending: 'Pending', complete: 'Complete', failed: 'Failed', transferExpired: 'Expired', transferCapture: 'Latest transfer capture time',
        failure: 'Latest failed capture attempt', attempt: 'Attempted at', attemptLimit: 'An unfinished or failed newer attempt does not refresh or replace the displayed complete capture.',
        wuaSource: 'Windows Update Agent cache (wua-cache); caller-visible, non-hidden, not-installed software updates',
        wuaMethod: 'Offline WUA cache search', unverified: 'No successful source read verified', observed: 'Observed', partial: 'Partial', denied: 'Access denied', unavailable: 'Unavailable',
        observedCount: 'Cached results observed', retained: 'Rows retained', atLeast: 'at least', countLimit: 'Counts describe this cached search before metadata and row-retention limits, not whole-device patch coverage.',
        wuaLimit: 'Cache freshness is unknown. Installed, hidden and driver updates are excluded. Zero results, vendor severity and downloaded flags do not establish patch status or exploitability.',
        historySource: 'Windows Update Agent retained history; checked local reboot-indicator sources',
        historyMethod: 'GetTotalHistoryCount and bounded QueryHistory', partialHistoryMethod: 'Retained-history attempt; successful row-read coverage is partial or unconfirmed', emptyHistoryMethod: 'GetTotalHistoryCount; no QueryHistory needed for zero retained events',
        events: 'Retained events', historyLimit: 'Retained installation and removal events are not current installed-update inventory. Reboot indicators cover only the checked sources; no urgent reboot is inferred.',
        reboot: 'Reboot indicators', pendingReboot: 'At least one checked indicator is set', clearReboot: 'No checked indicator set', unknownReboot: 'Unknown / incomplete source coverage', build: 'Reported build / revision',
        absentScope: 'This report does not include the separate source. Absence does not prove that local consent is disabled.',
        unsupported: 'OS release or APT configuration unsupported', sourceMissing: 'Source unavailable', sourceInvalid: 'Source invalid or unsupported', sourceChanged: 'Source changed during capture', resourceLimit: 'Resource limit reached', collectionFailed: 'Capture failed',
    },
    de: {
        title: 'Patch-Belege', intro: 'Gespeicherte Beobachtungen mit getrennten Quellen und ursprünglichen Erfassungszeiten. Keine aktuelle Aussage zu Patch-Konformität oder Sicherheit.',
        boundary: 'Öffnen und Aktualisieren lesen nur den Manager. Paket-Caches werden nicht erneuert; keine Suche, Updateinstallation oder Neustarts.',
        linux: 'Linux · vollständige bekannte APT-Kandidaten', windows: 'Windows · Updateergebnisse aus dem Cache', history: 'Windows · gespeicherter Verlauf und Neustartkontext',
        source: 'Quelle / Umfang', method: 'Methode', captured: 'Ursprünglicher Erfassungszeitpunkt', status: 'Beobachtung', recent: 'Aktuelle Erfassung', stale: 'Historische Erfassung',
        missing: 'Keine berechtigte akzeptierte Beobachtung. Zahlen sind unbekannt.', expired: 'Ursprüngliche Beobachtung abgelaufen. Zahlen sind ausgeblendet.', awaiting: 'Vollständige Generation ausstehend. Zahlen sind unbekannt.',
        notConfigured: 'Diese separate Quelle ist nicht eingerichtet. Eine lokale Freigabe wird nicht abgeleitet.', revoked: 'Identität widerrufen oder nicht mehr berechtigt. Zahlen sind ausgeblendet.',
        loading: 'Gespeicherte Belege werden gelesen…', error: 'Gespeicherte Belege konnten nicht bestätigt werden. Zahlen sind ausgeblendet; zum Wiederholen aktualisieren.', session: 'Die Sitzung ist beendet. Erneut anmelden.',
        clock: 'Der Zeitbezug ist nicht verlässlich. Zahlen sind ausgeblendet.', refresh: 'Gespeicherte Patch-Belege aktualisieren', open: 'Quellenansicht öffnen',
        aptSource: 'Für den Agent sichtbare dpkg-Pakete und vorhandene lokale APT-Indizes; vollständige Generation bekannter Kandidaten', aptMethod: 'Debian-Paketversionsvergleich; nur vorhandene Metadaten',
        candidates: 'Bekannte neuere Kandidaten', held: 'Zurückgehaltene Kandidaten', unknown: 'Unbekannte Paketvergleiche', compared: 'Verglichene / installierte Pakete',
        lower: 'Einige Pakete konnten nicht verglichen werden. Die Zahl bekannter Kandidaten ist eine Untergrenze, auch bei null.',
        cache: 'Cache-Aktualität', unknownFreshness: 'Unbekannt; Erfassungs- und Dateizeiten belegen keine erfolgreiche Quellenaktualisierung.', staleCache: 'Bei Erfassung veraltet (mindestens 48 Stunden alt).',
        index: 'Änderungszeit des ältesten Paketindex', metadataAge: 'Alter des ältesten Paketindex bei Erfassung (Stunden)',
        aptLimit: 'Zurückgehaltene Pakete sind enthalten. Installierbarkeit, Abhängigkeiten, gestaffelte Freigabe, CVEs und Neustartbedarf sind ungeprüft. Null Kandidaten belegt keinen vollständigen Patchstand.',
        transfer: 'Neueste Übertragung', pending: 'Ausstehend', complete: 'Abgeschlossen', failed: 'Fehlgeschlagen', transferExpired: 'Abgelaufen', transferCapture: 'Erfassungszeit der neuesten Übertragung',
        failure: 'Neuester fehlgeschlagener Erfassungsversuch', attempt: 'Versuch am', attemptLimit: 'Ein neuerer unvollständiger oder fehlgeschlagener Versuch erneuert und ersetzt die angezeigte vollständige Erfassung nicht.',
        wuaSource: 'Windows Update Agent-Cache (wua-cache); für den Aufrufer sichtbare, nicht ausgeblendete, nicht installierte Softwareupdates',
        wuaMethod: 'Offline-Suche im WUA-Cache', unverified: 'Kein erfolgreicher Quellenzugriff bestätigt', observed: 'Beobachtet', partial: 'Teilweise', denied: 'Zugriff verweigert', unavailable: 'Nicht verfügbar',
        observedCount: 'Beobachtete Cache-Ergebnisse', retained: 'Aufbewahrte Zeilen', atLeast: 'mindestens', countLimit: 'Zahlen gelten für diese Cache-Suche vor Metadaten- und Aufbewahrungsgrenzen, nicht für die Patch-Abdeckung des Geräts.',
        wuaLimit: 'Cache-Aktualität unbekannt. Installierte, ausgeblendete und Treiberupdates fehlen. Null Ergebnisse, Hersteller-Schweregrad und Downloadkennzeichen belegen weder Patchstand noch Ausnutzbarkeit.',
        historySource: 'Gespeicherter Windows Update Agent-Verlauf; geprüfte lokale Neustartindikatoren',
        historyMethod: 'GetTotalHistoryCount und begrenztes QueryHistory', partialHistoryMethod: 'Verlaufsversuch; erfolgreicher Zeilenzugriff ist teilweise oder unbestätigt', emptyHistoryMethod: 'GetTotalHistoryCount; bei null gespeicherten Ereignissen kein QueryHistory nötig',
        events: 'Gespeicherte Ereignisse', historyLimit: 'Gespeicherte Installations- und Entfernungsereignisse sind kein aktueller Update-Installationsbestand. Neustartindikatoren gelten nur für geprüfte Quellen; kein dringender Neustartbedarf wird abgeleitet.',
        reboot: 'Neustartindikatoren', pendingReboot: 'Mindestens ein geprüfter Indikator gesetzt', clearReboot: 'Keiner der geprüften Indikatoren gesetzt', unknownReboot: 'Unbekannte / unvollständige Quellenabdeckung', build: 'Gemeldeter Build / Revision',
        absentScope: 'Die separate Quelle ist nicht in dieser Meldung enthalten. Dies belegt keine deaktivierte lokale Freigabe.',
        unsupported: 'Betriebssystemversion oder APT-Konfiguration nicht unterstützt', sourceMissing: 'Quelle nicht verfügbar', sourceInvalid: 'Quelle ungültig oder nicht unterstützt', sourceChanged: 'Quelle während der Erfassung geändert', resourceLimit: 'Ressourcengrenze erreicht', collectionFailed: 'Erfassung fehlgeschlagen',
    },
};
type Labels = typeof copy.en;
type Facts = [string, ReactNode][];
const time = (value: string) => <time dateTime={value}>{value}</time>;
function FactsList({ facts }: { facts: Facts }) {
    return <dl className="patch-evidence-facts">{facts.map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value}</dd></div>)}</dl>;
}
function Heading({ labels, loading, refresh, disabled, onOpenSource }: { labels: Labels; loading: boolean; refresh: () => void; disabled: boolean; onOpenSource: () => void }) {
    return <><div className="patch-evidence-heading"><h2>{labels.title}</h2><button type="button" className="button small" disabled={loading || disabled} onClick={refresh}>{labels.refresh}</button></div><p>{labels.intro}</p><p className="patch-evidence-boundary">{labels.boundary}</p><button type="button" className="text-button" disabled={disabled} onClick={onOpenSource}>{labels.open}</button></>;
}

/** Metadata-only reader: no candidate-row query, package action or new endpoint. */
export function LinuxPatchEvidence({ deviceId, onOpenSource }: { deviceId: string; onOpenSource: () => void }) {
    const [locale] = useLocale(), c = copy[locale], resource = useCompleteUpdates(deviceId, true, false), { view } = resource;
    const visible = !resource.error && view && completeUpdatesGenerationVisible(view, resource.elapsed), manifest = visible ? view.complete!.manifest : null;
    const age = manifest && view ? inventoryAge(view.serverNow, manifest.collectedAt) + resource.elapsed : Infinity;
    const status = resource.error ? resource.error === 'session' ? c.session : resource.error === 'clock' ? c.clock : c.error : resource.loading ? c.loading : manifest ? age > 120000 ? c.stale : c.recent : view?.status === 'not_configured' ? c.notConfigured : view?.status === 'revoked' ? c.revoked : view?.complete?.state === 'expired' || view?.status === 'available' ? c.expired : view?.status === 'awaiting' ? c.awaiting : c.missing;
    const facts: Facts = [[c.source, c.aptSource], [c.method, manifest ? c.aptMethod : c.unverified]];
    if (manifest) facts.push([c.captured, time(manifest.collectedAt)], [c.candidates, manifest.candidateCount], [c.held, manifest.heldCount], [c.unknown, manifest.unknownCount], [c.compared, `${manifest.checkedCount} / ${manifest.installedCount}`], [c.cache, manifest.metadata.freshness === 'stale' ? c.staleCache : c.unknownFreshness], [c.index, manifest.metadata.oldestIndexModifiedAt ? time(manifest.metadata.oldestIndexModifiedAt) : c.unknownFreshness], [c.metadataAge, manifest.metadata.ageSeconds === null ? c.unknownFreshness : new Intl.NumberFormat(locale, { maximumFractionDigits: 1 }).format(manifest.metadata.ageSeconds / 3600)]);
    const transfer = !resource.error && view?.transfer, failure = !resource.error && view?.failure;
    const failureLabels = { not_supported: c.unsupported, source_missing: c.sourceMissing, source_invalid: c.sourceInvalid, source_changed: c.sourceChanged, resource_limit: c.resourceLimit, collection_failed: c.collectionFailed };
    return <section className="patch-evidence" aria-label={c.title} aria-busy={resource.loading}>
        <Heading labels={c} loading={resource.loading} refresh={resource.refresh} disabled={resource.error === 'session'} onOpenSource={onOpenSource}/>
        <section className="patch-evidence-card" aria-label={c.linux}><h3>{c.linux}</h3><p role={resource.error ? 'alert' : 'status'}>{status}</p><FactsList facts={facts}/>{manifest && manifest.unknownCount > 0 && <p className="patch-evidence-caution">{c.lower}</p>}<p>{c.aptLimit}</p>
            {transfer && <FactsList facts={[[c.transfer, transfer.state === 'expired' || view && completeUpdatesTransferExpired(view, resource.elapsed) ? c.transferExpired : c[transfer.state]], [c.transferCapture, time(transfer.collectedAt)]]}/>}
            {failure && <FactsList facts={[[c.failure, failureLabels[failure.reason]], [c.attempt, time(failure.attemptedAt)]]}/>}
            {(transfer || failure) && <p className="patch-evidence-caution">{c.attemptLimit}</p>}
        </section>
    </section>;
}

/** Uses only the existing resource's current, admitted source projections.
 * Earlier successful captures stay in their source view, never replace failures. */
export function WindowsPatchEvidence({ resource, onOpenSource }: { resource: WindowsInventoryResource; onOpenSource: () => void }) {
    const [locale] = useLocale(), c = copy[locale];
    const admitted = !resource.error && resource.snapshot && ['fresh', 'stale'].includes(resource.status ?? '') && Number.isFinite(resource.elapsedMS) && resource.elapsedMS >= 0;
    const visible = (capture: string) => admitted && resource.view && inventoryAge(resource.view.serverNow, capture) + resource.elapsedMS >= 0 && inventoryAge(resource.view.serverNow, capture) + resource.elapsedMS < 86400000;
    const updates = resource.updates && visible(resource.updates.collectedAt) ? resource.updates : null;
    const context = resource.patchContext && visible(resource.patchContext.collectedAt) ? resource.patchContext : null;
    const absent = (expired: boolean, ahead: boolean) => resource.error ? resource.error === 'session' ? c.session : resource.error === 'clock' ? c.clock : c.error : resource.loading ? c.loading : resource.status === 'revoked' ? c.revoked : expired ? c.expired : ahead ? c.clock : resource.snapshot ? c.absentScope : c.missing;
    const observed = updates && ['observed', 'partial'].includes(updates.quality), historyObserved = context && ['observed', 'partial'].includes(context.history.quality);
    const count = (total: number, exact: boolean) => `${exact ? '' : `${c.atLeast} `}${new Intl.NumberFormat(locale).format(total)}`;
    const updateFacts: Facts = [[c.source, c.wuaSource], [c.method, observed && updates.reason !== 'windows_updates_offline_not_verified' ? c.wuaMethod : c.unverified], [c.cache, c.unknownFreshness]];
    if (updates) updateFacts.push([c.captured, time(updates.collectedAt)], [c.status, c[updates.quality]]);
    if (observed) updateFacts.push([c.observedCount, count(updates.observedCount, updates.countExact)], [c.retained, updates.rows.length]);
    const historyFacts: Facts = [[c.source, c.historySource], [c.method, historyObserved && context.history.reason !== 'windows_patch_context_offline_not_verified' ? context.history.totalCount === 0 && context.history.quality === 'observed' ? c.emptyHistoryMethod : context.history.rows.length > 0 ? c.historyMethod : c.partialHistoryMethod : c.unverified]];
    if (context) {
        const reboot = Object.values(context.reboot), display = (field: typeof context.os.build) => field.quality === 'observed' ? field.value : field.quality === 'absent' ? c.missing : c[field.quality];
        historyFacts.push([c.captured, time(context.collectedAt)], [c.status, c[context.history.quality]], [c.build, `${display(context.os.build)} / ${display(context.os.revision)}`], [c.reboot, reboot.includes('pending') ? c.pendingReboot : reboot.every(state => state === 'clear') ? c.clearReboot : c.unknownReboot]);
    }
    if (historyObserved) historyFacts.push([c.events, count(context.history.totalCount, context.history.countExact)], [c.retained, context.history.rows.length]);
    return <section className="patch-evidence" aria-label={c.title} aria-busy={resource.loading}>
        <Heading labels={c} loading={resource.loading} refresh={resource.refresh} disabled={resource.error === 'session'} onOpenSource={onOpenSource}/>
        <div className="patch-evidence-grid">
            <section className="patch-evidence-card" aria-label={c.windows}><h3>{c.windows}</h3><p role={resource.error ? 'alert' : 'status'}>{updates ? resource.updatesStale ? c.stale : c.recent : absent(resource.updatesExpired, resource.updatesAhead)}</p><FactsList facts={updateFacts}/><p>{c.countLimit}</p><p>{c.wuaLimit}</p></section>
            <section className="patch-evidence-card" aria-label={c.history}><h3>{c.history}</h3><p role={resource.error ? 'alert' : 'status'}>{context ? resource.patchContextStale ? c.stale : c.recent : absent(resource.patchContextExpired, resource.patchContextAhead)}</p><FactsList facts={historyFacts}/><p>{c.historyLimit}</p></section>
        </div>
    </section>;
}
