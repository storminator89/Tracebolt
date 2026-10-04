import { useCallback, useEffect, useId, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { Boxes, Database, FileJson, Info, LoaderCircle, RefreshCw, ShieldQuestion, TriangleAlert, Upload, X } from 'lucide-react';
import { APIError, AUTH_REQUIRED_EVENT, mutateRaw, request } from './api';
import { useOperator } from './auth';
import { useLocale } from './i18n';
import type { Locale } from './i18n';
import { CATALOG_MAX_BYTES, effectiveSecurityCollectionStatus, effectiveSecurityFreshness, SECURITY_RESPONSE_MAX_BYTES, SECURITY_VIEW_LEASE_MS, validOfflineCatalogView, validSecurityCoverageView } from './security-coverage-types';
import type { OfflineCatalogView, SecurityCoverageView } from './security-coverage-types';
import './security-coverage.css';
import { AdvisoryReviewPanel } from './advisory-review';

const copy = {
    en: {
        title: 'Security coverage', subtitle: 'Separate observations, update offers and CVE evidence', catalogTitle: 'Offline advisory catalog', catalogSubtitle: 'Operator-supplied Debian 13 / Trixie interchange file',
        refresh: 'Refresh security coverage', refreshCatalog: 'Refresh catalog status', loading: 'Checking the manager…', unknown: 'Unknown', unverified: 'Unverified origin',
        access: 'Authenticated LAN operator access is required.', disabled: 'Offline catalogs require the managed-operations profile. Import is unavailable on this manager.',
        loadError: 'Current status could not be confirmed. Refresh before continuing.', invalid: 'The manager returned an unsupported or inconsistent response. No previous data is used.', timeout: 'The manager did not respond in time. Refresh status.', session: 'Your session has ended. Sign in again.', expired: 'Status needs refreshing. Previous information is no longer shown.',
        changed: 'The catalog changed. Refresh and review the current revision before choosing a file again.', busy: 'Another catalog import is in progress. Refresh status before trying again.', tooLarge: 'The file exceeds the 2 MiB limit.', invalidFile: 'Choose a non-empty UTF-8 JSON file no larger than 2 MiB.', rejected: 'The catalog was rejected. Check the normalized format and Debian 13 / Trixie release, then refresh status.', unavailable: 'Offline catalogs are unavailable. Refresh manager status.', uncertain: 'The action was not confirmed and may already have completed. Refresh status before deciding again. It will not be replayed.',
        observed: 'Observed binary inventory', updates: 'Offered updates', cves: 'CVE coverage', reported: 'Received package records', installed: 'Complete installed-package count', discovered: 'Discovered package count', exact: 'Exact discovered count', lowerBound: 'Lower bound only', partial: 'Partial inventory', complete: 'Complete binary enumeration', missing: 'No inventory evidence', fresh: 'Within collection window', stale: 'Stale / historical evidence', truncated: 'Truncated sample',
        not_configured: 'Collection not configured', awaiting: 'Awaiting observations', revoked: 'Device identity revoked', unavailableStatus: 'Collection unavailable', freshStatus: 'Current collection received', staleStatus: 'Collection is stale',
        checked: 'Checked by manager', collected: 'Inventory collected', received: 'Current collection received', generation: 'Observation generation', inventoryScope: 'Only installed binary-package metadata reported by this client. This is not source-package mapping or proof of the installed artifact’s origin.',
        updateNote: 'A native update-offer adapter is not implemented. Installed versions and advisory fix versions do not establish available updates.',
        cveNote: 'Affected CVEs and review candidates remain unknown. No package matching or vulnerability conclusion is performed here.', candidates: 'Review candidates',
        details: 'Evidence and coverage gaps', advisory_snapshot_unavailable: 'No offline advisory snapshot is loaded.', advisory_authority_unverified: 'The supplied advisory file has no verified vendor authority.', source_package_mapping_not_assessed: 'Source-package mapping is not evaluated by this assessment.', client_release_not_assessed: 'The exact client release is not evaluated by this assessment.', source_package_mapping_unavailable: 'Client source-package mapping is missing.', client_release_unverified: 'The client’s exact distribution release is unverified.', installed_artifact_origin_unverified: 'The installed artifact’s origin is unverified.',
        caution: 'Collection counts describe available evidence, not a security score. Missing or partial evidence must not be read as zero vulnerabilities.', catalogConfigured: 'Catalog supplied · origin unverified', catalogMissing: 'No catalog supplied',
        memory: 'Memory only · resets on manager restart', memoryNote: 'One active catalog is kept in manager memory. Restarting the manager removes it. Upload does not authenticate Debian or any vendor.', noCatalog: 'No offline catalog is loaded.', formatFacts: 'Imported format facts', formatNote: 'These counts describe this file’s format and declared scope. They do not verify vendor origin, current publication, package matches or security status.',
        provider: 'Declared provider', release: 'Declared release', format: 'Format', imported: 'Imported by manager', published: 'Vendor publication time', freshness: 'Advisory freshness', bytes: 'File bytes', rules: 'Rules in file', sources: 'Covered sources in file', digest: 'SHA-256 of supplied bytes', digestNote: 'A content identifier, not a signature or proof of origin.', synthetic: 'Synthetic file declared', yes: 'Yes', no: 'No',
        importSummary: 'Import a normalized JSON catalog', importNote: 'Select a local UTF-8 JSON file, up to 2 MiB and 10,000 rules / covered sources. It is sent only to this manager. The filename is not sent. No feed, model, command or installer is contacted.', choose: 'Choose JSON file', selected: 'JSON file selected', preparing: 'Reading selected file…', import: 'Import catalog', replace: 'Replace current catalog', cancel: 'Cancel file selection', cancelRequest: 'Cancel request', clear: 'Clear catalog', clearQuestion: 'Remove the active catalog from manager memory?', clearConfirm: 'Confirm clear', keep: 'Keep catalog', importedNotice: 'Catalog imported into memory. Its origin and freshness remain unverified.', clearedNotice: 'Catalog cleared from manager memory.', lease: 'File selection expires when status is refreshed, hidden or older than one minute. Importing replaces the active catalog only if its revision is unchanged.',
    },
    de: {
        title: 'Sicherheitsabdeckung', subtitle: 'Beobachtungen, Update-Angebote und CVE-Belege getrennt', catalogTitle: 'Offline-Hinweiskatalog', catalogSubtitle: 'Vom Operator gelieferte Austauschdatei für Debian 13 / Trixie',
        refresh: 'Sicherheitsabdeckung aktualisieren', refreshCatalog: 'Katalogstatus aktualisieren', loading: 'Manager wird geprüft…', unknown: 'Unbekannt', unverified: 'Herkunft unbestätigt',
        access: 'Ein authentifizierter LAN-Operator-Zugang ist erforderlich.', disabled: 'Offline-Kataloge erfordern das Profil managed-operations. Der Import ist auf diesem Manager nicht verfügbar.',
        loadError: 'Der aktuelle Status konnte nicht bestätigt werden. Vor dem Fortfahren aktualisieren.', invalid: 'Der Manager lieferte eine nicht unterstützte oder widersprüchliche Antwort. Frühere Daten werden nicht verwendet.', timeout: 'Der Manager hat nicht rechtzeitig geantwortet. Status aktualisieren.', session: 'Die Sitzung ist beendet. Erneut anmelden.', expired: 'Der Status muss aktualisiert werden. Frühere Informationen werden nicht mehr angezeigt.',
        changed: 'Der Katalog wurde geändert. Den aktuellen Stand aktualisieren und prüfen, bevor erneut eine Datei gewählt wird.', busy: 'Ein anderer Katalogimport läuft. Vor einem neuen Versuch den Status aktualisieren.', tooLarge: 'Die Datei überschreitet das Limit von 2 MiB.', invalidFile: 'Eine nicht leere UTF-8-JSON-Datei mit höchstens 2 MiB auswählen.', rejected: 'Der Katalog wurde abgelehnt. Normalisiertes Format und Debian 13 / Trixie prüfen, dann den Status aktualisieren.', unavailable: 'Offline-Kataloge sind nicht verfügbar. Managerstatus aktualisieren.', uncertain: 'Die Aktion wurde nicht bestätigt und kann bereits abgeschlossen sein. Vor einer neuen Entscheidung den Status aktualisieren. Keine automatische Wiederholung.',
        observed: 'Beobachtetes Binärpaket-Inventar', updates: 'Angebotene Updates', cves: 'CVE-Abdeckung', reported: 'Empfangene Paketeinträge', installed: 'Vollständige Anzahl installierter Pakete', discovered: 'Gefundene Pakete', exact: 'Exakte gefundene Anzahl', lowerBound: 'Nur Untergrenze', partial: 'Teilweise erfasst', complete: 'Vollständige Binärpaket-Erfassung', missing: 'Keine Inventarbelege', fresh: 'Im Erfassungszeitfenster', stale: 'Veraltete / historische Belege', truncated: 'Begrenzte Stichprobe',
        not_configured: 'Erfassung nicht eingerichtet', awaiting: 'Beobachtungen ausstehend', revoked: 'Geräteidentität widerrufen', unavailableStatus: 'Erfassung nicht verfügbar', freshStatus: 'Aktuelle Erfassung empfangen', staleStatus: 'Erfassung ist veraltet',
        checked: 'Vom Manager geprüft', collected: 'Inventar erfasst', received: 'Aktuelle Erfassung empfangen', generation: 'Beobachtungsgeneration', inventoryScope: 'Nur vom Client gemeldete Metadaten installierter Binärpakete. Dies ist keine Quellpaket-Zuordnung und kein Beleg für die Herkunft des installierten Artefakts.',
        updateNote: 'Ein nativer Adapter für Update-Angebote ist nicht implementiert. Installierte Versionen und Sicherheitskorrektur-Versionen belegen keine verfügbaren Updates.',
        cveNote: 'Betroffene CVEs und Prüfkandidaten bleiben unbekannt. Hier erfolgen weder Paketabgleich noch Schwachstellenbewertung.', candidates: 'Prüfkandidaten',
        details: 'Belege und Abdeckungslücken', advisory_snapshot_unavailable: 'Kein Offline-Hinweiskatalog geladen.', advisory_authority_unverified: 'Die Herstellerautorität der gelieferten Hinweisdatei ist nicht bestätigt.', source_package_mapping_not_assessed: 'Die Quellpaket-Zuordnung wird in dieser Bewertung nicht ausgewertet.', client_release_not_assessed: 'Die genaue Distributionsversion des Clients wird in dieser Bewertung nicht ausgewertet.', source_package_mapping_unavailable: 'Die Quellpaket-Zuordnung des Clients fehlt.', client_release_unverified: 'Die genaue Distributionsversion des Clients ist nicht bestätigt.', installed_artifact_origin_unverified: 'Die Herkunft des installierten Artefakts ist nicht bestätigt.',
        caution: 'Erfassungszahlen beschreiben verfügbare Belege, keinen Sicherheitswert. Fehlende oder teilweise Belege bedeuten nicht null Schwachstellen.', catalogConfigured: 'Katalog geliefert · Herkunft unbestätigt', catalogMissing: 'Kein Katalog geliefert',
        memory: 'Nur im Speicher · bei Manager-Neustart entfernt', memoryNote: 'Ein aktiver Katalog bleibt nur im Arbeitsspeicher des Managers. Ein Neustart entfernt ihn. Der Upload authentifiziert weder Debian noch einen anderen Hersteller.', noCatalog: 'Kein Offline-Katalog geladen.', formatFacts: 'Importierte Formatangaben', formatNote: 'Diese Zahlen beschreiben Format und angegebenen Umfang dieser Datei. Sie bestätigen weder Herstellerherkunft noch aktuelle Veröffentlichung, Paketreffer oder Sicherheitsstatus.',
        provider: 'Angegebener Anbieter', release: 'Angegebene Version', format: 'Format', imported: 'Vom Manager importiert', published: 'Hersteller-Veröffentlichung', freshness: 'Aktualität der Hinweise', bytes: 'Dateigröße in Bytes', rules: 'Regeln in der Datei', sources: 'Abgedeckte Quellpakete in der Datei', digest: 'SHA-256 der gelieferten Bytes', digestNote: 'Eine Inhaltskennung, keine Signatur und kein Herkunftsbeleg.', synthetic: 'Als synthetisch angegeben', yes: 'Ja', no: 'Nein',
        importSummary: 'Normalisierten JSON-Katalog importieren', importNote: 'Eine lokale UTF-8-JSON-Datei mit höchstens 2 MiB und 10.000 Regeln / Quellpaketen auswählen. Sie wird nur an diesen Manager gesendet. Der Dateiname wird nicht gesendet. Kein Feed, Modell, Befehl oder Installer wird aufgerufen.', choose: 'JSON-Datei auswählen', selected: 'JSON-Datei ausgewählt', preparing: 'Ausgewählte Datei wird gelesen…', import: 'Katalog importieren', replace: 'Aktuellen Katalog ersetzen', cancel: 'Dateiauswahl abbrechen', cancelRequest: 'Anfrage abbrechen', clear: 'Katalog leeren', clearQuestion: 'Aktiven Katalog aus dem Arbeitsspeicher des Managers entfernen?', clearConfirm: 'Leeren bestätigen', keep: 'Katalog behalten', importedNotice: 'Katalog in den Arbeitsspeicher importiert. Herkunft und Aktualität bleiben unbestätigt.', clearedNotice: 'Katalog aus dem Arbeitsspeicher des Managers entfernt.', lease: 'Die Dateiauswahl verfällt bei Statusaktualisierung, Ausblenden oder nach einer Minute. Ein Import ersetzt den aktiven Katalog nur bei unverändertem Revisionsstand.',
    },
};
type Labels = typeof copy.en;
type Failure = 'loadError' | 'invalid' | 'timeout' | 'session' | 'expired' | 'changed' | 'busy' | 'tooLarge' | 'rejected' | 'unavailable' | 'uncertain';
type View = OfflineCatalogView | SecurityCoverageView;
function date(value: string, locale: Locale): string { return new Intl.DateTimeFormat(locale === 'de' ? 'de-DE' : 'en-GB', { dateStyle: 'medium', timeStyle: 'medium', timeZone: 'UTC' }).format(new Date(value)) + ' UTC'; }
function count(value: number | null, locale: Locale, labels: Labels): string { return value === null ? labels.unknown : new Intl.NumberFormat(locale).format(value); }
function Notice({ children, error = false }: { children: ReactNode; error?: boolean }) { return <div className={`security-notice${error ? ' error' : ''}`} role={error ? 'alert' : undefined}>{error ? <TriangleAlert size={16}/> : <Info size={16}/>}<p>{children}</p></div>; }

/** One current request/configuration lease. Invalidation happens before React renders. */
function useSecurityResource<T extends View>(path: string, validate: (value: unknown) => value is T, clearLocal: () => void, recheckWindowFocus = true) {
    const [value, setValue] = useState<T | null>(null);
    const [loading, setLoading] = useState(false);
    const [pending, setPending] = useState<'import' | 'clear' | null>(null);
    const [error, setError] = useState<Failure | null>(null);
    const [notice, setNotice] = useState<'importedNotice' | 'clearedNotice' | 'uncertain' | null>(null);
    const alive = useRef(false), locked = useRef(false), suspended = useRef(false);
    const operation = useRef<{ controller: AbortController; kind: 'read' | 'import' | 'clear'; started: number; wallStarted: number } | null>(null);
    const current = useRef<{ value: T; deadline: number; anchor: number; wallAnchor: number } | null>(null);
    const deadline = useRef<number | undefined>(undefined);
    const reset = useRef(clearLocal); reset.current = clearLocal;
    const invalidate = useCallback((failure: Failure | null = null, preserveNotice = false) => {
        const uncertain = operation.current?.kind === 'import' || operation.current?.kind === 'clear';
        operation.current?.controller.abort(); operation.current = null; current.current = null;
        window.clearTimeout(deadline.current); reset.current();
        if (alive.current) { setValue(null); setLoading(false); setPending(null); setError(failure); if (uncertain) setNotice(failure === 'uncertain' ? null : 'uncertain'); else if (!preserveNotice) setNotice(null); }
    }, []);
    const install = useCallback((next: T, started: number, wallStarted: number) => {
        const anchor = performance.now();
        current.current = { value: next, anchor: started, wallAnchor: wallStarted, deadline: anchor + SECURITY_VIEW_LEASE_MS };
        setValue(next); setError(null);
        window.clearTimeout(deadline.current);
        deadline.current = window.setTimeout(() => invalidate('expired'), SECURITY_VIEW_LEASE_MS);
    }, [invalidate]);
    // A wall/monotonic discontinuity can only revoke authority. It never extends a lease
    // or establishes freshness, including platforms whose monotonic clock pauses in sleep.
    const sleepGap = (mono: number, wall: number) => Math.abs(Date.now() - wall - Math.max(0, performance.now() - mono)) > 1500;
    const active = useCallback((controller: AbortController) => {
        const op = operation.current;
        if (!alive.current || locked.current || suspended.current || controller.signal.aborted || op?.controller !== controller) return false;
        if (sleepGap(op.started, op.wallStarted) || performance.now() - op.started >= (op.kind === 'read' ? 10_000 : 15_000)) { invalidate(op.kind === 'read' ? 'timeout' : 'uncertain'); return false; }
        return true;
    }, [invalidate]);
    const load = useCallback(async () => {
        if (!alive.current || locked.current || suspended.current || document.visibilityState === 'hidden') return;
        invalidate(null, true);
        const controller = new AbortController(); const started = performance.now(), wallStarted = Date.now();
        operation.current = { controller, kind: 'read', started, wallStarted }; setLoading(true);
        const timeout = window.setTimeout(() => { if (active(controller)) invalidate('timeout', true); }, 10_000);
        try {
            const next = await request<unknown>(path, { signal: controller.signal }, SECURITY_RESPONSE_MAX_BYTES);
            if (!active(controller)) return;
            if (!validate(next)) { invalidate('invalid', true); return; }
            operation.current = null; install(next, started, wallStarted); setLoading(false);
        } catch (caught) {
            if (!active(controller)) return;
            if (caught instanceof APIError && caught.status === 401) locked.current = true;
            invalidate(caught instanceof APIError && caught.status === 401 ? 'session' : 'loadError', true);
        } finally { window.clearTimeout(timeout); }
    }, [active, install, invalidate, path, validate]);
    useEffect(() => {
        alive.current = true; locked.current = false; suspended.current = document.visibilityState === 'hidden';
        const lock = () => { locked.current = true; invalidate('session'); };
        const suspend = () => { suspended.current = true; invalidate(null, true); };
        const restore = () => { if (!alive.current || locked.current || document.visibilityState === 'hidden') return; suspended.current = false; void load(); };
        const focus = () => { if (recheckWindowFocus || suspended.current) restore(); };
        const navigate = () => invalidate(null, true);
        const visibility = () => document.visibilityState === 'hidden' ? suspend() : restore();
        const pageshow = (event: PageTransitionEvent) => { if (event.persisted || suspended.current) restore(); };
        window.addEventListener(AUTH_REQUIRED_EVENT, lock); window.addEventListener('pagehide', suspend); window.addEventListener('pageshow', pageshow); if (recheckWindowFocus) window.addEventListener('blur', suspend); window.addEventListener('focus', focus); window.addEventListener('hashchange', navigate); document.addEventListener('visibilitychange', visibility);
        const clockGuard = window.setInterval(() => { const clock = current.current; if (clock && (performance.now() >= clock.deadline || sleepGap(clock.anchor, clock.wallAnchor))) invalidate('expired'); }, 1000);
        void load();
        return () => { alive.current = false; window.clearInterval(clockGuard); invalidate(); window.removeEventListener(AUTH_REQUIRED_EVENT, lock); window.removeEventListener('pagehide', suspend); window.removeEventListener('pageshow', pageshow); window.removeEventListener('blur', suspend); window.removeEventListener('focus', focus); window.removeEventListener('hashchange', navigate); document.removeEventListener('visibilitychange', visibility); };
    }, [invalidate, load, recheckWindowFocus]);
    const ready = useCallback((): T | null => {
        if (locked.current || suspended.current || operation.current || !current.current || document.visibilityState === 'hidden') return null;
        if (performance.now() >= current.current.deadline || sleepGap(current.current.anchor, current.current.wallAnchor)) { invalidate('expired'); return null; }
        return current.current.value;
    }, [invalidate]);
    const mutate = useCallback(async (kind: 'import' | 'clear', raw: string) => {
        const baseline = ready();
        if (!validOfflineCatalogView(baseline) || !baseline.enabled) return;
        invalidate(); setPending(kind);
        const controller = new AbortController(); const started = performance.now(), wallStarted = Date.now();
        operation.current = { controller, kind, started, wallStarted };
        const timeout = window.setTimeout(() => { if (active(controller)) invalidate('uncertain'); }, 15_000);
        try {
            const next = await mutateRaw<unknown>(kind === 'import' ? '/security/catalog' : '/security/catalog/clear', kind === 'import' ? raw : JSON.stringify({ expectedRevision: baseline.revision }), kind === 'import' ? { 'X-Tracebolt-Catalog-Revision': baseline.revision } : {}, controller.signal, SECURITY_RESPONSE_MAX_BYTES);
            if (!active(controller)) return;
            if (!validate(next) || !validOfflineCatalogView(next) || !next.enabled || next.revision === baseline.revision || (kind === 'import' ? next.catalog === null : next.catalog !== null)) { invalidate('uncertain'); return; }
            operation.current = null; install(next, started, wallStarted); setPending(null); setNotice(kind === 'import' ? 'importedNotice' : 'clearedNotice');
        } catch (caught) {
            if (!active(controller)) return;
            const status = caught instanceof APIError ? caught.status : undefined;
            if (status === 401) locked.current = true;
            const failure: Failure = status === 401 ? 'session' : status === 409 ? 'changed' : status === 429 ? 'busy' : status === 413 ? 'tooLarge' : status === 400 ? 'rejected' : status === 404 ? 'unavailable' : 'uncertain';
            // A known rejection does not imply a successful mutation. Unknown transport outcomes do.
            if (failure !== 'uncertain') operation.current = null;
            invalidate(failure);
        } finally { window.clearTimeout(timeout); }
    }, [active, install, invalidate, ready, validate]);
    return { value, loading, pending, error, notice, load, ready, mutate, cancel: () => invalidate('uncertain'), elapsed: () => current.current ? Math.max(0, performance.now() - current.current.anchor) : Number.POSITIVE_INFINITY };
}

const noop = () => {};
export function SecurityCoveragePanel({ deviceId, sessionKey }: { deviceId: string; sessionKey?: string | number }) {
    const operator = useOperator(); const [locale] = useLocale();
    if (!operator || operator.mode !== 'lan' || !operator.authenticated) return <section className="security-panel"><Notice>{copy[locale].access}</Notice></section>;
    return <SecurityCoverageSession key={`${deviceId}:${String(sessionKey ?? operator.expiresAt ?? '')}`} deviceId={deviceId}/>;
}
function SecurityCoverageSession({ deviceId }: { deviceId: string }) {
    const [locale] = useLocale(); const labels = copy[locale]; const heading = useId();
    const validate = useCallback((value: unknown): value is SecurityCoverageView => validSecurityCoverageView(value, deviceId), [deviceId]);
    const resource = useSecurityResource(`/devices/${encodeURIComponent(deviceId)}/security`, validate, noop);
    const view = resource.value;
    const [, tick] = useState(0);
    useEffect(() => { if (!view) return; const timer = window.setInterval(() => tick(value => value + 1), 1000); return () => window.clearInterval(timer); }, [view]);
    const freshness = view ? effectiveSecurityFreshness(view, resource.elapsed()) : 'unknown';
    const status = view ? effectiveSecurityCollectionStatus(view, resource.elapsed()) : null;
    const statusLabel = status === 'fresh' ? labels.freshStatus : status === 'stale' ? labels.staleStatus : status === 'unavailable' ? labels.unavailableStatus : status ? labels[status] : '';
    return <section className="security-panel" aria-labelledby={heading} aria-busy={resource.loading}>
        <header className="security-heading"><span className="security-symbol"><ShieldQuestion size={20}/></span><div><h2 id={heading}>{labels.title}</h2><p>{labels.subtitle}</p></div><button type="button" className="button small" disabled={resource.loading || resource.error === 'session'} onClick={() => void resource.load()}><RefreshCw size={14}/>{labels.refresh}</button></header>
        {resource.loading && <div className="security-loading" role="status"><LoaderCircle className="spin" size={17}/>{labels.loading}</div>}
        {resource.error && <Notice error>{labels[resource.error]}</Notice>}
        {view && <><div className="security-status-line"><span className="security-badge">{statusLabel}</span><span>{labels.checked}: <time dateTime={view.serverNow}>{date(view.serverNow, locale)}</time></span></div>
            <div className="security-grid">
                <article className="security-metric"><h3><Boxes size={16}/>{labels.observed}</h3><strong>{count(view.inventory.reportedItemCount, locale, labels)}</strong><p>{labels.reported}</p><div className="security-badges"><span className={`security-badge${view.inventory.coverage === 'partial' ? ' caution' : ''}`}>{view.inventory.coverage === 'observed' ? labels.complete : view.inventory.coverage === 'partial' ? labels.partial : labels.missing}</span>{freshness !== 'unknown' && <span className={`security-badge${freshness === 'stale' ? ' caution' : ''}`}>{labels[freshness]}</span>}{view.inventory.truncated && <span className="security-badge caution">{labels.truncated}</span>}</div></article>
                <article className="security-metric"><h3><RefreshCw size={16}/>{labels.updates}</h3><strong className="security-unknown">{labels.unknown}</strong><p>{labels.updateNote}</p></article>
                <article className="security-metric"><h3><ShieldQuestion size={16}/>{labels.cves}</h3><strong className="security-unknown">{labels.unknown}</strong><p>{labels.cveNote}</p></article>
            </div>
            <div className="security-gaps"><h3>{labels.details}</h3><ul>{view.vulnerabilities.reasonCodes.map(reason => <li key={reason}><span aria-hidden="true"/> {labels[reason]}</li>)}</ul></div>
            <details className="security-details"><summary>{labels.observed}</summary><dl className="security-facts"><div><dt>{labels.installed}</dt><dd>{count(view.inventory.installedCount, locale, labels)}</dd></div><div><dt>{labels.discovered}</dt><dd>{count(view.inventory.observedCount, locale, labels)}{view.inventory.observedCount !== null && <small>{view.inventory.countExact ? labels.exact : labels.lowerBound}</small>}</dd></div><div><dt>{labels.collected}</dt><dd>{view.inventory.collectedAt ? date(view.inventory.collectedAt, locale) : labels.unknown}</dd></div><div><dt>{labels.received}</dt><dd>{view.receivedAt ? date(view.receivedAt, locale) : labels.unknown}</dd></div><div><dt>{labels.generation}</dt><dd>{view.inventory.generationId ?? labels.unknown}</dd></div><div><dt>{labels.candidates}</dt><dd>{labels.unknown}</dd></div></dl><p className="security-detail-note">{labels.inventoryScope}</p><p className="security-detail-note">{view.catalog.configured ? labels.catalogConfigured : labels.catalogMissing}</p></details>
        </>}
        <footer className="security-footer"><Info size={15}/><p>{labels.caution}</p></footer>
        <AdvisoryReviewPanel deviceId={deviceId}/>
    </section>;
}

export function OfflineCatalogPanel({ sessionKey }: { sessionKey?: string | number }) {
    const operator = useOperator(); const [locale] = useLocale();
    if (!operator || operator.mode !== 'lan' || !operator.authenticated) return <section className="security-panel"><Notice>{copy[locale].access}</Notice></section>;
    return <OfflineCatalogSession key={String(sessionKey ?? operator.expiresAt ?? '')}/>;
}
function OfflineCatalogSession() {
    const [locale] = useLocale(); const labels = copy[locale]; const heading = useId(), fileId = useId();
    const input = useRef<HTMLInputElement | null>(null), reader = useRef<FileReader | null>(null), raw = useRef<string | null>(null);
    const [selectedBytes, setSelectedBytes] = useState<number | null>(null), [reading, setReading] = useState(false), [fileError, setFileError] = useState<'invalidFile' | 'tooLarge' | null>(null), [confirmClear, setConfirmClear] = useState(false);
    const clearLocal = useCallback(() => { reader.current?.abort(); reader.current = null; raw.current = null; if (input.current) input.current.value = ''; setSelectedBytes(null); setReading(false); setFileError(null); setConfirmClear(false); }, []);
    const resource = useSecurityResource('/security/catalog', validOfflineCatalogView, clearLocal, false);
    const view = resource.value, catalog = view?.catalog;
    const selectFile = (file: File | undefined) => {
        clearLocal();
        if (!file || !resource.ready()?.enabled) return;
        if (file.size === 0 || file.size > CATALOG_MAX_BYTES) { setFileError(file.size > CATALOG_MAX_BYTES ? 'tooLarge' : 'invalidFile'); return; }
        // No filename is retained in state, rendered, placed in a URL or transmitted.
        const currentReader = new FileReader(); reader.current = currentReader; setReading(true);
        const failed = () => { if (reader.current !== currentReader) return; clearLocal(); setFileError('invalidFile'); };
        currentReader.onerror = failed;
        currentReader.onload = () => {
            if (reader.current !== currentReader || !resource.ready()?.enabled) return;
            try {
                if (!(currentReader.result instanceof ArrayBuffer) || currentReader.result.byteLength !== file.size || currentReader.result.byteLength > CATALOG_MAX_BYTES) { failed(); return; }
                // Preserve duplicate JSON keys and BOM for the authoritative parser.
                const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(currentReader.result);
                if (!text || new TextEncoder().encode(text).byteLength !== file.size) { failed(); return; }
                raw.current = text; setSelectedBytes(file.size); setReading(false); reader.current = null;
            } catch { failed(); }
        };
        currentReader.readAsArrayBuffer(file);
    };
    return <section className="security-panel security-catalog" aria-labelledby={heading} aria-busy={resource.loading || Boolean(resource.pending)}>
        <header className="security-heading"><span className="security-symbol"><Database size={20}/></span><div><h2 id={heading}>{labels.catalogTitle}</h2><p>{labels.catalogSubtitle}</p></div><button type="button" className="button small" disabled={resource.loading || resource.error === 'session'} onClick={() => void resource.load()}><RefreshCw size={14}/>{labels.refreshCatalog}</button></header>
        <div className="security-memory"><Database size={14}/><strong>{labels.memory}</strong></div><p className="security-detail-note">{labels.memoryNote}</p>
        {resource.loading && <div className="security-loading" role="status"><LoaderCircle size={17} className="spin"/>{labels.loading}</div>}
        {resource.error && <Notice error>{labels[resource.error]}</Notice>}
        {resource.notice && <div className="security-notice" role="status"><Info size={16}/><p>{labels[resource.notice]}</p></div>}
        {resource.pending && <div className="security-pending" role="status"><LoaderCircle size={17} className="spin"/><span>{labels.loading}</span><button type="button" className="button small" onClick={resource.cancel}><X size={14}/>{labels.cancelRequest}</button></div>}
        {view && !view.enabled && <Notice>{labels.disabled}</Notice>}
        {view?.enabled && <>
            <div className="security-status-line"><span className="security-badge">{catalog ? labels.unverified : labels.noCatalog}</span><span>{labels.checked}: {date(view.serverNow, locale)}</span></div>
            {catalog && <><div className="security-format-counts"><div><strong>{count(catalog.ruleCount, locale, labels)}</strong><span>{labels.rules}</span></div><div><strong>{count(catalog.coveredSourceCount, locale, labels)}</strong><span>{labels.sources}</span></div><div><strong>{count(catalog.byteCount, locale, labels)}</strong><span>{labels.bytes}</span></div></div><p className="security-detail-note">{labels.formatNote}</p><details className="security-details"><summary>{labels.formatFacts}</summary><dl className="security-facts"><div><dt>{labels.provider}</dt><dd>{catalog.provider}</dd></div><div><dt>{labels.release}</dt><dd>Debian 13 / {catalog.declaredRelease}</dd></div><div><dt>{labels.format}</dt><dd>{catalog.format}</dd></div><div><dt>{labels.imported}</dt><dd>{date(catalog.importedAt, locale)}</dd></div><div><dt>{labels.published}</dt><dd>{labels.unknown}</dd></div><div><dt>{labels.freshness}</dt><dd>{labels.unknown}</dd></div><div><dt>{labels.synthetic}</dt><dd>{catalog.synthetic ? labels.yes : labels.no}</dd></div><div className="security-digest"><dt>{labels.digest}</dt><dd>{catalog.sha256}<small>{labels.digestNote}</small></dd></div></dl></details></>}
            <details className="security-details security-import" onToggle={event => { if (!event.currentTarget.open) clearLocal(); }}><summary><Upload size={15}/>{labels.importSummary}</summary><p className="security-detail-note">{labels.importNote}</p><p className="security-detail-note">{labels.lease}</p><div className="security-file-controls"><input ref={input} id={fileId} type="file" accept="application/json,.json" aria-label={labels.choose} onChange={event => { const file = event.currentTarget.files?.[0]; event.currentTarget.value = ''; selectFile(file); }}/><label className="button" htmlFor={fileId}><FileJson size={15}/>{labels.choose}</label>{reading && <span role="status">{labels.preparing}</span>}{selectedBytes !== null && <span>{labels.selected} · {count(selectedBytes, locale, labels)} B</span>}{(reading || selectedBytes !== null) && <button type="button" className="button small" onClick={clearLocal}><X size={14}/>{labels.cancel}</button>}<button type="button" className="button primary" disabled={raw.current === null || reading} onClick={() => { if (raw.current !== null) void resource.mutate('import', raw.current); }}><Upload size={15}/>{catalog ? labels.replace : labels.import}</button></div>{fileError && <Notice error>{labels[fileError]}</Notice>}</details>
            {catalog && <div className="security-clear">{confirmClear ? <><p>{labels.clearQuestion}</p><button type="button" className="button" onClick={() => setConfirmClear(false)}>{labels.keep}</button><button type="button" className="button danger" onClick={() => void resource.mutate('clear', '')}>{labels.clearConfirm}</button></> : <button type="button" className="button small" onClick={() => { clearLocal(); setConfirmClear(true); }}>{labels.clear}</button>}</div>}
        </>}
    </section>;
}
