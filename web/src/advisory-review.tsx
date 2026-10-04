import { useCallback, useEffect, useId, useRef, useState } from 'react';
import { ChevronDown, LoaderCircle, RefreshCw, TriangleAlert } from 'lucide-react';
import { APIError, AUTH_REQUIRED_EVENT, getProtectedRequestEpoch, request } from './api';
import { useOperator } from './auth';
import { useLocale } from './i18n';
import { ADVISORY_REVIEW_LEASE_MS, ADVISORY_REVIEW_RESPONSE_MAX_BYTES, advisoryReviewRemainingMs, advisoryReviewVisible, validAdvisoryReviewView } from './advisory-review-types';
import type { AdvisoryReviewReason, AdvisoryReviewView } from './advisory-review-types';
import './advisory-review.css';

const copy = {
    en: {
        details: 'Conditional advisory review candidates', title: 'Review candidates', intro: 'Conditional inspection of reported source-package metadata against one operator-supplied, unverified offline catalog. Each row is a review candidate, not a finding or an available update.',
        access: 'Authenticated LAN operator access is required.', refresh: 'Refresh review candidates', loading: 'Reading review candidates…', recovering: 'Storage is busy. One automatic read retry in 2 seconds.', loadError: 'Review candidates could not be read. Refresh to try again.', invalid: 'The manager returned unsupported or inconsistent review candidates. Previous output is not used.', timeout: 'The manager did not respond in time. Refresh review candidates.', session: 'Your session has ended. Sign in again.', expired: 'The review candidate view expired or its time anchor changed. Refresh before using it.', busy: 'Another review is in progress. Retry in a moment.', changed: 'The package snapshot or catalog changed. Previous review candidates were cleared. Refresh to inspect the current selection.',
        not_configured: 'Review candidate collection not configured', awaiting: 'Awaiting package observations for review candidates', fresh: 'Package observations within the collection window', stale: 'Package observations stale; no review candidates shown', revoked: 'Device identity revoked; no review candidates shown', unavailable: 'Package observations unavailable; no review candidates shown',
        noReview: 'Review candidates require a fresh, activated managed-operations-v2 package observation. This view does not collect packages or change enrollment.',
        complete: 'Selected-scope inspection completed', partial: 'Partial selected-scope inspection', unavailableReview: 'Review candidate inspection unavailable', scope: 'Scope is limited to selected reported source metadata and declared catalog coverage. Completed inspection never means a secure host or complete CVE coverage.',
        trust: 'Catalog origin is unverified; catalog freshness is unknown. Installed artifact origin is unknown. The review core does not evaluate snapshot freshness; the manager collection window is checked separately.',
        bounds: 'Bounded inspection: up to 128 review candidate rows, 4,096 package/rule pairs, 1,024 version comparisons and 64 KiB of review output. Omitted rows are not fixed or unaffected verdicts.',
        empty: 'No review candidate rows were returned for this selected scope. This is not evidence of zero affected CVEs, available updates or a secure host.',
        unknownCounts: 'Affected CVEs: unknown. Offered updates: unknown. Declared fix versions do not establish installable updates or installed-artifact applicability.',
        selectedRows: 'Selected inventory rows', inventoryComplete: 'Declared inventory scope complete', inventoryPartial: 'Declared inventory scope not complete', candidateRows: 'Review candidate rows shown', pairs: 'Package/rule pairs inspected', comparisons: 'Version comparisons performed',
        revision: 'Exact catalog revision', hash: 'SHA-256 of supplied catalog bytes', hashNote: 'This hash identifies content; it is not a signature or proof of origin.', generation: 'Exact observation generation', catalogId: 'Catalog identity', provider: 'Declared provider', release: 'Declared catalog release', imported: 'Catalog imported by manager', published: 'Publication time unknown', noCatalog: 'No offline catalog supplied', synthetic: 'Synthetic catalog: no live review candidate rows are produced.',
        managerTime: 'Manager time', received: 'Package observations received', collected: 'Package observations collected', sequence: 'Received sequence', exactRelease: 'Exact reported release fields', absent: 'Absent field', emptyField: 'Explicitly empty field', unknown: 'Unknown',
        candidate: 'Review candidate', package: 'Reported binary package', architecture: 'Architecture', source: 'Reported source package', sourceVersion: 'Reported source version', mapping: 'Reported mapping basis', advisory: 'Declared advisory identifier', status: 'Declared catalog status', fix: 'Declared fix version (unverified)', noFix: 'No fix version declared', qualifications: 'Declared qualifications', noQualifications: 'None declared', basis: 'Review candidate basis', reason: 'Review candidate reason',
        'source-field': 'Explicit Source field', 'binary-default': 'Absent Source field: binary default', conditional_reported_source_below_declared_fix: 'Conditional: reported source version is below the declared fix', comparison_unavailable: 'Version comparison unavailable', declared_unresolved: 'Catalog declares an unresolved status', reported_source_below_declared_fix: 'Reported source version compared below the unverified declared fix.', declared_status_requires_review: 'Declared status requires review; no affected verdict is established.',
    },
    de: {
        details: 'Bedingte Hinweis-Prüfkandidaten', title: 'Prüfkandidaten', intro: 'Bedingte Prüfung gemeldeter Quellpaket-Metadaten gegen einen vom Operator gelieferten, unbestätigten Offline-Katalog. Jede Zeile ist ein Prüfkandidat, kein Befund und kein verfügbares Update.',
        access: 'Ein authentifizierter LAN-Operator-Zugang ist erforderlich.', refresh: 'Prüfkandidaten aktualisieren', loading: 'Prüfkandidaten werden gelesen…', recovering: 'Der Datenspeicher ist ausgelastet. Ein automatischer Leseversuch folgt in 2 Sekunden.', loadError: 'Prüfkandidaten konnten nicht gelesen werden. Zum Wiederholen aktualisieren.', invalid: 'Der Manager lieferte nicht unterstützte oder widersprüchliche Prüfkandidaten. Frühere Ergebnisse werden nicht verwendet.', timeout: 'Der Manager hat nicht rechtzeitig geantwortet. Prüfkandidaten aktualisieren.', session: 'Die Sitzung ist beendet. Erneut anmelden.', expired: 'Die Prüfkandidaten-Ansicht ist abgelaufen oder ihr Zeitanker hat sich geändert. Vor Nutzung aktualisieren.', busy: 'Eine andere Prüfung läuft. Gleich erneut versuchen.', changed: 'Paket-Snapshot oder Katalog wurden geändert. Frühere Prüfkandidaten wurden entfernt. Für die aktuelle Auswahl aktualisieren.',
        not_configured: 'Erfassung für Prüfkandidaten nicht eingerichtet', awaiting: 'Paketbeobachtungen für Prüfkandidaten ausstehend', fresh: 'Paketbeobachtungen im Erfassungszeitfenster', stale: 'Paketbeobachtungen veraltet; keine Prüfkandidaten angezeigt', revoked: 'Geräteidentität widerrufen; keine Prüfkandidaten angezeigt', unavailable: 'Paketbeobachtungen nicht verfügbar; keine Prüfkandidaten angezeigt',
        noReview: 'Prüfkandidaten benötigen eine aktuelle, aktivierte managed-operations-v2-Paketbeobachtung. Diese Ansicht erfasst keine Pakete und ändert kein Enrollment.',
        complete: 'Prüfung des ausgewählten Umfangs abgeschlossen', partial: 'Prüfung des ausgewählten Umfangs teilweise abgeschlossen', unavailableReview: 'Prüfkandidaten-Prüfung nicht verfügbar', scope: 'Der Umfang ist auf ausgewählte gemeldete Quellmetadaten und die deklarierte Katalogabdeckung begrenzt. Eine abgeschlossene Prüfung belegt niemals einen sicheren Host oder vollständige CVE-Abdeckung.',
        trust: 'Katalogherkunft unbestätigt; Katalogaktualität unbekannt. Herkunft installierter Artefakte unbekannt. Die Prüfung selbst bewertet keine Snapshot-Aktualität; das Erfassungszeitfenster wird separat vom Manager geprüft.',
        bounds: 'Begrenzte Prüfung: höchstens 128 Prüfkandidaten-Zeilen, 4.096 Paket-/Regelpaare, 1.024 Versionsvergleiche und 64 KiB Prüfergebnis. Ausgelassene Zeilen sind keine Bestätigung für behoben oder nicht betroffen.',
        empty: 'Für diesen ausgewählten Umfang wurden keine Prüfkandidaten-Zeilen zurückgegeben. Dies belegt weder null betroffene CVEs noch verfügbare Updates oder einen sicheren Host.',
        unknownCounts: 'Betroffene CVEs: unbekannt. Angebotene Updates: unbekannt. Deklarierte Korrekturversionen belegen weder installierbare Updates noch die Anwendbarkeit auf installierte Artefakte.',
        selectedRows: 'Ausgewählte Inventarzeilen', inventoryComplete: 'Deklarierter Inventarumfang vollständig', inventoryPartial: 'Deklarierter Inventarumfang nicht vollständig', candidateRows: 'Angezeigte Prüfkandidaten-Zeilen', pairs: 'Geprüfte Paket-/Regelpaare', comparisons: 'Durchgeführte Versionsvergleiche',
        revision: 'Exakte Katalogrevision', hash: 'SHA-256 der gelieferten Katalogbytes', hashNote: 'Dieser Hash kennzeichnet Inhalt; er ist keine Signatur und kein Herkunftsbeleg.', generation: 'Exakte Beobachtungsgeneration', catalogId: 'Katalogkennung', provider: 'Deklarierter Anbieter', release: 'Deklariertes Katalog-Release', imported: 'Katalog vom Manager importiert', published: 'Veröffentlichungszeit unbekannt', noCatalog: 'Kein Offline-Katalog geliefert', synthetic: 'Synthetischer Katalog: Es werden keine Live-Prüfkandidaten-Zeilen erzeugt.',
        managerTime: 'Managerzeit', received: 'Paketbeobachtungen empfangen', collected: 'Paketbeobachtungen erfasst', sequence: 'Empfangene Sequenz', exactRelease: 'Exakte gemeldete Release-Felder', absent: 'Feld fehlt', emptyField: 'Feld ausdrücklich leer', unknown: 'Unbekannt',
        candidate: 'Prüfkandidat', package: 'Gemeldetes Binärpaket', architecture: 'Architektur', source: 'Gemeldetes Quellpaket', sourceVersion: 'Gemeldete Quellversion', mapping: 'Gemeldete Zuordnungsgrundlage', advisory: 'Deklarierte Hinweiskennung', status: 'Deklarierter Katalogstatus', fix: 'Deklarierte Korrekturversion (unbestätigt)', noFix: 'Keine Korrekturversion deklariert', qualifications: 'Deklarierte Einschränkungen', noQualifications: 'Keine deklariert', basis: 'Prüfkandidaten-Grundlage', reason: 'Prüfkandidaten-Grund',
        'source-field': 'Ausdrückliches Source-Feld', 'binary-default': 'Source-Feld fehlt: Binärvorgabe', conditional_reported_source_below_declared_fix: 'Bedingt: gemeldete Quellversion liegt unter deklarierter Korrektur', comparison_unavailable: 'Versionsvergleich nicht verfügbar', declared_unresolved: 'Katalog deklariert einen ungelösten Status', reported_source_below_declared_fix: 'Gemeldete Quellversion liegt im Vergleich unter der unbestätigten deklarierten Korrektur.', declared_status_requires_review: 'Deklarierter Status erfordert Prüfung; keine bestätigte Betroffenheit.',
    },
};
const reasons: Record<'en' | 'de', Record<AdvisoryReviewReason, string>> = {
    en: {
        catalog_origin_unverified: 'Offline catalog origin is unverified.', catalog_freshness_unknown: 'Offline catalog freshness is unknown.', installed_artifact_origin_unknown: 'Installed artifact origin is unknown.', snapshot_freshness_not_evaluated: 'The review core did not evaluate snapshot freshness.', catalog_unavailable: 'No offline catalog is available.', synthetic_catalog: 'Synthetic catalog is excluded from live review candidates.', release_unavailable: 'Reported release evidence is unavailable.', release_facts_missing: 'Exact release facts are missing.', release_facts_inconsistent: 'Exact release facts are inconsistent.', catalog_release_mismatch: 'Reported release does not match the declared catalog release.', unsupported_release: 'Reported release is outside the supported review scope.', inventory_unavailable: 'Reported package inventory is unavailable.', inventory_partial: 'Reported inventory is partial.', package_installation_incomplete: 'An incomplete package installation was excluded.', source_package_not_covered: 'A reported source package is outside declared catalog coverage.', review_row_limit: 'Review candidate row limit reached.', review_pair_limit: 'Package/rule pair limit reached.', review_comparison_limit: 'Version comparison limit reached.', review_byte_limit: 'Review output byte limit reached; only an ordered prefix remains.', comparator_unavailable: 'A version comparator is unavailable.', comparison_failed: 'A version comparison failed.', declared_rule_uninterpretable: 'A declared catalog rule could not be interpreted.',
    },
    de: {
        catalog_origin_unverified: 'Offline-Katalogherkunft unbestätigt.', catalog_freshness_unknown: 'Offline-Katalogaktualität unbekannt.', installed_artifact_origin_unknown: 'Herkunft installierter Artefakte unbekannt.', snapshot_freshness_not_evaluated: 'Die Prüfung selbst hat die Snapshot-Aktualität nicht bewertet.', catalog_unavailable: 'Kein Offline-Katalog verfügbar.', synthetic_catalog: 'Synthetischer Katalog von Live-Prüfkandidaten ausgeschlossen.', release_unavailable: 'Gemeldete Release-Belege nicht verfügbar.', release_facts_missing: 'Exakte Release-Angaben fehlen.', release_facts_inconsistent: 'Exakte Release-Angaben sind widersprüchlich.', catalog_release_mismatch: 'Gemeldetes Release passt nicht zum deklarierten Katalog-Release.', unsupported_release: 'Gemeldetes Release außerhalb des unterstützten Prüfumfangs.', inventory_unavailable: 'Gemeldetes Paketinventar nicht verfügbar.', inventory_partial: 'Gemeldetes Inventar ist teilweise.', package_installation_incomplete: 'Eine unvollständige Paketinstallation wurde ausgeschlossen.', source_package_not_covered: 'Ein gemeldetes Quellpaket liegt außerhalb der deklarierten Katalogabdeckung.', review_row_limit: 'Grenze für Prüfkandidaten-Zeilen erreicht.', review_pair_limit: 'Grenze für Paket-/Regelpaare erreicht.', review_comparison_limit: 'Grenze für Versionsvergleiche erreicht.', review_byte_limit: 'Byte-Grenze des Prüfergebnisses erreicht; nur ein sortierter Anfang bleibt.', comparator_unavailable: 'Kein Versionsvergleicher verfügbar.', comparison_failed: 'Ein Versionsvergleich ist fehlgeschlagen.', declared_rule_uninterpretable: 'Eine deklarierte Katalogregel konnte nicht interpretiert werden.',
    },
};
type Failure = 'loadError' | 'invalid' | 'timeout' | 'session' | 'expired' | 'busy' | 'changed';
type Anchor = { mono: number; wall: number; epoch: number };
function elapsed(anchor: Anchor): number { return performance.now() - anchor.mono; }
function uncertain(anchor: Anchor): boolean { const delta = elapsed(anchor), wallDelta = Date.now() - anchor.wall; return !Number.isFinite(delta) || delta < 0 || !Number.isFinite(wallDelta) || Math.abs(wallDelta - delta) > 1500; }
function useAdvisoryReviewResource(deviceId: string) {
    const [value, setValue] = useState<AdvisoryReviewView | null>(null), [loading, setLoading] = useState(false), [recovering, setRecovering] = useState(false), [error, setError] = useState<Failure | null>(null), [, tick] = useState(0);
    const alive = useRef(false), locked = useRef(false), suspended = useRef(false);
    const pending = useRef<{ controller: AbortController; anchor: Anchor; timeout: number } | null>(null), current = useRef<Anchor | null>(null), expiry = useRef<number | undefined>(undefined);
    const invalidate = useCallback((failure: Failure | null = null) => {
        window.clearTimeout(expiry.current); pending.current?.controller.abort(); window.clearTimeout(pending.current?.timeout); pending.current = null; current.current = null;
        if (alive.current) { setValue(null); setLoading(false); setRecovering(false); setError(failure); }
    }, []);
    const load = useCallback(async () => {
        if (!alive.current || locked.current || suspended.current || document.visibilityState === 'hidden') return;
        invalidate(); const controller = new AbortController(), anchor = { mono: performance.now(), wall: Date.now(), epoch: getProtectedRequestEpoch() };
        pending.current = { controller, anchor, timeout: window.setTimeout(() => { if (pending.current?.controller === controller) invalidate('timeout'); }, 10000) }; setLoading(true);
        const active = () => {
            if (!alive.current || locked.current || suspended.current || controller.signal.aborted || pending.current?.controller !== controller) return false;
            if (anchor.epoch !== getProtectedRequestEpoch()) { locked.current = true; invalidate('session'); return false; }
            if (uncertain(anchor)) { invalidate('expired'); return false; }
            if (elapsed(anchor) >= 10000) { invalidate('timeout'); return false; }
            return true;
        };
        // At most one repeat, only for this fixed read's exact storage-contention code.
        // The controller, access epoch, clock anchor and total deadline never restart.
        for (let attempt = 0; attempt < 2; attempt++) {
            try {
                const next = await request<unknown>(`/devices/${encodeURIComponent(deviceId)}/security/review`, { signal: controller.signal }, ADVISORY_REVIEW_RESPONSE_MAX_BYTES);
                if (!active()) return;
                if (!validAdvisoryReviewView(next, deviceId)) { invalidate('invalid'); return; }
                window.clearTimeout(pending.current?.timeout); pending.current = null; current.current = anchor; setValue(next); setLoading(false); setRecovering(false);
                const remaining = next.collectionStatus === 'fresh' ? Math.min(ADVISORY_REVIEW_LEASE_MS - elapsed(anchor), advisoryReviewRemainingMs(next) - elapsed(anchor) + 1) : ADVISORY_REVIEW_LEASE_MS - elapsed(anchor);
                if (remaining <= 0) { invalidate('expired'); return; }
                expiry.current = window.setTimeout(() => invalidate('expired'), remaining);
                return;
            } catch (caught) {
                if (!active()) return;
                if (attempt === 0 && caught instanceof APIError && caught.status === 429 && caught.code === 'storage_busy') {
                    setRecovering(true);
                    await new Promise<void>(resolve => {
                        const finish = () => { window.clearTimeout(delay); controller.signal.removeEventListener('abort', finish); resolve(); };
                        const delay = window.setTimeout(finish, 2000);
                        controller.signal.addEventListener('abort', finish, { once: true });
                        if (controller.signal.aborted) finish();
                    });
                    if (!active()) return;
                    setRecovering(false);
                    continue;
                }
                if (caught instanceof APIError && caught.status === 401) locked.current = true;
                invalidate(caught instanceof APIError && caught.status === 401 ? 'session' : caught instanceof APIError && caught.status === 409 ? 'changed' : caught instanceof APIError && caught.status === 429 ? 'busy' : 'loadError');
                return;
            }
        }
    }, [deviceId, invalidate]);
    useEffect(() => {
        alive.current = true; locked.current = false; suspended.current = document.visibilityState === 'hidden';
        const lock = () => { locked.current = true; invalidate('session'); };
        const suspend = () => { suspended.current = true; invalidate(); };
        const restore = () => { if (locked.current || document.visibilityState === 'hidden') return; suspended.current = false; void load(); };
        const visibility = () => document.visibilityState === 'hidden' ? suspend() : restore();
        const show = (event: PageTransitionEvent) => { if (event.persisted || suspended.current) restore(); };
        const navigate = () => invalidate();
        window.addEventListener(AUTH_REQUIRED_EVENT, lock); window.addEventListener('pagehide', suspend); window.addEventListener('pageshow', show); window.addEventListener('blur', suspend); window.addEventListener('focus', restore); window.addEventListener('hashchange', navigate); window.addEventListener('popstate', navigate); document.addEventListener('visibilitychange', visibility);
        const timer = window.setInterval(() => { const anchor = current.current ?? pending.current?.anchor; if (anchor && anchor.epoch !== getProtectedRequestEpoch()) { locked.current = true; invalidate('session'); } else if (anchor && uncertain(anchor)) invalidate('expired'); else if (current.current) tick(value => value + 1); }, 1000);
        void load();
        return () => { alive.current = false; invalidate(); window.clearInterval(timer); window.removeEventListener(AUTH_REQUIRED_EVENT, lock); window.removeEventListener('pagehide', suspend); window.removeEventListener('pageshow', show); window.removeEventListener('blur', suspend); window.removeEventListener('focus', restore); window.removeEventListener('hashchange', navigate); window.removeEventListener('popstate', navigate); document.removeEventListener('visibilitychange', visibility); };
    }, [invalidate, load]);
    return { value, loading, recovering, error, load, elapsed: current.current ? elapsed(current.current) : Number.POSITIVE_INFINITY };
}

/** Read-only and lazy. Closing or changing the identity destroys the resource. */
export function AdvisoryReviewPanel({ deviceId, sessionKey }: { deviceId: string; sessionKey?: string | number }) {
    const operator = useOperator(), [locale] = useLocale();
    if (!operator || operator.mode !== 'lan' || !operator.authenticated) return <p>{copy[locale].access}</p>;
    return <ReviewDisclosure key={`${deviceId}:${String(sessionKey ?? operator.expiresAt ?? '')}`} deviceId={deviceId}/>;
}
function ReviewDisclosure({ deviceId }: { deviceId: string }) {
    const [open, setOpen] = useState(false), [locale] = useLocale(), id = useId();
    return <section className="advisory-review-disclosure"><button className="advisory-review-toggle" type="button" aria-expanded={open} aria-controls={id} onClick={() => setOpen(value => !value)}>{copy[locale].details}<ChevronDown size={16}/></button><div id={id}>{open && <ReviewContent deviceId={deviceId}/>}</div></section>;
}
function ReviewContent({ deviceId }: { deviceId: string }) {
    const [locale] = useLocale(), labels = copy[locale], resource = useAdvisoryReviewResource(deviceId), heading = useId();
    const view = resource.value, review = view && advisoryReviewVisible(view, resource.elapsed) ? view.review : null;
    const field = (value: string | null) => value === null ? labels.absent : value === '' ? labels.emptyField : value;
    const number = (value: number) => new Intl.NumberFormat(locale).format(value);
    return <div className="advisory-review" aria-labelledby={heading} aria-busy={resource.loading}>
        <header className="advisory-review-heading"><h3 id={heading}>{labels.title}</h3><button className="button small" type="button" disabled={resource.loading || resource.error === 'session'} onClick={() => void resource.load()}><RefreshCw size={14}/>{labels.refresh}</button></header>
        <p>{labels.intro}</p><p className="advisory-review-caution">{labels.unknownCounts}</p>
        {resource.loading && <p role="status"><LoaderCircle size={16} className="spin"/>{resource.recovering ? labels.recovering : labels.loading}</p>}
        {resource.error && <p className="advisory-review-error" role="alert"><TriangleAlert size={16}/>{labels[resource.error]}</p>}
        {view && <><p className="advisory-review-status">{labels[view.collectionStatus]}</p>{!review && <p>{labels.noReview}</p>}</>}
        {review && <>
            <p className="advisory-review-status">{review.status === 'unavailable' ? labels.unavailableReview : labels[review.status]}</p>
            <p>{labels.scope}</p><p className="advisory-review-caution">{labels.trust}</p><p>{labels.bounds}</p>
            <ul className="advisory-review-reasons">{review.reasonCodes.map(reason => <li key={reason}>{reasons[locale][reason]}</li>)}</ul>
            <dl className="advisory-review-facts"><div><dt>{labels.selectedRows}</dt><dd>{number(review.snapshot.inventoryRows)}</dd></div><div><dt>{labels.candidateRows}</dt><dd>{number(review.candidates.length)}</dd></div><div><dt>{labels.pairs}</dt><dd>{number(review.pairsInspected)}</dd></div><div><dt>{labels.comparisons}</dt><dd>{number(review.comparisons)}</dd></div></dl>
            <p>{review.snapshot.inventoryComplete ? labels.inventoryComplete : labels.inventoryPartial}</p>
            <section aria-label={labels.exactRelease}><h4>{labels.exactRelease}</h4><dl className="advisory-review-facts">{([['ID', 'id'], ['VERSION_ID', 'versionId'], ['VERSION_CODENAME', 'versionCodename']] as const).map(([name, key]) => <div key={key}><dt>{name}</dt><dd>{field(review.snapshot.release[key])}</dd></div>)}</dl></section>
            <dl className="advisory-review-facts"><div><dt>{labels.revision}</dt><dd>{review.revision}</dd></div><div><dt>{labels.generation}</dt><dd>{review.snapshot.generationId}</dd></div></dl>
            {review.catalog ? <><dl className="advisory-review-facts"><div><dt>{labels.catalogId}</dt><dd>{review.catalog.id}</dd></div><div><dt>{labels.hash}</dt><dd>{review.catalog.sha256}</dd></div><div><dt>{labels.provider}</dt><dd>{review.catalog.provider}</dd></div><div><dt>{labels.release}</dt><dd>{review.catalog.declaredRelease}</dd></div><div><dt>{labels.imported}</dt><dd><time dateTime={review.catalog.importedAt}>{review.catalog.importedAt}</time></dd></div></dl><p>{labels.published}</p><p>{labels.hashNote}</p>{review.catalog.synthetic && <p className="advisory-review-caution">{labels.synthetic}</p>}</> : <p>{labels.noCatalog}</p>}
            {review.candidates.length === 0 ? <p>{labels.empty}</p> : <ol className="advisory-review-candidates">{review.candidates.map(row => <li key={`${row.package}:${row.architecture}:${row.advisoryId}`}><article aria-label={`${labels.candidate}: ${row.package} / ${row.advisoryId}`}><h4>{labels.candidate}: {row.package} / {row.advisoryId}</h4><dl className="advisory-review-facts"><div><dt>{labels.package}</dt><dd>{row.package}</dd></div><div><dt>{labels.architecture}</dt><dd>{row.architecture}</dd></div><div><dt>{labels.source}</dt><dd>{row.reportedSourcePackage}</dd></div><div><dt>{labels.sourceVersion}</dt><dd>{row.reportedSourceVersion}</dd></div><div><dt>{labels.mapping}</dt><dd>{labels[row.sourceMapping]}</dd></div><div><dt>{labels.advisory}</dt><dd>{row.advisoryId}</dd></div><div><dt>{labels.status}</dt><dd>{row.declaredStatus}</dd></div><div><dt>{labels.fix}</dt><dd>{row.declaredFixedVersion || labels.noFix}</dd></div><div><dt>{labels.qualifications}</dt><dd>{row.qualifications.length ? row.qualifications.join(', ') : labels.noQualifications}</dd></div><div><dt>{labels.basis}</dt><dd>{labels[row.basis]}</dd></div><div><dt>{labels.reason}</dt><dd>{row.reason === 'reported_source_below_declared_fix' || row.reason === 'declared_status_requires_review' ? labels[row.reason] : reasons[locale][row.reason]}</dd></div></dl></article></li>)}</ol>}
        </>}
        {view && <dl className="advisory-review-facts"><div><dt>{labels.managerTime}</dt><dd><time dateTime={view.serverNow}>{view.serverNow}</time></dd></div><div><dt>{labels.received}</dt><dd>{view.receivedAt ?? labels.unknown}</dd></div><div><dt>{labels.sequence}</dt><dd>{view.sequence === null ? labels.unknown : number(view.sequence)}</dd></div>{review && <div><dt>{labels.collected}</dt><dd><time dateTime={review.snapshot.collectedAt}>{review.snapshot.collectedAt}</time></dd></div>}</dl>}
    </div>;
}
