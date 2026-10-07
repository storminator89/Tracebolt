import { useCallback, useEffect, useId, useRef, useState } from 'react';
import { ChevronDown, Info, LoaderCircle, RefreshCw, TriangleAlert } from 'lucide-react';
import { APIError, AUTH_REQUIRED_EVENT, request } from './api';
import { useOperator } from './auth';
import { useLocale } from './i18n';
import { effectivePackageStatus, PACKAGE_RESPONSE_MAX_BYTES, packageSnapshotVisible, releaseApplicability, validPackageView } from './package-observations-types';
import type { PackageView } from './package-observations-types';
import './package-observations.css';

const copy = {
    en: {
        details: 'Release and source-package observations', title: 'Observed package sources', intro: 'Agent-visible dpkg metadata only; no proof of host-wide coverage, vendor origin, updates or affected CVEs.',
        access: 'Authenticated LAN operator access is required.', refresh: 'Refresh package observations', loading: 'Reading package observations…',
        loadError: 'Package observations could not be read. Refresh to try again.', invalid: 'The manager returned unsupported or inconsistent package observations. Previous data is not used.', timeout: 'The manager did not respond in time. Refresh package observations.', session: 'Your session has ended. Sign in again.', expired: 'The time anchor is no longer reliable. Refresh before using these observations.', busy: 'The manager is busy. Retry in a moment.',
        not_configured: 'Package-source collection not configured', awaiting: 'Awaiting package observations', fresh: 'Within the collection window', stale: 'Stale / historical package observations', revoked: 'Device identity revoked', unavailable: 'Package observations unavailable',
        notConfiguredNote: 'This device has no package-source profile. Existing profiles are unchanged; this collection requires a fresh managed-operations-v2 store and explicit enrollment consent.',
        healthy: 'Source parsed successfully', unknown: 'Unknown', denied: 'Access denied', releaseTitle: 'Reported release fields', missing: 'Absent field', empty: 'Explicitly empty field',
        debian: 'Exact Debian 13 / Trixie identifiers observed', ubuntu: 'Exact Ubuntu 24.04 / Noble identifiers observed', incomplete: 'Release identifiers incomplete', inconsistent: 'Release identifiers inconsistent', unsupported: 'Release outside the reviewed adapter targets', routing: 'Identifier applicability is not OS authenticity or vulnerability coverage.',
        inventoryTitle: 'Package sample', observed: 'Full-source observed rows', installed: 'Full-source installed rows', selected: 'Selected rows shown', omitted: 'Rows omitted from export', complete: 'Complete declared dpkg row scope', partial: 'Partial exported inventory', truncated: 'Rows truncated by export bounds', bounds: 'Up to 128 rows / 16 KiB shown. Full-source counts include omitted rows and incomplete installations.',
        noRows: 'The successfully parsed source contains zero installed or incomplete rows in this namespace.', noEvidence: 'No package inventory evidence. Empty selected rows do not establish a zero package count.',
        binary: 'Binary package', version: 'Binary version', architecture: 'Architecture', source: 'Source package', sourceVersion: 'Source version', mapping: 'Mapping basis', rowDetails: 'Package details', state: 'Install state', 'source-field': 'Explicit Source field', 'binary-default': 'Absent Source field: binary default', installedState: 'Installed', incompleteState: 'Incomplete',
        checked: 'Manager time', received: 'Received by manager', collected: 'Collected by agent', retention: 'Latest frame stays stored until replaced, even after revocation. Hidden after 24 hours; not deleted by aging.',
        none: 'No source failure reported.', source_missing: 'The source was not available.', permission_denied: 'Permission to read the source was denied.', not_supported: 'The source is not supported.', timeoutReason: 'Source collection timed out.', invalid_source: 'The source did not pass validation.', read_failed: 'The source could not be read.', source_changed: 'The source changed during collection.', item_limit: 'A row limit was reached.', byte_limit: 'A byte limit was reached.', not_implemented: 'Source collection is not implemented.', collector_busy: 'The source collector was busy.',
    },
    de: {
        details: 'Release- und Quellpaket-Beobachtungen', title: 'Beobachtete Paketquellen', intro: 'Nur sichtbare dpkg-Metadaten; kein Beleg für hostweite Abdeckung, Herstellerherkunft, Updates oder betroffene CVEs.',
        access: 'Ein authentifizierter LAN-Operator-Zugang ist erforderlich.', refresh: 'Paketbeobachtungen aktualisieren', loading: 'Paketbeobachtungen werden gelesen…',
        loadError: 'Paketbeobachtungen konnten nicht gelesen werden. Zum Wiederholen aktualisieren.', invalid: 'Der Manager lieferte nicht unterstützte oder widersprüchliche Paketbeobachtungen. Frühere Daten werden nicht verwendet.', timeout: 'Der Manager hat nicht rechtzeitig geantwortet. Paketbeobachtungen aktualisieren.', session: 'Die Sitzung ist beendet. Erneut anmelden.', expired: 'Der Zeitanker ist nicht mehr verlässlich. Vor Nutzung dieser Beobachtungen aktualisieren.', busy: 'Der Manager ist ausgelastet. Gleich erneut versuchen.',
        not_configured: 'Quellpaket-Erfassung nicht eingerichtet', awaiting: 'Paketbeobachtungen ausstehend', fresh: 'Im Erfassungszeitfenster', stale: 'Veraltete / historische Paketbeobachtungen', revoked: 'Geräteidentität widerrufen', unavailable: 'Paketbeobachtungen nicht verfügbar',
        notConfiguredNote: 'Für dieses Gerät ist kein Quellpaket-Profil eingerichtet. Bestehende Profile bleiben unverändert; diese Erfassung benötigt einen neuen managed-operations-v2-Speicher und eine ausdrückliche Enrollment-Zustimmung.',
        healthy: 'Quelle erfolgreich eingelesen', unknown: 'Unbekannt', denied: 'Zugriff verweigert', releaseTitle: 'Gemeldete Release-Felder', missing: 'Feld fehlt', empty: 'Feld ausdrücklich leer',
        debian: 'Exakte Debian-13-/Trixie-Kennungen beobachtet', ubuntu: 'Exakte Ubuntu-24.04-/Noble-Kennungen beobachtet', incomplete: 'Release-Kennungen unvollständig', inconsistent: 'Release-Kennungen widersprüchlich', unsupported: 'Release außerhalb der geprüften Adapter-Ziele', routing: 'Passende Kennungen bestätigen weder die Betriebssystem-Echtheit noch die Schwachstellenabdeckung.',
        inventoryTitle: 'Paketstichprobe', observed: 'Beobachtete Einträge in der gesamten Quelle', installed: 'Installierte Einträge in der gesamten Quelle', selected: 'Angezeigte ausgewählte Einträge', omitted: 'Beim Export ausgelassene Einträge', complete: 'Vollständiger deklarierter dpkg-Eintragsumfang', partial: 'Teilweise exportiertes Inventar', truncated: 'Einträge durch Exportgrenzen gekürzt', bounds: 'Bis zu 128 Zeilen / 16 KiB angezeigt. Quellen-Gesamtzahlen enthalten ausgelassene Zeilen und unvollständige Installationen.',
        noRows: 'Die erfolgreich eingelesene Quelle enthält in diesem Namensraum keine installierten oder unvollständigen Einträge.', noEvidence: 'Keine Paketinventar-Belege. Eine leere Auswahl belegt keine Paketanzahl von null.',
        binary: 'Binärpaket', version: 'Binärversion', architecture: 'Architektur', source: 'Quellpaket', sourceVersion: 'Quellversion', mapping: 'Zuordnungsgrundlage', rowDetails: 'Paketdetails', state: 'Installationszustand', 'source-field': 'Ausdrückliches Source-Feld', 'binary-default': 'Source-Feld fehlt: Binärvorgabe', installedState: 'Installiert', incompleteState: 'Unvollständig',
        checked: 'Managerzeit', received: 'Vom Manager empfangen', collected: 'Vom Agent erfasst', retention: 'Neuester Frame bleibt bis zum Ersetzen gespeichert, auch nach Widerruf. Nach 24 Stunden ausgeblendet; durch Altern nicht gelöscht.',
        none: 'Kein Quellenfehler gemeldet.', source_missing: 'Die Quelle war nicht verfügbar.', permission_denied: 'Die Leseberechtigung für die Quelle wurde verweigert.', not_supported: 'Die Quelle wird nicht unterstützt.', timeoutReason: 'Die Quellenerfassung hat das Zeitlimit überschritten.', invalid_source: 'Die Quelle hat die Validierung nicht bestanden.', read_failed: 'Die Quelle konnte nicht gelesen werden.', source_changed: 'Die Quelle hat sich während der Erfassung verändert.', item_limit: 'Eine Grenze für Einträge wurde erreicht.', byte_limit: 'Eine Byte-Grenze wurde erreicht.', not_implemented: 'Die Quellenerfassung ist nicht implementiert.', collector_busy: 'Der Quellen-Collector war ausgelastet.',
    },
};
type Failure = 'loadError' | 'invalid' | 'timeout' | 'session' | 'expired' | 'busy';
type Anchor = { mono: number; wall: number };
function elapsed(anchor: Anchor): number { return performance.now() - anchor.mono; }
function uncertain(anchor: Anchor): boolean { const delta = elapsed(anchor), wallDelta = Date.now() - anchor.wall; return !Number.isFinite(delta) || delta < 0 || !Number.isFinite(wallDelta) || Math.abs(wallDelta - delta) > 1500; }
function usePackageResource(deviceId: string) {
    const [value, setValue] = useState<PackageView | null>(null), [loading, setLoading] = useState(false), [error, setError] = useState<Failure | null>(null), [, tick] = useState(0);
    const alive = useRef(false), locked = useRef(false), suspended = useRef(false);
    const pending = useRef<{ controller: AbortController; anchor: Anchor; timeout: number } | null>(null), current = useRef<Anchor | null>(null);
    const invalidate = useCallback((failure: Failure | null = null) => {
        pending.current?.controller.abort(); window.clearTimeout(pending.current?.timeout); pending.current = null; current.current = null;
        if (alive.current) { setValue(null); setLoading(false); setError(failure); }
    }, []);
    const load = useCallback(async () => {
        if (!alive.current || locked.current || suspended.current || document.visibilityState === 'hidden') return;
        invalidate(); const controller = new AbortController(), anchor = { mono: performance.now(), wall: Date.now() };
        pending.current = { controller, anchor, timeout: window.setTimeout(() => { if (pending.current?.controller === controller) invalidate('timeout'); }, 10000) }; setLoading(true);
        const active = () => {
            if (!alive.current || locked.current || suspended.current || controller.signal.aborted || pending.current?.controller !== controller) return false;
            if (uncertain(anchor)) { invalidate('expired'); return false; }
            if (elapsed(anchor) >= 10000) { invalidate('timeout'); return false; }
            return true;
        };
        try {
            const next = await request<unknown>(`/devices/${encodeURIComponent(deviceId)}/packages`, { signal: controller.signal }, PACKAGE_RESPONSE_MAX_BYTES);
            if (!active()) return;
            if (!validPackageView(next, deviceId)) { invalidate('invalid'); return; }
            window.clearTimeout(pending.current?.timeout); pending.current = null; current.current = anchor; setValue(next); setLoading(false);
        } catch (caught) {
            if (!active()) return;
            if (caught instanceof APIError && caught.status === 401) locked.current = true;
            invalidate(caught instanceof APIError && caught.status === 401 ? 'session' : caught instanceof APIError && caught.status === 429 ? 'busy' : 'loadError');
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
        window.addEventListener(AUTH_REQUIRED_EVENT, lock); window.addEventListener('pagehide', suspend); window.addEventListener('pageshow', show); window.addEventListener('blur', suspend); window.addEventListener('focus', restore); window.addEventListener('hashchange', navigate); document.addEventListener('visibilitychange', visibility);
        const timer = window.setInterval(() => { const anchor = current.current ?? pending.current?.anchor; if (anchor && uncertain(anchor)) invalidate('expired'); else if (current.current) tick(value => value + 1); }, 1000);
        void load();
        return () => { alive.current = false; invalidate(); window.clearInterval(timer); window.removeEventListener(AUTH_REQUIRED_EVENT, lock); window.removeEventListener('pagehide', suspend); window.removeEventListener('pageshow', show); window.removeEventListener('blur', suspend); window.removeEventListener('focus', restore); window.removeEventListener('hashchange', navigate); document.removeEventListener('visibilitychange', visibility); };
    }, [invalidate, load]);
    return { value, loading, error, load, elapsed: current.current ? elapsed(current.current) : Number.POSITIVE_INFINITY };
}

/** Nothing is fetched or retained until explicitly expanded in the private Security tab. */
export function PackageObservationsPanel({ deviceId, sessionKey }: { deviceId: string; sessionKey?: string | number }) {
    const operator = useOperator(), [locale] = useLocale();
    if (!operator || operator.mode !== 'lan' || !operator.authenticated) return <p>{copy[locale].access}</p>;
    return <PackageDisclosure key={`${deviceId}:${String(sessionKey ?? operator.expiresAt ?? '')}`} deviceId={deviceId}/>;
}
function PackageDisclosure({ deviceId }: { deviceId: string }) {
    const [open, setOpen] = useState(false), [locale] = useLocale(); const id = useId();
    return <section className="package-disclosure"><button className="package-disclosure-toggle" type="button" aria-expanded={open} aria-controls={id} onClick={() => setOpen(value => !value)}>{copy[locale].details}<ChevronDown size={16}/></button><div id={id}>{open && <PackageObservations deviceId={deviceId}/>}</div></section>;
}
function PackageObservations({ deviceId }: { deviceId: string }) {
    const [locale] = useLocale(), labels = copy[locale], id = useId(), resource = usePackageResource(deviceId);
    const view = resource.value, status = view ? effectivePackageStatus(view, resource.elapsed) : null;
    const snapshot = view && packageSnapshotVisible(view, resource.elapsed) ? view.snapshot : null;
    const number = (value: number | null) => value === null ? labels.unknown : new Intl.NumberFormat(locale).format(value);
    const field = (value: string | null) => value === null ? labels.missing : value === '' ? labels.empty : value;
    const reason = (value: NonNullable<typeof snapshot>['release']['reason']) => labels[value === 'timeout' ? 'timeoutReason' : value];
    return <div className="package-observations" aria-labelledby={id} aria-busy={resource.loading}>
        <header className="package-heading"><h3 id={id}>{labels.title}</h3><button className="button small" type="button" disabled={resource.loading || resource.error === 'session'} onClick={() => void resource.load()}><RefreshCw size={14}/>{labels.refresh}</button></header>
        <p className="package-note">{labels.intro}</p>
        {resource.loading && <p role="status"><LoaderCircle size={16} className="spin"/>{labels.loading}</p>}
        {resource.error && <p className="package-error" role="alert"><TriangleAlert size={16}/>{labels[resource.error]}</p>}
        {view && status && <><p className={`package-status package-status-${status}`}>{labels[status]}</p>{status === 'not_configured' && <p>{labels.notConfiguredNote}</p>}
            {snapshot && <>
                <section aria-label={labels.releaseTitle}><h4>{labels.releaseTitle}</h4><p>{labels[snapshot.release.quality]}</p>{snapshot.release.reason !== 'none' && <p>{reason(snapshot.release.reason)}</p>}<dl className="package-facts">{([['ID', 'id'], ['VERSION_ID', 'versionId'], ['VERSION_CODENAME', 'versionCodename']] as const).map(([label, key]) => <div key={key}><dt>{label}</dt><dd>{field(snapshot.release.fields[key])}</dd></div>)}</dl>{snapshot.release.quality === 'healthy' && <p>{labels[releaseApplicability(snapshot.release.fields)]}</p>}<p className="package-note">{labels.routing}</p></section>
                <section aria-label={labels.inventoryTitle}><h4>{labels.inventoryTitle}</h4><p>{labels[snapshot.inventory.quality]}</p>{snapshot.inventory.reason !== 'none' && <p>{reason(snapshot.inventory.reason)}</p>}
                    <dl className="package-counts"><div><dt>{labels.observed}</dt><dd>{number(snapshot.inventory.observedCount)}</dd></div><div><dt>{labels.installed}</dt><dd>{number(snapshot.inventory.installedCount)}</dd></div><div><dt>{labels.selected}</dt><dd>{number(snapshot.inventory.items.length)}</dd></div><div><dt>{labels.omitted}</dt><dd>{number(snapshot.inventory.observedCount === null ? null : snapshot.inventory.observedCount - snapshot.inventory.items.length)}</dd></div></dl>
                    {snapshot.inventory.quality === 'healthy' ? <><p className="package-status">{snapshot.inventory.complete ? labels.complete : labels.partial}</p>{snapshot.inventory.truncated && <p>{labels.truncated}</p>}{snapshot.inventory.observedCount === 0 && <p>{labels.noRows}</p>}</> : <p>{labels.noEvidence}</p>}
                    <p className="package-note">{labels.bounds}</p>
                    {snapshot.inventory.items.length > 0 && <div className="package-table-scroll" role="region" aria-label={labels.inventoryTitle} tabIndex={0}><table><caption className="sr-only">{labels.inventoryTitle}</caption><thead><tr>{[labels.binary, labels.version, labels.architecture, labels.source, labels.sourceVersion, labels.state].map(label => <th key={label} scope="col">{label}</th>)}</tr></thead><tbody>{snapshot.inventory.items.map(row => <tr key={`${row.name}:${row.architecture}`}><th scope="row">{row.name}</th><td>{row.version}</td><td>{row.architecture}</td><td><details className="package-row-details"><summary>{row.sourcePackage}<span className="sr-only"> · {labels.rowDetails}: {row.name} ({row.architecture})</span></summary><dl><dt>{labels.mapping}</dt><dd>{labels[row.sourceMapping]}</dd></dl></details></td><td>{row.sourceVersion}</td><td>{row.installState === 'installed' ? labels.installedState : labels.incompleteState}</td></tr>)}</tbody></table></div>}
                </section>
            </>}
            <dl className="package-facts package-times"><div><dt>{labels.checked}</dt><dd><time dateTime={view.serverNow}>{view.serverNow}</time></dd></div><div><dt>{labels.received}</dt><dd>{view.receivedAt ?? labels.unknown}</dd></div>{snapshot && <div><dt>{labels.collected}</dt><dd><time dateTime={snapshot.collectedAt}>{snapshot.collectedAt}</time></dd></div>}</dl>
        </>}
        <p className="package-note package-retention"><Info size={16}/>{labels.retention}</p>
    </div>;
}
