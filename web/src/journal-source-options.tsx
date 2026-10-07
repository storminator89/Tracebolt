import { useId } from 'react';
import { useLocale } from './i18n';
import type { JournalView } from './journal-types';
import { journalServiceLabel, journalSourceAccess, journalReportedAccess } from './journal-sources';
import './journal-source-options.css';

const copy = {
    en: {
        title: 'Log sources', grant: 'Last reported local permission', all: 'All current and future system services', exact: 'Exact service allowlist', enabled: 'Policy enabled', policyDisabled: 'Policy disabled', reportedAt: 'Reported at', fresh: 'Within the five-minute report window', stale: 'Historical report. Current permission is unknown; refresh after the endpoint reports again.', unknownScope: 'The endpoint has not reported a service permission summary. Current permission is unknown.', bounded: 'Every capture still selects one exact service and a bounded time window. The endpoint rechecks its current local policy before reading and delivery.', reported_allowed: 'Included in the last reported local grant.', reported_disabled: 'The latest policy report says local journal access is disabled.', outside_reported_scope: 'This service is outside the last reported exact allowlist. An administrator must approve a local policy change.', services: 'Service logs', supported: 'Supported with local permission',
        serviceHint: 'One exact service per capture, with local permission.',
        kernel: 'Kernel & hardware', system: 'Whole system journal', auth: 'System-wide authentication', unsupported: 'Not supported by this collector',
        kernelHint: 'Kernel, driver and hardware events need a separate kernel scope.',
        systemHint: 'System-wide events need a separate, broader content scope. The journal daemon’s own service logs are not the whole journal.',
        authHint: 'SSH service logs cover that service only. Authentication across sudo, PAM and other services needs a separate scope.',
        expansion: 'Broader sources need endpoint support and a separate local administrator grant; they cannot be enabled here.',
        selection: 'Selected service', access: 'Local log access', unknown: 'Permission not verified. The endpoint checks its current allowlist and query limits for every capture.',
        not_configured: 'This device is not eligible for the separate journal extension.',
        denied: 'The last request for this service was denied. An administrator must check its local permission and query limits; choosing the service does not grant access.',
        disabled: 'The last request for this service reported that local journal access is disabled.',
        helper_unavailable: 'The last request for this service could not obtain a result from the local journal helper.',
    },
    de: {
        title: 'Log-Quellen', grant: 'Zuletzt gemeldete lokale Freigabe', all: 'Alle aktuellen und zukünftigen Systemdienste', exact: 'Exakte Dienst-Freigabeliste', enabled: 'Richtlinie aktiviert', policyDisabled: 'Richtlinie deaktiviert', reportedAt: 'Gemeldet am', fresh: 'Innerhalb des fünfminütigen Meldefensters', stale: 'Historische Meldung. Die aktuelle Freigabe ist unbekannt; nach einer neuen Endpunktmeldung aktualisieren.', unknownScope: 'Der Endpunkt hat keinen Dienst-Freigabeumfang gemeldet. Die aktuelle Freigabe ist unbekannt.', bounded: 'Jede Erfassung wählt weiterhin genau einen Dienst und ein begrenztes Zeitfenster. Der Endpunkt prüft seine aktuelle lokale Richtlinie vor dem Lesen und Übermitteln erneut.', reported_allowed: 'In der zuletzt gemeldeten lokalen Freigabe enthalten.', reported_disabled: 'Die neueste Richtlinienmeldung meldet deaktivierten lokalen Journal-Zugriff.', outside_reported_scope: 'Dieser Dienst liegt außerhalb der zuletzt gemeldeten exakten Freigabeliste. Ein Administrator muss eine lokale Richtlinienänderung freigeben.', services: 'Dienst-Logs', supported: 'Mit lokaler Freigabe unterstützt',
        serviceHint: 'Genau ein Dienst pro Erfassung, mit lokaler Freigabe.',
        kernel: 'Kernel & Hardware', system: 'Gesamtes Systemjournal', auth: 'Systemweite Authentifizierung', unsupported: 'Von diesem Collector nicht unterstützt',
        kernelHint: 'Kernel-, Treiber- und Hardware-Ereignisse benötigen einen eigenen Kernel-Umfang.',
        systemHint: 'Systemweite Ereignisse benötigen einen eigenen, erweiterten Inhaltsumfang. Die Logs des Journal-Dienstes sind nicht das gesamte Journal.',
        authHint: 'SSH-Dienst-Logs decken nur diesen Dienst ab. Authentifizierung über sudo, PAM und weitere Dienste benötigt einen eigenen Umfang.',
        expansion: 'Erweiterte Quellen brauchen Endpunkt-Unterstützung und eine eigene lokale Administratorfreigabe; hier nicht aktivierbar.',
        selection: 'Ausgewählter Dienst', access: 'Lokaler Log-Zugriff', unknown: 'Freigabe nicht verifiziert. Der Endpunkt prüft bei jeder Erfassung die aktuelle Freigabeliste und Anfragegrenzen.',
        not_configured: 'Dieses Gerät ist für die separate Journal-Erweiterung nicht berechtigt.',
        denied: 'Die letzte Anfrage für diesen Dienst wurde verweigert. Ein Administrator muss die lokale Freigabe und Anfragegrenzen prüfen; die Auswahl gewährt keinen Zugriff.',
        disabled: 'Die letzte Anfrage für diesen Dienst meldete deaktivierten lokalen Journal-Zugriff.',
        helper_unavailable: 'Die letzte Anfrage für diesen Dienst konnte kein Ergebnis vom lokalen Journal-Helper erhalten.',
    },
};

/** No requests, grants or collector options originate in this view. */
export function JournalSourceOptions({ view = null }: { view?: JournalView | null }) {
    const [locale] = useLocale(), c = copy[locale], id = useId();
    return <section className="journal-source-options" aria-labelledby={id}>
        <h3 id={id}>{c.title}</h3>
        <JournalReportedPermission view={view}/>
        <p><strong>{c.services}:</strong> {c.serviceHint}</p>
        <p className="journal-warning">{c.unsupported}: <span>{c.kernel}</span>, <span>{c.system}</span>, <span>{c.auth}</span>.</p><p>{locale === 'de' ? 'Logs des Journal-Dienstes sind nicht das gesamte Journal; SSH-Logs zeigen nur SSH.' : 'Journal-daemon logs are not the whole journal; SSH logs cover SSH only.'} {c.expansion}</p>
    </section>;
}

export function JournalSelectedSource({ unit, view }: { unit: string; view: JournalView | null }) {
    const [locale] = useLocale(), c = copy[locale], historical = journalSourceAccess(view, unit), reported = journalReportedAccess(view, unit), access = reported === 'unknown' ? historical : reported, label = journalServiceLabel(unit, locale);
    if (!unit) return null;
    return <div className="journal-source-selection"><p><strong>{c.selection}:</strong> {label && <>{label} · </>}<span>{unit}</span></p><p className={access === 'unknown' ? 'journal-muted' : 'journal-warning'}><strong>{c.access}:</strong> {c[access]}</p></div>;
}

export function JournalReportedPermission({ view }: { view: JournalView | null }) {
    const [locale] = useLocale(), c = copy[locale], generation = view?.generation;
    const known = generation?.schemaVersion === 'tracebolt.journal-generation-view.v2';
    const status = !known ? (locale === 'de' ? 'Unbekannt' : 'Unknown') : !generation.fresh ? (locale === 'de' ? 'Veraltet · aktuelle Freigabe unbekannt' : 'Stale · current permission unknown') : generation.policyEnabled ? (locale === 'de' ? 'Aktuell gemeldet' : 'Fresh report') : c.policyDisabled;
    return <div className="journal-reported-permission">
        <p className={known && (!generation.fresh || !generation.policyEnabled) ? 'journal-warning' : undefined}><strong>{c.grant}:</strong> {known && <>{generation.serviceAuthorization === 'all-system-services' ? c.all : c.exact} · </>}{status}</p>
        <details><summary>{locale === 'de' ? 'Freigabedetails' : 'Permission details'}</summary>
            {!known ? <p>{c.unknownScope}</p> : <>
                {generation.serviceAuthorization === 'exact-units' && <ul>{generation.allowedUnits?.map(unit => <li key={unit}>{unit}</li>)}</ul>}
                <p>{c.reportedAt}: <time dateTime={generation.observedAt}>{generation.observedAt}</time></p>
                {!generation.fresh && <p>{c.stale}</p>}
            </>}
            <p className="journal-muted">{c.bounded}</p>
        </details>
    </div>;
}

/** Compact display only. The unchanged query and generation gates own admission. */
export function JournalPermissionSummary({ unit, view }: { unit: string; view: JournalView | null }) {
    const [locale] = useLocale(), generation = view?.generation;
    const historical = journalSourceAccess(view, unit), reported = journalReportedAccess(view, unit);
    const known = generation?.schemaVersion === 'tracebolt.journal-generation-view.v2';
    const access = !unit && known && generation.fresh ? generation.policyEnabled ? 'reported_scope' : 'reported_disabled' : reported === 'unknown' ? historical : reported;
    const stale = Boolean(generation && !generation.fresh);
    const label = stale ? (locale === 'de' ? 'Freigabemeldung veraltet · Zugriff unbekannt' : 'Policy report stale · permission unknown') : ({
        reported_scope: locale === 'de' ? (known && generation.serviceAuthorization === 'all-system-services' ? 'Alle Dienst-Units · gemeldete Freigabe' : 'Exakte Dienstfreigabe gemeldet') : (known && generation.serviceAuthorization === 'all-system-services' ? 'All service units · reported grant' : 'Exact service grant reported'),
        unknown: locale === 'de' ? 'Freigabe nicht verifiziert' : 'Permission not verified',
        not_configured: locale === 'de' ? 'Nicht eingerichtet' : 'Not configured',
        denied: locale === 'de' ? 'Zugriff verweigert' : 'Access denied',
        disabled: locale === 'de' ? 'Lokaler Zugriff deaktiviert' : 'Local access disabled',
        helper_unavailable: locale === 'de' ? 'Log-Helper nicht verfügbar' : 'Log helper unavailable',
        reported_allowed: locale === 'de' ? 'Lokal freigegeben laut Meldung' : 'Included in reported grant',
        reported_disabled: locale === 'de' ? 'Lokale Richtlinie deaktiviert' : 'Local policy disabled',
        outside_reported_scope: locale === 'de' ? 'Außerhalb der gemeldeten Freigabe' : 'Outside reported grant',
    })[access];
    return <p className={`journal-permission-summary ${stale || !['unknown', 'reported_allowed', 'reported_scope'].includes(access) ? 'journal-warning' : 'journal-muted'}`}>{label}</p>;
}
