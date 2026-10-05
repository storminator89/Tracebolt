import { useId } from 'react';
import { useLocale } from './i18n';
import type { JournalView } from './journal-types';
import { journalServiceLabel, journalSourceAccess } from './journal-sources';
import './journal-source-options.css';

const copy = {
    en: {
        title: 'Log sources', services: 'Service logs', supported: 'Supported with local permission',
        serviceHint: 'Find SSH, containers, networking, scheduled jobs or another observed service below. Each capture reads one exact service.',
        kernel: 'Kernel & hardware', system: 'Whole system journal', auth: 'System-wide authentication', unsupported: 'Not supported by this collector',
        kernelHint: 'Kernel, driver and hardware events need a separate kernel scope.',
        systemHint: 'System-wide events need a separate, broader content scope. The journal daemon’s own service logs are not the whole journal.',
        authHint: 'SSH service logs cover that service only. Authentication across sudo, PAM and other services needs a separate scope.',
        expansion: 'These broader sources cannot be enabled here. They require compatible endpoint support and a separate local administrator grant.',
        selection: 'Selected service', access: 'Local log access', unknown: 'Permission not verified. The endpoint checks its current allowlist and query limits for every capture.',
        not_configured: 'This device is not eligible for the separate journal extension.',
        denied: 'The last request for this service was denied. An administrator must check its local permission and query limits; choosing the service does not grant access.',
        disabled: 'The last request for this service reported that local journal access is disabled.',
        helper_unavailable: 'The last request for this service could not obtain a result from the local journal helper.',
    },
    de: {
        title: 'Log-Quellen', services: 'Dienst-Logs', supported: 'Mit lokaler Freigabe unterstützt',
        serviceHint: 'Unten SSH, Container, Netzwerk, geplante Aufgaben oder einen anderen beobachteten Dienst finden. Jede Erfassung liest genau einen Dienst.',
        kernel: 'Kernel & Hardware', system: 'Gesamtes Systemjournal', auth: 'Systemweite Authentifizierung', unsupported: 'Von diesem Collector nicht unterstützt',
        kernelHint: 'Kernel-, Treiber- und Hardware-Ereignisse benötigen einen eigenen Kernel-Umfang.',
        systemHint: 'Systemweite Ereignisse benötigen einen eigenen, erweiterten Inhaltsumfang. Die Logs des Journal-Dienstes sind nicht das gesamte Journal.',
        authHint: 'SSH-Dienst-Logs decken nur diesen Dienst ab. Authentifizierung über sudo, PAM und weitere Dienste benötigt einen eigenen Umfang.',
        expansion: 'Diese erweiterten Quellen lassen sich hier nicht aktivieren. Sie benötigen kompatible Endpunkt-Unterstützung und eine separate lokale Administratorfreigabe.',
        selection: 'Ausgewählter Dienst', access: 'Lokaler Log-Zugriff', unknown: 'Freigabe nicht verifiziert. Der Endpunkt prüft bei jeder Erfassung die aktuelle Freigabeliste und Anfragegrenzen.',
        not_configured: 'Dieses Gerät ist für die separate Journal-Erweiterung nicht berechtigt.',
        denied: 'Die letzte Anfrage für diesen Dienst wurde verweigert. Ein Administrator muss die lokale Freigabe und Anfragegrenzen prüfen; die Auswahl gewährt keinen Zugriff.',
        disabled: 'Die letzte Anfrage für diesen Dienst meldete deaktivierten lokalen Journal-Zugriff.',
        helper_unavailable: 'Die letzte Anfrage für diesen Dienst konnte kein Ergebnis vom lokalen Journal-Helper erhalten.',
    },
};

/** No requests, grants or collector options originate in this view. */
export function JournalSourceOptions() {
    const [locale] = useLocale(), c = copy[locale], id = useId();
    return <section className="journal-source-options" aria-labelledby={id}>
        <h3 id={id}>{c.title}</h3>
        <div className="journal-source-current"><strong>{c.services}</strong><span>{c.supported}</span><p>{c.serviceHint}</p></div>
        <details><summary>{locale === 'de' ? 'Weitere Linux-Log-Quellen' : 'Other Linux log sources'}</summary>
            <div className="journal-source-unavailable">{(['kernel', 'system', 'auth'] as const).map(source => <div key={source}>
                <strong>{c[source]}</strong><span>{c.unsupported}</span><p>{c[`${source}Hint`]}</p>
            </div>)}</div><p>{c.expansion}</p>
        </details>
    </section>;
}

export function JournalSelectedSource({ unit, view }: { unit: string; view: JournalView | null }) {
    const [locale] = useLocale(), c = copy[locale], access = journalSourceAccess(view, unit), label = journalServiceLabel(unit, locale);
    if (!unit) return null;
    return <div className="journal-source-selection"><p><strong>{c.selection}:</strong> {label && <>{label} · </>}<span>{unit}</span></p><p className={access === 'unknown' ? 'journal-muted' : 'journal-warning'}><strong>{c.access}:</strong> {c[access]}</p></div>;
}
