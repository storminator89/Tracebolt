import { useId } from 'react';
import { Info, LoaderCircle, RefreshCw, TriangleAlert } from 'lucide-react';
import { useLocale } from './i18n';
import { endpointAgeStatus } from './endpoint-identity-types';
import type { EndpointAddresses, EndpointReason } from './endpoint-identity-types';
import type { EndpointIdentityResource } from './endpoint-identity-resource';
import './endpoint-identity.css';

const copy = {
    en: {
        title: 'Hostname & interface addresses', refresh: 'Refresh reported identity', loading: 'Reading reported identity…', recovering: 'Storage is busy. One automatic read retry in 2 seconds.',
        intro: 'Reported from local Linux sources in the agent-visible namespaces. These display values are untrusted observations, not proof of identity or reachability.',
        permission: 'Collection is off by default and requires a protected, identity-bound acknowledgement by a local administrator. The manager cannot remotely verify whether local collection is currently enabled or disabled.',
        source: 'Sources: local uname hostname, bounded procfs interface/IPv6 reads and read-only IPv4/interface ioctls. No socket-peer inference, DNS lookup or network scan.',
        fresh: 'Recent observation', stale: 'Stale / historical observation', expired: 'Observation or device identity expired', revoked: 'Device identity revoked', unknown: 'Observation unavailable or identity not eligible', not_collected: 'No accepted hostname or interface observation',
        hidden: 'No hostname or address values are shown in this state.', staleHint: 'These are historical values. A later report without this extension does not refresh them or prove that they are still assigned.',
        hostname: 'Locally reported hostname', hostnameHint: 'Display name only; it may differ from the stable device identity and need not be unique or resolvable.',
        interfaces: 'Observed interfaces', complete: 'Complete enumeration in the visible namespace', partial: 'Partial address coverage', failed: 'Collection failed', emptyInterfaces: 'The successful interface enumeration contained no rows.',
        name: 'Interface', flags: 'Observed flags', up: 'Up', down: 'Down', loopback: 'Loopback', nonLoopback: 'Not loopback', index: 'Index', hardware: 'Hardware kind unknown',
        flagHint: 'Up/down and loopback are interface flags, not connectivity tests. Interface names do not identify physical, virtual, bridge or VPN hardware.',
        emptyAddresses: 'Complete: no assigned addresses observed for this family.', completeFamily: 'Complete family enumeration',
        unspecified: 'Unspecified', 'link-local': 'Link-local', multicast: 'Multicast', private: 'Private range', other: 'Other range',
        scopeHint: 'Addresses retain their assigned host bits. Range labels describe the numeric address only; “other” does not mean public or reachable. Link-local addresses belong to the interface shown. There is no inferred primary IP.',
        collected: 'Original collection time', received: 'Original receipt time', expires: 'Retention ends', sequence: 'Original sequence', generation: 'Original generation', retention: 'Values expire 24 hours after their original collection. Local disable does not confirm remote deletion of already delivered values.',
        loadError: 'The manager could not be read. Refresh to try again.', invalid: 'The manager returned inconsistent or unsupported identity data. Values were cleared.', timeout: 'The request timed out. Refresh to try again.', session: 'Your session has ended. Sign in again.', clock: 'The time anchor is no longer reliable. Refresh before continuing.', busy: 'The manager is busy. Retry in a moment.',
        none: 'No failure reported', source_missing: 'Source unavailable', permission_denied: 'Permission denied', not_supported: 'Not supported', collectionTimeout: 'Collection timed out', invalid_source: 'Invalid source', read_failed: 'Read failed', item_limit: 'Row rejection limit reached', byte_limit: 'Byte rejection limit reached', collector_busy: 'Collector busy', notCollectedReason: 'Not collected', address_unavailable: 'One or more address families could not be read',
    },
    de: {
        title: 'Hostname & Schnittstellen-Adressen', refresh: 'Gemeldete Identität aktualisieren', loading: 'Gemeldete Identität wird gelesen…', recovering: 'Der Speicher ist ausgelastet. Ein automatischer Leseversuch folgt in 2 Sekunden.',
        intro: 'Aus lokalen Linux-Quellen in den für den Agent sichtbaren Namensräumen gemeldet. Diese Anzeigewerte sind unvertraute Beobachtungen und kein Nachweis für Identität oder Erreichbarkeit.',
        permission: 'Die Erfassung ist standardmäßig aus und erfordert eine geschützte, identitätsgebundene Bestätigung durch einen lokalen Administrator. Der Manager kann nicht aus der Ferne bestätigen, ob die lokale Erfassung gerade aktiviert oder deaktiviert ist.',
        source: 'Quellen: lokaler uname-Hostname, begrenzte procfs-Lesezugriffe für Schnittstellen/IPv6 und lesende IPv4-/Schnittstellen-ioctls. Keine Ableitung aus Socket-Gegenstellen, DNS-Abfrage oder Netzwerkscan.',
        fresh: 'Aktuelle Beobachtung', stale: 'Veraltete / historische Beobachtung', expired: 'Beobachtung oder Geräteidentität abgelaufen', revoked: 'Geräteidentität widerrufen', unknown: 'Beobachtung nicht verfügbar oder Identität nicht berechtigt', not_collected: 'Keine akzeptierte Hostname- oder Schnittstellen-Beobachtung',
        hidden: 'In diesem Zustand werden keine Hostnamen oder Adressen angezeigt.', staleHint: 'Dies sind historische Werte. Ein späterer Bericht ohne diese Erweiterung aktualisiert sie nicht und belegt nicht, dass die Adressen noch zugewiesen sind.',
        hostname: 'Lokal gemeldeter Hostname', hostnameHint: 'Nur ein Anzeigename; er kann von der stabilen Geräteidentität abweichen und muss weder eindeutig noch auflösbar sein.',
        interfaces: 'Beobachtete Schnittstellen', complete: 'Vollständige Aufzählung im sichtbaren Namensraum', partial: 'Teilweise Adressabdeckung', failed: 'Erfassung fehlgeschlagen', emptyInterfaces: 'Die erfolgreiche Schnittstellen-Aufzählung enthielt keine Zeilen.',
        name: 'Schnittstelle', flags: 'Beobachtete Flags', up: 'Up', down: 'Down', loopback: 'Loopback', nonLoopback: 'Kein Loopback', index: 'Index', hardware: 'Hardware-Art unbekannt',
        flagHint: 'Up/Down und Loopback sind Schnittstellen-Flags und keine Verbindungstests. Schnittstellennamen belegen keine physische, virtuelle, Bridge- oder VPN-Hardware.',
        emptyAddresses: 'Vollständig: keine zugewiesenen Adressen für diese Familie beobachtet.', completeFamily: 'Vollständige Aufzählung dieser Familie',
        unspecified: 'Unbestimmt', 'link-local': 'Link-lokal', multicast: 'Multicast', private: 'Privater Bereich', other: 'Anderer Bereich',
        scopeHint: 'Adressen behalten ihre zugewiesenen Host-Bits. Bereichsangaben beschreiben nur die numerische Adresse; „anderer Bereich“ bedeutet weder öffentlich noch erreichbar. Link-lokale Adressen gehören zur angezeigten Schnittstelle. Es wird keine primäre IP abgeleitet.',
        collected: 'Ursprünglicher Erfassungszeitpunkt', received: 'Ursprünglicher Empfangszeitpunkt', expires: 'Aufbewahrung endet', sequence: 'Ursprüngliche Sequenz', generation: 'Ursprüngliche Generation', retention: 'Werte laufen 24 Stunden nach ihrer ursprünglichen Erfassung ab. Lokales Deaktivieren bestätigt keine entfernte Löschung bereits übertragener Werte.',
        loadError: 'Der Manager konnte nicht gelesen werden. Zum Wiederholen aktualisieren.', invalid: 'Der Manager hat widersprüchliche oder nicht unterstützte Identitätsdaten geliefert. Werte wurden entfernt.', timeout: 'Die Anfrage hat das Zeitlimit überschritten. Zum Wiederholen aktualisieren.', session: 'Die Sitzung ist beendet. Bitte erneut anmelden.', clock: 'Der Zeitanker ist nicht mehr verlässlich. Vor dem Fortsetzen aktualisieren.', busy: 'Der Manager ist ausgelastet. Gleich erneut versuchen.',
        none: 'Kein Fehler gemeldet', source_missing: 'Quelle nicht verfügbar', permission_denied: 'Berechtigung verweigert', not_supported: 'Nicht unterstützt', collectionTimeout: 'Erfassung hat Zeitlimit überschritten', invalid_source: 'Ungültige Quelle', read_failed: 'Lesen fehlgeschlagen', item_limit: 'Ablehnungsgrenze für Zeilen erreicht', byte_limit: 'Ablehnungsgrenze für Bytes erreicht', collector_busy: 'Collector ausgelastet', notCollectedReason: 'Nicht erfasst', address_unavailable: 'Eine oder mehrere Adressfamilien konnten nicht gelesen werden',
    },
};
export function EndpointHostnameStatus({ resource }: { resource: EndpointIdentityResource }) {
    const [locale] = useLocale(), labels = copy[locale];
    if (!resource.snapshot?.reportedHostname.value || !resource.view) return null;
    return <p className="endpoint-heading-source">{labels.hostname} · {labels[endpointAgeStatus(resource.view, resource.elapsed)]}</p>;
}
export function EndpointIdentityPanel({ resource }: { resource: EndpointIdentityResource }) {
    const [locale] = useLocale(), labels = copy[locale], id = useId(), { view, snapshot } = resource;
    const reason = (r: EndpointReason) => labels[r === 'timeout' ? 'collectionTimeout' : r === 'not_collected' ? 'notCollectedReason' : r];
    const status = view ? endpointAgeStatus(view, resource.elapsed) : null;
    const family = (section: EndpointAddresses, label: string) => <section className="endpoint-family" aria-label={label}><h5>{label}</h5>{section.meta.coverage === 'failed' ? <p className="endpoint-failure">{labels.failed}: {reason(section.meta.reason)}</p> : <><p className="endpoint-family-status">{section.items.length ? `${labels.completeFamily} · ${section.items.length}` : labels.emptyAddresses}</p>{section.items.length > 0 && <ul>{section.items.map(address => <li key={address.address}><span className="mono">{address.address}</span><span className="endpoint-scope">{labels[address.scope]}</span></li>)}</ul>}</>}</section>;
    const field = (label: string, value: string | null) => value && <div><dt>{label}</dt><dd>{value}</dd></div>;
    return <section className="detail-section endpoint-identity" aria-labelledby={id} aria-busy={resource.loading}>
        <header className="endpoint-heading"><h2 id={id}>{labels.title}</h2><button className="button small" disabled={resource.loading || resource.error === 'session'} onClick={resource.refresh}><RefreshCw size={14}/>{labels.refresh}</button></header>
        <p className="endpoint-note">{labels.intro}</p>
        {resource.loading && <p role="status"><LoaderCircle size={16} className="spin"/>{resource.recovering ? labels.recovering : labels.loading}</p>}
        {resource.error && <p className="endpoint-failure" role="alert"><TriangleAlert size={16}/>{labels[resource.error]}</p>}
        {status && <p className={`endpoint-status endpoint-status-${status}`}>{labels[status]}</p>}
        {view && !snapshot && <p>{labels.hidden}</p>}
        {(status === 'not_collected' || status === 'unknown') && <p className="endpoint-note">{labels.permission}</p>}
        {snapshot && <>
            {status === 'stale' && <p className="endpoint-note">{labels.staleHint}</p>}
            <div className="endpoint-hostname"><h3>{labels.hostname}</h3>{snapshot.reportedHostname.coverage === 'complete' ? <p className="endpoint-hostname-value mono">{snapshot.reportedHostname.value}</p> : <p className="endpoint-failure">{labels.failed}: {reason(snapshot.reportedHostname.reason)}</p>}<p className="endpoint-note">{labels.hostnameHint}</p></div>
            <div className="endpoint-interfaces-heading"><h3>{labels.interfaces}{snapshot.interfaces.meta.countExact && <> · {snapshot.interfaces.meta.observedCount}</>}</h3><p className={snapshot.interfaces.meta.coverage === 'complete' ? 'endpoint-note' : 'endpoint-failure'}>{labels[snapshot.interfaces.meta.coverage]}{snapshot.interfaces.meta.reason !== 'none' && <>: {reason(snapshot.interfaces.meta.reason)}</>}</p></div>
            {snapshot.interfaces.meta.coverage === 'complete' && snapshot.interfaces.items.length === 0 && <p>{labels.emptyInterfaces}</p>}
            <div className="endpoint-interfaces">{snapshot.interfaces.items.map(row => <article key={row.index} className="endpoint-interface" aria-label={`${labels.name} ${row.name}`}><header><h4><span className="mono">{row.name}</span><span>{labels.index} {row.index}</span></h4><p>{labels.flags}: {row.up ? labels.up : labels.down} · {row.loopback ? labels.loopback : labels.nonLoopback}</p><p className="endpoint-note">{labels.hardware}</p></header><div className="endpoint-families">{family(row.addresses.ipv4, 'IPv4')}{family(row.addresses.ipv6, 'IPv6')}</div></article>)}</div>
            <p className="endpoint-note">{labels.flagHint}</p><p className="endpoint-note">{labels.scopeHint}</p>
            <dl className="endpoint-facts">{field(labels.collected, snapshot.collectedAt)}{field(labels.received, view!.receivedAt)}{field(labels.expires, view!.expiresAt)}{field(labels.sequence, view!.sequence)}{field(labels.generation, snapshot.generationId)}</dl>
        </>}
        <details className="endpoint-source"><summary><Info size={14}/>{locale === 'de' ? 'Quelle, Freigabe & Aufbewahrung' : 'Source, permission & retention'}</summary><p>{labels.source}</p>{status !== 'not_collected' && status !== 'unknown' && <p>{labels.permission}</p>}<p>{labels.retention}</p></details>
    </section>;
}
