import { useId, useState } from 'react';
import { WindowsNetworkContextPanel } from './windows-network-context';
import { WindowsAdapterContextPanel } from './windows-adapter-context';
import { useLocale } from './i18n';
import { WindowsNetworkFinder } from './windows-network-finder';
import { initialNetworkFinderControls } from './windows-network-finder-model';
import { fullDate } from './utils';
import type { WindowsInventoryResource } from './windows-inventory-resource';
const copy = {
    en: { title: 'Network', missing: 'Network endpoints are not configured in this report. Separate local consent is required.', unavailable: 'No current network snapshot is available. This does not mean there are no endpoints.', expired: 'The network snapshot expired. Endpoint rows are hidden 24 hours after capture.', observed: 'Enumeration complete within scope', bounded: 'Bounded enumeration', partial: 'Partial enumeration', denied: 'Access denied', unavailableQuality: 'Unavailable', captured: 'Network captured', stale: 'Stale network observation. Values describe the original capture.', retained: 'retained', observedCount: 'observed', atLeast: 'at least', omitted: 'Endpoints omitted by collection or transfer limits.', empty: 'No endpoints returned by the caller-visible tables. This is not a whole-machine coverage claim.', failed: 'No endpoint rows available; this does not establish an empty network.', protocol: 'Protocol', family: 'IP version', local: 'Local endpoint', remote: 'Remote endpoint', state: 'TCP state', pid: 'API owning PID', notApplicable: 'Not applicable', scope: 'Scope & attribution', source: 'Windows IP Helper owner-PID tables: TCP and UDP, IPv4 and IPv6. Numeric addresses and ports only; no DNS, process names, traffic or remote actions.', attribution: 'PID is attribution reported by the API at capture time. It is not a verified executable identity and can be reused. UDP PID 0 means attribution is unavailable. TCP listeners and UDP have no remote peer; UDP has no TCP state. Addresses are sensitive, read-only observations. The base inventory’s 24-hour expiry hides all private sections.' },
    de: { title: 'Netzwerk', missing: 'Netzwerkendpunkte sind in dieser Meldung nicht eingerichtet. Eine separate lokale Zustimmung ist erforderlich.', unavailable: 'Kein aktueller Netzwerksnapshot verfügbar. Dies bedeutet nicht, dass keine Endpunkte existieren.', expired: 'Der Netzwerksnapshot ist abgelaufen. Endpunktzeilen werden 24 Stunden nach Erfassung ausgeblendet.', observed: 'Auflistung im Umfang vollständig', bounded: 'Begrenzte Auflistung', partial: 'Teilweise aufgelistet', denied: 'Zugriff verweigert', unavailableQuality: 'Nicht verfügbar', captured: 'Netzwerk erfasst', stale: 'Veraltete Netzwerkbeobachtung. Werte beschreiben die ursprüngliche Erfassung.', retained: 'gespeichert', observedCount: 'beobachtet', atLeast: 'mindestens', omitted: 'Endpunkte durch Erfassungs- oder Übertragungsgrenzen ausgelassen.', empty: 'Keine Endpunkte aus den für den Aufrufer sichtbaren Tabellen zurückgegeben. Dies belegt keine vollständige Geräteabdeckung.', failed: 'Keine Endpunktzeilen verfügbar; dies belegt kein leeres Netzwerk.', protocol: 'Protokoll', family: 'IP-Version', local: 'Lokaler Endpunkt', remote: 'Entfernter Endpunkt', state: 'TCP-Zustand', pid: 'Besitzende PID laut API', notApplicable: 'Nicht anwendbar', scope: 'Umfang & Zuordnung', source: 'Windows-IP-Helper-Tabellen mit besitzender PID: TCP und UDP, IPv4 und IPv6. Nur numerische Adressen und Ports; keine DNS-Abfragen, Prozessnamen, Verkehrsdaten oder entfernten Aktionen.', attribution: 'Die PID ist die Zuordnung der API zum Erfassungszeitpunkt. Sie ist keine verifizierte Programmidentität und kann wiederverwendet werden. UDP-PID 0 bedeutet, dass die Zuordnung nicht verfügbar ist. Lauschende TCP-Endpunkte und UDP haben keine entfernte Gegenstelle; UDP hat keinen TCP-Zustand. Adressen sind sensible, rein lesende Beobachtungen. Nach Ablauf des Basisinventars nach 24 Stunden werden alle privaten Bereiche ausgeblendet.' },
};
export function WindowsNetworkPanel({ resource, context }: { resource: WindowsInventoryResource; context?: { deviceId: string; sessionKey: string | null; enabled: boolean } }) {
    const [locale] = useLocale(), id = useId(), [source, setSource] = useState<'legacy' | 'route' | 'interface'>('legacy');
    return <>{context && <label className="windows-network-source" htmlFor={id}>{locale === 'de' ? 'Netzwerkquelle' : 'Network source'}<select id={id} value={source} onChange={event => setSource(event.target.value as typeof source)}><option value="legacy">{locale === 'de' ? 'Adapter & Endpunkte' : 'Adapters & endpoints'}</option><option value="route">{locale === 'de' ? 'Routen' : 'Routes'}</option><option value="interface">{locale === 'de' ? 'Rohe Zähler' : 'Raw counters'}</option></select></label>}{source === 'legacy' || !context ? <><WindowsAdapterContextPanel resource={resource}/><WindowsEndpointPanel resource={resource}/></> : <WindowsNetworkContextPanel {...context} kind={source}/>}</>;
}
function WindowsEndpointPanel({ resource }: { resource: WindowsInventoryResource }) {
    const [locale] = useLocale(), c = copy[locale], network = resource.network;
    const scope = network ? JSON.stringify([resource.view?.deviceId, network.grantId, network.generationId, network.collectedAt]) : null;
    const [state, setState] = useState(() => ({ ...initialNetworkFinderControls(), scope }));
    // Preserve a filter only across a reread of the same retained capture.
    // Absence, expiry, errors, suspension and source replacement discard it.
    const reset = scope !== null ? state.scope !== scope : !resource.loading && state.scope !== null;
    const controls = reset ? { ...initialNetworkFinderControls(), scope } : state;
    if (reset) setState(controls);
    if (!network) return <p role="status" className="windows-inventory-empty">{resource.networkExpired ? c.expired : resource.snapshot ? c.missing : c.unavailable}</p>;
    const quality = network.quality === 'unavailable' ? c.unavailableQuality : network.quality === 'observed' && network.truncated ? c.bounded : c[network.quality];
    return <section aria-label={c.title}>
        <div className="windows-inventory-section-header"><h3>{c.title}</h3><span className="windows-inventory-quality">{quality}</span></div>
        <p className="windows-inventory-times">{c.captured} <time dateTime={network.collectedAt}>{fullDate(network.collectedAt)}</time></p>
        {resource.networkStale && <p role="status" className="windows-inventory-caution">{c.stale}</p>}
        {(network.quality === 'observed' || network.quality === 'partial') && <p className="windows-inventory-count">{network.rows.length} {c.retained} · {network.countExact ? '' : `${c.atLeast} `}{network.observedCount} {c.observedCount}</p>}
        {network.truncated && <p className="windows-inventory-caution">{c.omitted}</p>}
        {network.rows.length ? <WindowsNetworkFinder network={network} locale={locale} controls={controls} onChange={value => setState({ ...value, scope: controls.scope })}/> : <p className="windows-inventory-empty">{network.quality === 'observed' && !network.truncated ? c.empty : c.failed}</p>}
        <details className="windows-inventory-scope"><summary>{c.scope}</summary><p>{c.source}</p><p>{c.attribution}</p></details>
    </section>;
}
