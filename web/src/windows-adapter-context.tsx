import { useLocale } from './i18n';
import { fullDate } from './utils';
import type { WindowsAdapterAddresses } from './windows-adapter-context-types';
import type { WindowsInventoryResource } from './windows-inventory-resource';
import './windows-adapter-context.css';

const copy = {
    en: {
        title: 'Adapters', name: 'Adapter', state: 'Link state', tx: 'TX link speed', rx: 'RX link speed', addresses: 'DNS & gateways', dns: 'DNS servers', gateways: 'Gateways', indices: 'Interface indices', captured: 'Adapters captured',
        up: 'Up', down: 'Down', testing: 'Testing', unknown: 'Unknown', dormant: 'Dormant', 'not-present': 'Not present', 'lower-layer-down': 'Lower layer down',
        observed: 'Enumeration complete within scope', bounded: 'Bounded enumeration', partial: 'Partial enumeration', denied: 'Access denied', unavailable: 'Unavailable', unsupported: 'Unsupported',
        shown: 'shown', observedCount: 'observed', atLeast: 'at least', omitted: 'Adapters omitted by collection or transfer limits.', empty: 'No adapters returned within the caller-visible scope.', failed: 'No adapter rows available. This does not establish that adapters are absent.',
        none: 'None configured', partialList: 'Partial list', partialEmpty: 'Partial list; no addresses returned', stale: 'Stale adapter observation. Values describe the original capture.', expired: 'The adapter snapshot expired. Adapter rows are hidden 24 hours after capture.',
        scope: 'About adapter observations', note: 'Link state and directional link speeds are reported by Windows. They do not establish reachability or measured throughput. Configured numeric DNS servers and gateways do not establish a working resolver, preferred route or Internet connection. Interface indices may change. This separate read-only scope performs no DNS lookup or network probe.'
    },
    de: {
        title: 'Adapter', name: 'Adapter', state: 'Verbindungszustand', tx: 'Linkrate (TX)', rx: 'Linkrate (RX)', addresses: 'DNS & Gateways', dns: 'DNS-Server', gateways: 'Gateways', indices: 'Schnittstellenindizes', captured: 'Adapter erfasst',
        up: 'Aktiv', down: 'Inaktiv', testing: 'Testbetrieb', unknown: 'Unbekannt', dormant: 'Ruhend', 'not-present': 'Nicht vorhanden', 'lower-layer-down': 'Untere Schicht inaktiv',
        observed: 'Auflistung im Umfang vollständig', bounded: 'Begrenzte Auflistung', partial: 'Teilweise aufgelistet', denied: 'Zugriff verweigert', unavailable: 'Nicht verfügbar', unsupported: 'Nicht unterstützt',
        shown: 'angezeigt', observedCount: 'beobachtet', atLeast: 'mindestens', omitted: 'Adapter durch Erfassungs- oder Übertragungsgrenzen ausgelassen.', empty: 'Keine Adapter im für den Aufrufer sichtbaren Umfang zurückgegeben.', failed: 'Keine Adapterzeilen verfügbar. Dies belegt nicht, dass keine Adapter vorhanden sind.',
        none: 'Keine konfiguriert', partialList: 'Unvollständige Liste', partialEmpty: 'Unvollständige Liste; keine Adressen zurückgegeben', stale: 'Veraltete Adapterbeobachtung. Werte beschreiben die ursprüngliche Erfassung.', expired: 'Der Adaptersnapshot ist abgelaufen. Adapterzeilen werden 24 Stunden nach Erfassung ausgeblendet.',
        scope: 'Hinweise zu Adapterbeobachtungen', note: 'Verbindungszustand und Geschwindigkeiten je Richtung stammen von Windows. Sie belegen weder Erreichbarkeit noch gemessenen Durchsatz. Konfigurierte numerische DNS-Server und Gateways belegen weder funktionierende Namensauflösung noch bevorzugte Route oder Internetverbindung. Schnittstellenindizes können sich ändern. Dieser separate lesende Umfang führt keine DNS-Abfragen oder Netzwerkprüfungen aus.'
    },
};
function linkSpeed(value: number, locale: 'en' | 'de'): string {
    const scales = [[1e12, 'Tbit/s'], [1e9, 'Gbit/s'], [1e6, 'Mbit/s'], [1e3, 'kbit/s'], [1, 'bit/s']] as const;
    const [scale, unit] = scales.find(([scale]) => value >= scale)!;
    return `${new Intl.NumberFormat(locale, { maximumFractionDigits: 2 }).format(value / scale)} ${unit}`;
}
function AddressList({ label, list, locale }: { label: string; list: WindowsAdapterAddresses; locale: 'en' | 'de' }) {
    const c = copy[locale];
    return <div><dt>{label}</dt><dd>{list.addresses.length ? <>{list.quality === 'partial' && <span className="windows-adapter-list-quality">{c.partialList}</span>}<ul>{list.addresses.map(address => <li key={address}>{address}</li>)}</ul></> : list.quality === 'observed' ? c.none : list.quality === 'partial' ? c.partialEmpty : c.unavailable}</dd></div>;
}
export function WindowsAdapterContextPanel({ resource }: { resource: WindowsInventoryResource }) {
    const [locale] = useLocale(), c = copy[locale], snapshot = resource.adapterContext;
    if (!snapshot) return resource.adapterContextExpired ? <p role="status" className="windows-inventory-empty">{c.expired}</p> : null;
    const quality = snapshot.quality === 'observed' && snapshot.truncated ? c.bounded : c[snapshot.quality];
    const headers = [c.name, c.state, c.tx, c.rx, c.addresses];
    return <section aria-label={c.title} className="windows-adapter-context">
        <div className="windows-inventory-section-header"><h3>{c.title}</h3><span className="windows-inventory-quality">{quality}</span></div>
        <p className="windows-inventory-times">{c.captured} <time dateTime={snapshot.collectedAt}>{fullDate(snapshot.collectedAt)}</time></p>
        {resource.adapterContextStale && <p role="status" className="windows-inventory-caution">{c.stale}</p>}
        {(snapshot.quality === 'observed' || snapshot.quality === 'partial') && <p className="windows-inventory-count">{snapshot.rows.length} {c.shown} · {snapshot.countExact ? '' : `${c.atLeast} `}{snapshot.observedCount} {c.observedCount}</p>}
        {snapshot.truncated && <p className="windows-inventory-caution">{c.omitted}</p>}
        {snapshot.rows.length ? <div className="windows-inventory-table-wrap"><table className="windows-inventory-table windows-adapter-table"><caption className="sr-only">{c.title}</caption><thead><tr>{headers.map(header => <th scope="col" key={header}>{header}</th>)}</tr></thead><tbody>{snapshot.rows.map(row => <tr key={`${row.ifIndex}:${row.ipv6IfIndex}`}>
            <td data-label={c.name}>{row.name}</td><td data-label={c.state}>{c[row.state]}</td>
            <td data-label={c.tx}>{row.txQuality === 'observed' && row.txLinkBps !== null ? <span title={`${row.txLinkBps} bit/s`}>{linkSpeed(row.txLinkBps, locale)}</span> : c[row.txQuality === 'unknown' ? 'unknown' : 'unavailable']}</td>
            <td data-label={c.rx}>{row.rxQuality === 'observed' && row.rxLinkBps !== null ? <span title={`${row.rxLinkBps} bit/s`}>{linkSpeed(row.rxLinkBps, locale)}</span> : c[row.rxQuality === 'unknown' ? 'unknown' : 'unavailable']}</td>
            <td data-label={c.addresses}><details className="windows-adapter-addresses" key={`${snapshot.generationId}:${snapshot.collectedAt}`}><summary>{c.addresses}</summary><dl><AddressList label={c.dns} list={row.dnsServers} locale={locale}/><AddressList label={c.gateways} list={row.gateways} locale={locale}/><div><dt>{c.indices}</dt><dd>IPv4: {row.ifIndex} · IPv6: {row.ipv6IfIndex}</dd></div></dl></details></td>
        </tr>)}</tbody></table></div> : <p className="windows-inventory-empty">{snapshot.quality === 'observed' && !snapshot.truncated ? c.empty : c.failed}</p>}
        <details className="windows-inventory-scope"><summary>{c.scope}</summary><p>{c.note}</p></details>
    </section>;
}
