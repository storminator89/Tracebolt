import { useState } from 'react';
import { FleetCopyValue } from './fleet-copy';
import { ChevronDown, RefreshCw } from 'lucide-react';
import { useLocale } from './i18n';
import { fullDate } from './utils';
import type { EndpointReason } from './endpoint-identity-types';
import type { FleetIdentityDisplay } from './fleet-identity-types';
import type { FleetIdentityResource } from './fleet-identity-resource';
import './fleet-identity.css';

const copy = {
    de: { title: 'Hostname & IP-Adressen', source: 'Vom Gerät gemeldet', unknown: 'Unbekannt', hostname: 'Hostname nicht verfügbar', ips: 'IP-Adressen nicht verfügbar', empty: 'Keine IP-Adressen gemeldet', partial: 'Teilweise erfasst', fresh: 'Aktuell', stale: 'Veraltet', expired: 'Abgelaufen', revoked: 'Widerrufen', not_collected: 'Nicht erfasst', loading: 'Hostname und IP-Adressen werden geladen …', loadError: 'Hostname und IP-Adressen konnten nicht geladen werden.', invalid: 'Ungültige Identitätsdaten wurden ausgeblendet.', timeout: 'Das Laden der Identitätsdaten hat zu lange gedauert.', session: 'Sitzung beendet. Bitte erneut anmelden.', clock: 'Zeitprüfung fehlgeschlagen. Bitte aktualisieren.', busy: 'Identitätsdaten sind vorübergehend nicht verfügbar.', refresh: 'Hostname und IP-Adressen aktualisieren', more: 'weitere', observed: 'Erfasst', down: 'inaktiv', scope: 'Gemeldete Schnittstellenadressen; keine primäre IP oder Erreichbarkeit abgeleitet.' },
    en: { title: 'Hostname & IP addresses', source: 'Reported by device', unknown: 'Unknown', hostname: 'Hostname unavailable', ips: 'IP addresses unavailable', empty: 'No IP addresses reported', partial: 'Partially collected', fresh: 'Recent', stale: 'Stale', expired: 'Expired', revoked: 'Revoked', not_collected: 'Not collected', loading: 'Loading hostnames and IP addresses …', loadError: 'Hostnames and IP addresses could not be loaded.', invalid: 'Invalid identity data was hidden.', timeout: 'Loading identity data timed out.', session: 'Session ended. Please sign in again.', clock: 'Time check failed. Please refresh.', busy: 'Identity data is temporarily unavailable.', refresh: 'Refresh hostnames and IP addresses', more: 'more', observed: 'Collected', down: 'down', scope: 'Reported interface addresses; no primary IP or reachability inferred.' },
};
export function FleetIdentityName({ identity, deviceId, group }: { identity?: FleetIdentityDisplay; deviceId: string; group?: string }) {
    const [locale] = useLocale(), c = copy[locale], [expanded, setExpanded] = useState(false);
    const reason = (value: EndpointReason | null | undefined) => !value || value === 'none' ? '' : value === 'permission_denied' ? locale === 'de' ? 'Zugriff verweigert' : 'Permission denied' : value === 'not_collected' ? c.not_collected : value === 'not_supported' ? locale === 'de' ? 'Nicht unterstützt' : 'Not supported' : locale === 'de' ? 'Erfassung fehlgeschlagen' : 'Collection failed';
    const status = c[identity?.status ?? 'unknown'], hostnameReason = reason(identity?.hostnameReason), addresses = identity?.addresses ?? [];
    const addressRow = (address: typeof addresses[number], detailed = false) => <div className="fleet-address" key={`${address.interfaceIndex}:${address.family}:${address.address}`}>
        <FleetCopyValue value={address.address} label={locale === 'de' ? `IP-Adresse kopieren: ${address.address} (${address.interfaceName})` : `Copy IP address: ${address.address} (${address.interfaceName})`}/>
        <span className={`fleet-address-scope ${detailed || !address.up || address.scope === 'link-local' || address.scope === 'loopback' ? '' : 'sr-only'}`} title={c.scope}>{address.interfaceName} · {address.scope}{!address.up ? ` · ${c.down}` : ''}</span>
    </div>;
    return <div className="fleet-identity-name">
        {identity?.hostname ? <FleetCopyValue key={identity.hostname} value={identity.hostname} hostname label={locale === 'de' ? `Hostname kopieren: ${identity.hostname}` : `Copy hostname: ${identity.hostname}`}/> : <strong>{c.hostname}</strong>}
        {identity?.status !== 'fresh' && <span className={`fleet-identity-age ${identity?.status === 'stale' ? 'text-warning' : ''}`}>{status}</span>}
        {!identity?.hostname && hostnameReason && hostnameReason !== status && <span className="fleet-identity-age">{hostnameReason}</span>}
        <div className="fleet-identity-addresses">
            {addresses.length ? addressRow(addresses[0], expanded) : <span>{identity?.coverage === 'complete' ? c.empty : `${c.ips}${reason(identity?.addressReason) ? ` · ${reason(identity?.addressReason)}` : ''}`}</span>}
            {identity?.coverage === 'partial' && <span className="text-warning">{c.partial}</span>}
        </div>
        <details className="fleet-identity-details" onToggle={event => setExpanded(event.currentTarget.open)}>
            <summary><span>{addresses.length > 1 ? `+${addresses.length - 1} ${c.more} IPs` : locale === 'de' ? 'Weitere Angaben' : 'More details'}</span><ChevronDown size={12}/></summary>
            <div className="fleet-identity-expanded">
                {expanded && addresses.slice(1).map(address => addressRow(address, true))}
                <dl><div><dt>Agent ID</dt><dd className="fleet-identity-id mono">ID: {deviceId}</dd></div><div><dt>{locale === 'de' ? 'Quelle' : 'Source'}</dt><dd>{c.source} · {locale === 'de' ? 'LAN-Agent' : 'LAN agent'}</dd></div>{group && <div><dt>{locale === 'de' ? 'Gruppe' : 'Group'}</dt><dd>{group}</dd></div>}{identity?.status === 'fresh' && <div><dt>Status</dt><dd>{status}</dd></div>}{identity?.collectedAt && <div><dt>{c.observed}</dt><dd>{fullDate(identity.collectedAt)}</dd></div>}</dl>
                <p>{c.scope}</p>
            </div>
        </details>
    </div>;
}
export function FleetIdentityNotice({ resource }: { resource: FleetIdentityResource }) {
    const [locale] = useLocale(), c = copy[locale];
    return <div className="fleet-identity-notice"><span role={resource.error ? 'alert' : 'status'}>{resource.error ? c[resource.error] : resource.loading ? c.loading : `${c.title} · ${c.source}`}</span><button className="text-button" disabled={resource.loading || resource.error === 'session'} onClick={resource.refresh} aria-label={c.refresh} title={c.refresh}><RefreshCw size={13}/>{locale === 'de' ? 'Aktualisieren' : 'Refresh'}</button></div>;
}
