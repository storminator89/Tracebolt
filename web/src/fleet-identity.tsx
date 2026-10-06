import { RefreshCw } from 'lucide-react';
import { useLocale } from './i18n';
import { fullDate } from './utils';
import type { EndpointReason } from './endpoint-identity-types';
import type { FleetIdentityDisplay } from './fleet-identity-types';
import type { FleetIdentityResource } from './fleet-identity-resource';
import './fleet-identity.css';

const copy = {
    de: { title: 'Hostname & IP-Adressen', source: 'Vom Gerät gemeldet', unknown: 'Unbekannt', hostname: 'Hostname nicht verfügbar', ips: 'IP-Adressen nicht verfügbar', empty: 'Keine IP-Adressen gemeldet', partial: 'Teilweise erfasst', fresh: 'Aktuell', stale: 'Veraltet', expired: 'Abgelaufen', revoked: 'Widerrufen', not_collected: 'Nicht erfasst', loading: 'Hostname und IP-Adressen werden geladen …', loadError: 'Hostname und IP-Adressen konnten nicht geladen werden.', invalid: 'Ungültige Identitätsdaten wurden ausgeblendet.', timeout: 'Das Laden der Identitätsdaten hat zu lange gedauert.', session: 'Sitzung beendet. Bitte erneut anmelden.', clock: 'Zeitprüfung fehlgeschlagen. Bitte aktualisieren.', busy: 'Identitätsdaten sind vorübergehend nicht verfügbar.', refresh: 'Hostname und IP-Adressen aktualisieren', more: 'weitere in den Gerätedetails', observed: 'Erfasst', down: 'inaktiv', scope: 'Gemeldete Schnittstellenadressen; keine primäre IP oder Erreichbarkeit abgeleitet.' },
    en: { title: 'Hostname & IP addresses', source: 'Reported by device', unknown: 'Unknown', hostname: 'Hostname unavailable', ips: 'IP addresses unavailable', empty: 'No IP addresses reported', partial: 'Partially collected', fresh: 'Recent', stale: 'Stale', expired: 'Expired', revoked: 'Revoked', not_collected: 'Not collected', loading: 'Loading hostnames and IP addresses …', loadError: 'Hostnames and IP addresses could not be loaded.', invalid: 'Invalid identity data was hidden.', timeout: 'Loading identity data timed out.', session: 'Session ended. Please sign in again.', clock: 'Time check failed. Please refresh.', busy: 'Identity data is temporarily unavailable.', refresh: 'Refresh hostnames and IP addresses', more: 'more in device details', observed: 'Collected', down: 'down', scope: 'Reported interface addresses; no primary IP or reachability inferred.' },
};
export function FleetIdentityName({ identity, deviceId }: { identity?: FleetIdentityDisplay; deviceId: string }) {
    const [locale] = useLocale(), c = copy[locale];
    const reason = (value: EndpointReason | null | undefined) => !value || value === 'none' ? '' : value === 'permission_denied' ? locale === 'de' ? 'Zugriff verweigert' : 'Permission denied' : value === 'not_collected' ? c.not_collected : value === 'not_supported' ? locale === 'de' ? 'Nicht unterstützt' : 'Not supported' : locale === 'de' ? 'Erfassung fehlgeschlagen' : 'Collection failed';
    const addresses = identity?.addresses ?? [];
    const addressText = addresses.map(address => `${address.address} · ${address.interfaceName} #${address.interfaceIndex} · ${address.scope}${!address.up ? ` · ${c.down}` : ''}`).join('\n');
    return <span className="fleet-identity-name">
        <strong>{identity?.hostname ?? c.hostname}</strong>
        <span className={`fleet-identity-age ${identity?.status === 'stale' ? 'text-warning' : ''}`} title={identity?.collectedAt ? `${c.observed}: ${fullDate(identity.collectedAt)}` : undefined}>{c.source} · {c[identity?.status ?? 'unknown']}</span>
        {!identity?.hostname && reason(identity?.hostnameReason) && <span className="fleet-identity-age">{reason(identity?.hostnameReason)}</span>}
        <span className="fleet-identity-addresses" title={addressText ? `${addressText}\n${c.scope}` : c.scope}>
            {addresses.length ? <>{addresses.slice(0, 2).map(address => <span className="fleet-address" key={`${address.interfaceIndex}:${address.family}:${address.address}`}><span className="mono">{address.address}</span><small>{address.interfaceName}{!address.up ? ` · ${c.down}` : ''}</small></span>)}{addresses.length > 2 && <span className="fleet-address-more">+{addresses.length - 2} {c.more}</span>}</> : <span>{identity?.coverage === 'complete' ? c.empty : `${c.ips}${reason(identity?.addressReason) ? ` · ${reason(identity?.addressReason)}` : ''}`}</span>}
            {identity?.coverage === 'partial' && <span className="text-warning">{c.partial}</span>}
        </span>
        <span className="fleet-identity-id mono" title={`Agent ID: ${deviceId}`}>ID: {deviceId}</span>
    </span>;
}
export function FleetIdentityNotice({ resource }: { resource: FleetIdentityResource }) {
    const [locale] = useLocale(), c = copy[locale];
    return <div className="fleet-identity-notice"><span role={resource.error ? 'alert' : 'status'}>{resource.error ? c[resource.error] : resource.loading ? c.loading : `${c.title} · ${c.source}`}</span><button className="text-button" disabled={resource.loading || resource.error === 'session'} onClick={resource.refresh} aria-label={c.refresh} title={c.refresh}><RefreshCw size={13}/>{locale === 'de' ? 'Aktualisieren' : 'Refresh'}</button></div>;
}
