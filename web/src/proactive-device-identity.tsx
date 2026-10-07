import { useLocale } from './i18n';
import type { FleetIdentityDisplay } from './fleet-identity-types';

const copy = {
    en: { hostname: 'Hostname unavailable', addresses: 'IP addresses unavailable', empty: 'No IP addresses reported', source: 'Reported', fresh: 'Recent', stale: 'Stale', expired: 'Expired', revoked: 'Revoked', not_collected: 'Not collected', unknown: 'Metadata unavailable', partial: 'Partially collected', more: 'more', down: 'down', denied: 'Permission denied' },
    de: { hostname: 'Hostname nicht verfügbar', addresses: 'IP-Adressen nicht verfügbar', empty: 'Keine IP-Adressen gemeldet', source: 'Gemeldet', fresh: 'Aktuell', stale: 'Veraltet', expired: 'Abgelaufen', revoked: 'Widerrufen', not_collected: 'Nicht erfasst', unknown: 'Metadaten nicht verfügbar', partial: 'Teilweise erfasst', more: 'weitere', down: 'inaktiv', denied: 'Zugriff verweigert' },
};
const visible = (identity?: FleetIdentityDisplay) => identity?.status === 'fresh' || identity?.status === 'stale';
export function proactiveDeviceName(identity: FleetIdentityDisplay | undefined, locale: 'en' | 'de') {
    return visible(identity) && identity?.hostname ? identity.hostname : copy[locale].hostname;
}
/** Increase the suffix only when necessary to distinguish enrolled IDs. */
export function shortProactiveDeviceId(id: string, ids: readonly string[]) {
    let length = Math.min(8, id.length);
    while (length < id.length && ids.some(other => other !== id && other.slice(-length) === id.slice(-length))) length++;
    return length < id.length ? `…${id.slice(-length)}` : id;
}

/** Reported metadata is ephemeral display text only, never a target or an AI input. */
export function ProactiveDeviceIdentity({ identity, deviceId, deviceIds }: { identity?: FleetIdentityDisplay; deviceId: string; deviceIds: readonly string[] }) {
    const [locale] = useLocale(), c = copy[locale], snapshot = visible(identity) ? identity : undefined;
    const addresses = snapshot?.addresses ?? [];
    return <span className="proactive-device-identity">
        <span className="proactive-device-name"><strong>{proactiveDeviceName(identity, locale)}</strong><span className="proactive-device-id mono" title={`Agent ID: ${deviceId}`}>ID {shortProactiveDeviceId(deviceId, deviceIds)}</span></span>
        <span className={`proactive-device-status ${identity?.status === 'stale' ? 'text-warning' : ''}`} title={snapshot?.collectedAt ?? undefined}>{snapshot ? `${c.source} · ` : ''}{c[identity?.status ?? 'unknown']}{snapshot?.hostnameReason === 'permission_denied' ? ` · ${c.denied}` : ''}</span>
        {addresses.length ? <>{addresses.slice(0, 2).map(address => <span className="proactive-device-address" key={`${address.interfaceIndex}:${address.family}:${address.address}`}><span className="mono">{address.address}</span><small>{address.interfaceName} · {address.scope}{!address.up ? ` · ${c.down}` : ''}</small></span>)}{addresses.length > 2 && <small>+{addresses.length - 2} {c.more}</small>}</> : <small>{snapshot?.coverage === 'complete' ? c.empty : c.addresses}{snapshot?.addressReason === 'permission_denied' ? ` · ${c.denied}` : ''}</small>}
        {snapshot?.coverage === 'partial' && <small className="text-warning">{c.partial}</small>}
    </span>;
}
