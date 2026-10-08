import { fullDate } from './utils';
import type { WindowsInventoryResource } from './windows-inventory-resource';
import type { WindowsServiceStartup, WindowsServiceStartupRow } from './windows-service-startup-types';

export const serviceStartupCopy = {
    en: {
        column: 'Startup mode', automatic: 'Automatic', manual: 'Manual', disabled: 'Disabled',
        denied: 'Access denied', unavailable: 'Unavailable', unknown: 'Unknown',
        absent: 'Not configured or not captured', trimmed: 'Not captured (trimmed)',
        delayed: 'delayed', notDelayed: 'not delayed', delayedStatus: 'delayed status', partial: 'partial',
        missing: 'Service startup metadata is not configured or was not captured. Separate local consent is required; missing values do not establish a startup mode.',
        note: 'Captured startup configuration is separate from the reported service state. It does not establish whether a service will run after boot. Trigger information is not collected.',
        captured: 'Startup configuration captured', stale: 'Stale startup configuration. Values describe the original capture and may have changed.',
        truncated: 'Startup rows omitted by capture or transfer limits. Missing rows are not a reported startup mode.',
        count: (shown: number, requested: number) => `${shown} startup rows captured · ${requested} base service rows requested`,
    },
    de: {
        column: 'Starttyp', automatic: 'Automatisch', manual: 'Manuell', disabled: 'Deaktiviert',
        denied: 'Zugriff verweigert', unavailable: 'Nicht verfügbar', unknown: 'Unbekannt',
        absent: 'Nicht eingerichtet oder nicht erfasst', trimmed: 'Nicht erfasst (gekürzt)',
        delayed: 'verzögert', notDelayed: 'nicht verzögert', delayedStatus: 'Verzögerungsstatus', partial: 'teilweise',
        missing: 'Dienststartdaten sind nicht eingerichtet oder wurden nicht erfasst. Eine separate lokale Zustimmung ist erforderlich; fehlende Werte belegen keinen Starttyp.',
        note: 'Die erfasste Startkonfiguration ist vom gemeldeten Dienstzustand getrennt. Sie belegt nicht, ob ein Dienst nach dem Systemstart laufen wird. Triggerinformationen werden nicht erfasst.',
        captured: 'Startkonfiguration erfasst', stale: 'Veraltete Startkonfiguration. Die Werte beschreiben die ursprüngliche Erfassung und können sich geändert haben.',
        truncated: 'Starttypzeilen durch Erfassungs- oder Übertragungsgrenzen ausgelassen. Fehlende Zeilen sind kein gemeldeter Starttyp.',
        count: (shown: number, requested: number) => `${shown} Starttypzeilen erfasst · ${requested} Basisdienstzeilen angefordert`,
    },
};
/** A null delayed flag is never rendered as false. Unknown modes stay unknown. */
export function serviceStartupCell(row: WindowsServiceStartupRow | undefined, startup: WindowsServiceStartup | null, locale: 'en' | 'de'): string {
    const c = serviceStartupCopy[locale];
    if (!startup) return c.absent;
    if (!row) return c.trimmed;
    if (row.startupQuality !== 'observed') return c[row.startupQuality];
    if (row.startupMode === 'manual' || row.startupMode === 'disabled') return c[row.startupMode];
    if (row.startupMode !== 'automatic') return c.unknown;
    if (row.delayedAutoQuality === 'observed' && row.delayedAutoStart !== null) return `${c.automatic} (${row.delayedAutoStart ? c.delayed : c.notDelayed})`;
    const quality = row.delayedAutoQuality;
    return `${c.automatic} · ${c.delayedStatus}: ${quality === 'denied' || quality === 'unavailable' ? c[quality] : c.unknown} (${c.partial})`;
}
export function WindowsServiceStartupNote({ resource, locale }: { resource: WindowsInventoryResource; locale: 'en' | 'de' }) {
    const c = serviceStartupCopy[locale], startup = resource.serviceStartup;
    if (!startup) return <p className="windows-inventory-caution">{c.missing}</p>;
    return <div className="windows-service-startup-note">
        <p>{c.note}</p><p className="windows-inventory-count">{c.count(startup.rows.length, startup.requestedCount)}</p>
        {startup.truncated && <p className="windows-inventory-caution">{c.truncated}</p>}
        <div className="windows-inventory-times"><span>{c.captured} <time dateTime={startup.collectedAt}>{fullDate(startup.collectedAt)}</time></span></div>
        {resource.serviceStartupStale && <p className="windows-inventory-caution">{c.stale}</p>}
    </div>;
}
