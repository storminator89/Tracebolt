import type { Device } from './types';
import { useLocale } from './i18n';
import { fullDate, relativeTime } from './utils';

/** A recorded capture time, not a receipt, refresh time or reachability check. */
export function reportTimestamp(value: unknown): value is string {
    if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d{1,9})?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$/.test(value)) return false;
    const day = new Date(`${value.slice(0, 10)}T00:00:00Z`), time = Date.parse(value);
    return Number.isFinite(time) && time !== -62135596800000 && Number.isFinite(day.getTime()) && day.toISOString().slice(0, 10) === value.slice(0, 10);
}

/** Go serializes an unset Device.LastSeen with this explicit UTC zero value. */
export function noReportTimestamp(value: unknown): boolean {
    return typeof value === 'string' && /^0001-01-01T00:00:00(?:\.0{1,9})?Z$/.test(value);
}

export function ReportTime({ device, full = false, className, available = true }: { device: Device; full?: boolean; className?: string; available?: boolean }) {
    const [locale] = useLocale();
    if (device.source === 'lan' && !device.synthetic && !reportTimestamp(device.lastSeen)) return <span className={className}>{available && noReportTimestamp(device.lastSeen) ? locale === 'de' ? 'Noch keine Meldung erfasst' : 'No report recorded yet' : locale === 'de' ? 'Meldungsstatus nicht verfügbar' : 'Report status unavailable'}</span>;
    return <time dateTime={device.lastSeen} title={fullDate(device.lastSeen)} className={className}>{full ? fullDate(device.lastSeen) : relativeTime(device.lastSeen)}</time>;
}
