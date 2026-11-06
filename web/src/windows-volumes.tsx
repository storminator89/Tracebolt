import { useId, useState, type ReactNode } from 'react';
import './windows-volumes.css';
import { useLocale } from './i18n';
import { fullDate } from './utils';
import type { WindowsInventoryResource } from './windows-inventory-resource';
const copy = {
    en: { sort: 'Sort captured volumes', original: 'Capture order', least: 'Caller available: lowest first', most: 'Caller available: highest first', sortHint: 'Only captured volumes. When sorting by capacity, unavailable values stay last.', title: 'Storage', missing: 'No current storage scope reported. Separate local consent is required; missing data does not mean no volumes.', observed: 'Enumeration complete within scope', bounded: 'Bounded enumeration', partial: 'Partial enumeration', denied: 'Access denied', unavailable: 'Unavailable', rowObserved: 'Capacity observed', captured: 'Storage captured', stale: 'Stale storage observation. Values describe the original capture.', shown: 'shown', observedCount: 'observed', atLeast: 'at least', omitted: 'Volumes omitted by collection or transfer limits.', empty: 'No caller-visible local volumes returned. This is not a whole-machine storage claim.', failed: 'No volume rows available; this does not establish an empty inventory.', volume: 'Volume GUID', type: 'Type', quality: 'Capacity quality', total: 'Caller total', free: 'Physical free', available: 'Caller available', unknown: 'Not available', scope: 'Caller-visible local volume GUIDs only. No labels, mount paths, serial numbers or network drives. Capacity failures are per volume; enumeration completeness does not imply every capacity was readable.', quota: 'Caller total and caller available can be quota-limited. Physical free can exceed caller total. IEC units are abbreviated; exact bytes are available on each value. No used-space total is inferred.', fixed: 'Fixed', removable: 'Removable', cdrom: 'Optical', ramdisk: 'RAM disk', unknownType: 'Unknown' },
    de: { sort: 'Erfasste Volumes sortieren', original: 'Erfassungsreihenfolge', least: 'Aufrufer-verfügbar: niedrigste zuerst', most: 'Aufrufer-verfügbar: höchste zuerst', sortHint: 'Nur erfasste Volumes. Bei Kapazitätssortierung stehen unbekannte Werte zuletzt.', title: 'Speicher', missing: 'Kein aktueller Speicherumfang gemeldet. Eine separate lokale Zustimmung ist erforderlich; fehlende Daten bedeuten nicht, dass keine Volumes existieren.', observed: 'Auflistung im Umfang vollständig', bounded: 'Begrenzte Auflistung', partial: 'Teilweise aufgelistet', denied: 'Zugriff verweigert', unavailable: 'Nicht verfügbar', rowObserved: 'Kapazität erfasst', captured: 'Speicher erfasst', stale: 'Veraltete Speicherbeobachtung. Werte beschreiben die ursprüngliche Erfassung.', shown: 'angezeigt', observedCount: 'beobachtet', atLeast: 'mindestens', omitted: 'Volumes durch Erfassungs- oder Übertragungsgrenzen ausgelassen.', empty: 'Keine für den Aufrufer sichtbaren lokalen Volumes zurückgegeben. Dies ist keine Aussage über den gesamten Gerätespeicher.', failed: 'Keine Volume-Zeilen verfügbar; dies belegt kein leeres Inventar.', volume: 'Volume-GUID', type: 'Typ', quality: 'Kapazitätsqualität', total: 'Aufrufer-Gesamt', free: 'Physisch frei', available: 'Aufrufer-verfügbar', unknown: 'Nicht verfügbar', scope: 'Nur für den Aufrufer sichtbare lokale Volume-GUIDs. Keine Namen, Einhängepfade, Seriennummern oder Netzlaufwerke. Kapazitätsfehler gelten pro Volume; eine vollständige Auflistung bedeutet nicht, dass jede Kapazität lesbar war.', quota: 'Gesamt und verfügbar für den Aufrufer können durch Kontingente begrenzt sein. Physisch frei kann das Aufrufer-Gesamt übersteigen. IEC-Einheiten sind abgekürzt; exakte Bytes stehen an jedem Wert bereit. Daraus wird kein belegter Gesamtspeicher abgeleitet.', fixed: 'Fest', removable: 'Wechselmedium', cdrom: 'Optisch', ramdisk: 'RAM-Disk', unknownType: 'Unbekannt' },
};
/** BigInt throughout: presentation never rounds a uint64 through Number. */
export function volumeBytes(bytes: string, locale: 'en' | 'de'): string {
    const value = BigInt(bytes), units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB'];
    let unit = 0, scale = 1n;
    while (unit < units.length - 1 && value >= scale * 1024n) { scale *= 1024n; unit++; }
    const whole = value / scale, tenth = value % scale * 10n / scale;
    return `${value % scale ? '≈ ' : ''}${whole}${tenth ? `${locale === 'de' ? ',' : '.'}${tenth}` : ''} ${units[unit]}`;
}
export function WindowsStoragePanel({ resource }: { resource: WindowsInventoryResource }) {
    const [locale] = useLocale(), c = copy[locale], volumes = resource.volumes;
    if (!volumes) return <p role="status" className="windows-inventory-empty">{c.missing}</p>;
    return <VolumeCapacities key={`${resource.view?.deviceId}:${volumes.grantId}:${volumes.generationId}:${volumes.collectedAt}`} resource={resource} locale={locale}/>;
}
function VolumeCapacities({ resource, locale }: { resource: WindowsInventoryResource; locale: 'en' | 'de' }) {
    const volumes = resource.volumes!, c = copy[locale], id = useId();
    const [sort, setSort] = useState('original');
    const rows = [...volumes.rows];
    if (sort !== 'original') rows.sort((a, b) => {
        const left = a.capacity?.availableBytes, right = b.capacity?.availableBytes;
        if (left === undefined) return right === undefined ? 0 : 1;
        if (right === undefined) return -1;
        const order = BigInt(left) < BigInt(right) ? -1 : BigInt(left) > BigInt(right) ? 1 : 0;
        return sort === 'least' ? order : -order;
    });
    const headers = [c.volume, c.type, c.quality, c.total, c.free, c.available];
    const bytes = (value: string | undefined): ReactNode => value === undefined ? c.unknown : <span title={`${value} ${locale === 'de' ? 'Bytes' : 'bytes'}`} aria-label={`${value} ${locale === 'de' ? 'Bytes' : 'bytes'}`}>{volumeBytes(value, locale)}</span>;
    return <section aria-label={c.title}>
        <div className="windows-inventory-section-header"><h3>{c.title}</h3><span className="windows-inventory-quality">{c[volumes.quality]}</span></div>
        <p className="windows-inventory-times">{c.captured} <time dateTime={volumes.collectedAt}>{fullDate(volumes.collectedAt)}</time></p>
        {resource.volumesStale && <p role="status" className="windows-inventory-caution">{c.stale}</p>}
        {volumes.quality !== 'denied' && volumes.quality !== 'unavailable' && <p className="windows-inventory-count">{volumes.rows.length} {c.shown} · {volumes.countExact ? '' : `${c.atLeast} `}{volumes.observedCount} {c.observedCount}</p>}
        {volumes.truncated && <p className="windows-inventory-caution">{c.omitted}</p>}
        {volumes.rows.length > 1 && <div className="windows-volume-sort"><label htmlFor={id}>{c.sort}</label><select id={id} value={sort} aria-describedby={`${id}-scope`} onChange={event => setSort(event.target.value)}><option value="original">{c.original}</option><option value="least">{c.least}</option><option value="most">{c.most}</option></select><span id={`${id}-scope`}>{c.sortHint}</span></div>}
        {volumes.rows.length ? <div className="windows-inventory-table-wrap"><table className="windows-inventory-table"><caption className="sr-only">{c.title}</caption><thead><tr>{headers.map(h => <th key={h} scope="col" aria-sort={h === c.available && sort !== 'original' ? sort === 'least' ? 'ascending' : 'descending' : undefined}>{h}</th>)}</tr></thead><tbody>{rows.map(row => {
            const cells = [row.volumeId, row.driveType === 'unknown' ? c.unknownType : c[row.driveType], row.quality === 'observed' ? c.rowObserved : c[row.quality], bytes(row.capacity?.totalBytes), bytes(row.capacity?.freeBytes), bytes(row.capacity?.availableBytes)];
            return <tr key={row.volumeId}>{cells.map((cell, index) => <td key={index} data-label={headers[index]}>{cell}</td>)}</tr>;
        })}</tbody></table></div> : <p className="windows-inventory-empty">{volumes.quality === 'observed' ? c.empty : c.failed}</p>}
        <p className="windows-inventory-exclusions">{c.scope}</p><p className="windows-inventory-exclusions">{c.quota}</p>
    </section>;
}
