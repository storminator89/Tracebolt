import { HardDrive, Folder } from 'lucide-react';
import { useLocale } from './i18n';
import { fullDate } from './utils';
import { volumeBytes } from './windows-volumes';
import type { WindowsInventoryResource } from './windows-inventory-resource';
import type { WindowsStorageField, WindowsStorageGroup } from './windows-storage-context-types';
import './windows-storage-context.css';

const copy = {
    en: {
        title: 'Drive mapping & provider disks', drives: 'Drive letters', disks: 'Provider disks', captured: 'Context captured', observed: 'Enumeration complete', partial: 'Partial source', enumerationComplete: 'Enumeration complete', enumerationPartial: 'Enumeration incomplete', friendly: 'Friendly label', denied: 'Access denied', unavailable: 'Unavailable', empty: 'Not reported', unknown: 'Unknown', shown: 'shown', counted: 'observed', atLeast: 'at least', omitted: 'Rows omitted by collection or transfer limits.', noDrives: 'No local drive letters returned.', noDisks: 'No provider disks returned.', failed: 'No rows available. This does not establish an empty inventory.',
        providerHealth: 'MSFT_PhysicalDisk health', health: { 0: 'Healthy', 1: 'Warning', 2: 'Unhealthy', 5: 'Unknown' }, code: 'Code', disk: 'Provider row', deviceId: 'Provider DeviceId', size: 'Provider size', media: 'Media', bus: 'Bus', operations: 'Operational status codes', unspecified: 'Unspecified', virtual: 'File-backed virtual', reserved: 'Reserved', mapping: 'Volume GUID', fixed: 'Fixed', removable: 'Removable', cdrom: 'Optical', ramdisk: 'RAM disk',
        absent: 'Drive mapping and provider disk context is unavailable for this capture. Separate local approval is required.', stale: 'Stale storage context; values describe the original capture.', expired: 'Drive mapping and provider disk context expired after 24 hours.', ahead: 'Storage context is hidden until its capture time can be verified.',
        details: 'Provider details & sources', caution: 'MSFT_PhysicalDisk reports provider health, not SMART or proof of whole-device health. RAID, virtual disks and Storage Spaces may hide underlying devices.', coverage: 'Completeness describes enumeration only; individual mappings and disk fields may be denied or unknown. Missing letters do not establish that a volume has no mount points.', source: 'Drive letters: fixed local drive APIs with exact volume GUID mapping. Physical disks: local MSFT_PhysicalDisk. No volume-to-physical-disk mapping is inferred.', identifiers: 'DeviceId is a transient, capture-local provider identifier, not an OS disk number or stable asset identifier. Friendly labels can be user-edited. Numeric status codes are preserved, including unrecognized values.', consent: 'Separate windows-storage-context-v1 local approval. Identifying metadata is operator-only and excluded from AI/provider export. No disk serials, unique IDs, file paths, I/O performance or storage actions.',
        reasons: { windows_storage_context_access_denied: 'Source access denied.', windows_storage_context_unavailable: 'Source unavailable.', windows_storage_context_unsupported_platform: 'Source unsupported.', windows_storage_context_invalid_metadata: 'Some source metadata was invalid.', windows_storage_context_bounds: 'Source collection limit reached.', windows_storage_context_partial_result: 'Some source fields were not available.', windows_storage_context_budget_exhausted: 'Source collection time limit reached.' },
    },
    de: {
        title: 'Laufwerkszuordnung & Provider-Datenträger', drives: 'Laufwerksbuchstaben', disks: 'Provider-Datenträger', captured: 'Kontext erfasst', observed: 'Auflistung vollständig', partial: 'Quelle teilweise', enumerationComplete: 'Auflistung vollständig', enumerationPartial: 'Auflistung unvollständig', friendly: 'Anzeigename', denied: 'Zugriff verweigert', unavailable: 'Nicht verfügbar', empty: 'Nicht gemeldet', unknown: 'Unbekannt', shown: 'angezeigt', counted: 'beobachtet', atLeast: 'mindestens', omitted: 'Zeilen durch Erfassungs- oder Übertragungsgrenzen ausgelassen.', noDrives: 'Keine lokalen Laufwerksbuchstaben zurückgegeben.', noDisks: 'Keine Provider-Datenträger zurückgegeben.', failed: 'Keine Zeilen verfügbar. Dies belegt kein leeres Inventar.',
        providerHealth: 'MSFT_PhysicalDisk-Zustand', health: { 0: 'Fehlerfrei', 1: 'Warnung', 2: 'Fehlerhaft', 5: 'Unbekannt' }, code: 'Code', disk: 'Provider-Zeile', deviceId: 'Provider-DeviceId', size: 'Provider-Größe', media: 'Medium', bus: 'Bus', operations: 'Betriebsstatuscodes', unspecified: 'Nicht angegeben', virtual: 'Dateibasiert virtuell', reserved: 'Reserviert', mapping: 'Volume-GUID', fixed: 'Fest', removable: 'Wechselmedium', cdrom: 'Optisch', ramdisk: 'RAM-Disk',
        absent: 'Für diese Erfassung sind keine Laufwerkszuordnungen und Provider-Datenträgerdaten verfügbar. Eine gesonderte lokale Freigabe ist erforderlich.', stale: 'Veralteter Speicherkontext; Werte gelten für die ursprüngliche Erfassung.', expired: 'Laufwerkszuordnungen und Provider-Datenträgerdaten nach 24 Stunden abgelaufen.', ahead: 'Speicherkontext bleibt ausgeblendet, bis die Erfassungszeit geprüft werden kann.',
        details: 'Provider-Details & Quellen', caution: 'MSFT_PhysicalDisk meldet den Provider-Zustand, keine SMART-Daten oder einen Nachweis des gesamten Gerätezustands. RAID, virtuelle Datenträger und Storage Spaces können zugrunde liegende Geräte verbergen.', coverage: 'Vollständigkeit gilt nur für die Auflistung; einzelne Zuordnungen und Datenträgerfelder können verweigert oder unbekannt sein. Fehlende Buchstaben belegen keine fehlenden Einhängepunkte eines Volumes.', source: 'Laufwerksbuchstaben: feste lokale Laufwerks-APIs mit exakter Volume-GUID-Zuordnung. Physische Datenträger: lokal über MSFT_PhysicalDisk. Es wird keine Zuordnung von Volumes zu physischen Datenträgern abgeleitet.', identifiers: 'DeviceId ist eine vorübergehende, erfassungsgebundene Provider-Kennung, keine Datenträgernummer des Betriebssystems oder beständige Gerätekennung. Anzeigenamen können vom Nutzer geändert werden. Numerische Statuscodes bleiben einschließlich unbekannter Werte erhalten.', consent: 'Separate lokale Zustimmung für windows-storage-context-v1. Identifizierende Metadaten nur für Operatoren; vom KI-/Provider-Export ausgeschlossen. Keine Datenträgerseriennummern, eindeutigen IDs, Dateipfade, E/A-Leistungsdaten oder Speicheraktionen.',
        reasons: { windows_storage_context_access_denied: 'Zugriff auf Quelle verweigert.', windows_storage_context_unavailable: 'Quelle nicht verfügbar.', windows_storage_context_unsupported_platform: 'Quelle nicht unterstützt.', windows_storage_context_invalid_metadata: 'Einige Quellmetadaten waren ungültig.', windows_storage_context_bounds: 'Erfassungsgrenze der Quelle erreicht.', windows_storage_context_partial_result: 'Einige Quellfelder waren nicht verfügbar.', windows_storage_context_budget_exhausted: 'Zeitlimit der Quelle erreicht.' },
    },
};
// Values are from the fixed MSFT_PhysicalDisk contract. Unknown/future codes stay numeric.
// https://learn.microsoft.com/en-us/windows-hardware/drivers/storage/msft-physicaldisk
export function WindowsStorageContextPanel({ resource }: { resource: WindowsInventoryResource }) {
    const [locale] = useLocale(), c = copy[locale], context = resource.storageContext;
    if (!context) return <p role="status" className="windows-inventory-empty">{resource.storageContextExpired ? c.expired : resource.storageContextAhead ? c.ahead : c.absent}</p>;
    const binding = `${resource.view?.deviceId}:${context.grantId}:${context.generationId}:${context.collectedAt}`;
    const field = (v: WindowsStorageField) => v.quality === 'observed' ? v.value : c[v.quality];
    const coded = (n: number | null, labels: Record<number, string>) => n === null ? c.unknown : `${labels[n] ?? c.code} (${n})`;
    const health = (n: number | null) => coded(n, c.health);
    const media = (n: number | null) => coded(n, { 0: c.unspecified, 3: 'HDD', 4: 'SSD', 5: 'SCM' });
    const bus = (n: number | null) => coded(n, { 0: c.unknown, 1: 'SCSI', 2: 'ATAPI', 3: 'ATA', 4: 'IEEE 1394', 5: 'SSA', 6: 'Fibre Channel', 7: 'USB', 8: 'RAID', 9: 'iSCSI', 10: 'SAS', 11: 'SATA', 12: 'SD', 13: 'MMC', 14: c.reserved, 15: c.virtual, 16: 'Storage Spaces', 17: 'NVMe' });
    const coverage = (group: WindowsStorageGroup<unknown>, noRows: string) => <>
        {['observed', 'partial'].includes(group.quality) && <p className="windows-inventory-count">{group.complete ? c.enumerationComplete : c.enumerationPartial} · {group.rows.length} {c.shown} · {group.countExact ? '' : `${c.atLeast} `}{group.observedCount} {c.counted}</p>}
        {group.reason && <p className="windows-storage-reason">{c.reasons[group.reason]}</p>}
        {group.truncated && <p className="windows-inventory-caution">{c.omitted}</p>}
        {!group.rows.length && <p className="windows-inventory-empty">{group.quality === 'observed' ? noRows : c.failed}</p>}
    </>;
    return <section className="windows-storage-context" aria-label={c.title}>
        <div className="windows-inventory-section-header"><h3>{c.title}</h3><span className="windows-inventory-times">{c.captured} <time dateTime={context.collectedAt}>{fullDate(context.collectedAt)}</time></span></div>
        {resource.storageContextStale && <p role="status" className="windows-inventory-caution">{c.stale}</p>}
        <div className="windows-storage-groups">
            <section className="windows-storage-group windows-storage-drives" aria-label={c.drives}>
                <div className="windows-storage-heading"><h4><Folder size={16} aria-hidden="true"/>{c.drives}</h4><span>{c[context.drives.quality]}</span></div>
                {coverage(context.drives, c.noDrives)}
                <dl>{context.drives.rows.map(row => <div key={row.letter}><dt><bdi>{row.letter}</bdi><small>{c[row.driveType]}</small></dt><dd><bdi>{row.volumeGuid ?? c[row.quality === 'observed' ? 'unknown' : row.quality]}</bdi>{row.reason && <small>{c.reasons[row.reason]}</small>}</dd></div>)}</dl>
            </section>
            <section className="windows-storage-group windows-storage-disks" aria-label={c.disks}>
                <div className="windows-storage-heading"><h4><HardDrive size={16} aria-hidden="true"/>{c.disks}</h4><span>{c[context.disks.quality]}</span></div>
                {coverage(context.disks, c.noDisks)}
                {context.disks.rows.map(row => <article className="windows-storage-disk" key={row.index}>
                    <h5><bdi>{row.friendlyName.value ?? `${c.disk} ${row.index + 1}`}</bdi></h5>
                    <p className="windows-storage-health">{c.providerHealth}: <strong>{health(row.healthStatus)}</strong></p>
                    <p>{media(row.mediaType)} · {bus(row.busType)} · {row.sizeBytes === null ? c.unknown : <span title={`${row.sizeBytes} bytes`} aria-label={`${row.sizeBytes} ${locale === 'de' ? 'Bytes' : 'bytes'}`}>{volumeBytes(row.sizeBytes, locale)}</span>}</p>
                </article>)}
            </section>
        </div>
        <p className="windows-inventory-caution">{c.caution}</p>
        <details className="windows-storage-details" key={binding}><summary>{c.details}</summary>
            {context.disks.rows.map(row => <section className="windows-storage-provider-details" key={row.index}>
                <h5><bdi>{row.friendlyName.value ?? `${c.disk} ${row.index + 1}`}</bdi></h5>
                <dl>{[[c.friendly, field(row.friendlyName)], [c.deviceId, field(row.deviceId)], [c.providerHealth, health(row.healthStatus)], [c.operations, row.operationalStatus.length ? row.operationalStatus.join(', ') : c.unknown], [c.size, row.sizeBytes === null ? c.unknown : `${row.sizeBytes} ${locale === 'de' ? 'Bytes' : 'bytes'}`]].map(([label, value]) => <div key={label}><dt>{label}</dt><dd><bdi>{value}</bdi></dd></div>)}</dl>
            </section>)}
            <p>{c.coverage}</p><p>{c.source}</p><p>{c.identifiers}</p><p>{c.consent}</p>
        </details>
    </section>;
}
