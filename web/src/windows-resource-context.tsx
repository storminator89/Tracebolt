import { Cpu, MemoryStick } from 'lucide-react';
import { useLocale } from './i18n';
import { fullDate } from './utils';
import type { WindowsInventoryResource } from './windows-inventory-resource';
import { windowsCommitRemaining, windowsResourceBytes, type WindowsResourceLabel, type WindowsResourceCount } from './windows-resource-context-types';
import './windows-resource-context.css';

const copy = {
    en: {
        title: 'CPU & memory', cpu: 'CPU', ram: 'Physical memory', commit: 'Committed memory', pagefiles: 'Pagefiles', captured: 'Captured', observed: 'Observed', partial: 'Partial', denied: 'Access denied', unavailable: 'Unavailable', empty: 'Not reported', unknown: 'Unknown',
        model: 'CPU model', cores: 'Reported cores', logical: 'Reported logical processors', architecture: 'Reported architecture', processor: 'Processor row', installed: 'Installed RAM (SMBIOS)', usable: 'OS-usable RAM', available: 'Available physical RAM', committed: 'Committed', limit: 'Current commit limit', remaining: 'Remaining commit capacity', allocated: 'Allocated', inUse: 'In use', count: 'Pagefile count', none: 'No pagefiles reported', pageSize: 'Page size', bytes: 'bytes',
        absent: 'No CPU & memory context reported for this capture.', stale: 'Stale observation; values describe the original capture.', expired: 'CPU & memory context expired after 24 hours.', ahead: 'CPU & memory context is hidden until its capture time can be verified.',
        details: 'CPU & memory sources & exact values', processorsSource: 'Processor rows', installedSource: 'Installed memory', memorySource: 'Memory accounting', pagefilesSource: 'Pagefile aggregate',
        cpuNote: 'Win32_Processor reports model, architecture and counts for at most four complete rows. Larger enumerations are unavailable. Totals include only complete source counts; rows do not establish physical socket topology. Existing CPU utilization is unavailable with multiple active processor groups. CPU configuration can remain independently available and does not add multi-group utilization coverage.',
        ramNote: 'Installed RAM is the SMBIOS amount reported by GetPhysicallyInstalledSystemMemory. K32GetPerformanceInfo reports OS-usable and available physical memory. These source amounts can differ and do not identify reserved-memory causes.',
        commitNote: 'Committed bytes and the current limit come from K32GetPerformanceInfo. Remaining capacity is their difference at capture time. The limit can change; committed memory is not pagefile usage or a pressure, health or thrashing assessment.',
        pagefilesNote: 'EnumPageFilesW supplies aggregate allocated and in-use bytes. These are separate from physical RAM and commit accounting. No pagefile paths or names are collected.',
        consent: 'Separate default-off windows-resource-context-v1 local approval. Operator-only context, excluded from AI/provider export. No health-policy changes, memory actions or host grants.',
        reasons: { windows_resource_context_access_denied: 'Source access denied.', windows_resource_context_unavailable: 'Source unavailable.', windows_resource_context_unsupported_platform: 'Source unsupported.', windows_resource_context_invalid_metadata: 'Source metadata was invalid.', windows_resource_context_bounds: 'Source collection limit reached.', windows_resource_context_partial_result: 'Some source fields were not available.', windows_resource_context_budget_exhausted: 'Source collection time limit reached.' },
    },
    de: {
        title: 'CPU & Arbeitsspeicher', cpu: 'CPU', ram: 'Physischer Arbeitsspeicher', commit: 'Zugesicherter Speicher', pagefiles: 'Auslagerungsdateien', captured: 'Erfasst', observed: 'Beobachtet', partial: 'Teilweise', denied: 'Zugriff verweigert', unavailable: 'Nicht verfügbar', empty: 'Nicht gemeldet', unknown: 'Unbekannt',
        model: 'CPU-Modell', cores: 'Gemeldete Kerne', logical: 'Gemeldete logische Prozessoren', architecture: 'Gemeldete Architektur', processor: 'Prozessorzeile', installed: 'Installierter RAM (SMBIOS)', usable: 'Vom Betriebssystem nutzbarer RAM', available: 'Verfügbarer physischer RAM', committed: 'Zugesichert', limit: 'Aktuelles Zusicherungslimit', remaining: 'Verbleibende Zusicherungskapazität', allocated: 'Zugewiesen', inUse: 'Belegt', count: 'Anzahl der Auslagerungsdateien', none: 'Keine Auslagerungsdateien gemeldet', pageSize: 'Seitengröße', bytes: 'Bytes',
        absent: 'Für diese Erfassung wurden keine CPU- und Arbeitsspeicherdaten gemeldet.', stale: 'Veraltete Beobachtung; Werte gelten für die ursprüngliche Erfassung.', expired: 'CPU- und Arbeitsspeicherdaten nach 24 Stunden abgelaufen.', ahead: 'CPU- und Arbeitsspeicherdaten bleiben ausgeblendet, bis die Erfassungszeit geprüft werden kann.',
        details: 'CPU- und Speicherquellen & exakte Werte', processorsSource: 'Prozessorzeilen', installedSource: 'Installierter Arbeitsspeicher', memorySource: 'Speicherbelegung', pagefilesSource: 'Auslagerungsdateien gesamt',
        cpuNote: 'Win32_Processor meldet Modell, Architektur und Anzahlen für höchstens vier vollständige Zeilen. Größere Auflistungen sind nicht verfügbar. Summen enthalten nur vollständige Quellangaben; Zeilen belegen keine physische Sockeltopologie. Die bestehende CPU-Auslastungsmessung ist bei mehreren aktiven Prozessorgruppen nicht verfügbar. Die CPU-Konfiguration kann unabhängig davon verfügbar sein und ergänzt keine gruppenübergreifende Auslastungsmessung.',
        ramNote: 'Installierter RAM ist die von GetPhysicallyInstalledSystemMemory gemeldete SMBIOS-Menge. K32GetPerformanceInfo meldet den vom Betriebssystem nutzbaren und verfügbaren physischen Speicher. Diese Quellangaben können abweichen und erklären keine Speicherreservierungen.',
        commitNote: 'Zugesicherte Bytes und das aktuelle Limit stammen aus K32GetPerformanceInfo. Die verbleibende Kapazität ist ihre Differenz zum Erfassungszeitpunkt. Das Limit kann sich ändern; zugesicherter Speicher ist keine Auslagerungsdateibelegung oder Bewertung von Speicherdruck, Zustand oder Thrashing.',
        pagefilesNote: 'EnumPageFilesW liefert insgesamt zugewiesene und belegte Bytes. Diese Angaben sind von physischem RAM und zugesichertem Speicher getrennt. Es werden keine Pfade oder Namen von Auslagerungsdateien erfasst.',
        consent: 'Separate, standardmäßig deaktivierte lokale Zustimmung für windows-resource-context-v1. Daten nur für Operatoren; vom KI-/Provider-Export ausgeschlossen. Keine Änderungen an Zustandsrichtlinien, Speicheraktionen oder Host-Freigaben.',
        reasons: { windows_resource_context_access_denied: 'Zugriff auf Quelle verweigert.', windows_resource_context_unavailable: 'Quelle nicht verfügbar.', windows_resource_context_unsupported_platform: 'Quelle nicht unterstützt.', windows_resource_context_invalid_metadata: 'Quellmetadaten waren ungültig.', windows_resource_context_bounds: 'Erfassungsgrenze der Quelle erreicht.', windows_resource_context_partial_result: 'Einige Quellfelder waren nicht verfügbar.', windows_resource_context_budget_exhausted: 'Zeitlimit der Quelle erreicht.' },
    },
};
export function WindowsResourceContextPanel({ resource }: { resource: WindowsInventoryResource }) {
    const [locale] = useLocale(), c = copy[locale], context = resource.resourceContext;
    if (!context) return <p role="status" className="windows-inventory-empty windows-resource-absent">{resource.resourceContextExpired ? c.expired : resource.resourceContextAhead ? c.ahead : c.absent}</p>;
    const { processors, installedMemory, memory, pagefiles } = context, binding = `${resource.view?.deviceId}:${context.grantId}:${context.generationId}:${context.collectedAt}`, remaining = windowsCommitRemaining(memory);
    const field = (value: WindowsResourceLabel | WindowsResourceCount) => value.quality === 'observed' ? typeof value.value === 'number' ? value.value.toLocaleString(locale) : value.value : c[value.quality];
    const bytes = (value: string | null, quality: 'observed' | 'denied' | 'unavailable') => value === null ? c[quality === 'observed' ? 'unknown' : quality] : windowsResourceBytes(value, locale);
    const rows = (values: (readonly [string, string | null])[]) => <dl>{values.map(([label, value]) => <div key={label}><dt>{label}</dt><dd><bdi>{value}</bdi></dd></div>)}</dl>;
    const sourceGroups = [[c.processorsSource, processors], [c.installedSource, installedMemory], [c.memorySource, memory], [c.pagefilesSource, pagefiles]] as const;
    const exactBytes = [[c.installed, installedMemory.installedBytes], [c.usable, memory.physicalTotalBytes], [c.available, memory.physicalAvailableBytes], [c.committed, memory.commitTotalBytes], [c.limit, memory.commitLimitBytes], [c.remaining, remaining], [c.pageSize, memory.pageSizeBytes], [`${c.pagefiles} · ${c.allocated}`, pagefiles.totalBytes], [`${c.pagefiles} · ${c.inUse}`, pagefiles.totalInUseBytes]] as const;
    return <section className="windows-resource-context" aria-label={c.title}>
        <div className="windows-inventory-section-header"><h3><MemoryStick size={16} aria-hidden="true"/>{c.title}</h3><span className="windows-inventory-times">{c.captured} <time dateTime={context.collectedAt}>{fullDate(context.collectedAt)}</time></span></div>
        {resource.resourceContextStale && <p role="status" className="windows-inventory-caution">{c.stale}</p>}
        <div className="windows-resource-groups">
            <section aria-label={c.cpu}><h4><Cpu size={15} aria-hidden="true"/>{c.cpu}<span>{c[processors.quality]}</span></h4>{rows([[c.model, processors.rows.length ? processors.rows.map(row => field(row.name)).join(' · ') : c[processors.quality]], [c.cores, processors.totalCores === null ? c.unknown : processors.totalCores.toLocaleString(locale)], [c.logical, processors.totalLogicalProcessors === null ? c.unknown : processors.totalLogicalProcessors.toLocaleString(locale)]])}</section>
            <section aria-label={c.ram}><h4>{c.ram}</h4>{rows([[c.installed, bytes(installedMemory.installedBytes, installedMemory.quality)], [c.usable, bytes(memory.physicalTotalBytes, memory.quality)], [c.available, bytes(memory.physicalAvailableBytes, memory.quality)]])}</section>
            <section aria-label={c.commit}><h4>{c.commit}<span>{c[memory.quality]}</span></h4>{rows([[c.committed, bytes(memory.commitTotalBytes, memory.quality)], [c.limit, bytes(memory.commitLimitBytes, memory.quality)], [c.remaining, bytes(remaining, memory.quality)]])}</section>
            <section aria-label={c.pagefiles}><h4>{c.pagefiles}<span>{c[pagefiles.quality]}</span></h4>{pagefiles.count === 0 ? <p className="windows-resource-none">{c.none}</p> : rows([[c.allocated, bytes(pagefiles.totalBytes, pagefiles.quality)], [c.inUse, bytes(pagefiles.totalInUseBytes, pagefiles.quality)]])}</section>
        </div>
        <details className="windows-resource-details" key={binding}><summary>{c.details}</summary>
            {sourceGroups.map(([label, source]) => <p key={source.source}><strong>{label} · {source.source}: </strong>{source.reason ? c.reasons[source.reason] : c.observed}</p>)}
            {processors.rows.map((row, index) => <div className="windows-resource-processor" key={index}><h5>{c.processor} {index + 1}</h5>{rows([[c.model, field(row.name)], [c.architecture, field(row.architecture)], [c.cores, field(row.cores)], [c.logical, field(row.logicalProcessors)]])}</div>)}
            {rows(exactBytes.map(([label, value]) => [label, value === null ? c.unknown : `${value} ${c.bytes}`]))}
            {rows([[c.count, pagefiles.count === null ? c.unknown : pagefiles.count.toLocaleString(locale)]])}
            <p>{c.cpuNote}</p><p>{c.ramNote}</p><p>{c.commitNote}</p><p>{c.pagefilesNote}</p><p>{c.consent}</p>
        </details>
    </section>;
}
