import { BatteryCharging, CircuitBoard, Monitor } from 'lucide-react';
import { useLocale } from './i18n';
import { fullDate } from './utils';
import type { WindowsInventoryResource } from './windows-inventory-resource';
import { windowsFirmwareDate, type WindowsHardwareField } from './windows-hardware-context-types';
import './windows-hardware-context.css';

const copy = {
    en: {
        title: 'Device', system: 'System', firmware: 'BIOS', chassis: 'Chassis', power: 'Power', captured: 'Captured', observed: 'Observed', partial: 'Partial', denied: 'Access denied', unavailable: 'Unavailable', empty: 'Not reported', unknown: 'Unknown',
        manufacturer: 'Manufacturer', model: 'Model', vendor: 'BIOS vendor', version: 'BIOS version', releaseDate: 'BIOS release date', biosSerial: 'BIOS serial (Win32_BIOS)', chassisSerial: 'Chassis serial (Win32_SystemEnclosure)', ac: 'AC power', battery: 'Battery', charging: 'Charging', percentage: 'Battery level', remaining: 'Estimated time remaining',
        acLine: { online: 'Connected', offline: 'Disconnected', unknown: 'Unknown' }, batteryPresence: { present: 'Present', absent: 'No battery reported', unknown: 'Unknown' }, charge: { yes: 'Yes', no: 'No', unknown: 'Unknown' }, seconds: 's',
        absent: 'Hardware and power context is unavailable for this capture. Separate local approval is required.', stale: 'Stale observation; values describe the original capture.', expired: 'Hardware and power context expired after 24 hours.', ahead: 'Hardware and power context is hidden until its capture time can be verified.',
        details: 'Sources & consent', systemSource: 'System: local Win32_ComputerSystem. Chassis: local Win32_SystemEnclosure; its serial is a physical-asset label.', biosSource: 'BIOS: local Win32_BIOS. Its serial is a source label, not a verified system serial or unique device ID.', powerSource: 'Power: GetSystemPowerStatus. Battery level and remaining time are source estimates. Unknown values do not establish that a battery is absent.', consent: 'Separate local hardware/power approval. Operator-only identifying metadata; excluded from AI/provider export. No hardware changes or power actions.',
        reasons: { windows_hardware_context_access_denied: 'Source access denied.', windows_hardware_context_unavailable: 'Source unavailable.', windows_hardware_context_unsupported_platform: 'Source unsupported.', windows_hardware_context_invalid_metadata: 'Some source metadata was invalid.', windows_hardware_context_bounds: 'Source collection limit reached.', windows_hardware_context_partial_result: 'Some fields were not available.', windows_hardware_context_budget_exhausted: 'Source collection time limit reached.' },
    },
    de: {
        title: 'Gerät', system: 'System', firmware: 'BIOS', chassis: 'Gehäuse', power: 'Stromversorgung', captured: 'Erfasst', observed: 'Beobachtet', partial: 'Teilweise', denied: 'Zugriff verweigert', unavailable: 'Nicht verfügbar', empty: 'Nicht gemeldet', unknown: 'Unbekannt',
        manufacturer: 'Hersteller', model: 'Modell', vendor: 'BIOS-Hersteller', version: 'BIOS-Version', releaseDate: 'BIOS-Veröffentlichung', biosSerial: 'BIOS-Seriennummer (Win32_BIOS)', chassisSerial: 'Gehäuseseriennummer (Win32_SystemEnclosure)', ac: 'Netzstrom', battery: 'Akku', charging: 'Lädt', percentage: 'Akkustand', remaining: 'Geschätzte Restlaufzeit',
        acLine: { online: 'Verbunden', offline: 'Getrennt', unknown: 'Unbekannt' }, batteryPresence: { present: 'Vorhanden', absent: 'Kein Akku gemeldet', unknown: 'Unbekannt' }, charge: { yes: 'Ja', no: 'Nein', unknown: 'Unbekannt' }, seconds: 's',
        absent: 'Für diese Erfassung sind keine Hardware- und Stromdaten verfügbar. Eine separate lokale Zustimmung ist erforderlich.', stale: 'Veraltete Beobachtung; Werte gelten für die ursprüngliche Erfassung.', expired: 'Hardware- und Stromdaten nach 24 Stunden abgelaufen.', ahead: 'Hardware- und Stromdaten bleiben ausgeblendet, bis die Erfassungszeit geprüft werden kann.',
        details: 'Quellen & Zustimmung', systemSource: 'System: lokal über Win32_ComputerSystem. Gehäuse: lokal über Win32_SystemEnclosure; dessen Seriennummer ist eine physische Gerätekennzeichnung.', biosSource: 'BIOS: lokal über Win32_BIOS. Dessen Seriennummer ist eine Quellangabe, keine geprüfte Systemseriennummer oder eindeutige Geräte-ID.', powerSource: 'Stromversorgung: GetSystemPowerStatus. Akkustand und Restlaufzeit sind Schätzwerte der Quelle. Unbekannte Werte belegen keinen fehlenden Akku.', consent: 'Separate lokale Zustimmung zu Hardware- und Stromdaten. Identifizierende Metadaten nur für Operatoren; vom KI-/Provider-Export ausgeschlossen. Keine Hardwareänderungen oder Energieaktionen.',
        reasons: { windows_hardware_context_access_denied: 'Zugriff auf Quelle verweigert.', windows_hardware_context_unavailable: 'Quelle nicht verfügbar.', windows_hardware_context_unsupported_platform: 'Quelle nicht unterstützt.', windows_hardware_context_invalid_metadata: 'Einige Quellmetadaten waren ungültig.', windows_hardware_context_bounds: 'Erfassungsgrenze der Quelle erreicht.', windows_hardware_context_partial_result: 'Einige Felder waren nicht verfügbar.', windows_hardware_context_budget_exhausted: 'Zeitlimit der Quelle erreicht.' },
    },
};
export function WindowsHardwareContextPanel({ resource }: { resource: WindowsInventoryResource }) {
    const [locale] = useLocale(), c = copy[locale], context = resource.hardwareContext;
    if (!context) return <p role="status" className="windows-inventory-empty">{resource.hardwareContextExpired ? c.expired : resource.hardwareContextAhead ? c.ahead : c.absent}</p>;
    const { system, firmware, chassis, power } = context, binding = `${resource.view?.deviceId}:${context.grantId}:${context.generationId}:${context.collectedAt}`;
    const field = (value: WindowsHardwareField) => value.quality === 'observed' ? value.value : c[value.quality];
    const releaseDate = firmware.releaseDate.quality === 'observed' ? windowsFirmwareDate(firmware.releaseDate.value) ?? c.unknown : field(firmware.releaseDate);
    const groups = [
        { key: 'system', label: c.system, icon: Monitor, source: system, rows: [[c.manufacturer, field(system.manufacturer)], [c.model, field(system.model)]] },
        { key: 'chassis', label: c.chassis, icon: Monitor, source: chassis, rows: [[c.chassisSerial, field(chassis.serialNumber)]] },
        { key: 'firmware', label: c.firmware, icon: CircuitBoard, source: firmware, rows: [[c.vendor, field(firmware.vendor)], [c.version, field(firmware.version)], [c.releaseDate, releaseDate]] },
        { key: 'power', label: c.power, icon: BatteryCharging, source: power, rows: [[c.ac, c.acLine[power.acLineStatus]], [c.battery, c.batteryPresence[power.batteryPresence]], [c.charging, c.charge[power.charging]], [c.percentage, power.batteryPercent === null ? c.unknown : `${power.batteryPercent}%`], [c.remaining, power.estimatedSeconds === null ? c.unknown : `${power.estimatedSeconds.toLocaleString(locale)} ${c.seconds}`]] },
    ];
    return <section className="windows-hardware-context" aria-label={c.title}>
        <div className="windows-inventory-section-header"><h3>{c.title}</h3><span className="windows-inventory-times">{c.captured} <time dateTime={context.collectedAt}>{fullDate(context.collectedAt)}</time></span></div>
        {resource.hardwareContextStale && <p role="status" className="windows-inventory-caution">{c.stale}</p>}
        <div className="windows-hardware-groups">{groups.map(({ key, label, icon: Icon, source, rows }) => <section className={`windows-hardware-group windows-hardware-${key}`} aria-label={label} key={key}>
            <div className="windows-hardware-heading"><h4><Icon size={16} aria-hidden="true"/>{label}</h4><span className="windows-hardware-quality">{c[source.quality]}</span></div>
            <dl>{rows.map(([label, value]) => <div key={label}><dt>{label}</dt><dd><bdi>{value}</bdi></dd></div>)}</dl>
        </section>)}</div>
        <details className="windows-hardware-details" key={binding}><summary>{c.details}</summary>
            <dl><div><dt>{c.biosSerial}</dt><dd><bdi>{field(firmware.serialNumber)}</bdi></dd></div></dl>
            {groups.map(({ key, label, source }) => <p key={key}><strong>{label}: </strong>{source.reason ? c.reasons[source.reason] : c.observed}</p>)}
            <p>{c.systemSource}</p><p>{c.biosSource}</p><p>{c.powerSource}</p><p>{c.consent}</p>
        </details>
    </section>;
}
