import { Gauge } from 'lucide-react';
import { useLocale } from './i18n';
import { fullDate } from './utils';
import { inventoryAge } from './complete-packages-types';
import type { WindowsInventoryResource } from './windows-inventory-resource';
import { windowsStorageIOMetricKeys, type WindowsStorageIOMetric, type WindowsStorageIOReason } from './windows-storage-io-types';
import './windows-storage-io.css';

const copy = {
    en: {
        title: 'Disk I/O · PerfDisk aggregate', absent: 'No disk I/O sample reported for this capture.', expired: 'Disk I/O capture expired after 24 hours.', ahead: 'Disk I/O is hidden until its sample time can be verified.', stale: 'Stale sample; values describe the original window.',
        captured: 'Captured', sample: 'Sample window', age: 'Sample age', seconds: 's', throughput: 'Throughput', operations: 'Operations', latency: 'Average latency', queue: 'Requests', read: 'Read', write: 'Write', average: 'Average queue length', current: 'Outstanding at sample end', including: 'Includes requests in service', ops: 'ops/s', requests: 'requests', observed: 'Observed', partial: 'Partial', denied: 'Access denied', unavailable: 'Unavailable', idle: 'Idle · no operations', details: 'Disk I/O sources & limits', source: 'Source',
        note: 'The PerfDisk _Total aggregate is a provider-wide sample. It does not identify individual disks, establish complete backing-device coverage, or guarantee a stable device population during hot-plug.',
        window: 'Rates and average queue length describe the displayed query-call interval. Latency is milliseconds per completed operation; idle latency is undefined. Outstanding requests is an instantaneous sample-end count, including requests being serviced.',
        boundary: 'No join to drive letters, volumes or MSFT_PhysicalDisk. These observations do not assess storage health or pressure. Private operator context; excluded from AI/export and action paths.',
        reasons: { windows_storage_io_access_denied: 'Access denied', windows_storage_io_unavailable: 'Source unavailable', windows_storage_io_unsupported_platform: 'Source unsupported', windows_storage_io_invalid_metadata: 'Invalid source metadata', windows_storage_io_bounds: 'Source limit reached', windows_storage_io_partial_result: 'Some counters unavailable', windows_storage_io_budget_exhausted: 'Sample time limit reached', windows_storage_io_counter_missing: 'Counter unavailable', windows_storage_io_counter_reset: 'Counter reset', windows_storage_io_invalid_timebase: 'Invalid sample timebase', windows_storage_io_idle: 'Idle · no operations' },
    },
    de: {
        title: 'Datenträger-I/O · PerfDisk gesamt', absent: 'Für diese Erfassung wurde keine Datenträger-I/O-Messung gemeldet.', expired: 'Datenträger-I/O-Erfassung nach 24 Stunden abgelaufen.', ahead: 'Datenträger-I/O bleibt bis zur Prüfung der Messzeit ausgeblendet.', stale: 'Veraltete Messung; Werte gelten für das ursprüngliche Zeitfenster.',
        captured: 'Erfasst', sample: 'Messfenster', age: 'Alter der Messung', seconds: 's', throughput: 'Durchsatz', operations: 'Operationen', latency: 'Mittlere Latenz', queue: 'Anfragen', read: 'Lesen', write: 'Schreiben', average: 'Mittlere Warteschlangenlänge', current: 'Am Messende ausstehend', including: 'Einschließlich Anfragen in Bearbeitung', ops: 'Vorgänge/s', requests: 'Anfragen', observed: 'Beobachtet', partial: 'Teilweise', denied: 'Zugriff verweigert', unavailable: 'Nicht verfügbar', idle: 'Inaktiv · keine Vorgänge', details: 'Datenträger-I/O: Quellen & Grenzen', source: 'Quelle',
        note: 'Das PerfDisk-Aggregat _Total ist eine providerweite Messung. Es identifiziert keine einzelnen Datenträger, belegt keine vollständige Erfassung der zugrunde liegenden Geräte und garantiert bei Hot-Plug keine unveränderte Geräteauswahl.',
        window: 'Raten und mittlere Warteschlangenlänge gelten für das angezeigte Abfrageintervall. Die Latenz wird in Millisekunden pro abgeschlossenem Vorgang angegeben; ohne Vorgänge ist sie nicht definiert. Ausstehende Anfragen sind eine Momentaufnahme am Messende, einschließlich Anfragen in Bearbeitung.',
        boundary: 'Keine Zuordnung zu Laufwerksbuchstaben, Volumes oder MSFT_PhysicalDisk. Diese Beobachtungen bewerten weder Speicherzustand noch Überlastung. Private Operatordaten; von KI/Export und Aktionen ausgeschlossen.',
        reasons: { windows_storage_io_access_denied: 'Zugriff verweigert', windows_storage_io_unavailable: 'Quelle nicht verfügbar', windows_storage_io_unsupported_platform: 'Quelle nicht unterstützt', windows_storage_io_invalid_metadata: 'Ungültige Quellmetadaten', windows_storage_io_bounds: 'Erfassungsgrenze erreicht', windows_storage_io_partial_result: 'Einige Zähler nicht verfügbar', windows_storage_io_budget_exhausted: 'Messzeitlimit erreicht', windows_storage_io_counter_missing: 'Zähler nicht verfügbar', windows_storage_io_counter_reset: 'Zähler zurückgesetzt', windows_storage_io_invalid_timebase: 'Ungültige Messzeitbasis', windows_storage_io_idle: 'Inaktiv · keine Vorgänge' },
    },
};
export function WindowsStorageIOPanel({ resource }: { resource: WindowsInventoryResource }) {
    const [locale] = useLocale(), c = copy[locale], context = resource.storageIO;
    if (!context) return <p role="status" className="windows-inventory-empty windows-storage-io-absent">{resource.storageIOExpired ? c.expired : resource.storageIOAhead ? c.ahead : c.absent}</p>;
    const p = context.perfDisk, binding = `${resource.view?.deviceId}:${context.grantId}:${context.generationId}:${context.collectedAt}`;
    const reason = (value: WindowsStorageIOReason) => value ? c.reasons[value] : c.observed;
    const number = (value: number) => value.toLocaleString(locale, { maximumFractionDigits: 3 });
    // Retain tiny positive values rather than rounding them into a false zero.
    const precise = (value: number) => value > 0 && value < 0.001 ? value.toLocaleString(locale, { notation: 'scientific', maximumFractionDigits: 3 }) : number(value);
    const metric = (m: WindowsStorageIOMetric, unit: string, multiplier = 1) => {
        if (m.value === null) return <span className="windows-storage-io-missing">{reason(m.reason)}</span>;
        // Avoid overflow when displaying an otherwise finite source value in ms.
        const value = m.value * multiplier;
        return <bdi>{Number.isFinite(value) ? precise(value) : `${precise(m.value)} × ${multiplier}`} {unit}</bdi>;
    };
    const rows = (items: [string, WindowsStorageIOMetric, string, number?][]) => <dl>{items.map(([label, m, unit, multiplier]) => <div key={label}><dt>{label}</dt><dd>{metric(m, unit, multiplier)}</dd></div>)}</dl>;
    const sampleAge = resource.view && p.sampleEndedAt ? inventoryAge(resource.view.serverNow, p.sampleEndedAt) + resource.elapsedMS : null;
    return <section className="windows-storage-io" aria-label={c.title}>
        <div className="windows-inventory-section-header"><h3><Gauge size={16} aria-hidden="true"/>{c.title}</h3><span className="windows-storage-io-quality">{c[p.quality]}</span></div>
        <div className="windows-storage-io-window">{p.sampleStartedAt && p.sampleEndedAt ? <><span>{c.sample}: <time dateTime={p.sampleStartedAt}>{fullDate(p.sampleStartedAt)}</time> → <time dateTime={p.sampleEndedAt}>{fullDate(p.sampleEndedAt)}</time> · {number(p.intervalMilliseconds! / 1000)} {c.seconds}</span><span>{c.age}: {sampleAge !== null && sampleAge >= 0 ? `${number(Math.floor(sampleAge / 1000))} ${c.seconds}` : c.unavailable}</span></> : <span>{c.captured}: <time dateTime={context.collectedAt}>{fullDate(context.collectedAt)}</time> · {reason(p.reason)}</span>}</div>
        {resource.storageIOStale && <p role="status" className="windows-inventory-caution">{c.stale}</p>}
        <div className="windows-storage-io-groups">
            <section aria-label={c.throughput}><h4>{c.throughput}</h4>{rows([[c.read, p.readBytesPerSecond, 'B/s'], [c.write, p.writeBytesPerSecond, 'B/s']])}</section>
            <section aria-label={c.operations}><h4>{c.operations}</h4>{rows([[c.read, p.readOperationsPerSecond, c.ops], [c.write, p.writeOperationsPerSecond, c.ops]])}</section>
            <section aria-label={c.latency}><h4>{c.latency}</h4>{rows([[c.read, p.readLatencySeconds, 'ms', 1000], [c.write, p.writeLatencySeconds, 'ms', 1000]])}</section>
            <section aria-label={c.queue}><h4>{c.queue}</h4>{rows([[c.average, p.averageQueueLength, c.requests], [c.current, p.currentQueueLength, c.requests]])}<p className="windows-storage-io-including">{c.including}</p></section>
        </div>
        <details className="windows-storage-io-details" key={binding}><summary>{c.details}</summary><p>{c.source}: {p.source}</p><p>{c.note}</p><p>{c.window}</p><p>{c.boundary}</p><dl>{windowsStorageIOMetricKeys.map(k => <div key={k}><dt>{k}</dt><dd><bdi>{p[k].value === null ? reason(p[k].reason) : String(p[k].value)}</bdi></dd></div>)}</dl></details>
    </section>;
}
