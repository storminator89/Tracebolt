import { useEffect, useMemo, useState } from 'react';
import { useLocale } from './i18n';
import { summarizeResource, type HistoryInterval, type ResourceSummary } from './resource-history-analysis';
import type { ResourceHistory, ResourceKey } from './resource-history-types';

const copy = {
    en: { title: 'Sample statistics', current: 'Selected interval', previous: 'Previous equal interval', metric: 'Resource', count: 'Usable samples', coverage: 'Minute buckets with usable samples', minimum: 'Minimum', median: 'Median', p95: '95th percentile', maximum: 'Maximum', gap: 'Longest gap including interval edges', change: 'Median difference', none: 'No usable samples', minutes: 'min', points: 'percentage points', note: 'Statistics describe retained samples, not time-weighted load, continuous coverage or health. Missing samples are not zero. Percentile uses the nearest-rank method; repeated original timestamps count once. Differences do not establish a cause or improvement.', buckets: 'Partial edge minutes are included in the bucket count. A gap includes the interval edges and does not reconstruct missing measurements.', withheld: 'Conflicting original timestamps withheld', repeats: 'Repeated timestamps ignored', unavailable: 'Unavailable observations', reports: 'Retained reports in interval', bounds: 'Exact UTC interval', disk: 'Root filesystem usage', windowsDisk: 'System-volume usage', memory: 'Memory usage', cpu: 'CPU usage' },
    de: { title: 'Messwertstatistik', current: 'Ausgewählter Zeitraum', previous: 'Vorheriger gleich langer Zeitraum', metric: 'Ressource', count: 'Verwendbare Messwerte', coverage: 'Minuten mit verwendbaren Messwerten', minimum: 'Minimum', median: 'Median', p95: '95. Perzentil', maximum: 'Maximum', gap: 'Größte Lücke einschließlich Zeitraumrändern', change: 'Median-Differenz', none: 'Keine verwendbaren Messwerte', minutes: 'Min.', points: 'Prozentpunkte', note: 'Die Statistik beschreibt gespeicherte Messwerte, keine zeitgewichtete Last, lückenlose Abdeckung oder Gesundheit. Fehlende Messwerte sind keine Null. Das Perzentil nutzt die Nächster-Rang-Methode; wiederholte Originalzeitpunkte zählen einmal. Differenzen belegen weder Ursache noch Verbesserung.', buckets: 'Angebrochene Randminuten zählen mit. Eine Lücke schließt die Zeitraumränder ein und rekonstruiert keine fehlenden Messwerte.', withheld: 'Widersprüchliche Originalzeitpunkte ausgelassen', repeats: 'Wiederholte Zeitpunkte ignoriert', unavailable: 'Nicht verfügbare Beobachtungen', reports: 'Gespeicherte Meldungen im Zeitraum', bounds: 'Exakter UTC-Zeitraum', disk: 'Belegung des Root-Dateisystems', windowsDisk: 'Belegung des Systemvolumes', memory: 'Speicherbelegung', cpu: 'CPU-Auslastung' },
};

export function ResourceHistorySummary({ view, current, previous, platform }: { view: ResourceHistory; current: HistoryInterval; previous: HistoryInterval | null; platform?: 'windows' }) {
    const [locale] = useLocale(), c = copy[locale], [open, setOpen] = useState(false), comparing = previous !== null;
    useEffect(() => { if (comparing) setOpen(true); }, [comparing]);
    const rows = useMemo(() => (['cpu', 'memory', 'disk'] as const).map(key => ({ key, current: summarizeResource(view, key, current), previous: previous ? summarizeResource(view, key, previous) : null })), [view, current, previous]);
    const number = (value: number) => new Intl.NumberFormat(locale, { maximumFractionDigits: 1 }).format(value);
    const percent = (value: number | null) => value === null ? '—' : `${number(value)}%`;
    const name = (key: ResourceKey) => key === 'cpu' ? c.cpu : key === 'memory' ? c.memory : platform === 'windows' ? c.windowsDisk : c.disk;
    const bounds = (interval: HistoryInterval) => <span className="resource-summary-bounds"><time dateTime={interval.start}>{interval.start}</time> ≤ t {interval.endInclusive ? '≤' : '<'} <time dateTime={interval.end}>{interval.end}</time></span>;
    const stats = (summary: ResourceSummary) => <dl>
        <div><dt>{c.count}</dt><dd>{summary.usable}</dd></div>
        <div><dt>{c.coverage}</dt><dd>{summary.minuteBuckets} / {summary.expectedBuckets}</dd></div>
        <div><dt>{c.minimum}</dt><dd>{percent(summary.minimum)}</dd></div>
        <div><dt>{c.median}</dt><dd>{percent(summary.median)}</dd></div>
        <div><dt>{c.p95}</dt><dd>{percent(summary.p95)}</dd></div>
        <div><dt>{c.maximum}</dt><dd>{percent(summary.maximum)}</dd></div>
        <div><dt>{c.gap}</dt><dd>{number(summary.longestGapMs / 60000)} {c.minutes}</dd></div>
        <div><dt>{c.reports}</dt><dd>{summary.reports}</dd></div>
        {summary.unavailable > 0 && <div><dt>{c.unavailable}</dt><dd>{summary.unavailable}</dd></div>}
        {summary.repeated > 0 && <div><dt>{c.repeats}</dt><dd>{summary.repeated}</dd></div>}
        {summary.conflicts > 0 && <div><dt>{c.withheld}</dt><dd>{summary.conflicts}</dd></div>}
    </dl>;
    return <details className="resource-history-summary" open={open}><summary onClick={event => { event.preventDefault(); setOpen(value => !value); }}>{c.title}</summary>{open && <><p>{c.note}</p>
        <div className="resource-summary-period"><strong>{c.current}</strong>{bounds(current)}</div>
        {previous && <div className="resource-summary-period"><strong>{c.previous}</strong>{bounds(previous)}</div>}
        <div className="resource-summary-grid">{rows.map(row => <section key={row.key} aria-label={name(row.key)}><h4>{name(row.key)}</h4><h5>{c.current}</h5>{row.current.usable === 0 && <p>{c.none}</p>}{stats(row.current)}
            {row.previous && <><h5>{c.previous}</h5>{row.previous.usable === 0 && <p>{c.none}</p>}{stats(row.previous)}<p className="resource-summary-change"><strong>{c.change}: </strong>{row.current.median === null || row.previous.median === null ? '—' : `${row.current.median - row.previous.median > 0 ? '+' : ''}${number(row.current.median - row.previous.median)} ${c.points}`}</p></>}
        </section>)}</div><p>{c.buckets}</p>
    </>}</details>;
}
