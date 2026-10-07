import { useId, useMemo, useState } from 'react';
import { useOperator } from './auth';
import { useLocale } from './i18n';
import { fullDate } from './utils';
import { useResourceHistory } from './resource-history-resource';
import { resourceSegments, type ResourceHistory, type ResourceKey, type ResourceMetric } from './resource-history-types';
import './resource-history.css';

const copy = {
    en: { title: 'Last 24 hours', memory: 'Memory', disk: 'Root filesystem', empty: 'History will appear as reports arrive.', unknown: 'No valid measurements in this period', loading: 'Loading history…', unavailable: 'History is unavailable.', invalid: 'History could not be verified. Refresh to try again.', session: 'Sign in again to view history.', retry: 'Retry', revoked: 'Device revoked', expired: 'Device certificate expired', not_configured: 'History is unavailable for this enrollment.', detail: 'About this history', note: 'Last accepted sample per minute; gaps mean missing data. Recording starts with reports after this update.', diskNote: 'Root filesystem usage, not disk activity.', keyboard: 'Use the left and right arrow keys to inspect measurements.', gap: 'No measurement', valid: 'observations', now: 'Now' },
    de: { title: 'Letzte 24 Stunden', memory: 'Arbeitsspeicher', disk: 'Root-Dateisystem', empty: 'Der Verlauf entsteht mit eingehenden Meldungen.', unknown: 'Keine gültigen Messungen in diesem Zeitraum', loading: 'Verlauf wird geladen …', unavailable: 'Verlauf nicht verfügbar.', invalid: 'Verlauf konnte nicht geprüft werden. Erneut versuchen.', session: 'Zum Anzeigen des Verlaufs erneut anmelden.', retry: 'Erneut versuchen', revoked: 'Gerät widerrufen', expired: 'Gerätezertifikat abgelaufen', not_configured: 'Verlauf für diese Registrierung nicht verfügbar.', detail: 'Hinweise zum Verlauf', note: 'Letzte akzeptierte Messung pro Minute; Lücken bedeuten fehlende Daten. Aufzeichnung ab den Meldungen nach diesem Update.', diskNote: 'Belegung des Root-Dateisystems, keine Datenträgeraktivität.', keyboard: 'Mit den Pfeiltasten links und rechts Messungen prüfen.', gap: 'Keine Messung', valid: 'Messungen', now: 'Jetzt' },
};
const W = 360, H = 154, LEFT = 29, RIGHT = 7, TOP = 12, BOTTOM = 25, width = W - LEFT - RIGHT, height = H - TOP - BOTTOM;
function ResourceChart({ view, metric, label }: { view: ResourceHistory; metric: ResourceKey; label: string }) {
    const [locale] = useLocale(), c = copy[locale], description = useId(), [selected, setSelected] = useState<ResourceMetric | null>(null);
    const segments = useMemo(() => resourceSegments(view, metric), [view, metric]), points = useMemo(() => segments.flat(), [segments]);
    const start = Date.parse(view.windowStart), end = Date.parse(view.serverNow), x = (at: string) => LEFT + (Date.parse(at) - start) / (end - start) * width, y = (value: number) => TOP + (100 - value) / 100 * height;
    const sample = selected && points.find(point => point.collectedAt === selected.collectedAt) || null;
    const time = (at: number) => new Intl.DateTimeFormat(locale, { hour: '2-digit', minute: '2-digit' }).format(at);
    const line = (segment: ResourceMetric[]) => segment.map((point, i) => `${i ? 'L' : 'M'}${x(point.collectedAt).toFixed(2)},${y(point.value!).toFixed(2)}`).join(' ');
    return <figure className={`resource-history-chart ${metric}`}><figcaption><span>{label}</span><span className="resource-history-unit">%</span></figcaption>
        <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label={`${label} · ${c.title}. ${points.length} ${c.valid}. ${c.keyboard}`} aria-describedby={description} tabIndex={points.length ? 0 : undefined}
            onPointerMove={event => { const rect = event.currentTarget.getBoundingClientRect(), target = start + (((event.clientX - rect.left) / rect.width * W - LEFT) / width) * (end - start); const nearest = points.reduce<ResourceMetric | null>((best, point) => !best || Math.abs(Date.parse(point.collectedAt) - target) < Math.abs(Date.parse(best.collectedAt) - target) ? point : best, null); setSelected(nearest && Math.abs(Date.parse(nearest.collectedAt) - target) <= 120000 ? nearest : null); }}
            onPointerLeave={() => setSelected(null)} onBlur={() => setSelected(null)} onKeyDown={event => { if (!points.length || !['ArrowLeft', 'ArrowRight', 'Home', 'End', 'Escape'].includes(event.key)) return; event.preventDefault(); if (event.key === 'Escape') { setSelected(null); return; } const index = sample ? points.indexOf(sample) : points.length; setSelected(points[event.key === 'Home' ? 0 : event.key === 'End' ? points.length - 1 : event.key === 'ArrowLeft' ? Math.max(0, index - 1) : Math.min(points.length - 1, index + 1)]); }}>
            {[0, 50, 100].map(value => <g key={value} className="resource-chart-grid"><line x1={LEFT} x2={W - RIGHT} y1={y(value)} y2={y(value)}/><text x={LEFT - 7} y={y(value) + 3} textAnchor="end">{value}</text></g>)}
            {[0, .25, .5, .75, 1].map(fraction => <text className="resource-chart-time" key={fraction} x={LEFT + fraction * width} y={H - 5} textAnchor={fraction === 0 ? 'start' : fraction === 1 ? 'end' : 'middle'}>{time(start + fraction * (end - start))}</text>)}
            {segments.map((segment, index) => <g key={index}>{segment.length > 1 && <path className="resource-chart-area" d={`${line(segment)} L${x(segment.at(-1)!.collectedAt)},${y(0)} L${x(segment[0].collectedAt)},${y(0)} Z`}/>}<path className="resource-chart-line" d={line(segment)}/>{segment.length === 1 && <circle className="resource-chart-dot" cx={x(segment[0].collectedAt)} cy={y(segment[0].value!)} r={2.7}/>}</g>)}
            {sample && <g><line className="resource-chart-cursor" x1={x(sample.collectedAt)} x2={x(sample.collectedAt)} y1={TOP} y2={y(0)}/><circle className="resource-chart-dot" cx={x(sample.collectedAt)} cy={y(sample.value!)} r={3.5}/></g>}
        </svg>
        {!points.length && <span className="resource-chart-empty">{c.unknown}</span>}
        <div id={description} className={`resource-chart-inspection ${sample ? 'visible' : ''}`} aria-live="polite">{sample ? <><strong>{new Intl.NumberFormat(locale, { maximumFractionDigits: 1 }).format(sample.value!)}%</strong><time dateTime={sample.collectedAt}>{fullDate(sample.collectedAt)}</time></> : <span>{c.keyboard}</span>}</div>
    </figure>;
}
export function ResourceHistoryCharts({ deviceId, sessionKey, ready, platform }: { deviceId: string; sessionKey: string | null; ready: boolean; platform?: 'windows' }) {
    const operator = useOperator(), [locale] = useLocale(), c = copy[locale];
    const enabled = ready && operator?.mode === 'lan' && operator.authenticated;
    const { view, loading, error, retry } = useResourceHistory(deviceId, sessionKey, Boolean(enabled));
    if (operator?.mode !== 'lan' || !operator.authenticated) return null;
    return <section className="resource-history" aria-label={c.title} aria-busy={loading}>
        <header><h3>{c.title}</h3></header>
        {error ? <div className="resource-history-message" role="status"><span>{c[error]}</span>{error !== 'session' && <button type="button" className="text-button" onClick={retry}>{c.retry}</button>}</div> : !view ? <p className="resource-history-message" role="status">{c.loading}</p> : ['revoked', 'expired', 'not_configured'].includes(view.status) ? <p className="resource-history-message" role="status">{c[view.status as 'revoked' | 'expired' | 'not_configured']}</p> : <><div className="resource-history-grid">{(['cpu', 'memory', 'disk'] as const).map(metric => <ResourceChart key={metric} view={view} metric={metric} label={metric === 'cpu' ? 'CPU' : metric === 'disk' && platform === 'windows' ? locale === 'de' ? 'Systemvolume' : 'System volume' : c[metric]}/>)}</div>{view.status === 'awaiting' && <p className="resource-history-message">{c.empty}</p>}</>}
        <details className="resource-history-note"><summary>{c.detail}</summary><p>{c.note}</p><p>{platform === 'windows' ? locale === 'de' ? 'Belegung des Windows-Systemvolumes, keine Datenträgeraktivität.' : 'Windows system-volume usage, not disk activity.' : c.diskNote}</p></details>
    </section>;
}
