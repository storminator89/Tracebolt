import { Activity, Check, CheckCircle2, CircleHelp, Clock3, Cpu, HardDrive, MemoryStick, Radio, Settings2, TriangleAlert } from 'lucide-react';
import { useLocale } from './i18n';
import { fullDate, relativeTime } from './utils';
import { validJournalUnit } from './journal-types';
import type { HealthCheck, HealthIncident, HealthKind, HealthView } from './health-types';
import type { Device, Metric } from './types';

export const healthCopy = {
    en: { title: 'Health', clear: 'Monitored checks clear', attention: 'Needs attention', unknown: 'Current status unknown', maintenance: 'Maintenance active', checking: 'Checking health…', unavailable: 'Health checks unavailable', unavailableHint: 'Refresh to check access and current data.', scope: 'Contact · root disk · selected services', noServices: 'No service checks selected', cpu: 'CPU', memory: 'Memory', disk: 'Root disk /', services: 'Services', reading: 'Current reading', stale: 'Stale reading', missing: 'No reading', denied: 'Unavailable', good: 'Within threshold', pending: 'Confirming', open: 'Alert open', unknownCheck: 'Unknown', current: 'Current issues', none: 'No open alerts', choose: 'Choose services', currentChecks: 'Current checks', healthyServices: 'checked services clear', monitored: 'selected', seen: 'Observed', started: 'Started', lastSeen: 'Last observed', contact: 'Agent contact', recentContact: 'Recent report', oldContact: 'Report overdue', unknownContact: 'Contact unknown', waiting: 'Waiting for confirmation', currentUnknown: 'Current state unknown', inspectDisk: 'Review disk usage', inspectContact: 'Check agent connection', inspectService: 'Review service state', inspectUnknown: 'Check the latest report', evidence: 'Show evidence', logs: 'Open logs', ack: 'Acknowledge alert', acknowledged: 'Acknowledged', readingsOnly: 'CPU and memory show usage; no alert rules are configured for them.', empty: 'Waiting for the first health evaluation', configured: 'Checks & settings', history: 'Alert history', details: 'Evidence & check scope', settingsHint: 'Selected services and maintenance', historyEmpty: 'No recorded incidents', maintenanceUntil: 'Until', checked: 'Evaluated', countsOpen: 'open', countsPending: 'confirming', countsUnknown: 'unknown', pause: 'New alerts paused', checkScope: 'Selected checks only', measurementDetails: 'Reading sources', source: 'Source' },
    de: { title: 'Health', clear: 'Überwachte Prüfungen unauffällig', attention: 'Aufmerksamkeit nötig', unknown: 'Aktueller Zustand unbekannt', maintenance: 'Wartung aktiv', checking: 'Health wird geprüft …', unavailable: 'Health-Prüfungen nicht verfügbar', unavailableHint: 'Aktualisieren, um Zugriff und aktuelle Daten zu prüfen.', scope: 'Kontakt · Root-Datenträger · ausgewählte Dienste', noServices: 'Keine Dienstprüfung ausgewählt', cpu: 'CPU', memory: 'Arbeitsspeicher', disk: 'Root-Datenträger /', services: 'Dienste', reading: 'Aktuelle Messung', stale: 'Messung veraltet', missing: 'Keine Messung', denied: 'Nicht verfügbar', good: 'Im Prüfbereich', pending: 'Wird bestätigt', open: 'Warnung offen', unknownCheck: 'Unbekannt', current: 'Aktuelle Hinweise', none: 'Keine offenen Warnungen', choose: 'Dienste auswählen', currentChecks: 'Aktuelle Prüfungen', healthyServices: 'geprüfte Dienste unauffällig', monitored: 'ausgewählt', seen: 'Beobachtet', started: 'Begonnen', lastSeen: 'Zuletzt beobachtet', contact: 'Agent-Kontakt', recentContact: 'Aktuelle Meldung', oldContact: 'Meldung überfällig', unknownContact: 'Kontakt unbekannt', waiting: 'Bestätigung ausstehend', currentUnknown: 'Aktueller Zustand unbekannt', inspectDisk: 'Speicherbelegung prüfen', inspectContact: 'Agent-Verbindung prüfen', inspectService: 'Dienstzustand prüfen', inspectUnknown: 'Letzte Meldung prüfen', evidence: 'Belege ansehen', logs: 'Logs öffnen', ack: 'Warnung bestätigen', acknowledged: 'Bestätigt', readingsOnly: 'CPU und Arbeitsspeicher zeigen die Auslastung; dafür sind keine Alarmregeln eingerichtet.', empty: 'Erste Health-Auswertung steht aus', configured: 'Prüfungen & Einstellungen', history: 'Warnungsverlauf', details: 'Belege & Prüfumfang', settingsHint: 'Dienste und Wartung', historyEmpty: 'Keine gespeicherten Vorfälle', maintenanceUntil: 'Bis', checked: 'Ausgewertet', countsOpen: 'offen', countsPending: 'ausstehend', countsUnknown: 'unbekannt', pause: 'Neue Warnungen pausiert', checkScope: 'Nur ausgewählte Prüfungen', measurementDetails: 'Messquellen', source: 'Quelle' },
};
type Copy = typeof healthCopy.en | typeof healthCopy.de;
export function healthCheckTitle(kind: HealthKind, target: string, locale: 'en' | 'de') { return kind === 'offline' ? healthCopy[locale].contact : kind === 'filesystem' ? healthCopy[locale].disk : target; }

export function healthMetric(metric: Metric | undefined, now: number): { value: number | null; state: 'current' | 'stale' | 'missing' | 'denied' } {
    if (!metric) return { value: null, state: 'missing' };
    if (metric.quality === 'denied') return { value: null, state: 'denied' };
    const at = Date.parse(metric.collectedAt), age = now - at;
    if (metric.quality === 'stale' || Number.isFinite(age) && age > 120000) return { value: null, state: 'stale' };
    if (metric.quality !== 'healthy' || !Number.isFinite(age) || age < 0 || !Number.isFinite(metric.value) || metric.value === null || metric.value < 0 || metric.value > 100 || metric.unit !== '%') return { value: null, state: 'missing' };
    return { value: metric.value, state: 'current' };
}
export function healthDashboardState(view: HealthView) {
    const unresolved = view.incidents.filter(incident => !incident.resolvedAt);
    const open = new Set([...unresolved.map(incident => incident.key), ...view.checks.filter(check => check.state === 'open').map(check => check.key)]).size;
    const pending = view.checks.filter(check => check.state === 'pending').length, unknown = view.checks.filter(check => check.state === 'unknown').length;
    const state = view.status === 'maintenance' ? 'maintenance' : open || pending ? 'attention' : unknown || view.status === 'unknown' || !view.evaluatedAt ? 'unknown' : 'clear';
    return { state, open, pending, unknown, unresolved } as const;
}
function ShortTime({ value, now }: { value: string | null; now: number }) {
    return value ? <time dateTime={value} title={fullDate(value)}>{Number.isFinite(now) ? relativeTime(value, now) : fullDate(value)}</time> : <span>—</span>;
}
function stateText(check: HealthCheck | undefined, c: Copy) { return check?.state === 'ok' ? c.good : check?.state === 'open' ? c.open : check?.state === 'pending' ? c.pending : c.unknownCheck; }
function Usage({ value, locale }: { value: number | null; locale: string }) {
    return <><strong className="health-card-value">{value === null ? '—' : new Intl.NumberFormat(locale, { maximumFractionDigits: 1, minimumFractionDigits: 1 }).format(value)}{value !== null && <span>%</span>}</strong><div className="health-usage-track" aria-hidden="true">{value !== null && <span style={{ width: `${value}%` }}/>}</div></>;
}
export function HealthDashboard({ view, now, device, disabled, onSettings, onEvidence, onAcknowledge, onOpenLogs }: {
    view: HealthView; now: number; device?: Device; disabled: boolean; onSettings: () => void; onEvidence: () => void;
    onAcknowledge: (incident: HealthIncident) => void; onOpenLogs?: (unit: string) => void;
}) {
    const [locale] = useLocale(), c = healthCopy[locale], summary = healthDashboardState(view);
    const source = device?.id === view.deviceId && device.source === 'lan' && !device.synthetic && device.platform === 'linux' ? device : undefined;
    const cpu = healthMetric(source?.cpu, now), memory = healthMetric(source?.memory, now);
    const disk = view.checks.find(check => check.kind === 'filesystem'), contact = view.checks.find(check => check.kind === 'offline'), services = view.checks.filter(check => check.kind === 'service');
    const serviceUnknown = services.filter(check => check.state === 'unknown').length, serviceIssues = services.filter(check => check.state === 'open' || check.state === 'pending').length;
    const serviceState = serviceIssues ? 'open' : serviceUnknown || !services.length ? 'unknown' : 'ok';
    const Icon = summary.state === 'clear' ? CheckCircle2 : summary.state === 'unknown' ? CircleHelp : summary.state === 'maintenance' ? Clock3 : TriangleAlert;
    const issues: { check: HealthCheck; incident?: HealthIncident }[] = [];
    for (const incident of summary.unresolved) {
        const check = view.checks.find(item => item.key === incident.key) ?? { key: incident.key, kind: incident.kind, target: incident.target, state: 'unknown', observedAt: null, value: null };
        issues.push({ check, incident });
    }
    for (const check of view.checks) if (check.state !== 'ok' && !issues.some(issue => issue.check.key === check.key)) issues.push({ check });
    return <>
        <div className={`health-hero health-hero-${summary.state}`} data-health-state={summary.state}>
            <span className="health-hero-icon"><Icon size={25} aria-hidden="true"/></span>
            <div className="health-hero-main"><span className="health-eyebrow">{c.checkScope}</span><h3>{!view.evaluatedAt ? c.empty : c[summary.state]}</h3><p>{c.scope}</p>
                {(summary.open > 0 || summary.pending > 0 || summary.unknown > 0) && <div className="health-counts">{summary.open > 0 && <span>{summary.open} {c.countsOpen}</span>}{summary.pending > 0 && <span>{summary.pending} {c.countsPending}</span>}{summary.unknown > 0 && <span className="neutral">{summary.unknown} {c.countsUnknown}</span>}</div>}
            </div>
            <div className="health-hero-contact"><span><Radio size={14} aria-hidden="true"/>{contact?.state === 'ok' ? c.recentContact : contact?.state === 'open' || contact?.state === 'pending' ? c.oldContact : c.unknownContact}</span><ShortTime value={contact?.observedAt ?? null} now={now}/>{view.maintenanceUntil && <small>{c.maintenanceUntil} <time dateTime={view.maintenanceUntil}>{fullDate(view.maintenanceUntil)}</time></small>}</div>
        </div>
        <ul className="health-cards" aria-label={c.currentChecks}>
            {[{ title: c.cpu, metric: source?.cpu, reading: cpu, Icon: Cpu }, { title: c.memory, metric: source?.memory, reading: memory, Icon: MemoryStick }].map(({ title, metric, reading, Icon: MetricIcon }) => <li className="health-reading-card" key={title}><h4><MetricIcon size={17} aria-hidden="true"/>{title}</h4><Usage value={reading.value} locale={locale}/><span className="health-card-state">{reading.state === 'current' ? c.reading : c[reading.state]}</span><small>{c.seen} · <ShortTime value={metric?.collectedAt && Date.parse(metric.collectedAt) > 0 ? metric.collectedAt : null} now={now}/></small></li>)}
            <li className={`health-reading-card health-reading-${disk?.state ?? 'unknown'}`}><h4><HardDrive size={17} aria-hidden="true"/>{c.disk}</h4><Usage value={disk?.state !== 'unknown' ? disk?.value ?? null : null} locale={locale}/><span className={`health-card-state health-state-${disk?.state ?? 'unknown'}`}>{stateText(disk, c)}</span><small>{c.seen} · <ShortTime value={disk?.observedAt ?? null} now={now}/></small></li>
            <li className={`health-reading-card health-reading-${serviceState}`}><h4><Activity size={17} aria-hidden="true"/>{c.services}</h4><strong className="health-card-value">{services.length ? serviceIssues || serviceUnknown ? `${serviceIssues + serviceUnknown}` : `${services.length}/${services.length}` : '—'}</strong><span className={`health-card-state health-state-${serviceState}`}>{!services.length ? c.noServices : serviceIssues ? c.attention : serviceUnknown ? c.currentUnknown : c.healthyServices}</span><small>{services.length > 0 && `${services.length} ${c.monitored}`}</small><button type="button" className="text-button" onClick={onSettings}><Settings2 size={13} aria-hidden="true"/>{c.choose}</button></li>
        </ul>
        {issues.length > 0 ? <section className="health-issues" aria-label={c.current}><header><h3>{c.current}</h3><span>{issues.length}</span></header><ul>{issues.map(({ check, incident }) => {
            const title = healthCheckTitle(check.kind, check.target, locale), staleOpen = incident && check.state === 'unknown';
            const action = check.state === 'unknown' ? c.inspectUnknown : check.kind === 'filesystem' ? c.inspectDisk : check.kind === 'offline' ? c.inspectContact : c.inspectService;
            return <li key={check.key} className={`health-issue health-issue-${check.state}`}><span className="health-issue-icon">{check.state === 'unknown' ? <CircleHelp size={18} aria-hidden="true"/> : <TriangleAlert size={18} aria-hidden="true"/>}</span><div className="health-issue-main"><strong>{title}</strong><p>{staleOpen ? `${c.open} · ${c.currentUnknown}` : stateText(check, c)}</p><span>{action}</span><small>{incident ? c.started : c.lastSeen} · <ShortTime value={incident?.openedAt ?? check.observedAt} now={now}/></small></div><div className="health-issue-actions">{check.kind === 'service' && onOpenLogs && validJournalUnit(check.target) ? <button type="button" className="button small" onClick={() => onOpenLogs(check.target)} aria-label={`${c.logs}: ${check.target}`}>{c.logs}</button> : <button type="button" className="button small" onClick={onEvidence}>{c.evidence}</button>}{incident && (!incident.acknowledgedAt ? <button type="button" className="text-button" disabled={disabled} onClick={() => onAcknowledge(incident)} aria-label={`${c.ack}: ${title}`}>{c.ack}</button> : <span className="health-acknowledged"><Check size={13} aria-hidden="true"/>{c.acknowledged}</span>)}</div></li>;
        })}</ul></section> : <p className="health-clear-line"><Check size={14} aria-hidden="true"/>{c.none}{view.status === 'maintenance' && <span> · {c.pause}</span>}</p>}
        <p className="health-reading-note">{c.readingsOnly}</p>
    </>;
}
