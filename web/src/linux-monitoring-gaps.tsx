import { useId, useState } from 'react';
import { ArrowRight, CircleHelp, Clock3, Eye, HardDrive, Info, Radio, RotateCcw, SearchX, Server, Wrench } from 'lucide-react';
import { useLocale } from './i18n';
import type { HealthKind } from './health-types';
import type { InvestigationsView } from './investigations-types';
import type { Device } from './types';
import './linux-monitoring-gaps.css';

const copy = {
    en: {
        title: 'Linux checks without current evidence', devices: 'devices', checks: 'unknown checks',
        scope: 'Authorized Linux checks only. Independent of incident pages and filters.',
        search: 'Find a Linux monitoring gap', kind: 'Check type', all: 'All check types', offline: 'Agent contact', filesystem: 'Root filesystem /', service: 'Selected service',
        shown: 'Matching devices', reset: 'Clear coverage filters', empty: 'No matching unknown checks.', emptyHint: 'Clear filters to see the remaining gaps.', noGaps: 'No unknown checks in this source view.', noGapsHint: 'This is not a whole-device health verdict.',
        read: 'Source read at', evaluated: 'Original manager evaluation', observed: 'Original source observation', receipt: 'Original accepted-report receipt', unknown: 'Not available',
        review: 'Open Health for', health: 'Open Health', maintenance: 'Maintenance until', noEvaluation: 'No manager evaluation is available for this device.',
        state: 'Unknown checks', readOnly: 'Read only', evidence: 'Original evidence times', details: 'Scope & permissions',
        limits: 'Missing or stale evidence does not prove failure or recovery.',
        permissions: 'Health uses existing permissions. Opening it enables no checks, acknowledges no incidents and runs no actions. Windows and other monitoring sources are not included.',
    },
    de: {
        title: 'Linux-Prüfungen ohne aktuelle Belege', devices: 'Geräte', checks: 'unbekannte Prüfungen',
        scope: 'Nur freigegebene Linux-Prüfungen. Unabhängig von Vorfallseiten und Filtern.',
        search: 'Linux-Prüflücke finden', kind: 'Prüfart', all: 'Alle Prüfarten', offline: 'Agent-Kontakt', filesystem: 'Root-Dateisystem /', service: 'Ausgewählter Dienst',
        shown: 'Passende Geräte', reset: 'Abdeckungsfilter zurücksetzen', empty: 'Keine passenden unbekannten Prüfungen.', emptyHint: 'Filter zurücksetzen, um die übrigen Lücken zu sehen.', noGaps: 'Keine unbekannten Prüfungen in dieser Quellenansicht.', noGapsHint: 'Das ist kein Gesundheitsurteil über das gesamte Gerät.',
        read: 'Quelle abgerufen', evaluated: 'Ursprüngliche Manager-Auswertung', observed: 'Ursprüngliche Quellenbeobachtung', receipt: 'Ursprünglicher Eingang des akzeptierten Berichts', unknown: 'Nicht verfügbar',
        review: 'Health öffnen für', health: 'Health öffnen', maintenance: 'Wartung bis', noEvaluation: 'Für dieses Gerät ist keine Manager-Auswertung verfügbar.',
        state: 'Unbekannte Prüfungen', readOnly: 'Nur lesen', evidence: 'Originale Belegzeiten', details: 'Umfang & Rechte',
        limits: 'Fehlende oder veraltete Belege beweisen weder Ausfall noch Erholung.',
        permissions: 'Health nutzt bestehende Rechte. Das Öffnen aktiviert keine Prüfung, bestätigt keinen Vorfall und führt keine Aktion aus. Windows und andere Überwachungsquellen sind nicht enthalten.',
    },
};
const SEARCH_LIMIT = 160;
const checkIcons = { offline: Radio, filesystem: HardDrive, service: Server };
function ExactTime({ value, fallback }: { value: string | null; fallback: string }) {
    return value ? <time dateTime={value}>{value}</time> : <span>{fallback}</span>;
}

/** The queue supplies only its currently guarded, aged source; no extra reader or snapshot. */
export function LinuxMonitoringGaps({ view, devices }: { view: InvestigationsView; devices: Device[] }) {
    const [locale] = useLocale(), c = copy[locale], label = useId();
    const [query, setQuery] = useState(''), [kind, setKind] = useState<'all' | HealthKind>('all');
    const names = new Map(devices.filter(device => device.platform === 'linux' && device.source === 'lan' && !device.synthetic).map(device => [device.id, device.name]));
    const gaps = view.devices.map(device => ({ device, checks: device.checks.filter(check => device.evaluatedAt === null || check.state === 'unknown') })).filter(row => row.checks.length > 0).sort((a, b) => a.device.deviceId.localeCompare(b.device.deviceId));
    const needle = query.trim().toLowerCase();
    const rows = gaps.map(row => ({ ...row, checks: row.checks.filter(check => (kind === 'all' || check.kind === kind) && [row.device.deviceId, names.get(row.device.deviceId) ?? '', check.target, c[check.kind]].some(value => value.toLowerCase().includes(needle))) })).filter(row => row.checks.length > 0);
    const total = gaps.reduce((sum, row) => sum + row.checks.length, 0), shown = rows.reduce((sum, row) => sum + row.checks.length, 0);
    return <details className="panel linux-monitoring-gaps">
        <summary><CircleHelp size={16} aria-hidden="true" focusable="false"/>{c.title}: <span className="linux-monitoring-gaps-count">{gaps.length} {c.devices} · {total} {c.checks}</span></summary>
        <p className="linux-monitoring-gaps-scope"><span className="linux-monitoring-gaps-badge"><Eye size={14} aria-hidden="true" focusable="false"/>{c.readOnly}</span>{c.scope}</p>
        <p className="linux-monitoring-gaps-notice"><CircleHelp size={16} aria-hidden="true" focusable="false"/>{c.limits}</p>
        <div className="linux-monitoring-gaps-filters">
            <label htmlFor={`${label}-search`}>{c.search}<input id={`${label}-search`} type="search" maxLength={SEARCH_LIMIT} value={query} onChange={event => setQuery(event.target.value.slice(0, SEARCH_LIMIT))}/></label>
            <label htmlFor={`${label}-kind`}>{c.kind}<select id={`${label}-kind`} value={kind} onChange={event => setKind(event.target.value as 'all' | HealthKind)}><option value="all">{c.all}</option>{(['offline', 'filesystem', 'service'] as const).map(value => <option value={value} key={value}>{c[value]}</option>)}</select></label>
            <button className="text-button" type="button" disabled={!query && kind === 'all'} onClick={() => { setQuery(''); setKind('all'); }}><RotateCcw size={14} aria-hidden="true" focusable="false"/>{c.reset}</button>
        </div>
        <p role="status">{c.shown}: {rows.length} / {gaps.length} · {c.checks}: {shown} / {total}</p>
        {rows.length ? <ul className="linux-monitoring-gaps-devices" role="list">{rows.map(({ device, checks }) => <li key={device.deviceId}>
            <div className="linux-monitoring-gaps-device-heading"><h3>{names.get(device.deviceId) || device.deviceId}</h3><span className="linux-monitoring-gaps-badge"><CircleHelp size={14} aria-hidden="true" focusable="false"/>{c.state}</span></div><p className="linux-monitoring-gaps-identity">{device.deviceId}</p>
            {device.evaluatedAt === null && <p>{c.noEvaluation}</p>}
            {device.maintenanceUntil && <p className="linux-monitoring-gaps-maintenance"><Wrench size={14} aria-hidden="true" focusable="false"/>{c.maintenance}: <ExactTime value={device.maintenanceUntil} fallback={c.unknown}/></p>}
            <ul className="linux-monitoring-gaps-checks" role="list">{checks.map(check => { const Icon = checkIcons[check.kind]; return <li key={check.key}><Icon size={16} aria-hidden="true" focusable="false"/><strong>{c[check.kind]}{check.kind === 'service' ? `: ${check.target}` : ''}</strong></li>; })}</ul>
            <a className="linux-monitoring-gaps-health" href={`#/devices/${encodeURIComponent(device.deviceId)}/health`} aria-label={`${c.review} ${names.get(device.deviceId) || device.deviceId} (${device.deviceId})`}>{c.health}<ArrowRight size={14} aria-hidden="true" focusable="false"/></a>
            <details className="linux-monitoring-gaps-evidence">
                <summary><Clock3 size={14} aria-hidden="true" focusable="false"/>{c.evidence}</summary>
                <p>{c.evaluated}: <ExactTime value={device.evaluatedAt} fallback={c.unknown}/></p>
                <ul>{checks.map(check => <li key={check.key}><strong>{c[check.kind]}{check.kind === 'service' ? `: ${check.target}` : ''}</strong><span>{check.kind === 'offline' ? c.receipt : c.observed}: <ExactTime value={check.observedAt} fallback={c.unknown}/></span></li>)}</ul>
            </details>
        </li>)}</ul> : <div className="linux-monitoring-gaps-empty"><SearchX size={20} aria-hidden="true" focusable="false"/><strong>{total ? c.empty : c.noGaps}</strong><p>{total ? c.emptyHint : c.noGapsHint}</p></div>}
        <details className="linux-monitoring-gaps-source"><summary><Info size={14} aria-hidden="true" focusable="false"/>{c.details}</summary><p>{c.read}: <ExactTime value={view.serverNow} fallback={c.unknown}/></p><p>{c.permissions}</p></details>
    </details>;
}
