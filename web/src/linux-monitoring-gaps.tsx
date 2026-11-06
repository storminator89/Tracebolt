import { useId, useState } from 'react';
import { useLocale } from './i18n';
import type { HealthKind } from './health-types';
import type { InvestigationsView } from './investigations-types';
import type { Device } from './types';
import './linux-monitoring-gaps.css';

const copy = {
    en: {
        title: 'Linux checks without current evidence', devices: 'devices', checks: 'unknown checks',
        scope: 'Review the existing Linux Health checks even when no incident is open. This list uses current authorized Linux source coverage, independently of the incident pages and their filters. Windows and other monitoring sources are not included.',
        search: 'Find a Linux monitoring gap', kind: 'Check type', all: 'All check types', offline: 'Agent contact', filesystem: 'Root filesystem /', service: 'Selected service',
        shown: 'Matching devices', reset: 'Clear coverage filters', empty: 'No matching unknown checks in this source view. Clear these filters to review the remaining gaps.',
        read: 'Source read at', evaluated: 'Original manager evaluation', observed: 'Original source observation', receipt: 'Original accepted-report receipt', unknown: 'Not available',
        review: 'Open Health for', maintenance: 'Maintenance until', noEvaluation: 'No manager evaluation is available for this device.',
        limits: 'Missing or stale evidence is not proof of a device failure or recovery. Opening Health uses its existing permissions and does not enable a check, acknowledge an incident or run an action.',
    },
    de: {
        title: 'Linux-Prüfungen ohne aktuelle Belege', devices: 'Geräte', checks: 'unbekannte Prüfungen',
        scope: 'Bestehende Linux-Health-Prüfungen auch ohne offenen Vorfall prüfen. Diese Liste nutzt die aktuelle freigegebene Linux-Quellenabdeckung, unabhängig von den Vorfallseiten und deren Filtern. Windows und andere Überwachungsquellen sind nicht enthalten.',
        search: 'Linux-Prüflücke finden', kind: 'Prüfart', all: 'Alle Prüfarten', offline: 'Agent-Kontakt', filesystem: 'Root-Dateisystem /', service: 'Ausgewählter Dienst',
        shown: 'Passende Geräte', reset: 'Abdeckungsfilter zurücksetzen', empty: 'Keine passenden unbekannten Prüfungen in dieser Quellenansicht. Filter zurücksetzen, um die übrigen Lücken zu prüfen.',
        read: 'Quelle abgerufen', evaluated: 'Ursprüngliche Manager-Auswertung', observed: 'Ursprüngliche Quellenbeobachtung', receipt: 'Ursprünglicher Eingang des akzeptierten Berichts', unknown: 'Nicht verfügbar',
        review: 'Health öffnen für', maintenance: 'Wartung bis', noEvaluation: 'Für dieses Gerät ist keine Manager-Auswertung verfügbar.',
        limits: 'Fehlende oder veraltete Belege beweisen weder Geräteausfall noch Erholung. Health verwendet bestehende Rechte; das Öffnen aktiviert keine Prüfung, bestätigt keinen Vorfall und führt keine Aktion aus.',
    },
};
const SEARCH_LIMIT = 160;
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
        <summary>{c.title}: {gaps.length} {c.devices} · {total} {c.checks}</summary>
        <p>{c.scope}</p><p>{c.read}: <ExactTime value={view.serverNow} fallback={c.unknown}/></p>
        <div className="linux-monitoring-gaps-filters">
            <label htmlFor={`${label}-search`}>{c.search}<input id={`${label}-search`} type="search" maxLength={SEARCH_LIMIT} value={query} onChange={event => setQuery(event.target.value.slice(0, SEARCH_LIMIT))}/></label>
            <label htmlFor={`${label}-kind`}>{c.kind}<select id={`${label}-kind`} value={kind} onChange={event => setKind(event.target.value as 'all' | HealthKind)}><option value="all">{c.all}</option>{(['offline', 'filesystem', 'service'] as const).map(value => <option value={value} key={value}>{c[value]}</option>)}</select></label>
            <button className="text-button" type="button" disabled={!query && kind === 'all'} onClick={() => { setQuery(''); setKind('all'); }}>{c.reset}</button>
        </div>
        <p role="status">{c.shown}: {rows.length} / {gaps.length} · {c.checks}: {shown} / {total}</p>
        {rows.length ? <ul className="linux-monitoring-gaps-devices">{rows.map(({ device, checks }) => <li key={device.deviceId}>
            <h3>{names.get(device.deviceId) || device.deviceId}</h3><p>{device.deviceId}</p>
            <p>{c.evaluated}: <ExactTime value={device.evaluatedAt} fallback={c.unknown}/></p>
            {device.evaluatedAt === null && <p>{c.noEvaluation}</p>}
            {device.maintenanceUntil && <p>{c.maintenance}: <ExactTime value={device.maintenanceUntil} fallback={c.unknown}/></p>}
            <ul>{checks.map(check => <li key={check.key}><strong>{c[check.kind]}{check.kind === 'service' ? `: ${check.target}` : ''}</strong><span>{check.kind === 'offline' ? c.receipt : c.observed}: <ExactTime value={check.observedAt} fallback={c.unknown}/></span></li>)}</ul>
            <a href={`#/devices/${encodeURIComponent(device.deviceId)}/health`} aria-label={`${c.review} ${names.get(device.deviceId) || device.deviceId} (${device.deviceId})`}>{c.review} {names.get(device.deviceId) || device.deviceId}</a>
        </li>)}</ul> : <p>{c.empty}</p>}
        <p>{c.limits}</p>
    </details>;
}
