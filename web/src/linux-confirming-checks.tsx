import { useId, useRef, useState } from 'react';
import { ArrowRight, ChevronRight, Clock3, HardDrive, Info, Radio, RotateCcw, SearchX, Server } from 'lucide-react';
import { useLocale } from './i18n';
import type { HealthKind } from './health-types';
import type { InvestigationsView } from './investigations-types';
import type { Device } from './types';
import './linux-confirming-checks.css';

const copy = {
    en: {
        title: 'Linux checks awaiting confirmation', checks: 'confirming checks', devices: 'devices', state: 'Confirming',
        scope: 'Authorized Linux checks only. Independent of incident pages and filters.',
        meaning: 'These conditions have not opened an incident. Confirmation still needs further manager evaluation.',
        search: 'Find a confirming check', kind: 'Confirming check type', all: 'All check types',
        offline: 'Agent contact', filesystem: 'Root filesystem /', service: 'Selected service',
        reset: 'Clear confirming-check filters', shown: 'Shown', empty: 'No matching confirming checks.',
        emptyHint: 'Clear filters to see the remaining checks.', none: 'No confirming checks in this source view.',
        noneHint: 'This is not a whole-device health verdict.', health: 'Open Health', review: 'Open Health for',
        reading: 'Root allocation', evidence: 'Original evidence times', evaluated: 'Manager evaluation',
        observed: 'Source observation', receipt: 'Accepted-report receipt', unavailable: 'Not available',
        details: 'How confirmation works', read: 'Source read at',
        timing: 'The source provides no confirmation start or remaining duration. Refreshing does not advance confirmation; stale or missing evidence becomes unknown.',
        permissions: 'Read only. Opening Health enables no checks, acknowledges no incidents and runs no actions. Windows and other monitoring sources are not included.',
    },
    de: {
        title: 'Linux-Prüfungen mit ausstehender Bestätigung', checks: 'ausstehende Prüfungen', devices: 'Geräte', state: 'Wird bestätigt',
        scope: 'Nur freigegebene Linux-Prüfungen. Unabhängig von Vorfallseiten und Filtern.',
        meaning: 'Diese Bedingungen haben noch keinen Vorfall eröffnet. Zur Bestätigung sind weitere Manager-Auswertungen nötig.',
        search: 'Ausstehende Prüfung finden', kind: 'Art der ausstehenden Prüfung', all: 'Alle Prüfarten',
        offline: 'Agent-Kontakt', filesystem: 'Root-Dateisystem /', service: 'Ausgewählter Dienst',
        reset: 'Filter für ausstehende Prüfungen zurücksetzen', shown: 'Angezeigt', empty: 'Keine passenden ausstehenden Prüfungen.',
        emptyHint: 'Filter zurücksetzen, um die übrigen Prüfungen zu sehen.', none: 'Keine ausstehenden Prüfungen in dieser Quellenansicht.',
        noneHint: 'Das ist kein Gesundheitsurteil über das gesamte Gerät.', health: 'Health öffnen', review: 'Health öffnen für',
        reading: 'Root-Belegung', evidence: 'Originale Belegzeiten', evaluated: 'Manager-Auswertung',
        observed: 'Quellenbeobachtung', receipt: 'Eingang des akzeptierten Berichts', unavailable: 'Nicht verfügbar',
        details: 'So funktioniert die Bestätigung', read: 'Quelle abgerufen',
        timing: 'Die Quelle liefert weder Bestätigungsbeginn noch Restdauer. Aktualisieren treibt die Bestätigung nicht voran; veraltete oder fehlende Belege werden unbekannt.',
        permissions: 'Nur lesen. Health zu öffnen aktiviert keine Prüfung, bestätigt keinen Vorfall und führt keine Aktion aus. Windows und andere Überwachungsquellen sind nicht enthalten.',
    },
};
const SEARCH_LIMIT = 160;
const icons = { offline: Radio, filesystem: HardDrive, service: Server };
function ExactTime({ value, fallback }: { value: string | null; fallback: string }) {
    return value ? <time dateTime={value}>{value}</time> : <span>{fallback}</span>;
}

/** Pure view of the queue's current authorized, aged Linux source. Never retains evidence. */
export function LinuxConfirmingChecks({ view, devices }: { view: InvestigationsView; devices: Device[] }) {
    const [locale] = useLocale(), c = copy[locale], id = useId(), search = useRef<HTMLInputElement>(null);
    const [query, setQuery] = useState(''), [kind, setKind] = useState<'all' | HealthKind>('all');
    const names = new Map(devices.filter(device => device.platform === 'linux' && device.source === 'lan' && !device.synthetic).map(device => [device.id, device.name]));
    const candidates = view.devices.map(device => ({ device, checks: device.checks.filter(check => check.state === 'pending') }))
        .filter(row => row.checks.length > 0).sort((a, b) => a.device.deviceId.localeCompare(b.device.deviceId));
    const needle = query.trim().toLowerCase();
    const rows = candidates.map(row => ({ ...row, checks: row.checks.filter(check => (kind === 'all' || check.kind === kind)
        && [row.device.deviceId, names.get(row.device.deviceId) ?? '', check.target, c[check.kind]].some(value => value.toLowerCase().includes(needle))) })).filter(row => row.checks.length > 0);
    const total = candidates.reduce((sum, row) => sum + row.checks.length, 0), shown = rows.reduce((sum, row) => sum + row.checks.length, 0);
    return <details className="panel linux-confirming-checks">
        <summary><Clock3 size={16} aria-hidden="true" focusable="false"/>{c.title}: <span>{total} {c.checks} · {candidates.length} {c.devices}</span><ChevronRight className="linux-confirming-chevron" size={16} aria-hidden="true" focusable="false"/></summary>
        <p className="linux-confirming-scope">{c.scope}</p>
        <p className="linux-confirming-meaning">{c.meaning}</p>
        <div className="linux-confirming-filters">
            <label htmlFor={`${id}-search`}>{c.search}<input ref={search} id={`${id}-search`} type="search" value={query} maxLength={SEARCH_LIMIT} onChange={event => setQuery(event.target.value.slice(0, SEARCH_LIMIT))}/></label>
            <label htmlFor={`${id}-kind`}>{c.kind}<select id={`${id}-kind`} value={kind} onChange={event => setKind(event.target.value as 'all' | HealthKind)}><option value="all">{c.all}</option>{(['offline', 'filesystem', 'service'] as const).map(value => <option key={value} value={value}>{c[value]}</option>)}</select></label>
            <button type="button" className="text-button" disabled={!query && kind === 'all'} onClick={() => { setQuery(''); setKind('all'); search.current?.focus(); }}><RotateCcw size={14} aria-hidden="true" focusable="false"/>{c.reset}</button>
        </div>
        <p role="status">{c.shown}: {shown} / {total} {c.checks} · {rows.length} / {candidates.length} {c.devices}</p>
        {rows.length ? <ul className="linux-confirming-devices" role="list">{rows.map(({ device, checks }) => <li key={device.deviceId}>
            <header><div><h3>{names.get(device.deviceId) || device.deviceId}</h3><p className="linux-confirming-identity">{device.deviceId}</p></div>
                <a href={`#/devices/${encodeURIComponent(device.deviceId)}/health`} aria-label={`${c.review} ${names.get(device.deviceId) || device.deviceId} (${device.deviceId})`}>{c.health}<ArrowRight size={14} aria-hidden="true" focusable="false"/></a>
            </header>
            <ul className="linux-confirming-targets" role="list">{checks.map(check => { const Icon = icons[check.kind]; return <li key={check.key}>
                <Icon size={16} aria-hidden="true" focusable="false"/><div><strong>{c[check.kind]}{check.kind === 'service' ? `: ${check.target}` : ''}</strong>
                    {check.kind === 'filesystem' && check.value !== null && <small>{c.reading}: {new Intl.NumberFormat(locale, { maximumFractionDigits: 1 }).format(check.value)}%</small>}</div>
                <span className="linux-confirming-state">{c.state}</span>
            </li>; })}</ul>
            <details className="linux-confirming-evidence"><summary>{c.evidence}</summary>
                <p>{c.evaluated}: <ExactTime value={device.evaluatedAt} fallback={c.unavailable}/></p>
                <ul>{checks.map(check => <li key={check.key}><strong>{c[check.kind]}{check.kind === 'service' ? `: ${check.target}` : ''}</strong><span>{check.kind === 'offline' ? c.receipt : c.observed}: <ExactTime value={check.observedAt} fallback={c.unavailable}/></span></li>)}</ul>
            </details>
        </li>)}</ul> : <div className="linux-confirming-empty"><SearchX size={20} aria-hidden="true" focusable="false"/><strong>{total ? c.empty : c.none}</strong><p>{total ? c.emptyHint : c.noneHint}</p></div>}
        <details className="linux-confirming-source"><summary><Info size={14} aria-hidden="true" focusable="false"/>{c.details}</summary><p>{c.timing}</p><p>{c.permissions}</p><p>{c.read}: <ExactTime value={view.serverNow} fallback={c.unavailable}/></p></details>
    </details>;
}
