import { useEffect, useState } from 'react';
import { Filter, RefreshCw } from 'lucide-react';
import { useLocale } from './i18n';
import { fullDate } from './utils';
import type { Device } from './types';
import type { InvestigationsResource } from './investigations-resource';
import { INVESTIGATIONS_PAGE_SIZE } from './investigations-types';
import { InvestigationList, InvestigationNotice } from './investigations';
import { useWindowsIncidentInbox } from './windows-incident-inbox-resource';
import { WindowsIncidentReadOnlyRow } from './windows-incident-inbox';
import { WINDOWS_INCIDENT_PAGE_SIZE } from './windows-incident-inbox-types';
import { windowsDeviceLabel } from './windows-device-label';
import { IncidentTimeline } from './incident-timeline';
import { IncidentComparison } from './incident-comparison';
import { comparisonEpisodes, comparisonSelection, MAX_COMPARISON_EPISODES, toggleComparison } from './incident-comparison-model';
import { ApplicationIncidentWorkspace } from './application-incidents';
import { ManagerReadinessPanel } from './manager-readiness-panel';
import { incidentTimeline } from './incident-timeline-model';
import { filterQueueCurrentCheck } from './incident-current-check-filter';
import type { QueueCurrentCheck } from './incident-current-check-filter';
import { QUEUE_SEARCH_LIMIT, filterIncidentQueue, incidentQueueRows, incidentQueueLifecycleCounts, queueSourceScopes } from './incident-work-queue-model';
import type { QueueLifecycle, QueuePlatform, QueueScope, QueueSeen, QueueSource } from './incident-work-queue-model';
import './incident-work-queue.css';

const copy = {
    en: {
        compare: 'Compare episode', title: 'Investigations', refresh: 'Refresh work queue', intro: 'A read-only Linux and Windows incident work queue, with independent manager application incidents below. Seen does not mean recovered. Opening a row grants or executes nothing.',
        currentCheck: 'Current check on loaded pages', allCurrentChecks: 'All current checks', unknownCurrent: 'Missing or stale evidence', attentionCurrent: 'Current attention', pendingCurrent: 'Awaiting confirmation', inactiveCurrent: 'Monitoring disabled or removed', currentHint: 'Current checks are separate from episode outcomes. This filter applies only to loaded incidents; unavailable source rows remain unknown.',
        scope: 'Status', lifecycle: 'Episode outcome on loaded pages', allOutcomes: 'All episode outcomes', openOutcome: 'Still open', recoveredOutcome: 'Check recovery or reports resumed', stoppedOutcome: 'Closed without confirmed recovery', search: 'Search loaded incidents', searchHint: 'Device name, identity, incident or target', reset: 'Clear page filters', active: 'Open', all: 'All retained', platform: 'Platform on loaded pages', source: 'Source on loaded pages', seen: 'Seen on loaded pages', allPlatforms: 'Linux and Windows', allSources: 'All sources', allSeen: 'Seen and unseen', acknowledged: 'Seen', unacknowledged: 'Not seen',
        'linux-health': 'Linux Health', 'windows-assessment': 'Windows assessment', 'windows-full-services': 'Windows complete service inventory',
        paging: 'Each source has its own live page and total. Only those pages are merged below, newest opening first. Platform, source, seen, outcome and search filters apply to loaded pages, not the full retained history. Refresh starts both sources at page one. Device search and group filters do not narrow this fleet-wide queue.',
        linux: 'Linux Health', windows: 'Windows incidents', previous: 'Previous', next: 'Next', first: 'First page', page: 'Source page', retained: 'retained', opened: 'open', recovered: 'recovered', stopped: 'monitoring stopped', closed: 'closed', readAt: 'Read at', devices: 'authorized devices', unknown: 'with incomplete current checks', unknownChecks: 'unknown checks', disabledChecks: 'disabled checks', unavailableDevices: 'unavailable devices',
        loading: 'Reading Windows incidents…', failed: 'Windows incidents unavailable or expired. Their counts and rows are unknown.', noLinux: 'No current Linux investigation data.', noWindows: 'No current Windows incident data.', queue: 'Incident work queue', shown: 'Rows shown from current source pages', partial: 'Source coverage is incomplete. Available rows are a partial queue; an unavailable source is not empty success.', empty: 'No matching incidents on the current source pages. This is not a fleet-health assessment. Check source coverage and other pages.', incompleteEmpty: 'No matching rows from the available pages. Missing source rows and totals remain unknown.', changed: 'This live page is now empty although matching history remains. Return to its first page.', unavailableTime: 'Not available', unnamed: 'Windows device',
    },
    de: {
        compare: 'Episode vergleichen', title: 'Untersuchungen', refresh: 'Arbeitsliste aktualisieren', intro: 'Eine rein lesende Arbeitsliste für Linux- und Windows-Vorfälle mit eigenständigen Anwendungsvorfällen des Managers darunter. Gesehen bedeutet nicht erholt. Das Öffnen einer Zeile erteilt keine Freigabe und führt nichts aus.',
        currentCheck: 'Aktuelle Prüfung auf geladenen Seiten', allCurrentChecks: 'Alle aktuellen Prüfungen', unknownCurrent: 'Fehlende oder veraltete Evidenz', attentionCurrent: 'Aktuell auffällig', pendingCurrent: 'Bestätigung ausstehend', inactiveCurrent: 'Überwachung deaktiviert oder entfernt', currentHint: 'Aktuelle Prüfungen sind vom Episodenausgang getrennt. Dieser Filter gilt nur für geladene Vorfälle; Zeilen nicht verfügbarer Quellen bleiben unbekannt.',
        scope: 'Status', lifecycle: 'Episodenausgang auf geladenen Seiten', allOutcomes: 'Alle Episodenausgänge', openOutcome: 'Weiter offen', recoveredOutcome: 'Prüfung erholt oder Berichte fortgesetzt', stoppedOutcome: 'Ohne bestätigte Erholung geschlossen', search: 'Geladene Vorfälle durchsuchen', searchHint: 'Gerätename, Identität, Vorfall oder Prüfziel', reset: 'Seitenfilter zurücksetzen', active: 'Offen', all: 'Alle gespeicherten', platform: 'Plattform auf geladenen Seiten', source: 'Quelle auf geladenen Seiten', seen: 'Kenntnisnahme auf geladenen Seiten', allPlatforms: 'Linux und Windows', allSources: 'Alle Quellen', allSeen: 'Gesehen und ungesehen', acknowledged: 'Gesehen', unacknowledged: 'Ungesehen',
        'linux-health': 'Linux Health', 'windows-assessment': 'Windows-Bewertung', 'windows-full-services': 'Vollständiges Windows-Dienstinventar',
        paging: 'Jede Quelle hat eine eigene aktuelle Seite und Trefferzahl. Nur diese Seiten werden unten nach Eröffnungszeit zusammengeführt. Plattform-, Quellen-, Kenntnisnahme-, Ausgangs- und Suchfilter gelten für geladene Seiten, nicht für die gesamte Historie. Aktualisieren beginnt beide Quellen auf Seite eins. Gerätesuche und Gruppenfilter grenzen diese flottenweite Liste nicht ein.',
        linux: 'Linux Health', windows: 'Windows-Vorfälle', previous: 'Zurück', next: 'Weiter', first: 'Erste Seite', page: 'Quellseite', retained: 'gespeichert', opened: 'offen', recovered: 'erholt', stopped: 'Überwachung beendet', closed: 'geschlossen', readAt: 'Abgerufen', devices: 'freigegebene Geräte', unknown: 'mit unvollständig bewertbaren Prüfungen', unknownChecks: 'unbekannte Prüfungen', disabledChecks: 'deaktivierte Prüfungen', unavailableDevices: 'nicht verfügbare Geräte',
        loading: 'Windows-Vorfälle werden gelesen …', failed: 'Windows-Vorfälle nicht verfügbar oder abgelaufen. Ihre Anzahlen und Zeilen sind unbekannt.', noLinux: 'Keine aktuellen Linux-Untersuchungsdaten.', noWindows: 'Keine aktuellen Windows-Vorfalldaten.', queue: 'Vorfall-Arbeitsliste', shown: 'Angezeigte Zeilen der aktuellen Quellseiten', partial: 'Die Quellenabdeckung ist unvollständig. Verfügbare Zeilen bilden eine Teilliste; eine nicht verfügbare Quelle ist kein leerer Erfolg.', empty: 'Keine passenden Vorfälle auf den aktuellen Quellseiten. Das ist keine Flottenbewertung. Quellenabdeckung und weitere Seiten prüfen.', incompleteEmpty: 'Keine passenden Zeilen der verfügbaren Seiten. Zeilen und Anzahlen fehlender Quellen bleiben unbekannt.', changed: 'Diese aktuelle Seite ist jetzt leer, obwohl passende Historie vorhanden ist. Zur ersten Seite zurückkehren.', unavailableTime: 'Nicht verfügbar', unnamed: 'Windows-Gerät',
    },
};
function QueueTime({ value, fallback }: { value: string | null; fallback: string }) {
    return value ? <time dateTime={value} title={value}>{fullDate(value)}</time> : <span>{fallback}</span>;
}

/** The workspace owns the guarded Linux reader; the private Windows reader
 * remounts by actor, session and route revision to end obsolete reads. */
export function IncidentWorkQueue({ devices, sessionKey, linux, scope, onScope, linuxOffset, onLinuxPage }: { devices: Device[]; sessionKey: string | null; linux: InvestigationsResource; scope: QueueScope; onScope: (scope: QueueScope) => void; linuxOffset: number; onLinuxPage: (offset: number) => void }) {
    const [locale] = useLocale(), c = copy[locale];
    const [platform, setPlatform] = useState<QueuePlatform>('all'), [source, setSource] = useState<QueueSource>('all'), [seen, setSeen] = useState<QueueSeen>('all');
    const [lifecycle, setLifecycle] = useState<QueueLifecycle>('all'), [query, setQuery] = useState('');
    const [currentCheck, setCurrentCheck] = useState<QueueCurrentCheck>('all');
    const [windowsOffset, setWindowsOffset] = useState(0), scopes = queueSourceScopes(scope);
    // Deliberately read-only even for shared administrators. Existing inbox owns writes.
    const windows = useWindowsIncidentInbox(true, sessionKey, false, scopes.windows, 'all', windowsOffset, true);
    const linuxView = linux.view, windowsView = windows.view, complete = !!linuxView && !!windowsView;
    const searchNames = new Map(devices.filter(device => device.source === 'lan' && !device.synthetic).map(device => [`${device.platform}:${device.id}`, device.name]));
    const rows = filterQueueCurrentCheck(filterIncidentQueue(incidentQueueRows(linuxView, windowsView), platform, source, seen, lifecycle, query, searchNames), currentCheck, linuxView, windowsView?.serverNow ?? null, windows.age);
    const outcomes = incidentQueueLifecycleCounts(rows);
    // Store only opaque choices. Every render resolves them against the visible,
    // guarded live rows; scope/source loss cannot leave cached private content.
    const comparisonScope = JSON.stringify([sessionKey, scope, linuxOffset, windowsOffset, platform, source, seen, lifecycle, query, currentCheck, linux.locked]);
    const [selection, setSelection] = useState({ scope: comparisonScope, ids: [] as string[], expanded: false });
    const selected = comparisonSelection(selection.scope === comparisonScope && !linux.locked ? selection.ids : [], rows);
    const visibleIdentities = JSON.stringify(rows.map(row => row.identity));
    useEffect(() => {
        setSelection(current => {
            if (current.scope !== comparisonScope || linux.locked) return { scope: comparisonScope, ids: [], expanded: false };
            const ids = comparisonSelection(current.ids, rows);
            return ids.length === current.ids.length && ids.every((id, index) => id === current.ids[index]) ? current : { ...current, ids, expanded: current.expanded && ids.length >= 2 };
        });
    }, [comparisonScope, visibleIdentities, linux.locked]);
    const episodes = comparisonEpisodes(selected, rows, linuxView, windowsView?.serverNow ?? null, windows.age);
    const toggleEpisode = (identity: string) => setSelection(current => {
        const ids = toggleComparison(current.scope === comparisonScope ? current.ids : [], rows, identity);
        return { scope: comparisonScope, ids, expanded: current.scope === comparisonScope && current.expanded && ids.length >= 2 };
    });
    const resetFilters = () => { setPlatform('all'); setSource('all'); setSeen('all'); setLifecycle('all'); setQuery(''); setCurrentCheck('all'); };
    const names = new Map(devices.filter(device => device.platform === 'windows' && device.source === 'lan' && !device.synthetic).map(device => [device.id, device.name]));
    const deviceIds = [...names.keys(), ...(windowsView?.items.map(item => item.deviceId) ?? [])];
    const unknownLinux = linuxView?.devices.filter(device => device.evaluatedAt === null || device.checks.some(check => check.state === 'unknown')).length ?? 0;
    const refresh = () => {
        if (linuxOffset) onLinuxPage(0); else linux.refresh();
        if (windowsOffset) setWindowsOffset(0); else windows.refresh();
    };
    const paging = (kind: 'linux' | 'windows') => {
        const view = kind === 'linux' ? linuxView : windowsView, offset = kind === 'linux' ? linuxOffset : windowsOffset;
        const pending = kind === 'linux' ? linux.pending : windows.loading, setOffset = kind === 'linux' ? onLinuxPage : setWindowsOffset;
        const size = kind === 'linux' ? INVESTIGATIONS_PAGE_SIZE : WINDOWS_INCIDENT_PAGE_SIZE;
        return view && <><div className="incident-queue-paging"><span>{c.page}: {view.items.length ? `${offset + 1}–${offset + view.items.length}` : '0'} / {view.total}</span><button className="button small" disabled={pending || offset === 0} aria-label={`${c[kind]}: ${c.previous}`} onClick={() => setOffset(Math.max(0, offset - size))}>{c.previous}</button><button className="button small" disabled={pending || offset + view.items.length >= view.total} aria-label={`${c[kind]}: ${c.next}`} onClick={() => setOffset(offset + size)}>{c.next}</button></div>{view.items.length === 0 && view.total > 0 && <p>{c.changed} <button className="text-button" onClick={() => setOffset(0)}>{c.first}</button></p>}</>;
    };
    return <div className="incident-work-queue">
        <div className="page-heading"><h1>{c.title}</h1><button className="button small" disabled={linux.pending || windows.loading || linux.locked} onClick={refresh}><RefreshCw size={14}/>{c.refresh}</button></div>
        <p className="investigations-note">{c.intro}</p>
        <ManagerReadinessPanel sessionKey={sessionKey}/>
        <div className="incident-queue-toolbar">
            <label>{c.scope}<select value={scope} onChange={event => { onScope(event.target.value as QueueScope); onLinuxPage(0); setWindowsOffset(0); }}><option value="active">{c.active}</option><option value="all">{c.all}</option></select></label>
            <label>{c.platform}<select value={platform} onChange={event => setPlatform(event.target.value as QueuePlatform)}><option value="all">{c.allPlatforms}</option><option value="linux">Linux</option><option value="windows">Windows</option></select></label>
            <label>{c.source}<select value={source} onChange={event => setSource(event.target.value as QueueSource)}><option value="all">{c.allSources}</option>{(['linux-health', 'windows-assessment', 'windows-full-services'] as const).map(value => <option value={value} key={value}>{c[value]}</option>)}</select></label>
            <label>{c.seen}<select value={seen} onChange={event => setSeen(event.target.value as QueueSeen)}><option value="all">{c.allSeen}</option><option value="seen">{c.acknowledged}</option><option value="unseen">{c.unacknowledged}</option></select></label>
            <label>{c.lifecycle}<select value={lifecycle} onChange={event => setLifecycle(event.target.value as QueueLifecycle)}><option value="all">{c.allOutcomes}</option><option value="open">{c.openOutcome}</option><option value="recovered">{c.recoveredOutcome}</option><option value="stopped">{c.stoppedOutcome}</option></select></label>
            <label><Filter size={14} aria-hidden="true" focusable="false"/>{c.currentCheck}<select value={currentCheck} onChange={event => setCurrentCheck(event.target.value as QueueCurrentCheck)}><option value="all">{c.allCurrentChecks}</option><option value="unknown">{c.unknownCurrent}</option><option value="attention">{c.attentionCurrent}</option><option value="pending">{c.pendingCurrent}</option><option value="inactive">{c.inactiveCurrent}</option></select></label>
            <label className="incident-queue-search">{c.search}<input type="search" value={query} maxLength={QUEUE_SEARCH_LIMIT} placeholder={c.searchHint} onChange={event => setQuery(event.target.value.slice(0, QUEUE_SEARCH_LIMIT))}/></label>
            <button className="text-button" onClick={resetFilters} disabled={platform === 'all' && source === 'all' && seen === 'all' && lifecycle === 'all' && query === '' && currentCheck === 'all'}>{c.reset}</button>
        </div>
        <p className="investigations-note">{c.currentHint}</p>
        <p className="investigations-note">{c.paging}</p>
        <div className="incident-queue-sources">
            <section className="panel incident-queue-source" aria-label={c.linux}><h2>{c.linux}</h2><InvestigationNotice resource={linux}/>{linuxView ? <><p>{linuxView.counts.all} {c.retained} · {linuxView.counts.open} {c.opened} · {linuxView.counts.recovered} {c.recovered} · {linuxView.counts.closed} {c.stopped}</p><p>{linuxView.devices.length} {c.devices} · {unknownLinux} {c.unknown}</p><p>{c.readAt}: <QueueTime value={linuxView.serverNow} fallback={c.unavailableTime}/></p></> : !linux.pending && <p>{c.noLinux}</p>}{paging('linux')}</section>
            <section className="panel incident-queue-source" aria-label={c.windows}><h2>{c.windows}</h2>{windows.loading && <p role="status">{c.loading}</p>}{windows.error && <p role="alert">{c.failed}</p>}{windowsView ? <><p>{windowsView.counts.total} {c.retained} · {windowsView.counts.active} {c.opened} · {windowsView.counts.resolved} {c.closed} · {windowsView.counts.acknowledged} {c.acknowledged} · {windowsView.counts.unacknowledged} {c.unacknowledged}</p><p>{windowsView.coverage.devices} {c.devices} · {windowsView.coverage.unavailableDevices} {c.unavailableDevices} · {windowsView.coverage.unknownChecks} {c.unknownChecks} · {windowsView.coverage.disabledChecks} {c.disabledChecks}</p><p>{c.readAt}: <QueueTime value={windowsView.serverNow} fallback={c.unavailableTime}/></p></> : !windows.loading && <p>{c.noWindows}</p>}{paging('windows')}</section>
        </div>
        {!complete && <p className="investigation-failure" role="status">{c.partial}</p>}
        <IncidentComparison episodes={episodes} expanded={selection.scope === comparisonScope && selection.expanded} onExpanded={expanded => setSelection(current => current.scope === comparisonScope ? { ...current, expanded } : current)} onClear={() => setSelection({ scope: comparisonScope, ids: [], expanded: false })} onRemove={toggleEpisode}/>
        <section className="panel" aria-label={c.queue}><p className="incident-queue-label">{c.shown}: {rows.length}</p>{rows.length > 0 && <p className="incident-queue-label">{c.openOutcome}: {outcomes.open} · {c.recoveredOutcome}: {outcomes.recovered} · {c.stoppedOutcome}: {outcomes.stopped}</p>}{rows.length ? <ul className="incident-queue-list">{rows.map(row => <li key={row.identity} className="incident-queue-entry"><label className="incident-comparison-toggle"><input type="checkbox" checked={selected.includes(row.identity)} disabled={linux.locked || selected.length >= MAX_COMPARISON_EPISODES && !selected.includes(row.identity)} onChange={() => toggleEpisode(row.identity)} aria-label={`${c.compare}: ${c[row.source]} · ${row.item.deviceId} · ${row.platform === 'linux' ? row.item.incident.id : row.item.incidentId} · ${row.platform === 'linux' ? row.item.incident.key : row.item.key}`}/>{c.compare}</label><p className="incident-queue-label">{row.platform === 'linux' ? 'Linux' : 'Windows'} · {c[row.source]} · {row.seenAt ? c.acknowledged : c.unacknowledged}</p>{row.platform === 'linux' && linuxView ? <InvestigationList view={{ ...linuxView, items: [row.item] }} devices={devices}/> : row.platform === 'windows' && windowsView ? <WindowsIncidentReadOnlyRow item={row.item} name={windowsDeviceLabel(row.item.deviceId, names, deviceIds, c.unnamed)} serverNow={windowsView.serverNow} age={windows.age}/> : null}<IncidentTimeline model={incidentTimeline(row, linuxView, windowsView?.serverNow ?? null, windows.age)} platform={row.platform}/></li>)}</ul> : <p className="incident-queue-empty">{complete ? c.empty : c.incompleteEmpty}</p>}</section>
        <ApplicationIncidentWorkspace/>
    </div>;
}
