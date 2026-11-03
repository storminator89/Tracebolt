import { useState } from 'react';
import { RefreshCw } from 'lucide-react';
import { useLocale } from './i18n';
import { fullDate } from './utils';
import type { Device } from './types';
import { useInvestigations } from './investigations-resource';
import { INVESTIGATIONS_PAGE_SIZE } from './investigations-types';
import { InvestigationList, InvestigationNotice } from './investigations';
import { useWindowsIncidentInbox } from './windows-incident-inbox-resource';
import { WindowsIncidentReadOnlyRow } from './windows-incident-inbox';
import { WINDOWS_INCIDENT_PAGE_SIZE } from './windows-incident-inbox-types';
import { windowsDeviceLabel } from './windows-device-label';
import { filterIncidentQueue, incidentQueueRows, queueSourceScopes } from './incident-work-queue-model';
import type { QueuePlatform, QueueScope, QueueSeen, QueueSource } from './incident-work-queue-model';
import './incident-work-queue.css';

const copy = {
    en: {
        title: 'Investigations', refresh: 'Refresh work queue', intro: 'A read-only work queue for Linux and Windows incidents. Seen does not mean recovered. Opening a row grants or executes nothing.',
        scope: 'Status', active: 'Open', all: 'All retained', platform: 'Platform on loaded pages', source: 'Source on loaded pages', seen: 'Seen on loaded pages', allPlatforms: 'Linux and Windows', allSources: 'All sources', allSeen: 'Seen and unseen', acknowledged: 'Seen', unacknowledged: 'Not seen',
        'linux-health': 'Linux Health', 'windows-assessment': 'Windows assessment', 'windows-full-services': 'Windows complete service inventory',
        paging: 'Each source has its own live page and total. Only those pages are merged below, newest opening first. Platform, source and seen filters apply to loaded pages, not the full retained history. Refresh starts both sources at page one. Device search and group filters do not narrow this fleet-wide queue.',
        linux: 'Linux Health', windows: 'Windows incidents', previous: 'Previous', next: 'Next', first: 'First page', page: 'Source page', retained: 'retained', opened: 'open', recovered: 'recovered', stopped: 'monitoring stopped', closed: 'closed', readAt: 'Read at', devices: 'authorized devices', unknown: 'with incomplete current checks', unknownChecks: 'unknown checks', disabledChecks: 'disabled checks', unavailableDevices: 'unavailable devices',
        loading: 'Reading Windows incidents…', failed: 'Windows incidents unavailable or expired. Their counts and rows are unknown.', noLinux: 'No current Linux investigation data.', noWindows: 'No current Windows incident data.', queue: 'Incident work queue', shown: 'Rows shown from current source pages', partial: 'Source coverage is incomplete. Available rows are a partial queue; an unavailable source is not empty success.', empty: 'No matching incidents on the current source pages. This is not a fleet-health assessment. Check source coverage and other pages.', incompleteEmpty: 'No matching rows from the available pages. Missing source rows and totals remain unknown.', changed: 'This live page is now empty although matching history remains. Return to its first page.', unavailableTime: 'Not available', unnamed: 'Windows device',
    },
    de: {
        title: 'Untersuchungen', refresh: 'Arbeitsliste aktualisieren', intro: 'Eine rein lesende Arbeitsliste für Linux- und Windows-Vorfälle. Gesehen bedeutet nicht erholt. Das Öffnen einer Zeile erteilt keine Freigabe und führt nichts aus.',
        scope: 'Status', active: 'Offen', all: 'Alle gespeicherten', platform: 'Plattform auf geladenen Seiten', source: 'Quelle auf geladenen Seiten', seen: 'Kenntnisnahme auf geladenen Seiten', allPlatforms: 'Linux und Windows', allSources: 'Alle Quellen', allSeen: 'Gesehen und ungesehen', acknowledged: 'Gesehen', unacknowledged: 'Ungesehen',
        'linux-health': 'Linux Health', 'windows-assessment': 'Windows-Bewertung', 'windows-full-services': 'Vollständiges Windows-Dienstinventar',
        paging: 'Jede Quelle hat eine eigene aktuelle Seite und Trefferzahl. Nur diese Seiten werden unten nach Eröffnungszeit zusammengeführt. Plattform-, Quellen- und Kenntnisnahmefilter gelten für geladene Seiten, nicht für die gesamte Historie. Aktualisieren beginnt beide Quellen auf Seite eins. Gerätesuche und Gruppenfilter grenzen diese flottenweite Liste nicht ein.',
        linux: 'Linux Health', windows: 'Windows-Vorfälle', previous: 'Zurück', next: 'Weiter', first: 'Erste Seite', page: 'Quellseite', retained: 'gespeichert', opened: 'offen', recovered: 'erholt', stopped: 'Überwachung beendet', closed: 'geschlossen', readAt: 'Abgerufen', devices: 'freigegebene Geräte', unknown: 'mit unvollständig bewertbaren Prüfungen', unknownChecks: 'unbekannte Prüfungen', disabledChecks: 'deaktivierte Prüfungen', unavailableDevices: 'nicht verfügbare Geräte',
        loading: 'Windows-Vorfälle werden gelesen …', failed: 'Windows-Vorfälle nicht verfügbar oder abgelaufen. Ihre Anzahlen und Zeilen sind unbekannt.', noLinux: 'Keine aktuellen Linux-Untersuchungsdaten.', noWindows: 'Keine aktuellen Windows-Vorfalldaten.', queue: 'Vorfall-Arbeitsliste', shown: 'Angezeigte Zeilen der aktuellen Quellseiten', partial: 'Die Quellenabdeckung ist unvollständig. Verfügbare Zeilen bilden eine Teilliste; eine nicht verfügbare Quelle ist kein leerer Erfolg.', empty: 'Keine passenden Vorfälle auf den aktuellen Quellseiten. Das ist keine Flottenbewertung. Quellenabdeckung und weitere Seiten prüfen.', incompleteEmpty: 'Keine passenden Zeilen der verfügbaren Seiten. Zeilen und Anzahlen fehlender Quellen bleiben unbekannt.', changed: 'Diese aktuelle Seite ist jetzt leer, obwohl passende Historie vorhanden ist. Zur ersten Seite zurückkehren.', unavailableTime: 'Nicht verfügbar', unnamed: 'Windows-Gerät',
    },
};
function QueueTime({ value, fallback }: { value: string | null; fallback: string }) {
    return value ? <time dateTime={value} title={value}>{fullDate(value)}</time> : <span>{fallback}</span>;
}

/** Existing private GET projections retain their own authority and clock guards.
 * Parent key includes actor, session and route revision to end obsolete reads. */
export function IncidentWorkQueue({ devices, sessionKey }: { devices: Device[]; sessionKey: string | null }) {
    const [locale] = useLocale(), c = copy[locale];
    const [scope, setScope] = useState<QueueScope>('active'), [platform, setPlatform] = useState<QueuePlatform>('all'), [source, setSource] = useState<QueueSource>('all'), [seen, setSeen] = useState<QueueSeen>('all');
    const [linuxOffset, setLinuxOffset] = useState(0), [windowsOffset, setWindowsOffset] = useState(0), scopes = queueSourceScopes(scope);
    // Keep the cross-page server-clock lower bound from the original workspace.
    const linux = useInvestigations(true, sessionKey, 'incident-work-queue', scopes.linux, linuxOffset, true);
    // Deliberately read-only even for shared administrators. Existing inbox owns writes.
    const windows = useWindowsIncidentInbox(true, sessionKey, false, scopes.windows, 'all', windowsOffset, true);
    const linuxView = linux.view, windowsView = windows.view, complete = !!linuxView && !!windowsView;
    const rows = filterIncidentQueue(incidentQueueRows(linuxView, windowsView), platform, source, seen);
    const names = new Map(devices.filter(device => device.platform === 'windows' && device.source === 'lan' && !device.synthetic).map(device => [device.id, device.name]));
    const deviceIds = [...names.keys(), ...(windowsView?.items.map(item => item.deviceId) ?? [])];
    const unknownLinux = linuxView?.devices.filter(device => device.evaluatedAt === null || device.checks.some(check => check.state === 'unknown')).length ?? 0;
    const refresh = () => {
        if (linuxOffset) setLinuxOffset(0); else linux.refresh();
        if (windowsOffset) setWindowsOffset(0); else windows.refresh();
    };
    const paging = (kind: 'linux' | 'windows') => {
        const view = kind === 'linux' ? linuxView : windowsView, offset = kind === 'linux' ? linuxOffset : windowsOffset;
        const pending = kind === 'linux' ? linux.pending : windows.loading, setOffset = kind === 'linux' ? setLinuxOffset : setWindowsOffset;
        const size = kind === 'linux' ? INVESTIGATIONS_PAGE_SIZE : WINDOWS_INCIDENT_PAGE_SIZE;
        return view && <><div className="incident-queue-paging"><span>{c.page}: {view.items.length ? `${offset + 1}–${offset + view.items.length}` : '0'} / {view.total}</span><button className="button small" disabled={pending || offset === 0} aria-label={`${c[kind]}: ${c.previous}`} onClick={() => setOffset(Math.max(0, offset - size))}>{c.previous}</button><button className="button small" disabled={pending || offset + view.items.length >= view.total} aria-label={`${c[kind]}: ${c.next}`} onClick={() => setOffset(offset + size)}>{c.next}</button></div>{view.items.length === 0 && view.total > 0 && <p>{c.changed} <button className="text-button" onClick={() => setOffset(0)}>{c.first}</button></p>}</>;
    };
    return <div className="incident-work-queue">
        <div className="page-heading"><h1>{c.title}</h1><button className="button small" disabled={linux.pending || windows.loading || linux.locked} onClick={refresh}><RefreshCw size={14}/>{c.refresh}</button></div>
        <p className="investigations-note">{c.intro}</p>
        <div className="incident-queue-toolbar">
            <label>{c.scope}<select value={scope} onChange={event => { setScope(event.target.value as QueueScope); setLinuxOffset(0); setWindowsOffset(0); }}><option value="active">{c.active}</option><option value="all">{c.all}</option></select></label>
            <label>{c.platform}<select value={platform} onChange={event => setPlatform(event.target.value as QueuePlatform)}><option value="all">{c.allPlatforms}</option><option value="linux">Linux</option><option value="windows">Windows</option></select></label>
            <label>{c.source}<select value={source} onChange={event => setSource(event.target.value as QueueSource)}><option value="all">{c.allSources}</option>{(['linux-health', 'windows-assessment', 'windows-full-services'] as const).map(value => <option value={value} key={value}>{c[value]}</option>)}</select></label>
            <label>{c.seen}<select value={seen} onChange={event => setSeen(event.target.value as QueueSeen)}><option value="all">{c.allSeen}</option><option value="seen">{c.acknowledged}</option><option value="unseen">{c.unacknowledged}</option></select></label>
        </div>
        <p className="investigations-note">{c.paging}</p>
        <div className="incident-queue-sources">
            <section className="panel incident-queue-source" aria-label={c.linux}><h2>{c.linux}</h2><InvestigationNotice resource={linux}/>{linuxView ? <><p>{linuxView.counts.all} {c.retained} · {linuxView.counts.open} {c.opened} · {linuxView.counts.recovered} {c.recovered} · {linuxView.counts.closed} {c.stopped}</p><p>{linuxView.devices.length} {c.devices} · {unknownLinux} {c.unknown}</p><p>{c.readAt}: <QueueTime value={linuxView.serverNow} fallback={c.unavailableTime}/></p></> : !linux.pending && <p>{c.noLinux}</p>}{paging('linux')}</section>
            <section className="panel incident-queue-source" aria-label={c.windows}><h2>{c.windows}</h2>{windows.loading && <p role="status">{c.loading}</p>}{windows.error && <p role="alert">{c.failed}</p>}{windowsView ? <><p>{windowsView.counts.total} {c.retained} · {windowsView.counts.active} {c.opened} · {windowsView.counts.resolved} {c.closed} · {windowsView.counts.acknowledged} {c.acknowledged} · {windowsView.counts.unacknowledged} {c.unacknowledged}</p><p>{windowsView.coverage.devices} {c.devices} · {windowsView.coverage.unavailableDevices} {c.unavailableDevices} · {windowsView.coverage.unknownChecks} {c.unknownChecks} · {windowsView.coverage.disabledChecks} {c.disabledChecks}</p><p>{c.readAt}: <QueueTime value={windowsView.serverNow} fallback={c.unavailableTime}/></p></> : !windows.loading && <p>{c.noWindows}</p>}{paging('windows')}</section>
        </div>
        {!complete && <p className="investigation-failure" role="status">{c.partial}</p>}
        <section className="panel" aria-label={c.queue}><p className="incident-queue-label">{c.shown}: {rows.length}</p>{rows.length ? <ul className="incident-queue-list">{rows.map(row => <li key={row.identity} className="incident-queue-entry"><p className="incident-queue-label">{row.platform === 'linux' ? 'Linux' : 'Windows'} · {c[row.source]} · {row.seenAt ? c.acknowledged : c.unacknowledged}</p>{row.platform === 'linux' && linuxView ? <InvestigationList view={{ ...linuxView, items: [row.item] }} devices={devices}/> : row.platform === 'windows' && windowsView ? <WindowsIncidentReadOnlyRow item={row.item} name={windowsDeviceLabel(row.item.deviceId, names, deviceIds, c.unnamed)} serverNow={windowsView.serverNow} age={windows.age}/> : null}</li>)}</ul> : <p className="incident-queue-empty">{complete ? c.empty : c.incompleteEmpty}</p>}</section>
    </div>;
}
