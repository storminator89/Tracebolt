import { useCallback, useEffect, useId, useLayoutEffect, useRef, useState } from 'react';
import { AUTH_REQUIRED_EVENT, getProtectedRequestEpoch } from './api';
import type { WindowsContactView } from './windows-contact-types';
import { Radio, RefreshCw } from 'lucide-react';
import { inventoryAge } from './complete-packages-types';
import { useLocale } from './i18n';
import type { Device } from './types';
import { fullDate } from './utils';
import type { WindowsContactResource } from './windows-contact-resource';
import { windowsContactDeviceEligible, windowsContactStatus } from './windows-contact-types';
import './windows-contact.css';

const copy = {
    en: { all: 'All', filterGroup: 'Filter saved contact incidents', filterScope: 'Filters saved incidents, not the current assessment.', noMatches: 'No saved incidents match this filter.', shown: 'Shown', of: 'of', title: 'Accepted-contact history', scope: 'Manager-accepted Windows reports. Live reachability is not checked.', status: 'Current assessment', unknown: 'Unknown', recent: 'Recent report', pending: 'Report overdue · confirmation pending', overdue: 'Report overdue · incident open', receipt: 'Last report accepted', sequence: 'Sequence', evaluated: 'Evaluated by manager', never: 'No accepted report recorded.', refreshing: 'Refreshing contact history…', unavailable: 'Contact history unavailable. Current state is unknown.', noAuthority: 'Current device access could not be verified. Contact history is hidden.', refresh: 'Refresh contact history', history: 'Recent contact incidents', empty: 'No retained contact incidents.', open: 'Open', recovered: 'Recovered', opened: 'Opened', confirmed: 'Last confirmed overdue', incidentReceipt: 'Report accepted before opening', resolved: 'Recovered at', recoveryReceipt: 'Recovery report accepted', id: 'Incident ID', details: 'Contact rules & limits', rules: 'An accepted report more than 120 seconds old starts a pending period. After 60 seconds of continuous manager confirmation, an overdue-report incident opens. Reports at most 120 seconds old must remain recent for 60 seconds to recover. Interrupted evaluation resets these waiting periods.', limits: 'Unknown means the current assessment cannot be established. An unknown assessment does not close an existing incident. This history does not determine whether the endpoint is offline. No automatic notification, AI analysis or remediation is started.', retention: 'Up to 100 incidents are retained. Recovered incidents are kept for 30 days; open incidents remain until recovery. Original acceptance and evaluation times are shown separately.', stale: 'The current assessment needs a newer manager evaluation. Retained history is shown below.' },
    de: { all: 'Alle', filterGroup: 'Gespeicherte Kontaktvorfälle filtern', filterScope: 'Filtert gespeicherte Vorfälle, nicht die aktuelle Bewertung.', noMatches: 'Keine gespeicherten Vorfälle für diesen Filter.', shown: 'Angezeigt', of: 'von', title: 'Verlauf akzeptierter Meldungen', scope: 'Vom Manager akzeptierte Windows-Meldungen. Die aktuelle Erreichbarkeit wird nicht geprüft.', status: 'Aktuelle Bewertung', unknown: 'Unbekannt', recent: 'Aktuelle Meldung', pending: 'Meldung überfällig · Bestätigung ausstehend', overdue: 'Meldung überfällig · Vorfall offen', receipt: 'Letzte Meldung akzeptiert', sequence: 'Sequenz', evaluated: 'Vom Manager bewertet', never: 'Noch keine akzeptierte Meldung erfasst.', refreshing: 'Meldungsverlauf wird aktualisiert …', unavailable: 'Meldungsverlauf nicht verfügbar. Der aktuelle Zustand ist unbekannt.', noAuthority: 'Die aktuelle Gerätefreigabe konnte nicht bestätigt werden. Der Meldungsverlauf ist ausgeblendet.', refresh: 'Meldungsverlauf aktualisieren', history: 'Letzte Kontaktvorfälle', empty: 'Keine gespeicherten Kontaktvorfälle.', open: 'Offen', recovered: 'Erholt', opened: 'Geöffnet', confirmed: 'Zuletzt als überfällig bestätigt', incidentReceipt: 'Vor Öffnung akzeptierte Meldung', resolved: 'Erholt am', recoveryReceipt: 'Erholungsmeldung akzeptiert', id: 'Vorfall-ID', details: 'Kontaktregeln & Grenzen', rules: 'Ist eine akzeptierte Meldung älter als 120 Sekunden, beginnt eine Wartezeit. Nach 60 Sekunden fortlaufender Bestätigung durch den Manager wird ein Vorfall wegen überfälliger Meldungen geöffnet. Für die Erholung müssen Meldungen 60 Sekunden lang höchstens 120 Sekunden alt bleiben. Eine unterbrochene Bewertung setzt diese Wartezeiten zurück.', limits: 'Unbekannt bedeutet, dass die aktuelle Bewertung nicht feststeht. Das schließt einen bestehenden Vorfall nicht. Dieser Verlauf stellt nicht fest, ob das Gerät offline ist. Es werden keine automatische Benachrichtigung, KI-Analyse oder Behebung gestartet.', retention: 'Bis zu 100 Vorfälle werden gespeichert. Erholte Vorfälle bleiben 30 Tage erhalten, offene bis zur Erholung. Ursprüngliche Annahme- und Bewertungszeiten werden getrennt angezeigt.', stale: 'Für die aktuelle Bewertung ist eine neuere Manager-Bewertung nötig. Der gespeicherte Verlauf wird unten angezeigt.' },
};
function Timestamp({ label, value }: { label: string; value: string }) { return <div><dt>{label}</dt><dd><time dateTime={value}>{fullDate(value)}</time></dd></div>; }
export function WindowsContactPanel({ device, resource, sessionKey, metadataReady }: { device: Device; resource: WindowsContactResource; sessionKey: string | null; metadataReady: boolean }) {
    const [locale] = useLocale(), c = copy[locale], { elapsedMS } = resource;
    const candidate = resource.view;
    const authority = metadataReady && windowsContactDeviceEligible(device, device.id) && candidate?.deviceId === device.id && sessionKey && Number.isFinite(elapsedMS) && elapsedMS >= 0 && inventoryAge(sessionKey, candidate.serverNow) > elapsedMS && inventoryAge(candidate.certificateExpiresAt, candidate.serverNow) > elapsedMS && device.agentCertificate?.expiresAt && inventoryAge(device.agentCertificate.expiresAt, candidate.serverNow) > elapsedMS && inventoryAge(candidate.serverNow, device.agentCertificate.checkedAt) + elapsedMS >= 0 && inventoryAge(candidate.serverNow, device.agentCertificate.checkedAt) + elapsedMS <= 120000;
    const view = authority && !resource.error && !resource.loading ? candidate : null;
    const status = view ? windowsContactStatus(view, elapsedMS) : 'unknown';
    return <section className="windows-contact" aria-label={c.title}>
        <header><h2><Radio size={16} aria-hidden="true"/>{c.title}</h2><button type="button" className="text-button" disabled={resource.loading || !metadataReady || !sessionKey || !windowsContactDeviceEligible(device, device.id) || resource.error === 'session'} onClick={resource.refresh}><RefreshCw size={14} aria-hidden="true"/>{c.refresh}</button></header>
        <p className="windows-contact-scope">{c.scope}</p>
        <div className="windows-contact-assessment"><span>{c.status}</span><strong>{c[status]}</strong></div>
        {!view && <p role="status">{resource.loading ? c.refreshing : resource.error ? c.unavailable : c.noAuthority}</p>}
        {view && <>
            <dl className="windows-contact-times">{view.lastAcceptedAt ? <><Timestamp label={c.receipt} value={view.lastAcceptedAt}/><div><dt>{c.sequence}</dt><dd>{view.sequence}</dd></div></> : <div><dd>{c.never}</dd></div>}{view.evaluatedAt && <Timestamp label={c.evaluated} value={view.evaluatedAt}/>}</dl>
            {status === 'unknown' && view.evaluatedAt && <p role="status">{c.stale}</p>}
        </>}
        <ContactIncidentHistory key={`${device.id}:${sessionKey}:${device.agentCertificate?.expiresAt}`} view={view} c={c} refreshing={resource.loading} focusAllowed={metadataReady && !!sessionKey && !resource.error && windowsContactDeviceEligible(device, device.id)} focusScope={`${device.id}:${sessionKey}:${device.agentCertificate?.expiresAt}`}/>
        <details className="windows-inventory-scope"><summary>{c.details}</summary><p>{c.rules}</p><p>{c.limits}</p><p>{c.retention}</p></details>
    </section>;
}

/** Filters only the current authorized snapshot; contains no reads or mutations. */
function ContactIncidentHistory({ view, c, refreshing, focusAllowed, focusScope }: { view: WindowsContactView | null; c: typeof copy.en; refreshing: boolean; focusAllowed: boolean; focusScope: string }) {
    const [filter, setFilter] = useState<'all' | 'open' | 'recovered'>('all'), listId = useId();
    const group = useRef<HTMLDivElement | null>(null), intent = useRef<{ filter: string; scope: string; epoch: number } | null>(null);
    const refreshState = useRef({ refreshing, focusAllowed, focusScope }); refreshState.current = { refreshing, focusAllowed, focusScope };
    const attachGroup = useCallback((node: HTMLDivElement | null) => {
        const active = document.activeElement, state = refreshState.current;
        if (!node && state.refreshing && state.focusAllowed && group.current?.contains(active)) {
            const key = active?.getAttribute('data-contact-filter');
            if (key && ['all', 'open', 'recovered'].includes(key)) intent.current = { filter: key, scope: state.focusScope, epoch: getProtectedRequestEpoch() };
        }
        group.current = node;
    }, []);
    useEffect(() => {
        const cancel = () => { intent.current = null; };
        const outside = (event: FocusEvent) => { if (!group.current?.contains(event.target as Node)) cancel(); };
        const events = ['blur', 'pagehide', 'hashchange', 'popstate', AUTH_REQUIRED_EVENT];
        events.forEach(event => window.addEventListener(event, cancel));
        document.addEventListener('visibilitychange', cancel); document.addEventListener('focusin', outside);
        document.addEventListener('pointerdown', cancel); document.addEventListener('keydown', cancel);
        return () => { cancel(); events.forEach(event => window.removeEventListener(event, cancel)); document.removeEventListener('visibilitychange', cancel); document.removeEventListener('focusin', outside); document.removeEventListener('pointerdown', cancel); document.removeEventListener('keydown', cancel); };
    }, []);
    useLayoutEffect(() => {
        const saved = intent.current;
        if (!saved || !focusAllowed || saved.scope !== focusScope || saved.epoch !== getProtectedRequestEpoch()) { intent.current = null; return; }
        if (refreshing) return;
        intent.current = null;
        if (view && document.visibilityState !== 'hidden' && document.activeElement === document.body) {
            group.current?.querySelector<HTMLButtonElement>(`[data-contact-filter="${saved.filter}"]`)?.focus({ preventScroll: true });
        }
    }, [view, refreshing, focusAllowed, focusScope]);
    // Retain only the non-sensitive filter choice through background reads.
    // No rows, counts or timestamps are retained when authority hides the view.
    if (!view) return null;
    const counts = { all: view.incidents.length, open: view.incidents.filter(row => !row.resolvedAt).length, recovered: view.incidents.filter(row => !!row.resolvedAt).length };
    const rows = view.incidents.filter(row => filter === 'all' || (filter === 'recovered') === !!row.resolvedAt).sort((a, b) => inventoryAge(b.openedAt, a.openedAt));
    return <div className="windows-contact-history">
        <h3>{c.history}</h3>
        {view.incidents.length > 0 && <><div ref={attachGroup} className="windows-contact-filters" role="group" aria-label={c.filterGroup}>
            {(['all', 'open', 'recovered'] as const).map(key => <button type="button" key={key} data-contact-filter={key} aria-pressed={filter === key} aria-controls={listId} onClick={() => setFilter(key)}>{`${c[key]} (${counts[key]})`}</button>)}
        </div><p>{c.filterScope}</p><p role="status" className="windows-contact-filter-count">{c.shown}: {rows.length} {c.of} {view.incidents.length}</p></>}
            {view.incidents.length === 0 ? <p>{c.empty}</p> : <div id={listId}>{rows.length === 0 ? <p>{c.noMatches}</p> : <ol className="windows-contact-incidents" role="list">{rows.map(row => <li key={row.id}>
                <div className="windows-contact-incident-heading"><strong>{row.resolvedAt ? c.recovered : c.open}</strong><span>{c.id}: <code>{row.id}</code></span></div>
                <dl className="windows-contact-times"><Timestamp label={c.opened} value={row.openedAt}/><Timestamp label={c.confirmed} value={row.lastConfirmedAt}/><Timestamp label={c.incidentReceipt} value={row.lastAcceptedAt}/><div><dt>{c.sequence}</dt><dd>{row.sequence}</dd></div>{row.resolvedAt && <Timestamp label={c.resolved} value={row.resolvedAt}/>} {row.recoveryAcceptedAt && <><Timestamp label={c.recoveryReceipt} value={row.recoveryAcceptedAt}/><div><dt>{c.sequence}</dt><dd>{row.recoverySequence}</dd></div></>}</dl>
            </li>)}</ol>}</div>}
    </div>;
}
