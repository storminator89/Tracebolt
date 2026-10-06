import { ArrowRight, RefreshCw, ShieldCheck } from 'lucide-react';
import { EmptyState, SectionHead } from './components';
import { t, useLocale } from './i18n';
import { fullDate } from './utils';
import { validJournalUnit } from './journal-types';
import { incidentScope, INVESTIGATIONS_PAGE_SIZE } from './investigations-types';
import type { InvestigationItem, InvestigationScope, InvestigationsView } from './investigations-types';
import type { InvestigationsResource } from './investigations-resource';
import type { Device } from './types';
import './investigations.css';
const labels = (de: boolean) => ({ open: de ? 'Offen' : 'Open', recovered: de ? 'Erholt' : 'Recovered', closed: de ? 'Überwachung beendet' : 'Monitoring stopped', all: de ? 'Alle Fälle' : 'All cases' });
function title(item: InvestigationItem, de: boolean) { return item.incident.kind === 'offline' ? de ? 'Agent-Kontakt fehlt' : 'Agent contact missing' : item.incident.kind === 'filesystem' ? de ? 'Root-Dateisystem fast voll' : 'Root filesystem nearly full' : `${item.incident.target}: ${de ? 'Dienst inaktiv' : 'service inactive'}`; }
function Time({ value }: { value: string | null }) { return value ? <time dateTime={value} title={value}>{fullDate(value)}</time> : <span>{t('Zeitpunkt unbekannt')}</span>; }
function rule(item: InvestigationItem, de: boolean) {
    if (item.incident.kind === 'offline') return de ? 'Mehr als 2 Minuten ohne akzeptierte Übertragung, danach 60 Sekunden Bestätigung durch den Manager.' : 'More than 2 minutes without an accepted report, followed by 60 seconds of manager confirmation.';
    if (item.incident.kind === 'filesystem') return de ? 'Root-Dateisystem / mindestens 90 % belegt, bestätigt durch fortlaufende Messwerte über 120 Sekunden. Erholung: höchstens 85 % für 60 Sekunden.' : 'Root filesystem / at least 90% used, confirmed by advancing samples over 120 seconds. Recovery: at most 85% for 60 seconds.';
    return de ? 'Ausgewählter Dienst meldet inaktiv oder fehlgeschlagen über 120 Sekunden. Erholung: 60 Sekunden aktiv.' : 'Selected service reports inactive or failed over 120 seconds. Recovery: active for 60 seconds.';
}
function failureText(resource: InvestigationsResource, de: boolean) {
    if (resource.failure === 'session') return de ? 'Sitzung beendet. Erneut anmelden, um Untersuchungen zu lesen.' : 'Session ended. Sign in again to read investigations.';
    if (resource.failure === 'invalid') return de ? 'Unvollständige Untersuchungsdaten. Keine verlässliche Fallzahl verfügbar.' : 'Invalid investigation data. Reliable case counts are unavailable.';
    if (resource.failure === 'clock') return de ? 'Zeitbezug geändert. Untersuchungen erneut laden.' : 'Time reference changed. Refresh investigations.';
    if (resource.failure === 'timeout') return de ? 'Zeitüberschreitung. Untersuchungen erneut laden.' : 'Investigation request timed out. Try again.';
    if (resource.failure === 'interrupted') return de ? 'Abfrage unterbrochen. Untersuchungen erneut laden.' : 'Request interrupted. Refresh investigations.';
    return de ? 'Untersuchungen nicht verfügbar. Keine verlässliche Fallzahl verfügbar.' : 'Investigations unavailable. Reliable case counts are unavailable.';
}
export function InvestigationNotice({ resource }: { resource: InvestigationsResource }) {
    const [locale] = useLocale(), de = locale === 'de';
    return <>{resource.pending && <p className="investigation-note" role="status">{de ? 'Untersuchungen werden gelesen …' : 'Reading investigations…'}</p>}{resource.failure && <p className="investigation-failure" role="alert">{failureText(resource, de)}</p>}</>;
}
export function InvestigationList({ view, devices, concise = false, onAll }: { view: InvestigationsView; devices: Device[]; concise?: boolean; onAll?: () => void }) {
    const [locale] = useLocale(), de = locale === 'de', status = labels(de);
    const items = concise ? view.items.slice(0, 4) : view.items;
    return <div className="investigation-list">{items.map(item => {
        const incident = item.incident, current = view.devices.find(device => device.deviceId === item.deviceId)!, check = current.checks.find(value => value.key === incident.key), state = incidentScope(incident);
        const name = devices.find(device => device.id === item.deviceId)?.name ?? item.deviceId;
        const deviceURL = `#/devices/${encodeURIComponent(item.deviceId)}`;
        return <article className="investigation-item" key={`${item.deviceId}:${incident.id}`}>
            <div className="investigation-row"><div><h3>{title(item, de)}</h3><p className="investigation-device">{name}</p></div><span className={`investigation-status investigation-${state}`}>{status[state]}</span></div>
            <p className="investigation-note">{de ? 'Warnung · Regelbasierter Health-Vorfall' : 'Warning · Rule-based health incident'}{incident.acknowledgedAt && ` · ${de ? 'Bestätigt' : 'Acknowledged'}`}</p>
            <p className="investigation-note">{de ? 'Begonnen: ' : 'Opened: '}<Time value={incident.openedAt}/>{' · '}{de ? 'Letzter Vorfallsbeleg: ' : 'Last incident evidence: '}<Time value={incident.lastObservedAt}/></p>
            {!concise && <details className="investigation-evidence"><summary>{de ? 'Belege & nächste Prüfung' : 'Evidence & next check'}</summary>
                <p>{de ? 'Der Manager hat die folgende Regel bestätigt:' : 'The manager confirmed this rule:'} {rule(item, de)}</p>
                <p>{de ? 'Ursache nicht ermittelt. Der Vorfall belegt die beobachtete Bedingung; er enthält keine Diagnose der zugrunde liegenden Ursache.' : 'Cause undetermined. The incident records the observed condition; it does not diagnose the underlying cause.'}</p>
                <dl><div><dt>{de ? 'Aktuelle Prüfung' : 'Current check'}</dt><dd>{!check ? (de ? 'Nicht mehr überwacht' : 'No longer monitored') : check.state === 'unknown' ? (de ? 'Unbekannt: aktuelle Belege fehlen oder sind veraltet' : 'Unknown: current evidence is missing or stale') : check.state === 'pending' ? t('Bestätigung ausstehend') : check.state === 'open' ? t('Warnung offen') : t('Schwelle nicht verletzt')}</dd></div>
                    {check && <><div><dt>{de ? 'Beobachtungszeit' : 'Observation time'}</dt><dd><Time value={check.observedAt}/></dd></div>{check.kind === 'filesystem' && check.state !== 'unknown' && check.value !== null && <div><dt>{de ? 'Aktuell belegt' : 'Currently used'}</dt><dd>{check.value.toFixed(1)} %</dd></div>}</>}
                    <div><dt>{de ? 'Health-Auswertung' : 'Health evaluation'}</dt><dd><Time value={current.evaluatedAt}/></dd></div>
                    {incident.resolvedAt && <div><dt>{status[state]}</dt><dd><Time value={incident.resolvedAt}/></dd></div>}
                    {incident.acknowledgedAt && <div><dt>{de ? 'Kenntnisnahme' : 'Acknowledged'}</dt><dd><Time value={incident.acknowledgedAt}/></dd></div>}
                </dl>
                {state === 'closed' && <p>{de ? 'Die Überwachung wurde beendet. Dies bestätigt keine Erholung.' : 'Monitoring was stopped. This does not confirm recovery.'}</p>}
                {current.maintenanceUntil && <p>{de ? 'Wartungsfenster bis: ' : 'Maintenance until: '}<Time value={current.maintenanceUntil}/></p>}
                <p>{incident.kind === 'service' ? (de ? 'Als Nächstes den Dienststatus und bei Bedarf die freigegebenen Dienstlogs prüfen.' : 'Next, inspect the service status and, if needed, the permitted service logs.') : incident.kind === 'filesystem' ? (de ? 'Als Nächstes die aktuellen Dateisystemwerte und die Belegung auf dem Gerät prüfen.' : 'Next, inspect current filesystem values and disk usage on the device.') : (de ? 'Als Nächstes den letzten Agent-Kontakt und den Agent-Dienst auf dem Gerät prüfen. Eine fehlende Übertragung beweist keinen Geräteausfall.' : 'Next, check the last agent contact and the agent service on the device. A missing report does not prove the device is down.')}</p>
                <div className="investigation-links"><a href={`${deviceURL}/health`}>{de ? 'Health & Verlauf öffnen' : 'Open Health & history'}<ArrowRight size={13}/></a><a href={`${deviceURL}/details`}>{de ? 'Gerätedetails' : 'Device details'}</a>{incident.kind === 'service' && validJournalUnit(incident.target) && <a href={`${deviceURL}/logs/${encodeURIComponent(incident.target)}`}>{de ? 'Dienstlogs öffnen' : 'Open service logs'}</a>}</div>
                {incident.kind === 'service' && !validJournalUnit(incident.target) && <p className="investigation-note">{de ? 'Für diesen Unit-Namen ist keine Journal-Verknüpfung verfügbar. Dienststatus in Health prüfen.' : 'A journal link is unavailable for this unit name. Inspect its service status in Health.'}</p>}
                <p className="investigation-note">{de ? 'Gespeicherter Regelverlauf und letzte Prüfung. Frühere Rohwerte oder Logzeilen werden hier nicht als Beleg gespeichert. Logs werden durch das Öffnen dieses Links nicht angefordert.' : 'Stored rule history and latest check. Earlier raw values or log lines are not saved here as evidence. Opening the logs link does not request a capture.'}</p>
            </details>}
            {concise && <button type="button" className="text-button" onClick={onAll}>{de ? 'Untersuchen' : 'Investigate'}<ArrowRight size={13}/></button>}
        </article>;
    })}</div>;
}
export function InvestigationsPage({ resource, devices, scope, offset, onScope, onPage }: { resource: InvestigationsResource; devices: Device[]; scope: InvestigationScope; offset: number; onScope: (scope: InvestigationScope) => void; onPage: (offset: number) => void }) {
    const [locale] = useLocale(), de = locale === 'de', view = resource.view, status = labels(de);
    const unavailableChecks = view?.devices.filter(device => device.checks.some(check => check.state === 'unknown')).length ?? 0;
    return <><div className="page-heading"><div><h1>{t('Untersuchungen')}</h1><p>{de ? 'Gespeicherte Health-Warnungen prüfen und den nächsten Schritt finden.' : 'Review stored health warnings and find the next check.'}</p></div><span className="rule-badge"><ShieldCheck size={15}/>{t('Deterministische Regeln')}</span></div>
        <div className="investigation-toolbar"><p>{de ? 'Agent-Kontakt · Root-Dateisystem / · ausgewählte Dienste' : 'Agent contact · Root filesystem / · selected services'}</p><button className="button small" disabled={resource.pending || resource.locked} onClick={resource.refresh}><RefreshCw size={14} className={resource.pending ? 'spin' : undefined}/>{de ? 'Untersuchungen aktualisieren' : 'Refresh investigations'}</button></div>
        <InvestigationNotice resource={resource}/>
        <div className="inventory-tabs" aria-label={de ? 'Untersuchungen filtern' : 'Filter investigations'}>{(['open', 'recovered', 'closed', 'all'] as const).map(item => <button key={item} className={scope === item ? 'selected' : ''} aria-pressed={scope === item} aria-label={`${status[item]} ${view?.counts[item] ?? '—'}`} onClick={() => onScope(item)}>{status[item]}<span>{view?.counts[item] ?? '—'}</span></button>)}</div>
        <section className="panel" aria-label={de ? 'Health-Untersuchungen' : 'Health investigations'}><SectionHead title={status[scope]} count={view?.total}/>{view && (view.items.length ? <InvestigationList view={view} devices={devices}/> : view.total > 0 ? <EmptyState title={de ? 'Diese Seite hat sich geändert' : 'This page has changed'} detail={de ? 'Der Verlauf enthält passende Fälle, aber diese Seite ist jetzt leer.' : 'Matching cases remain in the history, but this page is now empty.'} action={<button className="button small" onClick={() => onPage(0)}>{de ? 'Zur ersten Seite' : 'Go to first page'}</button>}/> : <EmptyState title={de ? 'Keine Fälle in dieser Ansicht' : 'No cases in this view'} detail={de ? 'Keine passenden Vorfälle im gespeicherten Verlauf. Fehlende Fälle bedeuten keinen gesunden Gerätezustand.' : 'No matching incidents in the retained history. Missing cases do not mean a healthy device.'}/>)}
            {!view && !resource.pending && <p className="investigation-note investigation-empty">{de ? 'Keine aktuellen Untersuchungsdaten verfügbar.' : 'No current investigation data available.'}</p>}
            {view && <div className="investigation-paging"><span>{view.items.length ? `${offset + 1}–${offset + view.items.length}` : '0'} / {view.total}</span><button className="button small" disabled={offset === 0 || resource.pending} onClick={() => onPage(Math.max(0, offset - INVESTIGATIONS_PAGE_SIZE))}>{de ? 'Zurück' : 'Previous'}</button><button className="button small" disabled={offset + view.items.length >= view.total || resource.pending} onClick={() => onPage(offset + INVESTIGATIONS_PAGE_SIZE)}>{de ? 'Weiter' : 'Next'}</button></div>}
        </section>
        {view && <p className="investigation-note">{de ? `${view.devices.length} freigegebene Linux-Geräte · ${unavailableChecks} mit nicht vollständig bewertbaren Prüfungen. Stand: ` : `${view.devices.length} authorized Linux devices · ${unavailableChecks} with incomplete current checks. Read at: `}<Time value={view.serverNow}/></p>}
        <p className="investigation-note">{de ? 'Lesende Zusammenfassung desselben Health-Verlaufs, keine separate Fallkopie. Bestätigen schließt einen Vorfall nicht. Erholung erfordert neue bestätigte Beobachtungen. Aufbewahrung: höchstens 100 Vorfälle pro Gerät; abgeschlossene Vorfälle werden bei der Auswertung nach 30 Tagen entfernt. Neue Vorfälle können die Seitenreihenfolge ändern.' : 'Read-only view of the same health history, without a separate case copy. Acknowledgement does not close an incident. Recovery requires new confirmed observations. Retention: at most 100 incidents per device; closed incidents are removed on evaluation after 30 days. New incidents can change page order.'}</p>
    </>;
}
