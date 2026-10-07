import { JournalAIInvestigation } from './journal-ai-result';
import { ArrowRight, RefreshCw } from 'lucide-react';
import { EmptyState } from './components';
import { t, useLocale } from './i18n';
import { fullDate } from './utils';
import { validJournalUnit } from './journal-types';
import { incidentScope, INVESTIGATIONS_PAGE_SIZE } from './investigations-types';
import type { InvestigationItem, InvestigationScope, InvestigationsView } from './investigations-types';
import type { InvestigationsResource } from './investigations-resource';
import type { Device } from './types';
import './investigations.css';
import { InvestigationAnalysisView } from './investigation-analysis';
const labels = (de: boolean) => ({ open: de ? 'Offen' : 'Open', recovered: de ? 'Erholt' : 'Recovered', closed: de ? 'Überwachung beendet' : 'Monitoring stopped', all: de ? 'Alle Fälle' : 'All cases' });
function title(item: InvestigationItem, de: boolean) { return item.incident.kind === 'offline' ? de ? 'Agent-Kontakt fehlt' : 'Agent contact missing' : item.incident.kind === 'filesystem' ? de ? 'Root-Dateisystem fast voll' : 'Root filesystem nearly full' : `${item.incident.target}: ${de ? 'Dienst inaktiv' : 'service inactive'}`; }
function Time({ value }: { value: string | null }) { return value ? <time dateTime={value} title={value}>{fullDate(value)}</time> : <span>{t('Zeitpunkt unbekannt')}</span>; }
function rule(item: InvestigationItem, de: boolean) {
    if (item.incident.kind === 'offline') return de ? 'Kein akzeptierter Bericht seit über 2 Minuten, weitere 60 Sekunden bestätigt.' : 'No accepted report for over 2 minutes, confirmed for another 60 seconds.';
    if (item.incident.kind === 'filesystem') return de ? 'Root-Dateisystem /: mindestens 90 % für 120 Sekunden. Erholung: höchstens 85 % für 60 Sekunden.' : 'Root filesystem /: at least 90% used for 120 seconds. Recovery: at most 85% for 60 seconds.';
    return de ? 'Dienst inaktiv oder fehlgeschlagen für 120 Sekunden. Erholung: 60 Sekunden aktiv.' : 'Service inactive or failed for 120 seconds. Recovery: active for 60 seconds.';
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
    return <>{resource.pending && !resource.view && <p className="investigations-note" role="status">{de ? 'Untersuchungen werden gelesen …' : 'Reading investigations…'}</p>}{resource.failure && <p className="investigation-failure" role="alert">{failureText(resource, de)}</p>}</>;
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
            <p className="investigations-note">{de ? 'Regelbasierte Warnung' : 'Rule-based warning'}{incident.acknowledgedAt && ` · ${de ? 'Bestätigt' : 'Acknowledged'}`}</p>
            <p className="investigations-note">{de ? 'Begonnen: ' : 'Opened: '}<Time value={incident.openedAt}/>{' · '}{de ? 'Letzter Beleg: ' : 'Last evidence: '}<Time value={incident.lastObservedAt}/></p>
            {!concise && <div className="investigation-links investigation-next"><a href={`${deviceURL}/health`}>{de ? 'Health prüfen' : 'Check Health'}<ArrowRight size={13}/></a>{incident.kind === 'service' && validJournalUnit(incident.target) && <a href={`${deviceURL}/logs/${encodeURIComponent(incident.target)}`}>{de ? 'Dienstlogs' : 'Service logs'}</a>}</div>}
            {!concise && <details className="investigation-evidence"><summary>{de ? 'Belege & nächste Prüfung' : 'Evidence & next check'}</summary>
                <p>{rule(item, de)}</p>
                <p>{de ? 'Ursache nicht ermittelt. Die Regel bestätigt nur den beobachteten Zustand.' : 'Cause undetermined. The rule confirms only the observed condition.'}</p>
                <dl><div><dt>{de ? 'Aktuelle Prüfung' : 'Current check'}</dt><dd>{!check ? (de ? 'Nicht mehr überwacht' : 'No longer monitored') : check.state === 'unknown' ? (de ? 'Unbekannt: aktuelle Belege fehlen oder sind veraltet' : 'Unknown: current evidence is missing or stale') : check.state === 'pending' ? t('Bestätigung ausstehend') : check.state === 'open' ? t('Warnung offen') : t('Schwelle nicht verletzt')}</dd></div>
                    {check && <><div><dt>{de ? 'Beobachtungszeit' : 'Observation time'}</dt><dd><Time value={check.observedAt}/></dd></div>{check.kind === 'filesystem' && check.state !== 'unknown' && check.value !== null && <div><dt>{de ? 'Aktuell belegt' : 'Currently used'}</dt><dd>{check.value.toFixed(1)} %</dd></div>}</>}
                    <div><dt>{de ? 'Health-Auswertung' : 'Health evaluation'}</dt><dd><Time value={current.evaluatedAt}/></dd></div>
                    {incident.resolvedAt && <div><dt>{status[state]}</dt><dd><Time value={incident.resolvedAt}/></dd></div>}
                    {incident.acknowledgedAt && <div><dt>{de ? 'Kenntnisnahme' : 'Acknowledged'}</dt><dd><Time value={incident.acknowledgedAt}/></dd></div>}
                </dl>
                {state === 'closed' && <p>{de ? 'Die Überwachung wurde beendet. Dies bestätigt keine Erholung.' : 'Monitoring was stopped. This does not confirm recovery.'}</p>}
                {current.maintenanceUntil && <p>{de ? 'Wartungsfenster bis: ' : 'Maintenance until: '}<Time value={current.maintenanceUntil}/></p>}
                <p>{incident.kind === 'service' ? (de ? 'Dienststatus und bei Bedarf freigegebene Logs prüfen.' : 'Check service status and, if needed, permitted logs.') : incident.kind === 'filesystem' ? (de ? 'Aktuelle Dateisystemwerte und Belegung auf dem Gerät prüfen.' : 'Check current filesystem values and disk usage on the device.') : (de ? 'Letzten Agent-Kontakt und Agent-Dienst prüfen. Fehlende Berichte beweisen keinen Geräteausfall.' : 'Check the last agent contact and agent service. Missing reports do not prove the device is down.')}</p>
                <div className="investigation-links"><a href={`${deviceURL}/details`}>{de ? 'Gerätedetails' : 'Device details'}</a></div>
                {incident.kind === 'service' && !validJournalUnit(incident.target) && <p className="investigations-note">{de ? 'Für diesen Unit-Namen ist keine Journal-Verknüpfung verfügbar. Dienststatus in Health prüfen.' : 'A journal link is unavailable for this unit name. Inspect its service status in Health.'}</p>}
                <p className="investigations-note">{de ? 'Keine früheren Rohwerte oder Logs gespeichert. Der Log-Link startet keine Erfassung.' : 'Earlier raw values and logs are not stored. The logs link does not start a capture.'}</p>
            </details>}
            {!concise && item.journalAI && <JournalAIInvestigation device={item.deviceId} incident={incident} state={item.journalAI.state}/>}
            {item.analysis && <InvestigationAnalysisView analysis={item.analysis} concise={concise}/>}
            {concise && <button type="button" className="text-button" onClick={onAll}>{de ? 'Untersuchen' : 'Investigate'}<ArrowRight size={13}/></button>}
        </article>;
    })}</div>;
}
function EmptyInvestigations({ view, scope, de }: { view: InvestigationsView; scope: InvestigationScope; de: boolean }) {
    if (!view.devices.length) return <EmptyState title={de ? 'Noch keine Geräte mit Health-Daten' : 'No devices with Health data yet'} detail={de ? 'Linux-Gerät und Health-Einrichtung prüfen. Kein Nachweis für gesunde Geräte.' : 'Check the Linux device and Health setup. This does not confirm device health.'} action={<a className="button" href="#/devices">{de ? 'Geräte prüfen' : 'Check devices'}</a>}/>;
    if (scope !== 'open') return <EmptyState title={de ? 'Keine Fälle in dieser Ansicht' : 'No cases in this view'} detail={de ? 'Keine passenden gespeicherten Vorfälle. Das bestätigt keinen gesunden Gerätezustand.' : 'No matching stored incidents. This does not confirm device health.'}/>;
    if (view.devices.some(device => device.evaluatedAt === null || device.checks.some(check => check.state === 'unknown'))) return <EmptyState title={de ? 'Keine offenen Vorfälle · Daten fehlen' : 'No open incidents · data missing'} detail={de ? 'Prüfwerte fehlen oder sind veraltet. Keine Entwarnung möglich.' : 'Check data is missing or stale. This does not confirm device health.'}/>;
    if (view.devices.some(device => device.checks.some(check => check.state === 'pending' || check.state === 'open'))) return <EmptyState title={de ? 'Noch kein bestätigter Vorfall' : 'No confirmed incident yet'} detail={de ? 'Health-Prüfungen sind auffällig oder werden noch bestätigt. Gerätewerte prüfen.' : 'Health checks are pending or show a warning. Review the device evidence.'}/>;
    return <EmptyState title={de ? 'Keine offenen Health-Probleme' : 'No open Health problems'} detail={de ? 'Nur die ausgewählten Health-Prüfungen, keine vollständige Geräteprüfung.' : 'Selected Health checks only, not a complete device assessment.'}/>;
}
export function InvestigationsPage({ resource, devices, scope, offset, onScope, onPage }: { resource: InvestigationsResource; devices: Device[]; scope: InvestigationScope; offset: number; onScope: (scope: InvestigationScope) => void; onPage: (offset: number) => void }) {
    const [locale] = useLocale(), de = locale === 'de', view = resource.view, status = labels(de);
    const unavailableChecks = view?.devices.filter(device => device.checks.some(check => check.state === 'unknown')).length ?? 0;
    return <><div className="page-heading"><h1>{t('Untersuchungen')}</h1><button className="button small" aria-label={de ? 'Untersuchungen aktualisieren' : 'Refresh investigations'} disabled={resource.pending || resource.locked} onClick={resource.refresh}><RefreshCw size={14} className={resource.pending ? 'spin' : undefined}/>{de ? 'Aktualisieren' : 'Refresh'}</button></div>
        <p className="investigations-note">{de ? 'Health-Probleme: Agentkontakt, Root-Dateisystem und ausgewählte Dienste. Vorhandene KI-Befunde stehen beim Vorfall.' : 'Health problems: agent contact, root filesystem and selected services. Available AI findings appear with the incident.'}</p>
        <InvestigationNotice resource={resource}/>
        <div className="inventory-tabs" aria-label={de ? 'Untersuchungen filtern' : 'Filter investigations'}>{(['open', 'recovered', 'closed', 'all'] as const).map(item => <button key={item} className={scope === item ? 'selected' : ''} aria-pressed={scope === item} aria-label={`${status[item]} ${view?.counts[item] ?? '—'}`} onClick={() => onScope(item)}>{status[item]}<span>{view?.counts[item] ?? '—'}</span></button>)}</div>
        <section className="panel" aria-label={de ? 'Health-Untersuchungen' : 'Health investigations'}>{view && (view.items.length ? <InvestigationList view={view} devices={devices}/> : view.total > 0 ? <EmptyState title={de ? 'Diese Seite hat sich geändert' : 'This page has changed'} detail={de ? 'Der Verlauf enthält passende Fälle, aber diese Seite ist jetzt leer.' : 'Matching cases remain in the history, but this page is now empty.'} action={<button className="button small" onClick={() => onPage(0)}>{de ? 'Zur ersten Seite' : 'Go to first page'}</button>}/> : <EmptyInvestigations view={view} scope={scope} de={de}/>)}
            {!view && !resource.pending && <p className="investigations-note investigation-empty">{de ? 'Keine aktuellen Untersuchungsdaten verfügbar.' : 'No current investigation data available.'}</p>}
            {view && <div className="investigation-paging"><span>{view.items.length ? `${offset + 1}–${offset + view.items.length}` : '0'} / {view.total}</span><button className="button small" disabled={offset === 0 || resource.pending} onClick={() => onPage(Math.max(0, offset - INVESTIGATIONS_PAGE_SIZE))}>{de ? 'Zurück' : 'Previous'}</button><button className="button small" disabled={offset + view.items.length >= view.total || resource.pending} onClick={() => onPage(offset + INVESTIGATIONS_PAGE_SIZE)}>{de ? 'Weiter' : 'Next'}</button></div>}
        </section>
        {view && <p className="investigations-note">{de ? `${view.devices.length} freigegebene Linux-Geräte · ${unavailableChecks} mit nicht vollständig bewertbaren Prüfungen. Stand: ` : `${view.devices.length} authorized Linux devices · ${unavailableChecks} with incomplete current checks. Read at: `}<Time value={view.serverNow}/></p>}
        <p className="investigations-note">{de ? 'Erholung erfordert neue bestätigte Beobachtungen. Maximal 100 Vorfälle pro Gerät; abgeschlossene Fälle werden bei der Auswertung nach 30 Tagen entfernt.' : 'Recovery requires new confirmed observations. Up to 100 incidents per device; closed cases are removed on evaluation after 30 days.'}</p>
    </>;
}
