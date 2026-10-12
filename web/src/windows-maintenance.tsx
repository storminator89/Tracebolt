import { useEffect, useState } from 'react';
import { ChevronDown, ChevronRight, Clock3, RefreshCw } from 'lucide-react';
import { inventoryAge } from './complete-packages-types';
import { useLocale } from './i18n';
import type { Device } from './types';
import { useWindowsMaintenance } from './windows-maintenance-resource';
import { WINDOWS_MAINTENANCE_DOMAINS, windowsMaintenanceCanStart, windowsMaintenanceEndTime, windowsMaintenanceState } from './windows-maintenance-types';
import type { WindowsMaintenanceDomain, WindowsMaintenanceEnd, WindowsMaintenanceIntent, WindowsMaintenanceStart, WindowsMaintenanceTarget, WindowsMaintenanceWindow } from './windows-maintenance-types';
import './windows-maintenance.css';

const copy = {
    en: {
        title: 'Windows maintenance', explanation: 'Marks planned maintenance until the reviewed end time. Checks and incidents continue; external alarms aren’t suppressed.', fleet: 'Fleet-wide; device search and group filters do not narrow these labels.', device: 'Exact Windows device', chooseDevice: 'Choose a device', domain: 'Maintenance scope', all: 'All Windows checks', contact: 'Contact', cpu: 'CPU percentage', disk: 'System-volume capacity', memory: 'Physical RAM percentage', service: 'Selected-service checks', intent: 'Operator intent', chooseIntent: 'Choose an intent', 'planned-work': 'Planned work', investigation: 'Investigation', other: 'Other maintenance', duration: 'Duration', minutes: 'minutes', day: '24 hours', reviewStart: 'Review maintenance start', start: 'Start maintenance', reviewEnd: 'Review early end', end: 'End maintenance now', cancel: 'Cancel review', review: 'Review exact maintenance change', exactEnd: 'Scheduled end (UTC)', startsNow: 'Starts when the manager accepts this change.', earlyEnd: 'End only the selected active window now. Its original scheduled end remains in history.', reviewExpired: 'This review is no longer current. Refresh and review again.', now: 'Maintenance now', until: 'until', ended: 'Ended early', expired: 'Expired', unknown: 'Unavailable', startedAt: 'Started', endedAt: 'Ended', history: 'Latest maintenance windows', retention: 'Latest four windows for this exact identity and scope. Expired means the bounded time ended; it does not establish recovery.', emptyHistory: 'No maintenance windows for this identity and scope.', empty: 'No admitted Windows targets are available.', noActive: 'No current maintenance labels. This is not a health assessment.', overlap: 'A current all-checks or matching-scope window overlaps this selection. End it or wait for expiry before starting another.', readOnly: 'Only the shared administrator can start or end maintenance. Your access is read-only.', refresh: 'Refresh maintenance', loading: 'Loading maintenance…', failed: 'Maintenance is unavailable or expired. Refresh before making a change.', started: 'Maintenance started. Incident and source states are unchanged.', endedNotice: 'Maintenance ended early. No recovery is implied.', uncertain: 'The change could not be confirmed. Only the current state is read again; the write is not retried. This target stays blocked while its revision is unchanged.', uncertainTarget: 'Unconfirmed change; refresh to reconcile', revision: 'Revision', activeLabels: 'Current maintenance labels',
    },
    de: {
        title: 'Windows-Wartung', explanation: 'Markiert geplante Wartung bis zum geprüften Ende. Prüfungen und Vorfälle laufen weiter; externe Alarme werden nicht unterdrückt.', fleet: 'Flottenweit; Gerätesuche und Gruppenfilter grenzen diese Markierungen nicht ein.', device: 'Exaktes Windows-Gerät', chooseDevice: 'Gerät auswählen', domain: 'Wartungsumfang', all: 'Alle Windows-Prüfungen', contact: 'Kontakt', cpu: 'CPU-Prozentwert', disk: 'Kapazität des Systemvolumes', memory: 'Physischer RAM-Prozentwert', service: 'Prüfungen ausgewählter Dienste', intent: 'Absicht des Operators', chooseIntent: 'Absicht auswählen', 'planned-work': 'Geplante Arbeiten', investigation: 'Untersuchung', other: 'Sonstige Wartung', duration: 'Dauer', minutes: 'Minuten', day: '24 Stunden', reviewStart: 'Wartungsstart prüfen', start: 'Wartung starten', reviewEnd: 'Vorzeitiges Ende prüfen', end: 'Wartung jetzt beenden', cancel: 'Prüfung abbrechen', review: 'Exakte Wartungsänderung prüfen', exactEnd: 'Geplantes Ende (UTC)', startsNow: 'Beginnt, wenn der Manager diese Änderung annimmt.', earlyEnd: 'Nur das ausgewählte aktive Fenster jetzt beenden. Das ursprünglich geplante Ende bleibt im Verlauf.', reviewExpired: 'Diese Prüfung ist nicht mehr aktuell. Aktualisieren und erneut prüfen.', now: 'Wartung jetzt', until: 'bis', ended: 'Vorzeitig beendet', expired: 'Abgelaufen', unknown: 'Nicht verfügbar', startedAt: 'Begonnen', endedAt: 'Beendet', history: 'Letzte Wartungsfenster', retention: 'Die letzten vier Fenster für diese exakte Identität und diesen Umfang. Abgelaufen bedeutet nur, dass die Zeit endete; es belegt keine Erholung.', emptyHistory: 'Keine Wartungsfenster für diese Identität und diesen Umfang.', empty: 'Keine zugelassenen Windows-Ziele verfügbar.', noActive: 'Keine aktuellen Wartungsmarkierungen. Dies ist keine Health-Bewertung.', overlap: 'Ein aktuelles Fenster für alle Prüfungen oder diesen Umfang überschneidet sich mit der Auswahl. Vor einem neuen Start beenden oder den Ablauf abwarten.', readOnly: 'Nur der gemeinsame Administrator kann Wartung starten oder beenden. Dein Zugriff ist nur lesend.', refresh: 'Wartung aktualisieren', loading: 'Wartung wird geladen …', failed: 'Wartung ist nicht verfügbar oder abgelaufen. Vor einer Änderung aktualisieren.', started: 'Wartung gestartet. Vorfalls- und Quellzustände bleiben unverändert.', endedNotice: 'Wartung vorzeitig beendet. Daraus folgt keine Erholung.', uncertain: 'Die Änderung konnte nicht bestätigt werden. Nur der aktuelle Stand wird erneut gelesen; der Schreibvorgang wird nicht wiederholt. Dieses Ziel bleibt bei unveränderter Version gesperrt.', uncertainTarget: 'Änderung unbestätigt; zum Abgleichen aktualisieren', revision: 'Version', activeLabels: 'Aktuelle Wartungsmarkierungen',
    },
};
type Copy = typeof copy.en;
type Review = { generation: number; kind: 'start'; body: WindowsMaintenanceStart } | { generation: number; kind: 'end'; body: WindowsMaintenanceEnd };
function MaintenanceTime({ value, locale }: { value: string; locale: string }) {
    return <time dateTime={value} title={value}>{new Date(value).toLocaleString(locale === 'de' ? 'de-DE' : 'en-GB')}</time>;
}
function MaintenanceState({ window, serverNow, age, c, locale }: { window: WindowsMaintenanceWindow; serverNow: string; age: number; c: Copy; locale: string }) {
    const state = windowsMaintenanceState(window, serverNow, age);
    return <span className={`windows-maintenance-badge is-${state}`}>{state === 'active' ? <>{c.now} · {c.until} <MaintenanceTime value={window.endsAt} locale={locale}/></> : c[state]}</span>;
}

/** Separate snapshots: maintenance metadata is never joined to incident rows. */
export function WindowsMaintenance({ devices, sessionKey, admin }: { devices: Device[]; sessionKey: string | null; admin: boolean }) {
    const [locale] = useLocale(), c = copy[locale];
    const [opened, setOpened] = useState(false), [deviceKey, setDeviceKey] = useState(''), [domain, setDomain] = useState<WindowsMaintenanceDomain>('all'), [intent, setIntent] = useState<WindowsMaintenanceIntent | ''>(''), [minutes, setMinutes] = useState(30), [review, setReview] = useState<Review | null>(null);
    const resource = useWindowsMaintenance(opened, sessionKey, admin), view = resource.view;
    useEffect(() => { setReview(null); }, [resource.generation, deviceKey, domain, intent, minutes]);
    const names = new Map(devices.filter(device => device.platform === 'windows' && device.source === 'lan' && !device.synthetic).map(device => [device.id, device.name]));
    const label = (target: WindowsMaintenanceTarget) => names.has(target.deviceId) ? `${names.get(target.deviceId)} · ${target.deviceId}` : target.deviceId;
    // The opaque all-scope key binds the selection to one original identity.
    const selectedDevice = view?.targets.find(target => target.key === deviceKey && target.domain === 'all');
    const target = selectedDevice && view?.targets.find(item => item.deviceId === selectedDevice.deviceId && item.domain === domain);
    const active = view?.targets.filter(item => item.windows[0] && windowsMaintenanceState(item.windows[0], view.serverNow, resource.age) === 'active') ?? [];
    const canStart = !!view && !!target && windowsMaintenanceCanStart(view, target, resource.age), uncertain = !!target && resource.isUncertain(target);
    const current = target?.windows[0], canEnd = !!view && !!current && windowsMaintenanceState(current, view.serverNow, resource.age) === 'active';
    const currentReview = review && review.generation === resource.generation && target?.key === review.body.key && target.revision === review.body.revision ? review : null;
    const reviewAllowed = !!currentReview && !resource.writing && !uncertain && (currentReview.kind === 'start' ? canStart && inventoryAge(currentReview.body.endsAt, view!.serverNow) - resource.age >= 60000 : canEnd && current!.id === currentReview.body.windowId);
    const beginReview = () => {
        if (!view || !target || !intent || !canStart || uncertain || resource.writing) return;
        const endsAt = windowsMaintenanceEndTime(view.serverNow, resource.age, minutes);
        if (endsAt) setReview({ generation: resource.generation, kind: 'start', body: { key: target.key, revision: target.revision, endsAt, intent } });
    };
    return <section className="windows-maintenance" aria-label={c.title}>
        <button className="text-button windows-maintenance-toggle" aria-expanded={opened} onClick={() => { setReview(null); setOpened(value => !value); }}><Clock3 size={15}/><span>{c.title}</span>{opened ? <ChevronDown size={14}/> : <ChevronRight size={14}/>}</button>
        {opened && <div className="windows-maintenance-content">
            <p>{c.explanation}</p>
            <div className="windows-maintenance-refresh"><button className="text-button" disabled={resource.loading || resource.writing} onClick={resource.refresh}><RefreshCw size={14}/>{c.refresh}</button></div>
            {!admin && <p>{c.readOnly}</p>}
            {resource.notice && <p role="status">{resource.notice === 'started' ? c.started : resource.notice === 'ended' ? c.endedNotice : c.uncertain}</p>}
            {resource.loading && <p role="status">{c.loading}</p>}
            {resource.error && <p role="alert">{c.failed}</p>}
            {view && <>
                {active.length > 0 ? <ul className="windows-maintenance-active" aria-label={c.activeLabels}>{active.map(item => <li key={item.key}><span>{label(item)} · {c[item.domain]}</span><MaintenanceState window={item.windows[0]} serverNow={view.serverNow} age={resource.age} c={c} locale={locale}/></li>)}</ul> : <p>{c.noActive}</p>}
                {view.targets.length === 0 ? <p>{c.empty}</p> : <>
                    <div className="windows-maintenance-fields">
                        <label>{c.device}<select aria-label={c.device} value={selectedDevice?.key ?? ''} disabled={resource.writing} onChange={event => { setDeviceKey(event.target.value); setIntent(''); setReview(null); }}><option value="">{c.chooseDevice}</option>{view.targets.filter(item => item.domain === 'all').map(item => <option key={item.key} value={item.key}>{label(item)}</option>)}</select></label>
                        <label>{c.domain}<select aria-label={c.domain} value={domain} disabled={!selectedDevice || resource.writing} onChange={event => { setDomain(event.target.value as WindowsMaintenanceDomain); setIntent(''); setReview(null); }}>{WINDOWS_MAINTENANCE_DOMAINS.map(value => <option key={value} value={value}>{c[value]}</option>)}</select></label>
                    </div>
                    {target && <>
                        {admin && <>
                            {uncertain && <p role="status">{c.uncertainTarget}</p>}
                            {canStart ? <div className="windows-maintenance-fields">
                                <label>{c.intent}<select aria-label={c.intent} value={intent} disabled={resource.writing || uncertain} required onChange={event => { setIntent(event.target.value as WindowsMaintenanceIntent | ''); setReview(null); }}><option value="">{c.chooseIntent}</option>{(['planned-work', 'investigation', 'other'] as const).map(value => <option key={value} value={value}>{c[value]}</option>)}</select></label>
                                <label>{c.duration}<select aria-label={c.duration} value={minutes} disabled={resource.writing || uncertain} onChange={event => { setMinutes(Number(event.target.value)); setReview(null); }}>{[15, 30, 60, 120, 240, 480, 1440].map(value => <option key={value} value={value}>{value === 1440 ? c.day : `${value} ${c.minutes}`}</option>)}</select></label>
                                <button className="button small" disabled={!intent || resource.writing || uncertain} onClick={beginReview}>{c.reviewStart}</button>
                            </div> : <p>{c.overlap}</p>}
                            {canEnd && <button className="button small" disabled={resource.writing || uncertain || target.revision >= Number.MAX_SAFE_INTEGER} onClick={() => setReview({ generation: resource.generation, kind: 'end', body: { key: target.key, revision: target.revision, windowId: current!.id } })}>{c.reviewEnd}</button>}
                            {currentReview && <div className="windows-maintenance-review" role="region" aria-label={c.review}>
                                <strong>{c.review}</strong><p>{label(target)} · {c[target.domain]} · {c.revision} {target.revision}</p>
                                {currentReview.kind === 'start' ? <><p>{c.intent}: {c[currentReview.body.intent]}</p><p>{c.startsNow}</p><p>{c.exactEnd}: <time dateTime={currentReview.body.endsAt}>{currentReview.body.endsAt}</time></p></> : <><p>{c.earlyEnd}</p><p>{c.exactEnd}: <time dateTime={current!.endsAt}>{current!.endsAt}</time></p></>}
                                {!reviewAllowed && <p role="status">{c.reviewExpired}</p>}
                                <div className="windows-maintenance-actions"><button className="button small" disabled={!reviewAllowed} onClick={() => { const approved = currentReview; setReview(null); if (reviewAllowed) void (approved.kind === 'start' ? resource.start(approved.body) : resource.end(approved.body)); }}>{currentReview.kind === 'start' ? c.start : c.end}</button><button className="text-button" disabled={resource.writing} onClick={() => setReview(null)}>{c.cancel}</button></div>
                            </div>}
                        </>}
                        <details className="windows-maintenance-history"><summary>{c.history} · {c[target.domain]}</summary><p>{c.retention}</p>{target.windows.length === 0 ? <p>{c.emptyHistory}</p> : <ol>{target.windows.map(window => <li key={window.id}><MaintenanceState window={window} serverNow={view.serverNow} age={resource.age} c={c} locale={locale}/><span>{c.intent}: {c[window.intent]}</span><span>{c.startedAt}: <MaintenanceTime value={window.startedAt} locale={locale}/></span><span>{c.exactEnd}: <time dateTime={window.endsAt}>{window.endsAt}</time></span>{window.endedAt && <span>{c.endedAt}: <MaintenanceTime value={window.endedAt} locale={locale}/></span>}</li>)}</ol>}</details>
                    </>}
                </>}
                <p>{c.fleet}</p>
            </>}
        </div>}
    </section>;
}
