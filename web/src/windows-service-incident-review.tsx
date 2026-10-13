import { useEffect, useRef, useState } from 'react';
import { AUTH_REQUIRED_EVENT, getProtectedRequestEpoch, request } from './api';
import { hasLogoutIntent, useOperator } from './auth';
import { useLocale } from './i18n';
import { validWindowsCapacityTimestamp } from './windows-capacity-types';
import { acceptWindowsHealthClock } from './windows-health-clock';
import { WindowsLocalTime } from './windows-local-time';
import { WindowsServiceActionsPanel } from './windows-service-actions';
import { validWindowsServiceIncidentReview, windowsServiceReviewCurrent, windowsServiceReviewClockKey, windowsServiceReviewRequestElapsed, windowsServiceReviewObservation, WINDOWS_SERVICE_INCIDENT_REVIEW_BYTES } from './windows-service-incident-review-types';
import type { WindowsServiceIncidentReviewContext } from './windows-service-incident-review-types';

const copy = {
    en: { title: 'Review incident service', close: 'Close service review', loading: 'Reading this incident’s service…', unavailable: 'This review is unavailable or expired. Close it and review the incident again.', current: 'Current reported service', unknown: 'Current service state is unknown. Missing or stale evidence does not establish a stopped service.', captured: 'Source capture', received: 'Manager receipt', active: 'Incident active', recovered: 'Incident recovered', policy: 'Closed after a policy change; recovery not established', opened: 'Incident opened', closed: 'Incident closed', evidence: 'Evidence & limits', match: 'Only this incident’s original device and exact service. Review an action separately.', not_configured: 'No separate service-control grant is configured.', unavailableControl: 'The separate service-control grant is unavailable.', target_mismatch: 'The local control grant does not match this incident’s exact service. Control is blocked.', operator_capability_required: 'A named operator with Windows service control permission is required. Incident acknowledgement and service control have separate permissions.', limit: 'This is the exact reported service name, not proof that the same service instance still exists. Observation does not establish application health or authorize an action.', partial: 'Caller-visible, partial source coverage', healthy: 'Caller-visible source coverage', running: 'Running', stopped: 'Stopped', paused: 'Paused', start_pending: 'Start pending', stop_pending: 'Stop pending', continue_pending: 'Continue pending', pause_pending: 'Pause pending' },
    de: { title: 'Vorfallsdienst prüfen', close: 'Dienstprüfung schließen', loading: 'Dienst dieses Vorfalls wird gelesen …', unavailable: 'Diese Prüfung ist nicht verfügbar oder abgelaufen. Schließe sie und prüfe den Vorfall erneut.', current: 'Aktuell gemeldeter Dienst', unknown: 'Der aktuelle Dienstzustand ist unbekannt. Fehlende oder veraltete Belege zeigen keinen gestoppten Dienst an.', captured: 'Quellerfassung', received: 'Manager-Empfang', active: 'Vorfall aktiv', recovered: 'Vorfall erholt', policy: 'Nach Richtlinienänderung geschlossen; keine Erholung belegt', opened: 'Vorfall geöffnet', closed: 'Vorfall geschlossen', evidence: 'Belege & Grenzen', match: 'Nur das ursprüngliche Gerät und der exakte Dienst. Aktion separat prüfen.', not_configured: 'Keine separate Freigabe zur Dienststeuerung eingerichtet.', unavailableControl: 'Die separate Freigabe zur Dienststeuerung ist nicht verfügbar.', target_mismatch: 'Die lokale Steuerungsfreigabe passt nicht zum exakten Dienst dieses Vorfalls. Die Steuerung ist gesperrt.', operator_capability_required: 'Ein benannter Operator mit Berechtigung zur Windows-Dienststeuerung ist erforderlich. Kenntnisnahme und Dienststeuerung haben separate Berechtigungen.', limit: 'Dies ist der exakt gemeldete Dienstname, kein Nachweis derselben Dienstinstanz. Die Beobachtung belegt weder den Anwendungszustand noch eine Aktionsberechtigung.', partial: 'Für den Aufrufer sichtbare, teilweise Quellabdeckung', healthy: 'Für den Aufrufer sichtbare Quellabdeckung', running: 'Läuft', stopped: 'Gestoppt', paused: 'Pausiert', start_pending: 'Start ausstehend', stop_pending: 'Stopp ausstehend', continue_pending: 'Fortsetzung ausstehend', pause_pending: 'Pause ausstehend' },
};
export function WindowsServiceIncidentReview({ incidentKey, deviceId, serviceName, sessionKey, onClose }: { incidentKey: string; deviceId: string; serviceName: string; sessionKey: string | null; onClose: () => void }) {
    const operator = useOperator(), [locale] = useLocale(), c = copy[locale];
    const scope = JSON.stringify([incidentKey, deviceId, serviceName, sessionKey, operator?.mode, operator?.authenticated, operator?.loginMode, operator?.actorId, operator?.capabilities]);
    const currentScope = useRef(scope); currentScope.current = scope;
    const [saved, setSaved] = useState<{ scope: string; context: WindowsServiceIncidentReviewContext } | null>(null), [loading, setLoading] = useState(true), [, tick] = useState(0);
    useEffect(() => {
        let alive = true, invalidated = false;
        const controller = new AbortController(), epoch = getProtectedRequestEpoch(), started = { mono: performance.now(), wall: Date.now(), epoch };
        let accepted: WindowsServiceIncidentReviewContext | null = null;
        const eligible = () => alive && !invalidated && currentScope.current === scope && epoch === getProtectedRequestEpoch() && !hasLogoutIntent() && document.visibilityState !== 'hidden' && operator?.mode === 'lan' && operator.authenticated && validWindowsCapacityTimestamp(sessionKey);
        const clear = () => { invalidated = true; controller.abort(); accepted = null; if (alive) { setSaved(null); setLoading(false); } };
        setSaved(null); setLoading(true);
        const timeout = window.setTimeout(clear, 10000);
        if (eligible()) void request<unknown>(`/fleet/windows-incidents/${incidentKey}/service-review`, { signal: controller.signal }, WINDOWS_SERVICE_INCIDENT_REVIEW_BYTES).then(value => {
            if (!eligible() || controller.signal.aborted || !validWindowsServiceIncidentReview(value, incidentKey, deviceId, serviceName)) { clear(); return; }
            const context: WindowsServiceIncidentReviewContext = { view: value, sessionKey: sessionKey!, anchor: started };
            if (!acceptWindowsHealthClock(windowsServiceReviewClockKey(sessionKey!), epoch, value.serverNow, windowsServiceReviewRequestElapsed(context)) || !windowsServiceReviewCurrent(context)) { clear(); return; }
            accepted = context; setSaved({ scope, context }); setLoading(false);
        }).catch(() => { if (alive) clear(); }).finally(() => window.clearTimeout(timeout)); else clear();
        const timer = window.setInterval(() => { if (!eligible() || accepted && !windowsServiceReviewCurrent(accepted)) clear(); else if (accepted) tick(n => n + 1); }, 250);
        const events = [AUTH_REQUIRED_EVENT, 'blur', 'pagehide', 'hashchange', 'popstate'];
        for (const event of events) window.addEventListener(event, clear);
        const visibility = () => { if (document.visibilityState === 'hidden') clear(); };
        document.addEventListener('visibilitychange', visibility);
        return () => { alive = false; controller.abort(); window.clearTimeout(timeout); window.clearInterval(timer); for (const event of events) window.removeEventListener(event, clear); document.removeEventListener('visibilitychange', visibility); };
    }, [scope, incidentKey, deviceId, serviceName, sessionKey]);
    const context = saved?.scope === scope && windowsServiceReviewCurrent(saved.context) && !hasLogoutIntent() ? saved.context : null;
    const view = context?.view, row = context ? windowsServiceReviewObservation(context) : null;
    const evidence = <>{row&&<><p>{c.captured}: <WindowsLocalTime value={row.collectedAt} locale={locale}/> · {c.received}: <WindowsLocalTime value={row.receivedAt} locale={locale}/></p><p>{c[row.quality]}</p></>}<p>{c.limit}</p></>;
    return <section className="windows-service-incident-review" aria-label={c.title}>
        <header><h3>{c.title}: {serviceName}</h3><button type="button" className="text-button" onClick={onClose}>{c.close}</button></header>
        {loading ? <p role="status">{c.loading}</p> : !view ? <p role="alert">{c.unavailable}</p> : <>
            <p><strong>{!view.incident.resolvedAt ? c.active : view.incident.closedReason === 'policy-changed' ? c.policy : c.recovered}</strong> · {c.opened}: <WindowsLocalTime value={view.incident.openedAt} locale={locale}/>{view.incident.resolvedAt && <> · {c.closed}: <WindowsLocalTime value={view.incident.resolvedAt} locale={locale}/></>}</p>
            {row ? <><p>{c.current}: <strong>{row.displayName || row.name}</strong> · {c[row.state]}</p>{row.quality==='partial'&&<p>{c.partial}</p>}</> : <p>{c.unknown}</p>}
            {view.control.status === 'matched' && context ? <><p>{c.match}</p><WindowsServiceActionsPanel deviceId={deviceId} sessionKey={sessionKey} review={context} reviewEvidence={evidence}/></> : <p role="status">{view.control.status === 'unavailable' ? c.unavailableControl : view.control.status === 'matched' ? c.unavailable : c[view.control.status]}</p>}
            {view.control.status!=='matched'&&<details className="windows-inventory-scope"><summary>{c.evidence}</summary>{evidence}</details>}
        </>}
    </section>;
}
