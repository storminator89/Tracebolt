import { useEffect, useRef, useState } from 'react';
import { AUTH_REQUIRED_EVENT, getProtectedRequestEpoch, request } from './api';
import { hasLogoutIntent, useOperator } from './auth';
import { useLocale } from './i18n';
import { validWindowsCapacityTimestamp } from './windows-capacity-types';
import { acceptWindowsHealthClock } from './windows-health-clock';
import { WindowsLocalTime } from './windows-local-time';
import { WindowsServiceActionsPanel } from './windows-service-actions';
import { windowsServiceReviewCurrent, windowsServiceReviewClockKey, windowsServiceReviewRequestElapsed, WINDOWS_SERVICE_INCIDENT_REVIEW_BYTES } from './windows-service-incident-review-types';
import { validWindowsCompleteServiceIncidentReview, windowsCompleteServiceReviewObservation } from './windows-complete-service-incident-review-types';
import type { WindowsCompleteServiceIncidentReviewContext } from './windows-complete-service-incident-review-types';

const copy = {
    en: { title: 'Review incident service', close: 'Close service review', loading: 'Reading service…', unavailable: 'Review expired or unavailable. Close and reopen it.', current: 'Current reported state', unknown: 'Current state unknown. Missing evidence does not mean stopped.', active: 'Incident active', recovered: 'Incident recovered', policy: 'Policy closed; recovery not established', opened: 'Opened', closed: 'Closed', evidence: 'Times and provenance', source: 'Complete service inventory', captured: 'Capture started', finished: 'Capture finished', received: 'Final manager receipt', expires: 'Inventory retention expires', grant: 'Grant', revision: 'Revision', generation: 'Generation', digest: 'Manifest SHA-256', sequence: 'Capture sequence', rows: 'Generation rows', match: 'Separate control grant matched. Choose and review an action.', not_configured: 'No separate control grant.', unavailableControl: 'Control grant unavailable.', target_mismatch: 'Control grant targets another identity or service.', operator_capability_required: 'Named Windows service-control permission required.', unsupported_target: 'Read-only: this service name is outside the supported control targets.', limit: 'Exact reported name; service-instance continuity and application health are not established. Reading creates no action.', running: 'Running', stopped: 'Stopped', paused: 'Paused', start_pending: 'Start pending', stop_pending: 'Stop pending', continue_pending: 'Continue pending', pause_pending: 'Pause pending', unknownState: 'Unknown' },
    de: { title: 'Vorfallsdienst prüfen', close: 'Dienstprüfung schließen', loading: 'Dienst wird gelesen …', unavailable: 'Prüfung abgelaufen oder nicht verfügbar. Schließen und neu öffnen.', current: 'Aktuell gemeldeter Zustand', unknown: 'Aktueller Zustand unbekannt. Fehlende Belege bedeuten nicht gestoppt.', active: 'Vorfall aktiv', recovered: 'Vorfall erholt', policy: 'Richtlinie geschlossen; keine Erholung belegt', opened: 'Geöffnet', closed: 'Geschlossen', evidence: 'Zeiten und Herkunft', source: 'Vollständiges Dienstinventar', captured: 'Erfassung begonnen', finished: 'Erfassung beendet', received: 'Finaler Manager-Empfang', expires: 'Inventaraufbewahrung endet', grant: 'Freigabe', revision: 'Revision', generation: 'Generation', digest: 'Manifest-SHA-256', sequence: 'Erfassungssequenz', rows: 'Generationszeilen', match: 'Separate Steuerungsfreigabe passt. Aktion auswählen und prüfen.', not_configured: 'Keine separate Steuerungsfreigabe.', unavailableControl: 'Steuerungsfreigabe nicht verfügbar.', target_mismatch: 'Steuerungsfreigabe gehört zu anderer Identität oder anderem Dienst.', operator_capability_required: 'Benannte Berechtigung zur Windows-Dienststeuerung erforderlich.', unsupported_target: 'Nur lesen: Dieser Dienstname liegt außerhalb der unterstützten Steuerungsziele.', limit: 'Exakt gemeldeter Name; Dienstkontinuität und Anwendungszustand sind nicht belegt. Lesen erzeugt keine Aktion.', running: 'Läuft', stopped: 'Gestoppt', paused: 'Pausiert', start_pending: 'Start ausstehend', stop_pending: 'Stopp ausstehend', continue_pending: 'Fortsetzung ausstehend', pause_pending: 'Pause ausstehend', unknownState: 'Unbekannt' },
};
export function WindowsCompleteServiceIncidentReview({ incidentKey, deviceId, serviceName, sessionKey, onClose }: { incidentKey: string; deviceId: string; serviceName: string; sessionKey: string | null; onClose: () => void }) {
    const operator = useOperator(), [locale] = useLocale(), c = copy[locale];
    const scope = JSON.stringify([incidentKey, deviceId, serviceName, sessionKey, operator?.mode, operator?.authenticated, operator?.loginMode, operator?.actorId, operator?.capabilities]);
    const currentScope = useRef(scope); currentScope.current = scope;
    const [saved, setSaved] = useState<{ scope: string; context: WindowsCompleteServiceIncidentReviewContext } | null>(null), [loading, setLoading] = useState(true), [, tick] = useState(0);
    useEffect(() => {
        let alive = true, invalidated = false;
        const controller = new AbortController(), epoch = getProtectedRequestEpoch(), started = { mono: performance.now(), wall: Date.now(), epoch };
        let accepted: WindowsCompleteServiceIncidentReviewContext | null = null;
        const eligible = () => alive && !invalidated && currentScope.current === scope && epoch === getProtectedRequestEpoch() && !hasLogoutIntent() && document.visibilityState !== 'hidden' && operator?.mode === 'lan' && operator.authenticated && validWindowsCapacityTimestamp(sessionKey);
        const clear = () => { invalidated = true; controller.abort(); accepted = null; if (alive) { setSaved(null); setLoading(false); } };
        setSaved(null); setLoading(true);
        const timeout = window.setTimeout(clear, 10000);
        if (eligible()) void request<unknown>(`/fleet/windows-incidents/complete/${incidentKey}/service-review`, { signal: controller.signal }, WINDOWS_SERVICE_INCIDENT_REVIEW_BYTES).then(value => {
            if (!eligible() || controller.signal.aborted || !validWindowsCompleteServiceIncidentReview(value, incidentKey, deviceId, serviceName)) { clear(); return; }
            const context: WindowsCompleteServiceIncidentReviewContext = { view: value, sessionKey: sessionKey!, anchor: started };
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
    const view = context?.view, row = context ? windowsCompleteServiceReviewObservation(context) : null;
    return <section className="windows-service-incident-review windows-complete-service-incident-review" aria-label={c.title}>
        <header><h3>{c.title}: {serviceName}</h3><button type="button" className="text-button" onClick={onClose}>{c.close}</button></header>
        {loading ? <p role="status">{c.loading}</p> : !view ? <p role="alert">{c.unavailable}</p> : <>
            <p><strong>{!view.incident.resolvedAt ? c.active : view.incident.closedReason === 'policy-changed' ? c.policy : c.recovered}</strong> · {c.opened}: <WindowsLocalTime value={view.incident.openedAt} locale={locale}/>{view.incident.resolvedAt && <> · {c.closed}: <WindowsLocalTime value={view.incident.resolvedAt} locale={locale}/></>}</p>
            <p>{row ? <>{c.current}: <strong>{row.state === 'unknown' ? c.unknownState : c[row.state]}</strong>{row.displayName && <> · {row.displayName}</>}</> : c.unknown}</p>
            <details className="windows-incident-provenance"><summary>{c.evidence}</summary>
                <p>{c.limit}</p>
                {row && <><p>{c.source}</p><dl>
                    {([['capturedAt', c.captured], ['captureFinishedAt', c.finished], ['receivedAt', c.received], ['expiresAt', c.expires]] as const).map(([field, label]) => <div key={field}><dt>{label}</dt><dd><WindowsLocalTime value={row.source[field]} locale={locale} exact/></dd></div>)}
                    {([['grantId', c.grant], ['grantRevision', c.revision], ['generationId', c.generation], ['manifestSha256', c.digest], ['sequence', c.sequence], ['rowCount', c.rows]] as const).map(([field, label]) => <div key={field}><dt>{label}</dt><dd className="windows-incident-identity">{row.source[field]}</dd></div>)}
                </dl></>}
            </details>
            {view.control.status === 'matched' && context ? <><p>{c.match}</p><WindowsServiceActionsPanel deviceId={deviceId} sessionKey={sessionKey} review={context}/></> : <p role="status">{view.control.status === 'unavailable' ? c.unavailableControl : view.control.status === 'matched' ? c.unavailable : c[view.control.status]}</p>}
        </>}
    </section>;
}
