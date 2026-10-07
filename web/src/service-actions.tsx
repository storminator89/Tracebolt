import { useEffect, useId, useRef, useState } from 'react';
import { LoaderCircle, RefreshCw, TriangleAlert } from 'lucide-react';
import { useLocale } from './i18n';
import type { ServiceActionPreview } from './service-action-types';
import type { useServiceActions } from './service-action-resource';
import './service-actions.css';

const copy = {
    en: {
        heading: 'Service action', select: 'Preview try-restart', refresh: 'Check action status', loading: 'Checking service action…', preparing: 'Preparing preview…', approving: 'Submitting approval…', cancel: 'Close preview', review: 'Review service action', approve: 'Approve try-restart',
        unavailable: 'Service actions unavailable.', access: 'A named operator with restart_service permission is required.',
        not_configured: 'Service actions are not configured.', operator_capability_required: 'A named operator with restart_service permission is required.', helper_unavailable: 'No compatible local helper report is available.', helper_stale: 'The local helper report is stale.', helper_disabled: 'The local helper is disabled.', action_in_progress: 'An existing action blocks another approval.', needs_intervention: 'Outcome unknown. Local investigation is required before another action.', capacity: 'Service-action capacity is unavailable.', ready: 'Choose a permitted service to preview try-restart.',
        warning: 'This may interrupt the service and its dependents. Only an active service can be restarted; inactive services are not started.', acknowledge: 'I accept the interruption risk for this exact action.', http: 'Disposable HTTP test: operator sessions and data are unencrypted. A stolen session can authorize actions in this local scope.',
        device: 'Device', unit: 'Service', actor: 'Operator', action: 'Action', expires: 'Preview expires', details: 'Approval details', plan: 'Plan digest', root: 'Local policy digest', digest: 'Preview digest', unitPolicy: 'Service policy digest', key: 'Command key ID', incarnation: 'Enrollment binding', transport: 'Transport profile',
        read: 'Status could not be checked. Check again before continuing.', invalid: 'The manager returned an unsupported or inconsistent action response. Approval is disabled.', session: 'Service-action access ended or changed. Sign in again.', expired: 'The preview expired. Check status and request a fresh preview.', changed: 'The action or permission changed. Review a fresh preview before approving.', uncertain: 'Approval is unconfirmed. Check the saved status; do not submit another approval.', clock: 'The time anchor is no longer reliable. Check status before continuing.',
        job: 'Saved action', approved: 'Approved; awaiting agent delivery. Execution is unconfirmed.', claimed: 'Claimed for delivery. Delivery, execution and outcome are unconfirmed until a result arrives.', operation_completed: 'Agent reports command completion. Restart and service health remain unconfirmed.', not_started: 'Agent reports that the operation was not started.', jobExpired: 'The action start window expired.', reported: 'Agent-reported result', observed: 'Reported state', reason: 'Reported reason', deadline: 'Start deadline', noRetry: 'No automatic retry. Check saved status for the result.',
    },
    de: {
        heading: 'Dienstaktion', select: 'Try-Restart prüfen', refresh: 'Aktionsstatus prüfen', loading: 'Dienstaktion wird geprüft…', preparing: 'Vorschau wird erstellt…', approving: 'Freigabe wird übermittelt…', cancel: 'Vorschau schließen', review: 'Dienstaktion prüfen', approve: 'Try-Restart freigeben',
        unavailable: 'Dienstaktionen nicht verfügbar.', access: 'Ein benannter Operator mit restart_service-Berechtigung ist erforderlich.',
        not_configured: 'Dienstaktionen sind nicht eingerichtet.', operator_capability_required: 'Ein benannter Operator mit restart_service-Berechtigung ist erforderlich.', helper_unavailable: 'Kein kompatibler lokaler Helper-Bericht verfügbar.', helper_stale: 'Der lokale Helper-Bericht ist veraltet.', helper_disabled: 'Der lokale Helper ist deaktiviert.', action_in_progress: 'Eine bestehende Aktion blockiert eine weitere Freigabe.', needs_intervention: 'Ausgang unbekannt. Vor einer weiteren Aktion ist eine lokale Prüfung erforderlich.', capacity: 'Kapazität für Dienstaktionen ist nicht verfügbar.', ready: 'Freigegebenen Dienst für die Try-Restart-Vorschau wählen.',
        warning: 'Der Dienst und abhängige Dienste können unterbrochen werden. Nur aktive Dienste werden neu gestartet; inaktive Dienste bleiben gestoppt.', acknowledge: 'Ich bestätige das Unterbrechungsrisiko für genau diese Aktion.', http: 'Einmaliger HTTP-Test: Operator-Sitzungen und Daten sind unverschlüsselt. Eine gestohlene Sitzung kann Aktionen innerhalb dieser lokalen Freigabe autorisieren.',
        device: 'Gerät', unit: 'Dienst', actor: 'Operator', action: 'Aktion', expires: 'Vorschau gültig bis', details: 'Freigabedetails', plan: 'Plan-Digest', root: 'Lokaler Policy-Digest', digest: 'Vorschau-Digest', unitPolicy: 'Dienst-Policy-Digest', key: 'Befehlsschlüssel-ID', incarnation: 'Enrollment-Bindung', transport: 'Transportprofil',
        read: 'Status konnte nicht geprüft werden. Vor dem Fortfahren erneut prüfen.', invalid: 'Der Manager lieferte eine nicht unterstützte oder widersprüchliche Antwort. Die Freigabe bleibt gesperrt.', session: 'Zugriff für Dienstaktionen beendet oder geändert. Erneut anmelden.', expired: 'Die Vorschau ist abgelaufen. Status prüfen und eine neue Vorschau anfordern.', changed: 'Aktion oder Berechtigung geändert. Vor der Freigabe eine neue Vorschau prüfen.', uncertain: 'Freigabe unbestätigt. Gespeicherten Status prüfen und keine weitere Freigabe senden.', clock: 'Der Zeitanker ist nicht mehr verlässlich. Vor dem Fortfahren den Status prüfen.',
        job: 'Gespeicherte Aktion', approved: 'Freigegeben; Zustellung an den Agent steht aus. Ausführung unbestätigt.', claimed: 'Zur Zustellung beansprucht. Zustellung, Ausführung und Ausgang bleiben bis zur Ergebnismeldung unbestätigt.', operation_completed: 'Agent meldet Befehlsabschluss. Neustart und Dienstzustand bleiben unbestätigt.', not_started: 'Der Agent meldet, dass die Operation nicht gestartet wurde.', jobExpired: 'Das Startzeitfenster der Aktion ist abgelaufen.', reported: 'Vom Agent gemeldetes Ergebnis', observed: 'Gemeldeter Zustand', reason: 'Gemeldeter Grund', deadline: 'Startfrist', noRetry: 'Keine automatische Wiederholung. Ergebnis im gespeicherten Status prüfen.',
    },
};
export function serviceActionLabel(locale: 'en' | 'de') { return copy[locale].select; }
type Workflow = ReturnType<typeof useServiceActions>;
export function ServiceActionPanel({ workflow, authorized }: { workflow: Workflow; authorized: boolean }) {
    const [locale] = useLocale(), labels = copy[locale], id = useId(), job = workflow.view?.job;
    return <section className="service-action-panel" aria-labelledby={id}>
        <header><h4 id={id}>{labels.heading}</h4>{authorized && <button type="button" className="button small" disabled={!!workflow.loading || workflow.error === 'session'} onClick={workflow.refresh}><RefreshCw size={14}/>{labels.refresh}</button>}</header>
        {!authorized ? <p className="package-note">{labels.unavailable} {labels.access}</p> : <>
            {workflow.loading && <p role="status"><LoaderCircle size={14} className="spin"/>{workflow.loading === 'preview' ? labels.preparing : workflow.loading === 'approve' ? labels.approving : labels.loading}</p>}
            {workflow.error && <p className="package-error" role="alert">{labels[workflow.error]}</p>}
            {!workflow.error && workflow.view && <p className="package-note">{labels[workflow.view.reason]}</p>}
            {workflow.selected && !workflow.preview && workflow.loading === 'preview' && <button type="button" className="text-button" onClick={workflow.close}>{labels.cancel}</button>}
            {workflow.preview && <Review key={workflow.preview.id} preview={workflow.preview} onApprove={workflow.approve} onClose={workflow.close}/>}
            {job && <section className="service-action-job" aria-label={labels.job}>
                <strong>{labels.job}: {job.unit}</strong>
                <p role="status">{job.state === 'expired' ? labels.jobExpired : labels[job.state]}</p>
                <dl><div><dt>ID</dt><dd>{job.id}</dd></div><div><dt>{labels.actor}</dt><dd>{job.actorId}</dd></div><div><dt>{labels.deadline}</dt><dd>{job.startDeadline}</dd></div></dl>
                {job.result && <p>{labels.reported}: {job.result.phase}{job.result.reason && <> · {labels.reason}: {job.result.reason}</>}{job.result.observedState && <> · {labels.observed}: {job.result.observedState}</>}</p>}
                {(job.state === 'approved' || job.state === 'claimed') && <p className="package-note">{labels.noRetry}</p>}
            </section>}
        </>}
    </section>;
}
function Review({ preview, onApprove, onClose }: { preview: ServiceActionPreview; onApprove: () => void; onClose: () => void }) {
    const [locale] = useLocale(), labels = copy[locale], [acknowledged, setAcknowledged] = useState(false), id = useId(), element = useRef<HTMLElement | null>(null);
    useEffect(() => {
        const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null, review = element.current;
        review?.focus();
        return () => { if (review?.contains(document.activeElement) && previous?.isConnected) previous.focus(); };
    }, []);
    return <section className="service-action-review" ref={element} tabIndex={-1} aria-labelledby={id} onKeyDown={event => { if (event.key === 'Escape') { event.stopPropagation(); onClose(); } }}>
        <h4 id={id}>{labels.review}</h4>
        <dl><div><dt>{labels.device}</dt><dd>{preview.deviceId}</dd></div><div><dt>{labels.unit}</dt><dd>{preview.plan.unit}</dd></div><div><dt>{labels.actor}</dt><dd>{preview.actorId}</dd></div><div><dt>{labels.action}</dt><dd>{preview.plan.action}</dd></div><div><dt>{labels.expires}</dt><dd>{preview.expiresAt}</dd></div></dl>
        <p className="service-action-warning"><TriangleAlert size={16}/>{labels.warning}</p>
        {preview.transportProfile === 'disposable-http-test' && <p className="package-error">{labels.http}</p>}
        <details><summary>{labels.details}</summary><dl><div><dt>{labels.plan}</dt><dd>{preview.planDigest}</dd></div><div><dt>{labels.root}</dt><dd>{preview.rootPolicyDigest}</dd></div><div><dt>{labels.digest}</dt><dd>{preview.digest}</dd></div><div><dt>{labels.unitPolicy}</dt><dd>{preview.plan.unitPolicyDigest}</dd></div><div><dt>{labels.key}</dt><dd>{preview.keyId}</dd></div><div><dt>{labels.incarnation}</dt><dd>{preview.incarnationDigest}</dd></div><div><dt>{labels.transport}</dt><dd>{preview.transportProfile}</dd></div></dl></details>
        <label className="service-action-consent"><input type="checkbox" checked={acknowledged} onChange={event => setAcknowledged(event.target.checked)}/>{labels.acknowledge}</label>
        <div className="service-action-buttons"><button type="button" className="button" onClick={onClose}>{labels.cancel}</button><button type="button" className="button primary" disabled={!acknowledged} onClick={() => { if (acknowledged) { setAcknowledged(false); onApprove(); } }}>{labels.approve}</button></div>
    </section>;
}
