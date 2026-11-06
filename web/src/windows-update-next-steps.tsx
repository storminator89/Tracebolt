import { CircleHelp, ClipboardCheck, Clock3, FileSearch, TriangleAlert } from 'lucide-react';
import { useLocale } from './i18n';
import type { UpdateJobView } from './windows-update-jobs-types';
import './windows-update-next-steps.css';

const copy = {
    en: {
        title: 'Next steps for this job', read: 'Read this job again', exact: 'Job', revision: 'Revision',
        readOnly: 'Reads saved evidence only. It does not repeat execution or extend an approval.',
        unresolved: 'An unconfirmed action is still tracked. Use “Read saved status” above to reconcile that action; do not submit a replacement.',
        pending: 'Read saved status when you want to check for a result. Waiting does not prove execution or success.',
        requested: 'Read saved status to check whether the exact readiness response has arrived. Do not send a replacement request.',
        review: 'A saved readiness result is not approval. Reopen the existing readiness review before considering an action.',
        failed: 'Review the recorded result and exact update revision. A failed attempt needs separately reviewed intervention; this view cannot retry or clear it.',
        uncertain: 'Keep this exact job reference. The outcome is uncertain; missing confirmation is not a failed or safely repeatable attempt.',
        notAttempted: 'Review why execution was not attempted. This saved result does not authorize another attempt or release an occupied job slot.',
        installed: 'Review the recorded result and restart requirement. Reported success is not current installation or whole-device patch coverage.',
        downloaded: 'Review the saved download result. Download success is not installation approval; installation needs its own fresh review.',
        schedule: 'Check the original approved UTC window in Job details. A planned start is not a guaranteed execution time.',
        endedSchedule: 'Review the original window and saved schedule state. There is no automatic reschedule or approval refund.',
        expired: 'The original readiness review has expired. Reading this job cannot extend it or restore its approval.',
        blocked: 'Review the saved readiness evidence. A change on the device still requires a separate fresh review before any action.',
        fallback: 'Review the exact saved state before deciding what to do next. No action is inferred from this guidance.',
        retirement: 'Closing is a separate reviewed step. It requires the signed successful result and endpoint confirmation; it does not retry the update.',
        closing: 'Read saved status to reconcile closing. Do not replace the job while closing remains unconfirmed.',
        closed: 'This job is closed. Its saved result remains evidence; no next job has been started by closing it.',
        closingBlocked: 'Closing is blocked. Do not reset state or create a replacement to bypass the occupied slot.',
        reason: 'Saved readiness reason',
    },
    de: {
        title: 'Nächste Schritte für diesen Auftrag', read: 'Diesen Auftrag erneut lesen', exact: 'Auftrag', revision: 'Revision',
        readOnly: 'Liest nur gespeicherte Belege. Wiederholt keine Ausführung und verlängert keine Freigabe.',
        unresolved: 'Eine unbestätigte Aktion wird noch verfolgt. Oben „Gespeicherten Status lesen“ zum Abgleich dieser Aktion verwenden; keinen Ersatzauftrag senden.',
        pending: 'Gespeicherten Status lesen, um nach einem Ergebnis zu sehen. Warten belegt weder Ausführung noch Erfolg.',
        requested: 'Gespeicherten Status lesen, um die Antwort zur exakten Bereitschaft zu prüfen. Keine Ersatzanfrage senden.',
        review: 'Ein gespeichertes Bereitschaftsergebnis ist keine Freigabe. Vor einer Aktion die bestehende Bereitschaftsprüfung erneut öffnen.',
        failed: 'Gespeichertes Ergebnis und exakte Updaterevision prüfen. Ein fehlgeschlagener Versuch erfordert einen separat geprüften Eingriff; diese Ansicht kann ihn nicht wiederholen oder zurücksetzen.',
        uncertain: 'Diese exakte Auftragsreferenz behalten. Das Ergebnis ist ungewiss; fehlende Bestätigung bedeutet keinen fehlgeschlagenen oder sicher wiederholbaren Versuch.',
        notAttempted: 'Prüfen, warum die Ausführung nicht versucht wurde. Dieses Ergebnis erlaubt weder einen weiteren Versuch noch die Freigabe eines belegten Auftragsplatzes.',
        installed: 'Gespeichertes Ergebnis und Neustartbedarf prüfen. Gemeldeter Erfolg belegt weder den aktuellen Installationsstand noch vollständige Patch-Abdeckung.',
        downloaded: 'Gespeichertes Downloadergebnis prüfen. Downloaderfolg ist keine Installationsfreigabe; Installation erfordert eine eigene frische Prüfung.',
        schedule: 'Das ursprünglich genehmigte UTC-Zeitfenster in den Auftragsdetails prüfen. Ein geplanter Start garantiert keine Ausführungszeit.',
        endedSchedule: 'Ursprüngliches Zeitfenster und gespeicherten Planungsstatus prüfen. Keine automatische Neuplanung oder Rückerstattung der Freigabe.',
        expired: 'Die ursprüngliche Bereitschaftsprüfung ist abgelaufen. Lesen verlängert sie nicht und stellt keine Freigabe wieder her.',
        blocked: 'Die gespeicherten Bereitschaftsbelege prüfen. Auch nach einer Änderung am Gerät ist vor einer Aktion eine separate frische Prüfung nötig.',
        fallback: 'Vor dem nächsten Schritt den exakten gespeicherten Zustand prüfen. Aus diesen Hinweisen folgt keine Aktion.',
        retirement: 'Abschließen ist ein separater geprüfter Schritt. Es erfordert das signierte erfolgreiche Ergebnis und Endpunktbestätigung; es wiederholt das Update nicht.',
        closing: 'Gespeicherten Status zum Abgleich des Abschließens lesen. Den Auftrag nicht ersetzen, solange der Abschluss unbestätigt bleibt.',
        closed: 'Dieser Auftrag ist geschlossen. Sein Ergebnis bleibt als Beleg erhalten; das Abschließen hat keinen nächsten Auftrag gestartet.',
        closingBlocked: 'Abschließen ist blockiert. Keinen Zustand zurücksetzen oder Ersatzauftrag zum Umgehen des belegten Platzes erstellen.',
        reason: 'Gespeicherter Bereitschaftsgrund',
    },
};

// Translate only the validated saved reason. Never decode HRESULTs or inspect
// current inventory to infer a different outcome or permission to act.
const readinessReasons: Record<string, { en: string; de: string }> = {
    readiness_unavailable: { en: 'No usable readiness response was saved. Check the separately configured executor and keep this job reference.', de: 'Keine nutzbare Bereitschaftsantwort gespeichert. Separat eingerichteten Executor prüfen und diese Auftragsreferenz behalten.' },
    readiness_unknown: { en: 'Required readiness facts are unknown. Unknown does not mean ready.', de: 'Erforderliche Bereitschaftsfakten sind unbekannt. Unbekannt bedeutet nicht bereit.' },
    offline_unverified: { en: 'The cached-only operation could not be verified. This workflow cannot switch to an online scan.', de: 'Der reine Cache-Vorgang konnte nicht bestätigt werden. Dieser Ablauf kann nicht auf eine Onlinesuche wechseln.' },
    selection_ineligible: { en: 'The exact cached update is not eligible. Review its GUID and revision; do not substitute another revision.', de: 'Das exakte Cache-Update ist nicht geeignet. GUID und Revision prüfen; keine andere Revision einsetzen.' },
    not_downloaded: { en: 'Installation content was not already downloaded. Download needs its own grant and fresh review.', de: 'Installationsinhalte waren nicht bereits heruntergeladen. Download erfordert eine eigene Freigabe und frische Prüfung.' },
    license_not_accepted: { en: 'The license was not already accepted. This workflow cannot accept it.', de: 'Die Lizenz war nicht bereits angenommen. Dieser Ablauf kann sie nicht annehmen.' },
    bundle_unsupported: { en: 'Bundled updates are not supported by this exact-update workflow.', de: 'Updatebündel werden von diesem Ablauf für exakte Updates nicht unterstützt.' },
    interaction_or_source_required: { en: 'Prompts, source media or a network requirement prevent this workflow. Do not bypass those requirements.', de: 'Eingaben, Quellmedien oder eine Netzwerkanforderung verhindern diesen Ablauf. Diese Anforderungen nicht umgehen.' },
    installer_busy: { en: 'Windows reported a busy installer at readiness time. This is not a live status or permission to stop it.', de: 'Windows meldete zum Prüfzeitpunkt einen belegten Installer. Das ist weder Live-Status noch Erlaubnis, ihn zu stoppen.' },
    restart_required_before: { en: 'Windows reported a restart requirement before installation. Coordinate any restart separately; this view cannot restart Windows.', de: 'Windows meldete Neustartbedarf vor der Installation. Einen Neustart separat abstimmen; diese Ansicht kann Windows nicht neu starten.' },
    download_metadata_unknown: { en: 'Download origins or size could not be established for review. Do not approve an unknown download.', de: 'Downloadherkunft oder Größe konnten nicht für die Prüfung bestimmt werden. Keinen unbekannten Download freigeben.' },
    already_downloaded: { en: 'Content was already downloaded at readiness time. This does not establish installation readiness.', de: 'Inhalte waren zum Prüfzeitpunkt bereits heruntergeladen. Das belegt keine Installationsbereitschaft.' },
    download_size_exceeds_review_limit: { en: 'The download exceeds this review’s size limit. This view cannot increase that limit.', de: 'Der Download überschreitet das Größenlimit dieser Prüfung. Diese Ansicht kann das Limit nicht erhöhen.' },
};

export function WindowsUpdateNextSteps({ job, unresolvedAction, disabled, onRead }: {
    job: NonNullable<UpdateJobView['job']>;
    unresolvedAction: boolean;
    disabled: boolean;
    onRead: () => void;
}) {
    const [locale] = useLocale(), c = copy[locale];
    const outcome = job.result?.outcome;
    const hint = outcome === 'failed' ? c.failed : outcome === 'uncertain' ? c.uncertain : outcome === 'not_attempted' ? c.notAttempted
        : outcome === 'succeeded' ? job.purpose === 'download' ? c.downloaded : c.installed
        : ['schedule_canceled', 'schedule_blocked', 'schedule_expired'].includes(job.state) ? c.endedSchedule
        : job.schedule ? c.schedule : job.state === 'requested' ? c.requested
        : ['approved', 'claimed'].includes(job.state) ? c.pending : job.state === 'preview' ? c.review
        : job.state === 'expired' ? c.expired : job.state === 'blocked' ? c.blocked : c.fallback;
    const reason = job.state === 'blocked' ? readinessReasons[job.reason]?.[locale] : undefined;
    const retirement = job.retirement?.state;
    const closing = retirement === 'available' ? c.retirement : retirement === 'pending' ? c.closing : retirement === 'retired' ? c.closed : retirement === 'blocked' ? c.closingBlocked : null;
    const Icon = unresolvedAction || outcome === 'uncertain' ? CircleHelp : outcome === 'failed' || job.state === 'blocked' ? TriangleAlert : outcome === 'succeeded' ? ClipboardCheck : Clock3;
    return <details className="windows-inventory-scope windows-update-next-steps">
        <summary><Icon size={16} aria-hidden="true" /> {c.title}</summary>
        <div role="group" aria-label={c.title}>
            <p className="windows-update-next-reference">{c.exact}: {job.id}<br />{job.selection.updateId} · {c.revision} {job.selection.revision}</p>
            {unresolvedAction && <p>{c.unresolved}</p>}
            <ol><li>{hint}</li>{reason && <li><strong>{c.reason}: </strong>{reason}</li>}{closing && <li>{closing}</li>}</ol>
            {!unresolvedAction && <button type="button" className="button small" disabled={disabled} onClick={onRead}><FileSearch size={14} aria-hidden="true" />{c.read}</button>}
            <p className="windows-inventory-exclusions">{c.readOnly}</p>
        </div>
    </details>;
}
