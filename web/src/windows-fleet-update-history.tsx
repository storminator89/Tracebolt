import { useState } from 'react';
import { Download, History, Package, RefreshCw, X } from 'lucide-react';
import { useOperator } from './auth';
import { useLocale } from './i18n';
import type { UpdateJobSummary, UpdateJobHistory } from './windows-update-jobs-types';
import { useFleetUpdateHistory } from './windows-fleet-update-history-resource';
import './windows-fleet-update-history.css';

const copy = {
    en: {
        title: 'Saved fleet update jobs', read: 'Read saved jobs for these devices', clear: 'Clear saved-job overview',
        scope: 'All saved updates for the frozen devices. No live status, patch coverage or new approval.',
        readAt: 'History read at (UTC)', unavailable: 'Saved jobs unavailable', notRead: 'Not read', pending: 'Read pending', empty: 'No saved jobs returned.',
        count: (read: number, total: number, jobs: number) => `${read}/${total} device histories read · ${jobs} saved ${jobs === 1 ? 'job' : 'jobs'}`,
        jobs: (n: number) => `${n} saved ${n === 1 ? 'job' : 'jobs'}`, failedCount: (n: number) => `${n} failed ${n === 1 ? 'result' : 'results'}`, uncertainCount: (n: number) => `${n} uncertain ${n === 1 ? 'result' : 'results'}`,
        readError: 'Saved jobs could not be read. Check access before reading again.', waiting: 'Other reads are still finishing. If this persists, reload the page; unsaved selections will be lost.',
        limits: 'Read limits', details: 'Job details', bounds: 'One manual read of up to 50 devices, four at a time. Only each endpoint’s bounded saved history is returned. This temporary view clears within five minutes or when closed. It does not change the worklist, saved jobs or unconfirmed writes.',
        purpose: { install: 'Installation', download: 'Download' }, revision: 'Revision',
        requested: 'Readiness pending', blocked: 'Readiness blocked', preview: 'Review required', approved: 'Approved; claim pending', claimed: 'Claimed; outcome unconfirmed', complete: 'Executor result saved', expired: 'Review expired',
        scheduled: 'Scheduled', schedule_canceled: 'Schedule canceled', schedule_blocked: 'Schedule blocked', schedule_expired: 'Schedule expired',
        succeeded: 'WUA reported success', failed: 'Failed result', uncertain: 'Uncertain result', not_attempted: 'Not attempted', reboot: 'Restart reported as required',
        requestedAt: 'Requested', approvedAt: 'Approved', claimedAt: 'Claimed', completedAt: 'Result recorded', window: 'Approved UTC window', retirement: 'Closure state',
        available: 'Available for review', retired: 'Closed', retirementPending: 'Closure pending', retirementBlocked: 'Closure blocked',
        previous: 'Previous jobs', next: 'Next jobs', page: (n: number, total: number) => `Page ${n} of ${total}`,
    },
    de: {
        title: 'Gespeicherte Flotten-Updateaufträge', read: 'Gespeicherte Aufträge dieser Geräte lesen', clear: 'Auftragsübersicht leeren',
        scope: 'Alle gespeicherten Updates der festgehaltenen Geräte. Kein Live-Status, keine Patch-Abdeckung oder neue Freigabe.',
        readAt: 'Verlauf gelesen um (UTC)', unavailable: 'Gespeicherte Aufträge nicht verfügbar', notRead: 'Nicht gelesen', pending: 'Lesen ausstehend', empty: 'Keine gespeicherten Aufträge zurückgegeben.',
        count: (read: number, total: number, jobs: number) => `${read}/${total} Geräteverläufe gelesen · ${jobs} ${jobs === 1 ? 'gespeicherter Auftrag' : 'gespeicherte Aufträge'}`,
        jobs: (n: number) => `${n} ${n === 1 ? 'gespeicherter Auftrag' : 'gespeicherte Aufträge'}`, failedCount: (n: number) => `${n} ${n === 1 ? 'fehlgeschlagenes Ergebnis' : 'fehlgeschlagene Ergebnisse'}`, uncertainCount: (n: number) => `${n} ${n === 1 ? 'ungewisses Ergebnis' : 'ungewisse Ergebnisse'}`,
        readError: 'Gespeicherte Aufträge konnten nicht gelesen werden. Zugriff vor erneutem Lesen prüfen.', waiting: 'Andere Lesezugriffe laufen noch. Falls dies anhält, Seite neu laden; ungespeicherte Auswahl geht verloren.',
        limits: 'Lesegrenzen', details: 'Auftragsdetails', bounds: 'Ein manueller Lesevorgang für bis zu 50 Geräte, jeweils vier gleichzeitig. Nur der begrenzte gespeicherte Verlauf jedes Endpunkts wird zurückgegeben. Diese vorübergehende Ansicht wird nach höchstens fünf Minuten oder beim Schließen geleert. Arbeitsliste, gespeicherte Aufträge und unbestätigte Schreibvorgänge bleiben unverändert.',
        purpose: { install: 'Installation', download: 'Download' }, revision: 'Revision',
        requested: 'Bereitschaft ausstehend', blocked: 'Bereitschaft blockiert', preview: 'Prüfung erforderlich', approved: 'Freigegeben; Abholung ausstehend', claimed: 'Abgeholt; Ergebnis unbestätigt', complete: 'Executor-Ergebnis gespeichert', expired: 'Prüfung abgelaufen',
        scheduled: 'Geplant', schedule_canceled: 'Planung abgebrochen', schedule_blocked: 'Planung blockiert', schedule_expired: 'Planung abgelaufen',
        succeeded: 'WUA hat Erfolg gemeldet', failed: 'Fehlgeschlagenes Ergebnis', uncertain: 'Ungewisses Ergebnis', not_attempted: 'Nicht versucht', reboot: 'Neustart als erforderlich gemeldet',
        requestedAt: 'Angefragt', approvedAt: 'Freigegeben', claimedAt: 'Abgeholt', completedAt: 'Ergebnis vermerkt', window: 'Genehmigtes UTC-Zeitfenster', retirement: 'Abschlussstatus',
        available: 'Zur Prüfung verfügbar', retired: 'Geschlossen', retirementPending: 'Abschluss ausstehend', retirementBlocked: 'Abschluss blockiert',
        previous: 'Vorherige Aufträge', next: 'Weitere Aufträge', page: (n: number, total: number) => `Seite ${n} von ${total}`,
    },
};
const utc = (value: number) => new Date(value * 1000).toISOString();
const time = (value: number) => <time dateTime={utc(value)}>{utc(value).replace('T', ' ').replace('.000Z', ' UTC')}</time>;
function DeviceHistory({ history, locale }: { history: UpdateJobHistory; locale: 'en' | 'de' }) {
    const c = copy[locale], [page, setPage] = useState(0), pages = Math.max(1, Math.ceil(history.jobs.length / 10)), current = Math.min(page, pages - 1);
    const state = (job: UpdateJobSummary) => job.result ? c[job.result.outcome] : c[job.state as 'requested'];
    return <>
        <p className="windows-inventory-exclusions">{c.readAt}: {time(history.serverNow)}</p>
        {history.jobs.length === 0 ? <p>{c.empty}</p> : <ol className="windows-fleet-history-jobs" start={current * 10 + 1}>{history.jobs.slice(current * 10, current * 10 + 10).map(job => <li key={job.id}>
            <p className="windows-fleet-history-outcome">{job.purpose === 'download' ? <Download size={14} aria-hidden="true"/> : <Package size={14} aria-hidden="true"/>}<strong>{c.purpose[job.purpose ?? 'install']} · {state(job)}</strong></p>
            <small>{job.selection.updateId} · {c.revision} {job.selection.revision}</small>
            {job.result?.rebootRequired === 'yes' && <p>{c.reboot}</p>}
            {job.retirement && <small>{c.retirement}: {job.retirement.state === 'pending' ? c.retirementPending : job.retirement.state === 'blocked' ? c.retirementBlocked : c[job.retirement.state]}</small>}
            <details className="windows-inventory-scope"><summary>{c.details}</summary><p>{job.id}</p><dl>
                {(['requestedAt', 'approvedAt', 'claimedAt'] as const).map(field => job[field] > 0 && <div key={field}><dt>{c[field]}</dt><dd>{time(job[field])}</dd></div>)}
                {job.result && <div><dt>{c.completedAt}</dt><dd>{time(job.result.completedAt)}</dd></div>}
                {job.schedule && <div><dt>{c.window}</dt><dd>{time(job.schedule.startAt)} – {time(job.schedule.endAt)}</dd></div>}
            </dl></details>
        </li>)}</ol>}
        {pages > 1 && <nav aria-label={c.title} className="windows-fleet-history-pagination"><button type="button" className="text-button" disabled={current === 0} onClick={() => setPage(current - 1)}>{c.previous}</button><span>{c.page(current + 1, pages)}</span><button type="button" className="text-button" disabled={current + 1 >= pages} onClick={() => setPage(current + 1)}>{c.next}</button></nav>}
    </>;
}

export function WindowsFleetUpdateHistory({ devices, availableIds }: { devices: Array<{ id: string; name: string }>; availableIds: string[] }) {
    const operator = useOperator(), [locale] = useLocale(), c = copy[locale], [opened, setOpened] = useState(false);
    const available = new Set(availableIds), ids = devices.filter(device => available.has(device.id)).map(device => device.id);
    const allowed = !!operator && !operator.checkingAccess && operator.mode === 'lan' && operator.authenticated && operator.loginMode === 'named' && !!operator.actorId && !!operator.expiresAt && !operator.insecureTestMode && !!operator.capabilities?.includes('windows_update_install');
    const resource = useFleetUpdateHistory(ids, operator?.actorId ?? '', operator?.expiresAt ?? '', opened && allowed);
    const read = resource.reports.filter(report => report.history), jobs = read.reduce((sum, report) => sum + report.history!.jobs.length, 0);
    return <section className="windows-fleet-update-history" aria-label={c.title}>
        <button type="button" className="text-button windows-fleet-history-toggle" aria-expanded={opened} onClick={() => setOpened(value => !value)}><History size={15} aria-hidden="true"/>{c.title}</button>
        {opened && <div>
            <p>{c.scope}</p>
            <div className="windows-fleet-history-actions"><button type="button" className="button small" disabled={!allowed || !ids.length || resource.loading || resource.waiting || resource.blocked} onClick={resource.read}><RefreshCw size={14} aria-hidden="true"/>{c.read}</button>{resource.hasRead && <button type="button" className="text-button" onClick={resource.clear}><X size={14} aria-hidden="true"/>{c.clear}</button>}</div>
            {resource.error && <p role="alert">{c.readError}</p>}{!resource.loading && resource.waiting && <p role="status">{c.waiting}</p>}
            {resource.hasRead && <>
                <p role="status">{c.count(read.length, devices.length, jobs)}</p>
                <ul className="windows-fleet-history-devices">{devices.map(device => {
                    const report = resource.reports.find(value => value.deviceId === device.id), history = report?.history;
                    const failed = history?.jobs.filter(job => job.result?.outcome === 'failed').length ?? 0, uncertain = history?.jobs.filter(job => job.result?.outcome === 'uncertain').length ?? 0;
                    return <li key={device.id}>{history ? <details><summary><strong>{device.name}</strong> · {c.jobs(history.jobs.length)}{failed > 0 && <> · {c.failedCount(failed)}</>}{uncertain > 0 && <> · {c.uncertainCount(uncertain)}</>}</summary><small>{device.id}</small><DeviceHistory key={`${device.id}:${history.serverNow}`} history={history} locale={locale}/></details> : <><strong>{device.name}</strong><small>{device.id}</small><p>{report || !available.has(device.id) ? c.unavailable : resource.loading ? c.pending : c.notRead}</p></>}</li>;
                })}</ul>
            </>}
            <details className="windows-inventory-scope"><summary>{c.limits}</summary><p>{c.bounds}</p></details>
        </div>}
    </section>;
}
