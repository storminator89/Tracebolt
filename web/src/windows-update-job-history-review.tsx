import { useEffect, useId, useRef, useState, type ReactNode } from 'react';
import type { UpdateJobSummary } from './windows-update-jobs-types';

type Purpose = 'all' | 'install' | 'download';
const copy = {
    en: {
        filters: 'Filter saved update jobs', search: 'Job ID, update ID or revision', purpose: 'Job purpose', result: 'Saved status or result',
        allPurposes: 'All purposes', install: 'Installation', download: 'Download', allResults: 'All saved states', clear: 'Clear job filters',
        showing: 'Showing', of: 'of', jobs: 'saved jobs', noMatch: 'No saved jobs match these filters.',
        scope: 'Filters apply only to the loaded saved jobs. Original order and evidence are unchanged.',
        'state:requested': 'Readiness pending', 'state:blocked': 'Readiness blocked', 'state:preview': 'Ready for review',
        'state:approved': 'Approved', 'state:claimed': 'Claimed; outcome unconfirmed', 'state:complete': 'Result saved',
        'state:expired': 'Review expired', 'state:scheduled': 'Scheduled', 'state:schedule_canceled': 'Schedule canceled',
        'state:schedule_blocked': 'Schedule blocked', 'state:schedule_expired': 'Schedule expired',
        'result:succeeded': 'Reported success', 'result:failed': 'Reported failure', 'result:uncertain': 'Outcome uncertain',
        'result:not_attempted': 'Not attempted',
    },
    de: {
        filters: 'Gespeicherte Updateaufträge filtern', search: 'Auftrags-ID, Update-ID oder Revision', purpose: 'Auftragszweck', result: 'Gespeicherter Status oder Ergebnis',
        allPurposes: 'Alle Zwecke', install: 'Installation', download: 'Download', allResults: 'Alle gespeicherten Zustände', clear: 'Auftragsfilter leeren',
        showing: 'Angezeigt:', of: 'von', jobs: 'gespeicherten Aufträgen', noMatch: 'Keine gespeicherten Aufträge passen zu diesen Filtern.',
        scope: 'Filter gelten nur für die geladenen gespeicherten Aufträge. Ursprüngliche Reihenfolge und Nachweise bleiben unverändert.',
        'state:requested': 'Bereitschaft ausstehend', 'state:blocked': 'Bereitschaft blockiert', 'state:preview': 'Zur Prüfung bereit',
        'state:approved': 'Freigegeben', 'state:claimed': 'Abgeholt; Ergebnis unbestätigt', 'state:complete': 'Ergebnis gespeichert',
        'state:expired': 'Prüfung abgelaufen', 'state:scheduled': 'Geplant', 'state:schedule_canceled': 'Planung abgebrochen',
        'state:schedule_blocked': 'Planung blockiert', 'state:schedule_expired': 'Planung abgelaufen',
        'result:succeeded': 'Erfolg gemeldet', 'result:failed': 'Fehler gemeldet', 'result:uncertain': 'Ergebnis ungewiss',
        'result:not_attempted': 'Nicht versucht',
    },
};
const resultKeys = [
    'state:requested', 'state:blocked', 'state:preview', 'state:approved', 'state:claimed', 'state:scheduled',
    'state:schedule_canceled', 'state:schedule_blocked', 'state:schedule_expired', 'state:expired', 'state:complete',
    'result:succeeded', 'result:failed', 'result:uncertain', 'result:not_attempted',
] as const;
type ResultKey = typeof resultKeys[number];

// Input is the existing validated, bounded history. Never derive execution or
// success from approval, a claim, elapsed time, retirement or current inventory.
export const updateJobResultKey = (job: UpdateJobSummary): string => job.result ? `result:${job.result.outcome}` : `state:${job.state}`;
export function filterSavedUpdateJobs(jobs: readonly UpdateJobSummary[], query: string, purpose: Purpose, result: 'all' | ResultKey): UpdateJobSummary[] {
    const text = query.trim().toLowerCase();
    return jobs.filter(job => (purpose === 'all' || (job.purpose === 'download' ? 'download' : 'install') === purpose)
        && (result === 'all' || updateJobResultKey(job) === result)
        && (!text || [job.id, job.selection.updateId, String(job.selection.revision)].some(value => value.toLowerCase().includes(text))));
}

/** Pure local review: no requests, persistence, current-inventory joins or action callbacks. */
export function WindowsUpdateJobHistoryReview({ jobs, locale, busy, children }: {
    jobs: readonly UpdateJobSummary[]; locale: 'en' | 'de'; busy: boolean; children: (job: UpdateJobSummary) => ReactNode;
}) {
    const c = copy[locale], id = useId(), input = useRef<HTMLInputElement>(null);
    const [query, setQuery] = useState(''), [purpose, setPurpose] = useState<Purpose>('all'), [result, setResult] = useState<'all' | ResultKey>('all');
    useEffect(() => { setQuery(''); setPurpose('all'); setResult('all'); }, [jobs]);
    const visible = filterSavedUpdateJobs(jobs, query, purpose, result), active = !!query || purpose !== 'all' || result !== 'all';
    const matchingPurposeAndText = filterSavedUpdateJobs(jobs, query, purpose, 'all');
    const count = (key: string) => matchingPurposeAndText.filter(job => updateJobResultKey(job) === key).length;
    return <div className="windows-update-history-review">
        <div className="windows-inventory-table-controls" role="group" aria-label={c.filters}>
            <label htmlFor={`${id}-search`}>{c.search}<input ref={input} id={`${id}-search`} type="search" autoComplete="off" spellCheck={false} maxLength={128} value={query} disabled={busy} onChange={event => setQuery(event.target.value)} /></label>
            <label htmlFor={`${id}-purpose`}>{c.purpose}<select id={`${id}-purpose`} value={purpose} disabled={busy} onChange={event => setPurpose(event.target.value as Purpose)}>
                <option value="all">{c.allPurposes}</option><option value="install">{c.install}</option><option value="download">{c.download}</option>
            </select></label>
            <label htmlFor={`${id}-result`}>{c.result}<select id={`${id}-result`} value={result} disabled={busy} onChange={event => setResult(event.target.value as 'all' | ResultKey)}>
                <option value="all">{c.allResults}</option>{resultKeys.filter(key => count(key) > 0 || key === result).map(key => <option key={key} value={key}>{c[key]} ({count(key)})</option>)}
            </select></label>
            <button type="button" className="text-button" disabled={busy || !active} onClick={() => { setQuery(''); setPurpose('all'); setResult('all'); input.current?.focus(); }}>{c.clear}</button>
        </div>
        <p aria-live="polite" aria-atomic="true">{c.showing} {visible.length} {c.of} {jobs.length} {c.jobs}</p>
        <p className="windows-inventory-exclusions">{c.scope}</p>
        {visible.length === 0 ? <p>{c.noMatch}</p> : <ul>{visible.map(job => <li key={job.id}>
            <p><strong>{job.purpose === 'download' ? c.download : c.install}</strong></p>{children(job)}
        </li>)}</ul>}
    </div>;
}
