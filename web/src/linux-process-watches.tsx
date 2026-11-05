import { useEffect, useId, useState } from 'react';
import { getProtectedRequestEpoch } from './api';
import { useOperator } from './auth';
import { useLocale } from './i18n';
import { processWatchCopy } from './linux-process-watches-copy';
import { LinuxProcessWatchChooser, processNameWhitespace } from './linux-process-watch-chooser';
import { useLinuxProcessWatches } from './linux-process-watches-resource';
import { PROCESS_WATCH_MAX_REVISION, processNameOrder, processWatchCondition, processWatchDeviceId, processWatchNames, processWatchRequestId } from './linux-process-watches-types';
import type { ProcessGeneration, ProcessObservation, ProcessWatchIncident, ProcessWatchRequest } from './linux-process-watches-types';
import './linux-process-watches.css';

type Copy = typeof processWatchCopy.en;
const emptyDraft = () => ({ text: '', failures: 2, sourceToken: null as string | null, editing: false });
type Review = { request: ProcessWatchRequest; generation: number };
function UTC({ value }: { value: string }) { return <time dateTime={value}>{value.replace('T', ' ').replace(/Z$/, ' UTC')}</time>; }
function Name({ value, c }: { value: string; c: Copy }) { const whitespace = processNameWhitespace(value); return <><bdi className="process-watch-name">{value}</bdi>{whitespace && <small> · {c.nameWhitespace}: {whitespace}</small>}</>; }
export function parseProcessWatchNames(text: string): string[] | null {
    // Newlines delimit names. Never trim, lowercase, normalize or interpret patterns.
    const names = [...new Set(text.split(/\r?\n/).filter(name => name !== ''))].sort(processNameOrder);
    return names.length > 0 && processWatchNames(names) ? names : null;
}
function Generation({ value: g, c }: { value: ProcessGeneration; c: Copy }) {
    return <dl><div><dt>{c.sequence}</dt><dd>{g.sequence}</dd></div>
        <div><dt>{c.captureStarted}</dt><dd><UTC value={g.captureStartedAt}/></dd></div>
        <div><dt>{c.captureFinished}</dt><dd><UTC value={g.captureFinishedAt}/></dd></div>
        <div><dt>{c.received}</dt><dd><UTC value={g.receivedAt}/></dd></div>
        <div><dt>{c.total}</dt><dd>{g.totalRows}</dd></div><div><dt>{c.unidentified}</dt><dd>{g.unidentifiedRows}</dd></div></dl>;
}
function Observation({ title, value, c }: { title: string; value: ProcessObservation; c: Copy }) {
    return <details><summary>{title}</summary><Generation value={value.generation} c={c}/><p>{c.active}: {value.activeCount} · {c.nonRunning}: {value.nonRunningCount}</p></details>;
}
export function LinuxProcessWatches({ deviceId }: { deviceId: string }) {
    const operator = useOperator();
    if (operator?.mode !== 'lan' || !operator.authenticated || !processWatchDeviceId(deviceId)) return null;
    const scope = JSON.stringify([operator.expiresAt, operator.loginMode, operator.actorId, operator.capabilities]);
    return <Watches key={JSON.stringify([deviceId, scope, getProtectedRequestEpoch()])} deviceId={deviceId} scope={scope} sessionEnd={operator.expiresAt ?? null}/>;
}
function Watches({ deviceId, scope, sessionEnd }: { deviceId: string; scope: string; sessionEnd: string | null }) {
    const [locale] = useLocale(), c = processWatchCopy[locale], uid = useId();
    const [open, setOpen] = useState(false), [draft, setDraft] = useState(emptyDraft), [choosing, setChoosing] = useState(false);
    const [savedReview, setReview] = useState<Review | null>(null), [consent, setConsent] = useState(false);
    const resource = useLinuxProcessWatches(open, deviceId, scope, sessionEnd), { view } = resource;
    const draftCurrent = !view || draft.sourceToken === null || draft.sourceToken === view.source.token;
    const text = draftCurrent ? draft.text : '', failures = draftCurrent ? draft.failures : 2;
    const names = parseProcessWatchNames(text), review = savedReview?.generation === resource.generation ? savedReview : null;
    useEffect(() => { setReview(null); setConsent(false); setChoosing(false); }, [resource.generation]);
    useEffect(() => { setDraft(emptyDraft()); setChoosing(false); }, [resource.privacyGeneration]);
    useEffect(() => { if (view && (!view.canManage || draft.sourceToken !== null && draft.sourceToken !== view.source.token)) setDraft(emptyDraft()); }, [view, draft.sourceToken]);
    const editable = Boolean(view?.canManage && view.revision !== String(PROCESS_WATCH_MAX_REVISION) && !resource.busy && !resource.uncertain && !resource.full);
    const canEnable = editable && view?.clockReliable && view.source.status === 'available';
    const reset = () => { setReview(null); setConsent(false); };
    const prepare = (operation: 'enable' | 'disable' | 'acknowledge', incidentId?: string) => {
        if (!view || !editable || operation === 'enable' && (!canEnable || names === null || ![2, 3].includes(failures)) || operation === 'disable' && !view.policy.enabled || operation === 'acknowledge' && (!view.clockReliable || !view.policy.sourceMatches || !view.incidents.some(i => i.id === incidentId && i.acknowledgedAt === null))) return;
        const common = { requestId: processWatchRequestId(), expectedRevision: view.revision, sourceToken: view.source.token };
        const request: ProcessWatchRequest = operation === 'acknowledge'
            ? { operation: 'acknowledge', body: { ...common, incidentId: incidentId! } }
            : { operation: 'policy', body: { ...common, enabled: operation === 'enable', names: operation === 'enable' ? names! : [], consecutiveFailures: operation === 'enable' ? failures : 0, retentionAcknowledged: operation === 'enable' } };
        setReview({ request, generation: resource.generation }); setConsent(false); setChoosing(false);
    };
    const apply = () => {
        if (!review || !view || !editable || !consent || review.request.body.expectedRevision !== view.revision || review.request.body.sourceToken !== view.source.token || review.request.operation === 'acknowledge' && (!view.clockReliable || !view.policy.sourceMatches) || review.request.operation === 'policy' && review.request.body.enabled && !canEnable) return;
        const request = review.request; reset(); setDraft(emptyDraft()); setChoosing(false); void resource.write(request);
    };
    const operation = (request: ProcessWatchRequest) => request.operation === 'acknowledge' ? c.acknowledge : request.body.enabled ? c.enable : c.disable;
    const incidentCard = (incident: ProcessWatchIncident) => <li key={incident.id} className="process-watch-incident">
        <h4><Name value={incident.name} c={c}/> · {c[incident.state]}</h4>
        <p>{incident.sourceCurrent ? c.currentSource : c.previousSource} · {c.id}: {incident.id}</p>
        <p>{c.samples}: {incident.opening.samples}</p>
        <Observation title={c.firstOpening} value={incident.opening.first} c={c}/><Observation title={c.lastOpening} value={incident.opening.last} c={c}/>
        <dl><div><dt>{c.opened}</dt><dd><UTC value={incident.openedAt}/></dd></div><div><dt>{c.lastObserved}</dt><dd><UTC value={incident.lastObservedAt}/></dd></div>
            {incident.closedAt && <div><dt>{c.closed}</dt><dd><UTC value={incident.closedAt}/></dd></div>}
            <div><dt>{c.seen}</dt><dd>{incident.acknowledgedAt ? <UTC value={incident.acknowledgedAt}/> : c.unseen}</dd></div></dl>
        {incident.state === 'monitoring_stopped' && incident.closedAt === null && <p>{c.closedUnknown}</p>}
        {incident.recovery && <><Observation title={c.firstRecovery} value={incident.recovery.first} c={c}/><Observation title={c.lastRecovery} value={incident.recovery.last} c={c}/></>}
        {editable && view?.clockReliable && view.policy.sourceMatches && !review && incident.acknowledgedAt === null && <button type="button" className="text-button" onClick={() => prepare('acknowledge', incident.id)}>{c.acknowledgeReview} · {incident.id}</button>}
    </li>;
    const reason = view?.source.reason;
    const editor = !review && (canEnable && (!view!.policy.enabled || draft.editing) || !view && resource.failure === 'expired' && draft.editing) && <form onSubmit={event => { event.preventDefault(); prepare('enable'); }}>
                {!view && <p role="status">{c.draftKept}</p>}
                <fieldset disabled={!canEnable}>
                    <button type="button" className="button small" onClick={() => setChoosing(true)}>{c.choose}</button>
                    {choosing && canEnable && view && <LinuxProcessWatchChooser key={resource.generation} view={view} elapsed={resource.elapsed} selected={text === '' ? [] : names} c={c} onAuthorityLost={() => { reset(); setDraft(emptyDraft()); setChoosing(false); resource.invalidate(); }} onChange={chosen => { reset(); setDraft({ text: chosen.join('\n'), failures, sourceToken: view.source.token, editing: true }); }}/>}
                    <p>{c.manual}</p><label htmlFor={`${uid}-names`}>{c.names}</label><p id={`${uid}-help`}>{c.namesHelp}</p>
                    <textarea id={`${uid}-names`} aria-describedby={`${uid}-help`} aria-invalid={text !== '' && names === null} value={text} rows={4} maxLength={1032} spellCheck={false} autoComplete="off" onChange={event => { reset(); setDraft({ text: event.target.value, failures, sourceToken: view!.source.token, editing: true }); }}/>
                    {text !== '' && names === null && <p role="alert">{c.invalidNames}</p>}
                    <label htmlFor={`${uid}-failures`}>{c.threshold}<select id={`${uid}-failures`} value={failures} onChange={event => { reset(); setDraft({ text, failures: Number(event.target.value), sourceToken: view!.source.token, editing: true }); }}><option value={2}>{c.two}</option><option value={3}>{c.three}</option></select></label>
                    <button type="submit" className="button small" disabled={names === null || !canEnable}>{c.review}</button>
                </fieldset>
            </form>;
    return <details className="linux-process-watches" onToggle={event => { if (event.target !== event.currentTarget) return; const next = event.currentTarget.open; setOpen(next); if (!next) { reset(); setDraft(emptyDraft()); setChoosing(false); } }}>
        <summary>{c.title}</summary>
        {open && <><p>{c.intro}</p><details><summary>{c.details}</summary><p>{c.scope}</p><p>{c.retention}</p><p>{c.semantics}</p><p>{c.recovery}</p><p>{c.note}</p><p>{c.fresh}</p></details>
            <button type="button" className="text-button" disabled={resource.busy !== null || resource.failure === 'session'} onClick={() => { reset(); resource.read(); }}>{c.refresh}</button>
            {resource.busy && <p role="status">{resource.busy === 'write' ? c.writing : c.loading}</p>}
            {resource.failure && <p role="alert">{c[resource.failure]}</p>}{resource.confirmed && <p role="status">{c.confirmed}</p>}{resource.full && <p role="alert">{c.full}</p>}
            {resource.previous.length > 0 && <div role="alert" className="process-watch-notice"><p>{c.previous}</p><details><summary>{c.earlier} ({resource.previous.length})</summary><ul>{resource.previous.map(request => <li key={request.body.requestId}>{request.body.requestId} · {operation(request)}</li>)}</ul></details></div>}
            {resource.uncertain && resource.busy !== 'write' && <div role="alert" className="process-watch-notice"><p>{c.uncertain}</p>{view && <p>{c.unresolved}</p>}<p>{c.request}: {resource.uncertain.body.requestId} · {operation(resource.uncertain)}</p></div>}
            {view && <><p>{c.snapshot}: <UTC value={view.serverNow}/> · {c.revision}: {view.revision}</p>
                <p>{view.policy.enabled ? c.on : c.off}</p>{view.policy.enabledAt && <p>{c.enabledAt}: <UTC value={view.policy.enabledAt}/></p>}
                {view.policy.enabled && <p>{c.selected}: {view.policy.names.map((name, index) => <span key={name}>{index > 0 && ', '}<Name value={name} c={c}/></span>)} · {c.threshold}: {view.policy.consecutiveFailures}</p>}
                {!view.policy.sourceMatches && view.policy.enabled && <p role="status">{c.mismatch}</p>}{!view.clockReliable && <p role="alert">{c.clockUnreliable}</p>}{!view.canManage && <p>{c.readOnly}</p>}{view.revision === String(PROCESS_WATCH_MAX_REVISION) && <p role="status">{c.maxRevision}</p>}
                <p role="status">{view.source.status === 'available' ? c.available : reason === 'unavailable' || reason === 'none' ? c.sourceUnavailable : c[reason!]}</p>
                {view.source.generation && <details><summary>{c.available}</summary><Generation value={view.source.generation} c={c}/></details>}
                {view.checks.length > 0 && <section aria-labelledby={`${uid}-current`}><h3 id={`${uid}-current`}>{c.current}</h3><ul className="process-watch-checks">{view.checks.map(check => {
                    const condition = processWatchCondition(view, check, resource.elapsed);
                    return <li key={check.name}><strong><Name value={check.name} c={c}/> · {c[condition]}</strong>{condition !== 'unknown' && <><p>{c.active}: {check.activeCount} · {c.nonRunning}: {check.nonRunningCount}</p>{condition === 'pending' && <p>{c.failures}: {check.failureCount}/{view.policy.consecutiveFailures}</p>}{condition === 'incident' && <p>{c.successes}: {check.successCount}/2</p>}</>}</li>;
                })}</ul></section>}
                {editable && !review && <>{canEnable && view.policy.enabled && !draft.editing && <button type="button" className="button small" onClick={() => { reset(); setDraft({ text: view.policy.names.join('\n'), failures: view.policy.consecutiveFailures, sourceToken: view.source.token, editing: true }); }}>{c.edit}</button>}{view.policy.enabled && <button type="button" className="text-button" onClick={() => prepare('disable')}>{c.disableReview}</button>}</>}
                {editor}
                {review && <section className="process-watch-review" aria-labelledby={`${uid}-review`}><h3 id={`${uid}-review`}>{c.reviewTitle}</h3>
                    <dl><div><dt>{c.operation}</dt><dd>{operation(review.request)}</dd></div><div><dt>{c.source}</dt><dd>{review.request.body.sourceToken}</dd></div><div><dt>{c.revision}</dt><dd>{review.request.body.expectedRevision}</dd></div>
                    {review.request.operation === 'acknowledge' ? <div><dt>{c.id}</dt><dd>{review.request.body.incidentId}</dd></div> : review.request.body.enabled && <><div><dt>{c.selected}</dt><dd><ul>{review.request.body.names.map(name => <li key={name}><Name value={name} c={c}/></li>)}</ul></dd></div><div><dt>{c.threshold}</dt><dd>{review.request.body.consecutiveFailures}</dd></div></>}</dl>
                    <p>{c.retention}</p><p>{c.recovery}</p>{review.request.operation === 'policy' && review.request.body.enabled && <p>{c.nameMeaning}</p>}
                    <label className="process-watch-consent"><input type="checkbox" checked={consent} disabled={!editable} onChange={event => setConsent(event.target.checked)}/>{review.request.operation === 'acknowledge' ? c.seenConsent : review.request.body.enabled ? c.enableConsent : c.disableConsent}</label>
                    <div className="process-watch-actions"><button type="button" className="button small" disabled={!consent || !editable} onClick={apply}>{operation(review.request)}</button><button type="button" className="text-button" onClick={reset}>{c.discard}</button></div>
                </section>}
                {view.earlierOmitted > 0 && <p role="status">{c.omitted}: {view.earlierOmitted}</p>}
                <section aria-labelledby={`${uid}-history`}><h3 id={`${uid}-history`}>{c.history}</h3>{view.incidents.length === 0 ? <p>{c.empty}</p> : <ol className="process-watch-history">{view.incidents.map(incidentCard)}</ol>}</section>
            </>}
            {!view && editor}
        </>}
    </details>;
}
