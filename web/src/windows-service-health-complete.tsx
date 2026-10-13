import { useEffect, useState } from 'react';
import { ListChecks, RefreshCw } from 'lucide-react';
import { getProtectedRequestEpoch } from './api';
import { inventoryAge } from './complete-packages-types';
import { useLocale } from './i18n';
import type { Device } from './types';
import { fullDate } from './utils';
import { windowsCapacityDeviceEligible } from './windows-capacity-types';
import { windowsServiceHealthCompleteCopy, completeServicePickerCopy } from './windows-service-health-complete-copy';
import type { WindowsServiceHealthCopy } from './windows-service-health-copy';
import { WindowsServiceHealthCompletePicker } from './windows-service-health-complete-picker';
import type { CompleteServiceSelectionEvidence } from './windows-service-health-complete-picker';
import type { WindowsServiceHealthCompleteResource } from './windows-service-health-complete-resource';
import { sameWindowsServiceNames } from './windows-service-health-types';
import { validWindowsServiceHealthCompleteSelection, windowsServiceHealthCompleteCheckStatus, windowsServiceHealthCompleteChoices, windowsServiceHealthCompleteStatus, sameWindowsServiceHealthSource, sourceBindingMatches, windowsServiceHealthSourceFresh } from './windows-service-health-complete-types';
import type { WindowsServiceHealthCompleteObservation, WindowsServiceHealthCompletePolicy, WindowsServiceHealthCompleteView } from './windows-service-health-complete-types';
import './windows-capacity.css';
import './windows-service-health.css';

function Timestamp({ label, value }: { label: string; value: string }) { return <div><dt>{label}</dt><dd><time dateTime={value}>{fullDate(value)}</time></dd></div>; }
function Observation({ value, c }: { value: WindowsServiceHealthCompleteObservation; c: WindowsServiceHealthCopy }) {
    return <dl className="windows-capacity-times"><div><dt>{c.reportedState}</dt><dd>{c.states[value.state]}</dd></div><Timestamp label={c.collected} value={value.collectedAt}/><Timestamp label={c.received} value={value.receivedAt}/><div><dt>{c.sequence}</dt><dd>{value.sequence}</dd></div></dl>;
}
function PolicyEditor({ view, resource, c, allowed, scope, deviceId, sessionKey, browsingAllowed }: { view: WindowsServiceHealthCompleteView | null; resource: WindowsServiceHealthCompleteResource; c: WindowsServiceHealthCopy; allowed: boolean; scope: string; deviceId: string; sessionKey: string | null; browsingAllowed: boolean }) {
    const [locale] = useLocale(), copy = completeServicePickerCopy[locale], policy = view?.policy ?? null;
    const [draft, setDraft] = useState<{ scope: string; policy: WindowsServiceHealthCompletePolicy } | null>(null), [conflicted, setConflicted] = useState(false);
    const [browse, setBrowse] = useState(false), [evidence, setEvidence] = useState<CompleteServiceSelectionEvidence | null>(null), [renew, setRenew] = useState(false);
    const ownSaveConfirmed = Boolean(draft && policy && resource.notice === 'saved' && policy.revision > draft.policy.revision && policy.enabled === draft.policy.enabled && sameWindowsServiceNames(policy.services, draft.policy.services));
    useEffect(() => { if (draft && policy && draft.policy.revision !== policy.revision) { setConflicted(!ownSaveConfirmed); setDraft(null); setRenew(false); } }, [draft, policy, ownSaveConfirmed]);
    const activeDraft = draft?.scope === scope && (!policy || draft.policy.revision === policy.revision) ? draft.policy : null;
    const enabled = activeDraft?.enabled ?? policy?.enabled ?? false, services = activeDraft?.services ?? policy?.services ?? [];
    const valid = validWindowsServiceHealthCompleteSelection(services, enabled);
    const reviewed = !!(view && evidence && view.inventory && sameWindowsServiceHealthSource(evidence.source, view.inventory.source) && windowsServiceHealthSourceFresh(evidence.source, view.serverNow, resource.elapsedMS));
    const differentGrant = !!(policy && evidence && !sourceBindingMatches(policy.source, evidence.source));
    const needsSource = !!(policy && (enabled && !policy.enabled || services.some(name => !policy.services.includes(name)) || renew && differentGrant));
    const reported = !!(policy && (!needsSource || reviewed && services.every(name => (!enabled || policy.enabled) && !differentGrant && policy.services.includes(name) || evidence!.names.includes(name))));
    const changed = Boolean(policy && (enabled !== policy.enabled || !sameWindowsServiceNames(services, policy.services) || renew && differentGrant));
    const editable = allowed && Boolean(policy) && !resource.saving && !resource.loading && !resource.unresolved && !resource.error;
    const change = (fields: Partial<Pick<WindowsServiceHealthCompletePolicy, 'enabled' | 'services'>>) => { if (editable && policy) { if (fields.services !== undefined || fields.enabled === false) setRenew(false); setConflicted(false); setDraft({ scope, policy: { ...policy, enabled, services, ...fields } }); } };
    const receiveEvidence = (value: CompleteServiceSelectionEvidence | null) => { if (!sameWindowsServiceHealthSource(evidence?.source ?? null, value?.source ?? null)) setRenew(false); setEvidence(value); };
    return <form className="windows-capacity-form" onSubmit={event => { event.preventDefault(); if (editable && valid && reported && changed && policy) resource.save({ enabled, services: [...services], expectedRevision: policy.revision, source: needsSource ? evidence!.source : null, reviewedNames: evidence?.names ?? [] }); }}>
        {!policy && <p>{c.policyUnknown}</p>}
        {(conflicted || draft && policy && draft.policy.revision !== policy.revision && !ownSaveConfirmed) && resource.notice !== 'conflict' && <p role="status">{c.conflict}</p>}
        <label className="windows-capacity-enable"><input type="checkbox" checked={enabled} disabled={!editable} onChange={event => change({ enabled: event.target.checked })}/>{c.enable}</label>
        {!browse && <button type="button" className="button small" disabled={!editable} onClick={() => setBrowse(true)}>{copy.load}</button>}
        <WindowsServiceHealthCompletePicker deviceId={deviceId} sessionKey={sessionKey} enabled={browse && browsingAllowed} disabled={!editable} selected={services} onChange={names => change({ services: names })} onEvidence={receiveEvidence} c={c}/>
        {differentGrant && policy?.source && <label className="windows-capacity-enable"><input type="checkbox" checked={renew} disabled={!editable || !reviewed || !services.every(name => evidence?.names.includes(name))} onChange={event => { setRenew(event.target.checked); change({}); }}/>{copy.renew}</label>}
        {policy && !valid && <p role="status">{c.invalid}</p>}
        {policy && valid && !reported && <p role="status">{c.selectionNeedsReport}</p>}
        {policy && <p>{c.revision}: {policy.revision}. {c.noChange}</p>}
        <div className="windows-capacity-actions"><button type="submit" className="button" disabled={!editable || !valid || !reported || !changed}>{resource.saving ? c.saving : c.save}</button><button type="button" className="text-button" disabled={!editable || !changed && !conflicted} onClick={() => { setDraft(null); setConflicted(false); setRenew(false); setBrowse(false); setEvidence(null); }}>{c.cancel}</button></div>
    </form>;
}
export function WindowsServiceHealthCompletePanel({ device, resource, sessionKey, metadataReady, admin, invalidateDraft = false }: { device: Device; resource: WindowsServiceHealthCompleteResource; sessionKey: string | null; metadataReady: boolean; admin: boolean; invalidateDraft?: boolean }) {
    const [locale] = useLocale(), c = windowsServiceHealthCompleteCopy[locale], { elapsedMS } = resource, candidate = resource.view;
    const authority = candidate?.schemaVersion === 'tracebolt.windows-service-view.v2' && metadataReady && windowsCapacityDeviceEligible(device, device.id) && candidate.deviceId === device.id && sessionKey && Number.isFinite(elapsedMS) && elapsedMS >= 0 && inventoryAge(sessionKey, candidate.serverNow) > elapsedMS && inventoryAge(candidate.certificateExpiresAt, candidate.serverNow) > elapsedMS && device.agentCertificate?.expiresAt && inventoryAge(device.agentCertificate.expiresAt, candidate.serverNow) > elapsedMS && inventoryAge(candidate.serverNow, device.agentCertificate.checkedAt) + elapsedMS >= 0 && inventoryAge(candidate.serverNow, device.agentCertificate.checkedAt) + elapsedMS <= 120000;
    const view = authority && !resource.error && !resource.loading && !resource.saving ? candidate : null;
    const status = view ? windowsServiceHealthCompleteStatus(view, elapsedMS) : 'unknown';
    const editorScope = JSON.stringify(['windows-services-complete', device.id, sessionKey, getProtectedRequestEpoch(), resource.draftGeneration, invalidateDraft, admin, windowsCapacityDeviceEligible(device, device.id), resource.error === 'session' || resource.error === 'authority']);
    return <section className="windows-capacity windows-service-health windows-service-health-complete" aria-label={c.title}>
        <header><h2><ListChecks size={16} aria-hidden="true"/>{c.title}</h2><button type="button" className="text-button" disabled={resource.loading || resource.saving || !metadataReady || !sessionKey || !windowsCapacityDeviceEligible(device, device.id) || resource.error === 'session'} onClick={resource.refresh}><RefreshCw size={14} aria-hidden="true"/>{c.refresh}</button></header>
        <p className="windows-capacity-scope">{c.scope}</p>
        <div className="windows-capacity-assessment"><span>{c.status}</span><strong>{c[status]}</strong></div>
        {!view && <p role="status">{resource.saving ? c.saving : resource.loading ? c.refreshing : resource.error ? c.unavailable : c.noAuthority}</p>}
        {resource.notice && <p role="status">{c[resource.notice]}</p>}
        {view && <>
            {view.evaluatedAt && <dl className="windows-capacity-times"><Timestamp label={c.evaluated} value={view.evaluatedAt}/></dl>}
            {status === 'unknown' && <p role="status">{c.stale}</p>}
            {view.checks.length > 0 && <ul className="windows-service-checks" aria-label={c.selected}>{view.checks.map(check => {
                const current = windowsServiceHealthCompleteCheckStatus(view, check, elapsedMS), displayName = windowsServiceHealthCompleteChoices(view, elapsedMS).find(row => row.name === check.name)?.displayName;
                return <li key={check.name}><div className="windows-service-check-heading"><span>{displayName || check.name}{displayName && <small>{c.name}: <code>{check.name}</code></small>}</span><strong>{current === 'running' ? c.states.running : c[current]}</strong></div>{current !== 'unknown' && check.observation && <Observation value={check.observation} c={c}/>}</li>;
            })}</ul>}
            <h3>{c.history}</h3>
            {view.incidents.length === 0 ? <p>{c.empty}</p> : <ol className="windows-capacity-incidents">{view.incidents.map(row => <li key={row.id}>
                <div className="windows-capacity-incident-heading"><strong>{row.resolvedAt ? row.closedReason === 'policy-changed' ? c.changed : c.recovered : c.open}</strong><span>{c.name}: <code>{row.name}</code></span><span>{c.id}: <code>{row.id}</code></span></div>
                <dl className="windows-capacity-times"><Timestamp label={c.opened} value={row.openedAt}/><Timestamp label={c.confirmed} value={row.lastConfirmedAt}/><div><dt>{c.revision}</dt><dd>{row.policyRevision}</dd></div>{row.resolvedAt && <Timestamp label={c.resolved} value={row.resolvedAt}/>}</dl>
                <details><summary>{c.opening}</summary><Observation value={row.openingObservation} c={c}/></details><details><summary>{c.lastStopped}</summary><Observation value={row.lastBadObservation} c={c}/></details>{row.recoveryObservation && <details><summary>{c.recovery}</summary><Observation value={row.recoveryObservation} c={c}/></details>}
            </li>)}</ol>}
        </>}
        <details className="windows-inventory-scope"><summary>{c.settings}</summary>
            {!admin && <p>{c.readOnly}</p>}
            <PolicyEditor key={editorScope} scope={editorScope} deviceId={device.id} sessionKey={sessionKey} browsingAllowed={Boolean(metadataReady && sessionKey && windowsCapacityDeviceEligible(device, device.id) && !invalidateDraft && resource.error !== 'session' && resource.error !== 'authority')} view={view} resource={resource} c={c} allowed={admin}/>
            {view?.inventory && windowsServiceHealthCompleteChoices(view, elapsedMS).length > 0 && <><p>{c.reportedList}: {view.inventory.services.length} · {view.inventory.quality === 'partial' ? c.partial : c.observedScope}</p><dl className="windows-capacity-times"><Timestamp label={c.collected} value={view.inventory.collectedAt}/><Timestamp label={c.received} value={view.inventory.receivedAt}/><div><dt>{c.sequence}</dt><dd>{view.inventory.sequence}</dd></div></dl></>}
            <p>{c.rules}</p><p>{c.limits}</p><p>{c.scopeLimit}</p><p>{c.retention}</p>
        </details>
    </section>;
}
