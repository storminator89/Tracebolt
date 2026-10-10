import { useEffect, useState } from 'react';
import { ListChecks, RefreshCw } from 'lucide-react';
import { getProtectedRequestEpoch } from './api';
import { inventoryAge } from './complete-packages-types';
import { useLocale } from './i18n';
import type { Device } from './types';
import { fullDate } from './utils';
import { windowsCapacityDeviceEligible } from './windows-capacity-types';
import { windowsServiceHealthCopy } from './windows-service-health-copy';
import type { WindowsServiceHealthCopy } from './windows-service-health-copy';
import { WindowsServiceHealthPicker } from './windows-service-health-picker';
import type { WindowsServiceHealthResource } from './windows-service-health-resource';
import { compareWindowsServiceNames, sameWindowsServiceNames, validWindowsServiceHealthSelection, windowsServiceHealthCheckStatus, windowsServiceHealthChoices, windowsServiceHealthStatus } from './windows-service-health-types';
import type { WindowsServiceHealthObservation, WindowsServiceHealthPolicy, WindowsServiceHealthView } from './windows-service-health-types';
import './windows-capacity.css';
import './windows-service-health.css';

function Timestamp({ label, value }: { label: string; value: string }) { return <div><dt>{label}</dt><dd><time dateTime={value}>{fullDate(value)}</time></dd></div>; }
function Observation({ value, c }: { value: WindowsServiceHealthObservation; c: WindowsServiceHealthCopy }) {
    return <dl className="windows-capacity-times"><div><dt>{c.reportedState}</dt><dd>{c.states[value.state]}</dd></div><Timestamp label={c.collected} value={value.collectedAt}/><Timestamp label={c.received} value={value.receivedAt}/><div><dt>{c.sequence}</dt><dd>{value.sequence}</dd></div></dl>;
}
function PolicyEditor({ view, resource, c, allowed, scope }: { view: WindowsServiceHealthView | null; resource: WindowsServiceHealthResource; c: WindowsServiceHealthCopy; allowed: boolean; scope: string }) {
    const policy = view?.policy ?? null;
    const [draft, setDraft] = useState<{ scope: string; policy: WindowsServiceHealthPolicy } | null>(null), [conflicted, setConflicted] = useState(false);
    const ownSaveConfirmed = Boolean(draft && policy && resource.notice === 'saved' && policy.revision > draft.policy.revision && policy.enabled === draft.policy.enabled && sameWindowsServiceNames(policy.services, draft.policy.services));
    useEffect(() => { if (draft && policy && draft.policy.revision !== policy.revision) { setConflicted(!ownSaveConfirmed); setDraft(null); } }, [draft, policy, ownSaveConfirmed]);
    const activeDraft = draft?.scope === scope && (!policy || draft.policy.revision === policy.revision) ? draft.policy : null;
    const enabled = activeDraft?.enabled ?? policy?.enabled ?? false, services = activeDraft?.services ?? policy?.services ?? [];
    const choices = view ? windowsServiceHealthChoices(view, resource.elapsedMS) : [];
    const valid = validWindowsServiceHealthSelection(services, enabled);
    const reported = Boolean(policy && services.every(name => (!enabled || policy.enabled) && policy.services.includes(name) || choices.some(row => row.name === name)));
    const changed = Boolean(policy && (enabled !== policy.enabled || !sameWindowsServiceNames(services, policy.services)));
    const editable = allowed && Boolean(policy) && !resource.saving && !resource.loading && !resource.unresolved && !resource.error;
    const change = (fields: Partial<Pick<WindowsServiceHealthPolicy, 'enabled' | 'services'>>) => { if (editable && policy) { setConflicted(false); setDraft({ scope, policy: { revision: policy.revision, enabled, services, ...fields } }); } };
    return <form className="windows-capacity-form" onSubmit={event => { event.preventDefault(); if (editable && valid && reported && changed && policy) resource.save({ enabled, services: [...services], expectedRevision: policy.revision }); }}>
        {!policy && <p>{c.policyUnknown}</p>}
        {(conflicted || draft && policy && draft.policy.revision !== policy.revision && !ownSaveConfirmed) && resource.notice !== 'conflict' && <p role="status">{c.conflict}</p>}
        <label className="windows-capacity-enable"><input type="checkbox" checked={enabled} disabled={!editable} onChange={event => change({ enabled: event.target.checked })}/>{c.enable}</label>
        <WindowsServiceHealthPicker choices={choices} selected={services} disabled={!editable} onChange={names => change({ services: [...names].sort(compareWindowsServiceNames) })} c={c}/>
        {policy && !valid && <p role="status">{c.invalid}</p>}
        {policy && valid && !reported && <p role="status">{c.selectionNeedsReport}</p>}
        {policy && <p>{c.revision}: {policy.revision}. {c.noChange}</p>}
        <div className="windows-capacity-actions"><button type="submit" className="button" disabled={!editable || !valid || !reported || !changed}>{resource.saving ? c.saving : c.save}</button><button type="button" className="text-button" disabled={!editable || !changed && !conflicted} onClick={() => { setDraft(null); setConflicted(false); }}>{c.cancel}</button></div>
    </form>;
}
export function WindowsServiceHealthPanel({ device, resource, sessionKey, metadataReady, admin, invalidateDraft = false }: { device: Device; resource: WindowsServiceHealthResource; sessionKey: string | null; metadataReady: boolean; admin: boolean; invalidateDraft?: boolean }) {
    const [locale] = useLocale(), c = windowsServiceHealthCopy[locale], { elapsedMS } = resource, candidate = resource.view;
    const authority = candidate?.schemaVersion === 'tracebolt.windows-service-view.v1' && metadataReady && windowsCapacityDeviceEligible(device, device.id) && candidate.deviceId === device.id && sessionKey && Number.isFinite(elapsedMS) && elapsedMS >= 0 && inventoryAge(sessionKey, candidate.serverNow) > elapsedMS && inventoryAge(candidate.certificateExpiresAt, candidate.serverNow) > elapsedMS && device.agentCertificate?.expiresAt && inventoryAge(device.agentCertificate.expiresAt, candidate.serverNow) > elapsedMS && inventoryAge(candidate.serverNow, device.agentCertificate.checkedAt) + elapsedMS >= 0 && inventoryAge(candidate.serverNow, device.agentCertificate.checkedAt) + elapsedMS <= 120000;
    const view = authority && !resource.error && !resource.loading && !resource.saving ? candidate : null;
    const status = view ? windowsServiceHealthStatus(view, elapsedMS) : 'unknown';
    const editorScope = JSON.stringify(['windows-services', device.id, sessionKey, getProtectedRequestEpoch(), resource.draftGeneration, invalidateDraft, admin, windowsCapacityDeviceEligible(device, device.id), resource.error === 'session' || resource.error === 'authority']);
    return <section className="windows-capacity windows-service-health" aria-label={c.title}>
        <header><h2><ListChecks size={16} aria-hidden="true"/>{c.title}</h2><button type="button" className="text-button" disabled={resource.loading || resource.saving || !metadataReady || !sessionKey || !windowsCapacityDeviceEligible(device, device.id) || resource.error === 'session'} onClick={resource.refresh}><RefreshCw size={14} aria-hidden="true"/>{c.refresh}</button></header>
        <p className="windows-capacity-scope">{c.scope}</p>
        <div className="windows-capacity-assessment"><span>{c.status}</span><strong>{c[status]}</strong></div>
        {!view && <p role="status">{resource.saving ? c.saving : resource.loading ? c.refreshing : resource.error ? c.unavailable : c.noAuthority}</p>}
        {resource.notice && <p role="status">{c[resource.notice]}</p>}
        {view && <>
            {view.evaluatedAt && <dl className="windows-capacity-times"><Timestamp label={c.evaluated} value={view.evaluatedAt}/></dl>}
            {status === 'unknown' && <p role="status">{c.stale}</p>}
            {view.checks.length > 0 && <ul className="windows-service-checks" aria-label={c.selected}>{view.checks.map(check => {
                const current = windowsServiceHealthCheckStatus(view, check, elapsedMS), displayName = windowsServiceHealthChoices(view, elapsedMS).find(row => row.name === check.name)?.displayName;
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
            <PolicyEditor key={editorScope} scope={editorScope} view={view} resource={resource} c={c} allowed={admin}/>
            {view?.inventory && windowsServiceHealthChoices(view, elapsedMS).length > 0 && <><p>{c.reportedList}: {view.inventory.services.length} · {view.inventory.quality === 'partial' ? c.partial : c.observedScope}</p><dl className="windows-capacity-times"><Timestamp label={c.collected} value={view.inventory.collectedAt}/><Timestamp label={c.received} value={view.inventory.receivedAt}/><div><dt>{c.sequence}</dt><dd>{view.inventory.sequence}</dd></div></dl></>}
            <p>{c.rules}</p><p>{c.limits}</p><p>{c.scopeLimit}</p><p>{c.retention}</p>
        </details>
    </section>;
}
