import { useEffect, useRef, useState } from 'react';
import { useLocale } from './i18n';
import type { FleetGroupsResource } from './fleet-groups';
import type { FleetGroup } from './fleet-groups-types';
import { groupMonitoringKey, groupMonitoringMetrics } from './fleet-group-monitoring-types';
import type { GroupMonitoringTarget, GroupMonitoringView } from './fleet-group-monitoring-types';
import { reviewGroupMonitoring, saveGroupMonitoring } from './fleet-group-monitoring-workflow';
import type { GroupMonitoringReview } from './fleet-group-monitoring-workflow';
import type { WindowsPercentageMetric } from './windows-capacity-types';

const copy = {
    en: {
        title: 'Group monitoring', effect: 'Keep selected Windows monitoring policies in sync.', details: 'Scope, exact IDs and revisions', scope: 'Keep only reviewed manager policies in sync for exact Windows members. New members are never included automatically. No collection, notifications, AI or device actions are granted.',
        disk: 'System-volume capacity', cpu: 'CPU percentage', memory: 'Physical RAM percentage', include: 'Include', enabled: 'Enable policy', threshold: 'Threshold (%)', settings: 'Inherited policies', devices: 'Exact Windows members',
        consent: 'Keep these reviewed policies in sync for these exact members until stopped or manually overridden.', review: 'Review inheritance', save: 'Save reviewed inheritance', cancel: 'Cancel review', close: 'Close inheritance', refresh: 'Refresh inheritance', loading: 'Checking inheritance…', saving: 'Saving inheritance…', unavailable: 'Inheritance is unavailable. Refresh before continuing.', failed: 'Review changed or expired. Refresh and review again.', saved: 'Inheritance saved. Synchronization may still be pending.', conflict: 'Conflict. Refresh and review again.', unconfirmed: 'Save is unconfirmed and will not be retried. Readback shows current state only; it does not prove this save succeeded.',
        stop: 'Stop inheriting', stopReview: 'Review stopping inheritance', stopSave: 'Stop reviewed inheritance', stopScope: 'The last device policy stays in place. Future group edits will no longer update this assignment.', stoppedSaved: 'Inheritance stopped. The last device policy stays in place.', fresh: 'Start new review', groupRevision: 'Group revision', definitionRevision: 'Definition revision', assignmentRevision: 'Assignment revision', policyRevision: 'Policy revision', current: 'Current policy', desired: 'Desired policy', on: 'Enabled', off: 'Disabled',
        status: 'Current inheritance', conflictCount: 'Conflict', manual: 'Manual', pending: 'Pending', inherited: 'Inherited', 'manual-override': 'Manual override', stopped: 'Stopped', otherOwner: 'Another group owns this metric', unavailableMembers: 'Unavailable Windows members', unavailableAssignments: 'Unavailable assignments', unavailableScope: 'Previously opted-in unavailable assignments may become pending when their definition changes. Their private identities are not shown.', fanout: 'Editing a definition also updates its existing inherited assignments listed below. Unchecked new members and manual overrides stay unchanged.', empty: 'No current Windows members.', readOnly: 'Read-only access.', reviewScope: 'Exact members, metrics and revisions are frozen below. Saving is single-use; uncertainty never triggers a retry.', invalid: 'Use a whole-number threshold from 50 to 99.',
    },
    de: {
        title: 'Gruppen-Monitoring', effect: 'Gewählte Windows-Monitoring-Richtlinien synchron halten.', details: 'Umfang, exakte IDs und Versionen', scope: 'Nur geprüfte Manager-Richtlinien für exakte Windows-Mitglieder synchron halten. Neue Mitglieder werden nie automatisch einbezogen. Keine Erfassung, Benachrichtigungen, KI oder Geräteaktionen werden freigegeben.',
        disk: 'Kapazität des Systemvolumes', cpu: 'CPU-Prozentwert', memory: 'Physischer RAM-Prozentwert', include: 'Einbeziehen', enabled: 'Richtlinie aktivieren', threshold: 'Schwellenwert (%)', settings: 'Vererbte Richtlinien', devices: 'Exakte Windows-Mitglieder',
        consent: 'Diese geprüften Richtlinien für diese exakten Mitglieder bis zum Stoppen oder manuellen Überschreiben synchron halten.', review: 'Vererbung prüfen', save: 'Geprüfte Vererbung speichern', cancel: 'Prüfung abbrechen', close: 'Vererbung schließen', refresh: 'Vererbung aktualisieren', loading: 'Vererbung wird geprüft …', saving: 'Vererbung wird gespeichert …', unavailable: 'Vererbung ist nicht verfügbar. Vor dem Fortfahren aktualisieren.', failed: 'Die Prüfung hat sich geändert oder ist abgelaufen. Aktualisieren und erneut prüfen.', saved: 'Vererbung gespeichert. Die Synchronisierung kann noch ausstehen.', conflict: 'Konflikt. Aktualisieren und erneut prüfen.', unconfirmed: 'Speichern ist unbestätigt und wird nicht wiederholt. Die Leseprüfung zeigt nur den aktuellen Stand; sie belegt keinen erfolgreichen Schreibvorgang.',
        stop: 'Vererbung stoppen', stopReview: 'Stoppen der Vererbung prüfen', stopSave: 'Geprüfte Vererbung stoppen', stopScope: 'Die letzte Geräte-Richtlinie bleibt bestehen. Künftige Gruppenänderungen ändern diese Zuordnung nicht mehr.', stoppedSaved: 'Vererbung gestoppt. Die letzte Geräte-Richtlinie bleibt bestehen.', fresh: 'Neu prüfen', groupRevision: 'Gruppenversion', definitionRevision: 'Definitionsversion', assignmentRevision: 'Zuordnungsversion', policyRevision: 'Richtlinienversion', current: 'Aktuelle Richtlinie', desired: 'Gewünschte Richtlinie', on: 'Aktiviert', off: 'Deaktiviert',
        status: 'Aktuelle Vererbung', conflictCount: 'Konflikt', manual: 'Manuell', pending: 'Ausstehend', inherited: 'Vererbt', 'manual-override': 'Manuell überschrieben', stopped: 'Gestoppt', otherOwner: 'Eine andere Gruppe besitzt diese Metrik', unavailableMembers: 'Nicht verfügbare Windows-Mitglieder', unavailableAssignments: 'Nicht verfügbare Zuordnungen', unavailableScope: 'Zuvor freigegebene, nicht verfügbare Zuordnungen können bei Definitionsänderungen ausstehend werden. Ihre privaten Identitäten werden nicht angezeigt.', fanout: 'Eine Definitionsänderung aktualisiert auch die unten aufgeführten bereits vererbten Zuordnungen. Nicht gewählte neue Mitglieder und manuelle Überschreibungen bleiben unverändert.', empty: 'Keine aktuellen Windows-Mitglieder.', readOnly: 'Nur lesender Zugriff.', reviewScope: 'Exakte Mitglieder, Metriken und Versionen sind unten gebunden. Speichern ist einmalig; Unklarheit führt nie zu einer Wiederholung.', invalid: 'Verwende einen ganzzahligen Schwellenwert von 50 bis 99.',
    },
};
type Draft = { metric: WindowsPercentageMetric; selected: boolean; enabled: boolean; threshold: string };
const draftsFor = (view: GroupMonitoringView | null): Draft[] => groupMonitoringMetrics.map(metric => { const definition = view?.definitions.find(d => d.metric === metric); return { metric, selected: false, enabled: definition?.enabled ?? false, threshold: String(definition?.thresholdPercent ?? 90) }; });

export function GroupMonitoring({ resource, group, onClose }: { resource: FleetGroupsResource; group: FleetGroup; onClose: () => void }) {
    const [locale] = useLocale(), c = copy[locale];
    const [view, setView] = useState<GroupMonitoringView | null>(null), [drafts, setDrafts] = useState(() => draftsFor(null)), [ids, setIds] = useState<string[]>([]), [consent, setConsent] = useState(false);
    const [review, setReview] = useState<GroupMonitoringReview | null>(null), [phase, setPhase] = useState<'loading' | 'draft' | 'reviewing' | 'reviewed' | 'saving' | 'done' | 'failed'>('loading'), [notice, setNotice] = useState<'saved' | 'stoppedSaved' | 'conflict' | 'unconfirmed' | null>(null);
    const alive = useRef(true), run = useRef(0), busy = useRef(false), initial = useRef(resource);
    const load = async () => {
        if (busy.current) return;
        busy.current = true; const current = ++run.current; setPhase('loading'); setReview(null); setNotice(null); setView(null); setIds([]); setConsent(false);
        try { const next = await initial.current.monitoringIO(group.id, true).get(); if (alive.current && current === run.current) { setView(next); setDrafts(draftsFor(next)); setPhase('draft'); } }
        catch { if (alive.current && current === run.current) setPhase('failed'); }
        finally { if (current === run.current) busy.current = false; }
    };
    useEffect(() => { alive.current = true; void load(); return () => { alive.current = false; run.current++; }; }, [group.id]); // The parent keys this panel by group and private resource generation.
    const selected = drafts.filter(d => d.selected), settings = selected.map(d => ({ metric: d.metric, enabled: d.enabled, thresholdPercent: Number(d.threshold) }));
    const members = [...new Map((view?.targets ?? []).map(t => [t.deviceId, t])).values()];
    const unavailableMembers = view ? (resource.view?.devices.filter(d => d.platform === 'windows' && group.memberIds.includes(d.id)).length ?? 0) - members.length : 0;
    const invalidThreshold = selected.some(d => !/^\d{2}$/.test(d.threshold) || Number(d.threshold) < 50 || Number(d.threshold) > 99);
    const technicalTargets = review?.targets ?? view?.targets ?? [];
    const technicalMembers = [...new Map(technicalTargets.map(t => [t.deviceId, t])).values()];
    const statusCounts = (['pending', 'inherited', 'manual-override', 'conflict', 'manual', 'stopped'] as const).map(status => ({ status, count: view?.targets.filter(t => t.status === status).length ?? 0 })).filter(row => row.count > 0);
    const valid = consent && selected.length > 0 && selected.every(d => /^\d{2}$/.test(d.threshold) && Number(d.threshold) >= 50 && Number(d.threshold) <= 99) && (!!view?.targets.some(t => selected.some(d => d.metric === t.metric) && (ids.includes(t.deviceId) || t.owned && ['pending', 'inherited'].includes(t.status))) || !!view && view.unavailableAssignments > 0 && selected.every(d => view.definitions.some(current => current.metric === d.metric))) && !view?.targets.some(t => ids.includes(t.deviceId) && selected.some(d => d.metric === t.metric) && t.status === 'conflict');
    const edit = (metric: WindowsPercentageMetric, patch: Partial<Draft>) => { setConsent(false); setDrafts(previous => previous.map(d => d.metric === metric ? { ...d, ...patch } : d)); };
    const prepare = async (stop?: GroupMonitoringTarget) => {
        if (busy.current || !resource.admin || phase !== 'draft' || !stop && !valid) return;
        busy.current = true; const current = ++run.current; setPhase('reviewing'); setNotice(null);
        try { const next = await resource.monitoringIO(group.id, true).get(); const frozen = reviewGroupMonitoring(next, settings, [...ids], consent, stop); if (alive.current && current === run.current) { setView(next); setReview(frozen); setPhase('reviewed'); } }
        catch { if (alive.current && current === run.current) { setReview(null); setPhase('failed'); } }
        finally { if (current === run.current) busy.current = false; }
    };
    const save = async () => {
        if (busy.current || !review || phase !== 'reviewed' || !resource.admin) return;
        busy.current = true; const current = ++run.current; setPhase('saving');
        try { const result = await saveGroupMonitoring(review, resource.monitoringIO(group.id)); if (alive.current && current === run.current) { setView(result.view); setNotice(result.status === 'saved' && review.stopping ? 'stoppedSaved' : result.status); setReview(null); setPhase('done'); setConsent(false); setIds([]); setDrafts(draftsFor(result.view)); } }
        catch { if (alive.current && current === run.current) { setReview(null); setPhase('failed'); } }
        finally { if (current === run.current) busy.current = false; }
    };
    const policyText = (value: { enabled: boolean; thresholdPercent: number }) => `${value.enabled ? c.on : c.off} · ${value.thresholdPercent}%`;
    return <section aria-label={c.title} className="fleet-inheritance">
        <h3>{c.title} · {group.name}</h3><p>{c.effect}</p>
        {['loading', 'reviewing', 'saving'].includes(phase) && <p role="status">{phase === 'saving' ? c.saving : c.loading}</p>}
        {phase === 'failed' && <p role="status">{view ? c.failed : c.unavailable}</p>}{notice && <p role="status">{c[notice]}</p>}
        {!resource.admin && <p>{c.readOnly}</p>}
        {unavailableMembers > 0 && <p>{c.unavailableMembers}: {unavailableMembers}</p>}
        {!!view?.unavailableAssignments && <p>{c.unavailableAssignments}: {view.unavailableAssignments}. {c.unavailableScope}</p>}
        {phase === 'draft' && view && resource.admin && <>
            <fieldset className="fleet-monitoring-settings"><legend>{c.settings}</legend>{drafts.map(d => <div key={d.metric} className="fleet-monitoring-setting">
                <label className="fleet-group-enable"><input type="checkbox" aria-label={`${c.include} ${c[d.metric]}`} checked={d.selected} onChange={e => edit(d.metric, { selected: e.target.checked })}/>{c[d.metric]}</label>
                <label className="fleet-group-enable"><input type="checkbox" aria-label={`${c.enabled} · ${c[d.metric]}`} checked={d.enabled} disabled={!d.selected} onChange={e => edit(d.metric, { enabled: e.target.checked })}/>{c.enabled}</label>
                <label className="fleet-group-field">{c.threshold}<input aria-label={`${c.threshold} · ${c[d.metric]}`} type="number" min="50" max="99" step="1" value={d.threshold} disabled={!d.selected} onChange={e => edit(d.metric, { threshold: e.target.value })}/></label>
            </div>)}</fieldset>
            <fieldset className="fleet-group-choices"><legend>{c.devices} ({ids.length}/25)</legend>{members.map(t => <label key={t.deviceId}><input type="checkbox" aria-label={`${t.name} ${t.deviceId}`} checked={ids.includes(t.deviceId)} disabled={!ids.includes(t.deviceId) && ids.length >= 25} onChange={e => { setConsent(false); setIds(previous => e.target.checked ? [...previous, t.deviceId] : previous.filter(id => id !== t.deviceId)); }}/><span><strong>{t.name}</strong></span></label>)}{!members.length && <p>{c.empty}</p>}</fieldset>
            <label className="fleet-group-enable"><input type="checkbox" checked={consent} onChange={e => setConsent(e.target.checked)}/>{c.consent}</label>
            {invalidThreshold && <p role="alert">{c.invalid}</p>}<button className="button" disabled={!valid} onClick={() => void prepare()}>{c.review}</button>
        </>}
        {review && <div className="fleet-inheritance-review"><h4>{review.stopping ? c.stopReview : c.review}</h4>{review.stopping && <p>{c.stopScope}</p>}
            <ul className="fleet-monitoring-summary">{review.body.definitions.map(d => <li key={d.metric}><strong>{c[d.metric]}</strong>: {policyText(d)}</li>)}</ul>
            <ul className="fleet-group-members">{review.targets.map(t => <li key={groupMonitoringKey(t)}><strong>{t.name} · {c[t.metric]}</strong><small>{c.current}: {policyText(t.policy)}</small>{!review.stopping && <small>{c.desired}: {policyText(review.body.definitions.find(d => d.metric === t.metric)!)}</small>}</li>)}</ul>
            {phase === 'reviewed' && <div className="fleet-group-actions"><button className="button" onClick={() => void save()}>{review.stopping ? c.stopSave : c.save}</button><button className="text-button" onClick={() => void load()}>{c.cancel}</button></div>}
        </div>}
        {view && !review && <details className="fleet-inheritance-status"><summary>{c.status}{statusCounts.map(row => <span key={row.status}> · {row.status === 'conflict' ? c.conflictCount : c[row.status]}: {row.count}</span>)}</summary><ul className="fleet-group-members">{members.map(member => <li key={member.deviceId}><strong>{member.name}</strong>{view.targets.filter(t => t.deviceId === member.deviceId).map(t => <div className="fleet-inheritance-status-row" key={t.metric}><div><span>{c[t.metric]} · {t.status === 'conflict' ? c.otherOwner : c[t.status]}</span><small>{c.current}: {policyText(t.policy)}{t.desired && <> · {c.desired}: {policyText(t.desired)}</>}</small></div>{resource.admin && phase === 'draft' && t.owned && ['pending', 'inherited'].includes(t.status) && <button className="text-button" aria-label={`${c.stop} · ${member.name} · ${c[t.metric]}`} onClick={() => void prepare(t)}>{c.stop}</button>}</div>)}</li>)}</ul></details>}
        <details className="fleet-inheritance-details"><summary>{c.details}</summary><p>{c.scope}</p><p>{c.fanout}</p>{review && <p>{c.reviewScope}</p>}{view && <p>{c.groupRevision}: {review?.body.expectedGroupRevision ?? view.groupRevision} · {c.definitionRevision}: {review?.body.expectedRevision ?? view.revision}</p>}
            <ul className="fleet-group-members">{technicalMembers.map(member => <li key={member.deviceId}><strong>{member.name}</strong><code>{member.deviceId}</code>{technicalTargets.filter(t => t.deviceId === member.deviceId).map(t => <small key={t.metric}>{c[t.metric]} · {c.assignmentRevision}: {t.assignmentRevision} · {c.policyRevision}: {t.policy.revision}</small>)}</li>)}</ul>
        </details>
        <div className="fleet-group-actions">{!busy.current && !review && <button className="text-button" onClick={() => void load()}>{phase === 'done' ? c.fresh : c.refresh}</button>}<button className="text-button" onClick={onClose}>{c.close}</button></div>
    </section>;
}
