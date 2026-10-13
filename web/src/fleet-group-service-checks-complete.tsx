import { useEffect, useRef, useState } from 'react';
import { Dialog } from './components';
import type { FleetGroupsResource } from './fleet-groups';
import type { FleetGroup } from './fleet-groups-types';
import { useLocale } from './i18n';
import { WindowsServiceHealthCompletePicker } from './windows-service-health-complete-picker';
import type { CompleteServiceSelectionEvidence } from './windows-service-health-complete-picker';
import { createGroupCompleteServiceChecksIO } from './fleet-group-service-checks-complete-resource';
import { completeServicePickerCopy, windowsServiceHealthCompleteCopy } from './windows-service-health-complete-copy';
import { WindowsLocalTime } from './windows-local-time';
import { sameWindowsServiceHealthSource, sourceBindingMatches } from './windows-service-health-complete-types';
import { compareWindowsServiceNames } from './windows-service-health-types';
import { applyGroupCompleteServiceChecks, groupCompleteServiceEvidenceAllowed, groupCompleteServiceSettingAllowed, reviewGroupCompleteServiceChecks, sameGroupCompleteServicePolicy } from './fleet-group-service-checks-complete-workflow';
import type { GroupCompleteServiceChecksView, GroupCompleteServiceDraft, GroupCompleteServiceResult, GroupCompleteServiceReview, GroupCompleteServiceSetting } from './fleet-group-service-checks-complete-workflow';
import './windows-service-health.css';

const copy = {
    en: {
        legacy: 'Previously used bounded-preview policies are incompatible and are excluded from this workflow. They remain available in Apply service checks.', preview: 'Complete caller-visible Win32 generation: search every captured row and browse pages of up to 100. Select up to eight exact services per device. Missing and ACL-invisible services stay unknown.', title: 'Apply complete service checks', summary: 'Choose exact Windows members, select services for each, then review once.', groupRevision: 'Group revision', selected: 'Selected devices', linux: 'Excluded Linux members', unavailable: 'Unavailable members', devices: 'Select Windows members', empty: 'No available Windows members.', loading: 'Reading current service policies…', load: 'Load selected service choices', choices: 'Choose services for each device', enable: 'Enable service checks', before: 'Previous policy', desired: 'Desired policy', revision: 'Policy revision', on: 'Enabled', off: 'Disabled', none: 'No services', unknown: 'Current service inventory is unknown. Retained names can still be removed or disabled.', retained: 'Existing names are retained for review. Enable starts unchecked for each device.', review: 'Review exact service checks', reviewing: 'Verifying selected members and policies…', consent: 'Apply these exact service-check policies to these selected members once.', apply: 'Apply reviewed service checks', applying: 'Applying service checks sequentially…', stop: 'Stop remaining writes', stopped: 'Stopped. Earlier outcomes are retained. An interrupted write may already have reached the manager.', fresh: 'Start fresh review', failed: 'The selection changed, expired or could not be verified. An existing preview policy is incompatible with this separate complete-generation workflow. Start a fresh review.', completed: 'This review is used. Every further change needs a fresh review.', results: 'Per-device service-check results', device: 'Device', outcome: 'Outcome', details: 'Scope and exact review details', scope: 'Changes only manager service-check policies using existing consented inventory. No host collection, service action, AI or notification is authorized.', snapshot: 'Only selected original identities are included. No inheritance, new-member adoption, background job, rollback or automatic retry.', safety: 'Stops on conflict or uncertainty. Matching readback cannot prove which attempt wrote the policy.', lease: 'Close, navigation, blur, access loss or the original authority deadline clears this private review.', key: 'Original-identity target', close: 'Cancel', changed: 'Changed · confirmed response', 'currently-matching': 'Currently matching · no write', conflict: 'Conflict · review again', unconfirmed: 'Unconfirmed · write may have happened', 'not-attempted': 'Not attempted', matching: 'Current policy matches. Our write remains unconfirmed.',
    },
    de: {
        legacy: 'Bereits verwendete begrenzte Vorschau-Richtlinien sind inkompatibel und werden hier ausgeschlossen. Sie bleiben unter Dienstprüfungen anwenden verfügbar.', preview: 'Vollständige für den Aufrufer sichtbare Win32-Generation: alle erfassten Zeilen durchsuchen und Seiten mit bis zu 100 Zeilen öffnen. Je Gerät bis zu acht exakte Dienste wählen. Fehlende und nicht sichtbare Dienste bleiben unbekannt.', title: 'Vollständige Dienstprüfungen anwenden', summary: 'Exakte Windows-Mitglieder und Dienste je Gerät auswählen, dann einmal gemeinsam prüfen.', groupRevision: 'Gruppenversion', selected: 'Gewählte Geräte', linux: 'Ausgeschlossene Linux-Mitglieder', unavailable: 'Nicht verfügbare Mitglieder', devices: 'Windows-Mitglieder wählen', empty: 'Keine verfügbaren Windows-Mitglieder.', loading: 'Aktuelle Dienstrichtlinien werden gelesen …', load: 'Dienstoptionen der Auswahl laden', choices: 'Dienste je Gerät auswählen', enable: 'Dienstprüfungen aktivieren', before: 'Bisherige Richtlinie', desired: 'Gewünschte Richtlinie', revision: 'Richtlinienversion', on: 'Aktiviert', off: 'Deaktiviert', none: 'Keine Dienste', unknown: 'Das aktuelle Dienstinventar ist unbekannt. Gespeicherte Namen können weiterhin entfernt oder deaktiviert werden.', retained: 'Bestehende Namen bleiben zur Prüfung erhalten. Aktivieren ist je Gerät zunächst nicht angehakt.', review: 'Exakte Dienstprüfungen prüfen', reviewing: 'Gewählte Mitglieder und Richtlinien werden geprüft …', consent: 'Diese exakten Dienstprüfungsrichtlinien einmal auf diese gewählten Mitglieder anwenden.', apply: 'Geprüfte Dienstprüfungen anwenden', applying: 'Dienstprüfungen werden nacheinander angewendet …', stop: 'Weitere Schreibvorgänge stoppen', stopped: 'Gestoppt. Frühere Ergebnisse bleiben erhalten. Ein unterbrochener Schreibvorgang kann den Manager bereits erreicht haben.', fresh: 'Neu prüfen', failed: 'Die Auswahl wurde geändert, ist abgelaufen oder konnte nicht bestätigt werden. Eine vorhandene Vorschau-Richtlinie ist mit diesem separaten Workflow für vollständige Generationen nicht kompatibel. Beginne eine neue Prüfung.', completed: 'Diese Prüfung wurde verwendet. Jede weitere Änderung benötigt eine neue Prüfung.', results: 'Dienstprüfungsergebnisse je Gerät', device: 'Gerät', outcome: 'Ergebnis', details: 'Umfang und exakte Prüfdetails', scope: 'Ändert nur Manager-Richtlinien für Dienstprüfungen mit bereits freigegebenem Inventar. Keine Erfassung, Dienstaktion, KI oder Benachrichtigung wird freigegeben.', snapshot: 'Nur gewählte ursprüngliche Identitäten sind enthalten. Keine Vererbung, Übernahme neuer Mitglieder, Hintergrundaufgabe, Rücknahme oder automatische Wiederholung.', safety: 'Stopp bei Konflikt oder unklarem Ergebnis. Passendes Zurücklesen beweist nicht, welcher Versuch die Richtlinie geschrieben hat.', lease: 'Schließen, Navigation, Fokusverlust, Zugriffsverlust oder die ursprüngliche Ablaufzeit löschen diese private Prüfung.', key: 'Ziel der ursprünglichen Identität', close: 'Abbrechen', changed: 'Geändert · bestätigte Antwort', 'currently-matching': 'Entspricht bereits · nicht geschrieben', conflict: 'Konflikt · erneut prüfen', unconfirmed: 'Unbestätigt · Änderung eventuell erfolgt', 'not-attempted': 'Nicht versucht', matching: 'Die aktuelle Richtlinie entspricht der Auswahl. Unser Schreibvorgang bleibt unbestätigt.',
    },
};
type Draft = GroupCompleteServiceDraft & { mono: number; wall: number; renew: boolean };
type CompleteIO = ReturnType<typeof createGroupCompleteServiceChecksIO>;
const age = (draft: Draft) => {
    const mono = performance.now() - draft.mono, wall = Date.now() - draft.wall;
    return Number.isFinite(mono) && mono >= 0 && Number.isFinite(wall) && Math.abs(wall - mono) <= 1500 ? mono : Infinity;
};
export function GroupCompleteServiceChecks({ resource, group, onClose }: { resource: FleetGroupsResource; group: FleetGroup; onClose: () => void }) {
    const stopped = useRef(false);
    const [locale] = useLocale(), c = copy[locale], picker = windowsServiceHealthCompleteCopy[locale];
    const [view, setView] = useState<GroupCompleteServiceChecksView | null>(null), [keys, setKeys] = useState<string[]>([]), [drafts, setDrafts] = useState<Draft[]>([]), [consent, setConsent] = useState(false);
    const [review, setReview] = useState<GroupCompleteServiceReview | null>(null), [results, setResults] = useState<GroupCompleteServiceResult[] | null>(null), [pending, setPending] = useState(false), [, tick] = useState(0);
    const [phase, setPhase] = useState<'loading' | 'members' | 'choices' | 'draft' | 'reviewing' | 'reviewed' | 'applying' | 'done' | 'stopped' | 'failed'>('loading');
    const alive = useRef(true), run = useRef(0), busy = useRef(false), io = useRef<CompleteIO | null>(null), initial = useRef(resource), close = useRef(onClose);
    close.current = onClose;
    const finish = (current: number) => { if (current === run.current) { busy.current = false; if (alive.current) setPending(false); } };
    const load = async () => {
        if (busy.current) return;
        busy.current = true; stopped.current = false; setPending(true); const current = ++run.current;
        setView(null); setKeys([]); setDrafts([]); setReview(null); setResults(null); setConsent(false); setPhase('loading');
        try { io.current?.dispose(); const parent = initial.current.io(true); io.current = createGroupCompleteServiceChecksIO(group, initial.current.sessionKey, parent.active); const value = await io.current.get(); if (alive.current && current === run.current) { setView(value); setPhase('members'); } }
        catch { if (alive.current && current === run.current) setPhase(previous => previous === 'stopped' ? previous : 'failed'); }
        finally { finish(current); }
    };
    useEffect(() => {
        alive.current = true; void load(); const timer = window.setInterval(() => { if (io.current && !io.current.active() && !stopped.current) close.current(); else tick(n => n + 1); }, 250);
        return () => { alive.current = false; run.current++; busy.current = false; io.current?.dispose(); initial.current.cancel(); window.clearInterval(timer); };
    }, [group.id]);
    const loadChoices = async () => {
        if (busy.current || !view || !keys.length || keys.length > 25 || phase !== 'members' || !resource.admin) return;
        busy.current = true; setPending(true); const current = ++run.current, channel = io.current!, chosen = [...keys]; setPhase('choices');
        try {
            const next: Draft[] = [];
            for (const key of chosen) {
                if (!channel.active()) throw new Error('Inactive');
                const mono = performance.now(), wall = Date.now(), choice = await channel.choice(key), original = view.members.find(m => m.key === key);
                if (!channel.active() || !original || original.deviceId !== choice.member.deviceId || original.name !== choice.member.name || !sameGroupCompleteServicePolicy(original.policy, choice.member.policy)) throw new Error('Service member changed');
                next.push({ choice, desired: { enabled: false, services: [...choice.member.policy.services], source: null }, evidence: null, mono, wall, renew: false });
            }
            if (alive.current && current === run.current) { setDrafts(next); setPhase('draft'); }
        } catch { if (alive.current && current === run.current) setPhase(previous => previous === 'stopped' ? previous : 'failed'); }
        finally { finish(current); }
    };
    const prepare = async () => {
        if (busy.current || !view || phase !== 'draft' || !drafts.length || !resource.admin || drafts.some(d => !allowed(d))) return;
        busy.current = true; setPending(true); const current = ++run.current; setPhase('reviewing'); setConsent(false);
        try { const next = await reviewGroupCompleteServiceChecks(view, drafts, io.current!); if (alive.current && current === run.current) { setReview(next); setDrafts([]); setPhase('reviewed'); } }
        catch { if (alive.current && current === run.current) setPhase(previous => previous === 'stopped' ? previous : 'failed'); }
        finally { finish(current); }
    };
    const apply = async () => {
        if (busy.current || !review || !consent || phase !== 'reviewed' || !resource.admin) return;
        busy.current = true; setPending(true); const current = ++run.current; setConsent(false); setPhase('applying');
        try { await applyGroupCompleteServiceChecks(review, io.current!, rows => { if (alive.current && current === run.current) setResults(rows); }); if (alive.current && current === run.current) setPhase(previous => previous === 'stopped' ? previous : 'done'); }
        catch { if (alive.current && current === run.current) setPhase(previous => previous === 'stopped' ? previous : 'failed'); }
        finally { finish(current); }
    };
    const stop = () => { stopped.current = true; io.current?.cancel(); resource.cancel(); setConsent(false); setDrafts([]); setPhase('stopped'); };
    const allowed = (d: Draft) => groupCompleteServiceSettingAllowed(d.choice, d.desired, age(d)) && groupCompleteServiceEvidenceAllowed(d.choice, d.desired, d.evidence);
    const sourceFor = (d: Draft, desired: GroupCompleteServiceSetting, evidence: CompleteServiceSelectionEvidence | null) => {
        const needs = desired.enabled && !d.choice.member.policy.enabled || desired.services.some(name => !d.choice.member.policy.services.includes(name));
        return needs || d.renew && desired.enabled && !!evidence && !sourceBindingMatches(d.choice.member.policy.source, evidence.source) ? evidence?.source ?? null : null;
    };
    const evidence = (key: string, value: CompleteServiceSelectionEvidence | null) => setDrafts(previous => previous.map(d => {
        if (d.choice.member.key !== key || sameWindowsServiceHealthSource(d.evidence?.source ?? null, value?.source ?? null) && JSON.stringify(d.evidence?.names) === JSON.stringify(value?.names)) return d;
        const next = { ...d, renew: d.renew && sameWindowsServiceHealthSource(d.evidence?.source ?? null, value?.source ?? null) };
        return { ...next, evidence: value, desired: { ...d.desired, source: sourceFor(next, d.desired, value) } };
    }));
    const edit = (key: string, patch: Partial<GroupCompleteServiceSetting>) => setDrafts(previous => previous.map(d => {
        if (d.choice.member.key !== key) return d;
        // Renewal is deliberate for exactly this enabled selection. Editing names
        // or disabling clears it; ordinary removal/disable keeps source:null.
        const next = { ...d, renew: d.renew && patch.services === undefined && patch.enabled !== false }, desired = { ...d.desired, ...patch };
        return { ...next, desired: { ...desired, source: sourceFor(next, desired, d.evidence) } };
    }));
    const renew = (key: string, checked: boolean) => setDrafts(previous => previous.map(d => {
        if (d.choice.member.key !== key || checked && (!d.desired.enabled || !d.evidence || !d.desired.services.length || d.desired.services.some(name => !d.evidence!.names.includes(name)) || sourceBindingMatches(d.choice.member.policy.source, d.evidence.source) || !sameWindowsServiceHealthSource(d.choice.member.inventory?.source ?? null, d.evidence.source))) return d;
        const next = { ...d, renew: checked };
        return { ...next, desired: { ...d.desired, source: sourceFor(next, d.desired, d.evidence) } };
    }));
    const rows = results ?? review?.members;
    const policy = (value: Pick<GroupCompleteServiceSetting, 'enabled' | 'services'>) => <><span>{value.enabled ? c.on : c.off}</span>{value.services.length ? <ul className="fleet-service-names">{value.services.map(name => <li key={name}><code>{name}</code></li>)}</ul> : <small>{c.none}</small>}</>;
    return <Dialog title={c.title} onClose={onClose} className="fleet-group-dialog"><h2>{c.title}</h2><p><strong>{group.name}</strong> · {c.groupRevision}: {review?.groupRevision ?? view?.groupRevision ?? group.revision}</p><p>{c.summary}</p><p>{c.legacy}</p>
        {view && <p className="fleet-monitoring-counts">{c.selected}: {rows?.length ?? keys.length}/25 · {c.linux}: {view.excludedLinuxMembers} · {c.unavailable}: {view.unavailableMembers}</p>}
        {['loading', 'choices'].includes(phase) && <p role="status">{c.loading}</p>}{phase === 'reviewing' && <p role="status">{c.reviewing}</p>}{phase === 'failed' && <p role="alert">{c.failed}</p>}
        {phase === 'members' && view && <fieldset className="fleet-group-choices"><legend>{c.devices}</legend>{view.members.map(member => <label key={member.key}><input type="checkbox" aria-label={`${member.name} ${member.deviceId}`} checked={keys.includes(member.key)} disabled={!keys.includes(member.key) && keys.length >= 25} onChange={e => setKeys(previous => e.target.checked ? [...previous, member.key] : previous.filter(key => key !== member.key))}/><span><strong>{member.name}</strong><small>{member.deviceId}</small></span></label>)}{!view.members.length && <p>{c.empty}</p>}</fieldset>}
        {phase === 'draft' && <><h3>{c.choices}</h3><p>{c.preview}</p><p>{c.retained}</p>{drafts.map((draft, index) => {
            const member = draft.choice.member, source = draft.evidence?.source;
            return <details className="fleet-service-device" key={member.key} open={index === 0 ? true : undefined}><summary><strong>{member.name}</strong> · {draft.desired.services.length}/8 · {draft.desired.enabled ? c.on : c.off}</summary><p>{member.deviceId}</p><p>{c.before}: {member.policy.enabled ? c.on : c.off} · {c.revision}: {member.policy.revision}</p>
                <label className="fleet-group-enable"><input type="checkbox" aria-label={`${c.enable} · ${member.name}`} checked={draft.desired.enabled} disabled={!member.policy.enabled && !draft.evidence?.names.length} onChange={e => edit(member.key, { enabled: e.target.checked })}/>{c.enable}</label>
                {source && member.policy.source && !sourceBindingMatches(member.policy.source, source) && <label className="fleet-group-enable"><input type="checkbox" aria-label={`${completeServicePickerCopy[locale].renew} · ${member.name}`} checked={draft.renew} disabled={pending || !draft.desired.enabled || !draft.desired.services.length || !sameWindowsServiceHealthSource(member.inventory?.source ?? null, source) || draft.desired.services.some(name => !draft.evidence?.names.includes(name))} onChange={event => renew(member.key, event.target.checked)}/>{completeServicePickerCopy[locale].renew}</label>}
                {!source && <p role="status">{c.unknown}</p>}
                {source && !sameWindowsServiceHealthSource(member.inventory?.source ?? null, source) && <p role="status">{locale === 'de' ? 'Die Generation wurde während dieser Gruppenauswahl geändert. Beginne eine neue Prüfung.' : 'The generation changed during this group selection. Start a fresh review.'}</p>}
                {source && <details className="fleet-service-source"><summary>{locale === 'de' ? 'Erfasste Dienste dieser Generation' : 'Captured services in this generation'} · {source.rowCount}</summary><p>{picker.collected}: <WindowsLocalTime value={source.capturedAt} locale={locale} exact/></p><p>{picker.received}: <WindowsLocalTime value={source.receivedAt} locale={locale} exact/></p><p>{picker.sequence}: {source.sequence}</p><code>{source.generationId}</code><small>{source.grantId} · {source.grantRevision}</small>{draft.desired.source && member.policy.source && !sourceBindingMatches(member.policy.source, source) && <p>{locale === 'de' ? 'Geänderte lokale Freigabe. Alle gewählten Dienste müssen erneut aus dieser Generation gewählt werden.' : 'Local grant changed. Every selected service needs fresh evidence from this generation.'}</p>}</details>}
                <WindowsServiceHealthCompletePicker deviceId={member.deviceId} sessionKey={resource.sessionKey} enabled={phase === 'draft'} disabled={pending} selected={draft.desired.services} c={picker} onEvidence={value => evidence(member.key, value)} onChange={services => edit(member.key, { services: [...services].sort(compareWindowsServiceNames) })}/>

            </details>;
        })}</>}
        {rows && <><p>{c.safety}</p><div className="fleet-group-table-wrap"><table className="fleet-group-table" role="table"><caption>{results ? c.results : c.review}</caption><thead role="rowgroup"><tr role="row"><th role="columnheader" scope="col">{c.device}</th><th role="columnheader" scope="col">{c.before}</th><th role="columnheader" scope="col">{c.desired}</th>{results && <th role="columnheader" scope="col">{c.outcome}</th>}</tr></thead><tbody role="rowgroup">{rows.map(row => <tr key={row.key} role="row"><td role="cell"><strong>{row.name}</strong><code>{row.deviceId}</code></td><td role="cell" data-label={c.before}>{policy(row.policy)}<small>{c.revision}: {row.policy.revision}</small></td><td role="cell" data-label={c.desired}>{policy(row.desired)}{row.desired.source && <small>{row.desired.source.kind} · {row.desired.source.grantId} · {row.desired.source.grantRevision}<code>{row.desired.source.generationId}</code></small>}</td>{results && <td role="cell" data-label={c.outcome}>{c[(row as GroupCompleteServiceResult).status]}{(row as GroupCompleteServiceResult).matchingAfterUnconfirmed && <small>{c.matching}</small>}</td>}</tr>)}</tbody></table></div></>}
        {phase === 'reviewed' && <label className="fleet-group-enable"><input type="checkbox" checked={consent} onChange={e => setConsent(e.target.checked)}/>{c.consent}</label>}
        <details className="fleet-group-limits"><summary>{c.details}</summary><p>{c.scope}</p><p>{c.snapshot}</p><p>{c.lease}</p><p>{picker.rules}</p><p>{picker.limits}</p>{review && <ul className="fleet-group-members">{review.members.map(m => <li key={m.key}><strong>{m.name}</strong><code>{m.deviceId}</code><small>{c.key}</small><code>{m.key}</code></li>)}</ul>}</details>
        {phase === 'applying' && <p role="status">{c.applying}</p>}{phase === 'stopped' && <p role="status">{c.stopped}</p>}{phase === 'done' && <p role="status">{c.completed}</p>}
        <div className="fleet-group-actions">{phase === 'members' && <button className="button" disabled={!keys.length || !resource.admin} onClick={() => void loadChoices()}>{c.load}</button>}{phase === 'draft' && <button className="button" disabled={!drafts.length || drafts.some(d => !allowed(d))} onClick={() => void prepare()}>{c.review}</button>}{phase === 'reviewed' && <button className="button" disabled={!consent} onClick={() => void apply()}>{c.apply}</button>}{['choices', 'reviewing', 'applying'].includes(phase) && <button className="button" onClick={stop}>{c.stop}</button>}{['draft', 'done', 'stopped', 'failed', 'reviewed'].includes(phase) && <button className="text-button" disabled={pending} onClick={() => void load()}>{c.fresh}</button>}<button className="text-button" onClick={onClose}>{c.close}</button></div>
    </Dialog>;
}
