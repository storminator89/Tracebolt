import { useEffect, useRef, useState } from 'react';
import { Dialog } from './components';
import type { FleetGroupsResource } from './fleet-groups';
import type { FleetGroup } from './fleet-groups-types';
import { useLocale } from './i18n';
import { WindowsServiceHealthPicker } from './windows-service-health-picker';
import { windowsServiceHealthCopy } from './windows-service-health-copy';
import { WindowsLocalTime } from './windows-local-time';
import { compareWindowsServiceNames } from './windows-service-health-types';
import { applyGroupServiceChecks, groupServiceChoices, groupServiceSettingAllowed, reviewGroupServiceChecks, sameGroupServicePolicy } from './fleet-group-service-checks-workflow';
import type { GroupServiceChecksView, GroupServiceDraft, GroupServiceResult, GroupServiceReview, GroupServiceSetting } from './fleet-group-service-checks-workflow';
import './windows-service-health.css';

const copy = {
    en: {
        preview: 'Existing bounded preview: up to 128 caller-visible service rows per device. Missing or out-of-preview services stay unknown and are never assumed healthy.', title: 'Apply service checks', summary: 'Choose exact Windows members, select services for each, then review once.', groupRevision: 'Group revision', selected: 'Selected devices', linux: 'Excluded Linux members', unavailable: 'Unavailable members', devices: 'Select Windows members', empty: 'No available Windows members.', loading: 'Reading current service policies…', load: 'Load selected service choices', choices: 'Choose services for each device', enable: 'Enable service checks', before: 'Previous policy', desired: 'Desired policy', revision: 'Policy revision', on: 'Enabled', off: 'Disabled', none: 'No services', unknown: 'Current service inventory is unknown. Retained names can still be removed or disabled.', retained: 'Existing names are retained for review. Enable starts unchecked for each device.', review: 'Review exact service checks', reviewing: 'Verifying selected members and policies…', consent: 'Apply these exact service-check policies to these selected members once.', apply: 'Apply reviewed service checks', applying: 'Applying service checks sequentially…', stop: 'Stop remaining writes', stopped: 'Stopped. Earlier outcomes are retained. An interrupted write may already have reached the manager.', fresh: 'Start fresh review', failed: 'The selection changed, expired or could not be verified. Start a fresh review.', completed: 'This review is used. Every further change needs a fresh review.', results: 'Per-device service-check results', device: 'Device', outcome: 'Outcome', details: 'Scope and exact review details', scope: 'Changes only manager service-check policies using existing consented inventory. No host collection, service action, AI or notification is authorized.', snapshot: 'Only selected original identities are included. No inheritance, new-member adoption, background job, rollback or automatic retry.', safety: 'Stops on conflict or uncertainty. Matching readback cannot prove which attempt wrote the policy.', lease: 'Close, navigation, blur, access loss or the original authority deadline clears this private review.', key: 'Original-identity target', close: 'Cancel', changed: 'Changed · confirmed response', 'currently-matching': 'Currently matching · no write', conflict: 'Conflict · review again', unconfirmed: 'Unconfirmed · write may have happened', 'not-attempted': 'Not attempted', matching: 'Current policy matches. Our write remains unconfirmed.',
    },
    de: {
        preview: 'Vorhandene begrenzte Vorschau: bis zu 128 für den Aufrufer sichtbare Dienstzeilen je Gerät. Fehlende Dienste oder Dienste außerhalb der Vorschau bleiben unbekannt und gelten nie als gesund.', title: 'Dienstprüfungen anwenden', summary: 'Exakte Windows-Mitglieder und Dienste je Gerät auswählen, dann einmal gemeinsam prüfen.', groupRevision: 'Gruppenversion', selected: 'Gewählte Geräte', linux: 'Ausgeschlossene Linux-Mitglieder', unavailable: 'Nicht verfügbare Mitglieder', devices: 'Windows-Mitglieder wählen', empty: 'Keine verfügbaren Windows-Mitglieder.', loading: 'Aktuelle Dienstrichtlinien werden gelesen …', load: 'Dienstoptionen der Auswahl laden', choices: 'Dienste je Gerät auswählen', enable: 'Dienstprüfungen aktivieren', before: 'Bisherige Richtlinie', desired: 'Gewünschte Richtlinie', revision: 'Richtlinienversion', on: 'Aktiviert', off: 'Deaktiviert', none: 'Keine Dienste', unknown: 'Das aktuelle Dienstinventar ist unbekannt. Gespeicherte Namen können weiterhin entfernt oder deaktiviert werden.', retained: 'Bestehende Namen bleiben zur Prüfung erhalten. Aktivieren ist je Gerät zunächst nicht angehakt.', review: 'Exakte Dienstprüfungen prüfen', reviewing: 'Gewählte Mitglieder und Richtlinien werden geprüft …', consent: 'Diese exakten Dienstprüfungsrichtlinien einmal auf diese gewählten Mitglieder anwenden.', apply: 'Geprüfte Dienstprüfungen anwenden', applying: 'Dienstprüfungen werden nacheinander angewendet …', stop: 'Weitere Schreibvorgänge stoppen', stopped: 'Gestoppt. Frühere Ergebnisse bleiben erhalten. Ein unterbrochener Schreibvorgang kann den Manager bereits erreicht haben.', fresh: 'Neu prüfen', failed: 'Die Auswahl wurde geändert, ist abgelaufen oder konnte nicht bestätigt werden. Beginne eine neue Prüfung.', completed: 'Diese Prüfung wurde verwendet. Jede weitere Änderung benötigt eine neue Prüfung.', results: 'Dienstprüfungsergebnisse je Gerät', device: 'Gerät', outcome: 'Ergebnis', details: 'Umfang und exakte Prüfdetails', scope: 'Ändert nur Manager-Richtlinien für Dienstprüfungen mit bereits freigegebenem Inventar. Keine Erfassung, Dienstaktion, KI oder Benachrichtigung wird freigegeben.', snapshot: 'Nur gewählte ursprüngliche Identitäten sind enthalten. Keine Vererbung, Übernahme neuer Mitglieder, Hintergrundaufgabe, Rücknahme oder automatische Wiederholung.', safety: 'Stopp bei Konflikt oder unklarem Ergebnis. Passendes Zurücklesen beweist nicht, welcher Versuch die Richtlinie geschrieben hat.', lease: 'Schließen, Navigation, Fokusverlust, Zugriffsverlust oder die ursprüngliche Ablaufzeit löschen diese private Prüfung.', key: 'Ziel der ursprünglichen Identität', close: 'Abbrechen', changed: 'Geändert · bestätigte Antwort', 'currently-matching': 'Entspricht bereits · nicht geschrieben', conflict: 'Konflikt · erneut prüfen', unconfirmed: 'Unbestätigt · Änderung eventuell erfolgt', 'not-attempted': 'Nicht versucht', matching: 'Die aktuelle Richtlinie entspricht der Auswahl. Unser Schreibvorgang bleibt unbestätigt.',
    },
};
type Draft = GroupServiceDraft & { mono: number; wall: number };
const age = (draft: Draft) => {
    const mono = performance.now() - draft.mono, wall = Date.now() - draft.wall;
    return Number.isFinite(mono) && mono >= 0 && Number.isFinite(wall) && Math.abs(wall - mono) <= 1500 ? mono : Infinity;
};
export function GroupServiceChecks({ resource, group, onClose }: { resource: FleetGroupsResource; group: FleetGroup; onClose: () => void }) {
    const [locale] = useLocale(), c = copy[locale], picker = windowsServiceHealthCopy[locale];
    const [view, setView] = useState<GroupServiceChecksView | null>(null), [keys, setKeys] = useState<string[]>([]), [drafts, setDrafts] = useState<Draft[]>([]), [consent, setConsent] = useState(false);
    const [review, setReview] = useState<GroupServiceReview | null>(null), [results, setResults] = useState<GroupServiceResult[] | null>(null), [pending, setPending] = useState(false), [, tick] = useState(0);
    const [phase, setPhase] = useState<'loading' | 'members' | 'choices' | 'draft' | 'reviewing' | 'reviewed' | 'applying' | 'done' | 'stopped' | 'failed'>('loading');
    const alive = useRef(true), run = useRef(0), busy = useRef(false), initial = useRef(resource);
    const finish = (current: number) => { if (current === run.current) { busy.current = false; if (alive.current) setPending(false); } };
    const load = async () => {
        if (busy.current) return;
        busy.current = true; setPending(true); const current = ++run.current;
        setView(null); setKeys([]); setDrafts([]); setReview(null); setResults(null); setConsent(false); setPhase('loading');
        try { const value = await initial.current.serviceChecksIO(group.id, true).get(); if (alive.current && current === run.current) { setView(value); setPhase('members'); } }
        catch { if (alive.current && current === run.current) setPhase(previous => previous === 'stopped' ? previous : 'failed'); }
        finally { finish(current); }
    };
    useEffect(() => {
        alive.current = true; void load(); const timer = window.setInterval(() => tick(n => n + 1), 1000);
        return () => { alive.current = false; run.current++; busy.current = false; initial.current.cancel(); window.clearInterval(timer); };
    }, [group.id]);
    const loadChoices = async () => {
        if (busy.current || !view || !keys.length || keys.length > 25 || phase !== 'members' || !resource.admin) return;
        busy.current = true; setPending(true); const current = ++run.current, io = resource.serviceChecksIO(group.id), chosen = [...keys]; setPhase('choices');
        try {
            const next: Draft[] = [];
            for (const key of chosen) {
                if (!io.active()) throw new Error('Inactive');
                const mono = performance.now(), wall = Date.now(), choice = await io.choice(key), original = view.members.find(m => m.key === key);
                if (!io.active() || !original || original.deviceId !== choice.member.deviceId || original.name !== choice.member.name || !sameGroupServicePolicy(original.policy, choice.member.policy)) throw new Error('Service member changed');
                next.push({ choice, desired: { enabled: false, services: [...choice.member.policy.services] }, mono, wall });
            }
            if (alive.current && current === run.current) { setDrafts(next); setPhase('draft'); }
        } catch { if (alive.current && current === run.current) setPhase(previous => previous === 'stopped' ? previous : 'failed'); }
        finally { finish(current); }
    };
    const prepare = async () => {
        if (busy.current || !view || phase !== 'draft' || !drafts.length || !resource.admin || drafts.some(d => !groupServiceSettingAllowed(d.choice, d.desired, age(d)))) return;
        busy.current = true; setPending(true); const current = ++run.current; setPhase('reviewing'); setConsent(false);
        try { const next = await reviewGroupServiceChecks(view, drafts, resource.serviceChecksIO(group.id)); if (alive.current && current === run.current) { setReview(next); setDrafts([]); setPhase('reviewed'); } }
        catch { if (alive.current && current === run.current) setPhase(previous => previous === 'stopped' ? previous : 'failed'); }
        finally { finish(current); }
    };
    const apply = async () => {
        if (busy.current || !review || !consent || phase !== 'reviewed' || !resource.admin) return;
        busy.current = true; setPending(true); const current = ++run.current; setConsent(false); setPhase('applying');
        try { await applyGroupServiceChecks(review, resource.serviceChecksIO(group.id), rows => { if (alive.current && current === run.current) setResults(rows); }); if (alive.current && current === run.current) setPhase(previous => previous === 'stopped' ? previous : 'done'); }
        catch { if (alive.current && current === run.current) setPhase(previous => previous === 'stopped' ? previous : 'failed'); }
        finally { finish(current); }
    };
    const stop = () => { resource.cancel(); setConsent(false); setDrafts([]); setPhase('stopped'); };
    const edit = (key: string, patch: Partial<GroupServiceSetting>) => setDrafts(previous => previous.map(d => d.choice.member.key === key ? { ...d, desired: { ...d.desired, ...patch } } : d));
    const rows = results ?? review?.members;
    const policy = (value: GroupServiceSetting) => <><span>{value.enabled ? c.on : c.off}</span>{value.services.length ? <ul className="fleet-service-names">{value.services.map(name => <li key={name}><code>{name}</code></li>)}</ul> : <small>{c.none}</small>}</>;
    return <Dialog title={c.title} onClose={onClose} className="fleet-group-dialog"><h2>{c.title}</h2><p><strong>{group.name}</strong> · {c.groupRevision}: {review?.groupRevision ?? view?.groupRevision ?? group.revision}</p><p>{c.summary}</p>
        {view && <p className="fleet-monitoring-counts">{c.selected}: {rows?.length ?? keys.length}/25 · {c.linux}: {view.excludedLinuxMembers} · {c.unavailable}: {view.unavailableMembers}</p>}
        {['loading', 'choices'].includes(phase) && <p role="status">{c.loading}</p>}{phase === 'reviewing' && <p role="status">{c.reviewing}</p>}{phase === 'failed' && <p role="alert">{c.failed}</p>}
        {phase === 'members' && view && <fieldset className="fleet-group-choices"><legend>{c.devices}</legend>{view.members.map(member => <label key={member.key}><input type="checkbox" aria-label={`${member.name} ${member.deviceId}`} checked={keys.includes(member.key)} disabled={!keys.includes(member.key) && keys.length >= 25} onChange={e => setKeys(previous => e.target.checked ? [...previous, member.key] : previous.filter(key => key !== member.key))}/><span><strong>{member.name}</strong><small>{member.deviceId}</small></span></label>)}{!view.members.length && <p>{c.empty}</p>}</fieldset>}
        {phase === 'draft' && <><h3>{c.choices}</h3><p>{c.preview}</p><p>{c.retained}</p>{drafts.map((draft, index) => {
            const member = draft.choice.member, choices = groupServiceChoices(draft.choice, age(draft));
            return <details className="fleet-service-device" key={member.key} open={index === 0 ? true : undefined}><summary><strong>{member.name}</strong> · {draft.desired.services.length}/8 · {draft.desired.enabled ? c.on : c.off}</summary><p>{member.deviceId}</p><p>{c.before}: {member.policy.enabled ? c.on : c.off} · {c.revision}: {member.policy.revision}</p>
                <label className="fleet-group-enable"><input type="checkbox" aria-label={`${c.enable} · ${member.name}`} checked={draft.desired.enabled} disabled={!member.policy.enabled && !choices.length} onChange={e => edit(member.key, { enabled: e.target.checked })}/>{c.enable}</label>
                {!choices.length && <p role="status">{c.unknown}</p>}
                {choices.length > 0 && member.inventory && <details className="fleet-service-source"><summary>{member.inventory.quality === 'partial' ? picker.partial : picker.reportedList} · {choices.length}</summary><p>{picker.collected}: <WindowsLocalTime value={member.inventory.collectedAt} locale={locale} exact/></p><p>{picker.received}: <WindowsLocalTime value={member.inventory.receivedAt} locale={locale} exact/></p><p>{picker.sequence}: {member.inventory.sequence}</p></details>}
                <WindowsServiceHealthPicker choices={choices} selected={draft.desired.services} disabled={false} c={picker} onChange={services => edit(member.key, { services: [...services].sort(compareWindowsServiceNames) })}/>
            </details>;
        })}</>}
        {rows && <><p>{c.safety}</p><div className="fleet-group-table-wrap"><table className="fleet-group-table" role="table"><caption>{results ? c.results : c.review}</caption><thead role="rowgroup"><tr role="row"><th role="columnheader" scope="col">{c.device}</th><th role="columnheader" scope="col">{c.before}</th><th role="columnheader" scope="col">{c.desired}</th>{results && <th role="columnheader" scope="col">{c.outcome}</th>}</tr></thead><tbody role="rowgroup">{rows.map(row => <tr key={row.key} role="row"><td role="cell"><strong>{row.name}</strong><code>{row.deviceId}</code></td><td role="cell" data-label={c.before}>{policy(row.policy)}<small>{c.revision}: {row.policy.revision}</small></td><td role="cell" data-label={c.desired}>{policy(row.desired)}</td>{results && <td role="cell" data-label={c.outcome}>{c[(row as GroupServiceResult).status]}{(row as GroupServiceResult).matchingAfterUnconfirmed && <small>{c.matching}</small>}</td>}</tr>)}</tbody></table></div></>}
        {phase === 'reviewed' && <label className="fleet-group-enable"><input type="checkbox" checked={consent} onChange={e => setConsent(e.target.checked)}/>{c.consent}</label>}
        <details className="fleet-group-limits"><summary>{c.details}</summary><p>{c.scope}</p><p>{c.snapshot}</p><p>{c.lease}</p><p>{picker.rules}</p><p>{picker.limits}</p>{review && <ul className="fleet-group-members">{review.members.map(m => <li key={m.key}><strong>{m.name}</strong><code>{m.deviceId}</code><small>{c.key}</small><code>{m.key}</code></li>)}</ul>}</details>
        {phase === 'applying' && <p role="status">{c.applying}</p>}{phase === 'stopped' && <p role="status">{c.stopped}</p>}{phase === 'done' && <p role="status">{c.completed}</p>}
        <div className="fleet-group-actions">{phase === 'members' && <button className="button" disabled={!keys.length || !resource.admin} onClick={() => void loadChoices()}>{c.load}</button>}{phase === 'draft' && <button className="button" disabled={!drafts.length || drafts.some(d => !groupServiceSettingAllowed(d.choice, d.desired, age(d)))} onClick={() => void prepare()}>{c.review}</button>}{phase === 'reviewed' && <button className="button" disabled={!consent} onClick={() => void apply()}>{c.apply}</button>}{['choices', 'reviewing', 'applying'].includes(phase) && <button className="button" onClick={stop}>{c.stop}</button>}{['draft', 'done', 'stopped', 'failed', 'reviewed'].includes(phase) && <button className="text-button" disabled={pending} onClick={() => void load()}>{c.fresh}</button>}<button className="text-button" onClick={onClose}>{c.close}</button></div>
    </Dialog>;
}
