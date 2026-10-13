import { useEffect, useRef, useState } from 'react';
import { Dialog } from './components';
import type { FleetGroupsResource } from './fleet-groups';
import type { FleetGroup } from './fleet-groups-types';
import { useLocale } from './i18n';
import { applyGroupMaintenanceEnd, reviewGroupMaintenanceEnd } from './fleet-group-maintenance-end-workflow';
import type { GroupMaintenanceEndResult, GroupMaintenanceEndReview } from './fleet-group-maintenance-end-workflow';
import type { GroupMaintenanceView } from './fleet-group-maintenance-workflow';
import { windowsMaintenanceState } from './windows-maintenance-types';
import { WindowsLocalTime } from './windows-local-time';

const copy = {
    en: {
        title: 'End group maintenance', summary: 'Select active windows to end early. Each original end stays in history; checks and incidents continue unchanged.',
        windows: 'Exact active windows', selected: 'Selected windows', linux: 'Excluded Linux members', unavailable: 'Unavailable members', empty: 'No active windows for currently admitted Windows members.',
        all: 'All Windows checks', contact: 'Contact', cpu: 'CPU percentage', disk: 'System-volume capacity', memory: 'Physical RAM percentage', service: 'Selected-service checks',
        review: 'Review early ends', reviewing: 'Checking exact active windows…', apply: 'End reviewed windows', consent: 'End only these exact active windows now. Keep each original end in history.',
        originalEnd: 'Original end', groupRevision: 'Group revision', revision: 'Maintenance revision', window: 'Window ID', details: 'Exact identities, windows and boundaries', key: 'Target key', device: 'Device / exact ID', scope: 'Scope', outcome: 'Outcome', results: 'Per-window maintenance results',
        stop: 'Stop remaining ends', stopped: 'Stopped. Earlier outcomes are retained. An interrupted end may already have reached the manager.', applying: 'Ending sequentially…', fresh: 'Start fresh review', close: 'Close maintenance', failed: 'The review changed or expired. Refresh and review again.', loading: 'Loading group maintenance…',
        safety: 'Stops on conflict, lost access or uncertainty. No rollback or automatic retry.', snapshot: 'Only the selected original identities, window IDs and revisions are eligible. Each end rechecks the group revision and original membership. Newer or replacement windows are never substituted.', notifications: 'Matching notifications can resume for new transitions. Early end sends no backlog and cannot recall in-flight delivery. No host actions or policy changes.',
        ended: 'Ended · confirmed response', conflict: 'Blocked / conflict · check whether the end happened', unconfirmed: 'Unconfirmed · end may have happened', 'not-attempted': 'Not attempted', matching: 'Current state matches; this does not prove this attempt ended it.', completed: 'This review has been used. Any further end needs a fresh review.',
    },
    de: {
        title: 'Gruppenwartung beenden', summary: 'Aktive Fenster zum vorzeitigen Beenden wählen. Jedes ursprüngliche Ende bleibt im Verlauf; Prüfungen und Vorfälle laufen unverändert weiter.',
        windows: 'Exakte aktive Fenster', selected: 'Gewählte Fenster', linux: 'Ausgeschlossene Linux-Mitglieder', unavailable: 'Nicht verfügbare Mitglieder', empty: 'Keine aktiven Fenster für aktuell zugelassene Windows-Mitglieder.',
        all: 'Alle Windows-Prüfungen', contact: 'Kontakt', cpu: 'CPU-Prozentwert', disk: 'Kapazität des Systemvolumes', memory: 'Physischer RAM-Prozentwert', service: 'Prüfungen ausgewählter Dienste',
        review: 'Vorzeitige Enden prüfen', reviewing: 'Exakte aktive Fenster werden geprüft …', apply: 'Geprüfte Fenster beenden', consent: 'Nur diese exakten aktiven Fenster jetzt beenden. Jedes ursprüngliche Ende bleibt im Verlauf.',
        originalEnd: 'Ursprüngliches Ende', groupRevision: 'Gruppenversion', revision: 'Wartungsversion', window: 'Fenster-ID', details: 'Exakte Identitäten, Fenster und Grenzen', key: 'Zielschlüssel', device: 'Gerät / exakte ID', scope: 'Umfang', outcome: 'Ergebnis', results: 'Wartungsergebnisse je Fenster',
        stop: 'Weitere Enden stoppen', stopped: 'Gestoppt. Bisherige Ergebnisse bleiben erhalten. Ein unterbrochenes Ende kann den Manager bereits erreicht haben.', applying: 'Wird nacheinander beendet …', fresh: 'Neu prüfen', close: 'Wartung schließen', failed: 'Die Prüfung hat sich geändert oder ist abgelaufen. Aktualisieren und erneut prüfen.', loading: 'Gruppenwartung wird geladen …',
        safety: 'Stopp bei Konflikt, Zugriffsverlust oder Unklarheit. Kein Rollback und keine automatische Wiederholung.', snapshot: 'Nur die gewählten ursprünglichen Identitäten, Fenster-IDs und Versionen sind zulässig. Jedes Ende prüft Gruppenversion und ursprüngliche Mitgliedschaft erneut. Neuere Fenster oder Ersatzidentitäten werden nie eingesetzt.', notifications: 'Passende Benachrichtigungen können für neue Übergänge wieder erfolgen. Ein vorzeitiges Ende sendet keinen Rückstau und ruft keine laufenden Zustellungen zurück. Keine Geräteaktionen oder Richtlinienänderungen.',
        ended: 'Beendet · bestätigte Antwort', conflict: 'Gesperrt / Konflikt · mögliches Ende prüfen', unconfirmed: 'Unbestätigt · Ende eventuell erfolgt', 'not-attempted': 'Nicht versucht', matching: 'Der aktuelle Stand entspricht der Auswahl; das beweist kein erfolgreiches Ende durch diesen Versuch.', completed: 'Diese Prüfung wurde verwendet. Jedes weitere Ende erfordert eine neue Prüfung.',
    },
};

export function GroupMaintenanceEnd({ resource, group, onClose }: { resource: FleetGroupsResource; group: FleetGroup; onClose: () => void }) {
    const [locale] = useLocale(), c = copy[locale];
    const [view, setView] = useState<GroupMaintenanceView | null>(null), [keys, setKeys] = useState<string[]>([]), [consent, setConsent] = useState(false);
    const [review, setReview] = useState<GroupMaintenanceEndReview | null>(null), [results, setResults] = useState<GroupMaintenanceEndResult[] | null>(null);
    const [phase, setPhase] = useState<'loading' | 'draft' | 'reviewing' | 'reviewed' | 'applying' | 'done' | 'stopped' | 'failed'>('loading'), [pending, setPending] = useState(false);
    const alive = useRef(true), run = useRef(0), busy = useRef(false), initial = useRef(resource);
    const load = async () => {
        if (busy.current) return;
        busy.current = true; setPending(true); const current = ++run.current;
        setView(null); setReview(null); setResults(null); setKeys([]); setConsent(false); setPhase('loading');
        try { const value = await initial.current.maintenanceIO(group.id, true).get(); if (alive.current && current === run.current) { setView(value); setPhase('draft'); } }
        catch { if (alive.current && current === run.current) setPhase(previous => previous === 'stopped' ? previous : 'failed'); }
        finally { if (current === run.current) { busy.current = false; if (alive.current) setPending(false); } }
    };
    useEffect(() => { alive.current = true; void load(); return () => { alive.current = false; run.current++; busy.current = false; initial.current.cancel(); }; }, [group.id]);
    const prepare = async () => {
        if (busy.current || !view || !keys.length || !resource.admin || phase !== 'draft') return;
        busy.current = true; setPending(true); const current = ++run.current; setPhase('reviewing'); setConsent(false);
        try {
            const next = await resource.maintenanceIO(group.id).get();
            const frozen = reviewGroupMaintenanceEnd(view, next, [...keys], 0);
            if (alive.current && current === run.current) { setReview(frozen); setPhase('reviewed'); }
        } catch { if (alive.current && current === run.current) setPhase(previous => previous === 'stopped' ? previous : 'failed'); }
        finally { if (current === run.current) { busy.current = false; if (alive.current) setPending(false); } }
    };
    const apply = async () => {
        if (busy.current || !review || !consent || phase !== 'reviewed' || !resource.admin) return;
        busy.current = true; setPending(true); const current = ++run.current; setPhase('applying'); setConsent(false);
        try { await applyGroupMaintenanceEnd(review, resource.maintenanceIO(group.id), rows => { if (alive.current && current === run.current) setResults(rows); }); if (alive.current && current === run.current) setPhase(previous => previous === 'stopped' ? previous : 'done'); }
        catch { if (alive.current && current === run.current) setPhase(previous => previous === 'stopped' ? previous : 'failed'); }
        finally { if (current === run.current) { busy.current = false; if (alive.current) setPending(false); } }
    };
    const stop = () => { resource.cancel(); setConsent(false); setPhase('stopped'); };
    const choices = view?.members.flatMap(member => member.targets.filter(target => target.windows[0] && windowsMaintenanceState(target.windows[0], view.serverNow, 0) === 'active').map(target => ({ deviceId: member.deviceId, name: member.name, target }))) ?? [];
    const rows = results ?? review?.members;
    return <Dialog title={c.title} onClose={onClose} className="fleet-group-dialog">
        <h2>{c.title}</h2><p><strong>{group.name}</strong> · {c.groupRevision}: {review?.groupRevision ?? view?.groupRevision ?? group.revision}</p><p>{c.summary}</p>
        {view && <p className="fleet-monitoring-counts">{c.selected}: {rows?.length ?? keys.length}/25 · {c.linux}: {view.excludedLinuxMembers} · {c.unavailable}: {view.unavailableMembers}</p>}
        {phase === 'loading' && <p role="status">{c.loading}</p>}{phase === 'reviewing' && <p role="status">{c.reviewing}</p>}{phase === 'failed' && <p role="alert">{c.failed}</p>}
        {phase === 'draft' && view && <fieldset className="fleet-group-choices"><legend>{c.windows}</legend>
            {choices.map(row => <label key={row.target.key}><input type="checkbox" aria-label={`${row.name} ${row.deviceId} ${c[row.target.domain]} ${row.target.windows[0].id}`} checked={keys.includes(row.target.key)} disabled={row.target.revision >= Number.MAX_SAFE_INTEGER || !keys.includes(row.target.key) && keys.length >= 25} onChange={event => setKeys(previous => event.target.checked ? [...previous, row.target.key] : previous.filter(key => key !== row.target.key))}/><span><strong>{row.name} · {c[row.target.domain]}</strong><small>{row.deviceId}</small><small>{c.originalEnd}: <WindowsLocalTime value={row.target.windows[0].endsAt} locale={locale}/></small><small>{c.window}: {row.target.windows[0].id} · {c.revision}: {row.target.revision}</small></span></label>)}
            {!choices.length && <p>{c.empty}</p>}
        </fieldset>}
        {review && <><p>{c.safety}</p><div className="fleet-group-table-wrap"><table className="fleet-group-table" role="table">
            <caption>{results ? c.results : c.review}</caption><thead role="rowgroup"><tr role="row"><th scope="col" role="columnheader">{c.device}</th><th scope="col" role="columnheader">{c.scope}</th><th scope="col" role="columnheader">{c.originalEnd}</th><th scope="col" role="columnheader">{c.revision}</th>{results && <th scope="col" role="columnheader">{c.outcome}</th>}</tr></thead>
            <tbody role="rowgroup">{rows?.map(row => <tr key={row.target.key} role="row"><td role="cell"><strong>{row.name}</strong><code>{row.deviceId}</code></td><td role="cell" data-label={c.scope}>{c[row.target.domain]}<small>{c.window}: {row.target.windows[0].id}</small></td><td role="cell" data-label={c.originalEnd}><WindowsLocalTime value={row.target.windows[0].endsAt} locale={locale}/></td><td role="cell" data-label={c.revision}>{row.target.revision}</td>{results && <td role="cell" data-label={c.outcome}>{c[(row as GroupMaintenanceEndResult).status]}{(row as GroupMaintenanceEndResult).matchingAfterUnconfirmed && <small>{c.matching}</small>}</td>}</tr>)}</tbody>
        </table></div>{phase === 'reviewed' && <label className="fleet-group-enable"><input type="checkbox" checked={consent} onChange={event => setConsent(event.target.checked)}/>{c.consent}</label>}</>}
        <details className="fleet-group-limits"><summary>{c.details}</summary><p>{c.snapshot}</p><p>{c.notifications}</p>{review && <ul className="fleet-group-members">{review.members.map(member => <li key={member.target.key}><strong>{member.name}</strong><code>{member.deviceId}</code><small>{c.key}</small><code>{member.target.key}</code><small>{c.window}: {member.target.windows[0].id} · {c.revision}: {member.target.revision}</small><small>{c.originalEnd} (UTC): <WindowsLocalTime value={member.target.windows[0].endsAt} locale={locale} exact/></small></li>)}</ul>}</details>
        {phase === 'applying' && <p role="status">{c.applying}</p>}{phase === 'stopped' && <p role="status">{c.stopped}</p>}{phase === 'done' && <p role="status">{c.completed}</p>}
        <div className="fleet-group-actions">{phase === 'draft' && <button className="button" disabled={!keys.length || !resource.admin} onClick={() => void prepare()}>{c.review}</button>}{phase === 'reviewed' && <button className="button" disabled={!consent} onClick={() => void apply()}>{c.apply}</button>}{['reviewing', 'applying'].includes(phase) && <button className="button" onClick={stop}>{c.stop}</button>}{['done', 'stopped', 'failed', 'reviewed'].includes(phase) && <button className="text-button" disabled={pending} onClick={() => void load()}>{c.fresh}</button>}<button className="text-button" onClick={onClose}>{c.close}</button></div>
    </Dialog>;
}
