import { useEffect, useId, useRef, useState } from 'react';
import { AUTH_REQUIRED_EVENT } from './api';
import type { useServiceActions } from './service-action-resource';
import type { ServiceActionPreview } from './service-action-types';
import { maxServiceSequenceSteps, sequenceBinding, sequencePreviewMatches, sequenceStepsMatch, type ServiceSequenceBinding, type ServiceSequenceStep } from './service-action-sequence-model';
import './service-action-sequence.css';

type Workflow = ReturnType<typeof useServiceActions>;
type Phase = 'editing' | 'binding' | 'ready' | 'preparing' | 'review' | 'waiting' | 'completed' | 'finished' | 'stopped';
type State = { scope: string; steps: ServiceSequenceStep[]; binding: ServiceSequenceBinding | null; phase: Phase; index: number; expected: string | null; reason: 'changed' | 'interrupted' | 'outcome' | 'manual'; receipts: { id: string; unit: string }[] };
const empty = (scope: string): State => ({ scope, steps: [], binding: null, phase: 'editing', index: 0, expected: null, reason: 'interrupted', receipts: [] });
const copy = {
    en: { title: 'Guided service sequence', scope: 'Keep up to eight permitted services in order for this view. Each step needs a fresh review and separate approval. Leaving this view, losing focus or reloading clears the sequence.', unit: 'Service for sequence', choose: 'Choose a permitted service', add: 'Add step', up: 'Move step up', remove: 'Remove step', save: 'Check and save sequence', saving: 'Checking the original action binding. No action is approved.', saved: 'Sequence saved for this view. No action is approved.', review: 'Review this step', next: 'Review next step', again: 'Start a new reviewed run', discard: 'Discard sequence', stop: 'Discarding this sequence does not cancel an approved action. Saved action history remains available.', pending: 'Waiting for this exact action result. No next step is requested automatically.', completed: 'This exact command completed. A restart and service health remain unconfirmed.', finished: 'All commands in this run reported completion. A new run needs new reviews and approvals.', stopped: 'Sequence stopped.', changed: 'The selected service, original authority or current action changed. Build and check a new sequence.', interrupted: 'The review was closed, expired or interrupted. No step will resume automatically.', outcome: 'The exact attempted action has no confirmed command-completion result. Check saved status and history; no action is retried.', manual: 'A separate manual selection detached this sequence. Its approval is independent.', step: 'Step', of: 'of', evidence: 'Command-completion references for this run', preparing: 'Preparing a fresh review for this step…' },
    de: { title: 'Geführte Dienstfolge', scope: 'Bis zu acht erlaubte Dienste in Reihenfolge für diese Ansicht vormerken. Jeder Schritt braucht eine neue Prüfung und separate Freigabe. Verlassen der Ansicht, Fokusverlust oder Neuladen löscht die Folge.', unit: 'Dienst für die Folge', choose: 'Erlaubten Dienst wählen', add: 'Schritt hinzufügen', up: 'Schritt nach oben', remove: 'Schritt entfernen', save: 'Folge prüfen und vormerken', saving: 'Ursprüngliche Aktionsbindung wird geprüft. Keine Aktion wird freigegeben.', saved: 'Folge für diese Ansicht vorgemerkt. Keine Aktion ist freigegeben.', review: 'Diesen Schritt prüfen', next: 'Nächsten Schritt prüfen', again: 'Neuen geprüften Durchlauf starten', discard: 'Folge verwerfen', stop: 'Verwerfen der Folge bricht keine freigegebene Aktion ab. Der gespeicherte Aktionsverlauf bleibt verfügbar.', pending: 'Warten auf genau dieses Aktionsergebnis. Kein nächster Schritt wird automatisch angefordert.', completed: 'Genau dieser Befehl wurde abgeschlossen. Neustart und Dienstzustand bleiben unbestätigt.', finished: 'Alle Befehle dieses Durchlaufs meldeten Abschluss. Ein neuer Durchlauf braucht neue Prüfungen und Freigaben.', stopped: 'Dienstfolge gestoppt.', changed: 'Dienst, ursprüngliche Berechtigung oder aktuelle Aktion haben sich geändert. Eine neue Folge zusammenstellen und prüfen.', interrupted: 'Die Prüfung wurde geschlossen, ist abgelaufen oder wurde unterbrochen. Kein Schritt wird automatisch fortgesetzt.', outcome: 'Für die exakte versuchte Aktion fehlt ein bestätigter Befehlsabschluss. Gespeicherten Status und Verlauf prüfen; keine Aktion wird wiederholt.', manual: 'Eine separate manuelle Auswahl hat diese Folge abgelöst. Ihre Freigabe ist unabhängig.', step: 'Schritt', of: 'von', evidence: 'Verweise auf Befehlsabschlüsse dieses Durchlaufs', preparing: 'Neue Prüfung für diesen Schritt wird vorbereitet…' },
};

/** Uses the existing controller only; no storage, new endpoints or background dispatch. */
export function useServiceActionSequence(workflow: Workflow, authorized: boolean) {
    const access = workflow.historyAccess, scope = authorized && access ? `${access.deviceId}:${access.access.actorId}:${access.access.sessionKey}:${access.access.insecureTestMode}` : '';
    const [state, setState] = useState<State>(() => empty(scope));
    const [, updateClock] = useState(0);
    const latest = useRef(state); latest.current = state;
    const sessionAnchor = useRef<{ scope: string; deadline: number | null; mono: number; wall: number; invalid: boolean } | null>(null);
    const current = state.scope === scope ? state : empty(scope);
    const active = ['binding', 'preparing', 'review', 'waiting'].includes(current.phase);
    const rawPreview = workflow.preview, step = current.steps[current.index];
    const manual = current.steps.length > 0 && !['editing', 'stopped'].includes(current.phase) && !!workflow.selected
        && (!['binding', 'preparing', 'review'].includes(current.phase) || workflow.selected !== step?.unit);
    const admitted = !!rawPreview && !!step && !!current.binding && sequencePreviewMatches(rawPreview, step, current.binding)
        && !!workflow.view && sequenceStepsMatch(current.steps, workflow.view);
    const reviewPreview: ServiceActionPreview | null = !scope ? rawPreview : state.scope !== scope ? null : manual ? rawPreview
        : current.phase === 'binding' ? null : active && (!admitted || current.phase !== 'review' || current.expected !== rawPreview?.id) ? null : rawPreview;
    const change = (next: State) => { latest.current = next; setState(next); };
    const stop = (reason: State['reason'], close = false) => { if (close) workflow.close(); change({ ...latest.current, phase: 'stopped', reason }); };
    const sessionFresh = () => {
        const anchor = sessionAnchor.current, mono = anchor ? performance.now() - anchor.mono : Infinity, wall = anchor ? Date.now() - anchor.wall : Infinity;
        return !!anchor && anchor.scope === scope && !anchor.invalid && Number.isFinite(mono) && mono >= 0 && Math.abs(mono - wall) < 1500
            && anchor.deadline !== null && performance.now() < anchor.deadline;
    };
    useEffect(() => {
        const now = performance.now(), wall = Date.now();
        if (!sessionAnchor.current || sessionAnchor.current.scope !== scope) sessionAnchor.current = { scope, deadline: null, mono: now, wall, invalid: false };
        const anchor = sessionAnchor.current, elapsed = now - anchor.mono;
        // Check the original clock before processing a replacement response.
        // A later read may shorten the deadline, never renew it.
        if (!Number.isFinite(elapsed) || elapsed < 0 || Math.abs(elapsed - (wall - anchor.wall)) >= 1500) anchor.invalid = true;
        if (scope && workflow.view && !anchor.invalid) {
            const remaining = workflow.sessionRemaining();
            if (!Number.isFinite(remaining) || remaining < 0) anchor.invalid = true;
            else if (remaining > 0 || anchor.deadline !== null) anchor.deadline = Math.min(anchor.deadline ?? Infinity, now + remaining);
        }
        updateClock(value => value + 1);
    }, [scope, workflow.view, workflow.sessionRemaining]);
    useEffect(() => { if (state.scope !== scope) change(empty(scope)); }, [scope, state.scope]);
    useEffect(() => {
        if (state.steps.length && (workflow.error === 'session' || workflow.error === 'clock' || !workflow.view && !workflow.loading)) change(empty(scope));
    }, [scope, state.steps.length, workflow.error, workflow.view, workflow.loading]);
    useEffect(() => {
        const timer = window.setInterval(() => { if (latest.current.steps.length && !sessionFresh()) { workflow.close(); change(empty(scope)); } }, 500);
        return () => window.clearInterval(timer);
    }, [scope, access?.access.sessionKey, workflow.close]);
    useEffect(() => {
        const clear = () => change(empty(scope));
        for (const event of ['blur', 'pagehide', 'popstate', 'hashchange', AUTH_REQUIRED_EVENT]) window.addEventListener(event, clear);
        document.addEventListener('visibilitychange', clear);
        return () => { for (const event of ['blur', 'pagehide', 'popstate', 'hashchange', AUTH_REQUIRED_EVENT]) window.removeEventListener(event, clear); document.removeEventListener('visibilitychange', clear); };
    }, [scope]);
    useEffect(() => {
        if (!scope || state.scope !== scope) return;
        if (manual) { stop('manual'); return; }
        if (['ready', 'completed', 'finished'].includes(state.phase) && workflow.view?.available && !sequenceStepsMatch(state.steps, workflow.view)) { stop('changed'); return; }
        if (!active) return;
        if (workflow.error || workflow.unresolved && workflow.loading !== 'approve') { stop(state.phase === 'waiting' ? 'outcome' : 'interrupted', state.phase !== 'waiting'); return; }
        if (state.phase === 'binding' || state.phase === 'preparing') {
            if (rawPreview) {
                if (!workflow.view || !step || !sequenceStepsMatch(state.steps, workflow.view) || rawPreview.plan.unit !== step.unit
                    || rawPreview.deviceId !== access?.deviceId || rawPreview.actorId !== access.access.actorId
                    || state.binding && !sequencePreviewMatches(rawPreview, step, state.binding)) { stop('changed', true); return; }
                if (state.phase === 'binding') { workflow.close(); change({ ...state, binding: sequenceBinding(rawPreview), phase: 'ready' }); }
                else change({ ...state, phase: 'review', expected: rawPreview.id });
            } else if (!workflow.loading && !workflow.selected) stop('interrupted');
        } else if (state.phase === 'review') {
            if (!rawPreview) stop('interrupted');
            else if (!admitted || rawPreview.id !== state.expected) stop('changed', true);
        } else if (state.phase === 'waiting' && !workflow.loading) {
            const job = workflow.view?.job;
            if (!job || job.id !== state.expected || job.unit !== step.unit || job.actorId !== access?.access.actorId) { stop('outcome'); return; }
            if (job.state === 'operation_completed' && job.result?.phase === 'operation_completed' && job.result.outcome === 'completed') {
                change({ ...state, phase: state.index === state.steps.length - 1 ? 'finished' : 'completed', receipts: [...state.receipts, { id: job.id, unit: job.unit }] });
            } else if (job.state !== 'approved' && job.state !== 'claimed') stop('outcome');
        }
    }, [scope, state, active, manual, rawPreview, admitted, workflow.view, workflow.loading, workflow.selected, workflow.error, workflow.unresolved]);
    const idle = !!scope && state.scope === scope && sessionFresh() && !!workflow.view?.available && !workflow.loading && !workflow.preview && !workflow.error && !workflow.unresolved;
    const canBegin = idle && sequenceStepsMatch(current.steps, workflow.view!) && current.steps.every(item => workflow.canSelect(item.unit));
    function begin(kind: 'binding' | 'preparing', index = 0, again = false) {
        const before = latest.current;
        if (before.scope !== scope || !sessionFresh() || !canBegin || !['editing', 'ready', 'completed', 'finished'].includes(before.phase)) return;
        change({ ...before, phase: kind, index, expected: null, ...(again ? { receipts: [] } : {}) });
        workflow.select(before.steps[index].unit);
    }
    return {
        state: current, visible: !!scope && state.scope === scope && (!!workflow.view?.configured || current.steps.length > 0), idle, canBegin, reviewPreview,
        add: (unit: string) => { const before = latest.current, row = workflow.view?.services.find(item => item.unit === unit); if (before.scope === scope && before.phase === 'editing' && idle && row && before.steps.length < maxServiceSequenceSteps && !before.steps.some(item => item.unit === unit)) change({ ...before, steps: [...before.steps, structuredClone(row)] }); },
        remove: (index: number) => { if (latest.current.phase === 'editing' && idle) change({ ...latest.current, steps: latest.current.steps.filter((_, i) => i !== index) }); },
        moveUp: (index: number) => { const before = latest.current; if (before.phase !== 'editing' || !idle || index < 1 || index >= before.steps.length) return; const steps = [...before.steps]; [steps[index - 1], steps[index]] = [steps[index], steps[index - 1]]; change({ ...before, steps }); },
        save: () => begin('binding'),
        review: () => begin('preparing', current.phase === 'completed' ? current.index + 1 : 0, current.phase === 'finished'),
        discard: () => { if (workflow.loading === 'approve') return; if (active && current.phase !== 'waiting') workflow.close(); change(empty(scope)); },
        approve: () => { const before = latest.current; if (!scope) { workflow.approve(); return; } if (before.scope !== scope || !reviewPreview || active && !manual && before.phase !== 'review') return; if (before.phase === 'review' && !manual) { if (!sessionFresh() || !admitted || before.expected !== reviewPreview.id) return; change({ ...before, phase: 'waiting' }); } workflow.approve(); },
        close: workflow.close,
    };
}

export function ServiceActionSequence({ sequence, workflow, locale }: { sequence: ReturnType<typeof useServiceActionSequence>; workflow: Workflow; locale: 'en' | 'de' }) {
    const c = copy[locale], id = useId(), [unit, setUnit] = useState(''), state = sequence.state;
    useEffect(() => { setUnit(''); }, [state.scope, state.steps]);
    if (!sequence.visible) return null;
    return <details className="service-action-sequence"><summary>{c.title}</summary><p>{c.scope}</p>
        {state.phase === 'editing' && <div className="service-action-sequence-controls"><label htmlFor={id}>{c.unit}<select id={id} value={unit} disabled={!sequence.idle} onChange={event => setUnit(event.target.value)}><option value="">{c.choose}</option>{workflow.view?.services.filter(row => !state.steps.some(step => step.unit === row.unit)).map(row => <option key={row.unit} value={row.unit}>{row.unit}</option>)}</select></label><button type="button" disabled={!sequence.idle || !unit || state.steps.length >= maxServiceSequenceSteps} onClick={() => sequence.add(unit)}>{c.add}</button></div>}
        <ol>{state.steps.map((step, index) => <li key={step.unit}><span>{step.unit}</span>{state.phase === 'editing' && <span><button type="button" aria-label={`${c.up}: ${step.unit}`} disabled={!sequence.idle || index === 0} onClick={() => sequence.moveUp(index)}>{c.up}</button><button type="button" aria-label={`${c.remove}: ${step.unit}`} disabled={!sequence.idle} onClick={() => sequence.remove(index)}>{c.remove}</button></span>}</li>)}</ol>
        {state.phase === 'editing' && <button type="button" disabled={!sequence.canBegin} onClick={sequence.save}>{c.save}</button>}
        {state.phase === 'binding' && <p role="status">{c.saving}</p>}
        {state.phase === 'ready' && <p>{c.saved}</p>}
        {['ready', 'preparing', 'review', 'waiting', 'completed', 'finished'].includes(state.phase) && <p>{c.step} {state.index + 1} {c.of} {state.steps.length}</p>}
        {state.phase === 'preparing' && <p role="status">{c.preparing}</p>}
        {state.phase === 'waiting' && <p role="status">{c.pending}</p>}
        {state.phase === 'completed' && <p>{c.completed}</p>}
        {state.phase === 'finished' && <p>{c.finished}</p>}
        {['ready', 'completed', 'finished'].includes(state.phase) && <button type="button" disabled={!sequence.canBegin} onClick={sequence.review}>{state.phase === 'completed' ? c.next : state.phase === 'finished' ? c.again : c.review}</button>}
        {state.phase === 'stopped' && <p role="alert">{c.stopped} {c[state.reason]}</p>}
        {state.receipts.length > 0 && <details><summary>{c.evidence}</summary><ul>{state.receipts.map(receipt => <li key={receipt.id}>{receipt.unit}: {receipt.id}</li>)}</ul></details>}
        {state.steps.length > 0 && <><p>{c.stop}</p><button type="button" disabled={workflow.loading === 'approve'} onClick={sequence.discard}>{c.discard}</button></>}
    </details>;
}
