import { useCallback, useEffect, useRef, useState } from 'react';
import { APIError, AUTH_REQUIRED_EVENT, getProtectedRequestEpoch } from './api';
import { hasLogoutIntent } from './auth';
import { cancelEventHistory, createEventHistory, createHistoryMessages, queryEventHistory, readEventHistory } from './windows-event-history-api';
import { eventHistoryAge, sameHistoryIdentity, sameSelectedEvent, validEventHistoryResult, validEventHistoryView, validSelectedEvents, validHistorySearch, sameSearch } from './windows-event-history-types';
import type { EventHistoryIdentity, EventHistoryRecord, EventHistoryReport, EventHistoryView, EventHistoryReceipt, HistorySearch, SelectedEvent } from './windows-event-history-types';
export type EventHistoryFailure = 'invalid' | 'session' | 'unavailable' | 'timeout' | 'uncertain' | 'conflict' | 'clock' | 'expired';
type Anchor = { mono: number; wall: number };
const clock = (): Anchor => ({ mono: performance.now(), wall: Date.now() });
const elapsed = (a: Anchor) => { const mono = performance.now() - a.mono, wall = Date.now() - a.wall; return Number.isFinite(mono) && mono >= 0 && Math.abs(wall - mono) <= 1500 ? mono : Infinity; };
type Reconcile = { action: 'create' | 'cancel'; identity?: EventHistoryIdentity; intent?: Approval };
type Approval = { search: HistorySearch; selected: SelectedEvent[]; receipt?: EventHistoryReceipt; floor: string; grant: string };
const sameReceipt = (a: EventHistoryReceipt, b: EventHistoryReceipt) => sameHistoryIdentity(a.identity,b.identity) && a.policyDigest===b.policyDigest && a.resultDigest===b.resultDigest && a.acceptedAt===b.acceptedAt && a.expiresAt===b.expiresAt;
const matchesApproval = (r: EventHistoryRecord, a: Approval) => r.description.grantId===a.grant && BigInt(r.description.identity.sequence)===BigInt(a.floor)+1n && (a.receipt ? r.description.query.search===undefined && sameSearch(r.description.sourceSearch,a.search) && r.description.searchReceipt!==undefined && sameReceipt(r.description.searchReceipt,a.receipt) && r.description.expiresAt===a.receipt.expiresAt && r.description.query.events.length===a.selected.length && r.description.query.events.every((e,i)=>sameSelectedEvent(e,a.selected[i])) : sameSearch(r.description.query.search,a.search) && r.description.query.events.length===0);
const activeState = (r?: EventHistoryRecord | null) => r && ['pending', 'claimed', 'accepted'].includes(r.state);

// Navigation keeps only reconciliation metadata, never selected headers,
// provider names, message bodies, checked consent or history-query authority.
type HistoryFence = { sessionBinding: string; floor: string; action: 'create' | 'cancel'; identity?: EventHistoryIdentity };
const historyFences = new Map<string, HistoryFence>();
const maxHistoryFences = 32;
let historyFenceEpoch = 0;
let historyProtectedEpoch = getProtectedRequestEpoch();
const syncHistoryFenceScope = () => { if (historyProtectedEpoch !== getProtectedRequestEpoch()) { historyProtectedEpoch = getProtectedRequestEpoch(); historyFenceEpoch++; historyFences.clear(); } };
const retainHistoryFence = (key: string, value: HistoryFence, expected?: HistoryFence): HistoryFence | null => {
    syncHistoryFenceScope();
    const current = historyFences.get(key);
    if (current !== expected || !current && historyFences.size >= maxHistoryFences) return null;
    const next = { ...value, ...(value.identity ? { identity: { ...value.identity } } : {}) }; historyFences.set(key, next); return next;
};
if (typeof window !== 'undefined') window.addEventListener(AUTH_REQUIRED_EVENT, () => { historyFenceEpoch++; historyFences.clear(); });
function reconcileHistoryFence(key: string, value: EventHistoryView, expected?: HistoryFence) {
    syncHistoryFenceScope();
    const fence = historyFences.get(key); if (!fence || expected && fence !== expected || value.sessionBinding !== fence.sessionBinding) return;
    const record = value.request;
    // A larger authoritative floor consumes the original create precondition;
    // this does not attribute someone else's record to our request or reopen it.
    if (fence.action === 'create' ? BigInt(value.expectedFloor) > BigInt(fence.floor) : fence.identity && (BigInt(value.expectedFloor) > BigInt(fence.identity.sequence) || record && sameHistoryIdentity(record.description.identity, fence.identity) && ['canceled', 'expired'].includes(record.state))) historyFences.delete(key);
}


/** Memory-only, one reviewed selection. Status reads never enqueue or recapture.
 * Epochs fence all late responses; cancellation remains available during a read
 * or ambiguous create, and the original deadline is never recomputed later. */
export function useWindowsEventHistory(deviceId: string, enabled: boolean, insecure: boolean, sessionKey: string | null) {
    const key = `${deviceId}:${enabled}:${insecure}:${sessionKey ?? ''}`;
    const fenceKey = JSON.stringify([deviceId, insecure, sessionKey]);
    syncHistoryFenceScope();
    const [data, setData] = useState<{ key: string; view: EventHistoryView } | null>(null), [result, setResult] = useState<{ key: string; report: EventHistoryReport; expiresAt: string } | null>(null);
    const [busy, setBusy] = useState<'' | 'status' | 'create' | 'query' | 'cancel'>(''), [failure, setFailure] = useState<EventHistoryFailure | null>(null), [reset, setReset] = useState(0), [paused, setPaused] = useState(false), [uncertain, setUncertain] = useState(false);
    const alive = useRef(false), locked = useRef(false), suspended = useRef(false), epoch = useRef(0), protectedScope = useRef(0);
    const current = useRef<EventHistoryView | null>(null), viewAnchor = useRef<Anchor | null>(null), approval = useRef<Approval | null>(null), owned = useRef<EventHistoryRecord | null>(null), pending = useRef<{ controller: AbortController; timeout: number; start: Anchor; action: string } | null>(null);
    const sessionBinding = useRef<string | null>(null), latest = useRef<{ server: string; floorTime: string; anchor: Anchor } | null>(null), deadline = useRef(Infinity), sessionDeadline = useRef(Infinity), capabilityDeadline = useRef(Infinity), lifetimeAnchor = useRef<Anchor | null>(null), floor = useRef('0'), uncertainRef = useRef(false), reconcile = useRef<Reconcile | null>(null);
    const abort = useCallback(() => { epoch.current++; pending.current?.controller.abort(); window.clearTimeout(pending.current?.timeout); pending.current = null; if (alive.current) setBusy(''); }, []);
    const discard = useCallback((reason: EventHistoryFailure | null = null) => { abort(); current.current = null; approval.current = null; owned.current = null; reconcile.current = null; uncertainRef.current = historyFences.has(fenceKey); if (alive.current) { setData(null); setResult(null); setUncertain(uncertainRef.current); setFailure(reason); setReset(n => n + 1); } }, [abort, fenceKey]);
    const bestEffortCancel = useCallback((identity?: EventHistoryIdentity, intent?: Approval | null) => {
        if ((!identity && !intent) || locked.current || hasLogoutIntent() || getProtectedRequestEpoch() !== protectedScope.current) return;
        const binding = sessionBinding.current;
        if (!binding) return;
        let cleanupFence = historyFences.get(fenceKey);
        if (cleanupFence && (cleanupFence.sessionBinding !== binding || (identity ? cleanupFence.action !== 'cancel' || !cleanupFence.identity || !sameHistoryIdentity(cleanupFence.identity, identity) : cleanupFence.action !== 'create' || cleanupFence.floor !== intent!.floor))) return;
        cleanupFence ??= retainHistoryFence(fenceKey, { action: identity ? 'cancel' : 'create', sessionBinding: binding, floor: intent?.floor ?? identity!.sequence, ...(identity ? { identity } : {}) }) ?? undefined;
        if (!cleanupFence) return;
        const controller = new AbortController(), timer = window.setTimeout(() => controller.abort(), 10000), cleanupEpoch = getProtectedRequestEpoch(), cleanupFenceEpoch = historyFenceEpoch;
        void (async () => {
            // A message follow-up replaces an accepted search. Cancel that exact
            // predecessor without resolving the still-ambiguous replacement floor.
            if (intent?.receipt) {
                if (historyFences.get(fenceKey) !== cleanupFence) return;
                try { await cancelEventHistory(deviceId, intent.receipt.identity, controller.signal, insecure, sessionKey); } catch { /* Replacement may have won. */ }
            }
            let target = identity;
            // A lifecycle loss can race a committed create whose response was
            // aborted. Reconcile only that exact captured intent, for at most
            // ten seconds; never enqueue, capture, or render from cleanup.
            while (!target && intent && !controller.signal.aborted && cleanupEpoch === getProtectedRequestEpoch() && cleanupFenceEpoch === historyFenceEpoch && !hasLogoutIntent()) {
                const value = await readEventHistory(deviceId, controller.signal, insecure, sessionKey);
                if (!validEventHistoryView(value, deviceId, sessionKey) || value.sessionBinding !== binding) return;
                if (value.request && matchesApproval(value.request, intent)) {
                    if (!activeState(value.request)) { reconcileHistoryFence(fenceKey, value, cleanupFence); return; }
                    target = value.request.description.identity; break;
                }
                if (BigInt(value.expectedFloor) > BigInt(intent.floor)) { reconcileHistoryFence(fenceKey, value, cleanupFence); return; }
                await new Promise<void>(resolve => { const delay = window.setTimeout(done, 3000); function done() { window.clearTimeout(delay); controller.signal.removeEventListener('abort', done); resolve(); } controller.signal.addEventListener('abort', done, { once: true }); });
            }
            if (target && !controller.signal.aborted && cleanupEpoch === getProtectedRequestEpoch() && cleanupFenceEpoch === historyFenceEpoch && !hasLogoutIntent()) {
                const upgraded = retainHistoryFence(fenceKey, { action: 'cancel', sessionBinding: binding, floor: target.sequence, identity: target }, cleanupFence); if (!upgraded) return; cleanupFence = upgraded;
                const value = await cancelEventHistory(deviceId, target, controller.signal, insecure, sessionKey);
                if (!controller.signal.aborted && cleanupEpoch === getProtectedRequestEpoch() && cleanupFenceEpoch === historyFenceEpoch && validEventHistoryView(value, deviceId, sessionKey)) reconcileHistoryFence(fenceKey, value, cleanupFence);
            }
        })().catch(() => { /* Local disclosure already ended; never log private errors. */ }).finally(() => window.clearTimeout(timer));
    }, [deviceId, fenceKey, insecure, sessionKey]);
    const clear = useCallback((reason: EventHistoryFailure | null = null, cancel = true) => { const intent = approval.current, record = owned.current ?? current.current?.request; const identity = record && activeState(record) && (!intent || matchesApproval(record, intent)) ? record.description.identity : undefined; discard(reason); if (cancel) bestEffortCancel(identity, intent); }, [bestEffortCancel, discard]);
    const begin = useCallback((action: 'status' | 'create' | 'query' | 'cancel') => {
        if (!enabled || !alive.current || locked.current || suspended.current || document.visibilityState === 'hidden' || hasLogoutIntent() || protectedScope.current !== getProtectedRequestEpoch()) return null;
        abort(); const revision = epoch.current, controller = new AbortController(), start = clock();
        setBusy(action); setFailure(null);
        const finish = () => { if (revision === epoch.current) { window.clearTimeout(pending.current?.timeout); pending.current = null; if (alive.current) setBusy(''); } };
        const active = () => {
            if (!alive.current || locked.current || suspended.current || revision !== epoch.current || controller.signal.aborted) return false;
            if (hasLogoutIntent() || protectedScope.current !== getProtectedRequestEpoch() || performance.now() >= sessionDeadline.current) { locked.current = true; clear('session', false); return false; }
            if (!Number.isFinite(elapsed(start)) || lifetimeAnchor.current && !Number.isFinite(elapsed(lifetimeAnchor.current))) { clear('clock'); return false; }
            if (performance.now() >= Math.min(deadline.current, capabilityDeadline.current) && (approval.current || owned.current)) { clear('expired'); return false; }
            return true;
        };
        pending.current = { controller, start, action, timeout: window.setTimeout(() => {
            if (!active()) return;
            if (action === 'create' || action === 'cancel') { uncertainRef.current = true; setUncertain(true); abort(); setResult(null); setFailure('uncertain'); }
            else clear('timeout');
        }, 10000) };
        return { active, finish, signal: controller.signal, start };
    }, [abort, clear, enabled]);
    const accept = useCallback((value: unknown, start: Anchor) => {
        if (!validEventHistoryView(value, deviceId, sessionKey)) { clear('invalid'); return false; }
        if (historyFences.has(fenceKey) && historyFences.get(fenceKey)!.sessionBinding !== value.sessionBinding) { locked.current = true; clear('session', false); return false; }
        if (sessionBinding.current !== null && sessionBinding.current !== value.sessionBinding) { locked.current = true; clear('session', false); return false; }
        const previous = latest.current;
        if (BigInt(value.expectedFloor) < BigInt(floor.current) || previous && (eventHistoryAge(value.serverNow, previous.server) < 0 || eventHistoryAge(value.serverNow, previous.floorTime) + 1500 < elapsed(previous.anchor))) { clear('clock'); return false; }
        sessionBinding.current = value.sessionBinding; floor.current = value.expectedFloor;
        latest.current = previous ? { ...previous, server: value.serverNow } : { server: value.serverNow, floorTime: value.serverNow, anchor: clock() };
        lifetimeAnchor.current ??= start;
        sessionDeadline.current = Math.min(sessionDeadline.current, start.mono + eventHistoryAge(value.sessionExpiresAt, value.serverNow));
        const oldView = current.current;
        const grantChanged = oldView && (oldView.capability?.grantId !== value.capability?.grantId || oldView.capability?.enabled !== value.capability?.enabled);
        const headersChanged = oldView && (oldView.headers?.generationId !== value.headers?.generationId || oldView.headers?.snapshotDigest !== value.headers?.snapshotDigest || oldView.headers?.collectedAt !== value.headers?.collectedAt);
        if (grantChanged) { if (approval.current || owned.current) { clear('conflict'); return false; } setReset(n => n + 1); }
        // An owned request commits immutable selected headers. New ordinary
        // telemetry cannot replace its selection or reset its result/search.
        if (headersChanged && !approval.current && !owned.current) setReset(n => n + 1);
        const prior = owned.current;
        if (approval.current && BigInt(value.expectedFloor) === BigInt(approval.current.floor)) return false;
        if (approval.current && value.request && !matchesApproval(value.request, approval.current)) { clear('conflict'); return false; }
        if (prior && value.request && (prior.state === 'claimed' && value.request.state === 'pending' || prior.state === 'accepted' && ['pending', 'claimed'].includes(value.request.state))) { clear('conflict'); return false; }
        if (prior && (!value.request || !sameHistoryIdentity(prior.description.identity, value.request.description.identity) || value.request.description.expiresAt !== prior.description.expiresAt || value.request.description.certificateHash !== prior.description.certificateHash || prior.receipt && value.request.receipt?.resultDigest !== prior.receipt.resultDigest)) { clear('conflict'); return false; }
        if (prior && value.request && (prior.claimedAt && value.request.claimedAt !== prior.claimedAt || prior.policyDigest && value.request.policyDigest !== prior.policyDigest || prior.receipt && value.request.receipt?.acceptedAt !== prior.receipt.acceptedAt)) { clear('conflict'); return false; }
        if (approval.current && value.request) {
            owned.current = value.request;
            deadline.current = Math.min(deadline.current, start.mono + eventHistoryAge(value.request.description.expiresAt, value.serverNow), start.mono + 86400000 - eventHistoryAge(value.serverNow, value.request.description.headerCollectedAt));
        }
        if (value.capability && approval.current) capabilityDeadline.current = start.mono + eventHistoryAge(value.capability.expiresAt, value.serverNow);
        if (approval.current && (value.localStatus !== 'enabled' || !value.capability?.enabled || value.capability.grantId !== approval.current.grant || performance.now() >= Math.min(deadline.current, capabilityDeadline.current))) { clear(performance.now() >= Math.min(deadline.current, capabilityDeadline.current) ? 'expired' : 'conflict'); return false; }
        if (value.request && ['canceled', 'expired'].includes(value.request.state)) { approval.current = null; owned.current = null; setResult(null); setReset(n => n + 1); }
        if (value.contentStatus !== 'available') setResult(null);
        reconcileHistoryFence(fenceKey, value); uncertainRef.current = historyFences.has(fenceKey); setUncertain(uncertainRef.current);
        current.current = value; viewAnchor.current = start; setData({ key, view: value }); setFailure(null); return true;
    }, [clear, deviceId, fenceKey, key, sessionKey]);
    const fail = useCallback((error: unknown, ambiguous = false) => {
        if (error instanceof APIError && (error.status === 401 || error.status === 403)) { locked.current = true; clear('session', false); return; }
        if (ambiguous) { uncertainRef.current = true; setUncertain(true); setResult(null); setFailure('uncertain'); return; }
        clear(error instanceof APIError && error.status === 409 ? 'conflict' : 'unavailable');
    }, [clear]);
    const load = useCallback(async () => {
        const view = current.current, r = view?.request;
        if (!r || !approval.current || !matchesApproval(r, approval.current) || view.contentStatus !== 'available' || r.state !== 'accepted' || !r.receipt || uncertainRef.current || pending.current) return;
        const op = begin('query'); if (!op) return;
        try { const value = await queryEventHistory(deviceId, r.description.identity, op.signal, insecure, sessionKey); if (!op.active()) return; if (!validEventHistoryResult(value, r, view.sessionExpiresAt)) { clear('invalid'); return; } deadline.current = Math.min(deadline.current, (viewAnchor.current ?? op.start).mono + eventHistoryAge(value.expiresAt, view.serverNow)); if (performance.now() >= deadline.current) { clear('expired'); return; } setResult({ key, report: value.report, expiresAt: value.expiresAt }); }
        catch (error) { if (op.active()) fail(error); } finally { op.finish(); }
    }, [begin, clear, deviceId, fail, insecure, key, sessionKey]);
    const refresh = useCallback(async () => {
        if (pending.current) return;
        const op = begin('status'); if (!op) return;
        try {
            const value = await readEventHistory(deviceId, op.signal, insecure, sessionKey);
            if (!op.active() || !accept(value, op.start)) return;
            // A failed create is never resubmitted. A matching authoritative
            // record reconciles it; absence remains ambiguous until user clears.
            const target = reconcile.current, record = current.current?.request;
            if (uncertainRef.current && target && record && (target.identity ? sameHistoryIdentity(record.description.identity, target.identity) : target.intent && matchesApproval(record, target.intent)) && (target.action === 'create' || ['canceled', 'expired'].includes(record.state))) { uncertainRef.current = false; reconcile.current = null; setUncertain(false); }
        } catch (error) { if (op.active()) fail(error); } finally { op.finish(); }
    }, [accept, begin, deviceId, fail, insecure, sessionKey]);
    const submit = useCallback(async (search: HistorySearch, selected: SelectedEvent[], receipt: EventHistoryReceipt | undefined, acknowledge: boolean, plaintext: boolean) => {
        const v=current.current;
        if (!v || pending.current || uncertainRef.current || historyFences.has(fenceKey) || !v.configured || v.localStatus!=='enabled' || !v.capability?.enabled || !acknowledge || plaintext!==insecure || !validHistorySearch(search,receipt ? v.request?.description.createdAt : v.serverNow)) return;
        if (receipt) {
            if (!result || result.key!==key || !owned.current || !approval.current || v.request?.state!=='accepted' || !v.request.receipt || !sameReceipt(v.request.receipt,receipt) || !sameSearch(v.request.description.query.search,search) || !validSelectedEvents(selected) || selected.some(e=>!result.report.events.some(row=>sameSelectedEvent(row.event,e)))) return;
        } else if (activeState(v.request)) return;
        approval.current={search:{...search}, selected:selected.map(e=>({...e})), receipt, floor:v.expectedFloor,grant:v.capability.grantId};
        reconcile.current={action:'create',intent:approval.current};
        if (!receipt) deadline.current=Infinity;
        capabilityDeadline.current=(viewAnchor.current??clock()).mono+eventHistoryAge(v.capability.expiresAt,v.serverNow);
        owned.current=null; setResult(null); setReset(n=>n+1);
        const op=begin('create'); if (!op) { approval.current=null; return; }
        const createFence = retainHistoryFence(fenceKey, { action: 'create', sessionBinding: v.sessionBinding, floor: v.expectedFloor });
        if (!createFence) { approval.current=null; reconcile.current=null; setFailure('unavailable'); op.finish(); return; }
        try {
            const value=receipt ? await createHistoryMessages(deviceId,v,receipt,selected,acknowledge,plaintext,op.signal,insecure,sessionKey) : await createEventHistory(deviceId,v,search,acknowledge,plaintext,op.signal,insecure,sessionKey);
            if (op.active() && accept(value,op.start)) reconcile.current=null;
        } catch(error) { if (op.active()) { const rejected = error instanceof APIError && error.status!==undefined && error.status>=400 && error.status<500; if (rejected) { if (historyFences.get(fenceKey) === createFence) historyFences.delete(fenceKey); approval.current=null; reconcile.current=null; } fail(error,!rejected); } }
        finally { op.finish(); }
    },[accept,begin,deviceId,fail,fenceKey,insecure,key,result,sessionKey]);
    const create = useCallback((search: HistorySearch, acknowledge: boolean, plaintext: boolean)=>submit(search,[],undefined,acknowledge,plaintext),[submit]);
    const messages = useCallback((selected: SelectedEvent[], acknowledge: boolean, plaintext: boolean)=>{
        const v=current.current, search=v?.request?.description.query.search, receipt=v?.request?.receipt;
        if (search && receipt) return submit(search,selected,receipt,acknowledge,plaintext);
    },[submit]);
    const cancel = useCallback(async () => {
        const r = owned.current ?? current.current?.request, a = approval.current;
        reconcile.current = { action: 'cancel', ...(r && (!a || matchesApproval(r, a)) ? { identity: r.description.identity } : a ? { intent: a } : {}) };
        abort(); setResult(null); setReset(n => n + 1); approval.current = null; owned.current = null; uncertainRef.current = false; setUncertain(false); deadline.current = Infinity;
        const op = begin('cancel'); if (!op) { discard(); return; }
        try {
            let identity = r && (!a || matchesApproval(r, a)) ? r.description.identity : undefined;
            if (!identity && a) {
                const status = await readEventHistory(deviceId, op.signal, insecure, sessionKey);
                if (!op.active()) return;
                if (!validEventHistoryView(status, deviceId, sessionKey)) { clear('invalid', false); return; }
                if (status.request && matchesApproval(status.request, a)) identity = status.request.description.identity;
                else { bestEffortCancel(undefined, a); uncertainRef.current = true; setUncertain(true); current.current = null; setData(null); setFailure('uncertain'); return; }
            }
            if (!identity) { discard(); return; }
            reconcile.current = { action: 'cancel', identity };
            const existingFence = historyFences.get(fenceKey);
            const ownsFence = !existingFence || existingFence.sessionBinding === sessionBinding.current && (existingFence.action === 'cancel' ? existingFence.identity && sameHistoryIdentity(existingFence.identity, identity) : BigInt(existingFence.floor) + 1n === BigInt(identity.sequence));
            if (!sessionBinding.current || !ownsFence || !retainHistoryFence(fenceKey, { action: 'cancel', sessionBinding: sessionBinding.current, floor: identity.sequence, identity }, existingFence)) { uncertainRef.current = true; setUncertain(true); setFailure('uncertain'); return; }
            const value = await cancelEventHistory(deviceId, identity, op.signal, insecure, sessionKey);
            if (op.active() && accept(value, op.start)) reconcile.current = null;
        } catch (error) { if (op.active()) fail(error, true); } finally { op.finish(); }
    }, [abort, accept, begin, bestEffortCancel, clear, deviceId, discard, fail, fenceKey, insecure, sessionKey]);
    useEffect(() => {
        alive.current = true; locked.current = false; suspended.current = document.visibilityState === 'hidden'; protectedScope.current = getProtectedRequestEpoch(); sessionBinding.current = null; latest.current = null; deadline.current = Infinity; sessionDeadline.current = Infinity; capabilityDeadline.current = Infinity; lifetimeAnchor.current = null; floor.current = '0'; uncertainRef.current = false; setUncertain(false); setPaused(suspended.current); discard();
        if (!enabled) return () => { alive.current = false; abort(); };
        const lock = () => { locked.current = true; clear('session', false); };
        const suspend = () => { suspended.current = true; clear(locked.current ? 'session' : null); setPaused(!locked.current); };
        const restore = () => { if (locked.current || hasLogoutIntent() || document.visibilityState === 'hidden') return; suspended.current = false; setPaused(false); void refresh(); };
        const visibility = () => document.visibilityState === 'hidden' ? suspend() : restore();
        window.addEventListener(AUTH_REQUIRED_EVENT, lock); window.addEventListener('blur', suspend); window.addEventListener('focus', restore); window.addEventListener('pagehide', suspend); window.addEventListener('pageshow', restore); window.addEventListener('hashchange', suspend); document.addEventListener('visibilitychange', visibility);
        const timer = window.setInterval(() => {
            if (locked.current) return;
            if (hasLogoutIntent() || getProtectedRequestEpoch() !== protectedScope.current || performance.now() >= sessionDeadline.current) { lock(); return; }
            const anchor = lifetimeAnchor.current ?? pending.current?.start;
            if (anchor && !Number.isFinite(elapsed(anchor))) { clear('clock'); return; }
            if (performance.now() >= Math.min(deadline.current, capabilityDeadline.current) && (owned.current || approval.current)) { clear('expired'); return; }
        }, 250);
        const poll = window.setInterval(() => { if (approval.current || owned.current || uncertainRef.current) void refresh(); }, 3000);
        void refresh();
        return () => { const intent = approval.current, record = owned.current ?? current.current?.request; const identity = record && activeState(record) && (!intent || matchesApproval(record, intent)) ? record.description.identity : undefined; alive.current = false; abort(); current.current = null; approval.current = null; owned.current = null; bestEffortCancel(identity, intent); window.clearInterval(timer); window.clearInterval(poll); window.removeEventListener(AUTH_REQUIRED_EVENT, lock); window.removeEventListener('blur', suspend); window.removeEventListener('focus', restore); window.removeEventListener('pagehide', suspend); window.removeEventListener('pageshow', restore); window.removeEventListener('hashchange', suspend); document.removeEventListener('visibilitychange', visibility); };
    }, [abort, bestEffortCancel, clear, discard, enabled, key, refresh]);
    const live = enabled && !locked.current && !suspended.current && protectedScope.current === getProtectedRequestEpoch() && !hasLogoutIntent() && document.visibilityState !== 'hidden';
    const view = live && data?.key === key ? data.view : null;
    const ready = view?.contentStatus === 'available' && approval.current && !result && !busy && !uncertain;
    useEffect(() => { if (ready) void load(); }, [ready, load]);
    useEffect(() => { if (failure === 'uncertain' && !busy) void refresh(); }, [busy, failure, refresh]);
    return { view, requestOwned: Boolean(approval.current), report: live && result?.key === key ? result.report : null, resultExpiresAt: live && result?.key === key ? result.expiresAt : null, busy, failure, reset, paused, uncertain, create, messages, cancel: () => void cancel(), discard: () => clear(), refresh: () => { if (locked.current || document.visibilityState === 'hidden') return; suspended.current = false; setPaused(false); void refresh(); } };
}
export type WindowsEventHistoryResource = ReturnType<typeof useWindowsEventHistory>;
