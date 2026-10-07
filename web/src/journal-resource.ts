import { useCallback, useEffect, useRef, useState } from 'react';
import { APIError, AUTH_REQUIRED_EVENT, getProtectedRequestEpoch } from './api';
import { journalReportedAccess, journalBrowsingAllowed } from './journal-sources';
import { hasLogoutIntent } from './auth';
import { cancelJournal, createJournal, queryJournal, readJournal } from './journal-api';
import { journalAge, journalBytes, JOURNAL_SEARCH_BYTES, validJournalDevice, validJournalPage, validJournalQuery, validJournalView, sameJournalIdentity, sameJournalQuery, sameJournalAuthorization, sameJournalGeneration } from './journal-types';
import type { JournalPage, JournalQuery, JournalRequest, JournalView, JournalGenerationView } from './journal-types';
export type JournalFailure = 'load' | 'invalid' | 'timeout' | 'session' | 'clock' | 'conflict' | 'uncertain';
type Anchor = { mono: number; wall: number };
const capture = (): Anchor => ({ mono: performance.now(), wall: Date.now() });
function elapsed(a: Anchor) { const m = performance.now() - a.mono, w = Date.now() - a.wall; return Number.isFinite(m) && m >= 0 && Number.isFinite(w) && Math.abs(m - w) <= 1500 ? m : Infinity; }
export function useJournal(deviceId: string, insecureTestMode: boolean, sessionKey: string | null) {
    const key = `${deviceId}:${sessionKey ?? ''}:${insecureTestMode}`;
    const [data, setData] = useState<{ key: string; view: JournalView } | null>(null), [result, setResult] = useState<{ key: string; page: JournalPage } | null>(null);
    const [busy, setBusy] = useState(false), [paused, setPaused] = useState(false), [failure, setFailure] = useState<JournalFailure | null>(null), [uncertain, setUncertain] = useState(false), [reset, setReset] = useState(0);
    const protectedScope = useRef(getProtectedRequestEpoch());
    const alive = useRef(false), locked = useRef(false), suspended = useRef(false), epoch = useRef(0), pending = useRef<{ controller: AbortController; started: Anchor; timeout: number } | null>(null);
    const latestGeneration = useRef<JournalGenerationView | null>(null);
    const latestRequest = useRef<JournalRequest | null>(null), retention = useRef<{ id: string; deadline: number } | null>(null), sessionDeadline = useRef(Infinity);
    const current = useRef<JournalView | null>(null), page = useRef<JournalPage | null>(null), anchor = useRef<Anchor | null>(null), latestTime = useRef<string | null>(null), floor = useRef('0'), history = useRef<number[]>([]);
    const cancel = useCallback(() => { epoch.current++; pending.current?.controller.abort(); window.clearTimeout(pending.current?.timeout); pending.current = null; if (alive.current) setBusy(false); }, []);
    const clearRows = useCallback(() => { page.current = null; history.current = []; if (alive.current) setResult(null); }, []);
    const clear = useCallback((error: JournalFailure | null = null) => { cancel(); current.current = null; anchor.current = null; clearRows(); if (alive.current) { setData(null); setFailure(error); setReset(n => n + 1); } }, [cancel, clearRows]);
    const begin = useCallback((mutation: boolean) => {
        if (!alive.current || locked.current || suspended.current || pending.current || document.visibilityState === 'hidden' || hasLogoutIntent() || protectedScope.current !== getProtectedRequestEpoch()) return null;
        const started = capture(), controller = new AbortController(), revision = ++epoch.current, protectedEpoch = getProtectedRequestEpoch();
        setBusy(true); setFailure(null);
        const timeout = window.setTimeout(() => { if (revision === epoch.current) { if (mutation) setUncertain(true); clear(mutation ? 'uncertain' : 'timeout'); } }, 10000);
        pending.current = { controller, started, timeout };
        const active = () => {
            if (!alive.current || locked.current || suspended.current || controller.signal.aborted || revision !== epoch.current || protectedEpoch !== getProtectedRequestEpoch() || document.visibilityState === 'hidden' || hasLogoutIntent()) return false;
            if (!Number.isFinite(elapsed(started))) { clear('clock'); return false; }
            if (elapsed(started) >= 10000) { if (mutation) setUncertain(true); clear(mutation ? 'uncertain' : 'timeout'); return false; }
            return true;
        };
        const finish = () => { if (revision === epoch.current) { window.clearTimeout(timeout); pending.current = null; if (alive.current) setBusy(false); } };
        return { signal: controller.signal, started, active, finish };
    }, [clear]);
    const acceptView = useCallback((value: unknown, started: Anchor) => {
        if (!validJournalView(value, deviceId)) { clear('invalid'); return false; }
        if (latestTime.current && journalAge(value.serverNow, latestTime.current) < 0 || BigInt(value.expectedFloor) < BigInt(floor.current)) { clear('clock'); return false; }
        const priorGeneration = latestGeneration.current, nextGeneration = value.generation;
        if (priorGeneration) {
            if (!nextGeneration || BigInt(nextGeneration.policyGeneration.revision) < BigInt(priorGeneration.policyGeneration.revision) || BigInt(nextGeneration.sequence) < BigInt(priorGeneration.sequence) || nextGeneration.policyGeneration.revision === priorGeneration.policyGeneration.revision && !sameJournalGeneration(nextGeneration.policyGeneration, priorGeneration.policyGeneration)) { clear('conflict'); return false; }
            if (sameJournalGeneration(nextGeneration.policyGeneration, priorGeneration.policyGeneration) && !sameJournalAuthorization(nextGeneration, priorGeneration) || priorGeneration.schemaVersion === 'tracebolt.journal-generation-view.v2' && nextGeneration.schemaVersion === 'tracebolt.journal-generation-view.v1' || priorGeneration.schemaVersion === 'tracebolt.journal-generation-view.v3' && nextGeneration.schemaVersion !== 'tracebolt.journal-generation-view.v3') { clear('conflict'); return false; }
            if (nextGeneration.sequence === priorGeneration.sequence && (nextGeneration.observedAt !== priorGeneration.observedAt || nextGeneration.receivedAt !== priorGeneration.receivedAt || !sameJournalGeneration(nextGeneration.policyGeneration, priorGeneration.policyGeneration) || !priorGeneration.fresh && nextGeneration.fresh)) { clear('conflict'); return false; }
            if (nextGeneration.sequence !== priorGeneration.sequence && (journalAge(nextGeneration.observedAt, priorGeneration.observedAt) <= 0 || journalAge(nextGeneration.receivedAt, priorGeneration.receivedAt) < 0)) { clear('conflict'); return false; }
        }
        if (nextGeneration && (!priorGeneration || !sameJournalGeneration(nextGeneration.policyGeneration, priorGeneration.policyGeneration))) { clearRows(); setReset(n => n + 1); }
        if (nextGeneration) latestGeneration.current = nextGeneration;
        const prior = latestRequest.current, next = value.request;
        if (prior && next && prior.description.identity.sequence === next.description.identity.sequence) {
            const rank = { pending: 0, claimed: 1, accepted: 2, canceled: 3, expired: 3 };
            if (!sameJournalIdentity(prior.description.identity, next.description.identity) || prior.description.createdAt !== next.description.createdAt || prior.description.expiresAt !== next.description.expiresAt || rank[next.state] < rank[prior.state] || prior.receipt && next.state === 'accepted' && (!next.receipt || next.receipt.resultDigest !== prior.receipt.resultDigest)) { clear('conflict'); return false; }
        }
        if (prior && !next && value.expectedFloor === prior.description.identity.sequence) { clear('conflict'); return false; }
        if (next) {
            latestRequest.current = next;
            const candidate = started.mono + journalAge(next.description.expiresAt, value.serverNow);
            retention.current = { id: next.description.identity.id, deadline: retention.current?.id === next.description.identity.id ? Math.min(retention.current.deadline, candidate) : candidate };
        }
        if (sessionKey) sessionDeadline.current = Math.min(sessionDeadline.current, started.mono + journalAge(sessionKey, value.serverNow));
        if (next && ['pending', 'claimed', 'accepted'].includes(next.state) && performance.now() >= retention.current!.deadline) { latestRequest.current = { ...next, state: 'expired', contentStatus: 'unavailable' }; clear('conflict'); return false; }
        if (sessionKey && performance.now() >= sessionDeadline.current) { locked.current = true; clear('session'); return false; }
        latestTime.current = value.serverNow; floor.current = value.expectedFloor; anchor.current = started; current.current = value; setData({ key, view: value }); return true;
    }, [clear, clearRows, deviceId, key, sessionKey]);
    const fail = useCallback((caught: unknown, mutation: boolean) => {
        if (caught instanceof APIError && caught.status === 401) { locked.current = true; clear('session'); return; }
        clear(mutation ? 'uncertain' : caught instanceof APIError && [404, 409, 410].includes(caught.status ?? 0) ? 'conflict' : 'load');
        if (mutation) setUncertain(true);
    }, [clear]);
    const refresh = useCallback(async (quiet = false, preserveCapture = false): Promise<string | null> => {
        if (pending.current) return null;
        if (!quiet) clear(); if (!validJournalDevice(deviceId)) { setFailure('invalid'); return null; }
        const op = begin(false); if (!op) return null;
        try {
            const value = await readJournal(deviceId, op.signal, insecureTestMode, sessionKey);
            if (!op.active()) return null;
            // Preparing a fresh draft is a status-only read. Keep the retained
            // page/search/history only while it is still the same capture.
            // A changed request needs the ordinary explicit refresh flow.
            const prior = current.current;
            if (preserveCapture && validJournalView(value, deviceId) && prior && (
                value.configured !== prior.configured || value.contentStatus !== prior.contentStatus || value.localStatus !== prior.localStatus ||
                Boolean(value.request) !== Boolean(prior.request) || value.request && prior.request && (
                    !sameJournalIdentity(value.request.description.identity, prior.request.description.identity) ||
                    value.request.description.certificateHash !== prior.request.description.certificateHash ||
                    Boolean(value.request.description.policyGeneration) !== Boolean(prior.request.description.policyGeneration) ||
                    value.request.description.policyGeneration && prior.request.description.policyGeneration && !sameJournalGeneration(value.request.description.policyGeneration, prior.request.description.policyGeneration) ||
                    !sameJournalQuery(value.request.description.query, prior.request.description.query) ||
                    value.request.state !== prior.request.state || value.request.receipt?.acceptedAt !== prior.request.receipt?.acceptedAt ||
                    value.request.receipt?.policyDigest !== prior.request.receipt?.policyDigest ||
                    value.request.receipt?.resultDigest !== prior.request.receipt?.resultDigest
                )
            )) { clear('conflict'); return null; }
            if (acceptView(value, op.started)) { setUncertain(false); return current.current!.serverNow; }
        } catch (caught) { if (op.active()) fail(caught, false); } finally { op.finish(); }
        return null;
    }, [acceptView, begin, clear, deviceId, fail, insecureTestMode, sessionKey]);
    const loadPage = useCallback(async (search: string, offset: number, previous: number[]) => {
        const view = current.current;
        if (pending.current || !view?.request?.receipt || view.contentStatus !== 'available' || journalBytes(search) > JOURNAL_SEARCH_BYTES || !anchor.current || journalAge(view.request.description.expiresAt, view.serverNow) <= elapsed(anchor.current)) return;
        clearRows(); const op = begin(false); if (!op) return;
        try {
            const value = await queryJournal(deviceId, view.request.description.identity, view.request.receipt.resultDigest, search, offset, op.signal, insecureTestMode, sessionKey);
            if (!op.active()) return;
            if (!validJournalPage(value, view, search, offset)) { clear('invalid'); return; }
            const deadline = op.started.mono + journalAge(value.expiresAt, value.serverNow);
            retention.current = { id: value.identity.id, deadline: Math.min(retention.current?.deadline ?? Infinity, deadline) };
            if (sessionKey) sessionDeadline.current = Math.min(sessionDeadline.current, op.started.mono + journalAge(sessionKey, value.serverNow));
            if (performance.now() >= retention.current.deadline) { latestRequest.current = { ...view.request, state: 'expired', contentStatus: 'unavailable' }; clear('conflict'); return; }
            if (latestTime.current && journalAge(value.serverNow, latestTime.current) < 0) { clear('clock'); return; }
            if (sessionKey && performance.now() >= sessionDeadline.current) { locked.current = true; clear('session'); return; }
            latestTime.current = value.serverNow; anchor.current = op.started; current.current = { ...view, serverNow: value.serverNow }; setData({ key, view: current.current });
            page.current = value; history.current = previous; setResult({ key, page: value });
        } catch (caught) { if (op.active()) fail(caught, false); } finally { op.finish(); }
    }, [begin, clear, clearRows, deviceId, fail, insecureTestMode, key, sessionKey]);
    const create = useCallback(async (query: JournalQuery, acknowledgeLogContent: boolean, acknowledgePlaintext: boolean) => {
        const view = current.current;
        if (['reported_disabled', 'outside_reported_scope'].includes(journalReportedAccess(view, query.unit))) return;
        const browse = query.browseMode === 'retained-v1';
        if (browse && !journalBrowsingAllowed(view, query.unit)) return;
        if (!view?.configured || view.generation && (!view.generation.fresh || !anchor.current || journalAge(view.generation.expiresAt, view.serverNow) <= elapsed(anchor.current)) || !browse && (!acknowledgeLogContent || insecureTestMode !== acknowledgePlaintext) || uncertain || !validJournalQuery(query, view.serverNow) || pending.current || view.request && ['pending', 'claimed'].includes(view.request.state)) return;
        clearRows(); const op = begin(true); if (!op) return;
        try { const value = await createJournal(deviceId, view.expectedFloor, query, acknowledgePlaintext, op.signal, insecureTestMode, sessionKey, view.generation?.policyGeneration); if (op.active()) acceptView(value, op.started); }
        catch (caught) { if (op.active()) fail(caught, true); } finally { op.finish(); }
    }, [acceptView, begin, clearRows, deviceId, fail, insecureTestMode, sessionKey, uncertain]);
    const cancelRequest = useCallback(async () => {
        const view = current.current;
        if (!view?.request || pending.current || uncertain || !['pending', 'claimed', 'accepted'].includes(view.request.state)) return;
        clearRows(); const op = begin(true); if (!op) return;
        try { const value = await cancelJournal(deviceId, view.request.description.identity, op.signal, insecureTestMode, sessionKey); if (op.active()) acceptView(value, op.started); }
        catch (caught) { if (op.active()) fail(caught, true); } finally { op.finish(); }
    }, [acceptView, begin, clearRows, deviceId, fail, insecureTestMode, sessionKey, uncertain]);
    useEffect(() => {
        alive.current = true; protectedScope.current = getProtectedRequestEpoch(); locked.current = false; suspended.current = document.visibilityState === 'hidden'; setPaused(suspended.current); latestTime.current = null; latestRequest.current = null; latestGeneration.current = null; retention.current = null; sessionDeadline.current = Infinity; floor.current = '0'; setUncertain(false); clear();
        const lock = () => { locked.current = true; setPaused(false); clear('session'); };
        const suspend = () => {
            suspended.current = true;
            // Later background events must not erase a denied/expired session.
            if (locked.current) { clear('session'); setPaused(false); return; }
            clear(); setPaused(true);
        };
        const restore = () => { if (locked.current || document.visibilityState === 'hidden' || hasLogoutIntent()) return; suspended.current = false; setPaused(false); void refresh(); };
        const visibility = () => document.visibilityState === 'hidden' ? suspend() : restore();
        const show = (event: PageTransitionEvent) => { if (event.persisted || suspended.current) restore(); };
        window.addEventListener(AUTH_REQUIRED_EVENT, lock); window.addEventListener('pagehide', suspend); window.addEventListener('pageshow', show); window.addEventListener('blur', suspend); window.addEventListener('focus', restore); window.addEventListener('hashchange', suspend); document.addEventListener('visibilitychange', visibility);
        const timer = window.setInterval(() => {
            if (locked.current) return;
            const base = anchor.current ?? pending.current?.started;
            if (hasLogoutIntent() || protectedScope.current !== getProtectedRequestEpoch()) { lock(); return; }
            if (base && !Number.isFinite(elapsed(base))) { clear('clock'); return; }
            const view = current.current;
            if (performance.now() >= sessionDeadline.current) { lock(); return; }
            if (!view || !anchor.current) {
                if (latestRequest.current && ['pending', 'claimed', 'accepted'].includes(latestRequest.current.state) && retention.current && performance.now() >= retention.current.deadline) { latestRequest.current = { ...latestRequest.current, state: 'expired', contentStatus: 'unavailable' }; clear('conflict'); }
                return;
            }
            if (view.generation?.fresh && journalAge(view.generation.expiresAt, view.serverNow) <= elapsed(anchor.current)) {
                const stale = { ...view, generation: { ...view.generation, fresh: false } }; current.current = stale; latestGeneration.current = stale.generation; setData({ key, view: stale }); setReset(n => n + 1);
            }
            if (view.request && retention.current && performance.now() >= retention.current.deadline && view.request.state !== 'expired') {
                cancel(); clearRows(); const expired: JournalView = { ...(current.current ?? view), contentStatus: 'unavailable', request: { ...view.request, state: 'expired', contentStatus: 'unavailable' } }; current.current = expired; latestRequest.current = expired.request; setData({ key, view: expired }); setReset(n => n + 1);
            }
        }, 250);
        void refresh();
        return () => { alive.current = false; clear(); window.clearInterval(timer); window.removeEventListener(AUTH_REQUIRED_EVENT, lock); window.removeEventListener('pagehide', suspend); window.removeEventListener('pageshow', show); window.removeEventListener('blur', suspend); window.removeEventListener('focus', restore); window.removeEventListener('hashchange', suspend); document.removeEventListener('visibilitychange', visibility); };
    }, [cancel, clear, clearRows, key, refresh, sessionKey]);
    const scopeActive = protectedScope.current === getProtectedRequestEpoch() && !hasLogoutIntent() && document.visibilityState !== 'hidden';
    const view = scopeActive && data?.key === key ? data.view : null;
    const contentKey = view?.contentStatus === 'available' ? `${view.request?.description.identity.id}:${view.request?.receipt?.resultDigest}` : '';
    useEffect(() => { if (contentKey) void loadPage('', 0, []); }, [contentKey, loadPage]);
    useEffect(() => {
        if (!view?.request || !['pending', 'claimed'].includes(view.request.state) || !['unknown', 'checking'].includes(view.localStatus)) return;
        const poll = window.setTimeout(() => void refresh(true), 3000);
        return () => window.clearTimeout(poll);
    }, [view, refresh]);
    // Only a safe status read follows an uncertain mutation. Never replay create/cancel.
    useEffect(() => { if (uncertain && failure === 'uncertain') void refresh(); }, [failure, refresh, uncertain]);
    return {
        view, page: scopeActive && result?.key === key ? result.page : null, busy, paused, failure, uncertain, reset, refresh: () => {
            // Explicit visible-page refresh may resume a lost/unpaired focus event.
            // It still rechecks the session/status; never replay create or cancel.
            if (!alive.current || locked.current || document.visibilityState === 'hidden' || hasLogoutIntent() || protectedScope.current !== getProtectedRequestEpoch()) return;
            suspended.current = false; setPaused(false); void refresh();
        },
        refreshWindow: () => refresh(true, true),
        create, cancelRequest: () => void cancelRequest(), search: (text: string) => void loadPage(text, 0, []),
        next: () => { const p = page.current; if (p?.nextOffset != null) void loadPage(p.search, p.nextOffset, [...history.current, p.offset]); },
        previous: () => { const p = page.current, previous = history.current; if (p && previous.length) void loadPage(p.search, previous[previous.length - 1], previous.slice(0, -1)); },
        canPrevious: history.current.length > 0,
    };
}
export type JournalResource = ReturnType<typeof useJournal>;
