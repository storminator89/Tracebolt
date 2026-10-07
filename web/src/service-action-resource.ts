import { useCallback, useEffect, useRef, useState } from 'react';
import { APIError, AUTH_REQUIRED_EVENT, getProtectedRequestEpoch } from './api';
import { approveServiceAction, InvalidServiceActionResponse, previewServiceAction, readServiceActions } from './service-action-api';
import type { ServiceActionAccess } from './service-action-api';
import { journalAge } from './journal-types';
import { serviceActionBlocksNew, serviceActionPending } from './service-action-types';
import type { ServiceActionPreview, ServiceActionView } from './service-action-types';

export type ServiceActionFailure = 'read' | 'invalid' | 'session' | 'expired' | 'changed' | 'uncertain' | 'clock';
type Anchor = { mono: number; wall: number };
const capture = (): Anchor => ({ mono: performance.now(), wall: Date.now() });
function elapsed(anchor: Anchor) {
    const mono = performance.now() - anchor.mono, wall = Date.now() - anchor.wall;
    return mono >= 0 && Number.isFinite(mono) && Math.abs(mono - wall) < 1500 ? mono : Infinity;
}
type Expected = { id: string; unit: string; actorId: string };
// Memory only, session-scoped: a quick close/reopen cannot erase an ambiguous
// submission. Server records remain authoritative after reload and on other tabs.
const unresolved = new Map<string, Expected>();
if (typeof window !== 'undefined') window.addEventListener(AUTH_REQUIRED_EVENT, () => unresolved.clear());
const MAX_POLL_MS = 120000;
export function useServiceActions(deviceId: string, access: ServiceActionAccess | null) {
    const actorId = access?.actorId ?? '', sessionKey = access?.sessionKey ?? '', insecure = access?.insecureTestMode ?? false;
    const scope = `${deviceId}:${actorId}:${sessionKey}`;
    const [view, setView] = useState<ServiceActionView | null>(null), [preview, setPreview] = useState<ServiceActionPreview | null>(null), [loading, setLoading] = useState<'read' | 'preview' | 'approve' | null>(null), [error, setError] = useState<ServiceActionFailure | null>(null), [selected, setSelected] = useState<string | null>(null), [, tick] = useState(0);
    const alive = useRef(false), locked = useRef(false), suspended = useRef(false), version = useRef(0), currentView = useRef<ServiceActionView | null>(null), currentPreview = useRef<ServiceActionPreview | null>(null), selectedUnit = useRef<string | null>(null);
    const pending = useRef<{ controller: AbortController; timeout: number; kind: 'read' | 'preview' | 'approve' } | null>(null), anchor = useRef<Anchor | null>(null), lastServerNow = useRef<string | null>(null), failure = useRef<ServiceActionFailure | null>(null);
    const polling = useRef<{ id: string; started: Anchor; lastRead: number } | null>(null);
    const fail = useCallback((next: ServiceActionFailure | null) => { failure.current = next; if (alive.current) setError(next); }, []);
    const discardPreview = useCallback(() => { currentPreview.current = null; selectedUnit.current = null; if (alive.current) { setPreview(null); setSelected(null); } }, []);
    const cancel = useCallback(() => { version.current++; pending.current?.controller.abort(); window.clearTimeout(pending.current?.timeout); pending.current = null; if (alive.current) setLoading(null); }, []);
    const clear = useCallback(() => { cancel(); discardPreview(); anchor.current = null; currentView.current = null; polling.current = null; if (alive.current) setView(null); }, [cancel, discardPreview]);
    const canSelect = useCallback((unit: string) => !!actorId && !locked.current && !suspended.current && !unresolved.has(scope) && !failure.current && currentView.current?.available === true && !serviceActionBlocksNew(currentView.current.job) && currentView.current.services.some(service => service.unit === unit) && pending.current?.kind !== 'approve' && pending.current?.kind !== 'read', [actorId, scope]);
    const run = useCallback(async (kind: 'read' | 'preview' | 'approve', unit?: string, approval?: ServiceActionPreview): Promise<void> => {
        if (!alive.current || !actorId || !sessionKey || locked.current || suspended.current || document.visibilityState === 'hidden') return;
        cancel(); const revision = version.current, controller = new AbortController(), started = capture(), epoch = getProtectedRequestEpoch(), credentials = { actorId, sessionKey, insecureTestMode: insecure };
        setLoading(kind); fail(null);
        if (kind !== 'preview') discardPreview();
        if (kind === 'approve' && approval) unresolved.set(scope, { id: approval.id, unit: approval.plan.unit, actorId: approval.actorId });
        const valid = () => alive.current && !locked.current && !suspended.current && !controller.signal.aborted && revision === version.current && epoch === getProtectedRequestEpoch();
        let reconcile = false;
        pending.current = { controller, kind, timeout: window.setTimeout(() => {
            if (!valid()) return;
            cancel(); discardPreview(); fail(kind === 'approve' ? 'uncertain' : 'read');
            if (kind === 'approve') void run('read');
        }, 10000) };
        try {
            const value = kind === 'preview' ? await previewServiceAction(deviceId, unit!, credentials, controller.signal, currentView.current?.schemaVersion) : kind === 'approve' ? await approveServiceAction(deviceId, approval!, credentials, controller.signal) : await readServiceActions(deviceId, credentials, controller.signal, currentView.current?.schemaVersion);
            if (!valid()) return;
            if (!Number.isFinite(elapsed(started)) || lastServerNow.current && journalAge(value.serverNow, lastServerNow.current) < 0) { discardPreview(); fail('clock'); return; }
            lastServerNow.current = value.serverNow; anchor.current = started;
            // A GET may expose a saved preview, but only this explicit row request
            // can present it for approval; reopening never revives old consent.
            currentView.current = { ...value, preview: null }; setView(currentView.current);
            const expected = unresolved.get(scope);
            if (expected && value.job?.id === expected.id && value.job.unit === expected.unit && value.job.actorId === expected.actorId) unresolved.delete(scope);
            if (unresolved.has(scope)) fail('uncertain');
            if (kind === 'preview') {
                if (!value.available || !value.preview || value.preview.plan.unit !== unit || selectedUnit.current !== unit) { discardPreview(); fail('changed'); return; }
                if (journalAge(value.preview.expiresAt, value.serverNow) <= elapsed(started)) { discardPreview(); fail('expired'); return; }
                currentPreview.current = value.preview; setPreview(value.preview);
            }
            if (kind === 'approve' && (!value.job || value.job.id !== approval!.id || value.job.unit !== approval!.plan.unit || value.job.actorId !== actorId)) { fail('uncertain'); reconcile = true; }
            if (serviceActionPending(value.job)) {
                if (polling.current?.id !== value.job!.id) polling.current = { id: value.job!.id, started: capture(), lastRead: performance.now() };
                else polling.current.lastRead = performance.now();
            } else polling.current = null;
        } catch (caught) {
            if (!valid()) return;
            discardPreview();
            if (caught instanceof APIError && caught.status === 401) { locked.current = true; unresolved.delete(scope); clear(); fail('session'); }
            else if (kind === 'approve') {
                // Even HTTP 409 can follow an uncertain durable write. Only a
                // matching saved job resolves the attempted approval.
                fail('uncertain'); reconcile = true;
            } else fail(caught instanceof InvalidServiceActionResponse ? 'invalid' : 'read');
        } finally {
            if (revision === version.current) { window.clearTimeout(pending.current?.timeout); pending.current = null; if (alive.current) setLoading(null); }
        }
        if (reconcile && alive.current && !locked.current && !suspended.current) void run('read');
    }, [actorId, cancel, clear, deviceId, discardPreview, fail, insecure, scope, sessionKey]);
    const select = useCallback((unit: string) => {
        if (!canSelect(unit) || selectedUnit.current === unit && pending.current?.kind === 'preview') return;
        discardPreview(); selectedUnit.current = unit; setSelected(unit); void run('preview', unit);
    }, [canSelect, discardPreview, run]);
    const approve = useCallback(() => {
        const value = currentPreview.current;
        if (!value || pending.current || !canSelect(value.plan.unit) || !anchor.current || !currentView.current || journalAge(value.expiresAt, currentView.current.serverNow) <= elapsed(anchor.current)) { if (value) { discardPreview(); fail('expired'); } return; }
        const view = currentView.current, row = view.services.find(service => service.unit === value.plan.unit);
        if (!row || row.unitPolicyDigest !== value.plan.unitPolicyDigest || (value.version === 'tracebolt.service-action-preview.v2' ? view.schemaVersion !== 'tracebolt.service-action-view.v2' || view.scope !== value.scope || view.reviewNotice !== value.reviewNotice || JSON.stringify(row.affectedServices) !== JSON.stringify(value.affectedServices) : view.schemaVersion !== 'tracebolt.service-action-view.v1')) { discardPreview(); fail('changed'); return; }
        // Clear synchronously before yielding so repeated clicks cannot resubmit.
        currentPreview.current = null; setPreview(null); void run('approve', undefined, value);
    }, [canSelect, discardPreview, fail, run]);
    const close = useCallback(() => { if (pending.current?.kind === 'approve') return; cancel(); discardPreview(); }, [cancel, discardPreview]);
    useEffect(() => {
        alive.current = true; locked.current = false; suspended.current = document.visibilityState === 'hidden'; lastServerNow.current = null; fail(null);
        const lock = () => { locked.current = true; unresolved.delete(scope); clear(); fail('session'); };
        const suspend = () => { suspended.current = true; clear(); };
        const restore = () => { if (locked.current || document.visibilityState === 'hidden') return; suspended.current = false; void run('read'); };
        const visibility = () => document.visibilityState === 'hidden' ? suspend() : restore();
        const show = (event: PageTransitionEvent) => { if (event.persisted || suspended.current) restore(); };
        window.addEventListener(AUTH_REQUIRED_EVENT, lock); window.addEventListener('pagehide', suspend); window.addEventListener('pageshow', show); window.addEventListener('blur', suspend); window.addEventListener('focus', restore); window.addEventListener('hashchange', suspend); window.addEventListener('popstate', suspend); document.addEventListener('visibilitychange', visibility);
        const timer = window.setInterval(() => {
            if (!alive.current || locked.current || suspended.current) return;
            if (anchor.current && !Number.isFinite(elapsed(anchor.current))) { clear(); fail('clock'); return; }
            if (currentPreview.current && anchor.current && currentView.current && journalAge(currentPreview.current.expiresAt, currentView.current.serverNow) <= elapsed(anchor.current)) { discardPreview(); fail('expired'); }
            const poll = polling.current;
            if (poll && elapsed(poll.started) < MAX_POLL_MS && performance.now() - poll.lastRead >= 3000 && !pending.current && !currentPreview.current && !failure.current) void run('read');
            if (anchor.current) tick(n => n + 1);
        }, 1000);
        if (actorId && sessionKey) void run('read');
        return () => { alive.current = false; clear(); window.clearInterval(timer); window.removeEventListener(AUTH_REQUIRED_EVENT, lock); window.removeEventListener('pagehide', suspend); window.removeEventListener('pageshow', show); window.removeEventListener('blur', suspend); window.removeEventListener('focus', restore); window.removeEventListener('hashchange', suspend); window.removeEventListener('popstate', suspend); document.removeEventListener('visibilitychange', visibility); };
    }, [actorId, clear, discardPreview, fail, run, scope, sessionKey]);
    return { view, preview, selected, loading, error, canSelect, select, approve, close, refresh: () => { if (!pending.current) void run('read'); }, unresolved: unresolved.has(scope) };
}
