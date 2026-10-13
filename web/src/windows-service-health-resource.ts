import { useEffect, useRef, useState } from 'react';
import { APIError, AUTH_REQUIRED_EVENT, getProtectedRequestEpoch, mutateRaw, request } from './api';
import { hasLogoutIntent } from './auth';
import { inventoryAge } from './complete-packages-types';
import { acceptWindowsCapacityClock, windowsCapacityElapsed } from './windows-capacity-clock';
import { validWindowsCapacityDeviceId, validWindowsCapacityTimestamp } from './windows-capacity-types';
import { sameWindowsServiceNames, validWindowsServiceHealthSelection, validWindowsServiceHealthView, windowsServiceHealthChoices, WINDOWS_SERVICE_HEALTH_VIEW_BYTES } from './windows-service-health-types';
import type { WindowsServiceHealthPolicy, WindowsServiceHealthView } from './windows-service-health-types';

export type WindowsServiceHealthFailure = 'invalid' | 'unavailable' | 'timeout' | 'session' | 'authority' | 'clock';
export type WindowsServiceHealthNotice = 'saved' | 'uncertain' | 'conflict' | null;
type Anchor = { mono: number; wall: number };
type Accepted = { key: string; epoch: number; view: WindowsServiceHealthView; started: Anchor };
type Intent = { enabled: boolean; services: string[]; expectedRevision: number };
const capture = (): Anchor => ({ mono: performance.now(), wall: Date.now() });
function elapsed(anchor: Anchor): number {
    const mono = performance.now() - anchor.mono, wall = Date.now() - anchor.wall;
    return Number.isFinite(mono) && mono >= 0 && Number.isFinite(wall) && Math.abs(wall - mono) <= 1500 ? mono : Infinity;
}
/** Private state is scoped to this mounted resource. Only timing watermarks survive remount. */
export function useWindowsServiceHealth(deviceId: string, enabled: boolean, sessionKey: string | null, admin: boolean, metadata: { checkedAt: string; expiresAt: string | null } | undefined) {
    const metadataCheckedAt = metadata?.checkedAt, metadataExpiresAt = metadata?.expiresAt;
    const key = JSON.stringify(['windows-services', deviceId, sessionKey]);
    const endpoint = 'windows-services';
    const [draftGeneration, setDraftGeneration] = useState(0);
    const [data, setData] = useState<Accepted | null>(null), [loading, setLoading] = useState(false), [saving, setSaving] = useState(false), [error, setError] = useState<WindowsServiceHealthFailure | null>(null), [, tick] = useState(0);
    const [noticeState, setNoticeState] = useState<{ key: string; epoch: number; value: WindowsServiceHealthNotice } | null>(null);
    const policyFloor = useRef<{ key: string; epoch: number; policy: WindowsServiceHealthPolicy } | null>(null);
    const reconciliation = useRef<{ key: string; epoch: number; intent: Intent; conflict: boolean } | null>(null);
    const refreshRef = useRef<() => void>(() => {}), saveRef = useRef<(intent: Intent) => void>(() => {});
    useEffect(() => {
        let alive = true, locked = false, suspended = document.visibilityState === 'hidden', revision = 0;
        let accepted: Accepted | null = null, pending: { controller: AbortController; timeout: number; started: Anchor; write: boolean; authorityBase?: Accepted } | null = null;
        const epoch = getProtectedRequestEpoch();
        if (policyFloor.current?.key !== key || policyFloor.current.epoch !== epoch) policyFloor.current = null;
        if (reconciliation.current?.key !== key || reconciliation.current.epoch !== epoch) reconciliation.current = null;
        const notify = (value: WindowsServiceHealthNotice) => { if (alive) setNoticeState({ key, epoch, value }); };
        const cancel = () => {
            if (pending?.write) notify('uncertain');
            revision++; pending?.controller.abort(); window.clearTimeout(pending?.timeout); pending = null;
        };
        const clear = (failure: WindowsServiceHealthFailure | null = null) => { cancel(); accepted = null; if (alive) { if (failure && ['invalid', 'session', 'authority', 'clock'].includes(failure)) setDraftGeneration(n => n + 1); setData(null); setLoading(false); setSaving(false); setError(failure); } };
        const lock = () => { locked = true; reconciliation.current = null; policyFloor.current = null; clear('session'); };
        const permitted = () => enabled && Boolean(endpoint) && alive && !locked && !suspended && document.visibilityState !== 'hidden';
        const age = (value: Accepted) => windowsCapacityElapsed(key, value.epoch, value.view.serverNow, elapsed(value.started));
        const authority = (value: Accepted): WindowsServiceHealthFailure | null => {
            if (epoch !== getProtectedRequestEpoch() || hasLogoutIntent()) return 'session';
            const offset = age(value);
            if (!Number.isFinite(offset)) return 'clock';
            if (!validWindowsCapacityTimestamp(sessionKey) || inventoryAge(sessionKey, value.view.serverNow) <= offset) return 'session';
            if (inventoryAge(value.view.certificateExpiresAt, value.view.serverNow) <= offset || !validWindowsCapacityTimestamp(metadataCheckedAt) || !validWindowsCapacityTimestamp(metadataExpiresAt) || inventoryAge(metadataExpiresAt, value.view.serverNow) <= offset || inventoryAge(value.view.serverNow, metadataCheckedAt) + offset < 0 || inventoryAge(value.view.serverNow, metadataCheckedAt) + offset > 120000) return 'authority';
            return null;
        };
        const read = async () => {
            if (!permitted() || pending?.write) return;
            if (epoch !== getProtectedRequestEpoch() || hasLogoutIntent()) { lock(); return; }
            clear();
            if (!validWindowsCapacityDeviceId(deviceId) || !validWindowsCapacityTimestamp(sessionKey)) { clear('invalid'); return; }
            const current = revision, controller = new AbortController(), started = capture();
            setLoading(true);
            pending = { controller, started, write: false, timeout: window.setTimeout(() => { if (current === revision) clear('timeout'); }, 10000) };
            const active = () => {
                if (!permitted() || controller.signal.aborted || current !== revision) return false;
                if (epoch !== getProtectedRequestEpoch() || hasLogoutIntent()) { lock(); return false; }
                const duration = elapsed(started);
                if (!Number.isFinite(duration)) { clear('clock'); return false; }
                if (duration >= 10000) { clear('timeout'); return false; }
                return true;
            };
            try {
                const response: unknown = await request(`/devices/${encodeURIComponent(deviceId)}/${endpoint}`, { signal: controller.signal }, WINDOWS_SERVICE_HEALTH_VIEW_BYTES);
                if (!active()) return;
                if (!validWindowsServiceHealthView(response, deviceId)) { clear('invalid'); return; }
                const floor = policyFloor.current?.policy;
                if (floor && (response.policy.revision < floor.revision || response.policy.revision === floor.revision && (response.policy.enabled !== floor.enabled || !sameWindowsServiceNames(response.policy.services, floor.services)))) { clear('invalid'); return; }
                if (!acceptWindowsCapacityClock(key, epoch, response.serverNow, elapsed(started))) { clear('clock'); return; }
                const next = { key, epoch, view: response, started }, failure = authority(next);
                if (failure) { if (failure === 'session') locked = true; clear(failure); return; }
                if (!reconciliation.current && floor && response.policy.revision > floor.revision) notify(null);
                const attempt = reconciliation.current;
                if (attempt?.key === key) {
                    const { intent } = attempt, policy = response.policy;
                    if (policy.revision > intent.expectedRevision) {
                        notify(!attempt.conflict && policy.enabled === intent.enabled && sameWindowsServiceNames(policy.services, intent.services) ? 'saved' : 'conflict');
                        reconciliation.current = null;
                    } else notify(attempt.conflict ? 'conflict' : 'uncertain');
                }
                policyFloor.current = { key, epoch, policy: { ...response.policy, services: [...response.policy.services] } };
                accepted = next; setData(next);
            } catch (caught) {
                if (!active()) return;
                if (caught instanceof APIError && caught.status === 401) lock();
                else clear(caught instanceof APIError && [403, 404, 410].includes(caught.status ?? 0) ? 'authority' : 'unavailable');
            } finally {
                if (current === revision) { window.clearTimeout(pending?.timeout); pending = null; if (alive) setLoading(false); }
            }
        };
        const save = async (intent: Intent) => {
            if (!permitted() || !admin || pending || reconciliation.current || !accepted) return;
            const accessFailure = authority(accepted);
            if (accessFailure) { if (accessFailure === 'session') locked = true; clear(accessFailure); return; }
            if (!validWindowsServiceHealthSelection(intent.services, intent.enabled) || typeof intent.enabled !== 'boolean' || !Number.isSafeInteger(intent.expectedRevision) || intent.expectedRevision < 0 || intent.expectedRevision >= Number.MAX_SAFE_INTEGER || intent.expectedRevision !== accepted.view.policy.revision || intent.enabled === accepted.view.policy.enabled && sameWindowsServiceNames(intent.services, accepted.view.policy.services)) return;
            // Newly added or re-enabled names require a currently reported unique choice.
            const choices = windowsServiceHealthChoices(accepted.view, age(accepted));
            if (intent.services.some(name => (intent.enabled && !accepted!.view.policy.enabled || !accepted!.view.policy.services.includes(name)) && !choices.some(row => row.name === name))) return;
            // Capture the authoritative base before clearing. Never resubmit this intent automatically.
            const authorityBase = accepted;
            reconciliation.current = { key, epoch, intent: { ...intent, services: [...intent.services] }, conflict: false };
            clear(); notify(null);
            const current = revision, controller = new AbortController(), started = capture();
            setSaving(true);
            pending = { controller, started, write: true, authorityBase, timeout: window.setTimeout(() => { if (current === revision) { clear('timeout'); void read(); } }, 10000) };
            try {
                const response: unknown = await mutateRaw(`/devices/${encodeURIComponent(deviceId)}/${endpoint}/policy`, JSON.stringify({ enabled: intent.enabled, services: intent.services, expectedRevision: intent.expectedRevision }), {}, controller.signal, WINDOWS_SERVICE_HEALTH_VIEW_BYTES);
                if (!permitted() || current !== revision || controller.signal.aborted) return;
                if (epoch !== getProtectedRequestEpoch() || hasLogoutIntent()) { lock(); return; }
                const failure = authority(authorityBase);
                if (failure) { if (failure === 'session') locked = true; clear(failure); return; }
                // A POST response is never installed as current assessment. Even a valid reply needs GET reconciliation.
                if (!Number.isFinite(elapsed(started)) || elapsed(started) >= 10000 || !validWindowsServiceHealthView(response, deviceId) || response.policy.revision !== intent.expectedRevision + 1 || response.policy.enabled !== intent.enabled || !sameWindowsServiceNames(response.policy.services, intent.services)) { setDraftGeneration(n => n + 1); notify('uncertain'); }
            } catch (caught) {
                if (!permitted() || current !== revision || controller.signal.aborted) return;
                if (caught instanceof APIError && caught.status === 401) { lock(); return; }
                const conflict = caught instanceof APIError && caught.status === 409;
                if (conflict || caught instanceof APIError && [403, 404, 410].includes(caught.status ?? 0)) setDraftGeneration(n => n + 1);
                if (reconciliation.current?.key === key) reconciliation.current.conflict = conflict;
                notify(conflict ? 'conflict' : 'uncertain');
            } finally {
                if (current === revision) {
                    window.clearTimeout(pending?.timeout); pending = null;
                    if (alive) { setSaving(false); notify(reconciliation.current?.conflict ? 'conflict' : 'uncertain'); void read(); }
                }
            }
        };
        const suspend = () => { suspended = true; setDraftGeneration(n => n + 1); clear(); };
        // A browser return can emit visibility, focus and pageshow together.
        // Resume once so later notifications cannot abort/restart the fresh read.
        const restore = () => { if (!alive || locked || !suspended || document.visibilityState === 'hidden') return; suspended = false; void read(); };
        const visibility = () => document.visibilityState === 'hidden' ? suspend() : restore();
        const show = (event: PageTransitionEvent) => { if (event.persisted || suspended) restore(); };
        clear(); refreshRef.current = () => { void read(); }; saveRef.current = intent => { void save(intent); };
        if (!enabled) return () => { alive = false; cancel(); refreshRef.current = () => {}; saveRef.current = () => {}; };
        window.addEventListener(AUTH_REQUIRED_EVENT, lock); window.addEventListener('blur', suspend); window.addEventListener('focus', restore); window.addEventListener('pagehide', suspend); window.addEventListener('pageshow', show); window.addEventListener('hashchange', suspend); document.addEventListener('visibilitychange', visibility);
        const clockTimer = window.setInterval(() => {
            if (epoch !== getProtectedRequestEpoch() || hasLogoutIntent()) { lock(); return; }
            if (accepted) { const failure = authority(accepted); if (failure) { if (failure === 'session') locked = true; clear(failure); return; } tick(n => n + 1); }
            else if (pending?.authorityBase) { const failure = authority(pending.authorityBase); if (failure) { if (failure === 'session') locked = true; clear(failure); } }
            else if (pending && !Number.isFinite(elapsed(pending.started))) clear('clock');
        }, 1000);
        const refreshTimer = window.setInterval(() => { if (!pending) void read(); }, 15000);
        void read();
        return () => { cancel(); alive = false; accepted = null; refreshRef.current = () => {}; saveRef.current = () => {}; window.clearInterval(clockTimer); window.clearInterval(refreshTimer); window.removeEventListener(AUTH_REQUIRED_EVENT, lock); window.removeEventListener('blur', suspend); window.removeEventListener('focus', restore); window.removeEventListener('pagehide', suspend); window.removeEventListener('pageshow', show); window.removeEventListener('hashchange', suspend); document.removeEventListener('visibilitychange', visibility); };
    }, [deviceId, enabled, key, sessionKey, admin, metadataCheckedAt, metadataExpiresAt, endpoint]);
    const candidate = enabled && data?.key === key && data.epoch === getProtectedRequestEpoch() && !hasLogoutIntent() ? data : null;
    const elapsedMS = candidate ? windowsCapacityElapsed(key, candidate.epoch, candidate.view.serverNow, elapsed(candidate.started)) : Infinity;
    const view = candidate && Number.isFinite(elapsedMS) && validWindowsCapacityTimestamp(sessionKey) && inventoryAge(sessionKey, candidate.view.serverNow) > elapsedMS && inventoryAge(candidate.view.certificateExpiresAt, candidate.view.serverNow) > elapsedMS && validWindowsCapacityTimestamp(metadataCheckedAt) && validWindowsCapacityTimestamp(metadataExpiresAt) && inventoryAge(metadataExpiresAt, candidate.view.serverNow) > elapsedMS && inventoryAge(candidate.view.serverNow, metadataCheckedAt) + elapsedMS >= 0 && inventoryAge(candidate.view.serverNow, metadataCheckedAt) + elapsedMS <= 120000 ? candidate.view : null;
    return { view, draftGeneration, elapsedMS, loading: enabled && loading, saving: enabled && saving, error: enabled ? error : null, notice: enabled && noticeState?.key === key && noticeState.epoch === getProtectedRequestEpoch() ? noticeState.value : null, unresolved: reconciliation.current?.key === key && reconciliation.current.epoch === getProtectedRequestEpoch(), refresh: () => refreshRef.current(), save: (intent: Intent) => saveRef.current(intent) };
}
export type WindowsServiceHealthResource = ReturnType<typeof useWindowsServiceHealth>;
