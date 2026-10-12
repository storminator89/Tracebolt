import { useEffect, useRef, useState } from 'react';
import { AUTH_REQUIRED_EVENT, getProtectedRequestEpoch, request } from './api';
import { hasLogoutIntent, validOperatorSession } from './auth';
import { inventoryAge } from './complete-packages-types';
import { validWindowsCapacityTimestamp } from './windows-capacity-types';
import { acceptWindowsHealthClock, windowsHealthElapsed } from './windows-health-clock';
import { validWindowsIncidentAcknowledgement, validWindowsIncidentInboxView, validWindowsIncidentQuery, WINDOWS_INCIDENT_ACK_BYTES, WINDOWS_INCIDENT_INBOX_BYTES, WINDOWS_INCIDENT_PAGE_SIZE } from './windows-incident-inbox-types';
import type { WindowsIncidentAckFilter, WindowsIncidentInboxView, WindowsIncidentScope } from './windows-incident-inbox-types';

type Anchor = { mono: number; wall: number };
const capture = (): Anchor => ({ mono: performance.now(), wall: Date.now() });
function elapsed(anchor: Anchor): number {
    const mono = performance.now() - anchor.mono, wall = Date.now() - anchor.wall;
    return Number.isFinite(mono) && mono >= 0 && Number.isFinite(wall) && Math.abs(wall - mono) <= 1500 ? mono : Infinity;
}
type Snapshot = { key: string; epoch: number; started: Anchor; view: WindowsIncidentInboxView };
type Commands = { refresh: () => void; acknowledge: (key: string) => Promise<void> };
type Notice = 'acknowledged' | 'uncertain' | null;
const noop: Commands = { refresh: () => {}, acknowledge: async () => {} };

/** Private on-demand inbox. No source recapture, background action, or POST retry. */
export function useWindowsIncidentInbox(enabled: boolean, sessionKey: string | null, admin: boolean, scope: WindowsIncidentScope, ack: WindowsIncidentAckFilter, offset: number) {
    const [snapshot, setSnapshot] = useState<Snapshot | null>(null), [loading, setLoading] = useState(false), [writing, setWriting] = useState(false), [error, setError] = useState(false), [notice, setNotice] = useState<Notice>(null), [, tick] = useState(0);
    const uncertain = useRef(new Set<string>()), uncertaintySession = useRef(sessionKey);
    const key = JSON.stringify([enabled, sessionKey, admin, scope, ack, offset]), clockKey = JSON.stringify(['windows-incident-inbox', sessionKey]);
    const live = useRef(key); live.current = key;
    const commands = useRef<Commands>(noop);
    useEffect(() => {
        if (uncertaintySession.current !== sessionKey) { uncertain.current.clear(); uncertaintySession.current = sessionKey; setNotice(null); }
        let alive = true, locked = false, suspended = document.visibilityState === 'hidden', operation = 0, reading = false, writingKey: string | null = null;
        let accepted: Snapshot | null = null;
        const epoch = getProtectedRequestEpoch(), pending = new Set<AbortController>();
        const abort = () => { operation++; for (const controller of pending) controller.abort(); pending.clear(); };
        const markUncertain = () => { if (writingKey) { uncertain.current.add(writingKey); if (alive) setNotice('uncertain'); } };
        const clear = (failure = false) => {
            markUncertain(); abort(); accepted = null; reading = false; writingKey = null;
            if (alive) { setSnapshot(null); setLoading(false); setWriting(false); setError(failure); }
        };
        const baseActive = () => alive && enabled && live.current === key && !locked && !suspended && document.visibilityState !== 'hidden' && !hasLogoutIntent() && epoch === getProtectedRequestEpoch() && validWindowsCapacityTimestamp(sessionKey);
        const viewActive = () => {
            if (!baseActive() || !accepted) return false;
            const age = windowsHealthElapsed(clockKey, epoch, accepted.view.serverNow, elapsed(accepted.started));
            return age < 120000 && inventoryAge(sessionKey!, accepted.view.serverNow) > age && inventoryAge(accepted.view.authorityExpiresAt, accepted.view.serverNow) > age;
        };
        const fetchValue = async (path: string, active: () => boolean, cap: number, body?: { key: string }) => {
            if (!active()) throw new Error('Inactive');
            const controller = new AbortController(), started = capture(); pending.add(controller);
            let timer = 0;
            const timeout = new Promise<never>((_, reject) => { timer = window.setTimeout(() => { controller.abort(); reject(new Error('Timeout')); }, 10000); });
            const current = () => active() && !controller.signal.aborted && elapsed(started) < 10000;
            try {
                const fetch = async () => {
                    let options: RequestInit = { signal: controller.signal };
                    if (body) {
                        const session = await request<unknown>('/auth/session', options, 32768);
                        if (!current() || !admin || !validOperatorSession(session) || session.mode !== 'lan' || !session.authenticated || session.loginMode !== 'shared' || session.expiresAt !== sessionKey || typeof session.csrfToken !== 'string' || session.csrfToken.length < 1 || session.csrfToken.length > 256 || inventoryAge(sessionKey!, session.serverNow) <= elapsed(started)) throw new Error('Inactive session');
                        options = { ...options, method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': session.csrfToken }, body: JSON.stringify(body) };
                    }
                    if (!current()) throw new Error('Inactive');
                    const value = await request<unknown>(path, options, cap);
                    if (!current()) throw new Error('Inactive');
                    return { value, started };
                };
                return await Promise.race([fetch(), timeout]);
            } finally { window.clearTimeout(timer); pending.delete(controller); }
        };
        const read = async () => {
            if (!baseActive() || reading || writingKey || !validWindowsIncidentQuery(scope, ack, offset, WINDOWS_INCIDENT_PAGE_SIZE)) return;
            clear(); const run = operation; reading = true; setLoading(true);
            try {
                const { value, started } = await fetchValue(`/fleet/windows-incidents?scope=${scope}&ack=${ack}&offset=${offset}&limit=${WINDOWS_INCIDENT_PAGE_SIZE}`, () => baseActive() && run === operation, WINDOWS_INCIDENT_INBOX_BYTES);
                if (!validWindowsIncidentInboxView(value, scope, ack, offset) || !acceptWindowsHealthClock(clockKey, epoch, value.serverNow, elapsed(started))) throw new Error('Invalid inbox');
                accepted = { key, epoch, started, view: value };
                if (!viewActive()) throw new Error('Expired inbox');
                setSnapshot(accepted); setError(false);
            } catch { if (alive && run === operation && live.current === key) clear(true); }
            finally { if (alive && run === operation && live.current === key) { reading = false; setLoading(false); } }
        };
        const acknowledge = async (incidentKey: string) => {
            const row = accepted?.view.items.find(item => item.key === incidentKey);
            if (!admin || !viewActive() || reading || writingKey || !row || row.acknowledgedAt !== null || uncertain.current.has(incidentKey)) return;
            const run = operation; writingKey = incidentKey; setWriting(true); setNotice(null);
            try {
                const { value, started } = await fetchValue('/fleet/windows-incidents/acknowledge', () => run === operation && viewActive(), WINDOWS_INCIDENT_ACK_BYTES, { key: incidentKey });
                if (!validWindowsIncidentAcknowledgement(value, incidentKey) || inventoryAge(value.acknowledgedAt, row.openedAt) < 0 || !acceptWindowsHealthClock(clockKey, epoch, value.serverNow, elapsed(started))) throw new Error('Invalid acknowledgement');
                writingKey = null; setNotice('acknowledged');
            } catch {
                if (alive && run === operation && live.current === key) markUncertain();
            } finally {
                if (alive && run === operation && live.current === key) {
                    writingKey = null; setWriting(false);
                    // Both confirmed and uncertain writes reconcile by GET only.
                    void read();
                }
            }
        };
        const lock = () => { locked = true; clear(true); uncertain.current.clear(); setNotice(null); };
        const suspend = () => { suspended = true; clear(true); };
        const restore = () => { if (locked || document.visibilityState === 'hidden') return; suspended = false; void read(); };
        const visibility = () => document.visibilityState === 'hidden' ? suspend() : restore();
        // A navigation event never reopens a private snapshot. The route-owned
        // component remount starts collapsed, including coalesced Back/Forward.
        const navigation = () => { locked = true; clear(); };
        commands.current = { refresh: () => { void read(); }, acknowledge };
        clear();
        if (!enabled) return () => { alive = false; abort(); commands.current = noop; };
        window.addEventListener(AUTH_REQUIRED_EVENT, lock); window.addEventListener('blur', suspend); window.addEventListener('focus', restore); window.addEventListener('pagehide', suspend); window.addEventListener('hashchange', navigation); document.addEventListener('visibilitychange', visibility);
        const timer = window.setInterval(() => {
            if (epoch !== getProtectedRequestEpoch() || hasLogoutIntent()) { if (!locked) lock(); }
            else if (accepted && !viewActive()) clear(true);
            else if (accepted) tick(value => value + 1);
        }, 250);
        void read();
        return () => {
            markUncertain(); alive = false; abort(); accepted = null; commands.current = noop; window.clearInterval(timer);
            window.removeEventListener(AUTH_REQUIRED_EVENT, lock); window.removeEventListener('blur', suspend); window.removeEventListener('focus', restore); window.removeEventListener('pagehide', suspend); window.removeEventListener('hashchange', navigation); document.removeEventListener('visibilitychange', visibility);
        };
    }, [enabled, key, clockKey, sessionKey, admin, scope, ack, offset]);
    const age = snapshot ? windowsHealthElapsed(clockKey, snapshot.epoch, snapshot.view.serverNow, elapsed(snapshot.started)) : Infinity;
    const available = enabled && snapshot?.key === key && snapshot.epoch === getProtectedRequestEpoch() && !hasLogoutIntent() && document.visibilityState !== 'hidden' && age < 120000 && validWindowsCapacityTimestamp(sessionKey) && inventoryAge(sessionKey, snapshot.view.serverNow) > age && inventoryAge(snapshot.view.authorityExpiresAt, snapshot.view.serverNow) > age;
    return { view: available ? snapshot.view : null, age, loading, writing, error, notice, isUncertain: (incidentKey: string) => uncertain.current.has(incidentKey), refresh: () => commands.current.refresh(), acknowledge: (incidentKey: string) => commands.current.acknowledge(incidentKey) };
}
