import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { APIError, AUTH_REQUIRED_EVENT, getProtectedRequestEpoch, hasPendingAPIRequests, request } from './api';
import { hasLogoutIntent } from './auth';
import { getLocale, t } from './i18n';
import type { Device, Metric } from './types';

const POLL_MS = 15000, TIMEOUT_MS = 10000, MAX_BACKOFF_MS = 120000;
type Anchor = { mono: number; wall: number };
type MetricKey = 'cpu' | 'memory' | 'disk';
type Snapshot = { scope: string; epoch: number; device: Device; checkedAt: string; anchor: Anchor; sampleAnchors: Record<MetricKey, Anchor> };
const capture = (): Anchor => ({ mono: performance.now(), wall: Date.now() });
function elapsed(anchor: Anchor): number {
    const mono = performance.now() - anchor.mono, wall = Date.now() - anchor.wall;
    return Number.isFinite(mono) && mono >= 0 && Math.abs(wall - mono) <= 1500 ? mono : Infinity;
}
/** Keep collection time and reported quality. A successful GET is not a new sample. */
function agedMetric(metric: Metric, managerNow: number, age: number): Metric {
    if (metric.quality !== 'healthy') return metric;
    const measured = Date.parse(metric.collectedAt);
    const old = !Number.isFinite(age) || age > 120000 || (Number.isFinite(managerNow) && (!Number.isFinite(measured) || measured > managerNow || managerNow - measured + age > 120000));
    return old ? { ...metric, quality: 'stale' } : metric;
}

/** One bounded metadata GET at a time. Only the visible authenticated Overview
 * polls; auxiliary summaries and collection grants are never refreshed here. */
export function useDeviceMetadata(id: string, scope: string, automatic: boolean) {
    const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
    const [refreshing, setRefreshing] = useState(false), [accessEnded, setAccessEnded] = useState(false), [error, setError] = useState('');
    const [automaticState, setAutomaticState] = useState<'off' | 'active' | 'backoff'>('off');
    const [, tick] = useState(0);
    const automaticRef = useRef(automatic), refreshRef = useRef<() => void>(() => {}), reconcileRef = useRef<() => void>(() => {});
    automaticRef.current = automatic;
    useEffect(() => {
        let alive = true, locked = false, suspended = document.visibilityState === 'hidden', failures = 0;
        let current: Snapshot | null = null, timer: number | undefined, ageTimer: number | undefined;
        const accessEpoch = getProtectedRequestEpoch(), hidden = () => document.visibilityState === 'hidden';
        let pending: { controller: AbortController; timeout: number; automatic: boolean } | null = null;
        const stopTimer = () => { window.clearTimeout(timer); timer = undefined; };
        const cancel = () => { pending?.controller.abort(); window.clearTimeout(pending?.timeout); pending = null; };
        const lock = () => {
            locked = true; stopTimer(); cancel(); current = null; setSnapshot(null); setRefreshing(false); setAccessEnded(true); setAutomaticState('off');
            setError(t('Die Sitzung ist abgelaufen. Bitte erneut anmelden.'));
        };
        const mayPoll = () => alive && !locked && !suspended && !hidden() && automaticRef.current && current?.device.source === 'lan' && !current.device.synthetic;
        const schedule = (delay = failures ? Math.min(MAX_BACKOFF_MS, POLL_MS * 2 ** failures) : POLL_MS) => {
            stopTimer();
            if (!mayPoll()) { setAutomaticState('off'); return; }
            setAutomaticState(failures ? 'backoff' : 'active');
            timer = window.setTimeout(() => { timer = undefined; void read(true); }, delay);
        };
        setSnapshot(null); setError(''); setRefreshing(false); setAccessEnded(false); setAutomaticState('off');
        const read = async (background = false) => {
            if (!alive || locked || pending) return;
            if (accessEpoch !== getProtectedRequestEpoch() || hasLogoutIntent()) { lock(); return; }
            if (background && !mayPoll()) return;
            if (hidden() || suspended) {
                if (!background) setError(getLocale() === 'de' ? 'Lesen pausiert. Im sichtbaren Fenster erneut versuchen.' : 'Read paused. Try again when this window is visible.');
                return;
            }
            // Existing metadata, inventory and session revalidation win. This is
            // a local timer only, never another overlapping network request.
            if (background && hasPendingAPIRequests()) { schedule(1000); return; }
            stopTimer();
            const controller = new AbortController(), epoch = getProtectedRequestEpoch(), started = capture();
            const active = () => {
                if (!alive || locked || controller.signal.aborted) return false;
                if (epoch !== getProtectedRequestEpoch() || hasLogoutIntent()) { lock(); return false; }
                if (background && !mayPoll()) return false;
                return true;
            };
            const failed = (message: string) => {
                failures = Math.min(failures + 1, 3); setError(message);
            };
            const timeoutMessage = () => t('Der Manager antwortet nicht. Erneut versuchen.');
            const timeout = () => { if (active()) { cancel(); setRefreshing(false); failed(timeoutMessage()); schedule(); } };
            setRefreshing(true); if (!background) setError('');
            pending = { controller, automatic: background, timeout: window.setTimeout(timeout, TIMEOUT_MS) };
            try {
                const value = await request<Device>(`/devices/${encodeURIComponent(id)}`, { signal: controller.signal }, 262144);
                if (!active()) return;
                if (hidden() || suspended) { suspend(); return; }
                if (elapsed(started) >= TIMEOUT_MS) { timeout(); return; }
                if (!value || value.id !== id) throw new APIError(t('Der Manager hat keine gültigen JSON-Daten zurückgegeben.'));
                failures = 0; setError('');
                // Current LAN replies include manager checkedAt. If an older
                // reply omits it, repeated GETs must not renew an unchanged
                // sample's fallback age either. Keep only three local anchors.
                const sampleAnchor = (key: MetricKey) => current?.device[key].collectedAt === value[key].collectedAt ? current.sampleAnchors[key] : started;
                current = { scope, epoch, device: value, checkedAt: new Date().toISOString(), anchor: started, sampleAnchors: { cpu: sampleAnchor('cpu'), memory: sampleAnchor('memory'), disk: sampleAnchor('disk') } };
                setSnapshot(current);
            } catch (caught) {
                if (!active()) return;
                if (caught instanceof APIError && caught.status === 401) { lock(); return; }
                // Access loss is terminal for automatic reads. Never retain the
                // previous private subtree or retry a denied/missing device.
                if (caught instanceof APIError && [403, 404, 410].includes(caught.status ?? 0)) { current = null; setSnapshot(null); }
                failed(caught instanceof Error ? caught.message : timeoutMessage());
            } finally {
                if (alive && pending?.controller === controller) {
                    window.clearTimeout(pending.timeout); pending = null; setRefreshing(false); schedule();
                }
            }
        };
        const suspend = () => {
            suspended = true; stopTimer(); setAutomaticState('off');
            if (!pending) return;
            const background = pending.automatic; cancel(); setRefreshing(false);
            if (!background) setError(getLocale() === 'de' ? 'Lesen unterbrochen. Erneut versuchen.' : 'Read interrupted. Try again.');
        };
        const resume = () => { if (!alive || locked || hidden()) return; suspended = false; schedule(); };
        const visibility = () => hidden() ? suspend() : resume();
        reconcileRef.current = () => {
            // Switching tabs stops the poll without remounting selected forms.
            if (!automaticRef.current && pending?.automatic) { cancel(); setRefreshing(false); }
            schedule();
        };
        refreshRef.current = () => { void read(); };
        window.addEventListener(AUTH_REQUIRED_EVENT, lock); window.addEventListener('pagehide', suspend); window.addEventListener('pageshow', resume);
        window.addEventListener('blur', suspend); window.addEventListener('focus', resume); document.addEventListener('visibilitychange', visibility);
        ageTimer = window.setInterval(() => {
            if (accessEpoch !== getProtectedRequestEpoch() || hasLogoutIntent()) { if (!locked) lock(); return; }
            if (mayPoll()) tick(value => value + 1);
        }, 1000);
        void read();
        return () => {
            alive = false; stopTimer(); cancel(); window.clearInterval(ageTimer); refreshRef.current = () => {}; reconcileRef.current = () => {};
            window.removeEventListener(AUTH_REQUIRED_EVENT, lock); window.removeEventListener('pagehide', suspend); window.removeEventListener('pageshow', resume);
            window.removeEventListener('blur', suspend); window.removeEventListener('focus', resume); document.removeEventListener('visibilitychange', visibility);
        };
    }, [id, scope]);
    useLayoutEffect(() => { reconcileRef.current(); }, [automatic, id, scope]);
    const visible = snapshot?.scope === scope && snapshot.epoch === getProtectedRequestEpoch() && !hasLogoutIntent() ? snapshot : null;
    let device = visible?.device ?? null;
    if (device && !device.synthetic && device.source === 'lan' && visible) {
        const age = elapsed(visible.anchor), managerNow = Date.parse(device.agentCertificate?.checkedAt ?? '');
        const metric = (key: MetricKey) => agedMetric(visible.device[key], managerNow, Number.isFinite(managerNow) ? age : elapsed(visible.sampleAnchors[key]));
        device = { ...device, cpu: metric('cpu'), memory: metric('memory'), disk: metric('disk') };
    }
    return { device, snapshot: visible, refreshing, accessEnded, error, automaticState, refresh: () => refreshRef.current() };
}
