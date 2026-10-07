import { useEffect, useRef, useState } from 'react';
import { Check, ChevronDown, CircleHelp, Clock3, Info, RefreshCw, TriangleAlert } from 'lucide-react';
import { APIError, AUTH_REQUIRED_EVENT, getProtectedRequestEpoch, request } from './api';
import { hasLogoutIntent, useOperator } from './auth';
import { useLocale } from './i18n';
import { fullDate } from './utils';
import { readJournal } from './journal-api';
import { validJournalView } from './journal-types';
import { validSystemView, SYSTEM_STATUS_BYTES } from './system-inventory-types';
import { validOverviewView, OVERVIEW_STATUS_BYTES } from './complete-overview-types';
import { inventoryAge, validCompletePackageView, COMPLETE_STATUS_BYTES } from './complete-packages-types';
import { basicCapability, journalCapability, overviewCapability, packageCapability, socketOwnerCapability, systemCapability } from './capability-observations';
import type { CapabilityObservation, CapabilityState } from './capability-observations';
import type { Device } from './types';
import type { SystemView } from './system-inventory-types';
import type { OverviewView } from './complete-overview-types';
import type { CompletePackageView } from './complete-packages-types';
import type { JournalView } from './journal-types';
import './device-capabilities.css';

type Sources = { system: SystemView; overview: OverviewView; packages: CompletePackageView; journal: JournalView };
type Source = keyof Sources;
type Anchor = { mono: number; wall: number };
type SourceSnapshot = { [K in Source]?: { value?: Sources[K]; error?: string; anchor: Anchor; offset?: number } };
const capture = (): Anchor => ({ mono: performance.now(), wall: Date.now() });
const elapsed = (a: Anchor) => { const m = performance.now() - a.mono, w = Date.now() - a.wall; return m >= 0 && Number.isFinite(m) && Math.abs(w - m) <= 1500 ? m : Infinity; };
type TimeEvidence = { scope: string; times: Map<Source, { serverNow: string; anchor: Anchor; offset: number }>; sessionDeadline: number };
const sourceFor: Record<string, Source> = { systemd: 'system', socket_inventory: 'system', socket_owner_metadata: 'system', complete_process_inventory: 'overview', complete_mount_inventory: 'overview', package_inventory: 'packages', journal_content: 'journal' };
const warning = (state: CapabilityState) => ['denied', 'failed', 'not_configured', 'stale', 'partial'].includes(state);
const labels: Record<'en' | 'de', Record<CapabilityState, string>> = {
    en: { supported: 'Supported', available: 'Collected', scope: 'Profile scope', unsupported: 'Unavailable', denied: 'Permission denied', failed: 'Failed', not_configured: 'Not configured', stale: 'Stale', unknown: 'Unknown', pending: 'Pending', partial: 'Incomplete fields', configured: 'Configured' },
    de: { supported: 'Unterstützt', available: 'Erfasst', scope: 'Profilumfang', unsupported: 'Nicht verfügbar', denied: 'Zugriff verweigert', failed: 'Fehlgeschlagen', not_configured: 'Nicht eingerichtet', stale: 'Veraltet', unknown: 'Unbekannt', pending: 'Ausstehend', partial: 'Unvollständige Felder', configured: 'Eingerichtet' },
};

/** Bounded status reads only. Never starts a capture, reads journal bodies,
 * queries inventory rows, changes a grant, or infers access from root setup. */
export function DeviceCapabilities({ device }: { device: Device }) {
    const operator = useOperator(), [locale] = useLocale(), [snapshots, setSnapshots] = useState<SourceSnapshot>({}), [loading, setLoading] = useState(false), [locked, setLocked] = useState(false), [revision, setRevision] = useState(0), [, tick] = useState(0);
    const completeProfile = device.capabilities.some(c => ['socket_inventory', 'package_inventory', 'complete_process_inventory', 'complete_mount_inventory'].includes(c.id) && c.status === 'scope');
    const ids = device.capabilities.filter(c => c.status === 'scope' && sourceFor[c.id] && (c.id !== 'systemd' || completeProfile)).map(c => c.id).sort().join(',');
    const enabled = device.source === 'lan' && !device.synthetic && operator?.mode === 'lan' && operator.authenticated;
    const sessionKey = operator?.expiresAt ?? null, insecure = operator?.insecureTestMode ?? false;
    const ageEvidence = useRef<TimeEvidence | null>(null);
    const ageScope = JSON.stringify([device.id, enabled, ids, sessionKey, insecure]);
    useEffect(() => {
        // Explicit refresh restarts the read, never the source/session clock.
        if (ageEvidence.current?.scope !== ageScope) ageEvidence.current = { scope: ageScope, times: new Map(), sessionDeadline: Infinity };
        const evidence = ageEvidence.current;
        let alive = true, stopped = false, suspended = document.visibilityState === 'hidden', pending: AbortController | null = null;
        let timer: number | undefined, timeout: number | undefined;
        const scopeEpoch = getProtectedRequestEpoch();
        const times = evidence.times;
        const wanted = [...new Set(ids.split(',').map(id => sourceFor[id]).filter(Boolean))];
        setSnapshots({}); setLocked(false); setLoading(false);
        const cancel = () => { pending?.abort(); pending = null; window.clearTimeout(timeout); window.clearTimeout(timer); };
        const lock = () => { stopped = true; cancel(); setSnapshots({}); setLocked(true); setLoading(false); };
        const read = async () => {
            if (!alive || stopped || suspended || pending || !enabled || !wanted.length || document.visibilityState === 'hidden') return;
            if (hasLogoutIntent() || scopeEpoch !== getProtectedRequestEpoch() || performance.now() >= evidence.sessionDeadline) { lock(); return; }
            const controller = new AbortController(); pending = controller; setLoading(true);
            const active = () => alive && !stopped && !suspended && !controller.signal.aborted && !hasLogoutIntent() && scopeEpoch === getProtectedRequestEpoch();
            timeout = window.setTimeout(() => { if (!active()) return; controller.abort(); for (const key of wanted) setSnapshots(previous => ({ ...previous, [key]: { error: 'timeout', anchor: capture() } })); pending = null; setLoading(false); timer = window.setTimeout(read, 15000); }, 10000);
            for (const key of wanted) {
                if (!active()) break;
                const anchor = capture();
                try {
                    const base = `/devices/${encodeURIComponent(device.id)}`;
                    const value = key === 'journal' ? await readJournal(device.id, controller.signal, insecure, sessionKey) : await request<unknown>(`${base}/inventory/${key}`, { signal: controller.signal }, key === 'system' ? SYSTEM_STATUS_BYTES : key === 'overview' ? OVERVIEW_STATUS_BYTES : COMPLETE_STATUS_BYTES);
                    if (!active()) break;
                    const valid = key === 'system' ? validSystemView(value, device.id) : key === 'overview' ? validOverviewView(value, device.id) : key === 'packages' ? validCompletePackageView(value, device.id) : validJournalView(value, device.id);
                    if (!valid || !Number.isFinite(elapsed(anchor))) throw new Error('invalid_status');
                    const serverNow = (value as Sources[Source]).serverNow, prior = times.get(key);
                    const advance = prior ? inventoryAge(serverNow, prior.serverNow) : 0;
                    if (advance < 0) throw new Error('invalid_status');
                    const offset = prior ? Math.max(0, elapsed(prior.anchor) + prior.offset - advance - elapsed(anchor)) : 0;
                    if (!Number.isFinite(offset)) throw new Error('invalid_status');
                    if (sessionKey) {
                        const left = inventoryAge(sessionKey, serverNow) - offset;
                        if (!Number.isFinite(left) || left <= elapsed(anchor)) { lock(); break; }
                        evidence.sessionDeadline = Math.min(evidence.sessionDeadline, anchor.mono + left);
                    }
                    times.set(key, { serverNow, anchor, offset });
                    setSnapshots(previous => ({ ...previous, [key]: { value, anchor, offset } }));
                } catch (error) {
                    if (!active()) break;
                    if (error instanceof APIError && error.status === 401) { lock(); break; }
                    setSnapshots(previous => ({ ...previous, [key]: { error: error instanceof APIError && error.status === 403 ? 'operator_access_denied' : error instanceof Error && error.message === 'invalid_status' ? 'invalid_status' : 'status_unavailable', anchor } }));
                }
            }
            if (pending === controller) { window.clearTimeout(timeout); pending = null; if (alive) setLoading(false); if (active()) timer = window.setTimeout(read, 15000); }
        };
        const suspend = () => { suspended = true; cancel(); setSnapshots({}); setLoading(false); };
        const resume = () => { if (!alive || stopped || document.visibilityState === 'hidden') return; suspended = false; void read(); };
        const visibility = () => document.visibilityState === 'hidden' ? suspend() : resume();
        window.addEventListener(AUTH_REQUIRED_EVENT, lock); window.addEventListener('blur', suspend); window.addEventListener('focus', resume); window.addEventListener('pagehide', suspend); window.addEventListener('pageshow', resume); document.addEventListener('visibilitychange', visibility);
        const ageTimer = window.setInterval(() => { if (hasLogoutIntent() || scopeEpoch !== getProtectedRequestEpoch() || performance.now() >= evidence.sessionDeadline) { if (!stopped) lock(); } else if (!suspended) tick(n => n + 1); }, 1000);
        void read();
        return () => { alive = false; cancel(); window.clearInterval(ageTimer); window.removeEventListener(AUTH_REQUIRED_EVENT, lock); window.removeEventListener('blur', suspend); window.removeEventListener('focus', resume); window.removeEventListener('pagehide', suspend); window.removeEventListener('pageshow', resume); document.removeEventListener('visibilitychange', visibility); };
    }, [device.id, enabled, ids, sessionKey, insecure, revision, ageScope]);
    const observation = (id: string): CapabilityObservation | null => {
        const source = sourceFor[id], snapshot = source && snapshots[source];
        if (!snapshot) return null;
        if (snapshot.error) return { state: snapshot.error === 'operator_access_denied' ? 'denied' : 'unknown', reason: snapshot.error };
        const age = elapsed(snapshot.anchor) + (snapshot.offset ?? 0);
        if (source === 'system' && id === 'socket_owner_metadata') return socketOwnerCapability(snapshot.value as SystemView, age);
        if (source === 'system') return systemCapability(snapshot.value as SystemView, id === 'systemd' ? 'services' : 'sockets', age);
        if (source === 'overview') return overviewCapability(snapshot.value as OverviewView, id === 'complete_process_inventory' ? 'processes' : 'volumes', age);
        if (source === 'packages') return packageCapability(snapshot.value as CompletePackageView, age);
        return journalCapability(snapshot.value as JournalView, age);
    };
    return <><div className="capability-heading"><div><h3>{locale === 'de' ? 'Erfassungsstatus' : 'Collection status'}</h3><p>{locale === 'de' ? 'Quellstatus und Profilumfang getrennt.' : 'Source status and profile scope shown separately.'}</p></div>{enabled && ids && <button className="button small" disabled={loading || locked} onClick={() => setRevision(n => n + 1)}><RefreshCw size={14}/>{locale === 'de' ? 'Status prüfen' : 'Check status'}</button>}</div>{locked && <p role="alert">{locale === 'de' ? 'Sitzung beendet. Erneut anmelden.' : 'Session ended. Sign in again.'}</p>}<div className="device-capabilities capability-observations">{device.capabilities.map(capability => {
        const result = capability.status === 'scope' && ids.split(',').includes(capability.id) ? observation(capability.id) ?? { state: 'unknown' as const } : basicCapability(capability, device);
        const tone = warning(result.state) ? 'attention' : ['supported', 'available'].includes(result.state) ? 'observed' : 'neutral';
        return <div key={capability.id} data-capability={capability.id} data-state={result.state} className={`capability-row ${tone}`}><span className={`capability-icon ${tone}`} aria-hidden="true">{tone === 'attention' ? <TriangleAlert size={16}/> : tone === 'observed' ? <Check size={16}/> : result.state === 'unknown' ? <CircleHelp size={16}/> : result.state === 'pending' ? <Clock3 size={16}/> : <Info size={16}/>}</span><div><strong>{capability.name}</strong>{result.at && <p className="capability-observed-at">{locale === 'de' ? 'Erfasst: ' : 'Observed: '}<time dateTime={result.at}>{fullDate(result.at)}</time></p>}<details><summary>{locale === 'de' ? 'Quelle & Details' : 'Source & details'}<ChevronDown size={12}/></summary><p>{capability.detail}</p>{result.reason && <p className="capability-reason">{result.reason}</p>}{capability.id === 'socket_inventory' && <p>{locale === 'de' ? 'Prozesszuordnung wird je Verbindung angezeigt.' : 'Process attribution is shown per connection.'}</p>}{capability.id === 'journal_content' && <p>{locale === 'de' ? 'Eingerichtet bestätigt die gemeldete Helferkonfiguration. Ein erfolgreicher Logabruf wird im Logs-Bereich belegt.' : 'Configured confirms reported helper configuration. Successful log reads are shown in Logs.'}</p>}</details></div><span className={`capability-state ${tone}`}>{labels[locale][result.state]}</span></div>;
    })}</div>{enabled && ids && <p className="capability-refresh-note">{locale === 'de' ? 'Prüfung alle 15 s im sichtbaren Fenster; ursprüngliche Erfassungszeiten bleiben.' : 'Checked every 15 s while visible; original capture times preserved.'}</p>}</>;
}
