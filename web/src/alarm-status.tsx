import { useEffect, useId, useRef, useState } from 'react';
import { Bell, BellOff, Check, ChevronDown, CircleHelp, Clock3, RefreshCw, TriangleAlert, XCircle } from 'lucide-react';
import { APIError, AUTH_REQUIRED_EVENT, getProtectedRequestEpoch, request } from './api';
import { hasLogoutIntent, LOGOUT_INTENT_KEY, useOperator } from './auth';
import { useLocale } from './i18n';
import { ALARM_STATUS_BYTES, validAlarmStatus } from './alarm-status-types';
import type { AlarmStatus } from './alarm-status-types';
import './alarm-status.css';

const copy = {
    en: {
        title: 'Alarm delivery', on: 'On', off: 'Off', unknown: 'Unknown', refresh: 'Refresh alarm status', loading: 'Loading alarm status…', details: 'Details',
        accepted: 'Provider accepted', pending: 'Pending', failed: 'Failed', uncertain: 'Uncertain', dropped: 'Dropped', queued: 'Queued', inFlight: 'In flight', suppressed: 'Suppressed',
        error: 'Alarm status could not be confirmed. Refresh to try again.', invalid: 'The manager returned an unsupported alarm status. Refresh to try again.', timeout: 'The manager did not respond in time. Refresh to try again.',
        session: 'Your session has ended. Sign in again.', paused: 'Refresh alarm status to load a new snapshot.', previous: 'Previous snapshot', loaded: 'Loaded', configuration: 'Delivery in this snapshot',
        acceptance: 'Provider acceptance does not confirm receipt by a person.',
        scope: 'Retained totals combine opening and recovery events, including previous destinations. Explicit synthetic tests are also counted. They are not complete delivery history or per-event confirmation.',
        pendingNote: 'Pending is queued plus in flight. Queued events are waiting; in-flight events have no recorded outcome yet.',
        failedNote: 'Failed events ended without provider acceptance. Uncertain events may have been accepted; they are not automatically replayed.',
        suppressedNote: 'Suppressed events are no longer eligible to send. Dropped is a separate durable count of events that could not be queued at capacity, not a retained state or successful delivery.',
        disabled: 'Delivery is disabled in manager configuration. Retained counts, if any, remain visible.',
        snapshot: 'Snapshot only. Loaded time uses this browser’s clock, not an event or server observation time. Refresh reads the manager’s saved counts.',
    },
    de: {
        title: 'Alarmversand', on: 'Ein', off: 'Aus', unknown: 'Unbekannt', refresh: 'Alarmstatus aktualisieren', loading: 'Alarmstatus wird geladen…', details: 'Details',
        accepted: 'Vom Anbieter angenommen', pending: 'Ausstehend', failed: 'Fehlgeschlagen', uncertain: 'Ungewiss', dropped: 'Verworfen', queued: 'Warteschlange', inFlight: 'In Übertragung', suppressed: 'Unterdrückt',
        error: 'Der Alarmstatus konnte nicht bestätigt werden. Zum Wiederholen aktualisieren.', invalid: 'Der Manager lieferte einen nicht unterstützten Alarmstatus. Zum Wiederholen aktualisieren.', timeout: 'Der Manager hat nicht rechtzeitig geantwortet. Zum Wiederholen aktualisieren.',
        session: 'Die Sitzung ist beendet. Erneut anmelden.', paused: 'Alarmstatus aktualisieren, um einen neuen Stand zu laden.', previous: 'Vorheriger Stand', loaded: 'Geladen', configuration: 'Versand in diesem Stand',
        acceptance: 'Die Annahme durch den Anbieter bestätigt keinen Empfang durch eine Person.',
        scope: 'Gespeicherte Summen umfassen Beginn- und Erholungsereignisse sowie frühere Ziele. Explizite synthetische Tests werden ebenfalls gezählt. Sie sind weder ein vollständiger Versandverlauf noch eine Bestätigung einzelner Ereignisse.',
        pendingNote: 'Ausstehend umfasst Warteschlange und laufende Übertragungen. Ereignisse in der Warteschlange warten auf ihren nächsten Versuch; bei laufenden Übertragungen fehlt das Ergebnis.',
        failedNote: 'Fehlgeschlagene Ereignisse endeten ohne Anbieterannahme. Ungewisse Ereignisse können angenommen worden sein und werden nicht automatisch wiederholt.',
        suppressedNote: 'Unterdrückte Ereignisse werden nicht mehr zum Versand freigegeben. Verworfen zählt separat und dauerhaft Ereignisse, die bei erreichter Kapazität nicht eingereiht werden konnten, keinen gespeicherten Zustand oder erfolgreichen Versand.',
        disabled: 'Der Versand ist in der Manager-Konfiguration deaktiviert. Vorhandene gespeicherte Zähler bleiben sichtbar.',
        snapshot: 'Ein geladener Stand. Die Ladezeit stammt aus der Browser-Uhr, nicht vom Ereignis oder einer Manager-Beobachtung. Aktualisieren liest die gespeicherten Zähler des Managers.',
    },
};
type Failure = 'error' | 'invalid' | 'timeout' | 'session' | 'paused';
type Snapshot = { view: AlarmStatus; loadedAt: string; epoch: number };
function useAlarmStatus() {
    const [snapshot, setSnapshot] = useState<Snapshot | null>(null), [loading, setLoading] = useState(false), [locked, setLocked] = useState(false);
    const [failure, setFailure] = useState<Failure | null>(null), refresh = useRef<() => void>(() => {});
    useEffect(() => {
        let alive = true, ended = false, suspended = document.visibilityState === 'hidden';
        let pending: { controller: AbortController; timeout: number } | null = null;
        const epoch = getProtectedRequestEpoch();
        const hidden = () => document.visibilityState === 'hidden';
        const cancel = () => { pending?.controller.abort(); window.clearTimeout(pending?.timeout); pending = null; };
        const lock = () => { if (!alive) return; ended = true; cancel(); setSnapshot(null); setLoading(false); setLocked(true); setFailure('session'); };
        const authorized = () => {
            if (!alive || ended) return false;
            if (epoch !== getProtectedRequestEpoch() || hasLogoutIntent()) { lock(); return false; }
            return true;
        };
        const suspend = () => { suspended = true; cancel(); setSnapshot(null); setLoading(false); setFailure('paused'); };
        const read = async () => {
            if (!authorized() || pending || suspended || document.visibilityState === 'hidden') return;
            const controller = new AbortController(), mono = performance.now(), wall = Date.now();
            const active = () => alive && !controller.signal.aborted && authorized() && pending?.controller === controller;
            const fail = (reason: Failure) => { cancel(); setLoading(false); setFailure(reason); };
            pending = { controller, timeout: window.setTimeout(() => { if (active()) fail('timeout'); }, 10000) };
            setLoading(true); setFailure(null);
            try {
                const value = await request<unknown>('/alerts/status', { signal: controller.signal, cache: 'no-store' }, ALARM_STATUS_BYTES);
                if (!active()) return;
                if (suspended || hidden()) { suspend(); return; }
                const elapsed = performance.now() - mono;
                if (elapsed < 0 || elapsed >= 10000 || Math.abs(Date.now() - wall - elapsed) > 1500) { fail('timeout'); return; }
                if (!validAlarmStatus(value)) { fail('invalid'); return; }
                setSnapshot({ view: value, loadedAt: new Date().toISOString(), epoch });
            } catch (error) {
                if (!active()) return;
                if (error instanceof APIError && [401, 403].includes(error.status ?? 0)) { lock(); return; }
                setFailure('error');
            } finally {
                if (alive && pending?.controller === controller) { window.clearTimeout(pending.timeout); pending = null; setLoading(false); }
            }
        };
        // Restore never retries a failed read or reuses a suspended snapshot.
        const resume = () => { if (!authorized() || document.visibilityState === 'hidden') return; suspended = false; };
        const visibility = () => document.visibilityState === 'hidden' ? suspend() : resume();
        const navigate = () => { cancel(); setSnapshot(null); setLoading(false); setFailure('paused'); };
        const storage = (event: StorageEvent) => { if ((event.key === LOGOUT_INTENT_KEY || event.key === null) && hasLogoutIntent()) lock(); };
        refresh.current = () => { void read(); };
        window.addEventListener(AUTH_REQUIRED_EVENT, lock); window.addEventListener('pagehide', suspend); window.addEventListener('pageshow', resume);
        window.addEventListener('hashchange', navigate); window.addEventListener('storage', storage); document.addEventListener('visibilitychange', visibility);
        // No network polling: only clear visible private data if access is revoked.
        const guard = window.setInterval(authorized, 1000);
        void read();
        return () => {
            alive = false; cancel(); window.clearInterval(guard); refresh.current = () => {};
            window.removeEventListener(AUTH_REQUIRED_EVENT, lock); window.removeEventListener('pagehide', suspend); window.removeEventListener('pageshow', resume);
            window.removeEventListener('hashchange', navigate); window.removeEventListener('storage', storage); document.removeEventListener('visibilitychange', visibility);
        };
    }, []);
    return { snapshot: snapshot?.epoch === getProtectedRequestEpoch() && !hasLogoutIntent() ? snapshot : null, loading, locked, failure, refresh: () => refresh.current() };
}
function AlarmStatusContent() {
    const [locale] = useLocale(), labels = copy[locale], heading = useId();
    const { snapshot, loading, locked, failure, refresh } = useAlarmStatus();
    const view = snapshot?.view, previous = !!view && (loading || failure !== null);
    const showCounts = !!view && (view.enabled || Object.values(view).some(value => typeof value === 'number' && value > 0));
    const count = (value: number) => new Intl.NumberFormat(locale).format(value);
    return <section className="panel alarm-status" aria-labelledby={heading}>
        <div className="alarm-status-heading"><h2 id={heading}><Bell size={16} aria-hidden="true"/>{labels.title}</h2>
            <span className="alarm-mode">{!view || previous ? <><CircleHelp size={14} aria-hidden="true"/>{labels.unknown}</> : view.enabled ? <><Bell size={14} aria-hidden="true"/>{labels.on}</> : <><BellOff size={14} aria-hidden="true"/>{labels.off}</>}</span>
            <button className="icon-button" onClick={refresh} disabled={loading || locked} aria-label={labels.refresh} title={labels.refresh}><RefreshCw size={15} className={loading ? 'spin' : ''} aria-hidden="true"/></button>
        </div>
        {failure && <p className="alarm-notice" role={failure === 'paused' ? 'status' : 'alert'}>{labels[failure]}</p>}
        {loading && !view && <p className="alarm-notice" role="status">{labels.loading}</p>}
        {snapshot && <p className="alarm-snapshot">{previous && <strong>{labels.previous} · </strong>}{labels.loaded} <time dateTime={snapshot.loadedAt}>{new Intl.DateTimeFormat(locale === 'de' ? 'de-DE' : 'en-GB', { dateStyle: 'short', timeStyle: 'medium', timeZone: 'UTC' }).format(new Date(snapshot.loadedAt))} UTC</time></p>}
        {showCounts && view && <><dl className={`alarm-counts${previous ? ' alarm-previous' : ''}`}>
            <div><dt><Check size={14} aria-hidden="true"/>{labels.accepted}</dt><dd>{count(view.providerAccepted)}</dd></div>
            <div><dt><Clock3 size={14} aria-hidden="true"/>{labels.pending}</dt><dd>{count(view.queued + view.inFlight)}</dd></div>
            <div className={view.failed ? 'alarm-failed' : ''}><dt><XCircle size={14} aria-hidden="true"/>{labels.failed}</dt><dd>{count(view.failed)}</dd></div>
            <div className={view.uncertain ? 'alarm-uncertain' : ''}><dt><CircleHelp size={14} aria-hidden="true"/>{labels.uncertain}</dt><dd>{count(view.uncertain)}</dd></div>
            {view.dropped > 0 && <div className="alarm-failed"><dt><TriangleAlert size={14} aria-hidden="true"/>{labels.dropped}</dt><dd>{count(view.dropped)}</dd></div>}
        </dl><p className="alarm-acceptance">{labels.acceptance}</p></>}
        <details className="alarm-details"><summary>{labels.details}<ChevronDown size={14} aria-hidden="true"/></summary><div>
            {view && <><dl className="alarm-breakdown"><div><dt>{labels.configuration}</dt><dd>{view.enabled ? labels.on : labels.off}</dd></div>{(['queued', 'inFlight', 'suppressed', 'dropped'] as const).map(key => <div key={key}><dt>{labels[key]}</dt><dd>{count(view[key])}</dd></div>)}</dl>{!view.enabled && <p>{labels.disabled}</p>}</>}
            <p>{labels.scope}</p><p>{labels.pendingNote}</p><p>{labels.failedNote}</p><p>{labels.suppressedNote}</p><p>{labels.acceptance}</p><p>{labels.snapshot}</p>
        </div></details>
    </section>;
}
export function AlarmStatusPanel() {
    const operator = useOperator();
    if (!operator || operator.mode !== 'lan' || !operator.authenticated) return null;
    return <AlarmStatusContent key={`${operator.actorId ?? ''}:${operator.expiresAt ?? ''}`}/>;
}
