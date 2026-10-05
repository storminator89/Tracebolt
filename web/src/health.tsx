import { useEffect, useId, useRef, useState } from 'react';
import { RefreshCw } from 'lucide-react';
import { APIError, AUTH_REQUIRED_EVENT, getProtectedRequestEpoch, mutate, request } from './api';
import { hasLogoutIntent } from './auth';
import { t, useLocale } from './i18n';
import { fullDate } from './utils';
import { HEALTH_VIEW_BYTES, parseHealthServices, validHealthDeviceId, validHealthView } from './health-types';
import { validJournalUnit } from './journal-types';
import { HealthServicePicker } from './health-service-picker';
import type { HealthKind, HealthView } from './health-types';
import './health.css';

type Failure = 'load' | 'change' | 'invalid' | 'session' | 'timeout' | 'interrupted' | 'clock';
type Action = 'acknowledge' | 'maintenance' | 'services';
type Commands = { refresh: () => void; change: (action: Action, body: unknown) => Promise<boolean> };
const emptyCommands: Commands = { refresh: () => {}, change: async () => false };
type Anchor = { mono: number; wall: number };
const capture = (): Anchor => ({ mono: performance.now(), wall: Date.now() });
function elapsed(anchor: Anchor): number {
    const mono = performance.now() - anchor.mono, wall = Date.now() - anchor.wall;
    return Number.isFinite(mono) && mono >= 0 && Math.abs(wall - mono) <= 1500 ? mono : Infinity;
}
export function useHealth(deviceId: string, sessionKey: string | null, autoRefresh = true) {
    const scope = JSON.stringify([deviceId, sessionKey]);
    const [snapshot, setSnapshot] = useState<{ scope: string; epoch: number; view: HealthView } | null>(null);
    const [pending, setPending] = useState(false), [failure, setFailure] = useState<Failure | null>(null), [locked, setLocked] = useState(false);
    const commands = useRef<Commands>(emptyCommands);
    useEffect(() => {
        let alive = true, accessEnded = false, suspended = document.visibilityState === 'hidden', revision = 0;
        let operation: { controller: AbortController; timer: number; started: Anchor; mutation: boolean } | null = null;
        let observed: Anchor | null = null, latestServer: string | null = null, currentView: HealthView | null = null;
        const accessEpoch = getProtectedRequestEpoch();
        const cancel = () => { revision++; operation?.controller.abort(); window.clearTimeout(operation?.timer); operation = null; if (alive) setPending(false); };
        const clear = (error: Failure | null) => { cancel(); observed = null; currentView = null; if (alive) { setSnapshot(null); setFailure(error); } };
        const lock = () => { accessEnded = true; clear('session'); if (alive) setLocked(true); };
        const run = async (action?: Action, body?: unknown): Promise<boolean> => {
            if (!alive || accessEnded || suspended || document.visibilityState === 'hidden' || operation) return false;
            if (accessEpoch !== getProtectedRequestEpoch() || hasLogoutIntent()) { lock(); return false; }
            if (!validHealthDeviceId(deviceId)) { clear('invalid'); return false; }
            const controller = new AbortController(), started = capture(), serial = ++revision, deadline = action ? 15000 : 10000;
            setPending(true); setFailure(null);
            // Keep a bounded, visibly refreshing snapshot so polling does not destroy form focus.
            if (action) { setSnapshot(null); observed = null; currentView = null; }
            operation = { controller, started, mutation: Boolean(action), timer: window.setTimeout(() => { if (serial === revision) clear(action ? 'change' : 'timeout'); }, deadline) };
            const active = () => {
                if (!alive || suspended || accessEnded || serial !== revision || controller.signal.aborted) return false;
                if (accessEpoch !== getProtectedRequestEpoch() || hasLogoutIntent()) { lock(); return false; }
                if (!Number.isFinite(elapsed(started))) { clear(action ? 'change' : 'clock'); return false; }
                if (elapsed(started) >= deadline) { clear(action ? 'change' : 'timeout'); return false; }
                return true;
            };
            try {
                const path = `/devices/${encodeURIComponent(deviceId)}/health`;
                const value = action ? await mutate<unknown>(`${path}/${action}`, body, controller.signal) : await request<unknown>(path, { signal: controller.signal }, HEALTH_VIEW_BYTES);
                if (!active()) return false;
                if (!validHealthView(value, deviceId)) { clear(action ? 'change' : 'invalid'); return false; }
                if (latestServer && Date.parse(value.serverNow) < Date.parse(latestServer)) { clear(action ? 'change' : 'clock'); return false; }
                latestServer = value.serverNow; observed = started; currentView = value;
                setSnapshot({ scope, epoch: accessEpoch, view: value });
                return true;
            } catch (caught) {
                if (!active()) return false;
                if (caught instanceof APIError && caught.status === 401) lock();
                else clear(action ? 'change' : 'load');
                return false;
            } finally {
                if (alive && operation?.controller === controller) { window.clearTimeout(operation.timer); operation = null; setPending(false); }
            }
        };
        const suspend = () => { const mutation = operation?.mutation; suspended = true; clear(mutation ? 'change' : 'interrupted'); };
        const restore = () => { if (accessEnded || document.visibilityState === 'hidden') return; suspended = false; if (autoRefresh) void run(); };
        const visibility = () => document.visibilityState === 'hidden' ? suspend() : restore();
        const show = (event: PageTransitionEvent) => { if (event.persisted || suspended) restore(); };
        commands.current = { refresh: () => { void run(); }, change: run };
        setLocked(false); setSnapshot(null); setFailure(null); setPending(false);
        window.addEventListener(AUTH_REQUIRED_EVENT, lock); window.addEventListener('pagehide', suspend); window.addEventListener('pageshow', show);
        window.addEventListener('blur', suspend); window.addEventListener('focus', restore); window.addEventListener('hashchange', suspend); document.addEventListener('visibilitychange', visibility);
        const poll = autoRefresh ? window.setInterval(() => { void run(); }, 30000) : undefined;
        const timer = window.setInterval(() => {
            if (accessEpoch !== getProtectedRequestEpoch() || hasLogoutIntent()) { if (!accessEnded) lock(); return; }
            const anchor = observed ?? operation?.started;
            if (anchor && !Number.isFinite(elapsed(anchor))) { clear(operation?.mutation ? 'change' : 'clock'); return; }
            if (observed && elapsed(observed) > 45000) { clear('load'); return; }
            if (observed && currentView) {
                // Original source age continues advancing between reads. An old
                // successful response must not look current until the next poll.
                const now = Date.parse(currentView.serverNow) + elapsed(observed);
                if (currentView.maintenanceUntil && Date.parse(currentView.maintenanceUntil) <= now) { clear(null); if (autoRefresh) void run(); return; }
                const evaluationExpired = currentView.evaluatedAt === null || now - Date.parse(currentView.evaluatedAt) > 120000;
                const checks = currentView.checks.map(check => {
                    const agesOut = check.kind !== 'offline' || check.state === 'ok';
                    return check.state !== 'unknown' && (evaluationExpired || agesOut && check.observedAt !== null && now - Date.parse(check.observedAt) > 120000)
                        ? { ...check, state: 'unknown' as const, value: null } : check;
                });
                if (checks.some((check, i) => check !== currentView!.checks[i])) {
                    const status = currentView.status === 'maintenance' ? 'maintenance' : checks.some(c => c.state === 'open' || c.state === 'pending') ? 'attention' : checks.some(c => c.state === 'unknown') ? 'unknown' : 'clear';
                    currentView = { ...currentView, checks, status }; setSnapshot({ scope, epoch: accessEpoch, view: currentView });
                }
            }
        }, 1000);
        void run();
        return () => {
            alive = false; cancel(); commands.current = emptyCommands;
            window.clearInterval(poll); window.clearInterval(timer);
            window.removeEventListener(AUTH_REQUIRED_EVENT, lock); window.removeEventListener('pagehide', suspend); window.removeEventListener('pageshow', show);
            window.removeEventListener('blur', suspend); window.removeEventListener('focus', restore); window.removeEventListener('hashchange', suspend); document.removeEventListener('visibilitychange', visibility);
        };
    }, [deviceId, scope, autoRefresh]);
    const view = snapshot?.scope === scope && snapshot.epoch === getProtectedRequestEpoch() && !hasLogoutIntent() ? snapshot.view : null;
    return { view, pending, failure, locked, refresh: () => commands.current.refresh(), change: (action: Action, body: unknown) => commands.current.change(action, body) };
}
function label(kind: HealthKind, target: string): string {
    return kind === 'offline' ? t('Agent-Kontakt') : kind === 'filesystem' ? t('Root-Dateisystem /') : target;
}
function Time({ value }: { value: string | null }) { return value ? <time dateTime={value} title={value}>{fullDate(value)}</time> : <span>{t('Zeitpunkt unbekannt')}</span>; }
function errorText(failure: Failure): string {
    switch (failure) {
        case 'change': return t('Änderung nicht bestätigt. Sie kann bereits gespeichert sein. Vor einem weiteren Versuch aktualisieren.');
        case 'invalid': return t('Die Health-Antwort ist unvollständig oder nicht unterstützt. Keine aktuellen Prüfwerte verfügbar.');
        case 'session': return t('Die Sitzung ist abgelaufen. Bitte erneut anmelden.');
        case 'timeout': return t('Der Manager antwortet nicht. Erneut versuchen.');
        case 'interrupted': return t('Health-Abfrage unterbrochen. Ansicht aktualisieren.');
        case 'clock': return t('Zeitbezug geändert. Keine aktuellen Prüfwerte verfügbar. Erneut aktualisieren.');
        default: return t('Health-Daten konnten nicht gelesen werden. Keine aktuellen Prüfwerte verfügbar.');
    }
}
export function HealthPanel({ deviceId, sessionKey = null, onOpenLogs }: { deviceId: string; sessionKey?: string | null; onOpenLogs?: (unit: string) => void }) {
    const [locale] = useLocale();
    const resource = useHealth(deviceId, sessionKey), view = resource.view, uid = useId();
    const [minutes, setMinutes] = useState<0 | 15 | 60 | 240>(60), [draft, setDraft] = useState<string[]>([]), [dirty, setDirty] = useState(false);
    const services = parseHealthServices(draft.join('\n')), configured = view?.monitoredServices.join('\n');
    useEffect(() => { setDraft([]); setDirty(false); setMinutes(60); }, [deviceId, sessionKey]);
    useEffect(() => { if (!dirty && configured !== undefined) setDraft(configured ? configured.split('\n') : []); }, [configured, dirty]);
    const disabled = resource.pending || resource.locked || !view;
    const saveServices = async () => { if (services === null || disabled) return; if (await resource.change('services', { services })) setDirty(false); };
    return <section className="health-panel" aria-labelledby={`${uid}-heading`}>
        <header className="health-heading"><h2 id={`${uid}-heading`}>{t('Health & Verlauf')}</h2><button type="button" className="button small" disabled={resource.pending || resource.locked} onClick={resource.refresh}><RefreshCw size={14} className={resource.pending ? 'spin' : undefined}/>{t('Health aktualisieren')}</button></header>
        <p className="health-note">{t('Agent-Kontakt · Root-Dateisystem / · ausgewählte Dienste')}</p>
        {resource.pending && <p className="health-note" role="status">{t('Health-Daten werden geprüft …')}</p>}
        {resource.failure && <p className="health-failure" role="alert">{errorText(resource.failure)}</p>}
        {view && <>
            <p className={`health-summary health-status-${view.status}`}>{view.status === 'attention' ? t('Ausgewählte Prüfungen benötigen Aufmerksamkeit.') : view.status === 'clear' ? t('Keine offenen Warnungen für die ausgewählten Prüfungen.') : view.status === 'maintenance' ? t('Wartungsfenster aktiv.') : t('Ausgewählte Prüfungen sind nicht vollständig bewertbar.')}</p>
            <p className="health-note">{t('Zuletzt ausgewertet:')} <Time value={view.evaluatedAt}/></p>
            <h3>{t('Aktuelle Prüfungen')}</h3><ul className="health-checks" aria-label={t('Aktuelle Prüfungen')}>{view.checks.map(check => <li key={check.key}>
                <div className="health-check-line"><strong>{label(check.kind, check.target)}</strong><span className={`health-state health-state-${check.state}`}>{check.state === 'ok' ? t('Schwelle nicht verletzt') : check.state === 'open' ? t('Warnung offen') : check.state === 'pending' ? t('Bestätigung ausstehend') : t('Unbekannt')}</span></div>
                <p className="health-note">{check.state !== 'unknown' && check.kind === 'filesystem' && check.value !== null && <>{check.value.toFixed(1)}{t('% belegt · ')}</>}{t('Beobachtet:')} <Time value={check.observedAt}/></p>
                {check.kind === 'service' && onOpenLogs && validJournalUnit(check.target) && <button type="button" className="text-button service-logs-link" aria-label={`${locale === 'de' ? 'Logs öffnen' : 'Open logs'}: ${check.target}`} onClick={() => onOpenLogs(check.target)}>{locale === 'de' ? 'Logs öffnen' : 'Open logs'}</button>}
            </li>)}</ul>
            <div className="health-controls">
                <form onSubmit={event => { event.preventDefault(); if (!disabled) void resource.change('maintenance', { minutes }); }}><h3>{t('Wartungsfenster')}</h3>
                    <p className="health-note">{view.maintenanceUntil ? <>{t('Wartung bis:')} <Time value={view.maintenanceUntil}/></> : t('Kein Wartungsfenster aktiv.')}</p>
                    <label htmlFor={`${uid}-maintenance`}>{t('Dauer ab jetzt')}</label><div className="health-control-row"><select id={`${uid}-maintenance`} value={minutes} disabled={resource.locked} onChange={event => setMinutes(Number(event.target.value) as typeof minutes)}><option value={15}>{t('15 Minuten')}</option><option value={60}>{t('1 Stunde')}</option><option value={240}>{t('4 Stunden')}</option><option value={0}>{t('Wartung beenden')}</option></select><button className="button small" disabled={disabled} type="submit">{t('Wartung anwenden')}</button></div>
                    <p className="health-note">{t('Wartung unterdrückt neue Warnungen. Bestehende Vorfälle bleiben sichtbar.')}</p>
                </form>
                <form onSubmit={event => { event.preventDefault(); void saveServices(); }}><h3>{t('Dienste auswählen')}</h3>
                    <HealthServicePicker deviceId={deviceId} sessionKey={sessionKey} selected={draft} disabled={resource.locked || !view} onChange={next => { setDirty(true); setDraft(next); }}/>
                    <button className="button small" disabled={disabled || services === null || !dirty} type="submit">{t('Dienstauswahl speichern')}</button>
                </form>
            </div>
            <h3>{t('Warnungsverlauf')}</h3>{view.incidents.length === 0 ? <p className="health-note">{t('Keine Vorfälle im gespeicherten Verlauf. Dies bewertet keine weiteren Gerätefunktionen.')}</p> : <ul className="health-incidents" aria-label={t('Warnungsverlauf')}>{view.incidents.map(incident => <li key={incident.id}>
                <div className="health-incident-line"><strong>{label(incident.kind, incident.target)}</strong><span className="health-state">{incident.resolvedAt ? incident.closedReason === 'monitoring_stopped' ? t('Überwachung beendet') : t('Erholt') : t('Warnung offen')}</span></div>
                <dl><div><dt>{t('Begonnen')}</dt><dd><Time value={incident.openedAt}/></dd></div><div><dt>{t('Zuletzt beobachtet')}</dt><dd><Time value={incident.lastObservedAt}/></dd></div>{incident.resolvedAt && <div><dt>{incident.closedReason === 'monitoring_stopped' ? t('Geschlossen') : t('Erholt')}</dt><dd><Time value={incident.resolvedAt}/></dd></div>}{incident.acknowledgedAt && <div><dt>{t('Bestätigt')}</dt><dd><Time value={incident.acknowledgedAt}/></dd></div>}</dl>
                {!incident.acknowledgedAt && <button type="button" className="button small" disabled={disabled} onClick={() => void resource.change('acknowledge', { incidentId: incident.id })} aria-label={t('Warnung bestätigen: {0}', { 0: label(incident.kind, incident.target) })}>{t('Warnung bestätigen')}</button>}
            </li>)}</ul>}
            <p className="health-note">{t('Bestätigen dokumentiert die Kenntnisnahme; es behebt oder schließt keinen Vorfall.')}</p>
        </>}
        <details className="health-policy">
            <summary>{t('Prüfumfang & Grenzen')}</summary>
            <p className="health-note">{t('Nur Agent-Kontakt, Root-Dateisystem / und ausdrücklich ausgewählte Dienste. Der Manager muss für die Auswertung laufen.')}</p>
            <p className="health-note">{t('Die sichtbare Ansicht wird alle 30 Sekunden neu gelesen. Fehlende oder veraltete Beobachtungen bleiben unbekannt.')}</p>
            <p className="health-note">{t('Gespeicherter Verlauf: höchstens 100 Vorfälle pro Gerät.')}</p>
            <p className="health-note">{t('Kontakt: nach mehr als 2 Minuten ohne Übertragung und weiteren 60 Sekunden Bestätigung. Root-Dateisystem: ab 90 % für 120 Sekunden; Erholung bei höchstens 85 % für 60 Sekunden. Ausgewählte Dienste: inaktiv für 120 Sekunden; Erholung nach 60 Sekunden aktiv. Fehlende Beobachtungen bestätigen keine Erholung.')}</p>
        </details>
    </section>;
}
