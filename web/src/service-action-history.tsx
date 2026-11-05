import { useEffect, useId, useRef, useState } from 'react';
import { AUTH_REQUIRED_EVENT, getProtectedRequestEpoch } from './api';
import { hasLogoutIntent } from './auth';
import { useLocale } from './i18n';
import { journalAge } from './journal-types';
import type { ServiceActionAccess } from './service-action-api';
import { readServiceActionHistory } from './service-action-history-api';
import type { ServiceActionHistory, ServiceActionHistoryEntry } from './service-action-history-types';
import './service-action-history.css';

const copy = {
    en: {
        count: 'Saved approvals', title: 'Saved service-action history', close: 'Close history', refresh: 'Refresh history', read: 'Read receipt', hide: 'Close receipt', loading: 'Reading saved approvals…', error: 'History is unavailable or changed. Refresh to read it again.', expired: 'This history snapshot expired or access was interrupted. Refresh to read it again.',
        scope: 'Up to 64 approvals for this original device and command key, newest first. Read-only snapshot, no polling or retries.', capacity: 'All 64 retained approval slots are used. New approvals are blocked; receipts remain readable.', empty: 'No saved service-action approvals.', snapshot: 'Status snapshot at',
        approved: 'Approved; execution unconfirmed', claimed: 'Claimed once; execution and outcome unconfirmed', operation_completed: 'Agent reports command completion; restart and service health unconfirmed', not_started: 'Agent reports the operation was not started', expiredState: 'Start window expired', needs_intervention: 'Outcome unknown; local investigation required',
        actor: 'Approving operator', job: 'Action ID', unit: 'Service', approvedAt: 'Approval recorded', deadline: 'Start deadline', claim: 'Delivery claimed', noClaim: 'No delivery claim recorded.', received: 'Manager received agent report', noReports: 'No agent result report received.', result: 'Reported phase', observed: 'Reported service state', reason: 'Reported reason', admitted: 'Admitted, not proof of execution', dispatching: 'Dispatching, not proof of completion', timeNote: 'Claim and manager receipt times are not native start or completion times. Missing reports never prove success. No action can be retried here.', binding: 'Original device and command-key binding',
    },
    de: {
        count: 'Gespeicherte Freigaben', title: 'Gespeicherte Dienstaktionshistorie', close: 'Historie schließen', refresh: 'Historie aktualisieren', read: 'Beleg lesen', hide: 'Beleg schließen', loading: 'Gespeicherte Freigaben werden gelesen…', error: 'Historie nicht verfügbar oder geändert. Zum erneuten Lesen aktualisieren.', expired: 'Dieser Historienschnappschuss ist abgelaufen oder der Zugriff wurde unterbrochen. Zum erneuten Lesen aktualisieren.',
        scope: 'Bis zu 64 Freigaben für dieses ursprüngliche Gerät und diesen Befehlsschlüssel, neueste zuerst. Nur lesbarer Schnappschuss, keine Abfragen im Hintergrund oder Wiederholungen.', capacity: 'Alle 64 gespeicherten Freigabeplätze sind belegt. Neue Freigaben sind gesperrt; Belege bleiben lesbar.', empty: 'Keine gespeicherten Dienstaktionsfreigaben.', snapshot: 'Statusschnappschuss vom',
        approved: 'Freigegeben; Ausführung unbestätigt', claimed: 'Einmal zur Zustellung abgeholt; Ausführung und Ausgang unbestätigt', operation_completed: 'Agent meldet Befehlsabschluss; Neustart und Dienstzustand unbestätigt', not_started: 'Agent meldet, dass die Operation nicht gestartet wurde', expiredState: 'Startzeitfenster abgelaufen', needs_intervention: 'Ausgang unbekannt; lokale Prüfung erforderlich',
        actor: 'Freigebender Operator', job: 'Aktions-ID', unit: 'Dienst', approvedAt: 'Freigabe erfasst', deadline: 'Startfrist', claim: 'Zur Zustellung abgeholt', noClaim: 'Keine Abholung zur Zustellung erfasst.', received: 'Agent-Bericht beim Manager eingegangen', noReports: 'Kein Agent-Ergebnisbericht eingegangen.', result: 'Gemeldete Phase', observed: 'Gemeldeter Dienstzustand', reason: 'Gemeldeter Grund', admitted: 'Angenommen, kein Ausführungsnachweis', dispatching: 'Wird übermittelt, kein Abschlussnachweis', timeNote: 'Abholungs- und Manager-Empfangszeiten sind keine nativen Start- oder Abschlusszeiten. Fehlende Berichte belegen keinen Erfolg. Hier kann keine Aktion wiederholt werden.', binding: 'Ursprüngliche Geräte- und Befehlsschlüsselbindung',
    },
};
function HistoryTime({ value, locale }: { value: string; locale: 'en' | 'de' }) {
    return <time dateTime={value} title={value}>{new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'medium', timeZone: 'UTC' }).format(new Date(value))} UTC</time>;
}
type Anchor = { mono: number; wall: number; epoch: number; lifetime: number };
const age = (a: Anchor) => { const mono = performance.now() - a.mono, wall = Date.now() - a.wall; return Number.isFinite(mono) && mono >= 0 && wall >= 0 && Math.abs(wall - mono) < 1500 ? Math.max(mono, wall) : Infinity; };
export function ServiceActionHistoryPanel({ deviceId, access }: { deviceId: string; access: ServiceActionAccess }) {
    // Synchronous identity replacement prevents even one render of another scope.
    return <History key={`${deviceId}:${access.actorId}:${access.sessionKey}:${access.insecureTestMode}`} deviceId={deviceId} access={access}/>;
}
function History({ deviceId, access }: { deviceId: string; access: ServiceActionAccess }) {
    const [locale] = useLocale(), c = copy[locale], id = useId();
    const [open, setOpen] = useState(false), [history, setHistory] = useState<ServiceActionHistory | null>(null), [selected, setSelected] = useState<string | null>(null), [busy, setBusy] = useState(false), [error, setError] = useState<'error' | 'expired' | null>(null), [, render] = useState(0);
    const alive = useRef(false), version = useRef(0), pending = useRef<AbortController | null>(null), anchor = useRef<Anchor | null>(null), locked = useRef(false), suspended = useRef(document.visibilityState === 'hidden'), last = useRef<Pick<ServiceActionHistory, 'incarnationDigest' | 'keyId' | 'serverNow'> | null>(null), origin = useRef<{ serverNow: string; started: Anchor } | null>(null);
    const clear = () => { version.current++; pending.current?.abort(); pending.current = null; anchor.current = null; setBusy(false); setHistory(null); setSelected(null); };
    useEffect(() => {
        alive.current = true;
        const interrupt = () => { suspended.current = true; clear(); setError('expired'); };
        const auth = () => { locked.current = true; interrupt(); };
        const restore = () => { if (document.visibilityState !== 'hidden') { suspended.current = false; render(n => n + 1); } };
        const visibility = () => document.visibilityState === 'hidden' ? interrupt() : restore();
        window.addEventListener(AUTH_REQUIRED_EVENT, auth);
        for (const event of ['pagehide', 'blur', 'hashchange', 'popstate']) window.addEventListener(event, interrupt);
        for (const event of ['pageshow', 'focus']) window.addEventListener(event, restore);
        document.addEventListener('visibilitychange', visibility);
        const timer = window.setInterval(() => { const a = anchor.current; if (a && (a.epoch !== getProtectedRequestEpoch() || hasLogoutIntent() || age(a) >= a.lifetime)) { clear(); setError('expired'); } }, 250);
        return () => { alive.current = false; version.current++; pending.current?.abort(); window.clearInterval(timer); window.removeEventListener(AUTH_REQUIRED_EVENT, auth); for (const event of ['pagehide', 'blur', 'hashchange', 'popstate']) window.removeEventListener(event, interrupt); for (const event of ['pageshow', 'focus']) window.removeEventListener(event, restore); document.removeEventListener('visibilitychange', visibility); };
    }, []);
    async function read() {
        if (!alive.current || locked.current || suspended.current || pending.current || hasLogoutIntent() || document.visibilityState === 'hidden') return;
        clear(); const controller = new AbortController(), token = version.current, started = { mono: performance.now(), wall: Date.now(), epoch: getProtectedRequestEpoch(), lifetime: 60000 };
        pending.current = controller; setBusy(true); setError(null);
        const timeout = window.setTimeout(() => { if (version.current === token) { clear(); setError('error'); } }, 10000);
        try {
            const value = await readServiceActionHistory(deviceId, access, controller.signal);
            if (!alive.current || controller.signal.aborted || token !== version.current || suspended.current || locked.current || started.epoch !== getProtectedRequestEpoch() || hasLogoutIntent()) return;
            started.lifetime = Math.min(60000, journalAge(access.sessionKey, value.serverNow));
            if (origin.current && journalAge(value.serverNow, origin.current.serverNow) + 1500 < age(origin.current.started)) throw new Error('History clock stalled');
            if (age(started) >= started.lifetime || last.current && (last.current.incarnationDigest !== value.incarnationDigest || last.current.keyId !== value.keyId || journalAge(value.serverNow, last.current.serverNow) <= 0)) throw new Error('History binding or clock changed');
            origin.current ??= { serverNow: value.serverNow, started };
            anchor.current = started; last.current = { incarnationDigest: value.incarnationDigest, keyId: value.keyId, serverNow: value.serverNow }; setHistory(value);
        } catch { if (alive.current && token === version.current) { clear(); setError('error'); } }
        finally { window.clearTimeout(timeout); if (alive.current && token === version.current) { pending.current = null; setBusy(false); } }
    }
    const label = (state: ServiceActionHistoryEntry['job']['state']) => state === 'expired' ? c.expiredState : c[state];
    const row = history?.jobs.find(r => r.job.id === selected);
    return <section className="service-action-history" aria-labelledby={id}>
        <header><button className="button small" id={id} aria-expanded={open} aria-controls={`${id}-content`} onClick={() => { clear(); setError(null); setOpen(!open); if (!open) void read(); }}>{open ? c.close : c.title}</button>{open && <button className="button small" disabled={busy || locked.current || suspended.current} onClick={() => void read()}>{c.refresh}</button>}</header>
        {open && <div id={`${id}-content`}><p className="package-note">{c.scope}</p>{busy && <p role="status">{c.loading}</p>}{error && <p role="alert">{c[error]}</p>}
            {history && <><p>{c.snapshot}: <HistoryTime value={history.serverNow} locale={locale}/></p>{history.jobs.length === 64 && <p role="status">{c.capacity}</p>}{history.jobs.length === 0 ? <p>{c.empty}</p> : <><h3 className="service-action-history-count">{c.count}: {history.jobs.length}</h3><ol className="service-action-history-cards" role="list">{history.jobs.map(entry => <li key={entry.job.id}><div className="service-action-history-card-heading"><strong>{entry.job.unit}</strong><span>#{entry.sequence}</span></div><p className="service-action-history-state">{label(entry.job.state)}</p><p className="service-action-history-date">{c.approvedAt}: <HistoryTime value={entry.job.approvedAt} locale={locale}/></p><button className="button small" aria-expanded={selected === entry.job.id} aria-controls={`${id}-receipt-${entry.sequence}`} onClick={() => setSelected(selected === entry.job.id ? null : entry.job.id)}>{selected === entry.job.id ? c.hide : c.read} #{entry.sequence}</button>
                {row === entry && <div className="service-action-history-receipt" id={`${id}-receipt-${entry.sequence}`}><dl><div><dt>{c.job}</dt><dd>{entry.job.id}</dd></div><div><dt>{c.actor}</dt><dd>{entry.job.actorId}</dd></div><div><dt>{c.unit}</dt><dd>{entry.job.unit}</dd></div><div><dt>{c.approvedAt}</dt><dd><HistoryTime value={entry.job.approvedAt} locale={locale}/></dd></div><div><dt>{c.deadline}</dt><dd><HistoryTime value={entry.job.startDeadline} locale={locale}/></dd></div></dl>{entry.claimedAt ? <p>{c.claim}: <HistoryTime value={entry.claimedAt} locale={locale}/></p> : <p>{c.noClaim}</p>}{entry.reports.length === 0 ? <p>{c.noReports}</p> : <ol className="service-action-history-reports">{entry.reports.map((report, n) => <li key={n}><p>{c.received}: <HistoryTime value={report.receivedAt} locale={locale}/></p><p>{c.result}: {report.result.phase === 'admitted' || report.result.phase === 'dispatching' ? c[report.result.phase] : label(report.result.phase)}</p>{report.result.observedState && <p>{c.observed}: {report.result.observedState}</p>}{report.result.reason && <p>{c.reason}: {report.result.reason}</p>}</li>)}</ol>}<p className="package-note">{c.timeNote}</p><details><summary>{c.binding}</summary><p>{history.incarnationDigest}</p><p>{history.keyId}</p><p>{entry.job.envelopeDigest}</p></details></div>}
            </li>)}</ol></>}</>}
        </div>}
    </section>;
}
