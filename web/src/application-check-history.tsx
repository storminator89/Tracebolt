import './application-check-history.css';
import { useEffect, useRef, useState } from 'react';
import { AUTH_REQUIRED_EVENT, getProtectedRequestEpoch, request } from './api';
import { hasLogoutIntent, LOGOUT_INTENT_KEY, useOperator } from './auth';
import { dateLocale, useLocale } from './i18n';
import { APPLICATION_HISTORY_BYTES, APPLICATION_HISTORY_MEDIA, validApplicationHistory } from './application-check-history-types';
import type { ApplicationHistory, ApplicationHistorySample } from './application-check-history-types';
import { acceptWindowsHealthClock, windowsHealthElapsed } from './windows-health-clock';

const copy = {
    en: { started: 'Started', title: 'Recent check observations', scope: 'Up to 32 completed observations per target, at most 24 hours. Sampled outcomes only, not uptime or continuous coverage. History is cleared on restart or configuration replacement. No new check is started.', loading: 'Loading saved observations…', unavailable: 'Observation history unavailable. Reload to try again.', reload: 'Reload history', empty: 'No completed observations retained.', omitted: 'Earlier observations are not retained.', gap: 'Observation gap before this sample.', clock: 'Clock changed. Earlier observations were discarded.', expired: 'History view expired. Reload saved observations.', success: 'Success observed', failure: 'Failure observed', unknown: 'Unknown outcome', disabled: 'Checks disabled. No history is available.', completed: 'Completed', asOf: 'Saved snapshot as of', source: 'This is the configuration active when read. Reload after configuration changes.', note: 'Times are the original check start and completion, not the time this view was opened.' },
    de: { started: 'Gestartet', title: 'Letzte Prüfbeobachtungen', scope: 'Bis zu 32 abgeschlossene Beobachtungen pro Ziel, höchstens 24 Stunden. Einzelbeobachtungen, keine Verfügbarkeitsquote oder lückenlose Abdeckung. Neustart oder Konfigurationswechsel löscht den Verlauf. Es wird keine neue Prüfung gestartet.', loading: 'Gespeicherte Beobachtungen werden geladen…', unavailable: 'Beobachtungsverlauf nicht verfügbar. Zum Wiederholen neu laden.', reload: 'Verlauf neu laden', empty: 'Keine abgeschlossenen Beobachtungen gespeichert.', omitted: 'Frühere Beobachtungen sind nicht mehr gespeichert.', gap: 'Beobachtungslücke vor dieser Prüfung.', clock: 'Uhr geändert. Frühere Beobachtungen wurden verworfen.', expired: 'Verlaufsansicht abgelaufen. Gespeicherte Beobachtungen neu laden.', success: 'Erfolg beobachtet', failure: 'Fehler beobachtet', unknown: 'Ergebnis unbekannt', disabled: 'Prüfungen deaktiviert. Kein Verlauf verfügbar.', completed: 'Abgeschlossen', asOf: 'Gespeicherter Stand vom', source: 'Es gilt die beim Lesen aktive Konfiguration. Nach Änderungen neu laden.', note: 'Zeiten zeigen ursprünglichen Prüfstart und Abschluss, nicht das Öffnen dieser Ansicht.' },
};

const reasons: Record<'en' | 'de', Record<string, string>> = {
 en: { http_2xx: 'HTTP 2xx', http_status: 'HTTP status', redirect_blocked: 'Redirect blocked', dns_failed: 'DNS failed', timeout: 'Timeout', request_failed: 'Request failed', tls_verification_failed: 'TLS verification failed', tls_handshake_failed: 'TLS handshake failed', destination_blocked: 'Destination blocked', invalid_configuration: 'Invalid configuration', dns_resolved: 'Resolved', tcp_connected: 'Connected', tcp_failed: 'TCP connection failed' },
 de: { http_2xx: 'HTTP 2xx', http_status: 'HTTP-Status', redirect_blocked: 'Weiterleitung gesperrt', dns_failed: 'DNS fehlgeschlagen', timeout: 'Zeitüberschreitung', request_failed: 'Anfrage fehlgeschlagen', tls_verification_failed: 'TLS-Verifizierung fehlgeschlagen', tls_handshake_failed: 'TLS-Verbindung fehlgeschlagen', destination_blocked: 'Ziel gesperrt', invalid_configuration: 'Ungültige Konfiguration', dns_resolved: 'Aufgelöst', tcp_connected: 'Verbunden', tcp_failed: 'TCP-Verbindung fehlgeschlagen' },
};

export function ApplicationCheckHistory() {
    const [locale] = useLocale(), c = copy[locale], operator = useOperator();
    const clockKey = `application-check-history:${JSON.stringify([operator?.expiresAt, operator?.loginMode, operator?.actorId, operator?.capabilities])}`;
    const [open, setOpen] = useState(false), [attempt, setAttempt] = useState(0);
    const [view, setView] = useState<ApplicationHistory | null>(null), [notice, setNotice] = useState<'loading' | 'unavailable' | 'expired' | null>(null);
    const details = useRef<HTMLDetailsElement>(null);
    useEffect(() => {
        setView(null); setNotice(null);
        if (!open || document.visibilityState === 'hidden' || !document.hasFocus() || hasLogoutIntent()) return;
        const controller = new AbortController(), epoch = getProtectedRequestEpoch(), mono = performance.now(), wall = Date.now();
        let alive = true, timer: number | undefined;
        const active = () => alive && !controller.signal.aborted && epoch === getProtectedRequestEpoch() && !hasLogoutIntent();
        const clear = () => { controller.abort(); setView(null); setNotice(null); setOpen(false); if (details.current) details.current.open = false; };
        const expire = () => { controller.abort(); setView(null); setNotice('expired'); };
        const storage = (e: StorageEvent) => { if ((e.key === LOGOUT_INTENT_KEY || e.key === null) && hasLogoutIntent()) clear(); };
        const visibility = () => { if (document.visibilityState === 'hidden') clear(); };
        setNotice('loading');
        const timeout = window.setTimeout(() => { if (active()) { controller.abort(); setView(null); setNotice('unavailable'); } }, 10000);
        void request<unknown>('/application-checks/status', { signal: controller.signal, cache: 'no-store', redirect: 'error', headers: { Accept: APPLICATION_HISTORY_MEDIA } }, APPLICATION_HISTORY_BYTES).then(value => {
            if (!active()) return;
            const elapsed = performance.now() - mono;
            if (document.visibilityState === 'hidden' || !document.hasFocus() || elapsed < 0 || elapsed >= 10000 || Math.abs(Date.now() - wall - elapsed) > 1500) { clear(); return; }
            if (!validApplicationHistory(value)) throw new Error('invalid_history');
            if (!acceptWindowsHealthClock(clockKey, epoch, value.serverNow, elapsed)) throw new Error('history_clock_regressed');
            const offset = windowsHealthElapsed(clockKey, epoch, value.serverNow, elapsed);
            if (!Number.isFinite(offset)) throw new Error('history_clock_unknown');
            window.clearTimeout(timeout);
            // No polling. A minute-old private snapshot must be explicitly read again.
            const remaining = value.items.flatMap(target => target.samples.map(sample => 86400000 - (Date.parse(value.serverNow) - Date.parse(sample.observedAt)) - offset - 1));
            const lifetime = Math.min(60000, ...remaining);
            if (lifetime <= 0) { expire(); return; }
            setView(value); setNotice(null);
            timer = window.setTimeout(expire, lifetime);
        }).catch(() => { if (active()) { setView(null); setNotice('unavailable'); } });
        const clock = window.setInterval(() => { const elapsed = performance.now() - mono; if (epoch !== getProtectedRequestEpoch() || hasLogoutIntent() || elapsed < 0 || !Number.isFinite(elapsed) || Math.abs(Date.now() - wall - elapsed) > 1500) clear(); }, 1000);
        window.addEventListener(AUTH_REQUIRED_EVENT, clear); window.addEventListener('blur', clear); window.addEventListener('pagehide', clear); window.addEventListener('storage', storage); document.addEventListener('visibilitychange', visibility);
        return () => { alive = false; controller.abort(); window.clearTimeout(timeout); window.clearTimeout(timer); window.clearInterval(clock); window.removeEventListener(AUTH_REQUIRED_EVENT, clear); window.removeEventListener('blur', clear); window.removeEventListener('pagehide', clear); window.removeEventListener('storage', storage); document.removeEventListener('visibilitychange', visibility); };
    }, [open, attempt, clockKey]);
    const describe = (s: ApplicationHistorySample) => `${s.httpStatus === null ? '' : `${s.httpStatus} · `}${s.state === 'ok' ? c.success : s.state === 'unknown' ? c.unknown : c.failure}`;
    return <details className="application-checks-details application-check-history" ref={details} onToggle={e => setOpen(e.currentTarget.open)}>
        <summary>{c.title}</summary>
        {open && <><p>{c.scope}</p><p>{c.note}</p>
            {notice && <p role={notice === 'unavailable' ? 'alert' : 'status'}>{c[notice]}</p>}
            {notice !== 'loading' && <button className="text-button" onClick={() => setAttempt(n => n + 1)}>{c.reload}</button>}
            {view && <><p>{c.asOf}: <time dateTime={view.serverNow}>{new Date(view.serverNow).toLocaleString(dateLocale())}</time>. {c.source}</p>{!view.enabled && <p>{c.disabled}</p>}{!view.clockReliable && <p role="status">{c.clock}</p>}
                {view.items.map(target => <section key={target.id} aria-label={target.id}><h3>{target.id} · {target.kind === 'http' ? target.targetScheme.toUpperCase() : target.kind.toUpperCase()}</h3>
                    {target.earlierOmitted && <p>{c.omitted}</p>}{target.samples.length === 0 && <p>{c.empty}</p>}
                    <ol className="application-history-samples" role="list">{[...target.samples].reverse().map(sample => <li key={sample.observedAt}>
                        {sample.gapBefore && <p className="application-history-gap">{c.gap}</p>}
                        <div className="application-history-outcome"><strong>{describe(sample)}</strong><span>{reasons[locale][sample.reason] ?? c.unknown}</span></div>
                        <dl className="application-history-times">
                            <div><dt>{c.started}</dt><dd><time dateTime={sample.observedAt}>{new Date(sample.observedAt).toLocaleString(dateLocale())}</time></dd></div>
                            <div><dt>{c.completed}</dt><dd><time dateTime={sample.completedAt}>{new Date(sample.completedAt).toLocaleString(dateLocale())}</time></dd></div>
                        </dl>
                    </li>)}</ol>
                </section>)}</>}
        </>}
    </details>;
}
