import { useEffect, useRef, useState } from 'react';
import { Plus, RefreshCw } from 'lucide-react';
import { APIError, AUTH_REQUIRED_EVENT, getProtectedRequestEpoch, hasPendingAPIRequests, request } from './api';
import { hasLogoutIntent, LOGOUT_INTENT_KEY, useOperator } from './auth';
import { dateLocale, t, useLocale } from './i18n';
import type { TranslationKey } from './translations';
import { APPLICATION_CHECKS_BYTES, applicationObservationAge, isHTTPApplicationCheck, projectApplicationCheck, validApplicationChecksView } from './application-checks-types';
import type { ApplicationCheckRow, ApplicationChecksStatus } from './application-checks-types';
import { applicationCheckEntryCopy, applicationCheckSetupRoute } from './application-check-entry';
import './application-checks.css';

const POLL_MS = 15000, TIMEOUT_MS = 10000;
type Anchor = { mono: number; wall: number };
type Snapshot = { view: ApplicationChecksStatus; epoch: number; anchor: Anchor; offset: number };
const capture = (): Anchor => ({ mono: performance.now(), wall: Date.now() });
function elapsed(anchor: Anchor, at = capture()): number {
    const mono = at.mono - anchor.mono, wall = at.wall - anchor.wall;
    return Number.isFinite(mono) && mono >= 0 && Math.abs(wall - mono) <= 1500 ? mono : Infinity;
}
const readError: TranslationKey = 'Anwendungsstatus nicht verfügbar. Erneut laden.';
const interrupted: TranslationKey = 'Anwendungsstatus unbekannt. Lesen im sichtbaren Fenster fortsetzen.';
function useApplicationChecks() {
    const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
    const [refreshing, setRefreshing] = useState(false), [locked, setLocked] = useState(false);
    const [notice, setNotice] = useState<TranslationKey | null>(null);
    const [, tick] = useState(0), refresh = useRef<() => void>(() => {});
    useEffect(() => {
        let alive = true, ended = false, suspended = document.visibilityState === 'hidden' || !document.hasFocus(), failures = 0;
        let current: Snapshot | null = null, timer: number | undefined;
        let pending: { controller: AbortController; timeout: number } | null = null;
        const epoch = getProtectedRequestEpoch();
        const foreground = () => !suspended && document.visibilityState !== 'hidden' && document.hasFocus();
        const stopTimer = () => { window.clearTimeout(timer); timer = undefined; };
        const cancel = () => { pending?.controller.abort(); window.clearTimeout(pending?.timeout); pending = null; };
        // Keep the last accepted clock watermark even when visible evidence is cleared.
        const clear = () => { setSnapshot(null); };
        const lock = () => { if (!alive) return; ended = true; stopTimer(); cancel(); current = null; clear(); setRefreshing(false); setLocked(true); setNotice('Die Sitzung ist abgelaufen. Bitte erneut anmelden.'); };
        const authorized = () => {
            if (!alive || ended) return false;
            if (epoch !== getProtectedRequestEpoch() || hasLogoutIntent()) { lock(); return false; }
            return true;
        };
        const schedule = (delay = failures ? Math.min(120000, POLL_MS * 2 ** failures) : current?.view.enabled === false ? 60000 : POLL_MS) => {
            stopTimer();
            if (authorized() && foreground()) timer = window.setTimeout(() => { timer = undefined; void read(); }, delay);
        };
        const failed = () => { clear(); failures = Math.min(failures + 1, 3); setNotice(readError); };
        const read = async () => {
            if (!authorized() || pending) return;
            if (!foreground()) { setNotice(interrupted); return; }
            // Session revalidation, inventory and existing foreground work win.
            if (hasPendingAPIRequests()) { schedule(1000); return; }
            stopTimer();
            const controller = new AbortController(), started = capture();
            const active = () => alive && !ended && !controller.signal.aborted && authorized() && pending?.controller === controller;
            const timeout = () => {
                if (!active()) return;
                cancel(); setRefreshing(false); failed(); schedule();
            };
            setRefreshing(true); setNotice(null);
            pending = { controller, timeout: window.setTimeout(timeout, TIMEOUT_MS) };
            try {
                const value = await request<unknown>('/application-checks/status', { signal: controller.signal, cache: 'no-store' }, APPLICATION_CHECKS_BYTES);
                if (!active()) return;
                if (!foreground()) { suspend(); return; }
                if (elapsed(started) >= TIMEOUT_MS) { timeout(); return; }
                if (!validApplicationChecksView(value)) throw new Error('invalid_application_status');
                // Repeated retained replies cannot renew an unchanged server clock.
                // Small clock advances also retain the elapsed local lower bound.
                const advance = current ? Date.parse(value.serverNow) - Date.parse(current.view.serverNow) : 0;
                if (advance < 0) throw new Error('application_clock_regressed');
                // After a clock discontinuity, preserve the more conservative elapsed
                // bound instead of letting a tiny server-time advance renew evidence.
                const previousAge = current ? Math.max(0, started.mono - current.anchor.mono, started.wall - current.anchor.wall) + current.offset : 0;
                if (!Number.isFinite(previousAge)) throw new Error('application_clock_unknown');
                const offset = Math.max(0, previousAge - Math.max(0, advance - 1));
                current = { view: value, epoch, anchor: started, offset };
                setSnapshot(current); failures = 0; setNotice(null);
            } catch (error) {
                if (!active()) return;
                if (error instanceof APIError && [401, 403, 404, 410].includes(error.status ?? 0)) {
                    lock(); if (error.status !== 401) setNotice(readError); return;
                }
                failed();
            } finally {
                if (alive && pending?.controller === controller) { window.clearTimeout(pending.timeout); pending = null; setRefreshing(false); schedule(); }
            }
        };
        const suspend = () => { suspended = true; stopTimer(); cancel(); clear(); setRefreshing(false); setNotice(interrupted); };
        const resume = () => { if (!authorized() || document.visibilityState === 'hidden' || !document.hasFocus()) return; suspended = false; schedule(0); };
        const visibility = () => document.visibilityState === 'hidden' ? suspend() : resume();
        const storage = (event: StorageEvent) => { if ((event.key === LOGOUT_INTENT_KEY || event.key === null) && hasLogoutIntent()) lock(); };
        refresh.current = () => { void read(); };
        window.addEventListener(AUTH_REQUIRED_EVENT, lock); window.addEventListener('blur', suspend); window.addEventListener('focus', resume);
        window.addEventListener('pagehide', suspend); window.addEventListener('pageshow', resume); window.addEventListener('storage', storage);
        document.addEventListener('visibilitychange', visibility);
        const ageTimer = window.setInterval(() => { if (authorized() && foreground()) tick(value => value + 1); }, 1000);
        void read();
        return () => {
            alive = false; stopTimer(); cancel(); window.clearInterval(ageTimer); refresh.current = () => {};
            window.removeEventListener(AUTH_REQUIRED_EVENT, lock); window.removeEventListener('blur', suspend); window.removeEventListener('focus', resume);
            window.removeEventListener('pagehide', suspend); window.removeEventListener('pageshow', resume); window.removeEventListener('storage', storage);
            document.removeEventListener('visibilitychange', visibility);
        };
    }, []);
    const visible = snapshot?.epoch === getProtectedRequestEpoch() && !hasLogoutIntent() ? snapshot : null;
    return { snapshot: visible, elapsed: visible ? elapsed(visible.anchor) + visible.offset : 0, refreshing, locked, notice, refresh: () => refresh.current() };
}
function resultLabel(row: ApplicationCheckRow): string {
    if (isHTTPApplicationCheck(row) && row.httpStatus !== null) return `${row.httpStatus} · ${row.state === 'ok' ? '2xx' : row.reason === 'redirect_blocked' ? t('Weiterleitung gesperrt') : t('HTTP-Fehler')}`;
    const labels: Partial<Record<ApplicationCheckRow['reason'], TranslationKey>> = {
        dns_resolved: 'Aufgelöst', tcp_connected: 'Verbunden', tcp_failed: 'TCP-Verbindung fehlgeschlagen', cancelled: 'Abgebrochen', invalid_configuration: 'Ungültige Konfiguration',
        dns_failed: 'DNS fehlgeschlagen', timeout: 'Zeitüberschreitung', request_failed: 'Netzwerkfehler', tls_verification_failed: 'TLS-Verifizierung fehlgeschlagen', tls_handshake_failed: 'TLS-Verbindung fehlgeschlagen', destination_blocked: 'Ziel gesperrt', stale: 'Unbekannt · veraltet', not_checked: 'Noch nicht beobachtet',
    };
    return t(labels[row.reason] ?? 'Unbekannt');
}
function ageLabel(age: number | null): string {
    if (age === null) return t('Unbekannt');
    const seconds = Math.floor(age / 1000);
    return seconds < 60 ? t('vor {0} s', { 0: seconds }) : seconds < 3600 ? t('vor {0} min', { 0: Math.floor(seconds / 60) }) : seconds < 86400 ? t('vor {0} h', { 0: Math.floor(seconds / 3600) }) : t('vor {0} Tagen', { 0: Math.floor(seconds / 86400) });
}
function CheckRow({ row, view, elapsedMs }: { row: ApplicationCheckRow; view: ApplicationChecksStatus; elapsedMs: number }) {
    const result = projectApplicationCheck(view, row, elapsedMs), tls = isHTTPApplicationCheck(result) ? result.tls : null;
    const rowHeaderId = `application-check-${row.id}`;
    const kindLabel = isHTTPApplicationCheck(row) ? row.targetScheme === 'http' ? t('HTTP · unverschlüsselt') : 'HTTPS' : row.kind.toUpperCase();
    const certificate = tls === null ? '—' : tls.state === 'not_applicable' ? t('Kein TLS') : tls.state === 'unknown' ? t('Unbekannt') : tls.state === 'expired' ? t('Abgelaufen') : tls.state === 'expiring' ? t('Läuft bald ab') : t('Ablauf > 30 Tage');
    return <tr role="row">
        <th id={rowHeaderId} scope="row" role="rowheader" headers="application-checks-application"><span className="application-id">{row.id}</span><small className={isHTTPApplicationCheck(row) && row.targetScheme === 'http' ? 'application-plaintext' : ''}>{kindLabel}</small></th>
        <td role="cell" headers={`${rowHeaderId} application-checks-result`}><span className="application-mobile-label" aria-hidden="true">{t(view.schemaVersion === 'tracebolt.application-checks.v2' ? 'Prüfergebnis' : 'HTTP-Ergebnis')}</span><span className="application-cell-value"><span className={`application-result application-${result.state === 'ok' ? 'ok' : result.state === 'unknown' ? 'unknown' : 'failed'}`}>{resultLabel(result)}</span></span></td>
        <td role="cell" headers={`${rowHeaderId} application-checks-certificate`}><span className="application-mobile-label" aria-hidden="true">{t('Blattzertifikat')}</span><span className="application-cell-value"><span className={`application-result application-tls-${tls?.state ?? 'not_applicable'}`} role={tls === null ? 'img' : undefined} aria-label={tls === null ? t('Zertifikat nicht Teil dieser Prüfung') : undefined}>{tls === null ? <><span className="application-certificate-mark">{certificate}</span><span className="application-mobile-certificate" aria-hidden="true">{t('Zertifikat nicht Teil dieser Prüfung')}</span></> : certificate}</span>{tls?.expiresAt && <time className="application-expiry" dateTime={tls.expiresAt} title={new Date(tls.expiresAt).toLocaleString(dateLocale())}>{new Date(tls.expiresAt).toLocaleDateString(dateLocale())}</time>}</span></td>
        <td role="cell" headers={`${rowHeaderId} application-checks-observed`}><span className="application-mobile-label" aria-hidden="true">{t('Beobachtet')}</span><span className="application-cell-value">{row.observedAt ? <time dateTime={row.observedAt} title={new Date(row.observedAt).toLocaleString(dateLocale())}>{ageLabel(applicationObservationAge(view, row, elapsedMs))}</time> : <span>—</span>}</span></td>
    </tr>;
}
// Fixed, reviewed source documentation only. Never derive a link from a target or status.
const configurationGuide = 'https://github.com/storminator89/Tracebolt/blob/bb76d6a6b7000b244b8075d5644562ad0da94c91/docs/application-checks.md';
function ConfigurationGuide() {
    return <a href={configurationGuide} target="_blank" rel="noopener noreferrer" referrerPolicy="no-referrer">{t('Anleitung zur Startdatei (GitHub)')}</a>;
}
const reasonHelp: Partial<Record<ApplicationCheckRow['reason'], TranslationKey>> = {
    destination_blocked: 'Ziel gesperrt: Alle aufgelösten IP-Adressen müssen zur exakten Freigabeliste und zur LAN-Freigabe passen.',
    stale: 'Veraltete oder zeitlich unplausible Ergebnisse bleiben unbekannt. Neu laden startet keine Prüfung.',
    invalid_configuration: 'Konfiguration ungültig: Einstellungen oder die Startdatei des Managers prüfen.',
    not_checked: 'Noch keine Beobachtung vorhanden. Auf den nächsten Prüfdurchlauf des Managers warten.',
    cancelled: 'Die Beobachtung wurde abgebrochen. Es liegt kein bestätigtes Ergebnis vor.',
    dns_failed: 'DNS fehlgeschlagen: Namensauflösung aus Sicht des Managers prüfen.',
    timeout: 'Zeitlimit erreicht: DNS, Verbindung oder Antwort überschritten das gemeinsame Limit von 5 Sekunden.',
    tcp_failed: 'TCP fehlgeschlagen: Erreichbarkeit des freigegebenen Ziels und einzelnen Ports vom Manager prüfen.',
    request_failed: 'Netzwerkfehler: Verbindung und HTTP-Antwort aus Sicht des Managers prüfen.',
    tls_verification_failed: 'TLS-Verifizierung fehlgeschlagen: Hostname, Zertifikatsgültigkeit und vorhandenen Vertrauensspeicher des Managers prüfen.',
    tls_handshake_failed: 'TLS-Verbindung fehlgeschlagen: TLS-Konfiguration und Erreichbarkeit vom Manager prüfen.',
    redirect_blocked: 'Weiterleitungen werden nicht verfolgt. Eine freigegebene, direkte Ressource konfigurieren.',
    http_status: 'HTTP-Fehler: Die Ressource antwortete außerhalb von 2xx. Dies ist keine vollständige Anwendungsdiagnose.',
};
function ApplicationChecksContent({ canManage }: { canManage: boolean }) {
    const [locale] = useLocale(), entry = applicationCheckEntryCopy[locale];
    const { snapshot, elapsed, refreshing, locked, notice, refresh } = useApplicationChecks();
    const view = snapshot?.view;
    const help = view?.enabled ? [...new Set(view.items.map(row => reasonHelp[projectApplicationCheck(view, row, elapsed).reason]).filter((key): key is TranslationKey => key !== undefined))] : [];
    return <section className="panel application-checks" aria-labelledby="application-checks-heading">
        <div className="application-checks-heading"><div><h2 id="application-checks-heading">{t('Anwendungsprüfungen')}</h2><p>{t(view?.enabled && view.schemaVersion === 'tracebolt.application-checks.v1' ? 'HTTP/TLS-Prüfung vom Manager.' : 'Prüfung vom Manager: HTTP/TLS, DNS, TCP.')}</p><p className="application-check-examples">{entry.examples}</p></div><div className="application-checks-actions">{canManage && !locked && <a className="button primary" href={applicationCheckSetupRoute}><Plus size={14}/>{entry.add}</a>}<button className="text-button" onClick={refresh} disabled={refreshing || locked} aria-label={t('Anwendungsstatus neu laden')} title={t('Gespeicherte Ergebnisse neu laden')}><RefreshCw size={14} className={refreshing ? 'spin' : ''}/>{t('Neu laden')}</button></div></div>
        {notice && <p className="application-checks-notice" role={notice === interrupted ? 'status' : 'alert'}>{t(notice)}</p>}
        {!view && !notice && <p className="application-checks-notice" role="status">{t('Anwendungsstatus wird geladen …')}</p>}
        {view?.enabled === false && <>
            <div className="application-checks-notice application-checks-inactive"><p>{t('Deaktiviert · keine Anwendungsprüfungen aktiv.')}</p>{!canManage && <p>{t('Ein Administrator richtet die Ziele ein.')}</p>}</div>
            <details className="application-checks-details"><summary>{t('Einrichtung und Freigaben')}</summary>
                <p>{t('Bis zu 8 HTTP/HTTPS-, DNS- oder TCP-Ziele auf dem Manager konfigurieren.')}</p>
                <p>{t('Entwurf speichern, Ziele und IP-Adressen prüfen, separat aktivieren. Speichern startet keine Prüfung.')}</p>
                <p>{t('Exakte Ziele und IPs freigeben; LAN und unverschlüsseltes HTTP separat bestätigen.')}</p>
                <p>{t('Nur nebenwirkungsfreie Ziele ohne Zugangsdaten. Ergebnisse nur im Arbeitsspeicher, keine Alarme.')}</p>
                <p><ConfigurationGuide/></p>
            </details>
        </>}
        {view?.enabled && <>
            <dl className="application-checks-timing"><div><dt>{t('Prüfintervall')}</dt><dd>{t('{0} s nach jedem Durchlauf', { 0: view.intervalSeconds })}</dd></div><div><dt>{t('Aktualitätsgrenze')}</dt><dd>{t('{0} s', { 0: view.maxAgeSeconds })}</dd></div></dl>
            <div className="application-checks-table"><table role="table"><thead role="rowgroup"><tr role="row"><th id="application-checks-application" scope="col" role="columnheader">{t('Anwendung')}</th><th id="application-checks-result" scope="col" role="columnheader">{t(view.schemaVersion === 'tracebolt.application-checks.v2' ? 'Prüfergebnis' : 'HTTP-Ergebnis')}</th><th id="application-checks-certificate" scope="col" role="columnheader">{t('Blattzertifikat')}</th><th id="application-checks-observed" scope="col" role="columnheader">{t('Beobachtet')}</th></tr></thead><tbody role="rowgroup">{view.items.map(row => <CheckRow key={row.id} row={row} view={view} elapsedMs={elapsed}/>)}</tbody></table></div>
            <details className="application-checks-details"><summary>{t('Beobachtungsumfang')}</summary>
                <p>{t('2xx ist ein HTTP-Status, kein Gesundheitsnachweis. Zertifikatsdaten stammen aus derselben Prüfung. Neu laden startet keine Prüfung.')}</p>
                <p>{t('Intervall ab Rundenende. Veraltete Ergebnisse bleiben unbekannt; Erfassungszeiten bleiben erhalten.')}</p>
                {view.schemaVersion === 'tracebolt.application-checks.v2' && <><p>{t('DNS: Systemauflösung mit Hosts-Datei, Cache oder Suchdomänen. Alle Ergebnisadressen müssen freigegeben sein; kein vollständiger, autoritativer DNS-Datensatz.')}</p><p>{t('TCP: Verbindung zur IP, dann schließen. Keine Daten, kein TLS, kein Funktionsnachweis.')}</p></>}
                {help.length > 0 && <ul className="application-checks-help">{help.map(key => <li key={key}>{t(key)}</li>)}</ul>}
                <p>{t('Ergebnisse bleiben im Arbeitsspeicher und erzeugen keine Alarme.')} <ConfigurationGuide/></p>
            </details>
        </>}
    </section>;
}
/** Development and signed-out pages must never issue this LAN-only read. */
export function ApplicationChecksPanel() {
    useLocale();
    const operator = useOperator();
    if (operator?.mode !== 'lan' || !operator.authenticated) return null;
    const scope = JSON.stringify([operator.expiresAt, operator.loginMode, operator.actorId, operator.capabilities]);
    const canManage = (operator.loginMode ?? 'shared') === 'shared' || operator.capabilities?.includes('manage_application_checks') === true;
    return <ApplicationChecksContent key={scope} canManage={canManage}/>;
}
