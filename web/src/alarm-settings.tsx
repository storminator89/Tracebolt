import { useEffect, useId, useRef, useState } from 'react';
import { BellRing, ChevronDown, RefreshCw } from 'lucide-react';
import { APIError, AUTH_REQUIRED_EVENT, getProtectedRequestEpoch, mutateRaw, request } from './api';
import { hasLogoutIntent, LOGOUT_INTENT_KEY, useOperator } from './auth';
import { useLocale } from './i18n';
import { ALARM_ENDPOINT_MAX, ALARM_SETTINGS_BYTES, createAlarmTestRequestId, validAlarmEndpoint, validAlarmSettings } from './alarm-settings-types';
import type { AlarmSettings, AlarmSettingsChange, AlarmTestRequest } from './alarm-settings-types';
import { ALARM_DELIVERY_CHANGED_EVENT } from './alarm-status-types';
import './alarm-settings.css';

const copy = {
    en: {
        title: 'Alarm setup', refresh: 'Refresh alarm setup', loading: 'Loading alarm setup…', unknown: 'Status unknown', unconfigured: 'No destination', on: 'On', off: 'Off', close: 'Close', cancel: 'Cancel', reset: 'Reset form',
        intro: 'Tracebolt webhook: public HTTPS, port 443. No Slack/Teams adapter or bearer-token field.',
        replace: 'Replace destination', configure: 'Add destination', enable: 'Enable alarms', disable: 'Disable alarms', test: 'Test destination',
        readonly: 'Your account can read these settings. Changing settings and sending tests requires alarm-management permission.',
        external: 'Read-only here. Change the manager’s settings file through the CLI setup.',
        unavailable: 'Managed alarm setup is unavailable on this manager.', blocked: 'The manager has blocked alarm changes and stopped dispatch. Manager restart and configuration or storage review are required. Refreshing alone cannot unblock it.',
        endpoint: 'New webhook URL (write-only)', urlHelp: 'Enter the full URL; it is never shown again. Blank leaves the saved destination unchanged. The manager verifies the public destination.',
        invalidEndpoint: 'Use a complete HTTPS URL on port 443, without a username, password, fragment, spaces or backslashes.',
        payload: 'I allow future alarm payloads to be shared with this destination: event, device and incident IDs; rule and target (agent, root filesystem or service); warning, opening/recovery, state, reason and timestamps. No logs, hostname, IP address or inventory are included.',
        plaintext: 'I understand this isolated HTTP-test connection exposes the webhook URL and its embedded secret between this browser and the manager. Outgoing webhook delivery still requires HTTPS.',
        future: 'Enables only future new health transitions. No backfill, provider contact or test on save.',
        enableNote: 'Enable the retained destination for future new health transitions only. Existing incidents are not backfilled and no test is sent.',
        disableNote: 'Disable future alarm delivery and retain the saved destination for later. Previously accepted messages cannot be recalled.',
        save: 'Save and enable', confirmEnable: 'Confirm enable', confirmDisable: 'Confirm disable',
        testNote: 'This sends one fixed synthetic test payload, including its test time and event ID, to the saved destination. It contains no live device information. Only one test per minute is allowed.',
        testAck: 'Send this synthetic test to the saved destination now.', confirmTest: 'Confirm and send test',
        testLimit: 'Wait at least one minute after the last test, then refresh before sending another.', testPending: 'A test is already queued or in flight. Refresh to check its recorded result.',
        acceptance: 'Provider acceptance does not confirm receipt by a person. Uncertain tests are never automatically replayed.',
        testResult: 'Last test', testEvent: 'Test event ID', testTime: 'Test created', queued: 'Queued', in_flight: 'In flight', provider_accepted: 'Provider accepted', failed: 'Failed', uncertain: 'Uncertain', suppressed: 'Suppressed',
        error: 'Alarm setup could not be confirmed. Refresh to try again.', invalid: 'The manager returned unsupported alarm settings. Refresh before making changes.', timeout: 'The manager did not respond in time. Refresh to try again.',
        session: 'Your session or permissions changed. Sign in again.', paused: 'Refresh alarm setup to load a new snapshot.', conflict: 'These settings changed. Refresh and review the current destination before trying again.',
        writeUncertain: 'The change or test could not be confirmed. It may have taken effect. Refresh before making another request; nothing will be replayed automatically.',
        limited: 'The manager declined another test for now. Wait at least one minute, then refresh.', randomUnavailable: 'A secure test ID could not be created. Refresh before trying again.',
        saved: 'Settings saved. No test was sent.', testQueued: 'Test request recorded. Refresh to read its saved result.', working: 'Confirming with the manager…',
    },
    de: {
        title: 'Alarme einrichten', refresh: 'Alarmeinrichtung aktualisieren', loading: 'Alarmeinrichtung wird geladen…', unknown: 'Status unbekannt', unconfigured: 'Kein Ziel', on: 'Ein', off: 'Aus', close: 'Schließen', cancel: 'Abbrechen', reset: 'Formular zurücksetzen',
        intro: 'Tracebolt-Webhook: öffentliches HTTPS, Port 443. Keine Slack-/Teams-Adapter oder Bearer-Token-Felder.',
        replace: 'Ziel ersetzen', configure: 'Ziel hinzufügen', enable: 'Alarme aktivieren', disable: 'Alarme deaktivieren', test: 'Ziel testen',
        readonly: 'Dieses Konto kann die Einstellungen lesen. Änderungen und Testversand erfordern die Berechtigung zur Alarmverwaltung.',
        external: 'Hier schreibgeschützt. Die Einstellungsdatei des Managers über die CLI-Einrichtung ändern.',
        unavailable: 'Die verwaltete Alarmeinrichtung ist auf diesem Manager nicht verfügbar.', blocked: 'Der Manager hat Alarmänderungen gesperrt und den Versand gestoppt. Ein Manager-Neustart und die Prüfung von Konfiguration oder Speicher sind erforderlich. Aktualisieren allein hebt die Sperre nicht auf.',
        endpoint: 'Neue Webhook-URL (nur Eingabe)', urlHelp: 'Vollständige URL eingeben; sie wird nicht erneut angezeigt. Leer lässt das Ziel unverändert. Der Manager prüft das öffentliche Ziel.',
        invalidEndpoint: 'Eine vollständige HTTPS-URL auf Port 443 ohne Benutzername, Passwort, Fragment, Leerzeichen oder Rückstriche verwenden.',
        payload: 'Ich erlaube die Weitergabe künftiger Alarminhalte an dieses Ziel: Ereignis-, Geräte- und Vorfall-IDs; Regel und Ziel (Agent, Root-Dateisystem oder Dienst); Warnung, Beginn/Erholung, Zustand, Grund und Zeitstempel. Keine Logs, Hostnamen, IP-Adressen oder Inventardaten sind enthalten.',
        plaintext: 'Ich verstehe, dass diese isolierte HTTP-Testverbindung die Webhook-URL und ihr eingebettetes Geheimnis zwischen diesem Browser und dem Manager offenlegt. Ausgehender Webhook-Versand erfordert weiterhin HTTPS.',
        future: 'Aktiviert nur künftige neue Zustandsübergänge. Kein Nachsenden, Anbieterkontakt oder Test beim Speichern.',
        enableNote: 'Das gespeicherte Ziel nur für künftige neue Zustandsübergänge aktivieren. Bestehende Vorfälle werden nicht nachgesendet; es wird kein Test gesendet.',
        disableNote: 'Künftigen Alarmversand deaktivieren und das gespeicherte Ziel für später behalten. Bereits angenommene Nachrichten können nicht zurückgerufen werden.',
        save: 'Speichern und aktivieren', confirmEnable: 'Aktivierung bestätigen', confirmDisable: 'Deaktivierung bestätigen',
        testNote: 'Sendet einmalig feste synthetische Testdaten mit Testzeit und Ereignis-ID an das gespeicherte Ziel. Es sind keine echten Gerätedaten enthalten. Pro Minute ist nur ein Test zulässig.',
        testAck: 'Diesen synthetischen Test jetzt an das gespeicherte Ziel senden.', confirmTest: 'Bestätigen und Test senden',
        testLimit: 'Nach dem letzten Test mindestens eine Minute warten und vor einem weiteren Test aktualisieren.', testPending: 'Ein Test wartet oder wird übertragen. Aktualisieren, um das gespeicherte Ergebnis zu prüfen.',
        acceptance: 'Die Annahme durch den Anbieter bestätigt keinen Empfang durch eine Person. Ungewisse Tests werden nie automatisch wiederholt.',
        testResult: 'Letzter Test', testEvent: 'Test-Ereignis-ID', testTime: 'Test erstellt', queued: 'Warteschlange', in_flight: 'In Übertragung', provider_accepted: 'Vom Anbieter angenommen', failed: 'Fehlgeschlagen', uncertain: 'Ungewiss', suppressed: 'Unterdrückt',
        error: 'Die Alarmeinrichtung konnte nicht bestätigt werden. Zum Wiederholen aktualisieren.', invalid: 'Der Manager lieferte nicht unterstützte Alarmeinstellungen. Vor Änderungen aktualisieren.', timeout: 'Der Manager hat nicht rechtzeitig geantwortet. Zum Wiederholen aktualisieren.',
        session: 'Die Sitzung oder Berechtigungen wurden geändert. Erneut anmelden.', paused: 'Alarmeinrichtung aktualisieren, um einen neuen Stand zu laden.', conflict: 'Diese Einstellungen wurden geändert. Aktualisieren und das aktuelle Ziel vor einem neuen Versuch prüfen.',
        writeUncertain: 'Die Änderung oder der Test konnte nicht bestätigt werden. Sie können bereits wirksam sein. Vor einer weiteren Anfrage aktualisieren; es wird nichts automatisch wiederholt.',
        limited: 'Der Manager hat einen weiteren Test vorerst abgelehnt. Mindestens eine Minute warten und dann aktualisieren.', randomUnavailable: 'Eine sichere Test-ID konnte nicht erstellt werden. Vor einem neuen Versuch aktualisieren.',
        saved: 'Einstellungen gespeichert. Es wurde kein Test gesendet.', testQueued: 'Testanfrage gespeichert. Aktualisieren, um das gespeicherte Ergebnis zu lesen.', working: 'Bestätigung durch den Manager wird abgewartet…',
    },
};
type Failure = 'error' | 'invalid' | 'timeout' | 'session' | 'paused' | 'conflict' | 'writeUncertain' | 'limited' | 'randomUnavailable';
type Editor = 'replace' | 'enable' | 'disable' | 'test' | null;
type Write = { kind: 'settings'; data: AlarmSettingsChange } | { kind: 'test'; data: AlarmTestRequest };

/** One bounded request at a time. Every suspended or uncertain write requires a fresh explicit read. */
function useAlarmSettings(canManage: boolean, clearForm: () => void, conceal: () => void) {
    const [view, setView] = useState<AlarmSettings | null>(null), [busy, setBusy] = useState<'read' | 'write' | null>(null), [locked, setLocked] = useState(false);
    const [failure, setFailure] = useState<Failure | null>(null), [notice, setNotice] = useState<'saved' | 'testQueued' | null>(null);
    const viewEpoch = useRef(getProtectedRequestEpoch());
    const callbacks = useRef({ clearForm, conceal }); callbacks.current = { clearForm, conceal };
    const commands = useRef({ read: () => {}, write: (_value: Write) => {}, dismiss: () => {}, invalidate: () => {} });
    useEffect(() => {
        let alive = true, ended = false, suspended = document.visibilityState === 'hidden', latest: AlarmSettings | null = null;
        let pending: { controller: AbortController; timeout: number; write: boolean } | null = null;
        const epoch = getProtectedRequestEpoch(); viewEpoch.current = epoch;
        const hidden = () => document.visibilityState === 'hidden';
        const cancel = () => { pending?.controller.abort(); window.clearTimeout(pending?.timeout); pending = null; };
        const clear = () => { latest = null; setView(null); setBusy(null); setNotice(null); callbacks.current.clearForm(); };
        const lock = () => { if (!alive) return; ended = true; cancel(); clear(); callbacks.current.conceal(); setLocked(true); setFailure('session'); };
        const authorized = () => { if (!alive || ended) return false; if (epoch !== getProtectedRequestEpoch() || hasLogoutIntent()) { lock(); return false; } return true; };
        const suspend = (hide: boolean) => {
            if (!alive) return;
            const uncertain = pending?.write; suspended = hide; cancel(); clear(); callbacks.current.conceal(); setFailure(uncertain ? 'writeUncertain' : 'paused');
        };
        const perform = async (write?: Write) => {
            if (!authorized() || pending || suspended || document.visibilityState === 'hidden') return;
            if (write && (!canManage || !latest || latest.mode !== 'managed' || latest.blocked || latest.revision !== write.data.expectedRevision)) return;
            const controller = new AbortController(), mono = performance.now(), wall = Date.now();
            const active = () => alive && !controller.signal.aborted && authorized() && pending?.controller === controller;
            const fail = (reason: Failure) => { cancel(); clear(); setFailure(reason); };
            pending = { controller, write: !!write, timeout: window.setTimeout(() => { if (active()) fail(write ? 'writeUncertain' : 'timeout'); }, 10000) };
            latest = null; setView(null); callbacks.current.clearForm(); setBusy(write ? 'write' : 'read'); setFailure(null); setNotice(null);
            try {
                const value = write
                    ? await mutateRaw<unknown>(write.kind === 'test' ? '/alerts/test' : '/alerts/settings', JSON.stringify(write.data), {}, controller.signal, ALARM_SETTINGS_BYTES)
                    : await request<unknown>('/alerts/settings', { signal: controller.signal, cache: 'no-store' }, ALARM_SETTINGS_BYTES);
                if (!active()) return;
                if (hidden()) { suspend(true); return; }
                const elapsed = performance.now() - mono;
                if (elapsed < 0 || elapsed >= 10000 || Math.abs(Date.now() - wall - elapsed) > 1500) { fail(write ? 'writeUncertain' : 'timeout'); return; }
                if (!validAlarmSettings(value)) { fail(write ? 'writeUncertain' : 'invalid'); return; }
                latest = value; setView(value);
                if (write) {
                    setNotice(write.kind === 'test' ? 'testQueued' : 'saved');
                    // Only a verified, current local mutation prompts a new read.
                    // No settings data becomes an optimistic delivery snapshot.
                    window.dispatchEvent(new Event(ALARM_DELIVERY_CHANGED_EVENT));
                }
            } catch (error) {
                if (!active()) return;
                if (error instanceof APIError && [401, 403].includes(error.status ?? 0)) { lock(); return; }
                fail(write ? error instanceof APIError && error.status === 409 ? 'conflict' : error instanceof APIError && error.status === 429 ? 'limited' : 'writeUncertain' : 'error');
            } finally {
                if (alive && pending?.controller === controller) { window.clearTimeout(pending.timeout); pending = null; setBusy(null); }
            }
        };
        const resume = () => { if (authorized() && document.visibilityState !== 'hidden') suspended = false; };
        const pagehide = () => suspend(true), navigate = () => suspend(false), visibility = () => document.visibilityState === 'hidden' ? suspend(true) : resume();
        const storage = (event: StorageEvent) => { if ((event.key === LOGOUT_INTENT_KEY || event.key === null) && hasLogoutIntent()) lock(); };
        commands.current = {
            read: () => { void perform(); }, write: value => { void perform(value); },
            dismiss: () => { callbacks.current.clearForm(); if (pending) { const write = pending.write; cancel(); clear(); setFailure(write ? 'writeUncertain' : 'paused'); } },
            invalidate: () => { cancel(); clear(); setFailure('randomUnavailable'); },
        };
        window.addEventListener(AUTH_REQUIRED_EVENT, lock); window.addEventListener('pagehide', pagehide); window.addEventListener('pageshow', resume);
        window.addEventListener('hashchange', navigate); window.addEventListener('popstate', navigate); window.addEventListener('storage', storage); document.addEventListener('visibilitychange', visibility);
        const guard = window.setInterval(authorized, 1000);
        void perform();
        return () => {
            alive = false; cancel(); window.clearInterval(guard); commands.current = { read: () => {}, write: () => {}, dismiss: () => {}, invalidate: () => {} };
            window.removeEventListener(AUTH_REQUIRED_EVENT, lock); window.removeEventListener('pagehide', pagehide); window.removeEventListener('pageshow', resume);
            window.removeEventListener('hashchange', navigate); window.removeEventListener('popstate', navigate); window.removeEventListener('storage', storage); document.removeEventListener('visibilitychange', visibility);
        };
    }, [canManage]);
    return { view: viewEpoch.current === getProtectedRequestEpoch() && !hasLogoutIntent() ? view : null, busy, locked, failure, notice, refresh: () => commands.current.read(), write: (value: Write) => commands.current.write(value), dismiss: () => commands.current.dismiss(), invalidate: () => commands.current.invalidate() };
}

function AlarmSettingsContent({ canManage, insecureTestMode }: { canManage: boolean; insecureTestMode: boolean }) {
    const [locale] = useLocale(), labels = copy[locale], heading = useId(), body = useId(), urlId = useId(), urlHelp = useId();
    const toggle = useRef<HTMLButtonElement>(null);
    const [expanded, setExpanded] = useState(false), [editor, setEditor] = useState<Editor>(null), [endpoint, setEndpoint] = useState('');
    const [payloadAck, setPayloadAck] = useState(false), [plaintextAck, setPlaintextAck] = useState(false), [testAck, setTestAck] = useState(false);
    const clearForm = () => { setEditor(null); setEndpoint(''); setPayloadAck(false); setPlaintextAck(false); setTestAck(false); };
    const { view, busy, locked, failure, notice, refresh, write, dismiss, invalidate } = useAlarmSettings(canManage, clearForm, () => setExpanded(false));
    const editable = !!view && canManage && view.mode === 'managed' && !view.blocked && !busy && !locked;
    const enabling = editor === 'replace' || editor === 'enable';
    const testPending = view?.test?.state === 'queued' || view?.test?.state === 'in_flight';
    const testTooSoon = !!view?.test && Date.now() - Date.parse(view.test.createdAt) < 60000;
    const canTest = editable && !!view?.configured && view.enabled && !testPending && !testTooSoon;
    const permitted = editable && editor !== null && (editor !== 'test' || canTest && testAck) && (editor !== 'replace' || validAlarmEndpoint(endpoint)) && (!enabling || payloadAck && (!insecureTestMode || plaintextAck));
    const choose = (value: Editor) => { if (!editable) return; clearForm(); setEditor(value); };
    const submit = () => {
        if (!permitted || !view || !editor) return;
        if (editor === 'test') {
            let requestId: string;
            try { requestId = createAlarmTestRequestId(); } catch { invalidate(); return; }
            write({ kind: 'test', data: { expectedRevision: view.revision, requestId, testAcknowledged: true } });
        } else write({ kind: 'settings', data: { expectedRevision: view.revision, operation: editor, endpoint: editor === 'replace' ? endpoint : '', payloadSharingAcknowledged: enabling && payloadAck, plaintextAcknowledged: enabling && insecureTestMode && plaintextAck } });
    };
    const close = () => { dismiss(); setExpanded(false); toggle.current?.focus(); };
    return <section className="panel alarm-settings" aria-labelledby={heading} onKeyDown={event => { if (event.key === 'Escape' && expanded) { event.preventDefault(); close(); } }}>
        <div className="alarm-settings-heading">
            <h2 id={heading}><button ref={toggle} className="alarm-settings-toggle" aria-expanded={expanded} aria-controls={body} onClick={() => expanded ? close() : setExpanded(true)}><BellRing size={16} aria-hidden="true"/>{labels.title}<ChevronDown size={14} aria-hidden="true"/></button></h2>
            <span className="alarm-settings-readback">{view ? view.configured ? `${view.destinationHost} · ${view.enabled ? labels.on : labels.off}` : labels.unconfigured : labels.unknown}</span>
            <button className="icon-button" onClick={refresh} disabled={!!busy || locked} aria-label={labels.refresh} title={labels.refresh}><RefreshCw size={15} aria-hidden="true" className={busy === 'read' ? 'spin' : ''}/></button>
        </div>
        {failure && <p className="alarm-settings-notice" role={failure === 'paused' ? 'status' : 'alert'}>{labels[failure]}</p>}
        {busy && <p className="alarm-settings-notice" role="status">{busy === 'write' ? labels.working : labels.loading}</p>}
        {notice && <p className="alarm-settings-notice" role="status">{labels[notice]}</p>}
        {expanded && <div id={body} className="alarm-settings-body">
            {editor === null && <p>{labels.intro}</p>}
            {view?.mode === 'external' && <p>{labels.external}</p>}
            {view?.mode === 'unavailable' && <p>{labels.unavailable}</p>}
            {view?.blocked && <p role="alert">{labels.blocked}</p>}
            {!canManage && <p>{labels.readonly}</p>}
            {editable && editor === null && <div className="alarm-settings-actions">
                <button className="button" onClick={() => choose('replace')}>{view.configured ? labels.replace : labels.configure}</button>
                {view.configured && <button className="button" onClick={() => choose(view.enabled ? 'disable' : 'enable')}>{view.enabled ? labels.disable : labels.enable}</button>}
                {view.configured && view.enabled && <button className="button" onClick={() => choose('test')} disabled={!canTest}>{labels.test}</button>}
            </div>}
            {editable && editor !== null && <form className="alarm-settings-form" onSubmit={event => { event.preventDefault(); submit(); }} autoComplete="off">
                <h3>{editor === 'replace' ? view.configured ? labels.replace : labels.configure : labels[editor]}</h3>
                {editor === 'replace' && <><label className="alarm-settings-field" htmlFor={urlId}>{labels.endpoint}<input id={urlId} type="password" autoComplete="off" spellCheck={false} autoCapitalize="none" maxLength={ALARM_ENDPOINT_MAX} value={endpoint} onChange={event => setEndpoint(event.target.value)} aria-describedby={urlHelp} aria-invalid={endpoint !== '' && !validAlarmEndpoint(endpoint)}/></label><p id={urlHelp}>{labels.urlHelp}</p>{endpoint !== '' && !validAlarmEndpoint(endpoint) && <p role="alert">{labels.invalidEndpoint}</p>}<p>{labels.future}</p></>}
                {editor === 'enable' && <p>{labels.enableNote}</p>}
                {editor === 'disable' && <p>{labels.disableNote}</p>}
                {enabling && <label className="alarm-settings-check"><input type="checkbox" checked={payloadAck} onChange={event => setPayloadAck(event.target.checked)}/><span>{labels.payload}</span></label>}
                {enabling && insecureTestMode && <label className="alarm-settings-check"><input type="checkbox" checked={plaintextAck} onChange={event => setPlaintextAck(event.target.checked)}/><span>{labels.plaintext}</span></label>}
                {editor === 'test' && <><p>{labels.testNote}</p><label className="alarm-settings-check"><input type="checkbox" checked={testAck} onChange={event => setTestAck(event.target.checked)}/><span>{labels.testAck}</span></label></>}
                <div className="alarm-settings-actions"><button className="button primary" type="submit" disabled={!permitted}>{editor === 'replace' ? labels.save : editor === 'enable' ? labels.confirmEnable : editor === 'disable' ? labels.confirmDisable : labels.confirmTest}</button><button className="button" type="button" onClick={() => { setEndpoint(''); setPayloadAck(false); setPlaintextAck(false); setTestAck(false); }}>{labels.reset}</button><button className="button" type="button" onClick={dismiss}>{labels.cancel}</button></div>
            </form>}
            {view?.test && <div className="alarm-test-result"><dl><div><dt>{labels.testResult}</dt><dd>{labels[view.test.state]}</dd></div><div><dt>{labels.testEvent}</dt><dd>{view.test.eventId}</dd></div><div><dt>{labels.testTime}</dt><dd><time dateTime={view.test.createdAt}>{new Intl.DateTimeFormat(locale === 'de' ? 'de-DE' : 'en-GB', { dateStyle: 'short', timeStyle: 'medium', timeZone: 'UTC' }).format(new Date(view.test.createdAt))} UTC</time></dd></div></dl>{testPending ? <p>{labels.testPending}</p> : testTooSoon && <p>{labels.testLimit}</p>}</div>}
            {(editor === 'test' || view?.test) && <p>{labels.acceptance}</p>}
            <div className="alarm-settings-actions"><button className="button" onClick={close}>{labels.close}</button></div>
        </div>}
    </section>;
}
export function AlarmSettingsPanel() {
    const operator = useOperator();
    if (!operator || operator.mode !== 'lan' || !operator.authenticated) return null;
    const canManage = (operator.loginMode ?? 'shared') === 'shared' || (operator.capabilities as readonly string[] | undefined)?.includes('manage_alarms') === true;
    return <AlarmSettingsContent key={`${operator.actorId ?? ''}:${operator.expiresAt ?? ''}:${canManage}:${operator.insecureTestMode}`} canManage={canManage} insecureTestMode={operator.insecureTestMode}/>;
}
