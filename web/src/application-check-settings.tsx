import { useEffect, useId, useRef, useState } from 'react';
import { Activity, ChevronDown, RefreshCw } from 'lucide-react';
import { APIError, AUTH_REQUIRED_EVENT, getProtectedRequestEpoch, mutateRaw, request } from './api';
import { hasLogoutIntent, LOGOUT_INTENT_KEY, useOperator } from './auth';
import { useLocale } from './i18n';
import { APPLICATION_CHECK_MAX_TARGETS, APPLICATION_CHECK_SETTINGS_BYTES, sameApplicationTargets, validApplicationCheckSettings, validApplicationTarget } from './application-check-settings-types';
import type { ApplicationCheckSettings, ApplicationCheckSettingsChange, ApplicationTarget } from './application-check-settings-types';
import './application-check-settings.css';

const copy = {
    en: {
        title: 'Application check setup', refresh: 'Refresh application check setup', loading: 'Loading check settings…', unknown: 'Status unknown', unconfigured: 'No targets', on: 'On', off: 'Off', close: 'Close', cancel: 'Cancel',
        intro: 'Up to 8 HTTP/HTTPS, DNS or TCP targets. HTTPS includes certificate-expiry checks.',
        configure: 'Add targets', edit: 'Edit targets', enable: 'Enable checks', disable: 'Disable checks', save: 'Save draft', confirmEnable: 'Confirm enable', confirmDisable: 'Confirm disable',
        readonly: 'Application-check setup requires administrator permission.', external: 'Read-only targets from the manager’s startup file.', unavailable: 'Managed application-check setup is unavailable on this manager.',
        blocked: 'The manager has stopped checks and blocked changes. Review its configuration and storage before restarting.',
        interval: 'Interval (seconds)', intervalHelp: '60–3600 seconds after each completed round.', target: 'Target', id: 'Target ID', kind: 'Type', url: 'URL', dnsHost: 'Hostname', tcpHost: 'Hostname or IP address', port: 'Port', ips: 'Allowed IP addresses',
        ipsHelp: '1–16 exact IPs; commas or new lines, no ranges. Every resolved address must match.', targetHelp: 'Use a fixed, side-effect-free target. No credentials, query strings, headers or request bodies.',
        privateAck: 'I approve private-LAN access to this exact target and its listed IP addresses.', httpAck: 'I accept unencrypted HTTP requests to this exact target.', add: 'Add target', remove: 'Remove target',
        saveNote: 'Saves a validated draft and stops previous checks. Checks stay off.',
        invalid: 'Check settings are invalid: use unique IDs (a–z, 0–9, _ or -), valid fixed destinations, exact allowed IPs and the required acknowledgements.', invalidInterval: 'Enter a whole interval from 60 to 3600 seconds.',
        review: 'Review saved targets', every: 'Seconds after each round', allowed: 'Allowed IPs', private: 'Private LAN approved', plaintextTarget: 'Plaintext HTTP approved',
        managerAck: 'I understand these checks run from the management server, not from the agents.',
        destinationsAck: 'I approve recurring checks to exactly these saved destinations and IP addresses at this interval.',
        transportAck: 'I understand this HTTP-test connection exposes target settings and approvals between this browser and the manager.',
        transportNote: 'This operator connection uses unencrypted HTTP. Target settings and approvals can be read or changed on the network.',
        disableNote: 'Stop recurring checks and retain these targets for later. Requests already in progress may have reached a target.',
        error: 'Check settings could not be confirmed. Refresh to try again.', invalidResponse: 'The manager returned unsupported check settings. Refresh before making changes.', timeout: 'The manager did not respond in time. Refresh to try again.',
        session: 'Your session or permissions changed. Sign in again.', paused: 'Refresh check settings to load a new snapshot.', conflict: 'These settings changed. Refresh and review the current targets before trying again.',
        writeUncertain: 'The change could not be confirmed and may have taken effect. Refresh before another request; nothing is replayed automatically.',
        saved: 'Draft saved. Checks are off.', enabled: 'Checks enabled for the reviewed targets.', disabled: 'Checks disabled. Saved targets retained.', working: 'Confirming with the manager…',
    },
    de: {
        title: 'Anwendungsprüfungen einrichten', refresh: 'Anwendungsprüfungseinrichtung aktualisieren', loading: 'Prüfeinstellungen werden geladen…', unknown: 'Status unbekannt', unconfigured: 'Keine Ziele', on: 'Ein', off: 'Aus', close: 'Schließen', cancel: 'Abbrechen',
        intro: 'Bis zu 8 HTTP/HTTPS-, DNS- oder TCP-Ziele. HTTPS umfasst die Prüfung des Zertifikatsablaufs.',
        configure: 'Ziele hinzufügen', edit: 'Ziele bearbeiten', enable: 'Prüfungen aktivieren', disable: 'Prüfungen deaktivieren', save: 'Entwurf speichern', confirmEnable: 'Aktivierung bestätigen', confirmDisable: 'Deaktivierung bestätigen',
        readonly: 'Die Einrichtung von Anwendungsprüfungen erfordert Administratorrechte.', external: 'Schreibgeschützte Ziele aus der Startdatei des Managers.', unavailable: 'Die verwaltete Einrichtung von Anwendungsprüfungen ist auf diesem Manager nicht verfügbar.',
        blocked: 'Der Manager hat Prüfungen gestoppt und Änderungen gesperrt. Vor einem Neustart Konfiguration und Speicher prüfen.',
        interval: 'Intervall (Sekunden)', intervalHelp: '60–3600 Sekunden nach jeder abgeschlossenen Prüfrunde.', target: 'Ziel', id: 'Ziel-ID', kind: 'Typ', url: 'URL', dnsHost: 'Hostname', tcpHost: 'Hostname oder IP-Adresse', port: 'Port', ips: 'Erlaubte IP-Adressen',
        ipsHelp: '1–16 exakte IPs; Kommas oder Zeilenumbrüche, keine Bereiche. Jede aufgelöste Adresse muss übereinstimmen.', targetHelp: 'Ein festes Ziel ohne Seiteneffekte verwenden. Keine Zugangsdaten, Abfrageparameter, Header oder Anfrageinhalte.',
        privateAck: 'Ich erlaube den Zugriff auf dieses genaue Ziel und seine aufgeführten IP-Adressen im privaten LAN.', httpAck: 'Ich akzeptiere unverschlüsselte HTTP-Anfragen an dieses genaue Ziel.', add: 'Ziel hinzufügen', remove: 'Ziel entfernen',
        saveNote: 'Speichert einen geprüften Entwurf und stoppt bisherige Prüfungen. Prüfungen bleiben aus.',
        invalid: 'Ungültige Prüfeinstellungen: eindeutige IDs (a–z, 0–9, _ oder -), gültige feste Ziele, exakte erlaubte IPs und erforderliche Bestätigungen verwenden.', invalidInterval: 'Ein ganzzahliges Intervall zwischen 60 und 3600 Sekunden eingeben.',
        review: 'Gespeicherte Ziele prüfen', every: 'Sekunden nach jeder Prüfrunde', allowed: 'Erlaubte IPs', private: 'Privates LAN freigegeben', plaintextTarget: 'Unverschlüsseltes HTTP freigegeben',
        managerAck: 'Ich verstehe, dass diese Prüfungen vom Management-Server ausgehen, nicht von den Agenten.',
        destinationsAck: 'Ich erlaube wiederkehrende Prüfungen genau dieser gespeicherten Ziele und IP-Adressen in diesem Intervall.',
        transportAck: 'Ich verstehe, dass diese HTTP-Testverbindung Zieleinstellungen und Freigaben zwischen diesem Browser und dem Manager offenlegt.',
        transportNote: 'Diese Bedienverbindung nutzt unverschlüsseltes HTTP. Zieleinstellungen und Freigaben können im Netzwerk mitgelesen oder verändert werden.',
        disableNote: 'Wiederkehrende Prüfungen stoppen und diese Ziele für später behalten. Bereits laufende Anfragen können ein Ziel schon erreicht haben.',
        error: 'Prüfeinstellungen konnten nicht bestätigt werden. Zum Wiederholen aktualisieren.', invalidResponse: 'Der Manager lieferte nicht unterstützte Prüfeinstellungen. Vor Änderungen aktualisieren.', timeout: 'Der Manager hat nicht rechtzeitig geantwortet. Zum Wiederholen aktualisieren.',
        session: 'Die Sitzung oder Berechtigungen wurden geändert. Erneut anmelden.', paused: 'Prüfeinstellungen aktualisieren, um einen neuen Stand zu laden.', conflict: 'Diese Einstellungen wurden geändert. Aktualisieren und die aktuellen Ziele vor einem neuen Versuch prüfen.',
        writeUncertain: 'Die Änderung konnte nicht bestätigt werden und kann bereits wirksam sein. Vor einer weiteren Anfrage aktualisieren; es wird nichts automatisch wiederholt.',
        saved: 'Entwurf gespeichert. Prüfungen sind aus.', enabled: 'Prüfungen für die geprüften Ziele aktiviert.', disabled: 'Prüfungen deaktiviert. Gespeicherte Ziele bleiben erhalten.', working: 'Bestätigung durch den Manager wird abgewartet…',
    },
};
type Labels = typeof copy.en;
type Failure = 'error' | 'invalidResponse' | 'timeout' | 'session' | 'paused' | 'conflict' | 'writeUncertain';
type Editor = 'save' | 'enable' | 'disable' | null;
type Draft = { kind: ApplicationTarget['kind']; id: string; url: string; host: string; port: string; ips: string; privateAck: boolean; httpAck: boolean };
const emptyTarget = (kind: Draft['kind'] = 'http', id = ''): Draft => ({ kind, id, url: '', host: '', port: '', ips: '', privateAck: false, httpAck: false });
const draftTarget = (target: ApplicationTarget): Draft => ({ ...emptyTarget(target.kind, target.id), url: target.kind === 'http' ? target.url : '', host: target.kind !== 'http' ? target.host : '', port: target.kind === 'tcp' ? String(target.port) : '', ips: target.allowedAddresses.join('\n') });
const asTarget = (draft: Draft): ApplicationTarget => {
    const base = { id: draft.id.trim(), allowedAddresses: draft.ips.split(/[,\n]/).map(ip => ip.trim()).filter(Boolean), allowPrivateLAN: draft.privateAck };
    return draft.kind === 'http' ? { ...base, kind: 'http', url: draft.url.trim(), plaintextHTTPAcknowledged: draft.httpAck } : draft.kind === 'dns' ? { ...base, kind: 'dns', host: draft.host.trim() } : { ...base, kind: 'tcp', host: draft.host.trim(), port: /^[1-9][0-9]{0,4}$/.test(draft.port) ? Number(draft.port) : 0 };
};

/** No automatic retry, no polling and no retained authority after interrupted reads/writes. */
function useApplicationSettings(clearForm: () => void, conceal: () => void) {
    const [view, setView] = useState<ApplicationCheckSettings | null>(null), [busy, setBusy] = useState<'read' | 'write' | null>(null), [locked, setLocked] = useState(false);
    const [failure, setFailure] = useState<Failure | null>(null), [notice, setNotice] = useState<'saved' | 'enabled' | 'disabled' | null>(null);
    const viewEpoch = useRef(getProtectedRequestEpoch());
    const callbacks = useRef({ clearForm, conceal }); callbacks.current = { clearForm, conceal };
    const commands = useRef({ read: () => {}, write: (_value: ApplicationCheckSettingsChange) => {}, dismiss: () => {} });
    useEffect(() => {
        let alive = true, ended = false, suspended = document.visibilityState === 'hidden', uncertainWrite = false, latest: ApplicationCheckSettings | null = null;
        let pending: { controller: AbortController; timeout: number; write: boolean } | null = null;
        const epoch = getProtectedRequestEpoch(); viewEpoch.current = epoch;
        const hidden = () => document.visibilityState === 'hidden';
        const cancel = () => { pending?.controller.abort(); window.clearTimeout(pending?.timeout); pending = null; };
        const clear = () => { latest = null; setView(null); setBusy(null); setNotice(null); callbacks.current.clearForm(); };
        const lock = () => { if (!alive) return; ended = true; cancel(); clear(); callbacks.current.conceal(); setLocked(true); setFailure('session'); };
        const authorized = () => { if (!alive || ended) return false; if (epoch !== getProtectedRequestEpoch() || hasLogoutIntent()) { lock(); return false; } return true; };
        const suspend = (hide: boolean) => { if (!alive) return; const uncertain = pending?.write || uncertainWrite; suspended = hide; cancel(); clear(); callbacks.current.conceal(); setFailure(uncertain ? 'writeUncertain' : 'paused'); };
        const perform = async (write?: ApplicationCheckSettingsChange) => {
            if (!authorized() || pending || suspended || document.visibilityState === 'hidden') return;
            if (write && (!latest || latest.mode !== 'managed' || latest.blocked || latest.revision !== write.expectedRevision || write.operation === 'enable' && (!latest.configured || latest.enabled))) return;
            const previous = latest, controller = new AbortController(), mono = performance.now(), wall = Date.now();
            const active = () => alive && !controller.signal.aborted && authorized() && pending?.controller === controller;
            const fail = (reason: Failure) => { if (write) uncertainWrite = reason === 'writeUncertain'; cancel(); clear(); setFailure(uncertainWrite ? 'writeUncertain' : reason); };
            pending = { controller, write: !!write, timeout: window.setTimeout(() => { if (active()) fail(write ? 'writeUncertain' : 'timeout'); }, 10000) };
            if (write) uncertainWrite = true;
            latest = null; setView(null); callbacks.current.clearForm(); setBusy(write ? 'write' : 'read'); setFailure(null); setNotice(null);
            try {
                const value = write ? await mutateRaw<unknown>('/application-checks/settings', JSON.stringify(write), {}, controller.signal, APPLICATION_CHECK_SETTINGS_BYTES) : await request<unknown>('/application-checks/settings', { signal: controller.signal, cache: 'no-store' }, APPLICATION_CHECK_SETTINGS_BYTES);
                if (!active()) return;
                if (hidden()) { suspend(true); return; }
                const elapsed = performance.now() - mono;
                if (elapsed < 0 || elapsed >= 10000 || Math.abs(Date.now() - wall - elapsed) > 1500) { fail(write ? 'writeUncertain' : 'timeout'); return; }
                if (!validApplicationCheckSettings(value)) { fail(write ? 'writeUncertain' : 'invalidResponse'); return; }
                if (write && (!previous || value.mode !== 'managed' || value.blocked || value.revision === previous.revision || value.enabled !== (write.operation === 'enable') || !sameApplicationTargets(value.targets, write.operation === 'save' ? write.targets : previous.targets) || value.intervalSeconds !== (write.operation === 'save' ? write.intervalSeconds : previous.intervalSeconds))) { fail('writeUncertain'); return; }
                uncertainWrite = false; latest = value; setView(value);
                if (write) setNotice(write.operation === 'save' ? 'saved' : write.operation === 'enable' ? 'enabled' : 'disabled');
            } catch (error) {
                if (!active()) return;
                if (error instanceof APIError && [401, 403].includes(error.status ?? 0)) { lock(); return; }
                fail(write ? error instanceof APIError && error.status === 409 ? 'conflict' : 'writeUncertain' : 'error');
            } finally {
                if (alive && pending?.controller === controller) { window.clearTimeout(pending.timeout); pending = null; setBusy(null); }
            }
        };
        const resume = () => { if (authorized() && document.visibilityState !== 'hidden') suspended = false; };
        const pagehide = () => suspend(true), navigate = () => suspend(false), visibility = () => document.visibilityState === 'hidden' ? suspend(true) : resume();
        const storage = (event: StorageEvent) => { if ((event.key === LOGOUT_INTENT_KEY || event.key === null) && hasLogoutIntent()) lock(); };
        commands.current = { read: () => { void perform(); }, write: value => { void perform(value); }, dismiss: () => { callbacks.current.clearForm(); if (pending) { const write = pending.write || uncertainWrite; cancel(); clear(); setFailure(write ? 'writeUncertain' : 'paused'); } } };
        window.addEventListener(AUTH_REQUIRED_EVENT, lock); window.addEventListener('pagehide', pagehide); window.addEventListener('pageshow', resume); window.addEventListener('hashchange', navigate); window.addEventListener('popstate', navigate); window.addEventListener('storage', storage); document.addEventListener('visibilitychange', visibility);
        const guard = window.setInterval(authorized, 1000); void perform();
        return () => {
            alive = false; cancel(); window.clearInterval(guard); commands.current = { read: () => {}, write: () => {}, dismiss: () => {} };
            window.removeEventListener(AUTH_REQUIRED_EVENT, lock); window.removeEventListener('pagehide', pagehide); window.removeEventListener('pageshow', resume); window.removeEventListener('hashchange', navigate); window.removeEventListener('popstate', navigate); window.removeEventListener('storage', storage); document.removeEventListener('visibilitychange', visibility);
        };
    }, []);
    return { view: viewEpoch.current === getProtectedRequestEpoch() && !hasLogoutIntent() ? view : null, busy, locked, failure, notice, refresh: () => commands.current.read(), write: (value: ApplicationCheckSettingsChange) => commands.current.write(value), dismiss: () => commands.current.dismiss() };
}
function SavedTargets({ view, labels }: { view: ApplicationCheckSettings; labels: Labels }) {
    return <div className="check-settings-snapshot"><p>{labels.every}: <strong>{view.intervalSeconds}</strong></p><ol>{view.targets.map(target => <li key={target.id}><strong>{target.id} · {target.kind === 'http' ? 'HTTP / HTTPS' : target.kind.toUpperCase()}</strong><span className="check-settings-destination">{target.kind === 'http' ? target.url : target.kind === 'tcp' ? `${target.host.includes(':') ? `[${target.host}]` : target.host}:${target.port}` : target.host}</span><span>{labels.allowed}: {target.allowedAddresses.join(', ')}</span>{target.allowPrivateLAN && <span>{labels.private}</span>}{target.kind === 'http' && target.plaintextHTTPAcknowledged && <span>{labels.plaintextTarget}</span>}</li>)}</ol></div>;
}
function TargetForm({ draft, index, count, labels, change, remove }: { draft: Draft; index: number; count: number; labels: Labels; change: (draft: Draft) => void; remove: () => void }) {
    const help = useId();
    const patch = (field: keyof Draft, value: string) => change({ ...draft, [field]: value, privateAck: false, httpAck: false });
    return <fieldset className="check-settings-target"><legend>{labels.target} {index + 1}</legend><div className="check-settings-fields">
        <label>{labels.id}<input value={draft.id} maxLength={48} spellCheck={false} autoCapitalize="none" onChange={event => patch('id', event.target.value)}/></label>
        <label>{labels.kind}<select value={draft.kind} onChange={event => change(emptyTarget(event.target.value as Draft['kind'], draft.id))}><option value="http">HTTP / HTTPS</option><option value="dns">DNS</option><option value="tcp">TCP</option></select></label>
        {draft.kind === 'http' ? <label className="check-settings-wide">{labels.url}<input type="text" value={draft.url} maxLength={1024} spellCheck={false} autoCapitalize="none" onChange={event => patch('url', event.target.value)}/></label> : <label className={draft.kind === 'dns' ? 'check-settings-wide' : ''}>{draft.kind === 'dns' ? labels.dnsHost : labels.tcpHost}<input value={draft.host} maxLength={253} spellCheck={false} autoCapitalize="none" onChange={event => patch('host', event.target.value)}/></label>}
        {draft.kind === 'tcp' && <label>{labels.port}<input type="text" inputMode="numeric" value={draft.port} maxLength={5} onChange={event => patch('port', event.target.value)}/></label>}
        <label className="check-settings-wide">{labels.ips}<textarea value={draft.ips} maxLength={1024} rows={2} spellCheck={false} autoCapitalize="none" aria-describedby={help} onChange={event => patch('ips', event.target.value)}/></label>
    </div><p id={help}>{labels.ipsHelp}</p>
        <label className="check-settings-check"><input type="checkbox" checked={draft.privateAck} onChange={event => change({ ...draft, privateAck: event.target.checked })}/><span>{labels.privateAck}</span></label>
        {draft.kind === 'http' && draft.url.trim().startsWith('http:') && <label className="check-settings-check"><input type="checkbox" checked={draft.httpAck} onChange={event => change({ ...draft, httpAck: event.target.checked })}/><span>{labels.httpAck}</span></label>}
        <button type="button" className="button" disabled={count <= 1} aria-label={`${labels.remove} ${index + 1}`} onClick={remove}>{labels.remove}</button>
    </fieldset>;
}
function ApplicationCheckSettingsContent({ insecureTestMode }: { insecureTestMode: boolean }) {
    const [locale] = useLocale(), labels = copy[locale], heading = useId(), body = useId();
    const toggle = useRef<HTMLButtonElement>(null);
    const [expanded, setExpanded] = useState(false), [editor, setEditor] = useState<Editor>(null), [drafts, setDrafts] = useState<Draft[]>([]), [interval, setInterval] = useState('60');
    const [managerAck, setManagerAck] = useState(false), [destinationsAck, setDestinationsAck] = useState(false), [transportAck, setTransportAck] = useState(false), [attempted, setAttempted] = useState(false);
    const resetApprovals = () => { setManagerAck(false); setDestinationsAck(false); setTransportAck(false); };
    const clearForm = () => { setEditor(null); setDrafts([]); setInterval('60'); resetApprovals(); setAttempted(false); };
    const { view, busy, locked, failure, notice, refresh, write, dismiss } = useApplicationSettings(clearForm, () => setExpanded(false));
    const editable = !!view && view.mode === 'managed' && !view.blocked && !busy && !locked;
    const targets = drafts.map(asTarget), validInterval = /^[0-9]{2,4}$/.test(interval) && Number(interval) >= 60 && Number(interval) <= 3600;
    const validTargets = targets.length > 0 && targets.length <= APPLICATION_CHECK_MAX_TARGETS && targets.every(validApplicationTarget) && new Set(targets.map(target => target.id)).size === targets.length;
    const permitted = editable && (editor === 'save' ? validInterval && validTargets : editor === 'enable' ? managerAck && destinationsAck && (!insecureTestMode || transportAck) : editor === 'disable');
    const choose = (next: Editor) => { if (!editable || !view) return; clearForm(); setEditor(next); if (next === 'save') { setInterval(String(view.intervalSeconds)); setDrafts(view.targets.length ? view.targets.map(draftTarget) : [emptyTarget()]); } };
    const submit = () => {
        setAttempted(true); if (!permitted || !view || !editor) return;
        write(editor === 'save' ? { expectedRevision: view.revision, operation: 'save', intervalSeconds: Number(interval), targets } : editor === 'enable' ? { expectedRevision: view.revision, operation: 'enable', checksFromManagerAcknowledged: true, destinationsAcknowledged: true, ...(insecureTestMode ? { plaintextAcknowledged: true as const } : {}) } : { expectedRevision: view.revision, operation: 'disable' });
    };
    const close = () => { dismiss(); setExpanded(false); toggle.current?.focus(); };
    return <section className="panel check-settings application-check-settings" aria-labelledby={heading} onKeyDown={event => { if (event.key === 'Escape' && expanded) { event.preventDefault(); close(); } }}>
        <div className="check-settings-heading"><h2 id={heading}><button ref={toggle} className="check-settings-toggle" aria-expanded={expanded} aria-controls={body} onClick={() => expanded ? close() : setExpanded(true)}><Activity size={17}/>{labels.title}<ChevronDown size={15}/></button></h2><span className="check-settings-state">{view ? view.configured ? `${view.targets.length} · ${view.enabled ? labels.on : labels.off}` : labels.unconfigured : busy === 'read' ? labels.loading : labels.unknown}</span><button className="icon-button" aria-label={labels.refresh} disabled={!!busy || locked} onClick={refresh}><RefreshCw size={15}/></button></div>
        {failure && <p className="check-settings-notice" role="alert">{labels[failure]}</p>}{notice && <p className="check-settings-notice" role="status">{labels[notice]}</p>}{busy === 'write' && <p className="check-settings-notice" role="status">{labels.working}</p>}
        {expanded && <div id={body} className="check-settings-body">
            {editor === null && <p>{labels.intro}</p>}{insecureTestMode && <p className="check-settings-warning">{labels.transportNote}</p>}
            {view?.mode === 'external' && <p>{labels.external}</p>}{view?.mode === 'unavailable' && <p>{labels.unavailable}</p>}{view?.blocked && <p role="alert">{labels.blocked}</p>}
            {view?.configured && editor !== 'save' && <>{editor === 'enable' && <h3>{labels.review}</h3>}<SavedTargets view={view} labels={labels}/></>}
            {editable && editor === null && <div className="check-settings-actions"><button className="button" onClick={() => choose('save')}>{view.configured ? labels.edit : labels.configure}</button>{view.configured && <button className="button" onClick={() => choose(view.enabled ? 'disable' : 'enable')}>{view.enabled ? labels.disable : labels.enable}</button>}</div>}
            {editable && editor !== null && <form className="check-settings-form" autoComplete="off" onSubmit={event => { event.preventDefault(); submit(); }}>
                {editor !== 'enable' && <h3>{editor === 'save' ? view.configured ? labels.edit : labels.configure : labels[editor]}</h3>}
                {editor === 'save' && <><p>{labels.targetHelp}</p><label className="check-settings-interval">{labels.interval}<input type="text" inputMode="numeric" maxLength={4} value={interval} onChange={event => { setInterval(event.target.value); resetApprovals(); }} aria-invalid={!validInterval}/></label><p>{labels.intervalHelp}</p>{!validInterval && <p role="alert">{labels.invalidInterval}</p>}
                    {drafts.map((draft, index) => <TargetForm key={index} draft={draft} index={index} count={drafts.length} labels={labels} change={next => { resetApprovals(); setDrafts(previous => previous.map((value, i) => i === index ? next : value)); }} remove={() => { resetApprovals(); setDrafts(previous => previous.filter((_, i) => i !== index)); }}/>) }
                    <div className="check-settings-actions"><button type="button" className="button" disabled={drafts.length >= APPLICATION_CHECK_MAX_TARGETS} onClick={() => { resetApprovals(); setDrafts(previous => previous.length < APPLICATION_CHECK_MAX_TARGETS ? [...previous, emptyTarget()] : previous); }}>{labels.add}</button><span>{drafts.length} / {APPLICATION_CHECK_MAX_TARGETS}</span></div>
                    {attempted && !validTargets && <p role="alert">{labels.invalid}</p>}<p>{labels.saveNote}</p>
                </>}
                {editor === 'enable' && <><label className="check-settings-check"><input type="checkbox" checked={managerAck} onChange={event => setManagerAck(event.target.checked)}/><span>{labels.managerAck}</span></label><label className="check-settings-check"><input type="checkbox" checked={destinationsAck} onChange={event => setDestinationsAck(event.target.checked)}/><span>{labels.destinationsAck}</span></label>{insecureTestMode && <label className="check-settings-check"><input type="checkbox" checked={transportAck} onChange={event => setTransportAck(event.target.checked)}/><span>{labels.transportAck}</span></label>}</>}
                {editor === 'disable' && <p>{labels.disableNote}</p>}
                <div className="check-settings-actions"><button className="button primary" type="submit" disabled={editor !== 'save' && !permitted}>{editor === 'save' ? labels.save : editor === 'enable' ? labels.confirmEnable : labels.confirmDisable}</button><button className="button" type="button" onClick={dismiss}>{labels.cancel}</button></div>
            </form>}
            <div className="check-settings-actions check-settings-close"><button className="button" onClick={close}>{busy ? labels.cancel : labels.close}</button></div>
        </div>}
    </section>;
}
export function ApplicationCheckSettingsPanel() {
    const operator = useOperator(), [locale] = useLocale();
    if (!operator || operator.mode !== 'lan' || !operator.authenticated) return null;
    const canManage = (operator.loginMode ?? 'shared') === 'shared' || operator.capabilities?.includes('manage_application_checks') === true;
    if (!canManage) return <section className="panel check-settings check-settings-readonly" aria-label={copy[locale].title}><p>{copy[locale].readonly}</p></section>;
    return <ApplicationCheckSettingsContent key={`${operator.actorId ?? ''}:${operator.expiresAt ?? ''}:${operator.insecureTestMode}`} insecureTestMode={operator.insecureTestMode}/>;
}
