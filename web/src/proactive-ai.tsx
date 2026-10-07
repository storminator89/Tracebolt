import { useEffect, useId, useRef, useState } from 'react';
import { Bot, ChevronDown, RefreshCw } from 'lucide-react';
import { APIError, AUTH_REQUIRED_EVENT, getProtectedRequestEpoch, mutateRaw, request } from './api';
import { hasLogoutIntent, LOGOUT_INTENT_KEY, useOperator } from './auth';
import { useLocale } from './i18n';
import { PROACTIVE_SETTINGS_BYTES, validProactiveAISettings } from './proactive-ai-types';
import type { ProactiveAIChange, ProactiveAISettings } from './proactive-ai-types';
import type { FleetIdentityResource } from './fleet-identity-resource';
import { ProactiveDeviceIdentity, proactiveDeviceName } from './proactive-device-identity';
import './proactive-ai.css';

const copy = {
    en: {
        title: 'Proactive AI diagnostics', refresh: 'Refresh proactive AI settings', loading: 'Reading proactive AI settings…', working: 'Saving settings…', unknown: 'Status unknown', on: 'On', off: 'Off',
        intro: 'Automatically analyze future health incidents on selected enrolled devices.',
        readonly: 'Named accounts can read these settings. Changes require the shared LAN administrator.', provider: 'Approved provider', model: 'Model', missingProvider: 'Configure an AI provider above, then refresh this panel.',
        scope: 'Data scope', scopeText: 'Stored health rule state, selected service name, numeric values and original event times only. No raw logs, device names, IP addresses or free-form notes.',
        unavailableDevice: 'Unavailable; remove before approving a new scope', devices: 'Selected enrolled devices', noDevices: 'No enrolled devices available.', consent: 'I approve future health-summary analyses for these selected devices with the exact provider URL and model shown above.',
        limits: 'At most 6 analyses/hour, one in flight, at least 60 seconds apart and a 30-minute incident cooldown. Evidence context is capped at 24 KiB; model output at 1,024 tokens.',
        forwarding: 'Provider charges may apply. Even local endpoints can forward data; masking is not guaranteed.',
        details: 'Limits & privacy details', privacy: 'Masking is best effort, not a guarantee that all sensitive content is removed. Opening investigations only reads stored results.',
        restartSummary: 'Approval survives manager restart for this exact scope. Provider changes disable it.',
        identityLoading: 'Loading reported hostnames and IP addresses…', identityUnavailable: 'Reported hostnames and IP addresses are unavailable.', identityRefresh: 'Refresh hostnames and IP addresses',
        persistentConsent: 'I approve future health-summary analyses, including after manager restart, for these selected devices with the exact provider URL and model shown above.',
        persistent: 'Approval is saved in a protected file on this manager with its original approval time. It remains valid after restart for this exact provider, device and data scope. Provider changes disable it; no older incidents are backfilled. Saving does not test provider connectivity.',
        reset: 'Approval resets to off after manager restart or provider changes.', connectivity: 'Saving does not test provider connectivity.',
        logs: 'Raw-log sharing is unavailable.', logsHelp: 'Raw logs require separate local collection approval and specific provider approval. Raw-log sharing is unavailable here.',
        save: 'Approve and enable', update: 'Approve updated scope', disable: 'Disable proactive AI', close: 'Close', cancel: 'Cancel waiting', saved: 'Settings saved. No connectivity test was sent.',
        error: 'Settings could not be read. Refresh to try again.', invalid: 'Unsupported settings received. Refresh before making changes.', timeout: 'The manager did not respond in time. Refresh to try again.',
        conflict: 'The provider or settings changed. Refresh and review the current destination, model and devices; approval must be given again.',
        uncertain: 'This change could not be confirmed and may already have taken effect. Refresh before another request. It will not be replayed automatically.',
        session: 'Your session or permissions changed. Sign in again.', paused: 'Refresh to review current settings before making changes.',
    },
    de: {
        title: 'Proaktive KI-Diagnostik', refresh: 'Proaktive KI-Einstellungen aktualisieren', loading: 'Proaktive KI-Einstellungen werden gelesen…', working: 'Einstellungen werden gespeichert…', unknown: 'Status unbekannt', on: 'Ein', off: 'Aus',
        intro: 'Künftige Health-Vorfälle ausgewählter freigegebener Geräte automatisch analysieren.',
        readonly: 'Benannte Konten können diese Einstellungen lesen. Änderungen erfordern den gemeinsamen LAN-Administrator.', provider: 'Freigegebener Anbieter', model: 'Modell', missingProvider: 'Oben einen KI-Anbieter einrichten, dann dieses Feld aktualisieren.',
        scope: 'Datenumfang', scopeText: 'Nur gespeicherter Health-Regelzustand, ausgewählter Dienstname, Zahlenwerte und ursprüngliche Ereigniszeiten. Keine Rohlogs, Gerätenamen, IP-Adressen oder Freitextnotizen.',
        unavailableDevice: 'Nicht verfügbar; vor einer neuen Freigabe entfernen', devices: 'Ausgewählte freigegebene Geräte', noDevices: 'Keine freigegebenen Geräte verfügbar.', consent: 'Ich erlaube künftige Health-Zusammenfassungsanalysen für diese ausgewählten Geräte mit genau der oben angezeigten Anbieter-URL und dem Modell.',
        limits: 'Höchstens 6 Analysen/Stunde, eine gleichzeitig, mindestens 60 Sekunden Abstand und 30 Minuten Vorfall-Abkühlzeit. Belegkontext: höchstens 24 KiB; Modellausgabe: 1.024 Tokens.',
        forwarding: 'Anbieterkosten können anfallen. Auch lokale Endpoints können Daten weiterleiten; Maskierung ist nicht garantiert.',
        details: 'Grenzen & Datenschutzdetails', privacy: 'Maskierung erfolgt nach bestem Bemühen und garantiert keine vollständige Entfernung sensibler Inhalte. Untersuchungen zeigen nur gespeicherte Ergebnisse.',
        restartSummary: 'Die Freigabe gilt nach einem Manager-Neustart für genau diesen Umfang weiter. Anbieteränderungen deaktivieren sie.',
        identityLoading: 'Gemeldete Hostnamen und IP-Adressen werden geladen…', identityUnavailable: 'Gemeldete Hostnamen und IP-Adressen sind nicht verfügbar.', identityRefresh: 'Hostname und IP-Adressen aktualisieren',
        persistentConsent: 'Ich erlaube künftige Health-Zusammenfassungsanalysen, auch nach einem Manager-Neustart, für diese ausgewählten Geräte mit genau der oben angezeigten Anbieter-URL und dem Modell.',
        persistent: 'Die Freigabe wird mit ihrem ursprünglichen Zeitpunkt in einer geschützten Datei auf diesem Manager gespeichert. Sie gilt nach einem Neustart für genau diesen Anbieter-, Geräte- und Datenumfang weiter. Anbieteränderungen deaktivieren sie; ältere Vorfälle werden nicht nachträglich analysiert. Speichern testet keine Anbieterverbindung.',
        reset: 'Nach Manager-Neustart oder Anbieteränderung wird die Freigabe deaktiviert.', connectivity: 'Speichern testet keine Anbieterverbindung.',
        logs: 'Rohlogs können hier nicht freigegeben werden.', logsHelp: 'Rohlogs benötigen eine separate lokale Erfassungsfreigabe und eine ausdrückliche Anbieterfreigabe. Rohlogs können hier nicht freigegeben werden.',
        save: 'Freigeben und aktivieren', update: 'Geänderten Umfang freigeben', disable: 'Proaktive KI deaktivieren', close: 'Schließen', cancel: 'Warten abbrechen', saved: 'Einstellungen gespeichert. Es wurde kein Verbindungstest gesendet.',
        error: 'Einstellungen konnten nicht gelesen werden. Zum Wiederholen aktualisieren.', invalid: 'Nicht unterstützte Einstellungen erhalten. Vor Änderungen aktualisieren.', timeout: 'Der Manager hat nicht rechtzeitig geantwortet. Zum Wiederholen aktualisieren.',
        conflict: 'Anbieter oder Einstellungen wurden geändert. Aktualisieren und Ziel, Modell und Geräte erneut prüfen und freigeben.',
        uncertain: 'Die Änderung konnte nicht bestätigt werden und kann bereits wirksam sein. Vor einer neuen Anfrage aktualisieren. Sie wird nicht automatisch wiederholt.',
        session: 'Sitzung oder Berechtigungen wurden geändert. Erneut anmelden.', paused: 'Aktualisieren, um die aktuellen Einstellungen vor Änderungen zu prüfen.',
    },
};
type Failure = 'error' | 'invalid' | 'timeout' | 'conflict' | 'uncertain' | 'session' | 'paused';

/** Serialized, bounded reads/writes. Uncertain writes are never retried. */
function useProactiveAI(canManage: boolean, clearForm: () => void) {
    const [view, setView] = useState<ProactiveAISettings | null>(null), [busy, setBusy] = useState<'read' | 'write' | null>(null), [failure, setFailure] = useState<Failure | null>(null), [saved, setSaved] = useState(false), [locked, setLocked] = useState(false);
    const form = useRef(clearForm); form.current = clearForm;
    const viewEpoch = useRef(getProtectedRequestEpoch());
    const commands = useRef({ read: () => {}, write: (_value: ProactiveAIChange) => {}, cancel: () => {} });
    useEffect(() => {
        let alive = true, ended = false, suspended = document.visibilityState === 'hidden', latest: ProactiveAISettings | null = null;
        let pending: { controller: AbortController; timeout: number; write: boolean } | null = null;
        let observed: { mono: number; wall: number } | null = null;
        const epoch = getProtectedRequestEpoch(); viewEpoch.current = epoch;
        const hidden = () => document.visibilityState === 'hidden';
        const cancel = () => { pending?.controller.abort(); window.clearTimeout(pending?.timeout); pending = null; };
        const clear = () => { latest = null; observed = null; setView(null); setBusy(null); setSaved(false); form.current(); };
        const fail = (reason: Failure) => { cancel(); clear(); setFailure(reason); };
        const lock = () => { if (!alive) return; ended = true; fail('session'); setLocked(true); };
        const authorized = () => { if (!alive || ended) return false; if (epoch !== getProtectedRequestEpoch() || hasLogoutIntent()) { lock(); return false; } return true; };
        const age = () => observed ? performance.now() - observed.mono : Infinity;
        const fresh = () => observed !== null && age() >= 0 && age() < 60000 && Math.abs(Date.now() - observed.wall - age()) <= 1500;
        const perform = async (write?: ProactiveAIChange) => {
            if (!authorized() || pending || suspended || document.visibilityState === 'hidden') return;
            if (write && (!canManage || !latest || latest.revision !== write.expectedRevision || latest.configRevision !== write.configRevision)) return;
            if (write && !fresh()) { fail('paused'); return; }
            if (write?.enabled && (!latest?.providerConfigured || !write.acknowledgeData || write.deviceIds.length === 0 || write.approvedBaseURL !== latest.baseURL || write.approvedModel !== latest.model || !write.deviceIds.every(id => latest!.availableDevices.some(device => device.id === id)))) return;
            const controller = new AbortController(), started = { mono: performance.now(), wall: Date.now() };
            const active = () => alive && !controller.signal.aborted && authorized() && pending?.controller === controller;
            pending = { controller, write: !!write, timeout: window.setTimeout(() => { if (active()) fail(write ? 'uncertain' : 'timeout'); }, 10000) };
            latest = null; observed = null; setView(null); form.current(); setBusy(write ? 'write' : 'read'); setFailure(null); setSaved(false);
            try {
                const value = write ? await mutateRaw<unknown>('/ai/proactive', JSON.stringify(write), {}, controller.signal, PROACTIVE_SETTINGS_BYTES) : await request<unknown>('/ai/proactive', { signal: controller.signal, cache: 'no-store' }, PROACTIVE_SETTINGS_BYTES);
                if (!active()) return;
                const elapsed = performance.now() - started.mono;
                if (hidden() || elapsed < 0 || elapsed >= 10000 || Math.abs(Date.now() - started.wall - elapsed) > 1500) { fail(write ? 'uncertain' : 'paused'); return; }
                if (!validProactiveAISettings(value)) { fail(write ? 'uncertain' : 'invalid'); return; }
                latest = value; observed = started; setView(value); setSaved(!!write);
            } catch (error) {
                if (!active()) return;
                if (error instanceof APIError && [401, 403].includes(error.status ?? 0)) { lock(); return; }
                fail(write ? error instanceof APIError && error.status === 409 ? 'conflict' : 'uncertain' : 'error');
            } finally {
                if (alive && pending?.controller === controller) { window.clearTimeout(pending.timeout); pending = null; setBusy(null); }
            }
        };
        const suspend = (hidden: boolean) => { if (!alive) return; suspended = hidden; fail(pending?.write ? 'uncertain' : 'paused'); };
        const resume = () => { if (authorized() && document.visibilityState !== 'hidden') suspended = false; };
        const hide = () => suspend(true), navigate = () => suspend(false), visibility = () => document.visibilityState === 'hidden' ? hide() : resume();
        const providerChanged = () => { if (!authorized()) return; fail(pending?.write ? 'uncertain' : 'paused'); if (!suspended) void perform(); };
        const storage = (event: StorageEvent) => { if ((event.key === LOGOUT_INTENT_KEY || event.key === null) && hasLogoutIntent()) lock(); };
        commands.current = { read: () => { void perform(); }, write: value => { void perform(value); }, cancel: () => { form.current(); if (pending) fail(pending.write ? 'uncertain' : 'paused'); } };
        window.addEventListener('tracebolt-ai-config-changed', providerChanged); window.addEventListener(AUTH_REQUIRED_EVENT, lock); window.addEventListener('pagehide', hide); window.addEventListener('pageshow', resume); window.addEventListener('blur', hide); window.addEventListener('focus', resume);
        window.addEventListener('hashchange', navigate); window.addEventListener('popstate', navigate); window.addEventListener('storage', storage); document.addEventListener('visibilitychange', visibility);
        const guard = window.setInterval(() => { if (authorized() && observed && !fresh()) fail('paused'); }, 1000);
        void perform();
        return () => {
            alive = false; cancel(); window.clearInterval(guard); commands.current = { read: () => {}, write: () => {}, cancel: () => {} };
            window.removeEventListener('tracebolt-ai-config-changed', providerChanged); window.removeEventListener(AUTH_REQUIRED_EVENT, lock); window.removeEventListener('pagehide', hide); window.removeEventListener('pageshow', resume); window.removeEventListener('blur', hide); window.removeEventListener('focus', resume);
            window.removeEventListener('hashchange', navigate); window.removeEventListener('popstate', navigate); window.removeEventListener('storage', storage); document.removeEventListener('visibilitychange', visibility);
        };
    }, [canManage]);
    return { view: viewEpoch.current === getProtectedRequestEpoch() && !hasLogoutIntent() ? view : null, busy, failure, saved, locked, refresh: () => commands.current.read(), write: (value: ProactiveAIChange) => commands.current.write(value), cancel: () => commands.current.cancel() };
}

type ProactiveAIProps = { fleetIdentity?: Pick<FleetIdentityResource, 'identities' | 'loading' | 'error' | 'refresh'> };

function ProactiveAIContent({ canManage, fleetIdentity }: ProactiveAIProps & { canManage: boolean }) {
    const [locale] = useLocale(), labels = copy[locale], heading = useId(), body = useId();
    const [expanded, setExpanded] = useState(false), [selected, setSelected] = useState<string[]>([]), [acknowledged, setAcknowledged] = useState(false);
    const toggle = useRef<HTMLButtonElement>(null);
    const state = useProactiveAI(canManage, () => { setSelected([]); setAcknowledged(false); });
    const { view, busy, failure, saved, locked } = state;
    useEffect(() => { setSelected(view?.deviceIds ?? []); setAcknowledged(false); }, [view]);
    const editable = !!view && canManage && !busy && !locked;
    const unavailable = selected.filter(id => !view?.availableDevices.some(device => device.id === id));
    const deviceIds = [...(view?.availableDevices.map(device => device.id) ?? []), ...unavailable];
    // These observations are display-only; mutations continue to use the exact enrolled IDs.
    const identityFor = (id: string) => !fleetIdentity?.loading && !fleetIdentity?.error ? fleetIdentity?.identities.get(id) : undefined;
    const canApprove = editable && !!view?.providerConfigured && selected.length > 0 && unavailable.length === 0;
    const close = () => { state.cancel(); setSelected(view?.deviceIds ?? []); setExpanded(false); toggle.current?.focus(); };
    const change = (enabled: boolean) => {
        if (!view || !editable || enabled && (!canApprove || !acknowledged)) return;
        state.write({ expectedRevision: view.revision, configRevision: view.configRevision, enabled, deviceIds: enabled ? selected : view.deviceIds, approvedBaseURL: view.baseURL, approvedModel: view.model, dataScope: 'health-summary-v1', acknowledgeData: enabled && acknowledged });
    };
    return <section className="panel proactive-ai" aria-labelledby={heading} onKeyDown={event => { if (event.key === 'Escape' && expanded) { event.preventDefault(); close(); } }}>
        <div className="proactive-ai-heading"><h2 id={heading}><button ref={toggle} className="proactive-ai-toggle" aria-expanded={expanded} aria-controls={body} onClick={() => expanded ? close() : setExpanded(true)}><Bot size={16} aria-hidden="true"/>{labels.title}<ChevronDown size={14} aria-hidden="true"/></button></h2><span>{view ? view.enabled ? labels.on : labels.off : labels.unknown}</span><button className="icon-button" onClick={state.refresh} disabled={!!busy || locked} aria-label={labels.refresh} title={labels.refresh}><RefreshCw size={15} className={busy === 'read' ? 'spin' : undefined} aria-hidden="true"/></button></div>
        {failure && <p className="proactive-ai-notice" role={failure === 'paused' ? 'status' : 'alert'}>{labels[failure]}</p>}
        {busy && <p className="proactive-ai-notice" role="status">{busy === 'write' ? labels.working : labels.loading}</p>}
        {saved && <p className="proactive-ai-notice" role="status">{labels.saved}</p>}
        {expanded && <div id={body} className="proactive-ai-body"><p>{labels.intro}</p>{!canManage && <p>{labels.readonly}</p>}
            {view && <><dl className="proactive-ai-destination"><div><dt>{labels.provider}</dt><dd>{view.providerConfigured ? view.baseURL : labels.missingProvider}</dd></div><div><dt>{labels.model}</dt><dd>{view.model || '—'}</dd></div></dl>
                <p><strong>{labels.scope}: </strong>{labels.scopeText}</p>
                <fieldset disabled={!editable || !view.providerConfigured} className="proactive-ai-devices"><legend>{labels.devices}</legend>{view.availableDevices.length ? view.availableDevices.map(device => <label className="proactive-ai-check proactive-ai-device" key={device.id}><input type="checkbox" value={device.id} aria-label={`${proactiveDeviceName(identityFor(device.id), locale)} · ${device.id}`} checked={selected.includes(device.id)} onChange={event => { setSelected(ids => event.target.checked ? [...ids, device.id] : ids.filter(id => id !== device.id)); setAcknowledged(false); }}/><ProactiveDeviceIdentity identity={identityFor(device.id)} deviceId={device.id} deviceIds={deviceIds}/></label>) : <p>{labels.noDevices}</p>}{unavailable.map(id => <label className="proactive-ai-check proactive-ai-device" key={id}><input type="checkbox" value={id} aria-label={`${labels.unavailableDevice} · ${id}`} checked onChange={() => { setSelected(ids => ids.filter(value => value !== id)); setAcknowledged(false); }}/><span><ProactiveDeviceIdentity deviceId={id} deviceIds={deviceIds}/><small>{labels.unavailableDevice}</small></span></label>)}</fieldset>
                {fleetIdentity && <div className="proactive-ai-identity-status">{(fleetIdentity.loading || fleetIdentity.error) && <span role="status">{fleetIdentity.loading ? labels.identityLoading : labels.identityUnavailable}</span>}<button className="text-button" disabled={fleetIdentity.loading || fleetIdentity.error === 'session'} onClick={fleetIdentity.refresh}>{labels.identityRefresh}</button></div>}
                <p className="proactive-ai-caveat">{labels.forwarding}</p><p className="proactive-ai-restart">{view.resetsOnRestart ? labels.reset : labels.restartSummary}</p>
                {canManage && <><label className="proactive-ai-check proactive-ai-consent"><input type="checkbox" disabled={!canApprove} checked={acknowledged} onChange={event => setAcknowledged(event.target.checked)}/><span>{view.resetsOnRestart ? labels.consent : labels.persistentConsent}</span></label><div className="proactive-ai-actions"><button className="button primary" disabled={!canApprove || !acknowledged} onClick={() => change(true)}>{view.enabled ? labels.update : labels.save}</button>{view.enabled && <button className="button" disabled={!editable} onClick={() => change(false)}>{labels.disable}</button>}</div></>}
                <details className="proactive-ai-details"><summary>{labels.details}</summary><p>{labels.limits}</p><p>{labels.privacy}</p><p>{labels.logs} {labels.logsHelp}</p><p>{view.resetsOnRestart ? labels.connectivity : labels.persistent}</p></details>
            </>}
            <div className="proactive-ai-actions">{busy && <button className="button" onClick={state.cancel}>{labels.cancel}</button>}<button className="button" onClick={close}>{labels.close}</button></div>
        </div>}
    </section>;
}
export function ProactiveAISettingsPanel({ fleetIdentity }: ProactiveAIProps = {}) {
    const operator = useOperator();
    if (!operator || operator.mode !== 'lan' || !operator.authenticated) return null;
    const canManage = (operator.loginMode ?? 'shared') === 'shared';
    return <ProactiveAIContent key={`${operator.actorId ?? ''}:${operator.expiresAt ?? ''}:${canManage}`} canManage={canManage} fleetIdentity={fleetIdentity}/>;
}
