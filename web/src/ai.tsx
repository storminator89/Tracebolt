import './ai-analysis.css';
import { t, ui } from './i18n';
import { useCallback, useEffect, useRef, useState } from 'react';
import { ArrowRight, Bot, Check, ChevronRight, CircleHelp, Cloud, FileCheck2, Fingerprint, Info, KeyRound, Link2, LoaderCircle, LockKeyhole, RefreshCw, Send, Server, ShieldCheck, SlidersHorizontal, Square, Trash2, TriangleAlert } from 'lucide-react';
import { APIError, mutate, request } from './api';
import type { AIConfig, AnalysisResult, Claim, EndpointInfo } from './ai-types';
import { endpointInfo, safeAIError, validAIConfig } from './ai-types';
import type { Case, Evidence } from './types';
import { Dialog, Loading, SectionHead, Source } from './components';
import { fullDate, qualityLabels } from './utils';
function useAIConfig() {
    const [config, setConfig] = useState<AIConfig | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const alive = useRef(true);
    const controller = useRef<AbortController | null>(null);
    useEffect(() => { alive.current = true; return () => { alive.current = false; controller.current?.abort(); }; }, []);
    const refresh = useCallback(async () => {
        controller.current?.abort();
        const current = new AbortController();
        controller.current = current;
        if (alive.current) {
            setLoading(true);
            setError('');
        }
        try {
            const next = await request<AIConfig>('/ai/config', { signal: current.signal });
            if (!validAIConfig(next))
                throw new APIError(t("Die KI-Konfiguration ist unvollst\u00E4ndig."));
            if (!alive.current || current.signal.aborted)
                return null;
            setConfig(next);
            return next;
        }
        catch (err) {
            if (alive.current && !current.signal.aborted) {
                setConfig(null);
                setError(safeAIError(err));
            }
            return null;
        }
        finally {
            if (alive.current && !current.signal.aborted)
                setLoading(false);
        }
    }, []);
    useEffect(() => { void refresh(); }, [refresh]);
    return { config, setConfig, loading, error, refresh, invalidate: (message: string) => { setConfig(null); setError(message); } };
}
function Destination({ info, endpoint, compact = false }: {
    info: EndpointInfo;
    endpoint: string;
    compact?: boolean;
}) { return <div className={`ai-destination ${compact ? 'compact' : ''}`}><span className="ai-destination-icon">{info.local ? <Server size={17}/> : <Cloud size={17}/>}</span><div><strong>{info.valid ? info.local ? t("Loopback-Anbieter") : t("Externer HTTPS-Anbieter") : t("Ziel festlegen")}</strong><code>{info.valid ? endpoint : t("Noch keine g\u00FCltige Basis-URL")}</code></div>{info.valid && <span className="ai-destination-tag">{info.local ? t("LOKALER ENDPOINT") : t("EXTERN")}</span>}</div>; }
export function AIProviderSettings() {
    const { config, setConfig, loading, error, refresh, invalidate } = useAIConfig();
    const [formRevision, setFormRevision] = useState('');
    const [baseURL, setBaseURL] = useState('');
    const [model, setModel] = useState('');
    const [apiKey, setAPIKey] = useState('');
    const [allowRemote, setAllowRemote] = useState(false);
    const [legacy, setLegacy] = useState(false);
    const [remember, setRemember] = useState(false);
    const [acknowledgeKeyStorage, setAcknowledgeKeyStorage] = useState(false);
    const [saving, setSaving] = useState(false);
    const [success, setSuccess] = useState('');
    const [confirmClear, setConfirmClear] = useState(false);
    const operation = useRef<AbortController | null>(null);
    const alive = useRef(true);
    const info = endpointInfo(baseURL);
    useEffect(() => { alive.current = true; return () => { alive.current = false; operation.current?.abort(); }; }, []);
    useEffect(() => {
        if (config) {
            setBaseURL(config.baseURL);
            setModel(config.model);
            setAllowRemote(config.allowRemoteEvidence);
            setLegacy(config.useLegacyMaxTokens);
            setAPIKey('');
            setRemember(false);
            setAcknowledgeKeyStorage(false);
            setFormRevision(config.revision);
        }
    }, [config]);
    const modelValid = model.length > 0 && model.length <= 128 && /^[\x21-\x7e]+$/.test(model);
    const keyValid = apiKey.length <= 4096 && /^[\x21-\x7e]*$/.test(apiKey) && (info.local || apiKey.length > 0);
    const persistenceReady = !remember || config?.persistenceAvailable === true && (!apiKey || config.persistentKeyAllowed === true && acknowledgeKeyStorage);
    const canSave = Boolean(config && !error && !loading && formRevision === config.revision && info.valid && modelValid && keyValid && (info.local || allowRemote) && persistenceReady && !saving);
    const save = async (event: React.SubmitEvent<HTMLFormElement>) => {
        event.preventDefault();
        if (!config || !canSave || operation.current)
            return;
        setSaving(true);
        setSuccess('');
        const secret = apiKey;
        setAPIKey('');
        setAcknowledgeKeyStorage(false);
        const current = new AbortController();
        operation.current = current;
        try {
            const change = { expectedRevision: config.revision, baseURL, model, apiKey: secret, approvedOrigin: info.origin, allowRemoteEvidence: !info.local && allowRemote, useLegacyMaxTokens: legacy };
            const next = await mutate<AIConfig>(remember ? '/ai/config/persistent' : '/ai/config', remember ? { ...change, acknowledgeKeyStorage: !!secret && acknowledgeKeyStorage } : change, current.signal);
            if (!validAIConfig(next) || !next.configured || next.revision === config.revision || next.baseURL !== baseURL || next.model !== model || next.keyConfigured !== !!secret || next.storage !== (remember ? 'protected-file' : 'memory-only')) throw new APIError(t("Die KI-Konfiguration ist unvollständig."));
            if (alive.current && !current.signal.aborted) {
                setConfig(next);
                window.dispatchEvent(new Event('tracebolt-ai-config-changed'));
                setSuccess(t("Konfiguration gespeichert. Der Anbieter wurde noch nicht kontaktiert."));
            }
        }
        catch {
            if (alive.current && !current.signal.aborted) {
                setAPIKey(''); setRemember(false); setAcknowledgeKeyStorage(false);
                invalidate(t('Die Änderung konnte nicht bestätigt werden und kann bereits wirksam sein. Vor einer neuen Anfrage erneut lesen. Keine automatische Wiederholung.'));
                window.dispatchEvent(new Event('tracebolt-ai-config-changed'));
            }
        }
        finally {
            if (operation.current === current) operation.current = null;
            if (alive.current && !current.signal.aborted)
                setSaving(false);
        }
    };
    const clear = async () => {
        if (!config || saving || operation.current)
            return;
        setConfirmClear(false);
        setSaving(true);
        setSuccess('');
        setAPIKey('');
        setAcknowledgeKeyStorage(false);
        const current = new AbortController();
        operation.current = current;
        try {
            const next = await mutate<AIConfig>('/ai/config/clear', { expectedRevision: config.revision }, current.signal);
            if (!validAIConfig(next) || next.configured || next.keyConfigured || next.revision === config.revision || next.storage !== 'memory-only') throw new APIError(t('Die KI-Konfiguration ist unvollständig.'));
            if (alive.current && !current.signal.aborted) {
                setConfig(next);
                window.dispatchEvent(new Event('tracebolt-ai-config-changed'));
                setSuccess(config.storage === 'protected-file' ? t("Anbieter, Schlüssel und gespeicherte proaktive Freigabe entfernt.") : t("Anbieter und Schl\u00FCssel aus dem Arbeitsspeicher entfernt."));
            }
        }
        catch {
            if (alive.current && !current.signal.aborted) {
                setAPIKey(''); setRemember(false); setAcknowledgeKeyStorage(false);
                invalidate(t('Die Änderung konnte nicht bestätigt werden und kann bereits wirksam sein. Vor einer neuen Anfrage erneut lesen. Keine automatische Wiederholung.'));
                window.dispatchEvent(new Event('tracebolt-ai-config-changed'));
            }
        }
        finally {
            if (operation.current === current) operation.current = null;
            if (alive.current && !current.signal.aborted)
                setSaving(false);
        }
    };
    return <section className="panel ai-settings-panel"><SectionHead title={t("KI-Anbieter")} action={<span className={`ai-config-status ${config?.configured ? 'configured' : ''}`}><span className="status-dot"/>{error ? t("Status unbekannt") : loading && !config ? t("L\u00E4dt \u2026") : config?.configured ? t("Konfiguriert \u00B7 ungetestet") : t("Nicht eingerichtet")}</span>}/>{error ? <div className="ai-inline-error" role="alert"><TriangleAlert size={17}/><p>{ui(error)}</p><button className="button small" onClick={() => void refresh()}>{t("Erneut versuchen")}</button></div> : loading || (config && formRevision !== config.revision) ? <Loading label={t("KI-Konfiguration wird geladen \u2026")}/> : config && <div className="ai-settings-layout"><form onSubmit={event => void save(event)} className="ai-provider-form"><label className="form-field"><span>{t("Basis-URL · OpenAI-kompatibel")}</span><div className="input-with-icon"><Link2 size={15}/><input disabled={saving} aria-label={t("KI Basis-URL")} value={baseURL} onChange={event => { setBaseURL(event.target.value); setAllowRemote(false); setAPIKey(''); setAcknowledgeKeyStorage(false); setSuccess(''); }} placeholder="http://127.0.0.1:11434/v1" type="url" maxLength={512} autoComplete="off" spellCheck={false}/></div>{baseURL && !info.valid && <small className="field-warning">{info.error}</small>}</label><label className="form-field"><span>{t("Modell")}</span><input disabled={saving} aria-label={t("KI Modell")} value={model} onChange={event => { setModel(event.target.value); setAPIKey(''); setAcknowledgeKeyStorage(false); setSuccess(''); }} placeholder={t("Modellkennung des Anbieters")} maxLength={128} autoComplete="off" spellCheck={false}/>{model && !modelValid && <small className="field-warning">{t("Modellkennung ohne Leer- oder Steuerzeichen eingeben.")}</small>}</label><label className="form-field"><span>{t("API-Schl\u00FCssel")}{config.keyConfigured && <span className="key-saved"><LockKeyhole size={11}/>{t("Schl\u00FCssel gesetzt")}</span>}</span><div className="input-with-icon"><KeyRound size={15}/><input disabled={saving} aria-label={t("KI API-Schl\u00FCssel")} type="password" value={apiKey} onChange={event => { setAPIKey(event.target.value); setAcknowledgeKeyStorage(false); setSuccess(''); }} maxLength={4096} autoComplete="off" spellCheck={false} placeholder={info.local ? t("Optional f\u00FCr Loopback") : t("Neuen Schl\u00FCssel eingeben")}/></div><small>{config.keyConfigured ? t('Ein gespeicherter Schlüssel wird nie automatisch übernommen. Zum Speichern erneut eingeben.') : remember ? t('Keine Speicherung im Browser. Dauerhafte Schlüsselspeicherung erfordert die separate Bestätigung unten.') : t("Nur im Arbeitsspeicher des Managers. Keine Speicherung im Browser oder auf Datentr\u00E4ger.")}</small>{apiKey && !keyValid && <small className="field-warning">{t("Schl\u00FCssel ohne Leer- oder Steuerzeichen eingeben.")}</small>}</label>{info.valid && !info.local && <label className="check-field remote-opt-in"><input disabled={saving} type="checkbox" checked={allowRemote} onChange={event => setAllowRemote(event.target.checked)}/><span>{t("Fallbelege für manuelle Analysen an {0} freigeben.", { "0": info.origin })}</span></label>}{config.persistenceAvailable === true && <div className="ai-persistence-options"><label className="check-field"><input disabled={saving} type="checkbox" checked={remember} onChange={event => { setRemember(event.target.checked); setAcknowledgeKeyStorage(false); setSuccess(''); }}/><span>{t('Anbieterkonfiguration nach einem Neustart auf diesem Manager behalten')}</span></label><p>{remember ? t('Geschützte Datei auf dem Manager. Dateischutz ist keine Verschlüsselung; Managerkonto, Administratoren und Sicherungen können darauf zugreifen. Keine Speicherung im Browser.') : t('Nur Arbeitsspeicher. Speichern entfernt zuvor gespeicherte Konfiguration und proaktive Freigabe.')}</p>{remember && apiKey.length > 0 && <><label className="check-field"><input disabled={saving || config.persistentKeyAllowed !== true} type="checkbox" checked={acknowledgeKeyStorage} onChange={event => setAcknowledgeKeyStorage(event.target.checked)}/><span>{t('Diesen Schlüssel auf diesem Manager speichern')}</span></label>{config.persistentKeyAllowed !== true && <p className="field-warning">{t('Schlüssel dürfen nur über den HTTPS-Operator-Zugang dauerhaft gespeichert werden. Im HTTP-Testmodus ist nur ein schlüsselloser Loopback-Anbieter möglich.')}</p>}</>}<p>{t('Speichern deaktiviert die proaktive Freigabe. Danach separat neu freigeben.')}</p></div>}<details className="ai-advanced"><summary><SlidersHorizontal size={14}/>{t("Kompatibilit\u00E4t")}<ChevronRight size={14}/></summary><label className="check-field"><input disabled={saving} type="checkbox" checked={legacy} onChange={event => setLegacy(event.target.checked)}/><span><code>max_tokens</code>{" " + t("statt") + " "}<code>max_completion_tokens</code><small>{t("Nur verwenden, wenn der Anbieter das \u00E4ltere Feld ben\u00F6tigt. Keine automatische Wiederholung.")}</small></span></label></details>{success && <div className="ai-form-message success" role="status"><Check size={15}/><span>{ui(success)}</span></div>}<div className="ai-form-actions"><button className="button primary" type="submit" disabled={!canSave}>{saving ? <LoaderCircle className="spin" size={14}/> : <Check size={14}/>}{t("Konfiguration speichern")}</button>{config.configured && <button className="icon-button danger-action" type="button" aria-label={t("KI-Anbieter entfernen")} title={t("Anbieter und Schl\u00FCssel entfernen")} onClick={() => setConfirmClear(true)} disabled={saving}><Trash2 size={16}/></button>}</div></form><aside className="ai-settings-context"><Destination info={info} endpoint={baseURL}/><div className="ai-memory-notice"><LockKeyhole size={16}/><div><strong>{config.storage === 'protected-file' ? t("Auf diesem Manager gespeichert") : t("Nur f\u00FCr diese Manager-Sitzung")}</strong><p>{config.storage === 'protected-file' ? t("Anbieter und gegebenenfalls Schlüssel bleiben in einer geschützten Datei nach einem Neustart verfügbar. Proaktive Analysen benötigen eine separate Freigabe.") : t("Nach einem Neustart m\u00FCssen Anbieter und Schl\u00FCssel neu gesetzt werden.")}</p></div></div><details className="ai-disclosure"><summary><Info size={14}/>{t("Daten & Grenzen")}<ChevronRight size={14}/></summary><ul><li>{t("Gesendet werden Falltitel, Zusammenfassung und ausgew\u00E4hlte Belege mit Rohtext, Quelle, Zeitpunkt und Datenqualit\u00E4t.")}</li><li>{t("Belege werden nicht automatisch von Geheimnissen oder personenbezogenen Inhalten bereinigt.")}</li><li>{t("Notizen, Ger\u00E4tekennungen und unbeteiligte Telemetrie sind ausgeschlossen.")}</li><li>{t("Ein Loopback-Endpoint kann Anfragen extern weiterleiten.")}</li><li>{t("Speichern stellt keine Verbindung her. Manuelle Fallanalysen starten nach deiner Bestätigung am Fall. Proaktive Health-Analysen werden separat freigegeben.")}</li></ul></details><div className="ai-scope-icons"><span><ShieldCheck size={14}/>{t("Keine Ausf\u00FChrung")}</span><span><FileCheck2 size={14}/>{t("Nur Fallbelege")}</span></div></aside></div>}{confirmClear && <Dialog title={t("KI-Anbieter entfernen")} onClose={() => setConfirmClear(false)} className="ai-confirm-dialog"><div className="confirm-symbol"><Trash2 size={22}/></div><h2>{t("KI-Anbieter entfernen?")}</h2><p>{config?.storage === 'protected-file' ? t("Konfiguration, Schlüssel und proaktive Freigabe werden dauerhaft entfernt. Eine laufende Anfrage wird abgebrochen.") : t("Konfiguration und Schl\u00FCssel werden aus dem Arbeitsspeicher entfernt. Eine laufende Anfrage wird abgebrochen.")}</p><div className="confirm-actions"><button className="button" onClick={() => setConfirmClear(false)}>{t("Abbrechen")}</button><button className="button primary" onClick={() => void clear()}>{t("Anbieter entfernen")}</button></div></Dialog>}</section>;
}
export function AIAnalysisPanel({ item, onSettings }: {
    item: Case;
    onSettings: () => void;
}) {
    const { config, setConfig, loading, error, refresh } = useAIConfig();
    const [result, setResult] = useState<AnalysisResult | null>(null);
    const [selectedEvidence, setSelectedEvidence] = useState<Evidence | null>(null);
    const [confirm, setConfirm] = useState<AIConfig | null>(null);
    const [reviewed, setReviewed] = useState(false);
    const [pending, setPending] = useState(false);
    const [analysisError, setAnalysisError] = useState('');
    const [preparing, setPreparing] = useState(false);
    const operation = useRef<AbortController | null>(null);
    const alive = useRef(true);
    useEffect(() => { alive.current = true; return () => { alive.current = false; operation.current?.abort(); }; }, []);
    const begin = async () => {
        setPreparing(true);
        setAnalysisError('');
        const latest = await refresh();
        if (alive.current) {
            setPreparing(false);
            if (latest?.configured) {
                if (result && result.configRevision !== latest.revision)
                    setResult(null);
                setReviewed(false);
                setConfirm(latest);
            }
        }
    };
    const analyze = async () => {
        if (!confirm || !reviewed || pending)
            return;
        const selected = confirm;
        setConfirm(null);
        setPending(true);
        setAnalysisError('');
        setResult(null);
        const current = new AbortController();
        operation.current = current;
        try {
            const response = await mutate<AnalysisResult>(`/cases/${encodeURIComponent(item.id)}/analyze`, { configRevision: selected.revision }, current.signal);
            if (!alive.current || current.signal.aborted)
                return;
            const latest = await request<AIConfig>('/ai/config', { signal: current.signal });
            if (!alive.current || current.signal.aborted)
                return;
            setConfig(latest);
            if (response.superseded || response.configRevision !== selected.revision || latest.revision !== selected.revision) {
                setAnalysisError(t("Die Anbieter-Konfiguration wurde ge\u00E4ndert. Das \u00FCberholte Ergebnis wird nicht angezeigt."));
                return;
            }
            setResult(response);
        }
        catch (err) {
            if (alive.current && !current.signal.aborted) {
                setAnalysisError(safeAIError(err));
                if (err instanceof APIError && err.status === 409)
                    void refresh();
            }
        }
        finally {
            if (alive.current && !current.signal.aborted)
                setPending(false);
        }
    };
    const cancel = () => { operation.current?.abort(); setPending(false); setAnalysisError(t("Anfrage lokal abgebrochen. Bereits \u00FCbertragene Daten k\u00F6nnen nicht zur\u00FCckgeholt werden.")); void refresh(); };
    const info = endpointInfo(config?.baseURL || '');
    const findings = result?.ai.status === 'completed' ? result.ai.findings : null;
    const statusLabels: Record<string, string> = { not_configured: t("Anbieter nicht eingerichtet"), canceled: t("Anfrage abgebrochen"), timeout: t("Zeitlimit erreicht"), busy: t("Andere Analyse l\u00E4uft"), invalid_response: t("Antwort nicht verwendbar"), unavailable: t("Anbieter nicht erreichbar") };
    return <section className="panel ai-analysis-panel"><SectionHead title={t("KI-Einordnung")} action={<span className="ai-suggestion-label"><Bot size={14}/>{t("Optional")}</span>}/>{error ? <div className="ai-inline-error" role="alert"><TriangleAlert size={16}/><p>{ui(error)}</p><button className="button small" onClick={() => void refresh()}>{t("Erneut versuchen")}</button></div> : loading && !config ? <Loading label={t("KI-Konfiguration wird geladen \u2026")}/> : !config?.configured ? <div className="ai-unconfigured"><span><Bot size={24}/></span><div><h3>{t("Noch kein Anbieter eingerichtet")}</h3></div><button className="button" onClick={onSettings}>{t("Einrichten")}<ArrowRight size={14}/></button></div> : <><div className="ai-analysis-toolbar"><div className="ai-model-label">{info.local ? <Server size={16}/> : <Cloud size={16}/>}<div><strong>{config.model}</strong><span title={config.baseURL}>{config.endpointOrigin}</span></div></div>{pending ? <button className="button" onClick={cancel}><Square size={13}/>{t("Abbrechen")}</button> : <button className="button" onClick={() => void begin()} disabled={preparing || config.busy}>{preparing ? <LoaderCircle className="spin" size={14}/> : <Send size={14}/>}{t("KI-Analyse prüfen")}</button>}</div>{pending ? <div className="ai-progress" role="status"><LoaderCircle size={18} className="spin"/><span>{t("Fallbelege werden analysiert …")}<small>{t("Der Regelbefund bleibt unver\u00E4ndert.")}</small></span></div> : config.busy ? <div className="ai-status-note"><Info size={14}/><span>{t("Eine andere Analyse l\u00E4uft.")}</span><button className="text-button" onClick={() => void refresh()}><RefreshCw size={12}/>{t("Status pr\u00FCfen")}</button></div> : null}</>}{analysisError && <div className="ai-inline-error" role="alert"><TriangleAlert size={16}/><p>{ui(analysisError)}</p></div>}{result && !findings && <div className="ai-result-status" role="status"><TriangleAlert size={18}/><div><strong>{statusLabels[result.ai.status] || t("Kein verwertbares Ergebnis")}</strong><p>{result.ai.reason || t("Der deterministische Befund bleibt g\u00FCltig. Es wurde keine Ma\u00DFnahme ausgef\u00FChrt.")}</p></div></div>}{result && findings && <div className="ai-result"><div className="ai-result-heading"><span><Bot size={14}/>{t("KI-Hypothesen")}<Source synthetic={result.packet.case.synthetic}/></span><span className="ai-unconfirmed"><CircleHelp size={13}/>{t("Ursache nicht best\u00E4tigt")}</span></div><ClaimList items={findings.hypotheses} evidence={result.packet.evidence} onEvidence={setSelectedEvidence}/>{(result.packet.gaps.length > 0 || findings.missingData.length > 0) && <details className="ai-findings-disclosure ai-data-gaps"><summary><TriangleAlert size={14}/>{t("Fehlende Daten")}<span>{result.packet.gaps.length + findings.missingData.length}</span><ChevronRight size={14}/></summary><ul>{result.packet.gaps.map((gap, index) => <li key={index}>{({ "missing-evidence": t("Verkn\u00FCpfte Belege fehlen"), "quality-stale": t("Veraltete Beobachtung"), "quality-unknown": t("Daten nicht verf\u00FCgbar"), "quality-denied": t("Zugriff auf Beobachtung verweigert"), "no-evidence": t("Keine Belege vorhanden") } as Record<string, string>)[gap.code] || gap.detail}{gap.evidenceIDs.length > 0 && <small>{gap.evidenceIDs.join(" · ")}</small>}</li>)}{findings.missingData.map((missing, index) => <li key={`missing-${index}`}>{missing}</li>)}</ul></details>}{findings.counterevidence.length > 0 && <ClaimList title={t("Gegenbelege")} items={findings.counterevidence} evidence={result.packet.evidence} onEvidence={setSelectedEvidence}/>}{result.ai.nextSteps.length > 0 && <div className="ai-next-check"><h3>{t("Nächste Prüfung · nur lesend")}</h3><ol>{result.ai.nextSteps.map((step, index) => <li key={index}>{step}</li>)}</ol></div>}<details className="ai-findings-disclosure ai-provenance"><summary><Fingerprint size={14}/>{t("Herkunft & Grenzen")}<ChevronRight size={14}/></summary><dl><div><dt>{t("Modell")}</dt><dd>{result.ai.provenance.model}</dd></div><div><dt>{t("Ziel")}</dt><dd>{result.ai.provenance.destination}</dd></div><div><dt>{t("Erstellt")}</dt><dd>{fullDate(result.generatedAt)}</dd></div><div><dt>{t("Belegzeitpunkte")}</dt><dd>{result.packet.observationWindow.from ? fullDate(result.packet.observationWindow.from) : t("Unbekannt")} – {result.packet.observationWindow.to ? fullDate(result.packet.observationWindow.to) : t("Unbekannt")}</dd></div><div><dt>{t("Prompt / Runbook")}</dt><dd>{result.ai.provenance.promptVersion} / {result.ai.provenance.runbookVersion}</dd></div><div><dt>{t("Paket-Hash")}</dt><dd><code>{result.ai.provenance.packetSHA256}</code></dd></div></dl><ul>{result.limitations.map((limit, index) => <li key={index}>{limit}</li>)}</ul><p>{t("Quellen bestätigen keine Hypothese. Neuladen verwirft dieses Ergebnis.")}</p></details></div>}{selectedEvidence && <Dialog title={t("Analysierter Beleg: {0}", { "0": selectedEvidence.title })} onClose={() => setSelectedEvidence(null)} className="ai-confirm-dialog ai-snapshot-dialog"><div className="eyebrow">{t("ANALYSIERTER BELEG")}</div><h2>{selectedEvidence.title}</h2><div className="ai-snapshot-badges"><Source synthetic={selectedEvidence.synthetic}/><span className={`quality-pill quality-${selectedEvidence.quality}`}>{qualityLabels[selectedEvidence.quality]}</span></div><code className="ai-snapshot-value">{selectedEvidence.value || t("Kein Wert vorhanden")}</code><p>{selectedEvidence.detail}</p><dl><div><dt>{t("Quelle")}</dt><dd>{selectedEvidence.source}</dd></div><div><dt>{t("Erfasst")}</dt><dd>{fullDate(selectedEvidence.collectedAt)}</dd></div><div><dt>{t("Beleg-ID")}</dt><dd><code>{selectedEvidence.id}</code></dd></div></dl><div className="ai-status-note"><Fingerprint size={14}/><span>{t("Unver\u00E4nderter Beleg aus dem analysierten Datenpaket.")}</span></div></Dialog>}{confirm && <Dialog title={t("Fallbelege zur KI-Analyse senden")} onClose={() => { setConfirm(null); setReviewed(false); }} className="ai-confirm-dialog ai-evidence-confirm"><div className="confirm-symbol"><Send size={21}/></div><h2>{t("Fallbelege senden?")}</h2><Destination info={endpointInfo(confirm.baseURL)} endpoint={confirm.baseURL} compact/><div className="ai-confirm-case"><FileCheck2 size={16}/><div><strong>{item.title}</strong><span>{item.evidenceIds.length}{" " + t("verkn\u00FCpfte Belege \u00B7 Modell:") + " "}{confirm.model}</span></div><Source synthetic={item.synthetic}/></div><div className="ai-send-warning"><TriangleAlert size={17}/><p>{t("Falltitel, Zusammenfassung und Beleg-Rohtexte werden ohne automatische Geheimnisfilterung gesendet. Auch Loopback-Anbieter k\u00F6nnen extern weiterleiten.")}</p></div><details className="ai-disclosure"><summary><Info size={14}/>{t("Was wird \u00FCbertragen?")}<ChevronRight size={14}/></summary><ul><li>{t("Fallmetadaten: Titel, Zusammenfassung, Kategorie, Regel, Zeitpunkte und Demo-Kennzeichnung.")}</li><li>{t("Ausgew\u00E4hlte verkn\u00FCpfte Belege: Titel, Quelle, Detail, Wert, Zeitpunkt und Datenqualit\u00E4t. H\u00F6chstens 32 Belege und 24 KiB Paketgr\u00F6\u00DFe.")}</li><li>{t("Keine Notizen, Ger\u00E4tekennungen oder unbeteiligte Telemetrie.")}</li><li>{t("Die Belegtexte stehen oben im Fall. Die Anfrage f\u00FChrt keine Befehle aus.")}</li></ul></details><label className="check-field review-consent"><input type="checkbox" checked={reviewed} onChange={event => setReviewed(event.target.checked)}/><span>{t("Ich habe Belege und Ziel gepr\u00FCft und gebe diese einzelne Anfrage frei.")}</span></label><div className="confirm-actions"><button className="button" onClick={() => { setConfirm(null); setReviewed(false); }}>{t("Abbrechen")}</button><button className="button primary" onClick={() => void analyze()} disabled={!reviewed}><Send size={14}/>{t("Jetzt analysieren")}</button></div></Dialog>}</section>;
}
function ClaimList({ title, items, evidence, onEvidence }: {
    title?: string;
    items: Claim[];
    evidence: Evidence[];
    onEvidence: (evidence: Evidence) => void;
}) { return <div className="ai-claims">{title && <h3>{title}</h3>}{items.length ? items.map((claim, index) => <div className="ai-claim" key={index}><span className="ai-claim-index">{String(index + 1).padStart(2, '0')}</span><div><p>{claim.statement}</p><div className="ai-citations">{claim.evidenceIDs.map(id => { const source = evidence.find(e => e.id === id); return source ? <button key={id} onClick={() => onEvidence(source)} title={`${source.title} · ${source.source}`} aria-label={t("Beleg \u00F6ffnen: {0}", { "0": source.title })}><FileCheck2 size={11}/>{source.title}<ChevronRight size={10}/></button> : <span key={id} className="invalid-citation">{t("Unbekannter Beleg:") + " "}{id}</span>; })}</div></div></div>) : <p className="ai-no-claims">{t("Das Modell hat keine beleggest\u00FCtzte Hypothese geliefert.")}</p>}</div>; }
