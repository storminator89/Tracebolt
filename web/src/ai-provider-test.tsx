import { useEffect, useRef, useState } from 'react';
import { APIError, mutate } from './api';
import type { AIConfig } from './ai-types';
import { Dialog } from './components';
import { t } from './i18n';

type TestStatus = 'passed' | 'unavailable' | 'timeout' | 'invalid_response' | 'canceled' | 'busy';
const statuses: TestStatus[] = ['passed', 'unavailable', 'timeout', 'invalid_response', 'canceled', 'busy'];

// Only the fixed response is displayed; provider text never enters the UI.
function isTestResult(value: unknown, revision: string): value is { schemaVersion: string; configRevision: string; status: TestStatus } {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
    const item = value as Record<string, unknown>;
    return Object.keys(item).length === 3 && item.schemaVersion === 'tracebolt.ai-provider-test.v1' && item.configRevision === revision && typeof item.status === 'string' && statuses.includes(item.status as TestStatus);
}

export function AIProviderTest({ config, disabled, onBusy, onRefresh }: { config: AIConfig; disabled: boolean; onBusy: (busy: boolean) => void; onRefresh: () => Promise<AIConfig | null> }) {
    const [confirm, setConfirm] = useState(false);
    const [acknowledged, setAcknowledged] = useState(false);
    const [busy, setBusy] = useState(false);
    const [status, setStatus] = useState<TestStatus | 'uncertain' | 'conflict' | null>(null);
    const [stale, setStale] = useState(false);
    const inFlight = useRef<AbortController | null>(null);
    const alive = useRef(true);
    const current = useRef(config.revision);
    current.current = config.revision;

    useEffect(() => {
        alive.current = true;
        return () => { alive.current = false; inFlight.current?.abort(); onBusy(false); };
    }, [onBusy]);
    useEffect(() => {
        inFlight.current?.abort(); inFlight.current = null; setBusy(false); onBusy(false);
        setConfirm(false); setAcknowledged(false); setStatus(null); setStale(false);
    }, [config.revision, onBusy]);
    useEffect(() => {
        const changed = () => { inFlight.current?.abort(); inFlight.current = null; setBusy(false); onBusy(false); setConfirm(false); setAcknowledged(false); setStatus(null); setStale(true); };
        window.addEventListener('tracebolt-ai-config-changed', changed);
        return () => window.removeEventListener('tracebolt-ai-config-changed', changed);
    }, [onBusy]);
    const cancel = () => {
        if (inFlight.current) {
            inFlight.current.abort(); inFlight.current = null; setBusy(false); onBusy(false); setStatus('uncertain');
        }
        setConfirm(false); setAcknowledged(false);
    };
    const run = async () => {
        if (!confirm || !acknowledged || busy || stale || disabled || !config.configured || inFlight.current) return;
        const revision = config.revision;
        const controller = new AbortController();
        inFlight.current = controller; setBusy(true); onBusy(true); setStatus(null);
        try {
            const result = await mutate<unknown>('/ai/test', { configRevision: revision, acknowledgeTest: true }, controller.signal);
            if (!alive.current || controller.signal.aborted || current.current !== revision) return;
            if (!isTestResult(result, revision)) { setStatus('uncertain'); return; }
            setStatus(result.status);
            if (result.status === 'busy') setStale(true);
        } catch (error) {
            if (!alive.current || controller.signal.aborted || current.current !== revision) return;
            if (error instanceof APIError && error.status === 409) { setStatus('conflict'); setStale(true); }
            else setStatus('uncertain');
        } finally {
            if (inFlight.current === controller) { inFlight.current = null; if (alive.current) { setBusy(false); onBusy(false); setConfirm(false); setAcknowledged(false); } }
        }
    };
    const refresh = async () => { const next = await onRefresh(); if (alive.current && next) { setStale(false); setStatus(null); } };
    const messages: Record<TestStatus | 'uncertain' | 'conflict', string> = {
        passed: t('Funktionstest bestanden: Verbindung und strukturiertes Antwortformat wurden geprüft. Modellqualität und lokaler Betrieb sind nicht belegt.'),
        unavailable: t('Der Anbieter war für den Funktionstest nicht verfügbar.'),
        timeout: t('Der Funktionstest hat das Zeitlimit erreicht.'),
        invalid_response: t('Die Testantwort hatte nicht das erwartete strukturierte Format.'),
        canceled: t('Der Funktionstest wurde abgebrochen. Bereits übertragene Daten können nicht zurückgerufen werden.'),
        busy: t('Eine andere Analyse läuft.'),
        uncertain: t('Das Testergebnis ist ungeklärt; die Anfrage kann bereits beim Anbieter angekommen sein. Keine automatische Wiederholung.'),
        conflict: t('Eine andere Analyse läuft oder die Anbieterkonfiguration wurde geändert. Bitte Status erneut lesen.'),
    };
    return <div className="ai-provider-test">
        <button className="button" type="button" disabled={disabled || !config.configured || config.busy || busy || stale} onClick={() => { setConfirm(true); setAcknowledged(false); setStatus(null); }}>{t('Gespeicherten Anbieter testen')}</button>
        {config.busy && <p role="status">{t('Eine andere Analyse läuft.')}</p>}
        {stale && status !== 'conflict' && status !== 'busy' && <p role="status">{messages.conflict}</p>}
        {(stale || status === 'conflict' || config.busy) && <button className="text-button" type="button" onClick={() => void refresh()}>{t('Status erneut lesen')}</button>}
        {status && <p role="status">{messages[status]}</p>}
        {confirm && <Dialog title={t('KI-Anbieter testen')} onClose={cancel} className="ai-confirm-dialog">
            <h2>{t('Gespeicherten Anbieter testen?')}</h2>
            <dl><div><dt>{t('Ziel')}</dt><dd><code>{config.baseURL}</code></dd></div><div><dt>{t('Modell')}</dt><dd>{config.model}</dd></div></dl>
            <p>{t('Eine synthetische Testnachricht wird an dieses Ziel gesendet. Fallbelege und Logs werden nicht gesendet. Der Anbieter kann weiterleiten und Kosten verursachen.')}</p>
            <p>{t('Der Test prüft Verbindung und strukturiertes Antwortformat, nicht Modellqualität oder lokalen Betrieb.')}</p>
            <label className="check-field"><input type="checkbox" checked={acknowledged} disabled={busy} onChange={event => setAcknowledged(event.target.checked)}/><span>{t('Ich bestätige diesen einmaligen Test für das angezeigte Ziel und Modell.')}</span></label>
            {busy && <p role="status">{t('Funktionstest läuft …')}</p>}
            <div className="confirm-actions"><button className="button" type="button" onClick={cancel}>{t('Abbrechen')}</button><button className="button primary" type="button" disabled={!acknowledged || busy || disabled || stale} onClick={() => void run()}>{t('Test jetzt ausführen')}</button></div>
        </Dialog>}
    </div>;
}
