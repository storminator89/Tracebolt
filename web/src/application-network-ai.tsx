import { useEffect, useRef, useState } from 'react';
import { APIError, mutate } from './api';
import { Dialog } from './components';
import { t } from './i18n';
import type { DNSApplicationCheck, TCPApplicationCheck } from './application-checks-types';

type Row = DNSApplicationCheck | TCPApplicationCheck;
type Preview = { schemaVersion: 'tracebolt.ai-network-review-preview.v1'; checkId: string; kind: 'dns' | 'tcp'; state: string; reason: string; observedAt: string; validUntil: string; snapshotToken: string; configRevision: string; baseURL: string; model: string };
type Findings = { hypotheses: { statement: string }[]; counterevidence: { statement: string }[]; missingData: string[] };
type Result = { ai: { status: string; findings: Findings | null; nextSteps: string[] }; rootCauseConfirmed: false };
export type NetworkReviewHistory = { checkId: string; kind: 'dns' | 'tcp'; state: string; reason: string; observedAt: string; baseURL: string; model: string; result: Result };
const record = (value: unknown): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value);
const str = (v: unknown, max = 2048): v is string => typeof v === 'string' && v.length > 0 && v.length <= max;
const exact = (v: Record<string, unknown>, keys: string[]) => Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v, k));
function preview(value: unknown, row: Row): value is Preview {
    if (!record(value) || !exact(value, ['schemaVersion','checkId','kind','state','reason','observedAt','validUntil','snapshotToken','configRevision','baseURL','model'])) return false;
    return value.schemaVersion === 'tracebolt.ai-network-review-preview.v1' && value.checkId === row.id && value.kind === row.kind && value.state === row.state && value.reason === row.reason && value.observedAt === row.observedAt && str(value.validUntil, 40) && Number.isFinite(Date.parse(value.validUntil)) && str(value.snapshotToken, 2048) && str(value.configRevision, 256) && str(value.baseURL, 2048) && str(value.model, 256);
}
function validResult(value: unknown, p: Preview): value is { result: Result } {
    if (!record(value) || !exact(value, ['schemaVersion','checkId','snapshotToken','configRevision','result']) || value.schemaVersion !== 'tracebolt.ai-network-review-result.v1' || value.checkId !== p.checkId || value.snapshotToken !== p.snapshotToken || value.configRevision !== p.configRevision || !record(value.result)) return false;
    const r = value.result, ai = r.ai;
    if (r.schemaVersion !== 'tracebolt.analysis.v1' || r.rootCauseConfirmed !== false || !record(ai) || !['completed','unavailable','timeout','canceled','busy','invalid_response','not_configured'].includes(String(ai.status)) || !Array.isArray(ai.nextSteps) || ai.nextSteps.length > 8 || !ai.nextSteps.every(x => str(x, 512))) return false;
    if (ai.status !== 'completed') return ai.findings === null;
    if (!record(ai.findings)) return false;
    const f = ai.findings;
    const claims = (x: unknown) => Array.isArray(x) && x.length <= 5 && x.every(c => record(c) && str(c.statement, 512));
    return claims(f.hypotheses) && claims(f.counterevidence) && Array.isArray(f.missingData) && f.missingData.length <= 8 && f.missingData.every(x => str(x, 512));
}

/** Review uses only a retained observation; opening never starts a network check. */
export function ApplicationNetworkAI({ row, onInterrupted, onCompleted }: { row: Row; onInterrupted?: () => void; onCompleted: (history: NetworkReviewHistory) => void }) {
    const [open, setOpen] = useState(false), [pending, setPending] = useState(false), [approved, setApproved] = useState(false);
    const [review, setReview] = useState<Preview | null>(null), [result, setResult] = useState<Result | null>(null), [resultPreview, setResultPreview] = useState<Preview | null>(null), [error, setError] = useState('');
    const operation = useRef<AbortController | null>(null), live = useRef(true), running = useRef(false);
    useEffect(() => { live.current = true; return () => { live.current = false; if (running.current) onInterrupted?.(); operation.current?.abort(); }; }, []);
    const close = () => { if (running.current) setError(t('Das Ergebnis ist ungeklärt. Daten können bereits übertragen worden sein. Keine automatische Wiederholung.')); operation.current?.abort(); operation.current = null; running.current = false; setOpen(false); setPending(false); setApproved(false); setReview(null); };
    const prepare = async () => {
        if (pending) return;
        setOpen(true); setPending(true); setApproved(false); setReview(null); setResult(null); setResultPreview(null); setError('');
        const controller = new AbortController(); operation.current = controller;
        try {
            const response = await mutate<unknown>('/ai/network-review/preview', { checkId: row.id }, controller.signal);
            if (!live.current || controller.signal.aborted) return;
            if (!preview(response, row)) { setError(t('Die Vorschau ist ungültig oder die Beobachtung hat sich geändert.')); return; }
            setReview(response);
        } catch (e) {
            if (live.current && !controller.signal.aborted) setError(e instanceof APIError && e.status === 409 ? t('Beobachtung oder Anbieter haben sich geändert oder sind nicht verfügbar. Bitte erneut prüfen.') : t('Vorschau nicht verfügbar. Es wurde keine KI-Anfrage gestartet.'));
        } finally { if (live.current && operation.current === controller) { operation.current = null; setPending(false); } }
    };
    const run = async () => {
        if (!review || !approved || pending) return;
        const selected = review, controller = new AbortController(); operation.current = controller;
        running.current = true; setPending(true); setApproved(false); setError(''); setResult(null);
        try {
            const response = await mutate<unknown>('/ai/network-review/run', { checkId: selected.checkId, snapshotToken: selected.snapshotToken, configRevision: selected.configRevision, acknowledge: true }, controller.signal);
            if (!live.current || controller.signal.aborted) return;
            if (!validResult(response, selected)) { setReview(null); setError(t('Das Ergebnis ist ungeklärt. Daten können bereits übertragen worden sein. Keine automatische Wiederholung.')); return; }
            if (response.result.ai.status === 'completed') {
                onCompleted({ checkId: selected.checkId, kind: selected.kind, state: selected.state, reason: selected.reason, observedAt: selected.observedAt, baseURL: selected.baseURL, model: selected.model, result: response.result });
            } else { setResult(response.result); setResultPreview(selected); }
            setReview(null); setOpen(false);
        } catch (e) {
            if (live.current && !controller.signal.aborted) { setReview(null); setError(e instanceof APIError && e.status === 409 ? t('Beobachtung oder Anbieter sind nicht mehr aktuell. Daten können bereits übertragen worden sein. Keine automatische Wiederholung.') : t('Das Ergebnis ist ungeklärt. Daten können bereits übertragen worden sein. Keine automatische Wiederholung.')); }
        } finally { if (live.current && operation.current === controller) { operation.current = null; running.current = false; setPending(false); } }
    };
    const statusText: Record<string, string> = { completed: t('KI-Hypothesen · Ursache nicht bestätigt'), unavailable: t('Anbieterantwort nicht verfügbar'), timeout: t('Zeitlimit erreicht'), canceled: t('Anfrage abgebrochen'), busy: t('Andere Analyse läuft'), invalid_response: t('Antwort nicht verwendbar'), not_configured: t('Anbieter nicht eingerichtet') };
    return <div className="application-network-ai">
        <button className="text-button" type="button" onClick={() => void prepare()} disabled={pending}>{t('KI-Analyse prüfen')}</button>
        {!open && error && <p role="alert">{error}</p>}
        {result && <div role="status"><strong>{statusText[result.ai.status] ?? t('KI-Ergebnis nicht verfügbar')}</strong><p>{t('Beobachtet')}: <time dateTime={row.observedAt ?? undefined}>{row.observedAt}</time></p>{resultPreview && <p>{t('Ziel')}: <code>{resultPreview.baseURL}</code> · {t('Modell')}: {resultPreview.model}</p>}
            {result.ai.findings && <><ul>{result.ai.findings.hypotheses.map((c, i) => <li key={i}>{c.statement}</li>)}</ul>{result.ai.findings.counterevidence.length > 0 && <><strong>{t('Gegenbelege')}</strong><ul>{result.ai.findings.counterevidence.map((c, i) => <li key={i}>{c.statement}</li>)}</ul></>}{result.ai.findings.missingData.length > 0 && <><strong>{t('Fehlende Daten')}</strong><ul>{result.ai.findings.missingData.map((v, i) => <li key={i}>{v}</li>)}</ul></>}</>}
            {result.ai.nextSteps.length > 0 && <><strong>{t('Nächste Prüfung · nur lesend')}</strong><ol>{result.ai.nextSteps.map((v, i) => <li key={i}>{v}</li>)}</ol></>}<p>{t('Die KI kann sich irren. Es wurde keine Aktion ausgeführt.')}</p></div>}
        {open && <Dialog title={t('Netzwerkbeobachtung zur KI-Analyse prüfen')} onClose={close} className="ai-confirm-dialog">
            <h2>{t('Netzwerkbeobachtung zur KI-Analyse prüfen')}</h2>
            {pending && <p role="status">{t('Anfrage läuft …')}</p>}
            {error && <p role="alert">{error}</p>}
            {review && <><p>{t('Diese vorhandene Beobachtung stammt vom Manager. Das Öffnen startet keine neue Netzwerkprüfung.')}</p>
                <dl><div><dt>{t('Ziel')}</dt><dd><code>{review.baseURL}</code></dd></div><div><dt>{t('Modell')}</dt><dd>{review.model}</dd></div><div><dt>{t('Art')}</dt><dd>{review.kind.toUpperCase()}</dd></div><div><dt>{t('Status')}</dt><dd>{review.state}</dd></div><div><dt>{t('Grund')}</dt><dd>{review.reason}</dd></div><div><dt>{t('Beobachtet')}</dt><dd><time dateTime={review.observedAt}>{review.observedAt}</time></dd></div><div><dt>{t('Vorschau gültig bis')}</dt><dd><time dateTime={review.validUntil}>{review.validUntil}</time></dd></div></dl>
                <p>{t('An den Anbieter werden diese Art, Status, Grund, Beobachtungszeit und die Manager-Perspektive sowie feste Erläuterungen und eine feste Belegkennung gesendet. Keine Prüfungs-ID, Hostname, IP-Adresse, Port, Ziel-URL oder Freitexte.')}</p>
                <p>{t('Der Anbieter kann Daten weiterleiten. KI-Ergebnisse sind unbestätigte Vorschläge und führen keine Aktion aus.')}</p>
                <label className="check-field"><input type="checkbox" checked={approved} disabled={pending} onChange={e => setApproved(e.target.checked)}/><span>{t('Ich bestätige die einmalige Übertragung dieser Beobachtung an den angezeigten Anbieter.')}</span></label>
            </>}
            <div className="confirm-actions"><button type="button" className="button" onClick={close}>{t('Abbrechen')}</button>{review && <button type="button" className="button primary" disabled={!approved || pending} onClick={() => void run()}>{t('Jetzt analysieren')}</button>}</div>
        </Dialog>}
    </div>;
}

/** This is an independent session-only record, never a current-row assertion. */
export function NetworkReviewHistoryView({ history, onDismiss }: { history: NetworkReviewHistory; onDismiss: () => void }) {
    const { result } = history;
    return <section className="application-network-history" aria-label={t('Frühere KI-Analyse dieser Sitzung')}>
        <h3>{t('Frühere KI-Analyse dieser Sitzung')}</h3>
        <p>{t('Historische Aufnahme – keine Aussage über die aktuelle Prüfung. Das frühere Prüfungslabel kann inzwischen anders konfiguriert sein.')}</p>
        <dl><div><dt>{t('Früheres Prüfungslabel')}</dt><dd>{history.checkId}</dd></div><div><dt>{t('Art')}</dt><dd>{history.kind.toUpperCase()}</dd></div><div><dt>{t('Status')}</dt><dd>{history.state}</dd></div><div><dt>{t('Grund')}</dt><dd>{history.reason}</dd></div><div><dt>{t('Beobachtet')}</dt><dd><time dateTime={history.observedAt}>{history.observedAt}</time></dd></div><div><dt>{t('Ziel')}</dt><dd><code>{history.baseURL}</code></dd></div><div><dt>{t('Modell')}</dt><dd>{history.model}</dd></div></dl>
        <strong>{t('KI-Hypothesen · Ursache nicht bestätigt')}</strong>
        {result.ai.findings && <><ul>{result.ai.findings.hypotheses.map((c, i) => <li key={i}>{c.statement}</li>)}</ul>{result.ai.findings.counterevidence.length > 0 && <><strong>{t('Gegenbelege')}</strong><ul>{result.ai.findings.counterevidence.map((c, i) => <li key={i}>{c.statement}</li>)}</ul></>}{result.ai.findings.missingData.length > 0 && <><strong>{t('Fehlende Daten')}</strong><ul>{result.ai.findings.missingData.map((v, i) => <li key={i}>{v}</li>)}</ul></>}</>}
        {result.ai.nextSteps.length > 0 && <><strong>{t('Nächste Prüfung · nur lesend')}</strong><ol>{result.ai.nextSteps.map((v, i) => <li key={i}>{v}</li>)}</ol></>}
        <p>{t('Die KI kann sich irren. Es wurde keine Aktion ausgeführt.')}</p>
        <button type="button" className="text-button" onClick={onDismiss}>{t('Frühere Analyse schließen')}</button>
    </section>;
}
