import { useEffect, useRef, useState } from 'react';
import { useLocale } from './i18n';
import { fullDate } from './utils';
import { useJournalAIReview } from './journal-ai-resource';
import { validJournalAIResult } from './journal-ai-types';
import type { JournalAIResult, JournalAIState } from './journal-ai-types';
import type { HealthIncident } from './health-types';
import { journalAge } from './journal-types';
export function journalAIStateLabel(state: JournalAIState, de: boolean) {
    const labels: Record<JournalAIState, [string, string]> = { capture_unconfirmed: ['Capture suppression unconfirmed', 'Erfassungsstopp unbestätigt'], cancel_pending: ['Capture cancellation pending', 'Erfassungsabbruch ausstehend'], not_started: ['Not started', 'Nicht gestartet'], preparing: ['Preparing capture', 'Erfassung vorbereiten'], capturing: ['Waiting for journal', 'Warten auf Journal'], analyzing: ['Analyzing', 'Analyse läuft'], completed: ['Finding available', 'Befund verfügbar'], canceled: ['Canceled', 'Abgebrochen'], expired: ['Expired', 'Abgelaufen'], unavailable: ['Unavailable', 'Nicht verfügbar'], invalid_response: ['Response discarded', 'Antwort verworfen'], timeout: ['Timed out', 'Zeitlimit erreicht'], interrupted: ['Interrupted', 'Unterbrochen'], busy: ['Budget or provider busy', 'Budget oder Anbieter belegt'] };
    return labels[state][de ? 1 : 0];
}
function JournalAIResultContent({ device, incident }: { device: string; incident: HealthIncident }) {
    const [locale] = useLocale(), de = locale === 'de';
    const [value, setValue] = useState<JournalAIResult | null>(null), [expired, setExpired] = useState(false);
    const observed = useRef({ wall: 0, mono: 0 });
    const retention = useRef<{ expiresAt: string; deadline: number } | null>(null), latestServer = useRef<string | null>(null);
    const state = useJournalAIReview(() => setValue(null));
    const read = async () => {
        setValue(null); setExpired(false);
        const started = { wall: Date.now(), mono: performance.now() };
        const v = await state.run(async read => {
            const result = await read<unknown>(`/ai/journal/${device}/${incident.id}`, 65536);
            if (!validJournalAIResult(result, incident)) throw Error('invalid');
            return result;
        });
        if (!v) return;
        if (latestServer.current && journalAge(v.serverNow, latestServer.current) < 0 || retention.current && v.expiresAt !== retention.current.expiresAt) { state.invalidate(); return; }
        latestServer.current = v.serverNow;
        if (v.expiresAt) {
            const candidate = started.mono + journalAge(v.expiresAt, v.serverNow);
            retention.current = { expiresAt: v.expiresAt, deadline: Math.min(retention.current?.deadline ?? Infinity, candidate) };
            // Reads can shorten the original capture lifetime, never renew it.
            if (performance.now() >= retention.current.deadline) { setExpired(true); return; }
        }
        observed.current = started; setValue(v);
    };
    useEffect(() => { void read(); }, [device, incident.id]);
    useEffect(() => {
        if (!value) return;
        const interval = window.setInterval(() => { const elapsed = performance.now() - observed.current.mono; if (elapsed < 0 || Math.abs(Date.now() - observed.current.wall - elapsed) > 1500 || retention.current && performance.now() >= retention.current.deadline) { setValue(null); setExpired(true); } }, 250);
        const poll = ['preparing', 'capturing', 'analyzing'].includes(value.state) ? window.setTimeout(() => void read(), 10000) : undefined;
        return () => { window.clearInterval(interval); window.clearTimeout(poll); };
    }, [value]);
    const result = value?.result, findings = result?.ai.findings;
    return <div className="journal-ai-result"><button className="button small" disabled={state.busy || state.locked} onClick={() => void read()}>{de ? 'Befund aktualisieren' : 'Refresh finding'}</button><p>{de ? 'Lesen startet keine Erfassung oder Analyse. Loggestützte Inhalte verfallen mit der ursprünglichen Erfassung.' : 'Reading starts no capture or analysis. Log-backed content expires with its original capture.'}</p>{state.busy && <p role="status">{de ? 'Wird gelesen…' : 'Reading…'}</p>}{(state.error || expired) && <p role="status">{expired ? (de ? 'Befund abgelaufen.' : 'Finding expired.') : (de ? 'Befund nicht verfügbar. Erneut laden.' : 'Finding unavailable. Refresh to review.')}</p>}
        {value && <p>{journalAIStateLabel(value.state, de)}{value.expiresAt && <> · {de ? 'Ablauf: ' : 'Expires: '}<time dateTime={value.expiresAt}>{fullDate(value.expiresAt)}</time></>}</p>}
        {result && <><p><strong>{de ? 'Unbestätigte Hypothesen. Menschliche Prüfung nötig.' : 'Unconfirmed hypotheses. Human review required.'}</strong></p><ul>{findings?.hypotheses.map((claim, i) => <li key={i}>{claim.statement}<small> ({claim.evidenceIDs.join(', ')})</small></li>)}</ul><h4>{de ? 'Nächste Prüfung · nur lesend' : 'Next checks · read-only'}</h4><ol>{result.ai.nextSteps.map((step, i) => <li key={i}>{step}</li>)}</ol><details><summary>{de ? 'Quellen, Gegenbelege & Lücken' : 'Sources, counterevidence & gaps'}</summary><ul>{result.packet.evidence.map(e => <li key={e.id}><strong>{e.id}</strong> · <time dateTime={e.collectedAt}>{fullDate(e.collectedAt)}</time><div>{e.source} · {e.detail}</div><pre>{e.value}</pre></li>)}</ul><ul>{findings?.counterevidence.map((c, i) => <li key={i}>{c.statement} ({c.evidenceIDs.join(', ')})</li>)}{findings?.missingData.map((m, i) => <li key={`m${i}`}>{m}</li>)}{result.packet.gaps.map((g, i) => <li key={`g${i}`}>{g.detail}</li>)}</ul><p>{result.ai.provenance.destination} · {result.ai.provenance.model}</p><ul>{result.limitations.map((l, i) => <li key={i}>{l}</li>)}</ul></details></>}
    </div>;
}
export function JournalAIInvestigation({ device, incident, state }: { device: string; incident: HealthIncident; state: JournalAIState }) {
    const [locale] = useLocale(), de = locale === 'de', [open, setOpen] = useState(false);
    return <details onToggle={e => setOpen(e.currentTarget.open)}><summary>{de ? 'Dienstlog-KI: ' : 'Service-log AI: '}{journalAIStateLabel(state, de)}</summary>{open && ['preparing', 'capturing', 'analyzing', 'completed'].includes(state) && <JournalAIResultContent key={`${device}:${incident.id}:${state}`} device={device} incident={incident}/>}</details>;
}
