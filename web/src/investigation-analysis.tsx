import { useLocale } from './i18n';
import { fullDate, qualityLabels } from './utils';
import type { InvestigationAnalysis } from './investigation-analysis-types';
import './proactive-ai.css';

function Time({ value }: { value: string }) { return <time dateTime={value}>{fullDate(value)}</time>; }
export function InvestigationAnalysisView({ analysis, concise }: { analysis: InvestigationAnalysis; concise: boolean }) {
    const [locale] = useLocale(), de = locale === 'de';
    const labels = {
        not_configured: de ? 'KI-Anbieter nicht eingerichtet' : 'AI provider not configured', busy: de ? 'KI-Anbieter belegt' : 'AI provider busy',
        running: de ? 'KI-Analyse läuft' : 'AI analysis running', completed: de ? 'KI-Hinweise gespeichert' : 'AI suggestions saved', timeout: de ? 'KI-Zeitlimit erreicht' : 'AI analysis timed out',
        unavailable: de ? 'KI nicht verfügbar' : 'AI unavailable', invalid_response: de ? 'KI-Antwort verworfen' : 'AI response discarded', canceled: de ? 'KI-Analyse abgebrochen' : 'AI analysis canceled', interrupted: de ? 'KI-Analyse unterbrochen' : 'AI analysis interrupted',
    };
    const result = analysis.result, findings = result?.ai.status === 'completed' ? result.ai.findings : null;
    const first = findings?.hypotheses[0]?.statement;
    const short = first && first.length > 200 ? `${first.slice(0, 197)}…` : first;
    return <div className="investigation-analysis">
        <p className="investigation-analysis-summary"><strong>{labels[analysis.status]}</strong>{short && <> · {de ? 'Unbestätigte Hypothese: ' : 'Unconfirmed hypothesis: '}{short}</>}</p>
        {!concise && <details><summary>{de ? 'KI-Analyse & Quellen' : 'AI analysis & sources'}</summary>
            <p>{de ? 'Unbestätigte Hypothesen. Quellen belegen keine Ursache; menschliche Prüfung nötig. Keine Schritte ausgeführt.' : 'Unconfirmed hypotheses. Sources do not prove a cause; human review is needed. No steps executed.'}</p>
            <p className="analysis-source">{de ? 'Gestartet: ' : 'Started: '}<Time value={analysis.createdAt}/>{analysis.finishedAt && <> · {de ? 'Beendet: ' : 'Finished: '}<Time value={analysis.finishedAt}/></>}</p>
            {analysis.recoveredAt && <p>{de ? 'Erholung im Health-Verlauf bestätigt: ' : 'Recovery confirmed in health history: '}<Time value={analysis.recoveredAt}/>{de ? '. Das bestätigt keine KI-Hypothese.' : '. This does not confirm an AI hypothesis.'}</p>}
            {!result && <p>{de ? 'Kein gespeichertes KI-Ergebnis verfügbar. Es wurde keine bestätigte Ursache ermittelt.' : 'No stored AI result is available. No cause was confirmed.'}</p>}
            {result && <>
                <p>{result.baseline.summary}</p>
                {findings && <><h4>{de ? 'Hypothesen' : 'Hypotheses'}</h4><ul>{findings.hypotheses.map((claim, index) => <li key={index}>{claim.statement}<div className="analysis-source">{de ? 'Quell-IDs: ' : 'Source IDs: '}{claim.evidenceIDs.join(', ') || '—'}</div></li>)}</ul>
                    {findings.counterevidence.length > 0 && <><h4>{de ? 'Mögliche Gegenbelege' : 'Possible counterevidence'}</h4><ul>{findings.counterevidence.map((claim, index) => <li key={index}>{claim.statement}<div className="analysis-source">{de ? 'Quell-IDs: ' : 'Source IDs: '}{claim.evidenceIDs.join(', ') || '—'}</div></li>)}</ul></>}
                </>}
                <h4>{de ? 'Quellen' : 'Sources'}</h4><ul>{result.packet.evidence.map(evidence => <li key={evidence.id}><strong>{evidence.id}</strong>{' · '}{evidence.title}<div className="analysis-source">{evidence.source}{' · '}<Time value={evidence.collectedAt}/>{' · '}{de ? 'Quellqualität bei Analyse: ' : 'Source quality at analysis: '}{qualityLabels[evidence.quality]}</div><div>{evidence.value}</div><div>{evidence.detail}</div></li>)}</ul>
                {(!!findings?.missingData.length || result.packet.gaps.length > 0 || result.packet.missingEvidenceIDs.length > 0) && <><h4>{de ? 'Datenlücken' : 'Data gaps'}</h4><ul>{findings?.missingData.map((item, index) => <li key={`missing-${index}`}>{item}</li>)}{result.packet.gaps.map((gap, index) => <li key={`gap-${index}`}>{gap.detail}{gap.evidenceIDs.length > 0 && <span className="analysis-source"> ({gap.evidenceIDs.join(', ')})</span>}</li>)}{result.packet.missingEvidenceIDs.length > 0 && <li>{de ? 'Fehlende Quell-IDs: ' : 'Missing source IDs: '}{result.packet.missingEvidenceIDs.join(', ')}</li>}</ul></>}
                <p>{de ? 'Keine zusätzlichen Logs oder historischen Messwerte geprüft.' : 'No additional logs or historical samples were checked.'}</p>
                <h4>{de ? 'Nächste Prüfung · nur lesend' : 'Next checks · read-only'}</h4><ol>{(findings ? result.ai.nextSteps : result.baseline.nextSteps).map((step, index) => <li key={index}>{step}</li>)}</ol>
                <p className="analysis-source">{de ? 'Anbieter / Modell: ' : 'Provider / model: '}{result.ai.provenance.provider} / {result.ai.provenance.model}{' · '}{de ? 'Ergebnis erstellt: ' : 'Result created: '}<Time value={result.generatedAt}/></p>
                <ul>{result.limitations.map((item, index) => <li className="analysis-source" key={index}>{item}</li>)}</ul>
            </>}
        </details>}
    </div>;
}
