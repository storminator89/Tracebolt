import type { Evidence } from './types';
export interface AIConfig { revision: string; configured: boolean; provider: string; baseURL: string; endpointOrigin: string; model: string; keyConfigured: boolean; useLegacyMaxTokens: boolean; allowRemoteEvidence: boolean; storage: 'memory-only'; resetsOnRestart: boolean; busy: boolean; limitations: string[] }
export interface Provenance { method: string; provider: string; model: string; promptVersion: string; runbookVersion: string; ruleId: string; packetSHA256: string; destination: string; endpointOrigin: string }
export interface Claim { statement: string; evidenceIDs: string[] }
export interface Findings { observedEvidenceIDs: string[]; hypotheses: Claim[]; counterevidence: Claim[]; missingData: string[]; nextCheck: string }
export interface AnalysisResult { schemaVersion: string; id: string; fingerprint: string; generatedAt: string; configRevision: string; superseded: boolean; packet: { case: { id: string; title: string; summary: string; synthetic: boolean }; evidence: Evidence[]; missingEvidenceIDs: string[]; observationWindow: { from: string | null; to: string | null }; gaps: { code: string; evidenceIDs: string[]; detail: string }[] }; baseline: { summary: string; evidenceIDs: string[]; nextCheck: string; nextSteps: string[]; provenance: Provenance }; ai: { status: 'not_configured' | 'completed' | 'canceled' | 'timeout' | 'busy' | 'invalid_response' | 'unavailable'; reason: string; findings: Findings | null; nextSteps: string[]; provenance: Provenance }; rootCauseConfirmed: false; limitations: string[] }
export interface EndpointInfo { valid: boolean; origin: string; local: boolean; error: string }
/** UX validation only. The server independently validates origin, DNS and transport. */
export function endpointInfo(value: string): EndpointInfo {
  const fail=(error:string):EndpointInfo=>({valid:false,origin:'',local:false,error});
  try {
    if(!value || value.length>512 || value.trim()!==value || /[\\%\r\n\t?#]/.test(value))return fail('Eine vollständige Basis-URL ohne Abfrage oder Fragment eingeben.');
    const url=new URL(value); const prefix=value.match(/^(https?):\/\/([^/]+)/);
    if(!prefix || url.username || url.password || !url.hostname || prefix[2]!==prefix[2].toLowerCase())return fail('Eine gültige http- oder https-URL ohne Zugangsdaten eingeben.');
    const local=/^(127\.0\.0\.1|\[::1\])(?::[1-9][0-9]{0,4})?$/.test(prefix[2]);
    if(!local && url.protocol!=='https:')return fail('HTTP ist nur für 127.0.0.1 oder [::1] erlaubt. Andere Anbieter benötigen HTTPS.');
    if(!local && !url.hostname.includes('.'))return fail('Lokale Anbieter als 127.0.0.1 oder [::1] angeben.');
    return {valid:true,origin:`${prefix[1]}://${prefix[2]}`,local,error:''};
  } catch { return fail('Eine gültige Basis-URL eingeben.'); }
}
export function safeAIError(error: unknown, secret=''): string { const message=error instanceof Error ? error.message : 'Die Anfrage konnte nicht abgeschlossen werden.'; return secret ? message.split(secret).join('[Schlüssel entfernt]') : message; }
