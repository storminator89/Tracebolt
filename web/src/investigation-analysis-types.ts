import type { AnalysisResult, Provenance } from './ai-types';
import type { HealthIncident } from './health-types';

export type StoredAnalysisResult = Omit<AnalysisResult, 'configRevision' | 'superseded'>;
export interface InvestigationAnalysis {
    status: 'running' | 'completed' | 'timeout' | 'unavailable' | 'invalid_response' | 'canceled' | 'interrupted' | 'not_configured' | 'busy';
    createdAt: string;
    finishedAt: string | null;
    recoveredAt: string | null;
    result: StoredAnalysisResult | null;
}
export const INVESTIGATION_ANALYSIS_BYTES = 32 * 1024;
const object = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);
const fields = (v: Record<string, unknown>, required: string[], optional: string[] = []) => required.every(key => Object.hasOwn(v, key)) && Object.keys(v).every(key => required.includes(key) || optional.includes(key));
const text = (v: unknown, maximum = 2048): v is string => typeof v === 'string' && v.length <= maximum && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(v);
const id = (v: unknown): v is string => typeof v === 'string' && /^[a-zA-Z0-9_-]{1,128}$/.test(v);
const timestamp = (v: unknown): v is string => typeof v === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(v) && Number.isFinite(Date.parse(v)) && Number(v.slice(0, 4)) >= 1970 && new Date(Date.parse(v)).toISOString().slice(0, 19) === v.slice(0, 19);
const timeBefore = (v: unknown, now: string): v is string => timestamp(v) && Date.parse(v) <= Date.parse(now);
const strings = (v: unknown, count = 32, maximum = 2048): v is string[] => Array.isArray(v) && v.length <= count && v.every(item => text(item, maximum));
const ids = (v: unknown): v is string[] => Array.isArray(v) && v.length <= 32 && v.every(id) && new Set(v).size === v.length;
const runbook = (v: unknown) => ['none', 'service', 'storage', 'network'].includes(String(v));
function provenance(v: unknown): v is Provenance {
    return object(v) && fields(v, ['method', 'provider', 'model', 'promptVersion', 'runbookVersion', 'ruleId', 'packetSHA256', 'destination', 'endpointOrigin']) && Object.values(v).every(value => text(value, 512));
}
function validResult(v: unknown, incident: HealthIncident, now: string): v is StoredAnalysisResult {
    if (!object(v) || !fields(v, ['schemaVersion', 'id', 'fingerprint', 'generatedAt', 'packet', 'baseline', 'ai', 'rootCauseConfirmed', 'limitations'], ['configRevision', 'superseded']) || v.schemaVersion !== 'tracebolt.analysis.v1' || !id(v.id) || !text(v.fingerprint, 128) || !timeBefore(v.generatedAt, now) || v.rootCauseConfirmed !== false || !strings(v.limitations, 16)) return false;
    if (Object.hasOwn(v, 'configRevision') && !id(v.configRevision) || Object.hasOwn(v, 'superseded') && v.superseded !== false) return false;
    const packet = v.packet;
    if (!object(packet) || !fields(packet, ['schemaVersion', 'dataScope', 'case', 'evidence', 'missingEvidenceIDs', 'observationWindow', 'gaps']) || packet.schemaVersion !== 'tracebolt.evidence-packet.v1' || packet.dataScope !== 'health-summary-v1') return false;
    const item = packet.case;
    if (!object(item) || !fields(item, ['id', 'title', 'summary', 'category', 'ruleId', 'runbookId', 'createdAt', 'updatedAt', 'synthetic']) || item.id !== incident.id || !text(item.title, 256) || !text(item.summary) || item.category !== incident.kind || item.ruleId !== `health:${incident.kind}` || !runbook(item.runbookId) || !timeBefore(item.createdAt, now) || !timeBefore(item.updatedAt, now) || item.synthetic !== false) return false;
    if (!Array.isArray(packet.evidence) || packet.evidence.length !== 2 || !ids(packet.missingEvidenceIDs) || packet.missingEvidenceIDs.length !== 0) return false;
    const evidenceIDs = new Set<string>();
    for (const evidence of packet.evidence) {
        if (!object(evidence) || !fields(evidence, ['id', 'title', 'source', 'quality', 'collectedAt', 'detail', 'value', 'synthetic']) || !id(evidence.id) || !['health-event', 'health-snapshot'].includes(evidence.id) || evidenceIDs.has(evidence.id) || !text(evidence.title) || !text(evidence.source) || !text(evidence.detail) || !text(evidence.value) || !['healthy', 'stale', 'unknown', 'denied'].includes(String(evidence.quality)) || !timeBefore(evidence.collectedAt, now) || evidence.synthetic !== false) return false;
        evidenceIDs.add(evidence.id);
    }
    const references = (value: unknown): value is string[] => ids(value) && value.every(key => evidenceIDs.has(key));
    const window = packet.observationWindow;
    if (!object(window) || !fields(window, ['from', 'to']) || !(window.from === null && window.to === null || timeBefore(window.from, now) && timeBefore(window.to, now) && Date.parse(window.from) <= Date.parse(window.to))) return false;
    if (!Array.isArray(packet.gaps) || packet.gaps.length > 64 || !packet.gaps.every(gap => object(gap) && fields(gap, ['code', 'evidenceIDs', 'detail']) && text(gap.code, 128) && ids(gap.evidenceIDs) && text(gap.detail))) return false;
    const baseline = v.baseline;
    if (!object(baseline) || !fields(baseline, ['summary', 'evidenceIDs', 'nextCheck', 'nextSteps', 'provenance']) || !text(baseline.summary) || !references(baseline.evidenceIDs) || !runbook(baseline.nextCheck) || !strings(baseline.nextSteps, 16) || !provenance(baseline.provenance)) return false;
    const ai = v.ai;
    if (!object(ai) || !fields(ai, ['status', 'reason', 'findings', 'nextSteps', 'provenance']) || !['not_configured', 'completed', 'canceled', 'timeout', 'busy', 'invalid_response', 'unavailable'].includes(String(ai.status)) || !text(ai.reason) || !strings(ai.nextSteps, 16) || !provenance(ai.provenance)) return false;
    if (ai.status !== 'completed') return ai.findings === null;
    const findings = ai.findings;
    const claims = (value: unknown) => Array.isArray(value) && value.length <= 5 && value.every(claim => object(claim) && fields(claim, ['statement', 'evidenceIDs']) && text(claim.statement, 512) && claim.statement.trim().length > 0 && references(claim.evidenceIDs) && claim.evidenceIDs.length > 0 && object(findings) && Array.isArray(findings.observedEvidenceIDs) && claim.evidenceIDs.every(id => (findings.observedEvidenceIDs as unknown[]).includes(id)));
    return object(findings) && fields(findings, ['observedEvidenceIDs', 'hypotheses', 'counterevidence', 'missingData', 'nextCheck']) && references(findings.observedEvidenceIDs) && claims(findings.hypotheses) && claims(findings.counterevidence) && strings(findings.missingData, 8, 512) && runbook(findings.nextCheck);
}
/** The optional extension fails closed without weakening the existing incident contract. */
export function validInvestigationAnalysis(v: unknown, incident: HealthIncident, now: string): v is InvestigationAnalysis {
    if (!object(v) || !fields(v, ['status', 'createdAt', 'finishedAt', 'recoveredAt', 'result']) || !['running', 'completed', 'timeout', 'unavailable', 'invalid_response', 'canceled', 'interrupted', 'not_configured', 'busy'].includes(String(v.status)) || !timeBefore(v.createdAt, now)) return false;
    if (Date.parse(v.createdAt) < Date.parse(incident.openedAt)) return false;
    if (v.status === 'running' ? v.finishedAt !== null || v.result !== null : !timeBefore(v.finishedAt, now) || Date.parse(v.finishedAt) < Date.parse(v.createdAt)) return false;
    if (v.recoveredAt !== null && (!timeBefore(v.recoveredAt, now) || Date.parse(v.recoveredAt) < Date.parse(incident.openedAt) || incident.closedReason !== 'recovered' || incident.resolvedAt === null || Date.parse(v.recoveredAt) !== Date.parse(incident.resolvedAt))) return false;
    if (v.result !== null && !validResult(v.result, incident, now)) return false;
    if (v.result !== null && (!object(v.result) || !object(v.result.ai) || v.result.ai.status !== v.status)) return false;
    try { return new TextEncoder().encode(JSON.stringify(v)).byteLength <= INVESTIGATION_ANALYSIS_BYTES; } catch { return false; }
}
