import type { AnalysisResult } from './ai-types';
import { endpointInfo } from './ai-types';

export interface CaseAnalysisPreview {
    schemaVersion: 'tracebolt.case-analysis-preview.v1';
    caseId: string;
    configRevision: string;
    baseURL: string;
    endpointOrigin: string;
    model: string;
    packetJSON: string;
    packetSHA256: string;
    validUntil: string;
    serverNow: string;
    /** Local UI deadline derived from the server-relative lease; the server enforces expiry. */
    expiresAtMs: number;
    previewToken: string;
    /** Parsed only for rendering; never sent back as replacement evidence. */
    packet: AnalysisResult['packet'];
}
const object = (value: unknown): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value);
const fields = (value: Record<string, unknown>, required: string[], optional: string[] = []) => required.every(key => Object.hasOwn(value, key)) && Object.keys(value).every(key => required.includes(key) || optional.includes(key));
const text = (value: unknown, maximum: number): value is string => typeof value === 'string' && new TextEncoder().encode(value).length <= maximum;
const id = (value: unknown): value is string => typeof value === 'string' && /^[a-zA-Z0-9_.:-]{1,128}$/.test(value);
const hash = (value: unknown): value is string => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const time = (value: unknown): value is string => typeof value === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(value) && Number.isFinite(Date.parse(value));
const ids = (value: unknown): value is string[] => Array.isArray(value) && value.length <= 32 && value.every(id) && new Set(value).size === value.length;
const strings = (value: unknown, maximum = 16, bytes = 2048): value is string[] => Array.isArray(value) && value.length <= maximum && value.every(item => text(item, bytes));
function validPacket(value: unknown, caseId: string): value is AnalysisResult['packet'] {
    if (!object(value) || !fields(value, ['schemaVersion', 'case', 'evidence', 'missingEvidenceIDs', 'observationWindow', 'gaps']) || value.schemaVersion !== 'tracebolt.evidence-packet.v1') return false;
    const item = value.case;
    if (!object(item) || !fields(item, ['id', 'title', 'summary', 'category', 'ruleId', 'runbookId', 'createdAt', 'updatedAt', 'synthetic']) || item.id !== caseId || !text(item.title, 256) || !text(item.summary, 2048) || !text(item.category, 64) || !text(item.ruleId, 128) || !text(item.runbookId, 64) || !time(item.createdAt) || !time(item.updatedAt) || typeof item.synthetic !== 'boolean') return false;
    if (!Array.isArray(value.evidence) || value.evidence.length > 32 || !ids(value.missingEvidenceIDs)) return false;
    const seen = new Set<string>();
    for (const evidence of value.evidence) {
        if (!object(evidence) || !fields(evidence, ['id', 'title', 'source', 'quality', 'collectedAt', 'detail', 'value', 'synthetic'], ['collectionProfile']) || !id(evidence.id) || seen.has(evidence.id) || !text(evidence.title, 256) || !text(evidence.source, 2048) || evidence.source === '' || !text(evidence.detail, 2048) || !text(evidence.value, 2048) || !time(evidence.collectedAt) || typeof evidence.synthetic !== 'boolean' || !['healthy', 'stale', 'unknown', 'denied'].includes(String(evidence.quality)) || (evidence.collectionProfile !== undefined && evidence.collectionProfile !== 'basic-readonly-v1')) return false;
        seen.add(evidence.id);
    }
    const window = value.observationWindow;
    return object(window) && fields(window, ['from', 'to']) && (window.from === null && window.to === null || time(window.from) && time(window.to) && Date.parse(window.from) <= Date.parse(window.to)) && Array.isArray(value.gaps) && value.gaps.length <= 34 && value.gaps.every(gap => object(gap) && fields(gap, ['code', 'evidenceIDs', 'detail']) && text(gap.code, 128) && ids(gap.evidenceIDs) && text(gap.detail, 2048));
}
/** The preview is memory-only server output, not a client-authored export packet. */
export function parseCaseAnalysisPreview(value: unknown, caseId: string, now = Date.now()): CaseAnalysisPreview | null {
    if (!object(value) || !fields(value, ['schemaVersion', 'caseId', 'configRevision', 'baseURL', 'endpointOrigin', 'model', 'packetJSON', 'packetSHA256', 'validUntil', 'serverNow', 'previewToken']) || value.schemaVersion !== 'tracebolt.case-analysis-preview.v1' || value.caseId !== caseId || !id(value.configRevision) || !text(value.baseURL, 512) || !text(value.endpointOrigin, 512) || !text(value.model, 128) || value.model === '' || !text(value.packetJSON, 24 * 1024) || !hash(value.packetSHA256) || !hash(value.previewToken) || !time(value.validUntil) || !time(value.serverNow) || Date.parse(value.validUntil) <= Date.parse(value.serverNow) || Date.parse(value.validUntil) - Date.parse(value.serverNow) > 120_000) return null;
    const destination = endpointInfo(value.baseURL);
    if (!destination.valid || destination.origin !== value.endpointOrigin) return null;
    try {
        const packet: unknown = JSON.parse(value.packetJSON);
        if (!validPacket(packet, caseId)) return null;
        return { ...value, packet, expiresAtMs: now + Date.parse(value.validUntil) - Date.parse(value.serverNow) } as unknown as CaseAnalysisPreview;
    } catch { return null; }
}
/** Compare data values independently of JSON member ordering and Go's HTML escaping. */
function sameData(a: unknown, b: unknown): boolean {
    if (a === b) return true;
    if (Array.isArray(a) && Array.isArray(b)) return a.length === b.length && a.every((value, index) => sameData(value, b[index]));
    if (!object(a) || !object(b)) return false;
    const keys = Object.keys(a);
    return keys.length === Object.keys(b).length && keys.every(key => Object.hasOwn(b, key) && sameData(a[key], b[key]));
}
export function validCaseAnalysisResult(value: unknown, preview: CaseAnalysisPreview): value is AnalysisResult {
    if (!object(value) || value.schemaVersion !== 'tracebolt.analysis.v1' || value.previewToken !== preview.previewToken || value.configRevision !== preview.configRevision || value.superseded !== false || value.rootCauseConfirmed !== false || !id(value.id) || !text(value.fingerprint, 128) || !time(value.generatedAt) || !strings(value.limitations) || !validPacket(value.packet, preview.caseId) || !sameData(value.packet, preview.packet)) return false;
    const provenance = (p: unknown) => object(p) && p.packetSHA256 === preview.packetSHA256 && ['method', 'provider', 'model', 'promptVersion', 'runbookVersion', 'ruleId', 'destination', 'endpointOrigin'].every(key => text(p[key], 512));
    const baseline = value.baseline;
    const ai = value.ai;
    if (!object(baseline) || !text(baseline.summary, 2048) || !ids(baseline.evidenceIDs) || !strings(baseline.nextSteps) || !provenance(baseline.provenance) || !object(ai) || !['not_configured', 'completed', 'canceled', 'timeout', 'busy', 'invalid_response', 'unavailable'].includes(String(ai.status)) || !text(ai.reason, 2048) || !strings(ai.nextSteps) || !provenance(ai.provenance) || !object(ai.provenance) || ai.provenance.model !== preview.model || ai.provenance.endpointOrigin !== preview.endpointOrigin) return false;
    if (ai.status !== 'completed') return ai.findings === null;
    const findings = ai.findings;
    const known = new Set(value.packet.evidence.map(evidence => evidence.id));
    const references = (v: unknown) => ids(v) && v.every(key => known.has(key));
    const claims = (v: unknown) => Array.isArray(v) && v.length <= 5 && v.every(claim => object(claim) && text(claim.statement, 512) && references(claim.evidenceIDs));
    return object(findings) && references(findings.observedEvidenceIDs) && claims(findings.hypotheses) && claims(findings.counterevidence) && strings(findings.missingData, 8, 512) && ['none', 'service', 'storage', 'network'].includes(String(findings.nextCheck));
}
