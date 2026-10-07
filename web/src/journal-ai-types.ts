import { journalAge, journalTime, validJournalGeneration, validJournalGenerationView, validJournalUnit } from './journal-types';
import type { JournalGenerationView, JournalPolicyGeneration } from './journal-types';
import { validJournalAnalysisResult } from './investigation-analysis-types';
import type { StoredAnalysisResult } from './investigation-analysis-types';
import type { HealthIncident } from './health-types';
export const JOURNAL_AI_SCOPE = 'service-journal-ai-v1';
export const JOURNAL_AI_SETTINGS_BYTES = 16384;
export interface JournalAITarget { deviceId: string; unit: string; generation: JournalPolicyGeneration }
export interface JournalAISettings {
    schemaVersion: 'tracebolt.journal-ai-settings.v1'; revision: string; enabled: boolean; ready: boolean; configRevision: string;
    providerSaved: boolean; baseURL: string; model: string; targets: JournalAITarget[]; lookbackMinutes: number; approvedAt: string;
    devices: string[]; plaintext: boolean; maxTargets: 8; maxAnalysesPerHour: 2; maxRows: 10; maxMessageBytes: 1024;
    dataScope: typeof JOURNAL_AI_SCOPE; retention: 'original-capture-expiry-memory-only'; blocked: boolean; cancellationPending: boolean;
}
export interface JournalAISource { deviceId: string; serverNow: string; generation: JournalGenerationView | null }
export const journalAIStates = ['not_started', 'preparing', 'capturing', 'analyzing', 'completed', 'canceled', 'expired', 'unavailable', 'invalid_response', 'timeout', 'interrupted', 'busy', 'cancel_pending', 'capture_unconfirmed'] as const;
export type JournalAIState = typeof journalAIStates[number];
export interface JournalAISummary { state: JournalAIState; expiresAt: string | null }
export interface JournalAIResult extends JournalAISummary { schemaVersion: 'tracebolt.journal-ai-result.v1'; serverNow: string; result: StoredAnalysisResult | null }
const object = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);
const exact = (v: unknown, keys: string[]): v is Record<string, unknown> => object(v) && Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v, k));
const text = (v: unknown, n = 2048): v is string => typeof v === 'string' && v.length <= n && !/[\u0000-\u001f\u007f]/.test(v);
export const journalAIDevice = (v: unknown): v is string => typeof v === 'string' && /^agent_[a-f0-9]{32}$/.test(v);
const revision = (v: unknown): v is string => text(v, 128) && /^[A-Za-z0-9_-]+$/.test(v);
export function validJournalAISettings(v: unknown): v is JournalAISettings {
    if (!exact(v, ['schemaVersion', 'revision', 'enabled', 'ready', 'configRevision', 'providerSaved', 'baseURL', 'model', 'targets', 'lookbackMinutes', 'approvedAt', 'devices', 'plaintext', 'maxTargets', 'maxAnalysesPerHour', 'maxRows', 'maxMessageBytes', 'dataScope', 'retention', 'blocked', 'cancellationPending']) || v.schemaVersion !== 'tracebolt.journal-ai-settings.v1' || !revision(v.revision) || !revision(v.configRevision) || ['enabled', 'ready', 'providerSaved', 'plaintext', 'blocked', 'cancellationPending'].some(k => typeof v[k] !== 'boolean') || !text(v.baseURL) || !text(v.model, 256) || !Array.isArray(v.targets) || v.targets.length > 8 || typeof v.lookbackMinutes !== 'number' || ![5, 15].includes(v.lookbackMinutes) || !text(v.approvedAt, 40) || !Array.isArray(v.devices) || v.devices.length > 25 || !v.devices.every(journalAIDevice) || new Set(v.devices).size !== v.devices.length || v.maxTargets !== 8 || v.maxAnalysesPerHour !== 2 || v.maxRows !== 10 || v.maxMessageBytes !== 1024 || v.dataScope !== JOURNAL_AI_SCOPE || v.retention !== 'original-capture-expiry-memory-only') return false;
    if (!v.targets.every(t => exact(t, ['deviceId', 'unit', 'generation']) && journalAIDevice(t.deviceId) && validJournalUnit(t.unit) && validJournalGeneration(t.generation)) || new Set(v.targets.map(t => `${t.deviceId}:${t.unit}`)).size !== v.targets.length) return false;
    if (v.enabled && (!v.targets.length || !journalTime(v.approvedAt)) || v.ready && (!v.enabled || !v.providerSaved || v.blocked)) return false;
    if (v.providerSaved) { try { const u = new URL(v.baseURL); if (!['http:', 'https:'].includes(u.protocol) || u.username || u.password || u.search || u.hash || !v.model) return false; } catch { return false; } }
    return true;
}
export function validJournalAISource(v: unknown, device: string): v is JournalAISource {
    return exact(v, ['deviceId', 'serverNow', 'generation']) && v.deviceId === device && journalAIDevice(device) && journalTime(v.serverNow) && (v.generation === null || validJournalGenerationView(v.generation, v.serverNow));
}
export function journalAIAllows(source: JournalAISource, unit: string, elapsed = 0): boolean {
    const g = source.generation;
    return elapsed >= 0 && elapsed < 60000 && !!g && g.schemaVersion === 'tracebolt.journal-generation-view.v2' && g.fresh && g.policyEnabled === true && journalAge(g.expiresAt, source.serverNow) > elapsed && validJournalUnit(unit) && (g.serviceAuthorization === 'all-system-services' || g.allowedUnits?.includes(unit) === true);
}
export function validJournalAISummary(v: unknown): v is JournalAISummary {
    return exact(v, ['state', 'expiresAt']) && journalAIStates.includes(v.state as JournalAIState) && (v.expiresAt === null || journalTime(v.expiresAt));
}
export function validJournalAIResult(v: unknown, incident: HealthIncident): v is JournalAIResult {
    if (!exact(v, ['schemaVersion', 'state', 'serverNow', 'expiresAt', 'result']) || v.schemaVersion !== 'tracebolt.journal-ai-result.v1' || !journalTime(v.serverNow) || !validJournalAISummary({ state: v.state, expiresAt: v.expiresAt })) return false;
    if (v.result !== null && (v.state !== 'completed' || !journalTime(v.expiresAt) || journalAge(v.expiresAt, v.serverNow) <= 0 || journalAge(v.expiresAt, v.serverNow) > 900000 || !validJournalAnalysisResult(v.result, incident, v.serverNow) || v.result.ai.status !== 'completed')) return false;
    return v.state !== 'completed' || v.result !== null;
}
