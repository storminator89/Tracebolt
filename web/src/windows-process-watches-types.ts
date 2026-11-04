import { fullProcessesGenerationId, validFullProcessesComplete, validFullProcessesRow } from './windows-full-processes-types';
import type { FullProcessesComplete } from './windows-full-processes-types';

export interface ProcessWatchPolicy { enabled: boolean; names: string[]; revision: number; source: { grantId: string; grantRevision: number } | null }
export interface ProcessWatchCheck { name: string; status: 'present' | 'not_observed' | 'unknown'; matches: number | null }
export interface ProcessWatchView { schemaVersion: 'tracebolt.windows-process-watch-view.v1'; deviceId: string; serverNow: string; expiresAt: string; policy: ProcessWatchPolicy; status: 'disabled' | 'current' | 'unknown'; checks: ProcessWatchCheck[]; source: FullProcessesComplete | null; unavailableNames: number | null }
const exact = (v: unknown, keys: string[]): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v, k));
const integer = (v: unknown, max = Number.MAX_SAFE_INTEGER): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 && v <= max;
const date = (v: unknown): v is string => typeof v === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(v) && Number.isFinite(Date.parse(v));
export function validProcessWatchNames(v: unknown): v is string[] { return Array.isArray(v) && v.length <= 8 && new Set(v).size === v.length && v.every(name => validFullProcessesRow({ pid: 0, parentPid: 0, threads: 0, name, nameQuality: 'observed' })); }
export function validProcessWatchView(v: unknown, device: string): v is ProcessWatchView {
 if (!exact(v, ['schemaVersion', 'deviceId', 'serverNow', 'expiresAt', 'policy', 'status', 'checks', 'source', 'unavailableNames']) || v.schemaVersion !== 'tracebolt.windows-process-watch-view.v1' || v.deviceId !== device || !date(v.serverNow) || !date(v.expiresAt) || Date.parse(v.expiresAt) <= Date.parse(v.serverNow) || Date.parse(v.expiresAt) - Date.parse(v.serverNow) > 30000 || !exact(v.policy, ['enabled', 'names', 'revision', 'source'])) return false;
 const p = v.policy;
 if (typeof p.enabled !== 'boolean' || !validProcessWatchNames(p.names) || !integer(p.revision) || p.enabled && (p.names.length === 0 || p.revision === 0) || !Array.isArray(v.checks) || v.checks.length !== (p.enabled ? p.names.length : 0)) return false;
 if (p.enabled) { if (!exact(p.source, ['grantId', 'grantRevision']) || typeof p.source.grantId !== 'string' || !/^[a-f0-9]{32}$/.test(p.source.grantId) || !integer(p.source.grantRevision) || p.source.grantRevision === 0) return false; }
 else if (p.names.length !== 0 || p.source !== null || v.status !== 'disabled') return false;
 if (v.status === 'current') {
  if (!p.enabled || !validFullProcessesComplete(v.source, device, v.serverNow) || !integer(v.unavailableNames, v.source.manifest.rowCount) || !p.source) return false;
  const source = p.source as { grantId: string; grantRevision: number }, m = v.source.manifest, serverNow = v.serverNow, expiresAt = v.expiresAt;
  if (source.grantId !== m.grantId || source.grantRevision !== m.grantRevision || m.generationId !== fullProcessesGenerationId(device, m.grantId, m.sequence) || [m.captureStartedAt, v.source.receivedAt].some(at => Date.parse(serverNow) - Date.parse(at) >= 300000 || Date.parse(expiresAt) > Date.parse(at) + 300000)) return false;
 } else if (!['disabled', 'unknown'].includes(v.status as string) || v.source !== null || v.unavailableNames !== null || p.enabled && v.status !== 'unknown') return false;
 let total = typeof v.unavailableNames === 'number' ? v.unavailableNames : 0;
 for (let i = 0; i < v.checks.length; i++) {
  const c = v.checks[i];
  if (!exact(c, ['name', 'status', 'matches']) || c.name !== p.names[i] || !['present', 'not_observed', 'unknown'].includes(c.status as string)) return false;
  if (c.status === 'unknown') { if (c.matches !== null) return false; }
  else { if (v.status !== 'current' || !integer(c.matches, 32768) || (c.status === 'present' ? c.matches < 1 : c.matches !== 0 || v.unavailableNames !== 0)) return false; total += c.matches; }
 }
 return v.source === null || total <= (v.source as FullProcessesComplete).manifest.rowCount;
}
