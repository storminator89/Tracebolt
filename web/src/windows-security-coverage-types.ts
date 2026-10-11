import { inventoryAge } from './complete-packages-types';
import type { WindowsInventorySnapshot } from './windows-inventory-types';

/** Private source reports only; neither protection nor TPM readiness. */
export const WINDOWS_SECURITY_COVERAGE_BYTES = 8192;
export const WINDOWS_SECURITY_COVERAGE_REASONS = ['', 'windows_security_coverage_access_denied', 'windows_security_coverage_unavailable', 'windows_security_coverage_unsupported_platform', 'windows_security_coverage_invalid_metadata', 'windows_security_coverage_bounds', 'windows_security_coverage_partial_result', 'windows_security_coverage_budget_exhausted'] as const;
interface Source { quality: 'observed' | 'partial' | 'denied' | 'unavailable'; reason: typeof WINDOWS_SECURITY_COVERAGE_REASONS[number] }
export interface WindowsAntivirusProduct { index: number; name: string | null; state: 'on' | 'off' | 'snoozed' | 'expired' | 'unknown'; signatureStatus: 'up-to-date' | 'out-of-date' | 'unknown' }
export interface WindowsSecurityCoverage {
    schemaVersion: 'tracebolt.windows-security-coverage.v1'; scope: 'windows-security-coverage-v1'; grantId: string; generationId: string; collectedAt: string;
    antivirus: Source & { reportedCount: number | null; rows: WindowsAntivirusProduct[]; truncated: boolean };
    tpm: Source & { presence: 'present' | 'not-found' | 'unknown'; version: '1.2' | '2.0' | 'unknown' };
}
const exact = (v: unknown, keys: readonly string[]): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v, k));
const timestamp = (v: unknown): v is string => typeof v === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(v) && Number(v.slice(0, 4)) >= 1970 && Number.isFinite(Date.parse(v)) && new Date(Date.parse(v)).toISOString().slice(0, 19) === v.slice(0, 19);
const reason = (v: unknown): boolean => WINDOWS_SECURITY_COVERAGE_REASONS.includes(v as Source['reason']);
const unavailable = (v: Record<string, unknown>): boolean => (v.quality === 'denied' || v.quality === 'unavailable') && v.reason !== '' && (v.quality === 'denied') === (v.reason === 'windows_security_coverage_access_denied');
const name = (v: unknown): boolean => typeof v === 'string' && v.length > 0 && v.length <= 128 && !/[\p{Cc}\u2028\u2029\u202a-\u202e\u2066-\u2069\uD800-\uDFFF]/u.test(v);
function antivirus(v: unknown): boolean {
    if (!exact(v, ['quality', 'reason', 'reportedCount', 'rows', 'truncated']) || !reason(v.reason) || !Array.isArray(v.rows) || v.rows.length > 16 || typeof v.truncated !== 'boolean') return false;
    if (v.reportedCount === null) return v.rows.length === 0 && !v.truncated && unavailable(v);
    if (typeof v.reportedCount !== 'number' || !Number.isSafeInteger(v.reportedCount) || Object.is(v.reportedCount, -0) || v.reportedCount < 0 || v.reportedCount > 65535 || v.rows.length > v.reportedCount || v.truncated !== (v.rows.length < v.reportedCount)) return false;
    let complete = !v.truncated;
    if (!v.rows.every((p, index) => {
        if (!exact(p, ['index', 'name', 'state', 'signatureStatus']) || p.index !== index || Object.is(p.index, -0) || p.name !== null && !name(p.name) || !['on', 'off', 'snoozed', 'expired', 'unknown'].includes(p.state as string) || !['up-to-date', 'out-of-date', 'unknown'].includes(p.signatureStatus as string)) return false;
        if (p.name === null || p.state === 'unknown' || p.signatureStatus === 'unknown') complete = false;
        return true;
    })) return false;
    return v.quality === 'observed' && complete && v.reason === '' || v.quality === 'partial' && v.reason !== '';
}
function tpm(v: unknown): boolean {
    if (!exact(v, ['quality', 'reason', 'presence', 'version']) || !reason(v.reason)) return false;
    if (v.presence === 'unknown') return v.version === 'unknown' && unavailable(v);
    if (v.presence === 'not-found') return v.version === 'unknown' && v.quality === 'observed' && v.reason === '';
    if (v.presence !== 'present') return false;
    if (v.version === 'unknown') return v.quality === 'partial' && v.reason !== '';
    return ['1.2', '2.0'].includes(v.version as string) && v.quality === 'observed' && v.reason === '';
}
export function validWindowsSecurityCoverage(v: unknown, snapshot: WindowsInventorySnapshot, serverNow: string): v is WindowsSecurityCoverage {
    if (!exact(v, ['schemaVersion', 'scope', 'grantId', 'generationId', 'collectedAt', 'antivirus', 'tpm']) || v.schemaVersion !== 'tracebolt.windows-security-coverage.v1' || v.scope !== 'windows-security-coverage-v1' || typeof v.grantId !== 'string' || !/^[a-f0-9]{32}$/.test(v.grantId) || typeof v.generationId !== 'string' || !/^sample_[a-f0-9]{32}$/.test(v.generationId) || v.generationId !== snapshot.generationId || !timestamp(v.collectedAt) || !timestamp(snapshot.collectedAt) || !timestamp(serverNow) || inventoryAge(v.collectedAt, snapshot.collectedAt) !== 0 || inventoryAge(v.collectedAt, serverNow) > 30000 || inventoryAge(serverNow, v.collectedAt) >= 86400000 || !antivirus(v.antivirus) || !tpm(v.tpm)) return false;
    const encoded = JSON.stringify(v).replace(/[<>&\u2028\u2029]/g, ch => `\\u${ch.charCodeAt(0).toString(16).padStart(4, '0')}`);
    return new TextEncoder().encode(encoded).byteLength <= WINDOWS_SECURITY_COVERAGE_BYTES;
}
/** Count alone and unknown-only product rows cannot refresh useful history. */
export function usefulWindowsSecurityCoverage(v: WindowsSecurityCoverage): boolean {
    return v.tpm.presence !== 'unknown' || v.antivirus.quality === 'observed' && v.antivirus.reportedCount === 0 || v.antivirus.rows.some(row => row.name !== null || row.state !== 'unknown' || row.signatureStatus !== 'unknown');
}
