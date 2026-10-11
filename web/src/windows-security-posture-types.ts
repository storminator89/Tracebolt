import { inventoryAge } from './complete-packages-types';
import type { WindowsInventorySnapshot } from './windows-inventory-types';

/** Private, read-only source observations, never an overall protection verdict. */
export const WINDOWS_SECURITY_POSTURE_BYTES = 4096;
export const WINDOWS_SECURITY_POSTURE_REASONS = ['', 'windows_security_posture_access_denied', 'windows_security_posture_unavailable', 'windows_security_posture_unsupported_platform', 'windows_security_posture_invalid_metadata', 'windows_security_posture_bounds', 'windows_security_posture_partial_result', 'windows_security_posture_budget_exhausted'] as const;
export type WindowsSecurityState = 'on' | 'off' | 'unknown';
export type WindowsSecurityQuality = 'observed' | 'partial' | 'denied' | 'unavailable';
interface WindowsSecuritySource { quality: WindowsSecurityQuality; reason: typeof WINDOWS_SECURITY_POSTURE_REASONS[number] }
export interface WindowsSecurityPosture {
    schemaVersion: 'tracebolt.windows-security-posture.v1'; scope: 'windows-security-posture-v1'; grantId: string; generationId: string; collectedAt: string;
    defender: WindowsSecuritySource & { mode: 'normal' | 'passive' | 'edr-block' | 'unknown'; serviceEnabled: WindowsSecurityState; antivirusEnabled: WindowsSecurityState; realTimeProtectionEnabled: WindowsSecurityState; signatureVersion: string | null; signatureAgeDays: number | null };
    firewall: WindowsSecuritySource & { profiles: { profile: 'domain' | 'private' | 'public'; active: WindowsSecurityState; enabled: WindowsSecurityState }[] };
}
const exact = (v: unknown, keys: readonly string[]): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v, k));
const state = (v: unknown): v is WindowsSecurityState => v === 'on' || v === 'off' || v === 'unknown';
const timestamp = (v: unknown): v is string => typeof v === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(v) && Number(v.slice(0, 4)) >= 1970 && Number.isFinite(Date.parse(v)) && new Date(Date.parse(v)).toISOString().slice(0, 19) === v.slice(0, 19);
function source(v: Record<string, unknown>, known: number, total: number): boolean {
    if (!WINDOWS_SECURITY_POSTURE_REASONS.includes(v.reason as WindowsSecuritySource['reason'])) return false;
    if (v.quality === 'observed') return v.reason === '' && known === total;
    if (v.quality === 'partial') return v.reason !== '' && known > 0;
    return (v.quality === 'denied' || v.quality === 'unavailable') && known === 0 && v.reason !== '' && (v.quality === 'denied') === (v.reason === 'windows_security_posture_access_denied');
}
export function validWindowsSecurityPosture(v: unknown, snapshot: WindowsInventorySnapshot, serverNow: string): v is WindowsSecurityPosture {
    if (!exact(v, ['schemaVersion', 'scope', 'grantId', 'generationId', 'collectedAt', 'defender', 'firewall']) || v.schemaVersion !== 'tracebolt.windows-security-posture.v1' || v.scope !== 'windows-security-posture-v1' || typeof v.grantId !== 'string' || !/^[a-f0-9]{32}$/.test(v.grantId) || typeof v.generationId !== 'string' || !/^sample_[a-f0-9]{32}$/.test(v.generationId) || v.generationId !== snapshot.generationId || !timestamp(v.collectedAt) || !timestamp(snapshot.collectedAt) || !timestamp(serverNow) || inventoryAge(v.collectedAt, snapshot.collectedAt) !== 0 || inventoryAge(v.collectedAt, serverNow) > 30000 || inventoryAge(serverNow, v.collectedAt) >= 86400000) return false;
    const d = v.defender, f = v.firewall;
    if (!exact(d, ['quality', 'reason', 'mode', 'serviceEnabled', 'antivirusEnabled', 'realTimeProtectionEnabled', 'signatureVersion', 'signatureAgeDays']) || !['normal', 'passive', 'edr-block', 'unknown'].includes(d.mode as string) || !state(d.serviceEnabled) || !state(d.antivirusEnabled) || !state(d.realTimeProtectionEnabled)) return false;
    if (d.signatureVersion !== null && !(typeof d.signatureVersion === 'string' && d.signatureVersion.length <= 64 && /^[0-9]+(\.[0-9]+){1,3}$/.test(d.signatureVersion))) return false;
    if (d.signatureAgeDays !== null && !(typeof d.signatureAgeDays === 'number' && Number.isSafeInteger(d.signatureAgeDays) && !Object.is(d.signatureAgeDays, -0) && d.signatureAgeDays >= 0 && d.signatureAgeDays <= 65534)) return false;
    const defenderKnown = [d.mode, d.serviceEnabled, d.antivirusEnabled, d.realTimeProtectionEnabled].filter(value => value !== 'unknown').length + Number(d.signatureVersion !== null) + Number(d.signatureAgeDays !== null);
    if (!source(d, defenderKnown, 6) || !exact(f, ['quality', 'reason', 'profiles']) || !Array.isArray(f.profiles) || f.profiles.length !== 3) return false;
    const profiles = ['domain', 'private', 'public'];
    if (!f.profiles.every((p, i) => exact(p, ['profile', 'active', 'enabled']) && p.profile === profiles[i] && state(p.active) && state(p.enabled))) return false;
    if (!source(f, f.profiles.reduce((known, p) => known + Number(p.active !== 'unknown') + Number(p.enabled !== 'unknown'), 0), 6)) return false;
    return new TextEncoder().encode(JSON.stringify(v)).byteLength <= WINDOWS_SECURITY_POSTURE_BYTES;
}
