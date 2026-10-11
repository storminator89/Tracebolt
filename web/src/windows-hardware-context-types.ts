import { inventoryAge } from './complete-packages-types';
import type { WindowsInventorySnapshot } from './windows-inventory-types';

/** Read-only source labels. BIOS serial is neither a system serial nor a device identifier. */
export const WINDOWS_HARDWARE_CONTEXT_BYTES = 6 * 1024;
export const WINDOWS_HARDWARE_CONTEXT_REASONS = ['', 'windows_hardware_context_access_denied', 'windows_hardware_context_unavailable', 'windows_hardware_context_unsupported_platform', 'windows_hardware_context_invalid_metadata', 'windows_hardware_context_bounds', 'windows_hardware_context_partial_result', 'windows_hardware_context_budget_exhausted'] as const;
export type WindowsHardwareFieldQuality = 'observed' | 'empty' | 'unavailable' | 'denied';
export interface WindowsHardwareField { value: string | null; quality: WindowsHardwareFieldQuality }
interface WindowsHardwareSource { quality: 'observed' | 'partial' | 'unavailable' | 'denied'; reason: typeof WINDOWS_HARDWARE_CONTEXT_REASONS[number] }
export interface WindowsHardwareContext {
    schemaVersion: 'tracebolt.windows-hardware-context.v1'; scope: 'windows-hardware-context-v1'; grantId: string; generationId: string; collectedAt: string;
    system: WindowsHardwareSource & { manufacturer: WindowsHardwareField; model: WindowsHardwareField };
    firmware: WindowsHardwareSource & { source: 'Win32_BIOS'; vendor: WindowsHardwareField; version: WindowsHardwareField; releaseDate: WindowsHardwareField; serialNumber: WindowsHardwareField };
    chassis: WindowsHardwareSource & { source: 'Win32_SystemEnclosure'; serialNumber: WindowsHardwareField };
    power: WindowsHardwareSource & { source: 'GetSystemPowerStatus'; acLineStatus: 'online' | 'offline' | 'unknown'; batteryPresence: 'present' | 'absent' | 'unknown'; charging: 'yes' | 'no' | 'unknown'; batteryPercent: number | null; estimatedSeconds: number | null };
}
const exact = (v: unknown, keys: readonly string[]): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v, k));
const integer = (v: unknown, max: number): v is number => typeof v === 'number' && Number.isSafeInteger(v) && !Object.is(v, -0) && v >= 0 && v <= max;
const timestamp = (v: unknown): v is string => typeof v === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(v) && Number(v.slice(0, 4)) >= 1970 && Number.isFinite(Date.parse(v)) && new Date(Date.parse(v)).toISOString().slice(0, 19) === v.slice(0, 19);
const label = (v: unknown, units: number): v is string => typeof v === 'string' && v.length > 0 && v.length <= units && !/[\p{Cc}\uFFFD\uD800-\uDFFF]/u.test(v);
const field = (v: unknown, units = 128): v is WindowsHardwareField => exact(v, ['value', 'quality']) && (v.quality === 'observed' ? label(v.value, units) : v.value === null && ['empty', 'denied', 'unavailable'].includes(v.quality as string));
const reason = (v: unknown): boolean => WINDOWS_HARDWARE_CONTEXT_REASONS.includes(v as WindowsHardwareSource['reason']);
const unavailable = (v: Record<string, unknown>): boolean => (v.quality === 'denied' || v.quality === 'unavailable') && v.reason !== '' && (v.quality === 'denied') === (v.reason === 'windows_hardware_context_access_denied');
function textSource(v: unknown, keys: string[], source?: string): boolean {
    if (!exact(v, ['quality', 'reason', ...keys, ...(source ? ['source'] : [])]) || !reason(v.reason) || source && v.source !== source || !keys.every(key => field(v[key], key === 'serialNumber' ? 64 : 128))) return false;
    if (source === 'Win32_BIOS' && (v.releaseDate as WindowsHardwareField).value !== null && windowsFirmwareDate((v.releaseDate as WindowsHardwareField).value) === null) return false;
    const fields = keys.map(key => v[key] as WindowsHardwareField), missing = fields.some(f => f.quality === 'denied' || f.quality === 'unavailable');
    if (v.quality === 'denied' || v.quality === 'unavailable') return unavailable(v) && fields.every(f => f.value === null && f.quality === v.quality);
    return v.quality === 'observed' && !missing && v.reason === '' || v.quality === 'partial' && missing && v.reason !== '';
}
function power(v: unknown): boolean {
    if (!exact(v, ['quality', 'reason', 'source', 'acLineStatus', 'batteryPresence', 'charging', 'batteryPercent', 'estimatedSeconds']) || !reason(v.reason) || v.source !== 'GetSystemPowerStatus' || !['online', 'offline', 'unknown'].includes(v.acLineStatus as string) || !['present', 'absent', 'unknown'].includes(v.batteryPresence as string) || !['yes', 'no', 'unknown'].includes(v.charging as string) || !(v.batteryPercent === null || integer(v.batteryPercent, 100)) || !(v.estimatedSeconds === null || integer(v.estimatedSeconds, 4294967294))) return false;
    if (v.batteryPresence !== 'present' && (v.charging !== 'unknown' || v.batteryPercent !== null || v.estimatedSeconds !== null)) return false;
    if (v.quality === 'denied' || v.quality === 'unavailable') return unavailable(v) && v.acLineStatus === 'unknown' && v.batteryPresence === 'unknown';
    if (v.estimatedSeconds !== null && v.acLineStatus !== 'offline') return false;
    const partial = v.acLineStatus === 'unknown' || v.batteryPresence === 'unknown' || v.batteryPresence === 'present' && (v.charging === 'unknown' || v.batteryPercent === null || v.acLineStatus === 'offline' && v.estimatedSeconds === null);
    return v.quality === 'observed' && !partial && v.reason === '' || v.quality === 'partial' && partial && v.reason !== '';
}
export function validWindowsHardwareContext(v: unknown, snapshot: WindowsInventorySnapshot, serverNow: string): v is WindowsHardwareContext {
    if (!exact(v, ['schemaVersion', 'scope', 'grantId', 'generationId', 'collectedAt', 'system', 'firmware', 'chassis', 'power']) || v.schemaVersion !== 'tracebolt.windows-hardware-context.v1' || v.scope !== 'windows-hardware-context-v1' || typeof v.grantId !== 'string' || !/^[a-f0-9]{32}$/.test(v.grantId) || typeof v.generationId !== 'string' || !/^sample_[a-f0-9]{32}$/.test(v.generationId) || v.generationId !== snapshot.generationId || !timestamp(v.collectedAt) || !timestamp(snapshot.collectedAt) || !timestamp(serverNow) || inventoryAge(v.collectedAt, snapshot.collectedAt) !== 0 || inventoryAge(v.collectedAt, serverNow) > 30000 || inventoryAge(serverNow, v.collectedAt) >= 86400000 || !textSource(v.system, ['manufacturer', 'model']) || !textSource(v.firmware, ['vendor', 'version', 'releaseDate', 'serialNumber'], 'Win32_BIOS') || !textSource(v.chassis, ['serialNumber'], 'Win32_SystemEnclosure') || !power(v.power)) return false;
    const encoded = JSON.stringify(v).replace(/[<>&\u2028\u2029]/g, ch => `\\u${ch.charCodeAt(0).toString(16).padStart(4, '0')}`);
    return new TextEncoder().encode(encoded).byteLength <= WINDOWS_HARDWARE_CONTEXT_BYTES;
}
/** Only real source values make a prior capture useful; partial can be entirely unknown. */
export function usefulWindowsHardwareContext(v: WindowsHardwareContext): boolean {
    return [v.system.manufacturer, v.system.model, v.firmware.vendor, v.firmware.version, v.firmware.releaseDate, v.firmware.serialNumber, v.chassis.serialNumber].some(field => field.value !== null) ||
        v.power.acLineStatus === 'online' || v.power.acLineStatus === 'offline' || v.power.batteryPresence === 'present' || v.power.batteryPresence === 'absent' ||
        v.power.charging === 'yes' || v.power.charging === 'no' || v.power.batteryPercent !== null || v.power.estimatedSeconds !== null;
}
/** Only an exact calendar day is presented as a date. Never guess a partial DMTF value. */
export function windowsFirmwareDate(value: string | null): string | null {
    if (!value || !/^\d{14}\.\d{6}[+-]\d{3}$/.test(value)) return null;
    const date = `${value.slice(0, 4)}-${value.slice(4, 6)}-${value.slice(6, 8)}`;
    return Number(value.slice(0, 4)) > 0 && Number.isFinite(Date.parse(date)) && new Date(date).toISOString().slice(0, 10) === date && Number(value.slice(8, 10)) < 24 && Number(value.slice(10, 12)) < 60 && Number(value.slice(12, 14)) < 60 ? date : null;
}
