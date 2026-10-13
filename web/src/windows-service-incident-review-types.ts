import { getProtectedRequestEpoch } from './api';
import { windowsHealthElapsed } from './windows-health-clock';
import { inventoryAge } from './complete-packages-types';
import { validWindowsCapacityTimestamp as timestamp } from './windows-capacity-types';
import { validWindowsIncidentItem } from './windows-incident-inbox-types';
import type { WindowsIncidentItem } from './windows-incident-inbox-types';
import { validWindowsActionBinding } from './windows-service-action-types';
import type { WindowsActionBinding } from './windows-service-action-types';

export const WINDOWS_SERVICE_INCIDENT_REVIEW_BYTES = 16 * 1024;
export const WINDOWS_SERVICE_REVIEW_HEADER = 'X-Tracebolt-Windows-Service-Review';
export interface WindowsServiceIncidentObservation {
    name: string; displayName: string; state: 'running' | 'stopped' | 'paused' | 'start_pending' | 'stop_pending' | 'continue_pending' | 'pause_pending';
    collectedAt: string; receivedAt: string; sequence: number; quality: 'healthy' | 'partial'; complete: boolean; truncated: boolean; countExact: boolean; observedCount: number;
}
export interface WindowsServiceIncidentReviewView {
    schemaVersion: 'tracebolt.windows-service-incident-review.v1'; serverNow: string; authorityExpiresAt: string;
    incident: WindowsIncidentItem; observation: WindowsServiceIncidentObservation | null;
    control: { status: 'matched' | 'not_configured' | 'unavailable' | 'target_mismatch' | 'operator_capability_required'; binding: WindowsActionBinding | null; bindingDigest: string | null };
}
/** In-memory review evidence, never a grant or a route/storage payload. */
export interface WindowsServiceIncidentReviewContext {
    view: WindowsServiceIncidentReviewView; sessionKey: string;
    anchor: { mono: number; wall: number; epoch: number };
}
const exact = (value: unknown, keys: readonly string[]): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const digest = (value: unknown): value is string => typeof value === 'string' && /^sha256:[a-f0-9]{64}$/.test(value);
const fresh = (at: unknown, now: string): at is string => timestamp(at) && inventoryAge(now, at) >= 0 && inventoryAge(now, at) <= 120000;
export function sameWindowsServiceReviewBinding(a: WindowsActionBinding, b: WindowsActionBinding): boolean {
    return (['managerId', 'keyId', 'endpointId', 'incarnationDigest', 'installationId', 'grantDigest', 'target', 'targetDigest'] as const).every(key => a[key] === b[key]);
}
export function validWindowsServiceIncidentReview(value: unknown, incidentKey: string, deviceId: string, serviceName: string): value is WindowsServiceIncidentReviewView {
    if (!exact(value, ['schemaVersion', 'serverNow', 'authorityExpiresAt', 'incident', 'observation', 'control']) || value.schemaVersion !== 'tracebolt.windows-service-incident-review.v1' || !timestamp(value.serverNow) || !timestamp(value.authorityExpiresAt) || inventoryAge(value.authorityExpiresAt, value.serverNow) <= 0 || inventoryAge(value.authorityExpiresAt, value.serverNow) > 120000 || !validWindowsIncidentItem(value.incident, value.serverNow) || value.incident.key !== incidentKey || value.incident.deviceId !== deviceId || value.incident.domain !== 'service' || value.incident.serviceName !== serviceName || value.incident.statusValidUntil && inventoryAge(value.authorityExpiresAt, value.incident.statusValidUntil) < 0) return false;
    const row = value.observation;
    if (row !== null) {
        if (!exact(row, ['name', 'displayName', 'state', 'collectedAt', 'receivedAt', 'sequence', 'quality', 'complete', 'truncated', 'countExact', 'observedCount']) || row.name !== serviceName || typeof row.displayName !== 'string' || new TextEncoder().encode(row.displayName).byteLength > 256 || /[\p{Cc}\p{Cf}\uFFFD\uD800-\uDFFF\u2028\u2029]/u.test(row.displayName) || !['running', 'stopped', 'paused', 'start_pending', 'stop_pending', 'continue_pending', 'pause_pending'].includes(row.state as string) || !fresh(row.collectedAt, value.serverNow) || !fresh(row.receivedAt, value.serverNow) || !Number.isSafeInteger(row.sequence) || Number(row.sequence) < 1 || !['healthy', 'partial'].includes(row.quality as string) || typeof row.complete !== 'boolean' || typeof row.truncated !== 'boolean' || typeof row.countExact !== 'boolean' || !Number.isSafeInteger(row.observedCount) || Number(row.observedCount) < 1 || Number(row.observedCount) > 2048) return false;
        if (row.quality === 'healthy' ? !row.complete || !row.countExact || row.truncated : row.complete || row.countExact && !row.truncated) return false;
    }
    const control = value.control;
    if (!exact(control, ['status', 'binding', 'bindingDigest']) || !['matched', 'not_configured', 'unavailable', 'target_mismatch', 'operator_capability_required'].includes(control.status as string)) return false;
    if (control.status === 'matched' ? !validWindowsActionBinding(control.binding, deviceId) || control.binding.target !== serviceName || !digest(control.bindingDigest) : control.binding !== null || control.bindingDigest !== null) return false;
    return new TextEncoder().encode(JSON.stringify(value)).byteLength <= WINDOWS_SERVICE_INCIDENT_REVIEW_BYTES;
}
export function windowsServiceReviewRequestElapsed(context: WindowsServiceIncidentReviewContext): number {
    const mono = performance.now() - context.anchor.mono, wall = Date.now() - context.anchor.wall;
    return context.anchor.epoch === getProtectedRequestEpoch() && Number.isFinite(mono) && mono >= 0 && Number.isFinite(wall) && Math.abs(wall - mono) <= 1500 ? mono : Infinity;
}
export function windowsServiceReviewClockKey(sessionKey: string): string { return JSON.stringify(['windows-service-incident-review', sessionKey]); }
export function windowsServiceReviewElapsed(context: WindowsServiceIncidentReviewContext): number {
    return windowsHealthElapsed(windowsServiceReviewClockKey(context.sessionKey), context.anchor.epoch, context.view.serverNow, windowsServiceReviewRequestElapsed(context));
}
export function windowsServiceReviewCurrent(context: WindowsServiceIncidentReviewContext): boolean {
    const age = windowsServiceReviewElapsed(context);
    return document.visibilityState !== 'hidden' && age < 120000 && inventoryAge(context.view.authorityExpiresAt, context.view.serverNow) > age && inventoryAge(context.sessionKey, context.view.serverNow) > age;
}
export function windowsServiceReviewObservation(context: WindowsServiceIncidentReviewContext): WindowsServiceIncidentObservation | null {
    const row = context.view.observation, age = windowsServiceReviewElapsed(context);
    return row && windowsServiceReviewCurrent(context) && inventoryAge(context.view.serverNow, row.collectedAt) + age <= 120000 && inventoryAge(context.view.serverNow, row.receivedAt) + age <= 120000 ? row : null;
}
