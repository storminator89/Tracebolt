import { inventoryAge } from './complete-packages-types';
import { validWindowsCapacityTimestamp as timestamp } from './windows-capacity-types';
import { validWindowsCompleteIncidentItem } from './windows-complete-incident-inbox-types';
import type { WindowsCompleteIncidentItem } from './windows-complete-incident-inbox-types';
import { fullServicesGenerationId, validFullServiceRow } from './windows-full-services-types';
import type { FullServiceState } from './windows-full-services-types';
import { validWindowsServiceHealthSource, windowsServiceHealthSourceFresh, sameWindowsServiceHealthSource } from './windows-service-health-complete-types';
import type { WindowsServiceHealthSource } from './windows-service-health-complete-types';
import { validWindowsActionBinding } from './windows-service-action-types';
import { windowsServiceReviewCurrent, windowsServiceReviewElapsed, WINDOWS_SERVICE_INCIDENT_REVIEW_BYTES } from './windows-service-incident-review-types';
import type { WindowsServiceReviewContext } from './windows-service-incident-review-types';

export interface WindowsCompleteServiceReviewObservation { name: string; displayName: string; state: FullServiceState | 'unknown'; source: WindowsServiceHealthSource }
export interface WindowsCompleteServiceIncidentReviewView {
    schemaVersion: 'tracebolt.windows-service-incident-review.v2'; serverNow: string; authorityExpiresAt: string;
    incident: Extract<WindowsCompleteIncidentItem, { sourceKind: 'windows_full_services' }>;
    observation: WindowsCompleteServiceReviewObservation | null;
    control: Omit<WindowsServiceReviewContext['view']['control'], 'status'> & { status: 'matched' | 'not_configured' | 'unavailable' | 'target_mismatch' | 'operator_capability_required' | 'unsupported_target' };
}
export interface WindowsCompleteServiceIncidentReviewContext extends WindowsServiceReviewContext { view: WindowsCompleteServiceIncidentReviewView }
const exact = (v: unknown, keys: readonly string[]): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v, k));
/** This additive decoder deliberately never feeds native names into the v1 contract. */
export function validWindowsCompleteServiceIncidentReview(value: unknown, key: string, deviceId: string, serviceName: string): value is WindowsCompleteServiceIncidentReviewView {
    if (!exact(value, ['schemaVersion', 'serverNow', 'authorityExpiresAt', 'incident', 'observation', 'control']) || value.schemaVersion !== 'tracebolt.windows-service-incident-review.v2' || !timestamp(value.serverNow) || !timestamp(value.authorityExpiresAt) || inventoryAge(value.authorityExpiresAt, value.serverNow) <= 0 || inventoryAge(value.authorityExpiresAt, value.serverNow) > 120000 || !validWindowsCompleteIncidentItem(value.incident, value.serverNow) || value.incident.sourceKind !== 'windows_full_services' || value.incident.key !== key || value.incident.deviceId !== deviceId || value.incident.serviceName !== serviceName || value.incident.statusValidUntil && inventoryAge(value.authorityExpiresAt, value.incident.statusValidUntil) < 0) return false;
    const row = value.observation;
    if (row !== null) {
        if (!exact(row, ['name', 'displayName', 'state', 'source']) || row.name !== serviceName || !validFullServiceRow({ name: row.name, displayName: row.displayName, displayNameQuality: 'observed', state: row.state === 'unknown' ? null : row.state, stateQuality: row.state === 'unknown' ? 'unavailable' : 'observed', pid: null, pidQuality: 'unavailable' }) || !validWindowsServiceHealthSource(row.source) || row.source.rowCount < 1 || row.source.generationId !== fullServicesGenerationId(deviceId, row.source.grantId, row.source.sequence) || !windowsServiceHealthSourceFresh(row.source, value.serverNow) || inventoryAge(value.authorityExpiresAt, row.source.capturedAt) > 300000 || inventoryAge(value.authorityExpiresAt, row.source.receivedAt) > 300000 || inventoryAge(row.source.expiresAt, value.authorityExpiresAt) < 0) return false;
    }
    if (value.incident.currentSource && (row === null || !sameWindowsServiceHealthSource(value.incident.currentSource, row.source as WindowsServiceHealthSource))) return false;
    const control = value.control;
    if (!exact(control, ['status', 'binding', 'bindingDigest']) || !['matched', 'not_configured', 'unavailable', 'target_mismatch', 'operator_capability_required', 'unsupported_target'].includes(control.status as string)) return false;
    if (control.status === 'matched' ? !validWindowsActionBinding(control.binding, deviceId) || control.binding.target !== serviceName || typeof control.bindingDigest !== 'string' || !/^sha256:[a-f0-9]{64}$/.test(control.bindingDigest) : control.binding !== null || control.bindingDigest !== null) return false;
    return new TextEncoder().encode(JSON.stringify(value)).byteLength + 1 <= WINDOWS_SERVICE_INCIDENT_REVIEW_BYTES;
}
export function windowsCompleteServiceReviewObservation(context: WindowsCompleteServiceIncidentReviewContext): WindowsCompleteServiceReviewObservation | null {
    const row = context.view.observation, age = windowsServiceReviewElapsed(context);
    return row && windowsServiceReviewCurrent(context) && inventoryAge(context.view.serverNow, row.source.capturedAt) + age < 300000 && inventoryAge(context.view.serverNow, row.source.receivedAt) + age < 300000 ? row : null;
}
