import { inventoryAge } from './complete-packages-types';
import { fullServicesGenerationId } from './windows-full-services-types';
import { validWindowsServiceHealthCompleteName, validWindowsServiceHealthSource, windowsServiceHealthSourceFresh, sourceBindingMatches } from './windows-service-health-complete-types';
import type { WindowsServiceHealthSource } from './windows-service-health-complete-types';
import { validWindowsIncidentAcknowledgement, validWindowsIncidentInboxView, validWindowsIncidentItem, WINDOWS_INCIDENT_ACK_BYTES, WINDOWS_INCIDENT_INBOX_BYTES, WINDOWS_INCIDENT_PAGE_SIZE } from './windows-incident-inbox-types';
import type { WindowsIncidentAcknowledgement, WindowsIncidentAckFilter, WindowsIncidentInboxView, WindowsIncidentItem, WindowsIncidentScope } from './windows-incident-inbox-types';

type Provenance = { openingSource: WindowsServiceHealthSource; lastBadSource: WindowsServiceHealthSource; recoverySource: WindowsServiceHealthSource | null; currentSource: WindowsServiceHealthSource | null };
export type WindowsCompleteIncidentItem =
    | (WindowsIncidentItem & { sourceKind: 'assessment_v1'; openingSource: null; lastBadSource: null; recoverySource: null; currentSource: null })
    | (Omit<WindowsIncidentItem, 'domain'> & { domain: 'service-complete'; sourceKind: 'windows_full_services' } & Provenance);
export type WindowsCompleteIncidentInboxView = Omit<WindowsIncidentInboxView, 'schemaVersion' | 'items'> & { schemaVersion: 'tracebolt.windows-incident-inbox.v2'; items: WindowsCompleteIncidentItem[] };
export type WindowsCompleteIncidentAcknowledgement = Omit<WindowsIncidentAcknowledgement, 'schemaVersion'> & { schemaVersion: 'tracebolt.windows-incident-ack.v2' };
export type WindowsInboxItem = WindowsIncidentItem | WindowsCompleteIncidentItem;
export type WindowsInboxView = WindowsIncidentInboxView | WindowsCompleteIncidentInboxView;
const provenanceKeys = ['sourceKind', 'openingSource', 'lastBadSource', 'recoverySource', 'currentSource'] as const;
const object = (value: unknown): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value);
/** Reuse v1 structural validation without weakening its closed public contract.
 * Complete native names are validated separately, never through the old name cap. */
function legacyShape(value: Record<string, unknown>) {
    const { sourceKind: _kind, openingSource: _opening, lastBadSource: _bad, recoverySource: _recovery, currentSource: _current, ...base } = value;
    return base.domain === 'service-complete' ? { ...base, domain: 'service', serviceName: 'CompleteService' } : base;
}
function sourceFor(value: unknown, deviceId: string, at: string): value is WindowsServiceHealthSource {
    return validWindowsServiceHealthSource(value) && value.generationId === fullServicesGenerationId(deviceId, value.grantId, value.sequence) && windowsServiceHealthSourceFresh(value, at);
}
export function validWindowsCompleteIncidentItem(value: unknown, now: string): value is WindowsCompleteIncidentItem {
    if (!object(value) || !provenanceKeys.every(key => Object.hasOwn(value, key)) || !validWindowsIncidentItem(legacyShape(value), now)) return false;
    if (value.sourceKind === 'assessment_v1') return value.domain !== 'service-complete' && provenanceKeys.slice(1).every(key => value[key] === null);
    if (value.sourceKind !== 'windows_full_services' || value.domain !== 'service-complete' || !validWindowsServiceHealthCompleteName(value.serviceName)) return false;
    const item = value as unknown as Extract<WindowsCompleteIncidentItem, { sourceKind: 'windows_full_services' }>;
    if (!sourceFor(item.openingSource, item.deviceId, item.openedAt) || !sourceFor(item.lastBadSource, item.deviceId, item.lastConfirmedAt) || item.collectedAt !== item.lastBadSource.capturedAt || item.receivedAt !== item.lastBadSource.receivedAt || !sourceBindingMatches(item.openingSource, item.lastBadSource) || item.lastBadSource.sequence < item.openingSource.sequence || inventoryAge(item.lastBadSource.capturedAt, item.openingSource.capturedAt) < 0) return false;
    if (item.closedReason === 'running') {
        if (!item.resolvedAt || !sourceFor(item.recoverySource, item.deviceId, item.resolvedAt) || item.recoveryCollectedAt !== item.recoverySource.capturedAt || item.recoveryReceivedAt !== item.recoverySource.receivedAt || !sourceBindingMatches(item.lastBadSource, item.recoverySource) || item.recoverySource.sequence <= item.lastBadSource.sequence || inventoryAge(item.recoverySource.capturedAt, item.lastBadSource.capturedAt) <= 0) return false;
    } else if (item.recoverySource !== null) return false;
    if (item.status === 'disabled' || item.status === 'unknown') return item.currentSource === null;
    if (!item.evaluatedAt || !item.statusValidUntil || !sourceFor(item.currentSource, item.deviceId, item.evaluatedAt) || !windowsServiceHealthSourceFresh(item.currentSource, now)) return false;
    if (item.resolvedAt === null && (!sourceBindingMatches(item.lastBadSource, item.currentSource) || item.currentSource.sequence < item.lastBadSource.sequence || inventoryAge(item.currentSource.capturedAt, item.lastBadSource.capturedAt) < 0)) return false;
    // Only the currently qualified source/evaluation can bound current confidence.
    // Historical opening/last-bad/recovery times never extend this deadline.
    return inventoryAge(item.statusValidUntil, now) > 0 && inventoryAge(item.statusValidUntil, item.currentSource.capturedAt) <= 300000 && inventoryAge(item.statusValidUntil, item.currentSource.receivedAt) <= 300000 && inventoryAge(item.currentSource.expiresAt, item.statusValidUntil) >= 0;
}
export function validWindowsCompleteIncidentInboxView(value: unknown, scope: WindowsIncidentScope, ack: WindowsIncidentAckFilter, offset: number, limit = WINDOWS_INCIDENT_PAGE_SIZE): value is WindowsCompleteIncidentInboxView {
    if (!object(value) || value.schemaVersion !== 'tracebolt.windows-incident-inbox.v2' || !Array.isArray(value.items) || !value.items.every(item => validWindowsCompleteIncidentItem(item, value.serverNow as string))) return false;
    if (!validWindowsIncidentInboxView({ ...value, schemaVersion: 'tracebolt.windows-incident-inbox.v1', items: value.items.map(item => legacyShape({ ...item })) }, scope, ack, offset, limit)) return false;
    return value.total as number <= 12500 && (value.counts as WindowsCompleteIncidentInboxView['counts']).total <= 12500 && new TextEncoder().encode(JSON.stringify(value)).byteLength <= WINDOWS_INCIDENT_INBOX_BYTES;
}
export function validWindowsCompleteIncidentAcknowledgement(value: unknown, key: string): value is WindowsCompleteIncidentAcknowledgement {
    return object(value) && value.schemaVersion === 'tracebolt.windows-incident-ack.v2' && validWindowsIncidentAcknowledgement({ ...value, schemaVersion: 'tracebolt.windows-incident-ack.v1' }, key) && new TextEncoder().encode(JSON.stringify(value)).byteLength <= WINDOWS_INCIDENT_ACK_BYTES;
}
export function windowsInboxSourceStatus(item: WindowsInboxItem, serverNow: string, elapsed: number): WindowsIncidentItem['status'] {
    if (item.status === 'disabled') return 'disabled';
    return Number.isFinite(elapsed) && elapsed >= 0 && item.statusValidUntil && inventoryAge(item.statusValidUntil, serverNow) > elapsed ? item.status : 'unknown';
}
