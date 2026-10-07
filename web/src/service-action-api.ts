import { APIError, getProtectedRequestEpoch, mutateRaw, request } from './api';
import { hasLogoutIntent, validOperatorSession } from './auth';
import { journalAge, journalTime } from './journal-types';
import { SERVICE_ACTION_VIEW_BYTES, SERVICE_ACTION_V2_VIEW_BYTES, validActionID, validServiceActionUnit, validServiceActionView, validServiceActionPreview } from './service-action-types';
import type { ServiceActionPreview, ServiceActionView } from './service-action-types';

export interface ServiceActionAccess { actorId: string; sessionKey: string; insecureTestMode: boolean }
export class InvalidServiceActionResponse extends Error {}
const path = (deviceId: string) => {
    if (!validActionID(deviceId, 'agent_')) throw new APIError('Invalid device.');
    return `/devices/${encodeURIComponent(deviceId)}/service-actions`;
};
async function session(access: ServiceActionAccess, signal: AbortSignal) {
    const epoch = getProtectedRequestEpoch();
    if (hasLogoutIntent()) throw new APIError('Session ended.', 401);
    const value = await request<unknown>('/auth/session', { signal }, SERVICE_ACTION_VIEW_BYTES);
    if (signal.aborted || epoch !== getProtectedRequestEpoch()) throw new DOMException('Aborted', 'AbortError');
    if (!validOperatorSession(value) || value.mode !== 'lan' || !value.authenticated || value.loginMode !== 'named' || value.actorId !== access.actorId || !value.capabilities?.includes('restart_service') || value.expiresAt !== access.sessionKey || value.insecureTestMode !== access.insecureTestMode || !journalTime(value.serverNow) || !journalTime(value.expiresAt) || journalAge(value.expiresAt, value.serverNow) <= 0 || hasLogoutIntent()) throw new APIError('Session ended or service-action access changed.', 401);
    return epoch;
}
async function operation(deviceId: string, access: ServiceActionAccess, signal: AbortSignal, operation?: 'preview' | 'approve', body?: unknown, responseVersion?: ServiceActionView['schemaVersion']) {
    const destination = path(deviceId), epoch = await session(access, signal);
    if (signal.aborted || epoch !== getProtectedRequestEpoch() || hasLogoutIntent()) throw new DOMException('Aborted', 'AbortError');
    // A discovered v2 capability explicitly selects the larger bound. Known v1
    // writes keep their original cap; only the initial GET negotiates a version.
    const maximum = responseVersion === 'tracebolt.service-action-view.v1' ? SERVICE_ACTION_VIEW_BYTES : SERVICE_ACTION_V2_VIEW_BYTES;
    const value = operation ? await mutateRaw<unknown>(`${destination}/${operation}`, JSON.stringify(body), {}, signal, maximum) : await request<unknown>(destination, { signal }, maximum);
    if (signal.aborted || epoch !== getProtectedRequestEpoch() || hasLogoutIntent()) throw new DOMException('Aborted', 'AbortError');
    if (!validServiceActionView(value, deviceId, access.actorId, access.insecureTestMode) || responseVersion !== undefined && value.schemaVersion !== responseVersion) throw new InvalidServiceActionResponse();
    return value;
}
export const readServiceActions = (deviceId: string, access: ServiceActionAccess, signal: AbortSignal, responseVersion?: ServiceActionView['schemaVersion']) => operation(deviceId, access, signal, undefined, undefined, responseVersion);
export function previewServiceAction(deviceId: string, unit: string, access: ServiceActionAccess, signal: AbortSignal, responseVersion: ServiceActionView['schemaVersion'] = 'tracebolt.service-action-view.v1') {
    if (!['tracebolt.service-action-view.v1', 'tracebolt.service-action-view.v2'].includes(responseVersion) || !validServiceActionUnit(unit)) throw new APIError('Invalid service unit.');
    return operation(deviceId, access, signal, 'preview', { unit }, responseVersion);
}
export function approveServiceAction(deviceId: string, preview: ServiceActionPreview, access: ServiceActionAccess, signal: AbortSignal) {
    if (!validServiceActionPreview(preview, deviceId, access.actorId, access.insecureTestMode, preview.createdAt) || preview.deviceId !== deviceId || preview.actorId !== access.actorId || !validActionID(preview.id, 'action_') || !/^sha256:[a-f0-9]{64}$/.test(preview.digest)) throw new APIError('Invalid preview.');
    return operation(deviceId, access, signal, 'approve', { previewId: preview.id, previewDigest: preview.digest }, preview.version === 'tracebolt.service-action-preview.v2' ? 'tracebolt.service-action-view.v2' : 'tracebolt.service-action-view.v1');
}
