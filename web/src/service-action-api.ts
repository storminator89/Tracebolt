import { APIError, getProtectedRequestEpoch, mutateRaw, request } from './api';
import { hasLogoutIntent, validOperatorSession } from './auth';
import { journalAge, journalTime } from './journal-types';
import { SERVICE_ACTION_VIEW_BYTES, validActionID, validServiceActionUnit, validServiceActionView } from './service-action-types';
import type { ServiceActionPreview } from './service-action-types';

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
async function operation(deviceId: string, access: ServiceActionAccess, signal: AbortSignal, operation?: 'preview' | 'approve', body?: unknown) {
    const destination = path(deviceId), epoch = await session(access, signal);
    if (signal.aborted || epoch !== getProtectedRequestEpoch() || hasLogoutIntent()) throw new DOMException('Aborted', 'AbortError');
    const value = operation ? await mutateRaw<unknown>(`${destination}/${operation}`, JSON.stringify(body), {}, signal, SERVICE_ACTION_VIEW_BYTES) : await request<unknown>(destination, { signal }, SERVICE_ACTION_VIEW_BYTES);
    if (signal.aborted || epoch !== getProtectedRequestEpoch() || hasLogoutIntent()) throw new DOMException('Aborted', 'AbortError');
    if (!validServiceActionView(value, deviceId, access.actorId, access.insecureTestMode)) throw new InvalidServiceActionResponse();
    return value;
}
export const readServiceActions = (deviceId: string, access: ServiceActionAccess, signal: AbortSignal) => operation(deviceId, access, signal);
export function previewServiceAction(deviceId: string, unit: string, access: ServiceActionAccess, signal: AbortSignal) {
    if (!validServiceActionUnit(unit)) throw new APIError('Invalid service unit.');
    return operation(deviceId, access, signal, 'preview', { unit });
}
export function approveServiceAction(deviceId: string, preview: ServiceActionPreview, access: ServiceActionAccess, signal: AbortSignal) {
    if (preview.deviceId !== deviceId || preview.actorId !== access.actorId || !validActionID(preview.id, 'action_') || !/^sha256:[a-f0-9]{64}$/.test(preview.digest)) throw new APIError('Invalid preview.');
    return operation(deviceId, access, signal, 'approve', { previewId: preview.id, previewDigest: preview.digest });
}
