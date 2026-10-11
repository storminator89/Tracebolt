import { APIError, getProtectedRequestEpoch, mutateRaw, request } from './api';
import { hasLogoutIntent, validOperatorSession } from './auth';
import { EVENT_CONTENT_RESULT_BYTES, EVENT_CONTENT_VIEW_BYTES, eventContentAge, eventContentTime } from './windows-event-content-types';
import type { EventContentIdentity, EventContentView, SelectedEvent } from './windows-event-content-types';
import { validWindowsDeviceId } from './windows-inventory-types';
const path = (deviceId: string) => { if (!validWindowsDeviceId(deviceId)) throw new APIError('Invalid device.'); return `/devices/${deviceId}/windows-event-content`; };
async function session(signal: AbortSignal, insecureTestMode: boolean, sessionKey: string | null) {
    const epoch = getProtectedRequestEpoch();
    if (hasLogoutIntent()) throw new APIError('Session ended.', 401);
    const value = await request<unknown>('/auth/session', { signal }, EVENT_CONTENT_VIEW_BYTES);
    if (signal.aborted || epoch !== getProtectedRequestEpoch()) throw new DOMException('Aborted', 'AbortError');
    if (!validOperatorSession(value) || value.mode !== 'lan' || !value.authenticated || value.loginMode !== 'shared' || value.insecureTestMode !== insecureTestMode || !eventContentTime(value.expiresAt) || !eventContentTime(value.serverNow) || eventContentAge(value.expiresAt, value.serverNow) <= 0 || sessionKey !== null && value.expiresAt !== sessionKey || hasLogoutIntent()) throw new APIError('Administrative session required.', 401);
}
async function guarded(deviceId: string, action: '' | 'create' | 'cancel' | 'query', body: unknown, signal: AbortSignal, insecureTestMode: boolean, sessionKey: string | null) {
    const route = path(deviceId), epoch = getProtectedRequestEpoch();
    await session(signal, insecureTestMode, sessionKey);
    if (signal.aborted || epoch !== getProtectedRequestEpoch() || hasLogoutIntent()) throw new DOMException('Aborted', 'AbortError');
    if (!action) return request<unknown>(route, { signal }, EVENT_CONTENT_VIEW_BYTES);
    return mutateRaw<unknown>(`${route}/${action}`, JSON.stringify(body), {}, signal, action === 'query' ? EVENT_CONTENT_RESULT_BYTES : EVENT_CONTENT_VIEW_BYTES);
}
export const readEventContent = (deviceId: string, signal: AbortSignal, insecure: boolean, sessionKey: string | null) => guarded(deviceId, '', null, signal, insecure, sessionKey);
export function createEventContent(deviceId: string, view: EventContentView, selected: SelectedEvent[], acknowledgeContent: boolean, acknowledgePlaintext: boolean, signal: AbortSignal, insecure: boolean, sessionKey: string | null) {
    if (!view.headers || !acknowledgeContent || acknowledgePlaintext !== insecure) throw new APIError('Content acknowledgement required.');
    return guarded(deviceId, 'create', { expectedFloor: view.expectedFloor, expectedHeaderGenerationId: view.headers.generationId, expectedHeaderSnapshotDigest: view.headers.snapshotDigest, selections: selected.map(({ channel, recordId }) => ({ channel, recordId })), acknowledgeContent, acknowledgePlaintext }, signal, insecure, sessionKey);
}
export const cancelEventContent = (deviceId: string, identity: EventContentIdentity, signal: AbortSignal, insecure: boolean, sessionKey: string | null) => guarded(deviceId, 'cancel', { identity }, signal, insecure, sessionKey);
export const queryEventContent = (deviceId: string, identity: EventContentIdentity, signal: AbortSignal, insecure: boolean, sessionKey: string | null) => guarded(deviceId, 'query', { identity }, signal, insecure, sessionKey);
