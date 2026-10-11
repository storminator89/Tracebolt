import { APIError, getProtectedRequestEpoch, mutateRaw, request } from './api';
import { hasLogoutIntent, validOperatorSession } from './auth';
import { EVENT_HISTORY_RESULT_BYTES, EVENT_HISTORY_VIEW_BYTES, eventHistoryAge, eventHistoryTime } from './windows-event-history-types';
import type { EventHistoryIdentity, EventHistoryView, EventHistoryReceipt, HistorySearch, SelectedEvent } from './windows-event-history-types';
import { validWindowsDeviceId } from './windows-inventory-types';
const path = (deviceId: string) => { if (!validWindowsDeviceId(deviceId)) throw new APIError('Invalid device.'); return `/devices/${deviceId}/windows-event-history`; };
async function session(signal: AbortSignal, insecureTestMode: boolean, sessionKey: string | null) {
    const epoch = getProtectedRequestEpoch();
    if (hasLogoutIntent()) throw new APIError('Session ended.', 401);
    const value = await request<unknown>('/auth/session', { signal }, EVENT_HISTORY_VIEW_BYTES);
    if (signal.aborted || epoch !== getProtectedRequestEpoch()) throw new DOMException('Aborted', 'AbortError');
    if (!validOperatorSession(value) || value.mode !== 'lan' || !value.authenticated || value.loginMode !== 'shared' || value.insecureTestMode !== insecureTestMode || !eventHistoryTime(value.expiresAt) || !eventHistoryTime(value.serverNow) || eventHistoryAge(value.expiresAt, value.serverNow) <= 0 || sessionKey !== null && value.expiresAt !== sessionKey || hasLogoutIntent()) throw new APIError('Administrative session required.', 401);
}
async function guarded(deviceId: string, action: '' | 'create' | 'messages' | 'cancel' | 'query', body: unknown, signal: AbortSignal, insecureTestMode: boolean, sessionKey: string | null) {
    const route = path(deviceId), epoch = getProtectedRequestEpoch();
    await session(signal, insecureTestMode, sessionKey);
    if (signal.aborted || epoch !== getProtectedRequestEpoch() || hasLogoutIntent()) throw new DOMException('Aborted', 'AbortError');
    if (!action) return request<unknown>(route, { signal }, EVENT_HISTORY_VIEW_BYTES);
    return mutateRaw<unknown>(`${route}/${action}`, JSON.stringify(body), {}, signal, action === 'query' ? EVENT_HISTORY_RESULT_BYTES : EVENT_HISTORY_VIEW_BYTES);
}
export const readEventHistory = (deviceId: string, signal: AbortSignal, insecure: boolean, sessionKey: string | null) => guarded(deviceId, '', null, signal, insecure, sessionKey);
export function createEventHistory(deviceId: string, view: EventHistoryView, search: HistorySearch, acknowledgeHistory: boolean, acknowledgePlaintext: boolean, signal: AbortSignal, insecure: boolean, sessionKey: string | null) {
 if (!acknowledgeHistory || acknowledgePlaintext!==insecure) throw new APIError('History acknowledgement required.');
 return guarded(deviceId,'create',{expectedFloor:view.expectedFloor,search,acknowledgeHistory,acknowledgePlaintext},signal,insecure,sessionKey);
}
export function createHistoryMessages(deviceId: string, view: EventHistoryView, receipt: EventHistoryReceipt, selected: SelectedEvent[], acknowledgeContent: boolean, acknowledgePlaintext: boolean, signal: AbortSignal, insecure: boolean, sessionKey: string | null) {
 if (!acknowledgeContent || acknowledgePlaintext!==insecure) throw new APIError('Content acknowledgement required.');
 return guarded(deviceId,'messages',{expectedFloor:view.expectedFloor,receipt,selections:selected.map(({channel,recordId})=>({channel,recordId})),acknowledgeContent,acknowledgePlaintext},signal,insecure,sessionKey);
}
export const cancelEventHistory = (deviceId: string, identity: EventHistoryIdentity, signal: AbortSignal, insecure: boolean, sessionKey: string | null) => guarded(deviceId, 'cancel', { identity }, signal, insecure, sessionKey);
export const queryEventHistory = (deviceId: string, identity: EventHistoryIdentity, signal: AbortSignal, insecure: boolean, sessionKey: string | null) => guarded(deviceId, 'query', { identity }, signal, insecure, sessionKey);
