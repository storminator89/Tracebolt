import { APIError, getProtectedRequestEpoch, request } from './api';
import { hasLogoutIntent, validOperatorSession } from './auth';
import { journalAge } from './journal-types';
import type { ServiceActionAccess } from './service-action-api';
import { SERVICE_ACTION_HISTORY_BYTES, validServiceActionHistory } from './service-action-history-types';
import { validActionID } from './service-action-types';

export async function readServiceActionHistory(device: string, access: ServiceActionAccess, signal: AbortSignal) {
    if (!validActionID(device, 'agent_') || !validActionID(access.actorId, 'operator_')) throw new APIError('Invalid service-action identity.');
    const epoch = getProtectedRequestEpoch();
    const active = () => { if (signal.aborted || epoch !== getProtectedRequestEpoch() || hasLogoutIntent()) throw new DOMException('Aborted', 'AbortError'); };
    active();
    const session = await request<unknown>('/auth/session', { signal, cache: 'no-store', redirect: 'error' }, 32768);
    active();
    if (!validOperatorSession(session) || session.mode !== 'lan' || !session.authenticated || session.loginMode !== 'named' || session.actorId !== access.actorId || !session.capabilities?.includes('restart_service') || session.expiresAt !== access.sessionKey || session.insecureTestMode !== access.insecureTestMode || journalAge(session.expiresAt, session.serverNow) <= 0) throw new APIError('Service-action history access ended.', 401);
    const value = await request<unknown>(`/devices/${device}/service-actions/history`, { signal, cache: 'no-store', redirect: 'error' }, SERVICE_ACTION_HISTORY_BYTES);
    active();
    if (!validServiceActionHistory(value, device, access.actorId) || journalAge(value.serverNow, session.serverNow) < 0 || journalAge(session.expiresAt, value.serverNow) <= 0) throw new APIError('Invalid service-action history.');
    return value;
}
