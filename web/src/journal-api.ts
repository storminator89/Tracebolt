import { APIError, getProtectedRequestEpoch, mutateRaw, request } from './api';
import { hasLogoutIntent, validOperatorSession } from './auth';
import { JOURNAL_PAGE_BYTES, JOURNAL_VIEW_BYTES, validJournalDevice, journalAge, journalTime } from './journal-types';
import type { JournalIdentity, JournalQuery, JournalPolicyGeneration } from './journal-types';
const path = (deviceId: string) => { if (!validJournalDevice(deviceId)) throw new APIError('Invalid journal device.'); return `/devices/${encodeURIComponent(deviceId)}/journal`; };
/** Every content read rechecks the operator. Queries carry text in bounded POST bodies, never URLs. */
async function session(signal: AbortSignal, insecureTestMode: boolean, sessionKey: string | null) {
    const epoch = getProtectedRequestEpoch();
    if (hasLogoutIntent()) throw new APIError('Session ended.', 401);
    const value = await request<unknown>('/auth/session', { signal }, JOURNAL_VIEW_BYTES);
    if (signal.aborted || epoch !== getProtectedRequestEpoch()) throw new DOMException('Aborted', 'AbortError');
    if (!validOperatorSession(value) || value.mode !== 'lan' || !value.authenticated || value.insecureTestMode !== insecureTestMode || !journalTime(value.serverNow) || !journalTime(value.expiresAt) || journalAge(value.expiresAt, value.serverNow) <= 0 || sessionKey !== null && value.expiresAt !== sessionKey || hasLogoutIntent()) throw new APIError('Session ended.', 401);
    return value;
}
export async function readJournal(deviceId: string, signal: AbortSignal, insecureTestMode: boolean, sessionKey: string | null) {
    const epoch = getProtectedRequestEpoch();
    await session(signal, insecureTestMode, sessionKey);
    if (signal.aborted || epoch !== getProtectedRequestEpoch() || hasLogoutIntent()) throw new DOMException('Aborted', 'AbortError');
    return request<unknown>(path(deviceId), { signal }, JOURNAL_VIEW_BYTES);
}
export async function createJournal(deviceId: string, expectedFloor: string, query: JournalQuery, acknowledgePlaintext: boolean, signal: AbortSignal, insecureTestMode: boolean, sessionKey: string | null, expectedPolicyGeneration?: JournalPolicyGeneration) {
    const epoch = getProtectedRequestEpoch();
    await session(signal, insecureTestMode, sessionKey);
    if (signal.aborted || epoch !== getProtectedRequestEpoch() || hasLogoutIntent()) throw new DOMException('Aborted', 'AbortError');
    if (insecureTestMode !== acknowledgePlaintext) throw new APIError('Plaintext acknowledgement does not match this session.');
    return mutateRaw<unknown>(`${path(deviceId)}/create`, JSON.stringify({ expectedFloor, query, acknowledgeLogContent: true, acknowledgePlaintext, ...(expectedPolicyGeneration ? { expectedPolicyGeneration } : {}) }), {}, signal, JOURNAL_VIEW_BYTES);
}
export async function cancelJournal(deviceId: string, identity: JournalIdentity, signal: AbortSignal, insecureTestMode: boolean, sessionKey: string | null) {
    const epoch = getProtectedRequestEpoch();
    await session(signal, insecureTestMode, sessionKey);
    if (signal.aborted || epoch !== getProtectedRequestEpoch() || hasLogoutIntent()) throw new DOMException('Aborted', 'AbortError');
    return mutateRaw<unknown>(`${path(deviceId)}/cancel`, JSON.stringify({ identity }), {}, signal, JOURNAL_VIEW_BYTES);
}
export async function queryJournal(deviceId: string, identity: JournalIdentity, snapshotDigest: string, search: string, offset: number, signal: AbortSignal, insecureTestMode: boolean, sessionKey: string | null) {
    const epoch = getProtectedRequestEpoch();
    await session(signal, insecureTestMode, sessionKey);
    if (signal.aborted || epoch !== getProtectedRequestEpoch() || hasLogoutIntent()) throw new DOMException('Aborted', 'AbortError');
    return mutateRaw<unknown>(`${path(deviceId)}/query`, JSON.stringify({ identity, snapshotDigest, search, offset, limit: 100 }), {}, signal, JOURNAL_PAGE_BYTES);
}
