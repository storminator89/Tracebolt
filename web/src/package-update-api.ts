import { APIError, getProtectedRequestEpoch, mutateRaw, request } from './api';
import { hasLogoutIntent, validOperatorSession } from './auth';
import { PACKAGE_UPDATE_VIEW_BYTES, canonicalPackageSelection, packageIdentityKey, packageUpdateReady, parsePackageUpdateView, validPackageIdentity, validPackageUpdateID } from './package-update-types';
import type { PackageIdentity, PackageUpdatePreview, PackageUpdateView } from './package-update-types';
export class PackageUpdateNotReady extends Error { constructor(public view: PackageUpdateView) { super('Package update readiness changed.'); } }
export interface PackageUpdateAccess { actorId: string; sessionKey: string; insecureTestMode: boolean }
function path(deviceId: string) {
    if (!validPackageUpdateID(deviceId, 'agent_')) throw new TypeError('Invalid package-update device');
    return `/devices/${deviceId}/package-updates`;
}
export async function readPackageUpdates(deviceId: string, signal: AbortSignal, requestId?: string) {
    if (requestId !== undefined && !validPackageUpdateID(requestId, 'update_')) throw new TypeError('Invalid package-update request');
    const destination = path(deviceId) + (requestId ? `/jobs/${requestId}` : '');
    const view = parsePackageUpdateView(await request<unknown>(destination, { signal }, PACKAGE_UPDATE_VIEW_BYTES), deviceId);
    if (requestId !== undefined && view.job?.requestId !== requestId) throw new TypeError('Wrong recovered package-update request');
    return view;
}
async function revalidateAccess(access: PackageUpdateAccess, signal: AbortSignal, capability: 'plan_updates' | 'execute_updates') {
    const epoch = getProtectedRequestEpoch();
    if (hasLogoutIntent()) throw new APIError('Session ended.', 401);
    const session = await request<unknown>('/auth/session', { signal }, 32768);
    if (signal.aborted || epoch !== getProtectedRequestEpoch()) throw new DOMException('Aborted', 'AbortError');
    if (!validOperatorSession(session) || session.mode !== 'lan' || !session.authenticated || session.loginMode !== 'named'
        || session.actorId !== access.actorId || session.expiresAt !== access.sessionKey || session.insecureTestMode !== access.insecureTestMode
        || !session.capabilities?.includes(capability) || hasLogoutIntent() || Date.parse(session.expiresAt!) <= Date.parse(session.serverNow)) throw new APIError('Session or update capability changed.', 401);
    return { epoch, serverNow: session.serverNow };
}
/** An exact missing prepare record is not evidence that a new operation is safe.
 * Recheck current access/admission only; callers must retain the original ID. */
export async function readPackageUpdateRetryGate(deviceId: string, access: PackageUpdateAccess, signal: AbortSignal) {
    const { epoch } = await revalidateAccess(access, signal, 'plan_updates');
    const view = await readPackageUpdates(deviceId, signal);
    if (signal.aborted || epoch !== getProtectedRequestEpoch() || hasLogoutIntent()) throw new DOMException('Aborted', 'AbortError');
    return view;
}
async function write(deviceId: string, access: PackageUpdateAccess, signal: AbortSignal, action: 'prepare' | 'approve', body: { requestId: string; packages?: PackageIdentity[]; previewDigest?: string }, mode: 'native' | 'simulation', reviewed?: PackageUpdatePreview) {
    const destination = path(deviceId), started = performance.now();
    const status = await readPackageUpdates(deviceId, signal);
    if (!packageUpdateReady(status) || status.executionMode !== mode || action === 'prepare' && !status.available
        || action === 'approve' && (status.job?.state !== 'preview_ready' || status.job.requestId !== body.requestId || !status.preview || status.preview.digest !== body.previewDigest || JSON.stringify(status.preview) !== JSON.stringify(reviewed))) throw new PackageUpdateNotReady(status);
    const { epoch, serverNow } = await revalidateAccess(access, signal, action === 'prepare' ? 'plan_updates' : 'execute_updates');
    const elapsed = performance.now() - started;
    if (!Number.isFinite(elapsed) || elapsed < 0 || elapsed >= 10000 || Date.parse(serverNow) < Date.parse(status.serverNow)
        || reviewed && (reviewed.actorId !== access.actorId || reviewed.transportProfile !== (access.insecureTestMode ? 'disposable-http-test' : 'production-tls') || Date.parse(reviewed.expiresAt) <= Date.parse(serverNow) + elapsed)) throw new PackageUpdateNotReady(status);
    const value = await mutateRaw<unknown>(`${destination}/${action}`, JSON.stringify(body), {}, signal, PACKAGE_UPDATE_VIEW_BYTES);
    if (signal.aborted || epoch !== getProtectedRequestEpoch() || hasLogoutIntent()) throw new DOMException('Aborted', 'AbortError');
    const response = parsePackageUpdateView(value, deviceId);
    if (response.executionMode !== mode || response.job?.requestId !== body.requestId) throw new TypeError('Changed package-update operation');
    return response;
}
export function preparePackageUpdates(deviceId: string, requestId: string, packages: PackageIdentity[], access: PackageUpdateAccess, signal: AbortSignal, mode: 'native' | 'simulation' = 'simulation') {
    if (!validPackageUpdateID(requestId, 'update_') || packages.length < 1 || packages.length > 32 || !packages.every(validPackageIdentity)
        || new Set(packages.map(packageIdentityKey)).size !== packages.length) throw new TypeError('Invalid package selection');
    // Deliberately no candidate versions, provenance, commands or options.
    return write(deviceId, access, signal, 'prepare', { requestId, packages: canonicalPackageSelection(packages) }, mode);
}
export function approvePackageUpdates(deviceId: string, preview: PackageUpdatePreview, access: PackageUpdateAccess, signal: AbortSignal, mode: 'native' | 'simulation' = 'simulation') {
    if (!validPackageUpdateID(preview.requestId, 'update_') || !/^sha256:[a-f0-9]{64}$/.test(preview.digest) || preview.actorId !== access.actorId
        || preview.transportProfile !== (access.insecureTestMode ? 'disposable-http-test' : 'production-tls')) throw new TypeError('Invalid package preview');
    return write(deviceId, access, signal, 'approve', { requestId: preview.requestId, previewDigest: preview.digest }, mode, preview);
}
