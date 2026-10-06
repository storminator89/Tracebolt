import { t, apiErrorText } from './i18n';
const retainedErrorCodes = ['storage_busy', 'cve_progress_unavailable', 'cve_progress_uncertain', 'cve_feed_changed', 'cve_assessment_interrupted', 'inventory_generation_expired', 'cve_clock_changed'] as const;
export class APIError extends Error {
    constructor(message: string, public status?: number, public code?: typeof retainedErrorCodes[number]) { super(message); this.name = 'APIError'; }
}
export const AUTH_REQUIRED_EVENT = 'tracebolt:authentication-required';
const pendingRequests = new Map<AbortController, boolean>();
/** Background metadata reads yield to both private reads and access revalidation. */
export function hasPendingAPIRequests(): boolean { return [...pendingRequests.keys()].some(controller => !controller.signal.aborted); }
let protectedEpoch = 0;
/** A delayed read remains bound to the access scope in which it started. */
export function getProtectedRequestEpoch(): number { return protectedEpoch; }
export function abortProtectedRequests(): void {
    protectedEpoch++;
    for (const [controller, protectedRoute] of pendingRequests)
        if (protectedRoute) {
            controller.abort();
            pendingRequests.delete(controller);
        }
}
async function boundedJSON(response: Response, maximum: number): Promise<unknown> {
    const length = response.headers?.get('Content-Length');
    if (length && /^\d+$/.test(length) && Number(length) > maximum) {
        await response.body?.cancel();
        throw new APIError(t("Der Manager hat keine gültigen JSON-Daten zurückgegeben."));
    }
    if (!response.body) throw new APIError(t("Der Manager hat keine gültigen JSON-Daten zurückgegeben."));
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let count = 0;
    try {
        for (;;) {
            const chunk = await reader.read();
            if (chunk.done) break;
            count += chunk.value.byteLength;
            if (count > maximum) {
                await reader.cancel();
                throw new APIError(t("Der Manager hat keine gültigen JSON-Daten zurückgegeben."));
            }
            chunks.push(chunk.value);
        }
    } finally { reader.releaseLock(); }
    const bytes = new Uint8Array(count);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as unknown;
}
export async function request<T>(path: string, options?: RequestInit, maxResponseBytes?: number): Promise<T> {
    if (maxResponseBytes !== undefined && (!Number.isSafeInteger(maxResponseBytes) || maxResponseBytes < 1 || maxResponseBytes > 262144))
        throw new APIError(t("Der Manager hat keine gültigen JSON-Daten zurückgegeben."));
    const controller = new AbortController();
    const protectedRoute = !path.startsWith('/auth/') || path === '/auth/logout';
    const epoch = protectedEpoch;
    pendingRequests.set(controller, protectedRoute);
    const externalSignal = options?.signal;
    const abort = () => controller.abort();
    if (externalSignal?.aborted)
        controller.abort();
    else
        externalSignal?.addEventListener('abort', abort, { once: true });
    const active = () => {
        if (controller.signal.aborted || (protectedRoute && epoch !== protectedEpoch))
            throw new DOMException(t("Anfrage abgebrochen."), 'AbortError');
    };
    try {
        active();
        let response: Response;
        try {
            response = await fetch(`/api${path}`, { ...options, signal: controller.signal, credentials: 'same-origin', headers: { Accept: 'application/json', ...options?.headers } });
        }
        catch (error) {
            if (controller.signal.aborted || (error instanceof Error && error.name === 'AbortError'))
                throw new DOMException(t("Anfrage abgebrochen."), 'AbortError');
            throw new APIError(t("Der Manager ist unter dieser Adresse nicht erreichbar. Pr\u00FCfe, ob er l\u00E4uft."));
        }
        active();
        if (response.status === 401 && protectedRoute) {
            abortProtectedRequests();
            if (typeof window !== 'undefined')
                window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT));
            throw new APIError(t("Die Sitzung ist abgelaufen. Bitte erneut anmelden."), 401);
        }
        if (!response.ok) {
            let message = t("Die Anfrage konnte nicht geladen werden (HTTP {0}).", { "0": response.status });
            let code: APIError['code'];
            try {
                const data = maxResponseBytes === undefined ? await response.json() : await boundedJSON(response, maxResponseBytes) as { error?: { code?: string; message?: string } };
                if (typeof data.error?.code === 'string' && (retainedErrorCodes as readonly string[]).includes(data.error.code)) code = data.error.code as APIError['code'];
                message = apiErrorText(data.error?.code, typeof data.error?.message === "string" ? data.error.message : message);
            }
            catch { /* Preserve status if response is not JSON. */ }
            active();
            throw new APIError(message, response.status, code);
        }
        let data: T;
        try {
            data = (maxResponseBytes === undefined ? await response.json() : await boundedJSON(response, maxResponseBytes)) as T;
        }
        catch {
            active();
            throw new APIError(t("Der Manager hat keine g\u00FCltigen JSON-Daten zur\u00FCckgegeben."));
        }
        active();
        return data;
    }
    finally {
        pendingRequests.delete(controller);
        externalSignal?.removeEventListener('abort', abort);
    }
}
export async function mutate<T>(path: string, data: unknown, signal?: AbortSignal): Promise<T> {
    const epoch = protectedEpoch;
    const { csrfToken } = await request<{
        csrfToken: string;
    }>('/session', { signal });
    if (epoch !== protectedEpoch || signal?.aborted)
        throw new DOMException(t("Anfrage abgebrochen."), 'AbortError');
    return request<T>(path, { signal, method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken }, body: JSON.stringify(data) });
}

/** Raw catalog JSON is preserved so duplicate keys remain visible to the server.
 * This helper retains the protected epoch across the CSRF read and never accepts
 * caller-supplied credentials or a destination other than the existing API path. */
export async function mutateRaw<T>(path: string, rawJson: string, headers: Record<string, string> = {}, signal?: AbortSignal, maxResponseBytes = 32768): Promise<T> {
    if (typeof rawJson !== 'string' || new TextEncoder().encode(rawJson).byteLength > 2097152 || Object.keys(headers).some(key => key !== 'X-Tracebolt-Catalog-Revision'))
        throw new APIError(t("Die Anfrage konnte nicht geladen werden (HTTP {0}).", { "0": 400 }), 400);
    const epoch = protectedEpoch;
    const { csrfToken } = await request<{ csrfToken: string }>('/session', { signal }, maxResponseBytes);
    if (epoch !== protectedEpoch || signal?.aborted)
        throw new DOMException(t("Anfrage abgebrochen."), 'AbortError');
    if (typeof csrfToken !== 'string' || csrfToken.length < 1 || csrfToken.length > 256)
        throw new APIError(t("Die Anfrage konnte nicht geladen werden (HTTP {0}).", { "0": 400 }), 400);
    return request<T>(path, { signal, method: 'POST', headers: { ...headers, 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken }, body: rawJson }, maxResponseBytes);
}
