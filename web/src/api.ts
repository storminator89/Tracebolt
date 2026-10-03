import { t, apiErrorText } from './i18n';
export class APIError extends Error {
    constructor(message: string, public status?: number) { super(message); this.name = 'APIError'; }
}
export const AUTH_REQUIRED_EVENT = 'tracebolt:authentication-required';
const pendingRequests = new Map<AbortController, boolean>();
let protectedEpoch = 0;
export function abortProtectedRequests(): void {
    protectedEpoch++;
    for (const [controller, protectedRoute] of pendingRequests)
        if (protectedRoute) {
            controller.abort();
            pendingRequests.delete(controller);
        }
}
export async function request<T>(path: string, options?: RequestInit): Promise<T> {
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
            try {
                const data = await response.json();
                message = apiErrorText(data.error?.code, typeof data.error?.message === "string" ? data.error.message : message);
            }
            catch { /* Preserve status if response is not JSON. */ }
            active();
            throw new APIError(message, response.status);
        }
        let data: T;
        try {
            data = await response.json() as T;
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
