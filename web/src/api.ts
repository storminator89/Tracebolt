export class APIError extends Error { constructor(message: string, public status?: number) { super(message); this.name = 'APIError'; } }
export async function request<T>(path: string, options?: RequestInit): Promise<T> {
  let response: Response;
  try { response = await fetch(`/api${path}`, { ...options, headers: { Accept: 'application/json', ...options?.headers } }); }
  catch (error) { if (error instanceof Error && error.name === 'AbortError') throw error; throw new APIError('Der Manager ist unter dieser Adresse nicht erreichbar. Prüfe, ob er läuft.'); }
  if (!response.ok) {
    let message = `Die Anfrage konnte nicht geladen werden (HTTP ${response.status}).`;
    try { const data = await response.json(); message = data.error?.message || message; } catch { /* Preserve status if response is not JSON. */ }
    throw new APIError(message, response.status);
  }
  try { return await response.json() as T; } catch { throw new APIError('Der Manager hat keine gültigen JSON-Daten zurückgegeben.'); }
}
export async function mutate<T>(path: string, data: unknown, signal?: AbortSignal): Promise<T> {
  const { csrfToken } = await request<{csrfToken: string}>('/session', {signal});
  return request<T>(path, { signal, method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken }, body: JSON.stringify(data) });
}
