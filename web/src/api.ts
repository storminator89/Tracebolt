export class APIError extends Error { constructor(message: string, public status?: number) { super(message); this.name = 'APIError'; } }
export async function request<T>(path: string, options?: RequestInit): Promise<T> {
  let response: Response;
  try { response = await fetch(`/api${path}`, { ...options, headers: { Accept: 'application/json', ...options?.headers } }); }
  catch { throw new APIError('Der lokale Manager ist nicht erreichbar. Prüfe, ob er auf Port 8787 läuft.'); }
  if (!response.ok) {
    let message = `Die Anfrage konnte nicht geladen werden (HTTP ${response.status}).`;
    try { const data = await response.json(); message = data.error?.message || message; } catch { /* Preserve status if response is not JSON. */ }
    throw new APIError(message, response.status);
  }
  try { return await response.json() as T; } catch { throw new APIError('Der Manager hat keine gültigen JSON-Daten zurückgegeben.'); }
}
export async function mutate<T>(path: string, data: unknown): Promise<T> {
  const { csrfToken } = await request<{csrfToken: string}>('/session');
  return request<T>(path, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken }, body: JSON.stringify(data) });
}
