import { afterEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, mutateRaw, request } from './api';
const json = (value: unknown) => new Response(JSON.stringify(value), { headers: { 'Content-Type': 'application/json' } });
afterEach(() => { abortProtectedRequests(); vi.unstubAllGlobals(); });
describe('bounded raw catalog API helper', () => {
 it('preserves duplicate JSON keys for server validation and carries only the allowed revision header', async () => {
  const raw = '{"schema":"a","schema":"b"}';
  const fetch = vi.fn().mockResolvedValueOnce(json({ csrfToken: 'fixture-csrf' })).mockResolvedValueOnce(json({ ok: true }));
  vi.stubGlobal('fetch', fetch);
  await expect(mutateRaw('/security/catalog', raw, { 'X-Tracebolt-Catalog-Revision': 'revision_' + '1'.repeat(32) })).resolves.toEqual({ ok: true });
  expect(fetch.mock.calls[1][1]).toEqual(expect.objectContaining({ body: raw, method: 'POST', headers: expect.objectContaining({ 'X-CSRF-Token': 'fixture-csrf', 'X-Tracebolt-Catalog-Revision': 'revision_' + '1'.repeat(32) }) }));
 });
 it('rejects body/credential header misuse before fetching a session', async () => {
  const fetch = vi.fn(); vi.stubGlobal('fetch', fetch);
  await expect(mutateRaw('/security/catalog', '{}', { Authorization: 'not-sent' })).rejects.toMatchObject({ status: 400 });
  await expect(mutateRaw('/security/catalog', 'x'.repeat(2097153))).rejects.toMatchObject({ status: 400 });
  expect(fetch).not.toHaveBeenCalled();
 });
 it('does not write after a bounded session read is revoked', async () => {
  const response = new Response(new ReadableStream({ start(controller) { abortProtectedRequests(); controller.enqueue(new TextEncoder().encode('{"csrfToken":"old"}')); controller.close(); } }));
  const fetch = vi.fn().mockImplementation(() => { abortProtectedRequests(); return Promise.resolve(response); });
  vi.stubGlobal('fetch', fetch);
  await expect(mutateRaw('/security/catalog', '{}')).rejects.toHaveProperty('name', 'AbortError');
  expect(fetch).toHaveBeenCalledOnce();
 });
 it('bounds success and error response streams without Content-Length', async () => {
  for (const status of [200, 400]) {
   vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('x'.repeat(64), { status })));
   await expect(request('/security/catalog', undefined, 32)).rejects.toThrow();
  }
 });
 it('rejects a declared oversize or invalid UTF-8 response', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('{}', { headers: { 'Content-Length': '999' } })));
  await expect(request('/security/catalog', undefined, 32)).rejects.toThrow();
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(new Uint8Array([123, 34, 120, 34, 58, 34, 255, 34, 125]))));
  await expect(request('/security/catalog', undefined, 32)).rejects.toThrow();
 });
 it('bounds and validates CSRF readback before any mutation', async () => {
  for (const token of [undefined, '', 'x'.repeat(257)]) {
   const fetch = vi.fn().mockResolvedValue(json({ csrfToken: token })); vi.stubGlobal('fetch', fetch);
   await expect(mutateRaw('/security/catalog', '{}')).rejects.toThrow(); expect(fetch).toHaveBeenCalledOnce();
  }
 });
});
