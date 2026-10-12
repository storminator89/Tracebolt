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

describe('exact scheduled MSI preview response budget', () => {
 const path = `/windows-managed-msi/worklists/worklist_${'a'.repeat(32)}/schedule-preview`;
 const maximum = 2 * 1024 * 1024;
 it('sends the exact preview once through the real CSRF and bounded request helpers', async () => {
  const raw = JSON.stringify({ revision: 3, startAt: 1791799320, endAt: 1791799620 });
  const fetch = vi.fn().mockResolvedValueOnce(json({ csrfToken: 'fixture-csrf' })).mockResolvedValueOnce(json({ items: [], excluded: [] }));
  const beforeSend = vi.fn(() => true); vi.stubGlobal('fetch', fetch);
  await expect(mutateRaw(path, raw, {}, undefined, maximum, beforeSend)).resolves.toEqual({ items: [], excluded: [] });
  expect(beforeSend).toHaveBeenCalledOnce();
  expect(fetch.mock.calls.map(call => call[0])).toEqual(['/api/session', `/api${path}`]);
  expect(fetch.mock.calls[1][1]).toEqual(expect.objectContaining({ method: 'POST', body: raw, headers: expect.objectContaining({ 'X-CSRF-Token': 'fixture-csrf' }) }));
 });
 it('keeps the final pre-send guard before the preview POST', async () => {
  const fetch = vi.fn().mockResolvedValue(json({ csrfToken: 'fixture-csrf' })); vi.stubGlobal('fetch', fetch);
  await expect(mutateRaw(path, '{}', {}, undefined, maximum, () => false)).rejects.toHaveProperty('name', 'AbortError');
  expect(fetch.mock.calls.map(call => call[0])).toEqual(['/api/session']);
 });
 it.each([`${path}/`, `${path}?unexpected=1`, path.replace('worklist_', 'agent_'), '/security/catalog'])('does not widen the response budget for %s', async other => {
  const fetch = vi.fn(); vi.stubGlobal('fetch', fetch);
  await expect(request(other, { method: 'POST' }, maximum)).rejects.toThrow();
  expect(fetch).not.toHaveBeenCalled();
 });
 it('rejects a larger caller cap before any fetch', async () => {
  const fetch = vi.fn(); vi.stubGlobal('fetch', fetch);
  await expect(request(path, { method: 'POST' }, maximum + 1)).rejects.toThrow();
  expect(fetch).not.toHaveBeenCalled();
 });
 it('accepts the exact response limit and rejects one extra streamed byte', async () => {
  const raw = JSON.stringify({ value: 'x'.repeat(maximum - 12) });
  expect(new TextEncoder().encode(raw).byteLength).toBe(maximum);
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(raw)));
  await expect(request(path, { method: 'POST' }, maximum)).resolves.toHaveProperty('value');
  const cancel = vi.fn();
  const chunks = [new TextEncoder().encode(raw), new Uint8Array([32])];
  const body = new ReadableStream({ pull(controller) { controller.enqueue(chunks.shift()!); }, cancel }, { highWaterMark: 0 });
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(body, { headers: { 'Content-Length': '2' } })));
  await expect(request(path, { method: 'POST' }, maximum)).rejects.toThrow();
  expect(cancel).toHaveBeenCalledOnce();expect(body.locked).toBe(false);
 });
});
