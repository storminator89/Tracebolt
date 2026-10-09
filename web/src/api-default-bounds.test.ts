import { afterEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, AUTH_REQUIRED_EVENT, hasPendingAPIRequests, mutate, request } from './api';
import type { Case, Device } from './types';
import { windowsDevice } from './windows-inventory-fixture';

const DEFAULT_BYTES = 256 * 1024;
const device = `agent_${'a'.repeat(32)}`;
const encoder = new TextEncoder();
const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status });
const padded = (bytes: number) => `{"value":"${'x'.repeat(bytes - 12)}"}`;
const invalidUTF8 = new Uint8Array([123, 34, 120, 34, 58, 34, 255, 34, 125]);
function reply(response: Response) {
    const fetch = vi.fn().mockResolvedValue(response);
    vi.stubGlobal('fetch', fetch);
    return fetch;
}
afterEach(() => { abortProtectedRequests(); vi.unstubAllGlobals(); });

describe('default bounded responses', () => {
    it('accepts the exact byte limit without calling Response.json', async () => {
        const response = new Response(padded(DEFAULT_BYTES));
        const decode = vi.spyOn(response, 'json');
        reply(response);
        await expect(request('/capabilities')).resolves.toHaveProperty('value');
        expect(decode).not.toHaveBeenCalled();
        expect(hasPendingAPIRequests()).toBe(false);
    });

    it.each([
        '/session', '/auth/session', '/auth/login', '/auth/logout', '/capabilities', '/ai/config',
        '/enrollment', '/windows/enrollment', `/devices/${device}/operational`, `/devices/${device}/health/services`,
    ])('bounds ordinary success at %s without an explicit cap', async path => {
        reply(new Response(padded(DEFAULT_BYTES + 1)));
        await expect(request(path)).rejects.toThrow('gültigen JSON');
        expect(hasPendingAPIRequests()).toBe(false);
    });

    it.each([undefined, '2', String(DEFAULT_BYTES)])('counts stream bytes independently of Content-Length %s', async length => {
        const cancel = vi.fn();
        const chunks = [encoder.encode(padded(DEFAULT_BYTES)), new Uint8Array([32])];
        const body = new ReadableStream<Uint8Array>({
            pull(controller) { controller.enqueue(chunks.shift()!); },
            cancel,
        }, { highWaterMark: 0 });
        reply(new Response(body, { headers: length === undefined ? {} : { 'Content-Length': length } }));
        await expect(request('/capabilities')).rejects.toThrow('gültigen JSON');
        expect(cancel).toHaveBeenCalledOnce();
        expect(body.locked).toBe(false);
    });

    it('rejects a declared oversize without reading the body', async () => {
        const pull = vi.fn();
        const cancel = vi.fn();
        reply(new Response(new ReadableStream({ pull, cancel }, { highWaterMark: 0 }), { headers: { 'Content-Length': String(DEFAULT_BYTES + 1) } }));
        await expect(request('/capabilities')).rejects.toThrow('gültigen JSON');
        expect(pull).not.toHaveBeenCalled();
        expect(cancel).toHaveBeenCalledOnce();
    });

    it('does not require Content-Length equality for an in-budget body', async () => {
        reply(new Response('{"x":"€"}', { headers: { 'Content-Length': '2' } }));
        await expect(request('/capabilities')).resolves.toEqual({ x: '€' });
    });

    it('counts UTF-8 bytes rather than JavaScript characters', async () => {
        const body = JSON.stringify({ value: '€'.repeat(Math.ceil(DEFAULT_BYTES / 3)) });
        expect(body.length).toBeLessThan(DEFAULT_BYTES);
        expect(encoder.encode(body).byteLength).toBeGreaterThan(DEFAULT_BYTES);
        reply(new Response(body));
        await expect(request('/capabilities')).rejects.toThrow('gültigen JSON');
    });

    it.each([invalidUTF8, encoder.encode('{'), null])('rejects malformed UTF-8, JSON, or an empty body', async body => {
        reply(new Response(body));
        await expect(request('/capabilities')).rejects.toThrow('gültigen JSON');
    });

    it('bounds ordinary mutation responses after a successful CSRF read', async () => {
        const fetch = vi.fn().mockResolvedValueOnce(json({ csrfToken: 'fixture-token' }))
            .mockResolvedValueOnce(new Response(padded(DEFAULT_BYTES + 1)));
        vi.stubGlobal('fetch', fetch);
        await expect(mutate('/ai/config', {})).rejects.toThrow('gültigen JSON');
        expect(fetch.mock.calls.map(call => call[0])).toEqual(['/api/session', '/api/ai/config']);
    });

    it('never sends a mutation after an oversized CSRF response', async () => {
        const fetch = reply(new Response(JSON.stringify({ csrfToken: 'fixture-token', padding: 'x'.repeat(DEFAULT_BYTES) })));
        await expect(mutate('/ai/config', {})).rejects.toThrow('gültigen JSON');
        expect(fetch).toHaveBeenCalledOnce();
    });
});

describe('bounded errors retain status without trusting unusable bodies', () => {
    it.each(['/capabilities', '/overview', '/cases/fixture/notes'])('bounds oversized errors even on legacy projection %s', async path => {
        const cancel = vi.fn();
        reply(new Response(new ReadableStream({
            start(controller) { controller.enqueue(encoder.encode(JSON.stringify({ error: { code: 'storage_busy', message: 'x'.repeat(DEFAULT_BYTES) } }))); },
            cancel,
        }), { status: 429, headers: { 'Content-Length': '2' } }));
        await expect(request(path)).rejects.toMatchObject({ status: 429, code: undefined });
        expect(cancel).toHaveBeenCalledOnce();
    });

    it('retains bounded valid error text and known error codes', async () => {
        reply(json({ error: { code: 'storage_busy', message: 'inert fixture message' } }, 429));
        await expect(request('/capabilities')).rejects.toMatchObject({ status: 429, code: 'storage_busy' });
    });

    it.each([invalidUTF8, encoder.encode('{'), null])('preserves HTTP status for malformed error bytes or missing bodies', async body => {
        reply(new Response(body, { status: 503 }));
        await expect(request('/capabilities')).rejects.toMatchObject({ status: 503, code: undefined });
    });

    it('does not retain an error code when UTF-8 is invalid', async () => {
        const prefix = encoder.encode('{"error":{"code":"storage_busy","message":"');
        const suffix = encoder.encode('"}}');
        reply(new Response(new Uint8Array([...prefix, 255, ...suffix]), { status: 429 }));
        await expect(request('/capabilities')).rejects.toMatchObject({ status: 429, code: undefined });
    });

    it('bounds login 401 without announcing a protected session expiry', async () => {
        const expired = vi.fn();
        window.addEventListener(AUTH_REQUIRED_EVENT, expired);
        try {
            reply(new Response(JSON.stringify({ error: { code: 'storage_busy', message: 'x'.repeat(DEFAULT_BYTES) } }), { status: 401 }));
            await expect(request('/auth/login', { method: 'POST' })).rejects.toMatchObject({ status: 401, code: undefined });
            expect(expired).not.toHaveBeenCalled();
        } finally { window.removeEventListener(AUTH_REQUIRED_EVENT, expired); }
    });
});

describe('narrow legacy success compatibility, not a byte-safety guarantee', () => {
    it('preserves a full case with 100 legal notes, including Go JSON escaping', async () => {
        const at = '2026-10-08T00:00:00Z';
        const item: Case = {
            id: 'case-fixture', title: 'Synthetic case', deviceId: 'fixture', deviceName: 'Synthetic device',
            severity: 'warning', status: 'open', category: 'service', summary: 'Inert history fixture',
            ruleId: 'fixture-rule', confidence: 'evidence-backed', createdAt: at, updatedAt: at,
            evidenceIds: [], evidence: [], runbookId: 'service', nextSteps: [], synthetic: true,
            notes: Array.from({ length: 100 }, (_, i) => ({ id: String(i).padStart(24, '0'), text: '<'.repeat(2000), createdAt: at, author: 'Local operator' })),
            timeline: Array.from({ length: 100 }, (_, i) => ({ id: String(i).padStart(24, '0'), type: 'note', title: 'Operator note added', detail: 'Local case note saved. No endpoint action was executed.', time: at, deviceId: 'fixture', caseId: 'case-fixture' })),
        };
        const encoded = JSON.stringify(item).replaceAll('<', '\\u003c');
        expect(encoder.encode(encoded).byteLength).toBeGreaterThan(1024 * 1024);
        reply(new Response(encoded));
        await expect(request('/cases/case-fixture')).resolves.toEqual(item);
        vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(json({ csrfToken: 'fixture-token' })).mockResolvedValueOnce(new Response(encoded)));
        await expect(mutate('/cases/case-fixture/notes', { text: '<'.repeat(2000) })).resolves.toEqual(item);
    });

    it('preserves the stored Device shape and fleet list without inventing field limits', async () => {
        // Store.Seed accepts model.Device JSON without an evidence byte/count cap.
        // This synthetic stored projection is not a claim about native telemetry admission.
        const item: Device = { ...windowsDevice(), id: 'fixture', source: 'synthetic', synthetic: true,
            evidence: Array.from({ length: 128 }, (_, i) => ({ id: `evidence-${i}`, title: 'Synthetic evidence', source: 'synthetic-fixture', quality: 'healthy', collectedAt: '2026-10-08T00:00:00Z', detail: 'x'.repeat(2000), value: '', synthetic: true })) };
        expect(encoder.encode(JSON.stringify(item)).byteLength).toBeGreaterThan(DEFAULT_BYTES);
        reply(json(item));
        await expect(request('/devices/fixture')).resolves.toEqual(item);
        reply(json({ items: [item], total: 1 }));
        await expect(request('/devices')).resolves.toHaveProperty('items', [item]);
    });

    const routes = [
        ['/overview', 'GET'], ['/devices', 'GET'], ['/cases', 'GET'], ['/devices/fixture', 'GET'],
        ['/cases/fixture', 'GET'], ['/cases/fixture/notes', 'POST'], ['/cases/fixture/status', 'POST'],
    ];
    it.each(routes)('preserves uncapped full projection %s %s', async (path, method) => {
        reply(new Response(padded(DEFAULT_BYTES + 1)));
        await expect(request(path, { method })).resolves.toHaveProperty('value');
    });
    it.each(routes)('still applies an explicit caller cap to %s %s', async (path, method) => {
        reply(new Response(padded(DEFAULT_BYTES + 1)));
        await expect(request(path, { method }, DEFAULT_BYTES)).rejects.toThrow('gültigen JSON');
    });
    it.each([
        ['/overview?extra=1', 'GET'], ['/devices/fixture/operational', 'GET'], ['/cases/fixture/analyze', 'POST'],
        ['/cases/fixture/notes', 'GET'], ['/cases/fixture', 'POST'], ['/overview', 'POST'],
        ['/cases/fixture/notes?extra=1', 'POST'], ['/cases/%61', 'GET'], [`/cases/${'a'.repeat(97)}`, 'GET'],
    ])('does not expand the exception to %s %s', async (path, method) => {
        reply(new Response(padded(DEFAULT_BYTES + 1)));
        await expect(request(path, { method })).rejects.toThrow('gültigen JSON');
    });
});

describe('existing larger route budgets apply without an explicit cap', () => {
    const routes: [string, number][] = [
        [`/devices/${device}/package-updates`, 512 * 1024],
        [`/devices/${device}/package-updates/prepare`, 512 * 1024],
        [`/devices/${device}/resource-history`, 1536 * 1024],
        [`/devices/${device}/resource-history?afterSequence=1`, 1536 * 1024],
        ['/investigations?scope=open&offset=0', 2 * 1024 * 1024],
    ];
    it.each(routes)('accepts the existing byte budget for %s', async (path, cap) => {
        reply(new Response(padded(cap)));
        await expect(request(path)).resolves.toHaveProperty('value');
    });
    it.each(routes)('rejects a byte above the existing budget for %s', async (path, cap) => {
        reply(new Response(padded(cap + 1)));
        await expect(request(path)).rejects.toThrow('gültigen JSON');
    });
});

describe('cancellation during bounded body reads', () => {
    it('invalidates a protected 401 without consuming its response body', async () => {
        const pull = vi.fn();
        const expired = vi.fn();
        const body = new ReadableStream({ pull }, { highWaterMark: 0 });
        const response = new Response(body, { status: 401 });
        const reader = vi.spyOn(body, 'getReader');
        reply(response);
        window.addEventListener(AUTH_REQUIRED_EVENT, expired);
        try {
            await expect(request('/capabilities')).rejects.toMatchObject({ status: 401 });
            expect(expired).toHaveBeenCalledOnce();
            expect(reader).not.toHaveBeenCalled();
            expect(pull).not.toHaveBeenCalled();
            expect(response.bodyUsed).toBe(false);
            expect(hasPendingAPIRequests()).toBe(false);
        } finally { window.removeEventListener(AUTH_REQUIRED_EVENT, expired); await body.cancel(); }
    });

    it.each([
        ['external', 200], ['revocation', 200], ['external', 429], ['revocation', 429],
    ] as const)('does not return late bytes after %s during status %s', async (kind, status) => {
        let feed!: ReadableStreamDefaultController<Uint8Array>;
        let reading!: () => void;
        const started = new Promise<void>(resolve => { reading = resolve; });
        const body = new ReadableStream<Uint8Array>({ start(controller) { feed = controller; }, pull() { reading(); } }, { highWaterMark: 0 });
        const fetch = reply(new Response(body, { status }));
        const external = new AbortController();
        const pending = request('/capabilities', { signal: external.signal });
        await started;
        if (kind === 'external') external.abort(); else abortProtectedRequests();
        expect(fetch.mock.calls[0][1].signal.aborted).toBe(true);
        feed.enqueue(encoder.encode('{"private":"must not return"}')); feed.close();
        await expect(pending).rejects.toHaveProperty('name', 'AbortError');
        expect(hasPendingAPIRequests()).toBe(false);
    });

    it('does not send a write after the CSRF body is revoked', async () => {
        const fetch = reply(new Response(new ReadableStream<Uint8Array>({
            pull(controller) {
                abortProtectedRequests();
                controller.enqueue(encoder.encode('{"csrfToken":"stale-fixture-token"}')); controller.close();
            },
        }, { highWaterMark: 0 })));
        await expect(mutate('/ai/config', {})).rejects.toHaveProperty('name', 'AbortError');
        expect(fetch).toHaveBeenCalledOnce();
        expect(hasPendingAPIRequests()).toBe(false);
    });
});
