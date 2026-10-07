import { afterEach, describe, expect, it, vi } from 'vitest';
import { request } from './api';
import { historyDevice, historyFixture } from './resource-history-fixture';
afterEach(() => vi.unstubAllGlobals());
describe('bounded history transport', () => {
    it('permits the dedicated bounded 24-hour response without broadening other endpoints', async () => {
        const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify(historyFixture()))); vi.stubGlobal('fetch', fetch);
        expect((await request<{ deviceId: string }>(`/devices/${historyDevice}/resource-history`, undefined, 1536 * 1024)).deviceId).toBe(historyDevice);
        await expect(request('/devices', undefined, 1536 * 1024)).rejects.toThrow(); expect(fetch).toHaveBeenCalledTimes(1);
    });
    it('cancels a body above the history response limit', async () => {
        let canceled = false; const body = new ReadableStream({ start(controller) { controller.enqueue(new TextEncoder().encode(' '.repeat(1536 * 1024 + 1))); }, cancel() { canceled = true; } });
        vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(body)));
        await expect(request(`/devices/${historyDevice}/resource-history`, undefined, 1536 * 1024)).rejects.toThrow(); expect(canceled).toBe(true);
    });
});


describe('bounded history delta transport', () => {
    it('allows only the history canonical cursor response cap', async () => {
        const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify(historyFixture()))); vi.stubGlobal('fetch', fetch);
        expect((await request<{ deviceId: string }>(`/devices/${historyDevice}/resource-history?afterSequence=4`, undefined, 1536 * 1024)).deviceId).toBe(historyDevice);
        for (const suffix of ['?afterSequence=0', '?afterSequence=01', '?afterSequence=4&extra=1', '?range=1']) await expect(request(`/devices/${historyDevice}/resource-history${suffix}`, undefined, 1536 * 1024)).rejects.toThrow();
        expect(fetch).toHaveBeenCalledTimes(1);
    });
});
