import { act, cleanup, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, hasPendingAPIRequests, request } from './api';
import { useDeviceMetadata } from './device-metadata-resource';
import { setLocale } from './i18n';
import type { Device, Metric } from './types';

const id = `agent_${'5'.repeat(32)}`, now = '2026-10-05T12:00:00Z';
function device(value = 0.4): Device {
    const metric: Metric = { value, unit: '%', quality: 'healthy', source: 'Synthetic API fixture', collectedAt: now };
    return { id, name: 'Synthetic API metrics', platform: 'linux', os: 'Linux fixture', site: 'Fixture', group: 'Fixture', ip: null, status: 'unknown', source: 'lan', synthetic: false, lastSeen: now, agentVersion: 'fixture', cpu: metric, memory: metric, disk: metric, uptime: '', tags: [], capabilities: [], evidence: [], trend: [], caseIds: [] };
}
function Harness() {
    const value = useDeviceMetadata(id, 'synthetic-api-session', true);
    return <div>{value.device && <output>{value.device.cpu.value}</output>}{value.error && <p role="alert">{value.error}</p>}<span>{value.automaticState}</span></div>;
}
const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status });
const flush = () => act(async () => {}), advance = (ms: number) => act(async () => { await vi.advanceTimersByTimeAsync(ms); });
beforeEach(() => { vi.useFakeTimers(); vi.setSystemTime(now); localStorage.clear(); sessionStorage.clear(); setLocale('en', false); });
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe('actual API transport for live device metadata', () => {
    it('sends only bounded same-origin GETs and yields to an existing protected read', async () => {
        let finish!: (response: Response) => void;
        const fetch = vi.fn(async (url: string) => url.endsWith('/health') ? new Promise<Response>(resolve => { finish = resolve; }) : json(device())); vi.stubGlobal('fetch', fetch);
        render(<Harness/>); await flush(); expect(screen.getByRole('status')).toHaveTextContent('0.4'); expect(hasPendingAPIRequests()).toBe(false);
        const health = request(`/devices/${id}/health`); expect(hasPendingAPIRequests()).toBe(true);
        await advance(30000); expect(fetch.mock.calls.filter(([url]) => url === `/api/devices/${id}`)).toHaveLength(1);
        await act(async () => { finish(json({})); await health; }); expect(hasPendingAPIRequests()).toBe(false);
        await advance(1000); const calls = fetch.mock.calls.filter(([url]) => url === `/api/devices/${id}`); expect(calls).toHaveLength(2);
        const options = (calls[1] as unknown as [string, RequestInit])[1]; expect(options).toMatchObject({ credentials: 'same-origin', headers: { Accept: 'application/json' } }); expect(options.method).toBeUndefined(); expect(options.body).toBeUndefined();
    });
    it('also defers automatic reads while session access is being revalidated', async () => {
        let finish!: (response: Response) => void;
        const fetch = vi.fn(async (url: string) => url === '/api/auth/session' ? new Promise<Response>(resolve => { finish = resolve; }) : json(device())); vi.stubGlobal('fetch', fetch);
        render(<Harness/>); await flush(); const session = request('/auth/session'); await advance(20000); expect(fetch.mock.calls.filter(([url]) => url === `/api/devices/${id}`)).toHaveLength(1);
        await act(async () => { finish(json({ authenticated: true })); await session; }); await advance(1000); expect(fetch.mock.calls.filter(([url]) => url === `/api/devices/${id}`)).toHaveLength(2);
    });
    it('clears values and stops after an actual HTTP 401', async () => {
        const fetch = vi.fn().mockResolvedValueOnce(json(device())).mockResolvedValue(json({}, 401)); vi.stubGlobal('fetch', fetch);
        render(<Harness/>); await flush(); await advance(15000); expect(screen.queryByRole('status')).not.toBeInTheDocument(); expect(screen.getByRole('alert')).toHaveTextContent(/session.*expired/i);
        await advance(180000); expect(fetch).toHaveBeenCalledTimes(2); expect(hasPendingAPIRequests()).toBe(false);
    });
    it('bounds an oversized automatic reply, cancels its body and backs off without replacing the sample', async () => {
        let canceled = false;
        const stream = new ReadableStream({ start(controller) { controller.enqueue(new TextEncoder().encode(' '.repeat(262145))); }, cancel() { canceled = true; } });
        const fetch = vi.fn().mockResolvedValueOnce(json(device())).mockResolvedValueOnce(new Response(stream)).mockResolvedValue(json(device(15))); vi.stubGlobal('fetch', fetch);
        render(<Harness/>); await flush(); await advance(15000); expect(canceled).toBe(true); expect(screen.getByRole('status')).toHaveTextContent('0.4'); expect(screen.getByRole('alert')).toBeVisible();
        await advance(29999); expect(fetch).toHaveBeenCalledTimes(2); await advance(1); expect(fetch).toHaveBeenCalledTimes(3); expect(screen.getByRole('status')).toHaveTextContent('15');
    });
    it('does not let a canceled transport that ignores AbortSignal starve future polling or install late data', async () => {
        let finish!: (response: Response) => void;
        const fetch = vi.fn().mockResolvedValueOnce(json(device())).mockImplementationOnce(() => new Promise<Response>(resolve => { finish = resolve; })).mockResolvedValue(json(device(15))); vi.stubGlobal('fetch', fetch);
        render(<Harness/>); await flush(); await advance(15000); expect(hasPendingAPIRequests()).toBe(true);
        await advance(10000); expect(hasPendingAPIRequests()).toBe(false); await advance(30000); expect(screen.getByRole('status')).toHaveTextContent('15');
        await act(async () => finish(json(device(99)))); expect(screen.getByRole('status')).toHaveTextContent('15'); expect(fetch).toHaveBeenCalledTimes(3);
    });
});
