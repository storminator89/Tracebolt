import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests } from './api';
import { AuthBoundary } from './auth';
import { DeviceDetail } from './details';
import { journalNow, journalSession } from './journal-fixtures';
import { setLocale } from './i18n';
import type { Device, Metric } from './types';
const id = 'synthetic-device';
function device(fresh = false): Device {
    const metric: Metric = { value: fresh ? 42 : 11, unit: '%', quality: 'healthy', source: 'Synthetic transport fixture', collectedAt: journalNow };
    return { id, name: 'Synthetic transport fixture', platform: 'linux', os: fresh ? 'Updated Linux fixture' : 'Linux fixture', site: 'Fixture', group: 'Fixture', ip: null, status: 'unknown', source: 'synthetic', synthetic: true, lastSeen: journalNow, agentVersion: 'fixture', cpu: metric, memory: metric, disk: metric, uptime: '', tags: [], capabilities: [], evidence: [], trend: [], caseIds: [] };
}
const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status });
const panel = () => <AuthBoundary><DeviceDetail id={id} onClose={vi.fn()} onCase={vi.fn()}/></AuthBoundary>;
const refresh = () => screen.getByRole('button', { name: 'Refresh device metadata' });
function server() { const fetch = vi.fn(async (url: string) => url === '/api/auth/session' ? json(journalSession) : json(device())); vi.stubGlobal('fetch', fetch); return fetch; }
beforeEach(() => { localStorage.clear(); sessionStorage.clear(); setLocale('en', false); });
afterEach(() => { cleanup(); abortProtectedRequests(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });
describe('device metadata actual protected request boundary', () => {
    it('sends exactly one same-origin GET on an explicit click, without mutations or query data', async () => {
        const fetch = server(); render(panel()); await screen.findByRole('heading', { name: 'Synthetic transport fixture' });
        fetch.mockResolvedValueOnce(json(device(true))); fireEvent.click(refresh()); await screen.findByText('Updated Linux fixture');
        const calls = fetch.mock.calls.filter(([url]) => url === `/api/devices/${id}`); expect(calls).toHaveLength(2);
        const options = (calls[1] as unknown as [string, RequestInit])[1]; expect(options).toMatchObject({ credentials: 'same-origin', headers: { Accept: 'application/json' } }); expect(options.method).toBeUndefined(); expect(options.body).toBeUndefined();
    });
    it('clears the whole private page on actual 401 and stays signed out after focus', async () => {
        const fetch = server(); render(panel()); await screen.findByRole('heading', { name: 'Synthetic transport fixture' });
        fetch.mockResolvedValueOnce(json({}, 401)); fireEvent.click(refresh()); await screen.findByLabelText('Operator password');
        expect(screen.queryByRole('heading', { name: 'Synthetic transport fixture' })).not.toBeInTheDocument(); expect(screen.queryByRole('tab')).not.toBeInTheDocument();
        act(() => window.dispatchEvent(new Event('focus'))); expect(fetch).toHaveBeenCalledTimes(3);
    });
    it.each(['declared', 'streamed'] as const)('bounds a %s oversized refresh and keeps the previous snapshot labelled unchanged', async kind => {
        const fetch = server(); render(panel()); await screen.findByRole('heading', { name: 'Synthetic transport fixture' });
        let canceled = false; const stream = new ReadableStream({ start(controller) { controller.enqueue(new TextEncoder().encode(' '.repeat(262145))); }, cancel() { canceled = true; } });
        fetch.mockResolvedValueOnce(new Response(stream, kind === 'declared' ? { headers: { 'Content-Length': '262145' } } : undefined));
        fireEvent.click(refresh()); await screen.findByRole('alert'); expect(canceled).toBe(true); expect(screen.getByRole('alert')).toHaveTextContent('Displayed device metadata is unchanged');
        expect(document.querySelector('.device-metrics')).toHaveTextContent('11%'); expect(refresh()).toBeEnabled(); expect(fetch).toHaveBeenCalledTimes(3);
    });
    it('keeps hidden metadata concealed and discards a late refresh when visibility revalidation loses access', async () => {
        const fetch = server(); render(panel()); await screen.findByRole('heading', { name: 'Synthetic transport fixture' });
        let finish!: (response: Response) => void; fetch.mockImplementationOnce(() => new Promise<Response>(resolve => { finish = resolve; })); fireEvent.click(refresh()); await waitFor(() => expect(finish).toBeDefined());
        const visible = vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden'); act(() => document.dispatchEvent(new Event('visibilitychange')));
        expect(screen.queryByRole('heading', { name: 'Synthetic transport fixture' })).not.toBeInTheDocument();
        fetch.mockResolvedValueOnce(json({ ...journalSession, authenticated: false, csrfToken: null, expiresAt: null, expiresInSeconds: null }));
        visible.mockReturnValue('visible'); act(() => document.dispatchEvent(new Event('visibilitychange'))); await screen.findByLabelText('Operator password');
        await act(async () => finish(json(device(true)))); expect(screen.queryByText('Updated Linux fixture')).not.toBeInTheDocument(); expect(screen.queryByRole('tab')).not.toBeInTheDocument();
        expect(fetch.mock.calls.filter(([url]) => url === `/api/devices/${id}`)).toHaveLength(2);
    });
});
