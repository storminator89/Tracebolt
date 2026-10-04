import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests } from './api';
import { useOperator } from './auth';
import { setLocale } from './i18n';
import { PackageObservationsPanel } from './package-observations';
import { PACKAGE_RESPONSE_MAX_BYTES } from './package-observations-types';
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
const empty = { schemaVersion: 'tracebolt.package-view.v1', deviceId: 'agent_fixture', status: 'not_configured', serverNow: '2026-10-04T00:00:00Z', receivedAt: null, sequence: null, maxAgeSeconds: 120, snapshot: null };
function open() { render(<PackageObservationsPanel deviceId="agent_fixture"/>); fireEvent.click(screen.getByRole('button', { name: 'Release and source-package observations' })); }
beforeEach(() => { setLocale('en', false); vi.mocked(useOperator).mockReturnValue({ mode: 'lan', authenticated: true, expiresAt: '2026-10-04T00:30:00Z', insecureTestMode: false, logout: vi.fn(), theme: 'light', setTheme: vi.fn() }); });
afterEach(() => { cleanup(); abortProtectedRequests(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });
describe('package view using the actual bounded protected request helper', () => {
    it('fetches only the same-origin authenticated GET endpoint', async () => {
        const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify(empty))); vi.stubGlobal('fetch', fetch); open(); await screen.findByText('Package-source collection not configured'); expect(fetch).toHaveBeenCalledExactlyOnceWith('/api/devices/agent_fixture/packages', expect.objectContaining({ credentials: 'same-origin', signal: expect.any(AbortSignal), headers: { Accept: 'application/json' } }));
    });
    it.each(['declared', 'stream', 'utf8'] as const)('fails closed for an invalid %s response', async kind => {
        const response = kind === 'declared' ? new Response('{}', { headers: { 'Content-Length': String(PACKAGE_RESPONSE_MAX_BYTES + 1) } }) : kind === 'stream' ? new Response(' '.repeat(PACKAGE_RESPONSE_MAX_BYTES + 1) + JSON.stringify(empty)) : new Response(new Uint8Array([123, 34, 255, 34, 58, 49, 125]));
        vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response)); open(); await screen.findByRole('alert'); expect(screen.queryByText('Package-source collection not configured')).not.toBeInTheDocument(); expect(screen.queryByRole('table')).not.toBeInTheDocument();
    });
    it('cancels a held streamed response on close and cannot reinstate it', async () => {
        let stream!: ReadableStreamDefaultController<Uint8Array>;
        const fetch = vi.fn().mockResolvedValue(new Response(new ReadableStream<Uint8Array>({ start(controller) { stream = controller; } }))); vi.stubGlobal('fetch', fetch); open(); await act(async () => {}); const signal = fetch.mock.calls[0][1].signal as AbortSignal;
        fireEvent.click(screen.getByRole('button', { name: 'Release and source-package observations' })); expect(signal.aborted).toBe(true); await act(async () => { stream.enqueue(new TextEncoder().encode(JSON.stringify(empty))); stream.close(); }); expect(screen.queryByText('Package-source collection not configured')).not.toBeInTheDocument();
    });
    it('locks and clears package details on an actual 401 authentication response', async () => {
        vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('{}', { status: 401 }))); open(); expect(await screen.findByRole('alert')).toHaveTextContent('Your session has ended.'); expect(screen.getByRole('button', { name: 'Refresh package observations' })).toBeDisabled();
    });
});
