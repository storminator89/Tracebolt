import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, AUTH_REQUIRED_EVENT } from './api';
import { EndpointIdentityPanel } from './endpoint-identity';
import { useEndpointIdentity } from './endpoint-identity-resource';
import { endpointDevice, endpointView } from './endpoint-identity-fixtures';
import { ENDPOINT_VIEW_BYTES } from './endpoint-identity-types';
import { setLocale } from './i18n';
const response = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });
function Harness() { return <EndpointIdentityPanel resource={useEndpointIdentity(endpointDevice, true)}/>; }
beforeEach(() => setLocale('en', false));
afterEach(() => { cleanup(); abortProtectedRequests(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });
describe('endpoint identity released protected request', () => {
    it('uses only bounded same-origin read-only GET without data in URLs', async () => {
        const fetch = vi.fn().mockResolvedValue(response(endpointView())); vi.stubGlobal('fetch', fetch); render(<Harness/>); await screen.findByText('fixture-linux');
        expect(fetch).toHaveBeenCalledTimes(1); expect(fetch.mock.calls[0][0]).toBe(`/api/devices/${endpointDevice}/inventory/endpoint-identity`); expect(fetch.mock.calls[0][1]).toMatchObject({ credentials: 'same-origin', headers: { Accept: 'application/json' } }); expect(fetch.mock.calls[0][1].method).toBeUndefined(); expect(fetch.mock.calls[0][1].body).toBeUndefined();
    });
    it.each(['declared', 'streamed'] as const)('rejects overlong %s response before showing values', async kind => {
        let canceled = false; const stream = new ReadableStream({ start(controller) { controller.enqueue(new TextEncoder().encode(' '.repeat(ENDPOINT_VIEW_BYTES + 1))); }, cancel() { canceled = true; } });
        vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(stream, kind === 'declared' ? { headers: { 'Content-Length': String(ENDPOINT_VIEW_BYTES + 1) } } : undefined))); render(<Harness/>); await screen.findByRole('alert'); expect(canceled).toBe(true); expect(screen.queryByText('fixture-linux')).not.toBeInTheDocument();
    });
    it('locks on actual 401 and cannot restore on focus', async () => {
        const fetch = vi.fn().mockResolvedValue(response({}, 401)); vi.stubGlobal('fetch', fetch); render(<Harness/>); await screen.findByRole('alert'); expect(screen.getByRole('alert')).toHaveTextContent('session has ended'); expect(screen.getByRole('button', { name: 'Refresh reported identity' })).toBeDisabled(); act(() => window.dispatchEvent(new Event('focus'))); expect(fetch).toHaveBeenCalledTimes(1);
    });
    it('discards a delayed actual response after protected epoch invalidation', async () => {
        let finish!: (value: Response) => void; vi.stubGlobal('fetch', vi.fn().mockImplementation(() => new Promise(resolve => { finish = resolve; }))); render(<Harness/>); await waitFor(() => expect(finish).toBeDefined()); act(() => { abortProtectedRequests(); window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT)); }); await act(async () => finish(response(endpointView()))); expect(screen.queryByText('fixture-linux')).not.toBeInTheDocument();
    });
    it('replaces rather than retains previously shown values on a failed refresh', async () => {
        const fetch = vi.fn().mockResolvedValueOnce(response(endpointView())).mockResolvedValueOnce(response({}, 500)); vi.stubGlobal('fetch', fetch); render(<Harness/>); await screen.findByText('fixture-linux'); fireEvent.click(screen.getByRole('button', { name: 'Refresh reported identity' })); expect(screen.queryByText('fixture-linux')).not.toBeInTheDocument(); await screen.findByRole('alert'); expect(screen.queryByText('192.0.2.19')).not.toBeInTheDocument();
    });
});
