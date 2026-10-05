import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, AUTH_REQUIRED_EVENT } from './api';
import { CachedUpdatesPanel } from './cached-updates';
import { useCachedUpdates } from './cached-updates-resource';
import { cachedUpdatesDevice, cachedUpdatesView } from './cached-updates-fixtures';
import { CACHED_UPDATES_VIEW_BYTES } from './cached-updates-types';
import { setLocale } from './i18n';
const response = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });
function Harness() { return <CachedUpdatesPanel resource={useCachedUpdates(cachedUpdatesDevice, true)}/>; }
beforeEach(() => setLocale('en', false));
afterEach(() => { cleanup(); abortProtectedRequests(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });
describe('cachedUpdates identity released protected request', () => {
    it('uses only bounded same-origin read-only GET without data in URLs', async () => {
        const fetch = vi.fn().mockResolvedValue(response(cachedUpdatesView())); vi.stubGlobal('fetch', fetch); render(<Harness/>); await screen.findByText('curl');
        expect(fetch).toHaveBeenCalledTimes(1); expect(fetch.mock.calls[0][0]).toBe(`/api/devices/${cachedUpdatesDevice}/inventory/cached-updates`); expect(fetch.mock.calls[0][1]).toMatchObject({ credentials: 'same-origin', headers: { Accept: 'application/json' } }); expect(fetch.mock.calls[0][1].method).toBeUndefined(); expect(fetch.mock.calls[0][1].body).toBeUndefined();
    });
    it.each(['declared', 'streamed'] as const)('rejects overlong %s response before showing values', async kind => {
        let canceled = false; const stream = new ReadableStream({ start(controller) { controller.enqueue(new TextEncoder().encode(' '.repeat(CACHED_UPDATES_VIEW_BYTES + 1))); }, cancel() { canceled = true; } });
        vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(stream, kind === 'declared' ? { headers: { 'Content-Length': String(CACHED_UPDATES_VIEW_BYTES + 1) } } : undefined))); render(<Harness/>); await screen.findByRole('alert'); expect(canceled).toBe(true); expect(screen.queryByText('curl')).not.toBeInTheDocument();
    });
    it('locks on actual 401 and cannot restore on focus', async () => {
        const fetch = vi.fn().mockResolvedValue(response({}, 401)); vi.stubGlobal('fetch', fetch); render(<Harness/>); await screen.findByRole('alert'); expect(screen.getByRole('alert')).toHaveTextContent('session has ended'); expect(screen.getByRole('button', { name: 'Refresh stored update report' })).toBeDisabled(); act(() => window.dispatchEvent(new Event('focus'))); expect(fetch).toHaveBeenCalledTimes(1);
    });
    it('discards a delayed actual response after protected epoch invalidation', async () => {
        let finish!: (value: Response) => void; vi.stubGlobal('fetch', vi.fn().mockImplementation(() => new Promise(resolve => { finish = resolve; }))); render(<Harness/>); await waitFor(() => expect(finish).toBeDefined()); act(() => { abortProtectedRequests(); window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT)); }); await act(async () => finish(response(cachedUpdatesView()))); expect(screen.queryByText('curl')).not.toBeInTheDocument();
    });
    it('replaces rather than retains previously shown values on a failed refresh', async () => {
        const fetch = vi.fn().mockResolvedValueOnce(response(cachedUpdatesView())).mockResolvedValueOnce(response({}, 500)); vi.stubGlobal('fetch', fetch); render(<Harness/>); await screen.findByText('curl'); fireEvent.click(screen.getByRole('button', { name: 'Refresh stored update report' })); expect(screen.queryByText('curl')).not.toBeInTheDocument(); await screen.findByRole('alert'); expect(screen.queryByText('fixture-held')).not.toBeInTheDocument();
    });
});
