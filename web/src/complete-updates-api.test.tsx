import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, AUTH_REQUIRED_EVENT } from './api';
import { useOperator } from './auth';
import { CompleteUpdatesPanel } from './complete-updates';
import { updateDevice, updatePage, updateRows, updateView } from './complete-updates-fixtures';
import { COMPLETE_UPDATES_PAGE_BYTES, COMPLETE_UPDATES_STATUS_BYTES } from './complete-updates-types';
import { setLocale } from './i18n';

vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
function open() { render(<CompleteUpdatesPanel deviceId={updateDevice}/>); }
const response = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });
beforeEach(() => { setLocale('en', false); vi.mocked(useOperator).mockReturnValue({ mode: 'lan', authenticated: true, expiresAt: '2026-10-04T01:00:00Z', insecureTestMode: false, logout: vi.fn(), theme: 'light', setTheme: vi.fn() }); });
afterEach(() => { cleanup(); abortProtectedRequests(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe('complete inventory through real bounded protected request helpers', () => {
    it('uses authenticated same-origin GET and CSRF-protected JSON POST without queries or cursors in URLs', async () => {
        const view = updateView();
        const fetch = vi.fn().mockImplementation(async (path: string, options?: RequestInit) => path.endsWith('/query') ? response(updatePage(view, updateRows(), options!.body as string)) : path === '/api/session' ? response({ csrfToken: 'synthetic-csrf' }) : response(view)); vi.stubGlobal('fetch', fetch);
        open(); await screen.findByRole('table'); fireEvent.change(screen.getByLabelText('Search all candidate rows'), { target: { value: 'fixture-update-000349' } }); fireEvent.click(screen.getByRole('button', { name: 'Search' })); await screen.findByText('fixture-update-000349', { selector: 'th' });
        const requests = fetch.mock.calls.filter(([path]) => path.endsWith('/query'));
        expect(requests).toHaveLength(2); expect(requests[1][1]).toMatchObject({ method: 'POST', credentials: 'same-origin', headers: { Accept: 'application/json', 'Content-Type': 'application/json', 'X-CSRF-Token': 'synthetic-csrf' } });
        expect(JSON.parse(requests[1][1].body)).toEqual({ generationId: view.complete!.binding.generationId, cursor: '', search: 'fixture-update-000349', limit: 100 });
        for (const [path, options] of fetch.mock.calls) { expect(path).not.toContain('?'); expect(path).not.toContain('fixture-update-000349'); expect(options.credentials).toBe('same-origin'); expect(options.signal).toBeInstanceOf(AbortSignal); }
    });
    it('a revoked protected epoch between CSRF acquisition and POST cannot send a query or restore rows', async () => {
        let finish!: (value: Response) => void;
        const fetch = vi.fn().mockImplementation(async (path: string) => path === '/api/session' ? new Promise<Response>(resolve => { finish = resolve; }) : response(updateView())); vi.stubGlobal('fetch', fetch); open(); await waitFor(() => expect(finish).toBeDefined());
        act(() => { abortProtectedRequests(); window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT)); }); await act(async () => finish(response({ csrfToken: 'synthetic-csrf' })));
        expect(fetch.mock.calls.some(([path]) => path.endsWith('/query'))).toBe(false); expect(screen.queryByRole('table')).not.toBeInTheDocument(); expect(screen.getByRole('alert')).toHaveTextContent('Your session has ended.');
    });
    it.each(['status', 'page'] as const)('rejects oversized %s response bodies', async stage => {
        const maximum = stage === 'status' ? COMPLETE_UPDATES_STATUS_BYTES : COMPLETE_UPDATES_PAGE_BYTES;
        const fetch = vi.fn().mockImplementation(async (path: string) => path === '/api/session' ? response({ csrfToken: 'synthetic-csrf' }) : (stage === 'status' || path.endsWith('/query')) ? new Response(' '.repeat(maximum + 1)) : response(updateView())); vi.stubGlobal('fetch', fetch); open(); await screen.findByRole('alert'); expect(screen.queryByRole('table')).not.toBeInTheDocument();
    });
    it.each(['status', 'csrf', 'page'] as const)('fails closed and conceals data for actual 401 at %s', async stage => {
        const fetch = vi.fn().mockImplementation(async (path: string) => stage === 'status' || stage === 'csrf' && path === '/api/session' || stage === 'page' && path.endsWith('/query') ? response({}, 401) : path === '/api/session' ? response({ csrfToken: 'synthetic-csrf' }) : response(updateView())); vi.stubGlobal('fetch', fetch); open(); await screen.findByRole('alert'); expect(screen.getByRole('alert')).toHaveTextContent('Your session has ended.'); expect(screen.queryByRole('table')).not.toBeInTheDocument(); expect(screen.getByRole('button', { name: 'Refresh complete update inventory' })).toBeDisabled();
    });
});
