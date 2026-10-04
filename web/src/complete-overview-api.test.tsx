import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, AUTH_REQUIRED_EVENT } from './api';
import { useOperator } from './auth';
import { CompleteOverviewPanel } from './complete-overview';
import { overviewDevice, overviewPage, overviewView, processRows, volumeRows } from './complete-overview-fixtures';
import { OVERVIEW_PAGE_BYTES, OVERVIEW_STATUS_BYTES } from './complete-overview-types';
import { setLocale } from './i18n';
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
const response = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });
const open = () => render(<CompleteOverviewPanel deviceId={overviewDevice} section="processes"/>);
beforeEach(() => { setLocale('en', false); vi.mocked(useOperator).mockReturnValue({ mode: 'lan', authenticated: true, expiresAt: '2026-10-04T20:00:00Z', insecureTestMode: false, logout: vi.fn(), theme: 'light', setTheme: vi.fn() }); });
afterEach(() => { cleanup(); abortProtectedRequests(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });
describe('complete overview released protected API helpers', () => {
    it('sends pinned section/search/cursor only in a CSRF protected JSON POST body', async () => {
        const v = overviewView(), fetch = vi.fn().mockImplementation(async (path: string, options?: RequestInit) => path.endsWith('/query') ? response(overviewPage(v, processRows(), volumeRows(), options!.body as string)) : path === '/api/session' ? response({ csrfToken: 'synthetic-csrf' }) : response(v)); vi.stubGlobal('fetch', fetch);
        open(); await screen.findByRole('table'); fireEvent.change(screen.getByLabelText('Search this complete section'), { target: { value: 'fixture-process-000349' } }); fireEvent.click(screen.getByRole('button', { name: 'Search from first page' })); await screen.findByText('fixture-process-000349');
        const queries = fetch.mock.calls.filter(([path]) => path.endsWith('/query')); expect(queries).toHaveLength(2); expect(queries[1][1]).toMatchObject({ method: 'POST', credentials: 'same-origin', headers: { Accept: 'application/json', 'Content-Type': 'application/json', 'X-CSRF-Token': 'synthetic-csrf' } });
        expect(JSON.parse(queries[1][1].body)).toEqual({ section: 'processes', generationId: v.processes.complete!.binding.generationId, search: 'fixture-process-000349', cursor: '', limit: 100 });
        for (const [path] of fetch.mock.calls) { expect(path).not.toContain('?'); expect(path).not.toContain('fixture-process'); }
    });
    it('does not POST after protected authority changes during CSRF acquisition', async () => {
        let finish!: (v: Response) => void; const fetch = vi.fn().mockImplementation(async (path: string) => path === '/api/session' ? new Promise<Response>(resolve => { finish = resolve; }) : response(overviewView())); vi.stubGlobal('fetch', fetch); open(); await waitFor(() => expect(finish).toBeDefined());
        act(() => { abortProtectedRequests(); window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT)); }); await act(async () => finish(response({ csrfToken: 'synthetic-csrf' }))); expect(fetch.mock.calls.some(([path]) => path.endsWith('/query'))).toBe(false); expect(screen.queryByRole('table')).not.toBeInTheDocument();
    });
    it.each(['status', 'page'] as const)('bounds %s response streams', async stage => {
        vi.stubGlobal('fetch', vi.fn().mockImplementation(async (path: string) => path === '/api/session' ? response({ csrfToken: 'synthetic-csrf' }) : stage === 'status' || path.endsWith('/query') ? new Response(' '.repeat((stage === 'status' ? OVERVIEW_STATUS_BYTES : OVERVIEW_PAGE_BYTES) + 1)) : response(overviewView()))); open(); await screen.findByRole('alert'); expect(screen.queryByRole('table')).not.toBeInTheDocument();
    });
    it.each(['status', 'csrf', 'page'] as const)('locks and clears on actual 401 at %s', async stage => {
        vi.stubGlobal('fetch', vi.fn().mockImplementation(async (path: string) => stage === 'status' || stage === 'csrf' && path === '/api/session' || stage === 'page' && path.endsWith('/query') ? response({}, 401) : path === '/api/session' ? response({ csrfToken: 'synthetic-csrf' }) : response(overviewView()))); open(); await screen.findByRole('alert'); expect(screen.getByRole('alert')).toHaveTextContent('Your session has ended.'); expect(screen.queryByRole('table')).not.toBeInTheDocument(); expect(screen.getByRole('button', { name: 'Refresh section and restart' })).toBeDisabled();
    });
});
