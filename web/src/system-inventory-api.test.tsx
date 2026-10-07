import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, AUTH_REQUIRED_EVENT } from './api';
import { useOperator } from './auth';
import { SystemInventoryPanel } from './system-inventory';
import { serviceRows, socketRows, systemDevice, systemPage, systemView } from './system-inventory-fixtures';
import { SYSTEM_PAGE_BYTES, SYSTEM_STATUS_BYTES } from './system-inventory-types';
import { setLocale } from './i18n';

vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
const response = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });
const open = () => render(<SystemInventoryPanel deviceId={systemDevice} section="sockets"/>);
beforeEach(() => { setLocale('en', false); vi.mocked(useOperator).mockReturnValue({ mode: 'lan', authenticated: true, expiresAt: '2026-10-04T01:00:00Z', insecureTestMode: false, logout: vi.fn(), theme: 'light', setTheme: vi.fn() }); });
afterEach(() => { cleanup(); abortProtectedRequests(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe('system inventory released protected helpers', () => {
    it('sends fixed JSON POST with session/CSRF protection; searches and cursors never enter URLs', async () => {
        const view = systemView(), fetch = vi.fn().mockImplementation(async (path: string, options?: RequestInit) => path.endsWith('/query') ? response(systemPage(view, serviceRows(), socketRows(), options!.body as string)) : path === '/api/session' ? response({ csrfToken: 'synthetic-csrf' }) : response(view)); vi.stubGlobal('fetch', fetch);
        open(); await screen.findByRole('table'); fireEvent.change(screen.getByLabelText('Search this section'), { target: { value: 'fixture-proc-74' } }); fireEvent.change(screen.getByLabelText('Section filter'), { target: { value: 'connections' } }); fireEvent.click(screen.getByRole('button', { name: 'Apply' })); await screen.findByText('174 / fixture-proc-74');
        const queries = fetch.mock.calls.filter(([path]) => path.endsWith('/query')); expect(queries).toHaveLength(2); expect(queries[1][1]).toMatchObject({ method: 'POST', credentials: 'same-origin', headers: { Accept: 'application/json', 'Content-Type': 'application/json', 'X-CSRF-Token': 'synthetic-csrf' } });
        expect(JSON.parse(queries[1][1].body)).toEqual({ section: 'sockets', generationId: view.lastComplete.sockets!.meta.generationId, search: 'fixture-proc-74', cursor: '', filter: 'connections', limit: 25 });
        for (const [path] of fetch.mock.calls) { expect(path).not.toContain('?'); expect(path).not.toContain('fixture-proc-74'); }
    });
    it('does not POST after a protected epoch changes during CSRF acquisition', async () => {
        let finish!: (value: Response) => void; const fetch = vi.fn().mockImplementation(async (path: string) => path === '/api/session' ? new Promise<Response>(resolve => { finish = resolve; }) : response(systemView())); vi.stubGlobal('fetch', fetch); open(); await waitFor(() => expect(finish).toBeDefined());
        act(() => { abortProtectedRequests(); window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT)); }); await act(async () => finish(response({ csrfToken: 'synthetic-csrf' }))); expect(fetch.mock.calls.some(([path]) => path.endsWith('/query'))).toBe(false); expect(screen.queryByRole('table')).not.toBeInTheDocument();
    });
    it.each(['status', 'page'] as const)('enforces bounded %s response streams', async stage => {
        vi.stubGlobal('fetch', vi.fn().mockImplementation(async (path: string) => path === '/api/session' ? response({ csrfToken: 'synthetic-csrf' }) : stage === 'status' || path.endsWith('/query') ? new Response(' '.repeat((stage === 'status' ? SYSTEM_STATUS_BYTES : SYSTEM_PAGE_BYTES) + 1)) : response(systemView()))); open(); await screen.findByRole('alert'); expect(screen.queryByRole('table')).not.toBeInTheDocument();
    });
    it.each(['status', 'csrf', 'page'] as const)('locks on actual 401 at %s', async stage => {
        vi.stubGlobal('fetch', vi.fn().mockImplementation(async (path: string) => stage === 'status' || stage === 'csrf' && path === '/api/session' || stage === 'page' && path.endsWith('/query') ? response({}, 401) : path === '/api/session' ? response({ csrfToken: 'synthetic-csrf' }) : response(systemView()))); open(); await screen.findByRole('alert'); expect(screen.getByRole('alert')).toHaveTextContent('Your session has ended.'); expect(screen.queryByRole('table')).not.toBeInTheDocument(); expect(screen.getByRole('button', { name: 'Refresh section and restart' })).toBeDisabled();
    });
});
