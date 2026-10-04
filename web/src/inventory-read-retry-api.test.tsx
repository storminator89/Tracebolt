import { act, cleanup, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests } from './api';
import { useOperator } from './auth';
import { EndpointIdentityPanel } from './endpoint-identity';
import { useEndpointIdentity } from './endpoint-identity-resource';
import { endpointDevice, endpointView } from './endpoint-identity-fixtures';
import { ENDPOINT_VIEW_BYTES } from './endpoint-identity-types';
import { CompleteOverviewPanel } from './complete-overview';
import { overviewDevice, overviewPage, overviewView, processRows, volumeRows } from './complete-overview-fixtures';
import { OVERVIEW_STATUS_BYTES } from './complete-overview-types';
import { completeDevice, completeView } from './complete-packages-fixtures';
import { COMPLETE_STATUS_BYTES } from './complete-packages-types';
import { SoftwareOverview } from './software-overview';
import { setLocale } from './i18n';
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
type Kind = 'endpoint' | 'overview' | 'software';
const kinds: Kind[] = ['endpoint', 'overview', 'software'];
const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json', ...(status === 429 ? { 'Retry-After': '2' } : {}) } });
const busy = () => json({ error: { code: 'storage_busy', message: 'private diagnostics must not render' } }, 429);
const advance = (ms: number) => act(async () => { await vi.advanceTimersByTimeAsync(ms); });
function Endpoint() { return <EndpointIdentityPanel resource={useEndpointIdentity(endpointDevice, true, 'original')}/>; }
async function mount(kind: Kind) { render(kind === 'endpoint' ? <Endpoint/> : kind === 'overview' ? <CompleteOverviewPanel deviceId={overviewDevice} section="processes"/> : <SoftwareOverview deviceId={completeDevice} onOpenPackages={vi.fn()}/>); await act(async () => {}); }
const route = (kind: Kind) => kind === 'endpoint' ? `/api/devices/${endpointDevice}/inventory/endpoint-identity` : kind === 'overview' ? `/api/devices/${overviewDevice}/inventory/overview` : `/api/devices/${completeDevice}/inventory/packages`;
const payload = (kind: Kind) => kind === 'endpoint' ? endpointView() : kind === 'overview' ? overviewView() : completeView();
const marker = (kind: Kind) => kind === 'endpoint' ? 'fixture-linux' : kind === 'overview' ? 'fixture-process-000000' : 'Complete generation available';
const limit = (kind: Kind) => kind === 'endpoint' ? ENDPOINT_VIEW_BYTES : kind === 'overview' ? OVERVIEW_STATUS_BYTES : COMPLETE_STATUS_BYTES;
beforeEach(() => { vi.useFakeTimers(); setLocale('en', false); vi.mocked(useOperator).mockReturnValue({ mode: 'lan', authenticated: true, expiresAt: '2026-10-04T20:00:00Z', insecureTestMode: false, logout: vi.fn(), theme: 'light', setTheme: vi.fn() }); });
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe.each(kinds)('%s real bounded API error qualification', kind => {
    it('recovers from exact code using two same-origin GETs without body or secret URL fields', async () => {
        let reads = 0;
        const fetch = vi.fn().mockImplementation(async (path: string, options?: RequestInit) => path === '/api/session' ? json({ csrfToken: 'synthetic-csrf' }) : path.endsWith('/query') ? json(overviewPage(overviewView(), processRows(), volumeRows(), options!.body as string)) : ++reads === 1 ? busy() : json(payload(kind))); vi.stubGlobal('fetch', fetch);
        await mount(kind); expect(screen.getByRole('status')).toHaveTextContent('Storage is busy'); expect(screen.queryByText(marker(kind))).not.toBeInTheDocument(); await advance(2000); expect(screen.getByText(marker(kind))).toBeVisible();
        const calls = fetch.mock.calls.filter(([path]) => path === route(kind)); expect(calls).toHaveLength(2);
        for (const [url, options] of calls) { expect(url).not.toContain('?'); expect(options).toMatchObject({ credentials: 'same-origin', headers: { Accept: 'application/json' }, signal: expect.any(AbortSignal) }); expect(options.method).toBeUndefined(); expect(options.body).toBeUndefined(); }
        expect(document.body.textContent).not.toContain('private diagnostics'); if (kind !== 'overview') expect(fetch).toHaveBeenCalledTimes(2);
    });
    it.each([undefined, 'inventory_busy', 'STORAGE_BUSY', 'storage_busy ', ['storage_busy'], { code: 'storage_busy' }])('does not retry malformed or different code %j', async code => {
        const fetch = vi.fn().mockImplementation(async () => json({ error: { code, message: 'storage_busy' } }, 429)); vi.stubGlobal('fetch', fetch); await mount(kind); expect(screen.getByRole('alert')).toBeVisible(); await advance(3000); expect(fetch).toHaveBeenCalledTimes(1); expect(screen.queryByText(marker(kind))).not.toBeInTheDocument();
    });
    it.each(['json', 'utf8', 'oversized'] as const)('never extracts a retry code from malformed %s error data', async format => {
        const response = format === 'json' ? new Response('{"error":{"code":"storage_busy"}', { status: 429 }) : format === 'utf8' ? new Response(new Uint8Array([255]), { status: 429 }) : new Response(JSON.stringify({ error: { code: 'storage_busy' } }) + ' '.repeat(limit(kind)), { status: 429 });
        const fetch = vi.fn().mockResolvedValue(response); vi.stubGlobal('fetch', fetch); await mount(kind); await advance(3000); expect(fetch).toHaveBeenCalledTimes(1); expect(screen.getByRole('alert')).toBeVisible();
    });
    it('keeps HTTP status separate from an otherwise valid code', async () => {
        const fetch = vi.fn().mockImplementation(async () => json({ error: { code: 'storage_busy' } }, 403)); vi.stubGlobal('fetch', fetch); await mount(kind); await advance(3000); expect(fetch).toHaveBeenCalledTimes(1); expect(screen.getByRole('alert')).toBeVisible();
    });
    it('cancels the delay when the protected epoch changes between completed HTTP reads', async () => {
        const fetch = vi.fn().mockResolvedValueOnce(busy()).mockResolvedValueOnce(json(payload(kind))); vi.stubGlobal('fetch', fetch); await mount(kind); act(() => abortProtectedRequests()); await advance(3000); expect(fetch).toHaveBeenCalledTimes(1); expect(screen.getByRole('alert')).toHaveTextContent('session has ended'); expect(screen.queryByText(marker(kind))).not.toBeInTheDocument();
    });
    it('locks on an actual401 during the retry without another request', async () => {
        const fetch = vi.fn().mockResolvedValueOnce(busy()).mockResolvedValueOnce(json({}, 401)); vi.stubGlobal('fetch', fetch); await mount(kind); await advance(2000); expect(screen.getByRole('alert')).toHaveTextContent('session has ended'); act(() => window.dispatchEvent(new Event('focus'))); await advance(3000); expect(fetch).toHaveBeenCalledTimes(2); expect(screen.queryByText(marker(kind))).not.toBeInTheDocument();
    });
});

it('does not replay the actual overview POST after an exact storage_busy query response', async () => {
    const fetch = vi.fn().mockImplementation(async (path: string) => path === '/api/session' ? json({ csrfToken: 'synthetic-csrf' }) : path.endsWith('/query') ? busy() : json(overviewView())); vi.stubGlobal('fetch', fetch); await mount('overview'); expect(screen.getByRole('alert')).toBeVisible(); await advance(3000);
    expect(fetch.mock.calls.filter(([path]) => path.endsWith('/query'))).toHaveLength(1); expect(fetch.mock.calls.find(([path]) => path.endsWith('/query'))![1]).toMatchObject({ method: 'POST' }); expect(fetch).toHaveBeenCalledTimes(3);
});

it.each(['endpoint-first', 'software-first'] as const)('recovers the losing overview tile in the %s paired-read race', async order => {
    let slot = false;
    const fetch = vi.fn().mockImplementation(async (path: string) => {
        if (slot) return busy();
        slot = true; await new Promise<void>(resolve => window.setTimeout(resolve, 10)); slot = false;
        return json(path.endsWith('/endpoint-identity') ? endpointView() : completeView());
    });
    vi.stubGlobal('fetch', fetch);
    const software = <SoftwareOverview deviceId={completeDevice} onOpenPackages={vi.fn()}/>;
    render(order === 'endpoint-first' ? <><Endpoint/>{software}</> : <>{software}<Endpoint/></>); await act(async () => {});
    expect(screen.getByText('Storage is busy. One automatic read retry in 2 seconds.')).toBeVisible(); await advance(2010);
    expect(screen.getByText('fixture-linux')).toBeVisible(); expect(screen.getByText('Complete generation available')).toBeVisible(); expect(fetch).toHaveBeenCalledTimes(3);
    const loser = order === 'endpoint-first' ? route('software') : route('endpoint'); expect(fetch.mock.calls.filter(([path]) => path === loser)).toHaveLength(2);
    for (const [, options] of fetch.mock.calls) { expect(options.method).toBeUndefined(); expect(options.body).toBeUndefined(); }
});
