import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, mutate, request } from './api';
import { useOperator } from './auth';
import { setLocale } from './i18n';
import { AdvisoryReviewPanel } from './advisory-review';
import { ADVISORY_REVIEW_RESPONSE_MAX_BYTES } from './advisory-review-types';
import { reviewDeviceId, reviewView } from './advisory-review-fixtures';
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } });
const busy = () => json({ error: { code: 'storage_busy', message: 'private path must not render' } }, 429);
const advance = (ms: number) => act(async () => { await vi.advanceTimersByTimeAsync(ms); });
async function mount() { render(<AdvisoryReviewPanel deviceId={reviewDeviceId}/>); fireEvent.click(screen.getByRole('button', { name: 'Conditional advisory review candidates' })); await act(async () => {}); }
beforeEach(() => { vi.useFakeTimers(); setLocale('en', false); vi.mocked(useOperator).mockReturnValue({ mode: 'lan', authenticated: true, expiresAt: '2026-10-04T00:30:00Z', insecureTestMode: false, logout: vi.fn(), theme: 'light', setTheme: vi.fn() }); });
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe('actual API error qualification and delayed access scope', () => {
    it('recovers from the real bounded 429 code with exactly two same-origin read fetches', async () => {
        const fetch = vi.fn().mockResolvedValueOnce(busy()).mockResolvedValueOnce(json(reviewView())); vi.stubGlobal('fetch', fetch); await mount();
        expect(screen.getByRole('status')).toHaveTextContent('Storage is busy'); expect(screen.queryByRole('article')).not.toBeInTheDocument(); await advance(2000); expect(screen.getByRole('article')).toBeVisible();
        expect(fetch).toHaveBeenCalledTimes(2); for (const [url, options] of fetch.mock.calls) { expect(url).toBe('/api/devices/agent_fixture/security/review'); expect(options).toMatchObject({ credentials: 'same-origin', headers: { Accept: 'application/json' }, signal: expect.any(AbortSignal) }); expect(options.method).toBeUndefined(); expect(options.body).toBeUndefined(); }
        expect(document.body.textContent).not.toContain('private path');
    });
    it.each([undefined, 'review_busy', 'STORAGE_BUSY', 'storage_busy ', ['storage_busy'], { code: 'storage_busy' }])('does not turn malformed or different machine code %j into a retry', async code => {
        const fetch = vi.fn().mockResolvedValue(json({ error: { code, message: 'storage_busy' } }, 429)); vi.stubGlobal('fetch', fetch); await mount(); expect(screen.getByRole('alert')).toHaveTextContent('Another review is in progress'); await advance(3000); expect(fetch).toHaveBeenCalledTimes(1);
    });
    it.each(['json', 'utf8', 'oversized'] as const)('does not recover a retry code from a malformed %s body', async kind => {
        const response = kind === 'json' ? new Response('{"error":{"code":"storage_busy"}', { status: 429 }) : kind === 'utf8' ? new Response(new Uint8Array([255]), { status: 429 }) : new Response(JSON.stringify({ error: { code: 'storage_busy' } }) + ' '.repeat(ADVISORY_REVIEW_RESPONSE_MAX_BYTES), { status: 429 });
        const fetch = vi.fn().mockResolvedValue(response); vi.stubGlobal('fetch', fetch); await mount(); await advance(3000); expect(fetch).toHaveBeenCalledTimes(1); expect(screen.getByRole('alert')).toHaveTextContent('Another review is in progress');
    });
    it('keeps code and status separate so a 403 storage_busy cannot retry', async () => {
        const fetch = vi.fn().mockResolvedValue(json({ error: { code: 'storage_busy' } }, 403)); vi.stubGlobal('fetch', fetch); await mount(); await advance(3000); expect(fetch).toHaveBeenCalledTimes(1); expect(screen.getByRole('alert')).toHaveTextContent('could not be read');
    });
    it('refuses a retry after the protected epoch changes between completed HTTP requests', async () => {
        const fetch = vi.fn().mockResolvedValueOnce(busy()).mockResolvedValueOnce(json(reviewView())); vi.stubGlobal('fetch', fetch); await mount(); expect(fetch).toHaveBeenCalledTimes(1);
        act(() => abortProtectedRequests()); await advance(3000); expect(fetch).toHaveBeenCalledTimes(1); expect(screen.getByRole('alert')).toHaveTextContent('session has ended'); expect(screen.queryByRole('article')).not.toBeInTheDocument();
    });
    it('never replays a mutation which receives the same storage_busy code', async () => {
        const fetch = vi.fn().mockResolvedValueOnce(json({ csrfToken: 'synthetic-csrf-fixture' })).mockResolvedValueOnce(busy()); vi.stubGlobal('fetch', fetch);
        await expect(mutate('/cases/fixture/notes', { text: 'synthetic note' })).rejects.toMatchObject({ status: 429, code: 'storage_busy' }); await advance(3000); expect(fetch).toHaveBeenCalledTimes(2); expect(fetch.mock.calls[0][0]).toBe('/api/session'); expect(fetch.mock.calls[1][1]).toMatchObject({ method: 'POST' });
    });
    it('exposes only the allowlisted code on generic API errors', async () => {
        vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(json({ error: { code: 'storage_busy' } }, 429)).mockResolvedValueOnce(json({ error: { code: '/private/unknown-code' } }, 429)));
        await expect(request('/devices/agent_fixture/security/review')).rejects.toMatchObject({ code: 'storage_busy', status: 429 });
        await expect(request('/devices/agent_fixture/security/review')).rejects.toMatchObject({ code: undefined, status: 429 });
    });
});
