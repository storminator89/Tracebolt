import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests } from './api';
import { useOperator } from './auth';
import { setLocale } from './i18n';
import { AdvisoryReviewPanel } from './advisory-review';
import { ADVISORY_REVIEW_RESPONSE_MAX_BYTES } from './advisory-review-types';
import { reviewDeviceId, reviewView } from './advisory-review-fixtures';
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
function open() { render(<AdvisoryReviewPanel deviceId={reviewDeviceId}/>); fireEvent.click(screen.getByRole('button', { name: 'Conditional advisory review candidates' })); }
beforeEach(() => { setLocale('en', false); vi.mocked(useOperator).mockReturnValue({ mode: 'lan', authenticated: true, expiresAt: '2026-10-04T00:30:00Z', insecureTestMode: false, logout: vi.fn(), theme: 'light', setTheme: vi.fn() }); });
afterEach(() => { cleanup(); abortProtectedRequests(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });
describe('actual bounded protected advisory review request', () => {
    it('fetches only the same-origin GET with no query, body, provider call or mutation', async () => {
        const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify(reviewView()))); vi.stubGlobal('fetch', fetch); open(); await screen.findByRole('article'); expect(fetch).toHaveBeenCalledExactlyOnceWith('/api/devices/agent_fixture/security/review', expect.objectContaining({ credentials: 'same-origin', signal: expect.any(AbortSignal), headers: { Accept: 'application/json' } })); expect(fetch.mock.calls[0][1].body).toBeUndefined(); expect(fetch.mock.calls[0][1].method).toBeUndefined();
    });
    it.each(['declared', 'stream', 'utf8'] as const)('rejects malformed or oversized %s responses', async kind => {
        const response = kind === 'declared' ? new Response('{}', { headers: { 'Content-Length': String(ADVISORY_REVIEW_RESPONSE_MAX_BYTES + 1) } }) : kind === 'stream' ? new Response(' '.repeat(ADVISORY_REVIEW_RESPONSE_MAX_BYTES + 1) + JSON.stringify(reviewView())) : new Response(new Uint8Array([123, 34, 255, 34, 58, 49, 125])); vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response)); open(); await screen.findByRole('alert'); expect(screen.queryByRole('article')).not.toBeInTheDocument();
    });
    it('cancels held streamed bytes on close and prevents late installation', async () => {
        let stream!: ReadableStreamDefaultController<Uint8Array>; const fetch = vi.fn().mockResolvedValue(new Response(new ReadableStream<Uint8Array>({ start(controller) { stream = controller; } }))); vi.stubGlobal('fetch', fetch); open(); await act(async () => {}); const signal = fetch.mock.calls[0][1].signal as AbortSignal; fireEvent.click(screen.getByRole('button', { name: 'Conditional advisory review candidates' })); expect(signal.aborted).toBe(true); await act(async () => { stream.enqueue(new TextEncoder().encode(JSON.stringify(reviewView()))); stream.close(); }); expect(screen.queryByRole('article')).not.toBeInTheDocument();
    });
    it.each([401, 409, 429])('handles the actual HTTP %s response safely', async status => {
        vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('{"error":{"message":"private path"}}', { status }))); open(); expect(await screen.findByRole('alert')).toHaveTextContent(status === 401 ? 'session has ended' : status === 409 ? 'snapshot or catalog changed' : 'Another review is in progress'); expect(document.body.textContent).not.toContain('private path'); expect(screen.queryByRole('article')).not.toBeInTheDocument();
    });
});
