import { actionV2View, actionV2Preview } from './service-action-v2-fixtures';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests } from './api';
import { approveServiceAction, previewServiceAction, readServiceActions } from './service-action-api';
import { actionAccess, actionDevice, actionDigest, actionID, actionJobView, actionPreview, actionSession, actionView } from './service-action-fixtures';
const response = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
beforeEach(() => { localStorage.clear(); sessionStorage.clear(); });
afterEach(() => { abortProtectedRequests(); vi.unstubAllGlobals(); });
describe('service-action protected API', () => {
    it('rechecks the exact named operator, sends CSRF, and approves only preview ID plus digest', async () => {
        const fetch = vi.fn().mockResolvedValueOnce(response(actionSession)).mockResolvedValueOnce(response({ csrfToken: 'fixture-token' })).mockResolvedValueOnce(response(actionJobView())); vi.stubGlobal('fetch', fetch);
        await approveServiceAction(actionDevice, actionPreview(), actionAccess, new AbortController().signal);
        expect(fetch.mock.calls.map(call => call[0])).toEqual(['/api/auth/session', '/api/session', `/api/devices/${actionDevice}/service-actions/approve`]);
        const options = fetch.mock.calls[2][1]; expect(options.method).toBe('POST'); expect(options.credentials).toBe('same-origin'); expect(options.headers['X-CSRF-Token']).toBe('fixture-token'); expect(JSON.parse(options.body)).toEqual({ previewId: actionID, previewDigest: actionDigest });
    });
    it('sends only the exact selected unit when creating a preview', async () => {
        const fetch = vi.fn().mockResolvedValueOnce(response(actionSession)).mockResolvedValueOnce(response({ csrfToken: 'fixture-token' })).mockResolvedValueOnce(response({ ...actionView(), preview: actionPreview() })); vi.stubGlobal('fetch', fetch);
        await previewServiceAction(actionDevice, 'fixture.service', actionAccess, new AbortController().signal);
        expect(JSON.parse(fetch.mock.calls[2][1].body)).toEqual({ unit: 'fixture.service' });
    });
    it.each(['shared', 'capability', 'actor', 'expiry', 'transport'] as const)('refuses a changed %s session before a protected read or write', async kind => {
        const session = { ...actionSession, ...(kind === 'shared' ? { loginMode: 'shared', actorId: null, capabilities: ['read'] } : kind === 'capability' ? { capabilities: ['read'] } : kind === 'actor' ? { actorId: `operator_${'f'.repeat(32)}` } : kind === 'expiry' ? { expiresAt: '2026-10-05T14:00:00Z' } : { insecureTestMode: true, transport: 'http', transportWarning: 'unencrypted_lan_test' }) };
        const fetch = vi.fn().mockResolvedValue(response(session)); vi.stubGlobal('fetch', fetch);
        await expect(readServiceActions(actionDevice, actionAccess, new AbortController().signal)).rejects.toMatchObject({ status: 401 }); expect(fetch).toHaveBeenCalledTimes(1);
    });
    it('does not mutate after session invalidation during CSRF lookup', async () => {
        const fetch = vi.fn().mockResolvedValueOnce(response(actionSession)).mockImplementationOnce(async () => { abortProtectedRequests(); return response({ csrfToken: 'fixture' }); }); vi.stubGlobal('fetch', fetch);
        await expect(approveServiceAction(actionDevice, actionPreview(), actionAccess, new AbortController().signal)).rejects.toMatchObject({ name: 'AbortError' }); expect(fetch).toHaveBeenCalledTimes(2);
    });
    it('rejects malformed and oversized status instead of enabling an action', async () => {
        const fetch = vi.fn().mockResolvedValueOnce(response(actionSession)).mockResolvedValueOnce(response({ ...actionView(), command: 'extra' })).mockResolvedValueOnce(response(actionSession)).mockResolvedValueOnce(response({ padding: 'x'.repeat(33000) })); vi.stubGlobal('fetch', fetch);
        await expect(readServiceActions(actionDevice, actionAccess, new AbortController().signal)).rejects.toThrow();
        await expect(readServiceActions(actionDevice, actionAccess, new AbortController().signal)).rejects.toThrow();
    });
});

describe('v2 protected service API', () => {
    it('verifies full impact and submits only the reviewed ID and digest', async () => {
        const fetch = vi.fn().mockResolvedValueOnce(response(actionSession)).mockResolvedValueOnce(response({ csrfToken: 'fixture-token' })).mockResolvedValueOnce(response({ ...actionV2View(), preview: null, job: actionJobView().job, available: false, reason: 'action_in_progress' })); vi.stubGlobal('fetch', fetch);
        await approveServiceAction(actionDevice, actionV2Preview(), actionAccess, new AbortController().signal);
        expect(JSON.parse(fetch.mock.calls[2][1].body)).toEqual({ previewId: actionID, previewDigest: actionDigest });
    });
    it('refuses altered impact before any approval request', () => {
        const fetch = vi.fn(); vi.stubGlobal('fetch', fetch); const preview = actionV2Preview(); preview.affectedServices = ['fixture.service'];
        expect(() => approveServiceAction(actionDevice, preview, actionAccess, new AbortController().signal)).toThrow(); expect(fetch).not.toHaveBeenCalled();
    });
    it('accepts a bounded v2 response beyond the original v1 transport cap', async () => {
        const view = actionV2View(); view.preview = null; delete view.excludedServices;
        view.services = Array.from({ length: 256 }, (_, i) => ({ unit: `service-${String(i).padStart(3,'0')}.service`, unitPolicyDigest: actionDigest, affectedServices: [`service-${String(i).padStart(3,'0')}.service`] }));
        expect(JSON.stringify(view).length).toBeGreaterThan(32768);
        const fetch = vi.fn().mockResolvedValueOnce(response(actionSession)).mockResolvedValueOnce(response(view)); vi.stubGlobal('fetch', fetch);
        await expect(readServiceActions(actionDevice, actionAccess, new AbortController().signal)).resolves.toEqual(view);
    });
});
