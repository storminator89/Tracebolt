import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests } from './api';
import { readServiceActionHistory } from './service-action-history-api';
import { actionAccess, actionDevice, actionSession } from './service-action-fixtures';
import { actionHistory } from './service-action-history-fixtures';
const response = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
beforeEach(() => { localStorage.clear(); sessionStorage.clear(); });
afterEach(() => { abortProtectedRequests(); vi.unstubAllGlobals(); });
describe('deliberate Linux history transport', () => {
    it('revalidates named access and only reads the exact bounded history route', async () => {
        const fetch = vi.fn().mockResolvedValueOnce(response(actionSession)).mockResolvedValueOnce(response(actionHistory())); vi.stubGlobal('fetch', fetch);
        await expect(readServiceActionHistory(actionDevice, actionAccess, new AbortController().signal)).resolves.toEqual(actionHistory());
        expect(fetch.mock.calls.map(call => call[0])).toEqual(['/api/auth/session', `/api/devices/${actionDevice}/service-actions/history`]);
        for (const [, options] of fetch.mock.calls) { expect(options.cache).toBe('no-store'); expect(options.redirect).toBe('error'); expect(options.credentials).toBe('same-origin'); expect(options.method).toBeUndefined(); expect(options.body).toBeUndefined(); }
    });
    it.each(['shared', 'capability', 'actor', 'expiry', 'transport', 'expired'] as const)('refuses %s before reading history', async kind => {
        const session = { ...actionSession, ...(kind === 'shared' ? { loginMode: 'shared', actorId: null, capabilities: ['read'] } : kind === 'capability' ? { capabilities: ['read'] } : kind === 'actor' ? { actorId: `operator_${'f'.repeat(32)}` } : kind === 'expiry' ? { expiresAt: '2026-10-05T14:00:00Z' } : kind === 'expired' ? { serverNow: actionSession.expiresAt } : { insecureTestMode: true, transport: 'http', transportWarning: 'unencrypted_lan_test' }) };
        const fetch = vi.fn().mockResolvedValue(response(session)); vi.stubGlobal('fetch', fetch);
        await expect(readServiceActionHistory(actionDevice, actionAccess, new AbortController().signal)).rejects.toThrow(); expect(fetch).toHaveBeenCalledTimes(1);
    });
    it.each(['extra', 'oversized', 'future-session', 'before-session'] as const)('rejects %s response', async kind => {
        const h = actionHistory();
        const body = kind === 'extra' ? { ...h, envelope: 'extra' } : kind === 'oversized' ? { padding: 'x'.repeat(131073) } : { ...h, serverNow: kind === 'future-session' ? actionSession.expiresAt : '2026-10-05T11:59:59Z' };
        const fetch = vi.fn().mockResolvedValueOnce(response(actionSession)).mockResolvedValueOnce(response(body)); vi.stubGlobal('fetch', fetch);
        await expect(readServiceActionHistory(actionDevice, actionAccess, new AbortController().signal)).rejects.toThrow();
    });
    it('does not publish a response after the access epoch changes', async () => {
        const fetch = vi.fn().mockResolvedValueOnce(response(actionSession)).mockImplementationOnce(async () => { abortProtectedRequests(); return response(actionHistory()); }); vi.stubGlobal('fetch', fetch);
        await expect(readServiceActionHistory(actionDevice, actionAccess, new AbortController().signal)).rejects.toMatchObject({ name: 'AbortError' }); expect(fetch).toHaveBeenCalledTimes(2);
    });
    it('rejects malformed device identifiers before any request', async () => {
        const fetch = vi.fn(); vi.stubGlobal('fetch', fetch); await expect(readServiceActionHistory('../device', actionAccess, new AbortController().signal)).rejects.toThrow(); expect(fetch).not.toHaveBeenCalled();
    });
});
