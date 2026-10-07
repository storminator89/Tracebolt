import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { request } from './api';
import { SERVICE_ACTION_VIEW_BYTES } from './service-action-types';
import { PACKAGE_UPDATE_VIEW_BYTES } from './package-update-types';
import { approvePackageUpdates, preparePackageUpdates, readPackageUpdateRetryGate, readPackageUpdates } from './package-update-api';
import { nativePackageUpdateJob, nativePackageUpdates, packageUpdateJob, packageUpdatePreview, simulatedPackageUpdates, updateWorkflowActor, updateWorkflowDevice, updateWorkflowRequest, updateWorkflowTime } from './package-update-fixtures';
import type { OperatorSession } from './auth';
const session: OperatorSession = { mode: 'lan', transport: 'https', insecureTestMode: false, transportWarning: null, authenticationRequired: true, authenticated: true, csrfToken: 'fixture-csrf', serverNow: updateWorkflowTime, expiresAt: '2026-10-07T02:00:00Z', expiresInSeconds: 3600, loginMode: 'named', actorId: updateWorkflowActor, capabilities: ['read', 'plan_updates', 'execute_updates'] };
const access = { actorId: updateWorkflowActor, sessionKey: session.expiresAt!, insecureTestMode: false };
const controller = () => new AbortController();
const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } });
beforeEach(() => { localStorage.clear(); sessionStorage.clear(); });
afterEach(() => vi.unstubAllGlobals());
describe('package-update independent capability API', () => {
    it('uses bounded read-only status without mutation and supports exact request recovery', async () => {
        const fetch = vi.fn().mockResolvedValue(json(packageUpdateJob())); vi.stubGlobal('fetch', fetch);
        await readPackageUpdates(updateWorkflowDevice, controller().signal, updateWorkflowRequest);
        expect(fetch).toHaveBeenCalledTimes(1); expect(fetch.mock.calls[0][0]).toBe(`/api/devices/${updateWorkflowDevice}/package-updates/jobs/${updateWorkflowRequest}`);
        expect(fetch.mock.calls[0][1].method).toBeUndefined();
    });
    it('rejects a different job returned for an exact recovery ID', async () => {
        vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json(packageUpdateJob())));
        await expect(readPackageUpdates(updateWorkflowDevice, controller().signal, `update_${'f'.repeat(32)}`)).rejects.toThrow('Wrong recovered');
    });
    it('preserves the exact missing-job code and does not reinterpret a generic 404', async () => {
        const fetch = vi.fn().mockResolvedValueOnce(json({ error: { code: 'package_update_not_found', message: 'No saved job.' } }, 404)).mockResolvedValueOnce(json({ error: { code: 'not_found', message: 'Unknown route.' } }, 404)); vi.stubGlobal('fetch', fetch);
        await expect(readPackageUpdates(updateWorkflowDevice, controller().signal, updateWorkflowRequest)).rejects.toMatchObject({ status: 404, code: 'package_update_not_found' });
        await expect(readPackageUpdates(updateWorkflowDevice, controller().signal, updateWorkflowRequest)).rejects.toMatchObject({ status: 404, code: undefined });
    });
    it('rechecks the exact named plan session and current status without writing for a missing-request retry gate', async () => {
        const fetch = vi.fn().mockImplementation(async (url: string) => json(url.endsWith('/auth/session') ? { ...session, capabilities: ['read', 'plan_updates'] } : packageUpdateJob('succeeded'))); vi.stubGlobal('fetch', fetch);
        expect((await readPackageUpdateRetryGate(updateWorkflowDevice, access, controller().signal)).available).toBe(true);
        expect(fetch.mock.calls.map(([url]) => url)).toEqual(['/api/auth/session', `/api/devices/${updateWorkflowDevice}/package-updates`]);
        expect(fetch.mock.calls.some(([, options]) => options.method === 'POST')).toBe(false);
    });
    it('does not reopen a missing-request retry gate after the plan capability is removed', async () => {
        const fetch = vi.fn().mockResolvedValue(json({ ...session, capabilities: ['read', 'execute_updates'] })); vi.stubGlobal('fetch', fetch);
        await expect(readPackageUpdateRetryGate(updateWorkflowDevice, access, controller().signal)).rejects.toMatchObject({ status: 401 }); expect(fetch).toHaveBeenCalledTimes(1);
    });
    it.each(['prepare', 'approve'] as const)('%s requires only its independent capability and sends exact minimal body', async action => {
        const capabilities: OperatorSession['capabilities'] = action === 'prepare' ? ['read', 'plan_updates'] : ['read', 'execute_updates'];
        const fetch = vi.fn().mockImplementation(async (url: string) => json(url.endsWith('/auth/session') ? { ...session, capabilities } : url.endsWith('/session') ? { csrfToken: 'fixture-csrf' } : url.endsWith('/package-updates') ? action === 'prepare' ? simulatedPackageUpdates() : packageUpdateJob() : packageUpdateJob(action === 'prepare' ? 'preview_ready' : 'approved'))); vi.stubGlobal('fetch', fetch);
        if (action === 'prepare') await preparePackageUpdates(updateWorkflowDevice, updateWorkflowRequest, [{ name: 'curl', architecture: 'amd64' }], access, controller().signal);
        else await approvePackageUpdates(updateWorkflowDevice, packageUpdatePreview(), access, controller().signal);
        const writes = fetch.mock.calls.filter(([, options]) => options.method === 'POST'); expect(writes).toHaveLength(1);
        expect(JSON.parse(writes[0][1].body)).toEqual(action === 'prepare' ? { requestId: updateWorkflowRequest, packages: [{ name: 'curl', architecture: 'amd64' }] } : { requestId: updateWorkflowRequest, previewDigest: packageUpdatePreview().digest });
        expect(writes[0][1].headers['X-CSRF-Token']).toBe('fixture-csrf');
    });
    it.each(['shared', 'wrong-actor', 'wrong-capability', 'expired', 'changed-transport'] as const)('blocks changed %s access before any mutation', async change => {
        const altered = { ...session, ...(change === 'shared' ? { loginMode: 'shared', actorId: null, capabilities: ['read'] } : change === 'wrong-actor' ? { actorId: `operator_${'f'.repeat(32)}` } : change === 'wrong-capability' ? { capabilities: ['read', 'execute_updates'] } : change === 'expired' ? { expiresAt: updateWorkflowTime } : { insecureTestMode: true, transport: 'http', transportWarning: 'unencrypted_lan_test' }) };
        const fetch = vi.fn().mockImplementation(async (url: string) => json(url.endsWith('/package-updates') ? simulatedPackageUpdates() : altered)); vi.stubGlobal('fetch', fetch);
        await expect(preparePackageUpdates(updateWorkflowDevice, updateWorkflowRequest, [{ name: 'curl', architecture: 'amd64' }], access, controller().signal)).rejects.toThrow();
        expect(fetch.mock.calls.some(([, options]) => options.method === 'POST')).toBe(false);
    });
    it('canonicalizes multi-architecture selection without forwarding any version evidence', async () => {
        const fetch = vi.fn().mockImplementation(async (url: string) => json(url.endsWith('/auth/session') ? session : url.endsWith('/session') ? { csrfToken: 'fixture-csrf' } : url.endsWith('/package-updates') ? simulatedPackageUpdates() : packageUpdateJob())); vi.stubGlobal('fetch', fetch);
        await preparePackageUpdates(updateWorkflowDevice, updateWorkflowRequest, [{ name: 'zlib1g', architecture: 'amd64' }, { name: 'curl', architecture: 'arm64' }, { name: 'curl', architecture: 'amd64' }], access, controller().signal);
        const write = fetch.mock.calls.find(([, options]) => options.method === 'POST')!;
        expect(JSON.parse(write[1].body).packages).toEqual([{ name: 'curl', architecture: 'amd64' }, { name: 'curl', architecture: 'arm64' }, { name: 'zlib1g', architecture: 'amd64' }]);
    });
    it('rejects arbitrary fields and oversized or duplicate identities before network access', () => {
        const fetch = vi.fn(); vi.stubGlobal('fetch', fetch);
        expect(() => preparePackageUpdates(updateWorkflowDevice, updateWorkflowRequest, [{ name: 'curl', architecture: 'amd64', command: 'install' } as never], access, controller().signal)).toThrow();
        expect(() => preparePackageUpdates(updateWorkflowDevice, updateWorkflowRequest, Array(33).fill({ name: 'curl', architecture: 'amd64' }), access, controller().signal)).toThrow();
        expect(() => preparePackageUpdates(updateWorkflowDevice, updateWorkflowRequest, Array(2).fill({ name: 'curl', architecture: 'amd64' }), access, controller().signal)).toThrow(); expect(fetch).not.toHaveBeenCalled();
    });
    it('rejects mismatched preview actor or transport before network access', () => {
        const fetch = vi.fn(); vi.stubGlobal('fetch', fetch); const preview = packageUpdatePreview();
        expect(() => approvePackageUpdates(updateWorkflowDevice, { ...preview, actorId: `operator_${'f'.repeat(32)}` }, access, controller().signal)).toThrow();
        expect(() => approvePackageUpdates(updateWorkflowDevice, { ...preview, transportProfile: 'disposable-http-test' }, access, controller().signal)).toThrow(); expect(fetch).not.toHaveBeenCalled();
    });
    it.each(['prepare', 'approve'] as const)('uses current native readiness before named %s capability and sends only the reviewed request', async action => {
        const fetch = vi.fn().mockImplementation(async (url: string) => json(url.endsWith('/package-updates') ? action === 'prepare' ? nativePackageUpdates() : nativePackageUpdateJob() : url.endsWith('/auth/session') ? { ...session, capabilities: ['read', action === 'prepare' ? 'plan_updates' : 'execute_updates'] } : url.endsWith('/session') ? { csrfToken: 'fixture-csrf' } : nativePackageUpdateJob(action === 'prepare' ? 'preview_ready' : 'approved'))); vi.stubGlobal('fetch', fetch);
        if (action === 'prepare') await preparePackageUpdates(updateWorkflowDevice, updateWorkflowRequest, [{ name: 'curl', architecture: 'amd64' }], access, controller().signal, 'native');
        else await approvePackageUpdates(updateWorkflowDevice, packageUpdatePreview(), access, controller().signal, 'native');
        expect(fetch.mock.calls.slice(0, 2).map(([url]) => url)).toEqual([`/api/devices/${updateWorkflowDevice}/package-updates`, '/api/auth/session']);
        expect(fetch.mock.calls.filter(([, options]) => options.method === 'POST')).toHaveLength(1);
    });
    it.each(['stale', 'expired', 'changed-actor', 'changed-transport', 'changed-digest', 'changed-bytes', 'mode-switch'] as const)('blocks native approval when readiness is %s before POST', async change => {
        const status = change === 'mode-switch' ? packageUpdateJob() : nativePackageUpdateJob();
        if (change === 'stale') status.reason = 'native_adapter_unavailable';
        if (change === 'expired') status.preview!.expiresAt = updateWorkflowTime;
        if (change === 'changed-actor') status.preview!.actorId = `operator_${'f'.repeat(32)}`;
        if (change === 'changed-transport') status.preview!.transportProfile = 'disposable-http-test';
        if (change === 'changed-digest') status.preview!.digest = `sha256:${'f'.repeat(64)}`;
        if (change === 'changed-bytes') status.preview!.items[0].toVersion = '2.0';
        const fetch = vi.fn().mockImplementation(async (url: string) => json(url.endsWith('/package-updates') ? status : session)); vi.stubGlobal('fetch', fetch);
        await expect(approvePackageUpdates(updateWorkflowDevice, packageUpdatePreview(), access, controller().signal, 'native')).rejects.toThrow();
        expect(fetch.mock.calls.some(([, options]) => options.method === 'POST')).toBe(false);
    });
    it('requires freshness through the subsequent capability read, not just when the preview was loaded', async () => {
        const fetch = vi.fn().mockImplementation(async (url: string) => json(url.endsWith('/package-updates') ? nativePackageUpdateJob() : { ...session, serverNow: '2026-10-07T01:05:01Z' })); vi.stubGlobal('fetch', fetch);
        await expect(approvePackageUpdates(updateWorkflowDevice, packageUpdatePreview(), access, controller().signal, 'native')).rejects.toThrow();
        expect(fetch.mock.calls.some(([, options]) => options.method === 'POST')).toBe(false);
    });
    it('rejects a changed result mode even when a POST response has the right request ID', async () => {
        const fetch = vi.fn().mockImplementation(async (url: string) => json(url.endsWith('/package-updates') ? nativePackageUpdateJob() : url.endsWith('/auth/session') ? session : url.endsWith('/session') ? { csrfToken: 'fixture-csrf' } : packageUpdateJob('approved'))); vi.stubGlobal('fetch', fetch);
        await expect(approvePackageUpdates(updateWorkflowDevice, packageUpdatePreview(), access, controller().signal, 'native')).rejects.toThrow('Changed package-update operation');
    });
    it('permits exactly 512 KiB for package routes and leaves service limits unchanged', async () => {
        expect(PACKAGE_UPDATE_VIEW_BYTES).toBe(512 * 1024); expect(SERVICE_ACTION_VIEW_BYTES).toBe(32768);
        const fetch = vi.fn().mockImplementation(async () => json({ data: 'x'.repeat(300 * 1024) })); vi.stubGlobal('fetch', fetch);
        await expect(request(`/devices/${updateWorkflowDevice}/package-updates`, undefined, PACKAGE_UPDATE_VIEW_BYTES)).resolves.toHaveProperty('data');
        const calls = fetch.mock.calls.length;
        await expect(request(`/devices/${updateWorkflowDevice}/package-updates`, undefined, PACKAGE_UPDATE_VIEW_BYTES + 1)).rejects.toThrow();
        await expect(request(`/devices/${updateWorkflowDevice}/service-actions`, undefined, PACKAGE_UPDATE_VIEW_BYTES)).rejects.toThrow();
        expect(fetch).toHaveBeenCalledTimes(calls);
        await expect(request(`/devices/${updateWorkflowDevice}/service-actions`, undefined, SERVICE_ACTION_VIEW_BYTES)).rejects.toThrow();
    });

});
