import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import App from './App';
import { abortProtectedRequests, APIError, AUTH_REQUIRED_EVENT, mutate, request } from './api';
import { setLocale } from './i18n';
import { windowsDevice, windowsDeviceId, windowsNow } from './windows-inventory-fixture';
import { windowsStorageIOView } from './windows-storage-io-fixture';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutate: vi.fn() }));
const prefix = `/devices/${windowsDeviceId}`;
const inventoryPath = `${prefix}/windows-inventory`;
const flush = () => act(async () => {});
// These resource-lifecycle checks start after the actual lazy route has mounted.
async function mountApp() { render(<App/>); await flush(); await act(async () => { await vi.dynamicImportSettled(); }); }
function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(done => { resolve = done; }); return { promise, resolve }; }
function route(hash: string) {
    // replaceState avoids jsdom queuing a second synthetic hashchange later.
    window.history.replaceState({}, '', `/#${hash}`);
    window.dispatchEvent(new Event('hashchange'));
}
const inventoryReads = () => vi.mocked(request).mock.calls.filter(([path]) => path === inventoryPath);
const storage = () => document.querySelector('.windows-storage-io');
function openStorage() {
    fireEvent.click(screen.getByRole('tab', { name: 'Inventory' }));
    fireEvent.click(screen.getByRole('tab', { name: 'Storage' }));
}
let nextInventory: () => Promise<ReturnType<typeof windowsStorageIOView>>;
beforeEach(() => {
    vi.useFakeTimers(); vi.setSystemTime(windowsNow); localStorage.clear(); sessionStorage.clear(); setLocale('en', false);
    window.history.replaceState({}, '', `/#${prefix}`);
    nextInventory = async () => windowsStorageIOView();
    vi.mocked(request).mockReset().mockImplementation(async path => {
        if (path === '/auth/session') return { mode: 'lan', transport: 'https', insecureTestMode: false, transportWarning: null, authenticationRequired: true, authenticated: true, csrfToken: 'synthetic-only', serverNow: windowsNow, expiresAt: '2026-10-07T13:00:00Z', expiresInSeconds: 3600, loginMode: 'shared', actorId: null, capabilities: ['read'] };
        if (path === prefix) return windowsDevice();
        if (path === inventoryPath) return nextInventory();
        if (path === '/overview') return { generatedAt: windowsNow, stats: { totalDevices: 1, healthyDevices: 1, attentionDevices: 0, openCases: 0, criticalCases: 0 }, devices: [windowsDevice()], cases: [], activity: [] };
        throw new APIError('Synthetic unavailable', 404);
    });
    vi.mocked(mutate).mockReset().mockRejectedValue(new APIError('Synthetic unavailable', 404));
});
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.restoreAllMocks(); });

describe('Windows inventory navigation lifecycle', () => {
    it('rereads after batched away-and-back navigation before the first inventory response', async () => {
        const old = deferred<ReturnType<typeof windowsStorageIOView>>(), fresh = deferred<ReturnType<typeof windowsStorageIOView>>();
        nextInventory = () => old.promise;
        await mountApp(); await flush(); expect(inventoryReads()).toHaveLength(1);
        const signal = inventoryReads()[0][1]?.signal;
        nextInventory = () => fresh.promise;
        act(() => { route('/devices'); route(prefix); }); await flush();
        expect(signal?.aborted).toBe(true);
        expect(inventoryReads()).toHaveLength(2);
        openStorage(); expect(storage()).toBeNull();
        await act(async () => old.resolve(windowsStorageIOView())); expect(storage()).toBeNull();
        await act(async () => fresh.resolve(windowsStorageIOView()));
        expect(storage()).toHaveTextContent('120.5 ops/s');
    });
    it('clears already displayed values until the same device has a fresh post-navigation response', async () => {
        await mountApp(); await flush(); openStorage(); expect(storage()).toHaveTextContent('120.5 ops/s');
        const fresh = deferred<ReturnType<typeof windowsStorageIOView>>(); nextInventory = () => fresh.promise;
        act(() => { route('/devices'); route(prefix); }); await flush();
        expect(storage()).toBeNull(); expect(inventoryReads()).toHaveLength(2);
        openStorage(); expect(storage()).toBeNull();
        await act(async () => fresh.resolve(windowsStorageIOView()));
        expect(storage()).toHaveTextContent('120.5 ops/s');
    });
    it('clears visible private values and does not read the departed device after navigation away', async () => {
        await mountApp(); await flush(); openStorage(); expect(storage()).toHaveTextContent('120.5 ops/s');
        const old = deferred<ReturnType<typeof windowsStorageIOView>>(); nextInventory = () => old.promise;
        fireEvent.click(screen.getByRole('button', { name: 'Refresh Windows inventory' }));
        const signal = inventoryReads().at(-1)![1]?.signal, count = inventoryReads().length;
        act(() => route('/devices')); await flush();
        expect(signal?.aborted).toBe(true); expect(storage()).toBeNull();
        await act(async () => old.resolve(windowsStorageIOView()));
        expect(storage()).toBeNull(); expect(inventoryReads()).toHaveLength(count);
    });
    it('keeps authentication loss terminal across a batched return and a late response', async () => {
        await mountApp(); await flush(); openStorage(); expect(storage()).toHaveTextContent('120.5 ops/s');
        const late = deferred<ReturnType<typeof windowsStorageIOView>>(); nextInventory = () => late.promise;
        fireEvent.click(screen.getByRole('button', { name: 'Refresh Windows inventory' }));
        const signal = inventoryReads().at(-1)![1]?.signal, count = inventoryReads().length;
        act(() => { route('/devices'); route(prefix); window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT)); }); await flush();
        expect(signal?.aborted).toBe(true); expect(storage()).toBeNull();
        await act(async () => late.resolve(windowsStorageIOView()));
        expect(screen.getByLabelText('Operator password', { exact: true })).toBeVisible();
        expect(storage()).toBeNull(); expect(inventoryReads()).toHaveLength(count);
    });
});
