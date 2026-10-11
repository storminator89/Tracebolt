import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, mutateRaw, request } from './api';
import { setLocale } from './i18n';
import { windowsCapacityDevice, windowsCapacitySession } from './windows-capacity-fixture';
import { windowsDeviceId, windowsNow } from './windows-inventory-fixture';
import { WindowsServiceHealthPanel } from './windows-service-health';
import { windowsServiceHealthView } from './windows-service-health-fixture';
import { useWindowsServiceHealth } from './windows-service-health-resource';
import { WINDOWS_SERVICE_HEALTH_VIEW_BYTES } from './windows-service-health-types';
import type { WindowsServiceHealthView } from './windows-service-health-types';

// Only the network boundary is faked. request/mutateRaw, CSRF, bounded stream
// reading, protected epochs, hook reconciliation, and the rendered panel are real.
const path = `/devices/${windowsDeviceId}/windows-services`, prefix = '/api' + path;
const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } });
const padded = (value: unknown, bytes: number) => { const raw = JSON.stringify(value); return raw + ' '.repeat(bytes - new TextEncoder().encode(raw).byteLength); };
const flush = async () => { await act(async () => { for (let i = 0; i < 50; i++) await Promise.resolve(); }); };
const advance = async (ms: number) => { await act(async () => vi.advanceTimersByTimeAsync(ms)); await flush(); };
function Harness() { const device = windowsCapacityDevice(), resource = useWindowsServiceHealth(device.id, true, windowsCapacitySession, true, device.agentCertificate); return <WindowsServiceHealthPanel device={device} resource={resource} sessionKey={windowsCapacitySession} metadataReady admin/>; }
const edit = () => { fireEvent.click(screen.getByText('Selected-service policy settings & limits')); fireEvent.click(screen.getByRole('checkbox', { name: 'Enable selected-service policy' })); fireEvent.click(screen.getByRole('checkbox', { name: /Fixture Background Service/ })); };
const save = () => fireEvent.click(screen.getByRole('button', { name: /^(Save selected-service policy|Saving policy…)$/ }));
const refresh = () => fireEvent.click(screen.getByRole('button', { name: 'Refresh selected-service policy' }));
let view: WindowsServiceHealthView, override: ((target: string, options?: RequestInit) => Promise<Response> | undefined) | null;
const calls: { target: string; options?: RequestInit }[] = [];
const writes = () => calls.filter(call => call.target === prefix + '/policy');
beforeEach(() => {
    abortProtectedRequests(); vi.useFakeTimers(); vi.setSystemTime(windowsNow); setLocale('en', false); localStorage.clear(); sessionStorage.clear(); view = windowsServiceHealthView(); override = null; calls.length = 0;
    vi.stubGlobal('fetch', vi.fn(async (target: string, options?: RequestInit) => {
        calls.push({ target, options }); const special = override?.(target, options); if (special) return special;
        if (target === '/api/session') return json({ csrfToken: 'synthetic-service-csrf' });
        if (target === prefix) return json(view);
        if (target === prefix + '/policy') {
            const body = JSON.parse(String(options?.body));
            view = { ...windowsServiceHealthView(body.enabled ? 'unknown' : 'disabled'), policy: { enabled: body.enabled, services: body.services, revision: body.expectedRevision + 1 }, checks: body.services.map((name: string) => ({ name, status: 'unknown', observation: null })) };
            return json(view);
        }
        throw new Error('Unexpected synthetic service route');
    }));
});
afterEach(async () => { cleanup(); abortProtectedRequests(); await flush(); vi.unstubAllGlobals(); vi.restoreAllMocks(); vi.useRealTimers(); });
describe('real selected-service API and React integration', () => {
    it('loads the live panel through real bounded request, including valid bytes above the generic 256KiB limit', async () => {
        override = target => target === prefix ? Promise.resolve(new Response(padded(view, 300 * 1024))) : undefined;
        render(<Harness/>); await flush(); expect(screen.getByText('Policy disabled')).toBeVisible(); expect(calls.map(call => call.target)).toEqual([prefix]);
        fireEvent.click(screen.getByText('Selected-service policy settings & limits')); expect(screen.getByRole('checkbox', { name: /Fixture Background Service/ })).toBeEnabled(); expect(writes()).toHaveLength(0);
    });
    it('sends exactly one selected-name save after CSRF and confirms only a separate GET', async () => {
        render(<Harness/>); await flush(); edit(); save(); save(); await flush();
        expect(calls.map(call => call.target)).toEqual([prefix, '/api/session', prefix + '/policy', prefix]); expect(writes()).toHaveLength(1);
        expect(writes()[0].options?.method).toBe('POST'); expect(writes()[0].options?.headers).toMatchObject({ 'X-CSRF-Token': 'synthetic-service-csrf', 'Content-Type': 'application/json' });
        expect(JSON.parse(String(writes()[0].options?.body))).toEqual({ enabled: true, services: ['FixtureService'], expectedRevision: 0 }); expect(screen.getByText('Current saved policy confirmed.')).toBeVisible();
        expect(localStorage.length + sessionStorage.length).toBe(0);
    });
    it('keeps outcome uncertain and never replays a real failed fetch mutation', async () => {
        render(<Harness/>); await flush(); edit(); override = target => target === prefix + '/policy' ? Promise.reject(new Error('private transport content')) : undefined;
        save(); await flush(); await advance(30000); expect(writes()).toHaveLength(1); expect(screen.getByText(/Save outcome is uncertain/)).toBeVisible(); expect(document.body).not.toHaveTextContent('private transport content'); expect(screen.getByRole('button', { name: 'Save selected-service policy' })).toBeDisabled();
    });
    it('reconciles an accepted save whose fetch response was lost without replay', async () => {
        render(<Harness/>); await flush(); edit(); override = target => { if (target !== prefix + '/policy') return; view = windowsServiceHealthView('unknown'); return Promise.reject(new TypeError('lost response')); };
        save(); await flush(); expect(screen.getByText('Current saved policy confirmed.')).toBeVisible(); await advance(15000); expect(writes()).toHaveLength(1);
    });
    it('retains conflict truth from a real 409 response and never exposes raw error text', async () => {
        render(<Harness/>); await flush(); edit(); override = target => { if (target !== prefix + '/policy') return; view = windowsServiceHealthView('unknown'); return Promise.resolve(json({ error: { code: 'windows_service_conflict', message: 'private conflict content' } }, 409)); };
        save(); await flush(); expect(screen.getByText(/save conflicted/)).toBeVisible(); expect(screen.queryByText('Current saved policy confirmed.')).toBeNull(); expect(document.body).not.toHaveTextContent('private conflict content'); expect(writes()).toHaveLength(1);
    });
    it('never posts when the CSRF response exceeds its unchanged 32KiB bound', async () => {
        render(<Harness/>); await flush(); edit(); override = target => target === '/api/session' ? Promise.resolve(json({ csrfToken: 'synthetic-service-csrf', padding: 'x'.repeat(32768) })) : undefined;
        save(); await flush(); expect(writes()).toHaveLength(0); expect(screen.getByText(/Save outcome is uncertain/)).toBeVisible();
    });
    it('never posts after protected epoch changes during the CSRF read', async () => {
        render(<Harness/>); await flush(); edit(); override = target => { if (target !== '/api/session') return; abortProtectedRequests(); return Promise.resolve(json({ csrfToken: 'synthetic-service-csrf' })); };
        save(); await flush(); expect(writes()).toHaveLength(0); expect(screen.queryByRole('button', { name: 'Remove service: FixtureService' })).toBeNull();
    });
    it('hides source choices and draft names after an actual 401 read', async () => {
        render(<Harness/>); await flush(); edit(); override = target => target === prefix ? Promise.resolve(json({ error: { code: 'authentication_required' } }, 401)) : undefined;
        refresh(); await flush(); expect(screen.queryByRole('button', { name: 'Remove service: FixtureService' })).toBeNull(); expect(screen.queryByRole('checkbox', { name: /Fixture Background Service/ })).toBeNull(); expect(screen.getByRole('checkbox', { name: 'Enable selected-service policy' })).toBeDisabled(); expect(writes()).toHaveLength(0);
    });
});
describe('exact selected-service transport response bounds', () => {
    it('allows the separate 512KiB response only at the two exact service routes', async () => {
        vi.mocked(fetch).mockImplementation(async () => new Response(padded({ ok: true }, WINDOWS_SERVICE_HEALTH_VIEW_BYTES)));
        for (const target of [path, path + '/policy']) await expect(request(target, undefined, WINDOWS_SERVICE_HEALTH_VIEW_BYTES)).resolves.toEqual({ ok: true });
        const count = vi.mocked(fetch).mock.calls.length;
        for (const target of ['/devices', path + '/', path + '?name=Spooler', path + '/policy/', path + '/policy?x=1', path + '/other', path.replace('windows-services', 'windows-%73ervices'), path.replace('windows-services', 'windows-capacity'), path.replace('windows-services', 'windows-resource/cpu')]) await expect(request(target, undefined, WINDOWS_SERVICE_HEALTH_VIEW_BYTES)).rejects.toThrow();
        expect(fetch).toHaveBeenCalledTimes(count);
    });
    it.each([path, path + '/policy'].flatMap(target => [undefined, '2'].map(length => ({ target, length }))))('cancels streamed bytes above the service response ceiling with absent/lying length: %j', async ({ target, length }) => {
        const cancel = vi.fn(); const body = new ReadableStream({ start(controller) { controller.enqueue(new TextEncoder().encode(' '.repeat(WINDOWS_SERVICE_HEALTH_VIEW_BYTES + 1))); }, cancel });
        vi.mocked(fetch).mockResolvedValue(new Response(body, { headers: length === undefined ? {} : { 'Content-Length': length } }));
        await expect(request(target, undefined, WINDOWS_SERVICE_HEALTH_VIEW_BYTES)).rejects.toThrow(); expect(cancel).toHaveBeenCalledOnce(); expect(body.locked).toBe(false);
    });
    it('counts Go HTML-escaped wire bytes and multibyte UTF-8 without broadening the ceiling', async () => {
        const escaped = '{"value":"' + '\\u003c'.repeat(50000) + '"}';
        expect(new TextEncoder().encode(escaped).byteLength).toBeGreaterThan(256 * 1024); vi.mocked(fetch).mockResolvedValueOnce(new Response(escaped));
        await expect(request(path, undefined, WINDOWS_SERVICE_HEALTH_VIEW_BYTES)).resolves.toEqual({ value: '<'.repeat(50000) });
        const multibyte = JSON.stringify({ value: '€'.repeat(Math.ceil(WINDOWS_SERVICE_HEALTH_VIEW_BYTES / 3)) });
        expect(multibyte.length).toBeLessThan(WINDOWS_SERVICE_HEALTH_VIEW_BYTES); expect(new TextEncoder().encode(multibyte).byteLength).toBeGreaterThan(WINDOWS_SERVICE_HEALTH_VIEW_BYTES); vi.mocked(fetch).mockResolvedValueOnce(new Response(multibyte));
        await expect(request(path, undefined, WINDOWS_SERVICE_HEALTH_VIEW_BYTES)).rejects.toThrow();
    });
    it('retains raw-mutation epoch and CSRF guards at the larger route response budget', async () => {
        const result = await mutateRaw<WindowsServiceHealthView>(path + '/policy', JSON.stringify({ enabled: true, services: ['FixtureService'], expectedRevision: 0 }), {}, undefined, WINDOWS_SERVICE_HEALTH_VIEW_BYTES);
        expect(result.policy.revision).toBe(1); expect(calls.map(call => call.target)).toEqual(['/api/session', prefix + '/policy']);
    });
});
