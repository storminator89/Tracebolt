import { useState } from 'react';
import vectors from './windows-fleet-identity-vectors.json';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, AUTH_REQUIRED_EVENT, request } from './api';
import { DeviceTable } from './components';
import { FleetIdentityNotice } from './fleet-identity';
import { useFleetIdentity } from './fleet-identity-resource';
import { fleetIdentityProjection, validFleetIdentityView, type FleetIdentitiesView } from './fleet-identity-types';
import { setLocale } from './i18n';
import { defaultFilters, filterDevices } from './utils';
import { windowsDevice, windowsDeviceId, windowsNow, windowsSnapshot } from './windows-inventory-fixture';
import { validWindowsFleetIdentity, type WindowsFleetIdentityView } from './windows-fleet-identity-types';

function item(): WindowsFleetIdentityView {
    const s = windowsSnapshot();
    return { schemaVersion: 'tracebolt.windows-fleet-identity-view.v1', deviceId: windowsDeviceId, collectionProfile: 'windows-inventory-v1', serverNow: windowsNow, maxAgeSeconds: 120, status: 'fresh', sequence: '1', receivedAt: '2026-10-07T12:00:01Z', expiresAt: '2026-10-08T12:00:00Z', latest: { schemaVersion: 'tracebolt.windows-fleet-identity.v1', collectionProfile: s.collectionProfile, generationId: s.generationId, collectedAt: s.collectedAt, hostname: s.hostname, network: s.network } };
}
const fleet = (v = item()): FleetIdentitiesView => ({ schemaVersion: 'tracebolt.fleet-identities.v2', serverNow: v.serverNow, items: [v] });
const response = (v: unknown) => new Response(JSON.stringify(v));
function Harness({ session = 'session-a', deviceId = windowsDeviceId }: { session?: string; deviceId?: string }) {
    const resource = useFleetIdentity(true, session, '', true), [query, setQuery] = useState('');
    return <><input aria-label="Search" value={query} onChange={e => setQuery(e.target.value)}/><FleetIdentityNotice resource={resource}/><DeviceTable identities={resource.identities} devices={filterDevices([{ ...windowsDevice(), id: deviceId }], { ...defaultFilters, query }, resource.identities)} onSelect={vi.fn()}/></>;
}
const refresh = () => fireEvent.click(screen.getByRole('button', { name: 'Refresh hostnames and IP addresses' }));
beforeEach(() => setLocale('en', false));
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe('Windows fleet identity', () => {
    it('consumes actual production HTTP response vectors through the strict reader and fleet UI', async () => {
        for (const [name, value] of Object.entries(vectors)) expect(validFleetIdentityView(value), name).toBe(true);
        const fresh = vectors.fresh;
        if (!validFleetIdentityView(fresh)) throw new Error('Invalid production fixture');
        const deviceId = fresh.items[0].deviceId, display = fleetIdentityProjection(fresh, 0).get(deviceId)!;
        const fetch = vi.fn().mockResolvedValue(response(fresh)); vi.stubGlobal('fetch', fetch);
        const ui = render(<Harness deviceId={deviceId}/>); await screen.findByText(display.hostname!);
        expect(ui.container.querySelector('fleet')).toBeNull();
        for (const address of display.addresses) {
            fireEvent.change(screen.getByLabelText('Search'), { target: { value: address.address } });
            expect(screen.getAllByRole('row')).toHaveLength(2);
        }
        expect(fetch.mock.calls[0][0]).toBe('/api/fleet/identities');
        expect(fetch).toHaveBeenCalledTimes(1);
    });
    it('admits the larger protected reader only for the exact v2 route', async () => {
        const fetch = vi.fn().mockResolvedValue(response(fleet())); vi.stubGlobal('fetch', fetch);
        await expect(request('/fleet/identities', undefined, 512 * 1024)).resolves.toMatchObject({ schemaVersion: 'tracebolt.fleet-identities.v2' });
        for (const path of ['/fleet/endpoint-identities', '/fleet/identities?extra=1', '/fleet/identities/']) await expect(request(path, undefined, 512 * 1024)).rejects.toThrow();
        expect(fetch).toHaveBeenCalledTimes(1);
    });
    it('keeps the typed Windows scope separate, with strict rows, receipt, expiry and v2 bounds', () => {
        expect(validWindowsFleetIdentity(item())).toBe(true); expect(validFleetIdentityView(fleet())).toBe(true);
        expect(validFleetIdentityView({ ...fleet(), schemaVersion: 'tracebolt.fleet-endpoint-identity.v1' })).toBe(false);
        for (const change of [(v: WindowsFleetIdentityView) => { Object.assign(v.latest!, { processes: windowsSnapshot().processes }); }, (v: WindowsFleetIdentityView) => { v.latest!.network.rows[0].address = 'host.invalid'; }, (v: WindowsFleetIdentityView) => { v.latest!.network.complete = false; }, (v: WindowsFleetIdentityView) => { v.expiresAt = '2026-10-09T12:00:00Z'; }, (v: WindowsFleetIdentityView) => { v.status = 'revoked'; }, (v: WindowsFleetIdentityView) => { v.receivedAt = '2026-10-07T12:00:11Z'; }]) {
            const v = item(); change(v); expect(validWindowsFleetIdentity(v)).toBe(false);
        }
        const bounded = fleet(); bounded.items = Array.from({ length: 50 }, (_, n) => ({ ...item(), deviceId: `agent_${n.toString(16).padStart(32, '0')}` }));
        expect(validFleetIdentityView(bounded)).toBe(true); bounded.items.push({ ...item(), deviceId: `agent_${'f'.repeat(32)}` }); expect(validFleetIdentityView(bounded)).toBe(false);
    });
    it('searches hostname and numeric dual-stack addresses without changing Device or trusting peer IP', () => {
        const source = { ...windowsDevice(), ip: '198.51.100.250' }, before = JSON.stringify(source), identities = fleetIdentityProjection(fleet(), 0);
        for (const query of ['fixture-windows', '192.0.2.40', '2001:db8::40']) expect(filterDevices([source], { ...defaultFilters, query }, identities)).toEqual([source]);
        expect(filterDevices([source], { ...defaultFilters, query: source.ip }, identities)).toEqual([]); expect(JSON.stringify(source)).toBe(before);
        expect(identities.get(source.id)?.addresses[0]).toMatchObject({ up: null, loopback: null, scope: 'unreported', prefixLength: 24 });
        expect(fleetIdentityProjection(fleet(), 121000).get(source.id)?.status).toBe('stale');
        expect(fleetIdentityProjection(fleet(), 86400000).get(source.id)).toMatchObject({ status: 'expired', hostname: null, addresses: [] });
    });
    it('shows unavailable hostname, partial dual-stack and original Windows scope without inventing interface state', async () => {
        const v = item(); v.latest!.hostname = { ...v.latest!.hostname, quality: 'unavailable', complete: false, countExact: false, observedCount: 0, rows: [] };
        v.latest!.network = { ...v.latest!.network, quality: 'partial', complete: false, truncated: true, observedCount: 3 };
        vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response(fleet(v)))); render(<Harness/>);
        await screen.findByText('192.0.2.40'); expect(screen.getByText('Hostname unavailable')).toBeVisible(); expect(screen.getByText('Unavailable')).toBeVisible(); expect(screen.getByText('Partially collected')).toBeVisible();
        const disclosure = document.querySelector('details')!; disclosure.open = true; fireEvent(disclosure, new Event('toggle'));
        await screen.findByText('2001:db8::40'); expect(screen.getByText('Reported by device · Windows LAN agent')).toBeVisible(); expect(screen.getByText('3 · truncated')).toBeVisible(); expect(screen.getByText(/Interface state unknown/)).toBeVisible();
        expect(screen.getByText('Fixture Ethernet · IPV6 /64')).toBeVisible(); expect(screen.queryByText(/· down/)).not.toBeInTheDocument();
        fireEvent.change(screen.getByLabelText('Search'), { target: { value: '2001:db8::40' } }); expect(screen.getAllByRole('row')).toHaveLength(2);
    });
    it('renders hostile Windows hostname as inert text', async () => {
        const v = item(); v.latest!.hostname.rows[0].value = '<img src=x onerror=alert(1)>';
        vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response(fleet(v)))); const { container } = render(<Harness/>);
        await screen.findByText('<img src=x onerror=alert(1)>'); expect(container.querySelector('img')).toBeNull();
    });
    it('removes original certificate-expired values from display and search while idle', async () => {
        vi.useFakeTimers(); const v = item(); v.expiresAt = '2026-10-07T12:00:11Z';
        vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response(fleet(v)))); render(<Harness/>);
        await act(async () => { await vi.advanceTimersByTimeAsync(0); }); expect(screen.getByText('fixture-windows')).toBeVisible();
        await act(async () => { await vi.advanceTimersByTimeAsync(1100); }); expect(screen.queryByText('fixture-windows')).not.toBeInTheDocument(); expect(screen.queryByText('192.0.2.40')).not.toBeInTheDocument(); expect(screen.getByText('Expired')).toBeVisible();
    });
    it('drops retained values and late replies after logout, allowing only a newly authenticated session', async () => {
        let finish!: (v: Response) => void;
        const fetch = vi.fn().mockResolvedValueOnce(response(fleet())).mockImplementationOnce(() => new Promise(resolve => { finish = resolve; })).mockResolvedValue(response(fleet())); vi.stubGlobal('fetch', fetch);
        const ui = render(<Harness/>); await screen.findByText('fixture-windows'); refresh(); await waitFor(() => expect(finish).toBeDefined());
        act(() => { abortProtectedRequests(); window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT)); });
        await act(async () => finish(response(fleet()))); expect(screen.queryByText('fixture-windows')).not.toBeInTheDocument(); expect(screen.getByRole('alert')).toHaveTextContent('Session ended');
        ui.rerender(<Harness session="session-b"/>); await screen.findByText('fixture-windows');
    });
    it('does not resurrect a reply from an old session while the new request is pending', async () => {
        let finish!: (v: Response) => void;
        const fetch = vi.fn().mockImplementationOnce(() => new Promise(resolve => { finish = resolve; })).mockImplementation(() => new Promise(() => {})); vi.stubGlobal('fetch', fetch);
        const ui = render(<Harness/>); await waitFor(() => expect(finish).toBeDefined()); const signal = fetch.mock.calls[0][1].signal;
        ui.rerender(<Harness session="session-b"/>); expect(signal.aborted).toBe(true);
        await act(async () => finish(response(fleet()))); expect(screen.queryByText('fixture-windows')).not.toBeInTheDocument();
    });
});
