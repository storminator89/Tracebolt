import { useState } from 'react';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, AUTH_REQUIRED_EVENT } from './api';
import { DeviceTable } from './components';
import { FleetIdentityNotice } from './fleet-identity';
import { useFleetIdentity } from './fleet-identity-resource';
import { FLEET_IDENTITY_BYTES, fleetIdentityProjection, validFleetIdentityView } from './fleet-identity-types';
import type { FleetIdentityView } from './fleet-identity-types';
import { emptyEndpointView, endpointComplete, endpointDevice, endpointFailed, endpointView } from './endpoint-identity-fixtures';
import { setLocale } from './i18n';
import type { Device } from './types';
import { defaultFilters, filterDevices } from './utils';
const response = (v: unknown, status = 200) => new Response(JSON.stringify(v), { status });
const fleet = (): FleetIdentityView => ({ schemaVersion: 'tracebolt.fleet-endpoint-identity.v1', serverNow: endpointView().serverNow, items: [endpointView()] });
function device(id = endpointDevice): Device {
 const metric = { value: null, unit: '%', quality: 'unknown' as const, source: 'fixture', collectedAt: '0001-01-01T00:00:00Z' };
 return { id, name: id, platform: 'linux', os: 'Linux', source: 'lan', synthetic: false, status: 'unknown', site: '', group: 'Lab', ip: '198.51.100.250', lastSeen: '0001-01-01T00:00:00Z', agentVersion: 'fixture', cpu: metric, memory: metric, disk: metric, uptime: '', tags: [], capabilities: [], evidence: [], trend: [], caseIds: [] };
}
function Harness({ enabled = true, revision = '', onSelect = vi.fn() }: { enabled?: boolean; revision?: string; onSelect?: (d: Device) => void }) {
 const resource = useFleetIdentity(enabled, 'session-a', revision), [query, setQuery] = useState('');
 return <><input aria-label="Search" value={query} onChange={e => setQuery(e.target.value)}/><FleetIdentityNotice resource={resource}/><DeviceTable devices={filterDevices([device()], { ...defaultFilters, query }, resource.identities)} identities={resource.identities} onSelect={onSelect}/></>;
}
const refresh = () => fireEvent.click(screen.getByRole('button', { name: 'Refresh hostnames and IP addresses' }));
beforeEach(() => setLocale('en', false));
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });
describe('bounded fleet identity', () => {
 it('strictly validates complete batches, record bounds, unique ordered IDs and synchronized clocks', () => {
  expect(validFleetIdentityView(fleet())).toBe(true); expect(validFleetIdentityView({ ...fleet(), items: [] })).toBe(true);
  for (const bad of [{ ...fleet(), extra: true }, { ...fleet(), items: [endpointView(), endpointView()] }, { ...fleet(), serverNow: '2026-10-04T12:00:11Z' }, { ...fleet(), serverNow: '2026-02-31T12:00:00Z', items: [] }, { ...fleet(), items: Array.from({ length: 26 }, (_, i) => ({ ...endpointView(), deviceId: `agent_${String(i).padStart(32, '0')}` })) }]) expect(validFleetIdentityView(bad)).toBe(false);
  const bad = fleet(); bad.items[0].latest!.interfaces.items[1].addresses.ipv4.items[0].address = 'host.invalid'; expect(validFleetIdentityView(bad)).toBe(false);
 });
 it('keeps a healthy member when a collected sibling crosses its certificate boundary', () => {
  const value = fleet(); value.items.push({ ...emptyEndpointView('expired'), deviceId: 'agent_88888888888888888888888888888888' });
  expect(validFleetIdentityView(value)).toBe(true); const display = fleetIdentityProjection(value, 0); expect(display.get(endpointDevice)?.hostname).toBe('fixture-linux'); expect(display.get(value.items[1].deviceId)?.status).toBe('expired'); expect(display.get(value.items[1].deviceId)?.addresses).toEqual([]);
  value.items[1].latest = endpointView().latest; expect(validFleetIdentityView(value)).toBe(false);
 });
 it('searches all scoped addresses and sorts by reported hostname without modifying Device or trusting a LAN peer IP', () => {
  const source = device(), before = JSON.stringify(source), display = fleetIdentityProjection(fleet(), 0), other = { ...device('agent_zz'), name: 'bbb' };
  for (const query of ['fixture-linux', 'fe80::19', source.id]) expect(filterDevices([source], { ...defaultFilters, query }, display)).toEqual([source]);
  expect(filterDevices([source], { ...defaultFilters, query: source.ip! }, display)).toEqual([]);
  expect(filterDevices([source, other], { ...defaultFilters, sort: 'name' }, display).map(d => d.id)).toEqual([other.id, source.id]); expect(JSON.stringify(source)).toBe(before);
  expect(fleetIdentityProjection(fleet(), 121000).get(source.id)?.status).toBe('stale'); expect(filterDevices([source], { ...defaultFilters, query: 'fixture-linux' }, fleetIdentityProjection(fleet(), 86400000))).toEqual([]);
 });
 it('makes one protected batch request, shows primary hostname and scoped multiple addresses, and selects the original stable Device', async () => {
  const fetch = vi.fn().mockResolvedValue(response(fleet())), onSelect = vi.fn(); vi.stubGlobal('fetch', fetch); render(<Harness onSelect={onSelect}/>); await screen.findByText('fixture-linux');
  expect(fetch).toHaveBeenCalledTimes(1); expect(fetch.mock.calls[0][0]).toBe('/api/fleet/endpoint-identities'); expect(fetch.mock.calls[0][1]).toMatchObject({ credentials: 'same-origin', headers: { Accept: 'application/json' } }); expect(fetch.mock.calls[0][1].method).toBeUndefined(); expect(fetch.mock.calls[0][1].body).toBeUndefined();
  const row = screen.getAllByRole('row')[1]; for (const text of ['192.0.2.19', '2001:db8::19', '+3 more in device details', `ID: ${endpointDevice}`]) expect(within(row).getByText(text)).toBeVisible();
  expect(row.querySelector('.fleet-identity-addresses')).toHaveAttribute('title', expect.stringContaining('fe80::19 · eth0 #2 · link-local')); expect(within(row).queryByText('198.51.100.250')).not.toBeInTheDocument(); expect(within(row).queryByRole('link')).not.toBeInTheDocument();
  fireEvent.click(within(row).getByRole('button', { name: 'Open details: fixture-linux' })); expect(onSelect).toHaveBeenCalledWith(device()); fireEvent.change(screen.getByLabelText('Search'), { target: { value: 'fe80::19' } }); expect(screen.getAllByRole('row')).toHaveLength(2); expect(fetch).toHaveBeenCalledTimes(1);
 });
 it('renders hostile text inertly and distinguishes missing hostname, partial addresses, denied reads and successful emptiness', async () => {
  const value = fleet(); value.items[0].latest!.reportedHostname.value = '<img src=x onerror=alert(1)>'; const fetch = vi.fn().mockResolvedValue(response(value)); vi.stubGlobal('fetch', fetch); const { container } = render(<Harness/>); await screen.findByText('<img src=x onerror=alert(1)>'); expect(container.querySelector('img')).toBeNull();
  value.items[0].latest!.reportedHostname = { coverage: 'failed', reason: 'permission_denied', value: null }; value.items[0].latest!.interfaces.meta = { ...endpointComplete(2), coverage: 'partial', reason: 'address_unavailable' }; value.items[0].latest!.interfaces.items[1].addresses.ipv6 = { meta: endpointFailed(), items: [] };
  fetch.mockResolvedValue(response(value)); refresh(); await screen.findByText('Permission denied'); expect(screen.getByText('192.0.2.19')).toBeVisible(); expect(screen.getByText('Partially collected')).toBeVisible();
  value.items[0].latest!.interfaces = { meta: endpointComplete(0), items: [] }; fetch.mockResolvedValue(response(value)); refresh(); await screen.findByText('No IP addresses reported');
  value.items[0].latest!.interfaces = { meta: endpointFailed('read_failed'), items: [] }; fetch.mockResolvedValue(response(value)); refresh(); await screen.findByText('IP addresses unavailable · Collection failed');
 });
 it.each(['not_collected', 'revoked', 'expired', 'unknown'] as const)('shows %s without guessed or last-good identity', async status => {
  const value = fleet(); value.items = [emptyEndpointView(status)]; vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response(value))); render(<Harness/>); await waitFor(() => expect(screen.getByRole('button', { name: 'Refresh hostnames and IP addresses' })).toBeEnabled());
  expect(screen.getByText('Hostname unavailable')).toBeVisible(); expect(screen.queryByText('fixture-linux')).not.toBeInTheDocument(); expect(screen.queryByText('198.51.100.250')).not.toBeInTheDocument(); expect(screen.getByText(`Reported by device · ${status === 'not_collected' ? 'Not collected' : status[0].toUpperCase() + status.slice(1)}`)).toBeVisible();
 });
 it('requests nothing when disabled and one bounded batch for 25 records', async () => {
  const value = fleet(); value.items = Array.from({ length: 25 }, (_, i) => ({ ...endpointView(), deviceId: `agent_${String(i).padStart(32, '0')}` })); const fetch = vi.fn().mockResolvedValue(response(value)); vi.stubGlobal('fetch', fetch); const { rerender } = render(<Harness enabled={false}/>); expect(fetch).not.toHaveBeenCalled(); rerender(<Harness/>); await waitFor(() => expect(fetch).toHaveBeenCalledTimes(1)); await waitFor(() => expect(screen.getByRole('button', { name: 'Refresh hostnames and IP addresses' })).toBeEnabled()); expect(screen.queryByRole('alert')).not.toBeInTheDocument();
 });
 it('clears failed refresh and delayed data on session loss', async () => {
  let finish!: (v: Response) => void; const fetch = vi.fn().mockResolvedValueOnce(response(fleet())).mockResolvedValueOnce(response({}, 503)).mockImplementationOnce(() => new Promise(resolve => { finish = resolve; })); vi.stubGlobal('fetch', fetch); render(<Harness/>); await screen.findByText('fixture-linux'); refresh(); expect(screen.queryByText('fixture-linux')).not.toBeInTheDocument(); await screen.findByRole('alert'); refresh(); await waitFor(() => expect(finish).toBeDefined()); act(() => { abortProtectedRequests(); window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT)); }); await act(async () => finish(response(fleet()))); expect(screen.queryByText('fixture-linux')).not.toBeInTheDocument(); expect(screen.getByRole('alert')).toHaveTextContent('Session ended'); act(() => window.dispatchEvent(new Event('focus'))); expect(fetch).toHaveBeenCalledTimes(3);
 });
 it('suspends on blur, reads freshly on focus, and ignores responses from an older route', async () => {
  const fetch = vi.fn().mockImplementation(() => Promise.resolve(response(fleet()))); vi.stubGlobal('fetch', fetch); const { rerender } = render(<Harness/>); await screen.findByText('fixture-linux'); act(() => window.dispatchEvent(new Event('blur'))); expect(screen.queryByText('fixture-linux')).not.toBeInTheDocument(); act(() => window.dispatchEvent(new Event('focus'))); await screen.findByText('fixture-linux'); expect(fetch).toHaveBeenCalledTimes(2);
  let finish!: (v: Response) => void; fetch.mockImplementationOnce(() => new Promise(resolve => { finish = resolve; })); refresh(); await waitFor(() => expect(finish).toBeDefined()); rerender(<Harness enabled={false} revision="details"/>); await act(async () => finish(response(fleet()))); expect(screen.queryByText('fixture-linux')).not.toBeInTheDocument(); rerender(<Harness revision="devices"/>); await screen.findByText('fixture-linux'); expect(fetch).toHaveBeenCalledTimes(4);
 });
 it('rejects oversized bytes and invalid batches without visible values', async () => {
  let canceled = false; const stream = new ReadableStream({ start(c) { c.enqueue(new TextEncoder().encode(' '.repeat(FLEET_IDENTITY_BYTES + 1))); }, cancel() { canceled = true; } }); const fetch = vi.fn().mockResolvedValueOnce(new Response(stream)).mockResolvedValueOnce(response({ ...fleet(), items: [endpointView(), endpointView()] })); vi.stubGlobal('fetch', fetch); render(<Harness/>); await screen.findByRole('alert'); expect(canceled).toBe(true); refresh(); await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('Invalid identity data')); expect(screen.queryByText('fixture-linux')).not.toBeInTheDocument();
 });
 it('locks after real HTTP 401 and cannot restore on focus', async () => {
  const fetch = vi.fn().mockResolvedValue(response({}, 401)); vi.stubGlobal('fetch', fetch); render(<Harness/>); await screen.findByRole('alert'); expect(screen.getByRole('button', { name: 'Refresh hostnames and IP addresses' })).toBeDisabled(); act(() => window.dispatchEvent(new Event('focus'))); expect(fetch).toHaveBeenCalledTimes(1);
 });
 it('ages and expires original metadata while idle', async () => {
  vi.useFakeTimers(); const value = fleet(); value.serverNow = value.items[0].serverNow = '2026-10-05T11:59:59Z'; value.items[0].status = 'stale'; vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response(value))); render(<Harness/>); await act(async () => { await vi.advanceTimersByTimeAsync(0); }); expect(screen.getByText('fixture-linux')).toBeVisible(); expect(screen.getByText('Reported by device · Stale')).toBeVisible(); await act(async () => { await vi.advanceTimersByTimeAsync(1100); }); expect(screen.queryByText('fixture-linux')).not.toBeInTheDocument(); expect(screen.queryByText('192.0.2.19')).not.toBeInTheDocument(); expect(screen.getByText('Reported by device · Expired')).toBeVisible();
 });
 it('retries only exact storage_busy once within its original deadline', async () => {
  vi.useFakeTimers(); const fetch = vi.fn().mockResolvedValueOnce(response({ error: { code: 'storage_busy' } }, 429)).mockResolvedValueOnce(response(fleet())); vi.stubGlobal('fetch', fetch); render(<Harness/>);
  await act(async () => { await vi.advanceTimersByTimeAsync(0); }); expect(fetch).toHaveBeenCalledTimes(1); await act(async () => { await vi.advanceTimersByTimeAsync(2001); }); expect(fetch).toHaveBeenCalledTimes(2); expect(screen.getByText('fixture-linux')).toBeVisible();
 });
 it('drops stalled reads at ten seconds and rejects an unreliable clock anchor', async () => {
  vi.useFakeTimers(); const fetch = vi.fn().mockImplementationOnce(() => new Promise(() => {})).mockResolvedValueOnce(response(fleet())); vi.stubGlobal('fetch', fetch); render(<Harness/>); await act(async () => { await vi.advanceTimersByTimeAsync(10001); }); expect(screen.getByRole('alert')).toHaveTextContent('timed out'); refresh(); await act(async () => { await vi.advanceTimersByTimeAsync(0); }); expect(screen.getByText('fixture-linux')).toBeVisible(); vi.setSystemTime(Date.now() + 10000); await act(async () => { await vi.advanceTimersByTimeAsync(1000); }); expect(screen.queryByText('fixture-linux')).not.toBeInTheDocument(); expect(screen.getByRole('alert')).toHaveTextContent('Time check failed');
 });

});
