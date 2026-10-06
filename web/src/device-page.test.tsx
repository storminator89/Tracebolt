import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import App from './App';
import { AUTH_REQUIRED_EVENT, request } from './api';
import { setLocale } from './i18n';
import type { Device, Metric, Overview } from './types';
import type { OperationalView } from './operational-types';
import { emptyEndpointView } from './endpoint-identity-fixtures';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn() }));
const id = `agent_${'7'.repeat(32)}`, secondID = `agent_${'8'.repeat(32)}`;
const now = '2026-10-04T00:00:10Z';
const session = { mode: 'lan', transport: 'https', insecureTestMode: false, transportWarning: null, authenticationRequired: true, authenticated: true, csrfToken: 'synthetic-session', serverNow: now, expiresAt: '2026-10-04T00:30:00Z', expiresInSeconds: 1800 };
const metric: Metric = { value: null, unit: '%', quality: 'unknown', source: 'Synthetic page fixture', collectedAt: '0001-01-01T00:00:00Z' };
function device(deviceID = id): Device {
 return { id: deviceID, name: deviceID === id ? 'Synthetic Linux fixture' : 'Synthetic second fixture', platform: 'linux', os: 'Linux fixture', site: 'Fixture', group: 'Fixture', ip: null, status: 'unknown', source: 'lan', synthetic: false, lastSeen: '0001-01-01T00:00:00Z', agentVersion: 'fixture', cpu: metric, memory: metric, disk: metric, uptime: '', tags: [], capabilities: [{ id: 'logs', name: 'Raw logs', detail: 'Not collected by this fixture.', status: 'unsupported' }], evidence: [], trend: [], caseIds: [] };
}
function operational(): OperationalView {
 return { schemaVersion: 'tracebolt.operational-view.v1', deviceId: id, status: 'not_configured', serverNow: now, receivedAt: null, sequence: null, maxAgeSeconds: 120, snapshot: null, lastGood: { volumes: null, network: null, services: null, processes: null, software: null, events: null }, assessments: { updates: { quality: 'unknown', reason: 'not_implemented' }, vulnerabilities: { quality: 'unknown', reason: 'not_implemented' } } };
}
function answer(path: string) {
 if (path === '/auth/session') return session;
 if (path === '/enrollment') return { schemaVersion: 'tracebolt.enrollment-operator.v2', serverNow: now, enabled: false, platforms: [], recordLimit: 25, items: [] };
 if (path === '/investigations?scope=open&offset=0') return { schemaVersion: 'tracebolt.investigations.v1', serverNow: now, scope: 'open', offset: 0, total: 0, counts: { open: 0, recovered: 0, closed: 0, all: 0 }, devices: [], items: [] };
 if (path === '/overview') return { product: 'Synthetic Tracebolt', mode: 'lan', generatedAt: now, stats: { totalDevices: 2, healthyDevices: 0, attentionDevices: 0, unknownDevices: 2, openCases: 0, criticalCases: 0 }, devices: [device(), device(secondID)], cases: [], activity: [] } satisfies Overview;
 if (path === `/devices/${id}/operational`) return operational();
 if (path === `/devices/${id}/inventory/endpoint-identity`) return emptyEndpointView();
 if (path === `/devices/${secondID}/inventory/endpoint-identity`) return { ...emptyEndpointView(), deviceId: secondID };
 if (path === `/devices/${id}`) return device();
 if (path === `/devices/${secondID}`) return device(secondID);
 throw new Error('Unexpected synthetic route');
}
async function navigate(path: string) {
 await act(async () => { window.history.replaceState({}, '', `/#/${path}`); window.dispatchEvent(new HashChangeEvent('hashchange')); });
}
async function open() { await navigate(`devices/${id}`); render(<App/>); return screen.findByRole('region', { name: 'Device Synthetic Linux fixture' }); }
beforeEach(() => {
 setLocale('en', false); localStorage.clear(); sessionStorage.clear(); window.history.replaceState({}, '', '/');
 vi.mocked(request).mockReset().mockImplementation(async path => answer(path));
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

describe('dedicated device page', () => {
 it('keeps the first Tab on the skip link when initially opening the device list', async () => {
  await navigate('devices'); render(<App/>); await screen.findByLabelText('Search devices');
  expect(screen.getByRole('main')).not.toHaveFocus(); await userEvent.tab();
  expect(screen.getByRole('link', { name: 'Skip to content' })).toHaveFocus();
 });
 it('replaces inventory with a full-width page, compact identity/status and collapsed technical details', async () => {
  const page = await open(); expect(screen.getByRole('main')).toContainElement(page);
  expect(page).toHaveClass('device-page'); expect(screen.getByRole('main')).toHaveClass('device-main');
  expect(within(page).getByRole('region', { name: 'Resources' })).toBeVisible();
  expect(page.querySelector('.software-overview')).toBeNull(); expect(page.querySelector('.agent-certificate')).toBeNull();
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument(); expect(document.body.style.overflow).not.toBe('hidden');
  expect(within(page).getByRole('heading', { name: 'Synthetic Linux fixture', level: 1 })).toBeVisible();
  expect(within(page).getByText('Not assessed', { selector: '.status' })).toBeVisible();
  expect(within(page).getByText('Time unknown', { selector: '.detail-time' })).toBeVisible(); expect(page).not.toHaveTextContent('0001');
  expect(screen.queryByLabelText('Search devices')).not.toBeInTheDocument(); expect(screen.queryByRole('button', { name: 'Add device' })).not.toBeInTheDocument();
  fireEvent.click(within(page).getByRole('tab', { name: 'Details' }));
  const technical = within(page).getByText('Device profile & technical details').closest('details')!;
  expect(technical).not.toHaveAttribute('open'); expect(within(technical).queryByText('IP address')).not.toBeInTheDocument();
  expect(within(page).getByRole('heading', { name: 'Hostname & interface addresses' })).toBeVisible();
  fireEvent.click(within(technical).getByText('Device profile & technical details'));
  expect(technical).toHaveAttribute('open'); expect(within(technical).getByText('Device name')).toBeVisible();
  fireEvent.click(within(page).getByRole('tab', { name: /^Capabilities/ }));
  expect(within(page).getByText('Raw logs')).toBeVisible(); expect(within(page).getByText('Unavailable', { selector: '.capability-state' })).toBeVisible();
 });
 it('returns to the inventory with one click and restores a keyboard focus target', async () => {
  const page = await open(); fireEvent.click(within(page).getByRole('button', { name: 'Back to devices' }));
  await screen.findByRole('heading', { name: 'Devices', level: 1 }); expect(window.location.hash).toBe('#/devices');
  expect(screen.queryByRole('region', { name: 'Device Synthetic Linux fixture' })).not.toBeInTheDocument();
  expect(screen.getByLabelText('Search devices')).toBeVisible(); expect(screen.getByRole('main')).toHaveFocus();
 });
 it('preserves Escape without closing the device when a keyboard-help modal owns dismissal', async () => {
  const page = await open(); fireEvent.keyDown(window, { key: '?' });
  await screen.findByRole('dialog', { name: 'Keyboard shortcuts' }); fireEvent.keyDown(document, { key: 'Escape' });
  await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument()); expect(page).toBeInTheDocument();
  expect(window.location.hash).toBe(`#/devices/${id}`);
  fireEvent.keyDown(document, { key: 'Escape' }); await screen.findByRole('heading', { name: 'Devices', level: 1 });
  expect(window.location.hash).toBe('#/devices');
 });
 it('aborts an inventory read on Back and discards late data after reopening from its hash', async () => {
  let finish!: (value: OperationalView) => void; let signal: AbortSignal | undefined;
  vi.mocked(request).mockImplementation(async (path, options) => path === `/devices/${id}/operational` ? new Promise<OperationalView>(resolve => { finish = resolve; signal = options?.signal as AbortSignal; }) : answer(path));
  const page = await open(); fireEvent.click(within(page).getByRole('tab', { name: 'Inventory' })); fireEvent.click(screen.getByText('Legacy inventory source', { selector: 'summary' })); fireEvent.click(screen.getByRole('button', { name: 'Open bounded preview' })); await waitFor(() => expect(signal).toBeDefined());
  fireEvent.click(within(page).getByRole('button', { name: 'Back to devices' })); await screen.findByLabelText('Search devices');
  expect(signal!.aborted).toBe(true); await act(async () => finish(operational())); expect(screen.queryByText('Operational inventory')).not.toBeInTheDocument();
  await navigate(`devices/${id}`); const restored = await screen.findByRole('region', { name: 'Device Synthetic Linux fixture' });
  expect(within(restored).getByRole('tab', { name: 'Overview' })).toHaveAttribute('aria-selected', 'true');
  await navigate(`devices/${secondID}`); await screen.findByRole('region', { name: 'Device Synthetic second fixture' });
  expect(screen.queryByRole('region', { name: 'Device Synthetic Linux fixture' })).not.toBeInTheDocument();
 });
 it('conceals the entire device on pagehide and only restores after session revalidation', async () => {
  await open(); act(() => window.dispatchEvent(new Event('pagehide')));
  expect(screen.queryByRole('region', { name: 'Device Synthetic Linux fixture' })).not.toBeInTheDocument();
  const restored = new Event('pageshow'); Object.defineProperty(restored, 'persisted', { value: true }); act(() => window.dispatchEvent(restored));
  await screen.findByRole('region', { name: 'Device Synthetic Linux fixture' });
  expect(vi.mocked(request).mock.calls.filter(([path]) => path === '/auth/session')).toHaveLength(2);
  act(() => window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT))); await screen.findByLabelText('Operator password');
  expect(screen.queryByRole('region', { name: 'Device Synthetic Linux fixture' })).not.toBeInTheDocument();
  expect(screen.queryByRole('tab')).not.toBeInTheDocument();
 });
 it('keeps a direct device route readable even when the separate fleet overview request fails', async () => {
  vi.mocked(request).mockImplementation(async path => { if (path === '/investigations?scope=open&offset=0') return { schemaVersion: 'tracebolt.investigations.v1', serverNow: now, scope: 'open', offset: 0, total: 0, counts: { open: 0, recovered: 0, closed: 0, all: 0 }, devices: [], items: [] };
 if (path === '/overview') throw new Error('Synthetic overview unavailable'); return answer(path); });
  const page = await open(); expect(within(page).getByRole('heading', { name: 'Synthetic Linux fixture' })).toBeVisible();
  expect(within(page).getByRole('button', { name: 'Back to devices' })).toBeEnabled();
  expect(screen.getByRole('alert')).toHaveTextContent('Synthetic overview unavailable');
 });
});

it('keeps shell and loaded fleet data on ordinary menu navigation without reauth or document reload', async () => {
 await navigate('devices'); render(<App/>); await screen.findByLabelText('Search devices');
 expect(screen.getByRole('columnheader', { name: 'Overall health' })).toBeVisible();
 fireEvent.change(screen.getByLabelText('Search devices'), { target: { value: 'Synthetic' } });
 const sidebar = screen.getByRole('complementary', { name: 'Main navigation' });
 fireEvent.click(within(sidebar).getByRole('button', { name: 'Overview' })); await screen.findByRole('heading', { name: 'Overview', level: 1 });
 fireEvent.click(within(sidebar).getByRole('button', { name: /Devices/ })); await screen.findByLabelText('Search devices');
 expect(screen.getByLabelText('Search devices')).toHaveValue('Synthetic');
 expect(screen.getByRole('complementary', { name: 'Main navigation' })).toBe(sidebar);
 expect(vi.mocked(request).mock.calls.filter(([path]) => path === '/overview')).toHaveLength(1);
 expect(vi.mocked(request).mock.calls.filter(([path]) => path === '/auth/session')).toHaveLength(1);
});

it('removes duplicate overview/list explanations while retaining explicit source and unassessed-state labels', async () => {
 await navigate('overview'); render(<App/>); await screen.findByRole('heading', { name: 'Overview', level: 1 });
 expect(document.querySelector('.page-heading .eyebrow')).toBeNull(); expect(document.querySelector('.page-heading p')).toBeNull();
 expect(screen.queryByText('Rule-based findings. Sources included.')).not.toBeInTheDocument(); expect(screen.queryByText('Sources clearly labelled')).not.toBeInTheDocument();
 expect(await screen.findByText('No open health incidents in the retained history. Missing cases do not mean a healthy device.')).toBeVisible();
 expect(screen.getAllByText('LAN agent').length).toBeGreaterThan(0); expect(screen.getByRole('columnheader', { name: 'Overall health' })).toBeVisible();
 const sidebar = screen.getByRole('complementary', { name: 'Main navigation' }); fireEvent.click(within(sidebar).getByRole('button', { name: /Devices/ })); await screen.findByLabelText('Search devices');
 expect(document.querySelector('.page-heading .eyebrow')).toBeNull(); expect(document.querySelector('.page-heading p')).toBeNull();
 expect(screen.queryByText('Sources and data quality stay visible.')).not.toBeInTheDocument(); expect(document.querySelector('.inventory-panel .table-footer')).toHaveTextContent('2 of 2 devices');
 expect(screen.getByLabelText('Filter by operating system')).toBeVisible(); expect(screen.getByLabelText('Filter by status')).toBeVisible(); expect(screen.getByLabelText('Sort devices')).toBeVisible();
 expect(vi.mocked(request).mock.calls.filter(([path]) => path === '/overview')).toHaveLength(1);
});
