import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
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
beforeEach(() => {
 setLocale('en', false); localStorage.clear(); sessionStorage.clear(); window.history.replaceState({}, '', '/');
 vi.mocked(request).mockReset().mockImplementation(async path => answer(path));
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

describe('device comparison in the inventory', () => {
 it('compares loaded rows without further requests, then opens the chosen existing device page', async () => {
  await navigate('devices'); render(<App/>);
  const button = await screen.findByRole('button', { name: 'Compare devices' }); await waitFor(() => expect(button).toBeEnabled());
  await act(async () => {}); vi.mocked(request).mockClear();
  fireEvent.click(button); fireEvent.change(screen.getByLabelText('Device 1'), { target: { value: id } }); fireEvent.change(screen.getByLabelText('Device 2'), { target: { value: secondID } });
  expect(screen.getByRole('table', { name: 'Compare devices' })).toBeVisible(); expect(request).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: `Open device: ${secondID}` }));
  await act(async () => { await vi.dynamicImportSettled(); });
  await screen.findByRole('region', { name: 'Device Synthetic second fixture' }); expect(window.location.hash).toBe(`#/devices/${secondID}`);
  expect(screen.queryByRole('table', { name: 'Compare devices' })).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Back to devices' })); await screen.findByLabelText('Search devices');
  fireEvent.click(screen.getByRole('button', { name: 'Compare devices' })); expect(screen.getByLabelText('Device 1')).toHaveValue('');
 });
 it('uses current inventory filters and does not silently restore a filtered-out comparison', async () => {
  await navigate('devices'); render(<App/>); const button = await screen.findByRole('button', { name: 'Compare devices' }); await waitFor(() => expect(button).toBeEnabled()); fireEvent.click(button);
  fireEvent.change(screen.getByLabelText('Device 1'), { target: { value: id } }); fireEvent.change(screen.getByLabelText('Device 2'), { target: { value: secondID } });
  fireEvent.change(screen.getByLabelText('Search devices'), { target: { value: 'second' } });
  expect(screen.queryByRole('table', { name: 'Compare devices' })).not.toBeInTheDocument(); expect(screen.getByLabelText('Device 1')).toHaveValue(''); expect(screen.getByLabelText('Device 2')).toHaveValue(secondID);
  fireEvent.change(screen.getByLabelText('Search devices'), { target: { value: '' } }); expect(screen.getByLabelText('Device 1')).toHaveValue('');
 });
 it('discards comparison content when authentication is lost', async () => {
  await navigate('devices'); render(<App/>); const button = await screen.findByRole('button', { name: 'Compare devices' }); await waitFor(() => expect(button).toBeEnabled()); fireEvent.click(button);
  fireEvent.change(screen.getByLabelText('Device 1'), { target: { value: id } }); fireEvent.change(screen.getByLabelText('Device 2'), { target: { value: secondID } });
  act(() => window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT)));
  expect(screen.queryByRole('table', { name: 'Compare devices' })).not.toBeInTheDocument(); expect(screen.queryByRole('combobox', { name: 'Device 1' })).not.toBeInTheDocument();
 });
});
