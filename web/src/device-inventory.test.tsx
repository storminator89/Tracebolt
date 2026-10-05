import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AUTH_REQUIRED_EVENT, mutateRaw, request } from './api';
import { AuthBoundary } from './auth';
import { DeviceDetail } from './details';
import { completePage, completeRows, completeView } from './complete-packages-fixtures';
import { serviceRows, socketRows, systemDevice, systemNow, systemPage, systemView } from './system-inventory-fixtures';
import { setLocale } from './i18n';
import type { Device, Metric } from './types';
import type { SystemPage } from './system-inventory-types';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutateRaw: vi.fn() }));
const metric: Metric = { value: null, unit: '%', quality: 'unknown', source: 'Synthetic fixture', collectedAt: '0001-01-01T00:00:00Z' };
const device: Device = { id: systemDevice, name: 'Synthetic system fixture', platform: 'linux', os: 'Linux fixture', site: 'Fixture', group: 'Fixture', ip: null, status: 'unknown', source: 'lan', synthetic: false, lastSeen: '0001-01-01T00:00:00Z', agentVersion: 'fixture', cpu: metric, memory: metric, disk: metric, uptime: '', tags: [], capabilities: [], evidence: [], trend: [], caseIds: [] };
const session = { mode: 'lan', transport: 'https', insecureTestMode: false, transportWarning: null, authenticationRequired: true, authenticated: true, csrfToken: 'fixture-session', serverNow: systemNow, expiresAt: '2026-10-04T01:00:00Z', expiresInSeconds: 3590 };
const operational = { schemaVersion: 'tracebolt.operational-view.v1', deviceId: systemDevice, status: 'not_configured', serverNow: systemNow, receivedAt: null, sequence: null, maxAgeSeconds: 120, snapshot: null, lastGood: { volumes: null, network: null, services: null, processes: null, software: null, events: null }, assessments: { updates: { quality: 'unknown', reason: 'not_implemented' }, vulnerabilities: { quality: 'unknown', reason: 'not_implemented' } } };
function packageView() { return { ...completeView(), deviceId: systemDevice }; }
function detail() { return <AuthBoundary><DeviceDetail id={systemDevice} onClose={vi.fn()} onCase={vi.fn()}/></AuthBoundary>; }
async function inventory() { render(detail()); fireEvent.click(await screen.findByRole('tab', { name: 'Inventory' })); fireEvent.click(screen.getByText('Legacy inventory source', { selector: 'summary' })); fireEvent.click(screen.getByRole('button', { name: 'Open bounded preview' })); return screen.getByRole('tablist', { name: 'Inventory source' }); }
beforeEach(() => {
    setLocale('en', false); localStorage.clear(); sessionStorage.clear();
    vi.mocked(request).mockReset().mockImplementation(async path => path === '/auth/session' ? session : path.endsWith('/operational') ? operational : path.endsWith('/inventory/system') ? systemView() : path.endsWith('/inventory/packages') ? packageView() : device);
    vi.mocked(mutateRaw).mockReset().mockImplementation(async (path, raw) => path.endsWith('/system/query') ? systemPage(systemView(), serviceRows(), socketRows(), raw) : completePage(packageView(), completeRows(), raw));
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

describe('inventory source tabs in the authenticated device drawer', () => {
    it('opens Packages directly from explicit device Details without eagerly reading any rows', async () => {
        render(detail()); fireEvent.click(await screen.findByRole('tab', { name: 'Details' })); const summary = await screen.findByRole('region', { name: 'Software · complete dpkg inventory' });
        await within(summary).findByText('Complete generation available'); expect(mutateRaw).not.toHaveBeenCalled();
        fireEvent.click(within(summary).getByRole('button', { name: 'Open Packages' }));
        await screen.findByRole('rowheader', { name: 'fixture-000000' });
        expect(screen.getByRole('tab', { name: 'Inventory' })).toHaveAttribute('aria-selected', 'true');
        expect(screen.getByRole('tab', { name: 'Packages' })).toHaveAttribute('aria-selected', 'true');
        expect(screen.getByRole('tab', { name: 'Packages' })).toHaveFocus();
        expect(vi.mocked(request).mock.calls.some(([path]) => path.endsWith('/operational'))).toBe(false);
        expect(vi.mocked(request).mock.calls.filter(([path]) => path.endsWith('/inventory/packages'))).toHaveLength(2);
        expect(screen.queryByRole('region', { name: 'Software · complete dpkg inventory' })).not.toBeInTheDocument();
        fireEvent.click(screen.getByRole('tab', { name: 'Overview' })); expect(screen.queryByRole('table')).not.toBeInTheDocument();
        fireEvent.click(screen.getByRole('tab', { name: 'Inventory' })); expect(screen.getByRole('tab', { name: 'Packages' })).toHaveAttribute('aria-selected', 'true');
    });
    it('keeps legacy preview bounded, lazily loads only selected sources, and replaces rather than stacks them', async () => {
        const tabs = await inventory(); expect(screen.getByRole('button', { name: 'Open bounded preview' })).toHaveAttribute('aria-pressed', 'true'); expect(vi.mocked(request).mock.calls.some(([path]) => path.endsWith('/inventory/system'))).toBe(false);
        fireEvent.click(within(tabs).getByRole('tab', { name: 'Services' })); await screen.findByRole('table'); expect(screen.queryByRole('heading', { name: 'Operational inventory' })).not.toBeInTheDocument(); expect(screen.getByRole('tabpanel', { name: 'Services' })).toHaveAttribute('aria-labelledby', within(tabs).getByRole('tab', { name: 'Services' }).id);
        fireEvent.click(within(tabs).getByRole('tab', { name: 'Connections' })); await screen.findByText('127.0.0.1:10000'); expect(screen.queryByRole('columnheader', { name: 'Service unit' })).not.toBeInTheDocument();
        fireEvent.click(within(tabs).getByRole('tab', { name: 'Packages' })); await screen.findByRole('rowheader', { name: 'fixture-000000' }); expect(screen.queryByRole('columnheader', { name: 'Local endpoint' })).not.toBeInTheDocument(); expect(screen.getAllByRole('table')).toHaveLength(1);
    });
    it('supports keyboard source navigation and resets source selection after leaving Inventory', async () => {
        const tabs = await inventory(), services = within(tabs).getByRole('tab', { name: 'Services' }); services.focus(); fireEvent.keyDown(services, { key: 'ArrowRight' }); expect(within(tabs).getByRole('tab', { name: 'Connections' })).toHaveFocus(); await screen.findByRole('table');
        fireEvent.click(screen.getByRole('tab', { name: 'Overview' })); expect(screen.queryByRole('table')).not.toBeInTheDocument(); fireEvent.click(screen.getByRole('tab', { name: 'Inventory' })); expect(screen.getByRole('tab', { name: 'Packages' })).toHaveAttribute('aria-selected', 'true');
    });
    it.each(['tab', 'auth', 'pagehide'] as const)('aborts pending system pages on %s and never installs late private results', async transition => {
        const tabs = await inventory(); let finish!: (value: SystemPage) => void, signal!: AbortSignal; vi.mocked(mutateRaw).mockImplementationOnce(async (_path, _raw, _headers, provided) => { signal = provided!; return new Promise<SystemPage>(resolve => { finish = resolve; }); });
        fireEvent.click(within(tabs).getByRole('tab', { name: 'Services' })); await waitFor(() => expect(signal).toBeDefined());
        if (transition === 'tab') fireEvent.click(screen.getByRole('tab', { name: 'Overview' })); if (transition === 'auth') { act(() => window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT))); await screen.findByLabelText('Operator password'); } if (transition === 'pagehide') act(() => window.dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true })));
        expect(signal.aborted).toBe(true); await act(async () => finish(systemPage(systemView(), serviceRows(), socketRows(), JSON.stringify({ section: 'services', cursor: '', search: '', filter: 'all', limit: 100 })))); expect(screen.queryByRole('rowheader', { name: 'fixture-000000.service' })).not.toBeInTheDocument();
    });
});
