import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, APIError, mutateRaw, request } from './api';
import { useOperator } from './auth';
import { setLocale } from './i18n';
import { endpointView } from './endpoint-identity-fixtures';
import { fleetIdentityProjection, validFleetIdentityView } from './fleet-identity-types';
import type { FleetIdentityDisplay, FleetIdentityView } from './fleet-identity-types';
import { useFleetIdentity } from './fleet-identity-resource';
import { ProactiveAISettingsPanel } from './proactive-ai';
import { ProactiveDeviceIdentity, shortProactiveDeviceId } from './proactive-device-identity';
import type { ProactiveAISettings } from './proactive-ai-types';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutateRaw: vi.fn() }));
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
const id = 'agent_00000000000000000000000000000001', second = 'agent_00000000000000000000000000000002';
const settings = (): ProactiveAISettings => ({ schemaVersion: 'tracebolt.proactive-ai-settings.v1', revision: 'revision-a', enabled: false, configRevision: 'config-a', providerConfigured: true, baseURL: 'http://127.0.0.1:11434/v1', model: 'fixture-model', deviceIds: [], availableDevices: [{ id }, { id: second }], dataScope: 'health-summary-v1', logsAllowed: false, resetsOnRestart: true, maxAnalysesPerHour: 6, cooldownMinutes: 30, minIntervalSeconds: 60, reason: '' });
const fleet = (): FleetIdentityView => ({ schemaVersion: 'tracebolt.fleet-endpoint-identity.v1', serverNow: endpointView().serverNow, items: [{ ...endpointView(), deviceId: id }] });
const identity = (): FleetIdentityDisplay => fleetIdentityProjection(fleet(), 0).get(id)!;
const consent = () => screen.getByRole('checkbox', { name: /I approve future health-summary/ });
const selectedDevice = () => screen.getByRole('checkbox', { name: new RegExp(id) });
function Harness() { const fleetIdentity = useFleetIdentity(true, 'fixture-session'); return <ProactiveAISettingsPanel fleetIdentity={fleetIdentity}/>; }
async function open() { await screen.findByText('Off'); fireEvent.click(screen.getByRole('button', { name: 'Proactive AI diagnostics' })); }
beforeEach(() => {
    localStorage.clear(); sessionStorage.clear(); setLocale('en', false);
    vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('visible');
    vi.mocked(useOperator).mockReturnValue({ mode: 'lan', authenticated: true, loginMode: 'shared', expiresAt: null, insecureTestMode: false, logout: vi.fn(), theme: 'light', setTheme: vi.fn() });
    vi.mocked(request).mockReset(); vi.mocked(mutateRaw).mockReset();
    vi.mocked(request).mockImplementation(async path => path === '/ai/proactive' ? settings() : fleet());
});
afterEach(() => { cleanup(); abortProtectedRequests(); vi.restoreAllMocks(); });

describe('compact reported identity', () => {
    it('shows only two reported addresses with interface/scope and a secondary stable ID', () => {
        expect(validFleetIdentityView(fleet())).toBe(true);
        const { container } = render(<ProactiveDeviceIdentity identity={identity()} deviceId={id} deviceIds={[id, second]}/>);
        expect(screen.getByText('fixture-linux')).toBeVisible(); expect(screen.getByText('Reported · Recent')).toBeVisible();
        for (const address of ['192.0.2.19', '2001:db8::19']) expect(screen.getByText(address)).toBeVisible();
        expect(screen.getAllByText('eth0 · other')).toHaveLength(2); expect(screen.getByText('+3 more')).toBeVisible();
        expect(screen.queryByText('127.0.0.1')).not.toBeInTheDocument(); expect(screen.queryByRole('link')).not.toBeInTheDocument();
        expect(container.querySelectorAll('.proactive-device-address')).toHaveLength(2);
        expect(screen.getByTitle(`Agent ID: ${id}`)).toHaveTextContent('ID …00000001');
    });
    it('keeps duplicate or missing hostnames distinguishable, including colliding ID suffixes', () => {
        const other = 'agent_10000000000000000000000000000001';
        expect(shortProactiveDeviceId(id, [id, other])).not.toBe(shortProactiveDeviceId(other, [id, other]));
        const value = identity(); render(<><ProactiveDeviceIdentity identity={value} deviceId={id} deviceIds={[id, second]}/><ProactiveDeviceIdentity identity={value} deviceId={second} deviceIds={[id, second]}/></>);
        expect(screen.getAllByText('fixture-linux')).toHaveLength(2); expect(screen.getByText('ID …00000001')).toBeVisible(); expect(screen.getByText('ID …00000002')).toBeVisible();
    });
    it('labels stale data and removes expired observations without a hostname or address fallback', () => {
        const { rerender } = render(<ProactiveDeviceIdentity identity={fleetIdentityProjection(fleet(), 121000).get(id)} deviceId={id} deviceIds={[id]}/>);
        expect(screen.getByText('Reported · Stale')).toBeVisible(); expect(screen.getByText('fixture-linux')).toBeVisible();
        rerender(<ProactiveDeviceIdentity identity={fleetIdentityProjection(fleet(), 86400000).get(id)} deviceId={id} deviceIds={[id]}/>);
        expect(screen.getByText('Expired')).toBeVisible(); expect(screen.getByText('Hostname unavailable')).toBeVisible(); expect(screen.getByText('IP addresses unavailable')).toBeVisible(); expect(screen.queryByText('fixture-linux')).not.toBeInTheDocument(); expect(screen.queryByText('192.0.2.19')).not.toBeInTheDocument();
    });
    it('preserves empty, denied, partial and localized unavailable states and renders text inertly', () => {
        const value = { ...identity(), hostname: '<img src=x onerror=alert(1)>', coverage: 'partial' as const };
        const { container, rerender } = render(<ProactiveDeviceIdentity identity={value} deviceId={id} deviceIds={[id]}/>);
        expect(screen.getByText(value.hostname)).toBeVisible(); expect(container.querySelector('img')).toBeNull(); expect(screen.getByText('Partially collected')).toBeVisible();
        rerender(<ProactiveDeviceIdentity identity={{ ...value, hostname: null, hostnameReason: 'permission_denied', addresses: [], coverage: 'complete' }} deviceId={id} deviceIds={[id]}/>);
        expect(screen.getByText('Reported · Recent · Permission denied')).toBeVisible(); expect(screen.getByText('No IP addresses reported')).toBeVisible();
        act(() => setLocale('de', false)); rerender(<ProactiveDeviceIdentity identity={{ ...value, hostname: null, addresses: [], coverage: 'failed', addressReason: 'permission_denied' }} deviceId={id} deviceIds={[id]}/>);
        expect(screen.getByText('Hostname nicht verfügbar')).toBeVisible(); expect(screen.getByText('IP-Adressen nicht verfügbar · Zugriff verweigert')).toBeVisible();
    });
});

describe('display-only proactive device metadata', () => {
    it('uses one existing fleet read and retains exact selected IDs through metadata refresh and failures', async () => {
        render(<Harness/>); await open(); expect(selectedDevice()).toHaveAccessibleName(`fixture-linux · ${id}`);
        fireEvent.click(selectedDevice()); fireEvent.click(consent());
        let finish!: (value: unknown) => void;
        vi.mocked(request).mockImplementation(path => path === '/fleet/endpoint-identities' ? new Promise(resolve => { finish = resolve; }) : Promise.resolve(settings()));
        fireEvent.click(screen.getByRole('button', { name: 'Refresh hostnames and IP addresses' }));
        expect(screen.queryByText('fixture-linux')).not.toBeInTheDocument(); expect(screen.queryByText('192.0.2.19')).not.toBeInTheDocument(); expect(selectedDevice()).toBeChecked(); expect(consent()).toBeChecked();
        const changed = fleet(); changed.items[0].latest!.reportedHostname.value = 'fixture-renamed';
        await act(async () => finish(changed)); expect(selectedDevice()).toHaveAccessibleName(`fixture-renamed · ${id}`); expect(selectedDevice()).toBeChecked();
        vi.mocked(request).mockRejectedValue(new APIError('fixture identity read failed', 503));
        fireEvent.click(screen.getByRole('button', { name: 'Refresh hostnames and IP addresses' }));
        await screen.findByText('Reported hostnames and IP addresses are unavailable.'); expect(screen.queryByText('fixture-renamed')).not.toBeInTheDocument(); expect(selectedDevice()).toBeChecked();
        expect(vi.mocked(request).mock.calls.filter(([path]) => path === '/ai/proactive')).toHaveLength(1);
        expect(vi.mocked(request).mock.calls.filter(([path]) => path === '/fleet/endpoint-identities')).toHaveLength(3);
        vi.mocked(mutateRaw).mockResolvedValue({ ...settings(), revision: 'revision-b', enabled: true, deviceIds: [id] });
        fireEvent.click(screen.getByRole('button', { name: 'Approve and enable' }));
        await screen.findByText('Settings saved. No connectivity test was sent.');
        const body = vi.mocked(mutateRaw).mock.calls[0][1];
        expect(JSON.parse(body)).toEqual({ expectedRevision: 'revision-a', configRevision: 'config-a', enabled: true, deviceIds: [id], approvedBaseURL: settings().baseURL, approvedModel: settings().model, dataScope: 'health-summary-v1', acknowledgeData: true });
        for (const value of ['fixture-linux', 'fixture-renamed', '192.0.2.19', 'hostname', 'addresses']) expect(body).not.toContain(value);
    });
    it('clears invalid identity metadata while retaining the authorized device choices', async () => {
        render(<Harness/>); await open(); fireEvent.click(selectedDevice());
        vi.mocked(request).mockResolvedValue({ ...fleet(), unsupported: true }); fireEvent.click(screen.getByRole('button', { name: 'Refresh hostnames and IP addresses' }));
        await screen.findByText('Reported hostnames and IP addresses are unavailable.'); expect(selectedDevice()).toBeChecked(); expect(consent()).not.toBeChecked(); expect(screen.queryByText('fixture-linux')).not.toBeInTheDocument();
    });
    it('supports keyboard selection, explicit consent and Escape focus return', async () => {
        const user = userEvent.setup(); render(<Harness/>); await open();
        selectedDevice().focus(); await user.keyboard(' '); expect(selectedDevice()).toBeChecked(); expect(consent()).not.toBeChecked();
        consent().focus(); await user.keyboard(' '); expect(consent()).toBeChecked();
        await user.keyboard('{Escape}'); const toggle = screen.getByRole('button', { name: 'Proactive AI diagnostics' });
        expect(toggle).toHaveFocus(); expect(toggle).toHaveAttribute('aria-expanded', 'false'); expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();
        await user.keyboard('{Enter}'); await waitFor(() => expect(consent()).not.toBeChecked()); expect(selectedDevice()).not.toBeChecked();
    });
});
