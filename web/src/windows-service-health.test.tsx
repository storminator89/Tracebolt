import wireFixture from '../../tests/fixtures/windows-service-health-view.json';
import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, APIError, AUTH_REQUIRED_EVENT, mutateRaw, request } from './api';
import { useOperator } from './auth';
import { DeviceDetail } from './details';
import { setLocale } from './i18n';
import { windowsCapacityDevice, windowsCapacitySession, windowsCapacityView } from './windows-capacity-fixture';
import { windowsCapacityDeviceEligible } from './windows-capacity-types';
import { windowsContactView } from './windows-contact-fixture';
import { windowsDeviceId, windowsNow, windowsView } from './windows-inventory-fixture';
import { windowsResourceView } from './windows-resource-fixture';
import { WindowsServiceHealthPanel } from './windows-service-health';
import { windowsServiceHealthCopy } from './windows-service-health-copy';
import { windowsServiceHealthIncident, windowsServiceHealthView } from './windows-service-health-fixture';
import { useWindowsServiceHealth } from './windows-service-health-resource';
import type { WindowsServiceHealthView } from './windows-service-health-types';
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutateRaw: vi.fn() }));
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
const operator = { mode: 'lan' as const, authenticated: true, expiresAt: windowsCapacitySession, insecureTestMode: false, logout: vi.fn(), theme: 'light' as const, setTheme: vi.fn(), loginMode: 'shared' as const, hasExplicitMetadata: true };
function Harness({ device = windowsCapacityDevice(), session = windowsCapacitySession, metadataReady = true, enabled = true, admin = true, invalidateDraft = false }: { device?: ReturnType<typeof windowsCapacityDevice>; session?: string | null; metadataReady?: boolean; enabled?: boolean; admin?: boolean; invalidateDraft?: boolean }) {
    const resource = useWindowsServiceHealth(device.id, enabled && metadataReady && Boolean(session) && windowsCapacityDeviceEligible(device, device.id), session, admin, device.agentCertificate);
    return <WindowsServiceHealthPanel invalidateDraft={invalidateDraft} device={device} resource={resource} sessionKey={session} metadataReady={metadataReady} admin={admin}/>;
}
const flush = () => act(async () => {});
const advance = (ms: number) => act(async () => vi.advanceTimersByTimeAsync(ms));
const settings = () => fireEvent.click(screen.getByText('Selected-service policy settings & limits'));
const enable = () => fireEvent.click(screen.getByRole('checkbox', { name: 'Enable selected-service policy' }));
const choose = () => fireEvent.click(screen.getByRole('checkbox', { name: /Fixture Background Service/ }));
const save = () => fireEvent.click(screen.getByRole('button', { name: /^(Save selected-service policy|Saving policy…)$/ }));
const refresh = () => fireEvent.click(screen.getByRole('button', { name: 'Refresh selected-service policy' }));
const edit = () => { settings(); enable(); choose(); };
const selected = () => screen.getByRole('checkbox', { name: /Fixture Background Service/ });
const saved = () => windowsServiceHealthView('unknown');
const history = () => screen.queryByText('wservice_0000000000000001');
beforeEach(() => { abortProtectedRequests(); vi.useFakeTimers(); vi.setSystemTime(windowsNow); setLocale('en', false); vi.mocked(request).mockReset().mockResolvedValue(windowsServiceHealthView()); vi.mocked(mutateRaw).mockReset().mockResolvedValue(saved()); vi.mocked(useOperator).mockReturnValue(operator); });
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.restoreAllMocks(); });
describe('selected-service panel and private policy lifecycle', () => {
    it.each(Object.entries(wireFixture))('renders exact Go evaluator-produced %s response without rewriting evidence', async (_name, value) => {
        vi.setSystemTime(value.serverNow); const device = windowsCapacityDevice(); device.id = value.deviceId; device.agentCertificate!.checkedAt = value.serverNow; device.agentCertificate!.expiresAt = value.certificateExpiresAt;
        vi.mocked(request).mockResolvedValue(value); render(<Harness device={device} session={value.certificateExpiresAt}/>); await flush();
        expect(document.querySelector('.windows-capacity-assessment strong')).toHaveTextContent(windowsServiceHealthCopy.en[value.status as WindowsServiceHealthView['status']]);
        if (value.incidents.length) expect(screen.getByText(value.incidents[0].id)).toBeVisible();
        if (value.evaluatedAt) expect(document.querySelector(`time[datetime="${value.evaluatedAt}"]`)).not.toBeNull();
        expect(mutateRaw).not.toHaveBeenCalled();
    });
    it.each(['en', 'de'] as const)('shows scoped service states and original incident observations in %s', async locale => {
        setLocale(locale, false); const c = windowsServiceHealthCopy[locale]; vi.mocked(request).mockResolvedValue(windowsServiceHealthView('running')); render(<Harness/>); await flush(); expect(screen.getByText(c.running)).toBeVisible(); expect(screen.getByText(c.recovered)).toBeVisible(); expect(history()).toBeVisible(); expect(document.querySelector('time[datetime="2026-10-07T12:00:00Z"]')).not.toBeNull(); const summary = screen.getByText(c.settings); expect(summary.parentElement).not.toHaveAttribute('open'); fireEvent.click(summary); expect(screen.getByText(c.rules)).toBeVisible(); expect(screen.getByText(c.limits)).toBeVisible(); expect(screen.getByText(c.scopeLimit)).toBeVisible(); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('starts independently disabled and needs a deliberate selection, enable, and save', async () => {
        render(<Harness/>); await flush(); settings(); expect(screen.getByText('Policy disabled')).toBeVisible(); expect(screen.getByRole('checkbox', { name: 'Enable selected-service policy' })).not.toBeChecked(); expect(screen.getByRole('button', { name: 'Save selected-service policy' })).toBeDisabled(); enable(); expect(screen.getByRole('button', { name: 'Save selected-service policy' })).toBeDisabled(); choose(); expect(screen.getByRole('button', { name: 'Save selected-service policy' })).toBeEnabled(); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('posts only exact canonically sorted names and expected revision to the isolated policy endpoint', async () => {
        render(<Harness/>); await flush(); edit(); fireEvent.click(screen.getByRole('checkbox', { name: /Print Spooler/ })); save(); await flush(); expect(mutateRaw).toHaveBeenCalledOnce(); expect(vi.mocked(mutateRaw).mock.calls[0].slice(0, 2)).toEqual([`/devices/${windowsDeviceId}/windows-services/policy`, JSON.stringify({ enabled: true, services: ['FixtureService', 'Spooler'], expectedRevision: 0 })]); expect(vi.mocked(request).mock.calls.every(([path]) => path === `/devices/${windowsDeviceId}/windows-services`)).toBe(true);
    });
    it('does not claim a POST response was saved before a newer matching GET confirms it', async () => {
        render(<Harness/>); await flush(); edit(); save(); await flush(); expect(screen.getByText(/Save outcome is uncertain/)).toBeVisible(); expect(screen.queryByText('Current saved policy confirmed.')).toBeNull(); expect(screen.getByRole('button', { name: 'Save selected-service policy' })).toBeDisabled(); vi.mocked(request).mockResolvedValue(saved()); refresh(); await flush(); expect(screen.getByText('Current saved policy confirmed.')).toBeVisible(); expect(selected()).toBeChecked(); expect(mutateRaw).toHaveBeenCalledOnce();
    });
    it('preserves dirty exact names and enable state across a delayed same-revision refresh', async () => {
        render(<Harness/>); await flush(); edit(); let finish!: (v: WindowsServiceHealthView) => void; vi.mocked(request).mockReturnValueOnce(new Promise(resolve => { finish = resolve; })); refresh(); expect(screen.getByRole('checkbox', { name: 'Enable selected-service policy' })).toBeChecked(); expect(screen.getByRole('button', { name: 'Remove service: FixtureService' })).toBeVisible(); expect(screen.getByRole('button', { name: 'Save selected-service policy' })).toBeDisabled(); await act(async () => finish(windowsServiceHealthView())); expect(selected()).toBeChecked(); expect(screen.getByRole('button', { name: 'Save selected-service policy' })).toBeEnabled(); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('drops an obsolete draft on a newer revision and exposes conflict without posting', async () => {
        render(<Harness/>); await flush(); edit(); const newer = windowsServiceHealthView(); newer.policy = { enabled: false, services: ['Spooler'], revision: 1 }; newer.checks = [{ name: 'Spooler', status: 'unknown', observation: null }]; vi.mocked(request).mockResolvedValue(newer); refresh(); await flush(); expect(selected()).not.toBeChecked(); expect(screen.getByRole('checkbox', { name: /Print Spooler/ })).toBeChecked(); expect(screen.getByRole('checkbox', { name: 'Enable selected-service policy' })).not.toBeChecked(); expect(screen.getByText(/save conflicted/)).toBeVisible(); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('discards changes without writing', async () => { render(<Harness/>); await flush(); edit(); fireEvent.click(screen.getByRole('button', { name: 'Discard changes' })); expect(selected()).not.toBeChecked(); expect(screen.getByRole('checkbox', { name: 'Enable selected-service policy' })).not.toBeChecked(); expect(mutateRaw).not.toHaveBeenCalled(); });
    it('requires a fresh source row for re-enable but permits disabling or removing an existing selection without source', async () => {
        const view = windowsServiceHealthView('unknown'); view.inventory = null; vi.mocked(request).mockResolvedValue(view); render(<Harness/>); await flush(); settings(); enable(); expect(screen.getByRole('button', { name: 'Save selected-service policy' })).toBeEnabled(); fireEvent.click(screen.getByRole('button', { name: 'Remove service: FixtureService' })); save(); await flush(); expect(JSON.parse(vi.mocked(mutateRaw).mock.calls[0][1])).toEqual({ enabled: false, services: [], expectedRevision: 1 });
    });
    it('withholds re-enable of retained names while source is missing', async () => {
        const view = windowsServiceHealthView(); view.policy = { enabled: false, services: ['FixtureService'], revision: 2 }; view.checks = [{ name: 'FixtureService', status: 'unknown', observation: null }]; view.inventory = null; vi.mocked(request).mockResolvedValue(view); render(<Harness/>); await flush(); settings(); enable(); expect(screen.getByText(/need a current unambiguous reported row/)).toBeVisible(); expect(screen.getByRole('button', { name: 'Save selected-service policy' })).toBeDisabled(); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('rechecks original source age at the save action before the next clock render', async () => {
        const view = windowsServiceHealthView(); view.inventory!.collectedAt = '2026-10-07T11:58:11Z'; vi.mocked(request).mockResolvedValue(view); render(<Harness/>); await flush(); edit(); const mono = performance.now(); vi.spyOn(performance, 'now').mockReturnValue(mono + 1001); vi.setSystemTime(Date.parse(windowsNow) + 1001); save(); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('clears private draft names when a save action discovers expired authority before the timer', async () => {
        render(<Harness session="2026-10-07T12:00:11Z"/>); await flush(); edit(); const mono = performance.now(); vi.spyOn(performance, 'now').mockReturnValue(mono + 1001); vi.setSystemTime(Date.parse(windowsNow) + 1001); save(); expect(mutateRaw).not.toHaveBeenCalled(); expect(screen.queryByRole('button', { name: 'Remove service: FixtureService' })).toBeNull(); expect(screen.getByRole('checkbox', { name: 'Enable selected-service policy' })).toBeDisabled();
    });
    it('keeps uncertain transport failure through repeated reads and never retries the mutation', async () => {
        render(<Harness/>); await flush(); edit(); vi.mocked(mutateRaw).mockRejectedValue(new Error('private-write-error')); save(); await flush(); await advance(30000); expect(screen.getByText(/Save outcome is uncertain/)).toBeVisible(); expect(mutateRaw).toHaveBeenCalledOnce(); expect(document.body).not.toHaveTextContent('private-write-error'); expect(screen.getByRole('button', { name: 'Save selected-service policy' })).toBeDisabled();
    });
    it('keeps uncertainty if the post-save read fails', async () => {
        render(<Harness/>); await flush(); edit(); vi.mocked(request).mockRejectedValue(new Error('private-read-error')); save(); await flush(); expect(screen.getByText(/Save outcome is uncertain/)).toBeVisible(); expect(screen.queryByText('Current saved policy confirmed.')).toBeNull(); await advance(15000); expect(mutateRaw).toHaveBeenCalledOnce(); expect(document.body).not.toHaveTextContent('private-read-error');
    });
    it.each(['same-revision', 'failed', 'pending'] as const)('invalidates a conflicting draft immediately while reconciliation is %s', async mode => {
        render(<Harness/>); await flush(); edit(); vi.mocked(mutateRaw).mockRejectedValue(new APIError('private-conflict', 409)); if (mode === 'failed') vi.mocked(request).mockRejectedValue(new Error('read failed')); if (mode === 'pending') vi.mocked(request).mockReturnValue(new Promise(() => {})); save(); await flush(); expect(screen.getByRole('checkbox', { name: 'Enable selected-service policy' })).not.toBeChecked(); expect(screen.queryByRole('button', { name: 'Remove service: FixtureService' })).toBeNull(); expect(screen.getByText(/save conflicted/)).toBeVisible(); expect(mutateRaw).toHaveBeenCalledOnce();
    });
    it('aborts a timed-out save, rejects its late reply and reconciles without replay', async () => {
        render(<Harness/>); await flush(); edit(); let finish!: (v: WindowsServiceHealthView) => void; vi.mocked(mutateRaw).mockReturnValue(new Promise(resolve => { finish = resolve; })); save(); await advance(10000); expect(vi.mocked(mutateRaw).mock.calls[0][3]?.aborted).toBe(true); await act(async () => finish(saved())); expect(screen.queryByText('Current saved policy confirmed.')).toBeNull(); expect(screen.getByText(/Save outcome is uncertain/)).toBeVisible(); await advance(30000); expect(mutateRaw).toHaveBeenCalledOnce();
    });
    it.each(['blur', 'hashchange', 'pagehide'] as const)('invalidates draft and aborts an interrupted save on %s without replay', async event => {
        render(<Harness/>); await flush(); edit(); let finish!: (v: WindowsServiceHealthView) => void; vi.mocked(mutateRaw).mockReturnValue(new Promise(resolve => { finish = resolve; })); save(); act(() => window.dispatchEvent(new Event(event))); expect(vi.mocked(mutateRaw).mock.calls[0][3]?.aborted).toBe(true); await act(async () => finish(saved())); act(() => window.dispatchEvent(new Event('focus'))); await flush(); expect(screen.getByText(/Save outcome is uncertain/)).toBeVisible(); expect(screen.queryByRole('button', { name: 'Remove service: FixtureService' })).toBeNull(); await advance(15000); expect(mutateRaw).toHaveBeenCalledOnce();
    });
    it('retains uncertainty when policy reading is temporarily disabled and later resumes', async () => {
        const result = render(<Harness/>); await flush(); edit(); vi.mocked(mutateRaw).mockReturnValue(new Promise(() => {})); save(); result.rerender(<Harness enabled={false}/>); expect(vi.mocked(mutateRaw).mock.calls[0][3]?.aborted).toBe(true); result.rerender(<Harness/>); await flush(); expect(screen.getByText(/Save outcome is uncertain/)).toBeVisible(); expect(mutateRaw).toHaveBeenCalledOnce();
    });
    it.each([403, 404, 410])('invalidates submitted names on POST authority loss %i before reconciliation', async code => {
        render(<Harness/>); await flush(); edit(); vi.mocked(mutateRaw).mockRejectedValue(new APIError('private-authority', code)); vi.mocked(request).mockReturnValue(new Promise(() => {})); save(); await flush(); expect(screen.queryByRole('button', { name: 'Remove service: FixtureService' })).toBeNull(); expect(screen.getByRole('button', { name: 'Save selected-service policy' })).toBeDisabled(); expect(mutateRaw).toHaveBeenCalledOnce();
    });
    it('drops a dirty draft after actual identity loss before later verification', async () => {
        const result = render(<Harness/>); await flush(); edit(); const revoked = windowsCapacityDevice(); revoked.capabilities = []; result.rerender(<Harness device={revoked}/>); expect(screen.queryByRole('button', { name: 'Remove service: FixtureService' })).toBeNull(); result.rerender(<Harness/>); await flush(); expect(selected()).not.toBeChecked();
    });
    it('rejects late results from another selected device', async () => {
        let finish!: (v: WindowsServiceHealthView) => void; vi.mocked(request).mockReturnValueOnce(new Promise(resolve => { finish = resolve; })); const result = render(<Harness/>); const other = windowsCapacityDevice(); other.id = `agent_${'8'.repeat(32)}`; vi.mocked(request).mockReturnValue(new Promise(() => {})); result.rerender(<Harness device={other}/>); await act(async () => finish(windowsServiceHealthView('attention'))); expect(history()).toBeNull();
    });
    it.each(['session', 'certificate'] as const)('hides private service history at original %s expiry across remount', async kind => {
        const view = windowsServiceHealthView('attention'), expiry = '2026-10-07T12:00:11Z'; if (kind === 'certificate') view.certificateExpiresAt = expiry; vi.mocked(request).mockResolvedValue(view); const result = render(<Harness session={kind === 'session' ? expiry : windowsCapacitySession}/>); await flush(); expect(history()).toBeVisible(); await advance(1000); expect(history()).toBeNull(); result.unmount(); render(<Harness session={kind === 'session' ? expiry : windowsCapacitySession}/>); await flush(); expect(history()).toBeNull();
    });
    it('ages only the current assessment to unknown while preserving open episode evidence', async () => {
        const view = windowsServiceHealthView('attention'); view.checks[0].observation!.collectedAt = '2026-10-07T11:58:11Z'; view.inventory!.collectedAt = '2026-10-07T11:58:11Z'; vi.mocked(request).mockResolvedValue(view); render(<Harness/>); await flush(); expect(screen.getByText('Selected-service incident open', { selector: '.windows-capacity-assessment strong' })).toBeVisible(); await advance(2000); expect(screen.getByText('Unknown', { selector: '.windows-capacity-assessment strong' })).toBeVisible(); expect(history()).toBeVisible(); expect(screen.getByText('Open')).toBeVisible();
    });
    it('does not refresh an old source by rereading or remounting with a stationary server clock', async () => {
        const view = windowsServiceHealthView('attention'); view.checks[0].observation!.collectedAt = '2026-10-07T11:58:11Z'; view.inventory!.collectedAt = '2026-10-07T11:58:11Z'; vi.mocked(request).mockResolvedValue(view); const result = render(<Harness/>); await flush(); result.unmount(); await advance(2000); render(<Harness/>); await flush(); expect(screen.getByText('Unknown', { selector: '.windows-capacity-assessment strong' })).toBeVisible(); expect(history()).toBeVisible();
    });
    it('shows policy-changed closure without fabricating running recovery', async () => {
        const view = windowsServiceHealthView(); view.policy.revision = 2; view.incidents = [windowsServiceHealthIncident('policy-changed')]; vi.mocked(request).mockResolvedValue(view); render(<Harness/>); await flush(); expect(screen.getByText('Closed because policy changed')).toBeVisible(); expect(screen.queryByText('Confirmed running again')).toBeNull(); expect(screen.queryByText('Recovery observation')).toBeNull();
    });
    it('locks and clears both history and editing after authentication epoch loss', async () => {
        vi.mocked(request).mockResolvedValue(windowsServiceHealthView('attention')); render(<Harness/>); await flush(); settings(); expect(history()).toBeVisible(); act(() => { abortProtectedRequests(); window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT)); }); expect(history()).toBeNull(); expect(screen.getByRole('checkbox', { name: 'Enable selected-service policy' })).toBeDisabled(); await advance(30000); expect(request).toHaveBeenCalledOnce();
    });
    it('rejects same-revision policy rewriting and policy revision rollback', async () => {
        const view = windowsServiceHealthView('unknown'); vi.mocked(request).mockResolvedValue(view); render(<Harness/>); await flush(); settings(); const rewritten = saved(); rewritten.policy.services = ['Spooler']; rewritten.checks[0].name = 'Spooler'; vi.mocked(request).mockResolvedValue(rewritten); refresh(); await flush(); expect(screen.getByText('Selected-service policy unavailable. Current assessment is unknown.')).toBeVisible(); expect(screen.queryByRole('button', { name: 'Remove service: FixtureService' })).toBeNull(); vi.mocked(request).mockResolvedValue(windowsServiceHealthView()); refresh(); await flush(); expect(screen.getByRole('checkbox', { name: 'Enable selected-service policy' })).toBeDisabled();
    });
    it.each(['disabled', 'no-session', 'synthetic', 'linux', 'manual', 'missing-identity'] as const)('does not fetch policy with %s scope', async reason => {
        const device = windowsCapacityDevice(); if (reason === 'synthetic') device.synthetic = true; if (reason === 'linux') device.platform = 'linux'; if (reason === 'manual') delete device.agentCertificate; if (reason === 'missing-identity') device.capabilities = []; render(<Harness device={device} enabled={reason !== 'disabled'} session={reason === 'no-session' ? null : windowsCapacitySession}/>); await flush(); expect(request).not.toHaveBeenCalled();
    });
});
describe('selected-service policy in the real Windows Health composition', () => {
    const setup = () => vi.mocked(request).mockImplementation(async path => path === `/devices/${windowsDeviceId}` ? windowsCapacityDevice() : path.endsWith('/windows-inventory') ? windowsView() : path.endsWith('/windows-contact') ? windowsContactView() : path.endsWith('/windows-capacity') ? windowsCapacityView() : path.endsWith('/windows-resource/cpu') ? windowsResourceView('cpu') : path.endsWith('/windows-resource/memory') ? windowsResourceView('memory') : path.endsWith('/windows-services') ? windowsServiceHealthView() : Promise.reject(new Error('Unexpected fixture read')));
    const panel = () => within(screen.getByRole('region', { name: 'Service checks' }));
    const edit = () => { const region = panel(); fireEvent.click(region.getByText('Selected-service policy settings & limits')); fireEvent.click(region.getByRole('checkbox', { name: 'Enable selected-service policy' })); fireEvent.click(region.getByRole('checkbox', { name: /Fixture Background Service/ })); };
    it('preserves a same-revision dirty draft through passive metadata revalidation without enabling siblings', async () => {
        setup(); render(<DeviceDetail id={windowsDeviceId} initialTab="health" onClose={vi.fn()} onCase={vi.fn()}/>); await flush(); fireEvent.change(screen.getByRole('combobox', { name: /Service-check source/ }), { target: { value: 'preview' } }); await flush(); edit(); fireEvent.click(screen.getByRole('button', { name: 'Refresh device metadata' })); await flush(); expect(panel().getByRole('checkbox', { name: /Fixture Background Service/ })).toBeChecked(); expect(panel().getByRole('button', { name: 'Save selected-service policy' })).toBeEnabled(); for (const title of ['System-volume capacity policy', 'CPU percentage policy', 'Physical RAM percentage policy']) expect(within(screen.getByRole('region', { name: title })).getByText('Policy disabled')).toBeVisible(); expect(mutateRaw).not.toHaveBeenCalled(); expect(vi.mocked(request).mock.calls.some(([path]) => path.endsWith('/health'))).toBe(false);
    });
    it('discards unsaved names when navigating away from Health and returning', async () => {
        setup(); render(<DeviceDetail id={windowsDeviceId} initialTab="health" onClose={vi.fn()} onCase={vi.fn()}/>); await flush(); fireEvent.change(screen.getByRole('combobox', { name: /Service-check source/ }), { target: { value: 'preview' } }); await flush(); edit(); fireEvent.click(screen.getByRole('tab', { name: 'Overview' })); expect(screen.queryByRole('region', { name: 'Service checks' })).toBeNull(); fireEvent.click(screen.getByRole('tab', { name: 'Health' })); await flush(); fireEvent.click(panel().getByText('Selected-service policy settings & limits')); expect(panel().getByRole('checkbox', { name: /Fixture Background Service/ })).not.toBeChecked(); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it.each([{ loginMode: 'named' as const, hasExplicitMetadata: true }, { loginMode: 'shared' as const, hasExplicitMetadata: false }])('keeps policy read-only without explicit shared admin metadata %j', async access => {
        setup(); vi.mocked(useOperator).mockReturnValue({ ...operator, ...access }); render(<DeviceDetail id={windowsDeviceId} initialTab="health" onClose={vi.fn()} onCase={vi.fn()}/>); await flush(); fireEvent.change(screen.getByRole('combobox', { name: /Service-check source/ }), { target: { value: 'preview' } }); await flush(); fireEvent.click(panel().getByText('Selected-service policy settings & limits')); expect(panel().getByRole('checkbox', { name: 'Enable selected-service policy' })).toBeDisabled(); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('never requests selected-service policy from Overview', async () => { setup(); render(<DeviceDetail id={windowsDeviceId} onClose={vi.fn()} onCase={vi.fn()}/>); await flush(); expect(vi.mocked(request).mock.calls.some(([path]) => path.endsWith('/windows-services'))).toBe(false); });
});
