import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { APIError, AUTH_REQUIRED_EVENT } from './api';
import { useOperator } from './auth';
import { setLocale } from './i18n';
import { PackageUpdatesWorkspace, PackageUpdateSelectionCell, PackageUpdateSelectionHeader } from './package-updates';
import { approvePackageUpdates, PackageUpdateNotReady, preparePackageUpdates, readPackageUpdateRetryGate, readPackageUpdates } from './package-update-api';
import { nativePackageUpdateJob, nativePackageUpdates, packageUpdateJob, packageUpdatePreview, simulatedPackageUpdates, unavailablePackageUpdates, updateWorkflowActor, updateWorkflowDevice } from './package-update-fixtures';
import type { PackageIdentity } from './package-update-types';
vi.mock('./auth', () => ({ useOperator: vi.fn() }));
vi.mock('./package-update-api', () => ({ approvePackageUpdates: vi.fn(), PackageUpdateNotReady: class extends Error {}, preparePackageUpdates: vi.fn(), readPackageUpdateRetryGate: vi.fn(), readPackageUpdates: vi.fn() }));
const operator = { mode: 'lan' as const, authenticated: true, hasExplicitMetadata: true, loginMode: 'named' as const, actorId: updateWorkflowActor, capabilities: ['read', 'plan_updates', 'execute_updates'] as const, expiresAt: '2026-10-07T02:00:00Z', insecureTestMode: false, logout: vi.fn(), theme: 'light' as const, setTheme: vi.fn() };
const rows: PackageIdentity[] = [{ name: 'curl', architecture: 'amd64' }, { name: 'curl', architecture: 'arm64' }];
function component(source = 'complete', deviceId = updateWorkflowDevice, items = rows) {
    return <PackageUpdatesWorkspace deviceId={deviceId} sessionKey={operator.expiresAt} source={source}><table><thead><tr><PackageUpdateSelectionHeader/><th>Detected package</th></tr></thead><tbody>{items.map(item => <tr key={`${item.name}:${item.architecture}`}><PackageUpdateSelectionCell {...item}/><td>{item.name}</td></tr>)}</tbody></table></PackageUpdatesWorkspace>;
}
const prepareButton = () => screen.getByRole('button', { name: 'Prepare selected updates (simulation)' });
const approveButton = () => screen.getByRole('button', { name: 'Confirm this exact update (simulation)' });
async function ready() { await screen.findByText(/SIMULATION ONLY/); }
async function prepare() { fireEvent.click(screen.getByRole('checkbox', { name: 'Select curl:amd64' })); fireEvent.click(prepareButton()); await screen.findByRole('region', { name: 'Immutable preparation review' }); }
beforeEach(() => {
    sessionStorage.clear(); setLocale('en', false); vi.mocked(useOperator).mockReturnValue(operator);
    vi.mocked(readPackageUpdates).mockReset().mockResolvedValue(simulatedPackageUpdates());
    vi.mocked(readPackageUpdateRetryGate).mockReset().mockResolvedValue(simulatedPackageUpdates());
    vi.mocked(preparePackageUpdates).mockReset().mockImplementation(async (_device, requestId, packages) => packageUpdateJob('preview_ready', packageUpdatePreview(packages, requestId)));
    vi.mocked(approvePackageUpdates).mockReset().mockImplementation(async (_device, preview) => packageUpdateJob('approved', preview));
});
afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); });
describe('detected selection to confirmed simulation workflow', () => {
    it('keeps production unavailable even with detected selection and named write capabilities', async () => {
        vi.mocked(readPackageUpdates).mockResolvedValue(unavailablePackageUpdates()); render(component()); await screen.findByText('Native package updates are not ready on this device.');
        fireEvent.click(screen.getByRole('checkbox', { name: 'Select curl:amd64' })); expect(prepareButton()).toBeDisabled(); expect(screen.queryByText(/SIMULATION ONLY/)).not.toBeInTheDocument(); expect(preparePackageUpdates).not.toHaveBeenCalled();
    });
    it('prepares only identities, renders immutable full provenance, and requires explicit risk acknowledgment', async () => {
        render(component()); await ready(); await prepare();
        expect(preparePackageUpdates).toHaveBeenCalledTimes(1); const args = vi.mocked(preparePackageUpdates).mock.calls[0];
        expect(args[1]).toMatch(/^update_[a-f0-9]{32}$/); expect(args[2]).toEqual([{ name: 'curl', architecture: 'amd64' }]);
        const review = screen.getByRole('region', { name: 'Immutable preparation review' });
        expect(review).toHaveTextContent('1:8.14.1-2 → 1:8.14.1-2+deb13u1'); expect(review).toHaveTextContent('Fixture Debian / trixie-security / main'); expect(review).toHaveTextContent('e'.repeat(64)); expect(review).toHaveTextContent('Preserve modified dpkg configuration files');
        expect(approveButton()).toBeDisabled(); fireEvent.click(screen.getByRole('checkbox', { name: /I have reviewed/ })); expect(approveButton()).toBeEnabled();
        fireEvent.click(approveButton()); await screen.findByText('Approved; awaiting execution evidence');
        expect(approvePackageUpdates).toHaveBeenCalledTimes(1); expect(screen.queryByText('All approved versions verified (simulation)')).not.toBeInTheDocument(); expect(sessionStorage.getItem('tracebolt.package-update-intent')).toBeNull();
    });
    it('limits exact name+architecture identities to 32 and allows removal', async () => {
        const items = Array.from({ length: 33 }, (_, i) => ({ name: `fixture-${i}`, architecture: 'amd64' })); render(component('complete', updateWorkflowDevice, items)); await ready();
        items.slice(0, 32).forEach(item => fireEvent.click(screen.getByLabelText(`Select ${item.name}:amd64`)));
        expect(screen.getByRole('checkbox', { name: 'Select fixture-32:amd64' })).toBeDisabled(); expect(screen.getByText('Selected identities (32/32)')).toBeVisible();
        fireEvent.click(screen.getByRole('button', { name: 'Remove fixture-0:amd64' })); expect(screen.getByRole('checkbox', { name: 'Select fixture-32:amd64' })).toBeEnabled();
    });
    it.each(['source', 'device', 'actor', 'capability'] as const)('resets selection and acknowledgment on %s change', async change => {
        const mounted = render(component()); await ready(); fireEvent.click(screen.getByRole('checkbox', { name: 'Select curl:amd64' }));
        if (change === 'actor') vi.mocked(useOperator).mockReturnValue({ ...operator, actorId: `operator_${'f'.repeat(32)}` });
        if (change === 'capability') vi.mocked(useOperator).mockReturnValue({ ...operator, capabilities: ['read', 'plan_updates'] });
        mounted.rerender(component(change === 'source' ? 'preview' : 'complete', change === 'device' ? `agent_${'f'.repeat(32)}` : updateWorkflowDevice));
        expect(screen.getByText('No packages selected.')).toBeVisible(); expect(screen.getByRole('checkbox', { name: 'Select curl:amd64' })).not.toBeChecked();
    });
    it('allows planning without execution capability and execution without planning capability', async () => {
        vi.mocked(useOperator).mockReturnValue({ ...operator, capabilities: ['read', 'plan_updates'] }); const mounted = render(component()); await ready(); await prepare(); expect(screen.getByRole('checkbox', { name: /I have reviewed/ })).toBeDisabled();
        const preview = vi.mocked(preparePackageUpdates).mock.calls[0]; vi.mocked(readPackageUpdates).mockResolvedValue(packageUpdateJob('preview_ready', packageUpdatePreview(preview[2], preview[1])));
        vi.mocked(useOperator).mockReturnValue({ ...operator, capabilities: ['read', 'execute_updates'] }); mounted.rerender(component()); await screen.findByRole('region', { name: 'Immutable preparation review' });
        expect(prepareButton()).toBeDisabled(); fireEvent.click(screen.getByRole('checkbox', { name: /I have reviewed/ })); expect(approveButton()).toBeEnabled();
    });
    it('does not grant named permissions from legacy or shared display defaults', async () => {
        vi.mocked(useOperator).mockReturnValue({ ...operator, hasExplicitMetadata: false }); render(component()); await ready(); expect(screen.getByRole('checkbox', { name: 'Select curl:amd64' })).toBeDisabled(); expect(prepareButton()).toBeDisabled();
    });
    it('recovers a lost preparation with its exact ID and never creates or automatically resends an operation', async () => {
        vi.mocked(preparePackageUpdates).mockRejectedValue(new Error('response lost')); render(component()); await ready();
        fireEvent.click(screen.getByRole('checkbox', { name: 'Select curl:amd64' })); fireEvent.click(prepareButton()); await screen.findByText(/The write response was lost/);
        const requestId = vi.mocked(preparePackageUpdates).mock.calls[0][1]; expect(prepareButton()).toBeDisabled();
        vi.mocked(readPackageUpdates).mockResolvedValue(packageUpdateJob('preview_ready', packageUpdatePreview([rows[0]], requestId)));
        fireEvent.click(screen.getByRole('button', { name: 'Recover same request status' })); await screen.findByRole('region', { name: 'Immutable preparation review' });
        expect(vi.mocked(readPackageUpdates).mock.calls.at(-1)?.[2]).toBe(requestId); expect(preparePackageUpdates).toHaveBeenCalledTimes(1); expect(screen.queryByText(/The write response was lost/)).not.toBeInTheDocument();
    });
    it('preserves a lost approval ID/digest across remount without storing provenance and recovers verified results', async () => {
        vi.mocked(approvePackageUpdates).mockRejectedValue(new Error('response lost')); const mounted = render(component()); await ready(); await prepare();
        fireEvent.click(screen.getByRole('checkbox', { name: /I have reviewed/ })); fireEvent.click(approveButton()); await screen.findByText(/The write response was lost/);
        const preview = vi.mocked(approvePackageUpdates).mock.calls[0][1]; const stored = sessionStorage.getItem('tracebolt.package-update-intent')!;
        expect(stored).toContain(preview.requestId); expect(stored).toContain(preview.digest); expect(stored).not.toContain('sourceLabel'); expect(stored).not.toContain('archiveSHA256');
        vi.mocked(readPackageUpdates).mockResolvedValue(packageUpdateJob('succeeded', preview)); mounted.unmount(); render(component('preview'));
        await screen.findByText('All approved versions verified (simulation)'); expect(screen.getByRole('region', { name: 'Verification evidence (simulation)' })).toHaveTextContent('Verified');
        expect(approvePackageUpdates).toHaveBeenCalledTimes(1); expect(vi.mocked(readPackageUpdates).mock.calls.at(-1)?.[2]).toBe(preview.requestId);
    });
    it('retries a lost preparation only on explicit request and preserves its exact operation ID', async () => {
        vi.mocked(preparePackageUpdates).mockRejectedValueOnce(new Error('response lost')); render(component()); await ready();
        fireEvent.click(screen.getByRole('checkbox', { name: 'Select curl:amd64' })); fireEvent.click(prepareButton()); await screen.findByText(/The write response was lost/);
        const first = vi.mocked(preparePackageUpdates).mock.calls[0]; fireEvent.click(screen.getByRole('button', { name: 'Retry the same request' }));
        await screen.findByRole('region', { name: 'Immutable preparation review' }); const second = vi.mocked(preparePackageUpdates).mock.calls[1];
        expect(second[1]).toBe(first[1]); expect(second[2]).toEqual(first[2]); expect(preparePackageUpdates).toHaveBeenCalledTimes(2);
    });
    it('retains uncertainty when exact recovery cannot establish the original request', async () => {
        vi.mocked(preparePackageUpdates).mockRejectedValue(new Error('response lost')); render(component()); await ready();
        fireEvent.click(screen.getByRole('checkbox', { name: 'Select curl:amd64' })); fireEvent.click(prepareButton()); await screen.findByText(/The write response was lost/);
        fireEvent.click(screen.getByRole('button', { name: 'Recover same request status' })); await screen.findByText(/The saved status does not establish/);
        expect(prepareButton()).toBeDisabled(); expect(preparePackageUpdates).toHaveBeenCalledTimes(1);
    });
    it.each(['approval-digest', 'prepare-selection'] as const)('rejects substituted %s after reload while retaining the same pending request', async changed => {
        const preview = packageUpdatePreview(), intent = changed === 'approval-digest' ? { mode: 'simulation', kind: 'approve', requestId: preview.requestId, previewDigest: preview.digest } : { mode: 'simulation', kind: 'prepare', requestId: preview.requestId, packages: [rows[0]] };
        sessionStorage.setItem('tracebolt.package-update-intent', JSON.stringify({ deviceId: updateWorkflowDevice, actorId: updateWorkflowActor, sessionKey: operator.expiresAt, intent }));
        const substituted = packageUpdateJob(changed === 'approval-digest' ? 'approved' : 'preview_ready', preview);
        if (changed === 'approval-digest') substituted.preview!.digest = `sha256:${'f'.repeat(64)}`;
        else substituted.preview!.items[0].architecture = 'arm64';
        vi.mocked(readPackageUpdates).mockResolvedValue(substituted); render(component());
        await screen.findByText(/Inconsistent update evidence/); expect(screen.queryByRole('region', { name: 'Immutable preparation review' })).not.toBeInTheDocument();
        expect(sessionStorage.getItem('tracebolt.package-update-intent')).toContain(intent.requestId); expect(prepareButton()).toBeDisabled(); expect(approvePackageUpdates).not.toHaveBeenCalled();
    });
    it('retains a preparing request through reload until its preview matches the original selected identities', async () => {
        const preview = packageUpdatePreview(), intent = { mode: 'simulation', kind: 'prepare', requestId: preview.requestId, packages: [rows[0]] };
        sessionStorage.setItem('tracebolt.package-update-intent', JSON.stringify({ deviceId: updateWorkflowDevice, actorId: updateWorkflowActor, sessionKey: operator.expiresAt, intent }));
        const preparing = packageUpdateJob('preparing', preview); preparing.preview = null; vi.mocked(readPackageUpdates).mockResolvedValue(preparing); render(component());
        await screen.findByText('Preparing'); expect(sessionStorage.getItem('tracebolt.package-update-intent')).toContain(intent.requestId);
        const changed = packageUpdateJob('preview_ready', preview); changed.preview!.items[0].architecture = 'arm64'; vi.mocked(readPackageUpdates).mockResolvedValue(changed);
        fireEvent.click(screen.getByRole('button', { name: 'Recover same request status' })); await screen.findByText(/Inconsistent update evidence/);
        expect(sessionStorage.getItem('tracebolt.package-update-intent')).toContain(intent.requestId); expect(approvePackageUpdates).not.toHaveBeenCalled();
    });
    it.each([false, true])('recovers a prepare lost before commit through exact not-found and explicit same-ID retry (reload=%s)', async reload => {
        vi.mocked(preparePackageUpdates).mockRejectedValueOnce(new Error('write lost before commit')); const mounted = render(component()); await ready();
        fireEvent.click(screen.getByRole('checkbox', { name: 'Select curl:amd64' })); fireEvent.click(prepareButton()); await screen.findByText(/The write response was lost/);
        const original = vi.mocked(preparePackageUpdates).mock.calls[0];
        vi.mocked(readPackageUpdates).mockRejectedValue(new APIError('No saved update job.', 404, 'package_update_not_found'));
        if (reload) { mounted.unmount(); render(component()); }
        else fireEvent.click(screen.getByRole('button', { name: 'Recover same request status' }));
        await screen.findByText(/This exact request is not recorded yet/);
        expect(readPackageUpdateRetryGate).toHaveBeenCalledTimes(1); expect(prepareButton()).toBeDisabled();
        expect(sessionStorage.getItem('tracebolt.package-update-intent')).toContain(original[1]); expect(preparePackageUpdates).toHaveBeenCalledTimes(1);
        fireEvent.click(screen.getByRole('button', { name: 'Retry the same request' })); await screen.findByRole('region', { name: 'Immutable preparation review' });
        const retry = vi.mocked(preparePackageUpdates).mock.calls[1]; expect(retry[1]).toBe(original[1]); expect(retry[2]).toEqual(original[2]);
        expect(sessionStorage.getItem('tracebolt.package-update-intent')).toBeNull();
    });
    it.each(['generic404', 'unreadable', 'unavailable', 'busy', 'changed-access'] as const)('does not grant a retry when recovery is %s', async failure => {
        const preview = packageUpdatePreview(), intent = { mode: 'simulation', kind: 'prepare', requestId: preview.requestId, packages: [rows[0]] };
        sessionStorage.setItem('tracebolt.package-update-intent', JSON.stringify({ deviceId: updateWorkflowDevice, actorId: updateWorkflowActor, sessionKey: operator.expiresAt, intent }));
        vi.mocked(readPackageUpdates).mockRejectedValue(failure === 'generic404' ? new APIError('Generic not found.', 404) : failure === 'unreadable' ? new APIError('Network failure.') : new APIError('No saved update job.', 404, 'package_update_not_found'));
        if (failure === 'unavailable') vi.mocked(readPackageUpdateRetryGate).mockResolvedValue(unavailablePackageUpdates());
        if (failure === 'busy') vi.mocked(readPackageUpdateRetryGate).mockResolvedValue(packageUpdateJob('approved', packageUpdatePreview(rows, `update_${'f'.repeat(32)}`)));
        if (failure === 'changed-access') vi.mocked(readPackageUpdateRetryGate).mockRejectedValue(new APIError('Access changed.', 401));
        render(component());
        await waitFor(() => expect(screen.queryByText('Reading saved update status…')).not.toBeInTheDocument());
        if (failure === 'changed-access') expect(screen.getByText(/Your session or update access changed/)).toBeVisible();
        else expect(screen.getByRole('button', { name: 'Retry the same request' })).toBeDisabled();
        if (failure === 'generic404' || failure === 'unreadable') expect(readPackageUpdateRetryGate).not.toHaveBeenCalled();
        expect(preparePackageUpdates).not.toHaveBeenCalled(); expect(approvePackageUpdates).not.toHaveBeenCalled();
    });
    it('keeps a changed immutable preview blocked instead of approving substituted bytes', async () => {
        render(component()); await ready(); await prepare(); const args = vi.mocked(preparePackageUpdates).mock.calls[0];
        const modified = packageUpdateJob('preview_ready', packageUpdatePreview(args[2], args[1])); modified.preview!.items[0].toVersion = 'substituted'; vi.mocked(readPackageUpdates).mockResolvedValue(modified);
        fireEvent.click(screen.getByRole('button', { name: 'Refresh saved update status' })); await screen.findByText(/Inconsistent update evidence/); expect(approveButton()).toBeDisabled(); expect(screen.queryByText(/substituted/)).not.toBeInTheDocument();
    });
    it('expires preview approval with server time and refuses a different actor', async () => {
        const expired = packageUpdateJob(); expired.preview!.expiresAt = expired.serverNow; vi.mocked(readPackageUpdates).mockResolvedValue(expired); render(component()); await ready(); expect(screen.getByRole('checkbox', { name: /I have reviewed/ })).toBeDisabled(); expect(approveButton()).toBeDisabled(); expect(screen.getByText(/This preview has expired/)).toBeVisible();
    });
    it('drops pending responses and browser intent when authentication is invalidated', async () => {
        let finish!: (value: ReturnType<typeof packageUpdateJob>) => void; vi.mocked(preparePackageUpdates).mockImplementation(() => new Promise(resolve => { finish = resolve; })); render(component()); await ready();
        fireEvent.click(screen.getByRole('checkbox', { name: 'Select curl:amd64' })); fireEvent.click(prepareButton()); await waitFor(() => expect(preparePackageUpdates).toHaveBeenCalledTimes(1));
        act(() => window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT))); await act(async () => finish(packageUpdateJob()));
        expect(screen.queryByRole('region', { name: 'Immutable preparation review' })).not.toBeInTheDocument(); expect(sessionStorage.getItem('tracebolt.package-update-intent')).toBeNull(); expect(screen.getByText(/Your session or update access changed/)).toBeVisible();
    });
    it('shows the whole path and risk copy in German', async () => {
        setLocale('de', false); render(component()); await screen.findByText(/NUR SIMULATION/); fireEvent.click(screen.getByRole('checkbox', { name: 'Auswählen curl:amd64' })); fireEvent.click(screen.getByRole('button', { name: 'Ausgewählte Updates vorbereiten (Simulation)' }));
        await screen.findByRole('region', { name: 'Unveränderliche Vorbereitung prüfen' }); expect(screen.getByRole('checkbox', { name: /Ich habe diese genauen Versionen/ })).toBeVisible(); expect(screen.getByRole('button', { name: 'Dieses genaue Update bestätigen (Simulation)' })).toBeDisabled();
    });
});


function nativeResponses() {
    vi.mocked(readPackageUpdates).mockResolvedValue(nativePackageUpdates());
    vi.mocked(readPackageUpdateRetryGate).mockResolvedValue(nativePackageUpdates());
    vi.mocked(preparePackageUpdates).mockImplementation(async (_device, requestId, packages) => nativePackageUpdateJob('preview_ready', packageUpdatePreview(packages, requestId)));
    vi.mocked(approvePackageUpdates).mockImplementation(async (_device, preview) => nativePackageUpdateJob('approved', preview));
}
async function nativeReady() { await screen.findByText('Updates run on this device. No automatic reboot.'); }
async function nativePrepare() {
    fireEvent.click(screen.getByRole('checkbox', { name: 'Select curl:amd64' }));
    fireEvent.click(screen.getByRole('button', { name: 'Prepare selected updates' }));
    await screen.findByRole('region', { name: 'Immutable preparation review' });
}
const nativeApproval = () => screen.getByRole('button', { name: 'Install these exact updates' });
describe('native selected-update consent and interruption boundaries', () => {
    it('distinguishes actual installation confirmation from simulation and requires the exact reviewed risk acknowledgment', async () => {
        nativeResponses(); render(component()); await nativeReady(); await nativePrepare();
        expect(screen.queryByText(/SIMULATION ONLY/)).not.toBeInTheDocument(); expect(nativeApproval()).toBeDisabled();
        expect(vi.mocked(preparePackageUpdates).mock.calls[0][5]).toBe('native');
        fireEvent.click(screen.getByRole('checkbox', { name: /I have reviewed/ })); fireEvent.click(nativeApproval());
        await screen.findByText('Approved; awaiting execution evidence');
        expect(vi.mocked(approvePackageUpdates).mock.calls[0][4]).toBe('native');
        expect(screen.queryByText('Endpoint verified all approved versions')).not.toBeInTheDocument();
    });
    it('disables preparation when native capability is stale or locally off', async () => {
        nativeResponses(); vi.mocked(readPackageUpdates).mockResolvedValue({ ...nativePackageUpdates(), available: false, reason: 'native_adapter_unavailable' });
        render(component()); await nativeReady(); fireEvent.click(screen.getByRole('checkbox', { name: 'Select curl:amd64' }));
        expect(screen.getByRole('button', { name: 'Prepare selected updates' })).toBeDisabled();
        expect(screen.getByText('Native package updates are not ready on this device.')).toBeVisible(); expect(preparePackageUpdates).not.toHaveBeenCalled();
    });
    it('revokes a checked acknowledgment when native readiness becomes stale with a retained preview', async () => {
        nativeResponses(); render(component()); await nativeReady(); await nativePrepare();
        fireEvent.click(screen.getByRole('checkbox', { name: /I have reviewed/ })); expect(nativeApproval()).toBeEnabled();
        const original = vi.mocked(preparePackageUpdates).mock.calls[0], stale = nativePackageUpdateJob('preview_ready', packageUpdatePreview(original[2], original[1])); stale.reason = 'native_adapter_unavailable';
        vi.mocked(readPackageUpdates).mockResolvedValue(stale); fireEvent.click(screen.getByRole('button', { name: 'Refresh saved update status' }));
        await screen.findByText('Native package updates are not ready on this device.');
        expect(screen.getByRole('checkbox', { name: /I have reviewed/ })).not.toBeChecked(); expect(screen.getByRole('checkbox', { name: /I have reviewed/ })).toBeDisabled(); expect(nativeApproval()).toBeDisabled();
        expect(approvePackageUpdates).not.toHaveBeenCalled();
    });
    it('reports a fresh readiness rejection without claiming an install was dispatched', async () => {
        nativeResponses(); render(component()); await nativeReady(); await nativePrepare();
        vi.mocked(approvePackageUpdates).mockRejectedValue(new PackageUpdateNotReady({ ...nativePackageUpdateJob(), reason: 'native_adapter_unavailable' }));
        fireEvent.click(screen.getByRole('checkbox', { name: /I have reviewed/ })); fireEvent.click(nativeApproval());
        await screen.findByText('Update readiness changed. Refresh the saved status before continuing.');
        expect(screen.queryByText(/The write response was lost/)).not.toBeInTheDocument(); expect(sessionStorage.getItem('tracebolt.package-update-intent')).toBeNull();
        expect(screen.queryByText('Endpoint verified all approved versions')).not.toBeInTheDocument();
    });
    it.each(['applying', 'verifying', 'succeeded', 'needs_intervention'] as const)('shows native endpoint-reported %s evidence without requiring idle readiness', async state => {
        nativeResponses(); vi.mocked(readPackageUpdates).mockResolvedValue(nativePackageUpdateJob(state)); render(component()); await nativeReady();
        const result = screen.getByRole('region', { name: 'Endpoint-reported verification' }); expect(result).toBeVisible(); expect(result).toHaveTextContent('native');
        expect(screen.queryByText(/SIMULATION ONLY/)).not.toBeInTheDocument();
        if (state === 'succeeded') expect(screen.getByText('Endpoint verified all approved versions')).toBeVisible();
        else expect(screen.queryByText('Endpoint verified all approved versions')).not.toBeInTheDocument();
    });
    it('keeps uncertain native preparation blocked without inventing preview or verification evidence', async () => {
        nativeResponses(); const uncertain = nativePackageUpdateJob('needs_intervention'); uncertain.preview = null; uncertain.job!.result = null; uncertain.job!.approvedAt = null; vi.mocked(readPackageUpdates).mockResolvedValue(uncertain);
        render(component()); await nativeReady(); expect(screen.getByText('Needs intervention; outcome not verified')).toBeVisible();
        expect(screen.queryByRole('region', { name: 'Immutable preparation review' })).not.toBeInTheDocument(); expect(screen.queryByRole('region', { name: 'Endpoint-reported verification' })).not.toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Prepare selected updates' })).toBeDisabled();
    });
    it('recovers a lost native approval after reload with the same mode, ID and digest', async () => {
        nativeResponses(); vi.mocked(approvePackageUpdates).mockRejectedValue(new Error('response lost')); const mounted = render(component()); await nativeReady(); await nativePrepare();
        fireEvent.click(screen.getByRole('checkbox', { name: /I have reviewed/ })); fireEvent.click(nativeApproval()); await screen.findByText(/The write response was lost/);
        const preview = vi.mocked(approvePackageUpdates).mock.calls[0][1]; expect(sessionStorage.getItem('tracebolt.package-update-intent')).toContain('"mode":"native"');
        vi.mocked(readPackageUpdates).mockResolvedValue(nativePackageUpdateJob('succeeded', preview)); mounted.unmount(); render(component());
        await screen.findByText('Endpoint verified all approved versions'); expect(approvePackageUpdates).toHaveBeenCalledTimes(1); expect(vi.mocked(readPackageUpdates).mock.calls.at(-1)?.[2]).toBe(preview.requestId);
    });
    it('recovers a native prepare lost before commit only by explicit same-ID native retry after exact not-found', async () => {
        nativeResponses(); vi.mocked(preparePackageUpdates).mockRejectedValueOnce(new Error('not committed')); const mounted = render(component()); await nativeReady();
        fireEvent.click(screen.getByRole('checkbox', { name: 'Select curl:amd64' })); fireEvent.click(screen.getByRole('button', { name: 'Prepare selected updates' })); await screen.findByText(/The write response was lost/);
        const original = vi.mocked(preparePackageUpdates).mock.calls[0]; vi.mocked(readPackageUpdates).mockRejectedValue(new APIError('Missing.', 404, 'package_update_not_found')); mounted.unmount(); render(component());
        await screen.findByText(/This exact request is not recorded yet/); expect(preparePackageUpdates).toHaveBeenCalledTimes(1);
        fireEvent.click(screen.getByRole('button', { name: 'Retry the same request' })); await screen.findByRole('region', { name: 'Immutable preparation review' });
        const retry = vi.mocked(preparePackageUpdates).mock.calls[1]; expect(retry[1]).toBe(original[1]); expect(retry[2]).toEqual(original[2]); expect(retry[5]).toBe('native');
    });
    it.each(['native', 'simulation'] as const)('rejects recovered %s intent when the server switches execution mode', async mode => {
        const preview = packageUpdatePreview(), intent = { mode, kind: 'approve', requestId: preview.requestId, previewDigest: preview.digest };
        sessionStorage.setItem('tracebolt.package-update-intent', JSON.stringify({ deviceId: updateWorkflowDevice, actorId: updateWorkflowActor, sessionKey: operator.expiresAt, intent }));
        vi.mocked(readPackageUpdates).mockResolvedValue(mode === 'native' ? packageUpdateJob('approved', preview) : nativePackageUpdateJob('approved', preview)); render(component());
        await screen.findByText(/Inconsistent update evidence/); expect(screen.queryByRole('region', { name: 'Immutable preparation review' })).not.toBeInTheDocument();
        expect(sessionStorage.getItem('tracebolt.package-update-intent')).toContain(preview.requestId); expect(approvePackageUpdates).not.toHaveBeenCalled();
    });
    it('does not reinterpret a legacy mode-less stored approval as native consent', async () => {
        const preview = packageUpdatePreview(); sessionStorage.setItem('tracebolt.package-update-intent', JSON.stringify({ deviceId: updateWorkflowDevice, actorId: updateWorkflowActor, sessionKey: operator.expiresAt, intent: { kind: 'approve', requestId: preview.requestId, previewDigest: preview.digest } }));
        nativeResponses(); render(component()); await screen.findByText(/Inconsistent update evidence/); expect(readPackageUpdates).not.toHaveBeenCalled(); expect(approvePackageUpdates).not.toHaveBeenCalled();
    });
});
