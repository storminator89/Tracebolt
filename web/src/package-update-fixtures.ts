import type { PackageIdentity, PackageUpdatePreview, PackageUpdateState, PackageUpdateView } from './package-update-types';
// Test fixtures only. Never import this adapter in application/runtime code.
export const updateWorkflowDevice = `agent_${'a'.repeat(32)}`;
export const updateWorkflowActor = `operator_${'b'.repeat(32)}`;
export const updateWorkflowRequest = `update_${'c'.repeat(32)}`;
export const updateWorkflowTime = '2026-10-07T01:00:00Z';
export function unavailablePackageUpdates(): PackageUpdateView { return { schemaVersion: 'tracebolt.package-update-workflow.v2', deviceId: updateWorkflowDevice, serverNow: updateWorkflowTime, executionMode: 'unavailable', available: false, reason: 'native_adapter_unavailable', preview: null, job: null }; }
export function simulatedPackageUpdates(): PackageUpdateView { return { ...unavailablePackageUpdates(), executionMode: 'simulation', available: true, reason: 'simulation_only' }; }
export function packageUpdatePreview(packages: PackageIdentity[] = [{ name: 'curl', architecture: 'amd64' }], requestId = updateWorkflowRequest): PackageUpdatePreview {
    return { requestId, digest: `sha256:${'d'.repeat(64)}`, actorId: updateWorkflowActor, expiresAt: '2026-10-07T01:05:00Z', transportProfile: 'production-tls', conffilePolicy: 'preserve-modified-dpkg-conffiles', totalBytes: 123456, items: packages.map(item => ({ ...item, fromVersion: '1:8.14.1-2', toVersion: '1:8.14.1-2+deb13u1', sourcePackage: item.name, sourceVersion: '1:8.14.1-2+deb13u1', sourceLabel: 'Fixture Debian', suite: 'trixie-security', component: 'main', archiveSHA256: `sha256:${'e'.repeat(64)}` })) };
}
export function packageUpdateJob(state: PackageUpdateState = 'preview_ready', preview = packageUpdatePreview()): PackageUpdateView {
    const approved = ['approved', 'delivery_unknown', 'applying', 'verifying', 'succeeded', 'needs_intervention'].includes(state);
    const active = ['preparing', 'approved', 'delivery_unknown', 'applying', 'verifying'].includes(state);
    return { ...simulatedPackageUpdates(), available: ['expired', 'revoked', 'preparation_failed', 'succeeded'].includes(state), reason: ['needs_intervention', 'delivery_unknown'].includes(state) ? 'needs_intervention' : active ? 'operation_in_progress' : 'simulation_only', preview, job: { requestId: preview.requestId, state, createdAt: updateWorkflowTime, updatedAt: updateWorkflowTime, approvedAt: approved ? updateWorkflowTime : null, result: ['applying', 'verifying', 'succeeded', 'needs_intervention'].includes(state) ? { phase: state as 'applying' | 'verifying' | 'succeeded' | 'needs_intervention', observedAt: updateWorkflowTime, packages: preview.items.map(item => ({ name: item.name, architecture: item.architecture, expectedVersion: item.toVersion, observedVersion: state === 'succeeded' ? item.toVersion : null, outcome: state === 'succeeded' ? 'verified' : 'unknown' })), reboot: { state: 'unknown', source: 'simulation', observedAt: updateWorkflowTime }, reason: state === 'succeeded' ? 'simulated_verified' : state === 'needs_intervention' ? 'runner_state_unknown' : 'simulated_running' } : null } };
}

export function nativePackageUpdates(): PackageUpdateView { return { ...simulatedPackageUpdates(), executionMode: 'native', reason: 'ready' }; }
export function nativePackageUpdateJob(state: PackageUpdateState = 'preview_ready', preview = packageUpdatePreview()): PackageUpdateView {
    const view = packageUpdateJob(state, preview); view.executionMode = 'native';
    if (view.reason === 'simulation_only') view.reason = 'ready';
    if (view.job?.result) {
        view.job.result.reboot.source = 'native';
        if (view.job.result.reason === 'simulated_running') view.job.result.reason = 'native_running';
        if (view.job.result.reason === 'simulated_verified') view.job.result.reason = 'native_verified';
    }
    return view;
}
