import { describe, expect, it } from 'vitest';
import goWorkflowFixtures from './package-update-go-fixtures.json';
import { emptyCachedUpdatesView } from './cached-updates-fixtures';
import { nativePackageUpdateJob, nativePackageUpdates, packageUpdateJob, packageUpdatePreview, simulatedPackageUpdates, unavailablePackageUpdates, updateWorkflowDevice } from './package-update-fixtures';
import { parsePackageUpdateView, validPackageUpdateView } from './package-update-types';
const valid = (value: unknown) => validPackageUpdateView(value, updateWorkflowDevice);
describe('package-update workflow contract', () => {
    it.each(Object.entries(goWorkflowFixtures))('accepts the real Go wire projection for %s', (_state, view) => { expect(validPackageUpdateView(view, view.deviceId)).toBe(true); });
    it('keeps unconfigured native execution unavailable and cannot promote inventory to evidence', () => {
        expect(valid(unavailablePackageUpdates())).toBe(true); expect(valid({ ...unavailablePackageUpdates(), available: true })).toBe(false);
        expect(valid({ ...unavailablePackageUpdates(), executionMode: 'native' })).toBe(true);
        expect(valid({ ...nativePackageUpdates(), schemaVersion: 'tracebolt.package-update-workflow.v1' })).toBe(false);
        expect(valid({ ...unavailablePackageUpdates(), preview: packageUpdatePreview() })).toBe(false);
        expect(valid(emptyCachedUpdatesView())).toBe(false);
    });
    it.each(['preview_ready', 'approved', 'delivery_unknown', 'applying', 'verifying', 'succeeded', 'needs_intervention', 'expired', 'revoked', 'preparation_failed'] as const)('validates simulation %s with retained immutable preview', state => { expect(valid(packageUpdateJob(state))).toBe(true); });
    it('requires distinct exact identities and bounded preparation size', () => {
        const view = packageUpdateJob(); view.preview!.items.push({ ...view.preview!.items[0] }); expect(valid(view)).toBe(false);
        view.preview!.items[1].architecture = 'arm64'; expect(valid(view)).toBe(true);
        view.preview!.items = Array.from({ length: 33 }, (_, i) => ({ ...view.preview!.items[0], name: `fixture-${i}` })); expect(valid(view)).toBe(false);
    });
    it.each(['command', 'plan', 'selectedPackages', 'approval', 'services'])('rejects unknown field %s', key => { expect(valid({ ...simulatedPackageUpdates(), [key]: null })).toBe(false); });
    it('rejects every missing top-level field', () => { for (const key of Object.keys(simulatedPackageUpdates())) { const value: Record<string, unknown> = { ...simulatedPackageUpdates() }; delete value[key]; expect(valid(value), key).toBe(false); } });
    it.each(['', 'agent_', 'demo_fixture', 'agent_/../other', `agent_${'A'.repeat(32)}`, `agent_${'g'.repeat(32)}`, `agent_${'0'.repeat(32)}`])('rejects invalid expected device %s', deviceId => { expect(validPackageUpdateView({ ...unavailablePackageUpdates(), deviceId }, deviceId)).toBe(false); });
    it.each([null, '', 'yesterday', '2026-10-07', '2026-10-07T01:00:00', '2026-10-07T01:00:00+00:00', '2026-02-29T01:00:00Z', '2026-10-07T24:00:00Z', '1970-01-01T00:00:00Z'])('rejects invalid clock %j', serverNow => { expect(valid({ ...unavailablePackageUpdates(), serverNow })).toBe(false); });
    it('preserves UTC fractional precision', () => { const value = { ...unavailablePackageUpdates(), serverNow: '2026-10-07T01:00:00.123456789Z' }; expect(parsePackageUpdateView(value, updateWorkflowDevice)).toEqual(value); });
    it('rejects inconsistent availability during preparation and approval', () => {
        for (const state of ['preview_ready', 'approved', 'applying', 'verifying', 'needs_intervention'] as const) expect(valid({ ...packageUpdateJob(state), available: true })).toBe(false);
    });
    it('accepts a terminal exact-history response when newer work blocks device admission', () => {
        expect(valid({ ...packageUpdateJob('succeeded'), available: false })).toBe(true);
    });
    it('rejects success with a running or unknown reason despite matching versions', () => {
        const view = packageUpdateJob('succeeded'); view.job!.result!.reason = 'simulated_running'; expect(valid(view)).toBe(false);
    });
    it('requires source archive evidence, actor and exact request binding', () => {
        const view = packageUpdateJob(); view.preview!.items[0].archiveSHA256 = 'e'.repeat(64); expect(valid(view)).toBe(false); view.preview!.items[0].archiveSHA256 = `sha256:${'e'.repeat(64)}`; expect(valid(view)).toBe(true);
        const actor = packageUpdateJob(); actor.preview!.actorId = 'shared'; expect(valid(actor)).toBe(false);
        const id = packageUpdateJob(); id.job!.requestId = `update_${'f'.repeat(32)}`; expect(valid(id)).toBe(false);
    });
    it('never accepts a success state without every approved version independently verified', () => {
        const noEvidence = packageUpdateJob('succeeded'); noEvidence.job!.result = null; expect(valid(noEvidence)).toBe(false);
        const mismatch = packageUpdateJob('succeeded'); mismatch.job!.result!.packages[0].observedVersion = 'old'; expect(valid(mismatch)).toBe(false);
        const unknown = packageUpdateJob('succeeded'); unknown.job!.result!.packages[0].outcome = 'unknown'; expect(valid(unknown)).toBe(false);
        const changed = packageUpdateJob('succeeded'); changed.job!.result!.packages[0].expectedVersion = 'other'; changed.job!.result!.packages[0].observedVersion = 'other'; expect(valid(changed)).toBe(false);
        const missing = packageUpdateJob('succeeded', packageUpdatePreview([{ name: 'curl', architecture: 'amd64' }, { name: 'curl', architecture: 'arm64' }])); missing.job!.result!.packages.pop(); expect(valid(missing)).toBe(false);
        const native = packageUpdateJob('succeeded'); native.job!.result!.reboot.source = 'native'; expect(valid(native)).toBe(false);
    });
    it.each(['preview_ready', 'approved', 'delivery_unknown', 'applying', 'verifying', 'succeeded', 'needs_intervention'] as const)('accepts native %s without relabeling it as simulation', state => { expect(valid(nativePackageUpdateJob(state))).toBe(true); });
    it('retains a native preview when current capabilities are stale but does not make it available', () => {
        const view = nativePackageUpdateJob(); view.reason = 'native_adapter_unavailable'; expect(valid(view)).toBe(true);
        view.available = true; expect(valid(view)).toBe(false);
    });
    it('accepts uncertain native preparation with no invented preview, approval or result', () => {
        const view = nativePackageUpdateJob('needs_intervention'); view.preview = null; view.job!.approvedAt = null; view.job!.result = null; expect(valid(view)).toBe(true);
    });
    it('requires source and result reason to match native mode', () => {
        for (const field of ['source', 'reason'] as const) {
            const view = nativePackageUpdateJob('succeeded');
            if (field === 'source') view.job!.result!.reboot.source = 'simulation'; else view.job!.result!.reason = 'simulated_verified';
            expect(valid(view)).toBe(false);
        }
        expect(valid({ ...nativePackageUpdates(), reason: 'simulation_only' })).toBe(false);
        expect(valid({ ...simulatedPackageUpdates(), reason: 'ready' })).toBe(false);
    });

});
