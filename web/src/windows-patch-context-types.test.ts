import goFixture from '../../internal/windowspatchcontext/testdata/snapshot.json';
import { describe, expect, it } from 'vitest';
import { windowsDeviceId, windowsNow, windowsView } from './windows-inventory-fixture';
import { windowsPatchContext, windowsPatchContextView } from './windows-patch-context-fixture';
import { validWindowsPatchContext, type WindowsPatchContext } from './windows-patch-context-types';
import { validWindowsInventoryView } from './windows-inventory-types';
import { windowsUpdates } from './windows-updates-fixture';
import { windowsAdapterContext } from './windows-adapter-context-fixture';
import { windowsNetwork } from './windows-network-fixture';
import { windowsVolumes } from './windows-volumes-fixture';
import { windowsEventsFixture } from './windows-events-fixture';
import { windowsServiceStartup } from './windows-service-startup-fixture';
const valid = (v: unknown) => validWindowsPatchContext(v, windowsView().snapshot!, windowsNow);

describe('Separate bounded Windows patch context contract', () => {
    it('accepts the Go Decode/Encode-validated canonical snapshot with exact original binding', () => {
        const snapshot = { ...windowsView().snapshot!, generationId: goFixture.generationId, collectedAt: goFixture.collectedAt };
        const serverNow = new Date(Date.parse(goFixture.collectedAt) + 1000).toISOString();
        expect(validWindowsPatchContext(goFixture, snapshot, serverNow)).toBe(true);
        expect(validWindowsInventoryView({ ...windowsView(), snapshot, serverNow, receivedAt: serverNow, patchContext: goFixture }, windowsDeviceId)).toBe(true);
        expect(validWindowsPatchContext(goFixture, { ...snapshot, collectedAt: new Date(Date.parse(snapshot.collectedAt) + 1).toISOString() }, serverNow)).toBe(false);
    });
    it('accepts the optional sibling and independent updates/adapter grants without modifying old views', () => {
        expect(valid(windowsPatchContext())).toBe(true);
        expect(validWindowsInventoryView(windowsView(), windowsDeviceId)).toBe(true);
        expect(validWindowsInventoryView({ ...windowsPatchContextView(), updates: windowsUpdates(), adapterContext: windowsAdapterContext() }, windowsDeviceId)).toBe(true);
    });
    it('keeps repeated events for the same update and nonconsecutive source indices', () => {
        const v = windowsPatchContext(); Object.assign(v.history.rows[1], { updateId: v.history.rows[0].updateId, revision: v.history.rows[0].revision, index: 63 }); v.history.totalCount = 64; expect(valid(v)).toBe(true);
    });
    it.each([true, false])('allows truthful partial history with exact=%s', countExact => {
        const v = windowsPatchContext(); Object.assign(v.history, { quality: 'partial', reason: 'windows_patch_context_invalid_metadata', countExact }); expect(valid(v)).toBe(true);
    });
    it.each(['absent', 'denied', 'unavailable'] as const)('retains independent %s OS evidence without inventing a value', quality => {
        const v = windowsPatchContext(); v.os.build = { value: null, quality }; expect(valid(v)).toBe(true); v.os.build.value = '0'; expect(valid(v)).toBe(false);
    });
    const mutations: [string, (v: WindowsPatchContext) => void][] = [
        ['unknown property', v => Object.assign(v, { raw: 'private' })], ['reused schema', v => Object.assign(v, { schemaVersion: 'tracebolt.windows-update-inspection.v1' })],
        ['wrong generation', v => { v.generationId = `sample_${'8'.repeat(32)}`; }], ['younger original capture', v => { v.collectedAt = '2026-10-07T12:00:00.000000001Z'; }],
        ['invalid OS text', v => { v.os.edition.value = 'Windows\nPro'; }], ['non-ASCII OS text', v => { v.os.release.value = '24HÄ'; }], ['long edition', v => { v.os.edition.value = 'x'.repeat(65); }],
        ['unobserved OS value', v => { v.os.edition.quality = 'denied'; }], ['empty observed OS', v => { v.os.edition.value = ''; }], ['noncanonical build', v => { v.os.build.value = '026100'; }], ['uint32 overflow', v => { v.os.revision.value = '4294967296'; }],
        ['invented reboot state', v => Object.assign(v.reboot, { servicing: 'healthy' })], ['unknown reboot source', v => Object.assign(v.reboot, { other: 'clear' })],
        ['empty partial reason', v => { v.history.quality = 'partial'; }], ['observed reason', v => { v.history.reason = 'windows_patch_context_bounds'; }], ['nonexact observed count', v => { v.history.countExact = false; }],
        ['raw reason', v => Object.assign(v.history, { reason: 'private error' })], ['int32 overflow', v => { v.history.totalCount = 2147483648; }], ['wrong truncation', v => { v.history.truncated = false; }], ['rows on denied result', v => { v.history.quality = 'denied'; }],
        ['newer row out of order', v => { v.history.rows[1].occurredAt = '2026-10-07T11:00:00Z'; }], ['index beyond total', v => { v.history.rows[1].index = 8; }], ['signed revision overflow', v => { v.history.rows[0].revision = 2147483648; }], ['double space OS text', v => { v.os.edition.value = 'Windows  Pro'; }],
        ['source index overflow', v => { v.history.rows[0].index = 64; }], ['duplicate index', v => { v.history.rows[1].index = 0; }], ['negative-zero index', v => { v.history.rows[0].index = -0; }],
        ['null GUID', v => { v.history.rows[0].updateId = '00000000-0000-0000-0000-000000000000'; }], ['uppercase HRESULT', v => { v.history.rows[0].hresult = '800A0001'; }], ['HRESULT prefix', v => { v.history.rows[0].hresult = '0x00000000'; }],
        ['impossible date', v => { v.history.rows[0].occurredAt = '2026-02-30T12:00:00Z'; }], ['too-future history', v => { v.history.rows[0].occurredAt = '2026-10-07T12:02:00.000000001Z'; }], ['pre-epoch event', v => { v.history.rows[0].occurredAt = '1969-12-31T23:59:59Z'; }],
        ['bad operation', v => Object.assign(v.history.rows[0], { operation: 'download' })], ['bad result', v => Object.assign(v.history.rows[0], { result: 'installed' })], ['long UTF8 title', v => { v.history.rows[0].title = 'ä'.repeat(129); }], ['unsafe format title', v => { v.history.rows[0].title = 'update\u202eexe'; }],
    ];
    it.each(mutations)('rejects %s', (_label, mutate) => { const v = windowsPatchContext(); mutate(v); expect(valid(v)).toBe(false); });
    it('uses inclusive uint32 and history skew bounds, while byte bounds count Go HTML escaping', () => {
        const v = windowsPatchContext(); v.os.build.value = '4294967295'; v.history.rows[0].revision = 2147483647; v.history.rows[0].occurredAt = '2026-10-07T12:02:00Z'; expect(valid(v)).toBe(true);
        v.history.rows = Array.from({ length: 64 }, (_, index) => ({ ...v.history.rows[0], index, title: '<'.repeat(256) })); v.history.totalCount = 64; v.history.truncated = false; expect(valid(v)).toBe(false);
    });
    it.each(['denied', 'unavailable'] as const)('accepts empty %s history, without implying an observed zero', quality => {
        const v = windowsPatchContext(); Object.assign(v.history, { quality, reason: quality === 'denied' ? 'windows_patch_context_access_denied' : 'windows_patch_context_unavailable', rows: [], totalCount: 0, truncated: false, countExact: false }); expect(valid(v)).toBe(true);
    });
    it('rejects sibling grant collisions, null siblings and private data after authority removal', () => {
        const v = { ...windowsPatchContextView(), updates: windowsUpdates(), adapterContext: windowsAdapterContext(), network: windowsNetwork(), volumes: windowsVolumes(), events: windowsEventsFixture(), serviceStartup: windowsServiceStartup(windowsView().snapshot!), processMetrics: { schemaVersion: 'tracebolt.windows-process-metrics.v1', scope: 'windows-process-metrics-v1', grantId: '7'.repeat(32), generationId: windowsView().snapshot!.generationId, collectedAt: windowsView().snapshot!.collectedAt, observedCount: 1, truncated: false, rows: [{ pid: 44, cpuPercent: null, cpuQuality: 'first-sample', memoryBytes: '42', memoryQuality: 'observed' }] } };
        expect(validWindowsInventoryView(v, windowsDeviceId)).toBe(true);
        for (const sibling of [v.updates, v.adapterContext, v.network, v.volumes, v.events, v.serviceStartup, v.processMetrics]) { const fresh = structuredClone(v); fresh.patchContext.grantId = sibling.grantId; expect(validWindowsInventoryView(fresh, windowsDeviceId)).toBe(false); }
        expect(validWindowsInventoryView({ ...v, patchContext: null }, windowsDeviceId)).toBe(false);
        for (const status of ['revoked', 'unavailable', 'awaiting', 'not_configured']) expect(validWindowsInventoryView({ ...v, status, snapshot: null }, windowsDeviceId)).toBe(false);
    });
});
