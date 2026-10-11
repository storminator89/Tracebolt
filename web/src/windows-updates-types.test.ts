import vectors from './windows-updates-go-fixture.json';
import { describe, expect, it } from 'vitest';
import { validWindowsInventoryView } from './windows-inventory-types';
import { windowsDeviceId, windowsNow, windowsView } from './windows-inventory-fixture';
import { windowsEventsFixture } from './windows-events-fixture';
import { windowsVolumes } from './windows-volumes-fixture';
import { windowsNetwork } from './windows-network-fixture';
import { windowsServiceStartup } from './windows-service-startup-fixture';
import { windowsUpdates, windowsUpdatesView } from './windows-updates-fixture';
import { validWindowsUpdates, WINDOWS_UPDATES_BYTES, WINDOWS_UPDATES_REASONS, type WindowsUpdates } from './windows-updates-types';

const valid = (v: unknown) => validWindowsUpdates(v, windowsView().snapshot!, windowsNow);
describe('cached Windows update operator contract', () => {
    it.each(vectors)('accepts the source-encoded Go vector: $name', vector => { expect(valid(vector.snapshot)).toBe(true); expect(validWindowsInventoryView({ ...windowsView(), updates: vector.snapshot }, windowsDeviceId)).toBe(true); });
    it('preserves old views and every combination of six independently optional siblings', () => {
        for (let bits = 0; bits < 64; bits++) {
            const v = windowsView(), before = JSON.stringify(v.snapshot);
            if (bits & 1) v.events = windowsEventsFixture();
            if (bits & 2) v.volumes = windowsVolumes();
            if (bits & 4) v.processMetrics = { schemaVersion: 'tracebolt.windows-process-metrics.v1', scope: 'windows-process-metrics-v1', grantId: 'b'.repeat(32), generationId: v.snapshot!.generationId, collectedAt: v.snapshot!.collectedAt, observedCount: 1, truncated: false, rows: [{ pid: 44, cpuPercent: null, cpuQuality: 'first-sample', memoryBytes: '42', memoryQuality: 'observed' }] };
            if (bits & 8) v.network = windowsNetwork();
            if (bits & 16) v.serviceStartup = windowsServiceStartup(v.snapshot!);
            if (bits & 32) v.updates = windowsUpdates();
            expect(validWindowsInventoryView(v, windowsDeviceId), `combination ${bits}`).toBe(true);
            expect(JSON.stringify(v.snapshot)).toBe(before);
        }
    });
    const mutations: [string, (v: WindowsUpdates) => void][] = [
        ['unknown member', v => Object.assign(v, { rawError: 'secret' })], ['unknown row member', v => Object.assign(v.rows[0], { url: 'https://example.invalid' })],
        ['missing member', v => { delete (v as Partial<WindowsUpdates>).reason; }], ['missing row member', v => { delete (v.rows[0] as Partial<typeof v.rows[0]>).metadataTruncated; }],
        ['unknown schema', v => Object.assign(v, { schemaVersion: 'tracebolt.windows-update-inspection.v2' })], ['wrong scope', v => Object.assign(v, { scope: 'windows-inventory-v1' })],
        ['uppercase grant', v => { v.grantId = 'D'.repeat(32); }], ['missing grant', v => { v.grantId = ''; }], ['other generation', v => { v.generationId = `sample_${'b'.repeat(32)}`; }],
        ['unknown source', v => Object.assign(v, { source: 'online' })], ['claimed fresh cache', v => Object.assign(v, { cacheFreshness: 'fresh' })], ['null freshness', v => Object.assign(v, { cacheFreshness: null })],
        ['wrong quality', v => Object.assign(v, { quality: 'healthy' })], ['arbitrary reason', v => Object.assign(v, { reason: 'HRESULT secret' })], ['array reason', v => Object.assign(v, { reason: [] })],
        ['count below rows', v => { v.observedCount = 0; }], ['count overflow', v => { v.observedCount = 2147483648; v.truncated = true; }], ['fraction count', v => { v.observedCount = 4.5; v.truncated = true; }], ['negative count', v => { v.observedCount = -1; }], ['negative zero count', v => { v.observedCount = -0; v.rows = []; }],
        ['silent truncation', v => { v.rows.pop(); }], ['invented truncation', v => { v.truncated = true; }], ['nonboolean truncation', v => Object.assign(v, { truncated: 0 })], ['nonboolean exactness', v => Object.assign(v, { countExact: 'true' })],
        ['inexact observed', v => { v.countExact = false; }], ['observed reason', v => { v.reason = 'windows_updates_bounds'; }], ['partial no reason', v => { v.quality = 'partial'; }],
        ['denied rows', v => { v.quality = 'denied'; v.reason = 'windows_updates_access_denied'; v.countExact = false; }], ['unavailable rows', v => { v.quality = 'unavailable'; v.reason = 'windows_updates_unavailable'; v.countExact = false; }],
        ['null rows', v => Object.assign(v, { rows: null })], ['null row', v => Object.assign(v.rows, { 0: null })], ['duplicate identity', v => { v.rows[1] = { ...v.rows[0] }; }], ['reverse identities', v => { v.rows.reverse(); }],
        ['nil UUID', v => { v.rows[0].updateId = '00000000-0000-0000-0000-000000000000'; }], ['uppercase UUID', v => { v.rows[0].updateId = 'AAAAAAAA-0000-0000-0000-000000000001'; }], ['short UUID', v => { v.rows[0].updateId = '1'; }],
        ['negative revision', v => { v.rows[0].revision = -1; }], ['negative zero revision', v => { v.rows[0].revision = -0; }], ['revision overflow', v => { v.rows[0].revision = 2147483648; }], ['fraction revision', v => { v.rows[0].revision = 0.1; }], ['string revision', v => Object.assign(v.rows[0], { revision: '1' })],
        ['null KB', v => Object.assign(v.rows[0], { kbArticleIds: null })], ['KB not string', v => Object.assign(v.rows[0], { kbArticleIds: [123] })], ['KB duplicate', v => { v.rows[0].kbArticleIds = ['KB1', 'KB1']; }], ['KB unsorted', v => { v.rows[0].kbArticleIds = ['KB2', 'KB1']; }], ['KB leading zero', v => { v.rows[0].kbArticleIds = ['KB01']; }], ['KB overlong', v => { v.rows[0].kbArticleIds = ['KB12345678901']; }], ['KB lowercase', v => { v.rows[0].kbArticleIds = ['kb1']; }], ['KB bound', v => { v.rows[0].kbArticleIds = Array.from({ length: 9 }, (_, i) => `KB${i + 1}`); }],
        ['unknown severity', v => Object.assign(v.rows[0], { severity: 'severe' })], ['array severity', v => Object.assign(v.rows[0], { severity: ['critical'] })], ['null downloaded', v => Object.assign(v.rows[0], { downloaded: null })], ['nonboolean metadata truncation', v => Object.assign(v.rows[0], { metadataTruncated: 0 })],
        ['earlier capture', v => { v.collectedAt = '2026-10-07T11:59:59.999999999Z'; }], ['later capture', v => { v.collectedAt = '2026-10-07T12:00:00.000000001Z'; }], ['non-UTC time', v => { v.collectedAt = '2026-10-07T12:00:00+00:00'; }], ['invalid calendar time', v => { v.collectedAt = '2026-02-30T12:00:00Z'; }],
    ];
    it.each(mutations)('rejects %s', (_label, mutate) => { const v = windowsUpdates(); mutate(v); expect(valid(v)).toBe(false); expect(validWindowsInventoryView({ ...windowsView(), updates: v }, windowsDeviceId)).toBe(false); });
    it.each(['', ' ', ' x', 'x ', 'x  y', 'x\ty', 'x\ny', 'x\u202ey', 'x\u00a0y', 'x\u2028y', 'x\u2029y', '\uD800', '\uDC00', 'x'.repeat(257), 'é'.repeat(129)])('rejects malformed title %j', title => { const v = windowsUpdates(); v.rows[0].title = title; expect(valid(v)).toBe(false); });
    it('accepts literal markup and valid Unicode without interpreting them, and allows boundary values', () => {
        const v = windowsUpdates(); v.rows[0].title = '<img src=x onerror=alert(1)> & 🛠'; v.rows[0].revision = 0; v.rows[1].revision = 2147483647; v.rows[0].kbArticleIds = ['KB1', 'KB1234567890']; expect(valid(v)).toBe(true);
        v.rows[1].updateId = v.rows[0].updateId; expect(valid(v)).toBe(true); v.rows[1].revision = 0; expect(valid(v)).toBe(false);
    });
    it('enforces 64 rows and Go HTML-escaped 24 KiB independently', () => {
        expect(valid(windowsUpdates(64))).toBe(true); expect(valid(windowsUpdates(65))).toBe(false);
        const v = windowsUpdates(64); v.rows.forEach(row => { row.title = '<'.repeat(60); });
        expect(new TextEncoder().encode(JSON.stringify(v)).length).toBeLessThan(WINDOWS_UPDATES_BYTES);
        expect(valid(v)).toBe(false);
    });
    it('preserves exact, bounded, partial and failure truth including zero and count lower bounds', () => {
        expect(valid(windowsUpdates(0))).toBe(true);
        const v = windowsUpdates(); v.observedCount = 2147483647; v.truncated = true; expect(valid(v)).toBe(true);
        for (const countExact of [false, true]) for (const reason of WINDOWS_UPDATES_REASONS.filter(Boolean)) { Object.assign(v, { quality: 'partial', reason, countExact }); expect(valid(v)).toBe(true); }
        Object.assign(v, { rows: [], observedCount: 0, truncated: false, countExact: false }); expect(valid(v)).toBe(true);
        for (const [quality, reason] of [['denied', 'windows_updates_access_denied'], ['unavailable', 'windows_updates_unavailable']] as const) {
            Object.assign(v, { quality, reason }); expect(valid(v)).toBe(true); v.countExact = true; expect(valid(v)).toBe(false); v.countExact = false;
            v.reason = quality === 'denied' ? 'windows_updates_unavailable' : 'windows_updates_access_denied'; expect(valid(v)).toBe(false);
        }
    });
    it('requires an independent grant from any present older extension', () => {
        for (const sibling of ['events', 'volumes', 'processMetrics', 'network', 'serviceStartup'] as const) {
            const v = windowsUpdatesView();
            const extensions = { events: windowsEventsFixture(), volumes: windowsVolumes(), network: windowsNetwork(), serviceStartup: windowsServiceStartup(v.snapshot!), processMetrics: { schemaVersion: 'tracebolt.windows-process-metrics.v1', scope: 'windows-process-metrics-v1', grantId: 'b'.repeat(32), generationId: v.snapshot!.generationId, collectedAt: v.snapshot!.collectedAt, observedCount: 1, truncated: false, rows: [{ pid: 44, cpuPercent: null, cpuQuality: 'first-sample', memoryBytes: '42', memoryQuality: 'observed' }] } };
            Object.assign(v, { [sibling]: extensions[sibling] }); expect(validWindowsInventoryView(v, windowsDeviceId)).toBe(true); v.updates.grantId = extensions[sibling].grantId; expect(validWindowsInventoryView(v, windowsDeviceId)).toBe(false);
        }
    });
    it('rejects absent base, explicit null, aliases, moved extension and non-data statuses', () => {
        expect(validWindowsInventoryView({ ...windowsView(), updates: null }, windowsDeviceId)).toBe(false);
        expect(validWindowsInventoryView({ ...windowsView(), windowsUpdates: windowsUpdates() }, windowsDeviceId)).toBe(false);
        for (const status of ['revoked', 'unavailable', 'awaiting', 'not_configured']) expect(validWindowsInventoryView({ ...windowsUpdatesView(), status, snapshot: null }, windowsDeviceId)).toBe(false);
        const v = windowsView(); Object.assign(v.snapshot!, { updates: windowsUpdates() }); expect(validWindowsInventoryView(v, windowsDeviceId)).toBe(false);
    });
    it('binds original capture exactly with nanosecond age, future and receipt constraints', () => {
        const v = windowsUpdatesView(); v.updates.collectedAt += ''; v.updates.collectedAt = v.snapshot!.collectedAt.replace('Z', '.000000000Z'); expect(validWindowsInventoryView(v, windowsDeviceId)).toBe(true);
        for (const time of ['2026-10-07T12:00:40.000000001Z', '2026-10-07T12:00:41Z']) { v.snapshot!.collectedAt = v.updates.collectedAt = time; v.status = 'stale'; expect(validWindowsInventoryView(v, windowsDeviceId)).toBe(false); }
        v.snapshot!.collectedAt = v.updates.collectedAt = '2026-10-07T12:00:11Z'; expect(validWindowsInventoryView(v, windowsDeviceId)).toBe(true);
        v.receivedAt = v.serverNow; v.snapshot!.collectedAt = v.updates.collectedAt = '2026-10-07T12:00:40Z'; expect(validWindowsInventoryView(v, windowsDeviceId)).toBe(true);
        v.snapshot!.collectedAt = v.updates.collectedAt = '2026-10-07T12:00:41Z'; expect(validWindowsInventoryView(v, windowsDeviceId)).toBe(false);
        v.snapshot!.collectedAt = v.updates.collectedAt = '2026-10-06T12:00:10Z'; expect(validWindowsInventoryView(v, windowsDeviceId)).toBe(false);
        v.snapshot!.collectedAt = v.updates.collectedAt = '2026-10-06T12:00:10.000000001Z'; expect(validWindowsInventoryView(v, windowsDeviceId)).toBe(true);
        v.snapshot!.collectedAt = v.updates.collectedAt = '2026-10-07T12:00:00Z'; v.receivedAt = '2026-10-07T11:59:29.999999999Z'; expect(validWindowsInventoryView(v, windowsDeviceId)).toBe(false);
    });
});
