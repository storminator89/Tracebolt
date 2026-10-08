import { describe, expect, it } from 'vitest';
import { sha256Bytes } from './sha256';
import { validWindowsInventorySnapshot, validWindowsInventoryView, type WindowsService } from './windows-inventory-types';
import { windowsDeviceId, windowsNow, windowsView } from './windows-inventory-fixture';
import { windowsVolumes } from './windows-volumes-fixture';
import { windowsNetwork } from './windows-network-fixture';
import { windowsServiceStartupView } from './windows-service-startup-fixture';
import { validWindowsServiceStartup, windowsServicesCanonicalJSON, windowsServicesDigest, WINDOWS_SERVICE_STARTUP_BYTES, type WindowsServiceStartup } from './windows-service-startup-types';
import vectors from './windows-service-startup-go-fixture.json';

describe('bounded synchronous canonical SHA-256', () => {
    it('matches standard empty, ASCII and multi-block UTF-8 vectors', () => {
        for (const [text, digest] of [['', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'], ['abc', 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'], ['a'.repeat(1000), '41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3']]) expect(sha256Bytes(new TextEncoder().encode(text))).toBe(digest);
    });
    it.each(vectors)('matches the cross-Go $name exact-row projection', vector => {
        const rows = vector.services as WindowsService[];
        expect(windowsServicesCanonicalJSON(rows)).toBe(vector.canonicalJSON);
        expect(windowsServicesDigest(rows)).toBe(vector.sha256);
        // JS property insertion order is not the canonical Go struct field order.
        const reordered = rows.map(row => ({ pid: row.pid, state: row.state, displayName: row.displayName, name: row.name }));
        expect(windowsServicesDigest(reordered)).toBe(vector.sha256);
        const view = windowsView(); view.snapshot!.services.rows = rows; view.snapshot!.services.observedCount = rows.length;
        expect(validWindowsInventorySnapshot(view.snapshot)).toBe(vector.validBase);
    });
});

describe('strict Windows service startup operator contract', () => {
    const valid = (v: WindowsServiceStartup) => validWindowsServiceStartup(v, windowsServiceStartupView().snapshot!, windowsNow);
    it('accepts absent capability without changing v1 rows and accepts all truthful field outcomes', () => {
        expect(validWindowsInventoryView(windowsView(), windowsDeviceId)).toBe(true);
        const v = windowsServiceStartupView(), before = JSON.stringify(v.snapshot);
        expect(validWindowsInventoryView(v, windowsDeviceId)).toBe(true);
        expect(JSON.stringify(v.snapshot)).toBe(before);
        expect(v.snapshot!.services.rows.every(row => Object.keys(row).join(',') === 'name,displayName,state,pid')).toBe(true);
    });
    it('accepts all 32 combinations of the five independent optional fields', () => {
        for (let bits = 0; bits < 32; bits++) {
            const v = windowsView();
            if (bits & 1) v.events = { schemaVersion: 'tracebolt.windows-event-metadata.v1', scope: 'windows-application-system-event-headers-v1', grantId: 'e'.repeat(32), generationId: v.snapshot!.generationId, collectedAt: '2026-10-07T12:00:02Z', channels: ['Application', 'System'].map(channel => ({ channel: channel as 'Application' | 'System', quality: 'observed', reason: '', complete: true, truncated: false, observedCount: 0, rows: [] })) };
            if (bits & 2) v.volumes = windowsVolumes();
            if (bits & 4) v.processMetrics = { schemaVersion: 'tracebolt.windows-process-metrics.v1', scope: 'windows-process-metrics-v1', grantId: 'b'.repeat(32), generationId: v.snapshot!.generationId, collectedAt: '2026-10-07T12:00:02Z', observedCount: 1, truncated: false, rows: [{ pid: 44, cpuPercent: null, cpuQuality: 'first-sample', memoryBytes: '42', memoryQuality: 'observed' }] };
            if (bits & 8) v.network = windowsNetwork();
            if (bits & 16) { v.snapshot!.services = windowsServiceStartupView().snapshot!.services; v.serviceStartup = windowsServiceStartupView().serviceStartup; }
            expect(validWindowsInventoryView(v, windowsDeviceId), `combination ${bits}`).toBe(true);
        }
    });
    const mutations: [string, (v: WindowsServiceStartup) => void][] = [
        ['unknown member', v => Object.assign(v, { private: 'not-for-display' })],
        ['unknown row member', v => Object.assign(v.rows[0], { executable: 'not-for-display' })],
        ['missing member', v => { delete (v as Partial<WindowsServiceStartup>).truncated; }],
        ['wrong schema', v => Object.assign(v, { schemaVersion: 'tracebolt.windows-service-startup.v2' })],
        ['wrong scope', v => Object.assign(v, { scope: 'windows-inventory-v1' })],
        ['missing grant', v => { v.grantId = ''; }], ['uppercase grant', v => { v.grantId = 'C'.repeat(32); }],
        ['wrong generation', v => { v.generationId = `sample_${'b'.repeat(32)}`; }],
        ['prefixed digest', v => { v.servicesSHA256 = `sha256:${v.servicesSHA256}`; }],
        ['uppercase digest', v => { v.servicesSHA256 = v.servicesSHA256.toUpperCase(); }], ['wrong digest', v => { v.servicesSHA256 = '0'.repeat(64); }],
        ['unsorted indices', v => { v.rows.reverse(); }], ['duplicate index', v => { v.rows[1].serviceIndex = 0; }],
        ['negative index', v => { v.rows[0].serviceIndex = -1; }], ['negative zero index', v => { v.rows[0].serviceIndex = -0; }],
        ['fractional index', v => { v.rows[0].serviceIndex = 0.5; }], ['out-of-range index', v => { v.rows[9].serviceIndex = 10; }],
        ['index ceiling', v => { v.rows[9].serviceIndex = 128; }],
        ['count below base', v => { v.requestedCount--; v.rows.pop(); }], ['count above base', v => { v.requestedCount++; v.truncated = true; }],
        ['count above cap', v => { v.requestedCount = 129; v.truncated = true; }], ['negative count', v => { v.requestedCount = -1; }],
        ['negative zero count', v => { v.requestedCount = -0; v.rows = []; }], ['fractional count', v => { v.requestedCount = 10.5; }],
        ['silent omission', v => { v.rows.pop(); }], ['false truncation', v => { v.truncated = true; }],
        ['null rows', v => Object.assign(v, { rows: null })],
        ['missing observed mode', v => { v.rows[0].startupMode = null; }], ['invented mode', v => Object.assign(v.rows[0], { startupMode: 'boot' })],
        ['denied with mode', v => { v.rows[0].startupQuality = 'denied'; }],
        ['unknown with mode', v => { v.rows[0].startupQuality = 'unknown'; }],
        ['unknown quality', v => Object.assign(v.rows[0], { startupQuality: 'healthy' })],
        ['denied with delayed observed', v => { v.rows[4].delayedAutoQuality = 'observed'; v.rows[4].delayedAutoStart = false; }],
        ['unavailable with delayed not applicable', v => { v.rows[5].delayedAutoQuality = 'not-applicable'; }],
        ['unknown with delayed unavailable', v => { v.rows[6].delayedAutoQuality = 'unavailable'; }],
        ['manual with delayed observed', v => { v.rows[2].delayedAutoQuality = 'observed'; v.rows[2].delayedAutoStart = false; }],
        ['disabled with delayed denied', v => { v.rows[3].delayedAutoQuality = 'denied'; }],
        ['automatic with delayed not applicable', v => { v.rows[0].delayedAutoQuality = 'not-applicable'; v.rows[0].delayedAutoStart = null; }],
        ['observed delayed null', v => { v.rows[0].delayedAutoStart = null; }], ['observed delayed number', v => Object.assign(v.rows[0], { delayedAutoStart: 0 })],
        ['denied delayed false', v => { v.rows[7].delayedAutoStart = false; }], ['unavailable delayed true', v => { v.rows[8].delayedAutoStart = true; }],
        ['capture before base by nanosecond', v => { v.collectedAt = '2026-10-07T11:59:59.999999999Z'; }],
        ['future capture', v => { v.collectedAt = '2026-10-07T12:00:40.000000001Z'; }],
        ['invalid date', v => { v.collectedAt = '2026-02-30T12:00:00Z'; }], ['non-UTC date', v => { v.collectedAt = '2026-10-07T12:00:00+00:00'; }],
        ['expired capture', v => { v.collectedAt = '2026-10-06T12:00:10Z'; }],
    ];
    it.each(mutations)('rejects %s', (_label, mutate) => { const v = windowsServiceStartupView().serviceStartup; mutate(v); expect(valid(v)).toBe(false); });
    it('requires original ordinal digest binding through reorder, trimming, duplicates and field changes', () => {
        for (const mutate of [v => { v.snapshot!.services.rows.reverse(); }, v => { v.snapshot!.services.rows[0].displayName += '!'; }, v => { v.snapshot!.services.rows[0].state = 'paused'; }, v => { v.snapshot!.services.rows[0].pid++; }, v => { v.snapshot!.services.rows[0].name = v.snapshot!.services.rows[1].name; }] as ((v: ReturnType<typeof windowsServiceStartupView>) => void)[]) {
            const v = windowsServiceStartupView(); mutate(v); expect(validWindowsInventoryView(v, windowsDeviceId)).toBe(false);
        }
        const v = windowsServiceStartupView();
        v.snapshot!.services.rows[1] = { ...v.snapshot!.services.rows[0] }; v.serviceStartup.servicesSHA256 = windowsServicesDigest(v.snapshot!.services.rows);
        expect(validWindowsInventoryView(v, windowsDeviceId)).toBe(true);
        v.serviceStartup.rows = [v.serviceStartup.rows[0], v.serviceStartup.rows[3], v.serviceStartup.rows[9]]; v.serviceStartup.truncated = true;
        expect(validWindowsInventoryView(v, windowsDeviceId)).toBe(true);
    });
    it('enforces 16 KiB and up to 128 requested indices even when fewer startup rows fit', () => {
        const v = windowsServiceStartupView(128);
        expect(new TextEncoder().encode(JSON.stringify(v.serviceStartup)).byteLength).toBeGreaterThan(WINDOWS_SERVICE_STARTUP_BYTES);
        expect(validWindowsInventoryView(v, windowsDeviceId)).toBe(false);
        while (new TextEncoder().encode(JSON.stringify(v.serviceStartup)).byteLength > WINDOWS_SERVICE_STARTUP_BYTES) { v.serviceStartup.rows.pop(); v.serviceStartup.truncated = true; }
        expect(validWindowsInventoryView(v, windowsDeviceId)).toBe(true);
        v.serviceStartup.rows = [v.serviceStartup.rows[0], { ...v.serviceStartup.rows[1], serviceIndex: 127 }];
        expect(validWindowsInventoryView(v, windowsDeviceId)).toBe(true);
        v.serviceStartup.rows = []; expect(validWindowsInventoryView(v, windowsDeviceId)).toBe(true);
        const zero = windowsServiceStartupView(0); expect(validWindowsInventoryView(zero, windowsDeviceId)).toBe(true);
    });
    it('does not accept extension fields inside v1 base rows or unrecognized aliases', () => {
        const v = windowsServiceStartupView(); Object.assign(v.snapshot!.services.rows[0], { startupMode: 'automatic' });
        expect(validWindowsInventorySnapshot(v.snapshot)).toBe(false);
        expect(validWindowsInventoryView({ ...windowsView(), serviceStartup: null }, windowsDeviceId)).toBe(false);
        expect(validWindowsInventoryView({ ...windowsView(), startup: windowsServiceStartupView().serviceStartup }, windowsDeviceId)).toBe(false);
    });
    it('rejects absent base, hidden-status payloads and capture beyond original receipt skew', () => {
        for (const status of ['revoked', 'unavailable', 'awaiting', 'not_configured']) expect(validWindowsInventoryView({ ...windowsServiceStartupView(), status, snapshot: null }, windowsDeviceId)).toBe(false);
        const v = windowsServiceStartupView(); v.serviceStartup.collectedAt = '2026-10-07T12:00:31Z'; expect(validWindowsInventoryView(v, windowsDeviceId)).toBe(true);
        v.serviceStartup.collectedAt = '2026-10-07T12:00:31.000000001Z'; expect(validWindowsInventoryView(v, windowsDeviceId)).toBe(false);
        v.serviceStartup.collectedAt = '2026-10-07T12:00:00.000000001Z'; expect(validWindowsInventoryView(v, windowsDeviceId)).toBe(true);
    });
});
