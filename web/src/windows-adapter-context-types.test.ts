import goFixture from './windows-adapter-context-go-fixture.json';
import { describe, expect, it } from 'vitest';
import { windowsAdapterContext, windowsAdapterContextView } from './windows-adapter-context-fixture';
import { validWindowsAdapterContext, WINDOWS_ADAPTER_CONTEXT_BYTES, WINDOWS_ADAPTER_STATES, type WindowsAdapterContext } from './windows-adapter-context-types';
import { validWindowsInventoryView } from './windows-inventory-types';
import { windowsDeviceId, windowsNow, windowsView } from './windows-inventory-fixture';
import { windowsNetwork } from './windows-network-fixture';
import { windowsVolumes } from './windows-volumes-fixture';
import { windowsEventsFixture } from './windows-events-fixture';
import { windowsServiceStartup } from './windows-service-startup-fixture';
import { windowsUpdates } from './windows-updates-fixture';

const valid = (v: unknown) => validWindowsAdapterContext(v, windowsAdapterContext().generationId, windowsNow);
describe('Windows adapter context strict contract', () => {
    it('accepts the Go-validated canonical vector, including Unicode, escaped HTML and nanosecond capture', () => {
        const serverNow = '2026-10-11T08:00:01Z';
        expect(validWindowsAdapterContext(goFixture, goFixture.generationId, serverNow)).toBe(true);
        expect(goFixture.rows[0].name).toBe('Invented adapter & <tag> 日本 😀');
        expect(goFixture.rows[0].gateways.addresses).toEqual(['fe80::1%7']);
        const v = { ...windowsView(), serverNow, receivedAt: '2026-10-11T08:00:00.123456790Z', snapshot: { ...windowsView().snapshot!, generationId: goFixture.generationId, collectedAt: goFixture.collectedAt }, adapterContext: goFixture };
        expect(validWindowsInventoryView(v, windowsDeviceId)).toBe(true);
        v.snapshot.collectedAt = '2026-10-11T08:00:00.123456788Z';
        expect(validWindowsInventoryView(v, windowsDeviceId)).toBe(false);
    });
    it('accepts every independent combination of six earlier siblings and rejects shared grants', () => {
        expect(valid(windowsAdapterContext())).toBe(true);
        expect(validWindowsInventoryView(windowsView(), windowsDeviceId)).toBe(true);
        const siblings = { events: windowsEventsFixture(), volumes: windowsVolumes(), network: windowsNetwork(), serviceStartup: windowsServiceStartup(windowsView().snapshot!), updates: windowsUpdates(), processMetrics: { schemaVersion: 'tracebolt.windows-process-metrics.v1', scope: 'windows-process-metrics-v1', grantId: 'b'.repeat(32), generationId: windowsView().snapshot!.generationId, collectedAt: '2026-10-07T12:00:02Z', observedCount: 1, truncated: false, rows: [{ pid: 44, cpuPercent: null, cpuQuality: 'first-sample', memoryBytes: '42', memoryQuality: 'observed' }] } };
        for (let flags = 0; flags < 64; flags++) {
            const v = windowsAdapterContextView(); Object.entries(siblings).forEach(([key, sibling], index) => { if (flags & 1 << index) Object.assign(v, { [key]: sibling }); });
            expect(validWindowsInventoryView(v, windowsDeviceId), `combination ${flags}`).toBe(true);
        }
        for (const [key, sibling] of Object.entries(siblings)) { const v = windowsAdapterContextView(); v.adapterContext.grantId = sibling.grantId; Object.assign(v, { [key]: sibling }); expect(validWindowsInventoryView(v, windowsDeviceId), key).toBe(false); }
    });
    const mutations: [string, (v: WindowsAdapterContext) => void][] = [
        ['extra snapshot property', v => Object.assign(v, { private: 'secret' })], ['extra row property', v => Object.assign(v.rows[0], { macAddress: 'secret' })], ['extra list property', v => Object.assign(v.rows[0].dnsServers, { source: 'secret' })],
        ['unknown scope', v => Object.assign(v, { scope: 'windows-inventory-v1' })], ['unknown version', v => Object.assign(v, { schemaVersion: 'tracebolt.windows-adapter-context.v2' })], ['missing grant', v => { v.grantId = ''; }], ['foreign generation', v => { v.generationId = `sample_${'b'.repeat(32)}`; }],
        ['negative index', v => { v.rows[0].ifIndex = -1; }], ['negative-zero index', v => { v.rows[0].ipv6IfIndex = -0; }], ['index overflow', v => { v.rows[0].ifIndex = 4294967296; }], ['fractional index', v => { v.rows[0].ifIndex = 4.5; }], ['absent indices', v => { v.rows[0].ifIndex = 0; v.rows[0].ipv6IfIndex = 0; }],
        ['empty name', v => { v.rows[0].name = ''; }], ['long UTF-8 name', v => { v.rows[0].name = 'ä'.repeat(49); }], ['leading whitespace', v => { v.rows[0].name = ' Ethernet'; }], ['trailing Unicode whitespace', v => { v.rows[0].name += '\u0085'; }], ['newline', v => { v.rows[0].name = 'A\nB'; }], ['DEL', v => { v.rows[0].name = 'A\u007fB'; }], ['bidi override', v => { v.rows[0].name = 'A\u202eB'; }], ['bidi isolate', v => { v.rows[0].name = 'A\u2066B'; }], ['unpaired surrogate', v => { v.rows[0].name = 'A\ud800B'; }],
        ['invented state', v => Object.assign(v.rows[0], { state: 'connected' })], ['observed zero speed', v => { v.rows[0].txLinkBps = 0; }], ['observed missing speed', v => { v.rows[0].rxLinkBps = null; }], ['speed overflow', v => { v.rows[0].txLinkBps = Number.MAX_SAFE_INTEGER + 1; }], ['fractional speed', v => { v.rows[0].txLinkBps = 1.5; }], ['negative speed', v => { v.rows[0].txLinkBps = -1; }], ['unknown populated speed', v => { v.rows[0].txQuality = 'unknown'; }], ['unavailable populated speed', v => { v.rows[0].rxQuality = 'unavailable'; }], ['unknown speed quality', v => Object.assign(v.rows[0], { txQuality: 'measured' })],
        ['unknown list quality', v => Object.assign(v.rows[0].dnsServers, { quality: 'complete' })], ['unavailable populated list', v => { v.rows[0].gateways.quality = 'unavailable'; }], ['null list', v => Object.assign(v.rows[0], { gateways: null })], ['null address array', v => Object.assign(v.rows[0].dnsServers, { addresses: null })], ['duplicate list', v => { v.rows[0].dnsServers.addresses = ['192.0.2.1', '192.0.2.1']; }], ['unsorted list', v => { v.rows[0].dnsServers.addresses.reverse(); }], ['list overflow', v => { v.rows[0].dnsServers.addresses = Array.from({ length: 9 }, (_, i) => `192.0.2.${i + 1}`); }],
        ['unsorted rows', v => { v.rows.reverse(); }], ['duplicate index pair', v => { v.rows[1] = { ...v.rows[0], name: 'Other name' }; }], ['duplicate row', v => { v.rows[1] = { ...v.rows[0] }; }], ['count underflow', v => { v.observedCount = 2; }], ['count overflow', v => { v.observedCount = 129; v.truncated = true; }], ['missing truncation', v => { v.observedCount++; }], ['false truncation', v => { v.truncated = true; }], ['observed inexact', v => { v.countExact = false; }], ['partial exact', v => { v.quality = 'partial'; }], ['unsupported populated', v => { v.quality = 'unsupported'; v.countExact = false; }],
        ['expired snapshot', v => { v.collectedAt = '2026-10-06T12:00:10Z'; }], ['future snapshot', v => { v.collectedAt = '2026-10-07T12:00:40.000000001Z'; }], ['invalid date', v => { v.collectedAt = '2026-02-30T12:00:00Z'; }], ['non-UTC capture', v => { v.collectedAt = '2026-10-07T12:00:04+00:00'; }],
    ];
    it.each(mutations)('rejects %s', (_label, mutate) => { const v = windowsAdapterContext(); mutate(v); expect(valid(v)).toBe(false); });
    it.each(['example.com', 'http://192.0.2.1', '192.000.2.1', '192.0.2.256', '127.1', '0x7f000001', '192.0.2.1%4', '[::1]', 'FE80::1', '2001:0db8::1', 'fe80::1%eth0', 'fe80::1%0', 'fe80::1%01', 'fe80::1%4294967296', 'fe80::1%4%5', '::ffff:c000:201', '::1/128'])('rejects noncanonical numeric list address %s', address => { const v = windowsAdapterContext(); v.rows[0].dnsServers.addresses = [address]; expect(valid(v)).toBe(false); });
    it.each(['0.0.0.0', '127.0.0.1', '224.0.0.1', '255.255.255.255', '::', '::1', 'ff02::1%4', 'fe80::1%4294967295', '::ffff:192.0.2.1', '::ffff:192.0.2.1%4'])('accepts native numeric address %s without inferring reachability', address => { const v = windowsAdapterContext(); v.rows[0].dnsServers.addresses = [address]; expect(valid(v)).toBe(true); });
    it('sorts address strings lexically rather than numerically', () => { const v = windowsAdapterContext(); v.rows[0].dnsServers.addresses = ['192.0.2.10', '192.0.2.2', 'fe80::1%10', 'fe80::1%2']; expect(valid(v)).toBe(true); });
    it('accepts every native state, positive safe speed and one-sided interface index', () => {
        for (const state of WINDOWS_ADAPTER_STATES) { const v = windowsAdapterContext(); v.rows[0].state = state; v.rows[0].txLinkBps = 1; v.rows[0].rxLinkBps = Number.MAX_SAFE_INTEGER; v.rows[0].ifIndex = 0; expect(valid(v)).toBe(true); }
        const v = windowsAdapterContext(); v.rows[0].name = 'ä'.repeat(48); expect(valid(v)).toBe(true); v.rows[0].name = 'Adapter 🖧'; expect(valid(v)).toBe(true);
    });
    it('preserves exact bounded counts, partial lower bounds, and truthful failed/empty snapshots', () => {
        const v = windowsAdapterContext(); Object.assign(v, { observedCount: 128, truncated: true }); expect(valid(v)).toBe(true);
        Object.assign(v, { quality: 'partial', countExact: false }); expect(valid(v)).toBe(true);
        Object.assign(v, { rows: [], observedCount: 0, truncated: false }); expect(valid(v)).toBe(true);
        for (const quality of ['denied', 'unavailable', 'unsupported', 'observed'] as const) { Object.assign(v, { quality, countExact: quality === 'observed' }); expect(valid(v)).toBe(true); }
    });
    it('enforces row limits and HTML-escaped Go byte size', () => {
        const v = windowsAdapterContext(); v.rows = Array.from({ length: 33 }, (_, i) => ({ ...v.rows[0], ifIndex: i + 1 })); v.observedCount = v.rows.length; expect(valid(v)).toBe(false);
        v.rows = v.rows.slice(0, 32).map(row => ({ ...row, name: '<'.repeat(96) })); v.observedCount = 32;
        expect(new TextEncoder().encode(JSON.stringify(v)).byteLength).toBeLessThan(WINDOWS_ADAPTER_CONTEXT_BYTES);
        expect(new TextEncoder().encode(JSON.stringify(v).replace(/</g, '\\u003c')).byteLength).toBeGreaterThan(WINDOWS_ADAPTER_CONTEXT_BYTES); expect(valid(v)).toBe(false);
    });
    it('rejects null, unknown aliases, invalid authority and conflicting sibling grants', () => {
        expect(validWindowsInventoryView({ ...windowsView(), adapterContext: null }, windowsDeviceId)).toBe(false);
        expect(validWindowsInventoryView({ ...windowsView(), adapters: windowsAdapterContext() }, windowsDeviceId)).toBe(false);
        for (const status of ['revoked', 'unavailable', 'awaiting', 'not_configured']) expect(validWindowsInventoryView({ ...windowsAdapterContextView(), status, snapshot: null }, windowsDeviceId)).toBe(false);
        const v = { ...windowsAdapterContextView(), network: windowsNetwork() }; v.adapterContext.grantId = v.network.grantId; expect(validWindowsInventoryView(v, windowsDeviceId)).toBe(false);
    });
    it('binds generation/capture to base inventory and original receipt at sub-millisecond boundaries', () => {
        const v = windowsAdapterContextView(); v.adapterContext.collectedAt = '2026-10-07T11:59:59.999999999Z'; expect(validWindowsInventoryView(v, windowsDeviceId)).toBe(false);
        v.adapterContext.collectedAt = '2026-10-07T12:00:31.000000001Z'; expect(valid(v.adapterContext)).toBe(true); expect(validWindowsInventoryView(v, windowsDeviceId)).toBe(false);
        v.adapterContext.collectedAt = '2026-10-07T12:00:00.000000001Z'; expect(validWindowsInventoryView(v, windowsDeviceId)).toBe(false);
        v.adapterContext.collectedAt = v.snapshot!.collectedAt; expect(validWindowsInventoryView(v, windowsDeviceId)).toBe(true);
    });
});
