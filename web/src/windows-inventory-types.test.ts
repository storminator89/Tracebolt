import { describe, expect, it } from 'vitest';
import { validWindowsInventorySnapshot, validWindowsInventoryView, windowsInventoryStatus } from './windows-inventory-types';
import { windowsDeviceId, windowsSection, windowsSnapshot, windowsView } from './windows-inventory-fixture';

describe('strict Windows inventory operator contract', () => {
    it('accepts only the Windows profile and exact section/row fields', () => {
        expect(validWindowsInventorySnapshot(windowsSnapshot())).toBe(true); expect(validWindowsInventoryView(windowsView(), windowsDeviceId)).toBe(true);
        for (const change of [v => { v.schemaVersion = 'tracebolt.operational.v1'; }, v => { v.collectionProfile = 'managed-operations-v3'; }, v => { v.platform = 'linux'; }, v => { v.processes.rows[0].commandLine = 'hidden'; }, v => { v.services.rows[0].state = 'active'; }, v => { v.hostname = { value: 'linux-shape' }; }, v => { v.software.rows[0].registryView = 'per-user'; }, v => { v.network.rows[0].mac = '00:11:22:33:44:55'; } ] as ((v: any) => void)[]) {
            const v = windowsSnapshot(); change(v); expect(validWindowsInventorySnapshot(v)).toBe(false);
        }
    });
    it('enforces quality, count, completeness and truncation independently', () => {
        const v = windowsSnapshot(); v.processes = { ...v.processes, quality: 'partial', observedCount: 200, complete: false, truncated: true }; expect(validWindowsInventorySnapshot(v)).toBe(true);
        v.processes.countExact = false; expect(validWindowsInventorySnapshot(v)).toBe(true);
        v.services = { ...windowsSection([]), quality: 'denied', complete: false, countExact: false }; expect(validWindowsInventorySnapshot(v)).toBe(true);
        for (const change of [s => { s.quality = 'healthy'; }, s => { s.complete = true; }, s => { s.truncated = false; }, s => { s.observedCount = 0; }, s => { s.observedCount = 2049; } ] as ((s: any) => void)[]) { const bad = structuredClone(v); change(bad.processes); expect(validWindowsInventorySnapshot(bad)).toBe(false); }
        v.services.countExact = true; expect(validWindowsInventorySnapshot(v)).toBe(false);
        v.hostname = windowsSection([]); expect(validWindowsInventorySnapshot(v)).toBe(false);
    });
    it('rejects oversized, malformed, control and formatting text, preserves inert printable labels', () => {
        for (const name of ['x'.repeat(257), 'é'.repeat(129), 'bad\nname', 'bad\u202Ename', 'bad\uFFFDname', '\uD800', 'bad\u2028name', 'C:\\sensitive.exe', '/path.exe', '   ']) { const v = windowsSnapshot(); v.processes.rows[0].name = name; expect(validWindowsInventorySnapshot(v)).toBe(false); }
        const v = windowsSnapshot(); v.hostname.rows[0].value = '<img src=x onerror=alert(1)>'; expect(validWindowsInventorySnapshot(v)).toBe(true);
        v.processes.source = 'x'.repeat(513); expect(validWindowsInventorySnapshot(v)).toBe(false);
    });
    it('enforces transport row ceilings and the escaped 48KiB snapshot bound', () => {
        for (const [section, cap] of [['processes', 128], ['services', 128], ['software', 128], ['network', 64]] as const) { const v = windowsSnapshot(), s = v[section]; s.rows = Array.from({ length: cap + 1 }, () => ({ ...s.rows[0] })) as typeof s.rows; s.observedCount = s.rows.length; expect(validWindowsInventorySnapshot(v)).toBe(false); }
        const v = windowsSnapshot(); v.software = windowsSection(Array.from({ length: 128 }, () => ({ name: '&'.repeat(256), version: '1', publisher: '', registryView: '64' as const }))); expect(validWindowsInventorySnapshot(v)).toBe(false);
    });
    it.each(['127.0.0.1', '0.0.0.0', '224.0.0.1', '192.000.2.1', '192.0.2.999', '::', '::1', 'ff02::1', 'FE80::1', 'fe80::1%4', '2001:0db8::1', '::ffff:127.0.0.1', '::ffff:224.0.0.1', 'example.com'])('rejects forbidden or noncanonical address %s', address => { const v = windowsSnapshot(); v.network.rows[0].address = address; expect(validWindowsInventorySnapshot(v)).toBe(false); });
    it('validates capture freshness against trusted server time including the bounded skew exception', () => {
        const v = windowsView(); v.snapshot!.collectedAt = '2026-10-07T11:57:00Z'; expect(validWindowsInventoryView(v, windowsDeviceId)).toBe(false); v.status = 'stale'; expect(validWindowsInventoryView(v, windowsDeviceId)).toBe(true);
        v.snapshot!.collectedAt = '2026-10-07T12:00:20Z'; expect(validWindowsInventoryView(v, windowsDeviceId)).toBe(true); v.status = 'fresh'; expect(validWindowsInventoryView(v, windowsDeviceId)).toBe(false); v.status = 'stale'; v.snapshot!.collectedAt = '2026-10-07T12:00:41Z'; expect(validWindowsInventoryView(v, windowsDeviceId)).toBe(false);
        expect(windowsInventoryStatus(windowsView(), 110001)).toBe('stale'); expect(windowsInventoryStatus(windowsView(), Infinity)).toBe('unavailable'); expect(windowsInventoryStatus(windowsView(), 86400000)).toBe('unavailable');
        const allowedSkew = windowsView(); allowedSkew.snapshot!.collectedAt = '2026-10-07T12:00:02Z'; expect(validWindowsInventoryView(allowedSkew, windowsDeviceId)).toBe(true); expect(windowsInventoryStatus(allowedSkew, 111001)).toBe('stale');
    });
    it('preserves submillisecond capture, receipt and expiry boundaries', () => {
        const v = windowsView(); v.serverNow = '2026-10-07T12:02:00.000000001Z'; v.status = 'stale'; expect(validWindowsInventoryView(v, windowsDeviceId)).toBe(true); v.status = 'fresh'; expect(validWindowsInventoryView(v, windowsDeviceId)).toBe(false);
        v.serverNow = '2026-10-07T12:00:10Z'; v.receivedAt = '2026-10-07T12:00:10.000000001Z'; expect(validWindowsInventoryView(v, windowsDeviceId)).toBe(false);
    });
    it('rejects wrong identity, unsafe sequence, malformed times and snapshots in revoked/unavailable states', () => {
        for (const change of [v => { v.deviceId = `agent_${'8'.repeat(32)}`; }, v => { v.sequence = 9007199254740992; }, v => { v.sequence = '1'; }, v => { v.receivedAt = '2026-10-07T12:00:11Z'; }, v => { v.serverNow = '2026-02-30T12:00:00Z'; }, v => { v.extra = true; }, v => { v.status = 'revoked'; }, v => { v.status = 'unavailable'; }, v => { v.collectionProfile = 'basic-readonly-v1'; } ] as ((v: any) => void)[]) { const v = windowsView(); change(v); expect(validWindowsInventoryView(v, windowsDeviceId)).toBe(false); }
        for (const status of ['revoked', 'unavailable'] as const) expect(validWindowsInventoryView({ ...windowsView(), status, snapshot: null }, windowsDeviceId)).toBe(true);
        expect(validWindowsInventoryView({ ...windowsView(), status: 'awaiting', sequence: null, receivedAt: null, snapshot: null }, windowsDeviceId)).toBe(true);
    });
});
