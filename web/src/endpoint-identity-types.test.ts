import { describe, expect, it } from 'vitest';
import goFixture from './endpoint-identity-go-fixture.json';
import { endpointAgeStatus, endpointSnapshotVisible, validEndpointSnapshot, validEndpointView } from './endpoint-identity-types';
import type { EndpointAddress, EndpointSnapshot } from './endpoint-identity-types';
import { emptyEndpointView, endpointComplete, endpointDevice, endpointFailed, endpointInterface, endpointSnapshot, endpointView } from './endpoint-identity-fixtures';

describe('strict endpoint identity display contract', () => {
    it('accepts the exact Go-marshaled synthetic DTO with decimal sequence, escaped text and nanosecond UTC timestamps', () => {
        expect(validEndpointView(goFixture, goFixture.deviceId)).toBe(true);
        expect(goFixture.sequence).toBe('17');
        expect(goFixture.latest.reportedHostname.value).toBe('synthetic-<lab>&host');
        expect(goFixture.latest.collectedAt).toBe('2026-10-04T14:00:00.123456789Z');
    });
    it('accepts complete and independent hostname/family failures', () => {
        const v = endpointView(); expect(validEndpointView(v, endpointDevice)).toBe(true);
        v.latest!.reportedHostname = { coverage: 'failed', reason: 'permission_denied', value: null };
        expect(validEndpointView(v, endpointDevice)).toBe(true);
        v.latest!.interfaces.items[1].addresses.ipv6 = { meta: endpointFailed(), items: [] };
        v.latest!.interfaces.meta = { ...endpointComplete(2), coverage: 'partial', reason: 'address_unavailable' };
        expect(validEndpointView(v, endpointDevice)).toBe(true);
        v.latest!.interfaces = { meta: endpointFailed('source_missing'), items: [] }; expect(validEndpointView(v, endpointDevice)).toBe(true);
    });
    it('accepts successful empty interfaces/families without calling failure empty', () => {
        const s = endpointSnapshot(); s.interfaces = { meta: endpointComplete(0), items: [] }; expect(validEndpointSnapshot(s)).toBe(true);
        s.interfaces = { meta: endpointComplete(1), items: [endpointInterface()] };
        s.interfaces.items[0].addresses = { ipv4: { meta: endpointComplete(0), items: [] }, ipv6: { meta: endpointComplete(0), items: [] } }; expect(validEndpointSnapshot(s)).toBe(true);
    });
    it.each(['not_collected', 'revoked', 'expired', 'unknown'] as const)('hides %s and rejects smuggled observations', status => {
        const v = emptyEndpointView(status); expect(validEndpointView(v, endpointDevice)).toBe(true); expect(endpointSnapshotVisible(v, 0)).toBe(false);
        v.latest = endpointSnapshot(); expect(validEndpointView(v, endpointDevice)).toBe(false);
    });
    it('binds exact device, schema, metadata keys, original timestamps and sequence', () => {
        for (const patch of [{ deviceId: 'agent_other' }, { schemaVersion: 'future' }, { maxAgeSeconds: 121 }, { sequence: 9 }, { sequence: '01' }, { sequence: '9223372036854775808' }, { receivedAt: null }, { expiresAt: null }, { receivedAt: '2026-10-04T11:59:59Z' }, { receivedAt: '2026-10-04T12:00:11Z' }, { expiresAt: '2026-10-05T12:00:01Z' }, { extra: true }, { status: 'disabled' }]) expect(validEndpointView({ ...endpointView(), ...patch }, endpointDevice)).toBe(false);
        const v = endpointView(); delete (v as unknown as Record<string, unknown>).sequence; expect(validEndpointView(v, endpointDevice)).toBe(false);
        expect(validEndpointView(endpointView(), 'agent_../bad')).toBe(false);
    });
    it('accepts only consistent fresh/stale/expired ages, including nanosecond boundaries', () => {
        const v = endpointView(); v.serverNow = '2026-10-04T12:02:00Z'; expect(validEndpointView(v, endpointDevice)).toBe(true);
        v.serverNow = '2026-10-04T12:02:00.000000001Z'; expect(validEndpointView(v, endpointDevice)).toBe(false); v.status = 'stale'; expect(validEndpointView(v, endpointDevice)).toBe(true);
        v.serverNow = '2026-10-05T11:59:59.999999999Z'; expect(validEndpointView(v, endpointDevice)).toBe(true);
        v.serverNow = '2026-10-05T12:00:00Z'; expect(validEndpointView(v, endpointDevice)).toBe(false); v.status = 'expired'; v.latest = null; expect(validEndpointView(v, endpointDevice)).toBe(true);
        v.serverNow = '2026-10-05T11:59:59Z'; expect(validEndpointView(v, endpointDevice)).toBe(false);
    });
    it('rejects unknown/revoked metadata and impossible/malformed dates', () => {
        for (const status of ['not_collected', 'revoked', 'unknown']) expect(validEndpointView({ ...endpointView(), latest: null, status }, endpointDevice)).toBe(false);
        for (const serverNow of ['2026-02-30T12:00:00Z', '2026-10-04T12:00:10+00:00', '1969-12-31T23:59:59Z', '2026-10-04T12:00:60Z', '2026-10-04T24:00:00Z', '2026-10-04T11:59:59Z']) expect(validEndpointView({ ...endpointView(), serverNow }, endpointDevice)).toBe(false);
    });
    it('ages from the original collection and never reveals values under an unreliable clock', () => {
        const v = endpointView(); expect(endpointAgeStatus(v, 110000)).toBe('fresh'); expect(endpointAgeStatus(v, 110001)).toBe('stale'); expect(endpointAgeStatus(v, 86390000)).toBe('expired');
        for (const delta of [-1, Infinity, NaN]) { expect(endpointAgeStatus(v, delta)).toBe('unknown'); expect(endpointSnapshotVisible(v, delta)).toBe(false); }
    });
    it.each(['', ' x', 'x ', 'x\n', 'x\u202e', 'x\ufffd', 'x\ud800', 'x\u2028', 'x'.repeat(254), 'é'.repeat(127)])('rejects unsafe or overlong hostname %j', value => {
        const s = endpointSnapshot(); s.reportedHostname.value = value; expect(validEndpointSnapshot(s)).toBe(false);
    });
    it('allows inert markup and bounded Unicode as reported text', () => {
        const s = endpointSnapshot(); s.reportedHostname.value = '<img src=x onerror=alert(1)>'; expect(validEndpointSnapshot(s)).toBe(true); s.reportedHostname.value = 'host-🦊'; expect(validEndpointSnapshot(s)).toBe(true);
    });
    it.each(['.', '..', 'eth 0', ' eth0', 'eth/0', 'eth:0', 'eth\\0', 'x'.repeat(16), 'x\u202e'])('rejects invalid interface name %j', name => {
        const s = endpointSnapshot(); s.interfaces.items[1].name = name; expect(validEndpointSnapshot(s)).toBe(false);
    });
    it('rejects duplicate/unordered indices/names and unsupported hardware assumptions', () => {
        for (const patch of [{ index: 0 }, { index: 1 }, { index: 2147483648 }, { name: 'lo' }, { up: 'true' }, { loopback: null }, { hardwareKind: 'physical' }, { mac: '00:00:00:00:00:00' }]) { const s = endpointSnapshot(); Object.assign(s.interfaces.items[1], patch); expect(validEndpointSnapshot(s)).toBe(false); }
        const s = endpointSnapshot(); s.interfaces.items.reverse(); expect(validEndpointSnapshot(s)).toBe(false);
    });
    it('rejects untruthful counts, prefixes on failure, and inconsistent aggregate coverage', () => {
        const mutate: ((s: EndpointSnapshot) => void)[] = [s => { s.interfaces.meta.observedCount = 1; }, s => { s.interfaces.meta.countExact = false; }, s => { s.interfaces.meta.coverage = 'partial'; s.interfaces.meta.reason = 'address_unavailable'; }, s => { s.interfaces.items[1].addresses.ipv6.meta = endpointFailed(); }, s => { s.interfaces.items[1].addresses.ipv6 = { meta: endpointFailed(), items: [] }; }, s => { s.interfaces.items[1].addresses.ipv4.meta.observedCount = 100; }, s => { s.reportedHostname.coverage = 'failed'; }, s => { Object.assign(s.reportedHostname, { reason: 'raw_os_error' }); }];
        for (const change of mutate) { const s = endpointSnapshot(); change(s); expect(validEndpointSnapshot(s)).toBe(false); }
    });
    it.each([
        ['ipv4', '0.0.0.0', 'unspecified'], ['ipv4', '127.9.8.7', 'loopback'], ['ipv4', '169.254.1.2', 'link-local'], ['ipv4', '224.0.0.1', 'multicast'], ['ipv4', '10.1.2.3', 'private'], ['ipv4', '172.31.255.1', 'private'], ['ipv4', '192.168.2.1', 'private'], ['ipv4', '192.0.2.19', 'other'],
        ['ipv6', '::', 'unspecified'], ['ipv6', '::1', 'loopback'], ['ipv6', 'fe80::1234', 'link-local'], ['ipv6', 'febf::1', 'link-local'], ['ipv6', 'ff02::1', 'multicast'], ['ipv6', 'fd00::1234', 'private'], ['ipv6', '2001:db8::19', 'other'], ['ipv6', '::ffff:192.168.1.2', 'private'], ['ipv6', '::ffff:127.0.0.1', 'loopback'], ['ipv6', '::ffff:0.0.0.0', 'other'],
    ] as const)('matches numeric scope for %s %s', (family, address, scope) => {
        const s = endpointSnapshot(), row = s.interfaces.items[1]; row.addresses[family] = { meta: endpointComplete(1), items: [{ family, address, scope }] }; expect(validEndpointSnapshot(s)).toBe(true);
    });
    it.each(['192.0.2.019', '256.1.2.3', '192.0.2.19/24', 'fixture.example', 'https://192.0.2.19', '192.0.2.19:80'])('rejects noncanonical/non-numeric IPv4 %s', address => {
        const s = endpointSnapshot(); s.interfaces.items[1].addresses.ipv4.items[0].address = address; expect(validEndpointSnapshot(s)).toBe(false);
    });
    it.each(['2001:DB8::19', '2001:0db8::19', '2001:db8:0:0:0:0:0:19', 'fe80::19%eth0', '2001:db8::19/64', '[2001:db8::19]', '1::2::3', '::ffff:c000:213', '::192.0.2.19', '1:2:3:4:5:6:7:8:9'])('rejects noncanonical IPv6 %s', address => {
        const s = endpointSnapshot(); s.interfaces.items[1].addresses.ipv6.items[0].address = address; expect(validEndpointSnapshot(s)).toBe(false);
    });
    it('rejects address ordering, duplication, wrong family or invented public scope', () => {
        const s = endpointSnapshot(), rows = s.interfaces.items[1].addresses.ipv6; rows.items.reverse(); expect(validEndpointSnapshot(s)).toBe(false); rows.items[1] = rows.items[0]; expect(validEndpointSnapshot(s)).toBe(false);
        rows.items = [{ family: 'ipv4', address: '192.0.2.19', scope: 'other' }]; rows.meta = endpointComplete(1); expect(validEndpointSnapshot(s)).toBe(false);
        rows.items = [{ family: 'ipv6', address: 'fe80::1', scope: 'other' }]; expect(validEndpointSnapshot(s)).toBe(false);
    });
    it('enforces interface, per-interface, whole snapshot byte and total address bounds', () => {
        const s = endpointSnapshot(); s.interfaces.items = Array.from({ length: 33 }, (_, n) => endpointInterface(n + 1, `if${n}`)); s.interfaces.meta = endpointComplete(33); expect(validEndpointSnapshot(s)).toBe(false);
        s.interfaces.items = [endpointInterface()]; s.interfaces.meta = endpointComplete(1);
        s.interfaces.items[0].addresses.ipv4.items = Array.from({ length: 32 }, (_, n): EndpointAddress => ({ family: 'ipv4', address: `192.0.2.${n}`, scope: 'other' })); s.interfaces.items[0].addresses.ipv4.meta = endpointComplete(32); expect(validEndpointSnapshot(s)).toBe(false);
        s.interfaces.items = Array.from({ length: 20 }, (_, n) => endpointInterface(n + 1, `if${n}`)); s.interfaces.meta = endpointComplete(20); expect(validEndpointSnapshot(s)).toBe(false);
        s.interfaces.items = Array.from({ length: 5 }, (_, n) => { const row = endpointInterface(n + 1, `if${n}`); row.addresses.ipv4.items = Array.from({ length: 26 }, (_, a): EndpointAddress => ({ family: 'ipv4', address: `192.0.2.${a}`, scope: 'other' })); row.addresses.ipv4.meta = endpointComplete(26); row.addresses.ipv6 = { meta: endpointComplete(0), items: [] }; return row; }); s.interfaces.meta = endpointComplete(5); expect(validEndpointSnapshot(s)).toBe(false);
    });
});
