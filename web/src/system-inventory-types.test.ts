import { describe, expect, it } from 'vitest';
import { serviceRows, socketRows, systemDevice, systemPage, systemView } from './system-inventory-fixtures';
import { systemAgeStatus, systemSectionVisible, validServiceRow, validSocketRow, validSystemPage, validSystemSearch, validSystemView } from './system-inventory-types';

describe('system inventory strict operator contracts', () => {
    it('accepts complete enumeration and coherent not-configured/awaiting states with canonical sequence strings', () => {
        expect(validSystemView(systemView(), systemDevice)).toBe(true);
        for (const status of ['not_configured', 'unknown', 'awaiting'] as const) expect(validSystemView({ ...systemView(), status, latest: null, lastComplete: { services: null, sockets: null }, sequence: null, receivedAt: null }, systemDevice)).toBe(true);
        expect(validSystemView({ ...systemView(), sequence: 9007199254740993 }, systemDevice)).toBe(false);
        expect(validSystemView({ ...systemView(), collectionProfile: '', status: 'fresh', sequence: null, receivedAt: null, latest: null, lastComplete: { services: null, sockets: null } }, systemDevice)).toBe(false);
    });
    it('validates service null semantics and escaped unit names without inferring missing main PID', () => {
        const service = serviceRows(1)[0]; expect(validServiceRow(service)).toBe(true); expect(validServiceRow({ ...service, name: 'example\\x20name.service' })).toBe(true);
        for (const bad of [{ ...service, mainPid: 0 }, { ...service, runtime: null, enablement: null }, { ...service, runtime: { ...service.runtime, extra: 1 } }, { ...service, name: '<script>.service' }, { ...service, enablement: 'bad\nstate' }, { ...service, uid: 1 }]) expect(validServiceRow(bad)).toBe(false);
        expect(validServiceRow({ ...service, runtime: null })).toBe(true); expect(validServiceRow({ ...service, enablement: null })).toBe(true);
    });
    it('accepts canonical numeric IPv4/IPv6 and preserves mapped address form', () => {
        const row = socketRows(2)[1];
        for (const address of ['::', '::1', '2001:db8::1', '2001:db8:1:2:3:4:5:6', '::ffff:192.0.2.1']) expect(validSocketRow({ ...row, family: 'ipv6', local: { address, port: 80 }, remote: { address: '::', port: 0 } })).toBe(true);
        for (const address of ['localhost', '127.000.0.1', '256.0.0.1', '0x7f000001']) expect(validSocketRow({ ...row, local: { address, port: 80 } })).toBe(false);
        for (const address of ['2001:0db8::1', '2001:DB8::1', 'fe80::1%eth0', '::ffff:c000:201', '1:2:3:4:5:6:7', '1:2:3:4:5:6:7:8:9', '1:::2']) expect(validSocketRow({ ...row, family: 'ipv6', local: { address, port: 80 }, remote: { address: '::', port: 0 } })).toBe(false);
    });
    it('rejects unknown socket enums, forged owner completeness, invalid null reasons and UID disclosure', () => {
        const row = socketRows(2)[1];
        for (const bad of [{ ...row, kind: 'connection' }, { ...row, state: 'made-up' }, { ...row, protocol: 'raw' }, { ...row, local: { ...row.local, port: 65536 } }, { ...row, owners: [] }, { ...row, owners: [{ pid: 1, processName: null, nameReason: 'none' }] }, { ...row, owners: [{ pid: 1, processName: 'bad\u202e', nameReason: 'none' }] }, { ...row, owners: [{ pid: 1, processName: 'fine', nameReason: 'none', uid: 1 }] }]) expect(validSocketRow(bad)).toBe(false);
        expect(validSocketRow({ ...row, owners: [{ pid: 1, processName: null, nameReason: 'process_gone' }], attribution: { coverage: 'partial', reason: 'process_gone' } })).toBe(true);
        expect(validSocketRow({ ...row, owners: [], attribution: { coverage: 'unavailable', reason: 'permission_denied' } })).toBe(true);
    });
    it('keeps each prior complete section at its original age when a fresh latest attempt failed', () => {
        const view = systemView(); view.serverNow = '2026-10-04T00:05:10Z'; view.receivedAt = '2026-10-04T00:05:05Z'; view.sequence = '9007199254740994'; view.latest!.generationId = `sample_${'b'.repeat(32)}`; view.latest!.collectedAt = '2026-10-04T00:05:00Z';
        for (const section of ['services', 'sockets'] as const) { view.latest![section] = { generationId: view.latest!.generationId, observedAt: view.latest!.collectedAt, coverage: 'failed', reason: 'timeout', countExact: false, observedCount: null }; view.lastComplete[section]!.status = 'stale'; }
        expect(validSystemView(view, systemDevice)).toBe(true); expect(systemSectionVisible(view, 'services', 1)).toBe(true); expect(systemAgeStatus(view.serverNow, view.lastComplete.services!.meta.observedAt)).toBe('stale');
        view.lastComplete.services!.status = 'fresh'; expect(validSystemView(view, systemDevice)).toBe(false);
    });
    it('rejects expired retained data, mismatched original metadata and healthy zero from failed sections', () => {
        const view = systemView();
        for (const bad of [{ ...view, extra: true }, { ...view, deviceId: 'agent_other' }, { ...view, serverNow: '2026-10-05T00:00:00Z' }, { ...view, latest: { ...view.latest, services: { ...view.latest!.services, observedCount: null } } }, { ...view, lastComplete: { ...view.lastComplete, services: { ...view.lastComplete.services, meta: { ...view.lastComplete.services!.meta, coverage: 'failed', reason: 'read_failed', countExact: false, observedCount: 0 } } } }]) expect(validSystemView(bad, systemDevice)).toBe(false);
    });
    it('bounds both page shapes and accepts null cursor expiry only at exhaustion', () => {
        const view = systemView();
        for (const section of ['services', 'sockets'] as const) {
            const page = systemPage(view, serviceRows(), socketRows(), JSON.stringify({ section, cursor: '', search: '', filter: 'all', limit: section === 'services' ? 100 : 25 }));
            expect(validSystemPage(page, systemDevice, section, view.lastComplete[section]!, '')).toBe(true);
            for (const bad of [{ ...page, cursorExpiresAt: null }, { ...page, generationId: `sample_${'b'.repeat(32)}` }, { ...page, scannedCount: 2049 }, { ...page, returnedCount: 101 }, { ...page, nextCursor: 'x'.repeat(2049) }, { ...page, status: 'freshness-invented' }]) expect(validSystemPage(bad, systemDevice, section, view.lastComplete[section]!, '')).toBe(false);
        }
    });
    it('permits bounded UTF-8 process-name searches but rejects control/format/unpaired-surrogate input', () => {
        for (const value of ['ä', 'имя', 'proc 👋', 'a'.repeat(128)]) expect(validSystemSearch(value)).toBe(true);
        for (const value of ['a'.repeat(129), 'ä'.repeat(65), 'bad\n', 'bad\u202e', '\uD800', '\uFFFD']) expect(validSystemSearch(value)).toBe(false);
    });
});
