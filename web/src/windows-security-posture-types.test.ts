import goFixture from '../../internal/windowssecurity/testdata/snapshot.json';
import { describe, expect, it } from 'vitest';
import { windowsDeviceId, windowsNow, windowsView } from './windows-inventory-fixture';
import { windowsSecurityPosture, windowsSecurityPostureView } from './windows-security-posture-fixture';
import { validWindowsSecurityPosture, type WindowsSecurityPosture } from './windows-security-posture-types';
import { validWindowsInventoryView } from './windows-inventory-types';
import { windowsPatchContext } from './windows-patch-context-fixture';
import { windowsUpdates } from './windows-updates-fixture';
import { windowsAdapterContext } from './windows-adapter-context-fixture';
import { windowsNetwork } from './windows-network-fixture';
import { windowsVolumes } from './windows-volumes-fixture';
import { windowsEventsFixture } from './windows-events-fixture';
import { windowsServiceStartup } from './windows-service-startup-fixture';
const valid = (v: unknown) => validWindowsSecurityPosture(v, windowsView().snapshot!, windowsNow);
const unknownDefender = { mode: 'unknown', serviceEnabled: 'unknown', antivirusEnabled: 'unknown', realTimeProtectionEnabled: 'unknown', signatureVersion: null, signatureAgeDays: null };

describe('Strict independent Windows security observations', () => {
    it('accepts the Go-validated canonical snapshot with exact base capture binding', () => {
        const snapshot = { ...windowsView().snapshot!, generationId: goFixture.generationId, collectedAt: goFixture.collectedAt };
        const serverNow = new Date(Date.parse(goFixture.collectedAt) + 1000).toISOString();
        expect(validWindowsSecurityPosture(goFixture, snapshot, serverNow)).toBe(true);
        expect(validWindowsInventoryView({ ...windowsView(), snapshot, serverNow, receivedAt: serverNow, securityPosture: goFixture }, windowsDeviceId)).toBe(true);
        expect(validWindowsSecurityPosture(goFixture, { ...snapshot, collectedAt: new Date(Date.parse(snapshot.collectedAt) + 1).toISOString() }, serverNow)).toBe(false);
    });
    it('accepts optional security alongside old scopes without changing old views', () => {
        expect(valid(windowsSecurityPosture())).toBe(true);
        expect(validWindowsInventoryView(windowsView(), windowsDeviceId)).toBe(true);
        expect(validWindowsInventoryView({ ...windowsSecurityPostureView(), patchContext: windowsPatchContext(), updates: windowsUpdates(), adapterContext: windowsAdapterContext() }, windowsDeviceId)).toBe(true);
    });
    it.each(['normal', 'passive', 'edr-block'] as const)('keeps %s mode independent of negative flags', mode => {
        const v = windowsSecurityPosture(); Object.assign(v.defender, { mode, antivirusEnabled: 'off', realTimeProtectionEnabled: 'off' }); expect(valid(v)).toBe(true);
    });
    it('allows partial unknown mode and unknown signature age without treating sentinel as an age', () => {
        const v = windowsSecurityPosture(); Object.assign(v.defender, { mode: 'unknown', quality: 'partial', reason: 'windows_security_posture_invalid_metadata', signatureAgeDays: null }); expect(valid(v)).toBe(true);
        Object.assign(v.defender, { signatureAgeDays: 65534 }); expect(valid(v)).toBe(true);
    });
    it.each(['denied', 'unavailable'] as const)('accepts unknown-only %s sources and preserves the other source', quality => {
        const reason = quality === 'denied' ? 'windows_security_posture_access_denied' : 'windows_security_posture_unavailable';
        const v = windowsSecurityPosture(); Object.assign(v.defender, unknownDefender, { quality, reason }); expect(valid(v)).toBe(true);
        v.firewall.profiles.forEach(p => { p.active = p.enabled = 'unknown'; }); Object.assign(v.firewall, { quality, reason }); expect(valid(v)).toBe(true);
        v.defender = windowsSecurityPosture().defender; expect(valid(v)).toBe(true);
    });
    const mutations: [string, (v: WindowsSecurityPosture) => void][] = [
        ['extra root property', v => Object.assign(v, { raw: 'private' })], ['extra Defender property', v => Object.assign(v.defender, { threat: 'private' })], ['extra firewall property', v => Object.assign(v.firewall, { rules: [] })], ['extra profile property', v => Object.assign(v.firewall.profiles[0], { port: 443 })],
        ['wrong schema', v => Object.assign(v, { schemaVersion: 'tracebolt.windows-patch-context.v1' })], ['wrong scope', v => Object.assign(v, { scope: 'windows-patch-context-v1' })], ['uppercase grant', v => { v.grantId = 'C'.repeat(32); }], ['short grant', v => { v.grantId = 'c'; }], ['wrong generation', v => { v.generationId = `sample_${'8'.repeat(32)}`; }], ['nanosecond capture change', v => { v.collectedAt = '2026-10-07T12:00:00.000000001Z'; }],
        ['invalid mode', v => Object.assign(v.defender, { mode: 'unprotected' })], ['invalid state', v => Object.assign(v.defender, { serviceEnabled: true })], ['unknown quality', v => Object.assign(v.defender, { quality: 'healthy' })], ['raw reason', v => Object.assign(v.defender, { quality: 'partial', reason: 'private exception' })],
        ['observed reason', v => { v.defender.reason = 'windows_security_posture_partial_result'; }], ['observed unknown mode', v => { v.defender.mode = 'unknown'; }], ['observed unknown flag', v => { v.defender.serviceEnabled = 'unknown'; }], ['observed unknown signatures', v => { v.defender.signatureVersion = null; }], ['observed unknown age', v => { v.defender.signatureAgeDays = null; }], ['empty partial reason', v => { v.defender.quality = 'partial'; }], ['partial all unknown', v => Object.assign(v.defender, unknownDefender, { quality: 'partial', reason: 'windows_security_posture_partial_result' })],
        ['denied known fields', v => Object.assign(v.defender, { quality: 'denied', reason: 'windows_security_posture_access_denied' })], ['denied non-denied reason', v => Object.assign(v.defender, unknownDefender, { quality: 'denied', reason: 'windows_security_posture_unavailable' })], ['unavailable denied reason', v => Object.assign(v.defender, unknownDefender, { quality: 'unavailable', reason: 'windows_security_posture_access_denied' })],
        ['long version', v => { v.defender.signatureVersion = '1.'.repeat(32) + '1'; }], ['non-version text', v => { v.defender.signatureVersion = '1.2 <script>'; }], ['single version component', v => { v.defender.signatureVersion = '123'; }], ['five version components', v => { v.defender.signatureVersion = '1.2.3.4.5'; }], ['empty version component', v => { v.defender.signatureVersion = '1..2'; }], ['non-ASCII version', v => { v.defender.signatureVersion = '1.２'; }], ['signed version', v => { v.defender.signatureVersion = '-1.2'; }],
        ['unknown-age sentinel', v => { v.defender.signatureAgeDays = 65535; }], ['uint32 sentinel', v => { v.defender.signatureAgeDays = 4294967295; }], ['negative age', v => { v.defender.signatureAgeDays = -1; }], ['negative zero age', v => { v.defender.signatureAgeDays = -0; }], ['fractional age', v => { v.defender.signatureAgeDays = .5; }], ['nonfinite age', v => { v.defender.signatureAgeDays = Infinity; }],
        ['missing profile', v => { v.firewall.profiles.pop(); }], ['extra profile', v => { v.firewall.profiles.push(v.firewall.profiles[0]); }], ['reordered profiles', v => { v.firewall.profiles.reverse(); }], ['duplicate profile', v => { v.firewall.profiles[1].profile = 'domain'; }], ['invalid activity', v => Object.assign(v.firewall.profiles[0], { active: 'enabled' })], ['observed unknown profile', v => Object.assign(v.firewall, { quality: 'observed', reason: '' })], ['empty partial firewall reason', v => { v.firewall.reason = ''; }], ['partial unknown firewall', v => { v.firewall.profiles.forEach(p => { p.active = p.enabled = 'unknown'; }); }], ['unavailable known firewall', v => Object.assign(v.firewall, { quality: 'unavailable', reason: 'windows_security_posture_unavailable' })],
    ];
    it.each(mutations)('rejects %s', (_label, mutate) => { const v = windowsSecurityPosture(); mutate(v); expect(valid(v)).toBe(false); });
    it('requires exact original time, UTC calendar validity, 30-second skew and less than 24 hours', () => {
        const v = windowsSecurityPosture(), snapshot = windowsView().snapshot!;
        expect(validWindowsSecurityPosture(v, snapshot, '2026-10-07T11:59:30Z')).toBe(true);
        expect(validWindowsSecurityPosture(v, snapshot, '2026-10-07T11:59:29.999999999Z')).toBe(false);
        expect(validWindowsSecurityPosture(v, snapshot, '2026-10-08T11:59:59.999999999Z')).toBe(true);
        expect(validWindowsSecurityPosture(v, snapshot, '2026-10-08T12:00:00Z')).toBe(false);
        for (const collectedAt of ['2026-02-30T12:00:00Z', '1969-12-31T23:59:59Z', '2026-10-07T12:00:00+00:00']) expect(validWindowsSecurityPosture({ ...v, collectedAt }, { ...snapshot, collectedAt }, collectedAt)).toBe(false);
    });
    it('rejects every sibling grant collision, null optional data and data retained after authority removal', () => {
        const v = { ...windowsSecurityPostureView(), patchContext: windowsPatchContext(), updates: windowsUpdates(), adapterContext: windowsAdapterContext(), network: windowsNetwork(), volumes: windowsVolumes(), events: windowsEventsFixture(), serviceStartup: windowsServiceStartup(windowsView().snapshot!), processMetrics: { schemaVersion: 'tracebolt.windows-process-metrics.v1', scope: 'windows-process-metrics-v1', grantId: '7'.repeat(32), generationId: windowsView().snapshot!.generationId, collectedAt: windowsView().snapshot!.collectedAt, observedCount: 1, truncated: false, rows: [{ pid: 44, cpuPercent: null, cpuQuality: 'first-sample', memoryBytes: '42', memoryQuality: 'observed' }] } };
        expect(validWindowsInventoryView(v, windowsDeviceId)).toBe(true);
        for (const sibling of [v.patchContext, v.updates, v.adapterContext, v.network, v.volumes, v.events, v.serviceStartup, v.processMetrics]) { const fresh = structuredClone(v); fresh.securityPosture.grantId = sibling.grantId; expect(validWindowsInventoryView(fresh, windowsDeviceId)).toBe(false); }
        expect(validWindowsInventoryView({ ...v, securityPosture: null }, windowsDeviceId)).toBe(false);
        for (const status of ['revoked', 'unavailable', 'awaiting', 'not_configured']) expect(validWindowsInventoryView({ ...v, status, snapshot: null }, windowsDeviceId)).toBe(false);
    });
});
