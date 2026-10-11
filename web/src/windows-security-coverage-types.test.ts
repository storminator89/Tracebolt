import { describe, expect, it } from 'vitest';
import { windowsDeviceId, windowsNow, windowsView } from './windows-inventory-fixture';
import { validWindowsInventoryView, type WindowsInventoryView } from './windows-inventory-types';
import { windowsSecurityCoverage, windowsSecurityCoverageView } from './windows-security-coverage-fixture';
import { usefulWindowsSecurityCoverage, validWindowsSecurityCoverage, WINDOWS_SECURITY_COVERAGE_REASONS, type WindowsSecurityCoverage } from './windows-security-coverage-types';
import { windowsSecurityPosture } from './windows-security-posture-fixture';
import { windowsStorageContext } from './windows-storage-context-fixture';
const valid = (v: unknown) => validWindowsSecurityCoverage(v, windowsView().snapshot!, windowsNow);
const unknown = (v: WindowsSecurityCoverage, reason: WindowsSecurityCoverage['antivirus']['reason'] = 'windows_security_coverage_unavailable') => {
    const quality = reason === 'windows_security_coverage_access_denied' ? 'denied' : 'unavailable';
    v.antivirus = { quality, reason, reportedCount: null, rows: [], truncated: false };
    v.tpm = { quality, reason, presence: 'unknown', version: 'unknown' };
};
function retained(): WindowsInventoryView { const v = windowsSecurityCoverageView(), old = windowsSecurityCoverage(); old.collectedAt = '2026-10-07T11:00:00Z'; old.generationId = `sample_${'b'.repeat(32)}`; unknown(v.securityCoverage); return { ...v, retainedContext: { securityCoverage: old } }; }
describe('bounded Windows antivirus and TPM contract', () => {
    it('keeps old views compatible and uses a separate grant from Defender and storage', () => {
        expect(validWindowsInventoryView(windowsView(), windowsDeviceId)).toBe(true);
        const v = { ...windowsSecurityCoverageView(), securityPosture: windowsSecurityPosture(), storageContext: windowsStorageContext() };
        expect(validWindowsInventoryView(v, windowsDeviceId)).toBe(true);
        for (const grantId of [v.securityPosture.grantId, v.storageContext.grantId]) expect(validWindowsInventoryView({ ...v, securityCoverage: { ...v.securityCoverage, grantId } }, windowsDeviceId)).toBe(false);
        expect(validWindowsInventoryView({ ...windowsView(), securityCoverage: null }, windowsDeviceId)).toBe(false);
    });
    it.each(WINDOWS_SECURITY_COVERAGE_REASONS.filter(Boolean))('preserves explicit failure %s with no asserted absence', reason => {
        const v = windowsSecurityCoverage(); unknown(v, reason); expect(valid(v)).toBe(true); expect(usefulWindowsSecurityCoverage(v)).toBe(false);
    });
    it('preserves readable zero count, supported-device not-found and unknown version separately', () => {
        const v = windowsSecurityCoverage(); unknown(v); v.antivirus = { quality: 'observed', reason: '', reportedCount: 0, rows: [], truncated: false }; expect(valid(v)).toBe(true); expect(usefulWindowsSecurityCoverage(v)).toBe(true);
        unknown(v); v.tpm = { quality: 'observed', reason: '', presence: 'not-found', version: 'unknown' }; expect(valid(v)).toBe(true); expect(usefulWindowsSecurityCoverage(v)).toBe(true);
        v.tpm = { quality: 'partial', reason: 'windows_security_coverage_invalid_metadata', presence: 'present', version: 'unknown' }; expect(valid(v)).toBe(true);
        for (const version of ['1.2', '2.0'] as const) { v.tpm = { quality: 'observed', reason: '', presence: 'present', version }; expect(valid(v)).toBe(true); }
    });
    it('requires useful fields rather than positive count or unknown-only rows for history', () => {
        const v = windowsSecurityCoverage(); unknown(v); v.antivirus = { quality: 'partial', reason: 'windows_security_coverage_partial_result', reportedCount: 1, rows: [{ index: 0, name: null, state: 'unknown', signatureStatus: 'unknown' }], truncated: false }; expect(valid(v)).toBe(true); expect(usefulWindowsSecurityCoverage(v)).toBe(false);
        for (const change of [{ name: 'Example' }, { state: 'off' as const }, { signatureStatus: 'out-of-date' as const }]) { const p = structuredClone(v); Object.assign(p.antivirus.rows[0], change); expect(usefulWindowsSecurityCoverage(p)).toBe(true); }
    });
    const mutations: [string, (v: WindowsSecurityCoverage) => void][] = [
        ['count overflow', v => { v.antivirus.reportedCount = 65536; }], ['negative zero count', v => { v.antivirus.reportedCount = -0; }], ['missing count', v => { v.antivirus.reportedCount = null; }], ['false truncation', v => { v.antivirus.truncated = true; }], ['sparse indexes', v => { v.antivirus.rows[0].index = 1; }], ['too many products', v => { v.antivirus.rows = Array.from({ length: 17 }, (_, index) => ({ ...v.antivirus.rows[0], index })); v.antivirus.reportedCount = 17; }], ['overlong UTF16 label', v => { v.antivirus.rows[0].name = '😀'.repeat(65); }], ['control label', v => { v.antivirus.rows[0].name = 'name\n'; }], ['bidi label', v => { v.antivirus.rows[0].name = 'name\u202e'; }], ['lone surrogate', v => { v.antivirus.rows[0].name = '\ud800'; }], ['empty label', v => { v.antivirus.rows[0].name = ''; }], ['unknown complete state', v => { v.antivirus.rows[0].state = 'unknown'; }], ['unknown complete signature', v => { v.antivirus.rows[0].signatureStatus = 'unknown'; }], ['not-found with version', v => { v.tpm.presence = 'not-found'; }], ['unknown presence with version', v => { v.tpm.presence = 'unknown'; }], ['observed unknown version', v => { v.tpm.version = 'unknown'; }], ['missing reason', v => { v.tpm.quality = 'partial'; v.tpm.version = 'unknown'; }],
    ];
    it.each(mutations)('rejects %s', (_, mutate) => { const v = windowsSecurityCoverage(); mutate(v); expect(valid(v)).toBe(false); });
    it('accepts exact UTF16 bounds and rejects Go HTML-escaped aggregate overflow', () => {
        const v = windowsSecurityCoverage(); v.antivirus.rows[0].name = '😀'.repeat(64); expect(valid(v)).toBe(true);
        v.antivirus.rows = Array.from({ length: 16 }, (_, index) => ({ ...v.antivirus.rows[0], index, name: '<'.repeat(128) })); v.antivirus.reportedCount = 16; expect(valid(v)).toBe(false);
        v.antivirus.rows = v.antivirus.rows.slice(0, 4); v.antivirus.quality = 'partial'; v.antivirus.reason = 'windows_security_coverage_bounds'; v.antivirus.truncated = true; expect(valid(v)).toBe(true);
    });
    it('rejects unknown raw fields and invalid binding, timestamps and expiry', () => {
        const v = windowsSecurityCoverage();
        for (const bad of [{ ...v, rawTPM: 'raw' }, { ...v, antivirus: { ...v.antivirus, remediationPath: 'path' } }, { ...v, tpm: { ...v.tpm, ownerAuth: 'raw' } }, { ...v, generationId: `sample_${'b'.repeat(32)}` }]) expect(valid(bad)).toBe(false);
        expect(validWindowsSecurityCoverage(v, windowsView().snapshot!, '2026-10-07T11:59:30Z')).toBe(true);
        expect(validWindowsSecurityCoverage(v, windowsView().snapshot!, '2026-10-07T11:59:29.999999999Z')).toBe(false);
        expect(validWindowsSecurityCoverage(v, windowsView().snapshot!, '2026-10-08T12:00:00Z')).toBe(false);
        for (const collectedAt of ['2026-02-30T12:00:00Z', '1969-12-31T12:00:00Z', '2026-10-07T12:00:00+00:00']) expect(validWindowsSecurityCoverage({ ...v, collectedAt }, { ...windowsView().snapshot!, collectedAt }, collectedAt)).toBe(false);
    });
    it('binds retained useful captures to the current grant and their own original age', () => {
        expect(validWindowsInventoryView(retained(), windowsDeviceId)).toBe(true);
        for (const change of [
            (v: WindowsInventoryView) => { delete v.securityCoverage; },
            (v: WindowsInventoryView) => { v.retainedContext!.securityCoverage!.grantId = '2'.repeat(32); },
            (v: WindowsInventoryView) => { v.retainedContext!.securityCoverage!.collectedAt = v.securityCoverage!.collectedAt; },
            (v: WindowsInventoryView) => { v.retainedContext!.securityCoverage!.collectedAt = '2026-10-06T12:00:10Z'; },
            (v: WindowsInventoryView) => { unknown(v.retainedContext!.securityCoverage!); },
            (v: WindowsInventoryView) => { v.status = 'revoked'; v.snapshot = null; },
        ]) { const v = retained(); change(v); expect(validWindowsInventoryView(v, windowsDeviceId)).toBe(false); }
    });
});
