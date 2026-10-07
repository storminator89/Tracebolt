import impactVectors from './service-action-impact-vectors.json';
import { describe, expect, it } from 'vitest';
import { actionActor, actionDevice, actionPreview, actionView } from './service-action-fixtures';
import { actionV2View } from './service-action-v2-fixtures';
import { affectedServicesDigest } from './service-action-impact';
import { validServiceActionView } from './service-action-types';
const valid = (v: unknown) => validServiceActionView(v, actionDevice, actionActor, false);
describe('v2 complete impact contract', () => {
    it('matches independently computed SHA-256 for every allowed impact size', () => {
        for (let n = 1; n <= 64; n++) {
            const services = Array.from({ length: n }, (_, i) => `unit-${String(i).padStart(3,'0')}${'x'.repeat(i)}.service`);
            // Independent Python hashlib vectors, one per permitted list length.
            const expected = impactVectors[n - 1];
            expect(affectedServicesDigest(services)).toBe(`sha256:${expected}`);
        }
    });
    it('accepts v1 and exact v2, empty excluded omission, 64 impact units and 256 capabilities', () => {
        expect(valid(actionV2View())).toBe(true); expect(valid({ ...actionView(), preview: actionPreview() })).toBe(true);
        const value = actionV2View(); delete value.excludedServices; expect(valid(value)).toBe(true);
        const impact = ['fixture.service', ...Array.from({ length: 63 }, (_, i) => `z${String(i).padStart(3,'0')}.service`)]; expect(valid(actionV2View(impact))).toBe(true);
        value.preview = null; value.services = Array.from({ length: 256 }, (_, i) => ({ unit: `u${String(i).padStart(3,'0')}.service`, unitPolicyDigest: value.services[0].unitPolicyDigest, affectedServices: [`u${String(i).padStart(3,'0')}.service`] })); expect(valid(value)).toBe(true);
    });
    it.each([
        ['missing target', (v: any) => { v.preview.affectedServices = ['dependent.service']; }],
        ['missing dependency', (v: any) => { v.preview.affectedServices = ['fixture.service']; }],
        ['forged digest', (v: any) => { v.preview.plan.affectedServicesDigest = `sha256:${'e'.repeat(64)}`; }],
        ['changed capability impact', (v: any) => { v.services[0].affectedServices = ['fixture.service']; }],
        ['changed notice', (v: any) => { v.preview.reviewNotice = 'Safe'; }],
        ['changed view notice', (v: any) => { v.reviewNotice += ' '; }],
        ['wrong scope', (v: any) => { v.scope = 'all'; }],
        ['duplicate impact', (v: any) => { v.services[0].affectedServices = ['fixture.service', 'fixture.service']; }],
        ['unsorted impact', (v: any) => { v.services[0].affectedServices.reverse(); }],
        ['empty impact', (v: any) => { v.services[0].affectedServices = []; }],
        ['oversized impact', (v: any) => { v.services[0].affectedServices = Array.from({ length: 65 }, (_, i) => `${i}.service`); }],
        ['mixed preview', (v: any) => { v.preview = actionPreview(); }],
        ['mixed plan', (v: any) => { v.preview.plan.version = 'tracebolt.action-plan.v1'; }],
        ['extra plan field', (v: any) => { v.preview.plan.command = 'restart'; }],
        ['missing digest', (v: any) => { delete v.preview.plan.affectedServicesDigest; }],
        ['unknown exclusion', (v: any) => { v.excludedServices[0].reason = 'safe'; }],
        ['duplicate exclusion', (v: any) => { v.excludedServices.push(v.excludedServices[0]); }],
        ['selectable exclusion', (v: any) => { v.excludedServices[0].unit = 'fixture.service'; }],
        ['duplicate capability', (v: any) => { v.services.push(v.services[0]); }],
        ['extra view field', (v: any) => { v.command = 'restart'; }],
    ])('rejects %s', (_name, mutate) => { const value = structuredClone(actionV2View()); mutate(value); expect(valid(value)).toBe(false); });
    it('keeps v2-only fields forbidden on v1', () => {
        for (const extra of [{ scope: 'control-existing-root-trusted-system-services' }, { reviewNotice: 'text' }, { excludedServices: [] }]) expect(valid({ ...actionView(), ...extra })).toBe(false);
        const value = actionView(); value.preview = actionV2View().preview; expect(valid(value)).toBe(false);
        value.preview = { ...actionPreview(), affectedServices: ['fixture.service'] }; expect(valid(value)).toBe(false);
        value.preview = null; value.services[0].affectedServices = ['fixture.service']; expect(valid(value)).toBe(false);
    });
});

it('retains valid all-excluded v2 reports without allowing a preview and keeps v1 empty-ready rejected', () => {
    const value = actionV2View(); value.services = []; value.preview = null; expect(valid(value)).toBe(true);
    value.preview = actionV2View().preview; expect(valid(value)).toBe(false);
    expect(valid({ ...actionView(), services: [] })).toBe(false);
});
