import { describe, expect, it } from 'vitest';
import { actionActor, actionDevice, actionJobView, actionPreview, actionView } from './service-action-fixtures';
import { validServiceActionView, validServiceActionUnit } from './service-action-types';
const valid = (value: unknown) => validServiceActionView(value, actionDevice, actionActor, false);
describe('closed service-action view contract', () => {
    it('accepts exact previews, decimal uint64 and each honest job state', () => {
        expect(valid({ ...actionView(), preview: actionPreview() })).toBe(true);
        for (const state of ['approved', 'claimed', 'expired', 'operation_completed', 'not_started', 'needs_intervention'] as const) expect(valid(actionJobView(state))).toBe(true);
        expect(valid({ ...actionJobView('claimed'), job: { ...actionJobView('claimed').job, result: { phase: 'dispatching' } } })).toBe(true);
    });
    it.each([
        (v: Record<string, unknown>) => { v.available = 'yes'; },
        (v: Record<string, unknown>) => { v.reason = 'success'; },
        (v: Record<string, unknown>) => { v.deviceId = `agent_${'f'.repeat(32)}`; },
        (v: Record<string, unknown>) => { v.command = 'systemctl'; },
        (v: Record<string, unknown>) => { v.serverNow = '2026-02-31T12:00:00Z'; },
        (v: Record<string, unknown>) => { v.services = [...actionView().services, actionView().services[0]]; },
        (v: Record<string, unknown>) => { v.preview = { ...actionPreview(), actorId: `operator_${'f'.repeat(32)}` }; },
        (v: Record<string, unknown>) => { v.preview = { ...actionPreview(), sequence: 9007199254740993 }; },
        (v: Record<string, unknown>) => { v.preview = { ...actionPreview(), sequence: '18446744073709551616' }; },
        (v: Record<string, unknown>) => { v.preview = { ...actionPreview(), transportProfile: 'disposable-http-test' }; },
        (v: Record<string, unknown>) => { v.preview = actionPreview('unlisted.service'); },
        (v: Record<string, unknown>) => { v.preview = { ...actionPreview(), plan: { ...actionPreview().plan, action: 'service.restart' } }; },
        (v: Record<string, unknown>) => { v.preview = { ...actionPreview(), digest: 'arbitrary' }; },
        (v: Record<string, unknown>) => { v.preview = { ...actionPreview(), digest: `sha256:${'0'.repeat(64)}` }; },
        (v: Record<string, unknown>) => { v.preview = { ...actionPreview(), expiresAt: '2026-10-05T12:02:00Z' }; },
        (v: Record<string, unknown>) => { v.job = actionJobView('claimed').job; },
        (v: Record<string, unknown>) => { v.job = { ...actionJobView('operation_completed').job, result: null }; },
        (v: Record<string, unknown>) => { v.job = { ...actionJobView('operation_completed').job, result: { phase: 'operation_completed', outcome: 'completed', observedState: 'healthy' } }; },
    ])('rejects malformed, expanded or inconsistent views (%#)', mutate => { const value = actionView() as unknown as Record<string, unknown>; mutate(value); expect(valid(value)).toBe(false); });
    it('accepts only the helper unit syntax, never command arguments, templates or paths', () => {
        for (const unit of ['a.service', 'fixture-1_test.service']) expect(validServiceActionUnit(unit)).toBe(true);
        for (const unit of ['ssh@host.service', '/fixture.service', 'fixture.service --all', '-fixture.service', 'fixture\\x2d.service', `a${'x'.repeat(128)}.service`]) expect(validServiceActionUnit(unit)).toBe(false);
    });
});
