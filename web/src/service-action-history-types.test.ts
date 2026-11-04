import { describe, expect, it } from 'vitest';
import { actionHistory, completedActionHistory, actionActor, actionDevice } from './service-action-history-fixtures';
import { validServiceActionHistory } from './service-action-history-types';
const valid = (v: unknown) => validServiceActionHistory(v, actionDevice, actionActor);
describe('closed Linux approval-history contract', () => {
    it('accepts empty, pending and original received transition receipts', () => {
        expect(valid(actionHistory())).toBe(true); expect(valid({ ...actionHistory(), jobs: [] })).toBe(true); expect(valid(completedActionHistory())).toBe(true);
        const h = completedActionHistory(); h.jobs[0].job.result = { observedState: 'active', outcome: 'completed', phase: 'operation_completed' }; expect(valid(h)).toBe(true);
    });
    it('accepts all 64 exact approvals newest first without dropping equal-time records', () => {
        const h = completedActionHistory(), row = h.jobs[0];
        h.jobs = Array.from({ length: 64 }, (_, i) => ({ ...structuredClone(row), sequence: String(64 - i), job: { ...row.job, id: `action_${(64 - i).toString(16).padStart(32, '0')}` } }));
        expect(valid(h)).toBe(true); h.jobs.push(structuredClone(row)); expect(valid(h)).toBe(false);
    });
    it.each(['extra', 'cross-device', 'zero-binding', 'sequence', 'duplicate', 'approval-order', 'partial', 'older-pending'] as const)('rejects %s history', kind => {
        const h = completedActionHistory();
        if (kind === 'extra') Object.assign(h, { envelope: 'never disclose' });
        if (kind === 'cross-device') h.deviceId = `agent_${'f'.repeat(32)}`;
        if (kind === 'zero-binding') h.keyId = `sha256:${'0'.repeat(64)}`;
        if (kind === 'sequence') h.jobs[0].sequence = '2';
        if (kind === 'duplicate') { h.jobs.unshift({ ...structuredClone(h.jobs[0]), sequence: '2' }); }
        if (kind === 'approval-order') { h.jobs.unshift({ ...structuredClone(h.jobs[0]), sequence: '2', job: { ...h.jobs[0].job, id: `action_${'e'.repeat(32)}`, approvedAt: '2026-10-05T11:59:59Z' } }); }
        if (kind === 'partial') delete (h.jobs[0] as Partial<typeof h.jobs[0]>).claimedAt;
        if (kind === 'older-pending') { const pending = actionHistory().jobs[0]; h.jobs.unshift({ ...h.jobs[0], sequence: '2', job: { ...h.jobs[0].job, id: `action_${'e'.repeat(32)}` } }); h.jobs[1] = pending; }
        expect(valid(h)).toBe(false);
    });
    it.each(['no-claim', 'late-claim', 'early-receipt', 'future-receipt', 'reverse-receipt', 'duplicate-phase', 'terminal-repeat', 'wrong-current', 'missing-report', 'extra-result'] as const)('rejects inconsistent %s receipts', kind => {
        const h = completedActionHistory(), row = h.jobs[0];
        if (kind === 'no-claim') row.claimedAt = null;
        if (kind === 'late-claim') row.claimedAt = row.job.startDeadline;
        if (kind === 'early-receipt') row.reports[0].receivedAt = row.job.approvedAt;
        if (kind === 'future-receipt') row.reports[2].receivedAt = '2026-10-05T12:00:11Z';
        if (kind === 'reverse-receipt') row.reports[1].receivedAt = '2026-10-05T12:00:01Z';
        if (kind === 'duplicate-phase') row.reports[1].result.phase = 'admitted';
        if (kind === 'terminal-repeat') row.reports[0].result = row.job.result!;
        if (kind === 'wrong-current') row.job.result = { phase: 'operation_completed', outcome: 'completed', observedState: 'failed' };
        if (kind === 'missing-report') row.reports = [];
        if (kind === 'extra-result') Object.assign(row.reports[0].result, { command: 'never' });
        expect(valid(h)).toBe(false);
    });
    it('preserves an agent-reported expiry within existing source clock skew before the manager deadline', () => {
        const h = actionHistory(), row = h.jobs[0]; h.serverNow = '2026-10-05T12:00:59Z'; row.claimedAt = '2026-10-05T12:00:01Z'; row.job.state = 'expired'; row.job.result = { phase: 'expired' }; row.reports = [{ receivedAt: h.serverNow, result: { phase: 'expired' } }]; expect(valid(h)).toBe(true);
        row.claimedAt = null; row.reports = []; row.job.result = null; expect(valid(h)).toBe(false);
    });
    it('preserves nanosecond claim, receipt and deadline boundaries', () => {
        const h = completedActionHistory(), row = h.jobs[0]; row.claimedAt = '2026-10-05T12:00:00.000000002Z'; row.reports[0].receivedAt = '2026-10-05T12:00:00.000000001Z'; expect(valid(h)).toBe(false);
        row.reports[0].receivedAt = row.claimedAt; expect(valid(h)).toBe(true);
    });
    it('does not turn claim without reports into failure or completion after the deadline', () => {
        const h = actionHistory(); h.serverNow = '2026-10-05T12:02:00Z'; h.jobs[0].claimedAt = '2026-10-05T12:00:01Z'; h.jobs[0].job.state = 'claimed'; expect(valid(h)).toBe(true);
        h.jobs[0].job.state = 'approved'; expect(valid(h)).toBe(false);
    });
});
