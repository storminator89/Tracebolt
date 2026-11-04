import { journalAge, journalTime } from './journal-types';
import { validActionID, validServiceActionView } from './service-action-types';
import type { ServiceActionJob, ServiceActionResult } from './service-action-types';

export const SERVICE_ACTION_HISTORY_BYTES = 128 * 1024;
export interface ServiceActionHistoryEntry {
    sequence: string; job: ServiceActionJob; claimedAt: string | null;
    reports: { receivedAt: string; result: ServiceActionResult }[];
}
export interface ServiceActionHistory {
    schemaVersion: 'tracebolt.service-action-history.v1'; deviceId: string; serverNow: string;
    incarnationDigest: string; keyId: string; limit: 64; jobs: ServiceActionHistoryEntry[];
}
const exact = (v: unknown, keys: string[]): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v, k));
const digest = (v: unknown): v is string => typeof v === 'string' && /^sha256:[a-f0-9]{64}$/.test(v) && v !== `sha256:${'0'.repeat(64)}`;
function validJob(job: unknown, device: string, actor: string, now: string): job is ServiceActionJob {
    return validServiceActionView({ schemaVersion: 'tracebolt.service-action-view.v1', deviceId: device, serverNow: now, configured: true, available: false, reason: 'not_configured', services: [], preview: null, job }, device, actor, false);
}
/** Closed, source-qualified projection. Claim/receipt times never become native
 * start/completion times, and command completion never becomes a healthy restart. */
export function validServiceActionHistory(v: unknown, device: string, actor: string): v is ServiceActionHistory {
    if (!validActionID(device, 'agent_') || !validActionID(actor, 'operator_') || !exact(v, ['schemaVersion', 'deviceId', 'serverNow', 'incarnationDigest', 'keyId', 'limit', 'jobs']) || v.schemaVersion !== 'tracebolt.service-action-history.v1' || v.deviceId !== device || !journalTime(v.serverNow) || !digest(v.incarnationDigest) || !digest(v.keyId) || v.limit !== 64 || !Array.isArray(v.jobs) || v.jobs.length > 64) return false;
    const ids = new Set<string>(), now = v.serverNow;
    return v.jobs.every((row, n, rows) => {
        if (!exact(row, ['sequence', 'job', 'claimedAt', 'reports']) || row.sequence !== String(rows.length - n) || !validJob(row.job, device, actor, now) || ids.has(row.job.id) || !Array.isArray(row.reports) || row.reports.length > 3) return false;
        ids.add(row.job.id);
        const job = row.job, reports = row.reports;
        if (n > 0 && !['expired', 'not_started', 'operation_completed'].includes(job.state)) return false;
        if (job.state === 'approved' && journalAge(job.startDeadline, now) <= 0 || job.state === 'expired' && row.claimedAt === null && journalAge(now, job.startDeadline) < 0) return false;
        if (n > 0 && journalAge((rows[n - 1] as ServiceActionHistoryEntry).job.approvedAt, job.approvedAt) < 0) return false;
        if (row.claimedAt === null) return row.reports.length === 0 && job.result === null && ['approved', 'expired'].includes(job.state);
        if (!journalTime(row.claimedAt) || journalAge(row.claimedAt, job.approvedAt) < 0 || journalAge(job.startDeadline, row.claimedAt) <= 0 || journalAge(now, row.claimedAt) < 0) return false;
        let previous = '', at = row.claimedAt;
        for (const report of row.reports) {
            if (!exact(report, ['receivedAt', 'result']) || !journalTime(report.receivedAt) || journalAge(report.receivedAt, at) < 0 || journalAge(now, report.receivedAt) < 0 || !report.result || typeof report.result !== 'object') return false;
            const result = report.result as ServiceActionResult, phase = result.phase;
            if (previous && (previous !== 'admitted' && previous !== 'dispatching' || phase === 'admitted' || phase === previous || phase === 'expired')) return false;
            const state = phase === 'admitted' || phase === 'dispatching' ? 'claimed' : phase;
            if (!validJob({ ...job, state, result }, device, actor, now)) return false;
            previous = phase; at = report.receivedAt;
        }
        return reports.length ? !!job.result && (['phase', 'reason', 'outcome', 'observedState'] as const).every(key => reports.at(-1)!.result[key] === job.result![key]) : job.result === null && job.state === 'claimed';
    });
}
