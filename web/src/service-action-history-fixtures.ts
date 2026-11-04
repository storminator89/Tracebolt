import { actionActor, actionDevice, actionDigest, actionJob, actionNow } from './service-action-fixtures';
import type { ServiceActionHistory } from './service-action-history-types';
export { actionActor, actionDevice, actionNow };
export function actionHistory(): ServiceActionHistory {
    return { schemaVersion: 'tracebolt.service-action-history.v1', deviceId: actionDevice, serverNow: actionNow, incarnationDigest: actionDigest, keyId: actionDigest, limit: 64, jobs: [{ sequence: '1', job: actionJob(), claimedAt: null, reports: [] }] };
}
export function completedActionHistory(): ServiceActionHistory {
    const h = actionHistory(), row = h.jobs[0];
    h.serverNow = '2026-10-05T12:00:10Z'; row.claimedAt = '2026-10-05T12:00:01Z'; row.job = actionJob('operation_completed');
    row.reports = [{ receivedAt: '2026-10-05T12:00:02Z', result: { phase: 'admitted' } }, { receivedAt: '2026-10-05T12:00:03Z', result: { phase: 'dispatching' } }, { receivedAt: '2026-10-05T12:00:04Z', result: row.job.result! }];
    return h;
}
export const historyActor = actionActor;
