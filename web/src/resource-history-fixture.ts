import type { ResourceHistory, ResourcePoint } from './resource-history-types';
export const historyDevice = 'agent_11111111111111111111111111111111';
export const historyNow = '2026-10-07T12:00:00Z';
/** Synthetic test/browser data only. No endpoint observations. */
export function historyFixture(offsets = [-300, -240, -60, 0]): ResourceHistory {
    const points: ResourcePoint[] = offsets.map((offset, index) => { const at = new Date(Date.parse(historyNow) + offset * 1000).toISOString(); return { sequence: String(index + 1), collectedAt: at, receivedAt: at, cpu: { value: index ? 35 + index : 0, quality: 'healthy', collectedAt: at }, memory: { value: 48 + index, quality: 'healthy', collectedAt: at }, disk: { value: 26, quality: 'healthy', collectedAt: at } }; });
    return { schemaVersion: 'tracebolt.resource-history.v1', deviceId: historyDevice, serverNow: historyNow, windowStart: '2026-10-06T12:00:00Z', status: points.length ? 'available' : 'awaiting', resolutionSeconds: 60, gapAfterSeconds: 120, points };
}
