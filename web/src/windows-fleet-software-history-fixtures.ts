import { softwareHistoryPage, softwareHistoryRows, softwareHistoryNow } from './windows-software-history-fixtures';
import type { FleetHistoryPage, FleetHistoryQuery } from './windows-fleet-software-history-types';
export { softwareHistoryNow as fleetHistoryNow };
export const fleetHistorySession = '2026-10-11T07:00:00Z';
export const fleetHistoryDevice = (i: number) => `agent_${(i + 1).toString(16).padStart(32, '0')}`;
const token = (mode: string, device: number, offset: number) => `fh_${mode}_${device}_${offset}.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`;
/** Invented vectors. No collector, deployment or browser evidence. */
export function fleetHistoryPage(query: FleetHistoryQuery = { view: 'history', name: '', version: '', cursor: '' }, total = 6, count = 24): FleetHistoryPage {
    const parts = query.cursor.match(/^fh_(fleet|device)_(\d+)_(\d+)\./), mode = parts?.[1] === 'device' ? 'device' : 'fleet';
    const device = Number(parts?.[2] ?? 0), offset = Number(parts?.[3] ?? 0), deadline = '2026-10-11T06:05:10Z';
    const indices = mode === 'device' ? [device] : Array.from({ length: Math.min(5, total - offset) }, (_, i) => offset + i);
    const items = indices.map(i => {
        const h = softwareHistoryPage({ search: query.name, sort: 'observed-desc', limit: mode === 'fleet' ? 3 : 20, cursor: '' }, softwareHistoryRows(count), mode === 'fleet' ? 0 : offset);
        return { deviceId: fleetHistoryDevice(i), identity: (i + 1).toString(16).padStart(64, '0'), authorityUntil: h.authorityUntil!, history: { ...h, schemaVersion: 'tracebolt.windows-fleet-software-history-device.v1' as const, deviceId: fleetHistoryDevice(i), nextCursor: '', cursorExpiresAt: deadline }, detailCursor: mode === 'fleet' ? token('device', i, 0) : '' };
    });
    const next = mode === 'fleet' ? offset + items.length < total ? token('fleet', 0, offset + items.length) : '' : offset + items[0].history.rows.length < items[0].history.matchingCount ? token('device', device, offset + items[0].history.rows.length) : '';
    return { schemaVersion: 'tracebolt.windows-fleet-software-history-page.v1', serverNow: softwareHistoryNow, status: 'ready', search: query.name, mode, totalDevices: total, offset, items, nextCursor: next, cursorExpiresAt: deadline };
}
