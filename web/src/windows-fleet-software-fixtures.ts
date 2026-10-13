import { fullSoftwareComplete, fullSoftwareNow, replaceFullSoftwareGeneration } from './windows-full-software-fixtures';
import type { FullSoftwareRow } from './windows-full-software-types';
import type { FleetSoftwareItem, FleetSoftwarePage, FleetSoftwareQuery } from './windows-fleet-software-types';
export const fleetSoftwareNow = fullSoftwareNow;
export const fleetSoftwareExpiry = '2026-10-11T06:05:10Z';
export const fleetSoftwareSession = '2026-10-11T07:00:00Z';
export const fleetSoftwareQuery: FleetSoftwareQuery = { name: 'Fixture', version: '', cursor: '' };
export const fleetSoftwareCursor = (value: string) => `${value}.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`;
export const fleetSoftwareDevice = (index: number) => `agent_${(index + 1).toString(16).padStart(32, '0')}`;
export function fleetSoftwareRows(): FullSoftwareRow[] {
    return Array.from({ length: 27 }, (_, index) => ({ registrationId: (index + 1).toString(16).padStart(64, '0'), registryView: index % 2 ? '64' : '32', name: index < 23 ? `Fixture [.*] Ä ${index}` : null, nameQuality: index < 23 ? 'observed' : 'unavailable', version: index === 0 ? '' : '1.2.3+literal', versionQuality: 'observed', publisher: null, publisherQuality: 'unavailable' }));
}
export function fleetSoftwareItem(index = 0, query = fleetSoftwareQuery, mode: 'fleet' | 'device' = 'fleet', offset = 0): FleetSoftwareItem {
    const complete = fullSoftwareComplete(), rows = fleetSoftwareRows(); complete.manifest.deviceId = fleetSoftwareDevice(index); replaceFullSoftwareGeneration(complete, rows, 1);
    const unknown = rows.filter(row => query.name !== '' && row.name === null || query.version !== '' && row.version === null);
    const matches = rows.filter(row => (query.name === '' || row.name?.toLowerCase().includes(query.name.toLowerCase())) && (query.version === '' || row.version?.toLowerCase().includes(query.version.toLowerCase())));
    return { deviceId: complete.manifest.deviceId, identity: (index + 101).toString(16).padStart(64, '0'), status: 'ready', authorityUntil: '2026-10-12T05:00:00Z', complete, latestAttempt: { sequence: 1, attemptedAt: complete.manifest.captureStartedAt, status: 'complete', reason: '' }, matchingCount: matches.length, unknownCount: unknown.length, rows: matches.slice(offset, offset + (mode === 'fleet' ? 3 : 20)), detailCursor: mode === 'fleet' ? fleetSoftwareCursor(`device_${index}_0`) : '' };
}
export function fleetSoftwarePage(query = fleetSoftwareQuery, totalDevices = 6): FleetSoftwarePage {
    const match = /^(fleet_(\d+)|device_(\d+)_(\d+))\./.exec(query.cursor), mode = match?.[3] !== undefined ? 'device' : 'fleet';
    const offset = Number(mode === 'device' ? match?.[4] : match?.[2]) || 0, index = Number(match?.[3]) || 0;
    const items = mode === 'fleet' ? Array.from({ length: Math.min(5, totalDevices - offset) }, (_, i) => fleetSoftwareItem(i + offset, query)) : [fleetSoftwareItem(index, query, 'device', offset)];
    const more = mode === 'fleet' ? offset + items.length < totalDevices : offset + items[0].rows.length < items[0].matchingCount;
    return { schemaVersion: 'tracebolt.windows-fleet-software-page.v1', serverNow: fleetSoftwareNow, status: 'ready', name: query.name, version: query.version, mode, totalDevices, offset, items, nextCursor: more ? fleetSoftwareCursor(mode === 'fleet' ? `fleet_${offset + items.length}` : `device_${index}_${offset + items[0].rows.length}`) : '', cursorExpiresAt: fleetSoftwareExpiry };
}
