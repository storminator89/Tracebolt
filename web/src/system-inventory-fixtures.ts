import type { SectionMeta, ServiceRow, SocketRow, SystemPage, SystemSection, SystemView } from './system-inventory-types';
export const systemDevice = 'agent_system_fixture', systemNow = '2026-10-04T00:00:10Z', systemGeneration = `sample_${'a'.repeat(32)}`;
// Synthetic component/contract fixtures only; never imported by production UI.
export function serviceRows(count = 350): ServiceRow[] { return Array.from({ length: count }, (_, index) => ({ name: `fixture-${String(index).padStart(6, '0')}.service`, runtime: { loadState: 'loaded', activeState: index % 3 === 0 ? 'failed' : 'active', subState: index % 3 === 0 ? 'failed' : 'running' }, enablement: index % 2 === 0 ? 'enabled' : 'disabled', mainPid: null })); }
export function socketRows(count = 75): SocketRow[] { return Array.from({ length: count }, (_, index) => ({ protocol: index % 3 === 0 ? 'udp' : 'tcp', family: 'ipv4', kind: index % 3 === 0 ? 'bound' : index % 3 === 1 ? 'listener' : 'connection', local: { address: '127.0.0.1', port: 10000 + index }, remote: { address: index % 3 === 2 ? '192.0.2.5' : '0.0.0.0', port: index % 3 === 2 ? 443 : 0 }, state: index % 3 === 0 ? 'bound' : index % 3 === 1 ? 'listen' : 'established', owners: [{ pid: 100 + index, processName: `fixture-proc-${index}`, nameReason: 'none' }], attribution: { coverage: 'observed', reason: 'none' } })); }
export function sectionMeta(count: number): SectionMeta { return { generationId: systemGeneration, observedAt: '2026-10-04T00:00:00Z', coverage: 'complete', reason: 'none', observedCount: count, countExact: true }; }
export function systemView(services = 350, sockets = 75): SystemView {
    return { schemaVersion: 'tracebolt.system-inventory-view.v1', deviceId: systemDevice, collectionProfile: 'managed-operations-v3', status: 'fresh', serverNow: systemNow, maxAgeSeconds: 120, sequence: '9007199254740993', receivedAt: '2026-10-04T00:00:05Z', latest: { generationId: systemGeneration, collectedAt: '2026-10-04T00:00:00Z', durationMs: 1, scope: 'agent-visible-linux-system', services: sectionMeta(services), sockets: sectionMeta(sockets) }, lastComplete: { services: { sequence: '9007199254740993', meta: sectionMeta(services), status: 'fresh' }, sockets: { sequence: '9007199254740993', meta: sectionMeta(sockets), status: 'fresh' } } };
}
export function systemPage(view: SystemView, services: ServiceRow[], sockets: SocketRow[], raw: string): SystemPage {
    const input = JSON.parse(raw) as { section: SystemSection; generationId: string; search: string; cursor: string; filter: string; limit: number };
    const all = input.section === 'services' ? services : sockets, selected = view.lastComplete[input.section]!;
    let index = input.cursor ? Number(input.cursor.slice(7)) : 0, scanned = 0; const serviceItems: ServiceRow[] = [], socketItems: SocketRow[] = [], query = input.search.trim().toLowerCase();
    for (; index < all.length && scanned < 2048 && serviceItems.length + socketItems.length < input.limit; index++) {
        scanned++;
        if (input.section === 'services') {
            const row = services[index], match = input.filter === 'active' ? row.runtime?.activeState === 'active' : input.filter === 'failed' ? row.runtime?.activeState === 'failed' : input.filter === 'enabled' ? row.enablement === 'enabled' || row.enablement === 'enabled-runtime' : true;
            const text = [row.name, row.runtime?.loadState, row.runtime?.activeState, row.runtime?.subState, row.enablement].filter(Boolean).join(' ').toLowerCase(); if (match && text.includes(query)) serviceItems.push(row);
        } else {
            const row = sockets[index], match = input.filter === 'tcp-listeners' ? row.protocol === 'tcp' && row.kind === 'listener' : input.filter === 'udp' ? row.protocol === 'udp' : input.filter === 'connections' ? row.kind === 'connection' : true;
            const text = [row.protocol, row.family, row.kind, row.local.address, row.local.port, row.remote.address, row.remote.port, row.state, ...row.owners.flatMap(owner => [owner.pid, owner.processName ?? ''])].join(' ').toLowerCase(); if (match && text.includes(query)) socketItems.push(row);
        }
    }
    const expiry = new Date(Math.min(Date.parse(view.serverNow) + 900000, Date.parse(selected.meta.observedAt) + 86400000)).toISOString();
    return { schemaVersion: 'tracebolt.system-inventory-page.v1', deviceId: view.deviceId, collectionProfile: 'managed-operations-v3', serverNow: view.serverNow, section: input.section, generationId: selected.meta.generationId, meta: selected.meta, status: selected.status, totalRows: all.length, returnedCount: serviceItems.length + socketItems.length, scannedCount: scanned, exhausted: index === all.length, nextCursor: index === all.length ? '' : `cursor_${index}`, cursorExpiresAt: index === all.length ? null : expiry, services: serviceItems, sockets: socketItems };
}
