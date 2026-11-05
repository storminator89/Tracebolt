import type { OperationalNetwork, OperationalSections, OperationalView } from './operational-types';
import { OPERATIONAL_PROFILE, OPERATIONAL_SCHEMA, SECTION_LIMITS } from './operational-types';

export function networkRow(name = 'fixture0', rxBytes: number | null = 1000, txBytes: number | null = 2000): OperationalNetwork {
    return { name, state: 'up', mtu: 1500, rxBytes, txBytes, rxErrors: 0, txErrors: 0, ipv4Count: null, ipv6Count: null };
}
/** Synthetic strict-DTO fixture; the native provider reports partial network
 * coverage because it deliberately omits all interface-address enumeration. */
export function networkView(sequence = 1, at = '2026-10-03T12:00:00Z', rows = [networkRow()]): OperationalView {
    const generationId = `sample_${sequence.toString(16).padStart(32, '0')}`;
    const unavailable = (name: keyof OperationalSections) => ({ meta: { quality: 'unknown' as const, reason: 'not_supported' as const, observedAt: at, generationId, complete: false, truncated: false, observedCount: 0, countExact: false, itemLimit: SECTION_LIMITS[name] }, items: [] });
    const sections: OperationalSections = { volumes: unavailable('volumes'), network: unavailable('network'), services: unavailable('services'), processes: unavailable('processes'), software: unavailable('software'), events: unavailable('events') };
    sections.network = { meta: { quality: 'healthy', reason: 'not_implemented', observedAt: at, generationId, complete: false, truncated: false, observedCount: rows.length, countExact: true, itemLimit: SECTION_LIMITS.network }, items: rows };
    return { schemaVersion: 'tracebolt.operational-view.v1', deviceId: 'agent_fixture', status: 'fresh', serverNow: at, receivedAt: at, sequence, maxAgeSeconds: 120, snapshot: { schemaVersion: OPERATIONAL_SCHEMA, collectionProfile: OPERATIONAL_PROFILE, generationId, collectedAt: at, durationMs: 1, sections }, lastGood: { volumes: null, network: null, services: null, processes: null, software: null, events: null }, assessments: { updates: { quality: 'unknown', reason: 'not_implemented' }, vulnerabilities: { quality: 'unknown', reason: 'not_implemented' } } };
}
