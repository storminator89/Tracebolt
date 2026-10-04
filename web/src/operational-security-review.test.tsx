import { act, cleanup, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { request } from './api';
import { setLocale } from './i18n';
import { OperationalInventoryPanel } from './operational';
import { effectiveOperationalStatus, OPERATIONAL_PROFILE, OPERATIONAL_SCHEMA, SECTION_LIMITS, SECTION_NAMES, validOperationalView } from './operational-types';
import type { OperationalMeta, OperationalSectionName, OperationalView } from './operational-types';

vi.mock('./api', async importOriginal => ({ ...await importOriginal<typeof import('./api')>(), request: vi.fn() }));
const at = '2026-10-03T12:00:00Z';
const generationId = `sample_${'a'.repeat(32)}`;
function meta(name: OperationalSectionName, observedCount = 0): OperationalMeta {
    return { quality: 'healthy', reason: 'none', observedAt: at, generationId, complete: true, truncated: false, observedCount, countExact: true, itemLimit: SECTION_LIMITS[name] };
}
function fixture(): OperationalView {
    return {
        schemaVersion: 'tracebolt.operational-view.v1', deviceId: 'agent_review', status: 'fresh', serverNow: '2026-10-03T12:00:10Z', receivedAt: '2026-10-03T12:00:05Z', sequence: 1, maxAgeSeconds: 120,
        snapshot: { schemaVersion: OPERATIONAL_SCHEMA, collectionProfile: OPERATIONAL_PROFILE, generationId, collectedAt: at, durationMs: 1, sections: {
            volumes: { meta: meta('volumes', 1), items: [{ id: 'mount_1', mountPoint: '/review-fixture', filesystem: 'ext4', kind: 'local', totalBytes: 100, availableBytes: 50, usedPercent: 50, measurementQuality: 'healthy', measurementReason: 'none' }] },
            network: { meta: meta('network'), items: [] },
            services: { meta: meta('services'), items: [] },
            processes: { meta: meta('processes'), items: [] },
            software: { meta: meta('software'), items: [] },
            events: { meta: { ...meta('events'), quality: 'unknown', complete: false, countExact: false, reason: 'not_supported' }, items: [] },
        } },
        lastGood: { volumes: null, network: null, services: null, processes: null, software: null, events: null },
        assessments: { updates: { quality: 'unknown', reason: 'not_implemented' }, vulnerabilities: { quality: 'unknown', reason: 'not_implemented' } },
    };
}
function defer<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(done => { resolve = done; }); return { promise, resolve }; }
beforeEach(() => {
    expect(validOperationalView(fixture(), 'agent_review'), 'The shared synthetic baseline must remain valid before every independent mutation or lifecycle test').toBe(true);
    vi.mocked(request).mockReset(); vi.mocked(request).mockResolvedValue(fixture()); setLocale('en', false);
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

describe('independent operational wire review', () => {
    it('accepts the synthetic bounded baseline', () => expect(validOperationalView(fixture(), 'agent_review')).toBe(true));
    it.each(['service', 'scope', 'socket', 'target', 'mount', 'automount', 'slice', 'timer', 'path', 'device', 'swap'])('accepts a collector-supported .%s journal unit', extension => {
        const value = fixture();
        value.snapshot!.sections.events = { meta: { ...meta('events', 1), complete: false, countExact: false, reason: 'not_supported' }, items: [{ source: 'systemd-journal', unit: `review.${extension}`, priority: 3, messageId: '', count: 1, firstSeen: at, lastSeen: at }] };
        expect(validOperationalView(value, 'agent_review')).toBe(true);
    });
    it('never calls future collection times fresh', () => {
        const value = fixture();
        value.snapshot!.collectedAt = '2026-10-03T12:00:20Z';
        for (const name of SECTION_NAMES) value.snapshot!.sections[name].meta.observedAt = value.snapshot!.collectedAt;
        expect(effectiveOperationalStatus(value, 0)).not.toBe('fresh');
    });
    it('never calls a future receipt fresh', () => {
        const value = fixture(); value.receivedAt = '2026-10-03T12:00:20Z';
        expect(effectiveOperationalStatus(value, 0)).not.toBe('fresh');
    });
    it('accepts a complete event group whose occurrence count exceeds its group count', () => {
        const value = fixture();
        value.snapshot!.sections.events = { meta: meta('events', 2), items: [{ source: 'agent', unit: '', priority: 3, messageId: '', count: 2, firstSeen: at, lastSeen: at }] };
        expect(validOperationalView(value, 'agent_review')).toBe(true);
    });
    it('rejects event occurrences greater than the reported discovered count', () => {
        const value = fixture();
        value.snapshot!.sections.events = { meta: { ...meta('events', 1), complete: false, reason: 'read_failed' }, items: [{ source: 'agent', unit: '', priority: 3, messageId: '', count: 2, firstSeen: at, lastSeen: at }] };
        expect(validOperationalView(value, 'agent_review')).toBe(false);
    });
    it('accepts truthful grouped journal events with incomplete coverage', () => {
        const value = fixture();
        value.snapshot!.sections.events = { meta: { ...meta('events', 2), complete: false, countExact: false, reason: 'not_supported' }, items: [{ source: 'systemd-journal', unit: '', priority: 3, messageId: '', count: 2, firstSeen: at, lastSeen: at }] };
        expect(validOperationalView(value, 'agent_review')).toBe(true);
    });
    it('accepts an unknown volume measurement with explicitly partial coverage', () => {
        const value = fixture(); Object.assign(value.snapshot!.sections.volumes.items[0], { totalBytes: null, availableBytes: null, usedPercent: null, measurementQuality: 'unknown', measurementReason: 'read_failed' });
        Object.assign(value.snapshot!.sections.volumes.meta, { complete: false, reason: 'read_failed' });
        expect(validOperationalView(value, 'agent_review')).toBe(true);
    });
    it('accepts unknown service states with explicitly partial coverage', () => {
        const value = fixture();
        value.snapshot!.sections.services = { meta: { ...meta('services', 1), complete: false, reason: 'invalid_source' }, items: [{ name: 'review.service', loadState: 'unknown', activeState: 'unknown', subState: 'unknown' }] };
        expect(validOperationalView(value, 'agent_review')).toBe(true);
    });
    it('accepts unimplemented network address counts with explicitly partial coverage', () => {
        const value = fixture();
        value.snapshot!.sections.network = { meta: { ...meta('network', 1), complete: false, reason: 'not_implemented' }, items: [{ name: 'review0', state: 'up', mtu: 1500, rxBytes: 1, txBytes: 1, rxErrors: 0, txErrors: 0, ipv4Count: null, ipv6Count: null }] };
        expect(validOperationalView(value, 'agent_review')).toBe(true);
    });
    it('accepts unknown process measurements with explicitly partial coverage', () => {
        const value = fixture();
        value.snapshot!.sections.processes = { meta: { ...meta('processes', 1), complete: false, reason: 'read_failed' }, items: [{ pid: 42, parentPid: null, name: 'review', state: 'sleeping', rssBytes: 2, cpuTimeSeconds: 1, threads: null }] };
        expect(validOperationalView(value, 'agent_review')).toBe(true);
    });
    it('rejects unknown volume measurements presented as complete', () => {
        const value = fixture(); Object.assign(value.snapshot!.sections.volumes.items[0], { totalBytes: null, availableBytes: null, usedPercent: null, measurementQuality: 'unknown', measurementReason: 'read_failed' });
        expect(validOperationalView(value, 'agent_review')).toBe(false);
    });
    it('rejects unknown service states presented as complete', () => {
        const value = fixture();
        value.snapshot!.sections.services = { meta: meta('services', 1), items: [{ name: 'review.service', loadState: 'unknown', activeState: 'unknown', subState: 'unknown' }] };
        expect(validOperationalView(value, 'agent_review')).toBe(false);
    });
    it('rejects unknown network measurements presented as complete', () => {
        const value = fixture();
        value.snapshot!.sections.network = { meta: meta('network', 1), items: [{ name: 'review0', state: 'up', mtu: 1500, rxBytes: 1, txBytes: 1, rxErrors: 0, txErrors: 0, ipv4Count: null, ipv6Count: null }] };
        expect(validOperationalView(value, 'agent_review')).toBe(false);
    });
    it('rejects unknown process measurements presented as complete', () => {
        const value = fixture();
        value.snapshot!.sections.processes = { meta: meta('processes', 1), items: [{ pid: 42, parentPid: null, name: 'review', state: 'sleeping', rssBytes: 2, cpuTimeSeconds: 1, threads: null }] };
        expect(validOperationalView(value, 'agent_review')).toBe(false);
    });
    it('rejects a retained section exceeding the section byte limit', () => {
        const value = fixture();
        value.lastGood.software = { meta: { ...meta('software', 256), quality: 'stale' }, items: Array.from({ length: 256 }, (_, i) => ({ name: `review-${i}-${'x'.repeat(110)}`, version: `1.${'1'.repeat(185)}`, architecture: 'all', manager: 'dpkg' as const })) };
        expect(new TextEncoder().encode(JSON.stringify(value.lastGood.software)).byteLength).toBeGreaterThan(48 * 1024);
        expect(validOperationalView(value, 'agent_review')).toBe(false);
    });
    it('rejects retained observation times newer than the current snapshot', () => {
        const value = fixture(); value.lastGood.services = { meta: { ...meta('services'), quality: 'stale', generationId: `sample_${'b'.repeat(32)}`, observedAt: '2026-10-03T12:00:01Z' }, items: [] };
        expect(validOperationalView(value, 'agent_review')).toBe(false);
    });
    it.each(['//home/review-private', '/tmp/../home/review-private', '/home/[redacted]/../review-private', '/review/'])('rejects noncanonical mount path %s', mountPoint => {
        const value = fixture(); value.snapshot!.sections.volumes.items[0].mountPoint = mountPoint;
        expect(validOperationalView(value, 'agent_review')).toBe(false);
    });
    it('rejects mount identifiers above the kernel uint32 bound', () => {
        const value = fixture(); value.snapshot!.sections.volumes.items[0].id = 'mount_4294967296';
        expect(validOperationalView(value, 'agent_review')).toBe(false);
    });
    it('rejects a remote filesystem mislabelled as locally measured', () => {
        const value = fixture(); value.snapshot!.sections.volumes.items[0].filesystem = 'nfs';
        expect(validOperationalView(value, 'agent_review')).toBe(false);
    });
    it('rejects a used percentage inconsistent with the numeric measurement', () => {
        const value = fixture(); value.snapshot!.sections.volumes.items[0].usedPercent = 0;
        expect(validOperationalView(value, 'agent_review')).toBe(false);
    });
    it.each(['.', '..'])('rejects non-interface name %s', name => {
        const value = fixture();
        value.snapshot!.sections.network = { meta: meta('network', 1), items: [{ name, state: 'up', mtu: 1500, rxBytes: 1, txBytes: 1, rxErrors: 0, txErrors: 0, ipv4Count: 0, ipv6Count: 0 }] };
        expect(validOperationalView(value, 'agent_review')).toBe(false);
    });
    it.each(['v1', '1 version', '1-', '1/secret', '1;secret'])('rejects invalid Debian package version %s', version => {
        const value = fixture(); value.snapshot!.sections.software = { meta: meta('software', 1), items: [{ name: 'review', version, architecture: 'all', manager: 'dpkg' }] };
        expect(validOperationalView(value, 'agent_review')).toBe(false);
    });
    it('rejects a zero admitted telemetry sequence', () => {
        const value = fixture(); value.sequence = 0;
        expect(validOperationalView(value, 'agent_review')).toBe(false);
    });
});

describe('independent suspension review', () => {
    it('invalidates a loaded private observation when the page is hidden', async () => {
        render(<OperationalInventoryPanel deviceId="agent_review"/>); await screen.findByText('/review-fixture');
        vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden');
        act(() => document.dispatchEvent(new Event('visibilitychange')));
        expect(screen.queryByText('/review-fixture')).not.toBeInTheDocument();
        expect(screen.queryByText('Within collection window')).not.toBeInTheDocument();
    });
    it('invalidates an in-flight observation across BFCache restoration', async () => {
        const pending = defer<OperationalView>(); const refreshed = defer<OperationalView>();
        vi.mocked(request).mockReturnValueOnce(pending.promise).mockReturnValue(refreshed.promise);
        render(<OperationalInventoryPanel deviceId="agent_review"/>);
        const originalSignal = vi.mocked(request).mock.calls[0][1]!.signal!;
        act(() => window.dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true })));
        act(() => window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true })));
        expect(originalSignal.aborted).toBe(true);
        await act(async () => pending.resolve(fixture()));
        expect(screen.queryByText('/review-fixture')).not.toBeInTheDocument();
    });
});
