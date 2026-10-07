import { describe, expect, it } from 'vitest';
import { basicCapability, capabilityFailure, journalCapability, overviewCapability, packageCapability, socketOwnerCapability, systemCapability } from './capability-observations';
import { socketOwnerSource, systemView } from './system-inventory-fixtures';
import { overviewView as retainedOverviewView } from './complete-overview-fixtures';
const overviewView = (...args: Parameters<typeof retainedOverviewView>) => { const view = retainedOverviewView(...args); view.serverNow = '2026-10-04T18:30:10Z'; return view; };
import { completeView } from './complete-packages-fixtures';
import { journalView } from './journal-fixtures';
import type { Device } from './types';

describe('capability source meaning', () => {
    it('keeps failure, absent support, missing config, denied, unknown and stale distinct', () => {
        expect(capabilityFailure('permission_denied').state).toBe('denied');
        expect(capabilityFailure('not_supported').state).toBe('unsupported');
        expect(capabilityFailure('read_failed').state).toBe('failed');
        expect(capabilityFailure('source_missing').state).toBe('failed');
        expect(capabilityFailure('not_collected').state).toBe('unknown');
        expect(systemCapability({ ...systemView(), status: 'not_configured', latest: null }, 'services', 0).state).toBe('not_configured');
        expect(systemCapability({ ...systemView(), status: 'awaiting', latest: null }, 'services', 0).state).toBe('unknown');
        expect(systemCapability(systemView(), 'services', 120001).state).toBe('stale');
    });
    it('does not turn zero rows into a failed or unconfigured source', () => {
        expect(systemCapability(systemView(0, 0), 'services', 0).state).toBe('available');
        expect(overviewCapability(overviewView(0, 0), 'processes', 0).state).toBe('available');
        expect(packageCapability(completeView(0), 0).state).toBe('available');
    });
    it('shows newer source failures despite retained complete data and keeps stale denials', () => {
        const v = systemView(); v.latest!.services = { ...v.latest!.services, coverage: 'failed', reason: 'permission_denied', countExact: false, observedCount: null };
        expect(systemCapability(v, 'services', 0).state).toBe('denied');
        expect(systemCapability({ ...v, status: 'stale' }, 'services', 200000).state).toBe('denied');
        expect(systemCapability(v, 'sockets', 0).state).toBe('available');
        v.latest!.services.reason = 'read_failed'; expect(systemCapability(v, 'services', 0).state).toBe('failed');
        v.latest!.services.reason = 'not_supported'; expect(systemCapability(v, 'services', 0).state).toBe('unsupported');
    });
    it('does not claim socket-owner coverage from a successful socket enumeration', () => {
        const got = systemCapability(systemView(), 'sockets', 0);
        expect(got).toEqual({ state: 'available', at: '2026-10-04T00:00:00Z' });
        expect(JSON.stringify(got)).not.toMatch(/owner|complete/);
        const view = systemView();
        expect(socketOwnerCapability(view, 0).state).toBe('unknown');
        view.latest!.socketOwnerProvenance = socketOwnerSource();
        expect(socketOwnerCapability(view, 0).state).toBe('available');
        expect(socketOwnerCapability(view, 120001).state).toBe('stale');
    });
    it('does not warn about normal exited processes or unsupported filesystem capacities', () => {
        const v = overviewView(); const fields = v.processes.complete!.manifest.processes.fieldCoverage;
        fields.observed -= 2; fields.exited = 1; fields.notApplicable = 1;
        expect(overviewCapability(v, 'processes', 0).state).toBe('available');
        fields.observed--; fields.denied = 1;
        expect(overviewCapability(v, 'processes', 0).state).toBe('denied');
        fields.denied = 0; fields.invalid = 1;
        expect(overviewCapability(v, 'processes', 0).state).toBe('partial');
    });
    it('uses capture age, not transfer completion or retained data, for freshness', () => {
        const v = overviewView();
        expect(overviewCapability(v, 'processes', 120001).state).toBe('stale');
        const p = completeView();
        expect(packageCapability(p, 6 * 3600000).state).toBe('available');
        expect(packageCapability(p, 6 * 3600000 + 120001).state).toBe('stale');
        expect(packageCapability(p, Infinity).state).toBe('stale');
    });
    it('keeps a newer failed complete capture visible', () => {
        const v = overviewView(); const c = v.processes.complete!;
        v.processes.failure = { sequence: String(BigInt(c.binding.sequence) + 1n), generationId: 'sample_' + 'b'.repeat(32), attemptedAt: v.serverNow, receivedAt: v.serverNow, reason: 'read_failed' };
        expect(overviewCapability(v, 'processes', 0).state).toBe('failed');
        v.processes.failure.sequence = c.binding.sequence;
        expect(overviewCapability(v, 'processes', 0).state).toBe('available');
        const p = completeView(); p.complete!.binding.sequence = '1';
        p.failure = { sequence: '2', generationId: 'sample_' + 'b'.repeat(32), attemptedAt: p.serverNow, receivedAt: p.serverNow, reason: 'collection_failed' };
        expect(packageCapability(p, 0).state).toBe('failed');
    });
    it('never infers successful log access from manager configuration or policy alone', () => {
        const j = journalView('awaiting'); expect(journalCapability(j, 0).state).toBe('unknown');
        j.localStatus = 'disabled'; expect(journalCapability(j, 0).state).toBe('not_configured');
        j.localStatus = 'denied'; expect(journalCapability(j, 0).state).toBe('denied');
        j.localStatus = 'helper_unavailable'; expect(journalCapability(j, 0).state).toBe('failed');
        j.localStatus = 'unknown'; j.generation = { schemaVersion: 'tracebolt.journal-generation-view.v2', policyEnabled: true, serviceAuthorization: 'all-system-services', allowedUnits: [], policyGeneration: { revision: '1', generation: 'a'.repeat(64), policyDigest: 'sha256:' + 'b'.repeat(64) }, sequence: '1', observedAt: j.serverNow, receivedAt: j.serverNow, expiresAt: '2026-10-04T12:02:00Z', fresh: true };
        expect(journalCapability(j, 0).state).toBe('configured');
        expect(journalCapability(j, 120000).state).toBe('stale');
    });
    it('keeps baseline denied and missing metrics visible without warning about static scope', () => {
        const d = { cpu: { value: null, quality: 'unknown', collectedAt: '2026-10-04T00:00:00Z' } } as Device;
        const c = { id: 'cpu', name: 'CPU', status: 'supported' as const, detail: '' };
        expect(basicCapability(c, d).state).toBe('unknown');
        d.cpu.quality = 'denied'; expect(basicCapability(c, d).state).toBe('denied');
        d.cpu.quality = 'stale'; expect(basicCapability(c, d).state).toBe('stale');
        expect(basicCapability({ ...c, id: 'host_inventory', status: 'limited' }, d).state).toBe('scope');
        expect(basicCapability({ ...c, id: 'host_inventory', status: 'denied' }, d).state).toBe('denied');
    });
});
