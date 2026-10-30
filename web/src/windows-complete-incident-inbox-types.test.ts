import { describe, expect, it } from 'vitest';
import wire from './windows-complete-incident-go-fixture.json';
import { fullServicesGenerationId } from './windows-full-services-types';
import legacyWire from '../../tests/fixtures/windows-incident-inbox-view.json';
import { completeIncidentFixture } from './windows-complete-incident-inbox-fixture';
import { validWindowsCompleteIncidentAcknowledgement, validWindowsCompleteIncidentInboxView, windowsInboxSourceStatus } from './windows-complete-incident-inbox-types';
import { validWindowsIncidentAcknowledgement, validWindowsIncidentInboxView } from './windows-incident-inbox-types';
const valid = (value: unknown) => validWindowsCompleteIncidentInboxView(value, 'active', 'all', 0);
const full = () => structuredClone(wire.active);

describe('complete-service incident inbox strict v2 projection', () => {
    it('accepts actual Go active, acknowledged and source-loss projections', () => {
        for (const view of Object.values(wire)) expect(valid(view)).toBe(true);
        expect(wire.active.items[0].key).toBe(wire.acknowledged.items[0].key);
        expect(wire.acknowledged.items[0].resolvedAt).toBeNull();
        expect(wire.unknown.items[0].openingSource).toEqual(wire.active.items[0].openingSource);
        expect(wire.unknown.items[0].currentSource).toBeNull();
        expect(wire.active.items[0].serviceName.length).toBe(100);
        expect(new TextEncoder().encode(wire.active.items[0].serviceName).length).toBeGreaterThan(256);
        expect(valid(completeIncidentFixture('active', '2027-01-01T12:00:00Z'))).toBe(true);
    });
    it('preserves exact old five-family rows and keys only under explicit legacy tagging', () => {
        const legacy = { ...structuredClone(legacyWire.active), schemaVersion: 'tracebolt.windows-incident-inbox.v2', items: legacyWire.active.items.map(item => ({ ...item, sourceKind: 'assessment_v1', openingSource: null, lastBadSource: null, recoverySource: null, currentSource: null })) };
        expect(valid(legacy)).toBe(true); expect(legacy.items.map(item => item.key)).toEqual(legacyWire.active.items.map(item => item.key));
        expect(validWindowsIncidentInboxView(legacy, 'active', 'all', 0)).toBe(false);
        expect(valid(legacyWire.active)).toBe(false);
        expect(validWindowsIncidentInboxView(legacyWire.active, 'active', 'all', 0)).toBe(true);
        const confused = { ...legacy, items: legacy.items.map(item => ({ ...item, currentSource: wire.active.items[0].currentSource })) }; expect(valid(confused)).toBe(false);
    });
    it.each(['sourceKind', 'openingSource', 'lastBadSource', 'currentSource', 'recoverySource'])('requires exact explicit %s', field => {
        const v = full(); delete (v.items[0] as Record<string, unknown>)[field]; expect(valid(v)).toBe(false);
    });
    it.each([
        { sourceKind: 'assessment_v1' }, { domain: 'service' }, { openingSource: null }, { lastBadSource: null }, { currentSource: null },
        { serviceName: '\u0000' }, { serviceName: 'x'.repeat(257) }, { serviceName: '\ud800' }, { status: 'pressure' }, { closedReason: 'within-policy' }, { extra: true },
    ])('rejects mismatched complete row shape %j', patch => { const v = full(); Object.assign(v.items[0], patch); expect(valid(v)).toBe(false); });
    it.each(['openingSource', 'lastBadSource', 'currentSource'] as const)('validates canonical %s and original device generation binding', field => {
        for (const patch of [{ grantRevision: 0 }, { kind: 'assessment_v1' }, { generationId: 'sample_' + 'c'.repeat(32) }, { sequence: 0 }, { rowCount: 8193 }, { manifestSha256: 'invalid' }, { extra: true }]) {
            const v = full(); Object.assign(v.items[0][field], patch); expect(valid(v)).toBe(false);
        }
    });
    it('rejects historical timestamp mismatch and unqualified source promotion', () => {
        const mismatch = full(); mismatch.items[0].collectedAt = '2026-10-13T00:00:00Z'; expect(valid(mismatch)).toBe(false);
        const unknown = structuredClone(wire.unknown); Object.assign(unknown.items[0], { currentSource: wire.active.items[0].currentSource }); expect(valid(unknown)).toBe(false);
        const expired = full(); expired.items[0].statusValidUntil = expired.serverNow; expect(valid(expired)).toBe(false);
        const extra = full(); Object.assign(extra, { control: true }); expect(valid(extra)).toBe(false);
    });
    it('bounds confidence by evaluator and both five-minute current-source ages only', () => {
        const v = full(), row = v.items[0], now = Date.parse(v.serverNow);
        const at = (delta: number) => new Date(now + delta).toISOString();
        for (const source of [row.openingSource, row.lastBadSource]) { source.capturedAt = at(-1000000); source.captureFinishedAt = at(-1000000); source.receivedAt = at(-1000000); source.expiresAt = at(-1000000 + 86400000); }
        row.openedAt = at(-999000); row.lastConfirmedAt = at(-999000); row.collectedAt = at(-1000000); row.receivedAt = at(-1000000);
        row.currentSource.capturedAt = at(-299000); row.currentSource.captureFinishedAt = at(-299000); row.currentSource.receivedAt = at(-299000); row.currentSource.expiresAt = at(-299000 + 86400000);
        row.statusValidUntil = at(1000); expect(valid(v)).toBe(true);
        expect(windowsInboxSourceStatus(completeIncidentFixture().items[0], v.serverNow, 120000)).toBe('unknown');
        row.statusValidUntil = at(1001); expect(valid(v)).toBe(false);
        row.statusValidUntil = at(1000); row.evaluatedAt = at(-120001); expect(valid(v)).toBe(false);
    });
    it('retains old source history after current source loss without reviving confidence', () => {
        const v = completeIncidentFixture('unknown'), row = v.items[0];
        v.serverNow = new Date(Date.parse(v.serverNow) + 10 * 86400000).toISOString(); v.authorityExpiresAt = new Date(Date.parse(v.serverNow) + 120000).toISOString();
        expect(valid(v)).toBe(true); expect(windowsInboxSourceStatus(row, v.serverNow, 0)).toBe('unknown');
        expect(windowsInboxSourceStatus(row, v.serverNow, -1)).toBe('unknown'); expect(windowsInboxSourceStatus(row, v.serverNow, Infinity)).toBe('unknown');
    });
    it('rejects mixed historical grants and current grant transfer on an open episode', () => {
        for (const field of ['lastBadSource', 'currentSource'] as const) {
            const v = full(), source = v.items[0][field]; source.grantId = 'c'.repeat(32); source.generationId = fullServicesGenerationId(v.items[0].deviceId, source.grantId, source.sequence);
            expect(valid(v)).toBe(false);
        }
        const closed = full(); Object.assign(closed.items[0], { resolvedAt: closed.serverNow, closedReason: 'policy-changed' }); const current = closed.items[0].currentSource;
        current.grantId = 'c'.repeat(32); current.generationId = fullServicesGenerationId(closed.items[0].deviceId, current.grantId, current.sequence);
        closed.scope = 'all'; expect(validWindowsCompleteIncidentInboxView(closed, 'all', 'all', 0)).toBe(true);
    });
    it('requires exact v2 acknowledgement schema, target and timestamp', () => {
        const ack = { schemaVersion: 'tracebolt.windows-incident-ack.v2', serverNow: wire.acknowledged.serverNow, key: wire.acknowledged.items[0].key, acknowledgedAt: wire.acknowledged.items[0].acknowledgedAt };
        expect(validWindowsCompleteIncidentAcknowledgement(ack, ack.key)).toBe(true);
        expect(validWindowsIncidentAcknowledgement(ack, ack.key)).toBe(false);
        for (const patch of [{ schemaVersion: 'tracebolt.windows-incident-ack.v1' }, { key: 'a'.repeat(64) }, { acknowledgedAt: null }, { extra: true }]) expect(validWindowsCompleteIncidentAcknowledgement({ ...ack, ...patch }, ack.key)).toBe(false);
    });
});
