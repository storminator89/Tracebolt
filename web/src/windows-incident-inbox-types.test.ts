import { describe, expect, it } from 'vitest';
import wire from '../../tests/fixtures/windows-incident-inbox-view.json';
import { windowsNow } from './windows-inventory-fixture';
import { windowsIncidentItem, windowsIncidentView } from './windows-incident-inbox-fixture';
import { validWindowsIncidentAcknowledgement, validWindowsIncidentInboxView, validWindowsIncidentQuery, windowsIncidentSourceStatus } from './windows-incident-inbox-types';
import type { WindowsIncidentScope } from './windows-incident-inbox-types';

describe('Windows incident inbox closed projection', () => {
    it('accepts deterministic actual Go projections for all five domains and separate policy closure', () => {
        expect(validWindowsIncidentInboxView(wire.active, 'active', 'all', 0)).toBe(true);
        expect(validWindowsIncidentInboxView(wire.resolved, 'resolved', 'all', 0)).toBe(true);
        expect(new Set(wire.active.items.map(item => item.domain))).toEqual(new Set(['contact', 'disk', 'cpu', 'memory', 'service']));
        expect(wire.active.items.find(item => item.domain === 'cpu')?.acknowledgedAt).not.toBeNull();
        expect(wire.active.items.every(item => item.resolvedAt === null)).toBe(true);
        expect(wire.resolved.items[0].closedReason).toBe('policy-changed');
        expect(wire.resolved.items[0].recoveryCollectedAt).toBeNull();
    });
    it('keeps acknowledgement independent of open/closed lifecycle', () => {
        const seenOpen = windowsIncidentItem({ acknowledgedAt: windowsNow });
        const closedUnseen = windowsIncidentItem({ resolvedAt: '2026-10-07T11:58:00Z', closedReason: 'policy-changed' });
        expect(validWindowsIncidentInboxView(windowsIncidentView([seenOpen], 'active', 'acknowledged'), 'active', 'acknowledged', 0)).toBe(true);
        expect(validWindowsIncidentInboxView(windowsIncidentView([closedUnseen], 'resolved', 'unacknowledged'), 'resolved', 'unacknowledged', 0)).toBe(true);
    });
    it.each(['active', 'recent', 'resolved', 'all'] as const)('binds the exact requested %s scope, acknowledgement and page', scope => {
        const view = windowsIncidentView([], scope);
        expect(validWindowsIncidentInboxView(view, scope, 'all', 0)).toBe(true);
        expect(validWindowsIncidentInboxView(view, (scope === 'active' ? 'all' : 'active') as WindowsIncidentScope, 'all', 0)).toBe(false);
        expect(validWindowsIncidentInboxView(view, scope, 'acknowledged', 0)).toBe(false);
        expect(validWindowsIncidentInboxView(view, scope, 'all', 25)).toBe(false);
    });
    it('rejects unknown fields, bad domains, cross-domain closure and malformed paging/counts', () => {
        const view = windowsIncidentView();
        const invalid: unknown[] = [
            { ...view, privateIdentity: 'not allowed' }, { ...view, counts: { ...view.counts, active: 5 } }, { ...view, nextOffset: 25 }, { ...view, total: 2 },
            { ...view, items: [{ ...view.items[0], secret: 'not allowed' }] }, { ...view, items: [{ ...view.items[0], key: 'uppercase'.repeat(8) }] },
            { ...view, items: [{ ...view.items[0], domain: 'linux' }] }, { ...view, items: [{ ...view.items[0], serviceName: 'UnexpectedService' }] },
            { ...view, items: [{ ...view.items[0], resolvedAt: null, closedReason: 'within-policy' }] }, { ...view, items: [{ ...view.items[0], acknowledgedAt: '2099-01-01T00:00:00Z' }] },
        ];
        for (const value of invalid) expect(validWindowsIncidentInboxView(value, 'active', 'all', 0)).toBe(false);
        expect(validWindowsIncidentQuery('active', 'all', 12500, 50)).toBe(true);
        expect(validWindowsIncidentQuery('active', 'all', 12501, 50)).toBe(false);
        expect(validWindowsIncidentQuery('active', 'all', 0, 51)).toBe(false);
    });
    it('accepts source-native recovery reasons and never invents a contact capture', () => {
        const contact = windowsIncidentItem({ domain: 'contact', incidentId: 'wcontact_0000000000000001', collectedAt: null, status: 'recent', resolvedAt: '2026-10-07T11:58:00Z', closedReason: 'reports-resumed', recoveryReceivedAt: '2026-10-07T11:57:30Z' });
        const service = windowsIncidentItem({ domain: 'service', incidentId: 'wservice_0000000000000001', serviceName: 'FixtureService', status: 'running', resolvedAt: '2026-10-07T11:58:00Z', closedReason: 'running', recoveryCollectedAt: '2026-10-07T11:57:20Z', recoveryReceivedAt: '2026-10-07T11:57:30Z' });
        for (const row of [contact, service]) expect(validWindowsIncidentInboxView(windowsIncidentView([row], 'resolved'), 'resolved', 'all', 0)).toBe(true);
        expect(validWindowsIncidentInboxView(windowsIncidentView([{ ...contact, collectedAt: contact.receivedAt }], 'resolved'), 'resolved', 'all', 0)).toBe(false);
    });
    it('accepts unknown current source alongside retained open incidents', () => {
        expect(validWindowsIncidentInboxView(windowsIncidentView([windowsIncidentItem({ status: 'unknown', evaluatedAt: null, statusValidUntil: null })]), 'active', 'all', 0)).toBe(true);
    });
    it('uses the current-source confidence deadline rather than historical last-bad capture or GET receipt', () => {
        const item = windowsIncidentItem({ statusValidUntil: new Date(Date.parse(windowsNow) + 1000).toISOString() });
        expect(validWindowsIncidentInboxView(windowsIncidentView([item]), 'active', 'all', 0)).toBe(true);
        expect(windowsIncidentSourceStatus(item, windowsNow, 999)).toBe('pressure');
        expect(windowsIncidentSourceStatus(item, windowsNow, 1000)).toBe('unknown');
        expect(windowsIncidentSourceStatus(item, windowsNow, Infinity)).toBe('unknown');
        const boundary = { ...item, statusValidUntil: windowsNow };
        expect(validWindowsIncidentInboxView(windowsIncidentView([boundary]), 'active', 'all', 0)).toBe(true);
        expect(windowsIncidentSourceStatus(boundary, windowsNow, 0)).toBe('unknown');
        expect(validWindowsIncidentInboxView(windowsIncidentView([{ ...item, statusValidUntil: null }]), 'active', 'all', 0)).toBe(false);
        expect(validWindowsIncidentInboxView(windowsIncidentView([{ ...item, status: 'unknown' }]), 'active', 'all', 0)).toBe(false);
    });
    it('rejects a recent response containing only an old untouched episode', () => {
        const row = windowsIncidentItem({ openedAt: '2026-09-01T11:55:00Z', lastConfirmedAt: '2026-09-01T11:57:00Z', collectedAt: '2026-09-01T11:56:00Z', receivedAt: '2026-09-01T11:56:01Z' });
        const view = { ...windowsIncidentView([row]), scope: 'recent' };
        expect(validWindowsIncidentInboxView(view, 'recent', 'all', 0)).toBe(false);
    });
    it('checks exact acknowledgement key, shape and server time without resolving the episode', () => {
        const key = '1'.repeat(64), value = { schemaVersion: 'tracebolt.windows-incident-ack.v1', serverNow: windowsNow, key, acknowledgedAt: windowsNow };
        expect(validWindowsIncidentAcknowledgement(value, key)).toBe(true);
        expect(validWindowsIncidentAcknowledgement(value, '2'.repeat(64))).toBe(false);
        expect(validWindowsIncidentAcknowledgement({ ...value, resolvedAt: windowsNow }, key)).toBe(false);
    });
});
