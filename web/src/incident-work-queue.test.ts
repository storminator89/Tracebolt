import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import legacyWire from '../../tests/fixtures/windows-incident-inbox-view.json';
import { ageInvestigations } from './investigations-types';
import type { InvestigationsView } from './investigations-types';
import { completeIncidentFixture } from './windows-complete-incident-inbox-fixture';
import { windowsInboxSourceStatus } from './windows-complete-incident-inbox-types';
import type { WindowsInboxView } from './windows-complete-incident-inbox-types';
import { WindowsIncidentReadOnlyRow } from './windows-incident-inbox';
import { IncidentWorkQueue } from './incident-work-queue';
import type { InvestigationsResource } from './investigations-resource';
import { filterIncidentQueue, incidentQueueRows, queueSourceScopes } from './incident-work-queue-model';

const now = legacyWire.active.serverNow, id = 'agent_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
function linuxFixture(): InvestigationsView {
    return {
        schemaVersion: 'tracebolt.investigations.v1', serverNow: now, scope: 'all', offset: 0, total: 1, counts: { open: 1, recovered: 0, closed: 0, all: 1 },
        devices: [{ schemaVersion: 'tracebolt.health-view.v1', deviceId: id, serverNow: now, evaluatedAt: now, status: 'attention', maintenanceUntil: null, monitoredServices: [], incidents: [], checks: [{ key: 'offline:contact', kind: 'offline', target: 'agent', state: 'ok', observedAt: now, value: null }, { key: 'filesystem:root', kind: 'filesystem', target: '/', state: 'open', observedAt: now, value: 95 }] }],
        items: [{ deviceId: id, incident: { id: 'health_0000000000000001', key: 'filesystem:root', kind: 'filesystem', target: '/', openedAt: '2026-10-07T12:01:00Z', lastObservedAt: now, acknowledgedAt: null, resolvedAt: null } }],
    };
}
const legacy = () => structuredClone(legacyWire.active) as WindowsInboxView;

// Source fixtures establish contracts only, not native collection or acceptance.
describe('federated incident queue contracts', () => {
    it('maps only exact shared lifecycle scopes and preserves distinct source identities and totals', () => {
        expect(queueSourceScopes('active')).toEqual({ linux: 'open', windows: 'active' });
        expect(queueSourceScopes('all')).toEqual({ linux: 'all', windows: 'all' });
        const linux = linuxFixture(), windows = legacy(), before = JSON.stringify({ linux, windows });
        const rows = incidentQueueRows(linux, windows);
        expect(rows).toHaveLength(6); expect(new Set(rows.map(row => row.identity)).size).toBe(6);
        const capacities = rows.filter(row => row.platform === 'windows' && row.item.incidentId === 'wcapacity_0000000000000001');
        expect(capacities).toHaveLength(3); expect(new Set(capacities.map(row => row.identity)).size).toBe(3);
        expect(rows.map(row => Date.parse(row.openedAt))).toEqual(rows.map(row => Date.parse(row.openedAt)).sort((a, b) => b - a));
        expect(incidentQueueRows(linux, windows).map(row => row.identity)).toEqual(rows.map(row => row.identity));
        expect(JSON.stringify({ linux, windows })).toBe(before);
    });
    it('filters loaded pages without merging complete-service and assessment sources or changing source counts', () => {
        const linux = linuxFixture(), windows = legacy(), full = completeIncidentFixture('active', now);
        const rows = [...incidentQueueRows(linux, windows), ...incidentQueueRows(null, full)];
        expect(filterIncidentQueue(rows, 'linux', 'all', 'all')).toHaveLength(1);
        expect(filterIncidentQueue(rows, 'all', 'windows-full-services', 'all')).toHaveLength(1);
        expect(filterIncidentQueue(rows, 'windows', 'windows-assessment', 'seen')).toHaveLength(1);
        expect(filterIncidentQueue(rows, 'linux', 'windows-full-services', 'all')).toEqual([]);
        expect(filterIncidentQueue(rows, 'all', 'all', 'unseen').every(row => row.seenAt === null)).toBe(true);
        expect(windows.counts.total).toBe(5); expect(full.counts.total).toBe(1);
    });
    it('keeps partial sources and seen incidents without inventing recovery after evidence expires', () => {
        const linux = linuxFixture(), windows = completeIncidentFixture('active', now);
        expect(incidentQueueRows(linux, null)).toHaveLength(1); expect(incidentQueueRows(null, windows)).toHaveLength(1); expect(incidentQueueRows(null, null)).toEqual([]);
        linux.items[0].incident.acknowledgedAt = now;
        const aged = ageInvestigations(linux, 121000);
        expect(aged.devices[0].checks.every(check => check.state === 'unknown')).toBe(true);
        expect(incidentQueueRows(aged, null)[0].item).toEqual(linux.items[0]); expect(linux.items[0].incident.resolvedAt).toBeNull();
        expect(windowsInboxSourceStatus(windows.items[0], now, 121000)).toBe('unknown'); expect(windows.items[0].resolvedAt).toBeNull();
    });
    it('server-renders provenance and verified Health links without forms, review, acknowledgement or injected content', () => {
        const view = completeIncidentFixture('active', now), item = view.items[0], before = JSON.stringify(item);
        const html = renderToStaticMarkup(createElement(WindowsIncidentReadOnlyRow, { item, name: '<script>fake name</script>', serverNow: now, age: 0 }));
        expect(html).toContain('<article class="windows-incident-row">'); expect(html).toContain(`href="#/devices/${encodeURIComponent(item.deviceId)}/health"`);
        expect(html).toContain(item.openingSource!.generationId); expect(html).toContain('Last incident confirmation'); expect(html).toContain('&lt;script&gt;fake name&lt;/script&gt;');
        expect(html).not.toMatch(/<button|<form|<script|Mark seen|Review service/); expect(JSON.stringify(item)).toBe(before);
    });
    it('keeps seen separate from active and policy closure while current confidence ages to unknown', () => {
        const item = completeIncidentFixture('active', now).items[0]; item.acknowledgedAt = now;
        const render = () => renderToStaticMarkup(createElement(WindowsIncidentReadOnlyRow, { item, name: 'Device', serverNow: now, age: 121000 }));
        const active = render(); expect(active).toContain('Source status: Unknown'); expect(active).toContain('>Active<'); expect(active).toContain('>Seen<');
        item.resolvedAt = now; item.closedReason = 'policy-changed';
        expect(render()).toContain('Closed: policy changed; no recovery established'); expect(render()).not.toContain('>Recovered<');
    });
    it('labels page-local filters and missing coverage without zero-count or whole-fleet success claims', () => {
        const linux: InvestigationsResource = { view: null, counts: null, readiness: 'unknown', pending: false, failure: null, locked: false, refresh: () => {} };
        const html = renderToStaticMarkup(createElement(IncidentWorkQueue, { devices: [], sessionKey: null, linux, scope: 'active', onScope: () => {}, linuxOffset: 0, onLinuxPage: () => {} }));
        for (const label of ['Platform on loaded pages', 'Source on loaded pages', 'Seen on loaded pages', 'Each source has its own live page and total.', 'Source coverage is incomplete.', 'No current Linux investigation data.', 'No current Windows incident data.', 'Missing source rows and totals remain unknown.']) expect(html).toContain(label);
        expect(html).not.toMatch(/0 retained|0 authorized devices|Mark seen|Review service/);
    });
});
