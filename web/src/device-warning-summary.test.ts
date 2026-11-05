import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { useHealth } from './health';
import { validHealthView } from './health-types';
import type { HealthIncident, HealthView } from './health-types';
import { WarningSummary } from './device-essentials';

const state = vi.hoisted(() => ({ locale: 'en' as 'en' | 'de' }));
vi.mock('./health', () => ({ useHealth: vi.fn() }));
vi.mock('./i18n', async original => ({ ...await original<typeof import('./i18n')>(), useLocale: () => [state.locale, vi.fn()] as const }));

const id = 'agent_summary_fixture', now = '2026-10-07T20:00:00Z', sessionKey = '2026-10-07T21:00:00Z';
function incident(patch: Partial<HealthIncident> = {}): HealthIncident {
    return { id: 'health_0000000000000001', key: 'service:fixture.service', kind: 'service', target: 'fixture.service', openedAt: now, lastObservedAt: now, resolvedAt: null, acknowledgedAt: null, ...patch };
}
function view(): HealthView {
    return { schemaVersion: 'tracebolt.health-view.v1', deviceId: id, serverNow: now, evaluatedAt: now, status: 'unknown', maintenanceUntil: null, monitoredServices: ['fixture.service'], incidents: [], checks: [
        { key: 'offline:contact', kind: 'offline', target: 'agent', state: 'ok', observedAt: now, value: 0 },
        { key: 'filesystem:root', kind: 'filesystem', target: '/', state: 'unknown', observedAt: null, value: null },
        { key: 'service:fixture.service', kind: 'service', target: 'fixture.service', state: 'unknown', observedAt: null, value: null },
    ] };
}
function draw(value: HealthView | null, pending = false, failure: ReturnType<typeof useHealth>['failure'] = null) {
    if (value) expect(validHealthView(value, id)).toBe(true);
    const before = JSON.stringify(value), refresh = vi.fn(), change = vi.fn();
    vi.mocked(useHealth).mockReturnValue({ view: value, now: Date.parse(now), pending, failure, locked: false, refresh, change });
    const html = renderToStaticMarkup(createElement(WarningSummary, { deviceId: id, sessionKey, onOpen: vi.fn() }));
    expect(JSON.stringify(value)).toBe(before);
    expect(useHealth).toHaveBeenLastCalledWith(id, sessionKey, false);
    expect(refresh).not.toHaveBeenCalled(); expect(change).not.toHaveBeenCalled();
    return html;
}
beforeEach(() => { state.locale = 'en'; vi.mocked(useHealth).mockReset(); });

describe('overview warning counts from the current guarded Health view', () => {
    it.each([null, now])('keeps an unresolved alert visible with unknown evidence, acknowledged at %s', acknowledgedAt => {
        const value = view(); value.incidents = [incident({ acknowledgedAt })];
        const html = draw(value);
        expect(html).toContain('class="device-essential-value caution">1 open</strong>');
        expect(html).toContain('>2 unknown</p>'); expect(html).toContain('>Review checks<');
        expect(html).not.toContain('>0 open<');
    });
    it('deduplicates an open incident and current open check for the same target', () => {
        const value = view(); value.status = 'attention'; value.incidents = [incident()]; value.checks[2].state = 'open'; value.checks[2].observedAt = now;
        const html = draw(value);
        expect(html).toContain('>1 open</strong>'); expect(html).toContain('>1 unknown</p>'); expect(html).not.toContain('>2 open<');
    });
    it('counts distinct unresolved targets beside pending and unknown checks', () => {
        const value = view(); value.status = 'attention'; value.incidents = [incident(), incident({ id: 'health_0000000000000002', key: 'filesystem:root', kind: 'filesystem', target: '/' })]; value.checks[0].state = 'pending';
        const html = draw(value);
        expect(html).toContain('>2 open</strong>'); expect(html).toContain('>1 pending</p>'); expect(html).toContain('>2 unknown</p>');
    });
    it.each(['recovered', 'monitoring_stopped'] as const)('does not count %s episodes as open or infer a healthy current result', closedReason => {
        const value = view(); value.incidents = [incident({ resolvedAt: now, closedReason })];
        const html = draw(value);
        expect(html).toContain('>Unknown</strong>'); expect(html).toContain('>2 unknown</p>'); expect(html).not.toContain('>0 open<'); expect(html).not.toContain('>1 open<');
    });
    it('keeps a saved unresolved incident open until closure even when current checks are clear', () => {
        const value = view(); value.status = 'clear'; value.checks = value.checks.map(check => ({ ...check, state: 'ok', observedAt: now, value: 0 })); value.incidents = [incident()];
        expect(draw(value)).toContain('>1 open</strong>');
        value.incidents[0].resolvedAt = now; value.incidents[0].closedReason = 'recovered';
        expect(draw(value)).toContain('>0 open</strong>');
    });
    it('does not hide open incidents or unknown evidence during maintenance', () => {
        const value = view(); value.status = 'maintenance'; value.maintenanceUntil = '2026-10-07T20:15:00Z'; value.incidents = [incident()];
        const html = draw(value);
        expect(html).toContain('>1 open</strong>'); expect(html).toContain('>2 unknown</p>'); expect(html).toContain('>Maintenance active</p>');
    });
    it('does not retain counts after the guarded view is cleared or unavailable', () => {
        const value = view(); value.incidents = [incident()]; expect(draw(value)).toContain('>1 open</strong>');
        for (const failure of ['session', 'clock', 'load', 'invalid', 'interrupted'] as const) {
            const html = draw(null, false, failure);
            expect(html).toContain('>Unknown</strong>'); expect(html).not.toContain('>1 open<'); expect(html).not.toContain('>0 open<'); expect(html).not.toContain('>2 unknown<');
        }
        expect(draw(null, true)).toContain('>Checking…</strong>');
    });
    it('renders the same open-plus-unknown distinction in German', () => {
        state.locale = 'de'; const value = view(); value.incidents = [incident()];
        const html = draw(value);
        expect(html).toContain('>1 offen</strong>'); expect(html).toContain('>2 unbekannt</p>'); expect(html).toContain('>Prüfungen öffnen<'); expect(html).not.toContain('>0 offen<');
    });
});
