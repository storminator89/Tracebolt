import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { HealthDashboard, healthDashboardState, healthMetric } from './health-dashboard';
import { setLocale } from './i18n';
import type { Device, Metric } from './types';
import type { HealthView } from './health-types';
const at = '2026-10-07T20:00:00Z', id = 'agent_dashboard_fixture';
const metric: Metric = { value: 31.2, unit: '%', quality: 'healthy', source: 'Invented test reading', collectedAt: at };
function view(): HealthView { return { schemaVersion: 'tracebolt.health-view.v1', deviceId: id, serverNow: at, evaluatedAt: at, status: 'clear', maintenanceUntil: null, monitoredServices: [], checks: [{ key: 'offline:contact', kind: 'offline', target: 'agent', state: 'ok', observedAt: at, value: null }, { key: 'filesystem:root', kind: 'filesystem', target: '/', state: 'ok', observedAt: at, value: 14.2 }], incidents: [] }; }
function device(): Device { return { id, source: 'lan', synthetic: false, platform: 'linux', name: 'Invented endpoint', os: 'Linux', site: '', group: '', ip: null, status: 'unknown', lastSeen: at, agentVersion: 'fixture', cpu: { ...metric, value: 99.9 }, memory: metric, disk: metric, uptime: '', tags: [], capabilities: [], evidence: [], trend: [], caseIds: [] }; }
function draw(v = view(), d: Device | null = device()) { const handlers = { onSettings: vi.fn(), onEvidence: vi.fn(), onAcknowledge: vi.fn(), onOpenLogs: vi.fn() }; return { ...render(<HealthDashboard view={v} now={Date.parse(v.serverNow)} device={d ?? undefined} disabled={false} {...handlers}/>), ...handlers }; }
beforeEach(() => { setLocale('en', false); });
afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); });
describe('one-glance health facts', () => {
    it('uses current CPU and memory readings without inventing CPU alert rules or an overall score', () => {
        draw(); const cards = screen.getByRole('list', { name: 'Current checks' }); expect(cards).toHaveTextContent('99.9%'); expect(cards).toHaveTextContent('31.2%'); expect(cards).toHaveTextContent('14.2%');
        expect(screen.getByText('Monitored checks clear')).toBeVisible(); expect(screen.getByText('Selected checks only')).toBeVisible(); expect(screen.getByText('No service checks selected')).toBeVisible(); expect(document.body).not.toHaveTextContent(/health score|Device is healthy|100% healthy/i);
        expect(screen.getByText(/no alert rules are configured/)).toBeVisible();
    });
    it('does not turn missing metadata or zero selected services into green readings', () => {
        draw(view(), null); expect(screen.getAllByText('No reading')).toHaveLength(2); expect(screen.getByText('No service checks selected').closest('li')).toHaveClass('health-reading-unknown');
    });
    it.each(['other-device', 'synthetic', 'non-lan', 'non-linux'])('rejects resource values outside the visible device scope: %s', kind => {
        const d = device(); if (kind === 'other-device') d.id = 'agent_other'; if (kind === 'synthetic') d.synthetic = true; if (kind === 'non-lan') d.source = 'local'; if (kind === 'non-linux') d.platform = 'windows'; draw(view(), d); expect(screen.getAllByText('No reading')).toHaveLength(2); expect(document.body).not.toHaveTextContent('99.9');
    });
    it('prioritizes retained open alerts even when the latest evidence is unknown', () => {
        const v = view(); v.status = 'unknown'; v.checks[1].state = 'unknown'; v.checks[1].value = null; v.incidents = [{ id: 'health_0000000000000001', key: 'filesystem:root', kind: 'filesystem', target: '/', openedAt: at, lastObservedAt: at, resolvedAt: null, acknowledgedAt: null }];
        const handlers = draw(v); expect(screen.getByText('Needs attention')).toBeVisible(); expect(screen.getByRole('region', { name: 'Current issues' })).toHaveTextContent('Alert open · Current state unknown'); expect(document.querySelector('[data-health-state]')).toHaveAttribute('data-health-state', 'attention'); fireEvent.click(screen.getByRole('button', { name: 'Show evidence' })); expect(handlers.onEvidence).toHaveBeenCalledOnce();
    });
    it('distinguishes first evaluation from clear or unavailable', () => {
        const v = view(); v.evaluatedAt = null; v.status = 'unknown'; v.checks.forEach(check => { check.state = 'unknown'; check.value = null; check.observedAt = null; }); draw(v); expect(screen.getByText('Waiting for the first health evaluation')).toBeVisible(); expect(screen.queryByText('Monitored checks clear')).not.toBeInTheDocument();
    });
    it('does not conceal open alerts during maintenance', () => {
        const v = view(); v.status = 'maintenance'; v.maintenanceUntil = '2026-10-07T20:15:00Z'; v.checks[1].state = 'open'; v.checks[1].value = 95; v.incidents = [{ id: 'health_0000000000000001', key: 'filesystem:root', kind: 'filesystem', target: '/', openedAt: at, lastObservedAt: at, resolvedAt: null, acknowledgedAt: null }]; draw(v); expect(screen.getByText('Maintenance active')).toBeVisible(); expect(screen.getByRole('region', { name: 'Current issues' })).toHaveTextContent('Review disk usage'); expect(screen.getByRole('button', { name: 'Acknowledge alert: Root disk /' })).toBeVisible();
    });
    it('offers scoped service logs and selection without executing repairs', () => {
        const v = view(); v.status = 'attention'; v.monitoredServices = ['fixture.service']; v.checks.push({ key: 'service:fixture.service', kind: 'service', target: 'fixture.service', state: 'pending', observedAt: at, value: null }); const handlers = draw(v);
        fireEvent.click(screen.getByRole('button', { name: 'Open logs: fixture.service' })); expect(handlers.onOpenLogs).toHaveBeenCalledWith('fixture.service'); fireEvent.click(screen.getByRole('button', { name: 'Choose services' })); expect(handlers.onSettings).toHaveBeenCalledOnce(); expect(handlers.onAcknowledge).not.toHaveBeenCalled();
    });
    it('localizes the primary dashboard and decimal measurements in German', () => {
        setLocale('de', false); draw(); expect(screen.getByText('Überwachte Prüfungen unauffällig')).toBeVisible(); expect(screen.getByRole('list', { name: 'Aktuelle Prüfungen' })).toHaveTextContent('31,2%'); expect(screen.getByRole('button', { name: 'Dienste auswählen' })).toBeVisible();
    });
    it('uses the authoritative parent clock instead of inventing a mount-time anchor', () => {
        const d = device(); d.cpu.collectedAt = '2026-10-07T19:58:01Z';
        const v = view(), handlers = { onSettings: vi.fn(), onEvidence: vi.fn(), onAcknowledge: vi.fn() };
        const rendered = render(<HealthDashboard view={v} now={Date.parse(at)} device={d} disabled={false} {...handlers}/>);
        expect(screen.getByText('99.9')).toBeVisible();
        rendered.rerender(<HealthDashboard view={v} now={Date.parse(at) + 2000} device={d} disabled={false} {...handlers}/>);
        expect(screen.queryByText('99.9')).not.toBeInTheDocument(); expect(screen.getByText('Stale reading')).toBeVisible();
    });
    it('withholds denied, malformed, future, nonpercentage and old readings', () => {
        const now = Date.parse(at); for (const change of [{ quality: 'denied' as const }, { quality: 'unknown' as const }, { value: Infinity }, { value: -1 }, { value: 101 }, { unit: 'bytes' }, { collectedAt: 'not-a-time' }, { collectedAt: '2026-10-07T20:00:01Z' }, { collectedAt: '2026-10-07T19:57:00Z' }]) expect(healthMetric({ ...metric, ...change }, now).value).toBeNull(); expect(healthMetric({ ...metric, value: 0 }, now).value).toBe(0);
    });
    it('never upgrades unknown checks to a clear scoped summary', () => {
        const v = view(); v.checks[1].state = 'unknown'; v.checks[1].value = null; expect(healthDashboardState(v).state).toBe('unknown');
    });
});
