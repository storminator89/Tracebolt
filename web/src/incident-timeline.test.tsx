import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import legacyWire from '../../tests/fixtures/windows-incident-inbox-view.json';
import healthWire from './health-go-fixture.json';
import { ageInvestigations, validInvestigationsView } from './investigations-types';
import type { InvestigationsView } from './investigations-types';
import type { InvestigationsResource } from './investigations-resource';
import type { HealthView } from './health-types';
import type { Device } from './types';
import { completeIncidentFixture } from './windows-complete-incident-inbox-fixture';
import { validWindowsIncidentInboxView, validWindowsIncidentItem } from './windows-incident-inbox-types';
import { validWindowsCompleteIncidentInboxView } from './windows-complete-incident-inbox-types';
import type { WindowsInboxView } from './windows-complete-incident-inbox-types';
import { fullServicesGenerationId } from './windows-full-services-types';
import { incidentTimeline, incidentLifecycle } from './incident-timeline-model';
import { IncidentTimeline } from './incident-timeline';
import { IncidentWorkQueue } from './incident-work-queue';
import { filterIncidentQueue, incidentQueueRows, incidentQueueLifecycleCounts, QUEUE_SEARCH_LIMIT } from './incident-work-queue-model';
import type { QueueRow } from './incident-work-queue-model';
import { setLocale } from './i18n';
import { useWindowsIncidentInbox } from './windows-incident-inbox-resource';
import { mutate, request } from './api';

vi.mock('./windows-incident-inbox-resource', () => ({ useWindowsIncidentInbox: vi.fn() }));
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), mutate: vi.fn(), request: vi.fn() }));
const now = legacyWire.active.serverNow;
const id = healthWire.deviceId;
function linuxFixture(): InvestigationsView {
    const health = structuredClone(healthWire) as HealthView;
    const value: InvestigationsView = { schemaVersion: 'tracebolt.investigations.v1', serverNow: health.serverNow, scope: 'all', offset: 0, total: health.incidents.length, counts: { open: health.incidents.length, recovered: 0, closed: 0, all: health.incidents.length }, items: health.incidents.map(incident => ({ deviceId: id, incident })), devices: [{ ...health, incidents: [] }] };
    if (!validInvestigationsView(value, 'all', 0)) throw new Error('Invalid Linux source fixture');
    return value;
}
function legacy(scene: 'active' | 'resolved' = 'active'): WindowsInboxView {
    const value = structuredClone(legacyWire[scene]);
    if (!validWindowsIncidentInboxView(value, scene, 'all', 0)) throw new Error('Invalid Windows source fixture');
    return value;
}
function linuxRow(view = linuxFixture()): Extract<QueueRow, { platform: 'linux' }> { return incidentQueueRows(view, null)[0] as Extract<QueueRow, { platform: 'linux' }>; }
function windowsRow(view = legacy(), domain?: string): Extract<QueueRow, { platform: 'windows' }> { return incidentQueueRows(null, view).find(row => row.platform === 'windows' && (!domain || row.item.domain === domain)) as Extract<QueueRow, { platform: 'windows' }>; }
function resource(view: InvestigationsView | null): InvestigationsResource { return { view, counts: view?.counts ?? null, readiness: 'unknown', pending: false, failure: null, locked: false, refresh: vi.fn() }; }
let windows: ReturnType<typeof useWindowsIncidentInbox>;
beforeEach(() => {
    setLocale('en', false);
    windows = { view: legacy(), age: 0, loading: false, writing: false, error: false, notice: null, refresh: vi.fn(), acknowledge: vi.fn(), isUncertain: () => false };
    vi.mocked(useWindowsIncidentInbox).mockImplementation(() => windows);
    vi.mocked(request).mockReset(); vi.mocked(mutate).mockReset();
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

describe('exact incident timeline projection', () => {
    it('retains delayed Linux evidence before opening without inventing raw opening/recovery samples', () => {
        const view = linuxFixture(), row = linuxRow(view), before = JSON.stringify(view);
        const model = incidentTimeline(row, view, null, 0);
        expect(Date.parse(row.item.incident.lastObservedAt)).toBeLessThan(Date.parse(row.openedAt));
        expect(model.episode.map(event => event.kind)).toEqual(['last-observed', 'opened']);
        expect(model.episode[0].at).toBe(row.item.incident.lastObservedAt);
        expect(model.current.observedAt).toBe(view.devices[0].checks.find(check => check.key === row.item.incident.key)!.observedAt);
        expect(model.sources).toEqual([]); expect(model.logsHref).toBeNull(); expect(JSON.stringify(view)).toBe(before);
    });
    it('keeps a Linux contact manager evaluation distinct from its current accepted-report receipt', () => {
        const view = linuxFixture(), row = linuxRow(view), receipt = '2026-10-04T23:59:00Z';
        row.item.incident = { ...row.item.incident, key: 'offline:contact', kind: 'offline', target: 'agent', openedAt: '2026-10-05T00:02:00Z', lastObservedAt: '2026-10-05T00:02:30Z' };
        view.devices[0].checks[0] = { ...view.devices[0].checks[0], state: 'open', observedAt: receipt };
        const model = incidentTimeline(row, view, null, 0);
        expect(model.contact).toBe('linux'); expect(model.episode.find(event => event.kind === 'linux-contact-evaluated')?.at).toBe(row.item.incident.lastObservedAt); expect(model.current.observedAt).toBe(receipt);
        render(<IncidentTimeline model={model} platform="linux"/>);
        expect(screen.getByText('Last retained contact evaluation by manager')).toBeInTheDocument();
        expect(screen.getByText('Original current accepted-report receipt')).toBeInTheDocument();
        expect(screen.getByText(/Linux contact history records manager evaluation times/)).toBeInTheDocument();
        expect(screen.queryByText('Last-bad evidence captured')).not.toBeInTheDocument();
    });
    it('never promotes seen, stale, missing or a later current check into episode recovery', () => {
        const view = linuxFixture(), row = linuxRow(view); row.item.incident.acknowledgedAt = view.serverNow;
        expect(incidentTimeline(row, view, null, 0).lifecycle).toBe('open');
        const aged = ageInvestigations(view, 121000); expect(incidentTimeline(row, aged, null, 0).current.state).toBe('unknown');
        row.item.incident.resolvedAt = view.serverNow; row.item.incident.closedReason = 'monitoring_stopped';
        view.devices[0].checks.find(check => check.key === row.item.incident.key)!.state = 'ok';
        expect(incidentTimeline(row, view, null, 0).lifecycle).toBe('stopped');
        expect(incidentTimeline(row, view, null, 0).episode.some(event => event.kind === 'recovered')).toBe(false);
        row.item.incident.closedReason = 'recovered'; view.devices[0].checks.find(check => check.key === row.item.incident.key)!.state = 'open';
        expect(incidentTimeline(row, view, null, 0).lifecycle).toBe('recovered');
        expect(incidentTimeline(row, { ...view, devices: [] }, null, 0).current.state).toBe('unknown');
        expect(incidentTimeline(row, { ...view, devices: [{ ...view.devices[0], checks: [] }] }, null, 0).current.state).toBe('not-monitored');
    });
    it('separates Windows contact receipt, later confirmation and actual report resumption', () => {
        const row = windowsRow(legacy(), 'contact'), model = incidentTimeline(row, null, now, 0);
        expect(model.contact).toBe('windows'); expect(model.episode[0]).toEqual({ kind: 'contact-received', at: row.item.receivedAt });
        expect(model.episode.some(event => event.kind.includes('captured'))).toBe(false);
        const closed = structuredClone(row);
        closed.item.resolvedAt = '2026-10-07T12:04:30Z'; closed.item.closedReason = 'reports-resumed'; closed.item.recoveryReceivedAt = '2026-10-07T12:04:00Z'; closed.item.status = 'recent'; closed.item.evaluatedAt = '2026-10-07T12:04:30Z'; closed.item.statusValidUntil = '2026-10-07T12:05:00Z';
        expect(validWindowsIncidentItem(closed.item, '2026-10-07T12:04:30Z')).toBe(true);
        const recovered = incidentTimeline(closed, null, '2026-10-07T12:04:30Z', 0);
        expect(recovered.lifecycle).toBe('recovered'); expect(recovered.episode.some(event => event.kind === 'reports-resumed')).toBe(true);
    });
    it('retains every simultaneous checkpoint and sorts sub-millisecond UTC timestamps exactly', () => {
        const row = windowsRow(legacy(), 'cpu');
        row.item.openedAt = '2026-10-07T12:03:30.000000900Z'; row.item.lastConfirmedAt = '2026-10-07T12:03:30.000000901Z';
        row.item.collectedAt = '2026-10-07T12:03:30.000000001Z'; row.item.receivedAt = row.item.collectedAt; row.item.acknowledgedAt = row.item.openedAt;
        const model = incidentTimeline(row, null, now, 0);
        expect(model.episode.map(event => event.kind)).toEqual(['bad-captured', 'bad-received', 'opened', 'seen', 'last-confirmed']);
        expect(model.episode).toHaveLength(5); expect(incidentTimeline(row, null, now, 0).episode).toEqual(model.episode);
    });
    it('preserves exact independent complete-source references after current evidence expires', () => {
        const view = completeIncidentFixture('active'), row = windowsRow(view), before = JSON.stringify(view);
        const fresh = incidentTimeline(row, null, view.serverNow, 0);
        expect(fresh.sources.map(value => value.role)).toEqual(['opening', 'last-bad']); expect(fresh.current.source).not.toBeNull();
        for (const age of [121000, Number.NaN, -1, Number.POSITIVE_INFINITY]) {
            const stale = incidentTimeline(row, null, view.serverNow, age);
            expect(stale.current.state).toBe('unknown'); expect(stale.current.source).toBeNull(); expect(stale.current.validUntil).toBeNull();
            expect(stale.episode).toEqual(fresh.episode); expect(stale.sources).toEqual(fresh.sources); expect(stale.lifecycle).toBe('open');
        }
        expect(incidentTimeline(row, null, null, 0).current.source).toBeNull(); expect(JSON.stringify(view)).toBe(before);
    });
    it('preserves a validated complete-service recovery generation and every original recovery checkpoint', () => {
        const view = completeIncidentFixture('active'), item = view.items[0];
        if (item.sourceKind !== 'windows_full_services') throw new Error('Expected complete source');
        const at = (delta: number) => new Date(Date.parse(item.lastBadSource.capturedAt) + delta).toISOString();
        const source = { ...item.lastBadSource, sequence: item.lastBadSource.sequence + 1, capturedAt: at(30000), captureFinishedAt: at(30100), receivedAt: at(30200), expiresAt: at(30000 + 86400000) };
        source.generationId = fullServicesGenerationId(item.deviceId, source.grantId, source.sequence);
        item.recoverySource = source; item.recoveryCollectedAt = source.capturedAt; item.recoveryReceivedAt = source.receivedAt;
        item.resolvedAt = at(35000); item.closedReason = 'running'; item.currentSource = source; item.evaluatedAt = item.resolvedAt; item.status = 'running'; item.statusValidUntil = at(100000);
        view.serverNow = at(40000); view.authorityExpiresAt = at(160000); view.scope = 'all'; view.counts.active = 0; view.counts.resolved = 1;
        expect(validWindowsCompleteIncidentInboxView(view, 'all', 'all', 0)).toBe(true);
        const before = JSON.stringify(view), model = incidentTimeline(windowsRow(view), null, view.serverNow, 0);
        expect(model.lifecycle).toBe('recovered'); expect(model.sources.map(value => value.role)).toEqual(['opening', 'last-bad', 'recovery']);
        expect(model.sources[2].source).toEqual(source);
        expect(model.episode.filter(event => event.kind.startsWith('recovery-'))).toEqual([
            { kind: 'recovery-captured', at: source.capturedAt }, { kind: 'recovery-finished', at: source.captureFinishedAt }, { kind: 'recovery-received', at: source.receivedAt },
        ]);
        expect(model.episode.find(event => event.kind === 'recovered')?.at).toBe(item.resolvedAt);
        const deadlineAge = Date.parse(item.statusValidUntil) - Date.parse(view.serverNow);
        expect(incidentTimeline(windowsRow(view), null, view.serverNow, deadlineAge - 1).current.state).toBe('running');
        const expired = incidentTimeline(windowsRow(view), null, view.serverNow, deadlineAge);
        expect(expired.current.state).toBe('unknown'); expect(expired.sources).toEqual(model.sources); expect(expired.episode).toEqual(model.episode); expect(expired.lifecycle).toBe('recovered'); expect(JSON.stringify(view)).toBe(before);
    });
    it('does not rebind a closed complete-source episode to a later current grant', () => {
        const view = completeIncidentFixture('active'), item = view.items[0];
        if (item.sourceKind !== 'windows_full_services' || !item.currentSource) throw new Error('Expected complete source');
        item.resolvedAt = item.lastConfirmedAt; item.closedReason = 'policy-changed';
        item.currentSource = { ...item.currentSource, grantId: 'e'.repeat(32), grantRevision: item.currentSource.grantRevision + 1, generationId: fullServicesGenerationId(item.deviceId, 'e'.repeat(32), item.currentSource.sequence) };
        view.scope = 'all'; view.counts.active = 0; view.counts.resolved = 1;
        expect(validWindowsCompleteIncidentInboxView(view, 'all', 'all', 0)).toBe(true);
        const model = incidentTimeline(windowsRow(view), null, view.serverNow, 0);
        expect(model.lifecycle).toBe('stopped'); expect(model.current.source?.grantId).toBe('e'.repeat(32)); expect(model.sources[0].source.grantId).not.toBe('e'.repeat(32));
        expect(model.episode.some(event => event.kind === 'recovered')).toBe(false);
    });
    it.each(['en', 'de'] as const)('renders all exact provenance fields and inert target text in %s', locale => {
        setLocale(locale, false);
        const view = completeIncidentFixture('active'), row = windowsRow(view); row.item.serviceName = '<img src=x onerror=alert(1)>'; const before = JSON.stringify(row);
        const model = incidentTimeline(row, null, view.serverNow, 0); const { container } = render(<IncidentTimeline model={model} platform="windows"/>);
        const source = model.sources[0].source;
        for (const text of [source.grantId, source.generationId, source.manifestSha256, source.expiresAt, source.kind, row.item.serviceName]) expect(container.textContent).toContain(text);
        expect(container.querySelectorAll('img,script,form,button')).toHaveLength(0);
        expect(container.querySelector('a')?.getAttribute('href')).toBe(`#/devices/${encodeURIComponent(row.item.deviceId)}/health`);
        expect(container.querySelectorAll('time')).not.toHaveLength(0); expect(JSON.stringify(row)).toBe(before);
        expect(container.textContent).toContain(locale === 'en' ? 'not a continuous event log' : 'kein lückenloses Ereignisprotokoll');
    });
    it('uses only the exact validated Linux service for log navigation', () => {
        const view = linuxFixture(), row = linuxRow(view);
        row.item.incident = { ...row.item.incident, kind: 'service', key: 'service:sshd@default.service', target: 'sshd@default.service' };
        expect(incidentTimeline(row, view, null, 0).logsHref).toBe(`#/devices/${encodeURIComponent(id)}/logs/sshd%40default.service`);
        row.item.incident.target = '<script>alert(1)</script>'; expect(incidentTimeline(row, view, null, 0).logsHref).toBeNull();
    });
});

describe('loaded-page incident investigation workflow', () => {
    it('combines literal bounded search and outcome filters without searching analysis content or changing source totals', () => {
        const linux = linuxFixture(), windows = legacy(), rows = incidentQueueRows(linux, windows), before = JSON.stringify({ linux, windows });
        const names = new Map([[`linux:${id}`, 'Primary Linux']]);
        expect(filterIncidentQueue(rows, 'all', 'all', 'all', 'all', 'PRIMARY LINUX', names)).toHaveLength(1);
        expect(filterIncidentQueue(rows, 'all', 'all', 'all', 'all', rows[0].item.deviceId)).not.toHaveLength(0);
        expect(filterIncidentQueue(rows, 'all', 'all', 'all', 'all', '.*')).toEqual([]);
        expect(filterIncidentQueue(rows, 'all', 'all', 'all', 'all', 'x'.repeat(QUEUE_SEARCH_LIMIT + 1000))).toEqual([]);
        const bounded = id + ' '.repeat(QUEUE_SEARCH_LIMIT - id.length) + 'not searched';
        expect(filterIncidentQueue(rows, 'all', 'all', 'all', 'all', bounded)).toEqual(filterIncidentQueue(rows, 'all', 'all', 'all', 'all', id));
        const first = linuxRow(linux); first.item.analysis = { secret: 'hidden AI content' } as never;
        expect(filterIncidentQueue([first], 'all', 'all', 'all', 'all', 'hidden AI content')).toEqual([]); delete first.item.analysis;
        const resolved = incidentQueueRows(null, legacy('resolved'));
        const counts = incidentQueueLifecycleCounts(resolved); expect(counts.open).toBe(0); expect(counts.recovered + counts.stopped).toBe(resolved.length);
        expect(filterIncidentQueue(resolved, 'all', 'all', 'all', 'stopped').every(row => incidentLifecycle(row) === 'stopped')).toBe(true);
        expect(JSON.stringify({ linux, windows })).toBe(before);
    });
    it.each(['en', 'de'] as const)('opens, filters, clears and refreshes the exact bounded source workflow in %s without new requests or writes', locale => {
        setLocale(locale, false);
        const linux = resource(linuxFixture()), onLinuxPage = vi.fn();
        render(<IncidentWorkQueue devices={[{ id, platform: 'linux', source: 'lan', synthetic: false, name: 'Primary Linux' } as Device]} sessionKey="session" linux={linux} scope="all" onScope={vi.fn()} linuxOffset={50} onLinuxPage={onLinuxPage}/>);
        const search = screen.getByRole('searchbox', { name: locale === 'en' ? 'Search loaded incidents' : 'Geladene Vorfälle durchsuchen' });
        fireEvent.change(search, { target: { value: 'Primary Linux' } });
        const queue = screen.getByRole('region', { name: locale === 'en' ? 'Incident work queue' : 'Vorfall-Arbeitsliste' });
        expect(queue.querySelectorAll('.incident-queue-entry')).toHaveLength(1);
        const details = within(queue).getByText(locale === 'en' ? 'Incident timeline' : 'Vorfall-Zeitverlauf').closest('details')!;
        fireEvent.click(details.querySelector('summary')!); expect(details.open).toBe(true);
        fireEvent.click(details.querySelector('summary')!); expect(details.open).toBe(false);
        fireEvent.click(details.querySelector('summary')!); expect(details.open).toBe(true);
        expect(search).toHaveAttribute('maxlength', String(QUEUE_SEARCH_LIMIT));
        fireEvent.change(search, { target: { value: '.*' } }); expect(queue.querySelectorAll('.incident-queue-entry')).toHaveLength(0);
        fireEvent.click(screen.getByRole('button', { name: locale === 'en' ? 'Clear page filters' : 'Seitenfilter zurücksetzen' }));
        expect(search).toHaveValue(''); expect(queue.querySelectorAll('.incident-queue-entry')).toHaveLength(6);
        fireEvent.change(screen.getByRole('combobox', { name: locale === 'en' ? 'Episode outcome on loaded pages' : 'Episodenausgang auf geladenen Seiten' }), { target: { value: 'stopped' } });
        expect(queue.querySelectorAll('.incident-queue-entry')).toHaveLength(0);
        fireEvent.click(screen.getByRole('button', { name: locale === 'en' ? 'Refresh work queue' : 'Arbeitsliste aktualisieren' })); expect(onLinuxPage).toHaveBeenCalledWith(0);
        expect(useWindowsIncidentInbox).toHaveBeenLastCalledWith(true, 'session', false, 'all', 'all', 0, true);
        expect(request).not.toHaveBeenCalled(); expect(mutate).not.toHaveBeenCalled(); expect(windows.acknowledge).not.toHaveBeenCalled();
    });
    it('removes an expanded timeline when its source is cleared and does not invent an empty-success source count', () => {
        const linux = resource(null), props = { devices: [], sessionKey: 'session', linux, scope: 'all' as const, onScope: vi.fn(), linuxOffset: 0, onLinuxPage: vi.fn() };
        const { rerender } = render(<IncidentWorkQueue {...props}/>);
        const summary = screen.getAllByText('Incident timeline')[0]; fireEvent.click(summary); expect(summary.closest('details')).toHaveAttribute('open');
        windows = { ...windows, view: null, error: true };
        rerender(<IncidentWorkQueue {...props} sessionKey={null}/>);
        expect(screen.queryByText('Incident timeline')).not.toBeInTheDocument();
        expect(screen.getByText('Windows incidents unavailable or expired. Their counts and rows are unknown.')).toBeInTheDocument();
        expect(screen.getByText('No matching rows from the available pages. Missing source rows and totals remain unknown.')).toBeInTheDocument();
    });
    it('updates current confidence independently of an expanded complete-source episode and supports locale changes', () => {
        windows = { ...windows, view: completeIncidentFixture('active'), age: 0 };
        const props = { devices: [], sessionKey: 'session', linux: resource(null), scope: 'active' as const, onScope: vi.fn(), linuxOffset: 0, onLinuxPage: vi.fn() };
        const { rerender } = render(<IncidentWorkQueue {...props}/>);
        fireEvent.click(screen.getByText('Incident timeline'));
        const episode = document.querySelector('.incident-timeline-events')!.textContent;
        windows = { ...windows, age: 121000 }; rerender(<IncidentWorkQueue {...props}/>);
        const current = screen.getByRole('region', { name: 'Current check, separate from this episode' });
        expect(within(current).getByText('Unknown: current evidence is missing or stale')).toBeInTheDocument();
        expect(within(current).queryByText('Qualified current generation')).not.toBeInTheDocument(); expect(document.querySelector('.incident-timeline-events')!.textContent).toBe(episode);
        act(() => setLocale('de', false)); expect(screen.getByText('Vorfall-Zeitverlauf')).toBeInTheDocument(); expect(screen.getByText(/^Weiter offen: 1/)).toBeInTheDocument();
        expect(request).not.toHaveBeenCalled(); expect(mutate).not.toHaveBeenCalled();
    });
});
