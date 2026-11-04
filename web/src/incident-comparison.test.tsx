import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import healthWire from './health-go-fixture.json';
import windowsWire from '../../tests/fixtures/windows-incident-inbox-view.json';
import type { HealthView } from './health-types';
import { validInvestigationsView } from './investigations-types';
import type { InvestigationsView } from './investigations-types';
import type { InvestigationsResource } from './investigations-resource';
import { completeIncidentFixture } from './windows-complete-incident-inbox-fixture';
import type { WindowsInboxView } from './windows-complete-incident-inbox-types';
import { validWindowsIncidentInboxView } from './windows-incident-inbox-types';
import { incidentQueueRows } from './incident-work-queue-model';
import { comparisonCheckpoints, comparisonEpisodes, comparisonSelection, MAX_COMPARISON_EPISODES, toggleComparison } from './incident-comparison-model';
import { IncidentWorkQueue } from './incident-work-queue';
import { setLocale } from './i18n';
import { useWindowsIncidentInbox } from './windows-incident-inbox-resource';
import { mutate, request } from './api';

vi.mock('./windows-incident-inbox-resource', () => ({ useWindowsIncidentInbox: vi.fn() }));
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), mutate: vi.fn(), request: vi.fn() }));

function linuxFixture(): InvestigationsView {
    const health = structuredClone(healthWire) as HealthView;
    const view: InvestigationsView = { schemaVersion: 'tracebolt.investigations.v1', serverNow: health.serverNow, scope: 'all', offset: 0, total: health.incidents.length, counts: { open: health.incidents.length, recovered: 0, closed: 0, all: health.incidents.length }, items: health.incidents.map(incident => ({ deviceId: health.deviceId, incident })), devices: [{ ...health, incidents: [] }] };
    if (!validInvestigationsView(view, 'all', 0)) throw new Error('Invalid Linux fixture');
    return view;
}
function windowsFixture(): WindowsInboxView {
    const view = structuredClone(windowsWire.active);
    if (!validWindowsIncidentInboxView(view, 'active', 'all', 0)) throw new Error('Invalid Windows fixture');
    return view;
}
function resource(view: InvestigationsView | null): InvestigationsResource { return { view, counts: view?.counts ?? null, readiness: 'unknown', pending: false, failure: null, locked: false, refresh: vi.fn() }; }
function props() { return { devices: [], sessionKey: 'session-a', linux: resource(linuxFixture()), scope: 'all' as const, onScope: vi.fn(), linuxOffset: 0, onLinuxPage: vi.fn() }; }
let windows: ReturnType<typeof useWindowsIncidentInbox>;
beforeEach(() => {
    setLocale('en', false);
    windows = { view: windowsFixture(), age: 0, loading: false, writing: false, error: false, notice: null, refresh: vi.fn(), acknowledge: vi.fn(), isUncertain: () => false };
    vi.mocked(useWindowsIncidentInbox).mockImplementation(() => windows);
    vi.mocked(request).mockReset(); vi.mocked(mutate).mockReset();
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); });
const panel = () => screen.getByRole('region', { name: 'Compare incident episodes' });
const choices = () => screen.getAllByRole('checkbox', { name: /^Compare episode:/ });
function choosePair() { fireEvent.click(screen.getByRole('checkbox', { name: /^Compare episode: Linux Health/ })); fireEvent.click(screen.getAllByRole('checkbox', { name: /^Compare episode: Windows assessment/ })[0]); }
function openComparison() { choosePair(); fireEvent.click(screen.getByRole('button', { name: 'Open comparison' })); }

describe('source-qualified comparison model', () => {
    it('retains only exact visible identities, removes duplicates and enforces the four-episode bound', () => {
        const rows = incidentQueueRows(linuxFixture(), windowsFixture()), ids = rows.map(row => row.identity);
        expect(ids.length).toBeGreaterThan(MAX_COMPARISON_EPISODES);
        expect(comparisonSelection(['missing', ids[0], ids[0], ...ids], rows)).toEqual(ids.slice(0, 4));
        expect(toggleComparison(ids.slice(0, 4), rows, ids[4])).toEqual(ids.slice(0, 4));
        expect(toggleComparison(ids.slice(0, 4), rows, ids[0])).toEqual(ids.slice(1, 4));
        expect(toggleComparison([], rows, 'missing')).toEqual([]);
        const other = structuredClone(rows[0]); other.identity = 'different-domain-same-local-id';
        expect(comparisonSelection([ids[0], other.identity], [rows[0], other])).toHaveLength(2);
    });
    it('does not cache rows, rewrite source times or attach unrelated AI/content fields', () => {
        const linux = linuxFixture(), windows = windowsFixture(), rows = incidentQueueRows(linux, windows), before = JSON.stringify({ linux, windows });
        const episodes = comparisonEpisodes(rows.slice(0, 2).map(row => row.identity), rows, linux, windows.serverNow, 0);
        expect(episodes).toHaveLength(2); expect(episodes.every(episode => episode.readAt === windows.serverNow)).toBe(true);
        expect(JSON.stringify(episodes)).not.toContain('analysis'); expect(JSON.stringify(episodes)).not.toContain('journalAI');
        expect(JSON.stringify({ linux, windows })).toBe(before);
        expect(comparisonEpisodes(episodes.map(episode => episode.identity), [], linux, windows.serverNow, 0)).toEqual([]);
    });
    it('merges every checkpoint in nanosecond order with deterministic ties and distinct episode ownership', () => {
        const linux = linuxFixture(), windows = windowsFixture(), rows = incidentQueueRows(linux, windows);
        const episodes = comparisonEpisodes(rows.slice(0, 2).map(row => row.identity), rows, linux, windows.serverNow, 0);
        episodes[0].model.episode = [{ kind: 'opened', at: '2026-10-07T12:03:30.000000900Z' }, { kind: 'seen', at: '2026-10-07T12:03:30.000000900Z' }];
        episodes[1].model.episode = [{ kind: 'bad-captured', at: '2026-10-07T12:03:30.000000001Z' }, { kind: 'opened', at: '2026-10-07T12:03:30.000000900Z' }];
        const before = JSON.stringify(episodes), checkpoints = comparisonCheckpoints(episodes);
        expect(checkpoints.map(event => [event.kind, event.episodeIndex])).toEqual([['bad-captured', 1], ['opened', 0], ['seen', 0], ['opened', 1]]);
        expect(checkpoints[0].identity).toBe(episodes[1].identity); expect(JSON.stringify(episodes)).toBe(before);
        expect(comparisonCheckpoints(episodes)).toEqual(checkpoints);
    });
    it('keeps complete-service provenance and retained outcome separate from expired current evidence', () => {
        const view = completeIncidentFixture('active'), rows = incidentQueueRows(null, view), ids = rows.map(row => row.identity);
        const fresh = comparisonEpisodes(ids, rows, null, view.serverNow, 0)[0];
        for (const age of [121000, NaN, -1, Infinity]) {
            const expired = comparisonEpisodes(ids, rows, null, view.serverNow, age)[0];
            expect(expired.model.current.state).toBe('unknown'); expect(expired.model.current.source).toBeNull();
            expect(expired.model.sources).toEqual(fresh.model.sources); expect(expired.model.episode).toEqual(fresh.model.episode); expect(expired.model.lifecycle).toBe('open');
        }
    });
    it('keeps administrative closure and seen distinct from selected-check recovery', () => {
        const linux = linuxFixture(), healthIncident = linux.items[0].incident;
        healthIncident.acknowledgedAt = linux.serverNow;
        healthIncident.resolvedAt = linux.serverNow; healthIncident.closedReason = 'monitoring_stopped';
        const windows = structuredClone(windowsWire.resolved);
        if (!validWindowsIncidentInboxView(windows, 'resolved', 'all', 0)) throw new Error('Invalid resolved fixture');
        const rows = incidentQueueRows(linux, windows);
        const selected = [rows.find(row => row.platform === 'linux')!.identity, rows.find(row => row.platform === 'windows' && row.item.closedReason === 'policy-changed')!.identity];
        const stopped = comparisonEpisodes(selected, rows, linux, windows.serverNow, 0);
        expect(stopped.every(episode => episode.model.lifecycle === 'stopped')).toBe(true);
        expect(comparisonCheckpoints(stopped).some(event => event.kind === 'recovered')).toBe(false);
        expect(comparisonCheckpoints(stopped).some(event => event.kind === 'seen')).toBe(true);
        healthIncident.closedReason = 'recovered';
        expect(comparisonEpisodes(selected, rows, linux, windows.serverNow, 0)[0].model.lifecycle).toBe('recovered');
    });
});

describe('complete local incident-comparison workflow', () => {
    it('selects two exact episodes, compares original chronology, closes/reopens and clears without requests or writes', () => {
        const p = props(); render(<IncidentWorkQueue {...p}/>);
        expect(within(panel()).queryByRole('button', { name: 'Open comparison' })).not.toBeInTheDocument();
        fireEvent.click(choices()[0]); expect(screen.getByRole('button', { name: 'Open comparison' })).toBeDisabled();
        fireEvent.click(screen.getByRole('checkbox', { name: /^Compare episode: Linux Health/ }));
        fireEvent.click(screen.getByRole('button', { name: 'Open comparison' }));
        expect(within(panel()).getAllByRole('article')).toHaveLength(2);
        const chronology = within(panel()).getByRole('region', { name: 'Original checkpoints across selected episodes' });
        expect(chronology.querySelectorAll('time').length).toBeGreaterThan(2);
        expect(within(panel()).getByText(/Source clocks may differ/)).toBeInTheDocument();
        expect(within(panel()).getAllByText(/Source page read at:/)).toHaveLength(2);
        fireEvent.click(screen.getByRole('button', { name: 'Close comparison' })); expect(within(panel()).queryAllByRole('article')).toHaveLength(0);
        fireEvent.click(screen.getByRole('button', { name: 'Open comparison' })); expect(within(panel()).getAllByRole('article')).toHaveLength(2);
        fireEvent.click(screen.getByRole('button', { name: 'Clear comparison' })); expect(within(panel()).queryAllByRole('article')).toHaveLength(0); expect(choices().every(checkbox => !(checkbox as HTMLInputElement).checked)).toBe(true);
        expect(request).not.toHaveBeenCalled(); expect(mutate).not.toHaveBeenCalled(); expect(windows.acknowledge).not.toHaveBeenCalled(); expect(windows.refresh).not.toHaveBeenCalled(); expect(p.linux.refresh).not.toHaveBeenCalled();
    });
    it('limits repeated selection to four while allowing removal and replacement, then closes below two', () => {
        render(<IncidentWorkQueue {...props()}/>);
        const inputs = choices(); inputs.slice(0, 4).forEach(input => fireEvent.click(input));
        expect(inputs.slice(0, 4).every(input => !(input as HTMLInputElement).disabled)).toBe(true);
        expect(inputs[4]).toBeDisabled(); expect(within(panel()).getByRole('status')).toHaveTextContent('Four episodes selected');
        fireEvent.click(inputs[4]); expect(within(panel()).getByText('Selected episodes: 4/4')).toBeInTheDocument();
        fireEvent.click(inputs[0]); expect(inputs[4]).not.toBeDisabled(); fireEvent.click(inputs[4]);
        fireEvent.click(screen.getByRole('button', { name: 'Open comparison' })); expect(within(panel()).getAllByRole('article')).toHaveLength(4);
        for (let i = 0; i < 3; i++) fireEvent.click(screen.getByRole('button', { name: 'Remove episode: 1' }));
        expect(within(panel()).queryAllByRole('article')).toHaveLength(0); expect(screen.getByRole('button', { name: 'Open comparison' })).toBeDisabled();
    });
    it('gives every source-qualified episode a distinct accessible choice even when local incident IDs collide', () => {
        render(<IncidentWorkQueue {...props()}/>);
        const labels = choices().map(input => input.getAttribute('aria-label'));
        expect(new Set(labels).size).toBe(labels.length);
        for (const label of labels) expect(label).toMatch(/ · (?:[a-f0-9]{64}|filesystem:root|offline:contact|service:.+)$/);
    });
    it('synchronously clears on session changes even when old source props are retained, with no resurrection', () => {
        const p = props(), mounted = render(<IncidentWorkQueue {...p}/>); openComparison();
        mounted.rerender(<IncidentWorkQueue {...p} sessionKey="session-b"/>);
        expect(within(panel()).queryAllByRole('article')).toHaveLength(0); expect(within(panel()).getByText('Selected episodes: 0/4')).toBeInTheDocument();
        mounted.rerender(<IncidentWorkQueue {...p}/>); expect(within(panel()).getByText('Selected episodes: 0/4')).toBeInTheDocument();
    });
    it.each(['platform', 'source', 'seen', 'outcome', 'search', 'linux-page', 'scope'] as const)('clears exact choices on %s change without restoring them on return', kind => {
        const p = props(), mounted = render(<IncidentWorkQueue {...p}/>); openComparison();
        const select = (name: string, value: string) => fireEvent.change(screen.getByRole('combobox', { name }), { target: { value } });
        if (kind === 'platform') select('Platform on loaded pages', 'linux');
        if (kind === 'source') select('Source on loaded pages', 'linux-health');
        if (kind === 'seen') select('Seen on loaded pages', 'unseen');
        if (kind === 'outcome') select('Episode outcome on loaded pages', 'open');
        if (kind === 'search') fireEvent.change(screen.getByRole('searchbox', { name: 'Search loaded incidents' }), { target: { value: 'agent_' } });
        if (kind === 'linux-page') mounted.rerender(<IncidentWorkQueue {...p} linuxOffset={50}/>);
        if (kind === 'scope') mounted.rerender(<IncidentWorkQueue {...p} scope="active"/>);
        expect(within(panel()).getByText('Selected episodes: 0/4')).toBeInTheDocument();
        const reset = screen.getByRole('button', { name: 'Clear page filters' }); if (!(reset as HTMLButtonElement).disabled) fireEvent.click(reset);
        mounted.rerender(<IncidentWorkQueue {...p}/>); expect(within(panel()).getByText('Selected episodes: 0/4')).toBeInTheDocument();
    });
    it('prunes lost-source episodes permanently, retains independent available choices, and fails closed on lock', () => {
        const p = props(), mounted = render(<IncidentWorkQueue {...p}/>); openComparison();
        windows = { ...windows, view: null, error: true }; mounted.rerender(<IncidentWorkQueue {...p}/>);
        expect(within(panel()).getByText('Selected episodes: 1/4')).toBeInTheDocument(); expect(within(panel()).queryAllByRole('article')).toHaveLength(0);
        expect(within(panel()).getByText(/Linux Health/)).toBeInTheDocument();
        windows = { ...windows, view: windowsFixture(), error: false }; mounted.rerender(<IncidentWorkQueue {...p}/>);
        expect(within(panel()).getByText('Selected episodes: 1/4')).toBeInTheDocument();
        mounted.rerender(<IncidentWorkQueue {...p} linux={{ ...p.linux, locked: true }}/>);
        expect(within(panel()).getByText('Selected episodes: 0/4')).toBeInTheDocument(); expect(choices().every(checkbox => (checkbox as HTMLInputElement).disabled)).toBe(true);
    });
    it('does not replace an exact chosen episode with a new episode under the same device and check', () => {
        const p = props(), mounted = render(<IncidentWorkQueue {...p}/>); openComparison();
        const newer = structuredClone(p.linux.view!); newer.items[0].incident.id = 'health_0000000000000002';
        mounted.rerender(<IncidentWorkQueue {...p} linux={resource(newer)}/>);
        expect(within(panel()).getByText('Selected episodes: 1/4')).toBeInTheDocument();
        expect(screen.getByRole('checkbox', { name: /^Compare episode: Linux Health/ })).not.toBeChecked();
        mounted.rerender(<IncidentWorkQueue {...p}/>); expect(within(panel()).getByText('Selected episodes: 1/4')).toBeInTheDocument();
    });
    it('preserves exact choices across ordinary live refresh while aging current evidence independently', () => {
        windows = { ...windows, view: completeIncidentFixture('active') };
        const p = props(), mounted = render(<IncidentWorkQueue {...p}/>);
        fireEvent.click(choices()[0]); fireEvent.click(choices()[1]); fireEvent.click(screen.getByRole('button', { name: 'Open comparison' }));
        const chronology = within(panel()).getByRole('region', { name: 'Original checkpoints across selected episodes' }).textContent;
        windows = { ...windows, view: structuredClone(windows.view), age: 121000 }; mounted.rerender(<IncidentWorkQueue {...p} linux={{ ...p.linux, view: structuredClone(p.linux.view) }}/>);
        expect(within(panel()).getByText('Selected episodes: 2/4')).toBeInTheDocument();
        expect(within(panel()).getAllByText('Unknown: current evidence is missing or stale')).not.toHaveLength(0);
        expect(within(panel()).getByRole('region', { name: 'Original checkpoints across selected episodes' }).textContent).toBe(chronology);
        expect(request).not.toHaveBeenCalled(); expect(mutate).not.toHaveBeenCalled();
    });
    it('renders inert targets and supports locale changes without losing the selected source identity', () => {
        const view = completeIncidentFixture('active'); view.items[0].serviceName = '<img src=x onerror=alert(1)>';
        windows = { ...windows, view }; render(<IncidentWorkQueue {...props()}/>);
        fireEvent.click(choices()[0]); fireEvent.click(choices()[1]); fireEvent.click(screen.getByRole('button', { name: 'Open comparison' }));
        expect(within(panel()).getByRole('article', { name: 'Episode 1' })).toHaveTextContent('<img src=x onerror=alert(1)>');
        expect(panel().querySelectorAll('img,script,form')).toHaveLength(0);
        act(() => setLocale('de', false));
        const de = screen.getByRole('region', { name: 'Vorfall-Episoden vergleichen' });
        expect(within(de).getByText('Ausgewählte Episoden: 2/4')).toBeInTheDocument(); expect(within(de).getByText(/Quelluhren können abweichen/)).toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', { name: 'Vergleich leeren' })); expect(within(de).getByText('Ausgewählte Episoden: 0/4')).toBeInTheDocument();
    });
});
