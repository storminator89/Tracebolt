import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { APIError, AUTH_REQUIRED_EVENT, request } from './api';
import { setLocale } from './i18n';
import { OperationalInventoryPanel } from './operational';
import { effectiveOperationalStatus, OPERATIONAL_PROFILE, OPERATIONAL_SCHEMA, operationalNow, SECTION_LIMITS, SECTION_NAMES, validOperationalView } from './operational-types';
import type { OperationalMeta, OperationalSectionName, OperationalSections, OperationalView } from './operational-types';
vi.mock('./api', async importOriginal => { const original = await importOriginal<typeof import('./api')>(); return { ...original, request: vi.fn() }; });
const collectedAt = '2026-10-03T12:00:00Z';
const serverNow = '2026-10-03T12:00:10Z';
function meta(name: OperationalSectionName, count = 1): OperationalMeta { return { quality: 'healthy', reason: 'none', observedAt: collectedAt, generationId: `sample_${'a'.repeat(32)}`,  complete: true, truncated: false, observedCount: count, countExact: true, itemLimit: SECTION_LIMITS[name] }; }
/** Deliberately synthetic, bounded test data. No runtime fallback exists. */
function fixture(deviceId = 'agent_fixture'): OperationalView {
    return {
        schemaVersion: 'tracebolt.operational-view.v1', deviceId, status: 'fresh', serverNow, receivedAt: '2026-10-03T12:00:05Z', sequence: 1, maxAgeSeconds: 120,
        snapshot: { schemaVersion: OPERATIONAL_SCHEMA, collectionProfile: OPERATIONAL_PROFILE, generationId: `sample_${'a'.repeat(32)}`, collectedAt, durationMs: 10,
            sections: {
                volumes: { meta: { ...meta('volumes'), complete: false, reason: 'read_failed' }, items: [{ id: 'mount_1', mountPoint: '/fixture', filesystem: 'ext4', kind: 'local', totalBytes: null, availableBytes: null, usedPercent: null, measurementQuality: 'unknown', measurementReason: 'read_failed' }] },
                network: { meta: { ...meta('network'), complete: false, reason: 'read_failed' }, items: [{ name: 'fixture0', state: 'up', mtu: 1500, rxBytes: 1024, txBytes: 2048, rxErrors: null, txErrors: 0, ipv4Count: 1, ipv6Count: null }] },
                services: { meta: meta('services'), items: [{ name: 'fixture.service', loadState: 'loaded', activeState: 'failed', subState: 'failed' }] },
                processes: { meta: { ...meta('processes'), complete: false, reason: 'read_failed' }, items: [{ pid: 42, parentPid: null, name: 'fixture-process', state: 'sleeping', rssBytes: 2048, cpuTimeSeconds: 3.5, threads: null }] },
                software: { meta: meta('software'), items: [{ name: 'fixture-package', version: '1.0', architecture: 'all', manager: 'dpkg' }] },
                events: { meta: meta('events', 2), items: [{ source: 'systemd-journal', unit: 'fixture.service', priority: 3, messageId: '', count: 2, firstSeen: '2026-10-03T11:59:50Z', lastSeen: collectedAt }] },
            } },
        lastGood: { volumes: null, network: null, services: null, processes: null, software: null, events: null },
        assessments: { updates: { quality: 'unknown', reason: 'not_implemented' }, vulnerabilities: { quality: 'unknown', reason: 'not_implemented' } },
    };
}
function unavailable(status: OperationalView['status'] = 'not_configured'): OperationalView { return { ...fixture(), status, receivedAt: null, sequence: null, snapshot: null }; }
function defer<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(done => { resolve = done; }); return { promise, resolve }; }
function sectionButton(name: string) { return screen.getByRole('button', { name: new RegExp(`^${name} `) }); }
beforeEach(() => { vi.mocked(request).mockReset(); vi.mocked(request).mockResolvedValue(fixture()); setLocale('en', false); });
afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); });

describe('operational view validation', () => {
    it('uses the renamed profile while retaining the Linux-only snapshot schema', () => {
        expect(OPERATIONAL_PROFILE).toBe('managed-operations-v1');
        expect(OPERATIONAL_SCHEMA).toBe('tracebolt.linux-operational.v1');
    });
    it('accepts the bounded fixture and explicit unavailable response', () => { expect(validOperationalView(fixture(), 'agent_fixture')).toBe(true); expect(validOperationalView(unavailable(), 'agent_fixture')).toBe(true); });
    it('rejects a cross-device result, expanded schema and missing required keys', () => {
        expect(validOperationalView(fixture('agent_other'), 'agent_fixture')).toBe(false);
        expect(validOperationalView({ ...fixture(), rawLogs: [] }, 'agent_fixture')).toBe(false);
        const value = fixture() as unknown as Record<string, unknown>; delete value.assessments;
        expect(validOperationalView(value, 'agent_fixture')).toBe(false);
    });
    it('rejects nullable item arrays, unexpected private fields and wrong fixed caps', () => {
        for (const change of [(section: Record<string, unknown>) => { section.items = null; }, (section: Record<string, unknown>) => { ((section.items as Record<string, unknown>[])[0]).commandLine = 'must never render'; }, (section: Record<string, unknown>) => { (section.meta as Record<string, unknown>).itemLimit = 999; }]) {
            const value = fixture(); change(value.snapshot!.sections.processes as unknown as Record<string, unknown>);
            expect(validOperationalView(value, 'agent_fixture')).toBe(false);
        }
    });
    it.each(['\u0000bad', '\u007fhidden', 'invalid\ud800', 'é'.repeat(65), 'hidden\u202etext'])('rejects invalid or oversized source strings', name => {
        const value = fixture(); value.snapshot!.sections.software.items[0].name = name;
        expect(validOperationalView(value, 'agent_fixture')).toBe(false);
    });
    it.each([NaN, Infinity, -1, Number.MAX_SAFE_INTEGER + 1, 1.5])('rejects invalid integer counters (%s)', count => {
        const value = fixture(); value.snapshot!.sections.network.items[0].rxBytes = count;
        expect(validOperationalView(value, 'agent_fixture')).toBe(false);
    });
    it('rejects out-of-range percentages, enums, dates and event windows', () => {
        let value = fixture(); value.snapshot!.sections.volumes.items[0].usedPercent = 101; expect(validOperationalView(value, 'agent_fixture')).toBe(false);
        value = fixture(); (value.snapshot!.sections.network.items[0] as { state: string }).state = 'ready'; expect(validOperationalView(value, 'agent_fixture')).toBe(false);
        value = fixture(); value.serverNow = '2026-02-31T12:00:10Z'; expect(validOperationalView(value, 'agent_fixture')).toBe(false);
        value = fixture(); value.snapshot!.sections.events.items[0].firstSeen = '2026-10-03T11:30:00Z'; expect(validOperationalView(value, 'agent_fixture')).toBe(false);
    });
    it('rejects per-section item overflow and a snapshot above 48 KiB', () => {
        const value = fixture(); const section = value.snapshot!.sections.software;
        section.items = Array.from({ length: 257 }, () => ({ name: 'a', version: 'v', architecture: 'all', manager: 'dpkg' })); section.meta.observedCount = 257;
        expect(validOperationalView(value, 'agent_fixture')).toBe(false);
        section.items = Array.from({ length: 256 }, (_, i) => ({ name: `${i}-${'x'.repeat(120)}`, version: '1'.repeat(190), architecture: 'amd64', manager: 'dpkg' })); section.meta.observedCount = 256;
        expect(validOperationalView(value, 'agent_fixture')).toBe(false);
    });
    it('bounds combined snapshot and last-good logical bytes after validating each section', () => {
        const base = fixture(); const original = base.snapshot!.sections;
        const retained: OperationalSections = {
            volumes: { meta: { ...original.volumes.meta, observedCount: 32 }, items: Array.from({ length: 32 }, (_, i) => ({ ...original.volumes.items[0], id: `mount_${i + 1}`, mountPoint: `/fixture-${i}-${'x'.repeat(140)}` })) },
            network: { meta: { ...original.network.meta, observedCount: 32 }, items: Array.from({ length: 32 }, (_, i) => ({ ...original.network.items[0], name: `fixture${i}${'x'.repeat(50)}` })) },
            services: { meta: meta('services', 128), items: Array.from({ length: 128 }, (_, i) => ({ ...original.services.items[0], name: `fixture${i}${'x'.repeat(108)}.service` })) },
            processes: { meta: { ...original.processes.meta, observedCount: 64 }, items: Array.from({ length: 64 }, (_, i) => ({ ...original.processes.items[0], pid: i + 1, name: `fixture${i}${'x'.repeat(50)}` })) },
            software: { meta: meta('software', 100), items: Array.from({ length: 100 }, (_, i) => ({ ...original.software.items[0], name: `fixture${i}${'x'.repeat(110)}`, version: '1'.repeat(192), architecture: 'a'.repeat(32) })) },
            events: { meta: meta('events', 64), items: Array.from({ length: 64 }, (_, i) => ({ ...original.events.items[0], source: 'agent', count: 1, unit: `fixture${i}${'x'.repeat(108)}.service`, messageId: 'a'.repeat(32) })) },
        };
        for (const name of SECTION_NAMES) {
            retained[name].meta.quality = 'stale';
            expect(validOperationalView({ ...base, lastGood: { ...base.lastGood, [name]: retained[name] } }, 'agent_fixture')).toBe(true);
        }
        const value = fixture(); value.lastGood = retained;
        value.snapshot!.sections.software = { ...retained.software, meta: { ...retained.software.meta, quality: 'healthy', observedCount: 80 }, items: retained.software.items.slice(0, 80) };
        expect(validOperationalView({ ...value, lastGood: base.lastGood }, 'agent_fixture')).toBe(true);
        expect(validOperationalView(value, 'agent_fixture')).toBe(false);
    });
    it('rejects unavailable sections posing as complete and fake assessed CVEs', () => {
        let value = fixture(); value.snapshot!.sections.volumes.meta.quality = 'unknown'; expect(validOperationalView(value, 'agent_fixture')).toBe(false);
        value = fixture(); (value.assessments.vulnerabilities as { quality: string }).quality = 'healthy'; expect(validOperationalView(value, 'agent_fixture')).toBe(false);
    });
    it('accepts bounded partial coverage and known-good retained data', () => {
        const value = fixture(); const latest = value.snapshot!.sections.services;
        value.lastGood.services = structuredClone(latest);
        latest.meta = { ...latest.meta, quality: 'denied', reason: 'permission_denied', complete: false, observedCount: 0 }; latest.items = [];
        const packages = value.snapshot!.sections.software;
        packages.meta = { ...packages.meta, complete: false, truncated: true, countExact: false, observedCount: 450, reason: 'item_limit' };
        expect(validOperationalView(value, 'agent_fixture')).toBe(true);
    });
    it('binds current sections to a generation and preserves independent retained generations', () => {
        const value = fixture(); value.snapshot!.durationMs = 20000;
        value.lastGood.services = structuredClone(value.snapshot!.sections.services);
        value.lastGood.services.meta.generationId = `sample_${'b'.repeat(32)}`;
        value.lastGood.services.meta.observedAt = '2026-10-03T11:30:00Z';
        expect(validOperationalView(value, 'agent_fixture')).toBe(true);
        value.snapshot!.sections.services.meta.generationId = `sample_${'c'.repeat(32)}`;
        expect(validOperationalView(value, 'agent_fixture')).toBe(false);
    });
    it('uses server time and monotonic elapsed time rather than the browser clock', () => {
        vi.spyOn(Date, 'now').mockReturnValue(0);
        const value = fixture(); expect(effectiveOperationalStatus(value, 0)).toBe('fresh');
        expect(effectiveOperationalStatus(value, 111000)).toBe('stale');
        expect(operationalNow(value, -9999)).toBe(Date.parse(serverNow));
        vi.spyOn(Date, 'now').mockReturnValue(Number.MAX_SAFE_INTEGER);
        expect(effectiveOperationalStatus(value, 0)).toBe('fresh');
        expect(effectiveOperationalStatus({ ...value, status: 'revoked' }, 0)).toBe('revoked');
    });
});

describe('read-only operational inventory', () => {
    it('loads via the protected API and renders all six bounded tables without other calls', async () => {
        render(<OperationalInventoryPanel deviceId="agent_fixture"/>);
        await screen.findByText('/fixture');
        expect(request).toHaveBeenCalledWith('/devices/agent_fixture/operational', { signal: expect.any(AbortSignal) });
        for (const [name, content] of [['Network', 'fixture0'], ['Services', 'fixture.service'], ['Processes', 'fixture-process'], ['Software', 'fixture-package'], ['Events', 'systemd-journal']]) {
            fireEvent.click(sectionButton(name)); expect(screen.getByText(content)).toBeVisible();
        }
        expect(screen.getByText(/Message text is never included/)).toBeVisible();
        expect(request).toHaveBeenCalledOnce(); expect(screen.getAllByText('Unknown · Not assessed')).toHaveLength(2);
        expect(screen.getByText(/These observations stay outside AI evidence/)).toBeVisible();
        expect(screen.getByText('Agent-visible namespace only; the service sandbox can limit mounts, processes and journals.')).toBeVisible();
    });
    it('does not replace unknown measurements with zero or imply absent vulnerabilities', async () => {
        render(<OperationalInventoryPanel deviceId="agent_fixture"/>); await screen.findByText('/fixture');
        const row = screen.getByText('/fixture').closest('tr')!;
        expect(within(row).getAllByText('Unknown')).toHaveLength(4); expect(within(row).queryByText('0%')).not.toBeInTheDocument();
        expect(screen.queryByText(/No vulnerabilities|Up to date|Secure/)).not.toBeInTheDocument();
        fireEvent.click(sectionButton('Processes')); expect(screen.getByText(/CPU time is cumulative/)).toBeVisible();
    });
    it.each(['not_configured', 'awaiting', 'revoked', 'unavailable'] as const)('shows explicit %s state without fake runtime inventory', async status => {
        vi.mocked(request).mockResolvedValue(unavailable(status)); render(<OperationalInventoryPanel deviceId="agent_fixture"/>);
        await screen.findByText('No current records are available.'); expect(screen.queryByText('/fixture')).not.toBeInTheDocument();
        expect(screen.queryByText('Complete coverage')).not.toBeInTheDocument(); expect(screen.getAllByText('Unknown · Not assessed')).toHaveLength(2);
    });
    it('keeps unsupported collection explicit', async () => {
        const value = fixture(); value.snapshot!.sections.events = { meta: { ...meta('events', 0), quality: 'unknown', reason: 'not_supported', complete: false }, items: [] };
        vi.mocked(request).mockResolvedValue(value); render(<OperationalInventoryPanel deviceId="agent_fixture"/>); await screen.findByText('/fixture'); fireEvent.click(sectionButton('Events'));
        expect(screen.getAllByText(/Not supported/).length).toBeGreaterThan(0); expect(screen.getByText('Incomplete coverage')).toBeVisible(); expect(screen.queryByText('Complete coverage')).not.toBeInTheDocument();
    });
    it('shows current denial plus the original last-good time and stale records', async () => {
        const value = fixture(); value.lastGood.services = structuredClone(value.snapshot!.sections.services); value.lastGood.services.meta.observedAt = '2026-10-03T11:30:00Z';
        value.snapshot!.sections.services = { meta: { ...meta('services', 0), quality: 'denied', reason: 'permission_denied', complete: false }, items: [] };
        vi.mocked(request).mockResolvedValue(value); render(<OperationalInventoryPanel deviceId="agent_fixture"/>); await screen.findByText('/fixture'); fireEvent.click(sectionButton('Services'));
        expect(screen.getByText('fixture.service')).toBeVisible(); expect(screen.getByText(/Latest attempt:.*Permission denied/)).toBeVisible(); expect(screen.getByText(/Showing the last successful observation/)).toBeVisible();
        expect(screen.getByText('03/10/2026, 11:30:00 UTC')).toBeVisible(); expect(screen.getAllByText('Retained / stale').length).toBeGreaterThan(0);
    });
    it('reports count lower bounds and truncation without fictitious pagination', async () => {
        const value = fixture(); value.snapshot!.sections.software.meta = { ...meta('software', 1200), complete: false, truncated: true, countExact: false, reason: 'item_limit' };
        vi.mocked(request).mockResolvedValue(value); render(<OperationalInventoryPanel deviceId="agent_fixture"/>); await screen.findByText('/fixture'); fireEvent.click(sectionButton('Software'));
        expect(screen.getByText('At least')).toBeVisible(); expect(screen.getByText('1,200 discovered')).toBeVisible(); expect(screen.getByText('1 records received')).toBeVisible(); expect(screen.getByText('256')).toBeVisible(); expect(screen.getByText('Truncated sample')).toBeVisible();
        expect(screen.queryByRole('button', { name: /next|page/i })).not.toBeInTheDocument();
        fireEvent.change(screen.getByRole('searchbox'), { target: { value: 'missing-package' } });
        expect(screen.getByText('No received records match this filter.')).toBeVisible(); expect(screen.getByText('0 matches in this received sample')).toBeVisible();
        expect(screen.getByText(/sample; cannot prove absence/)).toBeVisible(); expect(request).toHaveBeenCalledOnce();
    });
    it('distinguishes loaded system services and grouped source-event counts', async () => {
        render(<OperationalInventoryPanel deviceId="agent_fixture"/>); await screen.findByText('/fixture');
        fireEvent.click(sectionButton('Services'));
        expect(screen.getByText('Loaded system service units only. Unloaded installed units and per-user services are outside this collection.')).toBeVisible();
        fireEvent.click(sectionButton('Events')); expect(screen.getByText('2 source events discovered')).toBeVisible(); expect(screen.getByText('1 event groups received')).toBeVisible();
        act(() => setLocale('de', false)); fireEvent.click(sectionButton('Dienste'));
        expect(screen.getByText(/Nur geladene Systemdienst-Units/)).toBeVisible();
    });
    it('renders hostile source strings as inert text', async () => {
        const value = fixture(); const attack = '<img src=x onerror=alert(1)>'; value.snapshot!.sections.processes.items[0].name = attack;
        vi.mocked(request).mockResolvedValue(value); const { container } = render(<OperationalInventoryPanel deviceId="agent_fixture"/>); await screen.findByText('/fixture'); fireEvent.click(sectionButton('Processes'));
        expect(screen.getByText(attack)).toBeVisible(); expect(container.querySelector('img,script')).toBeNull();
    });
    it('does not replace a successfully observed empty list with older retained records', async () => {
        const value = fixture(); value.lastGood.services = structuredClone(value.snapshot!.sections.services);
        value.snapshot!.sections.services = { meta: meta('services', 0), items: [] };
        vi.mocked(request).mockResolvedValue(value); render(<OperationalInventoryPanel deviceId="agent_fixture"/>); await screen.findByText('/fixture');
        fireEvent.click(sectionButton('Services'));
        expect(screen.getByText('No eligible records were observed in this collection.')).toBeVisible();
        expect(screen.queryByText('fixture.service')).not.toBeInTheDocument(); expect(screen.queryByText(/Showing the last successful observation/)).not.toBeInTheDocument();
    });
    it('renders complete observed empty lists distinctly from missing data', async () => {
        const value = fixture(); value.snapshot!.sections.volumes = { meta: meta('volumes', 0), items: [] };
        vi.mocked(request).mockResolvedValue(value); render(<OperationalInventoryPanel deviceId="agent_fixture"/>);
        expect(await screen.findByText('No eligible records were observed in this collection.')).toBeVisible(); expect(screen.getByText('Complete coverage')).toBeVisible();
    });
    it('supports German and live locale switching without another inventory request', async () => {
        setLocale('de', false); render(<OperationalInventoryPanel deviceId="agent_fixture"/>); await screen.findByText('/fixture');
        expect(screen.getByRole('heading', { name: 'Betriebsinventar' })).toBeVisible(); expect(screen.getByText(/sichtbarer Agent-Namensraum/)).toBeVisible(); expect(screen.getAllByText('Unbekannt · Nicht bewertet')).toHaveLength(2);
        act(() => setLocale('en', false)); expect(screen.getByRole('heading', { name: 'Operational inventory' })).toBeVisible(); expect(request).toHaveBeenCalledOnce();
    });
});

describe('private inventory lifecycle', () => {
    it('rejects malformed private data with fixed local error copy', async () => {
        const value = fixture(); value.snapshot!.sections.volumes.items[0].mountPoint = 'PRIVATE_SOURCE\nSECRET'; vi.mocked(request).mockResolvedValue(value);
        render(<OperationalInventoryPanel deviceId="agent_fixture"/>); expect(await screen.findByRole('alert')).toHaveTextContent('unsupported or invalid'); expect(screen.queryByText(/PRIVATE_SOURCE/)).not.toBeInTheDocument();
    });
    it('never renders raw server errors', async () => {
        vi.mocked(request).mockRejectedValue(new APIError('SECRET INTERNAL ERROR', 500)); render(<OperationalInventoryPanel deviceId="agent_fixture"/>);
        expect(await screen.findByRole('alert')).toHaveTextContent('Operational inventory could not be loaded'); expect(screen.queryByText(/SECRET/)).not.toBeInTheDocument();
    });
    it('clears data immediately on device change, aborts the previous request and ignores its late result', async () => {
        const first = defer<OperationalView>(); const second = defer<OperationalView>(); vi.mocked(request).mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise);
        const { rerender } = render(<OperationalInventoryPanel deviceId="agent_fixture"/>); const signal = vi.mocked(request).mock.calls[0][1]!.signal!;
        rerender(<OperationalInventoryPanel deviceId="agent_second"/>); expect(signal.aborted).toBe(true);
        await act(async () => first.resolve(fixture())); expect(screen.queryByText('/fixture')).not.toBeInTheDocument();
        const next = fixture('agent_second'); next.snapshot!.sections.volumes.items[0].mountPoint = '/second'; await act(async () => second.resolve(next));
        expect(screen.getByText('/second')).toBeVisible(); expect(screen.queryByText('/fixture')).not.toBeInTheDocument();
    });
    it('clears received data and filter state when the session key changes', async () => {
        const { rerender } = render(<OperationalInventoryPanel deviceId="agent_fixture" sessionKey={1}/>); await screen.findByText('/fixture');
        fireEvent.change(screen.getByRole('searchbox'), { target: { value: 'private filter' } }); const pending = defer<OperationalView>(); vi.mocked(request).mockReturnValue(pending.promise);
        rerender(<OperationalInventoryPanel deviceId="agent_fixture" sessionKey={2}/>); expect(screen.queryByRole('searchbox')).not.toBeInTheDocument(); expect(screen.queryByText('/fixture')).not.toBeInTheDocument();
        await act(async () => pending.resolve(fixture())); expect(screen.getByRole('searchbox')).toHaveValue('');
    });
    it('clears displayed data on the shared authentication boundary event', async () => {
        render(<OperationalInventoryPanel deviceId="agent_fixture"/>); await screen.findByText('/fixture');
        act(() => window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT)));
        expect(screen.queryByText('/fixture')).not.toBeInTheDocument(); expect(screen.getByRole('alert')).toHaveTextContent('Your session has ended'); expect(screen.getByRole('button', { name: 'Refresh observations' })).toBeDisabled();
    });
    it('does not revive an in-flight response after an authentication loss', async () => {
        const pending = defer<OperationalView>(); vi.mocked(request).mockReturnValue(pending.promise); render(<OperationalInventoryPanel deviceId="agent_fixture"/>);
        act(() => window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT))); await act(async () => pending.resolve(fixture()));
        expect(screen.queryByText('/fixture')).not.toBeInTheDocument(); expect(screen.getByRole('alert')).toHaveTextContent('Your session has ended');
    });
    it('uses fixed 401 and 404 messages and prevents refreshing an expired session', async () => {
        vi.mocked(request).mockRejectedValue(new APIError('do not echo', 401)); const first = render(<OperationalInventoryPanel deviceId="agent_fixture"/>);
        expect(await screen.findByRole('alert')).toHaveTextContent('Your session has ended'); expect(screen.getByRole('button', { name: 'Refresh observations' })).toBeDisabled(); first.unmount();
        vi.mocked(request).mockRejectedValue(new APIError('do not echo', 404)); render(<OperationalInventoryPanel deviceId="agent_fixture"/>);
        expect(await screen.findByRole('alert')).toHaveTextContent('This device is no longer available');
    });
    it.each(['focus', 'pageshow', 'visibilitychange'])('clears a restored %s page and reacquires the server anchor', async eventName => {
        const pending = defer<OperationalView>();
        vi.mocked(request).mockResolvedValueOnce(fixture()).mockReturnValueOnce(pending.promise);
        render(<OperationalInventoryPanel deviceId="agent_fixture"/>); await screen.findByText('/fixture');
        if (eventName === 'visibilitychange') vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('visible');
        const event = eventName === 'pageshow' ? new PageTransitionEvent('pageshow', { persisted: true }) : new Event(eventName);
        act(() => { (eventName === 'visibilitychange' ? document : window).dispatchEvent(event); });
        expect(screen.queryByText('/fixture')).not.toBeInTheDocument();
        expect(screen.queryByText('Within collection window')).not.toBeInTheDocument();
        await act(async () => pending.resolve(fixture()));
        expect(screen.getByText('/fixture')).toBeVisible(); expect(request).toHaveBeenCalledTimes(2);
    });
    it('starts no request while hidden and fetches only after visibility returns', async () => {
        let visibility: DocumentVisibilityState = 'hidden';
        vi.spyOn(document, 'visibilityState', 'get').mockImplementation(() => visibility);
        render(<OperationalInventoryPanel deviceId="agent_fixture"/>);
        expect(request).not.toHaveBeenCalled(); visibility = 'visible';
        act(() => document.dispatchEvent(new Event('visibilitychange')));
        expect(await screen.findByText('/fixture')).toBeVisible(); expect(request).toHaveBeenCalledOnce();
    });
    it('ignores the first response after hiding, then displays only the restored response', async () => {
        const initial = defer<OperationalView>(); const restored = defer<OperationalView>();
        vi.mocked(request).mockReturnValueOnce(initial.promise).mockReturnValueOnce(restored.promise);
        let visibility: DocumentVisibilityState = 'visible';
        vi.spyOn(document, 'visibilityState', 'get').mockImplementation(() => visibility);
        render(<OperationalInventoryPanel deviceId="agent_fixture"/>);
        visibility = 'hidden'; act(() => document.dispatchEvent(new Event('visibilitychange')));
        await act(async () => initial.resolve(fixture())); expect(screen.queryByText('/fixture')).not.toBeInTheDocument();
        visibility = 'visible'; act(() => document.dispatchEvent(new Event('visibilitychange')));
        const response = fixture(); response.snapshot!.sections.volumes.items[0].mountPoint = '/restored';
        await act(async () => restored.resolve(response)); expect(screen.getByText('/restored')).toBeVisible();
        expect(screen.queryByText('/fixture')).not.toBeInTheDocument(); expect(request).toHaveBeenCalledTimes(2);
    });
    it('does not retry a locked session after page restoration', async () => {
        render(<OperationalInventoryPanel deviceId="agent_fixture"/>); await screen.findByText('/fixture');
        act(() => window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT)));
        act(() => { window.dispatchEvent(new Event('pagehide')); window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true })); window.dispatchEvent(new Event('focus')); });
        expect(screen.getByRole('alert')).toHaveTextContent('Your session has ended'); expect(request).toHaveBeenCalledOnce();
    });
    it('renders unknown age and stale status for a future collection anchor', async () => {
        const response = fixture(); response.snapshot!.collectedAt = '2026-10-03T12:00:20Z';
        for (const name of SECTION_NAMES) response.snapshot!.sections[name].meta.observedAt = response.snapshot!.collectedAt;
        vi.mocked(request).mockResolvedValue(response); render(<OperationalInventoryPanel deviceId="agent_fixture"/>); await screen.findByText('/fixture');
        expect(screen.queryByText('Within collection window')).not.toBeInTheDocument();
        const age = screen.getByText('Observation age').parentElement!;
        expect(within(age).getByText('Unknown')).toBeVisible(); expect(age).not.toHaveTextContent('0 s');
        expect(effectiveOperationalStatus(response, 30000)).toBe('stale');
    });
    it('ages a visible snapshot with monotonic elapsed time while the browser wall clock is wrong', async () => {
        vi.useFakeTimers(); let monotonic = 1000; vi.spyOn(performance, 'now').mockImplementation(() => monotonic);
        vi.spyOn(Date, 'now').mockReturnValue(0);
        render(<OperationalInventoryPanel deviceId="agent_fixture"/>);
        await act(async () => { await Promise.resolve(); });
        expect(screen.getByText('Within collection window')).toBeVisible();
        monotonic += 111000;
        await act(async () => { vi.advanceTimersByTime(1000); });
        expect(screen.queryByText('Within collection window')).not.toBeInTheDocument();
        expect(screen.getAllByText('Stale observation').length).toBeGreaterThan(0);
        expect(screen.getByText('/fixture')).toBeVisible(); expect(request).toHaveBeenCalledOnce();
    });
    it('aborts on unmount', () => { const pending = defer<OperationalView>(); vi.mocked(request).mockReturnValue(pending.promise); const { unmount } = render(<OperationalInventoryPanel deviceId="agent_fixture"/>); const signal = vi.mocked(request).mock.calls[0][1]!.signal!; unmount(); expect(signal.aborted).toBe(true); });
    it('times out a stalled request and ignores a late response', async () => {
        vi.useFakeTimers(); const pending = defer<OperationalView>(); vi.mocked(request).mockReturnValue(pending.promise); render(<OperationalInventoryPanel deviceId="agent_fixture"/>);
        await act(async () => { vi.advanceTimersByTime(10000); }); expect(screen.getByRole('alert')).toHaveTextContent('did not respond in time');
        await act(async () => pending.resolve(fixture())); expect(screen.queryByText('/fixture')).not.toBeInTheDocument();
    });
    it('retries explicitly and clears the previous failure', async () => {
        vi.mocked(request).mockRejectedValueOnce(new APIError('no connection')).mockResolvedValueOnce(fixture()); render(<OperationalInventoryPanel deviceId="agent_fixture"/>); await screen.findByRole('alert');
        fireEvent.click(screen.getByRole('button', { name: 'Refresh observations' })); await screen.findByText('/fixture'); expect(screen.queryByRole('alert')).not.toBeInTheDocument();
        await waitFor(() => expect(request).toHaveBeenCalledTimes(2));
    });
    it('does not read or persist inventory in browser storage', async () => {
        const storage = vi.spyOn(Storage.prototype, 'setItem'); render(<OperationalInventoryPanel deviceId="agent_fixture"/>); await screen.findByText('/fixture'); expect(storage).not.toHaveBeenCalled();
    });
});

// Keep the explicit contract fixtures complete if a section is added later.
it('includes exactly the bounded section keys', () => {
    const sections: OperationalSections = fixture().snapshot!.sections;
    expect(Object.keys(sections)).toEqual([...SECTION_NAMES]);
});
