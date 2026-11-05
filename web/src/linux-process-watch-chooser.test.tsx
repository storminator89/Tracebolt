import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, mutateRaw, request } from './api';
import { useOperator } from './auth';
import { overviewPage, overviewView, processRows } from './complete-overview-fixtures';
import { validOverviewView } from './complete-overview-types';
import { setLocale } from './i18n';
import { matchingProcessOverview } from './linux-process-watch-chooser';
import { processDevice, processEnabled, processNow, processView } from './linux-process-watches-fixtures';
import { LinuxProcessWatches } from './linux-process-watches';
import type { ProcessWatchesView } from './linux-process-watches-types';
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutateRaw: vi.fn() }));
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
const operator = { mode: 'lan' as const, authenticated: true, expiresAt: '2026-11-04T14:00:00Z', insecureTestMode: false, logout: vi.fn(), theme: 'light' as const, setTheme: vi.fn() };
const flush = () => act(async () => {});
const advance = (ms: number) => act(async () => { await vi.advanceTimersByTimeAsync(ms); });
function toggle(open: boolean) { const panel = document.querySelector('details.linux-process-watches') as HTMLDetailsElement; panel.open = open; fireEvent(panel, new Event('toggle')); }
function fixture(count = 3) {
    const watch = processView(), inventory = overviewView(count, 0), rows = processRows(count), g = watch.source.generation!;
    inventory.deviceId = processDevice; inventory.serverNow = processNow; g.totalRows = count;
    for (const section of ['processes', 'volumes'] as const) {
        const c = inventory[section].complete!;
        c.manifest.captureStartedAt = g.captureStartedAt; c.manifest.captureFinishedAt = g.captureFinishedAt; c.manifest.collectedAt = g.captureStartedAt;
        c.completedAt = g.receivedAt; c.retainedUntil = new Date(Date.parse(g.captureStartedAt) + 86400000).toISOString();
    }
    const c = inventory.processes.complete!;
    c.binding = { section: 'processes', sequence: g.sequence, generationId: g.generationId, manifestHash: g.manifestHash }; c.manifest.generationId = g.generationId;
    return { watch, inventory, rows };
}
async function start(f = fixture()) {
    vi.mocked(request).mockImplementation(async path => path.endsWith('/inventory/overview') ? f.inventory : f.watch);
    vi.mocked(mutateRaw).mockImplementation(async (_path, raw) => overviewPage(f.inventory, f.rows, [], raw));
    render(<LinuxProcessWatches deviceId={processDevice}/>); toggle(true); await flush();
    return f;
}
async function choose() { fireEvent.click(screen.getByRole('button', { name: 'Choose observed process names' })); await flush(); }
function draft() { return screen.getByLabelText('Exact process names, one per line'); }
function nextWatch(watch: ProcessWatchesView, seconds = 31) { const v = structuredClone(watch); v.serverNow = new Date(Date.parse(processNow) + seconds * 1000).toISOString(); v.validUntil = new Date(Date.parse(v.serverNow) + 30000).toISOString(); return v; }
beforeEach(() => { vi.useFakeTimers(); vi.setSystemTime(processNow); localStorage.clear(); sessionStorage.clear(); setLocale('en', false); vi.spyOn(document, 'hasFocus').mockReturnValue(true); vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('visible'); vi.mocked(useOperator).mockReturnValue(operator); vi.mocked(request).mockReset(); vi.mocked(mutateRaw).mockReset(); });
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.restoreAllMocks(); });

describe('Observed process name selection', () => {
    it('uses only observed literal names, combines duplicates and keeps consent separate', async () => {
        const f = fixture(4); f.rows[0].process!.name = ' Worker '; f.rows[1].process!.name = ' Worker '; f.rows[2].process!.name = 'näme'; f.rows[2].process!.state = 'zombie';
        f.rows[3].process = { pid: 4, parentPid: null, name: null, state: null, rssBytes: null, cpuTimeSeconds: null, threads: null, observation: { status: 'exited', reason: 'process_gone' } };
        f.inventory.processes.complete!.manifest.processes.fieldCoverage.observed--; f.inventory.processes.complete!.manifest.processes.fieldCoverage.exited++; f.watch.source.generation!.unidentifiedRows++;
        expect(validOverviewView(f.inventory, processDevice)).toBe(true); await start(f); expect(mutateRaw).not.toHaveBeenCalled(); await choose();
        const choices = screen.getByRole('region', { name: 'Names observed in this snapshot' }); expect(within(choices).getAllByRole('checkbox')).toHaveLength(2);
        fireEvent.click(within(choices).getByRole('checkbox', { name: 'Worker (Whitespace positions: 1 (U+0020), 8 (U+0020))' })); fireEvent.click(within(choices).getByRole('checkbox', { name: 'näme' })); expect(draft()).toHaveValue(' Worker \nnäme');
        expect(vi.mocked(mutateRaw).mock.calls.every(([path, raw]) => path.endsWith('/inventory/overview/query') && JSON.parse(raw).limit === 100)).toBe(true);
        fireEvent.click(screen.getByRole('button', { name: 'Review process monitoring' })); expect(screen.getByRole('checkbox')).not.toBeChecked(); expect(screen.getByRole('button', { name: 'Enable this reviewed policy' })).toBeDisabled();
    });
    it('gives literal whitespace variants distinct visible metadata and accessible checkbox names', async () => {
        const f = fixture(8), names = ['worker', ' worker', 'worker ', ' ', '  ', 'a b', 'a  b', 'a\u00a0b']; f.rows.forEach((row, index) => { row.process!.name = names[index]; }); await start(f); await choose();
        const labels = ['worker', 'worker (Whitespace positions: 1 (U+0020))', 'worker (Whitespace positions: 7 (U+0020))', '(Whitespace positions: 1 (U+0020))', '(Whitespace positions: 1 (U+0020), 2 (U+0020))', 'a b (Whitespace positions: 2 (U+0020))', 'a b (Whitespace positions: 2 (U+0020), 3 (U+0020))', 'a\u00a0b (Whitespace positions: 2 (U+00A0))'];
        for (const label of labels) expect(screen.getByRole('checkbox', { name: label })).toHaveAccessibleName(label);
        expect(screen.getByText('Whitespace positions: 2 (U+00A0)')).toBeVisible(); fireEvent.click(screen.getByRole('checkbox', { name: '(Whitespace positions: 1 (U+0020))' })); expect(draft()).toHaveValue(' ');
        fireEvent.click(screen.getByRole('button', { name: 'Review process monitoring' })); expect(screen.getByRole('region', { name: 'Review this exact local change' })).toHaveTextContent('Whitespace positions: 1 (U+0020)');
    });
    it('pages within one generation, keeps selected names and never presents global name counts', async () => {
        const f = await start(fixture(101)); await choose(); expect(screen.getAllByRole('checkbox')).toHaveLength(100);
        fireEvent.click(screen.getByRole('checkbox', { name: f.rows[0].process!.name! })); fireEvent.click(screen.getByRole('button', { name: 'Next process names' })); await flush();
        expect(screen.getAllByRole('checkbox')).toHaveLength(1); expect(draft()).toHaveValue(f.rows[0].process!.name); expect(screen.queryByRole('button', { name: 'Next process names' })).toBeNull();
        expect(screen.getByText(/^Names from this page only/)).toBeVisible(); expect(vi.mocked(mutateRaw).mock.calls[1][1]).toContain('cursor_100');
    });
    it('limits selection to eight unique names and preserves manual exact fallback', async () => {
        await start(fixture(9)); await choose(); const boxes = screen.getAllByRole('checkbox'); boxes.slice(0, 8).forEach(box => fireEvent.click(box)); expect(boxes[8]).toBeDisabled();
        fireEvent.click(boxes[0]); expect(boxes[8]).not.toBeDisabled(); fireEvent.change(draft(), { target: { value: ' Z \nz\n Z ' } });
        fireEvent.click(screen.getByRole('button', { name: 'Review process monitoring' })); const review = screen.getByRole('region', { name: 'Review this exact local change' }); expect(review.querySelectorAll('li')).toHaveLength(2); expect(review).toHaveTextContent('Z');
    });
    it.each(['sequence', 'hash', 'newer_failure', 'newer_pending', 'old_capture'] as const)('refuses a %s inventory source without querying rows', async kind => {
        const f = fixture(), c = f.inventory.processes.complete!;
        if (kind === 'sequence') c.binding.sequence = '4';
        if (kind === 'hash') c.binding.manifestHash = 'd'.repeat(64);
        if (kind === 'newer_failure') f.inventory.processes.failure = { sequence: '4', generationId: `sample_${'f'.repeat(32)}`, attemptedAt: processNow, receivedAt: processNow, reason: 'read_failed' };
        if (kind === 'newer_pending') f.inventory.processes.transfer = { binding: { ...c.binding, sequence: '4' }, manifest: c.manifest, state: 'pending', declaredRows: c.manifest.observedCount, acceptedRows: 0, expectedChunks: c.manifest.chunkCount, acceptedChunks: 0, collectedAt: c.manifest.collectedAt, startedAt: processNow, expiresAt: '2026-11-04T12:10:00Z' };
        if (kind === 'old_capture') c.manifest.captureStartedAt = c.manifest.collectedAt = '2026-11-04T10:00:00Z';
        await start(f); await choose(); expect(screen.getByText(/^Names are unavailable/)).toBeVisible(); expect(screen.queryByRole('checkbox')).toBeNull(); expect(mutateRaw).not.toHaveBeenCalled(); expect(draft()).toBeEnabled();
    });
    it('rechecks watch authority after the page and withholds changed or incomplete sources', async () => {
        const f = await start(); const changed = structuredClone(f.watch); changed.source = { ...changed.source, status: 'unknown', reason: 'newer_attempt', generation: null };
        vi.mocked(request).mockImplementation(async path => path.endsWith('/inventory/overview') ? f.inventory : changed); await choose();
        expect(screen.queryByRole('checkbox')).toBeNull(); expect(screen.getByText(/^Names are unavailable/)).toBeVisible(); expect(mutateRaw).toHaveBeenCalledTimes(1);
    });
    it.each(['replacement', 'read_only'] as const)('clears parent draft and authority immediately on a proven %s during paging', async change => {
        const f = await start(fixture(101)); await choose(); fireEvent.click(screen.getAllByRole('checkbox')[0]); expect(draft()).not.toHaveValue('');
        const current = structuredClone(f.watch); if (change === 'replacement') current.source.token = `processsource_${'f'.repeat(32)}`; else current.canManage = false;
        vi.mocked(request).mockImplementation(async path => path.endsWith('/inventory/overview') ? f.inventory : current); fireEvent.click(screen.getByRole('button', { name: 'Next process names' })); await flush();
        expect(screen.queryByRole('textbox')).toBeNull(); expect(screen.queryByRole('button', { name: 'Review process monitoring' })).toBeNull(); expect(screen.getByText('Private view cleared. Reload in the visible window.')).toBeVisible();
        vi.mocked(request).mockResolvedValue({ ...current, canManage: true }); fireEvent.click(screen.getByRole('button', { name: 'Reload process watches' })); await flush(); expect(draft()).toHaveValue('');
        expect(vi.mocked(mutateRaw).mock.calls.every(([path]) => path.endsWith('/inventory/overview/query'))).toBe(true);
    });
    it('rejects cursor replay and a repeated page rather than appending misleading options', async () => {
        const f = await start(fixture(201)); await choose(); const first = overviewPage(f.inventory, f.rows, [], JSON.stringify({ section: 'processes', cursor: '', search: '', limit: 100 }));
        vi.mocked(mutateRaw).mockResolvedValue(first); fireEvent.click(screen.getByRole('button', { name: 'Next process names' })); await flush(); expect(screen.queryByRole('checkbox')).toBeNull(); expect(screen.getByText(/^Names are unavailable/)).toBeVisible();
    });
    it('uses Enter to search without submitting the monitoring review', async () => {
        await start(); await choose(); fireEvent.change(draft(), { target: { value: 'manual-name' } }); const search = screen.getByLabelText('Find a process name or PID');
        fireEvent.change(search, { target: { value: '000001' } }); fireEvent.keyDown(search, { key: 'Enter' }); await flush();
        expect(screen.getAllByRole('checkbox')).toHaveLength(1); expect(screen.queryByRole('region', { name: 'Review this exact local change' })).toBeNull(); expect(vi.mocked(mutateRaw).mock.calls.at(-1)![1]).toContain('000001');
    });
    it('aborts search on input change and drops late pages without retry or collecting', async () => {
        const f = await start(); let finish!: (value: unknown) => void; vi.mocked(mutateRaw).mockImplementation(() => new Promise(resolve => { finish = resolve; })); await choose();
        const signal = vi.mocked(mutateRaw).mock.calls[0][3]; fireEvent.change(screen.getByLabelText('Find a process name or PID'), { target: { value: 'new' } }); expect(signal?.aborted).toBe(true);
        await act(async () => finish(overviewPage(f.inventory, f.rows, [], JSON.stringify({ section: 'processes', cursor: '', search: '', limit: 100 })))); expect(screen.queryByRole('checkbox')).toBeNull(); expect(request).toHaveBeenCalledTimes(2);
    });
    it('drops pending choices on closing, blur or expiry', async () => {
        await start(); await choose(); fireEvent.click(screen.getAllByRole('checkbox')[0]); act(() => window.dispatchEvent(new Event('blur'))); expect(screen.queryByRole('checkbox')).toBeNull(); expect(screen.queryByRole('textbox')).toBeNull();
        act(() => window.dispatchEvent(new Event('focus'))); fireEvent.click(screen.getByRole('button', { name: 'Reload process watches' })); await flush(); expect(draft()).toHaveValue('');
    });
    it('shortens displayed choice lifetime when the final authority lease expires earlier', async () => {
        const f = await start(); const shorter = structuredClone(f.watch); shorter.validUntil = '2026-11-04T12:00:02Z';
        vi.mocked(request).mockImplementation(async path => path.endsWith('/inventory/overview') ? f.inventory : shorter); await choose(); expect(screen.getAllByRole('checkbox')).toHaveLength(3);
        await advance(2000); expect(screen.queryByRole('checkbox')).toBeNull(); expect(screen.getByText(/^Names are unavailable/)).toBeVisible(); expect(draft()).toBeEnabled();
    });
    it('keeps 24-hour retained inventory separate from the strict watch freshness deadline', () => {
        const f = fixture(); expect(matchingProcessOverview(f.inventory, f.watch)).not.toBeNull();
        f.inventory.serverNow = '2026-11-04T12:01:40Z'; expect(matchingProcessOverview(f.inventory, f.watch)).toBeNull();
    });
});

describe('Unconfirmed editing drafts', () => {
    it('prefills saved names and threshold only after choosing edit', async () => {
        const f = fixture(); f.watch = processEnabled(); f.watch.policy.consecutiveFailures = 3; await start(f); expect(screen.queryByRole('textbox')).toBeNull();
        fireEvent.click(screen.getByRole('button', { name: 'Edit monitored processes' })); expect(draft()).toHaveValue('worker'); expect(screen.getByRole('combobox')).toHaveValue('3'); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('preserves an unapproved draft through expiry but requires refresh and fresh unchecked review', async () => {
        const f = await start(); fireEvent.change(draft(), { target: { value: 'custom' } }); fireEvent.change(screen.getByRole('combobox'), { target: { value: '3' } });
        fireEvent.click(screen.getByRole('button', { name: 'Review process monitoring' })); fireEvent.click(screen.getByRole('checkbox')); await advance(31000);
        expect(screen.queryByRole('checkbox')).toBeNull(); expect(draft()).toHaveValue('custom'); expect(draft()).toBeDisabled(); expect(screen.getByRole('button', { name: 'Review process monitoring' })).toBeDisabled();
        vi.mocked(request).mockResolvedValue(nextWatch(f.watch)); fireEvent.click(screen.getByRole('button', { name: 'Reload process watches' })); await flush(); expect(draft()).toHaveValue('custom'); expect(screen.getByRole('combobox')).toHaveValue('3');
        fireEvent.click(screen.getByRole('button', { name: 'Review process monitoring' })); expect(screen.getByRole('checkbox')).not.toBeChecked(); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('clears the retained draft when refreshed source identity changes', async () => {
        const f = await start(); fireEvent.change(draft(), { target: { value: 'private-name' } }); await advance(31000); const next = nextWatch(f.watch); next.source.token = `processsource_${'f'.repeat(32)}`;
        vi.mocked(request).mockResolvedValue(next); fireEvent.click(screen.getByRole('button', { name: 'Reload process watches' })); await flush(); expect(draft()).toHaveValue('');
    });
    it('never extends the saved session boundary when a later manager clock is unreliable', async () => {
        vi.mocked(useOperator).mockReturnValue({ ...operator, expiresAt: '2026-11-04T12:00:40Z' }); const f = await start(); fireEvent.change(draft(), { target: { value: 'private-name' } }); await advance(31000);
        const rollback = structuredClone(f.watch); rollback.clockReliable = false; rollback.serverNow = '2026-11-04T11:59:00Z'; rollback.validUntil = '2026-11-04T11:59:30Z'; rollback.source = { ...rollback.source, status: 'unknown', reason: 'stale', generation: null };
        vi.mocked(request).mockResolvedValue(rollback); fireEvent.click(screen.getByRole('button', { name: 'Reload process watches' })); await flush(); expect(screen.getByText(/^Manager clock is unreliable/)).toBeVisible();
        await advance(10000); expect(screen.queryByRole('textbox')).toBeNull(); expect(screen.getByText('Session ended. Sign in again.')).toBeVisible();
    });
    it('clears the retained draft when the session ends after the view expired', async () => {
        vi.mocked(useOperator).mockReturnValue({ ...operator, expiresAt: '2026-11-04T12:00:40Z' }); await start(); fireEvent.change(draft(), { target: { value: 'private-name' } }); await advance(31000); expect(draft()).toHaveValue('private-name'); await advance(10000);
        expect(screen.queryByRole('textbox')).toBeNull(); expect(screen.getByText('Session ended. Sign in again.')).toBeVisible();
    });
});
