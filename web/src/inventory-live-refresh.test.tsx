import { act, cleanup, fireEvent, render, renderHook, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, APIError, AUTH_REQUIRED_EVENT, hasPendingAPIRequests, mutate, mutateRaw, request } from './api';
import { CompleteOverviewPanel } from './complete-overview';
import { SystemInventoryPanel } from './system-inventory';
import { useCompleteOverview } from './complete-overview-resource';
import { useCompletePackages } from './complete-packages-resource';
import { useCompleteUpdates } from './complete-updates-resource';
import { useSystemInventory } from './system-inventory-resource';
import { overviewPage, overviewView, processRows, volumeRows } from './complete-overview-fixtures';
import { completePage, completeRows, completeView } from './complete-packages-fixtures';
import { updatePage, updateRows, updateView } from './complete-updates-fixtures';
import { serviceRows, socketRows, systemPage, systemView } from './system-inventory-fixtures';
import { validOverviewView } from './complete-overview-types';
import { validCompletePackageView } from './complete-packages-types';
import { validCompleteUpdateView } from './complete-updates-types';
import { validSystemView } from './system-inventory-types';
import type { OverviewPage, OverviewView } from './complete-overview-types';
import type { CompletePackagePage, CompletePackageView } from './complete-packages-types';
import type { CompleteUpdatePage, CompleteUpdateView } from './complete-updates-types';
import type { SystemFilter, SystemPage, SystemView } from './system-inventory-types';
import { InventoryLiveStatus } from './inventory-live-status';
import { setLocale } from './i18n';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), hasPendingAPIRequests: vi.fn(), request: vi.fn(), mutate: vi.fn(), mutateRaw: vi.fn() }));
vi.mock('./auth', async original => ({
    ...await original<typeof import('./auth')>(),
    useOperator: () => ({ mode: 'lan', authenticated: true, loginMode: 'shared', actorId: null, capabilities: ['read'], expiresAt: '2026-10-07T00:00:00Z', insecureTestMode: false }),
}));

type Kind = 'overview' | 'packages' | 'updates' | 'system';
type View = OverviewView | CompletePackageView | CompleteUpdateView | SystemView;
type Page = OverviewPage | CompletePackagePage | CompleteUpdatePage | SystemPage;
type Resource = {
    view: View | null; page: Page | null; scanned: number; matches: number;
    liveState: 'active' | 'paused' | 'retrying'; loading: boolean; error: string | null;
    search: string; elapsed: number; filter?: SystemFilter;
    changeSearch: (value: string) => void; changeFilter?: (value: SystemFilter) => void;
    startSearch: () => void; refresh: () => void; next: () => void;
};
type Fixture = { view: View; page: (raw: string) => Page; valid: () => boolean; generationId: string };
const kinds: Kind[] = ['overview', 'packages', 'updates', 'system'];
const hooks: Record<Kind, (id: string, metadataOnly?: boolean) => Resource> = {
    overview: id => useCompleteOverview(id, 'processes'),
    packages: (id, metadataOnly) => useCompletePackages(id, metadataOnly),
    updates: (id, metadataOnly) => useCompleteUpdates(id, metadataOnly),
    system: id => useSystemInventory(id, 'services', true),
};
const suffix: Record<Kind, string> = { overview: 'overview', packages: 'packages', updates: 'complete-updates', system: 'system' };
const statusBytes: Record<Kind, number> = { overview: 32768, packages: 16384, updates: 16384, system: 16384 };
const at = (time: string, milliseconds: number) => new Date(Date.parse(time) + milliseconds).toISOString();

// Existing synthetic fixtures and production validators remain authoritative. Give
// their sequences room for a newer generation without using lossy Number parsing.
function fixture(kind: Kind, generation = 0, milliseconds = 0): Fixture {
    const generationId = `sample_${(generation ? 'e' : 'a').repeat(32)}`, sequence = String(100 + generation);
    if (kind === 'overview') {
        const view = overviewView(), selected = view.processes.complete!;
        selected.binding = { ...selected.binding, sequence, generationId };
        selected.manifest.generationId = generationId;
        view.serverNow = at(view.serverNow, milliseconds);
        const rows = processRows(); if (generation) rows[0].process!.name = 'fixture-new-process-000000';
        return { view, generationId, valid: () => validOverviewView(view, view.deviceId), page: raw => overviewPage(view, rows, volumeRows(), raw) };
    }
    if (kind === 'packages') {
        const view = completeView(); view.complete!.binding = { ...view.complete!.binding, sequence, generationId }; view.complete!.manifest.generationId = generationId;
        view.serverNow = at(view.serverNow, milliseconds);
        const rows = completeRows(); if (generation) rows[0].version = rows[0].sourceVersion = '2.0';
        return { view, generationId, valid: () => validCompletePackageView(view, view.deviceId), page: raw => completePage(view, rows, raw) };
    }
    if (kind === 'updates') {
        const view = updateView(350); view.complete!.binding = { ...view.complete!.binding, sequence, generationId }; view.complete!.manifest.generationId = generationId;
        view.serverNow = at(view.serverNow, milliseconds);
        const rows = updateRows(350); if (generation) rows[0].candidateVersion = '3:1.0-1';
        return { view, generationId, valid: () => validCompleteUpdateView(view, view.deviceId), page: raw => updatePage(view, rows, raw) };
    }
    const view = systemView(); view.sequence = sequence; view.latest!.generationId = generationId;
    for (const section of ['services', 'sockets'] as const) {
        view.latest![section].generationId = generationId;
        view.lastComplete[section]!.sequence = sequence;
        view.lastComplete[section]!.meta.generationId = generationId;
    }
    view.serverNow = at(view.serverNow, milliseconds);
    const rows = serviceRows(); if (generation) { rows[0].enablement = 'disabled'; rows[1].runtime!.subState = 'exited'; }
    return { view, generationId, valid: () => validSystemView(view, view.deviceId), page: raw => systemPage(view, rows, socketRows(), raw) };
}

function pageGeneration(page: Page | null) { return page && ('binding' in page ? page.binding.generationId : page.generationId); }
function deferred<T>() {
    let resolve!: (value: T) => void, reject!: (error: unknown) => void;
    const promise = new Promise<T>((ok, fail) => { resolve = ok; reject = fail; });
    return { promise, resolve, reject };
}
const flush = () => act(async () => {});
const advance = (ms: number) => act(async () => { await vi.advanceTimersByTimeAsync(ms); });
let latest: Fixture;

async function start(kind: Kind, options: { metadataOnly?: boolean; cursorLifetime?: number } = {}) {
    latest = fixture(kind); expect(latest.valid()).toBe(true);
    vi.setSystemTime(latest.view.serverNow);
    vi.mocked(request).mockImplementation(async path => {
        expect(path).toBe(`/devices/${latest.view.deviceId}/inventory/${suffix[kind]}`);
        return structuredClone(latest.view);
    });
    vi.mocked(mutateRaw).mockImplementation(async (path, raw) => {
        expect(path).toBe(`/devices/${latest.view.deviceId}/inventory/${suffix[kind]}/query`);
        const page = latest.page(raw);
        if (options.cursorLifetime) page.cursorExpiresAt = at(page.serverNow, options.cursorLifetime);
        return page;
    });
    const mounted = renderHook(({ id }) => hooks[kind](id, options.metadataOnly), { initialProps: { id: latest.view.deviceId } });
    await flush();
    expect(mounted.result.current.error).toBeNull();
    if (!options.metadataOnly) expect(mounted.result.current.page).not.toBeNull();
    return mounted;
}

beforeEach(() => {
    vi.useFakeTimers(); setLocale('en', false);
    vi.mocked(request).mockReset(); vi.mocked(mutate).mockReset(); vi.mocked(mutateRaw).mockReset();
    vi.mocked(hasPendingAPIRequests).mockReset().mockReturnValue(false);
});
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.restoreAllMocks(); });

describe.each(kinds)('%s first-page inventory live refresh', kind => {
    it('checks status every 15 seconds without re-querying or rejuvenating an unchanged page', async () => {
        const { result } = await start(kind), original = result.current.page;
        await advance(14999); expect(request).toHaveBeenCalledTimes(1);
        await advance(1); expect(request).toHaveBeenCalledTimes(2);
        await advance(15000); expect(request).toHaveBeenCalledTimes(3);
        expect(mutateRaw).toHaveBeenCalledTimes(1);
        expect(result.current.page).toBe(original);
        expect(result.current.elapsed).toBe(30000);
        expect(result.current.liveState).toBe('active');
        for (const [path, init, maximum] of vi.mocked(request).mock.calls) {
            expect(path).toBe(`/devices/${latest.view.deviceId}/inventory/${suffix[kind]}`);
            expect(init).toEqual({ signal: expect.any(AbortSignal) });
            expect(maximum).toBe(statusBytes[kind]);
        }
    });

    it('expires the original cursor deadline even after a successful unchanged status read', async () => {
        const { result } = await start(kind, { cursorLifetime: 30000 }), page = result.current.page;
        await advance(15000); expect(result.current.page).toBe(page);
        await advance(14999); expect(result.current.page).toBe(page);
        await advance(1); expect(result.current.page).toBeNull(); expect(result.current.error).toBe('restart');
        expect(result.current.liveState).toBe('paused'); expect(mutateRaw).toHaveBeenCalledTimes(1);
        await advance(30000); expect(request).toHaveBeenCalledTimes(2);
    });

    it('stops at the original cursor deadline when authoritative manager time advances faster', async () => {
        const { result } = await start(kind, { cursorLifetime: 30000 });
        latest = fixture(kind, 0, 30000); expect(latest.valid()).toBe(true);
        await advance(15000); expect(result.current.page).toBeNull(); expect(result.current.error).toBe('restart');
        expect(result.current.liveState).toBe('paused'); expect(mutateRaw).toHaveBeenCalledTimes(1);
        await advance(30000); expect(request).toHaveBeenCalledTimes(2);
    });

    it('preserves observation age when manager time advances more slowly than elapsed local time', async () => {
        const { result } = await start(kind), page = result.current.page;
        latest = fixture(kind, 0, 5000); await advance(15000);
        expect(result.current.elapsed + 5000).toBe(15000); expect(result.current.page).toBe(page);
        await advance(15000); expect(result.current.elapsed + 5000).toBe(30000);
        expect(mutateRaw).toHaveBeenCalledTimes(1);
    });

    it('stages a bounded newer first page and commits its metadata and rows together', async () => {
        const { result } = await start(kind), originalPage = result.current.page, originalView = result.current.view;
        const held = deferred<unknown>(); latest = fixture(kind, 1, 15000); expect(latest.valid()).toBe(true);
        vi.mocked(mutateRaw).mockReturnValueOnce(held.promise);
        await advance(15000);
        expect(result.current.page).toBe(originalPage); expect(result.current.view).toBe(originalView);
        expect(result.current.loading).toBe(false);
        const [path, raw, headers, signal, maximum] = vi.mocked(mutateRaw).mock.calls[1];
        expect(path).toBe(`/devices/${latest.view.deviceId}/inventory/${suffix[kind]}/query`);
        expect(JSON.parse(raw)).toMatchObject({ generationId: latest.generationId, cursor: '', search: '', limit: 100 });
        expect(headers).toEqual({}); expect(signal).toBeInstanceOf(AbortSignal); expect(maximum).toBe(262144);
        await advance(4000); expect(request).toHaveBeenCalledTimes(2); expect(result.current.page).toBe(originalPage);
        const replacement = latest.page(raw); await act(async () => held.resolve(replacement));
        expect(result.current.page).toBe(replacement); expect(result.current.view).toEqual(latest.view);
        expect(pageGeneration(result.current.page)).toBe(latest.generationId);
        expect(result.current.scanned).toBe('scannedRows' in replacement ? replacement.scannedRows : replacement.scannedCount);
        expect(result.current.error).toBeNull();
        await advance(15000); expect(request).toHaveBeenCalledTimes(3); expect(mutateRaw).toHaveBeenCalledTimes(2);
    });

    it('keeps the submitted search and service filter across a new complete generation', async () => {
        const { result } = await start(kind);
        act(() => { result.current.changeSearch('fixture'); if (kind === 'system') result.current.changeFilter!('active'); });
        act(() => result.current.startSearch()); await flush();
        expect(result.current.search).toBe('fixture'); expect(result.current.page).not.toBeNull();
        latest = fixture(kind, 1, 15000); await advance(15000);
        const input = JSON.parse(vi.mocked(mutateRaw).mock.calls.at(-1)![1]);
        expect(input).toMatchObject({ generationId: latest.generationId, cursor: '', search: 'fixture' });
        if (kind === 'system') { expect(input.filter).toBe('active'); expect(result.current.filter).toBe('active'); }
        expect(result.current.search).toBe('fixture'); expect(pageGeneration(result.current.page)).toBe(latest.generationId);
    });

    it('pauses while a search is dirty and resumes only after its first-page submission', async () => {
        const { result } = await start(kind);
        act(() => result.current.changeSearch('fixture'));
        expect(result.current.liveState).toBe('paused');
        await advance(45000); expect(request).toHaveBeenCalledTimes(1); expect(mutateRaw).toHaveBeenCalledTimes(1);
        act(() => result.current.startSearch()); await flush(); expect(result.current.liveState).toBe('active');
        await advance(15000); expect(request).toHaveBeenCalledTimes(2); expect(mutateRaw).toHaveBeenCalledTimes(2);
    });

    it('leaves later pages unchanged until an explicit first-page restart', async () => {
        const { result } = await start(kind);
        act(() => result.current.next()); await flush();
        const laterPage = result.current.page; expect(laterPage).not.toBeNull(); expect(result.current.liveState).toBe('paused');
        latest = fixture(kind, 1, 15000); await advance(45000);
        expect(result.current.page).toBe(laterPage); expect(request).toHaveBeenCalledTimes(1); expect(mutateRaw).toHaveBeenCalledTimes(2);
        act(() => result.current.refresh()); await flush();
        expect(pageGeneration(result.current.page)).toBe(latest.generationId); expect(result.current.liveState).toBe('active');
    });

    it('defers automatic reads while another protected API request is pending', async () => {
        await start(kind); vi.mocked(hasPendingAPIRequests).mockReturnValue(true);
        await advance(30000); expect(request).toHaveBeenCalledTimes(1);
        vi.mocked(hasPendingAPIRequests).mockReturnValue(false); await advance(1000);
        expect(request).toHaveBeenCalledTimes(2); expect(mutateRaw).toHaveBeenCalledTimes(1);
    });

    it('retains rows and original age through 30/60/120-second retry backoff', async () => {
        const { result } = await start(kind), page = result.current.page, view = result.current.view;
        vi.mocked(request).mockRejectedValue(new APIError('Synthetic outage', 503));
        await advance(15000); expect(request).toHaveBeenCalledTimes(2); expect(result.current.liveState).toBe('retrying');
        for (const [delay, count] of [[30000, 3], [60000, 4], [120000, 5]] as const) {
            await advance(delay - 1); expect(request).toHaveBeenCalledTimes(count - 1);
            await advance(1); expect(request).toHaveBeenCalledTimes(count);
            expect(result.current.page).toBe(page); expect(result.current.view).toBe(view);
        }
        expect(result.current.elapsed).toBe(225000); expect(mutateRaw).toHaveBeenCalledTimes(1);
        vi.mocked(request).mockResolvedValue(structuredClone(latest.view));
        await advance(120000); expect(result.current.liveState).toBe('active'); expect(result.current.error).toBeNull();
        expect(result.current.page).toBe(page); expect(result.current.elapsed).toBe(345000);
        await advance(15000); expect(request).toHaveBeenCalledTimes(7);
    });

    it('retains the complete snapshot when a staged replacement fails or times out', async () => {
        const { result } = await start(kind), page = result.current.page, view = result.current.view;
        latest = fixture(kind, 1, 15000);
        vi.mocked(mutateRaw).mockRejectedValueOnce(new APIError('Synthetic page outage', 503));
        await advance(15000); expect(result.current.page).toBe(page); expect(result.current.view).toBe(view); expect(result.current.liveState).toBe('retrying');
        const held = deferred<unknown>(); vi.mocked(mutateRaw).mockReturnValueOnce(held.promise);
        await advance(30000); const call = vi.mocked(mutateRaw).mock.calls.at(-1)!, signal = call[3]!;
        await advance(9999); expect(signal.aborted).toBe(false); expect(result.current.page).toBe(page);
        await advance(1); expect(signal.aborted).toBe(true); expect(result.current.error).toBe('timeout');
        expect(result.current.page).toBe(page); expect(result.current.view).toBe(view);
        await act(async () => held.resolve(latest.page(call[1])));
        expect(result.current.page).toBe(page); expect(result.current.view).toBe(view); expect(result.current.elapsed).toBe(55000);
    });

    it.each([401, 403, 404, 409, 410])('fails closed rather than retaining rows after HTTP %s', async status => {
        const { result } = await start(kind); vi.mocked(request).mockRejectedValue(new APIError('Synthetic denial', status));
        await advance(15000); expect(result.current.page).toBeNull(); expect(result.current.view).toBeNull();
        expect(result.current.error).toBe(status === 401 ? 'session' : status === 409 ? 'restart' : 'loadError');
        await advance(120000); expect(request).toHaveBeenCalledTimes(2);
    });

    it('rejects changed evidence for the same generation and older generation replays', async () => {
        const { result, unmount } = await start(kind);
        const changed = structuredClone(latest.view);
        if ('lastComplete' in changed) { changed.lastComplete.services!.meta.observedCount = 351; changed.latest!.services.observedCount = 351; }
        else if ('processes' in changed) changed.processes.complete!.binding.manifestHash = 'f'.repeat(64);
        else changed.complete!.binding.manifestHash = 'f'.repeat(64);
        vi.mocked(request).mockResolvedValue(changed); await advance(15000);
        expect(result.current.error).toBe('invalid'); expect(result.current.page).toBeNull();
        unmount(); vi.mocked(request).mockClear(); vi.mocked(mutateRaw).mockClear();
        const mounted = await start(kind), replay = fixture(kind, 1, 15000);
        if ('lastComplete' in replay.view) { replay.view.sequence = '99'; replay.view.lastComplete.services!.sequence = '99'; replay.view.lastComplete.sockets!.sequence = '99'; }
        else if ('processes' in replay.view) replay.view.processes.complete!.binding.sequence = '99';
        else replay.view.complete!.binding.sequence = '99';
        expect(replay.valid()).toBe(true); vi.mocked(request).mockResolvedValue(replay.view); await advance(15000);
        expect(mounted.result.current.error).toBe('invalid'); expect(mounted.result.current.page).toBeNull();
    });

    it.each(['hashchange', AUTH_REQUIRED_EVENT])('aborts a staged page and suppresses its late response after %s', async event => {
        const { result } = await start(kind), held = deferred<unknown>(); latest = fixture(kind, 1, 15000);
        vi.mocked(mutateRaw).mockReturnValueOnce(held.promise); await advance(15000);
        const call = vi.mocked(mutateRaw).mock.calls[1];
        act(() => window.dispatchEvent(new Event(event))); expect(call[3]!.aborted).toBe(true);
        expect(result.current.page).toBeNull(); expect(result.current.view).toBeNull();
        await act(async () => held.resolve(latest.page(call[1]))); await advance(60000);
        expect(result.current.page).toBeNull(); expect(result.current.view).toBeNull(); expect(request).toHaveBeenCalledTimes(2);
    });

    it('clears immediately on a protected-access epoch change while a poll is in flight', async () => {
        const { result } = await start(kind), held = deferred<unknown>();
        vi.mocked(request).mockReturnValueOnce(held.promise); await advance(15000);
        act(() => abortProtectedRequests()); await act(async () => held.resolve(latest.view));
        expect(result.current.page).toBeNull(); expect(result.current.view).toBeNull(); expect(result.current.error).toBe('session');
    });

    it('aborts a pending poll on a device change and never installs its late result', async () => {
        const { result, rerender } = await start(kind), held = deferred<unknown>(), oldView = fixture(kind, 1, 15000).view;
        vi.mocked(request).mockReturnValueOnce(held.promise); await advance(15000);
        const oldSignal = vi.mocked(request).mock.calls[1][1]!.signal as AbortSignal;
        latest = fixture(kind, 0, 20000); latest.view.deviceId = `agent_${'f'.repeat(32)}`;
        expect(latest.valid()).toBe(true); rerender({ id: latest.view.deviceId }); await flush();
        const newPage = result.current.page, newView = result.current.view;
        expect(oldSignal.aborted).toBe(true); expect(newPage?.deviceId).toBe(latest.view.deviceId);
        await act(async () => held.resolve(oldView));
        expect(result.current.page).toBe(newPage); expect(result.current.view).toBe(newView); expect(result.current.error).toBeNull();
    });

    it('does not start a query or another poll after unmounting with a pending status read', async () => {
        const { unmount } = await start(kind), held = deferred<unknown>();
        vi.mocked(request).mockReturnValueOnce(held.promise); await advance(15000);
        const signal = vi.mocked(request).mock.calls[1][1]!.signal as AbortSignal;
        unmount(); expect(signal.aborted).toBe(true);
        await act(async () => held.resolve(fixture(kind, 1, 15000).view)); await advance(60000);
        expect(request).toHaveBeenCalledTimes(2); expect(mutateRaw).toHaveBeenCalledTimes(1);
    });

    it('fails closed on invalid staged page data without publishing the new metadata', async () => {
        const { result } = await start(kind); latest = fixture(kind, 1, 15000);
        vi.mocked(mutateRaw).mockImplementationOnce(async (_path, raw) => ({ ...latest.page(raw), deviceId: 'agent_wrong_fixture' }));
        await advance(15000); expect(result.current.error).toBe('invalid'); expect(result.current.page).toBeNull(); expect(result.current.view).toBeNull();
    });

    it('rejects a backwards manager clock even when the status payload is otherwise valid', async () => {
        const { result } = await start(kind); latest = fixture(kind, 0, -1); expect(latest.valid()).toBe(true);
        await advance(15000); expect(result.current.error).toBe('clock'); expect(result.current.page).toBeNull(); expect(result.current.view).toBeNull();
        expect(mutateRaw).toHaveBeenCalledTimes(1);
    });

    it('clears on a wall-clock discontinuity without issuing another inventory query', async () => {
        const { result } = await start(kind); vi.setSystemTime(Date.now() + 5000); await advance(1000);
        expect(result.current.page).toBeNull(); expect(result.current.view).toBeNull(); expect(result.current.error).toBe('clock');
        expect(request).toHaveBeenCalledTimes(1); expect(mutateRaw).toHaveBeenCalledTimes(1);
    });
});

describe('summary and visible polling boundaries', () => {
    it.each(['packages', 'updates'] as const)('%s metadata-only summary does not query pages or poll', async kind => {
        const { result } = await start(kind, { metadataOnly: true });
        expect(result.current.view).not.toBeNull(); expect(result.current.page).toBeNull();
        await advance(120000); expect(request).toHaveBeenCalledTimes(1); expect(mutateRaw).not.toHaveBeenCalled();
    });

    it('leaves the default system resource used by log and health pickers non-polling', async () => {
        const source = fixture('system'); vi.setSystemTime(source.view.serverNow);
        vi.mocked(request).mockResolvedValue(source.view); vi.mocked(mutateRaw).mockImplementation(async (_path, raw) => source.page(raw));
        const { result } = renderHook(() => useSystemInventory(source.view.deviceId, 'services')); await flush();
        expect(result.current.page).not.toBeNull(); await advance(120000);
        expect(request).toHaveBeenCalledTimes(1); expect(mutateRaw).toHaveBeenCalledTimes(1);
    });

    it.each(['en', 'de'] as const)('shows the first-page, paused and retrying states in %s', locale => {
        setLocale(locale, false); const mounted = render(<InventoryLiveStatus state="active"/>);
        const label = locale === 'de' ? 'Inventaraktualisierung' : 'Inventory auto-refresh';
        expect(screen.getByLabelText(label)).toHaveTextContent('15 s');
        expect(screen.getByLabelText(label)).toHaveAttribute('title', expect.stringContaining(locale === 'de' ? 'Erfassungszeiten bleiben unverändert' : 'Collection times are unchanged'));
        mounted.rerender(<InventoryLiveStatus state="paused"/>);
        expect(screen.getByLabelText(label)).toHaveTextContent(locale === 'de' ? 'Pausiert' : 'Paused');
        mounted.rerender(<InventoryLiveStatus state="retrying"/>);
        expect(screen.getByLabelText(label)).toHaveTextContent(locale === 'de' ? 'letzter Datenstand unverändert' : 'last snapshot unchanged');
    });
});

describe.each(['overview', 'packages', 'updates'] as const)('%s incomplete new transfer', kind => {
    it.each(['pending', 'failed'] as const)('keeps the complete page and original ages when a newer transfer is %s', async state => {
        const { result } = await start(kind), page = result.current.page;
        latest = fixture(kind, 0, 15000); const newer = fixture(kind, 1, 15000);
        const view = latest.view, newView = newer.view;
        if ('processes' in view && 'processes' in newView) {
            const selected = newView.processes.complete!;
            view.processes.transfer = {
                binding: selected.binding, manifest: selected.manifest, state, declaredRows: selected.manifest.observedCount,
                acceptedRows: 128, expectedChunks: selected.manifest.chunkCount, acceptedChunks: 1,
                collectedAt: selected.manifest.collectedAt, startedAt: selected.completedAt, expiresAt: at(view.serverNow, 60000),
            };
            if (state === 'failed') view.processes.failure = { sequence: '101', generationId: newer.generationId, attemptedAt: selected.manifest.collectedAt, receivedAt: view.serverNow, reason: 'collection_failed' };
        } else if ('complete' in view && 'complete' in newView) {
            const selected = newView.complete!;
            view.transfer = {
                binding: selected.binding, state, declaredRows: 350, acceptedRows: 128, expectedChunks: selected.manifest.chunkCount, acceptedChunks: 1,
                collectedAt: selected.manifest.collectedAt, startedAt: selected.completedAt, expiresAt: at(view.serverNow, 60000),
            };
            if (state === 'failed') view.failure = { sequence: '101', generationId: newer.generationId, attemptedAt: selected.manifest.collectedAt, receivedAt: view.serverNow, reason: 'collection_failed' };
        }
        expect(latest.valid()).toBe(true); await advance(15000);
        expect(result.current.page).toBe(page); expect(result.current.view).toEqual(view); expect(result.current.error).toBeNull();
        expect(mutateRaw).toHaveBeenCalledTimes(1); expect(result.current.elapsed).toBe(0);
        await advance(15000); expect(result.current.page).toBe(page); expect(result.current.elapsed).toBe(15000);
    });
});

it('retains the last complete system page when the newer capture has failed section observations', async () => {
    const { result } = await start('system'), page = result.current.page;
    latest = fixture('system', 0, 15000); const view = latest.view as SystemView;
    view.sequence = '101'; view.latest!.generationId = `sample_${'e'.repeat(32)}`;
    for (const section of ['services', 'sockets'] as const) view.latest![section] = {
        ...view.latest![section], generationId: view.latest!.generationId, coverage: 'failed', reason: 'permission_denied', observedCount: null, countExact: false,
    };
    expect(latest.valid()).toBe(true); await advance(15000);
    expect(result.current.page).toBe(page); expect(result.current.view).toEqual(view); expect(result.current.error).toBeNull();
    expect(mutateRaw).toHaveBeenCalledTimes(1);
});

describe.each(['overview', 'system'] as const)('%s live panel DOM continuity', kind => {
    it('keeps panel, table, scroll positions and submitted controls while a background generation is staged and installed', async () => {
        latest = fixture(kind); expect(latest.valid()).toBe(true); vi.setSystemTime(latest.view.serverNow);
        vi.mocked(request).mockImplementation(async () => structuredClone(latest.view));
        vi.mocked(mutateRaw).mockImplementation(async (_path, raw) => latest.page(raw));
        const openLogs = vi.fn();
        const mounted = render(<main>{kind === 'overview'
            ? <CompleteOverviewPanel deviceId={latest.view.deviceId} section="processes" sessionKey="same-session"/>
            : <SystemInventoryPanel deviceId={latest.view.deviceId} section="services" sessionKey="same-session" onOpenLogs={openLogs}/>}</main>);
        await flush();
        const search = screen.getByRole('searchbox', { name: 'Search this section' });
        fireEvent.change(search, { target: { value: '00000' } });
        const filter = kind === 'system' ? screen.getByRole('combobox', { name: 'Section filter' }) : null;
        if (filter) fireEvent.change(filter, { target: { value: 'active' } });
        const submitName = kind === 'overview' ? 'Search' : 'Apply';
        fireEvent.click(screen.getByRole('button', { name: submitName })); await flush();
        const main = screen.getByRole('main'), table = screen.getByRole('table');
        const panel = mounted.container.querySelector<HTMLElement>(kind === 'overview' ? '.complete-overview' : '.system-inventory')!;
        const scroller = table.closest<HTMLElement>('.package-table-scroll')!;
        expect(panel).not.toBeNull(); expect(scroller).not.toBeNull();
        main.scrollTop = 240; scroller.scrollTop = 120; scroller.scrollLeft = 77;
        const held = deferred<unknown>(); latest = fixture(kind, 1, 15000); expect(latest.valid()).toBe(true);
        vi.mocked(mutateRaw).mockReturnValueOnce(held.promise);
        await advance(15000);

        const expectStableDOM = () => {
            expect(mounted.container.querySelector(kind === 'overview' ? '.complete-overview' : '.system-inventory')).toBe(panel);
            expect(screen.getByRole('table')).toBe(table); expect(table.closest('.package-table-scroll')).toBe(scroller);
            expect(main.scrollTop).toBe(240); expect(scroller.scrollTop).toBe(120); expect(scroller.scrollLeft).toBe(77);
            expect(screen.getByRole('searchbox', { name: 'Search this section' })).toBe(search);
            expect(search).toHaveValue('00000'); expect(search).toBeEnabled();
            if (filter) { expect(screen.getByRole('combobox', { name: 'Section filter' })).toBe(filter); expect(filter).toHaveValue('active'); expect(filter).toBeEnabled(); }
            expect(screen.getByRole('button', { name: submitName })).toBeEnabled();
            expect(screen.getByRole('button', { name: 'Refresh section and restart' })).toBeEnabled();
            expect(panel).toHaveAttribute('aria-busy', 'false');
            expect(within(panel).queryByText(/Reading (complete overview|system inventory)/)).not.toBeInTheDocument();
            expect(within(panel).queryByRole('alert')).not.toBeInTheDocument();
        };
        expectStableDOM(); await advance(4000); expectStableDOM();
        const [, raw] = vi.mocked(mutateRaw).mock.calls[2];
        expect(JSON.parse(raw)).toMatchObject({ generationId: latest.generationId, cursor: '', search: '00000', ...(kind === 'system' ? { filter: 'active' } : {}) });
        await act(async () => held.resolve(latest.page(raw)));
        expectStableDOM();
        expect(within(table).getByText(kind === 'overview' ? 'fixture-new-process-000000' : 'exited')).toBeVisible();
        expect(within(panel).getByText(latest.generationId)).toBeInTheDocument();
        await advance(15000); expectStableDOM();

        expect(request).toHaveBeenCalledTimes(3); expect(mutateRaw).toHaveBeenCalledTimes(3);
        expect(vi.mocked(request).mock.calls.map(([path]) => path)).toEqual(Array(3).fill(`/devices/${latest.view.deviceId}/inventory/${suffix[kind]}`));
        expect(vi.mocked(mutateRaw).mock.calls.map(([path]) => path)).toEqual(Array(3).fill(`/devices/${latest.view.deviceId}/inventory/${suffix[kind]}/query`));
        expect(mutate).not.toHaveBeenCalled(); expect(openLogs).not.toHaveBeenCalled();
    });
});
