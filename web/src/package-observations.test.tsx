import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { APIError, AUTH_REQUIRED_EVENT, request } from './api';
import { useOperator } from './auth';
import { setLocale } from './i18n';
import { PackageObservationsPanel } from './package-observations';
import { effectivePackageStatus, PACKAGE_RESPONSE_MAX_BYTES, PACKAGE_RETENTION_MS, PACKAGE_SNAPSHOT_MAX_BYTES, packageReasons, releaseApplicability, validPackageSnapshot, validPackageView } from './package-observations-types';
import type { PackageRow, PackageSnapshot, PackageView } from './package-observations-types';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn() }));
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
const operator = { mode: 'lan' as const, authenticated: true, expiresAt: '2026-10-04T00:30:00Z', insecureTestMode: false, logout: vi.fn(), theme: 'light' as const, setTheme: vi.fn() };
function row(name = 'fixture-binary'): PackageRow { return { name, version: '2:1.0~rc1-2+b1', architecture: 'amd64', sourcePackage: 'fixture-source', sourceVersion: '2:1.0~rc1-2', sourceMapping: 'source-field', installState: 'installed' }; }
function snapshot(): PackageSnapshot { return { schemaVersion: 'tracebolt.linux-packages.v1', scope: 'agent-visible-dpkg', generationId: `sample_${'a'.repeat(32)}`, collectedAt: '2026-10-04T00:00:00Z', durationMs: 10, release: { quality: 'healthy', reason: 'none', fields: { id: 'debian', versionId: '13', versionCodename: 'trixie' } }, inventory: { quality: 'healthy', reason: 'none', complete: true, truncated: false, countExact: true, observedCount: 1, installedCount: 1, items: [row()] } }; }
function view(): PackageView { return { schemaVersion: 'tracebolt.package-view.v1', deviceId: 'agent_fixture', status: 'fresh', serverNow: '2026-10-04T00:00:10Z', receivedAt: '2026-10-04T00:00:05Z', sequence: 1, maxAgeSeconds: 120, snapshot: snapshot() }; }
function unknown(): PackageView { const value = view(); value.snapshot!.inventory = { quality: 'unknown', reason: 'read_failed', complete: false, truncated: false, countExact: false, observedCount: null, installedCount: null, items: [] }; return value; }
function partial(): PackageView { const value = view(); Object.assign(value.snapshot!.inventory, { complete: false, truncated: true, reason: 'item_limit', observedCount: 500, installedCount: 490 }); return value; }
function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(done => { resolve = done; }); return { promise, resolve }; }
function open() { fireEvent.click(screen.getByRole('button', { name: 'Release and source-package observations' })); }
async function show(value = view()) { vi.mocked(request).mockResolvedValue(value); const rendered = render(<PackageObservationsPanel deviceId="agent_fixture"/>); open(); await screen.findByText('Observed package sources'); await waitFor(() => expect(screen.queryByText('Reading package observations…')).not.toBeInTheDocument()); return rendered; }
beforeEach(() => { vi.mocked(request).mockReset(); vi.mocked(useOperator).mockReturnValue(operator); setLocale('en', false); });
afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); });

describe('strict package DTO parity', () => {
    it('accepts exact release/source mappings, complete zero, partial and unknown as distinct states', () => {
        for (const value of [view(), partial(), unknown()]) expect(validPackageView(value, 'agent_fixture')).toBe(true);
        const empty = snapshot(); Object.assign(empty.inventory, { items: [], observedCount: 0, installedCount: 0 }); expect(validPackageSnapshot(empty)).toBe(true);
        const noRelease = snapshot(); noRelease.release = { quality: 'denied', reason: 'permission_denied', fields: { id: null, versionId: null, versionCodename: null } }; expect(validPackageSnapshot(noRelease)).toBe(true);
        const fallback = snapshot(); Object.assign(fallback.inventory.items[0], { sourceMapping: 'binary-default', sourcePackage: 'fixture-binary', sourceVersion: '2:1.0~rc1-2+b1' }); expect(validPackageSnapshot(fallback)).toBe(true);
    });
    it('requires every exact outer and nested key and forbids unsolicited metadata', () => {
        const base = view();
        for (const key of Object.keys(base)) { const changed = { ...base } as Record<string, unknown>; delete changed[key]; expect(validPackageView(changed, base.deviceId)).toBe(false); }
        const sections = [snapshot(), snapshot().release, snapshot().release.fields, snapshot().inventory, row()];
        for (let section = 0; section < sections.length; section++) {
            for (const key of [...Object.keys(sections[section]), 'repositoryUrl']) {
                const changed = snapshot(), target = [changed, changed.release, changed.release.fields, changed.inventory, changed.inventory.items[0]][section] as unknown as Record<string, unknown>;
                if (key === 'repositoryUrl') target[key] = 'https://private.invalid'; else delete target[key];
                expect(validPackageSnapshot(changed)).toBe(false);
            }
        }
        expect(validPackageView({ ...base, target: 'trusted' }, base.deviceId)).toBe(false);
        expect(validPackageSnapshot({ ...snapshot(), SchemaVersion: 'tracebolt.linux-packages.v1' })).toBe(false);
    });
    it.each([
        ['schema', (s: PackageSnapshot) => { s.schemaVersion = 'other' as never; }], ['scope', (s: PackageSnapshot) => { s.scope = 'host-wide' as never; }],
        ['generation', (s: PackageSnapshot) => { s.generationId = `sample_${'A'.repeat(32)}`; }], ['invalid date', (s: PackageSnapshot) => { s.collectedAt = '2026-02-31T00:00:00Z'; }],
        ['offset date', (s: PackageSnapshot) => { s.collectedAt = '2026-10-04T00:00:00+00:00'; }], ['pre-epoch date', (s: PackageSnapshot) => { s.collectedAt = '1969-10-04T00:00:00Z'; }],
        ['duration overflow', (s: PackageSnapshot) => { s.durationMs = Number.MAX_SAFE_INTEGER + 1; }], ['duration fraction', (s: PackageSnapshot) => { s.durationMs = 0.5; }],
        ['negative duration', (s: PackageSnapshot) => { s.durationMs = -1; }], ['release length', (s: PackageSnapshot) => { s.release.fields.id = 'a'.repeat(129); }],
        ['release controls', (s: PackageSnapshot) => { s.release.fields.id = 'debian\n'; }], ['release unicode', (s: PackageSnapshot) => { s.release.fields.id = 'débían'; }],
        ['release healthy reason', (s: PackageSnapshot) => { s.release.reason = 'byte_limit'; }], ['release unknown facts', (s: PackageSnapshot) => { s.release.quality = 'unknown'; s.release.reason = 'source_missing'; }],
        ['impossible count', (s: PackageSnapshot) => { s.inventory.installedCount = 2; }], ['fraction count', (s: PackageSnapshot) => { s.inventory.observedCount = 1.1; }],
        ['null items', (s: PackageSnapshot) => { s.inventory.items = null as never; }], ['unknown prefix', (s: PackageSnapshot) => { s.inventory.quality = 'unknown'; s.inventory.reason = 'read_failed'; }],
        ['missing exactness', (s: PackageSnapshot) => { s.inventory.countExact = false; }], ['complete truncation', (s: PackageSnapshot) => { s.inventory.truncated = true; }],
        ['complete count mismatch', (s: PackageSnapshot) => { s.inventory.observedCount = 2; }], ['unknown reason', (s: PackageSnapshot) => { s.inventory.reason = '/private/source failure' as never; }],
    ])('rejects %s', (_label, change) => { const value = snapshot(); change(value); expect(validPackageSnapshot(value)).toBe(false); });
    it('enforces all row grammars, lengths, sort/identity and exact binary-default invariants', () => {
        const invalid: Partial<PackageRow>[] = [{ name: 'a' }, { name: 'a'.repeat(257) }, { sourcePackage: 'a' }, { sourcePackage: 'a'.repeat(257) }, { name: '<script>' }, { architecture: 'a'.repeat(65) }, { architecture: '' }, { architecture: 'source' }, { architecture: 'linux-any' }, { architecture: 'any-amd64' }, { architecture: 'any' }, { version: '' }, { version: 'v1' }, { version: '1'.repeat(513) }, { sourceVersion: '1'.repeat(513) }, { version: 'a:1' }, { version: ':1' }, { version: '1-' }, { version: '1-1:2' }, { version: '1\n' }, { sourceMapping: 'binary-default' }, { installState: 'residual' as never }];
        for (const fields of invalid) { const value = snapshot(); Object.assign(value.inventory.items[0], fields); expect(validPackageSnapshot(value), JSON.stringify(fields)).toBe(false); }
        for (const items of [[row(), row()], [row('zz-package'), row('aa-package')], [{ ...row(), architecture: 'arm64' }, row()]]) { const value = snapshot(); Object.assign(value.inventory, { items, observedCount: 2, installedCount: 2 }); expect(validPackageSnapshot(value)).toBe(false); }
        for (const version of ['1', '1.0-1', '2:1.0~rc1-2+b1', '1.0+vendor', '1'.repeat(512)]) { const value = snapshot(); value.inventory.items[0].version = version; expect(validPackageSnapshot(value)).toBe(true); }
        const edge = snapshot(); Object.assign(edge.inventory.items[0], { name: 'a'.repeat(256), sourcePackage: 'b'.repeat(256), architecture: 'a'.repeat(64) }); edge.release.fields.id = 'a'.repeat(128); edge.durationMs = Number.MAX_SAFE_INTEGER; expect(validPackageSnapshot(edge)).toBe(true);
    });
    it('rejects impossible partial totals and respects the 100000-source and 128-row bounds', () => {
        for (const change of [{ observedCount: 100001 }, { observedCount: 1 }, { installedCount: 0 }, { installedCount: 501 }, { truncated: false }, { reason: 'none' }, { complete: true }]) { const value = partial(); Object.assign(value.snapshot!.inventory, change); expect(validPackageView(value, 'agent_fixture')).toBe(false); }
        const feasible = partial(); Object.assign(feasible.snapshot!.inventory, { observedCount: 100000, installedCount: 100000 }); expect(validPackageView(feasible, 'agent_fixture')).toBe(true);
        feasible.snapshot!.inventory.items[0].installState = 'incomplete'; expect(validPackageView(feasible, 'agent_fixture')).toBe(false);
        const rows = snapshot(); rows.inventory.items = Array.from({ length: 128 }, (_, i) => row(`pkg-${String(i).padStart(3, '0')}`)); Object.assign(rows.inventory, { observedCount: 128, installedCount: 128 });
        // Dense long rows hit the byte cap independently, even under the row cap.
        expect(validPackageSnapshot(rows)).toBe(false);
        rows.inventory.items.push(row('pkg-128')); Object.assign(rows.inventory, { observedCount: 129, installedCount: 129 }); expect(validPackageSnapshot(rows)).toBe(false);
    });
    it('enforces the exact canonical 16 KiB cap without weakening field limits', () => {
        const value = snapshot(); value.inventory.items = Array.from({ length: 12 }, (_, i) => ({ ...row(`pkg-${String(i).padStart(3, '0')}`), version: '1'.repeat(512), sourceVersion: '1'.repeat(512), sourcePackage: 'a'.repeat(256) })); Object.assign(value.inventory, { observedCount: 12, installedCount: 12 });
        const size = () => new TextEncoder().encode(JSON.stringify(value)).byteLength;
        // Add bounded version characters deterministically until the exact boundary.
        while (size() > PACKAGE_SNAPSHOT_MAX_BYTES) { const item = value.inventory.items.find(row => row.sourceVersion.length > 1)!; item.sourceVersion = item.sourceVersion.slice(0, -1); }
        expect(size()).toBe(PACKAGE_SNAPSHOT_MAX_BYTES); expect(validPackageSnapshot(value)).toBe(true);
        value.inventory.items.find(row => row.sourceVersion.length < 512)!.sourceVersion += '1'; expect(size()).toBe(PACKAGE_SNAPSHOT_MAX_BYTES + 1); expect(validPackageSnapshot(value)).toBe(false);
    });
    it('enforces fixed quality/reason vocabulary without raw source errors', () => {
        for (const reason of packageReasons) { const value = unknown(); value.snapshot!.inventory.reason = reason; expect(validPackageView(value, 'agent_fixture')).toBe(reason !== 'none' && reason !== 'permission_denied'); }
        const denied = unknown(); denied.snapshot!.inventory.quality = 'denied'; denied.snapshot!.inventory.reason = 'permission_denied'; expect(validPackageView(denied, 'agent_fixture')).toBe(true); denied.snapshot!.inventory.reason = 'read_failed'; expect(validPackageView(denied, 'agent_fixture')).toBe(false);
    });
    it('accepts only coherent lifecycle, receipt, sequence and trusted-clock metadata', () => {
        const base = view();
        for (const change of [{ deviceId: 'agent_other' }, { status: 'unsupported' }, { maxAgeSeconds: 121 }, { sequence: 0 }, { sequence: Number.MAX_SAFE_INTEGER + 1 }, { sequence: 1.1 }, { sequence: null }, { receivedAt: null }, { receivedAt: '2026-10-04T00:00:11Z' }, { serverNow: '2026-02-31T00:00:10Z' }, { serverNow: '2026-10-04T00:03:00Z' }, { status: 'not_configured' }, { status: 'awaiting' }, { status: 'unavailable' }, { snapshot: null }]) expect(validPackageView({ ...base, ...change }, 'agent_fixture')).toBe(false);
        for (const status of ['not_configured', 'awaiting', 'revoked'] as const) expect(validPackageView({ ...base, status, snapshot: null, receivedAt: null, sequence: null }, base.deviceId)).toBe(true);
        expect(validPackageView({ ...base, status: 'unavailable', snapshot: null }, base.deviceId)).toBe(true);
        expect(validPackageView({ ...base, status: 'stale', serverNow: '2026-10-04T00:03:00Z' }, base.deviceId)).toBe(true);
        expect(validPackageView({ ...base, status: 'revoked' }, base.deviceId)).toBe(true);
        expect(validPackageView({ ...base, status: 'stale', serverNow: '2026-10-05T00:00:00Z' }, base.deviceId)).toBe(false);
        const future = view(); future.snapshot!.collectedAt = '2026-10-04T00:00:11Z'; expect(validPackageView(future, base.deviceId)).toBe(false);
    });
    it('ages both receipt and collection only from server time plus monotonic elapsed time', () => {
        vi.spyOn(Date, 'now').mockReturnValue(0); const value = view(); expect(effectivePackageStatus(value, 110000)).toBe('fresh'); expect(effectivePackageStatus(value, 110001)).toBe('stale');
        value.receivedAt = null; expect(effectivePackageStatus(value, 0)).toBe('stale'); value.receivedAt = '2026-10-04T00:00:11Z'; expect(effectivePackageStatus(value, 0)).toBe('stale');
        for (const delta of [NaN, Infinity, -1]) expect(effectivePackageStatus(view(), delta)).toBe('unavailable');
        expect(effectivePackageStatus(view(), PACKAGE_RETENTION_MS)).toBe('unavailable'); expect(effectivePackageStatus({ ...view(), status: 'revoked' }, PACKAGE_RETENTION_MS)).toBe('revoked'); expect(effectivePackageStatus({ ...view(), status: 'stale' }, 0)).toBe('stale');
    });
    it('does not lose sub-millisecond future or stale timestamp boundaries', () => {
        for (const field of ['receivedAt', 'collectedAt'] as const) {
            const value = view();
            if (field === 'receivedAt') value.receivedAt = '2026-10-04T00:00:10.000000001Z'; else value.snapshot!.collectedAt = '2026-10-04T00:00:10.000000001Z';
            expect(validPackageView(value, 'agent_fixture')).toBe(false); expect(effectivePackageStatus(value, 0)).toBe('stale');
        }
        const old = view(); old.serverNow = '2026-10-04T00:02:00.000000001Z'; expect(validPackageView(old, 'agent_fixture')).toBe(false); expect(effectivePackageStatus(old, 0)).toBe('stale');
    });
    it('uses exact release triples without normalizing missing, point releases, or aliases', () => {
        const fields = snapshot().release.fields;
        for (const [changed, expected] of [[fields, 'debian'], [{ id: 'ubuntu', versionId: '24.04', versionCodename: 'noble' }, 'ubuntu'], [{ ...fields, versionId: '13.1' }, 'inconsistent'], [{ ...fields, id: null }, 'incomplete'], [{ ...fields, id: '' }, 'incomplete'], [{ ...fields, id: 'derivative' }, 'unsupported'], [{ ...fields, versionId: '12', versionCodename: 'bookworm' }, 'unsupported']] as const) expect(releaseApplicability(changed)).toBe(expected);
    });
});

describe('package observations presentation and private lifecycle', () => {
    it('fetches only when expanded, uses the bounded endpoint and shows exact observed/full-source facts', async () => {
        vi.mocked(request).mockResolvedValue(partial()); const storage = vi.spyOn(Storage.prototype, 'setItem'); render(<PackageObservationsPanel deviceId="agent_fixture"/>); expect(request).not.toHaveBeenCalled();
        open(); await screen.findByRole('table'); expect(request).toHaveBeenCalledExactlyOnceWith('/devices/agent_fixture/packages', { signal: expect.any(AbortSignal) }, PACKAGE_RESPONSE_MAX_BYTES);
        expect(screen.getByText('2:1.0~rc1-2+b1')).toBeVisible(); expect(screen.getByText('2:1.0~rc1-2')).toBeVisible(); expect(screen.getByText('Explicit Source field')).not.toBeVisible(); fireEvent.click(screen.getByRole('table').querySelector('summary')!); expect(screen.getByText('Explicit Source field')).toBeVisible();
        for (const text of ['500', '490', '499', 'Partial exported inventory', 'Rows truncated by export bounds', 'trixie']) expect(screen.getByText(text)).toBeVisible();
        expect(screen.queryByRole('link')).not.toBeInTheDocument(); expect(document.body.textContent).not.toMatch(/0 CVEs|zero vulnerabilities|Available updates: 0/i); expect(storage).not.toHaveBeenCalled();
    });
    it('keeps binary-default and explicit Source evidence separate in keyboard-focusable row disclosures', async () => {
        const value = view(), inventory = value.snapshot!.inventory;
        inventory.items.push({ ...row('fixture-default'), sourcePackage: 'fixture-default', sourceVersion: '2:1.0~rc1-2+b1', sourceMapping: 'binary-default' });
        inventory.observedCount = inventory.installedCount = 2; await show(value);
        const table = screen.getByRole('table'); expect(within(table).getAllByRole('columnheader')).toHaveLength(6);
        expect(within(table).queryByRole('columnheader', { name: 'Mapping basis' })).not.toBeInTheDocument();
        const summaries = [...table.querySelectorAll('summary')];
        for (const [index, evidence] of ['Explicit Source field', 'Absent Source field: binary default'].entries()) {
            expect(screen.getByText(evidence)).not.toBeVisible(); summaries[index].focus(); expect(summaries[index]).toHaveFocus();
            expect(summaries[index]).toHaveTextContent(`Package details: ${inventory.items[index].name} (amd64)`);
            fireEvent.click(summaries[index]); expect(screen.getByText(evidence)).toBeVisible();
            fireEvent.click(summaries[index]); expect(screen.getByText(evidence)).not.toBeVisible();
        }
        expect(request).toHaveBeenCalledTimes(1);
        fireEvent.click(summaries[0]); fireEvent.click(screen.getByRole('button', { name: 'Release and source-package observations' }));
        expect(screen.queryByRole('table')).not.toBeInTheDocument(); open(); await screen.findByRole('table');
        expect(screen.getByText('Explicit Source field')).not.toBeVisible();
    });
    it('distinguishes successfully empty from unknown with fresh receipt, and clears older rows on refresh', async () => {
        await show(); const unknownValue = unknown(); vi.mocked(request).mockResolvedValue(unknownValue); fireEvent.click(screen.getByRole('button', { name: 'Refresh package observations' }));
        await screen.findByText('No package inventory evidence. Empty selected rows do not establish a zero package count.'); expect(screen.queryByRole('table')).not.toBeInTheDocument(); expect(screen.getByText('Within the collection window')).toBeVisible();
        const empty = view(); Object.assign(empty.snapshot!.inventory, { observedCount: 0, installedCount: 0, items: [] }); vi.mocked(request).mockResolvedValue(empty); fireEvent.click(screen.getByRole('button', { name: 'Refresh package observations' }));
        await screen.findByText('The successfully parsed source contains zero installed or incomplete rows in this namespace.'); expect(screen.queryByText('No package inventory evidence. Empty selected rows do not establish a zero package count.')).not.toBeInTheDocument();
    });
    it('does not present an unknown source-limit failure as a successful partial export', async () => {
        const value = unknown(); value.snapshot!.inventory.reason = 'item_limit'; await show(value);
        expect(screen.getByText('A row limit was reached.')).toBeVisible(); expect(screen.getByText('No package inventory evidence. Empty selected rows do not establish a zero package count.')).toBeVisible(); expect(screen.queryByText('Partial exported inventory')).not.toBeInTheDocument(); expect(screen.queryByText('Rows truncated by export bounds')).not.toBeInTheDocument();
    });
    it('shows missing and explicitly empty release fields separately; source failures remain fixed copy', async () => {
        const value = unknown(); value.snapshot!.release.fields = { id: '', versionId: null, versionCodename: 'noble' }; await show(value);
        expect(screen.getByText('Explicitly empty field')).toBeVisible(); expect(screen.getByText('Absent field')).toBeVisible(); expect(screen.getByText('Release identifiers incomplete')).toBeVisible(); expect(screen.getByText('The source could not be read.')).toBeVisible();
    });
    it('keeps historical, revoked, not-configured and unavailable states distinct', async () => {
        await show({ ...view(), status: 'stale', serverNow: '2026-10-04T00:03:00Z' }); expect(screen.getByText('Stale / historical package observations')).toBeVisible(); expect(screen.getAllByText('Source parsed successfully')).toHaveLength(2);
        for (const [status, label] of [['revoked', 'Device identity revoked'], ['not_configured', 'Package-source collection not configured'], ['unavailable', 'Package observations unavailable']] as const) {
            vi.mocked(request).mockResolvedValue({ ...view(), status, snapshot: null, ...(status === 'not_configured' ? { sequence: null, receivedAt: null } : {}) }); fireEvent.click(screen.getByRole('button', { name: 'Refresh package observations' })); await screen.findByText(label); expect(screen.queryByRole('table')).not.toBeInTheDocument();
        }
    });
    it.each(['close', 'device', 'session', 'unmount', 'hidden', 'pagehide', 'auth'] as const)('aborts and ignores a late package reply after %s', async transition => {
        const delayed = deferred<PackageView>(); vi.mocked(request).mockReturnValue(delayed.promise); const rendered = render(<PackageObservationsPanel deviceId="agent_fixture" sessionKey="one"/>); open(); const signal = vi.mocked(request).mock.calls[0][1]!.signal!;
        if (transition === 'close') open(); if (transition === 'device') rendered.rerender(<PackageObservationsPanel deviceId="agent_other" sessionKey="one"/>); if (transition === 'session') rendered.rerender(<PackageObservationsPanel deviceId="agent_fixture" sessionKey="two"/>); if (transition === 'unmount') rendered.unmount();
        if (transition === 'hidden') { vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden'); act(() => document.dispatchEvent(new Event('visibilitychange'))); }
        if (transition === 'pagehide') act(() => window.dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true })));
        if (transition === 'auth') act(() => window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT)));
        expect(signal.aborted).toBe(true); await act(async () => delayed.resolve(view())); expect(screen.queryByRole('table')).not.toBeInTheDocument(); expect(screen.queryByText('fixture-binary')).not.toBeInTheDocument();
    });
    it('reanchors from a new response after BFCache and rejects the suspended request', async () => {
        const old = deferred<PackageView>(); vi.mocked(request).mockReturnValueOnce(old.promise).mockResolvedValueOnce(unknown()); render(<PackageObservationsPanel deviceId="agent_fixture"/>); open(); act(() => window.dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true }))); act(() => window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true })));
        await screen.findByText('No package inventory evidence. Empty selected rows do not establish a zero package count.'); await act(async () => old.resolve(view())); expect(screen.queryByRole('table')).not.toBeInTheDocument(); expect(request).toHaveBeenCalledTimes(2);
    });
    it.each([3600000, -3600000, NaN])('clears rows on a wall/monotonic discontinuity of %s ms', async jump => {
        await show(); const wall = Date.now(); vi.spyOn(Date, 'now').mockReturnValue(wall + jump); await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('The time anchor is no longer reliable.'), { timeout: 2200 }); expect(screen.queryByRole('table')).not.toBeInTheDocument();
    });
    it('clears an invalid, future or missing receipt instead of preserving older package facts', async () => {
        await show(); vi.mocked(request).mockResolvedValue({ ...view(), receivedAt: null }); fireEvent.click(screen.getByRole('button', { name: 'Refresh package observations' })); await screen.findByRole('alert'); expect(screen.queryByRole('table')).not.toBeInTheDocument(); expect(screen.queryByText('Within the collection window')).not.toBeInTheDocument();
    });
    it.each([[429, 'The manager is busy. Retry in a moment.'], [500, 'Package observations could not be read. Refresh to try again.'], [401, 'Your session has ended. Sign in again.']] as const)('does not expose raw errors for HTTP %s', async (status, message) => {
        vi.mocked(request).mockRejectedValue(new APIError('/private/path raw internal error', status)); render(<PackageObservationsPanel deviceId="agent_fixture"/>); open(); expect(await screen.findByRole('alert')).toHaveTextContent(message); expect(document.body.textContent).not.toContain('/private/path'); if (status === 401) expect(screen.getByRole('button', { name: 'Refresh package observations' })).toBeDisabled();
    });
    it('times out an active request and suppresses its late result', async () => {
        vi.useFakeTimers(); const delayed = deferred<PackageView>(); vi.mocked(request).mockReturnValue(delayed.promise); render(<PackageObservationsPanel deviceId="agent_fixture"/>); open(); const signal = vi.mocked(request).mock.calls[0][1]!.signal!; await act(async () => vi.advanceTimersByTime(10000)); expect(signal.aborted).toBe(true); expect(screen.getByRole('alert')).toHaveTextContent('The manager did not respond in time.'); await act(async () => delayed.resolve(view())); expect(screen.queryByRole('table')).not.toBeInTheDocument();
    });
    it('ages the rendered collection and hides retained rows at 24 hours without changing source quality', async () => {
        vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] }); let mono = 1000, wall = 1000000;
        vi.spyOn(performance, 'now').mockImplementation(() => mono); vi.spyOn(Date, 'now').mockImplementation(() => wall);
        await show(); mono += 110001; wall += 110001; await act(async () => vi.advanceTimersByTime(1000));
        expect(screen.getByText('Stale / historical package observations')).toBeVisible(); expect(screen.getAllByText('Source parsed successfully')).toHaveLength(2); expect(screen.getByRole('table')).toBeVisible();
        mono += PACKAGE_RETENTION_MS; wall += PACKAGE_RETENTION_MS; await act(async () => vi.advanceTimersByTime(1000)); expect(screen.getByText('Package observations unavailable')).toBeVisible(); expect(screen.queryByRole('table')).not.toBeInTheDocument(); expect(screen.queryByText('fixture-binary')).not.toBeInTheDocument();
    });
    it('rejects a response received after monotonic rollback before the next timer tick', async () => {
        let mono = 1000; vi.spyOn(performance, 'now').mockImplementation(() => mono);
        const delayed = deferred<PackageView>(); vi.mocked(request).mockReturnValue(delayed.promise); render(<PackageObservationsPanel deviceId="agent_fixture"/>); open(); mono = 500;
        await act(async () => delayed.resolve(view())); expect(screen.getByRole('alert')).toHaveTextContent('The time anchor is no longer reliable.'); expect(screen.queryByRole('table')).not.toBeInTheDocument();
    });
    it('supports German labels and preserves exact identifier text', async () => {
        setLocale('de', false); vi.mocked(request).mockResolvedValue(partial()); render(<PackageObservationsPanel deviceId="agent_fixture"/>); fireEvent.click(screen.getByRole('button', { name: 'Release- und Quellpaket-Beobachtungen' })); const table = await screen.findByRole('table'); expect(within(table).getAllByRole('columnheader')).toHaveLength(6); expect(within(table).queryByRole('columnheader', { name: 'Zuordnungsgrundlage' })).not.toBeInTheDocument(); expect(within(table).getByText('Ausdrückliches Source-Feld')).not.toBeVisible(); fireEvent.click(table.querySelector('summary')!); expect(within(table).getByText('Ausdrückliches Source-Feld')).toBeVisible(); expect(screen.getByText('Teilweise exportiertes Inventar')).toBeVisible(); expect(screen.getByText('trixie')).toBeVisible();
    });
    it.each([null, { ...operator, authenticated: false }, { ...operator, mode: 'development' as const }])('does not fetch without authenticated LAN access', async currentOperator => {
        vi.mocked(useOperator).mockReturnValue(currentOperator); render(<PackageObservationsPanel deviceId="agent_fixture"/>); expect(screen.getByText('Authenticated LAN operator access is required.')).toBeVisible(); expect(request).not.toHaveBeenCalled();
    });
});
