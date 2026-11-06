import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { APIError, AUTH_REQUIRED_EVENT, mutateRaw, request } from './api';
import { useOperator } from './auth';
import { setLocale } from './i18n';
import { CompletePackagesPanel } from './complete-packages';
import { completeDevice, completePage, completeRows, completeView } from './complete-packages-fixtures';
import { CompletePackageSourceGroups, packageSourceGroups } from './complete-package-source-groups';
import type { CompletePackagePage } from './complete-packages-types';
import type { PackageRow } from './package-observations-types';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutateRaw: vi.fn() }));
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
const samples = (): PackageRow[] => [
    { name: 'fixture-bin', version: '1:2.0-1+b1', architecture: 'amd64', sourcePackage: 'fixture-src', sourceVersion: '1:2.0-1', sourceMapping: 'source-field', installState: 'installed' },
    { name: 'fixture-bin', version: '1:2.0-1+b2', architecture: 'arm64', sourcePackage: 'fixture-src', sourceVersion: '1:2.0-1', sourceMapping: 'source-field', installState: 'incomplete' },
    { name: 'fixture-src', version: '1:2.0-1', architecture: 'amd64', sourcePackage: 'fixture-src', sourceVersion: '1:2.0-1', sourceMapping: 'binary-default', installState: 'installed' },
    { name: 'other-bin', version: '3.0', architecture: 'amd64', sourcePackage: 'fixture-src', sourceVersion: '3.0', sourceMapping: 'source-field', installState: 'installed' },
];
let rows = samples(), view = completeView(4);
const page = (input = samples()) => completePage(completeView(input.length), input);
const ui = (value = page(), locale: 'en' | 'de' = 'en', search = '') => <CompletePackageSourceGroups page={value} locale={locale} search={search}/>;
const outer = (locale: 'en' | 'de' = 'en') => screen.getByText(locale === 'en' ? 'Shared source packages' : 'Gemeinsame Quellpakete').closest('summary')!;
async function expand(locale: 'en' | 'de' = 'en') { fireEvent.click(outer(locale)); await waitFor(() => expect(document.querySelector('.package-source-content')).not.toBeNull()); }
const openPanel = async () => { const mounted = render(<CompletePackagesPanel deviceId={completeDevice} sessionKey="first"/>); fireEvent.click(screen.getByRole('button', { name: 'Complete dpkg inventory' })); await screen.findByRole('table'); return mounted; };
const flush = async () => act(async () => { for (let i = 0; i < 12; i++) await Promise.resolve(); });
beforeEach(() => {
    rows = samples(); view = completeView(rows.length); view.complete!.manifest.installedCount = 3; setLocale('en', false);
    vi.mocked(useOperator).mockReturnValue({ mode: 'lan', authenticated: true, expiresAt: 'session', insecureTestMode: false, logout: vi.fn(), theme: 'light', setTheme: vi.fn() });
    vi.mocked(request).mockReset().mockImplementation(async () => view);
    vi.mocked(mutateRaw).mockReset().mockImplementation(async (_path, raw) => completePage(view, rows, raw));
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.useRealTimers(); vi.unstubAllGlobals(); });

describe('exact source package grouping', () => {
    it('preserves binary identities, architectures, versions, mapping bases and original order without mutation', () => {
        const input = samples(), before = JSON.stringify(input), groups = packageSourceGroups(input);
        expect(groups).toHaveLength(1); expect(groups[0].name).toBe('fixture-src'); expect(groups[0].version).toBe('1:2.0-1'); expect(groups[0].rows).toEqual(input.slice(0, 3));
        expect(groups[0].rows.map(r => r.sourceMapping)).toEqual(['source-field', 'source-field', 'binary-default']); expect(JSON.stringify(input)).toBe(before);
    });
    it('never folds versions, epochs, revisions, suffixes or distinct source names', () => {
        const versions = ['1:2.0-1', '2.0-1', '1:2.0-1+b1', '1:2.0~rc1-1', '1:2.0-2'];
        const input = versions.flatMap((sourceVersion, i) => ['amd64', 'arm64'].map(architecture => ({ ...samples()[0], name: `fixture-${i}`, sourceVersion, architecture })));
        input.push({ ...samples()[0], name: 'other-a', sourcePackage: 'another-src' });
        expect(packageSourceGroups(input).map(g => g.version)).toEqual(versions); expect(packageSourceGroups(input).every(g => g.rows.length === 2)).toBe(true);
    });
    it.each(['en', 'de'] as const)('shows compact scoped counts and all exact row evidence in %s', async locale => {
        const writes = vi.spyOn(Storage.prototype, 'setItem'); render(ui(page(), locale)); expect(document.querySelector('.package-source-content')).toBeNull(); await expand(locale);
        const group = document.querySelector('.package-source-group')!; expect(group).not.toHaveAttribute('open'); expect(group.querySelector('summary')).toHaveTextContent('fixture-src'); expect(group.querySelector('summary')).toHaveTextContent('1:2.0-1'); expect(group.querySelector('summary')).toHaveTextContent(locale === 'en' ? 'Package rows: 3' : 'Paketzeilen: 3');
        const summary = group.querySelector('summary')!; summary.focus(); fireEvent.click(summary); expect(summary).toHaveFocus(); expect(group).toHaveAttribute('open');
        expect(group.querySelector('.package-source-states')).toHaveTextContent(locale === 'en' ? 'Installed: 2' : 'Installiert: 2'); expect(group.querySelector('.package-source-states')).toHaveTextContent(locale === 'en' ? 'Incomplete: 1' : 'Unvollständig: 1');
        const entries = group.querySelectorAll('.package-source-binaries > li'); expect(entries).toHaveLength(3);
        samples().slice(0, 3).forEach((row, i) => { expect(entries[i]).toHaveTextContent(row.name); expect(entries[i]).toHaveTextContent(row.version); expect(entries[i]).toHaveTextContent(row.architecture); });
        expect(entries[0]).toHaveTextContent(locale === 'en' ? 'Explicit Source field' : 'Ausdrückliches Source-Feld'); expect(entries[2]).toHaveTextContent(locale === 'en' ? 'Binary default' : 'Binärvorgabe');
        expect(screen.getByText(locale === 'en' ? 'Loaded page only' : 'Nur geladene Seite')).toBeVisible(); expect(request).not.toHaveBeenCalled(); expect(mutateRaw).not.toHaveBeenCalled(); expect(writes).not.toHaveBeenCalled();
        outer(locale).focus(); fireEvent.click(outer(locale)); await waitFor(() => expect(document.querySelector('.package-source-content')).toBeNull()); expect(outer(locale)).toHaveFocus(); await expand(locale); expect(document.querySelector('.package-source-group')).not.toHaveAttribute('open');
    });
    it('shows a scoped no-group message but renders nothing for an empty page', async () => {
        const mounted = render(ui(page(completeRows(2)))); await expand(); expect(screen.getByText('No shared source pair on this page.')).toBeVisible(); mounted.rerender(ui(page([]))); expect(document.querySelector('.package-source-groups')).toBeNull();
    });
    it('escapes arbitrary text rather than creating links or HTML', async () => {
        const input = samples().slice(0, 2).map(r => ({ ...r, sourcePackage: '<img src=x onerror=bad()>', version: '<script>bad()</script>' })); render(ui(page(input))); await expand(); fireEvent.click(document.querySelector('.package-source-group > summary')!);
        expect(screen.getByText('<img src=x onerror=bad()>')).toBeVisible(); expect(screen.getAllByText('<script>bad()</script>')).toHaveLength(2); expect(document.querySelector('.package-source-groups img, .package-source-groups script, .package-source-groups a')).toBeNull();
    });
    it.each(['generation', 'manifest', 'device', 'cursor', 'rows', 'query', 'expiry'] as const)('closes disclosure on %s replacement', async change => {
        const first = page(), mounted = render(ui(first)); await expand(); const next = structuredClone(first);
        if (change === 'generation') next.binding.generationId = 'other'; if (change === 'manifest') next.binding.manifestHash = 'other'; if (change === 'device') next.deviceId = 'agent_other'; if (change === 'cursor') next.nextCursor = 'other'; if (change === 'rows') next.items[0].version = '2.0'; if (change === 'expiry') next.cursorExpiresAt = '2026-10-04T00:10:00Z';
        mounted.rerender(ui(next, 'en', change === 'query' ? 'fixture' : '')); expect(outer().closest('details')).not.toHaveAttribute('open'); expect(document.querySelector('.package-source-content')).toBeNull();
    });
    it('preserves open groups on locale changes without retaining replaced evidence', async () => {
        const source = page(), mounted = render(ui(source)); await expand(); fireEvent.click(document.querySelector('.package-source-group > summary')!); mounted.rerender(ui(source, 'de')); expect(document.querySelector('.package-source-group')).toHaveAttribute('open'); expect(document.querySelector('.package-source-group')).toHaveTextContent('Binärvorgabe');
    });
});

describe('source group private-reader integration', () => {
    it('preserves table order, capture metadata, scan totals and existing requests', async () => {
        await openPanel(); const table = screen.getByRole('table'), before = table.textContent; await expand(); fireEvent.click(document.querySelector('.package-source-group > summary')!);
        expect(table.textContent).toBe(before); expect(within(table).getAllByRole('rowheader').map(x => x.textContent)).toEqual(rows.map(r => r.name));
        expect(screen.getByText('Generation rows').nextElementSibling).toHaveTextContent('4'); expect(screen.getByText('Rows on this page').nextElementSibling).toHaveTextContent('4'); expect(screen.getByText(view.complete!.manifest.collectedAt)).toBeInTheDocument(); expect(request).toHaveBeenCalledTimes(1); expect(mutateRaw).toHaveBeenCalledTimes(1);
    });
    it('never accumulates groups across pages and leaves next/previous navigation available', async () => {
        rows = completeRows(102).map(r => ({ ...r, sourcePackage: 'shared-source', sourceVersion: '1.0', sourceMapping: 'source-field' })); view = completeView(102); await openPanel(); await expand(); expect(document.querySelector('.package-source-group > summary')).toHaveTextContent('Package rows: 100');
        fireEvent.click(screen.getByRole('button', { name: 'Next 100 rows' })); await screen.findByText('fixture-000100', { selector: 'th' }); expect(outer().closest('details')).not.toHaveAttribute('open'); await expand(); expect(document.querySelector('.package-source-group > summary')).toHaveTextContent('Package rows: 2'); expect(document.querySelector('.package-source-groups')).not.toHaveTextContent('fixture-000000');
        fireEvent.click(screen.getByRole('button', { name: 'Previous page' })); await screen.findByText('fixture-000000', { selector: 'th' }); expect(outer().closest('details')).not.toHaveAttribute('open'); expect(mutateRaw).toHaveBeenCalledTimes(3);
    });
    it('clears groups when editing search and keeps the server search scope unchanged', async () => {
        await openPanel(); await expand(); fireEvent.change(screen.getByRole('searchbox'), { target: { value: 'source-field' } }); expect(document.querySelector('.package-source-groups')).toBeNull(); fireEvent.click(screen.getByRole('button', { name: 'Search' })); await screen.findByRole('table'); await expand(); expect(document.querySelector('.package-source-group > summary')).toHaveTextContent('Package rows: 2'); expect(JSON.parse(vi.mocked(mutateRaw).mock.calls.at(-1)![1])).toMatchObject({ search: 'source-field', cursor: '' });
    });
    it.each(['close', 'blur', 'hidden', 'pagehide', 'auth', 'session', 'device'] as const)('clears expanded group evidence on %s', async transition => {
        const mounted = await openPanel(); await expand(); fireEvent.click(document.querySelector('.package-source-group > summary')!);
        act(() => {
            if (transition === 'close') fireEvent.click(screen.getByRole('button', { name: 'Complete dpkg inventory' }));
            else if (transition === 'session') mounted.rerender(<CompletePackagesPanel deviceId={completeDevice} sessionKey="new"/>);
            else if (transition === 'device') mounted.rerender(<CompletePackagesPanel deviceId="agent_other" sessionKey="first"/>);
            else if (transition === 'hidden') { vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden'); document.dispatchEvent(new Event('visibilitychange')); }
            else window.dispatchEvent(new Event(transition === 'auth' ? AUTH_REQUIRED_EVENT : transition));
        });
        expect(document.querySelector('.package-source-groups')).toBeNull(); expect(document.body).not.toHaveTextContent('fixture-bin'); expect(mutateRaw).toHaveBeenCalledTimes(1);
    });
    it('keeps failed-transfer warnings and the original completed generation', async () => {
        view.complete!.binding.sequence = '1'; view.failure = { sequence: '2', generationId: `sample_${'d'.repeat(32)}`, attemptedAt: '2026-10-04T00:00:08Z', receivedAt: '2026-10-04T00:00:09Z', reason: 'collection_failed' }; await openPanel(); await expand(); expect(screen.getByText('Latest collection attempt failed: Collection failed')).toBeVisible(); expect(screen.getByText('Declared counts are not completion. Pending or failed transfers leave the prior generation and its age unchanged.')).toBeVisible();
    });
    it('cannot extend the original paging lease by opening a group', async () => {
        vi.useFakeTimers(); vi.mocked(mutateRaw).mockImplementation(async (_p, raw) => ({ ...completePage(view, rows, raw), cursorExpiresAt: '2026-10-04T00:00:11Z' })); render(<CompletePackagesPanel deviceId={completeDevice} inline/>); await flush(); fireEvent.click(outer()); await act(async () => { await vi.advanceTimersByTimeAsync(1); }); expect(document.querySelector('.package-source-content')).not.toBeNull(); await act(async () => { await vi.advanceTimersByTimeAsync(1000); }); expect(document.querySelector('.package-source-groups')).toBeNull(); expect(mutateRaw).toHaveBeenCalledTimes(1);
    });
    it('rejects a late result after focus loss and never restores an expanded group', async () => {
        await openPanel(); await expand(); let resolve!: (value: CompletePackagePage) => void; vi.mocked(mutateRaw).mockImplementationOnce(() => new Promise(done => { resolve = done; })); fireEvent.click(screen.getByRole('button', { name: 'Refresh inventory and restart' })); await waitFor(() => expect(resolve).toBeDefined()); act(() => window.dispatchEvent(new Event('blur'))); await act(async () => resolve(completePage(view, rows))); expect(document.querySelector('.package-source-groups')).toBeNull();
    });
    it('clears source groups on revoked access instead of retaining a successful-looking group', async () => {
        await openPanel(); await expand(); vi.mocked(request).mockRejectedValueOnce(new APIError('session', 401)); fireEvent.click(screen.getByRole('button', { name: 'Refresh inventory and restart' })); await screen.findByText('Your session has ended. Sign in again.'); expect(document.querySelector('.package-source-groups')).toBeNull();
    });
});
