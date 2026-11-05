import { act, cleanup, fireEvent, render, renderHook, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { APIError, AUTH_REQUIRED_EVENT, mutateRaw, request } from './api';
import { CompletePackagesPanel } from './complete-packages';
import { completeDevice, completePage, completeRows, completeView } from './complete-packages-fixtures';
import { useCompletePackages } from './complete-packages-resource';
import type { CompletePackagePage } from './complete-packages-types';
import { setLocale } from './i18n';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutateRaw: vi.fn() }));
vi.mock('./auth', () => ({ useOperator: () => ({ mode: 'lan', authenticated: true, expiresAt: '2026-10-04T01:00:00Z' }) }));
let view = completeView(), rows = completeRows();
const inputs = () => vi.mocked(mutateRaw).mock.calls.map(call => JSON.parse(call[1]) as { cursor: string; search: string; generationId: string; limit: number });
async function open() {
    const hook = renderHook(() => useCompletePackages(completeDevice));
    await act(async () => {});
    await waitFor(() => expect({ page: hook.result.current.page !== null, error: hook.result.current.error, loading: hook.result.current.loading }).toEqual({ page: true, error: null, loading: false }));
    return hook;
}
async function move(action: () => void) { await act(async () => action()); }
beforeEach(() => {
    setLocale('en', false); view = completeView(); rows = completeRows();
    vi.mocked(request).mockReset().mockImplementation(async () => view);
    vi.mocked(mutateRaw).mockReset().mockImplementation(async (_path, raw) => completePage(view, rows, raw));
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.useRealTimers(); });

describe('bounded complete-package page navigation', () => {
    it.each(['en', 'de'] as const)('offers labelled First and Previous controls with truthful current-page counts in %s', async locale => {
        setLocale(locale, false); render(<CompletePackagesPanel deviceId={completeDevice} inline/>);
        await screen.findByRole('table');
        const first = locale === 'en' ? 'First page' : 'Erste Seite', previous = locale === 'en' ? 'Previous page' : 'Vorherige Seite', next = locale === 'en' ? 'Next 100 rows' : 'Nächste 100 Zeilen';
        expect(screen.getByRole('button', { name: first })).toBeDisabled(); expect(screen.getByRole('button', { name: previous })).toBeDisabled();
        fireEvent.click(screen.getByRole('button', { name: next })); await screen.findByText('fixture-000100', { selector: 'th' });
        expect(screen.getByRole('button', { name: previous })).toBeEnabled(); expect(screen.getByRole('button', { name: first })).toBeEnabled();
        fireEvent.click(screen.getByRole('button', { name: previous })); await screen.findByText('fixture-000000', { selector: 'th' });
        expect(screen.getByText(locale === 'en' ? 'Rows scanned through this page' : 'Bis zu dieser Seite geprüfte Zeilen').nextElementSibling).toHaveTextContent('100 / 350');
        expect(screen.getByRole('button', { name: previous })).toBeDisabled(); expect(screen.getByRole('button', { name: first })).toBeDisabled();
        expect(inputs().map(input => input.cursor)).toEqual(['', 'cursor_100', '']);
        expect(request).toHaveBeenCalledTimes(1);
    });
    it('rereads Previous and First with the exact generation/search/body bounds and restores counters without caching rows', async () => {
        const { result } = await open();
        await move(result.current.next); await move(result.current.next);
        expect(result.current.scanned).toBe(300);
        await move(result.current.previous); expect(result.current.scanned).toBe(200); expect(result.current.matches).toBe(200);
        await move(result.current.next); expect(result.current.scanned).toBe(300);
        await move(result.current.next); expect(result.current.page?.exhausted).toBe(true); expect(result.current.scanned).toBe(350);
        await move(result.current.first); expect(result.current.scanned).toBe(100); expect(result.current.matches).toBe(100); expect(result.current.canFirst).toBe(false);
        expect(inputs().map(input => input.cursor)).toEqual(['', 'cursor_100', 'cursor_200', 'cursor_100', 'cursor_200', 'cursor_300', '']);
        for (const input of inputs()) expect(input).toMatchObject({ generationId: view.complete!.binding.generationId, search: '', limit: 100 });
        expect(request).toHaveBeenCalledTimes(1);
    });
    it('moves backwards across an empty search window without claiming the search is complete or double-counting matches', async () => {
        view = completeView(2300); rows = completeRows(2300); const { result } = await open();
        await move(() => result.current.changeSearch('fixture-002299')); await move(result.current.startSearch);
        expect(result.current.page?.items).toHaveLength(0); expect(result.current.scanned).toBe(2048);
        await move(result.current.next); expect(result.current.matches).toBe(1); expect(result.current.scanned).toBe(2300);
        await move(result.current.previous); expect(result.current.page?.searchIncomplete).toBe(true); expect(result.current.matches).toBe(0); expect(result.current.scanned).toBe(2048);
        await move(result.current.next); expect(result.current.matches).toBe(1); expect(result.current.scanned).toBe(2300);
        expect(inputs().slice(1).every(input => input.search === 'fixture-002299')).toBe(true);
    });
    it.each(['previous', 'first'] as const)('hides current rows during a failed %s read and retries that checkpoint without carrying later counts', async navigation => {
        const { result } = await open(); await move(result.current.next); await move(result.current.next);
        vi.mocked(mutateRaw).mockRejectedValueOnce(new APIError('busy', 429)); await move(result.current[navigation]);
        expect(result.current.error).toBe('busy'); expect(result.current.page).toBeNull(); expect(mutateRaw).toHaveBeenCalledTimes(4);
        await move(result.current.retry); expect(result.current.error).toBeNull(); expect(result.current.scanned).toBe(navigation === 'previous' ? 200 : 100);
        expect(inputs().at(-1)?.cursor).toBe(navigation === 'previous' ? 'cursor_100' : '');
    });
    it('does not replace the original next token or renew the original expiry when First issues a new token', async () => {
        vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] });
        const mono = vi.spyOn(performance, 'now').mockReturnValue(1000), wall = vi.spyOn(Date, 'now').mockReturnValue(100000);
        const { result } = await open(); await move(result.current.next);
        view.serverNow = '2026-10-04T00:05:10Z';
        vi.mocked(mutateRaw).mockImplementationOnce(async (_path, raw) => ({ ...completePage(view, rows, raw), nextCursor: 'new_first_token', cursorExpiresAt: '2026-10-04T00:20:10Z' }));
        await move(result.current.first); expect(result.current.page).not.toBeNull();
        await move(result.current.next); expect(inputs().at(-1)?.cursor).toBe('cursor_100');
        mono.mockReturnValue(601000); wall.mockReturnValue(700000); act(() => vi.advanceTimersByTime(1000));
        expect(result.current.page).toBeNull(); expect(result.current.error).toBe('restart'); expect(result.current.canFirst).toBe(false);
    });
    it('rejects a valid renewed First response after the original deadline even when local time has not advanced', async () => {
        const { result } = await open(); await move(result.current.next);
        view.serverNow = '2026-10-04T00:16:10Z';
        vi.mocked(mutateRaw).mockImplementationOnce(async (_path, raw) => ({ ...completePage(view, rows, raw), cursorExpiresAt: '2026-10-04T00:31:10Z' }));
        await move(result.current.first); expect(result.current.page).toBeNull(); expect(result.current.error).toBe('restart');
    });
    it('does not extend the local lease when First repeats a frozen server time', async () => {
        vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] });
        const mono = vi.spyOn(performance, 'now').mockReturnValue(1000), wall = vi.spyOn(Date, 'now').mockReturnValue(100000);
        const { result } = await open(); await move(result.current.next);
        mono.mockReturnValue(601000); wall.mockReturnValue(700000); await move(result.current.first);
        mono.mockReturnValue(901000); wall.mockReturnValue(1000000); act(() => vi.advanceTimersByTime(1000));
        expect(result.current.page).toBeNull(); expect(result.current.error).toBe('restart');
    });
    it.each(['blur', 'pagehide', 'hashchange', AUTH_REQUIRED_EVENT] as const)('aborts a Previous request, clears navigation, and rejects late rows after %s', async event => {
        const { result } = await open(); await move(result.current.next); await move(result.current.next);
        let finish!: (page: CompletePackagePage) => void, signal!: AbortSignal;
        vi.mocked(mutateRaw).mockImplementationOnce(async (_path, _raw, _headers, supplied) => { signal = supplied!; return new Promise<CompletePackagePage>(resolve => { finish = resolve; }); });
        await move(result.current.previous); expect(result.current.page).toBeNull();
        act(() => window.dispatchEvent(new Event(event))); expect(signal.aborted).toBe(true);
        await act(async () => finish(completePage(view, rows, JSON.stringify({ cursor: 'cursor_100', search: '', limit: 100 }))));
        expect(result.current.page).toBeNull(); expect(result.current.canPrevious).toBe(false); expect(result.current.canFirst).toBe(false);
    });
    it('clears all navigation checkpoints when the search changes or refresh chooses a new generation', async () => {
        const { result } = await open(); await move(result.current.next);
        await move(() => result.current.changeSearch('fixture-000349')); expect(result.current.canFirst).toBe(false); expect(result.current.page).toBeNull();
        await move(result.current.startSearch); expect(result.current.scanned).toBe(350); expect(result.current.matches).toBe(1); expect(result.current.canPrevious).toBe(false);
        view = completeView(); view.complete!.binding.generationId = view.complete!.manifest.generationId = `sample_${'d'.repeat(32)}`;
        await move(result.current.refresh); expect(result.current.canFirst).toBe(false); expect(result.current.canPrevious).toBe(false); expect(inputs().at(-1)).toMatchObject({ cursor: '', generationId: view.complete!.binding.generationId });
    });
    it.each(['generation', 'count', 'next token'] as const)('rejects a changed %s when rereading a checkpoint', async changed => {
        const { result } = await open(); await move(result.current.next); await move(result.current.next);
        vi.mocked(mutateRaw).mockImplementationOnce(async (_path, raw) => {
            const page = completePage(view, rows, raw);
            if (changed === 'generation') page.binding = { ...page.binding, generationId: `sample_${'d'.repeat(32)}` };
            if (changed === 'count') { page.items = page.items.slice(0, 99); page.scannedRows = 99; }
            if (changed === 'next token') page.nextCursor = 'other_cursor';
            return page;
        });
        await move(result.current.previous); expect(result.current.error).toBe('invalid'); expect(result.current.page).toBeNull(); expect(result.current.canFirst).toBe(false);
    });
    it('bounds the backwards trail to 128 checkpoints and keeps First available beyond that limit', async () => {
        view = completeView(130); rows = completeRows(130);
        vi.mocked(mutateRaw).mockImplementation(async (_path, raw) => completePage(view, rows, JSON.stringify({ ...JSON.parse(raw), limit: 1 })));
        const { result } = await open();
        for (let i = 1; i < 130; i++) await move(result.current.next);
        expect(result.current.scanned).toBe(130); expect(result.current.page?.exhausted).toBe(true);
        for (let i = 0; i < 127; i++) await move(result.current.previous);
        expect(result.current.scanned).toBe(3); expect(result.current.canPrevious).toBe(false); expect(result.current.limitedBack).toBe(true); expect(result.current.canFirst).toBe(true);
        const requests = inputs().length; await move(result.current.previous); expect(inputs()).toHaveLength(requests);
        await move(result.current.first); expect(result.current.scanned).toBe(1); expect(result.current.limitedBack).toBe(false); expect(result.current.canFirst).toBe(false);
        await move(result.current.next); expect(result.current.scanned).toBe(2);
    });
});
