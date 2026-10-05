import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AUTH_REQUIRED_EVENT, mutateRaw, request } from './api';
import { DeviceInventoryWorkspace } from './device-inventory';
import { completeDevice, completePage, completeRows, completeView } from './complete-packages-fixtures';
import { emptyCachedUpdatesView } from './cached-updates-fixtures';
import { updatePage, updateRows, updateView } from './complete-updates-fixtures';
import { setLocale } from './i18n';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutateRaw: vi.fn() }));
let session = 'session-a';
vi.mock('./auth', () => ({ useOperator: () => ({ mode: 'lan', authenticated: true, expiresAt: session }) }));
const complete = () => ({ ...updateView(12), deviceId: completeDevice });
const preview = () => ({ ...emptyCachedUpdatesView(), deviceId: completeDevice });
function mount() { return render(<DeviceInventoryWorkspace deviceId={completeDevice} initialSource="packages"/>); }
async function updates() {
    mount(); await screen.findByRole('rowheader', { name: 'fixture-000000' });
    fireEvent.click(screen.getByRole('tab', { name: 'Updates' }));
    await screen.findByRole('rowheader', { name: 'fixture-update-000000' });
}
beforeEach(() => {
    session = 'session-a'; setLocale('en', false);
    vi.mocked(request).mockReset().mockImplementation(async path => path.endsWith('/cached-updates') ? preview() : path.endsWith('/complete-updates') ? complete() : completeView(12));
    vi.mocked(mutateRaw).mockReset().mockImplementation(async (path, body) => path.endsWith('/complete-updates/query') ? updatePage(complete(), updateRows(12), body) : completePage(completeView(12), completeRows(12), body));
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

describe('package and update source isolation', () => {
    it('opens package rows without any cached or complete update reads', async () => {
        mount(); await screen.findByRole('rowheader', { name: 'fixture-000000' });
        expect(request).toHaveBeenCalledTimes(1); expect(vi.mocked(request).mock.calls[0][0]).toBe(`/devices/${completeDevice}/inventory/packages`);
        expect(mutateRaw).toHaveBeenCalledTimes(1); expect(screen.queryByLabelText('Update view')).not.toBeInTheDocument();
    });
    it('keeps full and limited update readers mutually exclusive and restarts after switching back', async () => {
        await updates(); const selector = screen.getByLabelText('Update view'); selector.focus();
        expect(selector).toHaveValue('complete'); expect(vi.mocked(request).mock.calls.some(([path]) => path.endsWith('/cached-updates'))).toBe(false);
        fireEvent.change(selector, { target: { value: 'preview' } }); await screen.findByText('No accepted cached-update report');
        expect(selector).toHaveFocus(); expect(screen.queryByRole('rowheader', { name: 'fixture-update-000000' })).not.toBeInTheDocument();
        expect(screen.getAllByText(/A local administrator must explicitly enable/)[0]).toBeVisible();
        fireEvent.change(selector, { target: { value: 'complete' } }); await screen.findByRole('rowheader', { name: 'fixture-update-000000' });
        expect(selector).toHaveFocus(); expect(screen.queryByText('No accepted cached-update report')).not.toBeInTheDocument();
        expect(vi.mocked(request).mock.calls.filter(([path]) => path.endsWith('/complete-updates'))).toHaveLength(2);
        expect(vi.mocked(request).mock.calls.filter(([path]) => path.endsWith('/cached-updates'))).toHaveLength(1);
    });
    it('keyboard source tabs keep focus and destroy the previous update selection', async () => {
        mount(); await screen.findByRole('rowheader', { name: 'fixture-000000' });
        const packages = screen.getByRole('tab', { name: 'Packages' }); packages.focus(); fireEvent.keyDown(packages, { key: 'ArrowRight' });
        await screen.findByRole('rowheader', { name: 'fixture-update-000000' }); expect(screen.getByRole('tab', { name: 'Updates' })).toHaveFocus();
        fireEvent.change(screen.getByLabelText('Update view'), { target: { value: 'preview' } }); await screen.findByText('No accepted cached-update report');
        const tab = screen.getByRole('tab', { name: 'Updates' }); tab.focus(); fireEvent.keyDown(tab, { key: 'ArrowLeft' });
        await screen.findByRole('rowheader', { name: 'fixture-000000' }); expect(packages).toHaveFocus(); expect(screen.queryByLabelText('Update view')).not.toBeInTheDocument();
        fireEvent.keyDown(packages, { key: 'ArrowRight' }); await screen.findByRole('rowheader', { name: 'fixture-update-000000' }); expect(screen.getByLabelText('Update view')).toHaveValue('complete');
    });
    it.each(['complete', 'preview'] as const)('cancels an in-flight %s read and ignores its late result when the update source changes', async source => {
        await updates(); let finish!: (value: unknown) => void, signal!: AbortSignal;
        vi.mocked(request).mockImplementationOnce(async (_path, options) => { signal = options!.signal!; return new Promise(resolve => { finish = resolve; }); });
        if (source === 'complete') fireEvent.click(screen.getByRole('button', { name: 'Refresh complete update inventory' }));
        else fireEvent.change(screen.getByLabelText('Update view'), { target: { value: 'preview' } });
        await waitFor(() => expect(signal).toBeDefined());
        fireEvent.change(screen.getByLabelText('Update view'), { target: { value: source === 'complete' ? 'preview' : 'complete' } });
        expect(signal.aborted).toBe(true); await act(async () => finish(source === 'complete' ? complete() : preview()));
        if (source === 'complete') { await screen.findByText('No accepted cached-update report'); expect(screen.queryByRole('table')).not.toBeInTheDocument(); }
        else { await screen.findByRole('rowheader', { name: 'fixture-update-000000' }); expect(screen.queryByText('No accepted cached-update report')).not.toBeInTheDocument(); }
    });
    it.each(['session', 'device'] as const)('resets a limited preview when the %s changes', async change => {
        const rendered = mount(); await screen.findByRole('rowheader', { name: 'fixture-000000' });
        fireEvent.click(screen.getByRole('tab', { name: 'Updates' })); await screen.findByRole('rowheader', { name: 'fixture-update-000000' });
        fireEvent.change(screen.getByLabelText('Update view'), { target: { value: 'preview' } }); await screen.findByText('No accepted cached-update report');
        if (change === 'session') session = 'session-b';
        rendered.rerender(<DeviceInventoryWorkspace deviceId={change === 'device' ? 'agent_other' : completeDevice} initialSource="packages"/>);
        expect(screen.getByLabelText('Update view')).toHaveValue('complete'); expect(screen.queryByText('No accepted cached-update report')).not.toBeInTheDocument();
    });
    it('keeps lost-session reads locked without enabling either local collection scope', async () => {
        await updates(); act(() => window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT)));
        expect(screen.getByRole('alert')).toHaveTextContent('Your session has ended.');
        const calls = vi.mocked(request).mock.calls.length; act(() => window.dispatchEvent(new Event('focus'))); expect(request).toHaveBeenCalledTimes(calls);
    });
    it('provides the limited-preview choice in German', async () => {
        setLocale('de', false); mount(); await screen.findByRole('rowheader', { name: 'fixture-000000' });
        fireEvent.click(screen.getByRole('tab', { name: 'Updates' })); await screen.findByRole('rowheader', { name: 'fixture-update-000000' });
        expect(screen.getByLabelText('Updateansicht')).toHaveValue('complete'); expect(screen.getByRole('option', { name: 'Begrenzte Vorschau' })).toHaveValue('preview');
    });
});
