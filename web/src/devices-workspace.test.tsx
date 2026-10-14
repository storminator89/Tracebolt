import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { DevicesWorkspace } from './devices-workspace';
import { EnrollmentSection } from './enrollment';
import { mutate, request } from './api';
import { macOSFixtureList, macOSFixtureRecord } from './enrollment-macos-fixture';
import type { EnrollmentList } from './enrollment-types';
import type { EnrollmentAttention } from './enrollment-attention';
import { setLocale } from './i18n';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutate: vi.fn() }));
const operator = vi.hoisted(() => ({ insecureTestMode: false, mode: 'lan', authenticated: true, checkingAccess: false, actorId: null as string | null, expiresAt: null as string | null }));
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: () => operator }));
let current: EnrollmentList;
const changed = vi.fn(), attention = vi.fn<(value: EnrollmentAttention | null) => void>();
const summary = () => document.querySelector<HTMLElement>('.devices-setup-attention')!;
const flush = () => act(async () => {});
function developmentWorkspace() {
    return <DevicesWorkspace lan={false} toolsAvailable={false} inventory={<input aria-label="Inventory query" defaultValue="Retained filter"/>} tools={<button type="button">Existing active job control</button>} setup={onAttention => <EnrollmentSection onAttention={value => { attention(value); onAttention(value); }} onChanged={changed} onDevice={() => {}} deviceIds={[]}/>}/>;
}
// The callback identity must be stable just like React's state setter in App.
function StableWorkspace() {
    return <DevicesWorkspace lan toolsAvailable inventory={<input aria-label="Inventory query" defaultValue="Retained filter"/>} tools={<button type="button">Existing active job control</button>} setup={onAttention => <EnrollmentSection onAttention={onAttention} onChanged={changed} onDevice={() => {}} deviceIds={[]}/>}/>;
}
function fixture(pending = true) {
    const item = { ...macOSFixtureRecord(window.location.origin, 'claimed_pending'), platform: 'linux' };
    return { ...macOSFixtureList(pending ? [item] : []), platforms: ['linux'] };
}
beforeEach(() => {
    setLocale('en', false); current = fixture(); localStorage.clear(); sessionStorage.clear();
    operator.authenticated = true; operator.checkingAccess = false; operator.actorId = null; operator.expiresAt = null;
    window.history.replaceState({}, '', '/#/devices');
    Object.defineProperty(HTMLElement.prototype, 'scrollIntoView', { configurable: true, value: vi.fn() });
    vi.mocked(request).mockReset().mockImplementation(async () => structuredClone(current));
    vi.mocked(mutate).mockReset(); changed.mockReset(); attention.mockReset();
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.useRealTimers(); });

describe('local device workspaces', () => {
    it.each(['en', 'de'] as const)('keeps all sections in document order with non-routing keyboard jumps (%s)', async locale => {
        setLocale(locale, false); const user = userEvent.setup(); render(<StableWorkspace/>);
        await waitFor(() => expect(summary()).toHaveAttribute('data-state', 'pending-review'));
        const labels = locale === 'de' ? ['Inventar', 'Einrichten', 'Flottentools'] : ['Inventory', 'Setup', 'Fleet tools'];
        const index = screen.getByRole('navigation', { name: locale === 'de' ? 'Gerätebereiche' : 'Device workspaces' });
        const headings = labels.map(name => screen.getByRole('heading', { name }));
        headings.forEach((node, i) => { expect(node).toBeVisible(); if (i) expect(headings[i - 1].compareDocumentPosition(node) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy(); });
        const input = screen.getByRole('textbox', { name: 'Inventory query' }), job = screen.getByRole('button', { name: 'Existing active job control' }), enrollment = document.querySelector('.enrollment-panel');
        const hash = window.location.hash, historyLength = window.history.length, reads = vi.mocked(request).mock.calls.length;
        for (const i of [2, 0, 1, 2, 1]) {
            within(index).getByRole('button', { name: labels[i] }).focus(); await user.keyboard('{Enter}');
            expect(headings[i]).toHaveFocus(); expect(window.location.hash).toBe(hash); expect(window.history.length).toBe(historyLength);
            expect(screen.getByRole('textbox', { name: 'Inventory query' })).toBe(input); expect(input).toHaveValue('Retained filter');
            expect(screen.getByRole('button', { name: 'Existing active job control' })).toBe(job); expect(document.querySelector('.enrollment-panel')).toBe(enrollment);
        }
        await user.tab(); expect(screen.getByRole('combobox', { name: locale === 'de' ? 'Betriebssystem' : 'Operating system' })).toHaveFocus();
        expect(index.querySelectorAll('a,[role="tab"],[aria-selected],[aria-expanded]')).toHaveLength(0);
        expect(document.querySelector('[role="tabpanel"],[hidden]')).toBeNull(); expect(vi.mocked(request).mock.calls).toHaveLength(reads);
        expect(changed).not.toHaveBeenCalled(); expect(mutate).not.toHaveBeenCalled();
    });
    it('scrolls the existing main container after focus without moving browser history', async () => {
        render(<main id="main-content"><StableWorkspace/></main>); await waitFor(() => expect(summary()).toHaveTextContent('Awaiting review · 1'));
        const main = document.getElementById('main-content')!, heading = document.getElementById('devices-setup-heading')!;
        main.scrollTop = 200; heading.style.scrollMarginBlockStart = '16px';
        vi.spyOn(main, 'getBoundingClientRect').mockReturnValue({ top: 50 } as DOMRect);
        vi.spyOn(heading, 'getBoundingClientRect').mockReturnValue({ top: 350 } as DOMRect);
        const before = window.history.length;
        fireEvent.click(within(screen.getByRole('navigation', { name: 'Device workspaces' })).getByRole('button', { name: 'Setup' }));
        expect(heading).toHaveFocus(); expect(main.scrollTop).toBe(484); expect(window.history.length).toBe(before);
        expect(HTMLElement.prototype.scrollIntoView).not.toHaveBeenCalled(); expect(request).toHaveBeenCalledTimes(1);
    });
    it('projects only the selected profile and source state; checking, failures and suspension never retain a count', async () => {
        render(<StableWorkspace/>); await waitFor(() => expect(summary()).toHaveTextContent('Awaiting review · 1'));
        expect(summary()).toHaveTextContent('Linux · Basic read-only'); expect(summary()).not.toHaveTextContent('invite_'); expect(summary()).not.toHaveTextContent('ab'.repeat(32));
        let release!: (value: EnrollmentList) => void; vi.mocked(request).mockImplementationOnce(() => new Promise(resolve => { release = resolve; }));
        fireEvent.click(screen.getByRole('button', { name: 'Refresh enrollment status' }));
        expect(summary()).toHaveAttribute('data-state', 'checking'); expect(summary()).not.toHaveTextContent('· 1');
        await act(async () => release(structuredClone(current))); expect(summary()).toHaveTextContent('Awaiting review · 1');
        act(() => window.dispatchEvent(new Event('pagehide'))); expect(summary()).toHaveAttribute('data-state', 'unknown'); expect(summary()).not.toHaveTextContent('· 1');
        vi.mocked(request).mockRejectedValueOnce(new Error('Synthetic lost status'));
        fireEvent.click(screen.getByRole('button', { name: 'Refresh enrollment status' })); await flush();
        expect(summary()).toHaveAttribute('data-state', 'unknown'); expect(summary()).not.toHaveTextContent('· 1'); expect(summary()).toHaveTextContent('Profile not checked');
    });
    it('keeps automatic polling visible without a second live announcement channel', async () => {
        vi.useFakeTimers(); vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('visible');
        render(<StableWorkspace/>); await flush(); expect(summary()).toHaveTextContent('Awaiting review · 1');
        const currentSummary = summary();
        expect(currentSummary).not.toHaveAttribute('role'); expect(currentSummary).not.toHaveAttribute('aria-live'); expect(currentSummary).not.toHaveAttribute('aria-atomic');
        let release!: (value: EnrollmentList) => void; vi.mocked(request).mockImplementationOnce(() => new Promise(resolve => { release = resolve; }));
        await act(async () => { await vi.advanceTimersByTimeAsync(10000); });
        expect(request).toHaveBeenCalledTimes(2); expect(currentSummary).toHaveAttribute('data-state', 'checking');
        await act(async () => release(structuredClone(current)));
        expect(summary()).toBe(currentSummary); expect(currentSummary).toHaveTextContent('Awaiting review · 1');
        expect(currentSummary.closest('[role="status"],[aria-live]')).toBeNull();
        expect(within(screen.getByRole('navigation', { name: 'Device workspaces' })).getByRole('button', { name: 'Setup' })).toHaveAttribute('aria-describedby', currentSummary.id);
    });
    it('uses neutral context until the source owner has supplied a selection', () => {
        render(<DevicesWorkspace lan toolsAvailable inventory={null} tools={null} setup={() => null}/>);
        expect(summary()).toHaveTextContent('Platform not checked'); expect(summary()).toHaveTextContent('Profile not checked'); expect(summary()).not.toHaveTextContent('Linux');
        expect(request).not.toHaveBeenCalled();
    });
    it('keeps a pending fingerprint and unchecked comparison in the original dialog, restoring the trigger', async () => {
        const user = userEvent.setup(); render(<StableWorkspace/>); await waitFor(() => expect(summary()).toHaveTextContent('Awaiting review · 1'));
        fireEvent.click(screen.getByRole('button', { name: /Invitations/ }));
        const trigger = screen.getByRole('button', { name: /^Review invitation/ }); trigger.focus(); fireEvent.click(trigger);
        const dialog = screen.getByRole('dialog', { name: 'Review invitation' });
        expect(within(dialog).getByRole('checkbox')).not.toBeChecked(); expect(within(dialog).getByRole('button', { name: 'Approve device' })).toBeDisabled();
        expect(within(dialog).getByText(/abab abab/)).toBeVisible(); expect(summary()).not.toHaveTextContent(/abab|12ab|invite_/);
        await user.keyboard('{Escape}'); expect(trigger).toHaveFocus(); expect(mutate).not.toHaveBeenCalled();
    });
    it('keeps an unconfirmed action in the index with no pending count and no automatic retry', async () => {
        current = fixture(false); vi.mocked(mutate).mockRejectedValue(new Error('Synthetic lost response'));
        render(<StableWorkspace/>); await waitFor(() => expect(screen.getByRole('button', { name: 'Add device' })).toBeEnabled());
        fireEvent.click(screen.getByRole('button', { name: 'Add device' })); fireEvent.click(screen.getByRole('button', { name: 'Create invitation' })); await flush();
        expect(summary()).toHaveAttribute('data-state', 'unconfirmed'); expect(summary()).toHaveTextContent('Action unconfirmed'); expect(summary()).not.toHaveTextContent('· 0');
        expect(document.querySelector('.enrollment-panel [role="status"]')).toHaveTextContent('Creation is unconfirmed');
        fireEvent.keyDown(document, { key: 'Escape' }); fireEvent.click(within(screen.getByRole('navigation', { name: 'Device workspaces' })).getByRole('button', { name: 'Inventory' }));
        expect(summary()).toHaveAttribute('data-state', 'unconfirmed'); expect(mutate).toHaveBeenCalledTimes(1);
    });
    it('drops the former platform count immediately and uses only the newly selected source', async () => {
        render(<StableWorkspace/>); await waitFor(() => expect(summary()).toHaveTextContent('Awaiting review · 1'));
        let release!: (value: EnrollmentList) => void; vi.mocked(request).mockImplementationOnce(() => new Promise(resolve => { release = resolve; }));
        fireEvent.change(screen.getByRole('combobox', { name: 'Operating system' }), { target: { value: 'darwin' } });
        expect(summary()).toHaveTextContent('macOS · Basic read-only'); expect(summary()).not.toHaveTextContent('· 1');
        await act(async () => release(macOSFixtureList())); expect(summary()).toHaveAttribute('data-state', 'manual');
        expect(vi.mocked(request).mock.calls.map(([path]) => path)).toEqual(['/enrollment', '/macos/enrollment']); expect(mutate).not.toHaveBeenCalled();
    });
    it('drops the basic macOS count when only the selected profile changes', async () => {
        render(<StableWorkspace/>); await waitFor(() => expect(summary()).toHaveTextContent('Awaiting review · 1'));
        vi.mocked(request).mockResolvedValueOnce(macOSFixtureList([macOSFixtureRecord(window.location.origin, 'claimed_pending')]));
        fireEvent.change(screen.getByRole('combobox', { name: 'Operating system' }), { target: { value: 'darwin' } }); await flush();
        expect(summary()).toHaveTextContent('macOS · Basic read-only'); expect(summary()).toHaveTextContent('Awaiting review · 1');
        let release!: (value: EnrollmentList) => void; vi.mocked(request).mockImplementationOnce(() => new Promise(resolve => { release = resolve; }));
        fireEvent.change(screen.getByRole('combobox', { name: 'macOS collection scope' }), { target: { value: 'macos-read-inventory-v1' } });
        expect(summary()).toHaveTextContent('macOS · macOS inventory'); expect(summary()).not.toHaveTextContent('· 1');
        await act(async () => release({ ...macOSFixtureList(), collectionProfile: 'macos-read-inventory-v1', collectionPrivacy: 'macos_inventory_metadata_may_be_sensitive' }));
        expect(summary()).toHaveAttribute('data-state', 'manual');
        expect(vi.mocked(request).mock.calls.map(([path]) => path)).toEqual(['/enrollment', '/macos/enrollment', '/macos-inventory/enrollment']);
    });
    it('invalidates the projected profile and review after a configuration change or access recheck', async () => {
        const { rerender } = render(<StableWorkspace/>); await waitFor(() => expect(summary()).toHaveTextContent('Awaiting review · 1'));
        fireEvent.click(screen.getByRole('button', { name: /Invitations/ })); fireEvent.click(screen.getByRole('button', { name: /^Review invitation/ }));
        current = { ...fixture(false), enabled: false };
        fireEvent.click(screen.getByRole('button', { name: 'Refresh enrollment status' })); await flush();
        expect(screen.queryByRole('dialog')).toBeNull(); expect(summary()).toHaveAttribute('data-state', 'unavailable'); expect(summary()).not.toHaveTextContent('· 1');
        operator.checkingAccess = true; rerender(<StableWorkspace/>); expect(summary()).toHaveAttribute('data-state', 'unknown');
        operator.checkingAccess = false; operator.authenticated = false; rerender(<StableWorkspace/>); expect(summary()).toHaveAttribute('data-state', 'unknown');
    });
    it('does not count passed invitation deadlines as live pending review', async () => {
        current.serverNow = new Date(Date.parse(current.serverNow) + 601000).toISOString();
        render(<StableWorkspace/>); await waitFor(() => expect(summary()).toHaveAttribute('data-state', 'expired'));
        expect(summary()).toHaveTextContent('Invitation deadline passed'); expect(summary()).not.toHaveTextContent('· 0'); expect(summary()).not.toHaveTextContent('· 1');
    });
    it('downgrades the old source on session replacement until its existing reader returns', async () => {
        const { rerender } = render(<StableWorkspace/>); await waitFor(() => expect(summary()).toHaveTextContent('Awaiting review · 1'));
        operator.actorId = `operator_${'e'.repeat(32)}`; rerender(<StableWorkspace/>);
        expect(summary()).toHaveAttribute('data-state', 'unknown'); expect(summary()).not.toHaveTextContent('· 1');
        expect(request).toHaveBeenCalledTimes(1);
        fireEvent.click(screen.getByRole('button', { name: 'Refresh enrollment status' })); await flush();
        expect(summary()).toHaveTextContent('Awaiting review · 1'); expect(request).toHaveBeenCalledTimes(2);
    });
    it('emits exactly the scalar contract and clears it on unmount', async () => {
        const { unmount } = render(<EnrollmentSection onAttention={attention} onChanged={changed} onDevice={() => {}} deviceIds={[]}/>);
        await waitFor(() => expect(attention).toHaveBeenLastCalledWith({ platform: 'linux', profile: 'basic-readonly-v1', state: 'pending-review', pendingCount: 1 }));
        for (const [value] of attention.mock.calls) if (value) expect(Object.keys(value).sort()).toEqual(['pendingCount', 'platform', 'profile', 'state']);
        unmount(); expect(attention).toHaveBeenLastCalledWith(null);
    });
    it('keeps retained invitations from another profile visible without counting them as the selected profile', async () => {
        current.collectionProfile = 'managed-operations-v3'; current.collectionPrivacy = 'complete_system_inventory_metadata_may_be_sensitive';
        render(<StableWorkspace/>); await waitFor(() => expect(summary()).toHaveAttribute('data-state', 'retained-review'));
        expect(summary()).toHaveTextContent('Review retained invitations'); expect(summary()).toHaveTextContent('Complete inventory'); expect(summary()).not.toHaveTextContent('· 1');
    });
    it('leaves all local-development destinations visible without inventing LAN setup or tool availability', () => {
        render(developmentWorkspace()); expect(screen.getByRole('heading', { name: 'Setup' })).toBeVisible();
        expect(screen.getByText('Device setup requires a LAN manager.')).toBeVisible(); expect(screen.getByText('Fleet tools are unavailable in this context.')).toBeVisible();
        expect(summary()).toBeNull(); expect(request).not.toHaveBeenCalled();
    });
});
