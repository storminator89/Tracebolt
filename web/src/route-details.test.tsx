import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { lazy, useEffect, useState } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AuthBoundary, OperatorAccount, useOperator } from './auth';
import type { OperatorSession } from './auth';
import { AUTH_REQUIRED_EVENT, mutate, request } from './api';
import { setLocale } from './i18n';
import { DetailLoadingLifecycle, RouteDetailBoundary } from './route-details';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutate: vi.fn() }));
const session: OperatorSession = { mode: 'lan', transport: 'https', insecureTestMode: false, transportWarning: null, authenticationRequired: true, authenticated: true, csrfToken: 'synthetic-route-session', serverNow: '2026-10-14T00:00:00Z', expiresAt: '2026-10-14T00:30:00Z', expiresInSeconds: 1800, loginMode: 'named', actorId: `operator_${'1'.repeat(32)}`, capabilities: ['read'] };
const anonymous: OperatorSession = { ...session, authenticated: false, csrfToken: null, expiresAt: null, expiresInSeconds: null, actorId: null, capabilities: [] };
const mounted = vi.fn(), unmounted = vi.fn();
function PrivateDetail({ id = 'A' }: { id?: string }) {
    const operator = useOperator();
    useEffect(() => { mounted(id, operator?.actorId); return () => { unmounted(id); }; }, [id, operator?.actorId]);
    return <section aria-label={`Private ${id}`}><input aria-label="Private draft" defaultValue=""/>{operator?.actorId}</section>;
}
function pendingDetail() {
    let resolve!: (module: { default: typeof PrivateDetail }) => void;
    let reject!: (error: Error) => void;
    const load = vi.fn(() => new Promise<{ default: typeof PrivateDetail }>((yes, no) => { resolve = yes; reject = no; }));
    const Detail = lazy(load);
    return { Detail, load, resolve: () => resolve({ default: PrivateDetail }), reject: () => reject(new Error('Sensitive implementation error must not be shown')) };
}
function route(detail: ReturnType<typeof pendingDetail>, id = 'A') {
    return <DetailLoadingLifecycle><AuthBoundary><OperatorAccount/><RouteDetailBoundary key={id} onBack={() => {}} backLabel="Back to devices"><detail.Detail id={id}/></RouteDetailBoundary></AuthBoundary></DetailLoadingLifecycle>;
}
async function open(detail: ReturnType<typeof pendingDetail>) {
    const view = render(route(detail)); await screen.findByText('Loading view …');
    expect(detail.load).toHaveBeenCalledTimes(1); return view;
}
async function resolve(detail: ReturnType<typeof pendingDetail>) { await act(async () => { detail.resolve(); }); }
function event(name: string, persisted = false) {
    const value = new Event(name); if (persisted) Object.defineProperty(value, 'persisted', { value: true });
    act(() => window.dispatchEvent(value));
}
beforeEach(() => {
    setLocale('en', false); localStorage.clear(); sessionStorage.clear(); mounted.mockClear(); unmounted.mockClear();
    vi.mocked(request).mockReset().mockResolvedValue(session); vi.mocked(mutate).mockReset().mockResolvedValue(anonymous);
    vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('visible');
    event('focus');
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

describe('route-local deferred detail lifecycle', () => {
    it('does not start the module before confirmed authentication', async () => {
        const detail = pendingDetail(); vi.mocked(request).mockResolvedValue(anonymous);
        render(route(detail)); await screen.findByLabelText('Operator password');
        expect(detail.load).not.toHaveBeenCalled(); expect(mounted).not.toHaveBeenCalled();
    });
    it('only mounts the latest device when a pending module resolves', async () => {
        const detail = pendingDetail(), view = await open(detail); view.rerender(route(detail, 'B'));
        await resolve(detail); await screen.findByRole('region', { name: 'Private B' });
        expect(mounted).toHaveBeenCalledTimes(1); expect(mounted).toHaveBeenCalledWith('B', session.actorId);
        expect(screen.queryByRole('region', { name: 'Private A' })).not.toBeInTheDocument(); expect(detail.load).toHaveBeenCalledTimes(1);
    });
    it('retains suspension across keyed route replacement and a route-away/return', async () => {
        const detail = pendingDetail(), view = await open(detail); event('blur');
        view.rerender(route(detail, 'B')); await resolve(detail); expect(mounted).not.toHaveBeenCalled();
        view.rerender(<DetailLoadingLifecycle><AuthBoundary><h1>Overview</h1></AuthBoundary></DetailLoadingLifecycle>);
        view.rerender(route(detail, 'C')); expect(mounted).not.toHaveBeenCalled();
        event('focus'); await screen.findByRole('region', { name: 'Private C' });
        expect(mounted).toHaveBeenCalledExactlyOnceWith('C', session.actorId);
    });
    it('retains suspension through auth invalidation and fresh login while blurred', async () => {
        const detail = pendingDetail(); await open(detail); event('blur'); event(AUTH_REQUIRED_EVENT);
        await screen.findByLabelText('Operator password'); await resolve(detail);
        vi.mocked(request).mockResolvedValue({ ...session, actorId: `operator_${'2'.repeat(32)}`, csrfToken: 'replacement' });
        fireEvent.change(screen.getByLabelText('Operator username'), { target: { value: 'fixture' } });
        fireEvent.change(screen.getByLabelText('Operator password'), { target: { value: 'synthetic-password' } });
        fireEvent.click(screen.getByRole('button', { name: 'Sign in' })); await screen.findByText('Loading view …');
        expect(mounted).not.toHaveBeenCalled(); event('focus'); await screen.findByRole('region', { name: 'Private A' });
        expect(mounted).toHaveBeenCalledExactlyOnceWith('A', `operator_${'2'.repeat(32)}`);
    });
    it('cannot mount late private content after navigation away', async () => {
        const detail = pendingDetail(), view = await open(detail); view.rerender(<DetailLoadingLifecycle><AuthBoundary><h1>Overview</h1></AuthBoundary></DetailLoadingLifecycle>);
        await resolve(detail); expect(mounted).not.toHaveBeenCalled(); expect(screen.getByRole('heading', { name: 'Overview' })).toBeVisible();
        view.rerender(route(detail)); await screen.findByRole('region', { name: 'Private A' }); expect(detail.load).toHaveBeenCalledTimes(1);
    });
    it('discards pending content on auth invalidation and mounts only after fresh login', async () => {
        const detail = pendingDetail(); await open(detail); event(AUTH_REQUIRED_EVENT); await screen.findByLabelText('Operator password');
        await resolve(detail); expect(mounted).not.toHaveBeenCalled();
        vi.mocked(request).mockResolvedValue({ ...session, actorId: `operator_${'2'.repeat(32)}`, csrfToken: 'replacement' });
        fireEvent.change(screen.getByLabelText('Operator username'), { target: { value: 'fixture' } });
        fireEvent.change(screen.getByLabelText('Operator password'), { target: { value: 'synthetic-password' } });
        fireEvent.click(screen.getByRole('button', { name: 'Sign in' })); await screen.findByRole('region', { name: 'Private A' });
        expect(mounted).toHaveBeenCalledExactlyOnceWith('A', `operator_${'2'.repeat(32)}`);
    });
    it('cannot remount a detail after logout while its module is pending', async () => {
        const detail = pendingDetail(); await open(detail); fireEvent.click(screen.getByRole('button', { name: 'Sign out' }));
        await screen.findByLabelText('Operator password'); await resolve(detail); expect(mounted).not.toHaveBeenCalled();
        expect(vi.mocked(mutate).mock.calls.map(([path]) => path)).toEqual(['/auth/logout']);
    });
    it('waits after blur even though visibility still says visible', async () => {
        const detail = pendingDetail(); await open(detail); event('blur'); await resolve(detail);
        expect(mounted).not.toHaveBeenCalled(); expect(screen.queryByLabelText('Private draft')).not.toBeInTheDocument();
        event('focus'); await screen.findByRole('region', { name: 'Private A' }); expect(mounted).toHaveBeenCalledTimes(1);
    });
    it.each([
        ['blur', 'event-first'], ['blur', 'resolve-first'],
        ['pagehide', 'event-first'], ['pagehide', 'resolve-first'],
    ])('blocks first commit for same-task %s and import completion (%s)', async (suspension, order) => {
        const detail = pendingDetail(); await open(detail);
        await act(async () => {
            // No intermediate await/render: the pending Suspense retry and
            // eager suspension update must settle together in this task.
            if (order === 'event-first') window.dispatchEvent(new Event(suspension));
            detail.resolve();
            if (order === 'resolve-first') window.dispatchEvent(new Event(suspension));
        });
        expect(mounted).not.toHaveBeenCalled();
        expect(screen.queryByLabelText('Private draft')).not.toBeInTheDocument();
        if (suspension === 'pagehide') event('pageshow', true); else event('focus');
        await screen.findByRole('region', { name: 'Private A' });
        expect(mounted).toHaveBeenCalledTimes(1);
    });
    it.each(['pagehide', 'hidden'])('waits through %s and real auth revalidation before first mount', async suspension => {
        const detail = pendingDetail(); await open(detail);
        if (suspension === 'hidden') { vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden'); act(() => document.dispatchEvent(new Event('visibilitychange'))); } else event('pagehide');
        await resolve(detail); expect(mounted).not.toHaveBeenCalled();
        let finish!: (value: OperatorSession) => void;
        vi.mocked(request).mockImplementation(() => new Promise<OperatorSession>(yes => { finish = yes; }));
        if (suspension === 'hidden') { vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('visible'); act(() => document.dispatchEvent(new Event('visibilitychange'))); } else event('pageshow', true);
        await waitFor(() => expect(finish).toBeDefined()); event('focus'); expect(mounted).not.toHaveBeenCalled();
        expect(document.querySelector('.auth-private-view')).toHaveAttribute('inert');
        await act(async () => finish(session)); await screen.findByRole('region', { name: 'Private A' }); expect(mounted).toHaveBeenCalledTimes(1);
    });
    it('uses the replacement actor when resume revalidation replaces a pending session', async () => {
        const detail = pendingDetail(); await open(detail); event('pagehide'); await resolve(detail);
        vi.mocked(request).mockResolvedValue({ ...session, actorId: `operator_${'2'.repeat(32)}`, csrfToken: 'new-session' });
        event('pageshow', true); await screen.findByRole('region', { name: 'Private A' });
        expect(mounted).toHaveBeenCalledExactlyOnceWith('A', `operator_${'2'.repeat(32)}`);
    });
    it('never mounts pending content when resume access is denied', async () => {
        const detail = pendingDetail(); await open(detail); event('pagehide'); await resolve(detail);
        vi.mocked(request).mockResolvedValue(anonymous); event('pageshow', true); await screen.findByLabelText('Operator password'); expect(mounted).not.toHaveBeenCalled();
    });
    it('preserves loaded drafts and component identity across ordinary lifecycle and locale updates', async () => {
        const detail = pendingDetail(); await open(detail); await resolve(detail);
        const input = await screen.findByLabelText('Private draft'); fireEvent.change(input, { target: { value: 'unsaved fixture' } });
        event('blur'); event('focus'); event('pagehide'); event('pageshow', true);
        await waitFor(() => expect(document.querySelector('.auth-private-view')).not.toHaveAttribute('inert')); act(() => setLocale('de', false));
        expect(screen.getByLabelText('Private draft')).toBe(input); expect(input).toHaveValue('unsaved fixture');
        expect(mounted).toHaveBeenCalledTimes(1); expect(unmounted).not.toHaveBeenCalled();
    });
    it('provides a contained generic failure with deliberate page reload and usable navigation', async () => {
        const detail = pendingDetail(), onBack = vi.fn(); vi.spyOn(console, 'error').mockImplementation(() => {});
        render(<RouteDetailBoundary onBack={onBack} backLabel="Back to devices"><detail.Detail/></RouteDetailBoundary>);
        await act(async () => detail.reject()); expect(await screen.findByRole('alert')).toHaveTextContent('View could not be loaded');
        expect(screen.queryByText(/Sensitive implementation/)).not.toBeInTheDocument(); expect(screen.getByRole('button', { name: 'Reload page' })).toBeEnabled();
        event('focus'); event('pageshow', true); act(() => setLocale('de', false)); expect(screen.getByRole('button', { name: 'Seite neu laden' })).toBeEnabled();
        expect(detail.load).toHaveBeenCalledTimes(1); expect(mutate).not.toHaveBeenCalled();
        fireEvent.click(screen.getByRole('button', { name: 'Back to devices' })); expect(onBack).toHaveBeenCalledTimes(1);
        fireEvent.keyDown(document, { key: 'Escape' }); expect(onBack).toHaveBeenCalledTimes(2);
    });
    it('keeps Escape owned by a modal while pending and lets Back replace the pending route', async () => {
        const detail = pendingDetail();
        function Host() { const [open, setOpen] = useState(true); return open ? <RouteDetailBoundary onBack={() => setOpen(false)} backLabel="Back"><detail.Detail/></RouteDetailBoundary> : <h1>Devices</h1>; }
        render(<Host/>); const modal = document.createElement('div'); modal.setAttribute('role', 'dialog'); document.body.append(modal);
        fireEvent.keyDown(document, { key: 'Escape' }); expect(screen.getByText('Loading view …')).toBeVisible(); modal.remove();
        fireEvent.keyDown(document, { key: 'Escape' }); await screen.findByRole('heading', { name: 'Devices' }); await resolve(detail); expect(mounted).not.toHaveBeenCalled();
    });
});
