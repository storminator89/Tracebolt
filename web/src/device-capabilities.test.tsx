import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { DeviceCapabilities } from './device-capabilities';
import { APIError, AUTH_REQUIRED_EVENT, request } from './api';
import { setLocale } from './i18n';
import { systemDevice, systemView } from './system-inventory-fixtures';
import type { Device } from './types';
import type { SystemView } from './system-inventory-types';
import { journalSession, journalView } from './journal-fixtures';
import { overviewView } from './complete-overview-fixtures';
import { completeView } from './complete-packages-fixtures';
import { validCompletePackageView } from './complete-packages-types';
import type { CompletePackageView } from './complete-packages-types';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn() }));
const authFixture = vi.hoisted(() => ({ expiresAt: '2026-10-05T00:00:00Z' }));
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), hasLogoutIntent: () => false, useOperator: () => ({ mode: 'lan', authenticated: true, expiresAt: authFixture.expiresAt, insecureTestMode: false }) }));
const device = (): Device => ({ id: systemDevice, name: 'Synthetic fixture', platform: 'linux', os: 'Debian fixture', source: 'lan', synthetic: false, status: 'unknown', lastSeen: '2026-10-04T00:00:00Z', capabilities: [
    { id: 'host_inventory', name: 'Host attribution', status: 'limited', detail: 'Static scope is not a failed read.' },
    { id: 'systemd', name: 'Service inventory', status: 'scope', detail: 'Source data must establish this result.' },
    { id: 'socket_inventory', name: 'Connections', status: 'scope', detail: 'Owner fields are separate.' },
    { id: 'remote_actions', name: 'Remote control', status: 'unsupported', detail: 'Not part of this read profile.' },
] } as Device);
const row = (id: string) => document.querySelector(`[data-capability="${id}"]`)!;
beforeEach(() => { authFixture.expiresAt = '2026-10-05T00:00:00Z'; setLocale('en', false); vi.mocked(request).mockReset().mockImplementation(async () => systemView()); });
afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); });

describe('compact capability collection status', () => {
    it.each(['en', 'de'] as const)('keeps completed source evidence when a later status read times out (%s)', async locale => {
        setLocale(locale, false);
        vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'performance', 'Date'] });
        const overview = overviewView(); overview.serverNow = '2026-10-04T18:30:10Z';
        authFixture.expiresAt = new Date(Date.parse(overview.serverNow) + 300000).toISOString();
        let resolve!: (value: CompletePackageView) => void, signal: AbortSignal | undefined;
        vi.mocked(request).mockImplementation(async (path, options) => {
            if (path.endsWith('/overview')) return overview;
            signal = options?.signal as AbortSignal;
            return new Promise<CompletePackageView>(r => { resolve = r; });
        });
        const d = device(); d.id = overview.deviceId; d.capabilities.push(
            { id: 'complete_process_inventory', name: 'Complete processes', status: 'scope', detail: 'Accepted complete generation.' },
            { id: 'package_inventory', name: 'Complete packages', status: 'scope', detail: 'Independent source status.' },
        );
        render(<DeviceCapabilities device={d}/>);
        await act(async () => { await Promise.resolve(); });
        expect(request).toHaveBeenCalledTimes(2);
        expect(row('complete_process_inventory')).toHaveAttribute('data-state', 'available');
        const capturedAt = row('complete_process_inventory').querySelector('time')!.dateTime;
        await act(async () => { await vi.advanceTimersByTimeAsync(10000); });
        expect(signal!.aborted).toBe(true);
        expect(row('complete_process_inventory')).toHaveAttribute('data-state', 'available');
        expect(row('complete_process_inventory').querySelector('time')!.dateTime).toBe(capturedAt);
        expect(row('complete_process_inventory')).not.toHaveTextContent('timeout');
        expect(row('systemd')).toHaveAttribute('data-state', 'failed');
        expect(row('socket_inventory')).toHaveAttribute('data-state', 'failed');
        expect(row('package_inventory')).toHaveAttribute('data-state', 'failed');
        expect(row('systemd')).toHaveTextContent('timeout');
        expect(row('systemd')).toHaveTextContent(locale === 'de' ? 'Technisch fehlgeschlagen' : 'Technical failure');
        // A response ignored by the aborted transport must not replace timeout.
        const late = completeView(); late.deviceId = d.id;
        expect(validCompletePackageView(late, d.id)).toBe(true);
        await act(async () => resolve(late));
        expect(row('package_inventory')).toHaveAttribute('data-state', 'failed');
        expect(row('package_inventory')).toHaveTextContent('timeout');
        expect(row('package_inventory').querySelector('time')).toBeNull();
        expect(row('systemd')).toHaveAttribute('data-state', 'failed');
        expect(request).toHaveBeenCalledTimes(2);
        expect(vi.mocked(request).mock.calls.map(([path]) => path)).toEqual([
            `/devices/${d.id}/inventory/overview`, `/devices/${d.id}/inventory/packages`,
        ]);
        await act(async () => { await vi.advanceTimersByTimeAsync(100001); });
        expect(row('complete_process_inventory')).toHaveAttribute('data-state', 'stale');
        expect(row('complete_process_inventory').querySelector('time')!.dateTime).toBe(capturedAt);
        expect(vi.mocked(request).mock.calls.every(([, options]) => !options?.method || options.method === 'GET')).toBe(true);
    });
    it.each([
        ['operator denial', 'denied', 'operator_access_denied'],
        ['invalid response', 'failed', 'invalid_status'],
        ['unreadable source', 'failed', 'status_unavailable'],
    ])('does not replace a completed %s with a sibling timeout', async (kind, state, reason) => {
        vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'performance', 'Date'] });
        vi.mocked(request).mockImplementation(async path => {
            if (!path.endsWith('/overview')) return new Promise(() => {});
            if (kind === 'operator denial') throw new APIError('DO_NOT_DISPLAY_RAW_SOURCE_ERROR', 403);
            if (kind === 'invalid response') return { invalid: 'DO_NOT_DISPLAY_RAW_SOURCE_ERROR' };
            throw new Error('DO_NOT_DISPLAY_RAW_SOURCE_ERROR');
        });
        const d = device(); d.capabilities.push({ id: 'complete_process_inventory', name: 'Complete processes', status: 'scope', detail: 'Independent source.' });
        render(<DeviceCapabilities device={d}/>);
        await act(async () => { await Promise.resolve(); });
        expect(row('complete_process_inventory')).toHaveAttribute('data-state', state);
        expect(row('complete_process_inventory')).toHaveTextContent(reason);
        await act(async () => { await vi.advanceTimersByTimeAsync(10000); });
        expect(row('complete_process_inventory')).toHaveAttribute('data-state', state);
        expect(row('complete_process_inventory')).toHaveTextContent(reason);
        expect(row('complete_process_inventory')).not.toHaveTextContent('timeout');
        expect(row('systemd')).toHaveTextContent('timeout');
        expect(document.body).not.toHaveTextContent('DO_NOT_DISPLAY_RAW_SOURCE_ERROR');
    });
    it('replaces static orange scope badges with actual bounded source status', async () => {
        render(<DeviceCapabilities device={device()}/>);
        await waitFor(() => expect(row('systemd')).toHaveAttribute('data-state', 'available'));
        expect(row('systemd')).toHaveTextContent('Collected');
        expect(row('host_inventory')).toHaveAttribute('data-state', 'scope');
        expect(row('remote_actions')).toHaveAttribute('data-state', 'unsupported');
        expect(document.querySelectorAll('.capability-row.attention')).toHaveLength(0);
        expect(row('systemd').querySelector('details')).not.toHaveAttribute('open');
        expect(screen.getByText('Source data must establish this result.')).not.toBeVisible();
        fireEvent.click(row('systemd').querySelector('summary')!);
        expect(screen.getByText('Source data must establish this result.')).toBeVisible();
        expect(request).toHaveBeenCalledTimes(1);
        expect(vi.mocked(request).mock.calls[0][0]).toBe(`/devices/${systemDevice}/inventory/system`);
        expect(row('socket_inventory')).toHaveAttribute('data-state', 'available');
        const summary = document.querySelector('.device-readiness')!;
        expect(summary.querySelector('[data-readiness-state="available"]')).toHaveTextContent('2 Collected');
        expect(summary.querySelector('[data-readiness-state="scope"]')).toHaveTextContent('1 Profile scope');
        expect(summary.querySelector('[data-readiness-state="unsupported"]')).toHaveTextContent('1 Not supported');
        expect(summary).toHaveTextContent('managed-operations-v3');
        const counts = [...summary.querySelectorAll('[data-readiness-state] strong')].map(item => Number(item.textContent));
        expect(counts.reduce((sum, count) => sum + count, 0)).toBe(document.querySelectorAll('[data-capability]').length);
    });
    it('keeps permission failure visible but treats unsupported source as neutral', async () => {
        const v = systemView();
        v.latest!.services = { ...v.latest!.services, coverage: 'failed', reason: 'permission_denied', observedCount: null, countExact: false };
        v.latest!.sockets = { ...v.latest!.sockets, coverage: 'failed', reason: 'not_supported', observedCount: null, countExact: false };
        vi.mocked(request).mockResolvedValue(v);
        render(<DeviceCapabilities device={device()}/>);
        await waitFor(() => expect(row('systemd')).toHaveAttribute('data-state', 'denied'));
        expect(row('systemd')).toHaveClass('attention');
        expect(row('systemd')).toHaveTextContent('Permission denied');
        expect(row('socket_inventory')).toHaveAttribute('data-state', 'unsupported');
        expect(row('socket_inventory')).not.toHaveClass('attention');
    });
    it('does not display success for malformed, wrong-device or unreadable status', async () => {
        vi.mocked(request).mockResolvedValue({ ...systemView(), deviceId: 'agent_other' });
        render(<DeviceCapabilities device={device()}/>);
        await waitFor(() => expect(screen.getByRole('button', { name: 'Check status' })).toBeEnabled());
        expect(row('systemd')).toHaveAttribute('data-state', 'failed');
        vi.mocked(request).mockRejectedValue(new APIError('Denied', 403));
        fireEvent.click(screen.getByRole('button', { name: 'Check status' }));
        await waitFor(() => expect(row('systemd')).toHaveAttribute('data-state', 'denied'));
        expect(row('systemd')).toHaveTextContent('operator_access_denied');
    });
    it('aborts on suspension and discards late results before a fresh resume read', async () => {
        let resolve!: (value: SystemView) => void, signal: AbortSignal | undefined;
        vi.mocked(request).mockImplementation(async (_, options) => { signal = options?.signal as AbortSignal; return new Promise<SystemView>(r => { resolve = r; }); });
        render(<DeviceCapabilities device={device()}/>);
        await waitFor(() => expect(signal).toBeDefined());
        fireEvent.blur(window); expect(signal!.aborted).toBe(true);
        await act(async () => resolve(systemView()));
        expect(row('systemd')).toHaveAttribute('data-state', 'unknown');
        vi.mocked(request).mockResolvedValue(systemView()); fireEvent.focus(window);
        await waitFor(() => expect(row('systemd')).toHaveAttribute('data-state', 'available'));
        act(() => window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT)));
        expect(row('systemd')).toHaveAttribute('data-state', 'unknown');
        expect(screen.getByRole('button', { name: 'Check status' })).toBeDisabled();
        expect(document.querySelector('.device-readiness')).toHaveTextContent('Current evidence unavailable');
        expect(document.querySelector('.device-readiness [data-readiness-state]')).toBeNull();
        fireEvent.focus(window); expect(request).toHaveBeenCalledTimes(2);
    });
    it('does not renew the age of an unchanged source when server time stalls', async () => {
        vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'performance', 'Date'] });
        render(<DeviceCapabilities device={device()}/>);
        await act(async () => { await Promise.resolve(); });
        expect(row('systemd')).toHaveAttribute('data-state', 'available');
        await act(async () => { await vi.advanceTimersByTimeAsync(111000); });
        expect(request).toHaveBeenCalledTimes(8);
        expect(row('systemd')).toHaveAttribute('data-state', 'stale');
        expect(row('systemd')).toHaveTextContent('Stale');
    });
    it('manual refresh preserves stale age under unchanged server time and resets only for a different device', async () => {
        vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'performance', 'Date'] });
        const rendered = render(<DeviceCapabilities device={device()}/>);
        await act(async () => { await Promise.resolve(); });
        await act(async () => { await vi.advanceTimersByTimeAsync(111000); });
        expect(row('systemd')).toHaveAttribute('data-state', 'stale');
        for (let attempt = 0; attempt < 3; attempt++) {
            fireEvent.click(screen.getByRole('button', { name: 'Check status' }));
            await act(async () => { await Promise.resolve(); });
            expect(row('systemd')).toHaveAttribute('data-state', 'stale');
        }
        const next = { ...device(), id: 'agent_new_capability_fixture' };
        vi.mocked(request).mockResolvedValue({ ...systemView(), deviceId: next.id });
        rendered.rerender(<DeviceCapabilities device={next}/>);
        await act(async () => { await Promise.resolve(); });
        expect(row('systemd')).toHaveAttribute('data-state', 'available');
    });
    it('manual refresh cannot extend the original session deadline', async () => {
        vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'performance', 'Date'] });
        authFixture.expiresAt = '2026-10-04T00:00:40Z';
        render(<DeviceCapabilities device={device()}/>);
        await act(async () => { await Promise.resolve(); });
        await act(async () => { await vi.advanceTimersByTimeAsync(20000); });
        fireEvent.click(screen.getByRole('button', { name: 'Check status' }));
        await act(async () => { await Promise.resolve(); });
        await act(async () => { await vi.advanceTimersByTimeAsync(10000); });
        expect(screen.getByRole('button', { name: 'Check status' })).toBeDisabled();
        expect(row('systemd')).toHaveAttribute('data-state', 'unknown');
        expect(screen.getByRole('alert')).toHaveTextContent('Session ended');
    });
    it('keeps older managed service profiles informational without a v3 status request', async () => {
        const v = device(); v.capabilities = [{ id: 'systemd', name: 'Services', status: 'scope', detail: 'Managed operational preview.' }];
        render(<DeviceCapabilities device={v}/>);
        await act(async () => { await Promise.resolve(); });
        expect(row('systemd')).toHaveAttribute('data-state', 'scope');
        expect(request).not.toHaveBeenCalled();
    });
    it('does not issue source requests for a basic profile or a synthetic device', async () => {
        const v = device(); v.capabilities = v.capabilities.filter(c => c.status !== 'scope');
        const rendered = render(<DeviceCapabilities device={v}/>);
        await act(async () => { await Promise.resolve(); }); expect(request).not.toHaveBeenCalled();
        rendered.rerender(<DeviceCapabilities device={{ ...device(), synthetic: true }}/>);
        await act(async () => { await Promise.resolve(); }); expect(request).not.toHaveBeenCalled();
    });
    it.each(['en', 'de'] as const)('explains five distinct gap causes and next steps without creating authority (%s)', async locale => {
        setLocale(locale, false);
        render(<DeviceCapabilities device={device()}/>);
        await waitFor(() => expect(row('systemd')).toHaveAttribute('data-state', 'available'));
        const guide = document.querySelector('.capability-gap-guide')!;
        expect(guide.querySelectorAll('[data-gap]')).toHaveLength(5);
        const expected = locale === 'de' ? ['Nicht unterstützt', 'Lokal nicht freigegeben', 'Noch nicht erfasst', 'Veraltet', 'Technisch fehlgeschlagen'] : ['Not supported', 'Not granted locally', 'Not yet collected', 'Stale', 'Technical failure'];
        expected.forEach(text => expect(within(guide as HTMLElement).getByText(text)).toBeInTheDocument());
        guide.querySelectorAll('dd').forEach(step => expect(step.textContent!.length).toBeGreaterThan(50));
        expect(guide).toHaveTextContent(locale === 'de' ? 'Unbekannt oder nicht eingerichtet belegt keine davon.' : 'Unknown or not configured does not establish any of them.');
        expect(document.querySelector('.capability-heading')).toHaveTextContent(locale === 'de' ? 'Diese Ansicht erteilt keine Freigabe.' : 'This view grants no scope.');
        expect(row('systemd')).toHaveTextContent(locale === 'de' ? 'Im Profil vorgesehen · lokale Freigabe separat' : 'Advertised by profile · local approval separate');
        expect(document.querySelectorAll('input[type=search]')).toHaveLength(1); expect(document.querySelectorAll('select')).toHaveLength(1);
        expect(document.querySelector('input[type=checkbox],textarea,form')).toBeNull();
        expect(vi.mocked(request).mock.calls.every(([, options]) => !options?.method || options.method === 'GET')).toBe(true);
    });
    it('distinguishes explicit waiting, local denial and source failure from an unconfirmed cause', async () => {
        const v = systemView(); v.status = 'awaiting'; v.latest = null; v.sequence = null; v.receivedAt = null; v.lastComplete = { services: null, sockets: null };
        vi.mocked(request).mockResolvedValue(v);
        const shown = render(<DeviceCapabilities device={device()}/>);
        await waitFor(() => expect(row('systemd')).toHaveAttribute('data-state', 'not_collected'));
        expect(row('systemd')).toHaveTextContent('Check the existing agent');
        const j = journalView('awaiting'); j.deviceId = systemDevice; j.localStatus = 'disabled';
        const reply = async (path: string) => path === '/auth/session' ? { ...journalSession, expiresAt: authFixture.expiresAt } : j;
        vi.mocked(request).mockImplementation(reply);
        const d = device(); d.capabilities = [{ id: 'journal_content', name: 'Logs', status: 'scope', detail: 'Profile support alone does not establish local consent.' }];
        shown.rerender(<DeviceCapabilities device={d}/>);
        await waitFor(() => expect(row('journal_content')).toHaveAttribute('data-state', 'not_granted'));
        expect(row('journal_content')).toHaveTextContent('Not granted locally');
        expect(row('journal_content')).toHaveTextContent('any new approval starts unchecked');
        j.configured = false; vi.mocked(request).mockImplementation(reply);
        fireEvent.click(screen.getByRole('button', { name: 'Check status' }));
        await waitFor(() => expect(row('journal_content')).toHaveAttribute('data-state', 'not_configured'));
        expect(row('journal_content')).toHaveTextContent('does not prove whether local consent exists');
        vi.mocked(request).mockRejectedValue(new Error('DO_NOT_DISPLAY_RAW_SOURCE_ERROR'));
        fireEvent.click(screen.getByRole('button', { name: 'Check status' }));
        await waitFor(() => expect(row('journal_content')).toHaveAttribute('data-state', 'failed'));
        expect(row('journal_content')).toHaveTextContent('Technical failure');
        expect(document.body).not.toHaveTextContent('DO_NOT_DISPLAY_RAW_SOURCE_ERROR');
    });
});

describe('local capability list filters', () => {
    const visibleRows = () => [...document.querySelectorAll<HTMLElement>('[data-capability]')].filter(item => !item.hidden);
    const search = () => screen.getByRole('searchbox', { name: 'Search capabilities' });
    const status = () => screen.getByRole('combobox', { name: 'Filter by collection status' });
    async function ready() { await waitFor(() => expect(row('systemd')).toHaveAttribute('data-state', 'available')); }

    it('starts with every row, filters names, IDs and source details locally, and preserves readiness totals', async () => {
        render(<DeviceCapabilities device={device()}/>); await ready();
        expect(visibleRows()).toHaveLength(4); expect(screen.getByRole('status')).toHaveTextContent('4 of 4 capability rows');
        expect(search()).toHaveAttribute('aria-controls', document.querySelector('.capability-observations')!.id);
        expect(status()).toHaveValue('all'); expect(screen.queryByRole('button', { name: 'Clear filters' })).not.toBeInTheDocument();
        const reads = vi.mocked(request).mock.calls.length;
        for (const query of ['  SERVICE INVENTORY  ', 'SYSTEMD', 'Source data must establish']) {
            fireEvent.change(search(), { target: { value: query } });
            expect(visibleRows().map(item => item.dataset.capability)).toEqual(['systemd']);
            expect(screen.getByRole('status')).toHaveTextContent('1 of 4 capability rows'); expect(row('socket_inventory')).not.toBeVisible();
            expect(document.querySelector('[data-readiness-state="available"]')).toHaveTextContent('2 Collected');
        }
        fireEvent.click(screen.getByRole('button', { name: 'Clear filters' }));
        expect(search()).toHaveFocus(); expect(search()).toHaveValue(''); expect(visibleRows()).toHaveLength(4); expect(request).toHaveBeenCalledTimes(reads);
    });
    it('combines search and exact status without relabeling unsupported rows or hidden totals', async () => {
        render(<DeviceCapabilities device={device()}/>); await ready();
        fireEvent.change(status(), { target: { value: 'available' } }); expect(visibleRows().map(item => item.dataset.capability)).toEqual(['systemd', 'socket_inventory']);
        fireEvent.change(search(), { target: { value: 'Connections' } }); expect(visibleRows().map(item => item.dataset.capability)).toEqual(['socket_inventory']);
        fireEvent.change(status(), { target: { value: 'unsupported' } });
        expect(visibleRows()).toHaveLength(0); expect(screen.getByRole('status')).toHaveTextContent('0 of 4 capability rows');
        expect(screen.getByText('No matching capabilities. Change the search or status filter.')).toBeVisible(); expect(row('remote_actions')).toHaveAttribute('data-state', 'unsupported');
        fireEvent.change(search(), { target: { value: '' } }); expect(visibleRows().map(item => item.dataset.capability)).toEqual(['remote_actions']);
        expect(row('remote_actions')).not.toHaveClass('attention'); expect(request).toHaveBeenCalledTimes(1);
    });
    it('supports keyboard filter controls and restores search focus after clearing', async () => {
        const user = userEvent.setup(); render(<DeviceCapabilities device={device()}/>); await ready();
        await user.type(search(), 'systemd');
        await user.tab(); expect(status()).toHaveFocus();
        await user.tab(); expect(screen.getByRole('button', { name: 'Clear filters' })).toHaveFocus();
        await user.keyboard('{Enter}'); expect(search()).toHaveFocus();
        expect(visibleRows()).toHaveLength(4); expect(request).toHaveBeenCalledTimes(1);
    });
    it('keeps source disclosures and capture times through filtering, refresh and locale changes', async () => {
        render(<DeviceCapabilities device={device()}/>); await ready();
        const service = row('systemd'), disclosure = service.querySelector('details')!, summary = service.querySelector('summary')!, at = service.querySelector('time')!.dateTime;
        fireEvent.click(summary); expect(disclosure).toHaveAttribute('open');
        fireEvent.change(search(), { target: { value: 'remote_actions' } }); expect(service).not.toBeVisible();
        fireEvent.change(search(), { target: { value: 'systemd' } });
        expect(row('systemd')).toBe(service); expect(disclosure).toHaveAttribute('open'); expect(within(service as HTMLElement).getByText('Source data must establish this result.')).toBeVisible();
        fireEvent.click(screen.getByRole('button', { name: 'Check status' })); await ready();
        expect(search()).toHaveValue('systemd'); expect(service.querySelector('time')).toHaveAttribute('datetime', at); expect(disclosure).toHaveAttribute('open');
        act(() => setLocale('de', false));
        expect(screen.getByRole('searchbox', { name: 'Fähigkeiten durchsuchen' })).toHaveValue('systemd');
        expect(screen.getByRole('combobox', { name: 'Nach Erfassungsstatus filtern' })).toHaveValue('all'); expect(screen.getByRole('status')).toHaveTextContent('1 von 4 Fähigkeitszeilen'); expect(disclosure).toHaveAttribute('open');
        fireEvent.click(screen.getByRole('button', { name: 'Filter zurücksetzen' })); expect(visibleRows()).toHaveLength(4); expect(request).toHaveBeenCalledTimes(2);
    });
    it('does not restart the reader or renew source age when a selected state disappears', async () => {
        vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'performance', 'Date'] });
        render(<DeviceCapabilities device={device()}/>); await act(async () => {});
        fireEvent.change(status(), { target: { value: 'available' } }); expect(visibleRows()).toHaveLength(2);
        await act(async () => { await vi.advanceTimersByTimeAsync(111000); });
        expect(status()).toHaveValue('available'); expect(screen.getByRole('option', { name: 'Collected' })).toBeInTheDocument();
        expect(row('systemd')).toHaveAttribute('data-state', 'stale'); expect(visibleRows()).toHaveLength(0);
        expect(document.querySelector('[data-readiness-state="stale"]')).toHaveTextContent('2 Stale'); expect(request).toHaveBeenCalledTimes(8);
        fireEvent.click(screen.getByRole('button', { name: 'Clear filters' })); expect(visibleRows()).toHaveLength(4); expect(row('systemd')).toHaveAttribute('data-state', 'stale'); expect(request).toHaveBeenCalledTimes(8);
    });
    it('clears filters permanently across device/session changes and exposes session loss', async () => {
        const mounted = render(<DeviceCapabilities device={device()}/>); await ready();
        fireEvent.change(search(), { target: { value: 'systemd' } }); fireEvent.change(status(), { target: { value: 'available' } });
        const next = { ...device(), id: 'agent_next_filter_fixture' }; vi.mocked(request).mockResolvedValue({ ...systemView(), deviceId: next.id });
        mounted.rerender(<DeviceCapabilities device={next}/>); await ready(); expect(search()).toHaveValue(''); expect(status()).toHaveValue('all');
        vi.mocked(request).mockResolvedValue(systemView()); mounted.rerender(<DeviceCapabilities device={device()}/>); await ready();
        expect(search()).toHaveValue(''); expect(status()).toHaveValue('all');
        fireEvent.change(search(), { target: { value: 'Connections' } }); authFixture.expiresAt = '2026-10-06T00:00:00Z';
        mounted.rerender(<DeviceCapabilities device={device()}/>); await ready(); expect(search()).toHaveValue('');
        fireEvent.change(status(), { target: { value: 'available' } }); act(() => window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT)));
        expect(screen.getByRole('alert')).toHaveTextContent('Session ended'); expect(status()).toHaveValue('all'); expect(visibleRows()).toHaveLength(4);
        expect(row('systemd')).toHaveAttribute('data-state', 'unknown'); expect(document.querySelector('[data-readiness-state]')).toBeNull();
        const reads = vi.mocked(request).mock.calls.length;
        fireEvent.change(search(), { target: { value: 'systemd' } }); fireEvent.click(screen.getByRole('button', { name: 'Clear filters' })); fireEvent.focus(window); expect(request).toHaveBeenCalledTimes(reads);
    });
    it('filters failed observations without hiding the actual reason or introducing a write', async () => {
        vi.mocked(request).mockRejectedValue(new APIError('Do not show raw error', 403));
        render(<DeviceCapabilities device={device()}/>); await waitFor(() => expect(row('systemd')).toHaveAttribute('data-state', 'denied'));
        fireEvent.change(status(), { target: { value: 'denied' } }); fireEvent.change(search(), { target: { value: 'operator_access_denied' } });
        expect(visibleRows()).toHaveLength(2); expect(screen.getByRole('status')).toHaveTextContent('2 of 4 capability rows'); fireEvent.click(row('systemd').querySelector('summary')!);
        expect(within(row('systemd') as HTMLElement).getByText('operator_access_denied')).toBeVisible(); expect(document.body).not.toHaveTextContent('Do not show raw error');
        expect(request).toHaveBeenCalledTimes(1); expect(vi.mocked(request).mock.calls.every(([, options]) => !options?.method || options.method === 'GET')).toBe(true);
    });
    it('does not interpret a supplied empty list as healthy or fetch extra status', () => {
        render(<DeviceCapabilities device={{ ...device(), capabilities: [] }}/>);
        expect(screen.getByRole('status')).toHaveTextContent('0 of 0 capability rows'); expect(screen.getByText('No capabilities supplied for this device.')).toBeVisible();
        expect(screen.queryByText(/^Healthy$/i)).not.toBeInTheDocument(); expect(request).not.toHaveBeenCalled();
    });
});
