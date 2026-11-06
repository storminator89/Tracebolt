import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, AUTH_REQUIRED_EVENT, request } from './api';
import { setLocale } from './i18n';
import { WindowsInventoryWorkspace } from './windows-inventory';
import { useWindowsInventory, type WindowsInventoryResource } from './windows-inventory-resource';
import { windowsDeviceId, windowsNow } from './windows-inventory-fixture';
import { windowsServiceStartupView } from './windows-service-startup-fixture';
import { windowsServicesDigest } from './windows-service-startup-types';
import type { WindowsInventoryView } from './windows-inventory-types';
import { capturedServiceTriage } from './windows-service-triage';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn() }));
function resource(view: WindowsInventoryView = windowsServiceStartupView()): WindowsInventoryResource {
    return { updates: null, updatesStale: false, updatesExpired: false, updatesAhead: false, elapsedMS: 0, view, snapshot: view.snapshot, status: view.status, loading: false, error: null, refresh: vi.fn(), serviceStartup: view.serviceStartup ?? null, serviceStartupStale: view.status === 'stale', processMetrics: null, processMetricsStale: false, network: null, networkStale: false, networkExpired: false, adapterContext: null, adapterContextStale: false, adapterContextExpired: false, patchContext: null, patchContextStale: false, patchContextExpired: false, patchContextAhead: false, storageIO: null, storageIOStale: false, storageIOExpired: false, storageIOAhead: false, storageContext: null, storageContextStale: false, storageContextExpired: false, storageContextAhead: false, resourceContext: null, resourceContextStale: false, resourceContextExpired: false, resourceContextAhead: false, hardwareContext: null, hardwareContextStale: false, hardwareContextExpired: false, hardwareContextAhead: false, sessionContext: null, sessionContextStale: false, sessionContextExpired: false, sessionContextAhead: false, securityCoverage: null, securityCoverageStale: false, securityCoverageExpired: false, securityCoverageAhead: false, securityPosture: null, securityPostureStale: false, securityPostureExpired: false, securityPostureAhead: false, volumes: null, volumesStale: false, events: null, eventsStale: false };
}
function Harness({ id = windowsDeviceId, session = 'fixture' }: { id?: string; session?: string }) { return <WindowsInventoryWorkspace key={`${id}:${session}`} resource={useWindowsInventory(id, true, session)}/>; }
const flush = () => act(async () => {});
const services = (de = false) => fireEvent.click(screen.getByRole('tab', { name: de ? 'Dienste' : 'Services' }));
const names = () => within(screen.getByRole('table', { name: 'Services' })).getAllByRole('row').slice(1).map(row => within(row).getAllByRole('cell')[0].textContent);
const filter = (name: string) => fireEvent.click(screen.getByRole('button', { name }));
beforeEach(() => { setLocale('en', false); vi.mocked(request).mockReset().mockResolvedValue(windowsServiceStartupView()); });
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.restoreAllMocks(); });

describe('captured service triage model', () => {
    it('uses exact source states, not names, PID zero or text labels', () => {
        const view = windowsServiceStartupView(7), snapshot = view.snapshot!;
        const states = ['running', 'stopped', 'start_pending', 'stop_pending', 'continue_pending', 'pause_pending', 'paused'] as const;
        snapshot.services.rows.forEach((row, index) => { row.state = states[index]; row.pid = 0; row.name = 'stopped automatic'; });
        const counts = capturedServiceTriage(snapshot, null);
        expect([...counts.all]).toEqual([0, 1, 2, 3, 4, 5, 6]); expect([...counts.stopped]).toEqual([1]); expect([...counts.transitioning]).toEqual([2, 3, 4, 5]);
        expect(counts['startup-unknown'].size).toBe(7); expect(counts['automatic-stopped'].size).toBe(0);
    });
    it('uses original indices for duplicate names and counts known mode despite unknown delayed state', () => {
        const view = windowsServiceStartupView(), snapshot = view.snapshot!;
        snapshot.services.rows.forEach(row => { row.name = 'same'; row.state = 'stopped'; });
        view.serviceStartup.servicesSHA256 = windowsServicesDigest(snapshot.services.rows);
        const before = JSON.stringify(view), counts = capturedServiceTriage(snapshot, view.serviceStartup);
        expect([...counts['automatic-stopped']]).toEqual([0, 1, 7, 8, 9]); expect([...counts['startup-unknown']]).toEqual([4, 5, 6]);
        expect(counts.all.size).toBe(10); expect(JSON.stringify(view)).toBe(before);
    });
    it('keeps trimmed and denied metadata unknown, never manual or disabled', () => {
        const view = windowsServiceStartupView(); view.serviceStartup.rows = view.serviceStartup.rows.filter(row => [1, 4, 7].includes(row.serviceIndex)); view.serviceStartup.truncated = true;
        const counts = capturedServiceTriage(view.snapshot!, view.serviceStartup);
        expect([...counts['automatic-stopped']]).toEqual([1, 7]); expect([...counts['startup-unknown']]).toEqual([0, 2, 3, 4, 5, 6, 8, 9]);
    });
    it.each(['generation', 'count'] as const)('withholds startup classification on a foreign %s binding', field => {
        const view = windowsServiceStartupView();
        if (field === 'generation') view.serviceStartup.generationId = `sample_${'b'.repeat(32)}`;
        if (field === 'count') view.serviceStartup.requestedCount = 9;
        const counts = capturedServiceTriage(view.snapshot!, view.serviceStartup);
        expect(counts.stopped.size).toBe(5); expect(counts['automatic-stopped'].size).toBe(0); expect(counts['startup-unknown'].size).toBe(10);
    });
    it('handles successful empty captures without inventing a healthy service', () => {
        const view = windowsServiceStartupView(0); expect(Object.values(capturedServiceTriage(view.snapshot!, view.serviceStartup)).every(rows => rows.size === 0)).toBe(true);
    });
});

describe('captured service triage controls', () => {
    it.each(['en', 'de'] as const)('offers clear %s counts, scope and non-fault explanation', locale => {
        const de = locale === 'de'; setLocale(locale, false); render(<WindowsInventoryWorkspace resource={resource()}/>); services(de);
        const group = screen.getByRole('group', { name: de ? 'Erfasste Dienste prüfen' : 'Review captured services' });
        expect(within(group).getAllByRole('button')).toHaveLength(5);
        const automatic = within(group).getByRole('button', { name: de ? 'Automatisch + gestoppt (3)' : 'Automatic + stopped (3)' }); fireEvent.click(automatic); expect(automatic).toHaveAttribute('aria-pressed', 'true');
        expect(screen.getByText(de ? /Das belegt weder einen Fehler/ : /This is not proof of a fault/)).toBeVisible();
        expect(within(screen.getByRole('table', { name: de ? 'Dienste' : 'Services' })).getAllByRole('row')).toHaveLength(4);
        expect(group).toHaveAccessibleDescription(de ? /vor dem Textfilter/ : /before the text filter/);
        const icon = document.querySelector('.windows-service-triage svg'); expect(icon).toHaveAttribute('aria-hidden', 'true'); expect(icon).toHaveAttribute('focusable', 'false');
    });
    it('intersects text and exact filters while keeping captured counts independent', () => {
        render(<WindowsInventoryWorkspace resource={resource()}/>); services(); filter('Stopped (5)');
        expect(names()).toEqual(['Service-002', 'Service-004', 'Service-006', 'Service-008', 'Service-010']);
        fireEvent.change(screen.getByRole('searchbox'), { target: { value: 'Service-008' } }); expect(names()).toEqual(['Service-008']); expect(screen.getByRole('button', { name: 'Stopped (5)' })).toHaveAttribute('aria-pressed', 'true');
        expect(screen.getByText('Rows 1–1 of 1 matching · 10 captured')).toBeVisible();
        filter('Startup unknown (3)'); expect(screen.queryByRole('table')).toBeNull(); expect(screen.getByText('No captured rows match this filter.')).toBeVisible();
        fireEvent.change(screen.getByRole('searchbox'), { target: { value: '' } }); expect(names()).toEqual(['Service-005', 'Service-006', 'Service-007']);
        expect(screen.getByText(/These rows do not establish manual or disabled startup/)).toBeVisible();
    });
    it('retains sort and text, resets page on each filter selection, and supports keyboard repeats', async () => {
        const user = userEvent.setup(); render(<WindowsInventoryWorkspace resource={resource(windowsServiceStartupView(128))}/>); services();
        fireEvent.change(screen.getByRole('searchbox'), { target: { value: 'Service' } }); fireEvent.change(screen.getByRole('combobox'), { target: { value: 'name-desc' } });
        fireEvent.click(screen.getByRole('button', { name: 'Next page' })); expect(screen.getByText('Page 2 of 6')).toBeVisible();
        const stopped = screen.getByRole('button', { name: 'Stopped (64)' }); stopped.focus(); await user.keyboard('{Enter}'); expect(stopped).toHaveFocus(); expect(screen.getByText('Page 1 of 3')).toBeVisible();
        expect(screen.getByRole('searchbox')).toHaveValue('Service'); expect(screen.getByRole('combobox')).toHaveValue('name-desc'); expect(names()[0]).toBe('Service-128');
        const seen = [...names()]; fireEvent.click(screen.getByRole('button', { name: 'Next page' })); seen.push(...names()); fireEvent.click(screen.getByRole('button', { name: 'Next page' })); seen.push(...names());
        expect(seen).toHaveLength(64); expect(new Set(seen).size).toBe(64); stopped.focus(); await user.keyboard(' '); expect(screen.getByText('Page 1 of 3')).toBeVisible();
        expect(document.querySelectorAll('.windows-service-triage-options [aria-pressed=true]')).toHaveLength(1);
    });
    it('makes no requests, storage writes, navigation, links or action controls', () => {
        const before = JSON.stringify(windowsServiceStartupView()); const storage = vi.spyOn(Storage.prototype, 'setItem'), push = vi.spyOn(history, 'pushState'), replace = vi.spyOn(history, 'replaceState');
        render(<WindowsInventoryWorkspace resource={resource()}/>); services();
        for (const name of ['Stopped (5)', 'In transition (0)', 'Automatic + stopped (3)', 'Startup unknown (3)', 'All captured (10)']) filter(name);
        expect(request).not.toHaveBeenCalled(); expect(storage).not.toHaveBeenCalled(); expect(push).not.toHaveBeenCalled(); expect(replace).not.toHaveBeenCalled(); expect(screen.queryByRole('link')).toBeNull();
        expect(screen.queryByRole('button', { name: /approve|start service|stop service|restart service|kill|enable/i })).toBeNull(); expect(JSON.stringify(windowsServiceStartupView())).toBe(before);
    });
    it('does not add triage controls to software and resets on tab departure', () => {
        render(<WindowsInventoryWorkspace resource={resource()}/>); services(); filter('Stopped (5)'); fireEvent.click(screen.getByRole('tab', { name: 'Software' })); expect(screen.queryByRole('group', { name: 'Review captured services' })).toBeNull();
        services(); expect(screen.getByRole('button', { name: 'All captured (10)' })).toHaveAttribute('aria-pressed', 'true');
    });
    it('retains controls during a hidden same-snapshot load and resets on new original evidence', () => {
        const view = windowsServiceStartupView(), ui = render(<WindowsInventoryWorkspace resource={resource(view)}/>); services(); filter('Stopped (5)');
        ui.rerender(<WindowsInventoryWorkspace resource={{ ...resource(view), snapshot: null, view: null, loading: true }}/>); expect(screen.queryByRole('group', { name: 'Review captured services' })).toBeNull(); expect(screen.queryByRole('table')).toBeNull();
        ui.rerender(<WindowsInventoryWorkspace resource={resource(view)}/>); expect(screen.getByRole('button', { name: 'Stopped (5)' })).toHaveAttribute('aria-pressed', 'true');
        const next = windowsServiceStartupView(); next.snapshot!.generationId = next.serviceStartup.generationId = `sample_${'b'.repeat(32)}`; ui.rerender(<WindowsInventoryWorkspace resource={resource(next)}/>); expect(screen.getByRole('button', { name: 'All captured (10)' })).toHaveAttribute('aria-pressed', 'true');
    });
    it('recomputes unknown startup when independently admitted metadata disappears', () => {
        const view = windowsServiceStartupView(), ui = render(<WindowsInventoryWorkspace resource={resource(view)}/>); services(); filter('Automatic + stopped (3)');
        ui.rerender(<WindowsInventoryWorkspace resource={{ ...resource(view), serviceStartup: null }}/>); expect(screen.queryByRole('table')).toBeNull(); expect(screen.getByRole('button', { name: 'Automatic + stopped (0)' })).toHaveAttribute('aria-pressed', 'true'); filter('Startup unknown (10)'); expect(names()).toHaveLength(10);
    });
    it.each(['blur', 'hashchange', 'pagehide', AUTH_REQUIRED_EVENT])('clears triage with the protected resource on %s', async event => {
        render(<Harness/>); await flush(); services(); filter('Stopped (5)'); act(() => window.dispatchEvent(new Event(event)));
        expect(screen.queryByRole('group', { name: 'Review captured services' })).toBeNull(); expect(screen.queryByRole('table')).toBeNull(); expect(document.body.textContent).not.toContain('Service-002');
    });
    it('does not expose triage or rows when the existing parser rejects a foreign startup digest', async () => {
        const view = windowsServiceStartupView(); view.serviceStartup.servicesSHA256 = '0'.repeat(64); vi.mocked(request).mockResolvedValue(view);
        render(<Harness/>); await flush(); services(); expect(screen.queryByRole('group', { name: 'Review captured services' })).toBeNull(); expect(screen.queryByRole('table')).toBeNull();
    });
    it('clears triage at the original capture expiry without fetching or extending age', async () => {
        vi.useFakeTimers(); vi.setSystemTime(windowsNow); const view = windowsServiceStartupView(); view.status = 'stale'; view.snapshot!.collectedAt = view.serviceStartup.collectedAt = '2026-10-06T12:00:11Z'; vi.mocked(request).mockResolvedValue(view);
        render(<Harness/>); await flush(); services(); filter('Stopped (5)'); await act(async () => vi.advanceTimersByTimeAsync(1000));
        expect(screen.queryByRole('group', { name: 'Review captured services' })).toBeNull(); expect(screen.queryByRole('table')).toBeNull(); expect(request).toHaveBeenCalledTimes(1);
    });
});
