import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, AUTH_REQUIRED_EVENT, mutate, mutateRaw, request } from './api';
import { useOperator } from './auth';
import { DeviceDetail } from './details';
import { setLocale } from './i18n';
import { emptyEndpointView } from './endpoint-identity-fixtures';
import { completeView } from './complete-packages-fixtures';
import { updateDevice as id, updatePage, updateRows, updateView } from './complete-updates-fixtures';
import { validCompleteUpdateView } from './complete-updates-types';
import type { HealthView } from './health-types';
import type { Device, Metric } from './types';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutate: vi.fn(), mutateRaw: vi.fn() }));
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
const now = '2026-10-05T04:00:10Z', expiresAt = '2026-10-05T05:00:00Z';
const operator = { mode: 'lan' as const, authenticated: true, expiresAt, insecureTestMode: false, logout: vi.fn(), theme: 'light' as const, setTheme: vi.fn() };
let updates = updateView(12), health: HealthView;
const metric: Metric = { value: 48, unit: '%', quality: 'stale', source: 'Invented original source', collectedAt: '2026-10-05T03:00:00Z' };
function device(): Device {
    return { id, name: 'Synthetic essentials', platform: 'linux', os: 'Linux fixture', site: 'Fixture', group: 'Fixture', ip: null, status: 'unknown', source: 'lan', synthetic: false, lastSeen: metric.collectedAt, agentVersion: 'fixture', cpu: metric, memory: { ...metric, value: null, quality: 'unknown' }, disk: { ...metric, quality: 'denied' }, uptime: '', tags: [], capabilities: [], evidence: [], trend: [], caseIds: [], agentCertificate: { source: 'guided-enrollment', expiresAt: now, checkedAt: now } };
}
function answer(path: string) {
    if (path === `/devices/${id}`) return device();
    if (path.endsWith('/inventory/endpoint-identity')) return { ...emptyEndpointView(), deviceId: id };
    if (path.endsWith('/inventory/complete-updates')) return updates;
    if (path.endsWith('/health')) return health;
    if (path.endsWith('/inventory/packages')) return { ...completeView(), deviceId: id };
    throw new Error('Unexpected synthetic endpoint');
}
function deferred<T>() { let resolve!: (v: T) => void; const promise = new Promise<T>(done => { resolve = done; }); return { resolve, promise }; }
const flush = () => act(async () => {});
const calls = (suffix: string) => vi.mocked(request).mock.calls.filter(([path]) => path.endsWith(suffix));
const card = (name: string) => within(screen.getByRole('region', { name }));
const panel = () => <main><DeviceDetail id={id} onClose={vi.fn()} onCase={vi.fn()}/></main>;
beforeEach(() => {
    vi.useFakeTimers(); vi.setSystemTime(now); localStorage.clear(); sessionStorage.clear(); setLocale('en', false); vi.mocked(useOperator).mockReturnValue(operator);
    updates = updateView(12);
    health = { schemaVersion: 'tracebolt.health-view.v1', deviceId: id, serverNow: now, evaluatedAt: now, status: 'attention', maintenanceUntil: null, monitoredServices: ['fixture.service'], incidents: [], checks: [
        { key: 'offline:contact', kind: 'offline', target: 'agent', state: 'ok', observedAt: now, value: 0 },
        { key: 'filesystem:root', kind: 'filesystem', target: '/', state: 'unknown', observedAt: null, value: null },
        { key: 'service:fixture.service', kind: 'service', target: 'fixture.service', state: 'open', observedAt: now, value: 1 },
    ] };
    vi.mocked(request).mockReset().mockImplementation(async path => answer(path)); vi.mocked(mutate).mockReset();
    vi.mocked(mutateRaw).mockReset().mockImplementation(async (path, raw) => { if (path.endsWith('/inventory/complete-updates/query')) return updatePage(updates, updateRows(12), raw); throw new Error('Unexpected query'); });
});
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.restoreAllMocks(); });

describe('compact device essentials', () => {
    it('serializes identity, cached update metadata and selected warning reads without inventory pages or summary polling', async () => {
        const identity = deferred<unknown>(), update = deferred<unknown>(), warnings = deferred<unknown>();
        vi.mocked(request).mockImplementation(async path => path.endsWith('/inventory/endpoint-identity') ? identity.promise : path.endsWith('/inventory/complete-updates') ? update.promise : path.endsWith('/health') ? warnings.promise : answer(path));
        render(panel()); await flush(); expect(calls('/inventory/endpoint-identity')).toHaveLength(1); expect(calls('/inventory/complete-updates')).toHaveLength(0); expect(calls('/health')).toHaveLength(0);
        await act(async () => identity.resolve(answer(`/devices/${id}/inventory/endpoint-identity`)));
        expect(calls('/inventory/complete-updates')).toHaveLength(1); expect(calls('/health')).toHaveLength(0); expect(card('Updates').getByText('Checking…')).toBeVisible();
        await act(async () => update.resolve(updates)); expect(calls('/health')).toHaveLength(1); await act(async () => warnings.resolve(health));
        expect(card('Updates').getByText('12')).toBeVisible(); expect(card('Warnings').getByText('1 open')).toBeVisible(); expect(card('Warnings').getByText('1 unknown')).toBeVisible();
        expect(card('Updates').getByText('Cache is stale')).toBeVisible(); expect(card('Updates').getByText('Observed 0 min ago')).toBeVisible();
        expect(calls('/inventory/packages')).toHaveLength(0); expect(mutateRaw).not.toHaveBeenCalled(); expect(mutate).not.toHaveBeenCalled();
        const reads = vi.mocked(request).mock.calls.length; await act(async () => vi.advanceTimersByTimeAsync(31000)); expect(request).toHaveBeenCalledTimes(reads + 2); expect(calls('/inventory/complete-updates')).toHaveLength(1); expect(calls('/health')).toHaveLength(1);
        await act(async () => vi.advanceTimersByTimeAsync(15000)); expect(card('Warnings').getByText('Unknown')).toBeVisible(); expect(card('Warnings').queryByText('0 open')).not.toBeInTheDocument(); expect(request).toHaveBeenCalledTimes(reads + 3); expect(calls('/inventory/complete-updates')).toHaveLength(1); expect(calls('/health')).toHaveLength(1);
    });
    it('keeps unknown comparisons and stale/denied resource states visible instead of implying zero warnings or a patched device', async () => {
        updates = updateView(0); updates.complete!.manifest.unknownCount = 2; updates.complete!.manifest.checkedCount -= 2; updates.complete!.manifest.comparisonCoverage = 'partial'; updates.complete!.manifest.comparisonReason = 'candidate_unknown';
        health.checks[2] = { ...health.checks[2], state: 'unknown', observedAt: null, value: null }; health.status = 'unknown';
        expect(validCompleteUpdateView(updates, id)).toBe(true); render(panel()); await flush();
        expect(card('Updates').getByText('0+')).toBeVisible(); expect(card('Updates').getByText('Partial comparison · 2 comparisons unknown')).toBeVisible();
        expect(card('Warnings').getByText('Unknown')).toBeVisible(); expect(card('Warnings').queryByText('0 open')).not.toBeInTheDocument();
        const resources = screen.getByRole('region', { name: 'Resources' }); expect(resources).toHaveTextContent('Stale'); expect(resources).toHaveTextContent('Unavailable'); expect(resources).toHaveTextContent('Access denied');
        expect(card('Last report').queryByText('Live reachability is not checked.')).not.toBeInTheDocument(); expect(screen.getByRole('button', { name: /Certificate: Expired/ })).toBeVisible();
        expect(screen.queryByText('Invented original source')).not.toBeInTheDocument();
    });
    it('shows zero only for a complete available candidate generation and fully known selected checks', async () => {
        updates = updateView(0); health.status = 'clear'; health.checks = health.checks.map(check => ({ ...check, state: 'ok', observedAt: now, value: 0 }));
        render(panel()); await flush(); expect(card('Updates').getByText('0')).toBeVisible(); expect(card('Updates').getByText('cached candidates')).toBeVisible(); expect(card('Updates').getByText('Cache is stale')).toBeVisible();
        expect(card('Warnings').getByText('0 open')).toBeVisible(); expect(card('Warnings').getByText('Selected checks')).toBeVisible();
        expect(document.body).not.toHaveTextContent('Device is healthy'); expect(document.body).not.toHaveTextContent('Fully patched');
    });
    it.each(['awaiting', 'not_configured', 'revoked', 'unavailable'] as const)('does not promote %s update data to a current count', async state => {
        updates.status = state; if (state === 'awaiting' || state === 'not_configured') updates.complete = null;
        render(panel()); await flush(); expect(card('Updates').getByText('Unknown')).toBeVisible(); expect(card('Updates').queryByText('12')).not.toBeInTheDocument(); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('opens full update rows only on the explicit shortcut and preserves the selected subview on repeated clicks', async () => {
        render(panel()); await flush(); fireEvent.click(card('Updates').getByRole('button', { name: 'View updates' })); await flush();
        expect(screen.getByRole('tab', { name: 'Updates' })).toHaveAttribute('aria-selected', 'true'); expect(screen.getByRole('tab', { name: 'Updates' })).toHaveFocus();
        expect(mutateRaw).toHaveBeenCalledTimes(1); expect(vi.mocked(mutateRaw).mock.calls[0][0]).toMatch(/\/inventory\/complete-updates\/query$/);
        fireEvent.click(screen.getByRole('tab', { name: 'Inventory' })); await flush(); expect(screen.getByRole('tab', { name: 'Updates' })).toHaveAttribute('aria-selected', 'true'); expect(mutateRaw).toHaveBeenCalledTimes(1); expect(mutate).not.toHaveBeenCalled();
    });
    it('makes Details explicit, preserves disclosure/scroll during metadata refresh and keeps sources accessible', async () => {
        render(panel()); await flush(); expect(screen.queryByRole('region', { name: 'Agent certificate' })).not.toBeInTheDocument();
        fireEvent.click(card('Last report').getByRole('button', { name: 'Device details' })); await flush();
        expect(screen.getByRole('tab', { name: 'Details' })).toHaveFocus(); expect(screen.getByRole('region', { name: 'Agent certificate' })).toBeVisible(); expect(calls('/inventory/packages')).toHaveLength(1);
        expect(screen.getAllByText('Invented original source').length).toBe(3); expect(screen.getByText('Stable cryptographic device ID')).toBeVisible();
        const summary = screen.getByText('Device profile & technical details'), disclosure = summary.closest('details')!, main = screen.getByRole('main'); fireEvent.click(summary); main.scrollTop = 240;
        fireEvent.click(screen.getByRole('button', { name: 'Refresh device metadata' })); await flush();
        expect(disclosure).toHaveAttribute('open'); expect(main.scrollTop).toBe(240); expect(screen.getByRole('tab', { name: 'Details' })).toHaveAttribute('aria-selected', 'true');
    });
    it('cancels delayed update metadata on navigation and does not start the queued health read', async () => {
        const held = deferred<unknown>(); let signal: AbortSignal | undefined;
        vi.mocked(request).mockImplementation(async (path, options) => { if (path.endsWith('/inventory/complete-updates')) { signal = options?.signal as AbortSignal; return held.promise; } return answer(path); });
        render(panel()); await flush(); expect(signal).toBeDefined(); fireEvent.click(screen.getByRole('tab', { name: 'Details' })); await flush(); expect(signal!.aborted).toBe(true);
        await act(async () => held.resolve(updates)); expect(calls('/health')).toHaveLength(0); expect(screen.queryByRole('region', { name: 'Updates' })).not.toBeInTheDocument();
    });
    it('serializes visible-session restoration again and clears all summary counts on access loss', async () => {
        render(panel()); await flush(); const updateReads = calls('/inventory/complete-updates').length, warningReads = calls('/health').length;
        act(() => window.dispatchEvent(new Event('blur'))); expect(card('Updates').getByText('Unknown')).toBeVisible();
        const held = deferred<unknown>(); vi.mocked(request).mockImplementation(async path => path.endsWith('/inventory/endpoint-identity') ? held.promise : answer(path));
        act(() => window.dispatchEvent(new Event('focus'))); await flush(); expect(calls('/inventory/complete-updates')).toHaveLength(updateReads); expect(calls('/health')).toHaveLength(warningReads);
        await act(async () => held.resolve(answer(`/devices/${id}/inventory/endpoint-identity`))); expect(calls('/inventory/complete-updates')).toHaveLength(updateReads + 1); expect(calls('/health')).toHaveLength(warningReads + 1);
        act(() => window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT))); expect(screen.queryByRole('region', { name: 'Updates' })).not.toBeInTheDocument();
        const reads = vi.mocked(request).mock.calls.length; act(() => window.dispatchEvent(new Event('focus'))); await flush(); expect(request).toHaveBeenCalledTimes(reads);
    });
    it('keeps the first view concise and exposes interpretation through a native, state-preserving Details disclosure', async () => {
        render(panel()); await flush();
        const report = screen.getByRole('region', { name: 'Last report' });
        expect(within(report).getByRole('heading', { name: 'Last report' })).toBeVisible(); expect(report.querySelectorAll('p')).toHaveLength(0);
        expect(screen.queryByText(/Live reachability is not checked/)).not.toBeInTheDocument();
        expect(card('Warnings').getByText('Selected checks')).toBeVisible(); expect(card('Warnings').getByText('1 unknown')).toBeVisible();
        expect(card('Updates').getByText('cached candidates')).toBeVisible(); expect(card('Updates').getByText('Cache is stale')).toBeVisible();
        expect(screen.queryByText('No investigation for this device.')).not.toBeInTheDocument();
        expect(screen.getByRole('heading', { name: 'Investigations' })).toBeVisible(); expect(screen.getByRole('link', { name: 'All investigations' })).toHaveAttribute('href', '#/cases'); expect(screen.queryByRole('heading', { name: /^Related investigations/ })).not.toBeInTheDocument();
        expect(screen.getByText('Read-only', { selector: '.drawer-footer span' })).toBeVisible();
        fireEvent.click(within(report).getByRole('button', { name: 'Device details' })); await flush();
        const summary = screen.getByText('About these values', { selector: 'summary' }), disclosure = summary.closest('details')!;
        expect(disclosure).not.toHaveAttribute('open'); expect(within(disclosure).getByText(/Live reachability is not checked/)).not.toBeVisible();
        const reads = vi.mocked(request).mock.calls.length; summary.focus(); fireEvent.click(summary);
        expect(summary).toHaveFocus(); expect(disclosure).toHaveAttribute('open');
        expect(within(disclosure).getByText(/Live reachability is not checked/)).toBeVisible();
        expect(within(disclosure).getByText(/Unknown checks are not a healthy result/)).toBeVisible(); expect(within(disclosure).getByText(/existing APT cache/)).toBeVisible();
        fireEvent.click(screen.getByRole('button', { name: 'Refresh device metadata' })); await flush();
        expect(disclosure).toHaveAttribute('open'); expect(request).toHaveBeenCalledTimes(reads + 1);
        act(() => setLocale('de', false)); expect(screen.getByText('Hinweise zu den Werten', { selector: 'summary' })).toBe(summary);
        expect(disclosure).toHaveAttribute('open'); expect(within(disclosure).getByText(/Aktuelle Erreichbarkeit wird nicht geprüft/)).toBeVisible();
        fireEvent.click(summary); expect(disclosure).not.toHaveAttribute('open'); expect(request).toHaveBeenCalledTimes(reads + 1); expect(mutate).not.toHaveBeenCalled(); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('preserves first-view selection and does not repeat summary reads on metadata refresh', async () => {
        render(panel()); await flush(); const updatesCard = screen.getByRole('region', { name: 'Updates' }), warningsCard = screen.getByRole('region', { name: 'Warnings' });
        fireEvent.click(screen.getByRole('button', { name: 'Refresh device metadata' })); await flush();
        expect(screen.getByRole('region', { name: 'Updates' })).toBe(updatesCard); expect(screen.getByRole('region', { name: 'Warnings' })).toBe(warningsCard); expect(calls('/inventory/complete-updates')).toHaveLength(1); expect(calls('/health')).toHaveLength(1);
    });
});
