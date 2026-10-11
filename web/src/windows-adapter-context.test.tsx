import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AUTH_REQUIRED_EVENT, request } from './api';
import { setLocale } from './i18n';
import { WindowsInventoryWorkspace } from './windows-inventory';
import { useWindowsInventory } from './windows-inventory-resource';
import { windowsDeviceId, windowsNow, windowsView } from './windows-inventory-fixture';
import { windowsAdapterContextView } from './windows-adapter-context-fixture';
import { windowsNetwork } from './windows-network-fixture';
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn() }));
function view() { return { ...windowsAdapterContextView(), network: windowsNetwork() }; }
function Harness({ id = windowsDeviceId, session = 'fixture', enabled = true }: { id?: string; session?: string; enabled?: boolean }) { return <WindowsInventoryWorkspace resource={useWindowsInventory(id, enabled, session)}/>; }
const flush = () => act(async () => {});
async function network() { await flush(); fireEvent.click(screen.getByRole('tab', { name: 'Network' })); }
const adapterRow = (name = 'Fixture Ethernet') => within(screen.getByRole('table', { name: 'Adapters' })).getByText(name).closest('tr')!;
beforeEach(() => { setLocale('en', false); vi.mocked(request).mockReset().mockResolvedValue(view()); });
afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); });

describe('Compact adapter context in the existing Network tab', () => {
    it('shows truthful directional speeds and native states alongside unchanged endpoint metadata', async () => {
        render(<Harness/>); await network();
        expect(screen.getAllByRole('tab', { name: 'Network' })).toHaveLength(1);
        expect(screen.getAllByRole('table')).toHaveLength(2);
        expect(within(adapterRow()).getByText('Up')).toBeVisible();
        expect(within(adapterRow()).getByText('1 Gbit/s')).toHaveAttribute('title', '1000000000 bit/s');
        expect(within(adapterRow()).getByText('2.5 Gbit/s')).toBeVisible();
        const down = within(adapterRow('Fixture Wi-Fi')); expect(down.getByText('Down')).toBeVisible(); expect(down.getByText('Unknown')).toBeVisible(); expect(down.getAllByText('Unavailable').some(node => node.closest('td')?.dataset.label === 'RX link speed')).toBe(true);
        expect(screen.getByText('0.0.0.0:135')).toBeVisible(); expect(screen.getByText('[2001:db8::80]:443')).toBeVisible(); expect(screen.getByText('established')).toBeVisible();
        expect(screen.queryByText('fixture.exe')).toBeNull(); expect(screen.queryByRole('link')).toBeNull(); expect(screen.queryByRole('button', { name: /enable|connect|configure|probe/i })).toBeNull();
        expect(document.querySelector('time[datetime="2026-10-07T12:00:00Z"]')).not.toBeNull();
        fireEvent.click(screen.getByText('About adapter observations')); expect(screen.getByText(/do not establish reachability or measured throughput/)).toBeVisible();
    });
    it('keeps numeric DNS and gateway lists in collapsed accessible details with their own quality', async () => {
        render(<Harness/>); await network();
        const row = within(adapterRow()); expect(row.getByText('192.0.2.53')).not.toBeVisible();
        fireEvent.click(row.getByText('DNS & gateways')); expect(row.getByText('192.0.2.53')).toBeVisible(); expect(row.getByText('2001:db8::53')).toBeVisible(); expect(row.getByText('fe80::1%4')).toBeVisible(); expect(row.getByText('IPv4: 4 · IPv6: 4')).toBeVisible();
        fireEvent.click(row.getByText('DNS & gateways')); expect(row.getByText('192.0.2.53')).not.toBeVisible();
        const down = within(adapterRow('Fixture Wi-Fi')); fireEvent.click(down.getByText('DNS & gateways')); expect(down.getByText('None configured')).toBeVisible(); expect(down.getAllByText('Unavailable')).toHaveLength(2);
        const unknown = within(adapterRow('Fixture tunnel')); fireEvent.click(unknown.getByText('DNS & gateways')); expect(unknown.getByText('Partial list')).toBeVisible(); expect(unknown.getByText('198.51.100.53')).toBeVisible(); expect(unknown.getByText('Partial list; no addresses returned')).toBeVisible(); expect(unknown.getAllByText('Unknown')).toHaveLength(2);
    });
    it('does not infer an active link from configured addresses or zero speed from unavailable evidence', async () => {
        const v = view(); v.adapterContext.rows[0].state = 'down'; v.adapterContext.rows[0].txQuality = 'unknown'; v.adapterContext.rows[0].txLinkBps = null; vi.mocked(request).mockResolvedValue(v);
        render(<Harness/>); await network(); const row = within(adapterRow()); expect(row.getByText('Down')).toBeVisible(); expect(row.getByText('Unknown')).toBeVisible(); expect(row.queryByText('Up')).toBeNull(); expect(screen.queryByText('0 bit/s')).toBeNull();
    });
    it('supports adapter-only reports and does not invent rows when the scope is absent', async () => {
        vi.mocked(request).mockResolvedValue(windowsAdapterContextView()); render(<Harness/>); await network(); expect(screen.getByRole('table', { name: 'Adapters' })).toBeVisible(); expect(screen.getByText(/Network endpoints are not configured/)).toBeVisible();
        vi.mocked(request).mockResolvedValue(windowsView()); fireEvent.click(screen.getByRole('button', { name: 'Refresh Windows inventory' })); await flush(); expect(screen.queryByRole('table')).toBeNull(); expect(screen.queryByText('None configured')).toBeNull();
    });
    it.each(['denied', 'unavailable', 'unsupported', 'partial'] as const)('replaces old adapters with truthful %s evidence', async quality => {
        render(<Harness/>); await network(); const v = view(); Object.assign(v.adapterContext, { quality, countExact: false, rows: [], observedCount: 0 }); vi.mocked(request).mockResolvedValue(v); fireEvent.click(screen.getByRole('button', { name: 'Refresh Windows inventory' })); await flush();
        const section = within(screen.getByRole('region', { name: 'Adapters' })); expect(section.getByText(/No adapter rows available/)).toBeVisible(); expect(section.queryByText('0 shown · 0 observed')).toBeNull(); expect(screen.queryByText('Fixture Ethernet')).toBeNull(); expect(screen.getByText('[2001:db8::80]:443')).toBeVisible();
    });
    it('distinguishes exact empty and bounded/partial counts', async () => {
        const v = view(); Object.assign(v.adapterContext, { observedCount: 20, truncated: true }); vi.mocked(request).mockResolvedValue(v); render(<Harness/>); await network(); const section = within(screen.getByRole('region', { name: 'Adapters' })); expect(section.getByText('3 shown · 20 observed')).toBeVisible(); expect(section.getByText('Bounded enumeration')).toBeVisible();
        Object.assign(v.adapterContext, { quality: 'partial', countExact: false }); fireEvent.click(screen.getByRole('button', { name: 'Refresh Windows inventory' })); await flush(); expect(within(screen.getByRole('region', { name: 'Adapters' })).getByText('3 shown · at least 20 observed')).toBeVisible();
        Object.assign(v.adapterContext, { quality: 'observed', countExact: true, rows: [], observedCount: 0, truncated: false }); fireEvent.click(screen.getByRole('button', { name: 'Refresh Windows inventory' })); await flush(); expect(within(screen.getByRole('region', { name: 'Adapters' })).getByText('0 shown · 0 observed')).toBeVisible(); expect(within(screen.getByRole('region', { name: 'Adapters' })).getByText(/No adapters returned within the caller-visible scope/)).toBeVisible();
    });
    it('uses German labels, decimal formatting and the existing keyboard tab order', async () => {
        setLocale('de', false); render(<Harness/>); await flush(); fireEvent.keyDown(screen.getByRole('tab', { name: 'Schnittstellen' }), { key: 'ArrowRight' }); expect(screen.getByRole('tab', { name: 'Netzwerk' })).toHaveFocus();
        expect(screen.getByText('Linkrate (TX)')).toBeVisible(); expect(screen.getByText('2,5 Gbit/s')).toBeVisible(); expect(screen.getByText('Inaktiv')).toBeVisible(); expect(screen.getByText('Lokaler Endpunkt')).toBeVisible();
        fireEvent.keyDown(screen.getByRole('tab', { name: 'Netzwerk' }), { key: 'ArrowRight' }); expect(screen.getByRole('tab', { name: 'Speicher' })).toHaveFocus();
    });
    it('renders names as inert text and keeps details collapsed after navigation', async () => {
        const v = view(); v.adapterContext.rows[0].name = '<img src=x onerror=alert(1)>'; vi.mocked(request).mockResolvedValue(v); render(<Harness/>); await network(); expect(screen.getByText('<img src=x onerror=alert(1)>')).toBeVisible(); expect(screen.queryByRole('img')).toBeNull();
        const row = within(adapterRow('<img src=x onerror=alert(1)>')); fireEvent.click(row.getByText('DNS & gateways')); expect(row.getByText('192.0.2.53')).toBeVisible(); fireEvent.click(screen.getByRole('tab', { name: 'Interfaces' })); fireEvent.click(screen.getByRole('tab', { name: 'Network' })); expect(screen.getByText('192.0.2.53')).not.toBeVisible();
    });
});

describe('Adapter context privacy and original-capture lifecycle', () => {
    it('keeps manager receipt age authoritative even with a slightly younger capture', async () => {
        const v = view(); v.snapshot!.collectedAt = '2026-10-07T11:58:11Z'; v.adapterContext.collectedAt = v.snapshot!.collectedAt; v.network.collectedAt = v.snapshot!.collectedAt; v.receivedAt = '2026-10-07T11:57:51Z'; v.status = 'stale'; vi.mocked(request).mockResolvedValue(v); render(<Harness/>); await network(); expect(screen.getByText(/Stale adapter observation/)).toBeVisible();
    });
    it('turns stale just after two minutes without changing its capture', async () => {
        vi.useFakeTimers(); vi.setSystemTime(windowsNow); const v = view(); v.adapterContext.collectedAt = '2026-10-07T11:58:10Z'; v.snapshot!.collectedAt = v.adapterContext.collectedAt; v.status = 'fresh'; vi.mocked(request).mockResolvedValue(v); render(<Harness/>); await network(); expect(screen.queryByText(/Stale adapter observation/)).toBeNull();
        await act(async () => vi.advanceTimersByTimeAsync(1000)); expect(screen.getByText(/Stale adapter observation/)).toBeVisible(); expect(document.querySelector('time[datetime="2026-10-07T11:58:10Z"]')).not.toBeNull();
    });
    it('rejects a younger adapter capture that could renew its base privacy envelope', async () => {
        const v = view(); v.snapshot!.collectedAt = '2026-10-06T12:00:11Z'; v.status = 'stale'; vi.mocked(request).mockResolvedValue(v); render(<Harness/>); await network(); expect(screen.queryByRole('table')).toBeNull(); expect(screen.queryByText('192.0.2.53')).toBeNull(); expect(screen.getByRole('alert')).toHaveTextContent('inconsistent');
    });
    it('shows original 24-hour adapter expiry and never preserves hidden addresses', async () => {
        vi.useFakeTimers(); vi.setSystemTime(windowsNow); const v = view(); v.adapterContext.collectedAt = '2026-10-06T12:00:11Z'; v.snapshot!.collectedAt = v.adapterContext.collectedAt; v.status = 'stale'; vi.mocked(request).mockResolvedValue(v); render(<Harness/>); await network();
        fireEvent.click(within(adapterRow()).getByText('DNS & gateways')); await act(async () => vi.advanceTimersByTimeAsync(1000)); expect(screen.queryByRole('table')).toBeNull(); expect(screen.queryByText('192.0.2.53')).toBeNull(); expect(screen.getByText(/adapter snapshot expired/)).toBeVisible();
    });
    it.each(['blur', 'pagehide', 'hashchange', AUTH_REQUIRED_EVENT])('clears adapters and their collapsed details on %s', async event => {
        render(<Harness/>); await network(); act(() => window.dispatchEvent(new Event(event))); expect(screen.queryByText('Fixture Ethernet')).toBeNull(); expect(screen.queryByText('192.0.2.53')).toBeNull(); expect(screen.queryByRole('table')).toBeNull();
    });
    it('clears hidden-page data and does not read while disabled', async () => {
        const result = render(<Harness/>); await network(); vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden'); act(() => document.dispatchEvent(new Event('visibilitychange'))); expect(screen.queryByText('192.0.2.53')).toBeNull(); result.unmount(); vi.mocked(request).mockClear(); render(<Harness/>); await flush(); expect(request).not.toHaveBeenCalled(); cleanup(); vi.restoreAllMocks(); render(<Harness enabled={false}/>); await flush(); expect(request).not.toHaveBeenCalled();
    });
    it('aborts session/device replacements and ignores late responses', async () => {
        let resolve!: (v: ReturnType<typeof view>) => void; const result = render(<Harness/>); await network(); vi.mocked(request).mockReturnValueOnce(new Promise(done => { resolve = done; })); fireEvent.click(screen.getByRole('button', { name: 'Refresh Windows inventory' })); const signal = vi.mocked(request).mock.calls.at(-1)![1]?.signal;
        const next = windowsView(), id = `agent_${'8'.repeat(32)}`; next.deviceId = id; vi.mocked(request).mockResolvedValue(next); result.rerender(<Harness id={id} session="replacement"/>); await act(async () => resolve(view())); expect(signal?.aborted).toBe(true); expect(screen.queryByText('192.0.2.53')).toBeNull();
    });
    it('does not revive timed-out responses', async () => {
        vi.useFakeTimers(); vi.setSystemTime(windowsNow); let resolve!: (v: ReturnType<typeof view>) => void; render(<Harness/>); await network(); vi.mocked(request).mockReturnValue(new Promise(done => { resolve = done; })); fireEvent.click(screen.getByRole('button', { name: 'Refresh Windows inventory' })); await act(async () => vi.advanceTimersByTimeAsync(10001)); await act(async () => resolve(view())); expect(screen.queryByRole('table')).toBeNull(); expect(screen.getByRole('alert')).toHaveTextContent('timed out');
    });
    it('rejects a frozen manager clock rather than renewing observations', async () => {
        vi.useFakeTimers(); vi.setSystemTime(windowsNow); render(<Harness/>); await network(); await act(async () => vi.advanceTimersByTimeAsync(15000)); expect(screen.queryByRole('table')).toBeNull(); expect(screen.getByRole('alert')).toHaveTextContent('time reference changed');
    });
    it('clears adapter evidence on a changed browser clock', async () => {
        vi.useFakeTimers(); vi.setSystemTime(windowsNow); render(<Harness/>); await network(); vi.setSystemTime('2026-10-07T11:00:00Z'); await act(async () => vi.advanceTimersByTimeAsync(1000)); expect(screen.queryByRole('table')).toBeNull(); expect(screen.getByRole('alert')).toHaveTextContent('time reference changed');
    });
    it.each(['revoked', 'unavailable', 'awaiting', 'not_configured'] as const)('hides context for manager status %s', async status => {
        render(<Harness/>); await network(); vi.mocked(request).mockResolvedValue({ ...windowsView(), status, snapshot: null, ...(['awaiting', 'not_configured'].includes(status) ? { sequence: null, receivedAt: null } : {}) }); fireEvent.click(screen.getByRole('button', { name: 'Refresh Windows inventory' })); await flush(); expect(screen.queryByText('192.0.2.53')).toBeNull(); expect(screen.queryByRole('table')).toBeNull();
    });
    it('fails closed on unexpected private members without exposing their values', async () => {
        vi.mocked(request).mockResolvedValue({ ...view(), adapterContext: { ...view().adapterContext, extra: 'private-raw-secret' } }); render(<Harness/>); await network(); expect(screen.getByRole('alert')).toHaveTextContent('inconsistent'); expect(document.body).not.toHaveTextContent('private-raw-secret'); expect(screen.queryByRole('table')).toBeNull();
    });
});
