/** Actual unchanged React/resource lifecycle with deferred synthetic DTOs.
 * No browser, server, collector, native fixture or external network. */
import { useLayoutEffect } from 'react';
import { act, cleanup, fireEvent, render, screen, waitFor } from '../../web/node_modules/@testing-library/react/dist/index.js';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { APIError, mutateRaw, request } from '../../web/src/api';
import { CompleteOverviewPanel } from '../../web/src/complete-overview';
import { CompletePackagesPanel } from '../../web/src/complete-packages';
import { SystemInventoryPanel } from '../../web/src/system-inventory';
import { SoftwareOverview } from '../../web/src/software-overview';
import { overviewDevice, overviewGolden, overviewPage, overviewView, processRows, volumeRows } from '../../web/src/complete-overview-fixtures';
import { completeDevice, completePage, completeRows, completeView } from '../../web/src/complete-packages-fixtures';
import { serviceRows, socketRows, systemDevice, systemPage, systemView } from '../../web/src/system-inventory-fixtures';
import { setLocale } from '../../web/src/i18n';
import { hasInventoryReadiness, inventoryProjectionReady } from './inventory-readiness.mjs';

vi.mock('../../web/src/api', async original => ({ ...await original<typeof import('../../web/src/api')>(), request: vi.fn(), mutateRaw: vi.fn() }));
vi.mock('../../web/src/auth', () => ({ useOperator: () => ({ mode: 'lan', authenticated: true, expiresAt: '2026-10-04T20:00:00Z' }) }));

const kinds = ['overview', 'packages', 'system', 'software'] as const;
type Kind = typeof kinds[number];
function fixture(kind: Kind, count = 2) {
  if (kind === 'overview') {
    const view = overviewView(count);
    return { selector: '.complete-overview', view, element: <CompleteOverviewPanel deviceId={overviewDevice} section="processes"/>, page: (raw: string) => overviewPage(view, processRows(count), volumeRows(), raw), missing: () => { view.processes = { status: 'awaiting', complete: null, transfer: null, failure: null }; } };
  }
  if (kind === 'system') {
    const view = systemView(count);
    return { selector: '.system-inventory', view, element: <SystemInventoryPanel deviceId={systemDevice} section="services"/>, page: (raw: string) => systemPage(view, serviceRows(count), socketRows(), raw), missing: () => { view.status = 'expired'; view.serverNow = '2026-10-05T00:00:00Z'; view.latest = null; view.lastComplete = { services: null, sockets: null }; } };
  }
  const view = completeView(count);
  return { selector: kind === 'software' ? '.software-overview' : '.complete-packages', view, element: kind === 'software' ? <SoftwareOverview deviceId={completeDevice} onOpenPackages={() => {}}/> : <CompletePackagesPanel deviceId={completeDevice} inline/>, page: (raw: string) => completePage(view, completeRows(count), raw), missing: () => { view.status = 'awaiting'; view.complete = null; } };
}
function deferred() { let resolve!: (value: unknown) => void; const promise = new Promise<unknown>(done => { resolve = done; }); return { resolve, promise }; }
const ready = (selector: string) => inventoryProjectionReady([...document.querySelectorAll(selector)], selector);
const oldReady = (selector: string) => { const panel = document.querySelector(selector); return Boolean(panel && panel.getAttribute('aria-busy') === 'false' && !panel.querySelector('[role=alert]')); };
beforeEach(() => { setLocale('en', false); vi.mocked(request).mockReset(); vi.mocked(mutateRaw).mockReset(); });
afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.useRealTimers(); });

it.each(kinds)('%s rejects an unstarted layout and held reads, then accepts its rendered projection', async kind => {
  const f = fixture(kind), status = deferred(), page = deferred();
  vi.mocked(request).mockReturnValue(status.promise); vi.mocked(mutateRaw).mockReturnValue(page.promise);
  let initial: { old: boolean; corrected: boolean } | undefined;
  function Observe() { useLayoutEffect(() => { initial = { old: oldReady(f.selector), corrected: ready(f.selector) }; }, []); return f.element; }
  render(<Observe/>);
  expect(initial).toEqual({ old: true, corrected: false });
  expect(ready(f.selector)).toBe(false); expect(request).toHaveBeenCalledTimes(1);
  await act(async () => { status.resolve(f.view); });
  if (kind !== 'software') {
    await waitFor(() => expect(mutateRaw).toHaveBeenCalledTimes(1));
    expect(ready(f.selector)).toBe(false);
    await act(async () => { page.resolve(f.page(vi.mocked(mutateRaw).mock.calls[0][1])); });
  } else expect(mutateRaw).not.toHaveBeenCalled();
  await waitFor(() => expect(ready(f.selector)).toBe(true));
});

it.each(kinds)('%s rejects blur-cleared state and late completion without retrying', async kind => {
  const f = fixture(kind), status = deferred(); vi.mocked(request).mockReturnValue(status.promise);
  render(f.element); const signal = vi.mocked(request).mock.calls[0][1]!.signal!;
  act(() => { window.dispatchEvent(new Event('blur')); });
  expect(signal.aborted).toBe(true); expect(oldReady(f.selector)).toBe(true); expect(ready(f.selector)).toBe(false);
  await act(async () => { status.resolve(f.view); });
  expect(ready(f.selector)).toBe(false); expect(request).toHaveBeenCalledTimes(1); expect(mutateRaw).not.toHaveBeenCalled();
});

it.each(kinds)('%s rejects an unmounted panel and its delayed reply', async kind => {
  const f = fixture(kind), status = deferred(); vi.mocked(request).mockReturnValue(status.promise);
  const rendered = render(f.element), panel = document.querySelector(f.selector)!;
  rendered.unmount(); await act(async () => { status.resolve(f.view); });
  expect(ready(f.selector)).toBe(false); expect(inventoryProjectionReady([panel], f.selector)).toBe(false); expect(mutateRaw).not.toHaveBeenCalled();
});

it.each(kinds)('%s accepts a valid zero-count source without requiring rows', async kind => {
  const f = fixture(kind, 0); vi.mocked(request).mockResolvedValue(f.view); vi.mocked(mutateRaw).mockImplementation(async (_path, raw) => f.page(raw));
  render(f.element); await waitFor(() => expect(ready(f.selector)).toBe(true));
  expect(document.querySelectorAll(`${f.selector} tbody tr`)).toHaveLength(0);
  expect(mutateRaw).toHaveBeenCalledTimes(kind === 'software' ? 0 : 1);
});

it.each(kinds)('%s accepts validated missing/expired metadata without inventing an empty page', async kind => {
  const f = fixture(kind); f.missing(); vi.mocked(request).mockResolvedValue(f.view);
  render(f.element); await waitFor(() => expect(ready(f.selector)).toBe(true));
  expect(mutateRaw).not.toHaveBeenCalled(); expect(document.querySelectorAll(`${f.selector} tbody tr`)).toHaveLength(0);
});

it.each(kinds)('%s refuses the production timeout state instead of accepting its cleared shell', async kind => {
  vi.useFakeTimers(); const f = fixture(kind); vi.mocked(request).mockReturnValue(new Promise(() => {}));
  render(f.element); act(() => { vi.advanceTimersByTime(10000); });
  expect(document.querySelector(`${f.selector} [role=alert]`)).not.toBeNull(); expect(ready(f.selector)).toBe(false);
  expect(request).toHaveBeenCalledTimes(1); expect(mutateRaw).not.toHaveBeenCalled();
});

it.each(kinds)('%s refuses a failed HTTP read with an alert', async kind => {
  const f = fixture(kind); vi.mocked(request).mockRejectedValue(new APIError('synthetic bounded failure', 503));
  render(f.element); await screen.findByRole('alert'); expect(ready(f.selector)).toBe(false);
});

it.each(['overview', 'packages', 'system'] as const)('%s rejects a held page after blur or unmount and ignores the late page', async kind => {
  for (const transition of ['blur', 'unmount']) {
    const f = fixture(kind), page = deferred();
    vi.mocked(request).mockReset().mockResolvedValue(f.view); vi.mocked(mutateRaw).mockReset().mockReturnValue(page.promise);
    const rendered = render(f.element);
    await waitFor(() => expect(mutateRaw).toHaveBeenCalledTimes(1));
    const call = vi.mocked(mutateRaw).mock.calls[0];
    const panel = document.querySelector(f.selector)!;
    expect(ready(f.selector)).toBe(false);
    if (transition === 'blur') act(() => { window.dispatchEvent(new Event('blur')); });
    else rendered.unmount();
    expect(call[3]!.aborted).toBe(true); expect(ready(f.selector)).toBe(false);
    await act(async () => { page.resolve(f.page(call[1])); });
    expect(ready(f.selector)).toBe(false);
    expect(inventoryProjectionReady([panel], f.selector)).toBe(false);
    expect(request).toHaveBeenCalledTimes(1); expect(mutateRaw).toHaveBeenCalledTimes(1);
    cleanup();
  }
});

it.each(['overview', 'packages', 'system'] as const)('%s refuses a page HTTP failure even though metadata was accepted', async kind => {
  const f = fixture(kind); vi.mocked(request).mockResolvedValue(f.view); vi.mocked(mutateRaw).mockRejectedValue(new APIError('synthetic page failure', 503));
  render(f.element); await screen.findByRole('alert');
  expect(request).toHaveBeenCalledTimes(1); expect(mutateRaw).toHaveBeenCalledTimes(1); expect(ready(f.selector)).toBe(false);
});

it.each(['overview', 'packages', 'system'] as const)('%s refuses a held-page timeout and cannot accept a later page', async kind => {
  vi.useFakeTimers(); const f = fixture(kind), page = deferred();
  vi.mocked(request).mockResolvedValue(f.view); vi.mocked(mutateRaw).mockReturnValue(page.promise);
  await act(async () => { render(f.element); });
  expect(mutateRaw).toHaveBeenCalledTimes(1); const call = vi.mocked(mutateRaw).mock.calls[0];
  act(() => { vi.advanceTimersByTime(10000); });
  expect(call[3]!.aborted).toBe(true); expect(document.querySelector(`${f.selector} [role=alert]`)).not.toBeNull(); expect(ready(f.selector)).toBe(false);
  await act(async () => { page.resolve(f.page(call[1])); });
  expect(ready(f.selector)).toBe(false); expect(request).toHaveBeenCalledTimes(1); expect(mutateRaw).toHaveBeenCalledTimes(1);
});

it.each(['overview', 'packages', 'system'] as const)('%s rejects a draft-cleared accepted page', async kind => {
  const f = fixture(kind); vi.mocked(request).mockResolvedValue(f.view); vi.mocked(mutateRaw).mockImplementation(async (_path, raw) => f.page(raw));
  render(f.element); await waitFor(() => expect(ready(f.selector)).toBe(true));
  fireEvent.change(screen.getByRole('searchbox'), { target: { value: 'unsubmitted' } });
  expect(oldReady(f.selector)).toBe(true); expect(ready(f.selector)).toBe(false); expect(mutateRaw).toHaveBeenCalledTimes(1);
});

it('accepts a truthful retained overview page beside a failed collection attempt', async () => {
  const f = overviewGolden(); vi.mocked(request).mockResolvedValue(f.view); vi.mocked(mutateRaw).mockResolvedValue(f.processPage);
  render(<CompleteOverviewPanel deviceId={overviewDevice} section="processes"/>);
  await screen.findByText('Latest collection attempt failed'); await waitFor(() => expect(ready('.complete-overview')).toBe(true));
  expect(screen.queryByRole('alert')).toBeNull(); expect(screen.getByRole('table')).toBeVisible();
});

it('rejects duplicate panels and unsupported selectors', async () => {
  const f = fixture('overview'); vi.mocked(request).mockResolvedValue(f.view); vi.mocked(mutateRaw).mockImplementation(async (_path, raw) => f.page(raw));
  render(f.element); await waitFor(() => expect(ready(f.selector)).toBe(true));
  const panel = document.querySelector(f.selector)!;
  expect(inventoryProjectionReady([panel, panel], f.selector)).toBe(false);
  expect(inventoryProjectionReady([panel], '.unreviewed-source')).toBe(false);
  expect(hasInventoryReadiness('.unreviewed-source')).toBe(false);
});
