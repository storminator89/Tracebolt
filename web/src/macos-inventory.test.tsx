import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AUTH_REQUIRED_EVENT, mutateRaw } from './api';
import { setLocale } from './i18n';
import { MacInventoryWorkspace } from './macos-inventory';
import { macInventoryDeviceId, macInventoryFixture } from './macos-inventory-fixture';
import type { MacInventoryPage, MacInventoryQuery } from './macos-inventory-types';
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), mutateRaw: vi.fn() }));
const props = { deviceId: macInventoryDeviceId, enabled: true, configured: true, sessionKey: '2026-10-13T10:30:00Z', identityKey: 'original-identity' };
let amend: (value: MacInventoryPage) => MacInventoryPage;
beforeEach(() => { setLocale('en', false); amend = value => value; vi.mocked(mutateRaw).mockReset().mockImplementation(async (_path, raw) => amend(macInventoryFixture(JSON.parse(raw) as MacInventoryQuery))); });
afterEach(() => { cleanup(); vi.restoreAllMocks(); });
async function open() { const result = render(<MacInventoryWorkspace {...props}/>); await screen.findByText('Mac14,12'); return result; }
async function select(name: string) { fireEvent.click(screen.getByRole('tab', { name })); await waitFor(() => expect(screen.getByRole('button', { name: 'Refresh inventory' })).toBeEnabled()); }
describe('compact private Mac workspace', () => {
 it('uses exact body-only bounded queries and independent quality/freshness', async () => {
  await open(); expect(screen.getByText('Full selected-source coverage')).toBeVisible(); expect(screen.getByText('Fresh', { exact: true })).toBeVisible(); expect(screen.getByText('16 GiB')).toBeVisible(); expect(screen.getByText('Physical cores')).toBeVisible(); expect(screen.getByText('Logical processors')).toBeVisible();
  expect(mutateRaw).toHaveBeenCalledTimes(2);
  for (const [path, body, headers, signal, cap, guard] of vi.mocked(mutateRaw).mock.calls) { expect(path).toBe(`/devices/${macInventoryDeviceId}/macos-inventory/query`); expect(path).not.toContain('?'); expect(Object.keys(JSON.parse(body))).toEqual(['section', 'generationId', 'offset', 'limit']); expect(headers).toEqual({}); expect(signal).toBeInstanceOf(AbortSignal); expect(cap).toBe(32768); expect(typeof guard).toBe('function'); }
 });
 it('labels receipt evidence honestly and avoids values inferred from identifiers', async () => {
  await open(); await select('Package receipts'); expect(screen.getByText('com.example.fixture.editor')).toBeVisible(); expect(screen.getByText(/not a complete installed-software inventory/)).toBeVisible(); expect(screen.queryByText('Installed software', { exact: true })).not.toBeInTheDocument(); expect(screen.queryByRole('button', { name: /install|delete|export/i })).not.toBeInTheDocument();
 });
 it('shows provider denial and unknown count without replacing it by zero', async () => {
  amend = page => { page.sources!.receipts = { ...page.sources!.receipts, quality: 'denied', reason: 'macos_inventory_access_denied' }; page.sourceQuality = 'partial'; if (page.section === 'receipts') { page.receiptIds = []; page.total = 0; } return page; };
  await open(); await select('Package receipts'); expect(screen.getByText('Partial', { exact: true })).toBeVisible(); expect(screen.getAllByText('Provider access denied').length).toBeGreaterThan(0); expect(screen.queryByText(/0 source rows/)).not.toBeInTheDocument(); expect(screen.getByText('Count unknown', { exact: true })).toBeVisible(); expect(screen.queryByText('No receipt identifiers returned by this source.')).not.toBeInTheDocument();
 });
 it('shows safe process columns and explicit absent accounting labels', async () => {
  amend = page => { page.sourceQuality = 'partial'; if (page.section === 'processes') { page.processes[1].accountingName = ''; page.processes[1].nameQuality = 'unavailable'; } return page; };
  await open(); await select('Processes'); const table = screen.getByRole('table'); expect(within(table).getAllByRole('columnheader').map(h => h.textContent)).toEqual(['PID', 'PPID', 'Short accounting label']); expect(within(table).getByText('Unavailable')).toBeVisible(); expect(screen.getByText(/No arguments, paths, owners/)).toBeVisible();
 });
 it('keeps IPv4 and IPv6 separate and renders passive addresses without links', async () => {
  await open(); await select('IPv4 interfaces'); expect(screen.getByText('192.0.2.42/24')).toBeVisible(); await select('IPv6 interfaces'); expect(screen.queryByText('192.0.2.42/24')).not.toBeInTheDocument(); expect(screen.getByText('2001:db8::42/64')).toBeVisible(); expect(screen.queryByRole('link')).not.toBeInTheDocument(); expect(screen.getByText(/not reachability/)).toBeVisible();
 });
 it('preserves active panel, disclosure and scroll container through refresh', async () => {
  await open(); await select('Package receipts'); fireEvent.click(screen.getByText('Source & collection limits')); const disclosure = screen.getByText('Source & collection limits').closest('details')!, scroller = screen.getByTestId('mac-inventory-scroll'); scroller.scrollTop = 100; fireEvent.click(screen.getByRole('button', { name: 'Refresh inventory' })); await waitFor(() => expect(screen.getByRole('button', { name: 'Refresh inventory' })).toBeEnabled()); expect(screen.getByRole('tab', { name: 'Package receipts' })).toHaveAttribute('aria-selected', 'true'); expect(disclosure).toHaveAttribute('open'); expect(screen.getByTestId('mac-inventory-scroll')).toBe(scroller); expect(scroller.scrollTop).toBe(100);
 });
 it('does not read or promote basic Mac authority', () => {
  render(<MacInventoryWorkspace {...props} configured={false}/>); expect(screen.getByText(/This Mac has basic read-only scope/)).toBeVisible(); expect(mutateRaw).not.toHaveBeenCalled(); expect(screen.getByRole('button', { name: 'Refresh inventory' })).toBeDisabled();
 });
 it('provides German labels with the same read-only scope', async () => {
  setLocale('de', false); render(<MacInventoryWorkspace {...props}/>); await screen.findByText('Mac14,12'); expect(screen.getByText('Quellenabdeckung')).toBeVisible(); expect(screen.getByText('Physische Kerne')).toBeVisible(); expect(screen.getByText('Logische Prozessoren')).toBeVisible(); fireEvent.click(screen.getByRole('tab', { name: 'Paketbelege' })); await screen.findByText('com.example.fixture.editor'); expect(screen.getByText(/kein vollständiges Inventar installierter Software/)).toBeVisible(); expect(screen.getByText('Aktuell', { exact: true })).toBeVisible();
 });
});
describe('private result lifecycle', () => {
 it.each(['pagehide', 'hashchange', 'blur', AUTH_REQUIRED_EVENT])('clears rows and discards delayed responses on %s', async event => {
  await open(); let finish!:(page: MacInventoryPage)=>void, signal:AbortSignal|undefined;
  vi.mocked(mutateRaw).mockImplementation(async (_path, raw, _headers, pending) => new Promise(resolve => { signal = pending; finish = () => resolve(macInventoryFixture(JSON.parse(raw))); }));
  fireEvent.click(screen.getByRole('button', { name: 'Refresh inventory' })); act(() => window.dispatchEvent(new Event(event))); expect(signal?.aborted).toBe(true); expect(screen.queryByText('Mac14,12')).not.toBeInTheDocument(); await act(async () => finish(macInventoryFixture())); expect(screen.queryByText('Mac14,12')).not.toBeInTheDocument();
 });
 it.each(['sessionKey', 'identityKey', 'deviceId'] as const)('discards old identity rows synchronously on %s transition', async field => {
  const result = await open(); let finish!:(page: MacInventoryPage)=>void, signal:AbortSignal|undefined;
  vi.mocked(mutateRaw).mockImplementation(async (_path, _raw, _headers, pending) => new Promise(resolve => { if (!finish) { finish = resolve; signal = pending; } }));
  fireEvent.click(screen.getByRole('button', { name: 'Refresh inventory' })); result.rerender(<MacInventoryWorkspace {...props} {...{ [field]: field === 'deviceId' ? `agent_${'8'.repeat(32)}` : 'changed' }}/>); expect(signal?.aborted).toBe(true); expect(screen.queryByText('Mac14,12')).not.toBeInTheDocument(); await act(async () => finish(macInventoryFixture())); expect(screen.queryByText('Mac14,12')).not.toBeInTheDocument();
 });
 it('aborts old source reads and ignores late rows after selecting another panel', async () => {
  await open(); let finish!:(page:MacInventoryPage)=>void, oldSignal:AbortSignal|undefined;
  vi.mocked(mutateRaw).mockImplementation(async (_path, raw, _headers, signal) => { const q = JSON.parse(raw); if (q.section === 'receipts') return new Promise(resolve => { finish = resolve; oldSignal = signal; }); return macInventoryFixture(q); });
  fireEvent.click(screen.getByRole('tab', { name: 'Package receipts' })); await waitFor(() => expect(finish).toBeDefined()); await select('Processes'); expect(oldSignal?.aborted).toBe(true); await act(async () => finish(macInventoryFixture({ section: 'receipts', generationId: `sample_${'a'.repeat(32)}`, offset: 0, limit: 50 }))); expect(screen.queryByText('com.example.fixture.editor')).not.toBeInTheDocument(); expect(screen.getByText('fixture-agent')).toBeVisible();
 });
 it('rejects changed generation between summary and page without showing its rows', async () => {
  amend = page => { if (page.section === 'hardware') page.generationId = `sample_${'b'.repeat(32)}`; return page; }; render(<MacInventoryWorkspace {...props}/>); await screen.findByRole('alert'); expect(screen.queryByText('Mac14,12')).not.toBeInTheDocument();
 });
 it('clears previously visible rows after terminal-disable revalidation', async () => {
  await open(); amend = page => ({ ...page, status: 'disabled', hardware: null, receiptIds: [], processes: [], interfaces: [], total: 0, nextOffset: null }); fireEvent.click(screen.getByRole('button', { name: 'Refresh inventory' })); await screen.findByText(/Inventory collection is disabled/); expect(screen.queryByText('Mac14,12')).not.toBeInTheDocument();
 });
 it('clears original-expiry rows without waiting for another server response', async () => {
  let time = 0; vi.spyOn(Date, 'now').mockImplementation(() => time); vi.spyOn(performance, 'now').mockImplementation(() => time);
  amend = page => ({ ...page, authorityUntil: '2026-10-13T10:00:11Z' }); await open(); time = 1000; await screen.findByRole('alert'); expect(screen.getByRole('alert')).toHaveTextContent('expired'); expect(screen.queryByText('Mac14,12')).not.toBeInTheDocument();
 });
});

describe('generation-pinned whole-row paging', () => {
 it('keeps only the current bounded page and binds next/previous offsets', async () => {
  amend = page => { if (page.section === 'receipts') { page.total = 53; page.receiptIds = Array.from({length:Math.min(50,53-page.offset)}, (_,i)=>`com.fixture.item${String(page.offset+i).padStart(3,'0')}`); page.nextOffset = page.offset===0?50:null; } return page; };
  await open(); await select('Package receipts'); expect(screen.getByText('com.fixture.item000')).toBeVisible(); expect(screen.queryByText('com.fixture.item050')).not.toBeInTheDocument(); fireEvent.click(screen.getByRole('button',{name:'Next page'})); await screen.findByText('com.fixture.item050'); expect(screen.queryByText('com.fixture.item000')).not.toBeInTheDocument(); expect(screen.getByRole('button',{name:'Next page'})).toBeDisabled();
  expect(JSON.parse(vi.mocked(mutateRaw).mock.calls.at(-1)![1])).toEqual({section:'receipts',generationId:`sample_${'a'.repeat(32)}`,offset:50,limit:50}); fireEvent.click(screen.getByRole('button',{name:'Previous page'})); await screen.findByText('com.fixture.item000'); expect(screen.queryByText('com.fixture.item050')).not.toBeInTheDocument();
 });
 it('stops paging when the summary generation changes rather than mixing pages', async () => {
  amend = page => { if(page.section==='receipts'){page.total=4;page.nextOffset=3;}return page;}; await open(); await select('Package receipts'); amend=page=>({...page,generationId:`sample_${'b'.repeat(32)}`}); const before=vi.mocked(mutateRaw).mock.calls.length; fireEvent.click(screen.getByRole('button',{name:'Next page'})); await screen.findByRole('alert'); expect(mutateRaw).toHaveBeenCalledTimes(before+1); expect(screen.queryByText('com.example.fixture.editor')).not.toBeInTheDocument();
 });
});
