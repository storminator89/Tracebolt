import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { APIError, AUTH_REQUIRED_EVENT, mutateRaw } from './api';
import { setLocale } from './i18n';
import { MacInventoryWorkspace } from './macos-inventory';
import { macInventoryDeviceId, macInventoryFixtureClock } from './macos-inventory-fixture';
import type { MacInventoryPage } from './macos-inventory-types';
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), mutateRaw: vi.fn() }));
const props = { deviceId: macInventoryDeviceId, enabled: true, configured: true, sessionKey: '2026-10-13T10:30:00Z', identityKey: 'original-identity' };
let amend: (page: MacInventoryPage) => MacInventoryPage;
let macInventoryFixture: ReturnType<typeof macInventoryFixtureClock>;
beforeEach(() => { macInventoryFixture = macInventoryFixtureClock(); setLocale('en', false); amend = page => page; vi.mocked(mutateRaw).mockReset().mockImplementation(async (_path, raw) => amend(macInventoryFixture(JSON.parse(raw)))); });
afterEach(() => { cleanup(); vi.restoreAllMocks(); });
const input = () => screen.getByRole('textbox');
const draft = (value: string) => fireEvent.change(input(), { target: { value } });
const apply = () => fireEvent.click(screen.getByRole('button', { name: 'Apply' }));
const lastQuery = () => JSON.parse(vi.mocked(mutateRaw).mock.calls.at(-1)![1]);
async function open() { const result = render(<MacInventoryWorkspace {...props}/>); await screen.findByText('Mac14,12'); return result; }
async function select(name = 'Package receipts') { fireEvent.click(screen.getByRole('tab', { name })); await waitFor(() => expect(screen.getByRole('button', { name: 'Refresh inventory' })).toBeEnabled()); }
function revalidation() { const interval = vi.spyOn(window, 'setInterval'); return () => { const callback = interval.mock.calls.find(call => call[1] === 15000)?.[0] as () => void; expect(callback).toBeTypeOf('function'); return act(async () => callback()); }; }
describe('explicit private receipt and process lookup', () => {
 it('keeps drafts local until Apply, normalizes once and clears old rows immediately', async () => {
  await open(); expect(screen.queryByRole('textbox')).not.toBeInTheDocument(); await select(); const before = vi.mocked(mutateRaw).mock.calls.length; draft('  EDITOR  ');
  expect(input()).toHaveValue('  EDITOR  '); expect(mutateRaw).toHaveBeenCalledTimes(before); expect(screen.getByText('com.example.fixture.helper')).toBeVisible();
  apply(); expect(screen.queryByText('com.example.fixture.helper')).not.toBeInTheDocument(); expect(input()).toHaveValue('editor'); await screen.findByText('com.example.fixture.editor'); expect(screen.getByTestId('mac-lookup-count')).toHaveTextContent('1 matches · 3 source rows');
  expect(lastQuery()).toEqual({ schemaVersion: 'tracebolt.macos-read-inventory-query.v2', section: 'receipts', generationId: `sample_${'a'.repeat(32)}`, offset: 0, limit: 50, search: 'editor' });
  fireEvent.click(screen.getByRole('button', { name: 'Clear' })); expect(screen.queryByText('com.example.fixture.editor')).not.toBeInTheDocument(); await screen.findByText('com.example.fixture.helper'); expect(input()).toHaveValue(''); expect(lastQuery().search).toBe(''); await select('IPv4 interfaces'); expect(screen.queryByRole('textbox')).not.toBeInTheDocument();
 });
 it('applies on Enter and searches process numeric fields independently', async () => {
  const user = userEvent.setup(); await open(); await select('Processes'); await user.type(input(), '42{Enter}'); await waitFor(() => expect(screen.getByTestId('mac-lookup-count')).toHaveTextContent('1 matches · 2 source rows')); expect(screen.getByText('fixture-agent')).toBeVisible(); expect(screen.queryByText('fixture-init')).not.toBeInTheDocument(); draft('0'); apply(); await screen.findByText('fixture-init'); expect(screen.queryByText('fixture-agent')).not.toBeInTheDocument();
 });
 it.each(['Package receipts', 'Processes'])('shows observed no-match distinctly in %s', async section => {
  await open(); await select(section); draft('not-present'); apply(); await screen.findByText('No matches in this captured source.'); expect(screen.getByTestId('mac-lookup-count')).toHaveTextContent(`0 matches · ${section === 'Processes' ? 2 : 3} source rows`); expect(screen.queryByRole('table')).not.toBeInTheDocument(); expect(screen.queryByRole('button', { name: 'Next page' })).not.toBeInTheDocument();
 });
 it.each(['denied', 'unavailable'] as const)('keeps %s sources unknown even with a nonempty search', async quality => {
  amend = page => { page.sources!.processes = { ...page.sources!.processes, quality, reason: quality === 'denied' ? 'macos_inventory_access_denied' : 'macos_inventory_unavailable' }; page.sourceQuality = 'partial'; if (page.section === 'processes') { page.processes = []; page.total = 0; if (page.schemaVersion === 'tracebolt.macos-read-inventory-page.v2') page.matchingCount = 0; } return page; };
  await open(); await select('Processes'); draft('not-present'); apply(); await waitFor(() => expect(screen.getByRole('button', { name: 'Refresh inventory' })).toBeEnabled()); expect(screen.getByTestId('mac-lookup-count')).toHaveTextContent('Count unknown'); expect(screen.queryByText('No matches in this captured source.')).not.toBeInTheDocument(); expect(screen.queryByText(/0 matches/)).not.toBeInTheDocument();
 });
 it('rejects non-ASCII without a request or replacing applied results', async () => {
  await open(); await select(); const before = vi.mocked(mutateRaw).mock.calls.length; draft('K'); apply(); expect(screen.getByRole('alert')).toHaveTextContent('256 printable ASCII'); expect(input()).toHaveAttribute('aria-invalid', 'true'); expect(mutateRaw).toHaveBeenCalledTimes(before); expect(screen.getByText('com.example.fixture.editor')).toBeVisible();
 });
 it('revalidates the applied filter without applying or normalizing a newer draft', async () => {
  const tick = revalidation(); await open(); await select(); draft('editor'); apply(); await screen.findByText('com.example.fixture.editor'); draft('  HELPER  '); const before = vi.mocked(mutateRaw).mock.calls.length; await tick(); await waitFor(() => expect(mutateRaw).toHaveBeenCalledTimes(before + 2)); expect(lastQuery().search).toBe('editor'); expect(input()).toHaveValue('  HELPER  '); expect(screen.getByText('com.example.fixture.editor')).toBeVisible(); expect(screen.queryByText('com.example.fixture.helper')).not.toBeInTheDocument(); expect(screen.getByText(/Draft not applied/)).toBeVisible();
 });
 it('cancels an older Apply and rejects its late detail response after another Apply', async () => {
  await open(); await select(); let finish!: () => void, oldSignal: AbortSignal | undefined;
  vi.mocked(mutateRaw).mockImplementation(async (_path, raw, _headers, signal) => { const q = JSON.parse(raw); if (q.search === 'editor') return new Promise(resolve => { finish = () => resolve(macInventoryFixture(q)); oldSignal = signal; }); return macInventoryFixture(q); });
  draft('editor'); apply(); await waitFor(() => expect(finish).toBeDefined()); draft('helper'); apply(); expect(oldSignal?.aborted).toBe(true); await screen.findByText('com.example.fixture.helper'); await act(async () => finish()); expect(screen.queryByText('com.example.fixture.editor')).not.toBeInTheDocument(); expect(input()).toHaveValue('helper');
 });
 it('pins filtered paging to applied search and refreshes that filter at offset zero', async () => {
  const rows = Array.from({ length: 53 }, (_, i) => `com.fixture.item${String(i).padStart(3, '0')}`);
  vi.mocked(mutateRaw).mockImplementation(async (_path, raw) => { const q = JSON.parse(raw), page = macInventoryFixture(q); if (q.section !== 'receipts') return page; const all = [...rows, 'org.other'], matches = all.filter(row => row.includes(q.search)); return { ...page, receiptIds: matches.slice(q.offset, q.offset + q.limit), total: all.length, matchingCount: matches.length, nextOffset: q.offset + q.limit < matches.length ? q.offset + q.limit : null }; });
  await open(); await select(); draft('fixture'); apply(); await screen.findByText(rows[0]); expect(screen.getByTestId('mac-lookup-count')).toHaveTextContent('53 matches · 54 source rows'); draft('different-draft'); fireEvent.click(screen.getByRole('button', { name: 'Next page' })); await screen.findByText(rows[50]); expect(screen.queryByText(rows[0])).not.toBeInTheDocument(); expect(lastQuery()).toMatchObject({ search: 'fixture', offset: 50, generationId: `sample_${'a'.repeat(32)}` }); expect(screen.getByText('51–53 / 53')).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'Previous page' })); await screen.findByText(rows[0]); expect(lastQuery()).toMatchObject({ search: 'fixture', offset: 0 }); fireEvent.click(screen.getByRole('button', { name: 'Next page' })); await screen.findByText(rows[50]); fireEvent.click(screen.getByRole('button', { name: 'Refresh inventory' })); await screen.findByText(rows[0]); expect(lastQuery()).toMatchObject({ search: 'fixture', offset: 0 }); expect(input()).toHaveValue('different-draft');
 });
 it('blocks automatic replacement until deliberate refresh, keeping the applied filter', async () => {
  const tick = revalidation(); await open(); await select(); draft('editor'); apply(); await screen.findByText('com.example.fixture.editor'); amend = page => ({ ...page, generationId: `sample_${'b'.repeat(32)}` }); const before = vi.mocked(mutateRaw).mock.calls.length;
  await tick(); await screen.findByRole('alert'); expect(screen.queryByText('com.example.fixture.editor')).not.toBeInTheDocument(); expect(mutateRaw).toHaveBeenCalledTimes(before + 1); expect(input()).toHaveValue('editor'); await tick(); expect(mutateRaw).toHaveBeenCalledTimes(before + 1); fireEvent.click(screen.getByRole('button', { name: 'Refresh inventory' })); await screen.findByText('com.example.fixture.editor'); expect(lastQuery()).toMatchObject({ search: 'editor', generationId: `sample_${'b'.repeat(32)}`, offset: 0 });
 });
 it.each(['pagehide', 'hashchange', 'blur', AUTH_REQUIRED_EVENT])('forgets applied/draft text on %s and discards interrupted requests', async event => {
  await open(); await select(); draft('editor'); apply(); await screen.findByText('com.example.fixture.editor'); draft('private-draft'); let finish!: () => void, signal: AbortSignal | undefined;
  vi.mocked(mutateRaw).mockImplementation(async (_path, raw, _headers, pending) => new Promise(resolve => { signal = pending; finish = () => resolve(macInventoryFixture(JSON.parse(raw))); })); fireEvent.click(screen.getByRole('button', { name: 'Refresh inventory' })); act(() => window.dispatchEvent(new Event(event))); expect(signal?.aborted).toBe(true); expect(input()).toHaveValue(''); expect(screen.queryByText('com.example.fixture.editor')).not.toBeInTheDocument(); await act(async () => finish()); expect(input()).toHaveValue(''); expect(screen.queryByText('com.example.fixture.editor')).not.toBeInTheDocument();
 });
 it.each(['sessionKey', 'identityKey', 'deviceId'] as const)('forgets search on %s change', async field => {
  const result = await open(); await select(); draft('editor'); apply(); await screen.findByText('com.example.fixture.editor'); draft('private-draft'); vi.mocked(mutateRaw).mockImplementation(async () => new Promise(() => {})); result.rerender(<MacInventoryWorkspace {...props} {...{ [field]: field === 'deviceId' ? `agent_${'8'.repeat(32)}` : 'different' }}/>); expect(input()).toHaveValue(''); expect(screen.queryByText('com.example.fixture.editor')).not.toBeInTheDocument();
 });
 it('clears controls on section and access loss without restoring drafts', async () => {
  const result = await open(); await select(); draft('editor'); apply(); await screen.findByText('com.example.fixture.editor'); await select('Processes'); expect(input()).toHaveValue(''); draft('42'); await select(); expect(input()).toHaveValue(''); draft('private-draft'); result.rerender(<MacInventoryWorkspace {...props} enabled={false}/>); expect(screen.queryByRole('textbox')).not.toBeInTheDocument(); result.rerender(<MacInventoryWorkspace {...props}/>); await screen.findByText('com.example.fixture.editor'); expect(input()).toHaveValue('');
 });
 it('clears private query text on server access loss', async () => {
  await open(); await select(); draft('editor'); apply(); await screen.findByText('com.example.fixture.editor'); vi.mocked(mutateRaw).mockRejectedValue(new APIError('forbidden', 403)); fireEvent.click(screen.getByRole('button', { name: 'Refresh inventory' })); await screen.findByRole('alert'); expect(input()).toHaveValue(''); expect(screen.queryByText('com.example.fixture.editor')).not.toBeInTheDocument();
 });
 it('keeps text out of storage, history and URLs', async () => {
  const storage = vi.spyOn(Storage.prototype, 'setItem'), push = vi.spyOn(history, 'pushState'), replace = vi.spyOn(history, 'replaceState'); await open(); await select('Processes'); draft('42'); apply(); await screen.findByText('fixture-agent'); expect(storage).not.toHaveBeenCalled(); expect(push).not.toHaveBeenCalled(); expect(replace).not.toHaveBeenCalled(); for (const [path] of vi.mocked(mutateRaw).mock.calls) expect(path).toBe(`/devices/${macInventoryDeviceId}/macos-inventory/query`);
 });
 it('supports German search, Apply/Clear and no-match/count copy', async () => {
  setLocale('de', false); render(<MacInventoryWorkspace {...props}/>); await screen.findByText('Mac14,12'); fireEvent.click(screen.getByRole('tab', { name: 'Paketbelege' })); await screen.findByText('com.example.fixture.editor'); expect(screen.getByRole('textbox', { name: 'Belege suchen' })).toBeVisible(); draft('  ABSENT  '); fireEvent.click(screen.getByRole('button', { name: 'Anwenden' })); await screen.findByText('Keine Treffer in dieser erfassten Quelle.'); expect(screen.getByTestId('mac-lookup-count')).toHaveTextContent('0 Treffer · 3 Quellzeilen'); expect(input()).toHaveValue('absent'); fireEvent.click(screen.getByRole('button', { name: 'Leeren' })); await screen.findByText('com.example.fixture.editor'); expect(input()).toHaveValue('');
 });
});
