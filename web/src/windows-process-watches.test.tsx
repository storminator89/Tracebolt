import { StrictMode } from 'react';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, AUTH_REQUIRED_EVENT } from './api';
import { useOperator } from './auth';
import { setLocale } from './i18n';
import { WindowsProcessWatches } from './windows-process-watches';
import { validProcessWatchView } from './windows-process-watches-types';
import type { ProcessWatchView } from './windows-process-watches-types';
import fixtureJSON from './windows-process-watches-go-fixture.json';
import type { FullProcessesPage } from './windows-full-processes-types';

vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
const fixtures = fixtureJSON as Record<'disabled' | 'current' | 'absent' | 'unknown', ProcessWatchView>, device = fixtures.current.deviceId;
const response = (v: unknown, status = 200) => new Response(JSON.stringify(v), { status });
const page = (): FullProcessesPage => ({ schemaVersion: 'tracebolt.windows-full-processes-page.v1', deviceId: device, serverNow: fixtures.current.serverNow, status: 'ready', authorityUntil: fixtures.current.expiresAt, grantId: fixtures.current.source!.manifest.grantId, grantRevision: 1, complete: fixtures.current.source, latestAttempt: { sequence: 1, attemptedAt: fixtures.current.serverNow, status: 'complete', reason: '' }, search: '', sort: 'pid-asc', limit: 100, offset: 0, matchingCount: 1, rows: [{ pid: 0, parentPid: 0, name: 'FixtureProcess.exe', nameQuality: 'observed', threads: 0 }], nextCursor: '', cursorExpiresAt: fixtures.current.expiresAt });
function server() {
 let current = structuredClone(fixtures.disabled);
 const writes: unknown[] = [];
 vi.stubGlobal('fetch', vi.fn(async (path: string, options?: RequestInit) => {
  if (path === '/api/session') return response({ csrfToken: 'fixture-csrf' });
  if (path.endsWith('/policy')) { writes.push(JSON.parse(options!.body as string)); current = structuredClone(fixtures.current); return response(current); }
  return response(current);
 }));
 return { writes, set(value: ProcessWatchView) { current = structuredClone(value); } };
}
const open = async () => { fireEvent.click(screen.getByText('Process presence watches', { selector: 'summary' })); await screen.findByText('No presence watches enabled'); };
beforeEach(() => { abortProtectedRequests(); setLocale('en'); vi.mocked(useOperator).mockReturnValue({ mode: 'lan', authenticated: true, loginMode: 'shared', expiresAt: '2030-01-01T00:00:00Z', insecureTestMode: false, logout: vi.fn(), theme: 'light', setTheme: vi.fn() }); });
afterEach(() => { cleanup(); vi.useRealTimers(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });
describe('Windows process presence source contract', () => {
 it('validates every Go-emitted lifecycle view', () => { for (const v of Object.values(fixtures)) expect(validProcessWatchView(v, device)).toBe(true); });
 it('rejects zero matches with unavailable names and mismatched source authority', () => {
  const zero = structuredClone(fixtures.absent); zero.unavailableNames = 1; expect(validProcessWatchView(zero, device)).toBe(false);
  const grant = structuredClone(fixtures.current); grant.policy.source!.grantId = 'f'.repeat(32); expect(validProcessWatchView(grant, device)).toBe(false);
  const stale = structuredClone(fixtures.current); stale.serverNow = new Date(Date.parse(stale.serverNow) + 300000).toISOString(); stale.expiresAt = new Date(Date.parse(stale.serverNow) + 30000).toISOString(); expect(validProcessWatchView(stale, device)).toBe(false);
 });
});
describe('Windows process presence review', () => {
 it('is lazy and survives StrictMode effect replay with deliberate consent', async () => {
  const backend = server(); render(<StrictMode><WindowsProcessWatches deviceId={device} sessionKey="one" page={page()} enabled/></StrictMode>);
  expect(fetch).not.toHaveBeenCalled(); await open();
  fireEvent.change(screen.getByLabelText('Choose a name from this inventory page'), { target: { value: 'FixtureProcess.exe' } }); fireEvent.click(screen.getByRole('button', { name: 'Add name' }));
  expect(screen.getByRole('button', { name: 'Save and enable watches' })).toBeDisabled();
  fireEvent.click(screen.getByRole('checkbox')); fireEvent.click(screen.getByRole('button', { name: 'Save and enable watches' }));
  await screen.findByText('Selections saved.'); expect(backend.writes).toHaveLength(1); expect(backend.writes[0]).toEqual({ enabled: true, names: ['FixtureProcess.exe'], expectedRevision: 0, consent: true, source: fixtures.current.source }); expect(screen.getByText(/Observed in snapshot/)).toBeInTheDocument();
 });
 it('offers one explicit combined read and labels snapshot-only scope before opening', async () => {
  const backend = server(), refreshInventory = vi.fn(); render(<WindowsProcessWatches deviceId={device} sessionKey="combined" page={page()} enabled onRefreshInventory={refreshInventory}/>);
  expect(screen.getByText('Process presence watches', { selector: 'summary' })).toHaveTextContent('Snapshot · no alerts or incident history');
  await open(); const before = vi.mocked(fetch).mock.calls.length;
  fireEvent.click(screen.getByRole('button', { name: 'Refresh processes and watches' }));
  await screen.findByText('No presence watches enabled'); expect(refreshInventory).toHaveBeenCalledTimes(1); expect(vi.mocked(fetch).mock.calls.length).toBe(before + 1); expect(backend.writes).toHaveLength(0);
 });
 it('keeps exact-name draft across transient paging gaps and resets on confirmed source change', async () => {
  server(); const source = page(), ui = render(<WindowsProcessWatches deviceId={device} sessionKey="one" page={source} enabled/>); await open();
  fireEvent.change(screen.getByLabelText('Choose a name from this inventory page'), { target: { value: 'FixtureProcess.exe' } }); fireEvent.click(screen.getByRole('button', { name: 'Add name' })); fireEvent.click(screen.getByRole('checkbox'));
  ui.rerender(<WindowsProcessWatches deviceId={device} sessionKey="one" page={null} enabled/>); expect(screen.getByRole('button', { name: 'Remove FixtureProcess.exe' })).toBeInTheDocument(); expect(screen.getByRole('checkbox')).not.toBeChecked();
  ui.rerender(<WindowsProcessWatches deviceId={device} sessionKey="one" page={{ ...source }} enabled/>); expect(screen.getByRole('button', { name: 'Remove FixtureProcess.exe' })).toBeInTheDocument();
  const changed = structuredClone(source); changed.complete!.manifestSha256 = 'f'.repeat(64); ui.rerender(<WindowsProcessWatches deviceId={device} sessionKey="one" page={changed} enabled/>); await screen.findByText('The inventory changed. Review the selected names again.'); expect(screen.queryByRole('button', { name: 'Remove FixtureProcess.exe' })).toBeNull();
 });
 it('does not replay uncertain writes and clears private state on access invalidation', async () => {
  server(); render(<WindowsProcessWatches deviceId={device} sessionKey="one" page={page()} enabled/>); await open();
  fireEvent.change(screen.getByLabelText('Choose a name from this inventory page'), { target: { value: 'FixtureProcess.exe' } }); fireEvent.click(screen.getByRole('button', { name: 'Add name' })); fireEvent.click(screen.getByRole('checkbox'));
  vi.mocked(fetch).mockImplementation(async (path) => String(path).endsWith('/policy') ? Promise.reject(new Error('lost response')) : response({ csrfToken: 'fixture-csrf' }));
  fireEvent.click(screen.getByRole('button', { name: 'Save and enable watches' })); await screen.findByText(/Save result is uncertain/); expect(screen.getByRole('button', { name: 'Save and enable watches' })).toBeDisabled();
  const writes = vi.mocked(fetch).mock.calls.filter(([path]) => String(path).endsWith('/policy')); expect(writes).toHaveLength(1);
  act(() => window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT))); expect(screen.queryByRole('button', { name: 'Remove FixtureProcess.exe' })).toBeNull();
 });
 it('renders German labels and withholds editing from named readers', async () => {
  setLocale('de'); vi.mocked(useOperator).mockReturnValue({ ...vi.mocked(useOperator)()!, loginMode: 'named' }); server(); render(<WindowsProcessWatches deviceId={device} sessionKey="one" page={page()} enabled onRefreshInventory={vi.fn()}/>);
  expect(screen.getByText('Momentaufnahme · keine Alarme oder Vorfallshistorie')).toBeInTheDocument();
  fireEvent.click(screen.getByText('Prozessanwesenheit beobachten', { selector: 'summary' })); await screen.findByText('Keine Anwesenheitsprüfung aktiviert'); expect(screen.getByRole('button', { name: 'Prozessdaten und Prüfungen aktualisieren' })).toBeInTheDocument(); expect(screen.queryByRole('checkbox')).toBeNull(); expect(screen.getByText('Ein gemeinsamer Administrator kann diese Auswahl ändern.')).toBeInTheDocument();
 });
 it('hides expired view counts and requires fresh review', async () => {
  const backend = server(); backend.set(fixtures.current); render(<WindowsProcessWatches deviceId={device} sessionKey="one" page={page()} enabled/>); fireEvent.click(screen.getByText('Process presence watches', { selector: 'summary' })); await screen.findByText(/Observed in snapshot/);
  const mono = performance.now(), wall = Date.now();
  vi.spyOn(performance, 'now').mockReturnValue(mono + 31000); vi.spyOn(Date, 'now').mockReturnValue(wall + 31000);
  await screen.findByText('Current presence unknown'); expect(screen.queryByText(/Observed in snapshot/)).toBeNull();
  await waitFor(() => expect(screen.getByRole('button', { name: 'Save and enable watches' })).toBeDisabled());
  fireEvent.click(screen.getByRole('button', { name: 'Refresh watches' })); await screen.findByText('The result could not be verified. Reload watches before saving again.'); expect(screen.queryByText(/Observed in snapshot/)).toBeNull();
 });
});
