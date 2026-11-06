import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { EnrollmentHistoryFilter } from './enrollment-history-filter';
import { EnrollmentSection } from './enrollment';
import { AUTH_REQUIRED_EVENT, mutate, request } from './api';
import { enrollmentStates, terminal, type EnrollmentList, type EnrollmentSnapshot, type EnrollmentState } from './enrollment-types';
import { setLocale } from './i18n';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutate: vi.fn() }));
const operator = vi.hoisted(() => ({ mode: 'lan', authenticated: true, insecureTestMode: false, actorId: null as string | null, expiresAt: '2026-10-03T16:00:00Z' }));
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: () => operator }));
const now = '2026-10-03T15:00:00Z', seconds = Date.parse(now) / 1000;
function record(state: EnrollmentState, index = 1): EnrollmentSnapshot {
 return { version: 'tracebolt.enrollment-state.v2', binding: { instanceID: `manager_${'2'.repeat(32)}`, origin: 'https://localhost', profile: 'tls', collectionProfile: 'basic-readonly-v1', issuerFingerprint: 'a'.repeat(64) }, invitationID: `invite_${index.toString(16).padStart(32, '0')}`, createRequestID: `request_${'3'.repeat(32)}`, platform: 'linux', revision: 1, state, createdAt: seconds, deadlineAt: seconds + 600, updatedAt: seconds,
 claim: { claimID: `claim_${'4'.repeat(32)}`, requestID: '', keyFingerprint: 'ab'.repeat(32), csrHash: '', claimHash: '', comparisonCode: '12ab'.repeat(8), at: seconds },
 approval: { requestID: '', deviceID: ['created', 'claimed_pending'].includes(state) ? '' : `agent_${'6'.repeat(32)}`, keyFingerprint: 'ab'.repeat(32), at: seconds },
 intent: { intentID: '', requestID: '', serialHex: '', templateVersion: '', deviceID: '', keyFingerprint: '', notBefore: 0, notAfter: state === 'activated' ? seconds + 86400 : 0, at: 0 }, issuance: { requestID: '', certificateHash: '', at: 0 }, activation: { requestID: '', at: 0 }, termination: { requestID: '', from: '', at: 0 } };
}
const records = enrollmentStates.map((state, index) => record(state, index + 1));
function list(items = records): EnrollmentList { return { schemaVersion: 'tracebolt.enrollment-operator.v2', serverNow: now, enabled: true, platforms: ['linux'], recordLimit: 25, items }; }
function rows(items: readonly EnrollmentSnapshot[]) { return <ul aria-label="Fixture rows">{items.map(item => <li key={item.invitationID}>{item.invitationID} · {item.state}</li>)}</ul>; }
function filters(items: readonly EnrollmentSnapshot[] = records) { return <EnrollmentHistoryFilter items={items}>{rows}</EnrollmentHistoryFilter>; }
function search(value: string) { fireEvent.change(screen.getByRole('searchbox'), { target: { value } }); }
function visibleRows() { return screen.queryByRole('list', { name: 'Fixture rows' }) ? within(screen.getByRole('list', { name: 'Fixture rows' })).getAllByRole('listitem') : []; }
function count() { return screen.getByText(/^(?:\d+ of \d+ shown invitations|\d+ von \d+ angezeigten Einladungen)$/); }
beforeEach(() => { setLocale('en', false); localStorage.clear(); sessionStorage.clear(); operator.actorId = null; vi.mocked(request).mockReset().mockResolvedValue(list()); vi.mocked(mutate).mockReset(); });
afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });

describe('local invitation history filters', () => {
 it.each(['en', 'de'] as const)('filters only invitation IDs and preserves owner row order (%s)', locale => {
  setLocale(locale, false); const fetch = vi.fn(); vi.stubGlobal('fetch', fetch); const storage = vi.spyOn(Storage.prototype, 'setItem');
  render(filters()); const input = screen.getByRole('searchbox', { name: locale === 'de' ? 'Einladungs-IDs durchsuchen' : 'Search invitation IDs' });
  expect(input).toHaveAccessibleDescription(expect.stringContaining(locale === 'de' ? 'nicht die aktuelle Gültigkeit' : 'not current validity'));
  expect(visibleRows()).toHaveLength(10); search(`  ${records[9].invitationID.toUpperCase()}  `);
  expect(visibleRows()).toHaveLength(1); expect(visibleRows()[0]).toHaveTextContent(records[9].invitationID);
  search('agent_'); expect(visibleRows()).toHaveLength(0); search('request_'); expect(visibleRows()).toHaveLength(0); search('ab'.repeat(8)); expect(visibleRows()).toHaveLength(0);
  search('invite_'); expect(visibleRows().map(row => row.textContent?.split(' · ')[0])).toEqual(records.map(item => item.invitationID));
  expect(fetch).not.toHaveBeenCalled(); expect(request).not.toHaveBeenCalled(); expect(mutate).not.toHaveBeenCalled(); expect(storage).not.toHaveBeenCalled();
  expect(document.querySelectorAll('svg:not([aria-hidden="true"])')).toHaveLength(0);
 });
 it('keeps all stored phases distinct without interpreting validity or activation as reporting', () => {
  const expiredPending = { ...records[1], deadlineAt: seconds - 10 }; render(filters([expiredPending, ...records.filter((_, index) => index !== 1)]));
  fireEvent.click(screen.getByRole('button', { name: 'Before activation' })); expect(visibleRows()).toHaveLength(5); expect(visibleRows()[0]).toHaveTextContent('claimed_pending');
  fireEvent.click(screen.getByRole('button', { name: 'Activated' })); expect(visibleRows()).toHaveLength(1); expect(visibleRows()[0]).toHaveTextContent('activated');
  fireEvent.click(screen.getByRole('button', { name: 'Ended' })); expect(visibleRows()).toHaveLength(4);
  expect(visibleRows().map(row => row.textContent?.split(' · ')[1])).toEqual(['expired', 'canceled', 'rejected', 'revoked']);
  expect(screen.getByRole('button', { name: 'Ended' })).toHaveAttribute('aria-pressed', 'true');
  fireEvent.click(screen.getByRole('button', { name: 'All shown' })); expect(visibleRows()).toHaveLength(10);
 });
 it.each(['en', 'de'] as const)('combines filters, explains no matches and restores keyboard focus on clear (%s)', async locale => {
  setLocale(locale, false); render(filters()); const user = userEvent.setup();
  search(records[0].invitationID); const activated = screen.getByRole('button', { name: locale === 'de' ? 'Aktiviert' : 'Activated' }); activated.focus(); await user.keyboard('{Enter}');
  expect(visibleRows()).toHaveLength(0); expect(screen.getByText(locale === 'de' ? 'Keine angezeigte Einladung passt zu diesen Filtern.' : 'No shown invitations match these filters.')).toBeVisible();
  expect(count()).toHaveTextContent(locale === 'de' ? '0 von 10' : '0 of 10'); expect(count()).toHaveAttribute('aria-live', 'polite');
  const clear = screen.getByRole('button', { name: locale === 'de' ? 'Filter leeren' : 'Clear filters' }); clear.focus(); await user.keyboard(' ');
  expect(screen.getByRole('searchbox')).toHaveFocus(); expect(screen.getByRole('searchbox')).toHaveValue(''); expect(visibleRows()).toHaveLength(10); expect(clear).toBeDisabled();
 });
 it('never restores ended rows removed by the owner and reflects newer source rows without retaining snapshots', () => {
  const view = render(filters()); fireEvent.click(screen.getByRole('button', { name: 'Ended' })); expect(visibleRows()).toHaveLength(4);
  view.rerender(filters(records.filter(item => !terminal(item.state)))); expect(visibleRows()).toHaveLength(0); expect(count()).toHaveTextContent('0 of 6');
  fireEvent.click(screen.getByRole('button', { name: 'All shown' })); search(records[0].invitationID);
  view.rerender(filters([{ ...records[0], state: 'activated' }])); expect(visibleRows()).toHaveLength(1); expect(visibleRows()[0]).toHaveTextContent('activated');
  view.rerender(filters([])); expect(screen.getByText('No active invitations.')).toBeVisible(); expect(visibleRows()).toHaveLength(0);
 });
 it('bounds and renders arbitrary query text inertly without saving it', () => {
  render(filters()); search('<img src=x onerror=alert(1)>'); expect(visibleRows()).toHaveLength(0); expect(document.querySelector('img,script,iframe')).toBeNull();
  search('x'.repeat(200)); expect(screen.getByRole('searchbox')).toHaveValue('x'.repeat(128)); expect(localStorage.length).toBe(0); expect(sessionStorage.length).toBe(0);
 });
 it.each(['blur', 'pagehide', 'hashchange', AUTH_REQUIRED_EVENT])('clears filter memory on %s without an action', event => {
  render(filters()); search('private query'); fireEvent.click(screen.getByRole('button', { name: 'Ended' }));
  act(() => window.dispatchEvent(new Event(event))); expect(screen.getByRole('searchbox')).toHaveValue(''); expect(screen.getByRole('button', { name: 'All shown' })).toHaveAttribute('aria-pressed', 'true'); expect(mutate).not.toHaveBeenCalled();
 });
 it('clears filters on hidden visibility and unmount without restoring them on return', () => {
  const view = render(filters()); search('private query'); const visibility = vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden');
  act(() => document.dispatchEvent(new Event('visibilitychange'))); visibility.mockReturnValue('visible'); act(() => document.dispatchEvent(new Event('visibilitychange'))); expect(screen.getByRole('searchbox')).toHaveValue('');
  search('private query'); view.unmount(); render(filters()); expect(screen.getByRole('searchbox')).toHaveValue('');
 });
 it('does not take focus from a newer control when a review closes', () => {
  vi.spyOn(document, 'hasFocus').mockReturnValue(true);
  const content = (open: boolean) => <><button>Newer action</button><EnrollmentHistoryFilter items={records} reviewOpen={open}>{rows}</EnrollmentHistoryFilter></>;
  const view = render(content(true)); const newer = screen.getByRole('button', { name: 'Newer action' }); newer.focus();
  view.rerender(content(false)); expect(newer).toHaveFocus();
 });
 it('never moves review-close focus into a hidden or unfocused page', () => {
  const visibility = vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden'); const focused = vi.spyOn(document, 'hasFocus').mockReturnValue(true);
  const content = (open: boolean) => <EnrollmentHistoryFilter items={records} reviewOpen={open}>{rows}</EnrollmentHistoryFilter>;
  const view = render(content(true)); view.rerender(content(false)); expect(screen.getByRole('searchbox')).not.toHaveFocus();
  visibility.mockReturnValue('visible'); focused.mockReturnValue(false); view.rerender(content(true)); view.rerender(content(false)); expect(screen.getByRole('searchbox')).not.toHaveFocus();
 });
});

describe('existing enrollment history integration', () => {
 function section() { return <EnrollmentSection onChanged={() => {}} onDevice={() => {}} deviceIds={[]}/>; }
 async function open() { render(section()); const button = await screen.findByRole('button', { name: /Invitations/ }); fireEvent.click(button); await screen.findByRole('searchbox'); }
 it('leaves history admission, capacity and exact unchecked review unchanged while filtering', async () => {
  await open(); expect(count()).toHaveTextContent('6 of 6');
  const before = vi.mocked(request).mock.calls.length;
  fireEvent.click(screen.getByRole('button', { name: 'Ended' })); expect(screen.getByText('No shown invitations match these filters.')).toBeVisible();
  fireEvent.click(screen.getByRole('checkbox', { name: 'Show ended' })); expect(count()).toHaveTextContent('4 of 10');
  fireEvent.click(screen.getByRole('button', { name: 'Clear filters' })); search(records[1].invitationID);
  expect(screen.getByText('10 of 25 retained records · 15 record slots available')).toBeVisible();
  const row = screen.getByRole('button', { name: `Review invitation ${records[1].invitationID}` }); expect(document.querySelectorAll('.enrollment-row')).toHaveLength(1); row.focus(); await userEvent.setup().keyboard('{Enter}');
  const dialog = screen.getByRole('dialog', { name: 'Review invitation' }); expect(within(dialog).getByRole('checkbox')).not.toBeChecked(); expect(within(dialog).getByRole('button', { name: 'Approve device' })).toBeDisabled();
  expect(mutate).not.toHaveBeenCalled(); expect(request).toHaveBeenCalledTimes(before);
  fireEvent.keyDown(document, { key: 'Escape' }); await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull()); expect(row).toHaveFocus(); expect(screen.getByRole('searchbox')).toHaveValue(records[1].invitationID);
 });
 it('resets filters after history dismissal and operator-session replacement', async () => {
  const view = render(section()); fireEvent.click(await screen.findByRole('button', { name: /Invitations/ })); search('private query');
  fireEvent.click(screen.getByRole('button', { name: /Invitations/ })); expect(screen.queryByRole('searchbox')).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: /Invitations/ })); expect(screen.getByRole('searchbox')).toHaveValue('');
  search('private query'); operator.actorId = `operator_${'9'.repeat(32)}`; view.rerender(section()); expect(screen.getByRole('searchbox')).toHaveValue(''); expect(mutate).not.toHaveBeenCalled();
 });
 it('removes filters and rows on failed enrollment refresh', async () => {
  await open(); search('private query'); vi.mocked(request).mockRejectedValueOnce(new Error('private error'));
  fireEvent.click(screen.getByRole('button', { name: 'Refresh enrollment status' })); await screen.findByRole('alert');
  expect(screen.queryByRole('searchbox')).toBeNull(); expect(document.querySelectorAll('.enrollment-row')).toHaveLength(0); expect(document.body.innerHTML).not.toContain('private query'); expect(mutate).not.toHaveBeenCalled();
 });
 it('resets filters on operating-system changes without creating an invitation', async () => {
  vi.mocked(request).mockImplementation(async path => path === '/windows/enrollment' ? { ...list([]), enabled: false, platforms: ['windows'], collectionProfile: 'windows-inventory-v1', collectionPrivacy: 'windows_inventory_metadata_may_be_sensitive' } : list());
  await open(); search('private query'); fireEvent.change(screen.getByRole('combobox', { name: 'Operating system' }), { target: { value: 'windows' } });
  await waitFor(() => expect(request).toHaveBeenLastCalledWith('/windows/enrollment', expect.anything())); expect(screen.queryByRole('searchbox')).toBeNull();
  fireEvent.change(screen.getByRole('combobox', { name: 'Operating system' }), { target: { value: 'linux' } });
  fireEvent.click(await screen.findByRole('button', { name: /Invitations/ })); expect(screen.getByRole('searchbox')).toHaveValue(''); expect(mutate).not.toHaveBeenCalled();
 });
 it('returns focus to search when the reviewed row leaves its stored-phase filter', async () => {
  vi.spyOn(document, 'hasFocus').mockReturnValue(true); vi.mocked(request).mockResolvedValue(list([records[1]])); await open();
  fireEvent.click(screen.getByRole('button', { name: 'Before activation' }));
  const row = screen.getByRole('button', { name: `Review invitation ${records[1].invitationID}` }); row.focus(); await userEvent.setup().keyboard('{Enter}');
  const dialog = screen.getByRole('dialog', { name: 'Review invitation' });
  vi.mocked(request).mockResolvedValue(list([{ ...record('activated', 2), revision: 2 }])); fireEvent.click(within(dialog).getByRole('button', { name: 'Check status' }));
  await waitFor(() => expect(document.querySelectorAll('.enrollment-row')).toHaveLength(0));
  fireEvent.keyDown(document, { key: 'Escape' }); await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
  expect(screen.getByRole('searchbox')).toHaveFocus(); expect(screen.getByRole('button', { name: 'Before activation' })).toHaveAttribute('aria-pressed', 'true'); expect(mutate).not.toHaveBeenCalled();
 });
});
