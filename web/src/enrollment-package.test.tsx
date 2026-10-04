import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { EnrollmentSection } from './enrollment';
import { preparedEnrollmentCommand } from './enrollment-command';
import { AUTH_REQUIRED_EVENT, mutate, request } from './api';
import { AuthBoundary } from './auth';
import { validEnrollmentList } from './enrollment-types';
import type { EnrollmentCollectionProfile, EnrollmentList, EnrollmentSnapshot, InvitationCreation } from './enrollment-types';
import { setLocale } from './i18n';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutate: vi.fn() }));
const v1 = 'managed-operations-v1', v2 = 'managed-operations-v2', v3 = 'managed-operations-v3';
const v1Privacy = 'metadata_labels_may_be_sensitive', v2Privacy = 'package_source_metadata_may_be_sensitive', v3Privacy = 'complete_system_inventory_metadata_may_be_sensitive';
const serverNow = '2026-10-03T15:00:00Z', seconds = Date.parse(serverNow) / 1000;
const secret = 'S'.repeat(43), invitation = `invite_${'1'.repeat(32)}`;
// Certificate framing only. Native enrollment remains responsible for X.509 validation.
const certificate = '-----BEGIN CERTIFICATE-----\nQUJDRA==\n-----END CERTIFICATE-----';
const session = { mode: 'lan', transport: 'https', insecureTestMode: false, transportWarning: null, authenticationRequired: true, authenticated: true, csrfToken: 'synthetic-session', serverNow, expiresAt: '2026-10-03T15:30:00Z', expiresInSeconds: 1800 };
function listing(profile: EnrollmentCollectionProfile = v2): EnrollmentList {
 return { schemaVersion: 'tracebolt.enrollment-operator.v2', serverNow, enabled: true, platforms: ['linux'], recordLimit: 25, items: [], ...(profile === 'basic-readonly-v1' ? {} : { collectionProfile: profile, collectionPrivacy: profile === v1 ? v1Privacy : profile === v2 ? v2Privacy : v3Privacy }) };
}
function creation(profile: EnrollmentCollectionProfile = v2): InvitationCreation {
 const snapshot: EnrollmentSnapshot = {
  version: 'tracebolt.enrollment-state.v2', binding: { instanceID: `manager_${'2'.repeat(32)}`, origin: window.location.origin, profile: 'tls', collectionProfile: profile, issuerFingerprint: 'a'.repeat(64) },
  invitationID: invitation, createRequestID: `request_${'3'.repeat(32)}`, platform: 'linux', revision: 1, state: 'created', createdAt: seconds, deadlineAt: seconds + 600, updatedAt: seconds,
  claim: { claimID: '', requestID: '', keyFingerprint: '', csrHash: '', claimHash: '', comparisonCode: '', at: 0 }, approval: { requestID: '', deviceID: '', keyFingerprint: '', at: 0 },
  intent: { intentID: '', requestID: '', serialHex: '', templateVersion: '', deviceID: '', keyFingerprint: '', notBefore: 0, notAfter: 0, at: 0 }, issuance: { requestID: '', certificateHash: '', at: 0 }, activation: { requestID: '', at: 0 }, termination: { requestID: '', from: '', at: 0 },
 };
 return { schemaVersion: 'tracebolt.enrollment-invitation.v2', serverNow, snapshot, invitationSecret: secret, bootstrap: { schemaVersion: 'tracebolt.enrollment-bootstrap.v2', managerInstanceId: snapshot.binding.instanceID, profile: 'tls', enrollmentOrigin: window.location.origin, agentOrigin: 'https://localhost:9443', collectionProfile: profile, invitationId: invitation, serverCaPem: certificate, issuerRootPem: certificate, issuerPem: certificate } };
}
let current: EnrollmentList;
const changed = vi.fn();
function section() { return <EnrollmentSection onChanged={changed} onDevice={() => {}} deviceIds={[]}/>; }
async function open() {
 await waitFor(() => expect(screen.getByRole('button', { name: 'Add device' })).toBeEnabled());
 fireEvent.click(screen.getByRole('button', { name: 'Add device' }));
 return screen.getByRole('dialog', { name: 'Add device' });
}
async function add() { render(section()); return open(); }
function acknowledgeAndCreate(dialog: HTMLElement) {
 fireEvent.click(within(dialog).getByRole('checkbox'));
 fireEvent.click(within(dialog).getByRole('button', { name: 'Create invitation' }));
}
async function refresh() {
 fireEvent.click(screen.getByRole('button', { name: 'Refresh enrollment status' }));
 await waitFor(() => expect(screen.getByRole('button', { name: 'Refresh enrollment status' })).toBeEnabled());
}
function pendingCreation() {
 let finish!: (value: InvitationCreation) => void;
 vi.mocked(mutate).mockImplementation(() => new Promise<InvitationCreation>(resolve => { finish = resolve; }));
 return async () => { await act(async () => finish(creation())); };
}
beforeEach(() => {
 setLocale('en', false); current = listing(); localStorage.clear(); sessionStorage.clear(); changed.mockClear();
 vi.mocked(request).mockReset().mockImplementation(async () => structuredClone(current)); vi.mocked(mutate).mockReset();
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals(); vi.useRealTimers(); });

describe('exact package-source enrollment consent', () => {
 it('accepts only coherent explicit managed pairs and the unchanged basic omission', () => {
  for (const profile of ['basic-readonly-v1', v1, v2, v3] as const) expect(validEnrollmentList(listing(profile))).toBe(true);
  expect(validEnrollmentList({ ...listing('basic-readonly-v1'), collectionProfile: 'basic-readonly-v1' })).toBe(true);
  for (const profile of [undefined, 'basic-readonly-v1', v1, v2, 'managed-operations-v3', null]) {
   for (const privacy of [undefined, v1Privacy, v2Privacy, v3Privacy, 'anonymous', null]) {
    const allowed = (profile === undefined || profile === 'basic-readonly-v1') && privacy === undefined || profile === v1 && privacy === v1Privacy || profile === v2 && privacy === v2Privacy || profile === v3 && privacy === v3Privacy;
    expect(validEnrollmentList({ ...listing('basic-readonly-v1'), collectionProfile: profile, collectionPrivacy: privacy })).toBe(allowed);
   }
  }
 });
 it('explains the v2 scope, sensitivity, partial bounds, durable retention and fresh-store requirement before an unchecked gate', async () => {
  vi.mocked(mutate).mockResolvedValue(creation()); const dialog = await add();
  expect(within(dialog).getByText('Operational and package-source inventory · Linux')).toBeVisible();
  for (const text of ['Disk, network, service, process, software and event metadata', 'ID, VERSION_ID and VERSION_CODENAME', 'binary and source package names and exact versions', 'source-mapping basis and install state', 'personal or sensitive labels', '128 rows and 16 KiB', 'may be partial', 'agent-visible namespace', 'until replaced, including after revocation', 'Age-based hiding does not delete', 'unknown package observation replaces', 'No APT execution, package installation or changes, or AI export', 'fresh store and fresh enrollment', 'not silently migrated or reset']) expect(dialog.textContent).toContain(text);
  const checkbox = within(dialog).getByRole('checkbox', { name: 'I acknowledge this operational and package-source collection for the new device.' });
  expect(checkbox).not.toBeChecked(); expect(within(dialog).getByRole('button', { name: 'Create invitation' })).toBeDisabled();
  fireEvent.click(within(dialog).getByRole('button', { name: 'Create invitation' })); expect(mutate).not.toHaveBeenCalled();
  acknowledgeAndCreate(dialog); await screen.findByLabelText('One-time invitation secret');
  expect(mutate).toHaveBeenCalledExactlyOnceWith('/enrollment/invitations', { requestId: expect.stringMatching(/^request_[a-f0-9]{32}$/), platform: 'linux', collectionAcknowledged: true }, expect.any(AbortSignal));
  expect(JSON.stringify({ ...localStorage, ...sessionStorage })).not.toContain('collectionAcknowledged');
 });
 it('renders German copy with the same full scope and affirmative gate', async () => {
  const dialog = await add(); act(() => setLocale('de', false));
  expect(within(dialog).getByText('Betriebs- und Paketquelleninventar · Linux')).toBeVisible();
  for (const text of ['ID, VERSION_ID und VERSION_CODENAME', 'Binär- und Quellpaketnamen mit exakten Versionen', 'Quellpaketzuordnung und Installationszustand', 'sensible Bezeichnungen', '128 Zeilen und 16 KiB', 'unvollständig', 'auch nach einem Widerruf', 'Ausblenden löscht keine', 'Keine APT-Ausführung, Paketinstallation oder Paketänderungen und kein KI-Export', 'neuen Datenspeicher und ein neues Enrollment', 'nicht stillschweigend migriert oder zurückgesetzt']) expect(dialog.textContent).toContain(text);
  expect(within(dialog).getByRole('checkbox', { name: 'Ich bestätige diese Betriebs- und Paketquellenerfassung für das neue Gerät.' })).not.toBeChecked();
  expect(within(dialog).getByRole('button', { name: 'Einladung erstellen' })).toBeDisabled(); expect(mutate).not.toHaveBeenCalled();
 });
 it.each(['basic-readonly-v1', v1] as const)('preserves the %s request and consent surface', async profile => {
  current = listing(profile); vi.mocked(mutate).mockResolvedValue(creation(profile)); const dialog = await add();
  expect(dialog.textContent).not.toContain('package-source');
  if (profile === v1) { expect(within(dialog).getByText('Operational inventory · Linux')).toBeVisible(); fireEvent.click(within(dialog).getByRole('checkbox', { name: 'I acknowledge this additional collection for the new device.' })); }
  else expect(within(dialog).queryByRole('checkbox')).not.toBeInTheDocument();
  fireEvent.click(within(dialog).getByRole('button', { name: 'Create invitation' })); await screen.findByLabelText('One-time invitation secret');
  expect(mutate).toHaveBeenCalledExactlyOnceWith('/enrollment/invitations', { requestId: expect.any(String), platform: 'linux', ...(profile === v1 ? { collectionAcknowledged: true } : {}) }, expect.any(AbortSignal));
 });
 it.each(['basic-readonly-v1', v1] as const)('rejects a v2 create response rebound to %s', async profile => {
  vi.mocked(mutate).mockResolvedValue(creation(profile)); const dialog = await add(); acknowledgeAndCreate(dialog); await within(dialog).findByRole('alert');
  expect(screen.queryByLabelText('One-time invitation secret')).not.toBeInTheDocument(); expect(within(dialog).queryByRole('button', { name: 'Download bootstrap file' })).not.toBeInTheDocument(); expect(changed).not.toHaveBeenCalled();
 });
 it('rejects a bootstrap-only profile mismatch', async () => {
  const response = creation(); response.bootstrap.collectionProfile = v1; vi.mocked(mutate).mockResolvedValue(response);
  const dialog = await add(); acknowledgeAndCreate(dialog); await within(dialog).findByRole('alert');
  expect(screen.queryByLabelText('One-time invitation secret')).not.toBeInTheDocument(); expect(within(dialog).queryByRole('button', { name: 'Download bootstrap file' })).not.toBeInTheDocument();
 });
});

describe('fresh package consent across context replacement', () => {
 it('does not carry old v1 consent into v2 or retain v2 consent across close/reopen', async () => {
  current = listing(v1); let dialog = await add(); fireEvent.click(within(dialog).getByRole('checkbox'));
  current = listing(v2); await refresh(); expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  dialog = await open(); expect(within(dialog).getByRole('checkbox')).not.toBeChecked(); expect(within(dialog).getByRole('button', { name: 'Create invitation' })).toBeDisabled();
  fireEvent.click(within(dialog).getByRole('checkbox')); fireEvent.keyDown(document, { key: 'Escape' }); dialog = await open(); expect(within(dialog).getByRole('checkbox')).not.toBeChecked(); expect(mutate).not.toHaveBeenCalled();
 });
 it.each(['profile', 'recordLimit', 'privacy', 'clock', 'unavailable'] as const)('clears selected one-time material when the %s configuration changes or becomes invalid', async kind => {
  vi.mocked(mutate).mockResolvedValue(creation()); const dialog = await add(); acknowledgeAndCreate(dialog); await screen.findByLabelText('One-time invitation secret');
  if (kind === 'profile') current = listing(v1);
  else if (kind === 'recordLimit') current = { ...current, recordLimit: 24 };
  else if (kind === 'privacy') current = { ...current, collectionPrivacy: v1Privacy };
  else if (kind === 'clock') current = { ...current, serverNow: '' };
  else vi.mocked(request).mockRejectedValue(new Error('synthetic unavailable configuration'));
  await refresh(); expect(screen.queryByRole('dialog')).not.toBeInTheDocument(); expect(screen.queryByDisplayValue(secret)).not.toBeInTheDocument(); expect(screen.queryByRole('button', { name: 'Download bootstrap file' })).not.toBeInTheDocument();
 });
 it.each(['profile', 'privacy', 'clock', 'unavailable'] as const)('aborts pending creation and rejects late material after %s invalidation', async kind => {
  const finish = pendingCreation(); const dialog = await add(); acknowledgeAndCreate(dialog); const signal = vi.mocked(mutate).mock.calls[0][2]!;
  if (kind === 'profile') current = listing(v1);
  else if (kind === 'privacy') current = { ...current, collectionPrivacy: v1Privacy };
  else if (kind === 'clock') current = { ...current, serverNow: '' };
  else vi.mocked(request).mockRejectedValue(new Error('synthetic unavailable configuration'));
  await refresh(); expect(signal.aborted).toBe(true); await finish(); expect(screen.queryByRole('dialog')).not.toBeInTheDocument(); expect(screen.queryByDisplayValue(secret)).not.toBeInTheDocument(); expect(changed).not.toHaveBeenCalled();
 });
 it.each(['pagehide', 'hidden'] as const)('clears consent on %s and requires a fresh server anchor', async kind => {
  const dialog = await add(); fireEvent.click(within(dialog).getByRole('checkbox'));
  if (kind === 'pagehide') act(() => window.dispatchEvent(new Event('pagehide')));
  else { vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden'); act(() => document.dispatchEvent(new Event('visibilitychange'))); }
  expect(within(dialog).getByRole('checkbox')).not.toBeChecked(); expect(within(dialog).getByRole('button', { name: 'Create invitation' })).toBeDisabled();
  vi.restoreAllMocks(); const restored = new Event('pageshow'); Object.defineProperty(restored, 'persisted', { value: true }); act(() => window.dispatchEvent(restored));
  await waitFor(() => expect(request).toHaveBeenCalledTimes(2)); expect(within(dialog).getByRole('checkbox')).not.toBeChecked(); expect(within(dialog).getByRole('button', { name: 'Create invitation' })).toBeDisabled(); expect(mutate).not.toHaveBeenCalled();
 });
 it('does not restore a late create response after pagehide', async () => {
  const finish = pendingCreation(); const dialog = await add(); acknowledgeAndCreate(dialog); const signal = vi.mocked(mutate).mock.calls[0][2]!;
  act(() => window.dispatchEvent(new Event('pagehide'))); expect(signal.aborted).toBe(true); await finish(); expect(screen.queryByDisplayValue(secret)).not.toBeInTheDocument(); expect(changed).not.toHaveBeenCalled(); expect(within(dialog).getByRole('checkbox')).not.toBeChecked();
 });
 it('invalidates consent and pending material after monotonic clock rollback', async () => {
  vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] }); const clock = vi.spyOn(performance, 'now').mockReturnValue(1000);
  const finish = pendingCreation(); const dialog = await add(); acknowledgeAndCreate(dialog); const signal = vi.mocked(mutate).mock.calls[0][2]!;
  clock.mockReturnValue(0); act(() => vi.advanceTimersByTime(1000)); expect(signal.aborted).toBe(true); expect(screen.queryByRole('dialog')).not.toBeInTheDocument(); await finish(); expect(changed).not.toHaveBeenCalled(); expect(screen.queryByDisplayValue(secret)).not.toBeInTheDocument();
 });
 it('rejects a create response whose request clock regressed before the next tick', async () => {
  const clock = vi.spyOn(performance, 'now').mockReturnValue(1000); const finish = pendingCreation(); const dialog = await add(); acknowledgeAndCreate(dialog);
  clock.mockReturnValue(0); await finish(); expect(screen.queryByDisplayValue(secret)).not.toBeInTheDocument(); expect(screen.queryByRole('button', { name: 'Download bootstrap file' })).not.toBeInTheDocument(); expect(changed).not.toHaveBeenCalled();
 });
 it('clears consent and rejects late material when the authenticated session ends', async () => {
  vi.mocked(request).mockImplementation(async path => path === '/auth/session' ? session : structuredClone(current)); const finish = pendingCreation();
  render(<AuthBoundary>{section()}</AuthBoundary>); const dialog = await open(); acknowledgeAndCreate(dialog); const signal = vi.mocked(mutate).mock.calls[0][2]!;
  act(() => window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT))); await screen.findByLabelText('Operator password'); expect(signal.aborted).toBe(true); await finish(); expect(screen.queryByRole('dialog')).not.toBeInTheDocument(); expect(screen.queryByDisplayValue(secret)).not.toBeInTheDocument(); expect(changed).not.toHaveBeenCalled();
 });
 it('starts with fresh unchecked consent after authenticated-session replacement on BFCache restore', async () => {
  let activeSession = session;
  vi.mocked(request).mockImplementation(async path => path === '/auth/session' ? activeSession : structuredClone(current));
  render(<AuthBoundary>{section()}</AuthBoundary>); const dialog = await open(); fireEvent.click(within(dialog).getByRole('checkbox'));
  act(() => window.dispatchEvent(new Event('pagehide'))); activeSession = { ...session, csrfToken: 'synthetic-replacement-session' };
  const restored = new Event('pageshow'); Object.defineProperty(restored, 'persisted', { value: true }); act(() => window.dispatchEvent(restored));
  await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument()); const replacement = await open(); expect(within(replacement).getByRole('checkbox')).not.toBeChecked(); expect(within(replacement).getByRole('button', { name: 'Create invitation' })).toBeDisabled(); expect(mutate).not.toHaveBeenCalled();
 });
});

describe('revocation-only wall clock discontinuity detection', () => {
 it.each([3600000, -3600000])('requires new consent after a %s ms wall/monotonic discontinuity', async jump => {
  vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] }); vi.spyOn(performance, 'now').mockReturnValue(1000);
  const wall = vi.spyOn(Date, 'now').mockReturnValue(100000); const dialog = await add(); fireEvent.click(within(dialog).getByRole('checkbox'));
  wall.mockReturnValue(100000 + jump); act(() => vi.advanceTimersByTime(1000));
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument(); expect(screen.getByRole('button', { name: 'Add device' })).toBeDisabled(); expect(mutate).not.toHaveBeenCalled();
  await refresh(); const replacement = await open(); expect(within(replacement).getByRole('checkbox')).not.toBeChecked(); expect(within(replacement).getByRole('button', { name: 'Create invitation' })).toBeDisabled();
 });
 it.each([3600000, -3600000])('removes a displayed secret after a %s ms discontinuity without a lifecycle event', async jump => {
  vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] }); vi.spyOn(performance, 'now').mockReturnValue(1000);
  const wall = vi.spyOn(Date, 'now').mockReturnValue(100000); vi.mocked(mutate).mockResolvedValue(creation()); const dialog = await add(); acknowledgeAndCreate(dialog); await screen.findByLabelText('One-time invitation secret');
  wall.mockReturnValue(100000 + jump); act(() => vi.advanceTimersByTime(1000));
  expect(screen.queryByDisplayValue(secret)).not.toBeInTheDocument(); expect(screen.queryByRole('button', { name: 'Download bootstrap file' })).not.toBeInTheDocument(); expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
 });
 it.each([3600000, -3600000])('rejects a pending create response after a %s ms discontinuity before the next tick', async jump => {
  vi.spyOn(performance, 'now').mockReturnValue(1000); const wall = vi.spyOn(Date, 'now').mockReturnValue(100000);
  const finish = pendingCreation(); const dialog = await add(); acknowledgeAndCreate(dialog); const signal = vi.mocked(mutate).mock.calls[0][2]!;
  wall.mockReturnValue(100000 + jump); await finish();
  expect(signal.aborted).toBe(true); expect(screen.queryByRole('dialog')).not.toBeInTheDocument(); expect(screen.queryByDisplayValue(secret)).not.toBeInTheDocument(); expect(screen.queryByRole('button', { name: 'Download bootstrap file' })).not.toBeInTheDocument(); expect(changed).not.toHaveBeenCalled();
 });
 it('does not preserve old consent by refreshing after a discontinuity before the next tick', async () => {
  vi.spyOn(performance, 'now').mockReturnValue(1000); const wall = vi.spyOn(Date, 'now').mockReturnValue(100000);
  const dialog = await add(); fireEvent.click(within(dialog).getByRole('checkbox')); wall.mockReturnValue(104000); await refresh();
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument(); const replacement = await open(); expect(within(replacement).getByRole('checkbox')).not.toBeChecked(); expect(mutate).not.toHaveBeenCalled();
 });
 it('rejects an in-flight list whose wall clock changed while monotonic time paused', async () => {
  vi.spyOn(performance, 'now').mockReturnValue(1000); const wall = vi.spyOn(Date, 'now').mockReturnValue(100000);
  let finish!: (value: EnrollmentList) => void;
  vi.mocked(request).mockImplementationOnce(() => new Promise<EnrollmentList>(resolve => { finish = resolve; })); render(section());
  wall.mockReturnValue(104000); await act(async () => finish(listing()));
  expect(screen.getByRole('button', { name: 'Add device' })).toBeDisabled(); expect(screen.getByRole('alert')).toHaveTextContent('Enrollment status is unavailable. No fallback data is shown.'); expect(mutate).not.toHaveBeenCalled();
 });
 it('never grants time from the wall clock and allows only the bounded jitter tolerance', async () => {
  vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] }); vi.spyOn(performance, 'now').mockReturnValue(1000);
  const wall = vi.spyOn(Date, 'now').mockReturnValue(0); const dialog = await add(); fireEvent.click(within(dialog).getByRole('checkbox'));
  wall.mockReturnValue(1500); act(() => vi.advanceTimersByTime(1000)); expect(within(dialog).getByRole('button', { name: 'Create invitation' })).toBeEnabled();
  wall.mockReturnValue(1501); act(() => vi.advanceTimersByTime(1000)); expect(screen.queryByRole('dialog')).not.toBeInTheDocument(); expect(mutate).not.toHaveBeenCalled();
 });
});


describe('authoritative server-clock regression', () => {
 const earlier = '2026-10-03T14:59:59Z';
 it('closes acknowledged consent before accepting an earlier read anchor and requires fresh acknowledgement', async () => {
  const dialog = await add(); fireEvent.click(within(dialog).getByRole('checkbox'));
  current = { ...current, serverNow: earlier }; await refresh();
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument(); const replacement = await open();
  expect(within(replacement).getByRole('checkbox')).not.toBeChecked(); expect(within(replacement).getByRole('button', { name: 'Create invitation' })).toBeDisabled(); expect(mutate).not.toHaveBeenCalled();
 });
 it('clears an existing secret when a refresh supplies an earlier authoritative server timestamp', async () => {
  vi.mocked(mutate).mockResolvedValue(creation()); const dialog = await add(); acknowledgeAndCreate(dialog); await screen.findByLabelText('One-time invitation secret');
  current = { ...current, serverNow: earlier }; await refresh();
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument(); expect(screen.queryByDisplayValue(secret)).not.toBeInTheDocument(); expect(screen.queryByRole('button', { name: 'Download bootstrap file' })).not.toBeInTheDocument();
  const replacement = await open(); expect(within(replacement).getByRole('checkbox')).not.toBeChecked();
 });
 it('aborts a pending create during a backwards read and rejects its later material', async () => {
  const finish = pendingCreation(); const dialog = await add(); acknowledgeAndCreate(dialog); const signal = vi.mocked(mutate).mock.calls[0][2]!;
  current = { ...current, serverNow: earlier }; await refresh(); expect(signal.aborted).toBe(true); await finish();
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument(); expect(screen.queryByDisplayValue(secret)).not.toBeInTheDocument(); expect(changed).not.toHaveBeenCalled();
  const replacement = await open(); expect(within(replacement).getByRole('checkbox')).not.toBeChecked();
 });
 it('rejects backwards create-response time without exposing material or reinstating it through readback', async () => {
  const response = creation(); response.serverNow = earlier; vi.mocked(mutate).mockResolvedValue(response); const dialog = await add(); acknowledgeAndCreate(dialog);
  await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  expect(vi.mocked(mutate).mock.calls[0][2]!.aborted).toBe(true); expect(screen.queryByDisplayValue(secret)).not.toBeInTheDocument(); expect(screen.queryByRole('button', { name: 'Download bootstrap file' })).not.toBeInTheDocument(); expect(changed).not.toHaveBeenCalled();
  current = { ...current, serverNow: earlier, items: [response.snapshot] }; await refresh();
  expect(screen.queryByDisplayValue(secret)).not.toBeInTheDocument(); const replacement = await open(); expect(within(replacement).getByRole('checkbox')).not.toBeChecked(); expect(mutate).toHaveBeenCalledTimes(1);
 });
 it('allows equal authoritative timestamps despite monotonic request latency', async () => {
  vi.spyOn(performance, 'now').mockReturnValue(1000); const wall = vi.spyOn(Date, 'now').mockReturnValue(100000);
  const dialog = await add(); fireEvent.click(within(dialog).getByRole('checkbox'));
  vi.mocked(performance.now).mockReturnValue(2000); wall.mockReturnValue(101000); await refresh();
  expect(within(dialog).getByRole('checkbox')).toBeChecked(); expect(within(dialog).getByRole('button', { name: 'Create invitation' })).toBeEnabled();
 });
});


describe('fresh complete dpkg consent', () => {
 it('requires the separate managed-v3 acknowledgement and preserves its bootstrap binding', async () => {
  current = listing(v3); vi.mocked(mutate).mockResolvedValue({ ...creation(v3), bootstrapSHA256: 'b'.repeat(64) }); const dialog = await add();
  for (const text of ['Complete package, service and connection inventory', 'all supported installed and incomplete dpkg rows', 'Snap, Flatpak', 'up to 24 hours', 'fresh managed-operations-v3 store', 'private network topology', 'does not prove external reachability', 'No network scan, DNS lookup or UID collection']) expect(dialog.textContent).toContain(text);
  expect(within(dialog).getByRole('checkbox')).not.toBeChecked(); expect(within(dialog).getByRole('button', { name: 'Create invitation' })).toBeDisabled(); acknowledgeAndCreate(dialog); await screen.findByLabelText('One-time invitation secret');
  expect(mutate).toHaveBeenCalledExactlyOnceWith('/enrollment/invitations', { requestId: expect.any(String), platform: 'linux', collectionAcknowledged: true }, expect.any(AbortSignal));
 });
 it('cannot inherit managed-v2 consent after switching to managed-v3', async () => {
  current = listing(v2); let dialog = await add(); fireEvent.click(within(dialog).getByRole('checkbox')); current = listing(v3); await refresh(); expect(screen.queryByRole('dialog')).not.toBeInTheDocument(); dialog = await open(); expect(within(dialog).getByRole('checkbox')).not.toBeChecked(); expect(within(dialog).getByRole('button', { name: 'Create invitation' })).toBeDisabled();
 });
 it('fails closed if a present bootstrap SHA256 is invalid while older omitted-checksum responses stay compatible', async () => {
  current = listing(v3); vi.mocked(mutate).mockResolvedValue({ ...creation(v3), bootstrapSHA256: 'invalid' }); const dialog = await add(); acknowledgeAndCreate(dialog); await within(dialog).findByRole('alert'); expect(screen.queryByLabelText('One-time invitation secret')).not.toBeInTheDocument();
 });
 it('renders separate complete-dpkg consent in German', async () => {
  current = listing(v3); setLocale('de', false); render(section()); await waitFor(() => expect(screen.getByRole('button', { name: 'Gerät hinzufügen' })).toBeEnabled()); fireEvent.click(screen.getByRole('button', { name: 'Gerät hinzufügen' })); const dialog = screen.getByRole('dialog', { name: 'Gerät hinzufügen' }); expect(dialog.textContent).toContain('Vollständiges Paket-, Dienst- und Verbindungsinventar'); expect(within(dialog).getByRole('checkbox', { name: 'Ich bestätige die Erfassung von Betriebsmetadaten, allen unterstützten dpkg-Paketen, Systemdiensten und lokalen Verbindungsmetadaten für dieses neue Gerät.' })).not.toBeChecked();
 });
});


describe('public prepared-checkout command', () => {
 it('serializes only the fixed root/local-artifact command and validated public TLS fields', () => {
  const response = creation(v3), checksum = 'b'.repeat(64);
  const expected = '"$PWD/bin/agent-service" --action install --apply --pending-service' +
   ' --agent-binary "$PWD/bin/lan-agent" --agent-sha256 "$(sha256sum < "$PWD/bin/lan-agent" | cut -d \' \' -f 1)"' +
   ' --enroll-binary "$PWD/bin/enroll-agent" --enroll-sha256 "$(sha256sum < "$PWD/bin/enroll-agent" | cut -d \' \' -f 1)"' +
   ' --source-archive "$PWD/tracebolt-selected-source.tar" --source-sha256 "$(sha256sum < "$PWD/tracebolt-selected-source.tar" | cut -d \' \' -f 1)"' +
   ` --manager-origin '${window.location.origin}' --invitation-id '${invitation}' --bootstrap-sha256 '${checksum}' --server-ca-base64 '${btoa(certificate)}'`;
  const command = preparedEnrollmentCommand(response.bootstrap, response.snapshot, checksum);
  expect(command).toBe(expected); expect(command).not.toContain(secret); expect(command).not.toMatch(/sudo|curl|wget|invitation-secret/);
 });
 it('never derives or accepts a missing, uppercase, malformed or shell-bearing digest', () => {
  const response = creation();
  for (const checksum of [undefined, null, '', 'B'.repeat(64), 'a'.repeat(63), "'; touch /tmp/untrusted; '", 1]) expect(preparedEnrollmentCommand(response.bootstrap, response.snapshot, checksum)).toBeNull();
 });
 it('rejects untrusted origin, invitation identity, certificate and additional bootstrap fields before serialization', () => {
  const response = creation();
  for (const bootstrap of [{ ...response.bootstrap, enrollmentOrigin: 'https://other.example' }, { ...response.bootstrap, enrollmentOrigin: "https://localhost';touch /tmp/untrusted;#" }, { ...response.bootstrap, invitationId: "invite_';touch /tmp/untrusted;#" }, { ...response.bootstrap, serverCaPem: '$(touch /tmp/untrusted)' }, { ...response.bootstrap, invitationSecret: secret }]) expect(preparedEnrollmentCommand(bootstrap, response.snapshot, 'b'.repeat(64))).toBeNull();
  expect(preparedEnrollmentCommand(response.bootstrap, { ...response.snapshot, state: 'revoked' }, 'b'.repeat(64))).toBeNull();
 });
 it('keeps explicit HTTP-test transport separate and omits CA flags', () => {
  const response = creation(); const origin = 'http://manager.test:8080'; response.snapshot.binding.profile = 'http-test'; response.snapshot.binding.origin = origin; response.bootstrap.profile = 'http-test'; response.bootstrap.enrollmentOrigin = origin; response.bootstrap.agentOrigin = 'http://manager.test:8081'; response.bootstrap.serverCaPem = '';
  vi.stubGlobal('window', { location: { origin } });
  try { const command = preparedEnrollmentCommand(response.bootstrap, response.snapshot, 'b'.repeat(64)); expect(command).toContain("--manager-origin 'http://manager.test:8080'"); expect(command).toMatch(/ --insecure-http-test$/); expect(command).not.toContain('--server-ca-base64'); } finally { vi.unstubAllGlobals(); }
 });
 it('copies the public command only on an explicit click, separately from the hidden invitation', async () => {
  const clipboard = vi.fn().mockResolvedValue(undefined); Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: clipboard } });
  current = listing(v3); vi.mocked(mutate).mockResolvedValue({ ...creation(v3), bootstrapSHA256: 'b'.repeat(64) }); const dialog = await add(); acknowledgeAndCreate(dialog); await screen.findByLabelText('One-time invitation secret');
  expect(clipboard).not.toHaveBeenCalled(); expect(within(dialog).getByText('Run as root from the prepared local checkout')).toBeVisible(); expect(dialog.textContent).toContain('do not verify the publisher'); expect(dialog.textContent).toContain('No inventory is collected before approval and activation.');
  fireEvent.click(within(dialog).getByRole('button', { name: 'Copy public installation command' })); await waitFor(() => expect(clipboard).toHaveBeenCalledTimes(1)); expect(clipboard.mock.calls[0][0]).toBe(preparedEnrollmentCommand(creation(v3).bootstrap, creation(v3).snapshot, 'b'.repeat(64))); expect(clipboard.mock.calls[0][0]).not.toContain(secret); expect(screen.getByLabelText('One-time invitation secret')).toHaveAttribute('type', 'password');
 });
 it('keeps older responses usable without presenting an invented online command', async () => {
  vi.mocked(mutate).mockResolvedValue(creation()); const dialog = await add(); acknowledgeAndCreate(dialog); await screen.findByLabelText('One-time invitation secret'); expect(within(dialog).queryByRole('button', { name: 'Copy public installation command' })).not.toBeInTheDocument(); expect(within(dialog).getByRole('button', { name: 'Download bootstrap file' })).toBeVisible();
 });
});
