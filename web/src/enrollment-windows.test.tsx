import type {} from 'vitest/jsdom';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { EnrollmentSection } from './enrollment';
import { mutate, request } from './api';
import { preparedEnrollmentCommand, publicEnrollmentArguments } from './enrollment-command';
import { OFFICIAL_LINUX_BOOTSTRAP_PIN, selectEnrollmentCommand, verifiedDownloadCommand } from './verified-download-command';
import { publicBootstrap, validEnrollmentList } from './enrollment-types';
import type { EnrollmentList, EnrollmentSnapshot, EnrollmentState, InvitationCreation } from './enrollment-types';
import { setLocale } from './i18n';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutate: vi.fn() }));
const operator = vi.hoisted(() => ({ insecureTestMode: false }));
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: () => operator }));
const serverNow = '2026-10-07T15:00:00Z', seconds = Date.parse(serverNow) / 1000;
const invitation = `invite_${'1'.repeat(32)}`, secret = 'W'.repeat(43), fingerprint = 'ab'.repeat(32);
const certificate = '-----BEGIN CERTIFICATE-----\nQUJDRA==\n-----END CERTIFICATE-----';
const collectionConsent = 'I acknowledge this Windows inventory collection for the new device.';
const httpConsent = 'I explicitly accept unencrypted HTTP-test enrollment and Windows inventory transmission.';
function record(state: EnrollmentState = 'created', revision = 1): EnrollmentSnapshot {
 return {
  version: 'tracebolt.enrollment-state.v2', binding: { instanceID: `manager_${'2'.repeat(32)}`, origin: window.location.origin, profile: operator.insecureTestMode ? 'http-test' : 'tls', collectionProfile: 'windows-inventory-v1', issuerFingerprint: 'a'.repeat(64) },
  invitationID: invitation, createRequestID: `request_${'3'.repeat(32)}`, platform: 'windows', revision, state, createdAt: seconds, deadlineAt: seconds + 600, updatedAt: seconds,
  claim: { claimID: `claim_${'4'.repeat(32)}`, requestID: '', keyFingerprint: fingerprint, csrHash: '', claimHash: '', comparisonCode: '12ab'.repeat(8), at: seconds },
  approval: { requestID: '', deviceID: ['created', 'claimed_pending'].includes(state) ? '' : `agent_${'6'.repeat(32)}`, keyFingerprint: fingerprint, at: seconds },
  intent: { intentID: '', requestID: '', serialHex: '', templateVersion: '', deviceID: '', keyFingerprint: '', notBefore: 0, notAfter: 0, at: 0 }, issuance: { requestID: '', certificateHash: '', at: 0 }, activation: { requestID: '', at: 0 }, termination: { requestID: '', from: '', at: 0 },
 };
}
function listing(items: EnrollmentSnapshot[] = []): EnrollmentList {
 return { schemaVersion: 'tracebolt.enrollment-operator.v2', serverNow, enabled: true, platforms: ['windows'], recordLimit: 25, collectionProfile: 'windows-inventory-v1', collectionPrivacy: 'windows_inventory_metadata_may_be_sensitive', items };
}
function linuxListing(): EnrollmentList {
 return { schemaVersion: 'tracebolt.enrollment-operator.v2', serverNow, enabled: true, platforms: ['linux'], recordLimit: 25, items: [] };
}
function creation(): InvitationCreation {
 const snapshot = record();
 return { schemaVersion: 'tracebolt.enrollment-invitation.v2', serverNow, snapshot, invitationSecret: secret, bootstrapSHA256: 'b'.repeat(64), bootstrap: { schemaVersion: 'tracebolt.enrollment-bootstrap.v2', managerInstanceId: snapshot.binding.instanceID, profile: snapshot.binding.profile, enrollmentOrigin: window.location.origin, agentOrigin: operator.insecureTestMode ? 'http://localhost:8081' : 'https://localhost:9443', collectionProfile: snapshot.binding.collectionProfile, invitationId: invitation, serverCaPem: operator.insecureTestMode ? '' : certificate, issuerRootPem: certificate, issuerPem: certificate } };
}
let current: EnrollmentList;
const changed = vi.fn();
function section() { return <EnrollmentSection onChanged={changed} onDevice={() => {}} deviceIds={[]}/>; }
function select(platform: 'windows' | 'linux') { fireEvent.change(screen.getByRole('combobox'), { target: { value: platform } }); }
async function windows() {
 render(section());
 await waitFor(() => expect(screen.getByRole('button', { name: 'Add device' })).toBeEnabled());
 select('windows');
 await screen.findByText('Windows · Single invitation · Manual approval');
}
async function add() {
 await windows();
 fireEvent.click(screen.getByRole('button', { name: 'Add device' }));
 return screen.getByRole('dialog', { name: 'Add device' });
}
function acknowledge(dialog: HTMLElement) { fireEvent.click(within(dialog).getByRole('checkbox', { name: collectionConsent })); }
async function create() {
 vi.mocked(mutate).mockResolvedValue(creation()); const dialog = await add(); acknowledge(dialog);
 fireEvent.click(within(dialog).getByRole('button', { name: 'Create invitation' }));
 await within(dialog).findByLabelText('One-time invitation secret'); return dialog;
}
async function review(item: EnrollmentSnapshot) {
 current = listing([item]); await windows();
 fireEvent.click(screen.getByRole('button', { name: /Invitations/ }));
 fireEvent.click(screen.getByRole('button', { name: `Review invitation ${invitation}` }));
 return screen.getByRole('dialog', { name: 'Review invitation' });
}
beforeEach(() => {
 jsdom.reconfigure({ url: 'https://localhost/' }); setLocale('en', false); operator.insecureTestMode = false;
 current = listing(); changed.mockReset(); localStorage.clear(); sessionStorage.clear();
 vi.mocked(request).mockReset().mockImplementation(async path => structuredClone(path === '/windows/enrollment' ? current : linuxListing()));
 vi.mocked(mutate).mockReset();
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals(); vi.useRealTimers(); jsdom.reconfigure({ url: 'https://localhost/' }); });

describe('Windows enrollment contract and creation consent', () => {
 it('does not fetch Windows until selected, and keeps Linux as the initial platform', async () => {
  render(section()); await waitFor(() => expect(screen.getByRole('button', { name: 'Add device' })).toBeEnabled());
  expect(screen.getByRole('combobox', { name: 'Operating system' })).toHaveValue('linux');
  expect(request).toHaveBeenCalledExactlyOnceWith('/enrollment', { signal: expect.any(AbortSignal) });
  select('windows'); await screen.findByText('Windows · Single invitation · Manual approval');
  expect(request).toHaveBeenLastCalledWith('/windows/enrollment', { signal: expect.any(AbortSignal) });
 });
 it('rejects mismatched profiles, privacy, platform rows and bounds before opening a Windows dialog', async () => {
  expect(validEnrollmentList(current, 'windows')).toBe(true);
  for (const value of [linuxListing(), { ...current, collectionPrivacy: undefined }, { ...current, collectionPrivacy: 'metadata_labels_may_be_sensitive' }, { ...current, platforms: ['linux', 'windows'] }, { ...current, platforms: [] }, { ...current, recordLimit: 26 }, { ...current, items: [{ ...record(), platform: 'linux' }] }, { ...current, items: [{ ...record(), binding: { ...record().binding, collectionProfile: 'basic-readonly-v1' } }] }]) {
   expect(validEnrollmentList(value, 'windows')).toBe(false);
  }
  expect(validEnrollmentList(current, 'linux')).toBe(false);
  current = linuxListing(); render(section()); await waitFor(() => expect(screen.getByRole('button', { name: 'Add device' })).toBeEnabled());
  select('windows'); await screen.findByRole('alert');
  expect(screen.getByRole('button', { name: 'Add device' })).toBeDisabled(); expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
 });
 it('discloses bounded sensitive Windows metadata and posts the exact TLS request only after consent', async () => {
  vi.mocked(mutate).mockResolvedValue(creation()); const dialog = await add();
  expect(within(dialog).getByText(/Hostname, interface IP addresses, process names and IDs/)).toHaveTextContent('personal or sensitive');
  expect(within(dialog).getByText(/at most 1 hostname, 128 process rows, 128 service rows, 128 software rows and 64 interface-address rows/)).toHaveTextContent('Partial results and lower-bound counts');
  expect(within(dialog).getByRole('checkbox', { name: collectionConsent })).not.toBeChecked();
  expect(within(dialog).queryByRole('checkbox', { name: httpConsent })).not.toBeInTheDocument();
  const button = within(dialog).getByRole('button', { name: 'Create invitation' });
  expect(button).toBeDisabled(); fireEvent.click(button); expect(mutate).not.toHaveBeenCalled();
  acknowledge(dialog); fireEvent.click(button); await within(dialog).findByLabelText('One-time invitation secret');
  expect(mutate).toHaveBeenCalledExactlyOnceWith('/windows/enrollment/invitations', { requestId: expect.stringMatching(/^request_[a-f0-9]{32}$/), platform: 'windows', collectionAcknowledged: true, insecureHTTPAcknowledged: false }, expect.any(AbortSignal));
  expect(within(dialog).getByText('Prepare the reviewed Windows source build')).toBeVisible();
  expect(within(dialog).getByText(/No released Windows installer or download command is available/)).toBeVisible();
  expect(within(dialog).queryByRole('button', { name: 'Copy public installation command' })).not.toBeInTheDocument();
  expect(dialog.textContent).not.toMatch(/rc\.3|Run as root|sha256sum|curl|agent-service/);
  expect(JSON.stringify({ ...localStorage, ...sessionStorage })).not.toContain(secret);
 });
 it('requires a second unchecked HTTP-test acknowledgement and sends true only after both approvals', async () => {
  operator.insecureTestMode = true; jsdom.reconfigure({ url: 'http://localhost:8080/' });
  vi.mocked(mutate).mockResolvedValue(creation()); const dialog = await add();
  const consent = within(dialog).getByRole('checkbox', { name: httpConsent }), button = within(dialog).getByRole('button', { name: 'Create invitation' });
  expect(consent).not.toBeChecked(); expect(button).toBeDisabled();
  expect(within(dialog).getByText(/HTTP test: the invitation and approved hostname/)).toHaveTextContent('without encryption');
  acknowledge(dialog); expect(button).toBeDisabled(); fireEvent.click(button); expect(mutate).not.toHaveBeenCalled();
  fireEvent.click(consent); expect(button).toBeEnabled(); fireEvent.click(button);
  await within(dialog).findByLabelText('One-time invitation secret');
  expect(mutate).toHaveBeenCalledExactlyOnceWith('/windows/enrollment/invitations', { requestId: expect.any(String), platform: 'windows', collectionAcknowledged: true, insecureHTTPAcknowledged: true }, expect.any(AbortSignal));
 });
 it.each(['profile', 'platform', 'transport'] as const)('withholds instructions and secret when the creation response changes %s', async field => {
  const response = creation();
  if (field === 'profile') { response.snapshot.binding.collectionProfile = 'basic-readonly-v1'; response.bootstrap.collectionProfile = 'basic-readonly-v1'; }
  if (field === 'platform') response.snapshot.platform = 'linux';
  if (field === 'transport') { response.snapshot.binding.profile = 'http-test'; response.bootstrap.profile = 'http-test'; }
  vi.mocked(mutate).mockResolvedValue(response); const dialog = await add(); acknowledge(dialog);
  fireEvent.click(within(dialog).getByRole('button', { name: 'Create invitation' })); await within(dialog).findByRole('alert');
  expect(within(dialog).queryByLabelText('One-time invitation secret')).not.toBeInTheDocument();
  expect(within(dialog).queryByText('Prepare the reviewed Windows source build')).not.toBeInTheDocument();
  expect(within(dialog).queryByRole('button', { name: 'Download bootstrap file' })).not.toBeInTheDocument();
  expect(document.body.textContent).not.toContain(secret);
 });
 it('exports only the exact public bootstrap after a deliberate download', async () => {
  const dialog = await create(); let blob: Blob | undefined;
  vi.stubGlobal('URL', Object.assign(URL, { createObjectURL: vi.fn((value: Blob) => { blob = value; return 'blob:windows-public'; }), revokeObjectURL: vi.fn() }));
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
  fireEvent.click(within(dialog).getByRole('button', { name: 'Download bootstrap file' }));
  const text = await new Promise<string>((resolve, reject) => { const reader = new FileReader(); reader.onload = () => resolve(String(reader.result)); reader.onerror = reject; reader.readAsText(blob!); });
  expect(JSON.parse(text)).toEqual(creation().bootstrap); expect(Object.keys(JSON.parse(text))).toHaveLength(10); expect(text).not.toContain(secret);
  const response = creation(); expect(publicBootstrap({ ...response.bootstrap, invitationSecret: secret }, response.snapshot, secret)).toBeNull();
 });
 it('shows German scope and HTTP consent while keeping both gates unchecked', async () => {
  setLocale('de', false); operator.insecureTestMode = true;
  render(section()); await waitFor(() => expect(screen.getByRole('button', { name: 'Gerät hinzufügen' })).toBeEnabled());
  select('windows'); await screen.findByText('Windows · Einzelne Einladung · Manuelle Freigabe');
  fireEvent.click(screen.getByRole('button', { name: 'Gerät hinzufügen' })); const dialog = screen.getByRole('dialog');
  expect(within(dialog).getByText('Begrenztes Windows-Inventar')).toBeVisible();
  expect(within(dialog).getByText(/128 Prozesszeilen/)).toHaveTextContent('Untergrenze');
  expect(within(dialog).getAllByRole('checkbox')).toHaveLength(2);
  for (const checkbox of within(dialog).getAllByRole('checkbox')) expect(checkbox).not.toBeChecked();
  expect(within(dialog).getByRole('button', { name: 'Einladung erstellen' })).toBeDisabled();
 });
});

describe('Windows lifecycle and platform cancellation', () => {
 it('aborts a pending Windows GET and ignores its response after switching to Linux', async () => {
  let finish!: (value: EnrollmentList) => void, signal: AbortSignal | undefined;
  vi.mocked(request).mockImplementation(async (path, init) => path === '/windows/enrollment' ? new Promise<EnrollmentList>(resolve => { finish = resolve; signal = init?.signal as AbortSignal; }) : linuxListing());
  render(section()); await waitFor(() => expect(screen.getByRole('button', { name: 'Add device' })).toBeEnabled());
  select('windows'); expect(signal).toBeDefined(); select('linux'); expect(signal!.aborted).toBe(true);
  await act(async () => finish(listing([record()])));
  expect(screen.getByRole('combobox')).toHaveValue('linux'); expect(screen.queryByText(invitation)).not.toBeInTheDocument();
  expect(request).toHaveBeenCalledTimes(3);
 });
 it('aborts in-flight creation synchronously and never restores a delayed secret across selection', async () => {
  let finish!: (value: InvitationCreation) => void, signal: AbortSignal | undefined;
  vi.mocked(mutate).mockImplementation(async (_path, _body, pendingSignal) => new Promise<InvitationCreation>(resolve => { finish = resolve; signal = pendingSignal; }));
  const dialog = await add(); acknowledge(dialog); fireEvent.click(within(dialog).getByRole('button', { name: 'Create invitation' }));
  expect(signal).toBeDefined(); select('linux'); expect(signal!.aborted).toBe(true);
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument(); await act(async () => finish(creation()));
  expect(screen.queryByDisplayValue(secret)).not.toBeInTheDocument(); expect(changed).not.toHaveBeenCalled();
  select('windows'); await screen.findByText('Windows · Single invitation · Manual approval');
  fireEvent.click(screen.getByRole('button', { name: 'Add device' })); expect(screen.getByRole('checkbox', { name: collectionConsent })).not.toBeChecked();
 });
 it('clears a revealed secret on switch and requires new consent after reopening', async () => {
  const dialog = await create(); fireEvent.click(within(dialog).getByRole('button', { name: 'Reveal invitation secret' }));
  const input = screen.getByLabelText('One-time invitation secret'); expect(input).toHaveAttribute('type', 'text');
  select('linux'); expect(input).toHaveValue(''); expect(screen.queryByRole('dialog')).not.toBeInTheDocument(); expect(screen.queryByDisplayValue(secret)).not.toBeInTheDocument();
  select('windows'); await screen.findByText('Windows · Single invitation · Manual approval');
  fireEvent.click(screen.getByRole('button', { name: 'Add device' })); expect(screen.getByRole('checkbox', { name: collectionConsent })).not.toBeChecked();
 });
 it('removes a displayed secret when refreshed Windows consent metadata no longer matches', async () => {
  const dialog = await create(); const input = within(dialog).getByLabelText('One-time invitation secret');
  current = { ...current, collectionPrivacy: undefined };
  fireEvent.click(within(dialog).getByRole('button', { name: 'Check status' }));
  await screen.findByRole('alert'); expect(input).toHaveValue('');
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument(); expect(screen.queryByDisplayValue(secret)).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Add device' })).toBeDisabled();
 });
 it('clears both HTTP consent choices on pagehide and close', async () => {
  operator.insecureTestMode = true; const dialog = await add(); acknowledge(dialog); fireEvent.click(within(dialog).getByRole('checkbox', { name: httpConsent }));
  act(() => window.dispatchEvent(new Event('pagehide')));
  for (const checkbox of within(dialog).getAllByRole('checkbox')) expect(checkbox).not.toBeChecked();
  expect(within(dialog).getByRole('button', { name: 'Create invitation' })).toBeDisabled();
  fireEvent.keyDown(document, { key: 'Escape' }); expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  act(() => window.dispatchEvent(new Event('pageshow'))); await waitFor(() => expect(screen.getByRole('button', { name: 'Add device' })).toBeEnabled());
  fireEvent.click(screen.getByRole('button', { name: 'Add device' })); for (const checkbox of screen.getAllByRole('checkbox')) expect(checkbox).not.toBeChecked();
 });
 it('requires deliberate public-key comparison and uses the Windows approval suffix', async () => {
  vi.mocked(mutate).mockResolvedValue(record('approved', 3)); const dialog = await review(record('claimed_pending', 2));
  const button = within(dialog).getByRole('button', { name: 'Approve device' }); expect(button).toBeDisabled();
  fireEvent.click(within(dialog).getByRole('checkbox')); fireEvent.click(button); await within(dialog).findByText('Key approved');
  expect(mutate).toHaveBeenCalledExactlyOnceWith(`/windows/enrollment/${invitation}/approve`, { requestId: expect.any(String), expectedRevision: 2, expectedKeyFingerprint: fingerprint }, expect.any(AbortSignal));
 });
 it('aborts a pending comparison approval when switching platforms', async () => {
  let finish!: (value: EnrollmentSnapshot) => void, signal: AbortSignal | undefined;
  vi.mocked(mutate).mockImplementation(async (_path, _body, pendingSignal) => new Promise<EnrollmentSnapshot>(resolve => { finish = resolve; signal = pendingSignal; }));
  const dialog = await review(record('claimed_pending', 2)); fireEvent.click(within(dialog).getByRole('checkbox')); fireEvent.click(within(dialog).getByRole('button', { name: 'Approve device' }));
  select('linux'); expect(signal!.aborted).toBe(true); await act(async () => finish(record('approved', 3)));
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument(); expect(changed).not.toHaveBeenCalled();
 });
 it('keeps confirmation before canceling and uses the Windows termination suffix', async () => {
  vi.mocked(mutate).mockResolvedValue(record('canceled', 2)); const dialog = await review(record());
  fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel invitation' })); expect(mutate).not.toHaveBeenCalled();
  fireEvent.click(within(dialog).getByRole('button', { name: 'Confirm termination' })); await within(dialog).findByText('Canceled');
  expect(mutate).toHaveBeenCalledExactlyOnceWith(`/windows/enrollment/${invitation}/terminate`, { requestId: expect.any(String), expectedRevision: 1, action: 'canceled' }, expect.any(AbortSignal));
 });
});

describe('Linux installation command boundary', () => {
 it.each(['windows', 'darwin', 'Linux', ''])("rejects platform '%s' in every Linux serializer", platform => {
  const response = creation(); response.snapshot.platform = platform;
  response.snapshot.binding.collectionProfile = 'basic-readonly-v1'; response.bootstrap.collectionProfile = 'basic-readonly-v1';
  expect(publicEnrollmentArguments(response.bootstrap, response.snapshot, response.bootstrapSHA256)).toBeNull();
  expect(preparedEnrollmentCommand(response.bootstrap, response.snapshot, response.bootstrapSHA256)).toBeNull();
  expect(verifiedDownloadCommand(OFFICIAL_LINUX_BOOTSTRAP_PIN, response.bootstrap, response.snapshot, response.bootstrapSHA256)).toBeNull();
  expect(selectEnrollmentCommand(response.bootstrap, response.snapshot, response.bootstrapSHA256)).toBeNull();
 });
 it('rejects the Windows inventory profile even when its snapshot claims Linux', () => {
  const response = creation(); response.snapshot.platform = 'linux';
  expect(publicEnrollmentArguments(response.bootstrap, response.snapshot, response.bootstrapSHA256)).toBeNull();
  expect(preparedEnrollmentCommand(response.bootstrap, response.snapshot, response.bootstrapSHA256)).toBeNull();
  expect(verifiedDownloadCommand(OFFICIAL_LINUX_BOOTSTRAP_PIN, response.bootstrap, response.snapshot, response.bootstrapSHA256)).toBeNull();
  expect(selectEnrollmentCommand(response.bootstrap, response.snapshot, response.bootstrapSHA256)).toBeNull();
 });
});
