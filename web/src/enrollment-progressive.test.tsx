import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { EnrollmentSection } from './enrollment';
import { preparedEnrollmentCommand } from './enrollment-command';
import * as downloadCommands from './verified-download-command';
import { mutate, request } from './api';
import { groupedHex } from './enrollment-types';
import type { EnrollmentList, EnrollmentSnapshot, EnrollmentState, InvitationCreation } from './enrollment-types';
import { setLocale } from './i18n';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutate: vi.fn() }));
const operator = vi.hoisted(() => ({ insecureTestMode: false }));
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: () => operator }));
const serverNow = '2026-10-03T15:00:00Z', seconds = Date.parse(serverNow) / 1000;
const invitation = `invite_${'1'.repeat(32)}`, device = `agent_${'6'.repeat(32)}`, secret = 'S'.repeat(43);
const certificate = '-----BEGIN CERTIFICATE-----\nQUJDRA==\n-----END CERTIFICATE-----';
function record(state: EnrollmentState = 'created', revision = 1): EnrollmentSnapshot {
 return {
  version: 'tracebolt.enrollment-state.v2', binding: { instanceID: `manager_${'2'.repeat(32)}`, origin: window.location.origin, profile: 'tls', collectionProfile: 'managed-operations-v3', issuerFingerprint: 'a'.repeat(64) },
  invitationID: invitation, createRequestID: `request_${'3'.repeat(32)}`, platform: 'linux', revision, state, createdAt: seconds, deadlineAt: seconds + 600, updatedAt: seconds,
  claim: { claimID: `claim_${'4'.repeat(32)}`, requestID: '', keyFingerprint: 'ab'.repeat(32), csrHash: '', claimHash: '', comparisonCode: '12ab'.repeat(8), at: seconds },
  approval: { requestID: '', deviceID: ['created', 'claimed_pending'].includes(state) ? '' : device, keyFingerprint: 'ab'.repeat(32), at: seconds },
  intent: { intentID: '', requestID: '', serialHex: '', templateVersion: '', deviceID: '', keyFingerprint: '', notBefore: 0, notAfter: 0, at: 0 }, issuance: { requestID: '', certificateHash: '', at: 0 }, activation: { requestID: '', at: 0 }, termination: { requestID: '', from: '', at: 0 },
 };
}
function creation(complete = true): InvitationCreation {
 const snapshot = record();
 if (!complete) snapshot.binding.collectionProfile = 'managed-operations-v2';
 return { schemaVersion: 'tracebolt.enrollment-invitation.v2', serverNow, snapshot, invitationSecret: secret, bootstrapSHA256: 'b'.repeat(64), bootstrap: { schemaVersion: 'tracebolt.enrollment-bootstrap.v2', managerInstanceId: snapshot.binding.instanceID, profile: 'tls', enrollmentOrigin: window.location.origin, agentOrigin: 'https://localhost:9443', collectionProfile: snapshot.binding.collectionProfile, invitationId: invitation, serverCaPem: certificate, issuerRootPem: certificate, issuerPem: certificate } };
}
let current: EnrollmentList;
const clipboard = vi.fn(), onDevice = vi.fn();
function section() { return <EnrollmentSection onChanged={() => {}} onDevice={onDevice} deviceIds={[device]}/>; }
async function add() {
 render(section()); await waitFor(() => expect(screen.getByRole('button', { name: 'Add device' })).toBeEnabled());
 fireEvent.click(screen.getByRole('button', { name: 'Add device' })); return screen.getByRole('dialog', { name: 'Add device' });
}
async function create(complete = true) {
 if (!complete) { current.collectionProfile = 'managed-operations-v2'; current.collectionPrivacy = 'package_source_metadata_may_be_sensitive'; }
 vi.mocked(mutate).mockResolvedValue(creation(complete)); const dialog = await add();
 fireEvent.click(within(dialog).getByRole('checkbox')); fireEvent.click(within(dialog).getByRole('button', { name: 'Create invitation' }));
 await within(dialog).findByLabelText('One-time invitation secret'); return dialog;
}
async function refresh(dialog: HTMLElement) {
 fireEvent.click(within(dialog).getByRole('button', { name: 'Check status' }));
 await waitFor(() => expect(screen.getByRole('button', { name: 'Refresh enrollment status' })).toBeEnabled());
}
function currentStep(dialog: HTMLElement) { return within(dialog).getByRole('list', { name: 'Setup steps' }).querySelector('[aria-current="step"]'); }
function details(dialog: HTMLElement, summary: string) {
 const element = within(dialog).getByText(summary).closest('details'); expect(element).not.toBeNull(); return element!;
}
beforeEach(() => {
 setLocale('en', false); operator.insecureTestMode = false; localStorage.clear(); sessionStorage.clear();
 current = { schemaVersion: 'tracebolt.enrollment-operator.v2', serverNow, enabled: true, platforms: ['linux'], recordLimit: 25, items: [], collectionProfile: 'managed-operations-v3', collectionPrivacy: 'complete_system_inventory_metadata_may_be_sensitive' };
 clipboard.mockReset().mockResolvedValue(undefined); onDevice.mockReset();
 Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: clipboard } });
 vi.mocked(request).mockReset().mockImplementation(async () => structuredClone(current)); vi.mocked(mutate).mockReset();
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

describe('progressive invitation disclosure', () => {
 it('keeps HTTP risk, consent and the explicit disabled preparation notice visible before creation', async () => {
  vi.spyOn(downloadCommands, 'verifiedLinuxDownloadAvailable').mockReturnValue(false);
  operator.insecureTestMode = true; const dialog = await add();
  expect(currentStep(dialog)).toHaveTextContent('Install');
  expect(within(dialog).getByRole('note')).toBeVisible(); expect(within(dialog).getByRole('note')).toHaveTextContent('Passwords and data');
  expect(within(dialog).getByText(/connection metadata may reveal private network topology/)).toBeVisible();
  expect(within(dialog).getByText(/Inventory is available for up to 24 hours/)).toBeVisible();
  expect(within(dialog).getByText(/New managed-operations-v3 store and explicit enrollment consent required/)).toBeVisible();
  expect(within(dialog).getByText(/complete read-admin command is unavailable/)).toBeVisible();
  const disclosure = details(dialog, 'Collection, retention and limits'); expect(disclosure).not.toHaveAttribute('open');
  expect(within(disclosure).getByText(/without the older 128-row export prefix/)).not.toBeVisible();
  const consent = within(dialog).getByRole('checkbox'); expect(consent).toBeVisible(); expect(consent).not.toBeChecked();
  expect(within(dialog).getByRole('button', { name: 'Create invitation' })).toBeDisabled();
  fireEvent.click(within(disclosure).getByText('Collection, retention and limits'));
  expect(disclosure).toHaveAttribute('open'); expect(within(disclosure).getByText(/without the older 128-row export prefix/)).toBeVisible();
  expect(consent).not.toBeChecked(); expect(mutate).not.toHaveBeenCalled();
 });
 it('keeps the explicit disabled/manual command preview collapsed without hiding its prerequisites or secret rules', async () => {
  const response = creation(false), manual = preparedEnrollmentCommand(response.bootstrap, response.snapshot, response.bootstrapSHA256)!;
  vi.spyOn(downloadCommands, 'verifiedLinuxDownloadAvailable').mockReturnValue(false);
  vi.spyOn(downloadCommands, 'selectEnrollmentCommand').mockReturnValue({ kind: 'prepared-local', command: manual });
  const dialog = await create(false); const disclosure = details(dialog, 'Command and technical prerequisites');
  expect(disclosure).not.toHaveAttribute('open'); expect(within(disclosure).getByText(/do not verify the publisher/)).not.toBeVisible();
  expect(within(dialog).getByText(/This command does not download binaries/)).toBeVisible();
  expect(within(dialog).getByText(/Then return here to compare the key/)).toBeVisible();
  expect(within(dialog).getByText('Keep it out of URLs, command arguments and environment variables.')).toBeVisible();
  expect(within(dialog).getByText(/Available only now/)).toBeVisible();
  expect(within(dialog).getByLabelText('One-time invitation secret')).toHaveAttribute('type', 'password');
  expect(clipboard).not.toHaveBeenCalled();
  fireEvent.click(within(dialog).getByRole('button', { name: 'Copy public installation command' }));
  await waitFor(() => expect(clipboard).toHaveBeenCalledExactlyOnceWith(preparedEnrollmentCommand(creation(false).bootstrap, creation(false).snapshot, 'b'.repeat(64))));
  expect(clipboard.mock.calls[0][0]).not.toContain(secret);
  fireEvent.click(within(disclosure).getByText('Command and technical prerequisites'));
  expect(disclosure).toHaveAttribute('open'); expect(disclosure.querySelector('pre')).toBeVisible();
  expect(disclosure.textContent).not.toContain(secret); expect(mutate).toHaveBeenCalledTimes(1);
 });
 it('opens the public command by default when clipboard copy is unavailable', async () => {
  Object.defineProperty(navigator, 'clipboard', { configurable: true, value: undefined });
  const dialog = await create(false); const disclosure = details(dialog, 'Command and technical prerequisites');
  expect(disclosure).toHaveAttribute('open'); expect(disclosure.querySelector('pre')).toBeVisible();
  expect(within(dialog).queryByRole('button', { name: 'Copy public installation command' })).not.toBeInTheDocument();
  expect(within(dialog).getByLabelText('One-time invitation secret')).toHaveAttribute('type', 'password');
 });
 it('keeps German consent essential and disclosure separate without changing acknowledgement', async () => {
  const dialog = await add(); act(() => setLocale('de', false));
  expect(within(dialog).getByRole('list', { name: 'Einrichtungsschritte' })).toHaveTextContent('Installieren');
  expect(within(dialog).getByText(/Namen und Pfade können sensible Angaben enthalten/)).toBeVisible();
  expect(details(dialog, 'Erfassungsumfang, Speicherung und Grenzen')).not.toHaveAttribute('open');
  expect(within(dialog).getByRole('checkbox', { name: /Ich bestätige die Erfassung/ })).not.toBeChecked();
  expect(within(dialog).getByRole('button', { name: 'Einladung erstellen' })).toBeDisabled();
 });
});

describe('install, approve and connection verification', () => {
 it('moves from installation to visible fingerprint approval and leaves connection unconfirmed after activation', async () => {
  let dialog = await create(); expect(currentStep(dialog)).toHaveTextContent('Install');
  current.items = [record('claimed_pending', 2)]; await refresh(dialog);
  expect(currentStep(dialog)).toHaveTextContent('Approve'); expect(within(dialog).queryByLabelText('One-time invitation secret')).not.toBeInTheDocument();
  expect(within(dialog).queryByRole('button', { name: 'Copy public installation command' })).not.toBeInTheDocument();
  fireEvent.click(within(dialog).getByRole('button', { name: 'Compare device key' })); dialog = screen.getByRole('dialog', { name: 'Review invitation' });
  expect(currentStep(dialog)).toHaveTextContent('Approve');
  expect(within(dialog).getByText(groupedHex(record().claim.keyFingerprint))).toBeVisible();
  expect(within(dialog).getByText(groupedHex(record().claim.comparisonCode))).toBeVisible();
  expect(details(dialog, 'Destination & profile')).not.toHaveAttribute('open');
  const approve = within(dialog).getByRole('button', { name: 'Approve device' }); expect(approve).toBeDisabled();
  vi.mocked(mutate).mockResolvedValue(record('approved', 3)); fireEvent.click(within(dialog).getByRole('checkbox')); fireEvent.click(approve);
  await within(dialog).findByText('Key approved'); expect(currentStep(dialog)).toHaveTextContent('Connected');
  expect(within(dialog).getByText(/connection is not yet confirmed/)).toBeVisible();
  expect(mutate).toHaveBeenLastCalledWith(`/enrollment/${invitation}/approve`, { requestId: expect.any(String), expectedRevision: 2, expectedKeyFingerprint: record().claim.keyFingerprint }, expect.any(AbortSignal));
  current.items = [record('activated', 6)]; await refresh(dialog);
  expect(within(dialog).getByText(/check its latest report to verify the connection/)).toBeVisible();
  expect(within(dialog).getByText(/do not confirm ongoing collection/)).toBeVisible();
  expect(within(dialog).getByRole('list', { name: 'Setup steps' }).querySelector('.complete')).toBeNull();
  fireEvent.click(within(dialog).getByRole('button', { name: 'Open device' }));
  expect(onDevice).toHaveBeenCalledExactlyOnceWith(device); expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
 });
 it('does not show an active setup step for ended invitations', async () => {
  let dialog = await create(); current.items = [record('canceled', 2)]; await refresh(dialog);
  expect(currentStep(dialog)).toBeNull(); expect(within(dialog).queryByLabelText('One-time invitation secret')).not.toBeInTheDocument();
  expect(within(dialog).getByText(/This record has ended/)).toBeVisible();
  fireEvent.click(within(dialog).getByRole('button', { name: 'View invitation' })); dialog = screen.getByRole('dialog', { name: 'Review invitation' });
  expect(currentStep(dialog)).toBeNull(); expect(within(dialog).queryByRole('button', { name: 'Approve device' })).not.toBeInTheDocument();
 });
});
