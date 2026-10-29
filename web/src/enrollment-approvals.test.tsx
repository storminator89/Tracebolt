import type {} from 'vitest/jsdom';
import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { EnrollmentSection } from './enrollment';
import { mutate, request } from './api';
import { setLocale } from './i18n';
import type { EnrollmentList, EnrollmentSnapshot } from './enrollment-types';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutate: vi.fn() }));
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: () => ({ mode: 'lan', authenticated: true, insecureTestMode: false }) }));

const serverNow = '2026-10-07T15:00:00Z', seconds = Date.parse(serverNow) / 1000;
const invitation = `invite_${'1'.repeat(32)}`, fingerprint = 'ab'.repeat(32);
function record(deadline = seconds + 600): EnrollmentSnapshot {
 return {
  version: 'tracebolt.enrollment-state.v2', binding: { instanceID: `manager_${'2'.repeat(32)}`, origin: window.location.origin, profile: 'tls', collectionProfile: 'windows-inventory-v1', issuerFingerprint: 'a'.repeat(64) },
  invitationID: invitation, createRequestID: `request_${'3'.repeat(32)}`, platform: 'windows', revision: 2, state: 'claimed_pending', createdAt: seconds - 120, deadlineAt: deadline, updatedAt: seconds - 60,
  claim: { claimID: `claim_${'4'.repeat(32)}`, requestID: '', keyFingerprint: fingerprint, csrHash: '', claimHash: '', comparisonCode: '12ab'.repeat(8), at: seconds - 60 },
  approval: { requestID: '', deviceID: '', keyFingerprint: fingerprint, at: 0 },
  intent: { intentID: '', requestID: '', serialHex: '', templateVersion: '', deviceID: '', keyFingerprint: '', notBefore: 0, notAfter: 0, at: 0 }, issuance: { requestID: '', certificateHash: '', at: 0 }, activation: { requestID: '', at: 0 }, termination: { requestID: '', from: '', at: 0 },
 };
}
function listing(items: EnrollmentSnapshot[]): EnrollmentList {
 return { schemaVersion: 'tracebolt.enrollment-operator.v2', serverNow, enabled: true, platforms: ['windows'], recordLimit: 25, collectionProfile: 'windows-inventory-v1', collectionPrivacy: 'windows_inventory_metadata_may_be_sensitive', items };
}
let current: EnrollmentList;
async function showWindows() {
 render(<EnrollmentSection onChanged={()=>{}} onDevice={()=>{}} deviceIds={[]}/>);
 await screen.findByRole('button', { name: 'Add device' });
 fireEvent.change(screen.getByRole('combobox', { name: 'Operating system' }), { target: { value: 'windows' } });
 return screen.findByRole('region', { name: 'Device approvals · Windows' });
}
beforeEach(()=>{
 jsdom.reconfigure({ url:'https://localhost/' }); setLocale('en', false); current=listing([record()]);
 vi.mocked(request).mockReset().mockImplementation(async path => structuredClone(path === '/windows/enrollment' ? current : { schemaVersion:'tracebolt.enrollment-operator.v2', serverNow, enabled:true, platforms:['linux'], recordLimit:25, items:[] }));
 vi.mocked(mutate).mockReset();
});
afterEach(()=>{ cleanup(); vi.restoreAllMocks(); setLocale('en', false); });

describe('Windows device approvals',()=>{
 it('shows each request time and deadline in UTC without approving',async()=>{
  const second={...record(seconds+1200),invitationID:`invite_${'2'.repeat(32)}`,claim:{...record().claim,at:seconds-30}};
  current=listing([record(),second]);
  const region=await showWindows();
  const firstRow=await within(region).findByRole('button', { name:`Review device approval ${invitation}` });
  const secondRow=within(region).getByRole('button', { name:`Review device approval ${second.invitationID}` });
  expect(within(firstRow).getByText('Requested:')).toHaveTextContent('Requested: 2026-10-07 14:59:00 UTC');
  expect(within(firstRow).getByText('Request expires:')).toHaveTextContent('Request expires: 2026-10-07 15:10:00 UTC');
  expect(within(secondRow).getByText('Requested:')).toHaveTextContent('Requested: 2026-10-07 14:59:30 UTC');
  expect(within(secondRow).getByText('Request expires:')).toHaveTextContent('Request expires: 2026-10-07 15:20:00 UTC');
  expect(firstRow).toHaveAccessibleDescription('Requested: 2026-10-07 14:59:00 UTC Request expires: 2026-10-07 15:10:00 UTC');
  expect(mutate).not.toHaveBeenCalled();
 });
 it('shows missing or invalid request times and an unspecified deadline as unknown',async()=>{
  const bad={...record(0),claim:{...record().claim,at:'not a time' as unknown as number}};
  const missing={...record(),invitationID:`invite_${'2'.repeat(32)}`,claim:{...record().claim,at:0}};
  current=listing([bad,missing]);
  const region=await showWindows();
  const firstRow=await within(region).findByRole('button', { name:`Review device approval ${invitation}` });
  expect(within(firstRow).getByText('Requested: Unknown')).toBeVisible();
  expect(within(firstRow).getByText('Request expires: Unknown')).toBeVisible();
  expect(within(within(region).getByRole('button', { name:`Review device approval ${missing.invitationID}` })).getByText('Requested: Unknown')).toBeVisible();
  expect(mutate).not.toHaveBeenCalled();
 });
 it('labels request and deadline in German',async()=>{
  setLocale('de', false);
  render(<EnrollmentSection onChanged={()=>{}} onDevice={()=>{}} deviceIds={[]}/>);
  await screen.findByRole('button', { name:'Gerät hinzufügen' });
  fireEvent.change(screen.getByRole('combobox', { name:'Betriebssystem' }), { target:{value:'windows'} });
  const row=await screen.findByRole('button', { name:`Gerätefreigabe ${invitation} prüfen` });
  expect(within(row).getByText('Angefragt:')).toHaveTextContent('Angefragt: 2026-10-07 14:59:00 UTC');
  expect(within(row).getByText('Anfrage gültig bis:')).toHaveTextContent('Anfrage gültig bis: 2026-10-07 15:10:00 UTC');
 });
 it('opens the existing explicit key comparison without approving on open',async()=>{
  const region=await showWindows();
  const row=await within(region).findByRole('button', { name:`Review device approval ${invitation}` });
  fireEvent.click(row);
  const dialog=screen.getByRole('dialog', { name:'Review invitation' });
  expect(within(dialog).getByText(/Compare the full fingerprint and comparison value directly on the device/)).toBeVisible();
  expect(within(dialog).getByRole('checkbox')).not.toBeChecked();
  expect(within(dialog).getByRole('button', { name:'Approve device' })).toBeDisabled();
  expect(mutate).not.toHaveBeenCalled();
 });
 it('does not present expired requests as pending approvals',async()=>{
  current=listing([record(seconds-1)]);
  const region=await showWindows();
  await within(region).findByText('Pending requests have expired; review them in invitation history.');
  expect(within(region).queryByRole('button', { name:`Review device approval ${invitation}` })).not.toBeInTheDocument();
  expect(mutate).not.toHaveBeenCalled();
 });
 it('keeps expired requests separate when another request is still pending',async()=>{
  const expired={...record(seconds-1),invitationID:`invite_${'2'.repeat(32)}`};
  current=listing([record(),expired]);
  const region=await showWindows();
  await within(region).findByRole('button', { name:`Review device approval ${invitation}` });
  expect(within(region).queryByRole('button', { name:`Review device approval ${expired.invitationID}` })).not.toBeInTheDocument();
  expect(within(region).getByText('1 other request(s) expired; review them in invitation history.')).toBeVisible();
 });
 it('hides stale rows while a refresh is pending and after a failed read',async()=>{
  const region=await showWindows();
  await within(region).findByRole('button', { name:`Review device approval ${invitation}` });
  let fail!: (reason: Error)=>void;
  vi.mocked(request).mockImplementationOnce(()=>new Promise((_resolve,reject)=>{fail=reject;}));
  fireEvent.click(screen.getByRole('button', { name:'Refresh enrollment status' }));
  expect(within(region).getByText('Checking approvals…')).toBeVisible();
  expect(within(region).queryByRole('button', { name:`Review device approval ${invitation}` })).not.toBeInTheDocument();
  await act(async()=>fail(new Error('offline')));
  expect(await within(region).findByText('Device approvals cannot be confirmed right now. Refresh status.')).toBeVisible();
  expect(within(region).queryByRole('button', { name:`Review device approval ${invitation}` })).not.toBeInTheDocument();
 });
 it('shows the empty state in German and does not fetch other platforms',async()=>{
  current=listing([]); setLocale('de', false);
  render(<EnrollmentSection onChanged={()=>{}} onDevice={()=>{}} deviceIds={[]}/>);
  await screen.findByRole('button', { name:'Gerät hinzufügen' });
  fireEvent.change(screen.getByRole('combobox', { name:'Betriebssystem' }), { target:{value:'windows'} });
  const region=await screen.findByRole('region', { name:'Gerätefreigaben · Windows' });
  expect(await within(region).findByText('Keine Gerätefreigaben ausstehend.')).toBeVisible();
  expect(vi.mocked(request).mock.calls.map(call=>call[0])).toEqual(['/enrollment','/windows/enrollment']);
 });
});
