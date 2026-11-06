import type {} from 'vitest/jsdom';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { EnrollmentSection } from './enrollment';
import { mutate, request } from './api';
import { setLocale } from './i18n';
import type { EnrollmentList, EnrollmentSnapshot } from './enrollment-types';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutate: vi.fn() }));
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: () => ({ mode: 'lan', authenticated: true, insecureTestMode: false }) }));

const serverNow = '2026-10-07T15:00:00Z', seconds = Date.parse(serverNow) / 1000;
let invitation = `invite_${'1'.repeat(32)}`; const fingerprint = 'ab'.repeat(32);
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


async function startApproval() {
 const region=await showWindows();
 fireEvent.click(await within(region).findByRole('button', { name:`Review device approval ${invitation}` }));
 const dialog=screen.getByRole('dialog', { name:'Review invitation' });
 fireEvent.click(within(dialog).getByRole('checkbox'));
 expect(within(dialog).getByRole('button', { name:'Approve device' })).toBeEnabled();
 fireEvent.click(within(dialog).getByRole('button', { name:'Approve device' }));
 expect(mutate).toHaveBeenCalledTimes(1);
 return dialog;
}

describe('Interrupted enrollment review mutations',()=>{
 it.each(['visibility', 'pagehide'])('fences a pending approval after %s, including an unchanged GET',async(kind)=>{
  invitation=`invite_${(kind==='visibility'?'a':'b').repeat(32)}`; current=listing([record()]);
  vi.mocked(mutate).mockImplementation(()=>new Promise(()=>{}));
  const dialog=await startApproval();
  if(kind==='visibility'){
   const visibility=vi.spyOn(document,'visibilityState','get').mockReturnValue('hidden');
   await act(async()=>document.dispatchEvent(new Event('visibilitychange')));
   visibility.mockReturnValue('visible');
   await act(async()=>document.dispatchEvent(new Event('visibilitychange')));
  }else await act(async()=>window.dispatchEvent(new Event('pagehide')));
  expect(await within(dialog).findByText(/last action is unconfirmed/)).toBeVisible();
  expect(within(dialog).getByRole('checkbox')).toBeDisabled();
  expect(within(dialog).getByRole('button',{name:'Approve device'})).toBeDisabled();
  await waitFor(()=>expect(within(dialog).getByRole('button',{name:'Check status'})).toBeEnabled());
  fireEvent.click(within(dialog).getByRole('button',{name:'Check status'}));
  await waitFor(()=>expect(within(dialog).getByRole('button',{name:'Check status'})).toBeEnabled());
  expect(within(dialog).getByRole('button',{name:'Approve device'})).toBeDisabled();
  expect(mutate).toHaveBeenCalledTimes(1);
 });
 it('keeps a fence when navigating away and reopening the same pending request',async()=>{
  invitation=`invite_${'c'.repeat(32)}`; current=listing([record()]);
  vi.mocked(mutate).mockImplementation(()=>new Promise(()=>{}));
  await startApproval();
  await act(async()=>window.dispatchEvent(new Event('hashchange')));
  expect(screen.queryByRole('dialog',{name:'Review invitation'})).not.toBeInTheDocument();
  fireEvent.click(await screen.findByRole('button',{name:`Review invitation ${invitation}`}));
  const dialog=screen.getByRole('dialog',{name:'Review invitation'});
  expect(within(dialog).getByText(/last action is unconfirmed/)).toBeVisible();
  expect(within(dialog).getByRole('button',{name:'Approve device'})).toBeDisabled();
  expect(mutate).toHaveBeenCalledTimes(1);
 });
 it('fences a lost response until a later matching advanced observation',async()=>{
  invitation=`invite_${'d'.repeat(32)}`; current=listing([record()]);
  vi.mocked(mutate).mockRejectedValueOnce(new Error('lost response'));
  const dialog=await startApproval();
  expect(await within(dialog).findByText(/last action is unconfirmed/)).toBeVisible();
  expect(within(dialog).getByRole('button',{name:'Approve device'})).toBeDisabled();
  current=listing([{...record(),revision:3,state:'approved'}]);
  await waitFor(()=>expect(within(dialog).getByRole('button',{name:'Check status'})).toBeEnabled());
  fireEvent.click(within(dialog).getByRole('button',{name:'Check status'}));
  // Parent reconciliation and the dialog's revision effect settle separately.
  // Require every original postcondition in the same eventual observation.
  await waitFor(()=>{
   expect(within(dialog).queryByText(/last action is unconfirmed/)).not.toBeInTheDocument();
   expect(screen.queryByText('Action not confirmed. Refresh status before making another decision.')).not.toBeInTheDocument();
   expect(within(dialog).queryByRole('button',{name:'Approve device'})).not.toBeInTheDocument();
  });
  expect(mutate).toHaveBeenCalledTimes(1);
 });
 it('does not resolve uncertainty using a different key or an advanced pending revision',async()=>{
  invitation=`invite_${'f'.repeat(32)}`; current=listing([record()]);
  vi.mocked(mutate).mockRejectedValueOnce(new Error('lost response'));
  const dialog=await startApproval();
  await within(dialog).findByText(/last action is unconfirmed/);
  current=listing([{...record(),revision:3,state:'claimed_pending'}]);
  await waitFor(()=>expect(within(dialog).getByRole('button',{name:'Check status'})).toBeEnabled());
  fireEvent.click(within(dialog).getByRole('button',{name:'Check status'}));
  await waitFor(()=>expect(within(dialog).getByRole('button',{name:'Check status'})).toBeEnabled());
  expect(within(dialog).getByText(/last action is unconfirmed/)).toBeVisible();
  current=listing([{...record(),revision:4,state:'approved',claim:{...record().claim,keyFingerprint:'cd'.repeat(32)}}]);
  fireEvent.click(within(dialog).getByRole('button',{name:'Check status'}));
  await waitFor(()=>expect(within(dialog).queryByRole('button',{name:'Approve device'})).not.toBeInTheDocument());
  expect(within(dialog).getByText(/last action is unconfirmed/)).toBeVisible();
  expect(mutate).toHaveBeenCalledTimes(1);
 });
 it('keeps an unconfirmed rejection fenced if the invitation merely advances',async()=>{
  invitation=`invite_${'9'.repeat(32)}`; current=listing([record()]);
  vi.mocked(mutate).mockRejectedValueOnce(new Error('lost response'));
  const region=await showWindows();
  fireEvent.click(await within(region).findByRole('button',{name:`Review device approval ${invitation}`}));
  const dialog=screen.getByRole('dialog',{name:'Review invitation'});
  fireEvent.click(within(dialog).getByRole('button',{name:'Reject'}));
  fireEvent.click(within(dialog).getByRole('button',{name:'Confirm termination'}));
  await within(dialog).findByText(/last action is unconfirmed/);
  current=listing([{...record(),revision:3,state:'approved'}]);
  await waitFor(()=>expect(within(dialog).getByRole('button',{name:'Check status'})).toBeEnabled());
  fireEvent.click(within(dialog).getByRole('button',{name:'Check status'}));
  await waitFor(()=>expect(within(dialog).queryByRole('button',{name:'Approve device'})).not.toBeInTheDocument());
  expect(within(dialog).getByText(/last action is unconfirmed/)).toBeVisible();
  expect(mutate).toHaveBeenCalledTimes(1);
 });
 it('shows the fenced outcome in German and blocks approval',async()=>{
  invitation=`invite_${'8'.repeat(32)}`; current=listing([record()]); setLocale('de',false);
  vi.mocked(mutate).mockRejectedValueOnce(new Error('verlorene Antwort'));
  render(<EnrollmentSection onChanged={()=>{}} onDevice={()=>{}} deviceIds={[]}/>);
  await screen.findByRole('button',{name:'Gerät hinzufügen'});
  fireEvent.change(screen.getByRole('combobox',{name:'Betriebssystem'}),{target:{value:'windows'}});
  const row=await screen.findByRole('button',{name:`Gerätefreigabe ${invitation} prüfen`});
  fireEvent.click(row);
  const dialog=screen.getByRole('dialog',{name:'Einladung prüfen'});
  fireEvent.click(within(dialog).getByRole('checkbox'));
  fireEvent.click(within(dialog).getByRole('button',{name:'Gerät freigeben'}));
  expect(await within(dialog).findByText(/letzte Aktion ist nicht bestätigt/)).toBeVisible();
  expect(within(dialog).getByRole('button',{name:'Gerät freigeben'})).toBeDisabled();
  expect(mutate).toHaveBeenCalledTimes(1);
 });
 it('does not create an uncertain fence when nothing was sent',async()=>{
  invitation=`invite_${'e'.repeat(32)}`; current=listing([record()]);
  const region=await showWindows();
  fireEvent.click(await within(region).findByRole('button',{name:`Review device approval ${invitation}`}));
  const dialog=screen.getByRole('dialog',{name:'Review invitation'});
  await act(async()=>window.dispatchEvent(new Event('pagehide')));
  expect(within(dialog).queryByText(/last action is unconfirmed/)).not.toBeInTheDocument();
  await act(async()=>window.dispatchEvent(new Event('pageshow')));
  await waitFor(()=>expect(within(dialog).getByRole('checkbox')).toBeEnabled());
  expect(mutate).not.toHaveBeenCalled();
 });
});
