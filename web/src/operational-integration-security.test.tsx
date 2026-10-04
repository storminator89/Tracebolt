import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { EnrollmentSection } from './enrollment';
import { AUTH_REQUIRED_EVENT, mutate, request } from './api';
import { AuthBoundary } from './auth';
import type { EnrollmentList, EnrollmentSnapshot, EnrollmentState, InvitationCreation } from './enrollment-types';
import { setLocale } from './i18n';
vi.mock('./api',async original=>({...await original<typeof import('./api')>(),request:vi.fn(),mutate:vi.fn()}));
const invite='invite_'+'1'.repeat(32),fingerprint='ab'.repeat(32),secret='A'.repeat(43);
function record(state:EnrollmentState='created',revision=1):EnrollmentSnapshot {return {version:'tracebolt.enrollment-state.v2',binding:{instanceID:'manager_'+'2'.repeat(32),origin:'https://localhost',profile:'tls',collectionProfile:'basic-readonly-v1',issuerFingerprint:'c'.repeat(64)},invitationID:invite,createRequestID:'request_'+'3'.repeat(32),platform:'linux',revision,state,createdAt:1791046800,deadlineAt:1791047400,updatedAt:1791046810,claim:{claimID:'claim_'+'4'.repeat(32),requestID:'request_'+'5'.repeat(32),keyFingerprint:fingerprint,csrHash:'c'.repeat(64),claimHash:'d'.repeat(64),comparisonCode:'12ab'.repeat(8),at:1791046810},approval:{requestID:'',deviceID:state==='created'||state==='claimed_pending'?'':'agent_'+'6'.repeat(32),keyFingerprint:fingerprint,at:0},intent:{intentID:'',requestID:'',serialHex:'',templateVersion:'',deviceID:'',keyFingerprint:'',notBefore:0,notAfter:0,at:0},issuance:{requestID:'',certificateHash:'',at:0},activation:{requestID:'',at:0},termination:{requestID:'',from:'',at:0}};}
function listing(items:EnrollmentSnapshot[]=[],enabled=true):EnrollmentList {return {serverNow:new Date(1791046800*1000).toISOString(),schemaVersion:'tracebolt.enrollment-operator.v2',enabled,platforms:enabled?['linux']:[],recordLimit:25,items};}
function creation():InvitationCreation {const snapshot=record();return {serverNow:new Date(1791046800*1000).toISOString(),schemaVersion:'tracebolt.enrollment-invitation.v2',snapshot,invitationSecret:secret,bootstrap:{schemaVersion:'tracebolt.enrollment-bootstrap.v2',managerInstanceId:snapshot.binding.instanceID,profile:'tls',enrollmentOrigin:'https://localhost',agentOrigin:'https://localhost:9443',collectionProfile:snapshot.binding.collectionProfile,invitationId:invite,serverCaPem:'-----BEGIN CERTIFICATE-----\nVEVTVF9QVUJMSUNfQ0VSVElGSUNBVEU=\n-----END CERTIFICATE-----',issuerRootPem:'-----BEGIN CERTIFICATE-----\nUk9PVF9DRVJUSUZJQ0FURQ==\n-----END CERTIFICATE-----',issuerPem:'-----BEGIN CERTIFICATE-----\nSVNTVUVSX0NFUlRJRklDQVRF\n-----END CERTIFICATE-----'}};}
const changed=vi.fn(),device=vi.fn();
function section(){return <EnrollmentSection onChanged={changed} onDevice={device} deviceIds={[]}/>;}
let current:EnrollmentList;
beforeEach(()=>{setLocale('en',false);current=listing();vi.mocked(request).mockReset().mockImplementation(async()=>structuredClone(current));vi.mocked(mutate).mockReset();changed.mockClear();device.mockClear();localStorage.clear();sessionStorage.clear();window.location.hash='/devices';});
afterEach(()=>{cleanup();vi.restoreAllMocks();vi.unstubAllGlobals();vi.useRealTimers();});
async function add(){render(section());await waitFor(()=>expect(screen.getByRole('button',{name:'Add device'})).toBeEnabled());fireEvent.click(screen.getByRole('button',{name:'Add device'}));return screen.getByRole('dialog',{name:'Add device'});}
function managedListing():EnrollmentList{return {...listing(),collectionProfile:'managed-operations-v1',collectionPrivacy:'metadata_labels_may_be_sensitive'};}
function managedCreation():InvitationCreation{const value=creation();value.snapshot.binding.collectionProfile='managed-operations-v1';value.bootstrap.collectionProfile='managed-operations-v1';return value;}

describe('independent managed collection boundary coverage',()=>{
 it.each([
  {collectionProfile:'managed-operations-v1'},
  {collectionProfile:'managed-operations-v1',collectionPrivacy:'unknown'},
  {collectionProfile:'future-profile',collectionPrivacy:'metadata_labels_may_be_sensitive'},
  {collectionPrivacy:'metadata_labels_may_be_sensitive'},
  {collectionProfile:null,collectionPrivacy:'metadata_labels_may_be_sensitive'},
 ])('keeps creation disabled for invalid initial profile/privacy tuple %j',async tuple=>{
  vi.mocked(request).mockResolvedValue({...listing(),...tuple});render(section());await screen.findByRole('alert');expect(screen.getByRole('button',{name:'Add device'})).toBeDisabled();expect(mutate).not.toHaveBeenCalled();
 });
 it.each(['profile','platform','origin','identity','bootstrap'] as const)('rejects a mismatched %s before secret disclosure or export',async field=>{
  current=managedListing();const response=managedCreation();if(field==='profile')response.snapshot.binding.collectionProfile='basic-readonly-v1';if(field==='platform')response.snapshot.platform='windows';if(field==='origin')response.snapshot.binding.origin='https://elsewhere.invalid';if(field==='identity')response.bootstrap.managerInstanceId='manager_'+'9'.repeat(32);if(field==='bootstrap')response.bootstrap.collectionProfile='basic-readonly-v1';vi.mocked(mutate).mockResolvedValue(response);const dialog=await add();fireEvent.click(within(dialog).getByRole('checkbox'));fireEvent.click(within(dialog).getByRole('button',{name:'Create invitation'}));await within(dialog).findByRole('alert');expect(screen.queryByLabelText('One-time invitation secret')).not.toBeInTheDocument();expect(screen.queryByRole('button',{name:'Download bootstrap file'})).not.toBeInTheDocument();expect(changed).not.toHaveBeenCalled();
 });
 it.each(['close','hide','profile-change','auth'] as const)('aborts a managed creation and suppresses its late response after %s',async interruption=>{
  current=managedListing();let resolve!:(value:InvitationCreation)=>void;let signal:AbortSignal|undefined;vi.mocked(mutate).mockImplementation(async(_path,_data,s)=>new Promise<InvitationCreation>(done=>{resolve=done;signal=s;}));
  if(interruption==='auth'){vi.mocked(request).mockImplementation(async path=>path==='/auth/session'?session:structuredClone(current));render(<AuthBoundary>{section()}</AuthBoundary>);await waitFor(()=>expect(screen.getByRole('button',{name:'Add device'})).toBeEnabled());fireEvent.click(screen.getByRole('button',{name:'Add device'}));}else await add();
  const dialog=screen.getByRole('dialog',{name:'Add device'});fireEvent.click(within(dialog).getByRole('checkbox'));fireEvent.click(within(dialog).getByRole('button',{name:'Create invitation'}));expect(signal).toBeDefined();
  if(interruption==='close')fireEvent.keyDown(document,{key:'Escape'});if(interruption==='hide')act(()=>window.dispatchEvent(new Event('pagehide')));if(interruption==='auth')act(()=>window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT)));if(interruption==='profile-change'){current=listing();fireEvent.click(screen.getByRole('button',{name:'Refresh enrollment status'}));await waitFor(()=>expect(screen.queryByRole('dialog')).not.toBeInTheDocument());}
  expect(signal!.aborted).toBe(true);await act(async()=>resolve(managedCreation()));expect(screen.queryByLabelText('One-time invitation secret')).not.toBeInTheDocument();expect(screen.queryByRole('button',{name:'Download bootstrap file'})).not.toBeInTheDocument();expect(changed).not.toHaveBeenCalled();
 });
 it.each(['missing-privacy','unknown-profile','read-failure'] as const)('invalidates an open consent dialog after %s on periodic refresh',async failure=>{
  vi.useFakeTimers({toFake:['setInterval','clearInterval']});current={...managedListing(),items:[record()]};vi.mocked(mutate).mockImplementation(()=>new Promise(()=>{}));const dialog=await add();fireEvent.click(within(dialog).getByRole('checkbox'));if(failure==='missing-privacy')current={...current,collectionPrivacy:undefined};else if(failure==='unknown-profile')vi.mocked(request).mockResolvedValue({...current,collectionProfile:'future-profile'});else vi.mocked(request).mockRejectedValue(new Error('synthetic read failure'));
  // A periodic status refresh can occur while the modal is open.
  await act(async()=>{await vi.advanceTimersByTimeAsync(10000);});await screen.findByRole('alert');expect(screen.getByRole('button',{name:'Add device'})).toBeDisabled();
  const create=screen.queryByRole('button',{name:'Create invitation'});if(create)fireEvent.click(create);
  // A malformed current consent contract must not leave the older acknowledgement usable.
  expect(mutate).not.toHaveBeenCalled();
 });
 it('aborts an in-flight creation when the current managed contract becomes invalid',async()=>{
  vi.useFakeTimers({toFake:['setInterval','clearInterval']});current={...managedListing(),items:[record()]};let resolve!:(value:InvitationCreation)=>void;let signal:AbortSignal|undefined;vi.mocked(mutate).mockImplementation(async(_path,_data,s)=>new Promise<InvitationCreation>(done=>{resolve=done;signal=s;}));
  const dialog=await add();fireEvent.click(within(dialog).getByRole('checkbox'));fireEvent.click(within(dialog).getByRole('button',{name:'Create invitation'}));expect(signal).toBeDefined();current={...current,collectionPrivacy:undefined};await act(async()=>{await vi.advanceTimersByTimeAsync(10000);});await screen.findByRole('alert');expect(signal!.aborted).toBe(true);await act(async()=>resolve(managedCreation()));expect(screen.queryByLabelText('One-time invitation secret')).not.toBeInTheDocument();expect(screen.queryByRole('button',{name:'Download bootstrap file'})).not.toBeInTheDocument();expect(changed).not.toHaveBeenCalled();
 });
 it('suppresses a successful old create response and preserves its uncertain outcome after invalidation',async()=>{
  vi.useFakeTimers({toFake:['setInterval','clearInterval']});current={...managedListing(),items:[record()]};let resolve!:(value:InvitationCreation)=>void;vi.mocked(mutate).mockImplementation(()=>new Promise<InvitationCreation>(done=>{resolve=done;}));
  const dialog=await add();fireEvent.click(within(dialog).getByRole('checkbox'));fireEvent.click(within(dialog).getByRole('button',{name:'Create invitation'}));current={...current,collectionPrivacy:undefined};await act(async()=>{await vi.advanceTimersByTimeAsync(10000);});await screen.findByRole('alert');await act(async()=>resolve(managedCreation()));
  expect(screen.queryByLabelText('One-time invitation secret')).not.toBeInTheDocument();expect(screen.queryByRole('button',{name:'Download bootstrap file'})).not.toBeInTheDocument();expect(changed).not.toHaveBeenCalled();expect(screen.getByRole('status')).toHaveTextContent('An invitation may already exist');expect(mutate).toHaveBeenCalledTimes(1);
 });
 it('requires a fresh unchecked acknowledgement after an invalidated dialog is reopened',async()=>{
  vi.useFakeTimers({toFake:['setInterval','clearInterval']});current={...managedListing(),items:[record()]};const dialog=await add();fireEvent.click(within(dialog).getByRole('checkbox'));current={...current,collectionPrivacy:undefined};await act(async()=>{await vi.advanceTimersByTimeAsync(10000);});await screen.findByRole('alert');expect(screen.queryByRole('dialog')).not.toBeInTheDocument();current=managedListing();fireEvent.click(screen.getByRole('button',{name:'Refresh enrollment status'}));await waitFor(()=>expect(screen.getByRole('button',{name:'Add device'})).toBeEnabled());fireEvent.click(screen.getByRole('button',{name:'Add device'}));const fresh=screen.getByRole('dialog',{name:'Add device'});expect(within(fresh).getByRole('checkbox')).not.toBeChecked();expect(within(fresh).getByRole('button',{name:'Create invitation'})).toBeDisabled();expect(mutate).not.toHaveBeenCalled();
 });
 it('cannot restore consent availability from an older successful status response after a newer invalid one',async()=>{
  vi.useFakeTimers({toFake:['setInterval','clearInterval']});current={...managedListing(),items:[record()]};const dialog=await add();fireEvent.click(within(dialog).getByRole('checkbox'));let resolve!:(value:EnrollmentList)=>void;let signal:AbortSignal|undefined;
  vi.mocked(request).mockImplementationOnce(async(_path,options)=>new Promise<EnrollmentList>(done=>{resolve=done;signal=options?.signal as AbortSignal;}));await act(async()=>{await vi.advanceTimersByTimeAsync(10000);});expect(signal).toBeDefined();current={...current,collectionPrivacy:undefined};await act(async()=>{await vi.advanceTimersByTimeAsync(10000);});await screen.findByRole('alert');expect(signal!.aborted).toBe(true);await act(async()=>resolve(managedListing()));expect(screen.getByRole('button',{name:'Add device'})).toBeDisabled();expect(screen.queryByRole('dialog')).not.toBeInTheDocument();expect(mutate).not.toHaveBeenCalled();
 });
});

import App from './App';
import type { Device, Metric, Overview } from './types';
import type { OperationalView } from './operational-types';
const firstID='agent_'+'7'.repeat(32),secondID='agent_'+'8'.repeat(32);
const session={mode:'lan',transport:'https',insecureTestMode:false,transportWarning:null,authenticationRequired:true,authenticated:true,csrfToken:'synthetic-session',serverNow:'2026-10-03T12:00:00Z',expiresAt:'2026-10-03T12:30:00Z',expiresInSeconds:1800};
const metric:Metric={value:null,unit:'%',quality:'unknown',source:'Synthetic review fixture',collectedAt:'0001-01-01T00:00:00Z'};
function makeDevice(id=firstID):Device{return {id,name:`Synthetic ${id===firstID?'first':'second'} device`,platform:'linux',os:'Linux fixture',site:'Fixture',group:'Fixture',ip:null,status:'unknown',source:'lan',synthetic:false,lastSeen:'0001-01-01T00:00:00Z',agentVersion:'fixture',cpu:metric,memory:metric,disk:metric,uptime:'',tags:[],capabilities:[],evidence:[],trend:[],caseIds:[]};}
function overview():Overview{return {product:'Synthetic Tracebolt',mode:'lan',generatedAt:'2026-10-03T12:00:00Z',stats:{totalDevices:2,healthyDevices:0,attentionDevices:0,unknownDevices:2,openCases:0,criticalCases:0},devices:[makeDevice(),makeDevice(secondID)],cases:[],activity:[]};}
function view(id=firstID):OperationalView{return {schemaVersion:'tracebolt.operational-view.v1',deviceId:id,status:'not_configured',serverNow:'2026-10-03T12:00:00Z',receivedAt:null,sequence:null,maxAgeSeconds:120,snapshot:null,lastGood:{volumes:null,network:null,services:null,processes:null,software:null,events:null},assessments:{updates:{quality:'unknown',reason:'not_implemented'},vulnerabilities:{quality:'unknown',reason:'not_implemented'}}};}
async function navigate(id:string){await act(async()=>{window.history.replaceState({},'',`/#/devices/${id}`);window.dispatchEvent(new HashChangeEvent('hashchange'));});}

describe('actual App routing and access boundary',()=>{
 it.each(['device','close','auth'] as const)('aborts the operational read on %s transition and suppresses late old data',async interruption=>{
  await navigate(firstID);let resolve!:(value:OperationalView)=>void;let signal:AbortSignal|undefined;vi.mocked(request).mockImplementation(async(path,options)=>{if(path==='/auth/session')return session;if(path==='/enrollment')return listing();if(path==='/overview')return overview();if(path===`/devices/${firstID}/operational`)return new Promise<OperationalView>(done=>{resolve=done;signal=options?.signal as AbortSignal;});return makeDevice(path.includes(secondID)?secondID:firstID);});
  render(<App/>);fireEvent.click(await screen.findByRole('tab',{name:'Inventory'}));await waitFor(()=>expect(signal).toBeDefined());
  if(interruption==='device'){await navigate(secondID);await screen.findByRole('region',{name:'Device Synthetic second device'});expect(screen.getByRole('tab',{name:'Overview'})).toHaveAttribute('aria-selected','true');}
  if(interruption==='close'){fireEvent.keyDown(document,{key:'Escape'});await waitFor(()=>expect(screen.queryByRole('region',{name:'Device Synthetic first device'})).not.toBeInTheDocument());expect(window.location.hash).toBe('#/devices');}
  if(interruption==='auth'){act(()=>window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT)));await screen.findByLabelText('Operator password');}
  expect(signal!.aborted).toBe(true);await act(async()=>resolve(view()));expect(screen.queryByText('Operational inventory')).not.toBeInTheDocument();expect(request).not.toHaveBeenCalledWith(`/devices/${secondID}/operational`,expect.anything());
 });
});
