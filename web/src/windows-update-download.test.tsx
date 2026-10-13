import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { request, mutateRaw } from './api';
import { useOperator, validOperatorSession } from './auth';
import { setLocale } from './i18n';
import { WindowsUpdateJobs } from './windows-update-jobs';
import { validDownloadOrigins, validUpdateJobView, type UpdateJobView, type UpdatePreview } from './windows-update-jobs-types';
import type { WindowsInventoryResource } from './windows-inventory-resource';
vi.mock('./api',async original=>({...await original<typeof import('./api')>(),request:vi.fn(),mutateRaw:vi.fn()}));
vi.mock('./auth',async original=>({...await original<typeof import('./auth')>(),useOperator:vi.fn()}));
const now='2026-10-11T10:00:00Z',until='2026-10-11T11:00:00Z',seconds=Date.parse(now)/1000,device=`agent_${'1'.repeat(32)}`,digest=`sha256:${'3'.repeat(64)}`,selection={updateId:'11111111-2222-3333-4444-555555555555',revision:3};
let actor='',session:Record<string,unknown>,resource:WindowsInventoryResource;
const view=():UpdateJobView=>({version:'tracebolt.windows-selected-update-job.v1',deviceId:device,serverNow:seconds,available:false,reason:'ready',downloadEnabled:true,downloadAvailable:true,reusableJobs:true,grantExpiresAt:seconds+3600,coordinated:true,backgroundExecutor:true,executorAvailability:'verified_recent',executorObservedAt:seconds,mutationCapturedAt:seconds,mutation:{active:true,blocked:false,phase:'idle',revision:'1',retained:0},job:null});
const preview=(id:string):UpdatePreview=>({id,actorId:actor,binding:{managerId:`manager_${'4'.repeat(32)}`,deviceId:device,incarnationDigest:digest,executorId:`executor_${'5'.repeat(32)}`,executorKeyId:`sha256:${'8'.repeat(64)}`,grantId:`grant_${'6'.repeat(32)}`,keyId:digest},readiness:{purpose:'download',downloadMetadataKnown:true,downloadOrigins:'https://updates.invalid',downloadMinBytes:1024,downloadMaxBytes:2048,downloadSource:'default',selection,capturedAt:seconds,software:'yes',installed:'no',hidden:'no',downloaded:'no',eulaAccepted:'yes',canRequestUserInput:'unknown',canRequireSource:'unknown',requiresNetwork:'unknown',bundledCount:0,installerBusy:'unknown',rebootRequiredBefore:'unknown',rebootBehavior:'unknown',offlineVerified:'yes'},createdAt:seconds,expiresAt:seconds+60,digest});
const reviewed=(id:string):UpdateJobView=>({...view(),job:{purpose:'download',id,selection,state:'preview',reason:'ready',preview:preview(id),result:null}});
const approved=(id:string):UpdateJobView=>({...view(),downloadAvailable:false,reason:'job_pending_or_intervention',job:{purpose:'download',id,selection,state:'approved',reason:'ready',preview:null,result:null,occurrence:'1'}});
const succeeded=(id:string):UpdateJobView=>({...approved(id),job:{...approved(id).job!,state:'complete',resultDigest:digest,retirement:{state:'available'},result:{purpose:'download',jobId:id,envelopeDigest:digest,attempted:true,nativeReturned:true,cleanupSucceeded:true,aggregateResultKnown:true,aggregateHresultKnown:true,updateResultKnown:true,updateHresultKnown:true,aggregateOperationResult:2,downloadedAfter:'yes',outcome:'succeeded',operationResult:2,hresult:0,rebootRequired:'unknown',completedAt:seconds}}});
const flush=()=>act(async()=>{});
async function open(){const ui=render(<WindowsUpdateJobs resource={resource}/>);await flush();return ui;}
async function review(locale:'en'|'de'='en'){fireEvent.change(screen.getByRole('combobox'),{target:{value:`${selection.updateId}:3`}});fireEvent.click(screen.getByRole('button',{name:locale==='de'?'Download prüfen':'Review download'}));await flush();}
beforeEach(()=>{
 actor=`operator_${crypto.randomUUID().replaceAll('-','')}`;session={mode:'lan',transport:'https',insecureTestMode:false,transportWarning:null,authenticationRequired:true,authenticated:true,csrfToken:'csrf',serverNow:now,expiresAt:until,expiresInSeconds:3600,loginMode:'named',actorId:actor,capabilities:['read','windows_update_download']};resource={view:{deviceId:device},updates:{rows:[{...selection,title:'Synthetic update',downloaded:false}]}} as unknown as WindowsInventoryResource;
 vi.useFakeTimers();vi.setSystemTime(now);setLocale('en',false);sessionStorage.clear();vi.mocked(useOperator).mockReturnValue({...session,theme:'light',logout:vi.fn(),setTheme:vi.fn()} as never);
 vi.mocked(request).mockReset().mockImplementation(async path=>structuredClone(path==='/auth/session'?session:view()) as never);
 vi.mocked(mutateRaw).mockReset().mockImplementation(async(path,body,_headers,_signal,_cap,beforeSend)=>{if(beforeSend&&!beforeSend())throw Error('Canceled before send');const input=JSON.parse(body);return structuredClone(path.endsWith('/request-download')?reviewed(input.requestId):approved(input.previewId)) as never});
});
afterEach(()=>{cleanup();vi.useRealTimers();vi.restoreAllMocks()});
describe('selected Windows download review',()=>{
 it.each(['en','de'] as const)('requires separate unchecked download consent and suppresses duplicate approval in %s',async locale=>{
  setLocale(locale,false);expect(validOperatorSession(session)).toBe(true);await open();await review(locale);
  expect(screen.queryByRole('button',{name:'Check readiness'})).toBeNull();expect(screen.queryByText('Schedule this update')).toBeNull();
  const approve=screen.getByRole('button',{name:locale==='de'?'Download einmal freigeben':'Approve download once'});expect(approve).toBeDisabled();expect(screen.getByRole('checkbox')).not.toBeChecked();
  expect(document.body).toHaveTextContent(locale==='de'?'keine feste Datenobergrenze':'not a hard byte quota');expect(document.body).toHaveTextContent('https://updates.invalid');expect(document.body).toHaveTextContent(locale==='de'?'separate frische Installationsprüfung':'separate fresh installation review');
  fireEvent.click(screen.getByRole('checkbox'));fireEvent.click(approve);fireEvent.click(approve);await flush();expect(mutateRaw).toHaveBeenCalledTimes(2);expect(vi.mocked(mutateRaw).mock.calls.map(([path])=>path)).toEqual([`/devices/${device}/windows-update-jobs/request-download`,`/devices/${device}/windows-update-jobs/approve-download`]);
 });
 it('shows the download action only for explicit undownloaded selected rows and enabled availability',async()=>{
  resource.updates!.rows[0].downloaded=true;await open();fireEvent.change(screen.getByRole('combobox'),{target:{value:`${selection.updateId}:3`}});expect(screen.queryByRole('button',{name:'Review download'})).toBeNull();expect(mutateRaw).not.toHaveBeenCalled();
 });
 it('cancels a changed row at the final send boundary without creating an uncertain write',async()=>{
  await open();vi.mocked(mutateRaw).mockImplementationOnce(async(_path,_body,_h,_s,_cap,beforeSend)=>{resource.updates!.rows[0].downloaded=true;expect(beforeSend?.()).toBe(false);throw Error('Unsent')});await review();expect(screen.getByRole('alert')).not.toHaveTextContent('unconfirmed');
 });
 it('keeps a lost download approval GET-only across navigation',async()=>{
  const ui=await open();await review();const id=JSON.parse(vi.mocked(mutateRaw).mock.calls[0][1]).requestId;vi.mocked(mutateRaw).mockRejectedValueOnce(Error('lost'));fireEvent.click(screen.getByRole('checkbox'));fireEvent.click(screen.getByRole('button',{name:'Approve download once'}));await flush();ui.unmount();
  vi.mocked(request).mockImplementation(async path=>structuredClone(path==='/auth/session'?session:reviewed(id)) as never);await open();expect(screen.queryByRole('checkbox')).toBeNull();expect(screen.queryByRole('button',{name:'Review download'})).toBeNull();expect(screen.getByRole('alert')).toHaveTextContent('unconfirmed');expect(mutateRaw).toHaveBeenCalledTimes(2);expect(vi.mocked(request).mock.calls.at(-1)?.[0]).toContain(`?jobId=${id}`);
 });
 it('does not let installation capability approve a download',async()=>{
  await open();await review();session.capabilities=['read','windows_update_install'];fireEvent.click(screen.getByRole('checkbox'));fireEvent.click(screen.getByRole('button',{name:'Approve download once'}));await flush();expect(mutateRaw).toHaveBeenCalledTimes(1);expect(screen.getByRole('alert')).toBeInTheDocument();
 });
 it('preserves cached-only success and uses separate download retirement',async()=>{
  const id=`update_${'7'.repeat(32)}`,value=succeeded(id);expect(validUpdateJobView(value,device,actor)).toBe(true);vi.mocked(request).mockImplementation(async path=>structuredClone(path==='/auth/session'?session:value) as never);vi.mocked(mutateRaw).mockResolvedValue({...value,job:{...value.job!,retirement:{state:'pending',requestedAt:seconds}}});await open();expect(screen.getByText('Download succeeded; content cached')).toBeVisible();expect(screen.queryByText('WUA reported success')).toBeNull();fireEvent.click(screen.getByRole('button',{name:'Review completed job'}));expect(screen.getByRole('checkbox')).not.toBeChecked();expect(screen.getByRole('checkbox')).toHaveAccessibleName(/does not install the update/);fireEvent.click(screen.getByRole('checkbox'));fireEvent.click(screen.getByRole('button',{name:'Close completed job'}));await flush();expect(vi.mocked(mutateRaw).mock.calls[0][0]).toBe(`/devices/${device}/windows-update-jobs/retire-download`);expect(screen.getByText('Closing pending; next job blocked.')).toBeVisible();
 });
 it('displays unread decoded result fields as unknown',async()=>{
  const id=`update_${'8'.repeat(32)}`,value=approved(id);value.job!.state='complete';value.job!.result={purpose:'download',jobId:id,envelopeDigest:digest,attempted:true,nativeReturned:true,downloadedAfter:'unknown',outcome:'uncertain',operationResult:0,hresult:0,rebootRequired:'unknown',completedAt:seconds};vi.mocked(request).mockImplementation(async path=>structuredClone(path==='/auth/session'?session:value) as never);await open();fireEvent.click(screen.getByText('WUA download evidence',{selector:'summary'}));expect(screen.getByText('Aggregate result / HRESULT: unknown / unknown')).toBeVisible();expect(screen.getByText('Selected update result / HRESULT: unknown / unknown')).toBeVisible();
 });
 it('rejects purpose swaps, unknown result success, malformed estimates and origin disclosures',()=>{
  const id=`update_${'9'.repeat(32)}`;for(const change of [(v:UpdateJobView)=>{delete v.job!.purpose},(v:UpdateJobView)=>{v.job!.preview!.readiness.downloadMaxBytes=17179869185},(v:UpdateJobView)=>{v.job!.preview!.readiness.downloadOrigins='https://updates.invalid/path'},(v:UpdateJobView)=>{v.job!.preview!.readiness.downloadSource='other'}]){const value=reviewed(id);change(value);expect(validUpdateJobView(value,device,actor)).toBe(false)}
  const result=succeeded(id);delete result.job!.result!.aggregateResultKnown;expect(validUpdateJobView(result,device,actor)).toBe(false);
  for(const origin of ['https://UPDATES.invalid','https://updates.invalid:443','https://user@updates.invalid','https://updates.invalid\nhttps://updates.invalid','https://b.invalid\nhttps://a.invalid','file://host'])expect(validDownloadOrigins(origin)).toBe(false);
 });
});
