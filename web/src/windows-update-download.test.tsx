import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
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
  expect(document.body).toHaveTextContent(locale==='de'?'keine feste Datenobergrenze':'no hard byte quota');expect(document.body).toHaveTextContent('https://updates.invalid');expect(document.body).toHaveTextContent(locale==='de'?'separate frische Installationsprüfung':'separate fresh installation review');
  fireEvent.click(screen.getByRole('checkbox'));fireEvent.click(approve);fireEvent.click(approve);await flush();expect(mutateRaw).toHaveBeenCalledTimes(2);expect(vi.mocked(mutateRaw).mock.calls.map(([path])=>path)).toEqual([`/devices/${device}/windows-update-jobs/request-download`,`/devices/${device}/windows-update-jobs/approve-download`]);
 });
 it.each(['en','de'] as const)('keeps material download limits visible and exact identity in closed details in %s',async locale=>{
  setLocale(locale,false);await open();await review(locale);const de=locale==='de',group=screen.getByRole('group',{name:de?'Bereitschaft prüfen':'Check readiness'}),ui=within(group);
  expect(ui.getByText('Synthetic update')).toBeVisible();
  const identity=ui.getByText(`${selection.updateId} · Revision 3`),readiness=ui.getByText(de?'Bereitschaftsdetails':'Readiness details',{selector:'summary'});
  expect(identity).not.toBeVisible();expect(readiness.closest('details')).not.toHaveAttribute('open');
  for(const phrase of [de?/keine feste Datenobergrenze/:/no hard byte quota/,de?/Ursprünge begrenzen die Ziele nicht/:/origins do not restrict destinations/,de?/Downloads können Cache-Inhalte hinterlassen/:/downloads may leave cached content/,de?/danach separate frische Installationsprüfung/:/before a separate fresh installation review/])expect(ui.getByText(phrase)).toBeVisible();
  const technical=ui.getByText(de?/einschließlich konfigurierter Proxys, BITS/:/including configured proxies, BITS/),origins=ui.getByText(de?'Metadaten-Ursprünge':'Metadata origins',{selector:'summary'});
  expect(technical).not.toBeVisible();expect(ui.getByText('https://updates.invalid')).not.toBeVisible();
  fireEvent.click(readiness);expect(identity).toBeVisible();expect(ui.getByText(de?/Lizenz bereits angenommen/:/license already accepted/)).toBeVisible();fireEvent.click(readiness);
  fireEvent.click(origins);expect(technical).toBeVisible();expect(ui.getByText('https://updates.invalid')).toBeVisible();fireEvent.click(origins);
  expect(identity).not.toBeVisible();expect(technical).not.toBeVisible();expect(ui.getByRole('checkbox')).not.toBeChecked();expect(ui.getByRole('button',{name:de?'Download einmal freigeben':'Approve download once'})).toBeDisabled();expect(mutateRaw).toHaveBeenCalledTimes(1);
 });
 it('never substitutes an unrelated current row title for the exact reviewed download',async()=>{
  const ui=await open();await review();resource.updates!.rows=[{...resource.updates!.rows[0],updateId:'99999999-2222-3333-4444-555555555555',title:'Unrelated update'}];ui.rerender(<WindowsUpdateJobs resource={resource}/>);
  const group=screen.getByRole('group',{name:'Check readiness'});expect(within(group).getByText(`${selection.updateId} · Revision 3`)).toBeVisible();expect(group).not.toHaveTextContent('Unrelated update');expect(within(group).getByRole('checkbox')).not.toBeChecked();expect(mutateRaw).toHaveBeenCalledTimes(1);
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

const coexisting=(value:UpdateJobView=view()):UpdateJobView=>({...value,backgroundScheduling:true,schedulingAvailable:true});
const installationReview=(id:string):UpdateJobView=>{
 const downloaded=preview(id),{purpose:_,downloadMetadataKnown:__,downloadOrigins:___,downloadMinBytes:____,downloadMaxBytes:_____,downloadSource:______,...readiness}=downloaded.readiness;
 return {...coexisting(),available:true,job:{id,selection,state:'preview',reason:'ready',preview:{...downloaded,readiness:{...readiness,downloaded:'yes',canRequestUserInput:'no',canRequireSource:'no',requiresNetwork:'no',installerBusy:'no',rebootRequiredBefore:'no',rebootBehavior:'can'}},result:null}};
};
const scheduledInstallation=(id:string):UpdateJobView=>({...coexisting(),available:false,downloadAvailable:false,reason:'job_pending_or_intervention',job:{id,selection,state:'scheduled',reason:'schedule_waiting',preview:null,result:null,occurrence:'1',schedule:{version:'tracebolt.windows-selected-update-schedule.v1',digest,approvedAt:seconds,startAt:seconds+120,endAt:seconds+420,permitIssuedAt:0,revoked:false}}});
function enableCoexistence(capabilities=['read','windows_update_install','windows_update_download','windows_update_schedule']){
 session.capabilities=capabilities;
 vi.mocked(request).mockImplementation(async path=>structuredClone(path==='/auth/session'?session:coexisting({...view(),available:true})) as never);
 vi.mocked(mutateRaw).mockImplementation(async(path,body,_headers,_signal,_cap,beforeSend)=>{
  if(beforeSend&&!beforeSend())throw Error('Canceled before send');const input=JSON.parse(body);
  return structuredClone(path.endsWith('/request-download')?coexisting(reviewed(input.requestId)):path.endsWith('/approve-download')?coexisting(approved(input.previewId)):path.endsWith('/schedule')?scheduledInstallation(input.previewId):installationReview(input.requestId)) as never;
 });
}
describe('manual downloads with separately scheduled installations',()=>{
 it('admits independent profile capabilities without promoting old views or scheduled downloads',()=>{
  const id=`update_${'a'.repeat(32)}`,manual=view(),original=JSON.stringify(manual);
  for(const value of [manual,coexisting(),coexisting(reviewed(id)),coexisting(succeeded(id)),installationReview(id),scheduledInstallation(id),{...coexisting(),schedulingAvailable:false},{...coexisting(),schedulingAvailable:false,schedulingRevoked:true}])expect(validUpdateJobView(value,device,actor)).toBe(true);
  expect(JSON.stringify(manual)).toBe(original);expect(manual).not.toHaveProperty('backgroundScheduling');
  for(const patch of [{backgroundScheduling:false},{backgroundScheduling:undefined},{backgroundExecutor:undefined},{reusableJobs:undefined},{coordinated:undefined},{schedulingRevoked:true},{schedulingAvailable:'true'},{executorObservedAt:seconds-60},{downloadEnabled:undefined}])expect(validUpdateJobView({...coexisting(),...patch},device,actor)).toBe(false);
  expect(validUpdateJobView({...view(),schedulingAvailable:true},device,actor)).toBe(false);
  const schedule=scheduledInstallation(id).job!.schedule;
  for(const value of [coexisting(reviewed(id)),coexisting(approved(id)),coexisting(succeeded(id))])expect(validUpdateJobView({...value,job:{...value.job!,schedule}},device,actor)).toBe(false);
  expect(validUpdateJobView({...scheduledInstallation(id),job:{...scheduledInstallation(id).job!,purpose:'download'}},device,actor)).toBe(false);
  expect(validUpdateJobView({...coexisting(succeeded(id)),available:true},device,actor)).toBe(false);
  expect(validUpdateJobView({...coexisting(succeeded(id)),downloadAvailable:true},device,actor)).toBe(false);
 });
 it.each([
  {caps:['windows_update_download'],install:false,download:true,schedule:false},
  {caps:['windows_update_install'],install:true,download:false,schedule:false},
  {caps:['windows_update_download','windows_update_schedule'],install:false,download:true,schedule:false},
  {caps:['windows_update_install','windows_update_schedule'],install:true,download:false,schedule:true},
  {caps:['windows_update_install','windows_update_download'],install:true,download:true,schedule:false},
 ])('keeps operator affordances independent for $caps',async({caps,install,download,schedule})=>{
  enableCoexistence(['read',...caps]);await open();fireEvent.change(screen.getByRole('combobox'),{target:{value:`${selection.updateId}:3`}});
  expect(!!screen.queryByRole('button',{name:'Check readiness'})).toBe(install);expect(!!screen.queryByRole('button',{name:'Review download'})).toBe(download);expect(!!screen.queryByText('Revoke scheduling',{selector:'summary'})).toBe(schedule);expect(mutateRaw).not.toHaveBeenCalled();
 });
 it('does not promote scheduling-only permission into an update operation',async()=>{
  session.capabilities=['read','windows_update_schedule'];vi.mocked(useOperator).mockReturnValue({...session,theme:'light',logout:vi.fn(),setTheme:vi.fn()} as never);await open();expect(screen.getByText('Update installation is inactive.')).toBeInTheDocument();expect(request).not.toHaveBeenCalled();expect(mutateRaw).not.toHaveBeenCalled();
 });
 it.each(['en','de'] as const)('keeps a coexistence download manual with unchecked consent in %s',async locale=>{
  setLocale(locale,false);enableCoexistence();await open();await review(locale);const de=locale==='de';
  expect(screen.getByText(de?/Downloads bleiben manuell/:/Downloads stay manual/)).toBeVisible();
  expect(screen.queryByText(de?'Dieses Update planen':'Schedule this update',{selector:'summary'})).toBeNull();expect(document.querySelector('input[type="datetime-local"]')).toBeNull();
  const ack=screen.getByRole('checkbox'),approve=screen.getByRole('button',{name:de?'Download einmal freigeben':'Approve download once'});expect(ack).not.toBeChecked();expect(approve).toBeDisabled();
  fireEvent.click(ack);fireEvent.click(approve);await flush();expect(vi.mocked(mutateRaw).mock.calls.map(([path])=>path)).toEqual([`/devices/${device}/windows-update-jobs/request-download`,`/devices/${device}/windows-update-jobs/approve-download`]);
 });
 it.each(['en','de'] as const)('requires fresh separate installation and UTC acknowledgements in %s',async locale=>{
  setLocale(locale,false);enableCoexistence();resource.updates!.rows[0].downloaded=true;await open();const de=locale==='de';
  fireEvent.change(screen.getByRole('combobox'),{target:{value:`${selection.updateId}:3`}});expect(screen.queryByRole('button',{name:de?'Download prüfen':'Review download'})).toBeNull();fireEvent.click(screen.getByRole('button',{name:de?'Bereitschaft prüfen':'Check readiness'}));await flush();
  fireEvent.click(screen.getByText(de?'Dieses Update planen':'Schedule this update',{selector:'summary'}));fireEvent.change(screen.getByLabelText(de?'Beginn (UTC)':'Start (UTC)'),{target:{value:'2026-10-11T10:02'}});fireEvent.change(screen.getByLabelText(de?'Ende (UTC)':'End (UTC)'),{target:{value:'2026-10-11T10:07'}});
  const manual=screen.getByRole('checkbox',{name:de?/Revision und mögliche Unterbrechungen/:/revision and its possible interruption/}),scheduled=screen.getByRole('checkbox',{name:de?/vorausschauend/:/prospectively/}),approve=screen.getByRole('button',{name:de?'Geplantes Update einmal freigeben':'Approve scheduled update once'});
  expect(manual).not.toBeChecked();expect(scheduled).not.toBeChecked();expect(approve).toBeDisabled();fireEvent.click(manual);expect(scheduled).not.toBeChecked();expect(approve).toBeDisabled();fireEvent.click(manual);fireEvent.click(scheduled);fireEvent.click(approve);await flush();
  expect(vi.mocked(mutateRaw).mock.calls.map(([path])=>path)).toEqual([`/devices/${device}/windows-update-jobs/request`,`/devices/${device}/windows-update-jobs/schedule`]);expect(JSON.parse(vi.mocked(mutateRaw).mock.calls[1][1])).toMatchObject({acknowledged:true,startAt:seconds+120,endAt:seconds+420});expect(screen.queryByRole('button',{name:de?'Download prüfen':'Review download'})).toBeNull();
 });
 it('does not substitute download permission when installation scheduling authority is removed',async()=>{
  enableCoexistence();await open();fireEvent.change(screen.getByRole('combobox'),{target:{value:`${selection.updateId}:3`}});fireEvent.click(screen.getByRole('button',{name:'Check readiness'}));await flush();fireEvent.click(screen.getByText('Schedule this update',{selector:'summary'}));
  fireEvent.change(screen.getByLabelText('Start (UTC)'),{target:{value:'2026-10-11T10:02'}});fireEvent.change(screen.getByLabelText('End (UTC)'),{target:{value:'2026-10-11T10:07'}});fireEvent.click(screen.getByRole('checkbox',{name:/prospectively/}));session.capabilities=['read','windows_update_download','windows_update_schedule'];fireEvent.click(screen.getByRole('button',{name:'Approve scheduled update once'}));await flush();expect(mutateRaw).toHaveBeenCalledTimes(1);expect(screen.getByRole('alert')).toBeVisible();
 });
 it('keeps successful download retirement ahead of any new installation schedule',async()=>{
  enableCoexistence();const value=coexisting(succeeded(`update_${'b'.repeat(32)}`));vi.mocked(request).mockImplementation(async path=>structuredClone(path==='/auth/session'?session:value) as never);await open();expect(screen.getByText(/Downloads stay manual/)).toBeVisible();expect(screen.queryByRole('combobox')).toBeNull();expect(screen.queryByText('Schedule this update',{selector:'summary'})).toBeNull();expect(screen.getByRole('button',{name:'Review completed job'})).toBeEnabled();expect(mutateRaw).not.toHaveBeenCalled();
 });
 it('keeps the coexistence explanation out of the legacy manual profile',async()=>{await open();expect(screen.queryByText(/Downloads stay manual/)).toBeNull();expect(mutateRaw).not.toHaveBeenCalled()});
});
