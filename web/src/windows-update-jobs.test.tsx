import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { request, mutateRaw, AUTH_REQUIRED_EVENT } from './api';
import { useOperator, validOperatorSession } from './auth';
import { setLocale } from './i18n';
import { WindowsUpdateJobs, WindowsUpdateJobSession, updateScheduleWindow } from './windows-update-jobs';
import { validUpdateJobHistory, validUpdateJobView, type UpdateJobHistory, type UpdateJobView, type UpdatePreview } from './windows-update-jobs-types';
import type { WindowsInventoryResource } from './windows-inventory-resource';
vi.mock('./api',async original=>({...await original<typeof import('./api')>(),request:vi.fn(),mutateRaw:vi.fn()}));
vi.mock('./auth',async original=>({...await original<typeof import('./auth')>(),useOperator:vi.fn()}));
const now='2026-10-11T10:00:00Z',until='2026-10-11T11:00:00Z',seconds=Date.parse(now)/1000,device=`agent_${'1'.repeat(32)}`,digest=`sha256:${'3'.repeat(64)}`,selection={updateId:'11111111-2222-3333-4444-555555555555',revision:3};
let actor=`operator_${'2'.repeat(32)}`;
const resource={view:{deviceId:device},updates:{rows:[{...selection,title:'Cached fixture update'}]}} as unknown as WindowsInventoryResource;
const view=():UpdateJobView=>({version:'tracebolt.windows-selected-update-job.v1',deviceId:device,serverNow:seconds,available:true,reason:'ready',job:null});
const preview=(id:string):UpdatePreview=>({id,actorId:actor,binding:{managerId:`manager_${'4'.repeat(32)}`,deviceId:device,incarnationDigest:digest,executorId:`executor_${'5'.repeat(32)}`,executorKeyId:`sha256:${'8'.repeat(64)}`,grantId:`grant_${'6'.repeat(32)}`,keyId:digest},readiness:{selection,capturedAt:seconds,software:'yes',installed:'no',hidden:'no',downloaded:'yes',eulaAccepted:'yes',canRequestUserInput:'no',canRequireSource:'no',requiresNetwork:'no',bundledCount:0,installerBusy:'no',rebootRequiredBefore:'no',rebootBehavior:'can',offlineVerified:'yes'},createdAt:seconds,expiresAt:seconds+60,digest});
const previewView=(id:string):UpdateJobView=>({...view(),job:{id,selection,state:'preview',reason:'ready',preview:preview(id),result:null}});
const approved=(id:string):UpdateJobView=>({...view(),available:false,reason:'job_pending_or_intervention',job:{id,selection,state:'approved',reason:'ready',preview:null,result:null}});
const session={mode:'lan',transport:'https',insecureTestMode:false,transportWarning:null,authenticationRequired:true,authenticated:true,csrfToken:'csrf',serverNow:now,expiresAt:until,expiresInSeconds:3600,loginMode:'named',actorId:actor,capabilities:['read','windows_update_install']};
const flush=()=>act(async()=>{});
const open=async()=>{const ui=render(<WindowsUpdateJobs resource={resource}/>);await flush();return ui};
const review=async()=>{fireEvent.change(screen.getByRole('combobox'),{target:{value:`${selection.updateId}:3`}});fireEvent.click(screen.getByRole('button',{name:'Check readiness'}));await flush()};
beforeEach(()=>{actor=`operator_${crypto.randomUUID().replaceAll('-','')}`;session.actorId=actor;vi.useFakeTimers();vi.setSystemTime(now);setLocale('en',false);vi.mocked(useOperator).mockReturnValue({...session,mode:'lan',theme:'light',logout:vi.fn(),setTheme:vi.fn(),capabilities:['read','windows_update_install'],loginMode:'named'});vi.mocked(request).mockReset().mockImplementation(async path=>structuredClone(path==='/auth/session'?session:view()) as never);vi.mocked(mutateRaw).mockReset().mockImplementation(async(path,body,_headers,_signal,_cap,beforeSend)=>{if(beforeSend&&!beforeSend())throw new Error('Canceled before send');const input=JSON.parse(body);return structuredClone(path.endsWith('/request')?previewView(input.requestId):approved(input.previewId)) as never})});
afterEach(()=>{cleanup();vi.useRealTimers();vi.restoreAllMocks()});
describe('selected cached Windows update jobs',()=>{
 it('reviews exact GUID/revision and requires unchecked one-time approval',async()=>{await open();await review();const approve=screen.getByRole('button',{name:'Approve this update once'});expect(approve).toBeDisabled();expect(screen.getByRole('checkbox')).not.toBeChecked();fireEvent.click(screen.getByRole('checkbox'));fireEvent.click(approve);fireEvent.click(approve);await flush();expect(mutateRaw).toHaveBeenCalledTimes(2);const req=JSON.parse(vi.mocked(mutateRaw).mock.calls[0][1]);expect(req).toMatchObject(selection);expect(req.requestId).toMatch(/^update_[a-f0-9]{32}$/);expect(JSON.parse(vi.mocked(mutateRaw).mock.calls[1][1])).toEqual({previewId:req.requestId,previewDigest:digest,acknowledged:true});expect(screen.getByRole('status')).toHaveTextContent('awaiting one-time claim');expect(screen.queryByRole('checkbox')).toBeNull()});
 it.each(['en','de'] as const)('distinguishes readiness from setup without obscuring consent in %s',async locale=>{
  setLocale(locale,false);const de=locale==='de';await open();
  fireEvent.change(screen.getByRole('combobox'),{target:{value:`${selection.updateId}:3`}});
  fireEvent.click(screen.getByRole('button',{name:de?'Bereitschaft prüfen':'Check readiness'}));await flush();
  const readiness=screen.getByText(de?'Bereitschaftsdetails':'Readiness details',{selector:'summary'});
  const setup=screen.getByText(de?'Update-Einrichtung & Grenzen':'Update setup & limits',{selector:'summary'});
  expect(readiness.closest('details')).not.toHaveAttribute('open');expect(setup.closest('details')).not.toHaveAttribute('open');
  expect(screen.queryByText(de?'Installationsdetails':'Installation details')).toBeNull();
  expect(screen.getByText(de?/Prüfung gültig bis/:/Review expires/)).toBeVisible();
  expect(screen.getByRole('checkbox',{name:de?/mögliche Unterbrechungen/:/possible interruption/})).toBeVisible();
  expect(screen.getByRole('checkbox')).not.toBeChecked();expect(screen.getByRole('button',{name:de?'Dieses Update einmal freigeben':'Approve this update once'})).toBeDisabled();
  fireEvent.click(readiness);expect(screen.getByText(de?/Lizenz bereits angenommen/:/license already accepted/)).toBeVisible();
  fireEvent.click(setup);expect(screen.getByText(de?/Cache-Inventar belegt keine Installationsbereitschaft/:/Cached inventory does not establish installation readiness/)).toBeVisible();
  expect(mutateRaw).toHaveBeenCalledTimes(1);
 });
 it.each(['en','de'] as const)('keeps reported-result limits and uncertainty outside collapsed details in %s',async locale=>{
  setLocale(locale,false);const de=locale==='de',id=`update_${'7'.repeat(32)}`;
  const result:UpdateJobView={...approved(id),job:{...approved(id).job!,state:'complete',result:{jobId:id,envelopeDigest:digest,attempted:true,outcome:'uncertain',operationResult:3,hresult:0,rebootRequired:'unknown',completedAt:seconds}}};
  vi.mocked(request).mockImplementation(async path=>structuredClone(path==='/auth/session'?session:result) as never);await open();
  expect(screen.getByText(de?/Die Antwort ist unbestätigt/:/The response is unconfirmed/)).toBeVisible();
  expect(screen.getByText(de?/Es belegt keine vollständige Patch-Abdeckung/:/does not establish whole-device patch coverage/)).toBeVisible();
  expect(screen.getByText(de?'Auftragsdetails':'Job details',{selector:'summary'}).closest('details')).not.toHaveAttribute('open');
  expect(screen.queryByRole('checkbox')).toBeNull();expect(mutateRaw).not.toHaveBeenCalled();
 });
 it.each(['windows_service_control','execute_updates'] as const)('never promotes %s permission',async capability=>{vi.mocked(useOperator).mockReturnValue({...vi.mocked(useOperator)(),capabilities:['read',capability]} as ReturnType<typeof useOperator>);await open();expect(request).not.toHaveBeenCalled();expect(mutateRaw).not.toHaveBeenCalled();expect(screen.getByText('Update installation is inactive.')).toBeInTheDocument()});
 it.each(['blur','pagehide','popstate','hashchange',AUTH_REQUIRED_EVENT])('drops review on %s',async event=>{await open();await review();act(()=>window.dispatchEvent(new Event(event)));expect(screen.queryByRole('checkbox')).toBeNull();expect(mutateRaw).toHaveBeenCalledTimes(1)});
 it('never retries uncertain approval or revives review from status',async()=>{await open();await review();const id=JSON.parse(vi.mocked(mutateRaw).mock.calls[0][1]).requestId;vi.mocked(mutateRaw).mockRejectedValueOnce(new Error('lost response'));fireEvent.click(screen.getByRole('checkbox'));fireEvent.click(screen.getByRole('button',{name:'Approve this update once'}));await flush();expect(screen.getByRole('alert')).toHaveTextContent('unconfirmed');vi.mocked(request).mockImplementation(async path=>structuredClone(path==='/auth/session'?session:previewView(id)) as never);fireEvent.click(screen.getByRole('button',{name:'Read saved status'}));await flush();expect(screen.queryByRole('checkbox')).toBeNull();expect(mutateRaw).toHaveBeenCalledTimes(2)});
 it('dismisses and expires review without approval',async()=>{await open();await review();const id=JSON.parse(vi.mocked(mutateRaw).mock.calls[0][1]).requestId;fireEvent.click(screen.getByRole('button',{name:'Dismiss review'}));expect(screen.queryByRole('checkbox')).toBeNull();vi.mocked(request).mockImplementation(async path=>structuredClone(path==='/auth/session'?session:{...previewView(id),available:false,reason:'job_pending_or_intervention'}) as never);fireEvent.click(screen.getByRole('button',{name:'Read saved status'}));await flush();vi.mocked(mutateRaw).mockResolvedValueOnce(previewView(id));fireEvent.click(screen.getByRole('button',{name:'Check readiness'}));await flush();await act(async()=>vi.advanceTimersByTime(61000));expect(screen.queryByRole('checkbox')).toBeNull();expect(mutateRaw).toHaveBeenCalledTimes(2)});
 it('rejects inferred readiness, changed revision, identity and execution envelope',()=>{const v=previewView(`update_${'7'.repeat(32)}`);expect(validUpdateJobView(v,device,actor)).toBe(true);expect(validUpdateJobView({...v,envelope:'bad'},device,actor)).toBe(false);for(const change of [{eulaAccepted:'unknown'},{bundledCount:1},{requiresNetwork:'yes'},{selection:{...selection,revision:4}}]){const altered=structuredClone(v);Object.assign(altered.job!.preview!.readiness,change);expect(validUpdateJobView(altered,device,actor)).toBe(false)};expect(validUpdateJobView(v,`agent_${'9'.repeat(32)}`,actor)).toBe(false)});
 it.each(['en','de'] as const)('keeps inactive details compact and collapsed in %s',async locale=>{setLocale(locale,false);vi.mocked(request).mockImplementation(async path=>structuredClone(path==='/auth/session'?session:{...view(),available:false,reason:'executor_not_configured'}) as never);const {container}=await open();expect(screen.queryByRole('combobox')).toBeNull();expect(screen.queryByRole('checkbox')).toBeNull();expect(screen.getByText(locale==='de'?'Updateinstallation ist inaktiv.':'Update installation is inactive.')).toBeInTheDocument();expect(container.querySelector('details')).not.toHaveAttribute('open');const guide=screen.getByRole('link',{name:locale==='de'?'Einrichtungsanleitung':'Setup guide',hidden:true});expect(guide).toHaveAttribute('href','https://github.com/storminator89/Tracebolt/blob/main/docs/windows-selected-update-setup.md');expect(guide.closest('details')).not.toHaveAttribute('open');expect(mutateRaw).not.toHaveBeenCalled()});
});

it('requires explicit reopening of asynchronously reported readiness',async()=>{
 await open();let id='';
 vi.mocked(mutateRaw).mockImplementationOnce(async(_path,body)=>{id=JSON.parse(body).requestId;return {...view(),available:false,reason:'job_pending_or_intervention',job:{id,selection,state:'requested',reason:'readiness_pending',preview:null,result:null}} as never});
 await review();expect(screen.getByRole('status')).toHaveTextContent('Readiness pending');expect(screen.queryByRole('checkbox')).toBeNull();
 vi.mocked(request).mockImplementation(async path=>structuredClone(path==='/auth/session'?session:{...previewView(id),available:false,reason:'job_pending_or_intervention'}) as never);
 fireEvent.click(screen.getByRole('button',{name:'Read saved status'}));await flush();expect(screen.queryByRole('checkbox')).toBeNull();
 vi.mocked(mutateRaw).mockResolvedValueOnce({...previewView(id),available:false,reason:'job_pending_or_intervention'});
 fireEvent.click(screen.getByRole('button',{name:'Check readiness'}));await flush();expect(screen.getByRole('checkbox')).not.toBeChecked();
 expect(JSON.parse(vi.mocked(mutateRaw).mock.calls[1][1])).toEqual({requestId:id});expect(vi.mocked(mutateRaw).mock.calls[1][0]).toMatch(/\/preview$/);
});

const historyView=(id:string):UpdateJobHistory=>({...view(),version:'tracebolt.windows-selected-update-history.v1',remainingCapacity:31,jobs:[{...approved(id).job!,requestedAt:seconds,approvedAt:seconds,claimedAt:0}]} as unknown as UpdateJobHistory);
function validHistory(id:string):UpdateJobHistory { const h=historyView(id); delete (h.jobs[0] as unknown as Record<string,unknown>).preview; delete (h as unknown as Record<string,unknown>).job; return h; }
it('reads only a tracked exact ID after a lost request and never resubmits it on remount',async()=>{
 const ui=await open();vi.mocked(mutateRaw).mockRejectedValueOnce(new Error('lost request'));await review();const id=JSON.parse(vi.mocked(mutateRaw).mock.calls[0][1]).requestId;
 ui.unmount();vi.mocked(request).mockImplementation(async path=>structuredClone(path==='/auth/session'?session:approved(id)) as never);await open();
 expect(request).toHaveBeenCalledWith(`/devices/${device}/windows-update-jobs?jobId=${id}`,expect.anything(),16384);expect(mutateRaw).toHaveBeenCalledTimes(1);expect(screen.getByRole('status')).toHaveTextContent('awaiting one-time claim');
});
it('keeps a lost approval blocked after GET returns a preview, including across remount',async()=>{
 const ui=await open();await review();const id=JSON.parse(vi.mocked(mutateRaw).mock.calls[0][1]).requestId;vi.mocked(mutateRaw).mockRejectedValueOnce(new Error('lost approval'));fireEvent.click(screen.getByRole('checkbox'));fireEvent.click(screen.getByRole('button',{name:'Approve this update once'}));await flush();ui.unmount();
 vi.mocked(request).mockImplementation(async path=>structuredClone(path==='/auth/session'?session:previewView(id)) as never);await open();expect(screen.queryByRole('checkbox')).toBeNull();expect(screen.queryByRole('button',{name:'Check readiness'})).toBeNull();expect(screen.getByRole('alert')).toHaveTextContent('unconfirmed');expect(mutateRaw).toHaveBeenCalledTimes(2);
});
it('rejects a newer unrelated job instead of adopting it for exact reconciliation',async()=>{
 await open();vi.mocked(mutateRaw).mockRejectedValueOnce(new Error('lost request'));await review();vi.mocked(request).mockImplementation(async path=>structuredClone(path==='/auth/session'?session:approved(`update_${'9'.repeat(32)}`)) as never);fireEvent.click(screen.getByRole('button',{name:'Read saved status'}));await flush();expect(screen.getByRole('alert')).toHaveTextContent('unconfirmed');expect(screen.queryByRole('checkbox')).toBeNull();expect(mutateRaw).toHaveBeenCalledTimes(1);
});
it('opens bounded saved summaries by exact ID without a POST',async()=>{
 const id=`update_${'7'.repeat(32)}`,history=validHistory(id);expect(validUpdateJobHistory(history,device,actor)).toBe(true);
 vi.mocked(request).mockImplementation(async path=>structuredClone(path==='/auth/session'?session:path.endsWith('?history=1')?history:path.includes('?jobId=')?approved(id):view()) as never);await open();fireEvent.click(screen.getByText('Saved update jobs',{selector:'summary'}));fireEvent.click(screen.getByRole('button',{name:'Read saved jobs'}));await flush();expect(screen.getByText('Lifetime approvals remaining: 31/32')).toBeInTheDocument();fireEvent.click(screen.getByRole('button',{name:`Open saved job · ${id}`}));await flush();expect(request).toHaveBeenCalledWith(`/devices/${device}/windows-update-jobs?jobId=${id}`,expect.anything(),16384);expect(mutateRaw).not.toHaveBeenCalled();expect(screen.queryByRole('checkbox')).toBeNull();
});
it('rejects history envelopes, duplicate jobs, oversized lists and invented timestamps',()=>{
 const id=`update_${'7'.repeat(32)}`,h=validHistory(id);expect(validUpdateJobHistory(h,device,actor)).toBe(true);expect(validUpdateJobHistory({...h,permit:'bad'},device,actor)).toBe(false);expect(validUpdateJobHistory({...h,jobs:[...h.jobs,...h.jobs]},device,actor)).toBe(false);expect(validUpdateJobHistory({...h,jobs:Array(34).fill(h.jobs[0])},device,actor)).toBe(false);expect(validUpdateJobHistory({...h,jobs:[{...h.jobs[0],preview:preview(id)}]},device,actor)).toBe(false);expect(validUpdateJobHistory({...h,jobs:[{...h.jobs[0],claimedAt:seconds-1}]},device,actor)).toBe(false);
});
it('can select a fresh worklist job after an older completed result and then freezes it',async()=>{
 const id=`update_${'7'.repeat(32)}`,old={...view(),job:{...approved(id).job!,state:'complete',result:{jobId:id,envelopeDigest:digest,attempted:true,outcome:'succeeded',operationResult:2,hresult:0,rebootRequired:'no',completedAt:seconds}}};
 vi.mocked(request).mockImplementation(async path=>structuredClone(path==='/auth/session'?session:old) as never);render(<WindowsUpdateJobSession device={device} actor={actor} sessionKey={until} rows={resource.updates!.rows} oneJob/>);await flush();expect(screen.getByRole('combobox')).toBeInTheDocument();await review();expect(screen.getByRole('checkbox')).not.toBeChecked();fireEvent.click(screen.getByRole('button',{name:'Dismiss review'}));expect(screen.queryByRole('combobox')).toBeNull();
});
it('rechecks preview expiry after a slow session read before sending approval',async()=>{
 await open();await review();let resolve!:(value:unknown)=>void;vi.mocked(request).mockImplementationOnce(()=>new Promise(r=>{resolve=r}) as never);fireEvent.click(screen.getByRole('checkbox'));fireEvent.click(screen.getByRole('button',{name:'Approve this update once'}));await act(async()=>resolve({...session,serverNow:new Date((seconds+61)*1000).toISOString()}));expect(mutateRaw).toHaveBeenCalledTimes(1);expect(screen.queryByRole('checkbox')).toBeNull();expect(screen.getByRole('alert')).toHaveTextContent('unavailable or changed');
});
it('opening another saved result cannot replace a frozen planned selection or restore its review',async()=>{
 const planned=`update_${'7'.repeat(32)}`,old=`update_${'8'.repeat(32)}`,history=validHistory(old),receipt=vi.fn();vi.mocked(request).mockImplementation(async path=>structuredClone(path==='/auth/session'?session:path.endsWith('?history=1')?history:path.endsWith(old)?previewView(old):previewView(planned)) as never);render(<WindowsUpdateJobSession device={device} actor={actor} sessionKey={until} rows={resource.updates!.rows} initialJobId={planned} oneJob onReceipt={receipt}/>);await flush();fireEvent.click(screen.getByText('Saved update jobs',{selector:'summary'}));fireEvent.click(screen.getByRole('button',{name:'Read saved jobs'}));await flush();fireEvent.click(screen.getByRole('button',{name:`Open saved job · ${old}`}));await flush();expect(screen.queryByRole('button',{name:'Check readiness'})).toBeNull();expect(screen.queryByRole('checkbox')).toBeNull();expect(receipt.mock.calls.every(([value])=>value.jobId===planned)).toBe(true);fireEvent.click(screen.getByRole('button',{name:'Read saved status'}));await flush();expect(vi.mocked(request).mock.calls.at(-1)?.[0]).toBe(`/devices/${device}/windows-update-jobs?jobId=${planned}`);expect(mutateRaw).not.toHaveBeenCalled();
});
it('keeps lost write A as the reconciliation anchor after browsing saved job B and remounting',async()=>{
 const ui=await open();vi.mocked(mutateRaw).mockRejectedValueOnce(new Error('lost request A'));await review();const a=JSON.parse(vi.mocked(mutateRaw).mock.calls[0][1]).requestId,b=`update_${'8'.repeat(32)}`,history=validHistory(b);
 vi.mocked(request).mockImplementation(async path=>structuredClone(path==='/auth/session'?session:path.endsWith('?history=1')?history:path.endsWith(b)?approved(b):approved(a)) as never);
 fireEvent.click(screen.getByText('Saved update jobs',{selector:'summary'}));fireEvent.click(screen.getByRole('button',{name:'Read saved jobs'}));await flush();fireEvent.click(screen.getByRole('button',{name:`Open saved job · ${b}`}));await flush();expect(screen.getByRole('alert')).toHaveTextContent('unconfirmed');expect(screen.queryByRole('checkbox')).toBeNull();ui.unmount();await open();expect(vi.mocked(request).mock.calls.at(-1)?.[0]).toBe(`/devices/${device}/windows-update-jobs?jobId=${a}`);expect(mutateRaw).toHaveBeenCalledTimes(1);
});
it('never adopts historical B as a fresh worklist plan while lost write A is unresolved',async()=>{
 const ui=await open();vi.mocked(mutateRaw).mockRejectedValueOnce(new Error('lost request A'));await review();const a=JSON.parse(vi.mocked(mutateRaw).mock.calls[0][1]).requestId,b=`update_${'8'.repeat(32)}`,history=validHistory(b);ui.unmount();const receipt=vi.fn();vi.mocked(request).mockImplementation(async path=>{if(path==='/auth/session')return structuredClone(session) as never;if(path.endsWith('?history=1'))return structuredClone(history) as never;if(path.endsWith(b))return structuredClone(approved(b)) as never;throw new Error('A unavailable')});
 const list=render(<WindowsUpdateJobSession device={device} actor={actor} sessionKey={until} rows={resource.updates!.rows} oneJob onReceipt={receipt}/>);await flush();fireEvent.click(screen.getByText('Saved update jobs',{selector:'summary'}));fireEvent.click(screen.getByRole('button',{name:'Read saved jobs'}));await flush();fireEvent.click(screen.getByRole('button',{name:`Open saved job · ${b}`}));await flush();expect(receipt).not.toHaveBeenCalled();list.unmount();await open();expect(vi.mocked(request).mock.calls.at(-1)?.[0]).toBe(`/devices/${device}/windows-update-jobs?jobId=${a}`);expect(mutateRaw).toHaveBeenCalledTimes(1);
});

const scheduled=(id:string):UpdateJobView=>({...approved(id),schedulingAvailable:true,job:{...approved(id).job!,state:'scheduled',reason:'schedule_waiting',schedule:{version:'tracebolt.windows-selected-update-schedule.v1',digest:`sha256:${'a'.repeat(64)}`,approvedAt:seconds,startAt:seconds+120,endAt:seconds+420,permitIssuedAt:0,revoked:false}}});
const scheduleSession=()=>({...session,capabilities:['read','windows_update_install','windows_update_schedule']});
function enableScheduling(background=false){
 const profile=(value:UpdateJobView)=>background?backgroundScheduleView(value,true):value;
 vi.mocked(request).mockImplementation(async path=>structuredClone(path==='/auth/session'?scheduleSession():profile({...view(),schedulingAvailable:true})) as never);
 vi.mocked(mutateRaw).mockImplementation(async(path,body,_headers,_signal,_cap,beforeSend)=>{if(beforeSend&&!beforeSend())throw new Error('Canceled before send');const input=JSON.parse(body);return structuredClone(profile(path.endsWith('/request')?{...previewView(input.requestId),schedulingAvailable:true}:scheduled(input.previewId))) as never});
}
async function scheduleReview(locale:'en'|'de'='en'){
 setLocale(locale,false);const de=locale==='de';await open();
 fireEvent.change(screen.getByRole('combobox'),{target:{value:`${selection.updateId}:3`}});fireEvent.click(screen.getByRole('button',{name:de?'Bereitschaft prüfen':'Check readiness'}));await flush();
 fireEvent.click(screen.getByText(de?'Dieses Update planen':'Schedule this update',{selector:'summary'}));
 fireEvent.change(screen.getByLabelText(de?'Beginn (UTC)':'Start (UTC)'),{target:{value:'2026-10-11T10:02'}});
 fireEvent.change(screen.getByLabelText(de?'Ende (UTC)':'End (UTC)'),{target:{value:'2026-10-11T10:07'}});
}
it.each(['en','de'] as const)('requires separate prospective consent and sends one exact UTC schedule in %s',async locale=>{
 enableScheduling();await scheduleReview(locale);const de=locale==='de',ack=screen.getByRole('checkbox',{name:de?/vorausschauend für dieses UTC/:/prospectively for this UTC/}),button=screen.getByRole('button',{name:de?'Geplantes Update einmal freigeben':'Approve scheduled update once'});
 expect(ack).not.toBeChecked();expect(button).toBeDisabled();expect(screen.getByRole('button',{name:de?'Dieses Update einmal freigeben':'Approve this update once'})).toBeDisabled();
 fireEvent.click(ack);fireEvent.click(button);fireEvent.click(button);await flush();expect(mutateRaw).toHaveBeenCalledTimes(2);
 const id=JSON.parse(vi.mocked(mutateRaw).mock.calls[0][1]).requestId;
 expect(vi.mocked(mutateRaw).mock.calls[1][0]).toMatch(/\/schedule$/);expect(JSON.parse(vi.mocked(mutateRaw).mock.calls[1][1])).toEqual({previewId:id,previewDigest:digest,acknowledged:true,startAt:seconds+120,endAt:seconds+420});
 expect(screen.getByText(de?/Genehmigtes UTC-Zeitfenster/:/Approved UTC window/)).toHaveTextContent('2026-10-11 10:02:00 UTC');
 expect(screen.getByRole('button',{name:de?'Diese Planung abbrechen':'Cancel this schedule'})).toBeEnabled();expect(screen.getByText(de?/Abbruch und einmalige Abholung/:/Cancellation can race/)).toBeVisible();
});
it('never infers scheduling from manual install permission or the immediate approval checkbox',async()=>{
 await open();await review();expect(screen.queryByText('Schedule this update',{selector:'summary'})).toBeNull();expect(screen.queryByRole('button',{name:'Approve scheduled update once'})).toBeNull();
});
it.each(['blur','pagehide','popstate','hashchange',AUTH_REQUIRED_EVENT])('drops prospective acknowledgement on %s without sending a schedule',async event=>{
 enableScheduling();await scheduleReview();fireEvent.click(screen.getByRole('checkbox',{name:/prospectively for this UTC/}));act(()=>window.dispatchEvent(new Event(event)));expect(screen.queryByRole('button',{name:'Approve scheduled update once'})).toBeNull();expect(mutateRaw).toHaveBeenCalledTimes(1);
});
it('reconciles a lost schedule only through exact saved ID, selection and UTC window across remount',async()=>{
 enableScheduling();await scheduleReview();const id=JSON.parse(vi.mocked(mutateRaw).mock.calls[0][1]).requestId;vi.mocked(mutateRaw).mockRejectedValueOnce(new Error('lost schedule'));
 fireEvent.click(screen.getByRole('checkbox',{name:/prospectively for this UTC/}));fireEvent.click(screen.getByRole('button',{name:'Approve scheduled update once'}));await flush();expect(screen.getByRole('alert')).toHaveTextContent('unconfirmed');cleanup();
 const wrong=scheduled(id);wrong.job!.schedule!.endAt+=60;
 vi.mocked(request).mockImplementation(async path=>structuredClone(path==='/auth/session'?scheduleSession():wrong) as never);await open();expect(screen.getByRole('alert')).toHaveTextContent('unconfirmed');expect(screen.getByRole('button',{name:'Cancel this schedule'})).toBeDisabled();
 vi.mocked(request).mockImplementation(async path=>structuredClone(path==='/auth/session'?scheduleSession():scheduled(id)) as never);fireEvent.click(screen.getByRole('button',{name:'Read saved status'}));await flush();expect(screen.queryByRole('alert')).toBeNull();expect(screen.getByRole('button',{name:'Cancel this schedule'})).toBeEnabled();expect(mutateRaw).toHaveBeenCalledTimes(2);
 expect(vi.mocked(request).mock.calls.at(-1)?.[0]).toBe(`/devices/${device}/windows-update-jobs?jobId=${id}`);
});
it('cancels only the exact schedule digest and never retries a lost cancel',async()=>{
 const id=`update_${'7'.repeat(32)}`;vi.mocked(request).mockImplementation(async path=>structuredClone(path==='/auth/session'?scheduleSession():scheduled(id)) as never);await open();vi.mocked(mutateRaw).mockRejectedValueOnce(new Error('lost cancel'));fireEvent.click(screen.getByRole('button',{name:'Cancel this schedule'}));await flush();
 expect(JSON.parse(vi.mocked(mutateRaw).mock.calls[0][1])).toEqual({scheduleId:id,scheduleDigest:scheduled(id).job!.schedule!.digest});
 cleanup();const canceled=scheduled(id);canceled.job!.state='schedule_canceled';canceled.job!.reason='schedule_canceled';canceled.available=true;canceled.reason='ready';vi.mocked(request).mockImplementation(async path=>structuredClone(path==='/auth/session'?scheduleSession():canceled) as never);await open();expect(screen.getByText('Schedule canceled before claim')).toBeVisible();expect(screen.queryByRole('alert')).toBeNull();expect(mutateRaw).toHaveBeenCalledTimes(1);
});
it('requires explicit saved revocation evidence after an uncertain revoke, including without a job',async()=>{
 enableScheduling();await open();fireEvent.click(screen.getByText('Revoke scheduling',{selector:'summary'}));expect(screen.getByRole('button',{name:'Revoke scheduling for this grant'})).toBeDisabled();fireEvent.click(screen.getByRole('checkbox',{name:/Permanently revoke scheduling/}));vi.mocked(mutateRaw).mockRejectedValueOnce(new Error('lost revoke'));fireEvent.click(screen.getByRole('button',{name:'Revoke scheduling for this grant'}));await flush();
 expect(JSON.parse(vi.mocked(mutateRaw).mock.calls[0][1])).toEqual({acknowledged:true});vi.mocked(request).mockImplementation(async path=>structuredClone(path==='/auth/session'?scheduleSession():view()) as never);fireEvent.click(screen.getByRole('button',{name:'Read saved status'}));await flush();expect(screen.getByRole('alert')).toHaveTextContent('unconfirmed');
 vi.mocked(request).mockImplementation(async path=>structuredClone(path==='/auth/session'?scheduleSession():{...view(),schedulingRevoked:true}) as never);fireEvent.click(screen.getByRole('button',{name:'Read saved status'}));await flush();expect(screen.getByText('Scheduling was revoked for this original grant.')).toBeVisible();expect(screen.queryByRole('alert')).toBeNull();expect(mutateRaw).toHaveBeenCalledTimes(1);
});
it('strictly validates UTC input, schedule metadata and unchanged manual schemas',()=>{
 expect(updateScheduleWindow('2026-10-11T10:02','2026-10-11T10:07',seconds)).toEqual({startAt:seconds+120,endAt:seconds+420});
 for(const [start,end] of [['2026-10-11T10:00','2026-10-11T10:07'],['2026-10-12T10:01','2026-10-12T10:07'],['2026-10-11T10:02','2026-10-11T11:03'],['2026-02-30T10:02','2026-02-30T10:07'],['2026-10-11T10:02Z','2026-10-11T10:07']])expect(updateScheduleWindow(start,end,seconds)).toBeNull();
 const id=`update_${'7'.repeat(32)}`,good=scheduled(id);expect(validUpdateJobView(good,device,actor)).toBe(true);expect(validUpdateJobView({...view(),schedulingRevoked:true,schedulingAvailable:true},device,actor)).toBe(false);
 for(const fields of [{endAt:seconds+121},{startAt:seconds+86401},{permitIssuedAt:seconds+120},{signature:'forbidden'},{revoked:'yes'}]){const bad=structuredClone(good);Object.assign(bad.job!.schedule!,fields);expect(validUpdateJobView(bad,device,actor)).toBe(false)}
 const manual={...good,job:{...good.job!,schedule:undefined}};delete manual.job.schedule;expect(validUpdateJobView(manual,device,actor)).toBe(false);
});

it('recognizes only the separately granted scheduling capability in session metadata',()=>{
 expect(validOperatorSession(scheduleSession())).toBe(true);
 expect(validOperatorSession({...scheduleSession(),capabilities:['read','plan_updates','execute_updates','restart_service','manage_alarms','manage_application_checks','windows_service_control','windows_update_install','windows_update_schedule']})).toBe(true);
 expect(validOperatorSession({...scheduleSession(),capabilities:['read','windows_update_schedule','windows_update_schedule']})).toBe(false);
 expect(validOperatorSession({...scheduleSession(),capabilities:['read','schedule_anything']})).toBe(false);
});
it('rechecks scheduling permission and original preview expiry before posting',async()=>{
 enableScheduling();await scheduleReview();vi.mocked(request).mockResolvedValueOnce(session as never);
 fireEvent.click(screen.getByRole('checkbox',{name:/prospectively for this UTC/}));fireEvent.click(screen.getByRole('button',{name:'Approve scheduled update once'}));await flush();expect(mutateRaw).toHaveBeenCalledTimes(1);expect(screen.getByRole('alert')).toHaveTextContent('unavailable or changed');
});
it('validates triggered history without conflating original approval with later readiness',()=>{
 const id=`update_${'7'.repeat(32)}`,h=validHistory(id),item=scheduled(id).job!;
 h.serverNow=seconds+125;h.jobs=[{id,selection,state:'requested',reason:'readiness_pending',result:null,requestedAt:seconds+120,approvedAt:0,claimedAt:0,schedule:item.schedule}];
 expect(validUpdateJobHistory(h,device,actor)).toBe(true);
 expect(validUpdateJobHistory({...h,jobs:[{...h.jobs[0],approvedAt:seconds}]},device,actor)).toBe(false);
 expect(validUpdateJobHistory({...h,jobs:[{...h.jobs[0],state:'approved',reason:'ready',approvedAt:seconds,schedule:{...item.schedule!,permitIssuedAt:seconds+120}}]},device,actor)).toBe(true);
 expect(validUpdateJobHistory({...h,jobs:[{...h.jobs[0],approvedAt:seconds+1}]},device,actor)).toBe(false);
 const bad=scheduled(id);bad.job!.state='claimed';expect(validUpdateJobView(bad,device,actor)).toBe(false);
});

it.each(['en','de'] as const)('mounts compact coordinated owner and preserves the original update result in %s',async locale=>{
 setLocale(locale,false);const id=`update_${'7'.repeat(32)}`,owner=`transfer_${'8'.repeat(32)}`;
 let coordinated:UpdateJobView={...approved(id),coordinated:true,mutationCapturedAt:seconds,mutation:{active:true,blocked:true,domain:'managed_msi',jobId:owner,phase:'dispatch_intent',recovery:'intervention_required',revision:'7',retained:1},job:{...approved(id).job!,state:'complete',result:{jobId:id,envelopeDigest:digest,attempted:true,outcome:'uncertain',operationResult:3,hresult:0,rebootRequired:'unknown',completedAt:seconds}}};
 vi.mocked(request).mockImplementation(async path=>structuredClone(path==='/auth/session'?session:coordinated) as never);await open();const shared=document.querySelector('.windows-mutation-status')!;expect(shared).toHaveTextContent(locale==='de'?'Blockiert durch MSI':'Blocked by MSI');expect(shared.querySelector('[role=status]')).not.toHaveTextContent(owner);expect(shared.querySelector('details')).not.toHaveAttribute('open');expect(screen.getByText(locale==='de'?/Die Antwort ist unbestätigt/:/The response is unconfirmed/)).toBeVisible();
 coordinated={...coordinated,mutation:{active:true,blocked:false,phase:'idle',revision:'9',retained:1}};fireEvent.click(screen.getByRole('button',{name:locale==='de'?'Gespeicherten Status lesen':'Read saved status'}));await flush();expect(document.querySelector('.windows-mutation-status')).toHaveTextContent(locale==='de'?'Kein Besitzer gespeichert':'No owner saved');expect(screen.getByText(locale==='de'?/Die Antwort ist unbestätigt/:/The response is unconfirmed/)).toBeVisible();expect(mutateRaw).not.toHaveBeenCalled();
});
it('does not invite coordinated update approval without fresh idle evidence',async()=>{
 vi.mocked(mutateRaw).mockImplementation(async(_path,body)=>({...previewView(JSON.parse(body).requestId),coordinated:true}) as never);await open();await review();fireEvent.click(screen.getByRole('checkbox'));expect(screen.getByRole('button',{name:'Approve this update once'})).toBeDisabled();expect(document.body).toHaveTextContent('Shared status awaits the executor.');expect(mutateRaw).toHaveBeenCalledTimes(1);
});

const backgroundView=(value:UpdateJobView=view(),recent=false):UpdateJobView=>({...value,coordinated:true,backgroundExecutor:true,executorAvailability:recent?'verified_recent':'unknown',...(recent?{executorObservedAt:seconds}:{}),mutationCapturedAt:seconds,mutation:{active:true,blocked:false,phase:'idle',revision:'9',retained:1}});
it('strictly validates background evidence without promoting configuration or changing old views',()=>{
 expect(validUpdateJobView(view(),device,actor)).toBe(true);expect(validUpdateJobView(backgroundView(),device,actor)).toBe(true);
 const recent=backgroundView(view(),true);expect(validUpdateJobView(recent,device,actor)).toBe(true);
 for(const patch of [{backgroundExecutor:false},{backgroundExecutor:undefined},{coordinated:undefined},{executorAvailability:undefined},{executorAvailability:'running'},{executorObservedAt:0},{executorObservedAt:seconds+1},{executorObservedAt:seconds-1},{serverNow:seconds+60},{schedulingAvailable:true},{schedulingRevoked:true},{mutation:{active:false,blocked:true,phase:'unavailable',revision:'9',retained:1,recovery:'intervention_required'}}])expect(validUpdateJobView({...recent,...patch},device,actor)).toBe(false);
 expect(validUpdateJobView({...backgroundView(),executorObservedAt:seconds},device,actor)).toBe(false);expect(validUpdateJobView({...view(),executorAvailability:'unknown'},device,actor)).toBe(false);expect(validUpdateJobView({...view(),executorObservedAt:seconds},device,actor)).toBe(false);
 const scheduledBackground=backgroundView(scheduled(`update_${'7'.repeat(32)}`));scheduledBackground.schedulingAvailable=false;expect(validUpdateJobView(scheduledBackground,device,actor)).toBe(false);
 expect(validUpdateJobView({...recent,serverNow:seconds+59},device,actor)).toBe(true);
});
it.each(['en','de'] as const)('keeps background unknown and saved results visible with collapsed details in %s',async locale=>{
 setLocale(locale,false);const de=locale==='de',id=`update_${'7'.repeat(32)}`,history=validHistory(id);
 const result=backgroundView({...approved(id),job:{...approved(id).job!,state:'complete',result:{jobId:id,envelopeDigest:digest,attempted:true,outcome:'uncertain',operationResult:3,hresult:0,rebootRequired:'unknown',completedAt:seconds}}});
 vi.mocked(request).mockImplementation(async path=>structuredClone(path==='/auth/session'?session:path.endsWith('?history=1')?history:result) as never);await open();
 const status=document.querySelector('.windows-update-executor-status')!;
 expect(status).toBeVisible();expect(status).toHaveTextContent(de?'Update-Hintergrunddienst · Nur manuelle Freigaben':'Background update service · Manual approvals only');expect(status).toHaveTextContent(de?'Verfügbarkeit unbekannt':'Availability unknown');expect(status).not.toHaveTextContent(/recent|zuletzt|running|läuft/i);
 expect(screen.getByText(de?/Die Antwort ist unbestätigt/:/The response is unconfirmed/)).toBeVisible();expect(screen.getByText(de?'Auftragsdetails':'Job details',{selector:'summary'}).closest('details')).not.toHaveAttribute('open');
 expect(screen.queryByText(de?'Dieses Update planen':'Schedule this update')).toBeNull();expect(screen.queryByText(de?'Planungsberechtigung widerrufen':'Revoke scheduling')).toBeNull();expect(screen.queryByRole('checkbox')).toBeNull();
 fireEvent.click(screen.getByText(de?'Gespeicherte Updateaufträge':'Saved update jobs',{selector:'summary'}));fireEvent.click(screen.getByRole('button',{name:de?'Gespeicherte Aufträge lesen':'Read saved jobs'}));await flush();
 fireEvent.click(screen.getByRole('button',{name:`${de?'Gespeicherten Auftrag öffnen':'Open saved job'} · ${id}`}));await flush();expect(document.querySelector('.windows-update-executor-status')).toHaveTextContent(de?'Verfügbarkeit unbekannt':'Availability unknown');expect(mutateRaw).not.toHaveBeenCalled();
});
it.each(['en','de'] as const)('ages recent background evidence to unknown without a read or changing its saved owner in %s',async locale=>{
 setLocale(locale,false);const de=locale==='de',result=backgroundView(view(),true);result.mutationCapturedAt=seconds-59;result.executorObservedAt=seconds-59;
 vi.mocked(request).mockImplementation(async path=>structuredClone(path==='/auth/session'?session:result) as never);await open();const reads=vi.mocked(request).mock.calls.length;
 expect(document.querySelector('.windows-update-executor-status')).toHaveTextContent(de?'Zuletzt bestätigt · Verfügbarkeit nicht live geprüft':'Recent confirmation · Availability not checked live');
 await act(async()=>vi.advanceTimersByTime(1000));
 expect(document.querySelector('.windows-update-executor-status')).toHaveTextContent(de?'Verfügbarkeit unbekannt':'Availability unknown');expect(document.querySelector('.windows-update-executor-status')).not.toHaveTextContent(/recent|zuletzt/i);
 expect(document.querySelector('.windows-mutation-status')).toHaveTextContent(de?'Gespeicherter gemeinsamer Status':'Saved shared status');expect(document.querySelector('.windows-mutation-status')).toHaveTextContent(de?'Kein Besitzer gespeichert':'No owner saved');expect(request).toHaveBeenCalledTimes(reads);expect(mutateRaw).not.toHaveBeenCalled();
});
it('keeps background manual approval explicit and never exposes a schedule even with scheduling permission',async()=>{
 vi.mocked(request).mockImplementation(async path=>structuredClone(path==='/auth/session'?scheduleSession():backgroundView(view(),true)) as never);
 vi.mocked(mutateRaw).mockImplementation(async(_path,body)=>backgroundView(previewView(JSON.parse(body).requestId),true) as never);await open();await review();
 expect(screen.getByRole('checkbox')).not.toBeChecked();expect(screen.getByRole('button',{name:'Approve this update once'})).toBeDisabled();expect(screen.queryByText('Schedule this update')).toBeNull();expect(screen.queryByText('Revoke scheduling')).toBeNull();expect(document.querySelector('.windows-update-executor-status')).not.toHaveTextContent(/running/i);
 fireEvent.click(screen.getByRole('button',{name:'Dismiss review'}));expect(screen.queryByRole('checkbox')).toBeNull();expect(mutateRaw).toHaveBeenCalledTimes(1);
});
it('omits the background profile from unchanged foreground views',async()=>{await open();expect(document.querySelector('.windows-update-executor-status')).toBeNull()});
it('shows configured-only background availability as unknown without inventing shared evidence',async()=>{
 const configured=backgroundView();delete configured.mutation;delete configured.mutationCapturedAt;expect(validUpdateJobView(configured,device,actor)).toBe(true);
 vi.mocked(request).mockImplementation(async path=>structuredClone(path==='/auth/session'?session:configured) as never);await open();
 expect(document.querySelector('.windows-update-executor-status')).toHaveTextContent('Availability unknown');expect(document.body).toHaveTextContent('Shared status awaits the executor.');expect(document.querySelector('.windows-mutation-status')).toBeNull();expect(mutateRaw).not.toHaveBeenCalled();
});
it('dismissal does not renew the original background status clock',async()=>{
 const recent=(value:UpdateJobView)=>({...backgroundView(value,true),executorObservedAt:seconds-58,mutationCapturedAt:seconds-58});
 vi.mocked(request).mockImplementation(async path=>structuredClone(path==='/auth/session'?session:recent(view())) as never);vi.mocked(mutateRaw).mockImplementation(async(_path,body)=>recent(previewView(JSON.parse(body).requestId)) as never);
 await open();await review();await act(async()=>vi.advanceTimersByTime(1000));fireEvent.click(screen.getByRole('button',{name:'Dismiss review'}));await act(async()=>vi.advanceTimersByTime(1000));
 expect(document.querySelector('.windows-update-executor-status')).toHaveTextContent('Availability unknown');expect(document.querySelector('.windows-update-executor-status')).not.toHaveTextContent('Recent');expect(mutateRaw).toHaveBeenCalledTimes(1);
});


const backgroundScheduleView=(value:UpdateJobView=view(),recent=false):UpdateJobView=>({...backgroundView(value,recent),backgroundScheduling:true});
it('admits only an explicit combined background scheduling profile and preserves legacy views',()=>{
 const id=`update_${'7'.repeat(32)}`,legacy=view(),manual=backgroundView(),combined=backgroundScheduleView(scheduled(id));
 const legacyBytes=JSON.stringify(legacy),manualBytes=JSON.stringify(manual);
 expect(validUpdateJobView(legacy,device,actor)).toBe(true);expect(validUpdateJobView(manual,device,actor)).toBe(true);
 expect(JSON.stringify(legacy)).toBe(legacyBytes);expect(JSON.stringify(manual)).toBe(manualBytes);expect(manual).not.toHaveProperty('backgroundScheduling');
 expect(validUpdateJobView(combined,device,actor)).toBe(true);expect(validUpdateJobView(backgroundScheduleView(view(),true),device,actor)).toBe(true);
 expect(validUpdateJobView({...combined,schedulingAvailable:false},device,actor)).toBe(true);
 expect(validUpdateJobView({...backgroundScheduleView(),schedulingRevoked:true},device,actor)).toBe(true);
 for(const value of [undefined,false,null,0,'true']){
  expect(validUpdateJobView({...combined,backgroundScheduling:value},device,actor)).toBe(false);
  expect(validUpdateJobView({...manual,backgroundScheduling:value},device,actor)).toBe(false);
 }
 for(const outside of [legacy,{...legacy,coordinated:true},{...legacy,backgroundExecutor:false},{...legacy,backgroundExecutor:true,executorAvailability:'unknown'}])expect(validUpdateJobView({...outside,backgroundScheduling:true},device,actor)).toBe(false);
 for(const bad of [{...combined,backgroundExecutor:undefined},{...combined,coordinated:undefined},{...combined,executorAvailability:'running'},{...combined,schedulingRevoked:true},{...combined,schedulingAvailable:'true'}])expect(validUpdateJobView(bad,device,actor)).toBe(false);
 const absent={...combined};delete absent.backgroundScheduling;expect(validUpdateJobView(absent,device,actor)).toBe(false);
 delete absent.schedulingAvailable;expect(validUpdateJobView(absent,device,actor)).toBe(false);
 for(const fields of [{schedulingAvailable:true},{schedulingRevoked:true}])expect(validUpdateJobView({...manual,...fields},device,actor)).toBe(false);
});
it.each(['en','de'] as const)('uses separate consent and existing UTC schedule routes for combined background updates in %s',async locale=>{
 enableScheduling(true);await scheduleReview(locale);const de=locale==='de';
 const status=document.querySelector('.windows-update-executor-status')!;
 expect(status).toBeVisible();expect(status).toHaveTextContent(de?'Update-Hintergrunddienst · Genehmigte UTC-Zeitfenster':'Background update service · Approved UTC windows');
 expect(status).toHaveTextContent(de?'Zuletzt bestätigt · Verfügbarkeit nicht live geprüft':'Recent confirmation · Availability not checked live');
 const requirements=screen.getByText(de?'Ausführungsvoraussetzungen':'Execution requirements',{selector:'summary'});
 expect(requirements.closest('details')).not.toHaveAttribute('open');fireEvent.click(requirements);
 expect(screen.getByText(de?/separat aktivierte Update-Hintergrunddienst und der Beobachter/:/separately activated background update service and observer/)).toBeVisible();
 expect(requirements.closest('details')).toHaveTextContent(de?'Das feste UTC-Zeitfenster begrenzt die Auslösung, nicht den Abschluss.':'The fixed UTC window limits dispatch, not completion.');
 expect(requirements.closest('details')).toHaveTextContent(de?'Ursprüngliche Freigabe und aktuelles Zertifikat':'Original grant and current certificate');
 expect(requirements.closest('details')).toHaveTextContent(de?'Kein Download, keine Lizenzannahme, kein Neustart und kein Wiederholungsversuch':'No download, license acceptance, reboot or retry');
 expect(screen.queryByText(de?/administrativ gestartete Vordergrund-Executor/:/administrator-launched foreground executor/)).toBeNull();
 const manual=screen.getByRole('checkbox',{name:de?/Installation genau dieser Revision und mögliche/:/exact revision and its possible interruption/});
 const prospective=screen.getByRole('checkbox',{name:de?/vorausschauend für dieses UTC/:/prospectively for this UTC/});
 const submit=screen.getByRole('button',{name:de?'Geplantes Update einmal freigeben':'Approve scheduled update once'});
 expect(manual).not.toBeChecked();expect(prospective).not.toBeChecked();expect(submit).toBeDisabled();
 fireEvent.click(manual);expect(prospective).not.toBeChecked();expect(submit).toBeDisabled();fireEvent.click(manual);
 fireEvent.click(prospective);expect(screen.getByRole('button',{name:de?'Dieses Update einmal freigeben':'Approve this update once'})).toBeDisabled();
 fireEvent.click(submit);fireEvent.click(submit);await flush();expect(mutateRaw).toHaveBeenCalledTimes(2);
 const id=JSON.parse(vi.mocked(mutateRaw).mock.calls[0][1]).requestId;
 expect(vi.mocked(mutateRaw).mock.calls[1][0]).toBe(`/devices/${device}/windows-update-jobs/schedule`);
 expect(JSON.parse(vi.mocked(mutateRaw).mock.calls[1][1])).toEqual({previewId:id,previewDigest:digest,acknowledged:true,startAt:seconds+120,endAt:seconds+420});
 expect(screen.getByText(de?/Genehmigtes UTC-Zeitfenster:/:/Approved UTC window:/)).toHaveTextContent('2026-10-11 10:02:00 UTC – 2026-10-11 10:07:00 UTC');
 expect(screen.getByText(de?/Ursprüngliche vorausschauende Freigabe:/:/Original prospective approval:/)).toHaveTextContent('2026-10-11 10:00:00 UTC');
 expect(screen.getByRole('button',{name:de?'Diese Planung abbrechen':'Cancel this schedule'})).toBeEnabled();
 expect(screen.getByText(de?/Abbruch und einmalige Abholung/:/Cancellation can race/)).toBeVisible();
 expect(document.querySelector('.windows-update-executor-status')).toHaveTextContent(de?'Genehmigte UTC-Zeitfenster':'Approved UTC windows');
});
it.each(['en','de'] as const)('keeps combined unknown availability, shared owner and scheduled history visible in %s',async locale=>{
 setLocale(locale,false);const de=locale==='de',id=`update_${'7'.repeat(32)}`,owner=`transfer_${'8'.repeat(32)}`;
 const saved=backgroundScheduleView(scheduled(id));saved.serverNow=seconds+150;saved.schedulingAvailable=false;
 saved.mutation={active:true,blocked:true,domain:'managed_msi',jobId:owner,phase:'dispatch_intent',recovery:'intervention_required',revision:'10',retained:1};
 saved.job={...saved.job!,state:'complete',reason:'ready',schedule:{...saved.job!.schedule!,permitIssuedAt:seconds+120},result:{jobId:id,envelopeDigest:digest,attempted:true,outcome:'uncertain',operationResult:3,hresult:0,rebootRequired:'unknown',completedAt:seconds+150}};
 const history=validHistory(id);history.serverNow=saved.serverNow;history.jobs=[{id,selection,state:'complete',reason:'ready',result:saved.job.result,schedule:saved.job.schedule,requestedAt:seconds+120,approvedAt:seconds,claimedAt:seconds+125}];
 expect(validUpdateJobView(saved,device,actor)).toBe(true);expect(validUpdateJobHistory(history,device,actor)).toBe(true);
 const original=JSON.stringify(saved),sessionAt={...scheduleSession(),serverNow:new Date(saved.serverNow*1000).toISOString()};
 vi.mocked(request).mockImplementation(async path=>structuredClone(path==='/auth/session'?sessionAt:path.endsWith('?history=1')?history:saved) as never);await open();
 const status=document.querySelector('.windows-update-executor-status')!;
 expect(status).toBeVisible();expect(status).toHaveTextContent(de?'Genehmigte UTC-Zeitfenster':'Approved UTC windows');expect(status).toHaveTextContent(de?'Verfügbarkeit unbekannt':'Availability unknown');expect(status).not.toHaveTextContent(/recent|zuletzt|running|läuft/i);
 expect(document.querySelector('.windows-mutation-status [role=status]')).toBeVisible();expect(document.querySelector('.windows-mutation-status')).toHaveTextContent(de?'Blockiert durch MSI':'Blocked by MSI');
 expect(screen.getByText(de?/Die Antwort ist unbestätigt/:/The response is unconfirmed/)).toBeVisible();expect(screen.queryByRole('checkbox')).toBeNull();
 const details=screen.getByText(de?'Auftragsdetails':'Job details',{selector:'summary'});expect(details.closest('details')).not.toHaveAttribute('open');fireEvent.click(details);
 expect(details.closest('details')).toHaveTextContent('2026-10-11 10:02:00 UTC – 2026-10-11 10:07:00 UTC');
 expect(details.closest('details')).toHaveTextContent(`${de?'Ursprüngliche vorausschauende Freigabe':'Original prospective approval'}: 2026-10-11 10:00:00 UTC`);
 expect(details.closest('details')).toHaveTextContent(`${de?'Installationsfreigabe ausgestellt':'Installation permit issued'}: 2026-10-11 10:02:00 UTC`);
 fireEvent.click(screen.getByText(de?'Gespeicherte Updateaufträge':'Saved update jobs',{selector:'summary'}));fireEvent.click(screen.getByRole('button',{name:de?'Gespeicherte Aufträge lesen':'Read saved jobs'}));await flush();
 const times=screen.getByText(de?'Ursprüngliche Auftragszeiten':'Original job times',{selector:'summary'});fireEvent.click(times);
 expect(times.closest('details')).toHaveTextContent('2026-10-11 10:02:00 UTC – 2026-10-11 10:07:00 UTC');
 expect(times.closest('details')).toHaveTextContent(`${de?'Ursprüngliche vorausschauende Freigabe':'Original prospective approval'}: 2026-10-11 10:00:00 UTC`);
 expect(times.closest('details')).toHaveTextContent(`${de?'Installationsfreigabe ausgestellt':'Installation permit issued'}: 2026-10-11 10:02:00 UTC`);
 fireEvent.click(screen.getByRole('button',{name:`${de?'Gespeicherten Auftrag öffnen':'Open saved job'} · ${id}`}));await flush();
 expect(request).toHaveBeenCalledWith(`/devices/${device}/windows-update-jobs?jobId=${id}`,expect.anything(),16384);
 expect(document.querySelector('.windows-update-executor-status')).toHaveTextContent(de?'Verfügbarkeit unbekannt':'Availability unknown');expect(JSON.stringify(saved)).toBe(original);expect(mutateRaw).not.toHaveBeenCalled();
});
it.each(['en','de'] as const)('ages combined evidence to unknown without refreshing its profile or owner in %s',async locale=>{
 setLocale(locale,false);const de=locale==='de',saved=backgroundScheduleView(view(),true);saved.mutationCapturedAt=seconds-59;saved.executorObservedAt=seconds-59;
 vi.mocked(request).mockImplementation(async path=>structuredClone(path==='/auth/session'?scheduleSession():saved) as never);await open();const reads=vi.mocked(request).mock.calls.length;
 expect(document.querySelector('.windows-update-executor-status')).toHaveTextContent(de?'Zuletzt bestätigt':'Recent confirmation');
 await act(async()=>vi.advanceTimersByTime(1000));
 expect(document.querySelector('.windows-update-executor-status')).toHaveTextContent(de?'Genehmigte UTC-Zeitfenster':'Approved UTC windows');
 expect(document.querySelector('.windows-update-executor-status')).toHaveTextContent(de?'Verfügbarkeit unbekannt':'Availability unknown');
 expect(document.querySelector('.windows-mutation-status')).toHaveTextContent(de?'Gespeicherter gemeinsamer Status':'Saved shared status');
 expect(document.querySelector('.windows-mutation-status')).toHaveTextContent(de?'Kein Besitzer gespeichert':'No owner saved');expect(request).toHaveBeenCalledTimes(reads);expect(mutateRaw).not.toHaveBeenCalled();
});
it('keeps lost combined scheduling and cancel responses GET-only and reports a claimed cancel race',async()=>{
 enableScheduling(true);await scheduleReview();const id=JSON.parse(vi.mocked(mutateRaw).mock.calls[0][1]).requestId;
 vi.mocked(mutateRaw).mockRejectedValueOnce(new Error('lost combined schedule'));
 fireEvent.click(screen.getByRole('checkbox',{name:/prospectively for this UTC/}));fireEvent.click(screen.getByRole('button',{name:'Approve scheduled update once'}));await flush();cleanup();
 const saved=backgroundScheduleView(scheduled(id),true);
 vi.mocked(request).mockImplementation(async path=>structuredClone(path==='/auth/session'?scheduleSession():saved) as never);await open();
 expect(screen.queryByRole('alert')).toBeNull();expect(mutateRaw).toHaveBeenCalledTimes(2);
 vi.mocked(mutateRaw).mockRejectedValueOnce(new Error('lost combined cancel'));fireEvent.click(screen.getByRole('button',{name:'Cancel this schedule'}));await flush();
 expect(vi.mocked(mutateRaw).mock.calls[2][0]).toBe(`/devices/${device}/windows-update-jobs/cancel-schedule`);
 expect(JSON.parse(vi.mocked(mutateRaw).mock.calls[2][1])).toEqual({scheduleId:id,scheduleDigest:saved.job!.schedule!.digest});cleanup();
 const claimed=backgroundScheduleView(scheduled(id));claimed.serverNow=seconds+125;claimed.job!.state='claimed';claimed.job!.reason='ready';claimed.job!.schedule!.permitIssuedAt=seconds+120;
 vi.mocked(request).mockImplementation(async path=>structuredClone(path==='/auth/session'?{...scheduleSession(),serverNow:new Date(claimed.serverNow*1000).toISOString()}:claimed) as never);await open();
 expect(screen.getByText('Claimed; installation unconfirmed')).toBeVisible();expect(screen.queryByText('Schedule canceled before claim')).toBeNull();expect(screen.queryByRole('button',{name:'Cancel this schedule'})).toBeNull();expect(screen.queryByRole('alert')).toBeNull();expect(mutateRaw).toHaveBeenCalledTimes(3);
 expect(vi.mocked(request).mock.calls.at(-1)?.[0]).toBe(`/devices/${device}/windows-update-jobs?jobId=${id}`);
});
it('reconciles combined scheduling revocation only from explicit saved evidence',async()=>{
 enableScheduling(true);await open();fireEvent.click(screen.getByText('Revoke scheduling',{selector:'summary'}));fireEvent.click(screen.getByRole('checkbox',{name:/Permanently revoke scheduling/}));
 vi.mocked(mutateRaw).mockRejectedValueOnce(new Error('lost combined revocation'));fireEvent.click(screen.getByRole('button',{name:'Revoke scheduling for this grant'}));await flush();
 expect(vi.mocked(mutateRaw).mock.calls[0][0]).toBe(`/devices/${device}/windows-update-jobs/revoke-scheduling`);
 vi.mocked(request).mockImplementation(async path=>structuredClone(path==='/auth/session'?scheduleSession():backgroundScheduleView()) as never);fireEvent.click(screen.getByRole('button',{name:'Read saved status'}));await flush();expect(screen.getByRole('alert')).toHaveTextContent('unconfirmed');
 vi.mocked(request).mockImplementation(async path=>structuredClone(path==='/auth/session'?scheduleSession():{...backgroundScheduleView(),schedulingRevoked:true}) as never);fireEvent.click(screen.getByRole('button',{name:'Read saved status'}));await flush();
 expect(screen.getByText('Scheduling was revoked for this original grant.')).toBeVisible();expect(screen.queryByRole('alert')).toBeNull();expect(document.querySelector('.windows-update-executor-status')).toHaveTextContent('Approved UTC windows');expect(mutateRaw).toHaveBeenCalledTimes(1);
});

it.each(['busy','stale','absent'] as const)('allows a future background schedule and cancellation with %s shared evidence, but blocks immediate install',async shared=>{
 const profile=(value:UpdateJobView)=>{const result=backgroundScheduleView(value);result.schedulingAvailable=true;
  if(shared==='busy')result.mutation={active:true,blocked:true,domain:'managed_msi',jobId:`transfer_${'9'.repeat(32)}`,phase:'dispatch_intent',recovery:'intervention_required',revision:'10',retained:1};
  if(shared==='stale')result.mutationCapturedAt=seconds-61;
  if(shared==='absent'){delete result.mutation;delete result.mutationCapturedAt}return result;
 };
 vi.mocked(request).mockImplementation(async path=>structuredClone(path==='/auth/session'?scheduleSession():profile(view())) as never);
 vi.mocked(mutateRaw).mockImplementation(async(path,raw)=>{const body=JSON.parse(raw);let value=profile(path.endsWith('/request')?previewView(body.requestId):scheduled(body.previewId??body.scheduleId));
  if(path.endsWith('/cancel-schedule')){value.job!.state='schedule_canceled';value.job!.reason='schedule_canceled';value.available=true;value.reason='ready'}
  if(path.endsWith('/revoke-scheduling'))value={...profile(view()),schedulingAvailable:false,schedulingRevoked:true};return structuredClone(value) as never;
 });
 await scheduleReview();await act(async()=>vi.advanceTimersByTime(500));expect(screen.getByRole('group',{name:'Check readiness'})).toBeVisible();fireEvent.click(screen.getByRole('checkbox',{name:/I approve installation of this exact revision and/}));expect(screen.getByRole('button',{name:'Approve this update once'})).toBeDisabled();
 fireEvent.click(screen.getByRole('checkbox',{name:/prospectively for this UTC/}));fireEvent.click(screen.getByRole('button',{name:'Approve scheduled update once'}));await flush();expect(mutateRaw).toHaveBeenCalledTimes(2);expect(vi.mocked(mutateRaw).mock.calls[1][0]).toMatch(/\/schedule$/);
 const cancel=screen.getByRole('button',{name:'Cancel this schedule'});expect(cancel).toBeEnabled();fireEvent.click(cancel);await flush();expect(screen.getByText('Schedule canceled before claim')).toBeVisible();
 fireEvent.click(screen.getByText('Revoke scheduling',{selector:'summary'}));fireEvent.click(screen.getByRole('checkbox',{name:/Permanently revoke scheduling/}));fireEvent.click(screen.getByRole('button',{name:'Revoke scheduling for this grant'}));await flush();expect(screen.getByText('Scheduling was revoked for this original grant.')).toBeVisible();expect(mutateRaw).toHaveBeenCalledTimes(4);expect(vi.mocked(mutateRaw).mock.calls.some(([path])=>path.endsWith('/approve'))).toBe(false);
});
it.each(['actor','capability','expiry'] as const)('keeps final %s validation when prospective approval no longer requires shared idle',async changed=>{
 enableScheduling(true);await scheduleReview();const current=scheduleSession();if(changed==='actor')current.actorId=`operator_${'9'.repeat(32)}`;if(changed==='capability')current.capabilities=['read','windows_update_install'];if(changed==='expiry')current.serverNow=new Date((seconds+61)*1000).toISOString();vi.mocked(request).mockResolvedValueOnce(current as never);
 fireEvent.click(screen.getByRole('checkbox',{name:/prospectively for this UTC/}));fireEvent.click(screen.getByRole('button',{name:'Approve scheduled update once'}));await flush();expect(mutateRaw).toHaveBeenCalledTimes(1);expect(screen.getByRole('alert')).toHaveTextContent('unavailable or changed');
});
it('does not request readiness for a device with its own unresolved update even with future scheduling available',async()=>{
 const value=backgroundScheduleView(approved(`update_${'7'.repeat(32)}`));value.schedulingAvailable=true;vi.mocked(request).mockImplementation(async path=>structuredClone(path==='/auth/session'?scheduleSession():value) as never);await open();expect(screen.queryByRole('combobox')).toBeNull();expect(screen.queryByRole('button',{name:'Check readiness'})).toBeNull();expect(mutateRaw).not.toHaveBeenCalled();
});
it('rejects a fixed window whose start passes before the final named session check',async()=>{
 enableScheduling(true);const fixed={startAt:seconds+30,endAt:seconds+120};render(<WindowsUpdateJobSession device={device} actor={actor} sessionKey={until} rows={resource.updates!.rows} fixedScheduleWindow={fixed}/>);await flush();await review();expect(screen.queryByRole('button',{name:'Approve this update once'})).toBeNull();
 vi.mocked(request).mockResolvedValueOnce({...scheduleSession(),serverNow:new Date((seconds+30)*1000).toISOString()} as never);fireEvent.click(screen.getByRole('checkbox',{name:/prospectively for this UTC/}));fireEvent.click(screen.getByRole('button',{name:'Approve scheduled update once'}));await flush();expect(mutateRaw).toHaveBeenCalledTimes(1);expect(screen.getByRole('alert')).toHaveTextContent('unavailable or changed');
});

it('fixed fleet selection never substitutes another revision while the fresh inventory read is pending or changed',async()=>{
 const rows=[{...selection,title:'Exact fixture'}],props={device,actor,sessionKey:until,fixedSelection:selection,oneJob:true};const ui=render(<WindowsUpdateJobSession {...props} rows={[]}/>);await flush();expect(screen.queryByRole('combobox')).toBeNull();expect(screen.getByRole('button',{name:'Check readiness'})).toBeDisabled();
 ui.rerender(<WindowsUpdateJobSession {...props} rows={[{...rows[0],revision:4}]}/>);expect(screen.getByRole('button',{name:'Check readiness'})).toBeDisabled();ui.rerender(<WindowsUpdateJobSession {...props} rows={rows}/>);expect(screen.getByRole('button',{name:'Check readiness'})).toBeEnabled();
 let resolve!:(value:unknown)=>void;vi.mocked(request).mockImplementationOnce(()=>new Promise(r=>{resolve=r}) as never);fireEvent.click(screen.getByRole('button',{name:'Check readiness'}));ui.rerender(<WindowsUpdateJobSession {...props} rows={[{...rows[0],revision:4}]}/>);await act(async()=>resolve(session));expect(mutateRaw).not.toHaveBeenCalled();
});
it('a changed fixed pair clears the old unchecked preview and cannot approve it',async()=>{
 const rows=[{...selection,title:'Exact fixture'},{...selection,revision:4,title:'Other revision'}],props={device,actor,sessionKey:until,rows,oneJob:true};const ui=render(<WindowsUpdateJobSession {...props} fixedSelection={selection}/>);await flush();fireEvent.click(screen.getByRole('button',{name:'Check readiness'}));await flush();fireEvent.click(screen.getByRole('checkbox'));ui.rerender(<WindowsUpdateJobSession {...props} fixedSelection={{...selection,revision:4}}/>);await flush();expect(screen.queryByRole('button',{name:'Approve this update once'})).toBeNull();expect(screen.queryByRole('checkbox')).toBeNull();expect(mutateRaw).toHaveBeenCalledTimes(1);
});

it('a proven-unsent fixed selection veto at the CSRF boundary does not create an unreconcilable job',async()=>{
 const rows=[{...selection,title:'Exact fixture'}],props={device,actor,sessionKey:until,fixedSelection:selection,oneJob:true};const ui=render(<WindowsUpdateJobSession {...props} rows={rows}/>);await flush();let finish!:()=>void;let posted=false;
 vi.mocked(mutateRaw).mockImplementationOnce(async(_path,_body,_headers,_signal,_cap,beforeSend)=>{await new Promise<void>(resolve=>{finish=resolve});if(!beforeSend?.())throw new DOMException('Canceled before POST','AbortError');posted=true;throw new Error('Unexpected POST')});
 fireEvent.click(screen.getByRole('button',{name:'Check readiness'}));await flush();ui.rerender(<WindowsUpdateJobSession {...props} rows={[]}/>);await act(async()=>finish());expect(posted).toBe(false);expect(screen.getByRole('alert')).not.toHaveTextContent('unconfirmed');
 ui.rerender(<WindowsUpdateJobSession {...props} rows={rows}/>);fireEvent.click(screen.getByRole('button',{name:'Read saved status'}));await flush();expect(vi.mocked(request).mock.calls.filter(([path])=>path.includes('?jobId='))).toHaveLength(0);expect(screen.getByRole('button',{name:'Check readiness'})).toBeEnabled();
 fireEvent.click(screen.getByRole('button',{name:'Check readiness'}));await flush();expect(screen.getByRole('checkbox')).not.toBeChecked();
});
