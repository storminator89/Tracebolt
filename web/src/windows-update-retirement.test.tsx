import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { AUTH_REQUIRED_EVENT, mutateRaw, request } from './api';
import { WindowsUpdateJobSession } from './windows-update-jobs';
import { validUpdateJobHistory, validUpdateJobView, type UpdateJobHistory, type UpdateJobSummary, type UpdateJobView } from './windows-update-jobs-types';
import { canReviewUpdateRetirement, readUpdateRetirementIntent, saveUpdateRetirementIntent, updateRetirementIntent } from './windows-update-retirement-resource';
import { setLocale } from './i18n';
vi.mock('./api',async original=>({...await original<typeof import('./api')>(),request:vi.fn(),mutateRaw:vi.fn()}));
const now='2026-10-11T10:00:00Z',until='2026-10-11T11:00:00Z',at=Date.parse(now)/1000;
const device=`agent_${'1'.repeat(32)}`,jobId=`update_${'2'.repeat(32)}`,digest=(n:string)=>`sha256:${n.repeat(64)}`;
const selection={updateId:'11111111-2222-3333-4444-555555555555',revision:3};
let actor='',value:UpdateJobView,session:Record<string,unknown>;
const available=():UpdateJobView=>({version:'tracebolt.windows-selected-update-job.v1',deviceId:device,serverNow:at,available:false,reason:'job_pending_or_intervention',reusableJobs:true,grantExpiresAt:at+1800,coordinated:true,mutationCapturedAt:at,mutation:{active:true,blocked:false,phase:'idle',revision:'3',retained:1},job:{id:jobId,selection,state:'complete',reason:'ready',preview:null,result:{jobId,envelopeDigest:digest('3'),attempted:true,outcome:'succeeded',operationResult:2,hresult:0,rebootRequired:'yes',completedAt:at-3},occurrence:'1',resultDigest:digest('4'),retirement:{state:'available'}}});
const pending=():UpdateJobView=>({...available(),job:{...available().job!,retirement:{state:'pending',requestedAt:at-2}}});
const retired=():UpdateJobView=>({...available(),available:true,reason:'ready',retiredFloor:'1',job:{...available().job!,retirement:{state:'retired',requestedAt:at-2,claimedAt:at-1,retiredAt:at}}});
function summary(view:UpdateJobView):UpdateJobSummary {const {preview:_,resultDigest:__,...job}=view.job!;return {...job,requestedAt:at-10,approvedAt:at-8,claimedAt:at-6};}
const history=():UpdateJobHistory=>({version:'tracebolt.windows-selected-update-history.v1',deviceId:device,serverNow:at,available:true,reason:'ready',remainingCapacity:1,reusableJobs:true,grantExpiresAt:at+1800,retiredFloor:'1',jobs:[summary(retired())]});
const flush=()=>act(async()=>{});
const key=()=>`${actor}:${until}:${device}`;
async function mount(props:Partial<Parameters<typeof WindowsUpdateJobSession>[0]>={}){const ui=render(<WindowsUpdateJobSession device={device} actor={actor} sessionKey={until} rows={[{...selection,title:'Synthetic cached update'}]} {...props}/>);await flush();return ui;}
async function review(){fireEvent.click(screen.getByRole('button',{name:'Review completed job'}));fireEvent.click(screen.getByRole('checkbox'));}
async function close(){fireEvent.click(screen.getByRole('button',{name:'Close completed job'}));await flush();}
beforeEach(()=>{actor=`operator_${crypto.randomUUID().replaceAll('-','')}`;vi.useFakeTimers();vi.setSystemTime(now);setLocale('en',false);sessionStorage.clear();value=available();session={mode:'lan',transport:'https',insecureTestMode:false,transportWarning:null,authenticationRequired:true,authenticated:true,csrfToken:'synthetic',serverNow:now,expiresAt:until,expiresInSeconds:3600,loginMode:'named',actorId:actor,capabilities:['read','windows_update_install']};vi.mocked(request).mockReset().mockImplementation(async path=>structuredClone(path==='/auth/session'?session:path.endsWith('?history=1')?history():value) as never);vi.mocked(mutateRaw).mockReset().mockImplementation(async()=>structuredClone(pending()) as never);});
afterEach(()=>{cleanup();vi.useRealTimers();vi.restoreAllMocks();vi.unstubAllGlobals();sessionStorage.clear();});

it.each(['en','de'] as const)('opens one compact exact retirement review with unchecked consent in %s',async locale=>{
 setLocale(locale,false);const de=locale==='de';await mount();expect(screen.queryByRole('checkbox')).toBeNull();expect(screen.getByText(de?/Ursprüngliche Zustimmung läuft ab/:/Original consent expires/)).toHaveTextContent('2026-10-11 10:30:00 UTC');expect(document.body).not.toHaveTextContent('/32');
 fireEvent.click(screen.getByRole('button',{name:de?'Abgeschlossenen Auftrag prüfen':'Review completed job'}));
 const group=screen.getByRole('group',{name:de?'Abgeschlossenen Auftrag prüfen':'Review completed job'}),button=screen.getByRole('button',{name:de?'Abgeschlossenen Auftrag schließen':'Close completed job'});
 expect(group).toHaveTextContent(selection.updateId);expect(group.querySelector('details')).not.toHaveAttribute('open');expect(screen.getByRole('checkbox')).not.toBeChecked();expect(button).toBeDisabled();
 fireEvent.click(screen.getByRole('checkbox'));fireEvent.click(button);fireEvent.click(button);await flush();expect(mutateRaw).toHaveBeenCalledTimes(1);
 expect(vi.mocked(request).mock.calls.at(-1)?.[0]).toBe(`/devices/${device}/windows-update-jobs?jobId=${jobId}`);
 expect(vi.mocked(mutateRaw).mock.calls[0][0]).toBe(`/devices/${device}/windows-update-jobs/retire`);
 expect(JSON.parse(vi.mocked(mutateRaw).mock.calls[0][1])).toEqual({jobId,occurrence:'1',envelopeDigest:digest('3'),resultDigest:digest('4'),acknowledged:true});
 expect(screen.queryByRole('checkbox')).toBeNull();expect(document.body).toHaveTextContent(de?'WUA hat Erfolg gemeldet':'WUA reported success');expect(document.body).toHaveTextContent(de?'Windows meldet einen erforderlichen Neustart.':'Windows reports that a restart is required.');expect(document.body).toHaveTextContent(de?'Abschließen ausstehend; nächster Auftrag blockiert.':'Closing pending; next job blocked.');expect(screen.queryByRole('combobox')).toBeNull();
});
it('requires explicit available retirement evidence and never derives it from idle, non-attempt or missing fields',()=>{
 for(const state of ['blocked','pending','retired'] as const){const v=state==='pending'?pending():state==='retired'?retired():available();v.job!.retirement={state,...(state==='pending'?{requestedAt:at}:state==='retired'?{retiredAt:at}:{})};expect(canReviewUpdateRetirement(v,at)).toBe(false);}
 const missing=available();delete missing.job!.retirement;expect(validUpdateJobView(missing,device,actor)).toBe(true);expect(canReviewUpdateRetirement(missing,at)).toBe(false);
 for(const patch of [{resultDigest:undefined},{occurrence:undefined},{result:{...value.job!.result!,outcome:'not_attempted',attempted:false,operationResult:0,rebootRequired:'unknown'}},{result:{...value.job!.result!,outcome:'uncertain',operationResult:3,rebootRequired:'unknown'}}]){const v=available();Object.assign(v.job!,patch);expect(validUpdateJobView(v,device,actor)).toBe(false);expect(canReviewUpdateRetirement(v,at)).toBe(false);}
 expect(canReviewUpdateRetirement(available(),at+1800)).toBe(false);
});
it('strictly validates fresh fields, floor bounds, retirement times and bounded history while retaining legacy shapes',()=>{
 for(const v of [available(),pending(),retired()])expect(validUpdateJobView(v,device,actor)).toBe(true);
 const legacy=available();delete legacy.reusableJobs;delete legacy.grantExpiresAt;delete legacy.job!.occurrence;delete legacy.job!.resultDigest;delete legacy.job!.retirement;expect(validUpdateJobView(legacy,device,actor)).toBe(true);
 for(const patch of [{reusableJobs:false},{reusableJobs:undefined},{grantExpiresAt:undefined},{retiredFloor:'0'},{retiredFloor:'01'},{retiredFloor:'18446744073709551616'},{retiredFloor:'1'},{available:true,reason:'ready'}])expect(validUpdateJobView({...available(),...patch},device,actor)).toBe(false);
 for(const patch of [{occurrence:'0'},{occurrence:'01'},{occurrence:'18446744073709551616'},{retirement:{state:'pending'}},{retirement:{state:'pending',requestedAt:at-4}},{retirement:{state:'pending',requestedAt:at,claimedAt:at-1}},{retirement:{state:'retired',retiredAt:at}},{retirement:{state:'available',requestedAt:at}},{envelope:'forbidden'}])expect(validUpdateJobView({...available(),job:{...available().job!,...patch}},device,actor)).toBe(false);
 const blocked=pending();blocked.job!.retirement={state:'blocked',requestedAt:at-2,claimedAt:at-1};expect(validUpdateJobView(blocked,device,actor)).toBe(true);
 const h=history();expect(validUpdateJobHistory(h,device,actor)).toBe(true);expect(validUpdateJobHistory({...h,remainingCapacity:32},device,actor)).toBe(false);expect(validUpdateJobHistory({...h,jobs:[{...h.jobs[0],resultDigest:digest('4')}]},device,actor)).toBe(false);expect(validUpdateJobHistory({...h,jobs:[...h.jobs,...h.jobs]},device,actor)).toBe(false);
 const rows=Array.from({length:8},(_,i)=>({...summary(retired()),id:`update_${String(i+1).repeat(32)}`,occurrence:String(i+1),result:{...value.job!.result!,jobId:`update_${String(i+1).repeat(32)}`}}));const bounded={...h,retiredFloor:'8',jobs:rows};expect(validUpdateJobHistory(bounded,device,actor)).toBe(true);expect(validUpdateJobHistory({...bounded,jobs:[...rows,{...rows[0],id:`update_${'9'.repeat(32)}`,occurrence:'9',result:{...rows[0].result!,jobId:`update_${'9'.repeat(32)}`}}],retiredFloor:'9'},device,actor)).toBe(false);
});
it.each(['dismiss','Escape','blur','pagehide','popstate','hashchange',AUTH_REQUIRED_EVENT])('drops retirement acknowledgement on %s and sends no write',async event=>{
 await mount();await review();if(event==='dismiss')fireEvent.click(screen.getByRole('button',{name:'Dismiss review'}));else if(event==='Escape')fireEvent.keyDown(screen.getByRole('group',{name:'Review completed job'}),{key:'Escape'});else act(()=>window.dispatchEvent(new Event(event)));
 expect(screen.queryByRole('checkbox')).toBeNull();expect(mutateRaw).not.toHaveBeenCalled();if(event==='dismiss'||event==='Escape'){fireEvent.click(screen.getByRole('button',{name:'Review completed job'}));expect(screen.getByRole('checkbox')).not.toBeChecked();}
});
it.each(['occurrence','envelope','result','grant','unavailable','session','device'])('rejects changed %s during exact preflight',async change=>{
 await mount();await review();value=available();if(change==='occurrence'){value.retiredFloor='1';value.job!.occurrence='2';}if(change==='envelope')value.job!.result!.envelopeDigest=digest('8');if(change==='result')value.job!.resultDigest=digest('8');if(change==='grant')value.grantExpiresAt=at+1900;if(change==='unavailable')value.job!.retirement={state:'blocked'};if(change==='session')session.actorId=`operator_${'9'.repeat(32)}`;if(change==='device')value.deviceId=`agent_${'9'.repeat(32)}`;await close();expect(mutateRaw).not.toHaveBeenCalled();expect(screen.getByRole('alert')).toHaveTextContent('unavailable or changed');expect(screen.queryByRole('checkbox')).toBeNull();
});
it('guards the actual POST after a delayed CSRF read and retains only a reference for reconciliation',async()=>{
 const actual=await vi.importActual<typeof import('./api')>('./api');await mount();await review();let resolve!:(r:Response)=>void;const fetch=vi.fn().mockImplementationOnce(()=>new Promise<Response>(r=>{resolve=r}));vi.stubGlobal('fetch',fetch);vi.mocked(mutateRaw).mockImplementation(actual.mutateRaw);
 fireEvent.click(screen.getByRole('button',{name:'Close completed job'}));await flush();expect(fetch).toHaveBeenCalledTimes(1);expect(fetch.mock.calls[0][0]).toBe('/api/session');
 act(()=>window.dispatchEvent(new Event('blur')));await act(async()=>resolve(new Response(JSON.stringify({csrfToken:'synthetic'}),{status:200})));expect(fetch).toHaveBeenCalledTimes(1);expect(readUpdateRetirementIntent(key()).intent).toEqual(updateRetirementIntent(available()));expect(sessionStorage.getItem(`tracebolt.windows-update-retirement.v1:${key()}`)).not.toMatch(/signature|rebootRequired|acknowledged|outcome/);
});
it('keeps a lost retirement GET-only across remount, mismatched evidence and history browsing, then reconciles exact pending/retired',async()=>{
 const ui=await mount();await review();vi.mocked(mutateRaw).mockRejectedValueOnce(Error('lost'));await close();expect(screen.getByRole('alert')).toHaveTextContent('unconfirmed');ui.unmount();
 value=available();value.job!.resultDigest=digest('8');await mount();expect(vi.mocked(request).mock.calls.at(-1)?.[0]).toBe(`/devices/${device}/windows-update-jobs?jobId=${jobId}`);expect(screen.getByRole('button',{name:'Review completed job'})).toBeDisabled();expect(screen.getByRole('alert')).toHaveTextContent('unconfirmed');
 fireEvent.click(screen.getByText('Saved update jobs',{selector:'summary'}));fireEvent.click(screen.getByRole('button',{name:'Read saved jobs'}));await flush();expect(document.body).toHaveTextContent('Available job slot: 1/1');expect(document.body).not.toHaveTextContent('/32');expect(readUpdateRetirementIntent(key()).intent).not.toBeNull();
 value=pending();fireEvent.click(screen.getByRole('button',{name:'Read saved status'}));await flush();expect(screen.queryByRole('alert')).toBeNull();expect(screen.queryByRole('combobox')).toBeNull();value=retired();fireEvent.click(screen.getByRole('button',{name:'Read saved status'}));await flush();expect(readUpdateRetirementIntent(key()).intent).toBeNull();expect(document.body).toHaveTextContent('Job closed; no next job started.');expect(mutateRaw).toHaveBeenCalledTimes(1);
});
it('restores a reload reference only for its exact device and named session, never an acknowledgement',async()=>{
 expect(saveUpdateRetirementIntent(key(),updateRetirementIntent(value)!)).toBe(true);await mount();expect(vi.mocked(request).mock.calls.at(-1)?.[0]).toBe(`/devices/${device}/windows-update-jobs?jobId=${jobId}`);expect(screen.getByRole('button',{name:'Review completed job'})).toBeDisabled();expect(screen.queryByRole('checkbox')).toBeNull();expect(mutateRaw).not.toHaveBeenCalled();expect(readUpdateRetirementIntent(`${actor}:different-session:${device}`).intent).toBeNull();expect(readUpdateRetirementIntent(`${actor}:${until}:agent_${'9'.repeat(32)}`).intent).toBeNull();
});
it('does not turn missing or unwritable browser storage into retirement confirmation',async()=>{
 await mount();await review();vi.spyOn(Storage.prototype,'setItem').mockImplementation(()=>{throw Error('quota')});await close();expect(mutateRaw).not.toHaveBeenCalled();expect(screen.getByRole('alert')).toHaveTextContent('unavailable or changed');
 value=available();fireEvent.click(screen.getByRole('button',{name:'Read saved status'}));await flush();expect(screen.getByRole('button',{name:'Review completed job'})).toBeDisabled();expect(screen.getByRole('alert')).toHaveTextContent('unconfirmed');
});
it('preserves original success and reboot in an uncertain retirement worklist receipt without advancing the plan',async()=>{
 const onReceipt=vi.fn();await mount({oneJob:true,initialJobId:jobId,onReceipt});await review();vi.mocked(mutateRaw).mockRejectedValueOnce(Error('lost'));await close();expect(onReceipt.mock.calls.at(-1)?.[0]).toMatchObject({jobId,unconfirmed:true,state:'complete',result:{outcome:'succeeded',rebootRequired:'yes'}});expect(screen.queryByRole('combobox')).toBeNull();expect(mutateRaw).toHaveBeenCalledTimes(1);
});
it('uses the actual bounded API helper for retirement, including CSRF and the exact request path',async()=>{
 const actual=await vi.importActual<typeof import('./api')>('./api');await mount();await review();const fetch=vi.fn().mockResolvedValueOnce(new Response(JSON.stringify({csrfToken:'synthetic'}),{status:200})).mockResolvedValueOnce(new Response(JSON.stringify(pending()),{status:200}));vi.stubGlobal('fetch',fetch);vi.mocked(mutateRaw).mockImplementation(actual.mutateRaw);await close();
 expect(fetch).toHaveBeenCalledTimes(2);expect(fetch.mock.calls[1][0]).toBe(`/api/devices/${device}/windows-update-jobs/retire`);expect(fetch.mock.calls[1][1]).toMatchObject({method:'POST',credentials:'same-origin',headers:{'X-CSRF-Token':'synthetic'}});expect(JSON.parse(fetch.mock.calls[1][1].body)).toEqual({jobId,occurrence:'1',envelopeDigest:digest('3'),resultDigest:digest('4'),acknowledged:true});expect(screen.queryByRole('alert')).toBeNull();expect(document.body).toHaveTextContent('Closing pending; next job blocked.');
});
it('rejects an oversized real retirement response and keeps the write GET-only',async()=>{
 const actual=await vi.importActual<typeof import('./api')>('./api');await mount();await review();const fetch=vi.fn().mockResolvedValueOnce(new Response(JSON.stringify({csrfToken:'synthetic'}),{status:200})).mockResolvedValueOnce(new Response(JSON.stringify({...pending(),padding:'x'.repeat(16384)}),{status:200}));vi.stubGlobal('fetch',fetch);vi.mocked(mutateRaw).mockImplementation(actual.mutateRaw);await close();expect(fetch).toHaveBeenCalledTimes(2);expect(screen.getByRole('alert')).toHaveTextContent('unconfirmed');expect(readUpdateRetirementIntent(key()).intent).not.toBeNull();
});
it('accepts compact retired scheduled history with original approval before later readiness, without changing legacy ordering',()=>{
 const h=history();h.jobs[0].approvedAt=at-20;h.jobs[0].requestedAt=at-10;h.jobs[0].retirement={state:'retired',retiredAt:at};expect(validUpdateJobHistory(h,device,actor)).toBe(true);
 const legacy:Record<string,unknown>={...h,remainingCapacity:31};delete legacy.reusableJobs;delete legacy.grantExpiresAt;delete legacy.retiredFloor;const item={...h.jobs[0]};delete item.occurrence;delete item.retirement;legacy.jobs=[item];expect(validUpdateJobHistory(legacy,device,actor)).toBe(false);
});
