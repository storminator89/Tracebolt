import golden from '../../tests/fixtures/windows-service-action-history.json';
import current from '../../tests/fixtures/windows-service-action-view.json';
import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { AUTH_REQUIRED_EVENT, mutateRaw, request } from './api';
import { useOperator } from './auth';
import { setLocale } from './i18n';
import { WindowsServiceActionsPanel } from './windows-service-actions';
import { validWindowsActionHistory, validWindowsActionHistoryDetail } from './windows-service-action-history-types';
import type { WindowsActionHistory } from './windows-service-action-history-types';
vi.mock('./api',async original=>({...await original<typeof import('./api')>(),request:vi.fn(),mutateRaw:vi.fn()}));
vi.mock('./auth',async original=>({...await original<typeof import('./auth')>(),useOperator:vi.fn()}));
const history=golden.history as WindowsActionHistory,now=history.serverNow,until='2026-10-11T11:00:00Z';
const session={mode:'lan',transport:'https',insecureTestMode:false,transportWarning:null,authenticationRequired:true,authenticated:true,csrfToken:'csrf',serverNow:now,expiresAt:until,expiresInSeconds:3417,loginMode:'named',actorId:golden.actorId,capabilities:['read','windows_service_control']};
const base=`/devices/${golden.deviceId}/windows-service-actions`,flush=()=>act(async()=>{});
const status={...current.cases[0].complete,serverNow:now};
function respond(path:string){return structuredClone(path==='/auth/session'?session:path===base?status:path===base+'/history'?history:golden.details.find(d=>path.endsWith(d.job.identity.jobId)))}
beforeEach(()=>{vi.useFakeTimers();vi.setSystemTime(now);setLocale('en',false);vi.mocked(useOperator).mockReturnValue({...session,mode:'lan',theme:'light',logout:vi.fn(),setTheme:vi.fn(),capabilities:['read','windows_service_control'],loginMode:'named'});vi.mocked(request).mockReset().mockImplementation(async path=>respond(path) as never);vi.mocked(mutateRaw).mockReset()});
afterEach(()=>{cleanup();vi.useRealTimers();vi.restoreAllMocks()});
async function open(){const result=render(<WindowsServiceActionsPanel deviceId={golden.deviceId} sessionKey={until}/>);await flush();return result}
async function expand(){fireEvent.click(screen.getByRole('button',{name:'Saved action history'}));await flush()}
it('validates exact Go list and details and rejects expanded, cross-identity, oversized and inconsistent records',()=>{
 expect(validWindowsActionHistory(history,golden.deviceId)).toBe(true);
 for(const d of golden.details)expect(validWindowsActionHistoryDetail(d,history,history.jobs.find(j=>j.identity.jobId===d.job.identity.jobId)!,golden.actorId)).toBe(true);
 for(const bad of [{...history,envelope:'secret'},{...history,jobs:[...history.jobs,...history.jobs]},{...history,limit:65},{...history,binding:{...history.binding,endpointId:`agent_${'f'.repeat(32)}`}},{...history,jobs:[...history.jobs].reverse()},{...history,jobs:[{...history.jobs[0],outcome:'stopped-observed'},...history.jobs.slice(1)]}])expect(validWindowsActionHistory(bad,golden.deviceId)).toBe(false);
 const detail=golden.details[0],row=history.jobs[0];
 for(const bad of [{...detail,binding:{...detail.binding,incarnationDigest:`sha256:${'f'.repeat(64)}`}},{...detail,claimedAt:detail.job.startDeadline},{...detail,claimedAt:null},{...detail,serverNow:'2026-10-11T09:59:00Z'},{...detail,job:{...detail.job,identity:history.jobs[1].identity}},{...detail,envelope:'secret'}])expect(validWindowsActionHistoryDetail(bad,history,row,golden.actorId)).toBe(false);
});
it.each(['en','de'] as const)('reads history only on demand and exposes original receipt labels in %s',async locale=>{
 setLocale(locale,false);const {container}=await open();const title=locale==='de'?'Gespeicherte Aktionshistorie':'Saved action history';
 expect(screen.getByRole('button',{name:title})).toHaveAttribute('aria-expanded','false');expect(request).toHaveBeenCalledTimes(2);
 fireEvent.click(screen.getByRole('button',{name:title}));await flush();
 const list=container.querySelector('.windows-service-action-history-list')!;expect(list.querySelectorAll('li')).toHaveLength(3);expect(list.querySelector('li time')).toHaveAttribute('datetime',history.jobs[0].approvedAt);
 expect(container.querySelector('.windows-service-action-history-receipt')).toBeNull();
 fireEvent.click(within(list as HTMLElement).getByRole('button',{name:locale==='de'?'Beleg lesen #3':'Read receipt #3'}));await flush();
 const receipt=container.querySelector('.windows-service-action-history-receipt')!;
 expect(receipt).toHaveTextContent(golden.actorId);expect(receipt).toHaveTextContent(locale==='de'?'keinen Abschlusszeitpunkt':'no completion timestamp');expect(receipt).toHaveTextContent('FixtureService');expect(receipt.querySelector('time')).toHaveAttribute('datetime',golden.details[0].job.approvedAt);
 expect(mutateRaw).not.toHaveBeenCalled();
 fireEvent.click(screen.getByRole('button',{name:locale==='de'?'Beleg schließen #3':'Close receipt #3'}));expect(container.querySelector('.windows-service-action-history-receipt')).toBeNull();
 fireEvent.click(screen.getByRole('button',{name:title}));expect(container.querySelector('.windows-service-action-history-list')).toBeNull();
 fireEvent.click(screen.getByRole('button',{name:title}));await flush();expect(vi.mocked(request).mock.calls.filter(([p])=>p===base+'/history')).toHaveLength(2);
});
it.each(['blur','pagehide','popstate','hashchange',AUTH_REQUIRED_EVENT])('discards retained rows and late receipts after %s',async event=>{
 await open();await expand();let finish!:(v:unknown)=>void;
 vi.mocked(request).mockImplementation(async path=>path.endsWith(history.jobs[0].identity.jobId)?await new Promise(resolve=>{finish=resolve}):respond(path) as never);
 fireEvent.click(screen.getByRole('button',{name:'Read receipt #3'}));await flush();act(()=>window.dispatchEvent(new Event(event)));await act(async()=>finish(golden.details[0]));expect(screen.queryByText('Approving operator:',{exact:false})).toBeNull();expect(screen.queryByRole('button',{name:'Saved action history'})).toBeNull();expect(mutateRaw).not.toHaveBeenCalled();
});
it('discards a closed read and a superseded selected receipt without a replacement action',async()=>{
 const {container}=await open();await expand();let finish!:(v:unknown)=>void;
 vi.mocked(request).mockImplementation(async path=>path.endsWith(history.jobs[0].identity.jobId)?await new Promise(resolve=>{finish=resolve}):respond(path) as never);
 fireEvent.click(screen.getByRole('button',{name:'Read receipt #3'}));await flush();fireEvent.click(screen.getByRole('button',{name:'Read receipt #1'}));await flush();await act(async()=>finish(golden.details[0]));
 expect(container.querySelector('.windows-service-action-history-receipt')).toHaveTextContent(golden.details[2].job.identity.jobId);
 expect(container.querySelector('.windows-service-action-history-receipt')).not.toHaveTextContent(golden.details[0].job.identity.jobId);
 fireEvent.click(screen.getByRole('button',{name:'Read receipt #3'}));await flush();fireEvent.click(screen.getByRole('button',{name:'Saved action history'}));await act(async()=>finish(golden.details[0]));expect(container.querySelector('.windows-service-action-history-receipt')).toBeNull();expect(mutateRaw).not.toHaveBeenCalled();
});
it('removes history when the operator is lost during a read or a new incarnation is returned',async()=>{
 const {container}=await open();await expand();
 vi.mocked(request).mockImplementation(async path=>path==='/auth/session'?{...session,capabilities:['read']} as never:respond(path) as never);
 fireEvent.click(screen.getByRole('button',{name:'Read receipt #3'}));await flush();expect(screen.getByRole('alert')).toHaveTextContent('History is unavailable');expect(container.querySelector('.windows-service-action-history-list')).toBeNull();
 fireEvent.click(screen.getByRole('button',{name:'Saved action history'}));vi.mocked(request).mockImplementation(async path=>respond(path) as never);await expand();
 vi.mocked(request).mockImplementation(async path=>path.endsWith(history.jobs[0].identity.jobId)?{...golden.details[0],binding:{...history.binding,incarnationDigest:`sha256:${'f'.repeat(64)}`}} as never:respond(path) as never);
 fireEvent.click(screen.getByRole('button',{name:'Read receipt #3'}));await flush();expect(container.querySelector('.windows-service-action-history-list')).toBeNull();expect(mutateRaw).not.toHaveBeenCalled();
});
it('refresh closes history and keeps its original approval timestamps',async()=>{
 const {container}=await open();await expand();fireEvent.click(screen.getByRole('button',{name:'Read saved status'}));await flush();expect(container.querySelector('.windows-service-action-history-list')).toBeNull();await expand();expect(container.querySelector('li time')).toHaveAttribute('datetime',history.jobs[0].approvedAt);expect(mutateRaw).not.toHaveBeenCalled();
});
it('shows the existing 64-approval hard limit without polling or retry controls',async()=>{
 const full={...history,jobs:Array.from({length:64},(_,index)=>({...history.jobs[0],identity:{...history.jobs[0].identity,jobId:`action_${(64-index).toString(16).padStart(32,'0')}`,sequence:String(64-index)}}))};
 expect(validWindowsActionHistory(full,golden.deviceId)).toBe(true);
 expect(validWindowsActionHistory({...full,jobs:[...full.jobs,full.jobs[0]]},golden.deviceId)).toBe(false);
 vi.mocked(request).mockImplementation(async path=>structuredClone(path===base+'/history'?full:respond(path)) as never);
 await open();await expand();expect(screen.getByText(/All 64 retained approval slots are used/)).toBeVisible();expect(screen.queryByRole('button',{name:/retry/i})).toBeNull();
 const reads=vi.mocked(request).mock.calls.length;await act(async()=>vi.advanceTimersByTime(60000));expect(request).toHaveBeenCalledTimes(reads);expect(mutateRaw).not.toHaveBeenCalled();
});
it('renders a genuinely empty retained set without fabricating a receipt',async()=>{
 vi.mocked(request).mockImplementation(async path=>structuredClone(path===base+'/history'?{...history,jobs:[]}:respond(path)) as never);
 await open();await expand();expect(screen.getByText('No saved approvals for this service grant.')).toBeVisible();expect(screen.queryByRole('button',{name:/Read receipt/})).toBeNull();expect(mutateRaw).not.toHaveBeenCalled();
});
