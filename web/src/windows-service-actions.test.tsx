import golden from '../../tests/fixtures/windows-service-action-view.json';
import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, request, mutateRaw, AUTH_REQUIRED_EVENT } from './api';
import { useOperator } from './auth';
import { setLocale } from './i18n';
import { WindowsServiceActionsPanel } from './windows-service-actions';
import { WindowsInventoryWorkspace } from './windows-inventory';
import { useWindowsInventory } from './windows-inventory-resource';
import { validWindowsActionView } from './windows-service-action-types';
import type { WindowsActionView, WindowsActionPreview, WindowsServiceOperation } from './windows-service-action-types';
vi.mock('./api', async original => ({...await original<typeof import('./api')>(),request:vi.fn(),mutateRaw:vi.fn()}));
vi.mock('./auth', async original => ({...await original<typeof import('./auth')>(),useOperator:vi.fn()}));
const now='2026-10-11T10:00:00Z', until='2026-10-11T11:00:00Z',device=`agent_${'1'.repeat(32)}`,actor=`operator_${'2'.repeat(32)}`,digest=`sha256:${'3'.repeat(64)}`;
const binding={managerId:`manager_${'4'.repeat(32)}`,keyId:digest,endpointId:device,incarnationDigest:digest,installationId:`broker_${'5'.repeat(32)}`,grantDigest:digest,target:'FixtureService',targetDigest:digest};
const view=():WindowsActionView=>({schemaVersion:'tracebolt.windows-service-action-view.v1',deviceId:device,serverNow:now,configured:true,available:true,reason:'ready',target:binding.target,preview:null,job:null});
const preview=(operation:WindowsServiceOperation='start'):WindowsActionPreview=>({version:'tracebolt.windows-service-action-preview.v1',id:`action_${'6'.repeat(32)}`,binding,operation,actorId:actor,sequence:'1',createdAt:now,expiresAt:'2026-10-11T10:01:00Z',digest});
const approved=(operation:WindowsServiceOperation='start'):WindowsActionView=>({...view(),available:false,reason:'job_pending',job:{identity:{jobId:preview().id,sequence:'1',envelopeDigest:digest},target:binding.target,operation,actorId:actor,approvedAt:now,startDeadline:'2026-10-11T10:01:00Z',state:'approved',result:null}});
const session={mode:'lan',transport:'https',insecureTestMode:false,transportWarning:null,authenticationRequired:true,authenticated:true,csrfToken:'csrf',serverNow:now,expiresAt:until,expiresInSeconds:3600,loginMode:'named',actorId:actor,capabilities:['read','windows_service_control']};
const flush=()=>act(async()=>{});
const open=async()=>{const ui=render(<WindowsServiceActionsPanel deviceId={device} sessionKey={until}/>);await flush();return ui};
const review=async(op:WindowsServiceOperation='start')=>{fireEvent.click(screen.getByRole('button',{name:/Select service/}));fireEvent.change(screen.getByRole('combobox'),{target:{value:op}});fireEvent.click(screen.getByRole('button',{name:'Review action'}));await flush()};
beforeEach(()=>{vi.useFakeTimers();vi.setSystemTime(now);setLocale('en',false);vi.mocked(useOperator).mockReturnValue({...session,mode:'lan',theme:'light',logout:vi.fn(),setTheme:vi.fn(),capabilities:['read','windows_service_control'],loginMode:'named'});vi.mocked(request).mockReset().mockImplementation(async path=>structuredClone(path==='/auth/session'?session:view()) as never);vi.mocked(mutateRaw).mockReset().mockImplementation(async(path,body)=>{const input=JSON.parse(body);return structuredClone(path.endsWith('/preview')?{...view(),preview:preview(input.operation)}:approved()) as never})});
afterEach(()=>{act(()=>window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT)));cleanup();vi.useRealTimers();vi.restoreAllMocks()});
describe('selected Windows service control',()=>{
 it.each(['start','stop','restart'] as const)('previews %s exactly and approves only once',async op=>{await open();expect(mutateRaw).not.toHaveBeenCalled();await review(op);const approve=screen.getByRole('button',{name:'Approve this action once'});expect(approve).toBeDisabled();fireEvent.click(screen.getByRole('checkbox'));vi.mocked(mutateRaw).mockResolvedValueOnce(approved(op));fireEvent.click(approve);fireEvent.click(approve);await flush();expect(mutateRaw).toHaveBeenCalledTimes(2);expect(JSON.parse(vi.mocked(mutateRaw).mock.calls[0][1])).toEqual({target:'FixtureService',operation:op});expect(JSON.parse(vi.mocked(mutateRaw).mock.calls[1][1])).toEqual({previewId:preview().id,previewDigest:digest});expect(screen.queryByRole('checkbox')).toBeNull();expect(screen.getByRole('status')).toHaveTextContent('awaiting one-time claim')});
 it('requires the independent capability without reading authority',async()=>{vi.mocked(useOperator).mockReturnValue({...vi.mocked(useOperator)(),capabilities:['read','restart_service']} as ReturnType<typeof useOperator>);await open();expect(request).not.toHaveBeenCalled();expect(mutateRaw).not.toHaveBeenCalled()});
 it.each(['blur','pagehide','popstate','hashchange',AUTH_REQUIRED_EVENT])('clears preview after %s and never repeats approval',async event=>{await open();await review();act(()=>window.dispatchEvent(new Event(event)));expect(screen.queryByRole('checkbox')).toBeNull();expect(mutateRaw).toHaveBeenCalledTimes(1)});
 it('treats lost approval as uncertain and only GET reconciles it',async()=>{await open();await review();vi.mocked(mutateRaw).mockRejectedValueOnce(new Error('lost'));fireEvent.click(screen.getByRole('checkbox'));fireEvent.click(screen.getByRole('button',{name:'Approve this action once'}));await flush();expect(screen.getByRole('alert')).toHaveTextContent('unconfirmed');vi.mocked(request).mockImplementation(async path=>structuredClone(path==='/auth/session'?session:approved()) as never);fireEvent.click(screen.getByRole('button',{name:'Read saved status'}));await flush();expect(mutateRaw).toHaveBeenCalledTimes(2);expect(screen.queryByRole('button',{name:/Select service/})).toBeNull()});
 it('discards a late preview on navigation',async()=>{let finish!:(v:unknown)=>void;await open();vi.mocked(mutateRaw).mockImplementationOnce(()=>new Promise(resolve=>{finish=resolve}) as never);await review();act(()=>window.dispatchEvent(new Event('popstate')));await act(async()=>finish({...view(),preview:preview()}));expect(screen.queryByRole('checkbox')).toBeNull();expect(mutateRaw).toHaveBeenCalledTimes(1)});
 it('dismisses and expires previews without restoring them from a status read',async()=>{await open();await review();fireEvent.click(screen.getByRole('button',{name:'Dismiss preview'}));expect(screen.queryByRole('checkbox')).toBeNull();fireEvent.click(screen.getByRole('button',{name:'Read saved status'}));await flush();await review();await act(async()=>vi.advanceTimersByTime(61000));expect(screen.queryByRole('checkbox')).toBeNull();expect(mutateRaw).toHaveBeenCalledTimes(2)});
 it('rejects envelopes, inconsistent flags and cross-device previews',()=>{expect(validWindowsActionView(view(),device,actor)).toBe(true);expect(validWindowsActionView({...view(),envelope:'forbidden'},device,actor)).toBe(false);expect(validWindowsActionView({...view(),preview:{...preview(),binding:{...binding,endpointId:`agent_${'9'.repeat(32)}`}}},device,actor)).toBe(false);expect(validWindowsActionView({...approved(),available:true,reason:'ready'},device,actor)).toBe(false)});
});

it('validates and renders the exact synthetic Go operator API fixture',async()=>{
 for(const item of golden.cases){
  for(const value of [item.preview,item.approved,item.complete])expect(validWindowsActionView(value,golden.deviceId,golden.actorId)).toBe(true);
  const goldenSession={...session,actorId:golden.actorId};
  vi.mocked(useOperator).mockReturnValue({...vi.mocked(useOperator)(),actorId:golden.actorId} as ReturnType<typeof useOperator>);
  vi.mocked(request).mockImplementation(async path=>structuredClone(path==='/auth/session'?goldenSession:item.complete) as never);
  render(<WindowsServiceActionsPanel deviceId={golden.deviceId} sessionKey={until}/>);await flush();
  expect(screen.getByRole('status')).toHaveTextContent(item.operation==='stop'?'Stopped observed':'Running observed');
  expect(screen.queryByRole('checkbox')).toBeNull();cleanup();
 }
});

it.each(['en','de'] as const)('leads with outcome and keeps technical receipt and scope collapsed in %s',async locale=>{
 setLocale(locale,false);
 const complete=golden.cases.find(item=>item.operation==='restart')!.complete;
 vi.mocked(useOperator).mockReturnValue({...vi.mocked(useOperator)(),actorId:golden.actorId} as ReturnType<typeof useOperator>);
 vi.mocked(request).mockImplementation(async path=>structuredClone(path==='/auth/session'?{...session,actorId:golden.actorId}:complete) as never);
 const {container}=render(<WindowsServiceActionsPanel deviceId={golden.deviceId} sessionKey={until}/>);await flush();
 const status=screen.getByRole('status'),receipt=container.querySelector<HTMLDetailsElement>('.windows-service-action-receipt')!;
 expect(status.querySelector('strong')).toHaveTextContent(locale==='de'?'Laufender Zustand beobachtet':'Running observed');
 expect(status).toHaveTextContent(locale==='de'?'Neu starten: FixtureService':'Restart: FixtureService');
 expect(status).toHaveTextContent(locale==='de'?'Anwendungszustand ist damit nicht bestätigt':'application health is not established');
 expect(receipt).not.toHaveAttribute('open');
 expect(receipt).toHaveTextContent(locale==='de'?'Versucht / angefordert / beobachtet':'Attempted / requested / observed');
 expect(receipt.querySelector('time')).toHaveAttribute('datetime',complete.job.startDeadline);
 expect(container.querySelectorAll('details')).toHaveLength(2);
 for(const detail of container.querySelectorAll('details'))expect(detail).not.toHaveAttribute('open');
 // Native <details> owns disclosure; the readback remount closes it again.
 fireEvent.click(receipt.querySelector('summary')!);expect(receipt).toHaveAttribute('open');
 fireEvent.click(screen.getByRole('button',{name:locale==='de'?'Gespeicherten Status lesen':'Read saved status'}));await flush();
 expect(container.querySelector('.windows-service-action-receipt')).not.toHaveAttribute('open');
 expect(mutateRaw).not.toHaveBeenCalled();
});

it('keeps the intervention warning visible while its uncertain receipt stays collapsed',async()=>{
 const complete=structuredClone(golden.cases.find(item=>item.operation==='restart')!.complete);
 Object.assign(complete,{available:false,reason:'broker_busy'});Object.assign(complete.job,{state:'needs_intervention'});Object.assign(complete.job.result,{outcome:'intervention-required'});
 vi.mocked(useOperator).mockReturnValue({...vi.mocked(useOperator)(),actorId:golden.actorId} as ReturnType<typeof useOperator>);
 vi.mocked(request).mockImplementation(async path=>structuredClone(path==='/auth/session'?{...session,actorId:golden.actorId}:complete) as never);
 const {container}=render(<WindowsServiceActionsPanel deviceId={golden.deviceId} sessionKey={until}/>);await flush();
 expect(screen.getByRole('status').querySelector('strong')).toHaveTextContent('Outcome uncertain');
 const warning=screen.getByText('Intervention required; further actions blocked',{selector:'p'});
 expect(warning.closest('details')).toBeNull();
 expect(container.querySelector('.windows-service-action-receipt')).not.toHaveAttribute('open');
 expect(screen.queryByRole('button',{name:/Select service/})).toBeNull();
});


describe('Windows action uncertainty across navigation', () => {
 it.each(['lost', 'pending'] as const)('retains %s approval through unmount and idle readback without a replacement', async outcome => {
  const mounted = await open(); await review('restart');
  let finish!: (value: WindowsActionView) => void;
  vi.mocked(mutateRaw).mockImplementationOnce(() => outcome === 'lost' ? Promise.reject(new Error('lost response')) : new Promise(resolve => { finish = resolve; }));
  fireEvent.click(screen.getByRole('checkbox')); fireEvent.click(screen.getByRole('button', { name: 'Approve this action once' })); await flush();
  mounted.unmount(); await open();
  expect(screen.getByRole('alert')).toHaveTextContent('unconfirmed');
  expect(screen.queryByRole('button', { name: /Select service/ })).toBeNull();
  expect(screen.queryByRole('checkbox')).toBeNull(); expect(mutateRaw).toHaveBeenCalledTimes(2);
  if (outcome === 'pending') { await act(async () => finish(approved('restart'))); expect(screen.getByRole('alert')).toHaveTextContent('unconfirmed'); }
  vi.mocked(request).mockImplementation(async path => structuredClone(path === '/auth/session' ? session : approved('restart')) as never);
  fireEvent.click(screen.getByRole('button', { name: 'Read saved status' })); await flush();
  expect(screen.queryByRole('alert')).toBeNull(); expect(screen.getByRole('status')).toHaveTextContent('awaiting one-time claim');
  expect(mutateRaw).toHaveBeenCalledTimes(2); expect(screen.queryByRole('checkbox')).toBeNull();
 });
 it.each(['id', 'sequence', 'actor', 'operation', 'target'] as const)('does not resolve an uncertain approval with a different saved %s', async changed => {
  const mounted = await open(); await review(); vi.mocked(mutateRaw).mockRejectedValueOnce(new Error('lost'));
  fireEvent.click(screen.getByRole('checkbox')); fireEvent.click(screen.getByRole('button', { name: 'Approve this action once' })); await flush(); mounted.unmount();
  const other = approved();
  if (changed === 'id') other.job!.identity.jobId = `action_${'9'.repeat(32)}`;
  if (changed === 'sequence') other.job!.identity.sequence = '2';
  if (changed === 'actor') other.job!.actorId = `operator_${'9'.repeat(32)}`;
  if (changed === 'operation') other.job!.operation = 'stop';
  if (changed === 'target') { other.target = 'OtherService'; other.job!.target = 'OtherService'; }
  vi.mocked(request).mockImplementation(async path => structuredClone(path === '/auth/session' ? session : other) as never); await open();
  expect(screen.getByRole('alert')).toHaveTextContent('unconfirmed'); expect(mutateRaw).toHaveBeenCalledTimes(2);
 });
 it('keeps the fence through suspension but clears it after authentication ends', async () => {
  const mounted = await open(); await review(); vi.mocked(mutateRaw).mockRejectedValueOnce(new Error('lost'));
  fireEvent.click(screen.getByRole('checkbox')); fireEvent.click(screen.getByRole('button', { name: 'Approve this action once' })); await flush();
  act(() => window.dispatchEvent(new Event('pagehide'))); mounted.unmount(); const restored = await open();
  expect(screen.getByRole('alert')).toHaveTextContent('unconfirmed');
  act(() => window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT))); restored.unmount(); await open();
  expect(screen.queryByRole('alert')).toBeNull(); expect(screen.getByRole('button', { name: /Select service/ })).toBeEnabled();
  expect(mutateRaw).toHaveBeenCalledTimes(2);
 });
});


it('preserves an in-flight approval through actual inventory tab away/back navigation', async () => {
 function Inventory() { return <WindowsInventoryWorkspace resource={useWindowsInventory(device, false, until)} fullServices={{ deviceId: device, sessionKey: until, enabled: true }}/>; }
 render(<Inventory/>); await flush(); fireEvent.click(screen.getByRole('tab', { name: 'Services' })); await flush(); await review();
 let finish!: (value: WindowsActionView) => void;
 vi.mocked(mutateRaw).mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
 fireEvent.click(screen.getByRole('checkbox')); fireEvent.click(screen.getByRole('button', { name: 'Approve this action once' })); await flush();
 const submitted = vi.mocked(mutateRaw).mock.calls.at(-1)!;
 fireEvent.click(screen.getByRole('tab', { name: 'Hostname' })); await flush();
 expect(submitted[3]?.aborted).toBe(true); expect(screen.queryByRole('button', { name: 'Read saved status' })).toBeNull();
 fireEvent.click(screen.getByRole('tab', { name: 'Services' })); await flush();
 const actionPanel = () => within(document.querySelector<HTMLElement>('.windows-service-actions')!);
 expect(actionPanel().getByRole('alert')).toHaveTextContent('unconfirmed'); expect(screen.queryByRole('button', { name: /Select service/ })).toBeNull();
 await act(async () => finish(approved())); expect(actionPanel().getByRole('alert')).toHaveTextContent('unconfirmed');
 vi.mocked(request).mockImplementation(async path => structuredClone(path === '/auth/session' ? session : approved()) as never);
 fireEvent.click(screen.getByRole('button', { name: 'Read saved status' })); await flush();
 expect(actionPanel().queryByRole('alert')).toBeNull(); expect(actionPanel().getByRole('status')).toHaveTextContent('awaiting one-time claim');
 expect(vi.mocked(mutateRaw).mock.calls.filter(([path]) => /\/windows-service-actions\/(preview|approve)$/.test(path))).toHaveLength(2); expect(screen.queryByRole('checkbox')).toBeNull();
});


it.each(['device', 'actor', 'session'] as const)('isolates the unresolved fence by %s without erasing it on return', async changed => {
 const first = await open(); await review(); vi.mocked(mutateRaw).mockRejectedValueOnce(new Error('lost'));
 fireEvent.click(screen.getByRole('checkbox')); fireEvent.click(screen.getByRole('button', { name: 'Approve this action once' })); await flush(); first.unmount();
 const nextDevice = changed === 'device' ? `agent_${'9'.repeat(32)}` : device;
 const nextSession = { ...session, actorId: changed === 'actor' ? `operator_${'9'.repeat(32)}` : actor, expiresAt: changed === 'session' ? '2026-10-11T12:00:00Z' : until };
 vi.mocked(useOperator).mockReturnValue({ ...vi.mocked(useOperator)(), actorId: nextSession.actorId, expiresAt: nextSession.expiresAt } as ReturnType<typeof useOperator>);
 vi.mocked(request).mockImplementation(async path => structuredClone(path === '/auth/session' ? nextSession : { ...view(), deviceId: nextDevice }) as never);
 const other = render(<WindowsServiceActionsPanel deviceId={nextDevice} sessionKey={nextSession.expiresAt}/>); await flush();
 expect(screen.queryByRole('alert')).toBeNull(); expect(screen.getByRole('button', { name: /Select service/ })).toBeEnabled(); other.unmount();
 vi.mocked(useOperator).mockReturnValue({ ...vi.mocked(useOperator)(), actorId: actor, expiresAt: until } as ReturnType<typeof useOperator>);
 vi.mocked(request).mockImplementation(async path => structuredClone(path === '/auth/session' ? session : view()) as never); await open();
 expect(screen.getByRole('alert')).toHaveTextContent('unconfirmed'); expect(screen.queryByRole('button', { name: /Select service/ })).toBeNull(); expect(mutateRaw).toHaveBeenCalledTimes(2);
});


it('bounds unresolved approvals globally without eviction and frees capacity only by exact readback', async () => {
 let currentDevice = device;
 let currentSession = session;
 const idle = () => ({ ...view(), deviceId: currentDevice });
 vi.mocked(request).mockImplementation(async path => structuredClone(path === '/auth/session' ? currentSession : idle()) as never);
 vi.mocked(mutateRaw).mockImplementation(async (path, body) => {
  if (path.endsWith('/approve')) throw new Error('lost response');
  return { ...idle(), preview: { ...preview(JSON.parse(body).operation), binding: { ...binding, endpointId: currentDevice } } } as never;
 });
 const mount = async () => { const ui = render(<WindowsServiceActionsPanel deviceId={currentDevice} sessionKey={currentSession.expiresAt}/>); await flush(); return ui; };
 for (let index = 1; index <= 32; index++) {
  currentDevice = `agent_${index.toString(16).padStart(32, '0')}`;
  const ui = await mount(); await review(); fireEvent.click(screen.getByRole('checkbox')); fireEvent.click(screen.getByRole('button', { name: 'Approve this action once' })); await flush();
  expect(screen.getByRole('alert')).toHaveTextContent('unconfirmed'); ui.unmount();
 }
 expect(mutateRaw).toHaveBeenCalledTimes(64);
 currentDevice = `agent_${'f'.repeat(32)}`;
 // A new actor/session still shares the same bounded admission budget.
 currentSession = { ...session, actorId: `operator_${'f'.repeat(32)}`, expiresAt: '2026-10-11T12:00:00Z' };
 vi.mocked(useOperator).mockReturnValue({ ...vi.mocked(useOperator)(), actorId: currentSession.actorId, expiresAt: currentSession.expiresAt } as ReturnType<typeof useOperator>);
 let ui = await mount(); expect(screen.getByRole('alert')).toHaveTextContent('32 unconfirmed'); expect(screen.queryByRole('button', { name: /Select service/ })).toBeNull();
 fireEvent.click(screen.getByRole('button', { name: 'Read saved status' })); await flush(); expect(mutateRaw).toHaveBeenCalledTimes(64); ui.unmount();
 // The oldest entry was not evicted. Idle readback cannot release it.
 currentDevice = `agent_${'1'.padStart(32, '0')}`; currentSession = session;
 vi.mocked(useOperator).mockReturnValue({ ...vi.mocked(useOperator)(), actorId: actor, expiresAt: until } as ReturnType<typeof useOperator>);
 ui = await mount(); expect(screen.getByRole('alert')).toHaveTextContent('response is unconfirmed');
 vi.mocked(request).mockImplementation(async path => structuredClone(path === '/auth/session' ? session : { ...approved(), deviceId: currentDevice }) as never);
 fireEvent.click(screen.getByRole('button', { name: 'Read saved status' })); await flush(); expect(screen.queryByRole('alert')).toBeNull(); ui.unmount();
 currentDevice = `agent_${'f'.repeat(32)}`;
 vi.mocked(request).mockImplementation(async path => structuredClone(path === '/auth/session' ? session : idle()) as never);
 ui = await mount(); expect(screen.queryByRole('alert')).toBeNull(); expect(screen.getByRole('button', { name: /Select service/ })).toBeEnabled(); expect(mutateRaw).toHaveBeenCalledTimes(64); ui.unmount();
});


it.each(['lost', 'pending'] as const)('clears %s prior-session fences on auth epoch change without an AUTH event', async outcome => {
 const mounted = await open(); await review(); let finish!: (value: WindowsActionView) => void;
 vi.mocked(mutateRaw).mockImplementationOnce(() => outcome === 'lost' ? Promise.reject(new Error('lost')) : new Promise(resolve => { finish = resolve; }));
 fireEvent.click(screen.getByRole('checkbox')); fireEvent.click(screen.getByRole('button', { name: 'Approve this action once' })); await flush();
 act(() => abortProtectedRequests()); mounted.unmount(); await open();
 expect(screen.queryByRole('alert')).toBeNull(); expect(screen.getByRole('button', { name: /Select service/ })).toBeEnabled();
 if (outcome === 'pending') { await act(async () => finish(approved())); expect(screen.queryByRole('alert')).toBeNull(); }
 expect(mutateRaw).toHaveBeenCalledTimes(2);
});

it('rejects an old mounted preview after an authentication epoch change', async () => {
 await open(); await review(); fireEvent.click(screen.getByRole('checkbox'));
 act(() => abortProtectedRequests()); fireEvent.click(screen.getByRole('button', { name: 'Approve this action once' })); await flush();
 expect(screen.queryByRole('checkbox')).toBeNull(); expect(mutateRaw).toHaveBeenCalledTimes(1);
});
