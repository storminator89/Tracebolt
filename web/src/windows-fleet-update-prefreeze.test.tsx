import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { AUTH_REQUIRED_EVENT, mutateRaw, request } from './api';
import { useOperator } from './auth';
import { setLocale } from './i18n';
import type { Device } from './types';
import { useWindowsInventory } from './windows-inventory-resource';
import { WindowsFleetUpdateWorklist } from './windows-fleet-update-worklist';
import { windowsUpdatesView } from './windows-updates-fixture';
vi.mock('./api',async original=>({...await original<typeof import('./api')>(),request:vi.fn(),mutateRaw:vi.fn()}));
vi.mock('./auth',async original=>({...await original<typeof import('./auth')>(),useOperator:vi.fn()}));
vi.mock('./windows-inventory-resource',()=>({useWindowsInventory:vi.fn()}));
const first=`agent_${'1'.repeat(32)}`,second=`agent_${'2'.repeat(32)}`,now='2026-10-11T10:00:00Z',until='2026-10-11T11:00:00Z';
const selection={updateId:'11111111-2222-3333-4444-555555555555',revision:3};
const devices=[{id:first,name:'Workstation A',platform:'windows',source:'lan',synthetic:false},{id:second,name:'Workstation B',platform:'windows',source:'lan',synthetic:false}] as Device[];
const session={mode:'lan',transport:'https',insecureTestMode:false,transportWarning:null,authenticationRequired:true,authenticated:true,csrfToken:'csrf',serverNow:now,expiresAt:until,expiresInSeconds:3600,loginMode:'named',actorId:`operator_${'2'.repeat(32)}`,capabilities:['read','windows_update_install']};
const base=(id:string)=>({version:'tracebolt.windows-selected-update-job.v1',deviceId:id,serverNow:Date.parse(now)/1000,available:true,reason:'ready',job:null});
function inventory(id:string){const value=windowsUpdatesView(1);value.deviceId=id;value.serverNow=now;value.receivedAt=now;value.snapshot!.collectedAt=now;value.updates.collectedAt=now;Object.assign(value.updates.rows[0],selection,{title:'Exact cached revision',revision:id===first?3:4});return value;}
const flush=()=>act(async()=>{});
const text=(de=false)=>({title:de?'Windows-Updatearbeitsliste':'Windows update worklist',read:de?'Cache-Updates lesen':'Read cached updates',freeze:de?'Geräteauswahl festhalten':'Freeze device selection',select:de?'Update zur Prüfung auswählen':'Select update for review',clear:de?'Updateauswahl zurücksetzen':'Clear selected update',all:de?'Alle festgehaltenen Geräte anzeigen':'Show all frozen devices'});
function choose(de=false){fireEvent.click(screen.getByRole('button',{name:text(de).title}));for(const name of ['Workstation A','Workstation B'])fireEvent.click(screen.getByRole('checkbox',{name:new RegExp(name)}));}
async function read(de=false){fireEvent.click(screen.getByRole('button',{name:text(de).read}));await flush();}
function select(de=false){fireEvent.click(screen.getByRole('button',{name:`${text(de).select}: ${selection.updateId} · rev. 3`}));}
beforeEach(()=>{
 vi.useFakeTimers();vi.setSystemTime(now);setLocale('en',false);session.actorId=`operator_${crypto.randomUUID().replaceAll('-','')}`;
 vi.mocked(useOperator).mockReturnValue({...session,theme:'light',logout:vi.fn(),setTheme:vi.fn()} as never);
 vi.mocked(useWindowsInventory).mockReset().mockReturnValue({loading:false,updates:{rows:[{...selection,title:'Exact cached revision'}]}} as never);
 vi.mocked(request).mockReset().mockImplementation(async path=>structuredClone(path==='/auth/session'?session:path.endsWith('/windows-inventory')?inventory(path.split('/')[2]):base(path.split('/')[2])) as never);
 vi.mocked(mutateRaw).mockReset().mockImplementation(async(path,raw,_headers,_signal,_cap,beforeSend)=>{if(beforeSend&&!beforeSend())throw new Error('Canceled');const id=JSON.parse(raw).requestId,deviceId=path.split('/')[2];return {...base(deviceId),available:false,reason:'job_pending_or_intervention',job:{id,selection,state:'requested',reason:'readiness_pending',preview:null,result:null}} as never});
});
afterEach(()=>{cleanup();vi.useRealTimers();vi.restoreAllMocks()});

it.each(['en','de'] as const)('allows an explicit cache review before freezing and preserves exact intent without another read in %s',async locale=>{
 const de=locale==='de',c=text(de);setLocale(locale,false);render(<WindowsFleetUpdateWorklist devices={devices}/>);choose(de);
 expect(screen.getByRole('button',{name:c.read})).toBeEnabled();expect(request).not.toHaveBeenCalled();expect(useWindowsInventory).not.toHaveBeenCalled();
 await read(de);expect(request).toHaveBeenCalledTimes(2);expect(mutateRaw).not.toHaveBeenCalled();expect(screen.queryByRole('button',{name:/^(Open device|Gerät öffnen):/})).toBeNull();
 fireEvent.change(screen.getByRole('searchbox'),{target:{value:'KB1000000'}});select(de);
 expect(screen.getByRole('checkbox',{name:/Workstation A/})).toBeChecked();expect(screen.getByRole('checkbox',{name:/Workstation B/})).toBeChecked();expect(screen.getByRole('button',{name:c.clear})).toBeVisible();
 fireEvent.click(screen.getByRole('button',{name:c.freeze}));await flush();expect(request).toHaveBeenCalledTimes(2);expect(screen.getByText(`${de?'Festgehaltene Auswahl':'Frozen selection'} · 2`)).toBeVisible();
 expect(screen.getByRole('button',{name:`${de?'Gerät öffnen':'Open device'}: Workstation A`})).toBeVisible();expect(screen.queryByRole('button',{name:`${de?'Gerät öffnen':'Open device'}: Workstation B`})).toBeNull();expect(mutateRaw).not.toHaveBeenCalled();
 fireEvent.click(screen.getByRole('button',{name:`${de?'Gerät öffnen':'Open device'}: Workstation A`}));await flush();expect(useWindowsInventory).toHaveBeenCalledWith(first,true,until);expect(screen.queryByRole('combobox',{name:de?'Exaktes Cache-Update auswählen':'Choose an exact cached update'})).toBeNull();
 fireEvent.click(screen.getByRole('button',{name:de?'Bereitschaft prüfen':'Check readiness'}));await flush();expect(mutateRaw).toHaveBeenCalledTimes(1);expect(JSON.parse(vi.mocked(mutateRaw).mock.calls[0][1])).toMatchObject(selection);
 fireEvent.click(screen.getByRole('button',{name:c.all}));expect(screen.getByRole('button',{name:`${de?'Gerät öffnen':'Open device'}: Workstation B`})).toBeVisible();expect(mutateRaw).toHaveBeenCalledTimes(1);
});
it('clears the draft review when selected IDs change, without silently selecting another update',async()=>{
 render(<WindowsFleetUpdateWorklist devices={devices}/>);choose();await read();select();fireEvent.click(screen.getByRole('checkbox',{name:/Workstation B/}));await flush();
 expect(screen.queryByRole('searchbox')).toBeNull();expect(screen.queryByRole('button',{name:text().clear})).toBeNull();expect(request).toHaveBeenCalledTimes(2);
 await read();expect(request).toHaveBeenCalledTimes(3);expect(screen.queryByRole('button',{name:`${text().select}: ${selection.updateId} · rev. 4`})).toBeNull();
 fireEvent.click(screen.getByRole('button',{name:text().freeze}));await flush();fireEvent.click(screen.getByRole('button',{name:'Open device: Workstation A'}));await flush();expect(screen.getByRole('combobox',{name:'Choose an exact cached update'})).toHaveValue('');expect(mutateRaw).not.toHaveBeenCalled();
});
it('does not start reads for newly appearing devices and clears changed draft membership',async()=>{
 const ui=render(<WindowsFleetUpdateWorklist devices={devices}/>);choose();await read();select();ui.rerender(<WindowsFleetUpdateWorklist devices={[devices[0],{...devices[1],id:`agent_${'3'.repeat(32)}`,name:'New member'}]}/>);await flush();
 expect(screen.getByRole('checkbox',{name:/New member/})).not.toBeChecked();expect(screen.queryByRole('searchbox')).toBeNull();expect(request).toHaveBeenCalledTimes(2);expect(mutateRaw).not.toHaveBeenCalled();
});
it.each(['blur','pagehide','popstate','hashchange',AUTH_REQUIRED_EVENT,'hidden','close'])('clears a draft review on %s and does not restore it when freezing',async event=>{
 render(<WindowsFleetUpdateWorklist devices={devices}/>);choose();await read();select();
 if(event==='hidden'){vi.spyOn(document,'hidden','get').mockReturnValue(true);act(()=>document.dispatchEvent(new Event('visibilitychange')));vi.spyOn(document,'hidden','get').mockReturnValue(false);}
 else if(event==='close'){fireEvent.click(screen.getByRole('button',{name:text().title}));fireEvent.click(screen.getByRole('button',{name:text().title}));}
 else act(()=>window.dispatchEvent(new Event(event)));
 expect(screen.queryByRole('searchbox')).toBeNull();fireEvent.click(screen.getByRole('button',{name:text().freeze}));await flush();expect(screen.getByRole('button',{name:'Open device: Workstation A'})).toBeVisible();expect(screen.getByRole('button',{name:'Open device: Workstation B'})).toBeVisible();expect(request).toHaveBeenCalledTimes(2);expect(mutateRaw).not.toHaveBeenCalled();
});
it('cannot revive a late draft response after selecting a different set of devices',async()=>{
 let resolve!:(value:unknown)=>void;vi.mocked(request).mockImplementationOnce(()=>new Promise(r=>{resolve=r}) as never);
 render(<WindowsFleetUpdateWorklist devices={devices}/>);choose();await read();fireEvent.click(screen.getByRole('checkbox',{name:/Workstation A/}));await act(async()=>resolve(inventory(first)));
 expect(screen.queryByRole('searchbox')).toBeNull();fireEvent.click(screen.getByRole('button',{name:text().freeze}));await flush();expect(screen.queryByRole('button',{name:'Open device: Workstation A'})).toBeNull();expect(screen.getByRole('button',{name:'Open device: Workstation B'})).toBeVisible();expect(mutateRaw).not.toHaveBeenCalled();
});
it('does not restart the original five-minute retention deadline when freezing',async()=>{
 vi.spyOn(performance,'now').mockImplementation(()=>Date.now()-Date.parse(now));
 render(<WindowsFleetUpdateWorklist devices={devices}/>);choose();await read();select();
 act(()=>vi.advanceTimersByTime(240000));fireEvent.click(screen.getByRole('button',{name:text().freeze}));await flush();expect(screen.queryByRole('button',{name:'Open device: Workstation B'})).toBeNull();
 act(()=>vi.advanceTimersByTime(60000));expect(screen.queryByRole('searchbox')).toBeNull();expect(screen.getByRole('button',{name:'Open device: Workstation B'})).toBeVisible();expect(request).toHaveBeenCalledTimes(2);expect(mutateRaw).not.toHaveBeenCalled();
});
it('clears review and chosen devices on operator replacement',async()=>{
 const ui=render(<WindowsFleetUpdateWorklist devices={devices}/>);choose();await read();select();vi.mocked(useOperator).mockReturnValue({...session,actorId:`operator_${'9'.repeat(32)}`,theme:'light',logout:vi.fn(),setTheme:vi.fn()} as never);ui.rerender(<WindowsFleetUpdateWorklist devices={devices}/>);await flush();
 expect(screen.queryByRole('searchbox')).toBeNull();expect(screen.queryByRole('button',{name:text().read})).toBeNull();expect(screen.getByRole('button',{name:text().freeze})).toBeDisabled();expect(mutateRaw).not.toHaveBeenCalled();
});
it('keeps frozen IDs fixed when the visible fleet changes',async()=>{
 const ui=render(<WindowsFleetUpdateWorklist devices={devices} allDevices={devices}/>);choose();await read();select();fireEvent.click(screen.getByRole('button',{name:text().freeze}));await flush();ui.rerender(<WindowsFleetUpdateWorklist devices={[devices[1]]} allDevices={devices}/>);await flush();
 const triage=screen.getByRole('region',{name:'Cached update triage'});expect(within(triage).getAllByRole('status')[0]).toHaveTextContent('Reports read: 2/2');expect(screen.getByRole('button',{name:'Open device: Workstation A'})).toBeVisible();expect(request).toHaveBeenCalledTimes(2);expect(mutateRaw).not.toHaveBeenCalled();
});

it('preserves the review through same-membership fleet reordering and keeps the local search when freezing',async()=>{
 const ui=render(<WindowsFleetUpdateWorklist devices={devices}/>);choose();await read();select();fireEvent.change(screen.getByRole('searchbox'),{target:{value:'KB1000000'}});
 ui.rerender(<WindowsFleetUpdateWorklist devices={[...devices].reverse()}/>);await flush();expect(screen.getByRole('button',{name:text().clear})).toBeVisible();expect(screen.getByRole('searchbox')).toHaveValue('KB1000000');
 fireEvent.click(screen.getByRole('button',{name:text().freeze}));await flush();expect(screen.getByRole('searchbox')).toHaveValue('KB1000000');expect(screen.getByRole('button',{name:'Open device: Workstation A'})).toBeVisible();expect(screen.queryByRole('button',{name:'Open device: Workstation B'})).toBeNull();expect(request).toHaveBeenCalledTimes(2);expect(mutateRaw).not.toHaveBeenCalled();
});
it('allows an unchanged in-flight read to finish after freezing without restarting or auto-reviewing',async()=>{
 let resolve!:(value:unknown)=>void;vi.mocked(request).mockImplementationOnce(()=>new Promise(r=>{resolve=r}) as never);
 render(<WindowsFleetUpdateWorklist devices={devices}/>);choose();await read();fireEvent.click(screen.getByRole('button',{name:text().freeze}));await act(async()=>resolve(inventory(first)));
 expect(request).toHaveBeenCalledTimes(2);expect(screen.getByRole('button',{name:`Review reporting devices: ${selection.updateId} · rev. 3`})).toBeVisible();expect(screen.getByRole('button',{name:'Open device: Workstation A'})).toBeVisible();expect(screen.getByRole('button',{name:'Open device: Workstation B'})).toBeVisible();expect(useWindowsInventory).not.toHaveBeenCalled();expect(mutateRaw).not.toHaveBeenCalled();
});
