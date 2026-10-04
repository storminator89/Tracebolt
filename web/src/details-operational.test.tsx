import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { DeviceDetail } from './details';
import { AUTH_REQUIRED_EVENT, request } from './api';
import { AuthBoundary } from './auth';
import { setLocale } from './i18n';
import type { Device, Metric } from './types';
import type { OperationalView } from './operational-types';
vi.mock('./api',async original=>({...await original<typeof import('./api')>(),request:vi.fn()}));
const id='agent_'+'7'.repeat(32);
const metric:Metric={value:null,unit:'%',quality:'unknown',source:'Synthetic integration fixture',collectedAt:'0001-01-01T00:00:00Z'};
function device(overrides:Partial<Device>={}):Device{return {id,name:'Synthetic integration fixture',platform:'linux',os:'Linux fixture',site:'Fixture',group:'Fixture',ip:null,status:'unknown',source:'lan',synthetic:false,lastSeen:'0001-01-01T00:00:00Z',agentVersion:'fixture',cpu:metric,memory:metric,disk:metric,uptime:'',tags:[],capabilities:[],evidence:[],trend:[],caseIds:[],...overrides};}
function view(deviceId=id,status:OperationalView['status']='not_configured'):OperationalView{return {schemaVersion:'tracebolt.operational-view.v1',deviceId,status,serverNow:'2026-10-03T12:00:00Z',receivedAt:null,sequence:null,maxAgeSeconds:120,snapshot:null,lastGood:{volumes:null,network:null,services:null,processes:null,software:null,events:null},assessments:{updates:{quality:'unknown',reason:'not_implemented'},vulnerabilities:{quality:'unknown',reason:'not_implemented'}}};}
const session={mode:'lan',transport:'https',insecureTestMode:false,transportWarning:null,authenticationRequired:true,authenticated:true,csrfToken:'synthetic-session',serverNow:'2026-10-03T12:00:00Z',expiresAt:'2026-10-03T12:30:00Z',expiresInSeconds:1800};
let selected:Device;
beforeEach(()=>{setLocale('en',false);localStorage.clear();sessionStorage.clear();selected=device();vi.mocked(request).mockReset().mockImplementation(async path=>path==='/auth/session'?session:path.endsWith('/operational')?view(selected.id):selected);});
afterEach(()=>{cleanup();vi.restoreAllMocks();});
function detail(){return <AuthBoundary><DeviceDetail id={selected.id} onClose={vi.fn()} onCase={vi.fn()}/></AuthBoundary>;}
async function inventory(){render(detail());const tab=await screen.findByRole('tab',{name:'Inventory'});fireEvent.click(tab);return tab;}
describe('actual device page operational integration',()=>{
 it('loads the protected read model only when the Inventory tab is selected',async()=>{
  render(detail());const tab=await screen.findByRole('tab',{name:'Inventory'});expect(request).not.toHaveBeenCalledWith(expect.stringContaining('/operational'),expect.anything());fireEvent.click(tab);
  await screen.findByText('This device is not enrolled for the Linux operational profile. No operational inventory has been collected.');
  expect(tab).toHaveAttribute('aria-selected','true');expect(screen.getByRole('tabpanel',{name:'Inventory'})).toHaveAttribute('aria-labelledby',tab.id);expect(request).toHaveBeenCalledWith(`/devices/${id}/operational`,expect.objectContaining({signal:expect.any(AbortSignal)}));
  expect(screen.getByText('Available updates')).toBeVisible();expect(screen.getByText('Vulnerabilities / CVEs')).toBeVisible();expect(screen.queryByText('Secure')).not.toBeInTheDocument();
 });
 it.each([{synthetic:true},{source:'sandbox' as const},{source:'local' as const},{platform:'windows' as const},{platform:'macos' as const}])('does not invent operational support for %j',async overrides=>{
  selected=device(overrides);render(detail());await screen.findByRole('tab',{name:'Overview'});expect(screen.queryByRole('tab',{name:'Inventory'})).not.toBeInTheDocument();expect(request).not.toHaveBeenCalledWith(expect.stringContaining('/operational'),expect.anything());
 });
 it('permits an unsampled LAN identity to show its explicit awaiting state',async()=>{
  selected=device({platform:'unknown'});vi.mocked(request).mockImplementation(async path=>path==='/auth/session'?session:path.endsWith('/operational')?view(id,'awaiting'):selected);await inventory();await screen.findByText('The operational profile is selected. Waiting for its first accepted observation.');expect(screen.queryByText(/739\d+ days/)).not.toBeInTheDocument();expect(document.querySelector('.detail-badges .status-unknown')).toHaveTextContent('Unknown');
 });
 it('aborts and suppresses a late response after leaving the operational tab',async()=>{
  let resolve!:(value:OperationalView)=>void;let signal:AbortSignal|undefined;vi.mocked(request).mockImplementation(async(path,options)=>path==='/auth/session'?session:path.endsWith('/operational')?new Promise<OperationalView>(done=>{resolve=done;signal=options?.signal as AbortSignal;}):selected);
  await inventory();await waitFor(()=>expect(signal).toBeDefined());fireEvent.click(screen.getByRole('tab',{name:'Overview'}));expect(signal!.aborted).toBe(true);await act(async()=>resolve(view()));expect(screen.queryByText('Operational inventory')).not.toBeInTheDocument();expect(screen.getByRole('tab',{name:'Overview'})).toHaveAttribute('aria-selected','true');
 });
 it('clears the operational panel when operator access expires',async()=>{
  await inventory();await screen.findByText('Operational inventory');act(()=>window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT)));await screen.findByLabelText('Operator password');expect(screen.queryByRole('region',{name:'Device Synthetic integration fixture'})).not.toBeInTheDocument();expect(screen.queryByText('Operational inventory')).not.toBeInTheDocument();
 });
 it('renders a fixed error with no fabricated inventory on operational GET failure',async()=>{
  vi.mocked(request).mockImplementation(async path=>{if(path==='/auth/session')return session;if(path.endsWith('/operational'))throw new Error('private raw failure');return selected;});await inventory();const alert=await screen.findByRole('alert');expect(alert).not.toHaveTextContent('private raw failure');expect(screen.queryByRole('table')).not.toBeInTheDocument();
 });
 it('supports arrow and boundary keys between the device tabs',async()=>{
  render(detail());const overview=await screen.findByRole('tab',{name:'Overview'});overview.focus();fireEvent.keyDown(overview,{key:'ArrowRight'});const inventory=screen.getByRole('tab',{name:'Inventory'});expect(inventory).toHaveFocus();expect(inventory).toHaveAttribute('aria-selected','true');fireEvent.keyDown(inventory,{key:'End'});expect(screen.getByRole('tab',{name:/^Capabilities/})).toHaveFocus();fireEvent.keyDown(screen.getByRole('tab',{name:/^Capabilities/}),{key:'Home'});expect(overview).toHaveFocus();expect(overview).toHaveAttribute('aria-selected','true');
 });
 it('retains German tab and operational labels',async()=>{
  setLocale('de',false);render(detail());fireEvent.click(await screen.findByRole('tab',{name:'Inventar'}));const panel=screen.getByRole('tabpanel',{name:'Inventar'});await within(panel).findByText('Betriebsinventar');expect(within(panel).getByRole('button',{name:'Beobachtungen aktualisieren'})).toBeInTheDocument();
 });
});
