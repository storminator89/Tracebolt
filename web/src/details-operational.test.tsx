import userEvent from '@testing-library/user-event';
import { completeView, completeRows, completePage } from './complete-packages-fixtures';
import { overviewView, processRows, volumeRows, overviewPage } from './complete-overview-fixtures';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { DeviceDetail } from './details';
import { APIError, AUTH_REQUIRED_EVENT, mutateRaw, request } from './api';
import { AuthBoundary } from './auth';
import { setLocale } from './i18n';
import type { Device, Metric } from './types';
import type { OperationalView } from './operational-types';
vi.mock('./api',async original=>({...await original<typeof import('./api')>(),request:vi.fn(),mutateRaw:vi.fn()}));
const id='agent_'+'7'.repeat(32);
const metric:Metric={value:null,unit:'%',quality:'unknown',source:'Synthetic integration fixture',collectedAt:'0001-01-01T00:00:00Z'};
function device(overrides:Partial<Device>={}):Device{return {id,name:'Synthetic integration fixture',platform:'linux',os:'Linux fixture',site:'Fixture',group:'Fixture',ip:null,status:'unknown',source:'lan',synthetic:false,lastSeen:'0001-01-01T00:00:00Z',agentVersion:'fixture',cpu:metric,memory:metric,disk:metric,uptime:'',tags:[],capabilities:[],evidence:[],trend:[],caseIds:[],...overrides};}
function view(deviceId=id,status:OperationalView['status']='not_configured'):OperationalView{return {schemaVersion:'tracebolt.operational-view.v1',deviceId,status,serverNow:'2026-10-03T12:00:00Z',receivedAt:null,sequence:null,maxAgeSeconds:120,snapshot:null,lastGood:{volumes:null,network:null,services:null,processes:null,software:null,events:null},assessments:{updates:{quality:'unknown',reason:'not_implemented'},vulnerabilities:{quality:'unknown',reason:'not_implemented'}}};}
const session={mode:'lan',transport:'https',insecureTestMode:false,transportWarning:null,authenticationRequired:true,authenticated:true,csrfToken:'synthetic-session',serverNow:'2026-10-03T12:00:00Z',expiresAt:'2026-10-03T12:30:00Z',expiresInSeconds:1800};
let selected:Device;
beforeEach(()=>{setLocale('en',false);localStorage.clear();sessionStorage.clear();selected=device();vi.mocked(request).mockReset().mockImplementation(async path=>path==='/auth/session'?session:path.endsWith('/operational')?view(selected.id):selected);vi.mocked(mutateRaw).mockReset();});
afterEach(()=>{cleanup();vi.restoreAllMocks();});
function detail(){return <AuthBoundary><DeviceDetail id={selected.id} onClose={vi.fn()} onCase={vi.fn()}/></AuthBoundary>;}
async function inventory(){render(detail());const tab=await screen.findByRole('tab',{name:'Inventory'});fireEvent.click(tab);fireEvent.click(screen.getByText('Legacy inventory source', { selector: 'summary' })); fireEvent.click(screen.getByRole('button', { name: 'Open bounded preview' }));return tab;}
describe('actual device page operational integration',()=>{
 it('loads the protected read model only when the Inventory tab is selected',async()=>{
  render(detail());const tab=await screen.findByRole('tab',{name:'Inventory'});expect(request).not.toHaveBeenCalledWith(expect.stringContaining('/operational'),expect.anything());fireEvent.click(tab);fireEvent.click(screen.getByText('Legacy inventory source', { selector: 'summary' })); fireEvent.click(screen.getByRole('button', { name: 'Open bounded preview' }));
  await screen.findByText('This device is not enrolled for the Linux operational profile. No operational inventory has been collected.');
  expect(tab).toHaveAttribute('aria-selected','true');expect(screen.getByRole('tabpanel',{name:'Inventory'})).toHaveAttribute('aria-labelledby',tab.id);expect(request).toHaveBeenCalledWith(`/devices/${id}/operational`,expect.objectContaining({signal:expect.any(AbortSignal)}));
  expect(screen.getByText('Available updates')).toBeVisible();expect(screen.getByText('Vulnerabilities / CVEs')).toBeVisible();expect(screen.queryByText('Secure')).not.toBeInTheDocument();
 });
 it.each([{synthetic:true},{source:'sandbox' as const},{source:'local' as const}])('does not invent operational support for %j',async overrides=>{
  selected=device(overrides);render(detail());await screen.findByRole('tab',{name:'Overview'});expect(screen.queryByRole('tab',{name:'Inventory'})).not.toBeInTheDocument();expect(request).not.toHaveBeenCalledWith(expect.stringContaining('/operational'),expect.anything());
 });
 it('keeps basic Mac inventory separate without inventing Linux collection or expanded authority',async()=>{
  selected=device({platform:'macos',os:'Basic Mac fixture'});render(detail());
  const tab=await screen.findByRole('tab',{name:'Inventory'});fireEvent.click(tab);
  const panel=screen.getByRole('region',{name:'Mac inventory'});
  expect(within(panel).getByText(/This Mac has basic read-only scope/)).toBeVisible();
  expect(tab).toHaveAttribute('aria-selected','true');expect(screen.getByRole('tabpanel',{name:'Inventory'})).toHaveAttribute('aria-labelledby',tab.id);
  expect(within(panel).getByRole('button',{name:'Refresh inventory'})).toBeDisabled();expect(within(panel).queryByRole('table')).not.toBeInTheDocument();
  expect(screen.queryByText('Legacy inventory source')).not.toBeInTheDocument();expect(screen.queryByText('Operational inventory')).not.toBeInTheDocument();
  expect(vi.mocked(request).mock.calls.every(([path])=>path==='/auth/session'||path===`/devices/${id}`)).toBe(true);
  expect(mutateRaw).not.toHaveBeenCalled();
 });
 it.each(['not_configured','unavailable','missing'] as const)('keeps basic Windows inventory %s without inventing Linux collection',async status=>{
  selected=device({platform:'windows',os:'Basic Windows fixture'});
  vi.mocked(request).mockImplementation(async path=>{
   if(path==='/auth/session')return session;
   if(path===`/devices/${id}`)return selected;
   if(path.endsWith('/windows-inventory')){
    if(status==='missing')throw new APIError('private missing view',404);
    return {schemaVersion:'tracebolt.windows-inventory-view.v1',deviceId:id,collectionProfile:'windows-inventory-v1',serverNow:session.serverNow,maxAgeSeconds:120,status,sequence:null,receivedAt:null,snapshot:null};
   }
   throw new APIError('private unavailable source',404);
  });
  render(detail());const tab=await screen.findByRole('tab',{name:'Inventory'});fireEvent.click(tab);
  const panel=screen.getByRole('region',{name:'Windows inventory'});
  await within(panel).findByText(status==='not_configured'?'Windows inventory is not configured for this identity.':'Windows inventory is unavailable.');
  expect(within(panel).queryByRole('table')).not.toBeInTheDocument();expect(within(panel).queryByText('Recent observation')).not.toBeInTheDocument();
  expect(screen.queryByText('Legacy inventory source')).not.toBeInTheDocument();expect(screen.queryByText('Operational inventory')).not.toBeInTheDocument();
  const paths=vi.mocked(request).mock.calls.map(([path])=>path);
  expect(paths).toContain(`/devices/${id}/windows-inventory`);expect(paths.some(path=>path.endsWith('/operational')||path.includes('/inventory/')||path.endsWith('/packages')||path.includes('/journal'))).toBe(false);
  expect(document.body).not.toHaveTextContent('private missing view');expect(document.body).not.toHaveTextContent('private unavailable source');
 });
 it('permits an unsampled LAN identity to show its explicit awaiting state',async()=>{
  selected=device({platform:'unknown'});vi.mocked(request).mockImplementation(async path=>path==='/auth/session'?session:path.endsWith('/operational')?view(id,'awaiting'):selected);await inventory();await screen.findByText('The operational profile is selected. Waiting for its first accepted observation.');expect(screen.queryByText(/739\d+ days/)).not.toBeInTheDocument();expect(document.querySelector('.detail-badges .status-unknown')).toHaveTextContent('Not assessed');
 });
 it('aborts and suppresses a late response after leaving the operational tab',async()=>{
  let resolve!:(value:OperationalView)=>void;let signal:AbortSignal|undefined;vi.mocked(request).mockImplementation(async(path,options)=>path==='/auth/session'?session:path.endsWith('/operational')?new Promise<OperationalView>(done=>{resolve=done;signal=options?.signal as AbortSignal;}):selected);
  await inventory();await waitFor(()=>expect(signal).toBeDefined());fireEvent.click(screen.getByRole('tab',{name:'Overview'}));expect(signal!.aborted).toBe(true);await act(async()=>resolve(view()));expect(screen.queryByText('Operational inventory')).not.toBeInTheDocument();expect(screen.getByRole('tab',{name:'Overview'})).toHaveAttribute('aria-selected','true');
 });
 it('clears the operational panel when operator access expires',async()=>{
  await inventory();await screen.findByText('Operational inventory');act(()=>window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT)));await screen.findByLabelText('Operator password');expect(screen.queryByRole('region',{name:'Device Synthetic integration fixture'})).not.toBeInTheDocument();expect(screen.queryByText('Operational inventory')).not.toBeInTheDocument();
 });
 it('renders a fixed error with no fabricated inventory on operational GET failure',async()=>{
  vi.mocked(request).mockImplementation(async path=>{if(path==='/auth/session')return session;if(path.endsWith('/operational'))throw new Error('private raw failure');return selected;});await inventory();const alert=await within(screen.getByRole('region',{name:'Operational inventory'})).findByRole('alert');expect(alert).not.toHaveTextContent('private raw failure');expect(screen.queryByRole('table')).not.toBeInTheDocument();
 });
 it('supports arrow and boundary keys between the device tabs',async()=>{
  render(detail());const overview=await screen.findByRole('tab',{name:'Overview'});overview.focus();fireEvent.keyDown(overview,{key:'ArrowRight'});const inventory=screen.getByRole('tab',{name:'Inventory'});expect(inventory).toHaveFocus();expect(inventory).toHaveAttribute('aria-selected','true');fireEvent.keyDown(inventory,{key:'End'});expect(screen.getByRole('tab',{name:/^Capabilities/})).toHaveFocus();fireEvent.keyDown(screen.getByRole('tab',{name:/^Capabilities/}),{key:'Home'});expect(overview).toHaveFocus();expect(overview).toHaveAttribute('aria-selected','true');
 });
 it('retains German tab and operational labels',async()=>{
  setLocale('de',false);render(detail());fireEvent.click(await screen.findByRole('tab',{name:'Inventar'}));fireEvent.click(screen.getByText('Ältere Inventarquelle', { selector: 'summary' })); fireEvent.click(screen.getByRole('button', { name: 'Begrenzte Vorschau öffnen' }));const panel=screen.getByRole('tabpanel',{name:'Inventar'});await within(panel).findByText('Betriebsinventar');expect(within(panel).getByRole('button',{name:'Beobachtungen aktualisieren'})).toBeInTheDocument();
 });
});

 it.each([['complete_process_inventory','Processes','Open processes'],['package_inventory','Packages','Open packages']])('opens the exact %s source from capabilities without a route or action write',async(capability,source,button)=>{
  selected=device({capabilities:[{id:capability,name:source,status:'scope',detail:'Fixture'}]});
  const overview=overviewView(); overview.deviceId=id; const packages=completeView(); packages.deviceId=id;
  vi.mocked(request).mockImplementation(async path=>path==='/auth/session'?{...session,serverNow:overview.serverNow,expiresAt:'2026-10-05T00:00:00Z'}:path.endsWith('/inventory/overview')?overview:path.endsWith('/inventory/packages')?packages:selected);
  render(detail()); fireEvent.click(await screen.findByRole('tab',{name:/Capabilities/}));
  fireEvent.click(await screen.findByRole('button',{name:button}));
  const inventoryTab=screen.getByRole('tab',{name:'Inventory'});
  expect(inventoryTab).toHaveAttribute('aria-selected','true'); expect(source==='Packages'?screen.getByRole('tab',{name:source}):inventoryTab).toHaveFocus();
  expect(screen.getByRole('tab',{name:source})).toHaveAttribute('aria-selected','true');
  expect(mutateRaw).not.toHaveBeenCalled();
 });

// Await the destination rows: opening a view can schedule bounded read queries.
it.each(['en', 'de'] as const)('both capability destinations finish only their bounded read queries (%s)', async locale => {
 for (const source of ['packages', 'processes'] as const) {
  cleanup(); vi.mocked(request).mockReset(); vi.mocked(mutateRaw).mockReset(); setLocale(locale, false);
  const capability = source === 'packages' ? 'package_inventory' : 'complete_process_inventory';
  selected = device({ capabilities: [{ id: capability, name: source, status: 'scope', detail: 'Fixture' }] });
  const overview = overviewView(1, 1); overview.deviceId = id;
  const packages = completeView(1); packages.deviceId = id;
  const endpoint = `/devices/${id}/inventory/${source === 'packages' ? 'packages' : 'overview'}/query`;
  vi.mocked(request).mockImplementation(async path => path === '/auth/session' ? { ...session, serverNow: overview.serverNow, expiresAt: '2026-10-05T00:00:00Z' } : path.endsWith('/inventory/overview') ? overview : path.endsWith('/inventory/packages') ? packages : selected);
  vi.mocked(mutateRaw).mockImplementation(async (path, raw) => {
   expect(path).toBe(endpoint);
   const body = JSON.parse(raw);
   expect(body).toMatchObject({ cursor: '', search: '', limit: 100, generationId: source === 'packages' ? packages.complete!.binding.generationId : overview.processes.complete!.binding.generationId });
   if (source === 'processes') expect(body.section).toBe('processes');
   return source === 'packages' ? completePage(packages, completeRows(1), raw) : overviewPage(overview, processRows(1), volumeRows(1), raw);
  });
  const oldHash = window.location.hash;
  render(detail()); fireEvent.click(await screen.findByRole('tab', { name: locale === 'de' ? /^Fähigkeiten/ : /^Capabilities/ }));
  const openLabel = source === 'packages' ? locale === 'de' ? 'Pakete öffnen' : 'Open packages' : locale === 'de' ? 'Prozesse öffnen' : 'Open processes';
  const open = await screen.findByRole('button', { name: openLabel });
  expect(mutateRaw).not.toHaveBeenCalled(); fireEvent.click(open);
  await screen.findByText(source === 'packages' ? 'fixture-000000' : 'fixture-process-000000', { selector: source === 'packages' ? 'th' : 'td' });
  expect(vi.mocked(mutateRaw).mock.calls.map(([path]) => path)).toEqual([endpoint]);
  expect(vi.mocked(request).mock.calls.some(([path]) => /process-watches|policy|prepare|approve|execute|capture/.test(path))).toBe(false);
  expect(window.location.hash).toBe(oldHash);
  const inventory = screen.getByRole('tab', { name: locale === 'de' ? 'Inventar' : 'Inventory' });
  const destination = screen.getByRole('tab', { name: source === 'packages' ? locale === 'de' ? 'Pakete' : 'Packages' : locale === 'de' ? 'Prozesse' : 'Processes' });
  expect(inventory).toHaveAttribute('aria-selected', 'true'); expect(destination).toHaveAttribute('aria-selected', 'true');
  expect(source === 'packages' ? destination : inventory).toHaveFocus();
  act(() => window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT)));
  await screen.findByLabelText(locale === 'de' ? 'Operator-Passwort' : 'Operator password');
  expect(screen.queryByText(source === 'packages' ? 'fixture-000000' : 'fixture-process-000000', { selector: source === 'packages' ? 'th' : 'td' })).toBeNull();
  expect(vi.mocked(mutateRaw).mock.calls.map(([path]) => path)).toEqual([endpoint]);
 }
});

describe('package shortcut keyboard continuity',()=>{
 it.each(['en','de'] as const)('preserves destination focus and read-only query from both entrypoints (%s)',async locale=>{
  for(const source of ['details','security'] as const){
   cleanup();vi.mocked(request).mockReset();vi.mocked(mutateRaw).mockReset();setLocale(locale,false);const user=userEvent.setup();
   const packages=completeView(1);packages.deviceId=id;const endpoint=`/devices/${id}/inventory/packages/query`;
   vi.mocked(request).mockImplementation(async path=>path==='/auth/session'?{...session,serverNow:packages.serverNow,expiresAt:'2026-10-05T00:00:00Z'}:path.endsWith('/inventory/packages')?packages:selected);
   vi.mocked(mutateRaw).mockImplementation(async(path,raw)=>{expect(path).toBe(endpoint);expect(JSON.parse(raw)).toMatchObject({cursor:'',search:'',limit:100,generationId:packages.complete!.binding.generationId});return completePage(packages,completeRows(1),raw);});
   render(detail());fireEvent.click(await screen.findByRole('tab',{name:source==='details'?'Details':locale==='de'?/Sicherheitsabdeckung/:/Security coverage/}));
   const open=await screen.findByRole('button',{name:/^(Open Packages|Open packages|Pakete öffnen)$/});open.focus();expect(open).toHaveFocus();expect(mutateRaw).not.toHaveBeenCalled();await user.keyboard(source==='details'?'{Enter}':' ');
   await screen.findByText('fixture-000000',{selector:'th'});const destination=screen.getByRole('tab',{name:locale==='de'?'Pakete':'Packages'});expect(destination).toHaveAttribute('aria-selected','true');expect(destination).toHaveFocus();expect(open).not.toBeInTheDocument();expect(vi.mocked(mutateRaw).mock.calls.map(([path])=>path)).toEqual([endpoint]);
   act(()=>window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT)));await screen.findByLabelText(locale==='de'?'Operator-Passwort':'Operator password');expect(destination).not.toBeInTheDocument();expect(screen.queryByText('fixture-000000',{selector:'th'})).toBeNull();expect(vi.mocked(mutateRaw).mock.calls.map(([path])=>path)).toEqual([endpoint]);
  }
 });
});
