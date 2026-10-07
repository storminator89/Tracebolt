/** Bind hosted copy expectations to actual production rendering. */
import { act, cleanup, fireEvent, render, screen, waitFor } from '../../web/node_modules/@testing-library/react/dist/index.js';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { request, mutateRaw, abortProtectedRequests } from '../../web/src/api';
import { useOperator } from '../../web/src/auth';
import { setLocale } from '../../web/src/i18n';
import { ApplicationChecksPanel } from '../../web/src/application-checks';
import { applicationViewV2, applicationDNSRow, disabledApplicationViewV2 } from '../../web/src/application-checks-v2-fixtures';
import { AlarmStatusPanel } from '../../web/src/alarm-status';
import { JournalContent } from '../../web/src/journal';
import { journalView } from '../../web/src/journal-fixtures';
import { FleetIdentityName } from '../../web/src/fleet-identity';
import { fleetIdentityProjection } from '../../web/src/fleet-identity-types';
import { endpointView, endpointDevice } from '../../web/src/endpoint-identity-fixtures';
import { DeviceDetail } from '../../web/src/details';
import { EndpointIdentityPanel } from '../../web/src/endpoint-identity';
import { Status } from '../../web/src/components';
import { emptyEndpointView } from '../../web/src/endpoint-identity-fixtures';
import { systemPage, systemView, serviceRows } from '../../web/src/system-inventory-fixtures';
import { actionSession, actionView, actionDevice } from '../../web/src/service-action-fixtures';
import { openServiceActionDisplay } from './service-action-display-navigation.mjs';
import { conciseCopy } from './concise-copy-contracts.mjs';
import { conciseShellTargets } from './concise-shell-gallery.mjs';
import type { Device } from '../../web/src/types';
import type { JournalResource } from '../../web/src/journal-resource';
vi.mock('../../web/src/api', async original => ({ ...await original<typeof import('../../web/src/api')>(), request: vi.fn(), mutateRaw: vi.fn() }));
vi.mock('../../web/src/auth', async original => ({ ...await original<typeof import('../../web/src/auth')>(), useOperator: vi.fn() }));
const operator = { mode: 'lan' as const, authenticated: true, expiresAt: '2026-10-06T14:00:00Z', insecureTestMode: false, logout: vi.fn(), theme: 'light' as const, setTheme: vi.fn() };
beforeEach(() => {
 localStorage.clear(); sessionStorage.clear(); setLocale('en', false);
 vi.spyOn(document, 'hasFocus').mockReturnValue(true); vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('visible');
 vi.mocked(useOperator).mockReturnValue(operator); vi.mocked(request).mockReset(); vi.mocked(mutateRaw).mockReset();
});
afterEach(() => { cleanup(); abortProtectedRequests(); vi.restoreAllMocks(); });
const flush = () => act(async () => {});
describe('concise browser copy matches rendered production meaning', () => {
 it('keeps default-off local identity consent and unassessed health explicit while no observation exists', () => {
  const refresh=vi.fn();
  render(<><EndpointIdentityPanel resource={{view:emptyEndpointView('not_collected'),snapshot:null,loading:false,recovering:false,error:null,elapsed:0,refresh}}/><Status status="unknown" source="lan" synthetic={false}/></>);
  expect(screen.getByText(conciseCopy.endpointPermission)).toBeVisible();
  expect(screen.getByText('No accepted hostname or interface observation')).toBeVisible();
  expect(screen.getByText('No hostname or address values are shown in this state.')).toBeVisible();
  expect(document.querySelector('.endpoint-hostname-value,.endpoint-interface,.endpoint-identity input')).toBeNull();
  expect(screen.getByText('Not assessed')).toHaveAttribute('title','Overall health has not been assessed. The last observation time is shown separately.');
  expect(request).not.toHaveBeenCalled();expect(mutateRaw).not.toHaveBeenCalled();expect(refresh).not.toHaveBeenCalled();
 });
 it('retains DNS source/approval limits in the mixed application view', async () => {
  vi.mocked(request).mockResolvedValue(applicationViewV2([applicationDNSRow()]));render(<ApplicationChecksPanel/>);await flush();
  fireEvent.click(screen.getByText('Observation scope',{selector:'summary'}));
  expect(screen.getByRole('region',{name:'Application checks'})).toHaveTextContent(conciseCopy.applicationDNS);
  expect(vi.mocked(request).mock.calls.every(([path,init])=>path==='/application-checks/status'&&!init?.method&&!init?.body)).toBe(true);
 });
 it('retains separate exact-target, LAN and plaintext approvals in German disabled guidance', async () => {
  setLocale('de',false);vi.mocked(request).mockResolvedValue(disabledApplicationViewV2());render(<ApplicationChecksPanel/>);await flush();
  fireEvent.click(screen.getByText('Einrichtung und Freigaben',{selector:'summary'}));
  expect(screen.getByRole('region',{name:'Anwendungsprüfungen'})).toHaveTextContent(conciseCopy.applicationApprovalDE);
  expect(screen.getByRole('link',{name:'Prüfung hinzufügen'})).toHaveAttribute('href','#/settings/application-checks');expect(document.querySelector('form,input,select')).toBeNull();
 });
 it('distinguishes browser Loaded time from event/server time without enabling sending', async () => {
  vi.mocked(request).mockResolvedValue({schemaVersion:'tracebolt.alarm-status.v1',enabled:false,queued:0,inFlight:0,providerAccepted:0,failed:0,uncertain:0,suppressed:0,dropped:0});
  render(<AlarmStatusPanel/>);await flush();fireEvent.click(screen.getByText('Details',{selector:'summary'}));const panel=screen.getByRole('region',{name:'Alarm delivery'});
  expect(panel).toHaveTextContent(conciseCopy.alarmBrowserTime);expect(panel).toHaveTextContent('Delivery is disabled in manager configuration.');
  expect(panel.querySelector('form,input,select')).toBeNull();expect(request).toHaveBeenCalledTimes(1);
 });
 it('keeps reference/no-capture meaning, then clears and locks the paused log view', () => {
  const resource:JournalResource={view:journalView('awaiting'),page:null,busy:false,paused:false,failure:null,uncertain:false,reset:0,refresh:vi.fn(),refreshWindow:vi.fn(async()=>null),create:vi.fn(async()=>{}),cancelRequest:vi.fn(),search:vi.fn(),next:vi.fn(),previous:vi.fn(),canPrevious:false};
  const mounted=render(<JournalContent resource={resource} insecureTestMode/>);fireEvent.click(screen.getByText('Advanced',{selector:'summary'}));
  expect(screen.getByRole('region',{name:'Logs'})).toHaveTextContent(conciseCopy.journalReference);expect(resource.create).not.toHaveBeenCalled();
  for(const name of ['5 minutes ending at reference time','15 minutes ending at reference time','30 minutes ending at reference time','1 hour ending at reference time']) {
   expect(screen.getByRole('button',{name,exact:true})).toHaveAccessibleDescription(`${conciseCopy.journalReferenceLabel}: ${resource.view!.serverNow}`);
  }
  mounted.rerender(<JournalContent resource={{...resource,paused:true}} insecureTestMode/>);
  expect(screen.getByRole('status')).toHaveTextContent(conciseCopy.journalPaused);expect(screen.getByRole('button',{name:'Fetch logs'})).toBeDisabled();
  expect(screen.getByLabelText('Exact service unit')).toBeDisabled();expect(document.querySelector('.journal-results,.journal-search')).toBeNull();expect(resource.create).not.toHaveBeenCalled();
 });
 it('keeps one copyable address and reveals remaining addresses and stable identity on demand', async () => {
  const view=endpointView();const display=fleetIdentityProjection({schemaVersion:'tracebolt.fleet-endpoint-identity.v1',serverNow:view.serverNow,items:[view]},0).get(endpointDevice)!;
  render(<FleetIdentityName identity={{...display,addresses:display.addresses.slice(0,4)}} deviceId={endpointDevice}/>);
  expect(screen.getByText(conciseCopy.fleetMore)).toBeVisible();expect(screen.getByText(`ID: ${endpointDevice}`)).not.toBeVisible();expect(screen.getByText('fixture-linux')).toBeVisible();
  expect(screen.getByRole('button',{name:'Copy hostname: fixture-linux'})).toBeVisible();expect(screen.getByRole('button',{name:'Copy IP address: 192.0.2.19 (eth0)'})).toBeVisible();
  fireEvent.click(screen.getByText(conciseCopy.fleetMore));await screen.findByText('2001:db8::19');expect(screen.getByText(`ID: ${endpointDevice}`)).toBeVisible();
 });
});


it('the display setup helper reaches the actual Services action control through Inventory', async()=>{
 const inventory=systemView(1,0);inventory.deviceId=actionDevice;const metric={value:null,unit:'%',quality:'unknown',source:'Public display fixture',collectedAt:inventory.serverNow};
 const fixture={inventory,services:[{...serviceRows(1)[0],name:'fixture.service'}],ready:{...actionView(),deviceId:actionDevice},device:{id:actionDevice,name:'Public display fixture',platform:'linux',os:'Fixture Linux',site:'Fixture',group:'Fixture',ip:null,status:'unknown',source:'lan',synthetic:false,lastSeen:inventory.serverNow,agentVersion:'fixture',cpu:metric,memory:metric,disk:metric,uptime:'',tags:[],capabilities:[],evidence:[],trend:[],caseIds:[]}};
 const session={...actionSession,transport:'http' as const,insecureTestMode:true,transportWarning:'unencrypted_lan_test' as const};
 vi.mocked(useOperator).mockReturnValue({...operator,...session});
 vi.mocked(request).mockImplementation(async path=>{
  if(path==='/auth/session')return session;
  if(path===`/devices/${fixture.device.id}`)return fixture.device;
  if(path.endsWith('/inventory/system'))return fixture.inventory;
  if(path.endsWith('/service-actions'))return fixture.ready;
  throw new Error('Unrelated public fixture source unavailable');
 });
 vi.mocked(mutateRaw).mockImplementation(async(path,raw)=>{
  expect(path).toBe(`/devices/${fixture.device.id}/inventory/system/query`);
  const query=JSON.parse(raw);expect(query).toMatchObject({section:'services',cursor:'',search:'',filter:'all',limit:100});
  return systemPage(fixture.inventory,fixture.services,[],raw);
 });
 let loaded=false;
 const page={
  goto:async(url:string)=>expect(url).toBe(`http://127.0.0.1/#/devices/${fixture.device.id}`),
  reload:async()=>{loaded=true;render(<DeviceDetail id={fixture.device.id} onClose={vi.fn()} onCase={vi.fn()}/>);await flush();},
  getByRole:(_role:string,options:{name:string;exact:boolean})=>({click:async()=>{expect(loaded).toBe(true);fireEvent.click(await screen.findByRole('tab',{name:options.name,exact:options.exact}));await flush();}}),
 };
 await openServiceActionDisplay(page,'http://127.0.0.1',fixture.device.id);
 await waitFor(()=>expect(screen.getByRole('button',{name:'Preview try-restart: fixture.service'})).toBeEnabled());
 expect(screen.getByRole('tab',{name:'Services'})).toHaveAttribute('aria-selected','true');
 expect(vi.mocked(mutateRaw).mock.calls.every(([path])=>path.endsWith('/inventory/system/query'))).toBe(true);
});


const platformGalleryData = () => {
 const at='2026-10-07T18:00:00Z',metric={value:null,unit:'%',quality:'unknown' as const,source:'Invented platform gallery',collectedAt:at};
 const windows:Device={id:'demo-win-01',name:'Synthetic Windows gallery',platform:'windows',os:'Windows fixture',site:'Fixture',group:'Fixture',ip:null,status:'unknown',source:'synthetic',synthetic:true,lastSeen:at,agentVersion:'fixture',cpu:metric,memory:metric,disk:metric,uptime:'',tags:[],capabilities:[],evidence:[],trend:[],caseIds:[]};
 const linux:Device={...windows,id:'demo-linux-01',name:'Synthetic Linux gallery',platform:'linux',os:'Linux fixture'};
 return {generatedAt:at,devices:[windows,linux],cases:[{id:'case-demo-windows',deviceId:windows.id,synthetic:true,status:'open',severity:'critical'}],activity:[]};
};
it.each(['en','de'] as const)('routes the retained Windows gallery and three-card geometry to their actual platform views in %s',async locale=>{
 setLocale(locale,false);const data=platformGalleryData(),targets=conciseShellTargets(data);
 expect(targets.device.id).toBe('demo-win-01');expect(targets.statusDevice.id).toBe('demo-linux-01');expect(targets.selectedCase.deviceId).toBe(targets.device.id);
 vi.mocked(request).mockImplementation(async path=>{
  const device=data.devices.find(item=>path===`/devices/${item.id}`);if(device)return device;
  throw new Error('Unrelated public fixture source unavailable');
 });
 const windows=render(<DeviceDetail id={targets.device.id} onClose={vi.fn()} onCase={vi.fn()}/>);await flush();
 expect(screen.getByRole('heading',{name:targets.device.name,level:1})).toBeVisible();
 expect(document.querySelector('.windows-device-overview')).not.toBeNull();expect(document.querySelectorAll('.device-essential-card')).toHaveLength(0);
 windows.unmount();render(<DeviceDetail id={targets.statusDevice.id} onClose={vi.fn()} onCase={vi.fn()}/>);await flush();
 expect(screen.getByRole('heading',{name:targets.statusDevice.name,level:1})).toBeVisible();expect(document.querySelector('.windows-device-overview')).toBeNull();
 expect(document.querySelectorAll('.device-essential-card')).toHaveLength(3);
 expect([...document.querySelectorAll('.device-essential-value')].filter(value=>value.textContent===(locale==='de'?'Unbekannt':'Unknown'))).toHaveLength(2);
 expect(vi.mocked(request).mock.calls.some(([path])=>path.endsWith('/inventory/windows')||path.endsWith('/inventory/endpoint-identity'))).toBe(false);expect(mutateRaw).not.toHaveBeenCalled();
});
it('rejects missing, mislabelled or non-synthetic platform targets before a gallery capture',()=>{
 for(const change of [
  (data:ReturnType<typeof platformGalleryData>)=>{data.devices=data.devices.filter(item=>item.platform!=='linux');},
  (data:ReturnType<typeof platformGalleryData>)=>{data.devices[1].synthetic=false;},
  (data:ReturnType<typeof platformGalleryData>)=>{data.devices[1].platform='windows';},
  (data:ReturnType<typeof platformGalleryData>)=>{data.devices[0].synthetic=false;},
  (data:ReturnType<typeof platformGalleryData>)=>{data.cases=[];},
 ]){const data=platformGalleryData();change(data);expect(()=>conciseShellTargets(data)).toThrow('Required synthetic platform gallery fixtures are unavailable.');}
});
