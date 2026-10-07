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
import { systemPage, systemView, serviceRows } from '../../web/src/system-inventory-fixtures';
import { actionSession, actionView, actionDevice } from '../../web/src/service-action-fixtures';
import { openServiceActionDisplay } from './service-action-display-navigation.mjs';
import { conciseCopy } from './concise-copy-contracts.mjs';
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
  expect(screen.getByRole('link',{name:'Anwendungsprüfungen einrichten'})).toHaveAttribute('href','#/settings');expect(document.querySelector('form,input,select')).toBeNull();
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
 it('keeps the omitted-address count and stable identity while shortening the fleet label', () => {
  const view=endpointView();const display=fleetIdentityProjection({schemaVersion:'tracebolt.fleet-endpoint-identity.v1',serverNow:view.serverNow,items:[view]},0).get(endpointDevice)!;
  render(<FleetIdentityName identity={{...display,addresses:display.addresses.slice(0,4)}} deviceId={endpointDevice}/>);
  expect(screen.getByText(conciseCopy.fleetMore)).toBeVisible();expect(screen.getByText(`ID: ${endpointDevice}`)).toBeVisible();expect(screen.getByText('fixture-linux')).toBeVisible();
  expect(document.querySelector('.fleet-identity-addresses')).toHaveAttribute('title',expect.stringContaining('eth0'));
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
