import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, AUTH_REQUIRED_EVENT } from './api';
import { useOperator } from './auth';
import { setLocale } from './i18n';
import { WindowsUserSoftwarePanel } from './windows-user-software';
import { userSoftwareComplete,userSoftwareDevice,userSoftwarePage,userSoftwareRows,userSoftwareVector } from './windows-user-software-fixtures';
import type { UserSoftwareQuery } from './windows-user-software-types';
vi.mock('./auth',async original=>({...await original<typeof import('./auth')>(),useOperator:vi.fn()}));
const response=(v:unknown,status=200)=>new Response(JSON.stringify(v),{status});
function server(){
 const rows=userSoftwareRows(),state={rows,complete:userSoftwareComplete(rows),kind:'ready',requests:[] as UserSoftwareQuery[],defer:null as null|((q:UserSoftwareQuery)=>Promise<Response>)};
 const fetch=vi.fn(async(path:string,options?:RequestInit):Promise<Response>=>{
  if(path==='/api/session')return response({csrfToken:'invented-csrf'});if(path!==`/api/devices/${userSoftwareDevice}/windows-selected-user-software/query`)return response({},404);
  const q=JSON.parse(options!.body as string) as UserSoftwareQuery;state.requests.push(q);if(state.defer)return state.defer(q);
  if(state.kind!=='ready'){const p=userSoftwareVector(state.kind);return response({...p,source:q.source,search:q.search,sort:q.sort,limit:q.limit})}
  if(q.accountContextId&&q.accountContextId!==state.complete.manifest.accountContextId)return response({},409);
  return response(userSoftwarePage(q,state.rows,state.complete,q.cursor?Number(q.cursor.split('.')[0].slice(7)):0));
 });vi.stubGlobal('fetch',fetch);return{state,fetch};
}
const open=()=>render(<WindowsUserSoftwarePanel deviceId={userSoftwareDevice} sessionKey="test-session"/>);
beforeEach(()=>{setLocale('en',false);vi.mocked(useOperator).mockReturnValue({mode:'lan',authenticated:true,expiresAt:'fixture-session',insecureTestMode:false,logout:vi.fn(),theme:'light',setTheme:vi.fn()})});
afterEach(()=>{cleanup();abortProtectedRequests();vi.unstubAllGlobals();vi.restoreAllMocks()});
describe('selected-account bounded Software workspace',()=>{
 it.each(['en','de'] as const)('explains pending filters and resets locally without changing account or requesting data (%s)',async locale=>{
  setLocale(locale,false);const s=server();open();await screen.findByRole('table');
  const de=locale==='de',search=screen.getByRole('searchbox'),sources=screen.getByRole('combobox',{name:de?'Quellen':'Sources'}),sort=screen.getByRole('combobox',{name:de?'Software sortieren':'Sort software'}),reset=screen.getByRole('button',{name:de?'Kontosoftwaresuche, Quelle und Sortierung zurücksetzen':'Reset selected-account search, source and sort'}),hint=de?'Filter geändert. Mit „Anwenden“ die gespeicherte Erfassung dieses Kontos lesen.':'Filters changed. Apply to read this account’s saved capture.';
  expect(reset).toBeDisabled();expect(screen.queryByText(hint)).toBeNull();
  const captureTime=document.querySelector('.windows-full-software-age time')!.getAttribute('datetime');
  fireEvent.change(search,{target:{value:'0203'}});fireEvent.change(sources,{target:{value:'msix'}});fireEvent.change(sort,{target:{value:'source-desc'}});
  expect(screen.queryByRole('table')).toBeNull();expect(screen.getByText(hint)).toHaveAttribute('role','status');
  for(const control of [search,sources,sort])expect(control).toHaveAttribute('aria-describedby',screen.getByText(hint).id);
  expect(screen.getByText('Selected account dddddddddddd')).toBeVisible();expect(document.querySelector('.windows-full-software-age time')).toHaveAttribute('datetime',captureTime);
  const counts=document.querySelector('.windows-full-software-counts')!;expect(within(counts as HTMLElement).getByText('205')).toBeVisible();expect(within(counts as HTMLElement).getByText('—')).toBeVisible();expect(s.state.requests).toHaveLength(1);
  fireEvent.click(reset);expect(search).toHaveValue('');expect(sources).toHaveValue('');expect(sort).toHaveValue('name-asc');expect(search).toHaveFocus();expect(reset).toBeDisabled();expect(screen.getByText(hint)).toBeVisible();expect(screen.queryByRole('table')).toBeNull();expect(s.state.requests).toHaveLength(1);
  fireEvent.click(screen.getByRole('button',{name:de?'Anwenden':'Apply'}));await screen.findByRole('table');expect(s.state.requests).toHaveLength(2);expect(s.state.requests[1]).toMatchObject({accountContextId:'d'.repeat(64),source:'',search:'',sort:'name-asc',cursor:''});expect(screen.queryByText(hint)).toBeNull();expect(screen.getByRole('searchbox')).not.toHaveAttribute('aria-describedby');
  expect(s.fetch.mock.calls.every(([path])=>!path.includes('?')&&!path.includes('capture')&&!path.includes('consent'))).toBe(true);
 });
 it.each(['{Enter}',' '])('supports keyboard reset %s followed by a separate deliberate Apply',async key=>{
  const user=userEvent.setup(),s=server();open();await screen.findByRole('table');fireEvent.change(screen.getByRole('combobox',{name:'Sources'}),{target:{value:'hkcu'}});
  const reset=screen.getByRole('button',{name:'Reset selected-account search, source and sort'});reset.focus();await user.keyboard(key);
  expect(screen.getByRole('searchbox')).toHaveFocus();expect(screen.getByRole('combobox',{name:'Sources'})).toHaveValue('');expect(s.state.requests).toHaveLength(1);
  await user.keyboard('{Enter}');await screen.findByRole('table');expect(s.state.requests).toHaveLength(2);expect(s.state.requests[1].accountContextId).toBe('d'.repeat(64));
 });
 it('resets source-only and sort-only drafts and clears a UTF-8 validation error without reading',async()=>{
  const s=server();open();await screen.findByRole('table');const reset=screen.getByRole('button',{name:'Reset selected-account search, source and sort'});
  fireEvent.change(screen.getByRole('combobox',{name:'Sources'}),{target:{value:'msix'}});expect(reset).toBeEnabled();fireEvent.click(reset);
  fireEvent.change(screen.getByRole('combobox',{name:'Sort software'}),{target:{value:'version-desc'}});expect(reset).toBeEnabled();fireEvent.click(reset);
  fireEvent.change(screen.getByRole('searchbox'),{target:{value:'é'.repeat(129)}});fireEvent.click(screen.getByRole('button',{name:'Apply'}));expect(screen.getByRole('alert')).toHaveTextContent('256 UTF-8 bytes');expect(screen.queryByText(/Filters changed/)).toBeNull();
  fireEvent.click(reset);expect(screen.queryByRole('alert')).toBeNull();expect(screen.getByText(/Filters changed/)).toBeVisible();expect(screen.getByRole('searchbox')).toHaveFocus();expect(s.state.requests).toHaveLength(1);
 });
 it('keeps failed-source truth after reset instead of inventing an empty inventory',async()=>{
  const s=server();s.state.kind='bothUnavailable';open();await screen.findByText('Neither source was available; no empty inventory is established.');
  fireEvent.change(screen.getByRole('combobox',{name:'Sources'}),{target:{value:'msix'}});expect(screen.getByText(/Filters changed/)).toBeVisible();expect(screen.getByText(/Partial coverage/)).toHaveTextContent('HKCU: Access denied · MSIX: Unsupported');
  fireEvent.click(screen.getByRole('button',{name:'Reset selected-account search, source and sort'}));expect(s.state.requests).toHaveLength(1);fireEvent.click(screen.getByRole('button',{name:'Apply'}));await screen.findByText('Neither source was available; no empty inventory is established.');expect(screen.queryByText('No registrations in the completed sources.')).toBeNull();expect(s.state.requests[1].accountContextId).toBe(s.state.requests[0].accountContextId||userSoftwareVector('bothUnavailable').complete!.manifest.accountContextId);
 });
 it('keeps the original account pinned after reset and still requires explicit restart for replacement',async()=>{
  const s=server();open();await screen.findByRole('table');fireEvent.change(screen.getByRole('combobox',{name:'Sources'}),{target:{value:'msix'}});
  s.state.complete=userSoftwareComplete(s.state.rows,'e'.repeat(64),2);fireEvent.click(screen.getByRole('button',{name:'Reset selected-account search, source and sort'}));expect(s.state.requests).toHaveLength(1);
  fireEvent.click(screen.getByRole('button',{name:'Apply'}));await screen.findByRole('alert');expect(s.state.requests).toHaveLength(2);expect(s.state.requests[1]).toMatchObject({accountContextId:'d'.repeat(64),source:'',search:'',sort:'name-asc',cursor:''});expect(screen.getByRole('alert')).toHaveTextContent('Account, capture or access changed');expect(screen.queryByText(/Filters changed/)).toBeNull();expect(screen.queryByRole('searchbox')).toBeNull();expect(screen.queryByText('Selected account eeeeeeeeeeee')).toBeNull();
  fireEvent.click(screen.getByRole('button',{name:'Reload latest'}));await screen.findByRole('table');expect(screen.getByText('Selected account eeeeeeeeeeee')).toBeVisible();expect(s.state.requests[2].accountContextId).toBe('');
 });
 it.each(['en','de'] as const)('keeps capture-pending status distinct from local filter drafts (%s)',async locale=>{
  setLocale(locale,false);const s=server();s.state.defer=async q=>{const p=userSoftwarePage(q);p.latestAttempt={...p.latestAttempt!,sequence:p.complete!.manifest.sequence+1,captureNonce:'f'.repeat(64),status:'pending',reason:''};return response(p)};
  open();await screen.findByRole('table');fireEvent.change(screen.getByRole('searchbox'),{target:{value:'draft'}});
  expect(screen.getByText(locale==='de'?/Neuester Versuch:.*Erfassung ausstehend/:/Latest attempt:.*Capture pending/)).toBeVisible();expect(screen.getByText(locale==='de'?/Filter geändert/:/Filters changed/)).toBeVisible();expect(s.state.requests).toHaveLength(1);
 });
 it.each(['blur','pagehide','hashchange',AUTH_REQUIRED_EVENT])('drops local draft controls on %s without restoring rows or reading',async event=>{
  const s=server();open();await screen.findByRole('table');fireEvent.change(screen.getByRole('searchbox'),{target:{value:'draft'}});expect(screen.getByText(/Filters changed/)).toBeVisible();
  act(()=>window.dispatchEvent(new Event(event)));expect(screen.queryByText(/Filters changed/)).toBeNull();expect(screen.queryByRole('button',{name:'Reset selected-account search, source and sort'})).toBeNull();expect(screen.queryByRole('table')).toBeNull();expect(s.state.requests).toHaveLength(1);
 });
 it('expires a pending draft at original authority deadline without a reset granting more time',async()=>{
  const s=server();let mono=100,wall=Date.now();vi.spyOn(performance,'now').mockImplementation(()=>mono);vi.spyOn(Date,'now').mockImplementation(()=>wall);
  s.state.defer=async q=>{const p=userSoftwarePage(q);p.authorityUntil=p.cursorExpiresAt=new Date(Date.parse(p.serverNow)+1000).toISOString();return response(p)};
  open();await screen.findByRole('table');fireEvent.change(screen.getByRole('searchbox'),{target:{value:'draft'}});fireEvent.click(screen.getByRole('button',{name:'Reset selected-account search, source and sort'}));mono+=1000;wall+=1000;
  await waitFor(()=>expect(screen.queryByText(/Filters changed/)).toBeNull());expect(screen.queryByRole('searchbox')).toBeNull();expect(screen.getByRole('alert')).toHaveTextContent('expired');expect(s.state.requests).toHaveLength(1);
 });
 it.each(['en','de'] as const)('pages and filters captured data without collecting (%s)',async locale=>{
  setLocale(locale,false);const s=server();open();await screen.findByRole('table');expect(document.querySelectorAll('tbody tr')).toHaveLength(100);
  fireEvent.click(screen.getByRole('button',{name:locale==='en'?'Next software page':'Nächste Softwareseite'}));await screen.findByText('Selected App 0100');expect(s.state.requests.at(-1)!.accountContextId).toBe('d'.repeat(64));
  fireEvent.change(screen.getByRole('combobox',{name:locale==='en'?'Sources':'Quellen'}),{target:{value:'msix'}});expect(screen.queryByRole('table')).toBeNull();fireEvent.click(screen.getByRole('button',{name:locale==='en'?'Apply':'Anwenden'}));await screen.findByText('Selected App 0001');expect(s.state.requests.at(-1)).toMatchObject({source:'msix',cursor:'',accountContextId:'d'.repeat(64)});
  fireEvent.change(screen.getByRole('searchbox'),{target:{value:'0203'}});fireEvent.click(screen.getByRole('button',{name:locale==='en'?'Apply':'Anwenden'}));await screen.findByText('Selected App 0203');expect(document.querySelectorAll('tbody tr')).toHaveLength(1);expect(s.fetch.mock.calls.every(([path])=>!path.includes('?')&&!path.includes('capture')&&!path.includes('consent'))).toBe(true);
 });
 it('shows both failed sources as unknown, never positive empty',async()=>{const s=server();s.state.kind='bothUnavailable';open();await screen.findByText('Neither source was available; no empty inventory is established.');expect(screen.getByText(/Partial coverage/)).toHaveTextContent('HKCU: Access denied · MSIX: Unsupported');expect(screen.queryByRole('table')).toBeNull()});
 it('gives the precise default-off source-candidate next step',async()=>{const s=server();s.state.kind='notConfigured';open();await screen.findByText('Off. Separate local consent and a foreground capture are required.');fireEvent.click(screen.getByText('Capture this account'));expect(screen.getByText(/--user-software-enable/)).toHaveTextContent('--apply --selected-user-software');expect(screen.getByText(/--user-software-enable/)).toHaveTextContent('Setup does not install or start it');expect(s.state.requests).toHaveLength(1)});
 it('clears on blur and ignores a late response after logout',async()=>{const s=server();open();await screen.findByRole('table');act(()=>window.dispatchEvent(new Event('blur')));expect(screen.queryByRole('table')).toBeNull();let resolve!:(r:Response)=>void;s.state.defer=()=>new Promise(done=>{resolve=done});act(()=>window.dispatchEvent(new Event('focus')));await waitFor(()=>expect(resolve).toBeTypeOf('function'));act(()=>window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT)));await act(async()=>resolve(response(userSoftwarePage())));expect(screen.queryByRole('table')).toBeNull();expect(screen.getByRole('alert')).toHaveTextContent('Sign in again')});
 it('requires explicit restart on account replacement',async()=>{const s=server();open();await screen.findByRole('table');s.state.complete=userSoftwareComplete(s.state.rows,'e'.repeat(64),2);fireEvent.click(screen.getByRole('button',{name:'Refresh captured software'}));await screen.findByRole('alert');expect(screen.queryByRole('table')).toBeNull();expect(screen.getByRole('alert')).toHaveTextContent('Account, capture or access changed');fireEvent.click(screen.getByRole('button',{name:'Reload latest'}));await screen.findByRole('table');expect(screen.getByText('Selected account eeeeeeeeeeee')).toBeVisible()});
 it.each(['attempt','authority'] as const)('clears non-ready account metadata at its original %s deadline without rereading',async deadline=>{const s=server();let mono=100,wall=Date.now();vi.spyOn(performance,'now').mockImplementation(()=>mono);vi.spyOn(Date,'now').mockImplementation(()=>wall);s.state.defer=async q=>{const p=userSoftwarePage(q);p.status='unavailable';p.complete=null;p.rows=[];p.offset=0;p.matchingCount=0;p.nextCursor='';p.cursorExpiresAt=null;p.latestAttempt!.status='source_failed';p.latestAttempt!.reason='access_denied';if(deadline==='attempt'){p.latestAttempt!.attemptedAt=new Date(Date.parse(p.serverNow)-86400000+1000).toISOString()}else{p.authorityUntil=new Date(Date.parse(p.serverNow)+1000).toISOString()}return response(p)};open();await screen.findByText(/Selected account dddddddddddd/);mono+=1000;wall+=1000;await waitFor(()=>expect(screen.queryByText(/Selected account dddddddddddd/)).toBeNull());expect(s.state.requests).toHaveLength(1);expect(screen.getByRole('alert')).toHaveTextContent('expired')});

});
