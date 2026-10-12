import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
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
