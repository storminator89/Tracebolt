import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AuthBoundary, LOGOUT_INTENT_KEY, OperatorAccount, useOperator, validOperatorSession } from './auth';
import type { OperatorSession } from './auth';
import { abortProtectedRequests, APIError, AUTH_REQUIRED_EVENT, mutate, request } from './api';
vi.mock('./api',async importOriginal=>{const original=await importOriginal<typeof import('./api')>();return {...original,request:vi.fn(),mutate:vi.fn(),abortProtectedRequests:vi.fn()};});
const development:OperatorSession={mode:'development',transport:'http',insecureTestMode:false,transportWarning:null,authenticationRequired:false,authenticated:false,csrfToken:'development-csrf',serverNow:'2026-10-03T15:00:00Z',expiresAt:null,expiresInSeconds:null};
const anonymous:OperatorSession={mode:'lan',transport:'https',insecureTestMode:false,transportWarning:null,authenticationRequired:true,authenticated:false,csrfToken:null,serverNow:'2026-10-03T15:00:00Z',expiresAt:null,expiresInSeconds:null};
const authenticated:OperatorSession={...anonymous,authenticated:true,csrfToken:'session-csrf',expiresAt:'2026-10-03T15:30:00Z',expiresInSeconds:1800};
const namedAnonymous:OperatorSession={...anonymous,loginMode:'named',actorId:null,capabilities:[]};
const namedAuthenticated:OperatorSession={...authenticated,loginMode:'named',actorId:'operator_0123456789abcdef0123456789abcdef',capabilities:['read','plan_updates']};
function SessionMetadata(){const operator=useOperator();return <output aria-label="Session metadata">{JSON.stringify({loginMode:operator?.loginMode,actorId:operator?.actorId,capabilities:operator?.capabilities,hasExplicitMetadata:operator?.hasExplicitMetadata})}</output>;}
function PrivateApp(){return <><h2>Geschützte Geräte</h2><input aria-label="Privater Entwurf" defaultValue="nicht gespeichert"/><OperatorAccount/></>;}
beforeEach(()=>{vi.mocked(request).mockReset();vi.mocked(mutate).mockReset();vi.mocked(abortProtectedRequests).mockClear();localStorage.clear();sessionStorage.clear();});
afterEach(()=>{cleanup();vi.restoreAllMocks();vi.unstubAllGlobals();vi.useRealTimers();});
describe('explicit access contract',()=>{
  it('accepts development without pretending authentication',()=>expect(validOperatorSession(development)).toBe(true));
  it('rejects incomplete, contradictory, or unbounded session data',()=>{expect(validOperatorSession({})).toBe(false);expect(validOperatorSession({...development,authenticated:true})).toBe(false);expect(validOperatorSession({...authenticated,csrfToken:null})).toBe(false);expect(validOperatorSession({...authenticated,expiresInSeconds:Infinity})).toBe(false);expect(validOperatorSession({...anonymous,authenticationRequired:false})).toBe(false);});
  it('never mounts protected UI while bootstrapping',()=>{vi.mocked(request).mockImplementation(()=>new Promise(()=>{}));render(<AuthBoundary><PrivateApp/></AuthBoundary>);expect(screen.queryByText('Geschützte Geräte')).not.toBeInTheDocument();expect(screen.getByRole('status')).toHaveTextContent('Manager-Status');});
  it('fails closed on bootstrap failure, and retry reads status only',async()=>{vi.mocked(request).mockRejectedValueOnce(new APIError('Manager nicht erreichbar')).mockResolvedValue(development);render(<AuthBoundary><PrivateApp/></AuthBoundary>);await screen.findByRole('alert');expect(screen.queryByText('Geschützte Geräte')).not.toBeInTheDocument();expect(screen.queryByLabelText('Operator-Passwort')).not.toBeInTheDocument();fireEvent.click(screen.getByRole('button',{name:'Status erneut prüfen'}));await screen.findByText('Geschützte Geräte');expect(mutate).not.toHaveBeenCalled();});
  it('allows explicit development mode with no fake sign-in or logout',async()=>{vi.mocked(request).mockResolvedValue(development);render(<AuthBoundary><PrivateApp/></AuthBoundary>);await screen.findByText('Geschützte Geräte');expect(screen.getByText('Lokaler Zugriff · v0.1.0')).toBeVisible();expect(screen.queryByRole('button',{name:'Abmelden'})).not.toBeInTheDocument();expect(screen.queryByText('LAN · Sitzung aktiv')).not.toBeInTheDocument();});
  it('shows LAN sign-in and keeps app data absent',async()=>{vi.mocked(request).mockResolvedValue(anonymous);render(<AuthBoundary><PrivateApp/></AuthBoundary>);await screen.findByLabelText('Operator-Passwort');expect(screen.queryByLabelText('Operator-Benutzername')).not.toBeInTheDocument();expect(screen.queryByText('Geschützte Geräte')).not.toBeInTheDocument();expect(screen.getByRole('button',{name:'Anmelden'})).toBeDisabled();});
});
describe('named operator display contract',()=>{
  it('accepts complete named metadata and explicit legacy/development metadata',()=>{
    expect(validOperatorSession(namedAnonymous)).toBe(true);
    expect(validOperatorSession(namedAuthenticated)).toBe(true);
    expect(validOperatorSession({...namedAuthenticated,capabilities:['read','plan_updates','execute_updates','restart_service']})).toBe(true);
    expect(validOperatorSession({...anonymous,loginMode:'shared',actorId:null,capabilities:[]})).toBe(true);
    expect(validOperatorSession({...authenticated,loginMode:'shared',actorId:null,capabilities:['read']})).toBe(true);
    expect(validOperatorSession({...development,loginMode:'shared',actorId:null,capabilities:[]})).toBe(true);
  });
  it.each([
    ['mode alone',{...authenticated,loginMode:'named'}],
    ['actor alone',{...authenticated,actorId:namedAuthenticated.actorId}],
    ['capabilities alone',{...authenticated,capabilities:['read']}],
    ['unknown mode',{...namedAuthenticated,loginMode:'admin'}],
    ['missing actor',{...namedAuthenticated,actorId:undefined}],
    ['null named actor',{...namedAuthenticated,actorId:null}],
    ['malformed actor',{...namedAuthenticated,actorId:'operator_alice'}],
    ['all-zero actor',{...namedAuthenticated,actorId:'operator_00000000000000000000000000000000'}],
    ['wrong actor prefix',{...namedAuthenticated,actorId:'agent_0123456789abcdef0123456789abcdef'}],
    ['uppercase actor',{...namedAuthenticated,actorId:'operator_0123456789ABCDEF0123456789ABCDEF'}],
    ['missing capabilities',{...namedAuthenticated,capabilities:undefined}],
    ['null capabilities',{...namedAuthenticated,capabilities:null}],
    ['non-array capabilities',{...namedAuthenticated,capabilities:'read'}],
    ['unknown capability',{...namedAuthenticated,capabilities:['read','admin']}],
    ['non-string capability',{...namedAuthenticated,capabilities:['read',true]}],
    ['duplicate capability',{...namedAuthenticated,capabilities:['read','read']}],
    ['missing explicit read',{...namedAuthenticated,capabilities:['execute_updates']}],
    ['anonymous actor',{...namedAnonymous,actorId:namedAuthenticated.actorId}],
    ['anonymous capability',{...namedAnonymous,capabilities:['read']}],
    ['shared named actor',{...namedAuthenticated,loginMode:'shared'}],
    ['shared action capability',{...authenticated,loginMode:'shared',actorId:null,capabilities:['read','restart_service']}],
    ['shared missing read',{...authenticated,loginMode:'shared',actorId:null,capabilities:[]}],
    ['named development',{...development,loginMode:'named',actorId:null,capabilities:[]}],
    ['development grant',{...development,loginMode:'shared',actorId:null,capabilities:['read']}],
  ])('rejects %s',(_name,value)=>expect(validOperatorSession(value)).toBe(false));
  it('fails closed when bootstrap claims contradictory capabilities',async()=>{
    vi.mocked(request).mockResolvedValue({...namedAnonymous,capabilities:['restart_service']});
    render(<AuthBoundary><PrivateApp/></AuthBoundary>);
    await screen.findByRole('alert');
    expect(screen.queryByText('Geschützte Geräte')).not.toBeInTheDocument();
    expect(screen.queryByLabelText('Operator-Passwort')).not.toBeInTheDocument();
  });
  it('exposes only the validated server actor and capability snapshot',async()=>{
    vi.mocked(request).mockResolvedValue(namedAuthenticated);
    render(<AuthBoundary><SessionMetadata/></AuthBoundary>);
    expect(await screen.findByLabelText('Session metadata')).toHaveTextContent(JSON.stringify({loginMode:'named',actorId:namedAuthenticated.actorId,capabilities:['read','plan_updates'],hasExplicitMetadata:true}));
    expect(mutate).not.toHaveBeenCalled();
  });
  it('distinguishes explicit shared metadata from legacy display defaults',async()=>{
    vi.mocked(request).mockResolvedValue({...authenticated,loginMode:'shared',actorId:null,capabilities:['read']});
    render(<AuthBoundary><SessionMetadata/></AuthBoundary>);
    expect(await screen.findByLabelText('Session metadata')).toHaveTextContent(JSON.stringify({loginMode:'shared',actorId:null,capabilities:['read'],hasExplicitMetadata:true}));
  });
  it('keeps old shared sessions actorless and without maintenance grants',async()=>{
    vi.mocked(request).mockResolvedValue(authenticated);
    render(<AuthBoundary><SessionMetadata/></AuthBoundary>);
    expect(await screen.findByLabelText('Session metadata')).toHaveTextContent(JSON.stringify({loginMode:'shared',actorId:null,capabilities:['read'],hasExplicitMetadata:false}));
  });
});
describe('named operator sign-in',()=>{
  it('requires a username and sends it only in named mode without client grants',async()=>{
    vi.mocked(request).mockResolvedValueOnce(namedAnonymous).mockResolvedValue(namedAuthenticated);
    render(<AuthBoundary><PrivateApp/></AuthBoundary>);
    await screen.findByLabelText('Operator-Benutzername');
    fireEvent.change(screen.getByLabelText('Operator-Passwort'),{target:{value:'TEST_ONLY_PASSWORD_123'}});
    expect(screen.getByRole('button',{name:'Anmelden'})).toBeDisabled();
    fireEvent.change(screen.getByLabelText('Operator-Benutzername'),{target:{value:'   '}});
    expect(screen.getByRole('button',{name:'Anmelden'})).toBeDisabled();
    fireEvent.change(screen.getByLabelText('Operator-Benutzername'),{target:{value:'test.operator'}});
    fireEvent.click(screen.getByRole('button',{name:'Anmelden'}));
    expect(screen.getByLabelText('Operator-Passwort')).toHaveValue('');
    expect(screen.getByRole('button',{name:'Anmelden'})).toBeDisabled();
    await screen.findByText('Geschützte Geräte');
    expect(request).toHaveBeenLastCalledWith('/auth/login',expect.objectContaining({method:'POST',body:'{"username":"test.operator","password":"TEST_ONLY_PASSWORD_123"}'}));
    expect(JSON.stringify({...localStorage,...sessionStorage})).not.toMatch(/test\.operator|TEST_ONLY_PASSWORD_123|session-csrf|operator_012345/);
    expect(mutate).not.toHaveBeenCalled();
  });
  it('does not add a username to an explicit shared-mode login',async()=>{
    vi.mocked(request).mockResolvedValueOnce({...anonymous,loginMode:'shared',actorId:null,capabilities:[]}).mockResolvedValue({...authenticated,loginMode:'shared',actorId:null,capabilities:['read']});
    render(<AuthBoundary><PrivateApp/></AuthBoundary>);
    await screen.findByLabelText('Operator-Passwort');
    expect(screen.queryByLabelText('Operator-Benutzername')).not.toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Operator-Passwort'),{target:{value:'TEST_ONLY_PASSWORD_123'}});
    fireEvent.click(screen.getByRole('button',{name:'Anmelden'}));
    await screen.findByText('Geschützte Geräte');
    expect(request).toHaveBeenLastCalledWith('/auth/login',expect.objectContaining({body:'{"password":"TEST_ONLY_PASSWORD_123"}'}));
  });
  it('keeps named credential errors generic and localized',async()=>{
    vi.mocked(request).mockResolvedValueOnce(namedAnonymous).mockRejectedValue(new APIError('SECRET_FROM_SERVER',401));
    render(<AuthBoundary><PrivateApp/></AuthBoundary>);
    await screen.findByLabelText('Operator-Benutzername');
    fireEvent.change(screen.getByLabelText('Operator-Benutzername'),{target:{value:'test.operator'}});
    fireEvent.change(screen.getByLabelText('Operator-Passwort'),{target:{value:'TEST_ONLY_PASSWORD_123'}});
    fireEvent.click(screen.getByRole('button',{name:'Anmelden'}));
    await screen.findByText('Anmeldung nicht möglich. Benutzername und Passwort prüfen.');
    expect(document.body.textContent).not.toMatch(/SECRET_FROM_SERVER|TEST_ONLY_PASSWORD_123/);
    expect(screen.getByLabelText('Operator-Passwort')).toHaveValue('');
    fireEvent.change(screen.getByLabelText('Sprache'),{target:{value:'en'}});
    expect(screen.getByLabelText('Operator username')).toBeVisible();
    expect(screen.getByRole('alert')).toHaveTextContent('Unable to sign in. Check your username and password.');
  });
  it.each([
    ['shared response',authenticated],
    ['malformed grants',{...namedAuthenticated,capabilities:['read','admin']}],
  ])('rejects a named login with %s',async(_name,response)=>{
    vi.mocked(request).mockResolvedValueOnce(namedAnonymous).mockResolvedValue(response);
    render(<AuthBoundary><PrivateApp/></AuthBoundary>);
    await screen.findByLabelText('Operator-Benutzername');
    fireEvent.change(screen.getByLabelText('Operator-Benutzername'),{target:{value:'test.operator'}});
    fireEvent.change(screen.getByLabelText('Operator-Passwort'),{target:{value:'TEST_ONLY_PASSWORD_123'}});
    fireEvent.click(screen.getByRole('button',{name:'Anmelden'}));
    await screen.findByRole('alert');
    expect(screen.queryByText('Geschützte Geräte')).not.toBeInTheDocument();
    expect(screen.getByLabelText('Operator-Benutzername')).toBeVisible();
  });
});
describe('named reauthentication and lock paths',()=>{
  it('retains named mode after a protected 401 and requires explicit reauthentication',async()=>{
    vi.mocked(request).mockResolvedValue(namedAuthenticated);
    render(<AuthBoundary><PrivateApp/></AuthBoundary>);
    await screen.findByText('Geschützte Geräte');
    act(()=>window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT)));
    await screen.findByLabelText('Operator-Benutzername');
    expect(screen.queryByText('Geschützte Geräte')).not.toBeInTheDocument();
    expect(screen.getByLabelText('Operator-Benutzername')).toHaveValue('');
    fireEvent.change(screen.getByLabelText('Operator-Benutzername'),{target:{value:'test.operator'}});
    fireEvent.change(screen.getByLabelText('Operator-Passwort'),{target:{value:'TEST_ONLY_PASSWORD_123'}});
    fireEvent.click(screen.getByRole('button',{name:'Anmelden'}));
    await screen.findByText('Geschützte Geräte');
    expect(request).toHaveBeenLastCalledWith('/auth/login',expect.objectContaining({body:'{"username":"test.operator","password":"TEST_ONLY_PASSWORD_123"}'}));
    expect(mutate).not.toHaveBeenCalled();
  });
  it('retains named mode after the server-relative expiry timer',async()=>{
    vi.useFakeTimers();
    vi.mocked(request).mockResolvedValue({...namedAuthenticated,expiresInSeconds:1});
    render(<AuthBoundary><PrivateApp/></AuthBoundary>);
    await act(async()=>{});
    expect(screen.getByText('Geschützte Geräte')).toBeVisible();
    await act(async()=>{await vi.advanceTimersByTimeAsync(1000);});
    expect(screen.getByLabelText('Operator-Benutzername')).toBeVisible();
    expect(screen.queryByText('Geschützte Geräte')).not.toBeInTheDocument();
  });
  it('retains named mode when logout reports that the session has expired',async()=>{
    vi.mocked(request).mockResolvedValue(namedAuthenticated);
    vi.mocked(mutate).mockRejectedValue(new APIError('Expired',401));
    render(<AuthBoundary><PrivateApp/></AuthBoundary>);
    await screen.findByText('Geschützte Geräte');
    fireEvent.click(screen.getByRole('button',{name:'Abmelden'}));
    expect(await screen.findByLabelText('Operator-Benutzername')).toBeVisible();
    expect(screen.queryByText('Geschützte Geräte')).not.toBeInTheDocument();
  });
  it('uses named mode when fresh login follows a pending logout on reload',async()=>{
    localStorage.setItem(LOGOUT_INTENT_KEY,'1');
    vi.mocked(request).mockResolvedValue(namedAuthenticated);
    render(<AuthBoundary><PrivateApp/></AuthBoundary>);
    fireEvent.click(await screen.findByRole('button',{name:'Neu anmelden'}));
    expect(screen.getByLabelText('Operator-Benutzername')).toBeVisible();
    expect(localStorage.getItem(LOGOUT_INTENT_KEY)).toBe('1');
  });
  it('retains named mode after cross-tab logout locks the session',async()=>{
    vi.mocked(request).mockResolvedValue(namedAuthenticated);
    render(<AuthBoundary><PrivateApp/></AuthBoundary>);
    await screen.findByText('Geschützte Geräte');
    act(()=>window.dispatchEvent(new StorageEvent('storage',{key:LOGOUT_INTENT_KEY,newValue:'1'})));
    fireEvent.click(screen.getByRole('button',{name:'Neu anmelden'}));
    expect(screen.getByLabelText('Operator-Benutzername')).toBeVisible();
    expect(screen.queryByText('Geschützte Geräte')).not.toBeInTheDocument();
  });
  it('keeps the named login field after background session revalidation finds expiry',async()=>{
    vi.mocked(request).mockResolvedValueOnce(namedAuthenticated).mockResolvedValue(namedAnonymous);
    render(<AuthBoundary><PrivateApp/></AuthBoundary>);
    await screen.findByText('Geschützte Geräte');
    act(()=>window.dispatchEvent(new Event('pagehide')));
    act(()=>window.dispatchEvent(new Event('pageshow')));
    expect(await screen.findByLabelText('Operator-Benutzername')).toBeVisible();
    expect(screen.queryByText('Geschützte Geräte')).not.toBeInTheDocument();
  });
  it('discards private drafts when revalidation changes actor metadata',async()=>{
    vi.mocked(request).mockResolvedValueOnce(namedAuthenticated).mockResolvedValue({...namedAuthenticated,actorId:'operator_ffffffffffffffffffffffffffffffff'});
    render(<AuthBoundary><PrivateApp/></AuthBoundary>);
    await screen.findByText('Geschützte Geräte');
    fireEvent.change(screen.getByLabelText('Privater Entwurf'),{target:{value:'old actor draft'}});
    act(()=>window.dispatchEvent(new Event('pagehide')));
    act(()=>window.dispatchEvent(new Event('pageshow')));
    await waitFor(()=>expect(screen.getByText('Geschützte Geräte')).toBeVisible());
    expect(screen.getByLabelText('Privater Entwurf')).toHaveValue('nicht gespeichert');
  });
});
describe('secret-safe login and logout',()=>{
  it('sends one explicit login, clears password, stores no credential or session token',async()=>{vi.mocked(request).mockResolvedValueOnce(anonymous).mockResolvedValue(authenticated);render(<AuthBoundary><PrivateApp/></AuthBoundary>);await screen.findByLabelText('Operator-Passwort');fireEvent.change(screen.getByLabelText('Operator-Passwort'),{target:{value:'TEST_ONLY_PASSWORD_123'}});fireEvent.click(screen.getByRole('button',{name:'Anmelden'}));expect(screen.getByLabelText('Operator-Passwort')).toHaveValue('');await screen.findByText('Geschützte Geräte');expect(request).toHaveBeenLastCalledWith('/auth/login',expect.objectContaining({method:'POST',body:'{"password":"TEST_ONLY_PASSWORD_123"}',headers:{'Content-Type':'application/json'}}));expect(JSON.stringify({...localStorage,...sessionStorage})).not.toContain('TEST_ONLY_PASSWORD_123');expect(JSON.stringify({...localStorage,...sessionStorage})).not.toContain('session-csrf');expect(screen.getByText('LAN · Sitzung aktiv')).toBeVisible();});
  it('does not echo credentials after rejected login',async()=>{vi.mocked(request).mockResolvedValueOnce(anonymous).mockRejectedValue(new APIError('TEST_ONLY_PASSWORD_123',401));render(<AuthBoundary><PrivateApp/></AuthBoundary>);await screen.findByLabelText('Operator-Passwort');fireEvent.change(screen.getByLabelText('Operator-Passwort'),{target:{value:'TEST_ONLY_PASSWORD_123'}});fireEvent.click(screen.getByRole('button',{name:'Anmelden'}));await screen.findByText('Anmeldung nicht möglich. Passwort prüfen.');expect(screen.getByLabelText('Operator-Passwort')).toHaveValue('');expect(document.body.textContent).not.toContain('TEST_ONLY_PASSWORD_123');expect(screen.queryByText('Geschützte Geräte')).not.toBeInTheDocument();});
  it('logs out through the CSRF-protected real action and clears private view',async()=>{vi.mocked(request).mockResolvedValue(authenticated);vi.mocked(mutate).mockResolvedValue(anonymous);render(<AuthBoundary><PrivateApp/></AuthBoundary>);await screen.findByText('Geschützte Geräte');fireEvent.click(screen.getByRole('button',{name:'Abmelden'}));expect(screen.queryByText('Geschützte Geräte')).not.toBeInTheDocument();await screen.findByLabelText('Operator-Passwort');expect(mutate).toHaveBeenCalledWith('/auth/logout',{},expect.any(AbortSignal));expect(abortProtectedRequests).toHaveBeenCalled();expect(screen.getByText('Abgemeldet.')).toBeVisible();});
  it('does not claim logout succeeded when the server response is uncertain',async()=>{vi.mocked(request).mockResolvedValue(authenticated);vi.mocked(mutate).mockRejectedValue(new APIError('Network'));render(<AuthBoundary><PrivateApp/></AuthBoundary>);await screen.findByText('Geschützte Geräte');fireEvent.click(screen.getByRole('button',{name:'Abmelden'}));await screen.findByRole('button',{name:'Erneut abmelden'});expect(screen.queryByText('Geschützte Geräte')).not.toBeInTheDocument();expect(screen.queryByText('Abgemeldet.')).not.toBeInTheDocument();expect(screen.getByRole('alert')).toHaveTextContent('nicht bestätigt');});
});
describe('expiry and stale private work',()=>{
  it('purges visible data/drafts and aborts pending work on protected 401',async()=>{vi.mocked(request).mockResolvedValue(authenticated);render(<AuthBoundary><PrivateApp/></AuthBoundary>);await screen.findByText('Geschützte Geräte');fireEvent.change(screen.getByLabelText('Privater Entwurf'),{target:{value:'PRIVATE_DRAFT'}});act(()=>window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT)));await screen.findByLabelText('Operator-Passwort');expect(screen.queryByText('Geschützte Geräte')).not.toBeInTheDocument();expect(screen.queryByLabelText('Privater Entwurf')).not.toBeInTheDocument();expect(document.body.textContent).not.toContain('PRIVATE_DRAFT');expect(abortProtectedRequests).toHaveBeenCalled();expect(screen.getByText('Sitzung abgelaufen. Bitte erneut anmelden.')).toBeVisible();expect(mutate).not.toHaveBeenCalled();});
  it('uses server-relative TTL rather than browser calendar time',async()=>{vi.useFakeTimers();vi.mocked(request).mockResolvedValue({...authenticated,serverNow:'2000-01-01T00:00:00Z',expiresAt:'2000-01-01T00:00:01Z',expiresInSeconds:1});render(<AuthBoundary><PrivateApp/></AuthBoundary>);await act(async()=>{});expect(screen.getByText('Geschützte Geräte')).toBeVisible();await act(async()=>{await vi.advanceTimersByTimeAsync(1000);});expect(screen.queryByText('Geschützte Geräte')).not.toBeInTheDocument();expect(screen.getByLabelText('Operator-Passwort')).toBeVisible();});
  it('never automatically replays interrupted writes after reauthentication',async()=>{vi.mocked(request).mockResolvedValue(authenticated);render(<AuthBoundary><PrivateApp/></AuthBoundary>);await screen.findByText('Geschützte Geräte');act(()=>window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT)));await screen.findByLabelText('Operator-Passwort');fireEvent.change(screen.getByLabelText('Operator-Passwort'),{target:{value:'TEST_ONLY_PASSWORD_123'}});fireEvent.click(screen.getByRole('button',{name:'Anmelden'}));await screen.findByText('Geschützte Geräte');expect(mutate).not.toHaveBeenCalled();expect(vi.mocked(request).mock.calls.filter(([path])=>path==='/auth/login')).toHaveLength(1);});
  it('treats malformed bootstrap data as unavailable instead of disabled auth',async()=>{vi.mocked(request).mockResolvedValue({mode:'development'});render(<AuthBoundary><PrivateApp/></AuthBoundary>);await waitFor(()=>expect(screen.getByRole('alert')).toHaveTextContent('keinen gültigen Zugriffsstatus'));expect(screen.queryByText('Geschützte Geräte')).not.toBeInTheDocument();});
});

describe('cross-tab and reload logout intent',()=>{
  it('persists only a non-secret pending marker and remains locked after reload',async()=>{vi.mocked(request).mockResolvedValue(authenticated);vi.mocked(mutate).mockRejectedValue(new APIError('Network'));const first=render(<AuthBoundary><PrivateApp/></AuthBoundary>);await screen.findByText('Geschützte Geräte');fireEvent.click(screen.getByRole('button',{name:'Abmelden'}));await screen.findByRole('button',{name:'Erneut abmelden'});expect(localStorage.getItem(LOGOUT_INTENT_KEY)).toBe('1');first.unmount();render(<AuthBoundary><PrivateApp/></AuthBoundary>);await screen.findByText('Abmeldung noch nicht bestätigt. Bitte erneut abmelden.');expect(screen.queryByText('Geschützte Geräte')).not.toBeInTheDocument();expect(localStorage.getItem(LOGOUT_INTENT_KEY)).toBe('1');});
  it('locks private content on same-origin logout intent from another tab',async()=>{vi.mocked(request).mockResolvedValue(authenticated);render(<AuthBoundary><PrivateApp/></AuthBoundary>);await screen.findByText('Geschützte Geräte');localStorage.setItem(LOGOUT_INTENT_KEY,'1');act(()=>window.dispatchEvent(new StorageEvent('storage',{key:LOGOUT_INTENT_KEY,newValue:'1'})));expect(screen.queryByText('Geschützte Geräte')).not.toBeInTheDocument();expect(screen.getByRole('alert')).toHaveTextContent('anderen Tab');expect(abortProtectedRequests).toHaveBeenCalled();expect(mutate).not.toHaveBeenCalled();});
  it('removes the intent marker only after confirmed logout',async()=>{vi.mocked(request).mockResolvedValue(authenticated);let finish!:(value:OperatorSession)=>void;vi.mocked(mutate).mockImplementation(()=>new Promise<OperatorSession>(resolve=>{finish=resolve;}));render(<AuthBoundary><PrivateApp/></AuthBoundary>);await screen.findByText('Geschützte Geräte');fireEvent.click(screen.getByRole('button',{name:'Abmelden'}));expect(localStorage.getItem(LOGOUT_INTENT_KEY)).toBe('1');await act(async()=>{finish(anonymous);});await screen.findByText('Abgemeldet.');expect(localStorage.getItem(LOGOUT_INTENT_KEY)).toBeNull();});
  it('allows explicit fresh login to clear a pending intent without replaying writes',async()=>{localStorage.setItem(LOGOUT_INTENT_KEY,'1');vi.mocked(request).mockResolvedValue(authenticated);render(<AuthBoundary><PrivateApp/></AuthBoundary>);await screen.findByRole('button',{name:'Neu anmelden'});fireEvent.click(screen.getByRole('button',{name:'Neu anmelden'}));expect(localStorage.getItem(LOGOUT_INTENT_KEY)).toBe('1');fireEvent.change(screen.getByLabelText('Operator-Passwort'),{target:{value:'TEST_ONLY_PASSWORD_123'}});fireEvent.click(screen.getByRole('button',{name:'Anmelden'}));await screen.findByText('Geschützte Geräte');expect(localStorage.getItem(LOGOUT_INTENT_KEY)).toBeNull();expect(mutate).not.toHaveBeenCalled();});
});

describe('background and BFCache privacy',()=>{
  it('conceals private DOM on pagehide and respects a missed logout marker on pageshow',async()=>{vi.mocked(request).mockResolvedValue(authenticated);render(<AuthBoundary><PrivateApp/></AuthBoundary>);await screen.findByText('Geschützte Geräte');act(()=>window.dispatchEvent(new Event('pagehide')));expect(screen.getByText('Geschützte Geräte')).not.toBeVisible();localStorage.setItem(LOGOUT_INTENT_KEY,'1');act(()=>window.dispatchEvent(new Event('pageshow')));expect(screen.queryByText('Geschützte Geräte')).not.toBeInTheDocument();expect(screen.getByRole('alert')).toHaveTextContent('anderen Tab');});
  it('revalidates the real session before restoring a cached private view',async()=>{vi.mocked(request).mockResolvedValueOnce(authenticated).mockResolvedValue(anonymous);render(<AuthBoundary><PrivateApp/></AuthBoundary>);await screen.findByText('Geschützte Geräte');act(()=>window.dispatchEvent(new Event('pagehide')));act(()=>window.dispatchEvent(new Event('pageshow')));await screen.findByLabelText('Operator-Passwort');expect(screen.queryByText('Geschützte Geräte')).not.toBeInTheDocument();expect(request).toHaveBeenCalledTimes(2);});
  it('preserves a draft only after confirming the same session on return',async()=>{vi.mocked(request).mockResolvedValue(authenticated);render(<AuthBoundary><PrivateApp/></AuthBoundary>);await screen.findByText('Geschützte Geräte');fireEvent.change(screen.getByLabelText('Privater Entwurf'),{target:{value:'same-session draft'}});act(()=>window.dispatchEvent(new Event('pagehide')));act(()=>window.dispatchEvent(new Event('pageshow')));await waitFor(()=>expect(screen.getByText('Geschützte Geräte')).toBeVisible());expect(screen.getByLabelText('Privater Entwurf')).toHaveValue('same-session draft');});
});

describe('transport risk and fallback logout persistence',()=>{
 it('rejects missing or contradictory transport facts',()=>{expect(validOperatorSession({...anonymous,transport:undefined})).toBe(false);expect(validOperatorSession({...anonymous,transport:'http'})).toBe(false);expect(validOperatorSession({...anonymous,insecureTestMode:true})).toBe(false);expect(validOperatorSession({...anonymous,transport:'http',insecureTestMode:true,transportWarning:'unencrypted_lan_test'},'http:')).toBe(true);});
 it('shows an enduring unencrypted warning on login in both languages',async()=>{vi.stubGlobal('location',new URL('http://localhost/'));vi.mocked(request).mockResolvedValue({...anonymous,transport:'http',insecureTestMode:true,transportWarning:'unencrypted_lan_test'});render(<AuthBoundary><PrivateApp/></AuthBoundary>);await screen.findByLabelText('Operator-Passwort');expect(screen.getByRole('note')).toHaveTextContent('Unverschlüsselter LAN-Test');expect(screen.getByRole('note')).toHaveTextContent('Passwörter und Daten');expect(screen.getByRole('note')).toHaveTextContent('Server nachahmen');expect(screen.getByRole('note')).toHaveTextContent('Sitzungen übernehmen');fireEvent.change(screen.getByLabelText('Sprache'),{target:{value:'en'}});expect(screen.getByRole('note')).toHaveTextContent('Unencrypted LAN test');expect(screen.getByRole('note')).toHaveTextContent('impersonate the server');expect(screen.getByRole('note')).toHaveTextContent('hijack sessions');expect(screen.getByLabelText('Operator password')).toBeVisible();});
 it('persists received logout intent in sessionStorage when localStorage is unavailable',async()=>{vi.mocked(request).mockResolvedValue(authenticated);const set=Storage.prototype.setItem;vi.spyOn(Storage.prototype,'setItem').mockImplementation(function(this:Storage,key:string,value:string){if(this===localStorage)throw new Error('blocked');return set.call(this,key,value);});const first=render(<AuthBoundary><PrivateApp/></AuthBoundary>);await screen.findByText('Geschützte Geräte');act(()=>window.dispatchEvent(new StorageEvent('storage',{key:LOGOUT_INTENT_KEY,newValue:'1'})));expect(sessionStorage.getItem(LOGOUT_INTENT_KEY)).toBe('1');first.unmount();render(<AuthBoundary><PrivateApp/></AuthBoundary>);await screen.findByText('Abmeldung noch nicht bestätigt. Bitte erneut abmelden.');expect(screen.queryByText('Geschützte Geräte')).not.toBeInTheDocument();});
 it('warns when neither store can retain received logout intent',async()=>{vi.mocked(request).mockResolvedValue(authenticated);vi.spyOn(Storage.prototype,'setItem').mockImplementation(()=>{throw new Error('blocked');});render(<AuthBoundary><PrivateApp/></AuthBoundary>);await screen.findByText('Geschützte Geräte');act(()=>window.dispatchEvent(new StorageEvent('storage',{key:LOGOUT_INTENT_KEY,newValue:'1'})));expect(screen.getByRole('alert')).toHaveTextContent('Browsersperre konnte nicht gespeichert');expect(screen.queryByText('Geschützte Geräte')).not.toBeInTheDocument();});
});

describe('actual operator browser transport',()=>{
 it('fails closed when declared TLS arrives at an HTTP browser address',async()=>{vi.stubGlobal('location',new URL('http://localhost/'));vi.mocked(request).mockResolvedValue(anonymous);render(<AuthBoundary><PrivateApp/></AuthBoundary>);await screen.findByRole('alert');expect(screen.queryByLabelText('Operator-Passwort')).not.toBeInTheDocument();expect(screen.queryByText('Geschützte Geräte')).not.toBeInTheDocument();});
 it('rejects both transport mismatches without inferring trust from an endpoint name',()=>{expect(validOperatorSession(authenticated,'http:')).toBe(false);expect(validOperatorSession({...anonymous,transport:'http',insecureTestMode:true,transportWarning:'unencrypted_lan_test'},'https:')).toBe(false);expect(validOperatorSession(authenticated,'https:')).toBe(true);});
});
