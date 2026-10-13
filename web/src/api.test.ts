import { afterEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, AUTH_REQUIRED_EVENT, mutate, mutateRaw, request } from './api';
const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } });
afterEach(()=>{abortProtectedRequests();vi.unstubAllGlobals();});
describe('API honesty and mutation boundary',()=>{
  it('surfaces connection errors and never injects fixture data',async()=>{vi.stubGlobal('fetch',vi.fn().mockRejectedValue(new TypeError('network')));await expect(request('/overview')).rejects.toThrow('nicht erreichbar');await expect(request('/overview')).rejects.not.toThrow('8787');});
  it('surfaces invalid JSON',async()=>{vi.stubGlobal('fetch',vi.fn().mockResolvedValue(new Response('{')));await expect(request('/overview')).rejects.toThrow('gültigen JSON');});
  it('surfaces backend validation errors',async()=>{vi.stubGlobal('fetch',vi.fn().mockResolvedValue(json({error:{message:'Too long'}},400)));await expect(request('/cases/test')).rejects.toThrow('Too long');});
  it('fetches CSRF token then sends bounded JSON mutation',async()=>{const fetch=vi.fn().mockResolvedValueOnce(json({csrfToken:'example-token'})).mockResolvedValueOnce(json({id:'case'}));vi.stubGlobal('fetch',fetch);await expect(mutate('/cases/case/notes',{text:'test'})).resolves.toEqual({id:'case'});expect(fetch.mock.calls[1][1]).toEqual(expect.objectContaining({method:'POST',body:'{"text":"test"}',headers:expect.objectContaining({'X-CSRF-Token':'example-token','Content-Type':'application/json'})}));});
});

describe('authentication interruption boundary',()=>{
  it('signals protected 401 and rejects a late private response',async()=>{let finish!:(value:Response)=>void;const unauthorized=vi.fn();window.addEventListener(AUTH_REQUIRED_EVENT,unauthorized);const fetch=vi.fn().mockImplementation((url:string)=>url==='/api/slow'?new Promise<Response>(resolve=>{finish=resolve;}):Promise.resolve(json({error:{message:'authentication_required'}},401)));vi.stubGlobal('fetch',fetch);const slow=request('/slow').catch(error=>error);await expect(request('/devices')).rejects.toMatchObject({status:401});expect(unauthorized).toHaveBeenCalledOnce();finish(json({private:'must not return'}));await expect(slow).resolves.toHaveProperty('name','AbortError');window.removeEventListener(AUTH_REQUIRED_EVENT,unauthorized);});
  it('does not treat invalid login credentials as protected-session expiry',async()=>{const unauthorized=vi.fn();window.addEventListener(AUTH_REQUIRED_EVENT,unauthorized);vi.stubGlobal('fetch',vi.fn().mockResolvedValue(json({error:{message:'invalid_credentials'}},401)));await expect(request('/auth/login',{method:'POST'})).rejects.toMatchObject({status:401});expect(unauthorized).not.toHaveBeenCalled();window.removeEventListener(AUTH_REQUIRED_EVENT,unauthorized);});
  it('never issues a write after its CSRF read is invalidated',async()=>{const fetch=vi.fn().mockResolvedValue(new Response(new ReadableStream({pull(controller){abortProtectedRequests();controller.enqueue(new TextEncoder().encode('{"csrfToken":"stale-token"}'));controller.close();}}, {highWaterMark:0})));vi.stubGlobal('fetch',fetch);await expect(mutate('/cases/test/notes',{text:'must not replay'})).rejects.toHaveProperty('name','AbortError');expect(fetch).toHaveBeenCalledOnce();expect(fetch.mock.calls[0][0]).toBe('/api/session');});
  it('does not start a canceled request',async()=>{const fetch=vi.fn();vi.stubGlobal('fetch',fetch);const controller=new AbortController();controller.abort();await expect(request('/devices',{signal:controller.signal})).rejects.toHaveProperty('name','AbortError');expect(fetch).not.toHaveBeenCalled();});
});


describe('incident service-review mutation header', () => {
  const path = `/devices/agent_${'7'.repeat(32)}/windows-service-actions/preview`, header = 'X-Tracebolt-Windows-Service-Review', digest = `sha256:${'a'.repeat(64)}`;
  it('carries the canonical binding constraint only on explicit service preview', async () => {
    const fetch = vi.fn().mockResolvedValueOnce(json({csrfToken:'csrf'})).mockResolvedValueOnce(json({ok:true})); vi.stubGlobal('fetch', fetch);
    await mutateRaw(path, '{"target":"FixtureService","operation":"start"}', {[header]:digest});
    expect(fetch.mock.calls[1][1].headers).toMatchObject({[header]:digest,'X-CSRF-Token':'csrf'});
  });
  it.each(['/devices/agent_'+'7'.repeat(32)+'/windows-service-actions/approve', '/cases/case/notes', '/devices/agent_'+'7'.repeat(32)+'/windows-service-actions/preview?fallback=1'])('rejects the constraint on another mutation %s', async target => {
    const fetch = vi.fn(); vi.stubGlobal('fetch',fetch); await expect(mutateRaw(target,'{}',{[header]:digest})).rejects.toMatchObject({status:400}); expect(fetch).not.toHaveBeenCalled();
  });
  it.each(['', 'sha256:bad', digest+', '+digest])('rejects a malformed constraint %s', async value => {
    const fetch = vi.fn(); vi.stubGlobal('fetch',fetch); await expect(mutateRaw(path,'{}',{[header]:value})).rejects.toMatchObject({status:400}); expect(fetch).not.toHaveBeenCalled();
  });
  it('checks the original context again after the CSRF read without sending a preview', async () => {
    const fetch=vi.fn().mockResolvedValueOnce(json({csrfToken:'csrf'}));vi.stubGlobal('fetch',fetch);
    await expect(mutateRaw(path,'{}',{[header]:digest},undefined,16384,()=>false)).rejects.toHaveProperty('name','AbortError');expect(fetch).toHaveBeenCalledOnce();
  });
});
