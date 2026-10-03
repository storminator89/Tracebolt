import { afterEach, describe, expect, it, vi } from 'vitest';
import { mutate, request } from './api';
afterEach(()=>vi.unstubAllGlobals());
describe('API honesty and mutation boundary',()=>{
  it('surfaces connection errors and never injects fixture data',async()=>{vi.stubGlobal('fetch',vi.fn().mockRejectedValue(new TypeError('network')));await expect(request('/overview')).rejects.toThrow('nicht erreichbar');await expect(request('/overview')).rejects.not.toThrow('8787');});
  it('surfaces invalid JSON',async()=>{vi.stubGlobal('fetch',vi.fn().mockResolvedValue({ok:true,json:()=>Promise.reject(new SyntaxError())}));await expect(request('/overview')).rejects.toThrow('gültigen JSON');});
  it('surfaces backend validation errors',async()=>{vi.stubGlobal('fetch',vi.fn().mockResolvedValue({ok:false,status:400,json:()=>Promise.resolve({error:{message:'Too long'}})}));await expect(request('/cases/test')).rejects.toThrow('Too long');});
  it('fetches CSRF token then sends bounded JSON mutation',async()=>{const fetch=vi.fn().mockResolvedValueOnce({ok:true,json:()=>Promise.resolve({csrfToken:'example-token'})}).mockResolvedValueOnce({ok:true,json:()=>Promise.resolve({id:'case'})});vi.stubGlobal('fetch',fetch);await expect(mutate('/cases/case/notes',{text:'test'})).resolves.toEqual({id:'case'});expect(fetch.mock.calls[1][1]).toEqual(expect.objectContaining({method:'POST',body:'{"text":"test"}',headers:expect.objectContaining({'X-CSRF-Token':'example-token','Content-Type':'application/json'})}));});
});
