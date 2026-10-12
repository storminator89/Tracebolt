import { afterEach, expect, it, vi } from 'vitest';
import { mutateRaw } from './api';
afterEach(()=>vi.unstubAllGlobals());
it.each(['deliver','batches','preview','archive'])('checks the foreground guard after CSRF, before the actual %s POST',async operation=>{
 let resolve!:(response:Response)=>void,foreground=true;
 const fetch=vi.fn().mockImplementationOnce(()=>new Promise<Response>(r=>{resolve=r}));vi.stubGlobal('fetch',fetch);
 const pending=mutateRaw(`/windows-managed-msi/worklists/worklist_${'a'.repeat(32)}/${operation}`,'{}',{},undefined,32768,()=>foreground);
 foreground=false;resolve(new Response(JSON.stringify({csrfToken:'exact-test-token'}),{status:200,headers:{'Content-Type':'application/json'}}));
 await expect(pending).rejects.toMatchObject({name:'AbortError'});expect(fetch).toHaveBeenCalledTimes(1);expect(fetch.mock.calls[0][0]).toBe('/api/session');
});
it('keeps existing mutation callers unchanged when no foreground guard is supplied',async()=>{
 const fetch=vi.fn().mockResolvedValueOnce(new Response(JSON.stringify({csrfToken:'exact-test-token'}),{status:200})).mockResolvedValueOnce(new Response(JSON.stringify({accepted:true}),{status:200}));vi.stubGlobal('fetch',fetch);
 await expect(mutateRaw('/existing-fixture','{}')).resolves.toEqual({accepted:true});expect(fetch).toHaveBeenCalledTimes(2);expect(fetch.mock.calls[1][1].method).toBe('POST');
});
