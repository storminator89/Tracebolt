import {afterEach,describe,expect,it,vi} from 'vitest';
import {abortProtectedRequests,mutateRaw,request} from './api';
const path=`/devices/agent_${'a'.repeat(32)}/asset-fields`;
const json=(value:unknown,status=200)=>new Response(JSON.stringify(value),{status,headers:{'Content-Type':'application/json'}});
afterEach(()=>{abortProtectedRequests();vi.unstubAllGlobals();});
describe('asset fields bounded transport',()=>{
 it.each(['device_asset_fields_rejected','device_asset_fields_unconfirmed'])('retains structured %s',async code=>{vi.stubGlobal('fetch',vi.fn().mockResolvedValue(json({error:{code,message:'Result'}},409)));await expect(request(path)).rejects.toMatchObject({status:409,code});});
 it('bounds responses to the explicit private view cap',async()=>{vi.stubGlobal('fetch',vi.fn().mockResolvedValue(json({data:'x'.repeat(32768)})));await expect(request(path,{},32768)).rejects.toThrow();});
 it('does not invoke dispatch gate on CSRF failure',async()=>{const gate=vi.fn(()=>true);vi.stubGlobal('fetch',vi.fn().mockRejectedValue(new Error('network')));await expect(mutateRaw(path,'{}',{},undefined,32768,gate)).rejects.toThrow();expect(gate).not.toHaveBeenCalled();});
 it('respects the final send gate before starting POST',async()=>{const gate=vi.fn(()=>false),fetch=vi.fn().mockResolvedValue(json({csrfToken:'csrf'}));vi.stubGlobal('fetch',fetch);await expect(mutateRaw(path,'{}',{},undefined,32768,gate)).rejects.toHaveProperty('name','AbortError');expect(fetch).toHaveBeenCalledOnce();});
});
