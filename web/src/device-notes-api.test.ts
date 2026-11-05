import {afterEach,describe,expect,it,vi} from 'vitest';
import {abortProtectedRequests,mutateRaw,request} from './api';
const path=`/devices/agent_${'a'.repeat(32)}/handover-notes`;
const json=(value:unknown,status=200)=>new Response(JSON.stringify(value),{status,headers:{'Content-Type':'application/json'}});
afterEach(()=>{abortProtectedRequests();vi.unstubAllGlobals();});
describe('handover notes API transport bounds',()=>{
 it('accepts escaped maximum-size content only on its bounded route',async()=>{const value={text:'<'.repeat(25*2000)};const raw=JSON.stringify(value).replaceAll('<','\\u003c');expect(raw.length).toBeGreaterThan(262144);vi.stubGlobal('fetch',vi.fn().mockResolvedValue(new Response(raw)));await expect(request(path,{},512*1024)).resolves.toEqual(value);await expect(request('/other',{},512*1024)).rejects.toThrow();});
 it.each(['device_notes_rejected','device_notes_unconfirmed'])('retains structured %s without treating HTTP status as acceptance proof',async code=>{vi.stubGlobal('fetch',vi.fn().mockResolvedValue(json({error:{code,message:'Result'}},409)));await expect(request(path)).rejects.toMatchObject({status:409,code});});
 it('never reaches dispatch gate on CSRF network failure',async()=>{const gate=vi.fn(()=>true),fetch=vi.fn().mockRejectedValue(new Error('network'));vi.stubGlobal('fetch',fetch);await expect(mutateRaw(path,'{}',{},undefined,512*1024,gate)).rejects.toThrow();expect(gate).not.toHaveBeenCalled();expect(fetch).toHaveBeenCalledOnce();});
 it('dispatches only after the deliberate gate',async()=>{const gate=vi.fn(()=>false),fetch=vi.fn().mockResolvedValue(json({csrfToken:'csrf'}));vi.stubGlobal('fetch',fetch);await expect(mutateRaw(path,'{}',{},undefined,512*1024,gate)).rejects.toHaveProperty('name','AbortError');expect(gate).toHaveBeenCalledOnce();expect(fetch).toHaveBeenCalledOnce();});
});
