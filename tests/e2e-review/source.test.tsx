/** Supplemental DOM/source tests. These are not browser or screenshot evidence. */
import { beforeEach, afterEach, describe, expect, it, vi } from '../../web/node_modules/vitest/dist/index.js';
import { cleanup, render, screen, fireEvent, waitFor } from '../../web/node_modules/@testing-library/react/dist/index.js';
import App from '../../web/src/App';
import { defaultFilters, filterDevices, decodeRouteId, csvCell, noteBytes } from '../../web/src/utils';
const at='2026-10-03T12:00:00Z';
const metric={value:25,unit:'%',quality:'healthy',source:'synthetic-fixture',collectedAt:at};
const device={id:'review-device',name:'REVIEW-DEMO',platform:'windows',os:'Windows demo',site:'Synthetic',group:'Review',ip:null,status:'critical',source:'synthetic',synthetic:true,lastSeen:at,agentVersion:'demo',cpu:metric,memory:metric,disk:metric,uptime:'demo',tags:[],capabilities:[],evidence:[],trend:[],caseIds:[]};
const overview={product:'Tracebolt',mode:'local-development',generatedAt:at,devices:[device],cases:[],activity:[],stats:{totalDevices:1,healthyDevices:0,attentionDevices:1,unknownDevices:0,openCases:0,criticalCases:0}};
const response=(body:any,status=200)=>Promise.resolve(new Response(JSON.stringify(body),{status,headers:{'Content-Type':'application/json'}}));
beforeEach(()=>{localStorage.clear();location.hash='/devices';vi.stubGlobal('fetch',vi.fn(()=>response(overview)));});
afterEach(()=>{cleanup();vi.unstubAllGlobals();});
describe('Independent source/DOM regressions',()=>{
 it('combined attention retains critical and attention while excluding unknown',()=>{
  const devices=[device,{...device,id:'b',status:'attention'},{...device,id:'c',status:'unknown'},{...device,id:'d',status:'healthy'}];
  expect(filterDevices(devices as any,{...defaultFilters,status:'needs-attention'}).map(d=>d.status)).toEqual(['critical','attention']);
 });
 it('route parser rejects malformed percent encoding without throwing',()=>{expect(decodeRouteId('%E0%A4%A')).toBeUndefined();});
 it('CSV neutralizes formula starters and quote escaping',()=>{for(const value of ['=1+1','+1','-1','@SUM(A1)','  =1','\t=1']) expect(csvCell(value).startsWith('"\'')).toBe(true);expect(csvCell('a"b')).toBe('"a""b"');});
 it('notes count UTF-8 bytes explicitly',()=>{expect(noteBytes('é😀')).toBe(6);});
 it('skip-to-content preserves inventory route and moves DOM focus',async()=>{render(<App/>);await screen.findByRole('heading',{name:/Jedes Gerät/});fireEvent.click(screen.getByRole('link',{name:'Zum Inhalt'}));expect(location.hash).toBe('#/devices');expect(document.activeElement?.id).toBe('main-content');});
 it('initial API failure presents explicit failure with no fake inventory',async()=>{vi.stubGlobal('fetch',vi.fn(()=>response({error:{message:'controlled unavailable'}},503)));render(<App/>);expect(await screen.findByRole('alert')).toHaveTextContent('keine Ersatz-Demodaten');expect(screen.queryByText('REVIEW-DEMO')).toBeNull();});
 it('literal name markup is never interpreted as HTML',async()=>{const payload='<img src=x onerror="window.reviewXss=1">';vi.stubGlobal('fetch',vi.fn(()=>response({...overview,devices:[{...device,name:payload}]})));const {container}=render(<App/>);expect(await screen.findByText(payload)).toBeInTheDocument();expect(container.querySelector('img')).toBeNull();});
 it('malformed saved-view shape must not crash the inventory',async()=>{localStorage.setItem('local-rmm-saved-view',JSON.stringify({...defaultFilters,query:null}));render(<App/>);await screen.findByRole('heading',{name:/Jedes Gerät/});fireEvent.click(screen.getByRole('button',{name:'Gespeicherte Ansicht'}));await waitFor(()=>expect(screen.getByRole('heading',{name:/Jedes Gerät/})).toBeInTheDocument());});
});
