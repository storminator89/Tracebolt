/** Diagnostic-only fixture helpers. No raw errors, bodies, URLs, DOM text,
 * identifiers or input values are reported. Assertions and write count remain. */
import {createBrowserTransportDiagnostics} from './browser-transport-diagnostics.mjs';
const freshSteps=new Set(['read capability','capability status','capability response bytes','capability JSON decode','collection profile','collection privacy','open dialog','consent unchecked','creation disabled','acknowledge consent','arm primary reader','register creation response','submit creation','await creation response','creation status','request consent','await primary reader','primary reader snapshot','primary reader complete','primary reader validity','primary response binding','creation schema','secret type','masked field','masked value']);
const mobileSteps=new Set(['table ARIA','scroll table into view','focus table','press ArrowRight','horizontal scroll response','document offsets','document bounds','main box presence','main viewport bounds','device geometry read','device left inset','device right inset','device width','no legacy panels','no dialogs']);
export function v3DiagnosticStage(scope,step){return scope==='fresh'&&freshSteps.has(step)?`fresh consent / ${step}`:scope==='mobile'&&mobileSteps.has(step)?`mobile socket / ${step}`:'v3 diagnostic / unknown';}
export async function checkFreshV3Consent(page,{base,context,expect,mark,diagnostics}){
 const step=value=>{mark(v3DiagnosticStage('fresh',value));diagnostics?.operation(value.endsWith('response bytes')?'response-body':'other');};
 step('read capability');const capability=await context.request.get(base+'/api/enrollment');diagnostics?.response(capability);
 step('capability status');expect(capability.status()).toBe(200);
 step('capability response bytes');const capabilityBytes=await capability.body();
 step('capability JSON decode');const state=JSON.parse(capabilityBytes.toString('utf8'));
 step('collection profile');expect(state.collectionProfile).toBe('managed-operations-v3');
 step('collection privacy');expect(state.collectionPrivacy).toBe('complete_system_inventory_metadata_may_be_sensitive');
 step('open dialog');await page.getByRole('button',{name:'Add device',exact:true}).click();
 const consent=page.getByRole('checkbox',{name:'I acknowledge operational metadata, complete supported dpkg packages, system services, and local connection metadata for this new device.',exact:true});
 step('consent unchecked');await expect(consent).not.toBeChecked();
 step('creation disabled');await expect(page.getByRole('button',{name:'Create invitation',exact:true})).toBeDisabled();
 step('acknowledge consent');await consent.check();
 let capture;
 try{
  step('arm primary reader');capture=await page.evaluate(()=>window.__traceboltEnrollmentBody.arm());
  step('register creation response');diagnostics?.response(null);const pending=page.waitForResponse(r=>r.url()===base+'/api/enrollment/invitations'&&r.request().method()==='POST');
  step('submit creation');await page.getByRole('button',{name:'Create invitation',exact:true}).click();
  step('await creation response');const response=await pending;diagnostics?.response(response);
  step('creation status');expect(response.status()).toBe(201);
  step('request consent');expect(response.request().postDataJSON().collectionAcknowledged).toBe(true);
  // Observe only the application's original bounded reader. A failed secondary
  // CDP body lookup is not evidence of either primary success or primary failure.
  step('await primary reader');await expect.poll(()=>page.evaluate(id=>window.__traceboltEnrollmentBody.state(id),capture)).not.toMatch(/^(armed|waiting|reading)$/);
  step('primary reader snapshot');const primary=await page.evaluate(id=>window.__traceboltEnrollmentBody.snapshot(id),capture);diagnostics?.primary(primary);
  step('primary reader complete');expect(primary.phase).toBe('complete');
  step('primary reader validity');expect(primary.eof===true&&primary.signalAborted===false&&primary.requests===1).toBe(true);
  step('primary response binding');const consumed=await page.evaluate(id=>window.__traceboltEnrollmentBody.take(id),capture);
  expect(consumed!==null).toBe(true);expect(consumed.status).toBe(201);expect(consumed.requestBody===response.request().postData()).toBe(true);
  const created=consumed.body;
  step('creation schema');expect(created?.schemaVersion==='tracebolt.enrollment-invitation.v2').toBe(true);
  step('secret type');expect(typeof created.invitationSecret).toBe('string');
  step('masked field');const input=page.getByLabel('One-time invitation secret',{exact:true});await expect(input).toHaveAttribute('type','password');
  step('masked value');expect(await input.inputValue()===created.invitationSecret).toBe(true);
  return created;
 }finally{
  // Destructive take plus unconditional clear: no observer secret survives into
  // public-command, screenshot, dismissal or protected-session checks.
  try{await page.evaluate(()=>window.__traceboltEnrollmentBody.clear());}catch{}
 }
}
export async function checkV3Viewport(page,{expect,mark=()=>{}}){
 const step=value=>mark(v3DiagnosticStage('mobile',value));
 step('document offsets');expect(await page.evaluate(()=>({x:scrollX,y:scrollY,w:document.documentElement.scrollWidth,h:document.documentElement.scrollHeight,vw:innerWidth,vh:innerHeight}))).toEqual(expect.objectContaining({x:0,y:0}));
 step('document bounds');expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1&&document.body.scrollWidth<=innerWidth+1&&document.documentElement.scrollHeight<=innerHeight+1)).toBe(true);
 const main=page.locator('main.device-main');step('main box presence');const box=await main.boundingBox();expect(box).not.toBeNull();
 step('main viewport bounds');expect(box.x>=0&&box.y>=0&&box.x+box.width<=page.viewportSize().width+1&&box.y+box.height<=page.viewportSize().height+1).toBe(true);
 step('device geometry read');const geometry=await page.locator('.device-page').evaluate(el=>{const main=el.closest('main'),style=getComputedStyle(main),box=el.getBoundingClientRect(),parent=main.getBoundingClientRect();return{left:box.left-parent.left,right:parent.right-box.right,width:box.width,available:main.clientWidth-parseFloat(style.paddingLeft)-parseFloat(style.paddingRight)};});
 step('device left inset');expect(geometry.left).toBeGreaterThanOrEqual(0);
 step('device right inset');expect(geometry.right).toBeGreaterThanOrEqual(-1);
 step('device width');expect(Math.abs(geometry.width-geometry.available)).toBeLessThanOrEqual(1);
 step('no legacy panels');await expect(page.locator('.inventory-panel,.enrollment-panel')).toHaveCount(0);
 step('no dialogs');await expect(page.getByRole('dialog')).toHaveCount(0);
}
export async function checkMobileSocketViewport(page,{expect,mark}){
 const step=value=>mark(v3DiagnosticStage('mobile',value));const region=page.locator('.system-inventory .package-table-scroll');
 step('table ARIA');await expect(region).toHaveAttribute('aria-label','Local sockets and connections');
 step('scroll table into view');await region.scrollIntoViewIfNeeded();
 step('focus table');await region.focus();
 step('press ArrowRight');await page.keyboard.press('ArrowRight');
 step('horizontal scroll response');await expect.poll(()=>region.evaluate(el=>el.scrollLeft)).toBeGreaterThan(0);
 await checkV3Viewport(page,{expect,mark});return region;
}
const numericKeys=['tableCount','rowCount','scrollLeft','scrollTop','scrollWidth','clientWidth','clientHeight','tableLeft','tableTop','tableWidth','tableHeight','windowX','windowY','viewportWidth','viewportHeight','documentWidth','documentHeight','bodyWidth','bodyHeight','mainLeft','mainTop','mainWidth','mainHeight','mainClientWidth','mainScrollTop','deviceLeft','deviceRight','deviceWidth','deviceAvailable'];
const booleanKeys=['tablePresent','tableFocused','systemPresent','systemBusy','alertPresent','privateInert','documentVisible'];
export function sanitizeV3MobileSnapshot(value){
 const result={};if(!value||typeof value!=='object'||Array.isArray(value))return result;
 for(const key of numericKeys){const number=value[key];if(typeof number==='number'&&Number.isFinite(number)&&Math.abs(number)<=100000)result[key]=Math.round(number*1000)/1000;}
 for(const key of booleanKeys)if(typeof value[key]==='boolean')result[key]=value[key];
 return result;
}
// Browser-side fixed selectors, numeric geometry and booleans only.
export function readV3MobileSnapshot(){
 const system=document.querySelector('.system-inventory'),tables=document.querySelectorAll('.system-inventory .package-table-scroll'),table=tables[0],main=document.querySelector('main.device-main'),device=document.querySelector('.device-page');
 const t=table?.getBoundingClientRect(),m=main?.getBoundingClientRect(),d=device?.getBoundingClientRect(),style=main?getComputedStyle(main):null;
 return {tableCount:Math.min(tables.length,100),rowCount:Math.min(system?.querySelectorAll('tbody tr').length??0,10000),tablePresent:Boolean(table),tableFocused:Boolean(table&&document.activeElement===table),systemPresent:Boolean(system),systemBusy:system?.getAttribute('aria-busy')==='true',alertPresent:Boolean(system?.querySelector('[role=alert]')),privateInert:Boolean(document.querySelector('.auth-private-view[inert]')),documentVisible:document.visibilityState==='visible',scrollLeft:table?.scrollLeft,scrollTop:table?.scrollTop,scrollWidth:table?.scrollWidth,clientWidth:table?.clientWidth,clientHeight:table?.clientHeight,tableLeft:t?.left,tableTop:t?.top,tableWidth:t?.width,tableHeight:t?.height,windowX:scrollX,windowY:scrollY,viewportWidth:innerWidth,viewportHeight:innerHeight,documentWidth:document.documentElement.scrollWidth,documentHeight:document.documentElement.scrollHeight,bodyWidth:document.body.scrollWidth,bodyHeight:document.body.scrollHeight,mainLeft:m?.left,mainTop:m?.top,mainWidth:m?.width,mainHeight:m?.height,mainClientWidth:main?.clientWidth,mainScrollTop:main?.scrollTop,deviceLeft:d&&m?d.left-m.left:undefined,deviceRight:d&&m?m.right-d.right:undefined,deviceWidth:d?.width,deviceAvailable:main&&style?main.clientWidth-parseFloat(style.paddingLeft)-parseFloat(style.paddingRight):undefined};
}
export function createV3FailureDiagnostics(page,browser){
 const transport=createBrowserTransportDiagnostics(page,browser),events=[];let response=null,operation='other',primary=null;
 const resource=url=>{try{const path=new URL(url).pathname;return path==='/api/enrollment'?'enrollment-status':path==='/api/enrollment/invitations'?'enrollment-create':/^\/api\/devices\/agent_[a-f0-9]{32}\/inventory\/system$/.test(path)?'system-status':/^\/api\/devices\/agent_[a-f0-9]{32}\/inventory\/system\/query$/.test(path)?'system-query':null;}catch{return null;}};
 const record=(request,phase,status=0)=>{const route=resource(request.url()),method=request.method();if(route&&events.length<32&&['GET','POST'].includes(method)&&Number.isInteger(status)&&status>=0&&status<=599)events.push({resource:route,method,phase,status});};
 const listeners=[['request',r=>record(r,'request')],['response',r=>record(r.request(),'response',r.status())],['requestfailed',r=>record(r,'failed')]];
 for(const [event,listener]of listeners)page.on(event,listener);
 return {
  primary(value){primary=sanitizeV3PrimarySnapshot(value);},
  response(value){response=value;},operation(value){operation=value==='response-body'?'response-body':'other';},
  capture(error){let detail=null;try{detail=transport.capture(operation,error,{response});}catch{}let status=null;try{const value=response?.status();if(Number.isInteger(value)&&value>=100&&value<=599)status=value;}catch{}return {responseStatus:status,transport:detail,events:events.slice(),...(primary?{primary}: {})};},
  async mobile(){return sanitizeV3MobileSnapshot(await page.evaluate(readV3MobileSnapshot));},
  dispose(){transport.dispose();for(const [event,listener]of listeners)page.off(event,listener);response=null;primary=null;events.length=0;},
 };
}

export function sanitizeV3PrimarySnapshot(value){
 if(!value||typeof value!=='object')return null;
 const phases=new Set(['armed','waiting','reading','complete','aborted','failed','invalid','cancelled','oversized','invalidated','duplicate','missing','missing-body','invalid-request','cleared']);
 const safe={phase:phases.has(value.phase)?value.phase:'unknown'};
 for(const [key,maximum]of [['requests',2],['status',599],['bytes',262145]])if(Number.isInteger(value[key])&&value[key]>=0&&value[key]<=maximum)safe[key]=value[key];
 for(const key of ['eof','signalAborted'])if(typeof value[key]==='boolean')safe[key]=value[key];
 return safe;
}
