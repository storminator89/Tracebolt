import {openServiceActionDisplay} from './service-action-display-navigation.mjs';
/** Invented display DTOs only, including authentication. No request in this
 * gallery reaches an action API or helper. The real action suite remains
 * separate and must continue to prohibit screenshots of its private material.
 */
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
// Bundle the existing within-web fixtures and pure decoders, matching the
// journal runner's esbuild route for extensionless TypeScript imports.
const require=createRequire(new URL('../../web/package.json',import.meta.url));
const fixtureModule=require('esbuild').buildSync({stdin:{contents:`
 export {actionActor,actionDevice,actionNow,actionPreview,actionSession,actionView,actionJobView} from './src/service-action-fixtures.ts';
 export {validServiceActionView} from './src/service-action-types.ts';
 export {serviceRows,systemView,systemPage} from './src/system-inventory-fixtures.ts';
 export {validSystemView,validSystemPage} from './src/system-inventory-types.ts';
`,resolveDir:fileURLToPath(new URL('../../web/',import.meta.url)),loader:'ts'},bundle:true,write:false,platform:'node',format:'esm',logLevel:'silent'});
const {actionActor,actionDevice,actionNow,actionPreview,actionSession,actionView,actionJobView,validServiceActionView,serviceRows,systemView,systemPage,validSystemView,validSystemPage}=await import('data:text/javascript;base64,'+Buffer.from(fixtureModule.outputFiles[0].text).toString('base64'));

export const serviceActionDisplayCaseName='Synthetic presentation-only service actions show exact review and uncertain outcomes without approval or execution';
export const serviceActionDisplayDisclosure='Entirely invented intercepted authentication, inventory and action DTOs. Presentation only: no real login, permission, approval, action delivery, helper, service restart, host grant or native action acceptance. All identities and digests are fixed public fixture strings.';
let stage='setup';
export const serviceActionDisplayFailureStage=()=>stage;
const mark=value=>{stage=value;};
export function serviceActionDisplayFixtures(){
 const session={...actionSession,transport:'http',insecureTestMode:true,transportWarning:'unencrypted_lan_test'};
 const preview={...actionView(),preview:{...actionPreview(),transportProfile:'disposable-http-test'}};
 const ready=actionView(),complete=actionJobView('operation_completed'),unknown=actionJobView('needs_intervention');
 const stale={...actionView(),available:false,reason:'helper_stale',services:[]};
 const inventory=systemView(1,0);inventory.deviceId=actionDevice;inventory.serverNow=actionNow;inventory.receivedAt=actionNow;inventory.latest.collectedAt=actionNow;
 for(const section of ['services','sockets']){inventory.latest[section].observedAt=actionNow;inventory.lastComplete[section].meta.observedAt=actionNow;}
 const services=[{...serviceRows(1)[0],name:'fixture.service',runtime:{loadState:'loaded',activeState:'active',subState:'running'}}];
 const metric={value:null,unit:'%',quality:'unknown',source:'Public invented display fixture',collectedAt:actionNow};
 const device={id:actionDevice,name:'SYNTHETIC DISPLAY ONLY · service actions',platform:'linux',os:'Invented Linux display',site:'Fixture',group:'Fixture',ip:null,status:'unknown',source:'lan',synthetic:false,lastSeen:actionNow,agentVersion:'fixture',cpu:metric,memory:metric,disk:metric,uptime:'',tags:[],capabilities:[],evidence:[],trend:[],caseIds:[]};
 for(const value of [preview,ready,complete,unknown,stale])if(!validServiceActionView(value,actionDevice,actionActor,true))throw new Error('INVALID_DISPLAY_ACTION_FIXTURE');
 if(!validSystemView(inventory,actionDevice))throw new Error('INVALID_DISPLAY_INVENTORY_FIXTURE');
 return {session,preview,ready,complete,unknown,stale,inventory,services,device};
}

export function serviceActionDisplayRoute({base,fixture,state}){
 const prefix='/api/devices/'+actionDevice;
 return async route=>{
  const request=route.request(),url=new URL(request.url()),method=request.method();
  if(url.origin!==base){state.external.push('external-request');return route.abort('blockedbyclient');}
  if(/\/(?:approve|execute|dispatch|apply)(?:\/|$)/.test(url.pathname)){state.forbidden.push('blocked-action');return route.abort('blockedbyclient');}
  const fulfill=value=>route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(value)});
  // POST is the inventory query's read-only wire format. No data or authority
  // goes to the server, and only the exact in-memory fixture shape is accepted.
  if(method==='POST'&&url.pathname===prefix+'/inventory/system/query'){
   const raw=request.postData();let input;try{input=JSON.parse(raw??'null');}catch{state.forbidden.push('invalid-query');return route.abort('blockedbyclient');}
   if(!input||Object.keys(input).length!==6||input.generationId!==fixture.inventory.latest.generationId||input.section!=='services'||input.search!==''||input.cursor!==''||input.filter!=='all'||input.limit!==100){state.forbidden.push('nonfixture-query');return route.abort('blockedbyclient');}
   const result=systemPage(fixture.inventory,fixture.services,[],raw);
   if(!validSystemPage(result,actionDevice,'services',fixture.inventory.lastComplete.services,'','','all'))throw new Error('INVALID_DISPLAY_PAGE');
   state.inventoryReads++;return fulfill(result);
  }
  // Preview is also intercepted display data only, never an actual plan or job.
  if(method==='POST'&&url.pathname===prefix+'/service-actions/preview'&&state.phase==='ready'){
   if(request.postData()!==JSON.stringify({unit:'fixture.service'})){state.forbidden.push('nonfixture-preview');return route.abort('blockedbyclient');}
   state.previewReads++;return fulfill(fixture.preview);
  }
  if(method!=='GET'){state.forbidden.push('blocked-mutation');return route.abort('blockedbyclient');}
  if(url.pathname==='/api/auth/session')return fulfill(fixture.session);
  if(url.pathname==='/api/session')return fulfill({csrfToken:'synthetic-csrf'});
  if(url.pathname==='/api/overview')return fulfill({generatedAt:actionNow,devices:[fixture.device],cases:[],activity:[],stats:{totalDevices:1,healthyDevices:0,attentionDevices:0,unknownDevices:1,openCases:0,criticalCases:0}});
  if(url.pathname==='/api/investigations')return fulfill({schemaVersion:'tracebolt.investigations.v1',serverNow:actionNow,scope:'open',offset:0,total:0,counts:{open:0,recovered:0,closed:0,all:0},devices:[],items:[]});
  if(url.pathname===prefix)return fulfill(fixture.device);
  if(url.pathname===prefix+'/inventory/system')return fulfill(fixture.inventory);
  if(url.pathname===prefix+'/service-actions')return fulfill(fixture[state.phase]);
  if(url.pathname.startsWith('/api/'))return route.fulfill({status:503,contentType:'application/json',body:JSON.stringify({error:{code:'synthetic_display_unavailable',message:'No observation in this display fixture'}})});
  return route.continue();
 };
}

/** Reuse only the runner's browser and static production UI; never its login. */
export async function serviceActionDisplayBrowserCase({pageAt,expect,base,shot}){
 mark('setup');const page=await pageAt('/devices'),fixture=serviceActionDisplayFixtures();
 const state={forbidden:[],external:[],phase:'ready',previewReads:0,inventoryReads:0};
 await page.clock.install({time:new Date(actionNow)});await page.clock.pauseAt(new Date(Date.parse(actionNow)+100));
 await page.route('**/*',serviceActionDisplayRoute({base,fixture,state}));
 mark('fixture-document');await openServiceActionDisplay(page,base,actionDevice,mark);
 const panel=page.locator('.service-action-panel'),review=()=>page.locator('.service-action-review'),refresh=()=>panel.getByRole('button',{name:/^(Check action status|Aktionsstatus prüfen)$/});
 const capture=async (name,anchor=panel)=>{
  mark(name);await anchor.scrollIntoViewIfNeeded();
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1)).toBe(true);
  expect(await panel.evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);
  await expect(page.locator('input[type=password]')).toHaveCount(0);
  await shot(page,name,serviceActionDisplayDisclosure);
 };
 mark('unapproved-review');const select=page.getByRole('button',{name:'Preview try-restart: fixture.service',exact:true});await expect(select).toBeEnabled();await select.click();
 await expect(review()).toContainText('interrupt the service and its dependents');await expect(review()).toContainText('inactive services are not started');await expect(review()).toContainText('Disposable HTTP test');
 for(const value of [actionDevice,actionActor,'fixture.service','service.try-restart'])await expect(review()).toContainText(value);
 await expect(review().getByRole('checkbox')).not.toBeChecked();await expect(review().getByRole('button',{name:'Approve try-restart',exact:true})).toBeDisabled();
 await capture('synthetic-display-service-action-preview-desktop-en');
 await page.setViewportSize({width:390,height:844});await page.getByLabel('Language',{exact:true}).selectOption('de');await expect(review().getByRole('checkbox')).not.toBeChecked();await capture('synthetic-display-service-action-preview-mobile-de');await capture('synthetic-display-service-action-consent-mobile-de',page.locator('.service-action-consent'));
 await review().getByRole('button',{name:'Vorschau schließen',exact:true}).click();await expect(review()).toHaveCount(0);expect(state.previewReads).toBe(1);
 await page.getByLabel('Sprache',{exact:true}).selectOption('en');
 mark('agent-reported-result');state.phase='complete';await refresh().click();await expect(panel).toContainText('Restart and service health remain unconfirmed.');await expect(panel.getByRole('checkbox')).toHaveCount(0);await capture('synthetic-display-service-action-result-mobile-en');
 await page.setViewportSize({width:1440,height:1000});await capture('synthetic-display-service-action-result-desktop-en');
 mark('unknown-result');state.phase='unknown';await refresh().click();await expect(panel).toContainText('Outcome unknown.');await expect(select).toBeDisabled();await page.setViewportSize({width:390,height:844});await page.getByLabel('Language',{exact:true}).selectOption('de');await capture('synthetic-display-service-action-unknown-mobile-de');
 mark('stale-helper');state.phase='stale';await refresh().click();await expect(panel).toContainText('Der lokale Helper-Bericht ist veraltet.');await expect(panel.getByRole('checkbox')).toHaveCount(0);await capture('synthetic-display-service-action-stale-mobile-de');
 mark('final-no-action-guards');expect(state.previewReads).toBe(1);expect(state.inventoryReads).toBeGreaterThan(0);expect(state.forbidden).toEqual([]);expect(state.external).toEqual([]);expect(await page.context().cookies()).toEqual([]);
}
