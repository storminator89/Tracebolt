/** UI-only fixture: real loopback login/CSRF, exact intercepted settings and
 * persisted-result DTOs. No provider, collector, log export or configuration write. */
import fs from 'node:fs';
export const proactiveAICaseName='Synthetic proactive AI setup requires scoped approval and reads durable unconfirmed results without running a provider';
export const proactiveAIFixtureDisclosure='Rendered production UI with real loopback HTTP-test login and CSRF reads; exact intercepted invented proactive settings, already-collected display-only hostname/interface metadata and synthetic Go-generated persisted analysis DTOs. UI-only evidence; real scheduling, authorization and persistence are tested separately in Go. No real provider call, log collection/export, settings persistence, permission grant or native host operation.';
const stored=JSON.parse(fs.readFileSync(new URL('../../web/src/proactive-ai-go-fixture.json',import.meta.url),'utf8'));
export const proactiveAIFixtureDevice=stored.items[0].deviceId;
export const proactiveAIFixtureHostname='fixture-observer-01';
export const proactiveAIFixtureAddresses=['10.12.34.56','fe80::1234'];
/** Already-collected synthetic metadata for display only, never a collection request. */
export function proactiveAIIdentityFixture(status='fresh'){
 requireFixture(['fresh','stale','not_collected'].includes(status));
 const now=Date.parse(stored.serverNow),at=now-(status==='stale'?180000:1000);
 const serverNow=new Date(now).toISOString(),collectedAt=new Date(at).toISOString();
 const item={schemaVersion:'tracebolt.endpoint-identity-view.v1',deviceId:proactiveAIFixtureDevice,status,serverNow,maxAgeSeconds:120,sequence:null,receivedAt:null,expiresAt:null,latest:null};
 if(status!=='not_collected'){
  const complete=n=>({coverage:'complete',reason:'none',observedCount:n,countExact:true});
  item.sequence='1';item.receivedAt=new Date(at+100).toISOString();item.expiresAt=new Date(at+86400000).toISOString();
  item.latest={schemaVersion:'tracebolt.endpoint-identity.v1',generationId:'sample_'+('c'.repeat(32)),collectedAt,durationMs:1,scope:'agent-visible-linux-hostname-and-interface-addresses',reportedHostname:{coverage:'complete',reason:'none',value:proactiveAIFixtureHostname},interfaces:{meta:complete(1),items:[{index:2,name:'eth0',up:true,loopback:false,hardwareKind:'unknown',addresses:{ipv4:{meta:complete(1),items:[{family:'ipv4',address:proactiveAIFixtureAddresses[0],scope:'private'}]},ipv6:{meta:complete(1),items:[{family:'ipv6',address:proactiveAIFixtureAddresses[1],scope:'link-local'}]}}}]}};
 }
 return {schemaVersion:'tracebolt.fleet-endpoint-identity.v1',serverNow,items:[item]};
}
const stages=new Set(['setup','initial','review','close','save','uncertain','refresh','mobile-en','mobile-de','persisted-desktop','persisted-mobile','result-desktop','result-mobile','history','final-guards']);
let stage='setup';
export const proactiveAIFailureStage=()=>stage;
const mark=value=>{stage=stages.has(value)?value:'unknown';};
const exact=(value,keys)=>!!value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join(',')===[...keys].sort().join(',');
function requireFixture(condition){if(!condition)throw new Error('Unsupported synthetic proactive AI fixture request');}
export function proactiveAIResultFixture(){return structuredClone(stored);}

/** Deterministic local receiver model; never invokes provider or real settings. */
export function createProactiveAIFixture(){
 let current={schemaVersion:'tracebolt.proactive-ai-settings.v1',revision:'fixture-proactive-a',enabled:false,configRevision:'fixture-provider-a',providerConfigured:true,baseURL:'http://127.0.0.1:11434/v1',model:'fixture-model',deviceIds:[],availableDevices:[{id:proactiveAIFixtureDevice}],dataScope:'health-summary-v1',logsAllowed:false,resetsOnRestart:true,maxAnalysesPerHour:6,cooldownMinutes:30,minIntervalSeconds:60,reason:'disabled'};
 const counts={settingsReads:0,settingsWrites:0,resultReads:0,identityReads:0};
 const settings=()=>structuredClone(current);
 const provider=()=>({revision:current.configRevision,configured:true,provider:'openai-compatible',baseURL:current.baseURL,endpointOrigin:'http://127.0.0.1:11434',model:current.model,keyConfigured:false,useLegacyMaxTokens:false,allowRemoteEvidence:false,storage:current.resetsOnRestart?'memory-only':'protected-file',persistenceAvailable:true,persistentKeyAllowed:false,resetsOnRestart:current.resetsOnRestart,busy:false,limitations:[]});
 const handle=(method,pathname,data)=>{
  if(method==='GET'&&pathname==='/api/ai/proactive'){requireFixture(data===null);counts.settingsReads++;return settings();}
  if(method==='GET'&&pathname==='/api/fleet/endpoint-identities'){requireFixture(data===null);counts.identityReads++;return proactiveAIIdentityFixture();}
  if(method==='GET'&&pathname==='/api/ai/config'){requireFixture(data===null);return provider();}
  if(method==='GET'&&pathname==='/api/investigations?scope=open&offset=0'){requireFixture(data===null);counts.resultReads++;return proactiveAIResultFixture();}
  if(method==='POST'&&pathname==='/api/ai/proactive'){
   requireFixture(exact(data,['expectedRevision','configRevision','enabled','deviceIds','approvedBaseURL','approvedModel','dataScope','acknowledgeData'])&&data.expectedRevision===current.revision&&data.configRevision===current.configRevision&&data.approvedBaseURL===current.baseURL&&data.approvedModel===current.model&&data.dataScope==='health-summary-v1');
   requireFixture(data.enabled===true&&data.acknowledgeData===true&&Array.isArray(data.deviceIds)&&data.deviceIds.length===1&&data.deviceIds[0]===proactiveAIFixtureDevice);
   current={...current,revision:'fixture-proactive-b',enabled:true,deviceIds:[proactiveAIFixtureDevice],reason:'enabled'};counts.settingsWrites++;return settings();
  }
  requireFixture(false);
 };
 // Replace only the invented GET view; this is not a provider save or migration.
 const loadPersistedReadFixture=()=>{current={...current,revision:'fixture-persisted-scope',configRevision:'fixture-persisted-provider',enabled:true,deviceIds:[proactiveAIFixtureDevice],resetsOnRestart:false,reason:'enabled'};};
 return {settings,provider,counts,handle,loadPersistedReadFixture};
}

async function layout(page,panel,expect){
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1&&document.body.scrollWidth<=innerWidth+1)).toBe(true);
 expect(await panel.evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);
 for(const element of await panel.locator('h2,button,label,dd,p,li').all()){
  if(!await element.isVisible())continue;
  const box=await element.boundingBox();expect(box).not.toBe(null);expect(box.x).toBeGreaterThanOrEqual(0);expect(box.x+box.width).toBeLessThanOrEqual(page.viewportSize().width+1);
 }
}

/** Exactly one additive case using the existing hosted browser/login lifecycle. */
export async function proactiveAIBrowserCase({pageAt,login,expect,base,shot}){
 mark('setup');const page=await pageAt('/settings'),clockStart=Date.now();
 await page.clock.install({time:new Date(clockStart)});await page.clock.pauseAt(new Date(clockStart+1000));
 const fixture=createProactiveAIFixture(),unexpected=[],external=[];
 let csrf='',sessionSequence=0,consumedSession=0,holdWrite=false,releaseWrite=null,namedReadOnly=false;
 const gate=new Promise(resolve=>{releaseWrite=resolve;});
 const json=(route,value)=>route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(value)});
 await page.route('**/*',async route=>{
  const request=route.request(),url=new URL(request.url()),method=request.method();
  if(url.origin!==base){external.push('external-request');return route.abort('blockedbyclient');}
  if(namedReadOnly&&url.pathname==='/api/auth/session'&&method==='GET'){
   const response=await route.fetch(),session=await response.json();requireFixture(session.authenticated===true);
   return route.fulfill({response,json:{...session,loginMode:'named',actorId:'operator_'+ '1'.repeat(32),capabilities:['read']}});
  }
  if(url.pathname==='/api/session'&&method==='GET'){
   const response=await route.fetch();
   if(response.status()===200){const body=await response.json();if(typeof body.csrfToken==='string'){csrf=body.csrfToken;sessionSequence++;}}
   return route.fulfill({response});
  }
  if(url.pathname.startsWith('/api/ai/')||url.pathname==='/api/investigations'||url.pathname==='/api/fleet/endpoint-identities'){
   try{
    if(method==='GET')requireFixture(request.postData()===null);
    else{const headers=await request.allHeaders();requireFixture(method==='POST'&&headers['content-type']==='application/json'&&csrf!==''&&headers['x-csrf-token']===csrf&&sessionSequence>consumedSession);consumedSession=sessionSequence;}
    const body=fixture.handle(method,url.pathname+url.search,method==='GET'?null:request.postDataJSON());
    if(method==='POST'&&holdWrite){await gate;try{return await json(route,body);}catch{return;}}
    return json(route,body);
   }catch{unexpected.push('invalid-ai-fixture-request');return route.abort('blockedbyclient');}
  }
  if(method!=='GET'&&!(method==='POST'&&url.pathname==='/api/auth/login')){unexpected.push('unexpected-mutation');return route.abort('blockedbyclient');}
  return route.continue();
 });
 const panel=page.locator('.proactive-ai');
 const toggle=()=>panel.getByRole('button',{name:/^(Proactive AI diagnostics|Proaktive KI-Diagnostik)$/});
 const consent=()=>panel.getByRole('checkbox',{name:/^(I approve future health-summary|Ich erlaube künftige Health-Zusammenfassungsanalysen)/});
 const approve=()=>panel.getByRole('button',{name:'Approve and enable',exact:true});
 const choose=async()=>{await panel.getByRole('checkbox',{name:new RegExp(proactiveAIFixtureHostname)}).check();await consent().check();};
 const capture=async(name,target=panel)=>{await layout(page,target,expect);await target.scrollIntoViewIfNeeded();await expect(page.getByLabel('Operator password',{exact:true})).toHaveCount(0);await shot(page,name,proactiveAIFixtureDisclosure);};
 try {
 await expect(page.getByRole('heading',{name:'Sign in',exact:true})).toBeVisible();expect(fixture.counts.settingsReads).toBe(0);await login(page);
 mark('initial');await expect(panel).toContainText('Off');await expect(toggle()).toHaveAttribute('aria-expanded','false');await expect(panel.locator('input,form')).toHaveCount(0);expect(fixture.counts.settingsWrites).toBe(0);
 expect(await panel.evaluate(el=>el.previousElementSibling?.classList.contains('ai-settings-panel'))).toBe(true);
 await capture('synthetic-http-test-proactive-ai-collapsed-desktop-en');
 mark('review');await toggle().click();await expect(panel).toContainText(fixture.settings().baseURL);await expect(panel).toContainText('fixture-model');await expect(panel).toContainText(proactiveAIFixtureHostname);for(const address of proactiveAIFixtureAddresses)await expect(panel).toContainText(address);await expect(panel).toContainText('eth0');await expect(approve()).toBeDisabled();await expect(consent()).toBeDisabled();
 await panel.getByRole('checkbox',{name:new RegExp(proactiveAIFixtureHostname)}).check();await expect(approve()).toBeDisabled();await consent().check();await expect(approve()).toBeEnabled();await expect(panel.locator('.proactive-ai-caveat')).toContainText('Provider charges may apply. Even local endpoints can forward data; masking is not guaranteed.');await expect(panel.locator('.proactive-ai-caveat')).toBeVisible();
 const details=panel.locator('.proactive-ai-details');expect(await details.evaluate(el=>el.hasAttribute('open'))).toBe(false);await expect(panel).toContainText('No raw logs, device names, IP addresses or free-form notes.');await expect(panel.getByRole('checkbox',{name:/Include raw logs/})).toHaveCount(0);
 await details.locator('summary').click();await expect(details).toHaveAttribute('open','');await expect(details).toContainText('This health-summary scope excludes logs. Service-log AI below needs separate local and provider approval.');await expect(details).toContainText('24 KiB');await expect(details).toContainText('1,024 tokens');await details.locator('summary').click();expect(await details.evaluate(el=>el.hasAttribute('open'))).toBe(false);
 expect(await panel.evaluate(el=>!!(el.querySelector('.proactive-ai-consent')?.compareDocumentPosition(el.querySelector('.proactive-ai-details'))&Node.DOCUMENT_POSITION_FOLLOWING))).toBe(true);
 await capture('synthetic-http-test-proactive-ai-review-desktop-en');
 mark('close');await panel.getByRole('button',{name:'Close',exact:true}).click();await expect(toggle()).toHaveAttribute('aria-expanded','false');expect(fixture.counts.settingsWrites).toBe(0);await toggle().click();await expect(consent()).not.toBeChecked();await choose();
 mark('save');holdWrite=true;await approve().evaluate(button=>{button.click();button.click();});await expect.poll(()=>fixture.counts.settingsWrites).toBe(1);await expect(panel).toContainText('Saving settings…');
 mark('uncertain');await panel.getByRole('button',{name:'Close',exact:true}).click();await expect(panel).toContainText('may already have taken effect');releaseWrite();holdWrite=false;await expect(toggle()).toHaveAttribute('aria-expanded','false');expect(fixture.counts.settingsWrites).toBe(1);
 mark('refresh');await panel.getByRole('button',{name:'Refresh proactive AI settings',exact:true}).click();await expect(panel.locator('.proactive-ai-heading>span')).toHaveText('On');await toggle().click();await expect(consent()).not.toBeChecked();await expect(panel.getByRole('button',{name:'Approve updated scope',exact:true})).toBeDisabled();
 await page.setViewportSize({width:390,height:844});mark('mobile-en');await capture('synthetic-http-test-proactive-ai-enabled-mobile-en');
 await page.getByLabel('Language',{exact:true}).selectOption('de');mark('mobile-de');await expect(panel).toContainText('Keine Rohlogs, Gerätenamen, IP-Adressen oder Freitextnotizen.');await expect(panel.getByRole('checkbox',{name:/Rohlogs einschließen/})).toHaveCount(0);expect(await panel.locator('.proactive-ai-details').evaluate(el=>el.hasAttribute('open'))).toBe(false);await capture('synthetic-http-test-proactive-ai-enabled-mobile-de');await details.locator('summary').click();await expect(details).toHaveAttribute('open','');await capture('synthetic-http-test-proactive-ai-details-mobile-de',details);await details.locator('summary').click();await page.getByLabel('Sprache',{exact:true}).selectOption('en');
 mark('persisted-desktop');fixture.loadPersistedReadFixture();await page.setViewportSize({width:1440,height:1000});await page.reload();await expect(toggle()).toHaveAttribute('aria-expanded','false');await toggle().click();await expect(consent()).toHaveAccessibleName(/including after manager restart/);await expect(consent()).not.toBeChecked();await expect(panel.locator('.proactive-ai-restart')).toContainText('restart');await expect(panel).not.toContainText('Approval resets to off');
 const providerPanel=page.locator('.ai-settings-panel');await expect(providerPanel).toContainText('Saved on this manager');await expect(providerPanel).not.toContainText('For this manager session only');await expect(providerPanel.getByRole('checkbox',{name:'Keep provider configuration on this manager after restart',exact:true})).not.toBeChecked();await expect(providerPanel.getByLabel('AI API key',{exact:true})).toHaveValue('');await capture('synthetic-http-test-proactive-ai-persisted-desktop-en',providerPanel);await layout(page,panel,expect);
 mark('persisted-mobile');await page.setViewportSize({width:390,height:844});await page.getByLabel('Language',{exact:true}).selectOption('de');await expect(consent()).toHaveAccessibleName(/auch nach einem Manager-Neustart/);await expect(panel).not.toContainText('Nach Manager-Neustart oder Anbieteränderung wird');await capture('synthetic-http-test-proactive-ai-persisted-mobile-de');await layout(page,providerPanel,expect);await page.getByLabel('Sprache',{exact:true}).selectOption('en');
 mark('result-desktop');await page.setViewportSize({width:1440,height:1000});await page.evaluate(()=>{location.hash='/cases';});const item=page.locator('.investigation-item');await expect(item).toContainText('AI suggestions saved');await item.getByText('AI analysis & sources',{exact:true}).click();await expect(item).toContainText('Unconfirmed hypotheses.');await expect(item).toContainText('Unconfirmed hypotheses');await expect(item).toContainText('Next checks · read-only');await expect(item).toContainText('health-event');await expect(item).toContainText('health-snapshot');await expect(item.locator(`time[datetime="${stored.items[0].analysis.result.packet.evidence[0].collectedAt}"]`).first()).toBeVisible();await expect(item.getByRole('button',{name:/Analyze|Run|Restart/})).toHaveCount(0);
 await capture('synthetic-http-test-proactive-ai-result-desktop-en',item);mark('result-mobile');await page.setViewportSize({width:390,height:844});await capture('synthetic-http-test-proactive-ai-result-mobile-en',item);
 mark('history');const original=stored.items[0].analysis.result.id,before=fixture.counts.resultReads;await page.goBack();await expect(toggle()).toHaveAttribute('aria-expanded','false');await page.goForward();await expect(item).toContainText('AI suggestions saved');await page.reload();await expect(item).toContainText('AI suggestions saved');expect(fixture.counts.resultReads).toBeGreaterThan(before);expect(proactiveAIResultFixture().items[0].analysis.result.id).toBe(original);
 await page.evaluate(()=>{location.hash='/settings';});namedReadOnly=true;await page.reload();await toggle().click();await expect(panel).toContainText('Named accounts can read only.');await expect(panel.getByRole('button',{name:/Approve|Disable proactive/})).toHaveCount(0);await expect(panel.getByRole('checkbox').first()).toBeDisabled();await capture('synthetic-http-test-proactive-ai-readonly-mobile-en');
 mark('final-guards');expect(fixture.counts.settingsWrites).toBe(1);expect(fixture.counts.identityReads).toBeGreaterThan(0);expect(unexpected).toEqual([]);expect(external).toEqual([]);expect(await page.evaluate(values=>values.some(value=>JSON.stringify({...localStorage,...sessionStorage}).includes(value)),[proactiveAIFixtureDevice,proactiveAIFixtureHostname,...proactiveAIFixtureAddresses,fixture.settings().baseURL])).toBe(false);
 } finally { releaseWrite(); }
}
