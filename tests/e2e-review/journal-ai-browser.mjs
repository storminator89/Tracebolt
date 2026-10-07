/** Exact synthetic wire projections only. No native journal, real model or permission write. */
import fs from 'node:fs';
import {proactiveAIIdentityFixture} from './proactive-ai-browser.mjs';
export const journalAICaseName='Synthetic service-log AI requires independent capture/export scope and expires cited findings without real collection';
export const journalAIFixtureDisclosure='UI-only production rendering with real loopback HTTP-test login and CSRF reads; intercepted invented Go-generated service-log scope, policy, incident and cited-result DTOs. No journal collection, real provider request, key entry, persistent grant or host action. Native authorization, cancellation and rate bounds have separate Go tests.';
const stored=JSON.parse(fs.readFileSync(new URL('../../web/src/journal-ai-go-fixture.json',import.meta.url),'utf8'));
const stages=new Set(['setup','review','save','mobile','finding','expiry','guards']);let stage='setup';
export const journalAIFailureStage=()=>stage;
const mark=value=>{stage=stages.has(value)?value:'unknown';};
const clone=value=>structuredClone(value);
const requireFixture=value=>{if(!value)throw Error('Unsupported synthetic journal AI fixture request');};
const exact=(v,keys)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join(',')===[...keys].sort().join(',');
export function journalAIWireFixture(){return clone(stored);}
export function createJournalAIFixture(){
 let settings={...clone(stored.offSettings),plaintext:true},writes=0;
 const device=stored.source.deviceId,unit=stored.settings.targets[0].unit;
 return {get writes(){return writes;},get settings(){return clone(settings);},device,unit,handle(method,path,body){
  if(method==='GET'&&path==='/api/ai/journal'){requireFixture(body===null);return clone(settings);}
  if(method==='GET'&&path===`/api/ai/journal/source/${device}`){requireFixture(body===null);return clone(stored.source);}
  if(method==='POST'&&path==='/api/ai/journal'){
   requireFixture(exact(body,['dataScope','expectedRevision','configRevision','enabled','baseURL','model','targets','lookbackMinutes','acknowledgeCapture','acknowledgeExport','acknowledgePlaintext']));
   requireFixture(body.enabled===true&&body.dataScope==='service-journal-ai-v1'&&body.expectedRevision===settings.revision&&body.configRevision===settings.configRevision&&body.baseURL===settings.baseURL&&body.model===settings.model&&body.lookbackMinutes===5&&body.acknowledgeCapture===true&&body.acknowledgeExport===true&&body.acknowledgePlaintext===true);
   requireFixture(JSON.stringify(body.targets)===JSON.stringify([{deviceId:device,unit,generation:stored.source.generation.policyGeneration}]));
   settings={...clone(stored.settings),plaintext:true,revision:'fixture-journal-approved'};writes++;return {saved:true,revision:settings.revision,enabled:true,cancellationPending:false};
  }
  if(method==='GET'&&path.startsWith('/api/investigations?')){requireFixture(body===null&&new URLSearchParams(path.split('?')[1]).get('scope')==='open'&&new URLSearchParams(path.split('?')[1]).get('offset')==='0');return clone(stored.investigations);}
  if(method==='GET'&&path===`/api/ai/journal/${device}/${stored.result.result.packet.case.id}`){requireFixture(body===null);const result=clone(stored.result);result.serverNow=new Date(Date.parse(result.expiresAt)-2000).toISOString();return result;}
  throw Error('Unsupported synthetic journal AI fixture request');
 }};
}
export async function journalAIBrowserCase({pageAt,login,expect,base,shot}){
 mark('setup');const page=await pageAt('/settings'),start=Date.now();await page.clock.install({time:new Date(start)});await page.clock.pauseAt(new Date(start+1000));
 const fixture=createJournalAIFixture(),unexpected=[],external=[];let csrf='',sequence=0,consumed=0;
 await page.route('**/*',async route=>{const r=route.request(),u=new URL(r.url()),method=r.method();
  if(u.origin!==base){external.push('external');return route.abort('blockedbyclient');}
  if(u.pathname==='/api/session'&&method==='GET'){const response=await route.fetch();if(response.status()===200){const value=await response.json();if(typeof value.csrfToken==='string'){csrf=value.csrfToken;sequence++;}}return route.fulfill({response});}
  if(u.pathname==='/api/fleet/endpoint-identities'&&method==='GET'){const value=proactiveAIIdentityFixture();value.items[0].deviceId=fixture.device;return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(value)});}
  if(u.pathname.startsWith('/api/ai/journal')||u.pathname==='/api/investigations'){
   try {if(method==='GET')requireFixture(r.postData()===null);else{const headers=await r.allHeaders();requireFixture(method==='POST'&&headers['content-type']==='application/json'&&csrf!==''&&headers['x-csrf-token']===csrf&&sequence>consumed);consumed=sequence;}
    return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(fixture.handle(method,u.pathname+u.search,method==='GET'?null:r.postDataJSON()))});
   }catch{unexpected.push('invalid-journal-ai-fixture-request');return route.abort('blockedbyclient');}
  }
  if(method!=='GET'&&!(method==='POST'&&u.pathname==='/api/auth/login')){unexpected.push('unexpected-write');return route.abort('blockedbyclient');}
  return route.continue();
 });
 await login(page);const panel=page.locator('.journal-ai');await expect(panel.getByRole('button',{name:'Service-log AI',exact:true})).toHaveAttribute('aria-expanded','false');expect(fixture.writes).toBe(0);
 mark('review');await panel.getByRole('button',{name:'Service-log AI',exact:true}).click();await expect(panel).toContainText(fixture.settings.baseURL);await expect(panel).toContainText(fixture.settings.model);await panel.getByRole('button',{name:'Read local policy',exact:true}).click();await expect(panel.getByRole('button',{name:'Read local policy',exact:true})).toBeEnabled();await panel.getByRole('textbox',{name:'Service',exact:true}).fill(fixture.unit);await panel.getByRole('button',{name:'Add service',exact:true}).click();
 // Capture the actual pre-save German mobile review separately from saved state.
 const center=async element=>{await element.scrollIntoViewIfNeeded();await element.evaluate(el=>el.scrollIntoView({block:'center',inline:'nearest',behavior:'instant'}));};
 const mobileConsentFrame=async name=>{
  const labels=panel.locator('.proactive-ai-check');await expect(labels).toHaveCount(3);await center(labels.nth(1));
  for(let i=0;i<3;i++)await expect(labels.nth(i)).toBeInViewport({ratio:1});
  await expect(panel.getByRole('button',{name:'Dienstlog-KI freigeben und aktivieren',exact:true})).toBeInViewport({ratio:1});
  expect(fixture.writes).toBe(0);expect(fixture.settings.enabled).toBe(false);await shot(page,name,journalAIFixtureDisclosure);
 };
 await page.setViewportSize({width:390,height:844});await page.getByLabel('Language',{exact:true}).selectOption('de');
 const destination=panel.locator('.proactive-ai-destination'),scope=panel.locator('.proactive-ai-destination + p'),retention=panel.locator('.proactive-ai-destination + p + p');
 await center(scope);await expect(destination).toBeInViewport({ratio:1});await expect(scope).toBeInViewport({ratio:1});await expect(retention).toBeInViewport({ratio:1});
 await expect(destination).toContainText(fixture.settings.baseURL);await expect(destination).toContainText(fixture.settings.model);
 await shot(page,'synthetic-service-log-ai-scope-mobile-de',journalAIFixtureDisclosure);
 const mobileBoxes=panel.getByRole('checkbox');await expect(mobileBoxes).toHaveCount(3);for(let i=0;i<3;i++)await expect(mobileBoxes.nth(i)).not.toBeChecked();
 await expect(panel.getByRole('button',{name:'Dienstlog-KI freigeben und aktivieren',exact:true})).toBeDisabled();
 await mobileConsentFrame('synthetic-service-log-ai-consent-unchecked-mobile-de');
 await page.getByLabel('Sprache',{exact:true}).selectOption('en');await page.setViewportSize({width:1440,height:1000});
 const approve=panel.getByRole('button',{name:'Approve and enable service-log AI',exact:true}),boxes=panel.getByRole('checkbox');await expect(boxes).toHaveCount(3);for(let i=0;i<3;i++)await expect(boxes.nth(i)).not.toBeChecked();await expect(approve).toBeDisabled();await boxes.nth(0).check();await boxes.nth(1).check();await expect(approve).toBeDisabled();await boxes.nth(2).check();await expect(approve).toBeEnabled();await expect(panel).toContainText('credentials, personal data and secrets');await expect(panel).toContainText('at most 15 minutes');await panel.scrollIntoViewIfNeeded();await shot(page,'synthetic-service-log-ai-review-desktop-en',journalAIFixtureDisclosure);
 await page.setViewportSize({width:390,height:844});await page.getByLabel('Language',{exact:true}).selectOption('de');
 for(let i=0;i<3;i++)await expect(boxes.nth(i)).toBeChecked();await expect(panel.getByRole('button',{name:'Dienstlog-KI freigeben und aktivieren',exact:true})).toBeEnabled();
 await mobileConsentFrame('synthetic-service-log-ai-consent-checked-mobile-de');
 await page.getByLabel('Sprache',{exact:true}).selectOption('en');await page.setViewportSize({width:1440,height:1000});
 mark('save');await approve.click();await expect(panel).toContainText('Approval saved. No capture or provider test was sent.');expect(fixture.writes).toBe(1);for(let i=0;i<3;i++)await expect(boxes.nth(i)).not.toBeChecked();
 mark('mobile');await page.setViewportSize({width:390,height:844});await page.getByLabel('Language',{exact:true}).selectOption('de');await expect(panel).toContainText('Zugangsdaten, personenbezogene Daten und Geheimnisse');expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth&&document.body.scrollWidth<=innerWidth)).toBe(true);await shot(page,'synthetic-service-log-ai-saved-mobile-de',journalAIFixtureDisclosure);await page.getByLabel('Sprache',{exact:true}).selectOption('en');
 mark('finding');await page.evaluate(()=>{location.hash='/cases';});const item=page.locator('.investigation-item').filter({hasText:fixture.unit}).first();await item.locator('summary').filter({hasText:'Service-log AI:'}).click();await expect(item).toContainText('Unconfirmed hypotheses. Human review required.');await item.getByText('Sources, counterevidence & gaps',{exact:true}).click();await expect(item).toContainText('journal-window');await expect(item).toContainText('journal-row-');await shot(page,'synthetic-service-log-ai-finding-mobile-en',journalAIFixtureDisclosure);
 mark('expiry');await page.clock.runFor(2250);await expect(item).toContainText('Finding expired.');await expect(item.getByText('Sources, counterevidence & gaps',{exact:true})).toHaveCount(0);
 mark('guards');expect(fixture.writes).toBe(1);expect(unexpected).toEqual([]);expect(external).toEqual([]);const storage=await page.evaluate(()=>JSON.stringify({local:{...localStorage},session:{...sessionStorage}}));expect(storage.includes('journal-row-')||storage.includes('synthetic-log-secret')).toBe(false);
}
