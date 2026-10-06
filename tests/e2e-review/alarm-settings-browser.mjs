import {createAlarmBrowserDiagnostics} from './alarm-browser-diagnostics.mjs';
const diagnostics=createAlarmBrowserDiagnostics();
export const alarmSettingsFailureDetails=()=>diagnostics.details();
import {validAlarmSettings} from '../../web/src/alarm-settings-types.ts';
import {validAlarmStatus} from '../../web/src/alarm-status-types.ts';

export const alarmSettingsCaseName='Synthetic alarm setup renders explicit configuration and test consent with intercepted fake sender states';
export const alarmSettingsFixtureDisclosure='Rendered production UI with real loopback HTTP-test fixture login and exact same-origin intercepted invented alarm settings/status/test APIs and fake sender states. No real alarm configuration, provider request or test delivery; actual backend behavior is tested separately. Provider acceptance is not human receipt.';
export const alarmSettingsFixtureEndpoint='https://alarm-fixture.example.test/write-only-fixture?key=NOT_A_REAL_SECRET';
const fixtureHost='alarm-fixture.example.test',fixtureEvent='c'.repeat(64);
const exact=(value,keys)=>!!value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join(',')===[...keys].sort().join(',');
function requireFixture(condition){if(!condition)throw new Error('Unsupported synthetic alarm fixture request');}

/** A deterministic in-memory receiver model only; never invokes a sender or API. */
export function createAlarmSettingsFixture(createdAt='2026-10-06T12:00:00Z') {
 let current={schemaVersion:'tracebolt.alarm-settings.v1',mode:'managed',revision:'a'.repeat(32),configured:false,enabled:false,destinationHost:'',test:null,blocked:false};
 const counts={settingsReads:0,statusReads:0,settingsWrites:0,testWrites:0};
 const settings=()=>{requireFixture(validAlarmSettings(current));return structuredClone(current);};
 const status=()=>{
  const view={schemaVersion:'tracebolt.alarm-status.v1',enabled:current.enabled,queued:0,inFlight:0,providerAccepted:0,failed:0,uncertain:0,suppressed:0,dropped:0};
  if(current.test){const key={queued:'queued',in_flight:'inFlight',provider_accepted:'providerAccepted',failed:'failed',uncertain:'uncertain',suppressed:'suppressed'}[current.test.state];view[key]=1;}
  requireFixture(validAlarmStatus(view));return view;
 };
 const setTestState=state=>{requireFixture(current.test!==null&&['queued','in_flight','provider_accepted','failed','uncertain','suppressed'].includes(state));current={...current,test:{...current.test,state}};return settings();};
 const handle=(method,pathname,data)=>{
  if(method==='GET'&&pathname==='/api/alerts/settings'){requireFixture(data===null);counts.settingsReads++;return settings();}
  if(method==='GET'&&pathname==='/api/alerts/status'){requireFixture(data===null);counts.statusReads++;return status();}
  if(method==='POST'&&pathname==='/api/alerts/settings'){
   requireFixture(exact(data,['expectedRevision','operation','endpoint','payloadSharingAcknowledged','plaintextAcknowledged'])&&data.expectedRevision===current.revision);
   if(data.operation==='replace'){
    requireFixture(!current.configured&&data.endpoint===alarmSettingsFixtureEndpoint&&data.payloadSharingAcknowledged===true&&data.plaintextAcknowledged===true);
    current={...current,revision:'b'.repeat(32),configured:true,enabled:true,destinationHost:fixtureHost};
   }else{
    requireFixture(data.operation==='disable'&&current.configured&&current.enabled&&data.endpoint===''&&data.payloadSharingAcknowledged===false&&data.plaintextAcknowledged===false);
    current={...current,revision:'d'.repeat(32),enabled:false};
   }
   counts.settingsWrites++;return settings();
  }
  if(method==='POST'&&pathname==='/api/alerts/test'){
   requireFixture(exact(data,['expectedRevision','requestId','testAcknowledged'])&&current.configured&&current.enabled&&current.test===null&&data.expectedRevision===current.revision&&typeof data.requestId==='string'&&/^[0-9a-f]{32}$/.test(data.requestId)&&data.testAcknowledged===true);
   current={...current,test:{eventId:fixtureEvent,state:'queued',createdAt}};requireFixture(validAlarmSettings(current));counts.testWrites++;return settings();
  }
  requireFixture(false);
 };
 return {counts,settings,status,setTestState,handle};
}

async function alarmSettingsLayout({page,panel,expect}) {
 diagnostics.step('document-width');
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth&&document.body.scrollWidth<=innerWidth)).toBe(true);
 diagnostics.track(panel,-1);diagnostics.step('panel-width');
 expect(await panel.evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);
 let ordinal=0;
 for(const element of await panel.locator('h2,.alarm-settings-readback,button,input,label,time,dt,dd,p').all()){
  diagnostics.track(element,ordinal++);diagnostics.step('visibility');
  if(!await element.isVisible())continue;
  diagnostics.step('scroll-stability');await element.scrollIntoViewIfNeeded();
  // Nearest scrolling can round a subpixel bottom edge outside the viewport.
  // Center the measured target, then retain the full visibility assertion.
  diagnostics.step('scroll-center');await element.evaluate(el=>el.scrollIntoView({block:'center',inline:'nearest',behavior:'instant'}));
  diagnostics.step('viewport-ratio');await expect(element).toBeInViewport({ratio:1});
  diagnostics.step('bounding-box');const box=await element.boundingBox();expect(box).not.toBe(null);diagnostics.step('horizontal-bounds');expect(box.x).toBeGreaterThanOrEqual(0);expect(box.x+box.width).toBeLessThanOrEqual(page.viewportSize().width+1);
  diagnostics.step('element-width');expect(await element.evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);
 }
}

/** Reuses the repository's browser, fixture login, context, and screenshot runner. */
export async function alarmSettingsBrowserCase({pageAt,login,expect,base,shot}) {
 diagnostics.reset();diagnostics.mark('setup-bootstrap');
 const page=await pageAt('/settings'),clockStart=Date.now();
 await page.clock.install({time:new Date(clockStart)});await page.clock.pauseAt(new Date(clockStart+10000));
 const fixture=createAlarmSettingsFixture(new Date(clockStart+10000).toISOString()),requests=[],unexpected=[],external=[];
 const alarmPaths=new Set(['/api/alerts/settings','/api/alerts/test','/api/alerts/status']);
 // Every alarm request is intercepted. No mutation can reach a real alarm handler.
 await page.route('**/*',async route=>{
  const request=route.request(),url=new URL(request.url()),method=request.method();
  if(url.origin!==base){external.push(url.origin);return route.abort('blockedbyclient');}
  if(!['GET','POST'].includes(method)){unexpected.push(`${method} ${url.pathname}`);return route.abort('blockedbyclient');}
  if(url.pathname.startsWith('/api/alerts')){
   if(!alarmPaths.has(url.pathname)||url.search){unexpected.push('Unexpected alarm route');return route.abort('blockedbyclient');}
   requests.push(`${method} ${url.pathname}`);
   try{
    const data=method==='GET'?null:request.postDataJSON();
    if(method==='GET')requireFixture(request.postData()===null);
    else{const headers=await request.allHeaders();requireFixture(headers['content-type']==='application/json'&&typeof headers['x-csrf-token']==='string'&&headers['x-csrf-token'].length>0);}
    const body=fixture.handle(method,url.pathname,data);
    return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(body)});
   }catch{unexpected.push('Invalid synthetic alarm request');return route.abort('blockedbyclient');}
  }
  if(method==='POST'&&url.pathname!=='/api/auth/login'){unexpected.push(`Unexpected POST ${url.pathname}`);return route.abort('blockedbyclient');}
  return route.continue();
 });
 const panel=page.locator('.alarm-settings'),aggregate=page.locator('.alarm-status');
 diagnostics.reset(panel);diagnostics.mark('setup-bootstrap');
 const toggle=()=>panel.getByRole('button',{name:/^(Alarm setup|Alarme einrichten)$/});
 const refresh=()=>panel.getByRole('button',{name:/^(Refresh alarm setup|Alarmeinrichtung aktualisieren)$/});
 const field=()=>panel.locator('input[type=password]');
 const open=async()=>{await toggle().click();await expect(toggle()).toHaveAttribute('aria-expanded','true');};
 const chooseReplace=async()=>{await panel.getByRole('button',{name:/^(Add destination|Replace destination|Ziel hinzufügen|Ziel ersetzen)$/}).click();await expect(field()).toHaveValue('');};
 const acknowledge=async()=>{
  await panel.getByRole('checkbox',{name:/^(I allow future alarm payloads|Ich erlaube die Weitergabe)/}).check();
  await panel.getByRole('checkbox',{name:/^(I understand this isolated HTTP-test|Ich verstehe, dass diese isolierte HTTP-Testverbindung)/}).check();
 };
 const noReadback=async()=>{
  await expect(panel).not.toContainText(alarmSettingsFixtureEndpoint);await expect(panel).not.toContainText('NOT_A_REAL_SECRET');
  expect((await page.content()).includes(alarmSettingsFixtureEndpoint)).toBe(false);
  expect(await page.evaluate(()=>JSON.stringify({local:{...localStorage},session:{...sessionStorage}}).includes('NOT_A_REAL_SECRET'))).toBe(false);
 };
 const reload=async()=>{const before=fixture.counts.settingsReads;await refresh().click();await expect.poll(()=>fixture.counts.settingsReads).toBe(before+1);await expect(refresh()).toBeEnabled();};
 const refreshAggregate=async()=>{
  diagnostics.step('aggregate-refresh');
  await expect(aggregate.getByRole('button',{name:/^(Refresh alarm status|Alarmstatus aktualisieren)$/})).toBeEnabled();
  const before=fixture.counts.statusReads;
  await aggregate.getByRole('button',{name:/^(Refresh alarm status|Alarmstatus aktualisieren)$/}).click();
  await expect.poll(()=>fixture.counts.statusReads).toBe(before+1);
  await expect(aggregate.getByRole('button',{name:/^(Refresh alarm status|Alarmstatus aktualisieren)$/})).toBeEnabled();
  const german=await page.locator('html').getAttribute('lang')==='de',state=fixture.status();
  await expect(aggregate.locator('.alarm-mode')).toHaveText(state.enabled?(german?'Ein':'On'):(german?'Aus':'Off'));
  if(state.enabled||state.queued+state.inFlight+state.providerAccepted+state.failed+state.uncertain+state.suppressed>0)await expect(aggregate.locator('.alarm-counts dd')).toHaveText([state.providerAccepted,state.queued+state.inFlight,state.failed,state.uncertain].map(String));
  else await expect(aggregate.locator('.alarm-counts')).toHaveCount(0);
 };
 const capture=async(name)=>{diagnostics.mark(name.replace('synthetic-http-test-alarm-',''));await refreshAggregate();await alarmSettingsLayout({page,panel,expect});diagnostics.step('capture');diagnostics.track(panel,-1);diagnostics.step('capture');await panel.scrollIntoViewIfNeeded();await shot(page,name,alarmSettingsFixtureDisclosure);};
 await expect(page.getByRole('heading',{name:'Sign in',exact:true})).toBeVisible();expect(fixture.counts.settingsReads).toBe(0);await login(page);
 diagnostics.mark('setup-initial');
 await expect(panel).toBeVisible();await expect(panel.locator('.alarm-settings-readback')).toHaveText('No destination');await expect(toggle()).toHaveAttribute('aria-expanded','false');
 expect(fixture.counts.settingsReads).toBe(1);await expect(panel.locator('input,form')).toHaveCount(0);
 await capture('synthetic-http-test-alarm-setup-collapsed-desktop-en');
 await open();await chooseReplace();await expect(field()).toHaveAttribute('type','password');await expect(field()).toHaveAttribute('autocomplete','off');
 await field().fill(alarmSettingsFixtureEndpoint);await panel.getByRole('checkbox',{name:/^I allow future alarm payloads/}).check();
 await expect(panel.getByRole('button',{name:'Save and enable',exact:true})).toBeDisabled();await expect(panel).toContainText('isolated HTTP-test connection exposes the webhook URL');
 await panel.getByRole('checkbox',{name:/^I understand this isolated HTTP-test/}).check();await expect(panel.getByRole('button',{name:'Save and enable',exact:true})).toBeEnabled();
 await capture('synthetic-http-test-alarm-setup-form-desktop-en');
 diagnostics.mark('setup-cancel');
 await panel.getByRole('button',{name:'Cancel',exact:true}).click();await expect(panel.locator('input')).toHaveCount(0);expect(fixture.counts.settingsWrites).toBe(0);expect(fixture.counts.testWrites).toBe(0);await noReadback();
 diagnostics.mark('setup-escape');
 await chooseReplace();await expect(panel.getByRole('checkbox').first()).not.toBeChecked();await field().fill(alarmSettingsFixtureEndpoint);await acknowledge();await field().press('Escape');
 await expect(toggle()).toHaveAttribute('aria-expanded','false');await expect(toggle()).toBeFocused();await expect(panel.locator('input')).toHaveCount(0);expect(fixture.counts.settingsWrites).toBe(0);await noReadback();
 await open();await chooseReplace();await expect(panel.getByRole('checkbox').first()).not.toBeChecked();await field().fill(alarmSettingsFixtureEndpoint);await acknowledge();
 diagnostics.mark('setup-save');
 await panel.getByRole('button',{name:'Save and enable',exact:true}).click();await expect(panel.locator('.alarm-settings-readback')).toHaveText(`${fixtureHost} · On`);
 expect(fixture.counts.settingsWrites).toBe(1);expect(fixture.settings().revision).toBe('b'.repeat(32));expect(fixture.counts.testWrites).toBe(0);await expect(panel).toContainText('Settings saved. No test was sent.');await noReadback();
 diagnostics.mark('setup-test-consent');
 await panel.getByRole('button',{name:'Test destination',exact:true}).click();await expect(panel).toContainText('fixed synthetic test payload');await expect(panel).toContainText('no live device information');
 await expect(panel.getByRole('button',{name:'Confirm and send test',exact:true})).toBeDisabled();expect(fixture.counts.testWrites).toBe(0);
 await panel.getByRole('checkbox',{name:'Send this synthetic test to the saved destination now.',exact:true}).check();expect(fixture.counts.testWrites).toBe(0);
 diagnostics.mark('setup-test-send');
 await panel.getByRole('button',{name:'Confirm and send test',exact:true}).click();await expect(panel.locator('.alarm-test-result dd').first()).toHaveText('Queued');
 expect(fixture.counts.testWrites).toBe(1);await expect(panel.getByRole('button',{name:'Test destination',exact:true})).toBeDisabled();await noReadback();
 await capture('synthetic-http-test-alarm-setup-test-queued-desktop-en');
 diagnostics.mark('setup-accepted-refresh');
 fixture.setTestState('provider_accepted');await expect(panel.locator('.alarm-test-result dd').first()).toHaveText('Queued');await reload();await expect(panel.locator('.alarm-test-result dd').first()).toHaveText('Provider accepted');
 await expect(panel).toContainText('does not confirm receipt by a person');expect(fixture.counts.testWrites).toBe(1);await capture('synthetic-http-test-alarm-setup-test-accepted-desktop-en');
 diagnostics.mark('setup-uncertain-refresh');
 fixture.setTestState('uncertain');await reload();await expect(panel.locator('.alarm-test-result dd').first()).toHaveText('Uncertain');await expect(panel).toContainText('Uncertain tests are never automatically replayed.');
 diagnostics.mark('setup-idle-guard');
 const beforeIdle={...fixture.counts};await page.clock.runFor(1000);expect(fixture.counts).toEqual(beforeIdle);
 await page.setViewportSize({width:390,height:844});
 for(const locale of ['en','de']){
  diagnostics.mark(`setup-mobile-${locale}`);
  if(locale==='de')await page.getByLabel('Language',{exact:true}).selectOption('de');
  await expect(page.locator('html')).toHaveAttribute('lang',locale);await expect(panel.locator('.alarm-test-result dd').first()).toHaveText(locale==='de'?'Ungewiss':'Uncertain');await noReadback();
  await capture(`synthetic-http-test-alarm-setup-test-uncertain-mobile-${locale}`);
  await chooseReplace();await expect(field()).toHaveValue('');await expect(panel.getByRole('checkbox').first()).not.toBeChecked();await capture(`synthetic-http-test-alarm-setup-form-mobile-${locale}`);
  await panel.getByRole('button',{name:locale==='de'?'Abbrechen':'Cancel',exact:true}).click();expect(fixture.counts.settingsWrites).toBe(1);expect(fixture.counts.testWrites).toBe(1);await noReadback();
 }
 await page.setViewportSize({width:1440,height:1000});await capture('synthetic-http-test-alarm-setup-test-uncertain-desktop-de');
 diagnostics.mark('setup-disable');
 await panel.getByRole('button',{name:'Alarme deaktivieren',exact:true}).click();expect(fixture.counts.settingsWrites).toBe(1);await expect(panel.locator('input')).toHaveCount(0);
 await panel.getByRole('button',{name:'Deaktivierung bestätigen',exact:true}).click();await expect(panel.locator('.alarm-settings-readback')).toHaveText(`${fixtureHost} · Aus`);
 expect(fixture.counts.settingsWrites).toBe(2);expect(fixture.counts.testWrites).toBe(1);expect(fixture.settings().enabled).toBe(false);await noReadback();
 await aggregate.getByRole('button',{name:'Alarmstatus aktualisieren',exact:true}).click();await expect(aggregate.locator('.alarm-mode')).toHaveText('Aus');
 await page.setViewportSize({width:390,height:844});await capture('synthetic-http-test-alarm-setup-disabled-mobile-de');
 diagnostics.mark('setup-final-guards');
 expect(requests.filter(value=>value==='POST /api/alerts/settings')).toHaveLength(2);expect(requests.filter(value=>value==='POST /api/alerts/test')).toHaveLength(1);
 expect(requests.every(value=>['GET /api/alerts/settings','GET /api/alerts/status','POST /api/alerts/settings','POST /api/alerts/test'].includes(value))).toBe(true);expect(unexpected).toEqual([]);expect(external).toEqual([]);
}
