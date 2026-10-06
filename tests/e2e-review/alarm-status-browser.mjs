import {createAlarmBrowserDiagnostics} from './alarm-browser-diagnostics.mjs';
const diagnostics=createAlarmBrowserDiagnostics();
export const alarmStatusFailureDetails=()=>diagnostics.details();
import {validAlarmStatus} from '../../web/src/alarm-status-types.ts';

/** Aggregate invented DTOs only: no event timestamps, destinations or sender. */
export const alarmFixtureDisclosure = 'Real loopback fixture login with explicitly intercepted invented GET /api/alerts/status aggregates; browser Loaded time only, provider acceptance is not human receipt; no webhook, target probe, configuration, test send or native acceptance';
export function alarmStatusFixtures() {
 const off={schemaVersion:'tracebolt.alarm-status.v1',enabled:false,queued:0,inFlight:0,providerAccepted:0,failed:0,uncertain:0,suppressed:0,dropped:0};
 const retained={...off,enabled:true,queued:2,inFlight:1,providerAccepted:7,failed:4,uncertain:5,suppressed:9,dropped:11};
 return {off,retained,disabledRetained:{...retained,enabled:false,dropped:Number.MAX_SAFE_INTEGER}};
}

/** Measure actual element geometry, including clipping inside the panel. */
async function alarmLayout({page,panel,expect}) {
 diagnostics.step('document-width');
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth&&document.body.scrollWidth<=innerWidth)).toBe(true);
 diagnostics.track(panel,-1);diagnostics.step('panel-width');
 expect(await panel.evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);
 let ordinal=0;
 for(const element of await panel.locator('h2,.alarm-mode,button,time,dt,dd,summary,p').all()){
  diagnostics.track(element,ordinal++);diagnostics.step('visibility');
  if(!await element.isVisible())continue;
  diagnostics.step('scroll-stability');await element.scrollIntoViewIfNeeded();diagnostics.step('viewport-ratio');await expect(element).toBeInViewport({ratio:1});
  diagnostics.step('bounding-box');const box=await element.boundingBox();expect(box).not.toBe(null);
  diagnostics.step('horizontal-bounds');expect(box.x).toBeGreaterThanOrEqual(0);expect(box.x+box.width).toBeLessThanOrEqual(page.viewportSize().width+1);
  diagnostics.step('element-width');expect(await element.evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);
 }
}

/** Uses the existing runner's launch, real authentication, context and captures. */
export async function alarmStatusBrowserCase({pageAt,login,expect,base,shot}) {
 diagnostics.reset();diagnostics.mark('status-bootstrap');
 const fixtures=alarmStatusFixtures();for(const value of Object.values(fixtures))expect(validAlarmStatus(value)).toBe(true);
 const malformed={...fixtures.retained,queued:'SYNTHETIC_INVALID_COUNT'};expect(validAlarmStatus(malformed)).toBe(false);
 const page=await pageAt('/settings'),clockStart=Date.now();
 // Pause before login; the existing real server TTL and relative auth timer stay intact.
 await page.clock.install({time:new Date(clockStart)});await page.clock.pauseAt(new Date(clockStart+10000));
 const statusURL=`${base}/api/alerts/status`, mutations=[],alarmRequests=[],setupRequests=[],externalRequests=[],routeErrors=[];
 let reads=0,sessionReads=0,phase='snapshot',activeFixture=fixtures.off,held=null;
 page.on('request',request=>{
  const url=new URL(request.url()),method=request.method();
  if(url.origin!==base){externalRequests.push(url.origin);return;}
  if(!url.pathname.startsWith('/api/'))return;
  if(!['GET','HEAD'].includes(method)&&!(url.pathname==='/api/auth/login'&&method==='POST'))mutations.push(`${method} ${url.pathname}`);
  if(url.pathname==='/api/auth/session')sessionReads++;
  if(url.pathname==='/api/alerts/status')alarmRequests.push(`${method} ${url.pathname}${url.search}`);
  else if(url.pathname.startsWith('/api/alerts'))setupRequests.push(`${method} ${url.pathname}${url.search}`);
 });
 // Intercept this exact existing GET only; auth and every other handler stay real.
 await page.route(statusURL,async route=>{
  reads++;const request=route.request();
  expect(request.url()).toBe(statusURL);expect(request.method()).toBe('GET');expect(request.postData()).toBe(null);
  const selected=phase,body=JSON.stringify(selected==='malformed'?malformed:activeFixture);
  if(selected==='held'){
   let release;const gate=new Promise(done=>release=done),current={release,done:false,cancelled:false};held=current;
   await gate;
   try{await route.fulfill({status:200,contentType:'application/json',body});}
   catch{if(!current.cancelled)routeErrors.push('Unexpected held response failure');}
   finally{current.done=true;}
   return;
  }
  if(selected==='unavailable'||selected==='access-lost')return route.fulfill({status:selected==='unavailable'?503:401,contentType:'application/json',body:JSON.stringify({error:{code:selected==='unavailable'?'fixture_unavailable':'authentication_required',message:'Synthetic alarm-status fault injection'}})});
  return route.fulfill({status:200,contentType:'application/json',body});
 });
 const panel=page.locator('.alarm-status'),details=panel.locator('details'),summary=details.locator('summary');
 diagnostics.reset(panel);diagnostics.mark('status-bootstrap');
 const refresh=()=>panel.getByRole('button',{name:/^(Refresh alarm status|Alarmstatus aktualisieren)$/});
 const count=(name,breakdown=false)=>(breakdown?panel.locator('.alarm-breakdown'):panel.locator('.alarm-counts')).locator('div').filter({has:page.getByText(name,{exact:true})}).locator('dd');
 const reload=async()=>{const before=reads;await refresh().click();await expect.poll(()=>reads).toBe(before+1);await expect(refresh()).toBeEnabled();};
 const assertEmpty=async()=>{await expect(panel.locator('time,dd,.alarm-counts')).toHaveCount(0);};
 const beginHeld=async()=>{
  held=null;phase='held';activeFixture={...fixtures.retained,providerAccepted:71};expect(validAlarmStatus(activeFixture)).toBe(true);
  const before=reads;await refresh().dblclick();await expect.poll(()=>held!==null).toBe(true);await expect(refresh()).toBeDisabled();expect(reads).toBe(before+1);
 };
 const releaseHeld=async()=>{const current=held;current.cancelled=true;current.release();await expect.poll(()=>current.done).toBe(true);held=null;};
 try{
  await expect(page.getByRole('heading',{name:'Sign in',exact:true})).toBeVisible();expect(reads).toBe(0);await expect(panel).toHaveCount(0);
  await login(page);await expect(page.getByRole('region',{name:'Alarm delivery',exact:true})).toBeVisible();
  diagnostics.mark('status-initial');
  await expect(panel.locator('.alarm-mode')).toHaveText('Off');expect(reads).toBe(1);await expect(panel.locator('.alarm-counts')).toHaveCount(0);
  await expect(details).not.toHaveAttribute('open','');await expect(summary).toHaveAccessibleName('Details');
  await summary.focus();await page.keyboard.press('Enter');await expect(details).toHaveAttribute('open','');
  await expect(details).toContainText('Delivery is disabled in manager configuration.');
  await expect(details).toContainText('Loaded time uses this browser’s clock, not an event or server observation time.');
  await page.keyboard.press('Space');await expect(details).not.toHaveAttribute('open','');
  diagnostics.track(panel,-1);diagnostics.step('capture');await panel.scrollIntoViewIfNeeded();await shot(page,'synthetic-http-test-alarm-status-off-desktop-en',alarmFixtureDisclosure);

  diagnostics.mark('status-retained-desktop');
  activeFixture=fixtures.retained;await page.clock.runFor(1000);await reload();
  await expect(panel.locator('.alarm-mode')).toHaveText('On');
  for(const [name,value] of [['Provider accepted','7'],['Pending','3'],['Failed','4'],['Uncertain','5'],['Dropped','11']])await expect(count(name)).toHaveText(value);
  await expect(panel.locator('.alarm-acceptance')).toHaveText('Provider acceptance does not confirm receipt by a person.');
  await expect(panel.getByRole('button')).toHaveCount(1);await expect(panel.locator('a,input,select,textarea,form')).toHaveCount(0);
  const loaded=await panel.locator('time').getAttribute('datetime');expect(loaded).toBe(await page.evaluate(()=>new Date().toISOString()));
  const beforeIdle=reads;await page.clock.runFor(16000);expect(reads).toBe(beforeIdle);await expect(panel.locator('time')).toHaveAttribute('datetime',loaded);
  await summary.click();
  for(const [name,value] of [['Queued','2'],['In flight','1'],['Suppressed','9'],['Dropped','11']])await expect(count(name,true)).toHaveText(value);
  await expect(details).toContainText('Pending is queued plus in flight.');await expect(details).toContainText('Uncertain events may have been accepted; they are not automatically replayed.');
  await expect(details).toContainText('Dropped is a separate durable count');await expect(details).toContainText('including previous destinations.');
  await summary.click();await alarmLayout({page,panel,expect});diagnostics.track(panel,-1);diagnostics.step('capture');await panel.scrollIntoViewIfNeeded();
  await shot(page,'synthetic-http-test-alarm-status-retained-desktop-en',alarmFixtureDisclosure);
  await page.setViewportSize({width:390,height:844});
  for(const locale of ['en','de']){
   diagnostics.mark(`status-mobile-${locale}-summary`);
   const beforeLanguage=reads;if(locale==='de')await page.getByLabel('Language',{exact:true}).selectOption('de');
   await expect(page.locator('html')).toHaveAttribute('lang',locale);expect(reads).toBe(beforeLanguage);
   await expect(page.getByRole('region',{name:locale==='de'?'Alarmversand':'Alarm delivery',exact:true})).toBeVisible();
   if(locale==='de'){
    for(const [name,value] of [['Vom Anbieter angenommen','7'],['Ausstehend','3'],['Fehlgeschlagen','4'],['Ungewiss','5'],['Verworfen','11']])await expect(count(name)).toHaveText(value);
    await expect(panel.locator('.alarm-acceptance')).toHaveText('Die Annahme durch den Anbieter bestätigt keinen Empfang durch eine Person.');
   }
   await alarmLayout({page,panel,expect});diagnostics.track(panel,-1);diagnostics.step('capture');await panel.scrollIntoViewIfNeeded();
   await shot(page,`synthetic-http-test-alarm-status-retained-mobile-${locale}`,alarmFixtureDisclosure);
   diagnostics.mark(`status-mobile-${locale}-details`);
   await summary.click();await expect(details).toHaveAttribute('open','');await expect(summary).toHaveAccessibleName('Details');
   await alarmLayout({page,panel,expect});diagnostics.track(summary,-1);diagnostics.step('capture');await summary.scrollIntoViewIfNeeded();
   await shot(page,`synthetic-http-test-alarm-status-details-mobile-${locale}`,alarmFixtureDisclosure);
   await summary.click();await expect(details).not.toHaveAttribute('open','');
  }
  diagnostics.mark('status-disabled-retained');
  activeFixture=fixtures.disabledRetained;await reload();await expect(panel.locator('.alarm-mode')).toHaveText('Aus');
  await expect(count('Fehlgeschlagen')).toHaveText('4');await expect(count('Verworfen')).toHaveText(new Intl.NumberFormat('de').format(Number.MAX_SAFE_INTEGER));
  await alarmLayout({page,panel,expect});diagnostics.track(panel,-1);diagnostics.step('capture');await panel.scrollIntoViewIfNeeded();await shot(page,'synthetic-http-test-alarm-status-disabled-retained-mobile-de',alarmFixtureDisclosure);
  await page.getByLabel('Sprache',{exact:true}).selectOption('en');await page.setViewportSize({width:1440,height:1000});activeFixture=fixtures.retained;await reload();
  const previousLoaded=await panel.locator('time').getAttribute('datetime');
  diagnostics.mark('status-failure-reads');
  for(const failure of ['unavailable','malformed']){
   phase=failure;await page.clock.runFor(1000);await reload();await expect(panel.getByRole('alert')).toHaveText(failure==='unavailable'?'Alarm status could not be confirmed. Refresh to try again.':'The manager returned an unsupported alarm status. Refresh to try again.');
   await expect(panel.locator('.alarm-mode')).toHaveText('Unknown');await expect(panel.locator('.alarm-snapshot')).toContainText('Previous snapshot');
   await expect(panel.locator('time')).toHaveAttribute('datetime',previousLoaded);await expect(count('Provider accepted')).toHaveText('7');
   await expect(panel).not.toContainText('SYNTHETIC_INVALID_COUNT');await expect(panel).not.toContainText('Synthetic alarm-status fault injection');
   const beforeRetry=reads;await page.clock.runFor(1000);expect(reads).toBe(beforeRetry);
  }
  // An aborted ten-second read cannot overwrite a newer explicit refresh.
  diagnostics.mark('status-held-read');
  await beginHeld();await expect(panel.locator('.alarm-mode')).toHaveText('Unknown');await page.clock.runFor(10001);
  await expect(panel.getByRole('alert')).toHaveText('The manager did not respond in time. Refresh to try again.');
  await expect(panel.locator('time')).toHaveAttribute('datetime',previousLoaded);await expect(count('Provider accepted')).toHaveText('7');
  phase='snapshot';activeFixture={...fixtures.retained,providerAccepted:13};expect(validAlarmStatus(activeFixture)).toBe(true);await reload();
  const freshLoaded=await panel.locator('time').getAttribute('datetime');expect(freshLoaded).not.toBe(previousLoaded);
  await releaseHeld();await expect(count('Provider accepted')).toHaveText('13');await expect(panel.locator('time')).toHaveAttribute('datetime',freshLoaded);await expect(panel.locator('.alarm-mode')).toHaveText('On');

  diagnostics.mark('status-navigation');
  await beginHeld();await page.goto(`${base}/#/devices`);await expect(panel).toHaveCount(0);const awayReads=reads;await releaseHeld();await page.clock.runFor(1000);expect(reads).toBe(awayReads);
  phase='snapshot';activeFixture=fixtures.off;await page.goto(`${base}/#/settings`);await expect(panel.locator('.alarm-mode')).toHaveText('Off');await expect(panel.locator('.alarm-counts')).toHaveCount(0);expect(reads).toBe(awayReads+1);
  activeFixture=fixtures.retained;await reload();
  diagnostics.mark('status-suspension');
  for(const suspension of ['visibility','pagehide']){
   await beginHeld();const beforeSuspend=reads;
   await page.evaluate(kind=>{
    if(kind==='visibility'){Object.defineProperty(document,'visibilityState',{configurable:true,value:'hidden'});document.dispatchEvent(new Event('visibilitychange'));}
    else window.dispatchEvent(new PageTransitionEvent('pagehide',{persisted:true}));
   },suspension);
   await assertEmpty();await releaseHeld();await assertEmpty();
   const beforeRestore=sessionReads;phase='snapshot';activeFixture=fixtures.retained;
   await page.evaluate(kind=>{
    if(kind==='visibility'){Object.defineProperty(document,'visibilityState',{configurable:true,value:'visible'});document.dispatchEvent(new Event('visibilitychange'));}
    else window.dispatchEvent(new PageTransitionEvent('pageshow',{persisted:true}));
   },suspension);
   await expect.poll(()=>sessionReads).toBeGreaterThan(beforeRestore);await expect(panel).toBeVisible();await expect(refresh()).toBeEnabled();
   await expect(panel.getByRole('status')).toHaveText('Refresh alarm status to load a new snapshot.');await assertEmpty();await page.clock.runFor(1000);expect(reads).toBe(beforeSuspend);
   await reload();await expect(count('Provider accepted')).toHaveText('7');
  }
  diagnostics.mark('status-access-loss');
  phase='access-lost';const beforeLoss=reads;await refresh().click();await expect(page.getByRole('heading',{name:'Sign in',exact:true})).toBeVisible();
  await expect(panel).toHaveCount(0);await expect(page.locator('.app-shell')).toHaveCount(0);expect(reads).toBe(beforeLoss+1);
  const lockedReads=reads;await page.clock.runFor(5000);expect(reads).toBe(lockedReads);
  phase='snapshot';activeFixture=fixtures.off;await login(page);await expect(panel.locator('.alarm-mode')).toHaveText('Off');await expect(panel.locator('.alarm-counts')).toHaveCount(0);expect(reads).toBe(lockedReads+1);
  await page.clock.runFor(1000);expect(reads).toBe(lockedReads+1);
  diagnostics.mark('status-final-guards');
  expect(mutations).toEqual([]);expect(externalRequests).toEqual([]);expect(routeErrors).toEqual([]);
  expect(alarmRequests.length).toBe(reads);expect(alarmRequests.every(value=>value==='GET /api/alerts/status')).toBe(true);
  expect(setupRequests.length).toBeGreaterThan(0);expect(setupRequests.every(value=>value==='GET /api/alerts/settings')).toBe(true);
 }finally{
  if(held){held.cancelled=true;held.release();}
 }
}
