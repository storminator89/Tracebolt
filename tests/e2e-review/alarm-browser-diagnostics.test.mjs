import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import {createAlarmBrowserDiagnostics,sanitizeAlarmGeometry} from './alarm-browser-diagnostics.mjs';
const read=name=>fs.readFileSync(new URL(name,import.meta.url),'utf8');
test('geometry keeps only fixed finite bounded numeric fields',()=>{
 const v=sanitizeAlarmGeometry({viewportWidth:390,viewportHeight:844,elementLeft:-1.23456,elementWidth:NaN,elementHeight:Infinity,elementTop:100001,mainTop:'PRIVATE_TOKEN',bodyText:'PRIVATE_URL',endpoint:'PRIVATE_URL',elementClientWidth:0});
 assert.deepEqual(v,{viewportWidth:390,viewportHeight:844,elementLeft:-1.235,elementClientWidth:0});
 assert.equal(sanitizeAlarmGeometry(null),null);assert.equal(sanitizeAlarmGeometry('PRIVATE'),null);assert.equal(sanitizeAlarmGeometry([390]),null);assert.equal(sanitizeAlarmGeometry({raw:'PRIVATE'}),null);
 assert.equal(JSON.stringify(v).includes('PRIVATE'),false);
});
test('failure details admit only closed stages, steps and categories with a bounded index',async()=>{
 const d=createAlarmBrowserDiagnostics();let reads=0;
 d.reset({evaluate:async(_fn,_args,options)=>{reads++;assert.deepEqual(options,{timeout:750});return {category:'paragraph',geometry:{viewportWidth:390,elementHeight:88},rawError:'PRIVATE'};}});
 d.mark('status-mobile-en-details');d.step('viewport-ratio');const v=await d.details();assert.equal(reads,1);assert.deepEqual(v,{stage:'status-mobile-en-details',step:'viewport-ratio',elementCategory:'paragraph',elementIndex:-1,geometry:{viewportWidth:390,elementHeight:88}});
 d.mark('PRIVATE_URL');d.step('PRIVATE_TOKEN');d.track({evaluate:async()=>({category:'PRIVATE_TOKEN',geometry:{viewportWidth:390,token:'PRIVATE'}})},1000000);
 const invalid=await d.details();assert.equal(invalid.stage,'initial');assert.equal(invalid.step,'action');assert.equal(invalid.elementCategory,'none');assert.equal(invalid.elementIndex,-1);assert.equal(JSON.stringify(invalid).includes('PRIVATE'),false);
});
test('a detached or failed diagnostic probe never serializes its raw failure',async()=>{
 const d=createAlarmBrowserDiagnostics();d.reset({evaluate:async()=>{throw new Error('PRIVATE_URL_TOKEN');}});d.mark('setup-test-uncertain-mobile-en');
 const v=await d.details();assert.equal(v.geometry,null);assert.equal(v.elementCategory,'none');assert.equal(JSON.stringify(v).includes('PRIVATE'),false);
});
test('diagnostic source does not read credential-bearing text, attributes or request state',()=>{
 const helper=read('./alarm-browser-diagnostics.mjs');assert.doesNotMatch(helper,/innerText|textContent|innerHTML|outerHTML|\.value\b|location\.|postData|allHeaders|document\.cookie|localStorage|sessionStorage|\.message\b|\.stack\b/);
 const runner=read('./lan-browser.mjs');assert.match(runner,/alarmDiagnostics:await alarmSettingsFailureDetails\(\)/);assert.match(runner,/alarmDiagnostics:await alarmStatusFailureDetails\(\)/);
 for(const name of ['./alarm-status-browser.mjs','./alarm-settings-browser.mjs']){const source=read(name);assert.match(source,/toBeInViewport\(\{ratio:1\}\)/);assert.doesNotMatch(source,/setDefaultTimeout|waitForTimeout|ignoreHTTPSErrors/);assert.match(source,/diagnostics.step\('scroll-stability'\)/);assert.match(source,/diagnostics.step\('viewport-ratio'\)/);}
});


test('exact hosted subpixel failures fit completely after centered integer scrolling',()=>{
 const observed=[
  {top:769.578,height:74.75,left:35,width:320,viewport:390,bottom:844,mainTop:150,mainHeight:694,scrollTop:30,scrollHeight:3519,clip:0.328},
  {top:721.859,height:122.344,left:35,width:320,viewport:390,bottom:844,mainTop:150,mainHeight:694,scrollTop:487,scrollHeight:4186,clip:0.203}
 ];
 for(const f of observed){
  assert.equal(Number((f.top+f.height-f.bottom).toFixed(3)),f.clip);assert.ok(f.left>=0&&f.left+f.width<=f.viewport);assert.ok(f.height<f.mainHeight);
  const desired=f.scrollTop+(f.top+f.height/2)-(f.mainTop+f.mainHeight/2);
  const rounded=Math.max(0,Math.min(Math.round(desired),f.scrollHeight-f.mainHeight));
  const centeredTop=f.top-(rounded-f.scrollTop);
  assert.ok(centeredTop>=f.mainTop);assert.ok(centeredTop+f.height<=f.bottom);
 }
});

test('both walks retain stability then center instantly before the unchanged ratio-one assertion',()=>{
 for(const name of ['./alarm-status-browser.mjs','./alarm-settings-browser.mjs']){
  const source=read(name),stable=source.indexOf("diagnostics.step('scroll-stability');await element.scrollIntoViewIfNeeded();"),center=source.indexOf("el.scrollIntoView({block:'center',inline:'nearest',behavior:'instant'})"),ratio=source.indexOf("diagnostics.step('viewport-ratio');await expect(element).toBeInViewport({ratio:1});");
  assert.ok(stable>=0&&center>stable&&ratio>center);assert.match(source,/diagnostics.step\('scroll-center'\)/);
  assert.match(source,/toBeGreaterThanOrEqual\(0\)/);assert.match(source,/toBeLessThanOrEqual\(page.viewportSize\(\).width\+1\)/);
  assert.doesNotMatch(source,/setDefaultTimeout|waitForTimeout|ratio:0\./);
 }
});

test('the center diagnostic step remains a closed, data-free category',async()=>{
 const d=createAlarmBrowserDiagnostics();d.reset();d.mark('setup-form-mobile-de');d.step('scroll-center');
 assert.deepEqual(await d.details(),{stage:'setup-form-mobile-de',step:'scroll-center',elementCategory:'none',elementIndex:-1,geometry:null});
});
