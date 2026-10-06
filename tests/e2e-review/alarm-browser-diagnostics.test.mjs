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
