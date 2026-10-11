import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs';
import {windowsUpdatesBrowserFixture} from './windows-updates-browser.mjs';
import {requireWindowsPatchContextEvidence,windowsPatchContextDisclosure} from './windows-patch-context-browser.mjs';
const serverNow='2026-10-07T12:00:10Z',capturedAt='2026-10-07T12:00:00Z';
test('Docker web typecheck receives only the shared synthetic patch snapshot',()=>{
 const read=name=>fs.readFileSync(new URL(name,import.meta.url),'utf8');
 const docker=read('../../Dockerfile'),webStage=docker.split('FROM --platform=$BUILDPLATFORM golang:')[0],runtimeStage=docker.split('FROM scratch AS runtime')[1];
 const fixture='internal/windowspatchcontext/testdata/snapshot.json',copy=`COPY ${fixture} /src/${fixture}\n`;
 assert.ok(webStage.includes(copy));
 assert.ok(webStage.indexOf(copy)<webStage.indexOf('RUN npm run build'));
 assert.doesNotMatch(webStage,/^COPY internal\/\s/m);
 assert.doesNotMatch(runtimeStage,/windowspatchcontext|testdata\/snapshot\.json/);
 const ignore=read('../../.dockerignore').split(/\r?\n/);
 assert.ok(ignore.includes('!internal/')&&ignore.includes('!internal/**'));
 assert.match(read('../../web/src/windows-patch-context-types.test.ts'),/import goFixture from '\.\.\/\.\.\/internal\/windowspatchcontext\/testdata\/snapshot\.json'/);
 assert.equal(JSON.parse(read(`../../${fixture}`)).schemaVersion,'tracebolt.windows-patch-context.v1');
});
test('patch fixtures retain base binding and distinguish empty, partial, denied, absent and expired history',()=>{
 assert.match(windowsPatchContextDisclosure,/UI-only fixture evidence/);
 for(const phase of ['bounded','empty','partial','partial-empty','denied','unavailable','legacy']){
  const view=windowsUpdatesBrowserFixture({serverNow,capturedAt,phase});
  if(phase==='legacy'){assert.equal(view.patchContext,undefined);continue;}
  assert.equal(view.patchContext.collectedAt,capturedAt);assert.equal(view.patchContext.generationId,view.snapshot.generationId);assert.notEqual(view.patchContext.grantId,view.updates.grantId);
  for(const row of view.patchContext.history.rows)assert.ok(Date.parse(row.occurredAt)<Date.parse(capturedAt));
 }
 const expired=windowsUpdatesBrowserFixture({serverNow:'2026-10-08T12:00:00Z',capturedAt});assert.equal(expired.patchContext,undefined);
 const stale=windowsUpdatesBrowserFixture({serverNow:'2026-10-07T12:05:00Z',capturedAt});assert.equal(stale.patchContext.collectedAt,capturedAt);assert.equal(stale.status,'stale');
});
test('completion requires actual compact and history screenshot records for both languages and sizes',()=>{
 const source='a'.repeat(40),testName='synthetic',records=[];
 for(const kind of ['context','history'])for(const locale of ['en','de'])for(const width of [1440,390])records.push({file:`synthetic-windows-patch-${kind}-${width}-${locale}.png`,sourceSha:source,test:testName,locale,viewport:{width,height:width===390?844:1000},publicSafe:true,fullPage:false,fixtureDisclosure:windowsPatchContextDisclosure});
 assert.deepEqual(requireWindowsPatchContextEvidence(records,source,testName),{patchContext:4,patchHistory:4});
 for(const broken of [records.slice(1),[...records,records[0]],records.map((r,i)=>i? r:{...r,sourceSha:'b'.repeat(40)}),records.map((r,i)=>i?r:{...r,viewport:{width:390,height:844}}),records.map((r,i)=>i?r:{...r,publicSafe:false})])assert.throws(()=>requireWindowsPatchContextEvidence(broken,source,testName));
});
test('shared Updates browser case captures patch context without new browser, request, grant or clock mutation',()=>{
 const source=fs.readFileSync(new URL('./windows-inventory-browser.mjs',import.meta.url),'utf8'),runner=fs.readFileSync(new URL('./lan-browser.mjs',import.meta.url),'utf8'),helper=fs.readFileSync(new URL('./windows-patch-context-browser.mjs',import.meta.url),'utf8');
 assert.match(source,/mark\('patch-context'\);await exerciseWindowsPatchContext\(\{page,expect,locale,width,shot\}\)/);assert.match(runner,/requireWindowsPatchContextEvidence\(screenshots,sourceSha,name\)/);
 assert.doesNotMatch(helper,/chromium\.launch|newContext\(|spawn\(|execFile|writeFile|ignoreHTTPSErrors|fetch\(|localStorage|sessionStorage|waitForTimeout|setDefaultTimeout|clock\.runFor/);
});
