import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {windowsContactBrowserFixture,windowsContactHistoryDisclosure} from './windows-contact-history-browser.mjs';
test('Docker web typecheck admits exactly the imported synthetic Go-to-TypeScript fixtures',()=>{
 const read=name=>fs.readFileSync(new URL(name,import.meta.url),'utf8');
 const docker=read('../../Dockerfile'),ignore=read('../../.dockerignore').split(/\r?\n/).map(line=>line.trim()).filter(line=>line&&!line.startsWith('#'));
 const fixtures=['windows-contact-view.json','windows-capacity-view.json','windows-resource-view.json','windows-maintenance-view.json','windows-notifications-view.json','windows-service-health-view.json','windows-service-action-view.json','windows-service-action-history.json','windows-incident-inbox-view.json','windows-service-incident-review.json'];
 const webStage=docker.split('FROM --platform=$BUILDPLATFORM golang:')[0],runtimeStage=docker.split('FROM scratch AS runtime')[1];
 for(const fixture of fixtures){
  const path='tests/fixtures/'+fixture,copy=`COPY ${path} /src/${path}`;
  assert.equal(webStage.split('\n').filter(line=>line===copy).length,1,`${path} needs one exact web-stage COPY`);
  assert.ok(webStage.indexOf(copy)<webStage.indexOf('RUN npm run build'),`${path} must precede typecheck`);
  assert.ok(!runtimeStage.includes(path),`${path} must not enter the runtime stage`);
  assert.ok(Object.keys(JSON.parse(read('../../'+path))).length>0);
 }
 // New shared fixture imports must extend this reviewed exact allowlist and COPY
 // set; an ordinary checkout typecheck alone cannot detect Docker omissions.
 const sources=fs.readdirSync(new URL('../../web/src/',import.meta.url),{recursive:true}).filter(name=>/\.[cm]?[jt]sx?$/.test(name));
 const imported=[...new Set(sources.flatMap(name=>[...read('../../web/src/'+name).matchAll(/['"](?:\.\.\/)+tests\/fixtures\/([^'"]+)['"]/g)].map(match=>match[1])))];
 assert.deepEqual(imported.sort(),[...fixtures].sort(),'every imported test fixture needs explicit container admission');
 assert.match(read('../../web/src/windows-service-health-types.test.ts'),/import wireFixture from '\.\.\/\.\.\/tests\/fixtures\/windows-service-health-view\.json'/);
 assert.match(read('../../web/src/windows-service-health-types.test.ts'),/Object\.entries\(wireFixture\)/);
 assert.match(read('../../web/src/windows-service-actions.test.tsx'),/import golden from '\.\.\/\.\.\/tests\/fixtures\/windows-service-action-view\.json'/);
 assert.match(read('../../web/src/windows-incident-inbox-types.test.ts'),/import wire from '\.\.\/\.\.\/tests\/fixtures\/windows-incident-inbox-view\.json'/);
 assert.deepEqual(ignore.filter(line=>line.startsWith('!tests/fixtures')),['!tests/fixtures/',...fixtures.map(name=>'!tests/fixtures/'+name)]);
 const parent=ignore.indexOf('!tests/fixtures/');assert.equal(ignore[parent+1],'tests/fixtures/**');assert.equal(ignore[parent+2],'!tests/fixtures/windows-contact-view.json');
 assert.ok(ignore.includes('**')&&ignore.includes('tests/**'));
 assert.ok(!ignore.includes('!tests/**'));
 assert.doesNotMatch(webStage,/^COPY tests\/(?:fixtures\/)?\s/m);
 assert.match(read('../../web/src/windows-contact-types.test.ts'),/import wireFixture from '\.\.\/\.\.\/tests\/fixtures\/windows-contact-view\.json'/);
 assert.match(read('../../web/src/windows-contact-types.test.ts'),/Object\.entries\(wireFixture\)/);
 assert.ok(JSON.parse(read('../../web/tsconfig.json')).include.includes('src'));
});
test('invented contact GET advances manager time without renewing acceptance or evaluation',()=>{
 const origin='2026-10-07T12:00:10Z',first=windowsContactBrowserFixture(origin),later=windowsContactBrowserFixture('2026-10-07T12:02:11Z',origin);
 assert.equal(first.status,'overdue');assert.equal(later.status,'unknown');assert.equal(first.lastAcceptedAt,later.lastAcceptedAt);assert.equal(first.sequence,later.sequence);assert.equal(first.evaluatedAt,later.evaluatedAt);assert.deepEqual(first.incidents,later.incidents);assert.equal(later.incidents[0].resolvedAt,null);assert.match(windowsContactHistoryDisclosure,/Source-only test; no native Windows read/);
});
test('bounded contact case is integrated in the authenticated EN/DE desktop/mobile runner',()=>{
 const source=fs.readFileSync(new URL('./windows-contact-history-browser.mjs',import.meta.url),'utf8'),runner=fs.readFileSync(new URL('./windows-inventory-browser.mjs',import.meta.url),'utf8');
 assert.match(runner,/await login\(page\)/);assert.match(runner,/for\(const locale of \['en','de'\]\)for\(const width of \[1440,390\]\)/);assert.match(source,/await advance\(121000\)/);
 assert.match(runner,/await exerciseWindowsContactHistory\(/);assert.match(runner,/\.\.\.windowsContactHistoryStageNames/);assert.match(runner,/prefix\+'\/windows-contact'/);
 assert.match(runner,/expect\(writes\)\.toEqual\(\[\]\)/);assert.match(runner,/expect\(external\)\.toEqual\(\[\]\)/);assert.match(runner,/expect\(unexpected\)\.toEqual\(\[\]\)/);assert.doesNotMatch(source,/chromium\.launch|newContext\(|execFile|spawn\(|writeFile|ignoreHTTPSErrors|grantPermissions/);
});
test('injected completed recovery keeps the original incident receipt and adds separate recovery evidence',()=>{
 const origin='2026-10-07T12:00:10Z',opened=windowsContactBrowserFixture(origin),recovered=windowsContactBrowserFixture('2026-10-07T12:02:11Z',origin,'contact-recovered');
 assert.equal(recovered.status,'recent');assert.equal(recovered.incidents[0].id,opened.incidents[0].id);assert.equal(recovered.incidents[0].lastAcceptedAt,opened.incidents[0].lastAcceptedAt);assert.equal(recovered.incidents[0].sequence,opened.incidents[0].sequence);assert.equal(recovered.incidents[0].closedReason,'reports-resumed');assert.equal(Date.parse(recovered.incidents[0].resolvedAt)-Date.parse(recovered.incidents[0].recoveryAcceptedAt),60000);
});

// Static source accounting is deliberately order-independent. Every imported
// helper receiving the virtual-clock callback must contribute its literal waits;
// new dynamic timing needs an explicit bound rather than silently counting zero.
function windowsClockBudget(windows,read){
 const localeLoop=windows.match(/for\(const locale of (\[[^\]]+\])\)/),widthLoop=windows.match(/for\(const width of (\[[^\]]+\])\)/);
 assert.ok(localeLoop&&widthLoop,'explicit locale/width loops are required');
 const locales=JSON.parse(localeLoop[1].replaceAll("'",'"')),widths=JSON.parse(widthLoop[1]);
 assert.deepEqual(locales,['en','de']);assert.deepEqual(widths,[1440,390]);
 const imports=new Map([...windows.matchAll(/import \{([^}]+)\} from '(\.\/[^']+)';/g)].flatMap(([,names,path])=>names.split(',').map(name=>[name.trim(),path])));
 const calls=[...windows.matchAll(/await (\w+)\(\{([^\n]+)\}\);/g)].filter(([, ,args])=>/\badvance\s*:/.test(args));
 assert.equal(calls.length,(windows.match(/\badvance\s*:/g)||[]).length,'every advance-receiving helper must be accounted for');
 const helpers=calls.map(([,name])=>{
  assert.ok(imports.has(name),`clock helper ${name} must resolve to its imported source`);
  const source=read(imports.get(name)),amounts=[...source.matchAll(/await advance\((\d+)\)/g)].map(match=>Number(match[1]));
  assert.equal(amounts.length,(source.match(/\badvance\s*\(/g)||[]).length,`clock helper ${name} needs bounded literal advances`);
  assert.doesNotMatch(source,/\.clock\./,`clock helper ${name} must use the accounted callback`);
  return {name,amounts};
 });
 const fixedWindows=[...windows.matchAll(/await page\.clock\.runFor\((\d+)\)/g)].map(match=>Number(match[1]));
 const iterations=locales.length*widths.length,initialClockAdvance=1000,historyAllowancePerIteration=30000;
 assert.match(windows,/await page\.clock\.pauseAt\(new Date\(clockNow\+1000\)\);clockNow\+=1000;/);
 // Nonliteral runFor calls are only the one history probe and each helper callback.
 assert.equal((windows.match(/\.clock\.runFor\(/g)||[]).length,fixedWindows.length+calls.length+1);
 const fixedMS=initialClockAdvance+iterations*[...fixedWindows,...helpers.flatMap(helper=>helper.amounts)].reduce((sum,n)=>sum+n,0);
 return {iterations,helpers,fixedWindows,fixedMS,plannedMS:fixedMS+iterations*historyAllowancePerIteration};
}

test('only the Windows case receives a bounded session TTL above its full virtual-time budget',()=>{
 const read=name=>fs.readFileSync(new URL(name,import.meta.url),'utf8');
 const runner=read('./lan-browser.mjs'),windows=read('./windows-inventory-browser.mjs');
 const windowsCheck=runner.match(/await check\(windowsInventoryCaseName,\(\)=>windowsInventoryBrowserCase\(\{pageAt,login,expect,base,shot\}\),'(\d+)m'\);/);
 assert.ok(windowsCheck,'one explicit Windows fixture session TTL is required');
 const ttlMS=Number(windowsCheck[1])*60000;
 assert.equal(ttlMS,1200000,'Windows fixture TTL stays bounded at 20 minutes');
 assert.equal((runner.match(/,'20m'\);/g)||[]).length,1,'no other fixture session TTL is expanded');
 assert.match(runner,/await check\(resourceHistoryCaseName,[^\n]+,'10m'\);/);
 assert.match(runner,/await check\(capabilityCaseName,[^\n]+,'10m'\);/);
 assert.match(runner,/await check\(journalBrowseCaseName,[^\n]+,'30m'\);/);
 assert.match(runner,/async function check\(name,run,ttl='60s'\)/);
 assert.match(windows,/for\(const locale of \['en','de'\]\)for\(const width of \[1440,390\]\)/);
 const {iterations,helpers,fixedWindows,fixedMS,plannedMS}=windowsClockBudget(windows,read);
 assert.deepEqual(fixedWindows,[6000,6000]);
 assert.deepEqual(Object.fromEntries(helpers.map(({name,amounts})=>[name,amounts])),{exerciseWindowsContactHistory:[121000],windowsLogsBrowserCase:[15000,6000],exerciseWindowsEventContent:[3000]});
 // Preserve the single 500-ms history-settling probe. Its unchanged default
 // five-second Playwright poll cannot exhaust this conservative 30-second
 // virtual allowance at the default minimum 100-ms wall-time polling interval.
 assert.equal((windows.match(/await settleWindowsHistory\(/g)||[]).length,1);
 assert.match(windows,/expect\.poll\(async\(\)=>\{await advance\(500\);/);
 assert.doesNotMatch(windows,/setDefaultTimeout|expect\.configure/);
 assert.doesNotMatch(runner,/expect\.configure|setDefaultTimeout/);
 assert.equal(iterations,4);assert.equal(fixedMS,629000);
 assert.ok(fixedMS>600000,'fixed virtual advances alone exceed the previous 10-minute fixture TTL');
 assert.equal(fixedMS-iterations*121000,145000,'pre-contact subtotal includes all four event helper waits');
 // Service checks add read-only chooser/stage exercises, with no virtual advances.
 const services=read('./windows-service-health-browser.mjs');
 assert.match(windows,/await exerciseWindowsServiceHealth\(/);
 assert.doesNotMatch(services.replace(/\/\/[^\n]*/g,''),/\.clock\b|clockNow|\badvance\s*\(|\brunFor\s*\(|\b(?:setTimeout|setInterval|waitForTimeout|setDefaultTimeout)\s*\(|Date\.now\s*\(/);
 assert.equal(plannedMS,749000);
 assert.ok(plannedMS<ttlMS,`planned virtual time ${plannedMS} must fit below fixture TTL ${ttlMS}`);
});

test('Windows clock accounting reads helper timing and fails closed on unbounded additions',()=>{
 const read=name=>fs.readFileSync(new URL(name,import.meta.url),'utf8'),windows=read('./windows-inventory-browser.mjs');
 const baseline=windowsClockBudget(windows,read),eventPath='./windows-event-content-browser.mjs';
 const mutateEvent=replacement=>name=>name===eventPath?read(name).replace('await advance(3000)',replacement):read(name);
 const changed=windowsClockBudget(windows,mutateEvent('await advance(3001)'));
 assert.equal(changed.fixedMS,baseline.fixedMS+baseline.iterations);
 const added=windowsClockBudget(windows,name=>read(name)+(name===eventPath?'\nawait advance(7);':''));
 assert.equal(added.plannedMS,baseline.plannedMS+7*baseline.iterations);
 assert.throws(()=>windowsClockBudget(windows,mutateEvent('await advance(dynamicMS)')),/bounded literal advances/);
 const extra=windowsClockBudget("import {extraClockHelper} from './extra-clock-helper.mjs';\n"+windows+"\nawait extraClockHelper({advance:async ms=>{await page.clock.runFor(ms);}});",name=>name==='./extra-clock-helper.mjs'?'await advance(11);':read(name));
 assert.equal(extra.plannedMS,baseline.plannedMS+11*baseline.iterations);
 const lines=windows.split('\n'),clockHelperLines=lines.filter(line=>/await \w+\(\{[^\n]+\badvance:/.test(line));
 const reversed=[...clockHelperLines].reverse();let helperIndex=0;
 const reordered=lines.map(line=>clockHelperLines.includes(line)?reversed[helperIndex++]:line).join('\n');
 assert.equal(windowsClockBudget(reordered,read).plannedMS,baseline.plannedMS);
 assert.throws(()=>windowsClockBudget(windows+"\nawait unknownHelper({advance:async ms=>{await page.clock.runFor(ms);}});",read),/must resolve to its imported source/);
});
