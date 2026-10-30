/** Hosted-only synthetic browser gate. Uses the ordinary locked Chromium
 * installation and built web/dist. No Go process, SCM adapter or real API. */
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {createServer} from 'node:http';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import {randomBytes} from 'node:crypto';
import {createWindowsActionDiagnostic} from './windows-service-actions-diagnostics.mjs';
const downloadScreenshots=[],downloadVariants=[];
const retirementScreenshots=[],retirementVariants=[];
const softwareScreenshots=[],softwareVariants=[];
const fleetScheduleScreenshots=[],fleetScheduleVariants=[];
const scheduleScreenshots=[],scheduleVariants=[],backgroundScheduleScreenshots=[],backgroundScheduleVariants=[];
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..'),require=createRequire(path.join(root,'web/package.json'));
const sourceSha=process.env.TRACEBOLT_SOURCE_SHA??null,out=path.join(root,'artifacts/review'),dist=path.join(root,'web/dist');
const diagnostic=createWindowsActionDiagnostic(sourceSha,process.env.TRACEBOLT_WINDOWS_DIAGNOSTICS_TOKEN??randomBytes(16).toString('hex'));
const failure=()=>new Error('Synthetic Windows action browser gate failed; raw state withheld.');
let firstFailure=null;
const writeFailure=async()=>{try{const report=firstFailure??diagnostic.report();if(report){firstFailure=report;await fs.mkdir(out,{recursive:true});await fs.writeFile(path.join(out,'windows-service-actions-failure.json'),JSON.stringify(report)+'\n');}}catch{/* Diagnostics never replace the original failed outcome. */}};
async function bootstrap(step,load){diagnostic.begin('runner',null,null,step);try{return await load();}catch{await writeFailure();throw failure();}}
const {createWindowsServiceActionsFixture,exerciseWindowsServiceActions,windowsServiceActionsRoute,windowsServiceActionsCaseName,windowsServiceActionsDisclosure,windowsServiceActionsFailureStage,requireWindowsServiceActionsEvidence}=await bootstrap('imports',()=>import('./windows-service-actions-browser.mjs'));
const {createWindowsUpdateJobsFixture,windowsUpdateJobsRoute,exerciseWindowsUpdateJobs,windowsUpdateJobsCaseName,windowsUpdateJobsDisclosure,windowsUpdateJobsFailureStage,requireWindowsUpdateJobsEvidence,requireWindowsUpdateWorklistDetails,windowsUpdateJobsOrigin}=await bootstrap('imports',()=>import('./windows-update-jobs-browser.mjs'));
const {createWindowsServiceActionHistoryFixture,windowsServiceActionHistoryRoute,exerciseWindowsServiceActionHistory,windowsServiceActionHistoryCaseName,requireWindowsServiceActionHistoryEvidence,windowsServiceActionHistoryFailureStage}=await bootstrap('imports',()=>import('./windows-service-action-history-browser.mjs'));
const {createWindowsUpdateScheduleFixture,windowsUpdateScheduleRoute,exerciseWindowsUpdateSchedule,windowsUpdateScheduleCaseName,windowsUpdateScheduleDisclosure,windowsUpdateScheduleFailureStage,requireWindowsUpdateScheduleEvidence,windowsBackgroundUpdateScheduleCaseName,windowsBackgroundUpdateScheduleDisclosure,requireWindowsBackgroundUpdateScheduleEvidence,createWindowsFleetUpdateScheduleFixture,exerciseWindowsFleetUpdateSchedule,windowsFleetUpdateScheduleCaseName,windowsFleetUpdateScheduleDisclosure,windowsFleetUpdateScheduleScenes,requireWindowsFleetUpdateScheduleEvidence,requireWindowsFleetUpdateScheduleDetails,windowsFleetUpdateScheduleFailureStep}=await bootstrap('imports',()=>import('./windows-update-schedule-browser.mjs'));
const {createWindowsSoftwareJobsFixture,windowsSoftwareJobsRoute,exerciseWindowsSoftwareJobs,windowsSoftwareJobsCaseName,windowsSoftwareJobsDisclosure,windowsSoftwareJobsFailureStage,requireWindowsSoftwareJobsEvidence,requireWindowsSoftwareJobsDetails}=await bootstrap('imports',()=>import('./windows-software-jobs-browser.mjs'));
const {createWindowsUpdateRetirementFixture,windowsUpdateRetirementRoute,exerciseWindowsUpdateRetirement,windowsUpdateRetirementCaseName,windowsUpdateRetirementDisclosure,windowsUpdateRetirementFailureStage,requireWindowsUpdateRetirementEvidence,requireWindowsUpdateRetirementDetails}=await bootstrap('imports',()=>import('./windows-update-retirement-browser.mjs'));
const {createWindowsUpdateDownloadFixture,windowsUpdateDownloadRoute,exerciseWindowsUpdateDownload,windowsUpdateDownloadCaseName,windowsUpdateDownloadDisclosure,windowsUpdateDownloadScenes,windowsUpdateDownloadFailureStage,requireWindowsUpdateDownloadEvidence,requireWindowsUpdateDownloadDetails}=await bootstrap('imports',()=>import('./windows-update-download-browser.mjs'));
const {capture:captureCompleteServiceHealth}=await bootstrap('imports',()=>import('../../web/scripts/capture-windows-complete-service-health.mjs'));
const {sceneManifestSHA256:completeServiceSceneDigest,evidenceSummary:completeServiceEvidenceSummary,assertHostedSource,validateManifest:validateCompleteServiceManifest}=await bootstrap('imports',()=>import('../../web/scripts/windows-complete-service-health-contract.mjs'));
const {capture:captureCompleteIncidentInbox}=await bootstrap('imports',()=>import('../../web/scripts/capture-windows-complete-incident-inbox.mjs'));
const {evidenceSummary:completeIncidentEvidenceSummary}=await bootstrap('imports',()=>import('../../web/scripts/windows-complete-incident-inbox-contract.mjs'));
const {capture:captureCompleteNotifications}=await bootstrap('imports',()=>import('../../web/scripts/capture-windows-complete-notifications.mjs'));
const {evidenceSummary:completeNotificationEvidenceSummary}=await bootstrap('imports',()=>import('../../web/scripts/windows-complete-notifications-contract.mjs'));
const {capture:captureCompleteServiceReview}=await bootstrap('imports',()=>import('../../web/scripts/capture-windows-complete-service-review.mjs'));
const {evidenceSummary:completeServiceReviewEvidenceSummary}=await bootstrap('imports',()=>import('../../web/scripts/windows-complete-service-review-contract.mjs'));
const {chromium,expect}=await bootstrap('dependencies',()=>require('@playwright/test'));
const temporary=await bootstrap('temporary',()=>fs.mkdtemp(path.join(os.tmpdir(),'tracebolt-windows-actions-browser-')));
const screenshots=[],historyScreenshots=[],updateScreenshots=[],variants=[],historyVariants=[],updateVariants=[];let browser,context,server,timer,errors=0,apiRequests=0,passed=false,completeServiceHealthManifest=null,completeIncidentInboxManifest=null,completeNotificationsManifest=null,completeServiceReviewManifest=null;
await fs.mkdir(out,{recursive:true});

async function shot(page,name,fixtureDisclosure){
 const restore=diagnostic.checkpoint('screenshot');
 const isDownload=windowsUpdateDownloadScenes.some(scene=>['en','de'].some(locale=>[1440,390].some(width=>name===`synthetic-windows-update-download-${scene}-${width}-${locale}`)));
 const isRetirement=/^synthetic-windows-update-retirement-review-(1440|390)-(en|de)$/.test(name);
 const isFleetSchedule=windowsFleetUpdateScheduleScenes.some(scene=>['en','de'].some(locale=>[1440,390].some(width=>name===`synthetic-windows-fleet-update-schedule-${scene}-${width}-${locale}`)));
 const isSoftware=/^synthetic-windows-software-jobs-(review|result)-(1440|390)-(en|de)$/.test(name);
 const isBackgroundSchedule=/^synthetic-windows-background-update-schedule-(status|review|pending|canceled)-(1440|390)-(en|de)$/.test(name);
 const isSchedule=/^synthetic-windows-update-schedule-(review|pending|canceled)-(1440|390)-(en|de)$/.test(name);
 const isUpdate=/^synthetic-windows-update-jobs-(review|result|worklist)-(1440|390)-(en|de)$/.test(name);
 if(isDownload?fixtureDisclosure!==windowsUpdateDownloadDisclosure:isRetirement?fixtureDisclosure!==windowsUpdateRetirementDisclosure:isFleetSchedule?fixtureDisclosure!==windowsFleetUpdateScheduleDisclosure:isBackgroundSchedule?fixtureDisclosure!==windowsBackgroundUpdateScheduleDisclosure:isSoftware?fixtureDisclosure!==windowsSoftwareJobsDisclosure:isSchedule?fixtureDisclosure!==windowsUpdateScheduleDisclosure:isUpdate?fixtureDisclosure!==windowsUpdateJobsDisclosure:!/^synthetic-windows-service-(actions|action-history)-(1440|390)-(en|de)$/.test(name)||fixtureDisclosure!==windowsServiceActionsDisclosure)throw failure();
 await page.screenshot({path:path.join(out,name+'.png'),fullPage:false,animations:'disabled'});
 const isHistory=name.startsWith('synthetic-windows-service-action-history-');
 (isDownload?downloadScreenshots:isRetirement?retirementScreenshots:isFleetSchedule?fleetScheduleScreenshots:isBackgroundSchedule?backgroundScheduleScreenshots:isSoftware?softwareScreenshots:isSchedule?scheduleScreenshots:isUpdate?updateScreenshots:isHistory?historyScreenshots:screenshots).push({file:name+'.png',sourceSha,publicSafe:true,fullPage:false,viewport:page.viewportSize(),locale:await page.locator('html').getAttribute('lang'),fixtureDisclosure,test:isDownload?windowsUpdateDownloadCaseName:isRetirement?windowsUpdateRetirementCaseName:isFleetSchedule?windowsFleetUpdateScheduleCaseName:isBackgroundSchedule?windowsBackgroundUpdateScheduleCaseName:isSoftware?windowsSoftwareJobsCaseName:isSchedule?windowsUpdateScheduleCaseName:isUpdate?windowsUpdateJobsCaseName:isHistory?windowsServiceActionHistoryCaseName:windowsServiceActionsCaseName});
 restore();
}
async function run(){
 diagnostic.begin('runner',null,null,'dist');
 if(!/^[a-f0-9]{40}$/.test(sourceSha??''))throw failure();
 await assertHostedSource(sourceSha);
 const realDist=await fs.realpath(dist);await fs.access(path.join(realDist,'index.html'));
 diagnostic.set('server');server=createServer(async(request,response)=>{
  try{
   const url=new URL(request.url,'http://127.0.0.1');
   if(url.pathname.startsWith('/api/')){apiRequests++;response.writeHead(503);response.end();return;}
   if(request.method!=='GET'||url.search){response.writeHead(404);response.end();return;}
   const file=await fs.realpath(path.join(realDist,url.pathname==='/'?'index.html':decodeURIComponent(url.pathname)));
   const contentTypes={'.html':'text/html','.js':'text/javascript','.css':'text/css','.woff':'font/woff','.woff2':'font/woff2','.svg':'image/svg+xml','.png':'image/png','.ico':'image/x-icon'};
   if(!file.startsWith(realDist+path.sep)||!contentTypes[path.extname(file)])throw failure();
   response.writeHead(200,{'Content-Type':contentTypes[path.extname(file)],'Cache-Control':'no-store'});response.end(await fs.readFile(file));
  }catch{response.writeHead(404);response.end();}
 });
 await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
 const base='http://127.0.0.1:'+server.address().port;
 // Uses the existing hosted runner convention, including its --no-sandbox flag.
 // No alternate executable, download route, installation or local bypass.
 diagnostic.set('launch');browser=await chromium.launch({headless:true,args:['--no-sandbox'],env:{...process.env,HOME:temporary,XDG_CONFIG_HOME:temporary,XDG_CACHE_HOME:temporary}});
 for(const locale of ['en','de'])for(const width of [1440,390]){
  diagnostic.begin('service-actions',locale,width,'fixture');
  const fixture=createWindowsServiceActionsFixture(),state={blocked:[],external:[]};
  diagnostic.set('context');context=await browser.newContext({viewport:{width,height:width===390?844:1000},locale:'en-GB'});const page=await context.newPage();page.on('pageerror',()=>errors++);
  await page.clock.install({time:new Date(fixture.now)});await page.clock.pauseAt(new Date(Date.parse(fixture.now)+100));
  await page.route('**/*',windowsServiceActionsRoute({base,fixture,state}));
  diagnostic.track(windowsServiceActionsFailureStage);
  const details=await exerciseWindowsServiceActions({page,expect,base,fixture,locale,width,shot});
  diagnostic.set('guards');expect(state.blocked).toEqual([]);expect(state.external).toEqual([]);expect(await context.cookies()).toEqual([]);
  const stored=await page.evaluate(()=>JSON.stringify({local:{...localStorage},session:{...sessionStorage}}));for(const value of [fixture.preview.preview.id,fixture.preview.preview.digest,fixture.session.csrfToken])expect(stored.includes(value)).toBe(false);
  variants.push({locale,width,...details});diagnostic.set('close');await context.close();context=null;
  diagnostic.begin('action-history',locale,width,'fixture');
  const historyFixture=createWindowsServiceActionHistoryFixture(),historyState={blocked:[],external:[]};
  diagnostic.set('context');context=await browser.newContext({viewport:{width,height:width===390?844:1000},locale:'en-GB'});const historyPage=await context.newPage();historyPage.on('pageerror',()=>errors++);
  await historyPage.clock.install({time:new Date(historyFixture.now)});await historyPage.clock.pauseAt(new Date(Date.parse(historyFixture.now)+100));
  await historyPage.route('**/*',windowsServiceActionHistoryRoute({base,fixture:historyFixture,state:historyState}));
  diagnostic.track(windowsServiceActionHistoryFailureStage);
  const historyDetails=await exerciseWindowsServiceActionHistory({page:historyPage,expect,base,fixture:historyFixture,locale,width,shot});
  diagnostic.set('guards');expect(historyState.blocked).toEqual([]);expect(historyState.external).toEqual([]);expect(await context.cookies()).toEqual([]);
  const historyStorage=await historyPage.evaluate(()=>JSON.stringify({local:{...localStorage},session:{...sessionStorage}}));for(const detail of historyFixture.details)expect(historyStorage.includes(detail.job.identity.jobId)).toBe(false);
  historyVariants.push({locale,width,...historyDetails});diagnostic.set('close');await context.close();context=null;
  diagnostic.begin('update-jobs',locale,width,'fixture');
  const updateFixture=createWindowsUpdateJobsFixture(),updateState={blocked:[],external:[]};
  diagnostic.set('context');context=await browser.newContext({viewport:{width,height:width===390?844:1000},locale:'en-GB'});const updatePage=await context.newPage();updatePage.on('pageerror',()=>errors++);
  await updatePage.clock.install({time:new Date(updateFixture.now)});await updatePage.clock.pauseAt(new Date(Date.parse(updateFixture.now)+100));
  // Virtual HTTPS document: every request is fulfilled or aborted before any
  // DNS/TLS/network activity. No certificate exception or browser bypass.
  await updatePage.route('**/*',windowsUpdateJobsRoute({base:windowsUpdateJobsOrigin,fixture:updateFixture,state:updateState,asset:async(route,pathname)=>{
   const file=await fs.realpath(path.join(realDist,pathname==='/'?'index.html':decodeURIComponent(pathname)));
   const contentTypes={'.html':'text/html','.js':'text/javascript','.css':'text/css','.woff':'font/woff','.woff2':'font/woff2','.svg':'image/svg+xml','.png':'image/png','.ico':'image/x-icon'};
   if(!file.startsWith(realDist+path.sep)||!contentTypes[path.extname(file)])throw failure();
   await route.fulfill({status:200,contentType:contentTypes[path.extname(file)],body:await fs.readFile(file)});
  }}));
  diagnostic.track(windowsUpdateJobsFailureStage);
  const updateDetails=await exerciseWindowsUpdateJobs({page:updatePage,expect,base:windowsUpdateJobsOrigin,fixture:updateFixture,locale,width,shot});
  diagnostic.set('guards');requireWindowsUpdateWorklistDetails(updateDetails);expect(updateFixture.secondPostAttempts).toEqual({request:0,preview:0,approve:0,other:0});
  expect(updateState.blocked).toEqual([]);expect(updateState.external).toEqual([]);expect(await context.cookies()).toEqual([]);
  const updateStorage=await updatePage.evaluate(()=>JSON.stringify({local:{...localStorage},session:{...sessionStorage}}));for(const value of [updateFixture.savedID(),updateFixture.secondSavedID,updateFixture.digest,updateFixture.session.csrfToken])expect(updateStorage.includes(value)).toBe(false);
  updateVariants.push({locale,width,...updateDetails});diagnostic.set('close');await context.close();context=null;
  diagnostic.begin('update-download',locale,width,'fixture');
  const downloadFixture=createWindowsUpdateDownloadFixture(),downloadState={blocked:[],external:[]};
  diagnostic.set('context');context=await browser.newContext({viewport:{width,height:width===390?844:1000},locale:'en-GB'});const downloadPage=await context.newPage();downloadPage.on('pageerror',()=>errors++);
  await downloadPage.clock.install({time:new Date(downloadFixture.now)});await downloadPage.clock.pauseAt(new Date(Date.parse(downloadFixture.now)+100));
  await downloadPage.route('**/*',windowsUpdateDownloadRoute({base:windowsUpdateJobsOrigin,fixture:downloadFixture,state:downloadState,asset:async(route,pathname)=>{
   const file=await fs.realpath(path.join(realDist,pathname==='/'?'index.html':decodeURIComponent(pathname)));
   const contentTypes={'.html':'text/html','.js':'text/javascript','.css':'text/css','.woff':'font/woff','.woff2':'font/woff2','.svg':'image/svg+xml','.png':'image/png','.ico':'image/x-icon'};
   if(!file.startsWith(realDist+path.sep)||!contentTypes[path.extname(file)])throw failure();
   await route.fulfill({status:200,contentType:contentTypes[path.extname(file)],body:await fs.readFile(file)});
  }}));
  diagnostic.track(windowsUpdateDownloadFailureStage);
  const downloadDetails=await exerciseWindowsUpdateDownload({page:downloadPage,expect,base:windowsUpdateJobsOrigin,fixture:downloadFixture,locale,width,shot});diagnostic.set('guards');requireWindowsUpdateDownloadDetails(downloadDetails);
  expect(downloadState.blocked).toEqual([]);expect(downloadState.external).toEqual([]);expect(await context.cookies()).toEqual([]);
  const downloadStorage=await downloadPage.evaluate(()=>JSON.stringify({local:{...localStorage},session:{...sessionStorage}}));for(const value of [downloadFixture.downloadID(),downloadFixture.session.csrfToken])expect(downloadStorage.includes(value)).toBe(false);
  downloadVariants.push({locale,width,...downloadDetails});diagnostic.set('close');await context.close();context=null;
  diagnostic.begin('update-retirement',locale,width,'fixture');
  const retirementFixture=createWindowsUpdateRetirementFixture(),retirementState={blocked:[],external:[]};
  diagnostic.set('context');context=await browser.newContext({viewport:{width,height:width===390?844:1000},locale:'en-GB'});const retirementPage=await context.newPage();retirementPage.on('pageerror',()=>errors++);
  await retirementPage.clock.install({time:new Date(retirementFixture.now)});await retirementPage.clock.pauseAt(new Date(Date.parse(retirementFixture.now)+100));
  await retirementPage.route('**/*',windowsUpdateRetirementRoute({base:windowsUpdateJobsOrigin,fixture:retirementFixture,state:retirementState,asset:async(route,pathname)=>{
   const file=await fs.realpath(path.join(realDist,pathname==='/'?'index.html':decodeURIComponent(pathname)));
   const contentTypes={'.html':'text/html','.js':'text/javascript','.css':'text/css','.woff':'font/woff','.woff2':'font/woff2','.svg':'image/svg+xml','.png':'image/png','.ico':'image/x-icon'};
   if(!file.startsWith(realDist+path.sep)||!contentTypes[path.extname(file)])throw failure();
   await route.fulfill({status:200,contentType:contentTypes[path.extname(file)],body:await fs.readFile(file)});
  }}));
  diagnostic.track(windowsUpdateRetirementFailureStage);
  const retirementDetails=await exerciseWindowsUpdateRetirement({page:retirementPage,expect,base:windowsUpdateJobsOrigin,fixture:retirementFixture,locale,width,shot});diagnostic.set('guards');requireWindowsUpdateRetirementDetails(retirementDetails);
  expect(retirementState.blocked).toEqual([]);expect(retirementState.external).toEqual([]);expect(await context.cookies()).toEqual([]);
  const retirementStorage=await retirementPage.evaluate(()=>JSON.stringify({local:{...localStorage},session:{...sessionStorage}}));for(const value of [retirementFixture.retirementID,retirementFixture.retirementBody.resultDigest,retirementFixture.session.csrfToken])expect(retirementStorage.includes(value)).toBe(false);
  retirementVariants.push({locale,width,...retirementDetails});diagnostic.set('close');await context.close();context=null;
  // Both fresh profiles use the same bounded controller; earlier cases remain.
  for(const scheduleProfile of ['standalone','background']){
  diagnostic.begin(scheduleProfile==='background'?'background-schedule':'update-schedule',locale,width,'fixture');
  const scheduleFixture=createWindowsUpdateScheduleFixture(scheduleProfile),scheduleState={blocked:[],external:[]};
  diagnostic.set('context');context=await browser.newContext({viewport:{width,height:width===390?844:1000},locale:'en-GB'});const schedulePage=await context.newPage();schedulePage.on('pageerror',()=>errors++);
  await schedulePage.clock.install({time:new Date(scheduleFixture.now)});await schedulePage.clock.pauseAt(new Date(Date.parse(scheduleFixture.now)+100));
  await schedulePage.route('**/*',windowsUpdateScheduleRoute({base:windowsUpdateJobsOrigin,fixture:scheduleFixture,state:scheduleState,asset:async(route,pathname)=>{
   const file=await fs.realpath(path.join(realDist,pathname==='/'?'index.html':decodeURIComponent(pathname)));
   const contentTypes={'.html':'text/html','.js':'text/javascript','.css':'text/css','.woff':'font/woff','.woff2':'font/woff2','.svg':'image/svg+xml','.png':'image/png','.ico':'image/x-icon'};
   if(!file.startsWith(realDist+path.sep)||!contentTypes[path.extname(file)])throw failure();
   await route.fulfill({status:200,contentType:contentTypes[path.extname(file)],body:await fs.readFile(file)});
  }}));
  diagnostic.track(windowsUpdateScheduleFailureStage);
  const scheduleDetails=await exerciseWindowsUpdateSchedule({page:schedulePage,expect,base:windowsUpdateJobsOrigin,fixture:scheduleFixture,locale,width,shot});
  diagnostic.set('guards');expect(scheduleState.blocked).toEqual([]);expect(scheduleState.external).toEqual([]);expect(await context.cookies()).toEqual([]);
  const scheduleStorage=await schedulePage.evaluate(()=>JSON.stringify({local:{...localStorage},session:{...sessionStorage}}));for(const value of [scheduleFixture.savedID(),scheduleFixture.digest,scheduleFixture.scheduleDigest,scheduleFixture.session.csrfToken])expect(scheduleStorage.includes(value)).toBe(false);
  if(scheduleProfile==='background'){expect(scheduleDetails.backgroundScheduling).toBe(true);expect(scheduleDetails.compactBackgroundStatus).toBe(true);expect(scheduleDetails.separateManualApproval).toBe(true);backgroundScheduleVariants.push({locale,width,...scheduleDetails});}else scheduleVariants.push({locale,width,...scheduleDetails});diagnostic.set('close');await context.close();context=null;
  }
  // Three compact cached-triage/common-window scenes reuse the same intercepted controller,
  // installed browser, original clock/session bounds and screenshot helper.
  diagnostic.begin('fleet-schedule',locale,width,'fixture');
  const fleetFixture=createWindowsFleetUpdateScheduleFixture(),fleetState={blocked:[],external:[]};
  diagnostic.set('context');context=await browser.newContext({viewport:{width,height:width===390?844:1000},locale:'en-GB'});const fleetPage=await context.newPage();fleetPage.on('pageerror',()=>errors++);
  await fleetPage.clock.install({time:new Date(fleetFixture.now)});await fleetPage.clock.pauseAt(new Date(Date.parse(fleetFixture.now)+100));
  await fleetPage.route('**/*',windowsUpdateScheduleRoute({base:windowsUpdateJobsOrigin,fixture:fleetFixture,state:fleetState,asset:async(route,pathname)=>{
   const file=await fs.realpath(path.join(realDist,pathname==='/'?'index.html':decodeURIComponent(pathname)));
   const contentTypes={'.html':'text/html','.js':'text/javascript','.css':'text/css','.woff':'font/woff','.woff2':'font/woff2','.svg':'image/svg+xml','.png':'image/png','.ico':'image/x-icon'};
   if(!file.startsWith(realDist+path.sep)||!contentTypes[path.extname(file)])throw failure();
   await route.fulfill({status:200,contentType:contentTypes[path.extname(file)],body:await fs.readFile(file)});
  }}));
  diagnostic.track(windowsFleetUpdateScheduleFailureStep);
  const fleetDetails=await exerciseWindowsFleetUpdateSchedule({page:fleetPage,expect,base:windowsUpdateJobsOrigin,fixture:fleetFixture,locale,width,shot});diagnostic.set('guards');requireWindowsFleetUpdateScheduleDetails(fleetDetails);
  expect(fleetState.blocked).toEqual([]);expect(fleetState.external).toEqual([]);expect(await context.cookies()).toEqual([]);
  const fleetStorage=await fleetPage.evaluate(()=>JSON.stringify({local:{...localStorage},session:{...sessionStorage}}));for(const value of [fleetFixture.savedID(),fleetFixture.secondSavedID,fleetFixture.digest,fleetFixture.scheduleDigest,fleetFixture.session.csrfToken])expect(fleetStorage.includes(value)).toBe(false);
  fleetScheduleVariants.push({locale,width,...fleetDetails});diagnostic.set('close');await context.close();context=null;
  // Additive prepared-package case; every earlier capture and behavioral gate remains.
  diagnostic.begin('software-jobs',locale,width,'fixture');
  const softwareFixture=createWindowsSoftwareJobsFixture(),softwareState={blocked:[],external:[]};
  diagnostic.set('context');context=await browser.newContext({viewport:{width,height:width===390?844:1000},locale:'en-GB'});const softwarePage=await context.newPage();softwarePage.on('pageerror',()=>errors++);
  await softwarePage.clock.install({time:new Date(softwareFixture.now)});await softwarePage.clock.pauseAt(new Date(Date.parse(softwareFixture.now)+100));
  await softwarePage.route('**/*',windowsSoftwareJobsRoute({base:windowsUpdateJobsOrigin,fixture:softwareFixture,state:softwareState,asset:async(route,pathname)=>{
   const file=await fs.realpath(path.join(realDist,pathname==='/'?'index.html':decodeURIComponent(pathname)));
   const contentTypes={'.html':'text/html','.js':'text/javascript','.css':'text/css','.woff':'font/woff','.woff2':'font/woff2','.svg':'image/svg+xml','.png':'image/png','.ico':'image/x-icon'};
   if(!file.startsWith(realDist+path.sep)||!contentTypes[path.extname(file)])throw failure();
   await route.fulfill({status:200,contentType:contentTypes[path.extname(file)],body:await fs.readFile(file)});
  }}));
  diagnostic.track(windowsSoftwareJobsFailureStage);
  const softwareDetails=await exerciseWindowsSoftwareJobs({page:softwarePage,expect,base:windowsUpdateJobsOrigin,fixture:softwareFixture,locale,width,shot});
  diagnostic.set('guards');requireWindowsSoftwareJobsDetails(softwareDetails);expect(softwareFixture.softwareAttempts).toEqual({request:1,preview:1,approve:1});expect(softwareFixture.softwareCounts.unexpectedInstallWrites).toBe(0);expect(softwareFixture.softwareCounts.secondTargetWrites).toBe(0);
  expect(softwareState.blocked).toEqual([]);expect(softwareState.external).toEqual([]);expect(await context.cookies()).toEqual([]);
  const softwareStorage=await softwarePage.evaluate(()=>JSON.stringify({local:{...localStorage},session:{...sessionStorage}}));for(const value of [softwareFixture.softwareSavedID(),softwareFixture.softwareDigest,softwareFixture.softwareSelection.sha256,softwareFixture.session.csrfToken])expect(softwareStorage.includes(value)).toBe(false);
  softwareVariants.push({locale,width,...softwareDetails});diagnostic.set('close');await context.close();context=null;


 }
 diagnostic.begin('runner',null,null,'complete-service-health');
 // Additive component/hook evidence, not a whole-App scenario; reuse this browser.
 completeServiceHealthManifest=await captureCompleteServiceHealth({browser,expect,output:out});
 Object.assign(completeServiceHealthManifest,{sourceSha,sceneManifestSHA256:completeServiceSceneDigest});
 for(const row of completeServiceHealthManifest.captures)Object.assign(row,{sourceSha,publicSafe:true,fullPage:false});
 await assertHostedSource(sourceSha,completeServiceHealthManifest.sourceInputs);
 await validateCompleteServiceManifest(out,sourceSha,completeServiceHealthManifest);
 await fs.writeFile(path.join(out,'windows-complete-service-health-manifest.json'),JSON.stringify(completeServiceHealthManifest,null,2)+'\n');
 diagnostic.begin('runner',null,null,'complete-incident-inbox');
 completeIncidentInboxManifest=await captureCompleteIncidentInbox({browser,expect,output:out,sourceSha});
 await fs.writeFile(path.join(out,'windows-complete-incident-inbox-manifest.json'),JSON.stringify(completeIncidentInboxManifest,null,2)+'\n');
 diagnostic.begin('runner',null,null,'complete-notifications');
 completeNotificationsManifest=await captureCompleteNotifications({browser,expect,output:out,sourceSha});
 await fs.writeFile(path.join(out,'windows-complete-notifications-manifest.json'),JSON.stringify(completeNotificationsManifest,null,2)+'\n');
 diagnostic.begin('runner',null,null,'complete-service-review');
 completeServiceReviewManifest=await captureCompleteServiceReview({browser,expect,output:out,sourceSha});
 await fs.writeFile(path.join(out,'windows-complete-service-review-manifest.json'),JSON.stringify(completeServiceReviewManifest,null,2)+'\n');
 diagnostic.begin('runner',null,null,'evidence');
 requireWindowsUpdateDownloadEvidence(downloadScreenshots,sourceSha);if(downloadVariants.length!==4)throw failure();
 requireWindowsUpdateRetirementEvidence(retirementScreenshots,sourceSha);if(retirementVariants.length!==4)throw failure();
 requireWindowsServiceActionsEvidence(screenshots,sourceSha);requireWindowsServiceActionHistoryEvidence(historyScreenshots,sourceSha);if(errors||apiRequests||variants.length!==4)throw failure();if(historyVariants.length!==4)throw failure();requireWindowsUpdateJobsEvidence(updateScreenshots,sourceSha);if(updateVariants.length!==4)throw failure();requireWindowsUpdateScheduleEvidence(scheduleScreenshots,sourceSha);if(scheduleVariants.length!==4)throw failure();requireWindowsBackgroundUpdateScheduleEvidence(backgroundScheduleScreenshots,sourceSha);if(backgroundScheduleVariants.length!==4)throw failure();requireWindowsFleetUpdateScheduleEvidence(fleetScheduleScreenshots,sourceSha);if(fleetScheduleVariants.length!==4)throw failure();requireWindowsSoftwareJobsEvidence(softwareScreenshots,sourceSha);if(softwareVariants.length!==4)throw failure();
}
try{await Promise.race([run(),new Promise((_,reject)=>{timer=setTimeout(()=>reject(failure()),120000);})]);passed=true;}
catch{await writeFailure();console.log('FAIL: synthetic Windows action browser gate; raw diagnostics withheld.');}
finally{
 clearTimeout(timer);try{if(context)await context.close();}catch{if(passed)diagnostic.begin('runner',null,null,'close-context');passed=false;}try{if(browser)await browser.close();}catch{if(passed)diagnostic.begin('runner',null,null,'close-browser');passed=false;}
 if(server){try{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}catch{if(passed)diagnostic.begin('runner',null,null,'close-server');passed=false;}}
 if(!passed)await writeFailure();
 const report={sourceSha,createdAt:new Date().toISOString(),name:windowsServiceActionsCaseName,status:passed?'PASS':'FAIL',stage:windowsServiceActionsFailureStage(),scope:windowsServiceActionsDisclosure,variants:passed?variants:[],historyVariants:passed?historyVariants:[],updateVariants:passed?updateVariants:[],downloadVariants:passed?downloadVariants:[],downloadScope:windowsUpdateDownloadDisclosure,downloadStage:windowsUpdateDownloadFailureStage(),retirementVariants:passed?retirementVariants:[],retirementScope:windowsUpdateRetirementDisclosure,retirementStage:windowsUpdateRetirementFailureStage(),updateScope:windowsUpdateJobsDisclosure,updateStage:windowsUpdateJobsFailureStage(),scheduleVariants:passed?scheduleVariants:[],scheduleScope:windowsUpdateScheduleDisclosure,scheduleStage:windowsUpdateScheduleFailureStage(),backgroundScheduleVariants:passed?backgroundScheduleVariants:[],backgroundScheduleScope:windowsBackgroundUpdateScheduleDisclosure,fleetScheduleVariants:passed?fleetScheduleVariants:[],fleetScheduleScope:windowsFleetUpdateScheduleDisclosure,softwareVariants:passed?softwareVariants:[],softwareScope:windowsSoftwareJobsDisclosure,softwareStage:windowsSoftwareJobsFailureStage(),completeServiceHealth:passed?completeServiceEvidenceSummary():null,completeIncidentInbox:passed?completeIncidentEvidenceSummary():null,completeNotifications:passed?completeNotificationEvidenceSummary():null,completeServiceReview:passed?completeServiceReviewEvidenceSummary():null,runtimeErrorCount:errors,requestsToRealAPI:apiRequests,browserAcceptance:passed,durableStoreAcceptance:false,nativeAcceptance:false,secretsExported:false,realTelemetryExported:false};
 try{await fs.writeFile(path.join(out,'windows-service-actions-results.json'),JSON.stringify(report,null,2));await fs.writeFile(path.join(out,'windows-service-actions-manifest.json'),JSON.stringify({sourceSha,screenshots:[...screenshots,...historyScreenshots,...updateScreenshots,...retirementScreenshots,...downloadScreenshots,...scheduleScreenshots,...softwareScreenshots,...backgroundScheduleScreenshots,...fleetScheduleScreenshots]},null,2));}catch{if(passed)diagnostic.begin('runner',null,null,'report');passed=false;await writeFailure();throw failure();}
 await fs.rm(temporary,{recursive:true,force:true});process.exitCode=passed?0:1;
}
