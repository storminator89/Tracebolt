import {isDeepStrictEqual} from 'node:util';
import {validApplicationCheckSettings} from '../../web/src/application-check-settings-types.ts';

export const applicationCheckSettingsCaseName='Synthetic application check setup saves inert drafts and requires exact manager-origin enable consent';
export const applicationCheckSettingsFixtureDisclosure='Rendered production UI with real loopback HTTP-test fixture login and exact same-origin intercepted invented application-check settings. In-memory fixture only: no real configuration persistence, target probe, DNS request, TCP connection or permission grant. Named-role display DTOs are synthetic; real backend permission, persistence and lifecycle checks have separate Go tests.';
export const applicationCheckSettingsFixtureTargets=[
 {kind:'http',id:'fixture-web',url:'https://fixture-check.invalid/health',allowedAddresses:['10.20.30.40'],allowPrivateLAN:true,plaintextHTTPAcknowledged:false},
 {kind:'tcp',id:'fixture-port',host:'fixture-check.invalid',port:443,allowedAddresses:['10.20.30.40'],allowPrivateLAN:true},
];
export const applicationCheckSettingsEditedTargets=applicationCheckSettingsFixtureTargets.map(target=>target.kind==='tcp'?{...target,port:8443}:structuredClone(target));
const exact=(value,keys)=>!!value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join(',')===[...keys].sort().join(',');
function requireFixture(condition){if(!condition)throw new Error('Unsupported synthetic application-check settings request');}

/** In-memory receiver; every target must be an exact invented fixture. Never invokes an API or probe. */
export function createApplicationCheckSettingsFixture() {
 let current={schemaVersion:'tracebolt.application-check-settings.v1',mode:'managed',revision:'a'.repeat(32),configured:false,enabled:false,blocked:false,intervalSeconds:60,targets:[]};
 const counts={reads:0,saves:0,enables:0,disables:0};let generation=10;const revision=()=> (++generation).toString(16).padStart(32,'0');
 const settings=()=>{requireFixture(validApplicationCheckSettings(current));return structuredClone(current);};
 const handle=(method,pathname,data)=>{
  requireFixture(pathname==='/api/application-checks/settings');
  if(method==='GET'){requireFixture(data===null);counts.reads++;return settings();}
  requireFixture(method==='POST'&&data?.expectedRevision===current.revision);
  if(data.operation==='save'){
   requireFixture(exact(data,['expectedRevision','operation','intervalSeconds','targets'])&&data.intervalSeconds===75&&isDeepStrictEqual(data.targets,counts.saves===0?applicationCheckSettingsFixtureTargets:applicationCheckSettingsEditedTargets));
   current={...current,configured:true,enabled:false,revision:revision(),intervalSeconds:75,targets:structuredClone(data.targets)};counts.saves++;
  }else if(data.operation==='enable'){
   requireFixture(exact(data,['expectedRevision','operation','checksFromManagerAcknowledged','destinationsAcknowledged','plaintextAcknowledged'])&&current.configured&&!current.enabled&&data.checksFromManagerAcknowledged===true&&data.destinationsAcknowledged===true&&data.plaintextAcknowledged===true);
   current={...current,enabled:true,revision:revision()};counts.enables++;
  }else{
   requireFixture(exact(data,['expectedRevision','operation'])&&data.operation==='disable'&&current.configured&&current.enabled);
   current={...current,enabled:false,revision:revision()};counts.disables++;
  }
  return settings();
 };
 return {counts,settings,handle};
}

export async function applicationCheckSettingsBrowserCase({pageAt,login,expect,base,shot}) {
 const page=await pageAt('/settings'),clockStart=Date.now();
 await page.clock.install({time:new Date(clockStart)});await page.clock.pauseAt(new Date(clockStart+10000));
 const fixture=createApplicationCheckSettingsFixture(),requests=[],unexpected=[],external=[];let namedCapabilities=null;
 await page.route('**/*',async route=>{
  const request=route.request(),url=new URL(request.url()),method=request.method();
  if(url.origin!==base){external.push(url.origin);return route.abort('blockedbyclient');}
  if(!['GET','POST'].includes(method)){unexpected.push(`${method} ${url.pathname}`);return route.abort('blockedbyclient');}
  if(namedCapabilities&&method==='GET'&&url.pathname==='/api/auth/session'){
   const response=await route.fetch(),session=await response.json();requireFixture(session.authenticated===true);
   return route.fulfill({response,json:{...session,loginMode:'named',actorId:'operator_'+ '1'.repeat(32),capabilities:namedCapabilities}});
  }
  if(url.pathname.startsWith('/api/application-checks')){
   if(url.pathname!=='/api/application-checks/settings'||url.search){unexpected.push('Unexpected application-check route');return route.abort('blockedbyclient');}
   requests.push(`${method} ${url.pathname}`);
   try{
    const data=method==='GET'?null:request.postDataJSON();
    if(method==='GET')requireFixture(request.postData()===null);
    else{const headers=await request.allHeaders();requireFixture(headers['content-type']==='application/json'&&typeof headers['x-csrf-token']==='string'&&headers['x-csrf-token'].length>0);}
    return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(fixture.handle(method,url.pathname,data))});
   }catch{unexpected.push('Invalid synthetic application-check settings request');return route.abort('blockedbyclient');}
  }
  if(method==='POST'&&url.pathname!=='/api/auth/login'){unexpected.push(`Unexpected POST ${url.pathname}`);return route.abort('blockedbyclient');}
  return route.continue();
 });
 await expect(page.getByRole('heading',{name:'Sign in',exact:true})).toBeVisible();expect(fixture.counts.reads).toBe(0);await login(page);
 const panel=page.locator('.application-check-settings');
 const toggle=()=>panel.getByRole('button',{name:'Application check setup',exact:true});
 await expect(panel).toBeVisible();await expect.poll(()=>fixture.counts.reads).toBe(1);
 await toggle().click();await panel.getByRole('button',{name:'Add targets',exact:true}).click();
 await panel.getByLabel('Interval (seconds)',{exact:true}).fill('75');
 await panel.getByLabel('Target ID',{exact:true}).fill('fixture-web');
 await panel.getByLabel('URL',{exact:true}).fill(applicationCheckSettingsFixtureTargets[0].url);
 await panel.getByLabel('Allowed IP addresses',{exact:true}).fill('10.20.30.40');
 // The form's per-target consent remains a distinct unchecked control.
 await panel.locator('input[type=checkbox]').check();
 await panel.getByRole('button',{name:'Add target',exact:true}).click();
 await panel.getByLabel('Target ID',{exact:true}).nth(1).fill('fixture-port');
 await panel.getByLabel('Type',{exact:true}).nth(1).selectOption('tcp');
 await panel.getByLabel('Hostname or IP address',{exact:true}).fill('fixture-check.invalid');
 await panel.getByLabel('Port',{exact:true}).fill('443');
 await panel.getByLabel('Allowed IP addresses',{exact:true}).nth(1).fill('10.20.30.40');
 await panel.locator('input[type=checkbox]').last().check();
 await panel.scrollIntoViewIfNeeded();await shot(page,'synthetic-http-test-application-setup-draft-desktop-en',applicationCheckSettingsFixtureDisclosure);
 expect(fixture.counts.saves).toBe(0);expect(fixture.counts.enables).toBe(0);
 await panel.getByRole('button',{name:'Save draft',exact:true}).click();await expect.poll(()=>fixture.counts.saves).toBe(1);expect(fixture.settings().enabled).toBe(false);
 await panel.getByRole('button',{name:'Edit targets',exact:true}).click();
 await expect(panel.getByLabel('URL',{exact:true})).toHaveValue(applicationCheckSettingsFixtureTargets[0].url);
 await panel.getByLabel('Port',{exact:true}).fill('8443');
 for(const checkbox of await panel.getByRole('checkbox').all()){await expect(checkbox).not.toBeChecked();await checkbox.check();}
 await panel.getByRole('button',{name:'Save draft',exact:true}).click();await expect.poll(()=>fixture.counts.saves).toBe(2);
 expect(fixture.settings().enabled).toBe(false);expect(fixture.settings().targets[1].port).toBe(8443);
 await panel.getByRole('button',{name:'Enable checks',exact:true}).click();
 const confirm=panel.getByRole('button',{name:'Confirm enable',exact:true});await expect(confirm).toBeDisabled();
 await expect(panel).toContainText(applicationCheckSettingsFixtureTargets[0].url);await expect(panel).toContainText('10.20.30.40');await expect(panel).toContainText('8443');
 for(const checkbox of await panel.getByRole('checkbox').all())await expect(checkbox).not.toBeChecked();
 await panel.getByRole('button',{name:'Cancel',exact:true}).click();expect(fixture.counts.enables).toBe(0);
 await panel.getByRole('button',{name:'Enable checks',exact:true}).click();await expect(confirm).toBeDisabled();
 const acknowledgements=panel.getByRole('checkbox');await expect(acknowledgements).toHaveCount(3);
 for(const checkbox of await acknowledgements.all())await checkbox.check();
 await page.setViewportSize({width:390,height:844});await panel.scrollIntoViewIfNeeded();
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth&&document.body.scrollWidth<=innerWidth)).toBe(true);
 await shot(page,'synthetic-http-test-application-setup-enable-mobile-en',applicationCheckSettingsFixtureDisclosure);
 await confirm.click();await expect.poll(()=>fixture.counts.enables).toBe(1);
 await panel.getByRole('button',{name:'Disable checks',exact:true}).click();await panel.getByRole('button',{name:'Confirm disable',exact:true}).click();await expect.poll(()=>fixture.counts.disables).toBe(1);
 expect(fixture.settings().enabled).toBe(false);expect(fixture.settings().configured).toBe(true);
 await page.getByLabel('Language',{exact:true}).selectOption('de');await expect(page.locator('html')).toHaveAttribute('lang','de');
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth&&document.body.scrollWidth<=innerWidth)).toBe(true);
 await panel.scrollIntoViewIfNeeded();await shot(page,'synthetic-http-test-application-setup-disabled-mobile-de',applicationCheckSettingsFixtureDisclosure);
 expect(await page.evaluate(()=>JSON.stringify({local:{...localStorage},session:{...sessionStorage}}).includes('fixture-check.invalid'))).toBe(false);
 // Named-role UI behavior only; actual server permission denial is covered by Go.
 const beforeReadOnly=fixture.counts.reads;namedCapabilities=['read'];await page.reload();
 const rolePanel=page.locator('.check-settings');await expect(rolePanel).toContainText('Die Einrichtung von Anwendungsprüfungen erfordert Administratorrechte.');
 await expect(rolePanel.locator('input,button,textarea,.check-settings-snapshot')).toHaveCount(0);
 await expect(page.locator('body')).not.toContainText('fixture-check.invalid');expect(fixture.counts.reads).toBe(beforeReadOnly);
 namedCapabilities=['read','manage_application_checks'];await page.reload();await expect.poll(()=>fixture.counts.reads).toBe(beforeReadOnly+1);
 await panel.getByRole('button',{name:'Anwendungsprüfungen einrichten',exact:true}).click();
 await expect(panel.getByRole('button',{name:'Ziele bearbeiten',exact:true})).toBeVisible();
 await expect(panel).toContainText('fixture-check.invalid');
 expect(unexpected).toEqual([]);expect(external).toEqual([]);expect(requests.filter(value=>value.startsWith('POST'))).toHaveLength(4);
}
