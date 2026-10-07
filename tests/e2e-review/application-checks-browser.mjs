import {conciseCopy} from './concise-copy-contracts.mjs';
/** Invented retained DTOs only; no application target, probe or configuration. */
let stage='setup';
export const applicationChecksFailureStage=()=>stage;
const mark=value=>{stage=value;};
export const applicationFixtureDisclosure = 'Real fixture login with explicitly intercepted invented application-status DTOs; retained HTTP result and previously verified leaf expiry are shown separately; no actual management-server target probes, new TLS handshake or native acceptance';

export function applicationStatusFixture() {
 const serverNow='2026-10-06T12:00:00Z', observedAt='2026-10-06T11:58:55Z';
 const row=(id,patch={})=>({id,targetScheme:'https',state:'ok',reason:'http_2xx',observedAt,httpStatus:204,tls:{state:'expiring',expiresAt:'2026-10-13T12:00:00Z'},...patch});
 const items=[
  row('fixture-expiring'),
  row('fixture-http-error',{state:'http_error',reason:'http_status',httpStatus:503,tls:{state:'valid',expiresAt:'2026-12-01T12:00:00Z'}}),
  // The leaf was unexpired at the original observation, then expired before
  // this retained status read. This never claims verification of an expired leaf.
  row('fixture-retained-expired',{tls:{state:'expired',expiresAt:'2026-10-06T11:59:55Z'}}),
  row('fixture-unverified',{state:'tls_error',reason:'tls_verification_failed',httpStatus:null,tls:{state:'unknown',expiresAt:null}}),
 ];
 return {schemaVersion:'tracebolt.application-checks.v1',enabled:true,vantage:'management_server',serverNow,intervalSeconds:60,maxAgeSeconds:60+(items.length+1)*5,items};
}

/** Additional invented retained rows; deliberately no hostnames, addresses or ports. */
export function applicationHTTPStatusFixture() {
 const view=applicationStatusFixture();
 const items=[view.items[0],{...view.items[0],id:'fixture-plaintext',targetScheme:'http',tls:{state:'not_applicable',expiresAt:null}}];
 return {...view,items,intervalSeconds:75,maxAgeSeconds:75+(items.length+1)*5};
}
export function applicationMixedStatusFixture() {
 const view=applicationStatusFixture(), observedAt=view.items[0].observedAt;
 const items=[
  {kind:'dns',id:'fixture-dns',state:'ok',reason:'dns_resolved',observedAt},
  {kind:'tcp',id:'fixture-tcp',state:'ok',reason:'tcp_connected',observedAt},
  {...view.items[0],kind:'http'},
 ];
 return {...view,schemaVersion:'tracebolt.application-checks.v2',items,intervalSeconds:75,maxAgeSeconds:75+(items.length+1)*5};
}

/** Check actual hosted-browser geometry, including the table's own clipping. */
async function applicationRowLayout({page,panel,expect,fixture,mobile}) {
 const table=panel.locator('table'), wrapper=panel.locator('.application-checks-table');
 const columnNames=['Application',fixture.schemaVersion.endsWith('.v2')?'Result':'HTTP result','Leaf certificate','Observed'];
 const columns=table.getByRole('columnheader');await expect(columns).toHaveCount(4);
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth&&document.body.scrollWidth<=innerWidth)).toBe(true);
 expect(await wrapper.evaluate(el=>el.scrollWidth<=el.clientWidth+1&&el.scrollLeft===0)).toBe(true);
 for(const item of fixture.items){
  const row=table.locator('tbody tr').filter({has:page.getByText(item.id,{exact:true})});
  await row.scrollIntoViewIfNeeded();
  const header=row.getByRole('rowheader'), cells=row.getByRole('cell');await expect(cells).toHaveCount(3);
  await expect(header).toHaveAttribute('scope','row');await expect(header).toHaveAttribute('headers','application-checks-application');
  await expect(header).toBeInViewport({ratio:1});
  const headerBox=await header.boundingBox();expect(headerBox).not.toBe(null);
  let previous=headerBox;
  for(let i=0;i<3;i++){
   const cell=cells.nth(i), label=cell.locator('.application-mobile-label'), value=cell.locator('.application-cell-value');
   await expect(cell).toHaveAttribute('headers',`${await header.getAttribute('id')} ${await columns.nth(i+1).getAttribute('id')}`);
   await expect(label).toHaveText(columnNames[i+1]);await expect(label).toHaveAttribute('aria-hidden','true');
   await expect(value).toBeVisible();await expect(value).toBeInViewport({ratio:1});
   const cellBox=await cell.boundingBox(),valueBox=await value.boundingBox();expect(cellBox).not.toBe(null);expect(valueBox).not.toBe(null);
   expect(valueBox.x).toBeGreaterThanOrEqual(0);expect(valueBox.x+valueBox.width).toBeLessThanOrEqual(page.viewportSize().width+1);
   if(mobile){
    await expect(label).toBeVisible();await expect(label).toBeInViewport({ratio:1});
    const labelBox=await label.boundingBox();expect(labelBox.x+labelBox.width).toBeLessThanOrEqual(valueBox.x+1);
    expect(cellBox.y).toBeGreaterThanOrEqual(previous.y+previous.height-1);
   }else{
    await expect(label).toBeHidden();await expect(columns.nth(i+1)).toBeVisible();
    const columnBox=await columns.nth(i+1).boundingBox();expect(Math.abs(cellBox.x-columnBox.x)).toBeLessThanOrEqual(1);
    expect(Math.abs(cellBox.width-columnBox.width)).toBeLessThanOrEqual(1);expect(Math.abs(cellBox.y-headerBox.y)).toBeLessThanOrEqual(1);
    expect(cellBox.x).toBeGreaterThanOrEqual(previous.x+previous.width-1);
   }
   previous=cellBox;
  }
  for(const value of await row.locator('.application-result,time').all()){
   await expect(value).toBeVisible();await expect(value).toBeInViewport({ratio:1});
  }
  await expect(row.locator('td:last-child time')).toHaveAttribute('datetime',item.observedAt);
  expect(await wrapper.evaluate(el=>el.scrollWidth<=el.clientWidth+1&&el.scrollLeft===0)).toBe(true);
 }
}

/** Uses the existing LAN runner's real login, context, screenshot and cleanup. */
export async function applicationChecksBrowserCase({pageAt,login,expect,base,shot}) {
 mark('setup');
 const page=await pageAt('/overview');await page.clock.install({time:new Date()});
 const fixture=applicationStatusFixture(), statusPath='/api/application-checks/status';
 let reads=0,phase='retained',activeFixture=fixture;const mutations=[],applicationRequests=[];
 page.on('request',request=>{
  const url=new URL(request.url()),method=request.method();
  if(url.origin!==base||!url.pathname.startsWith('/api/'))return;
  // Login is the only authorized fixture mutation. Record only method/path,
  // never credentials, cookies, headers or bodies in diagnostics or artifacts.
  if(!['GET','HEAD'].includes(method)&&!(url.pathname==='/api/auth/login'&&method==='POST'))mutations.push(`${method} ${url.pathname}`);
  if(url.pathname.startsWith('/api/application-checks'))applicationRequests.push(`${method} ${url.pathname}${url.search}`);
 });
 await page.route(`${base}/api/application-checks/**`,route=>{
  const request=route.request();reads++;
  expect(request.url()).toBe(`${base}${statusPath}`);expect(request.method()).toBe('GET');expect(request.postData()).toBe(null);
  if(phase!=='retained')return route.fulfill({status:phase==='unavailable'?503:401,contentType:'application/json',body:JSON.stringify({error:{code:phase==='unavailable'?'fixture_unavailable':'authentication_required',message:'Synthetic application-status fault injection'}})});
  return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(activeFixture)});
 });
 await expect(page.getByRole('heading',{name:'Sign in',exact:true})).toBeVisible();expect(reads).toBe(0);
 await login(page);
 const panel=page.getByRole('region',{name:'Application checks',exact:true}), rows=panel.locator('tbody tr');
 const row=id=>rows.filter({has:page.getByText(id,{exact:true})});
 const reload=panel.getByRole('button',{name:'Reload application status',exact:true});
 mark('retained-http-rows');await expect(rows).toHaveCount(4);await expect(panel).toContainText('HTTP/TLS checks from the manager.');
 for(const name of ['Application','HTTP result','Leaf certificate','Observed'])await expect(panel.getByRole('columnheader',{name,exact:true})).toBeVisible();
 await expect(row('fixture-expiring').locator('td').nth(0).locator('.application-cell-value')).toHaveText('204 · 2xx');
 await expect(row('fixture-expiring').locator('td').nth(1)).toContainText('Expiring soon');
 await expect(row('fixture-http-error').locator('td').nth(0).locator('.application-cell-value')).toHaveText('503 · HTTP error');
 await expect(row('fixture-http-error').locator('td').nth(1)).toContainText('Expiry > 30 days');
 await expect(row('fixture-retained-expired').locator('td').nth(0).locator('.application-cell-value')).toHaveText('204 · 2xx');
 await expect(row('fixture-retained-expired').locator('td').nth(1)).toContainText('Expired');
 await expect(row('fixture-retained-expired').locator('.application-expiry')).toHaveAttribute('datetime',fixture.items[2].tls.expiresAt);
 await expect(row('fixture-unverified').locator('td').nth(0).locator('.application-cell-value')).toHaveText('TLS verification failed');
 await expect(row('fixture-unverified').locator('td').nth(1).locator('.application-cell-value')).toHaveText('Unknown');
 await expect(row('fixture-unverified').locator('.application-expiry')).toHaveCount(0);
 for(const item of fixture.items){await expect(row(item.id).locator('td:last-child time')).toHaveAttribute('datetime',item.observedAt);await expect(row(item.id).locator('td:last-child time')).toHaveText('1m ago');}
 await expect(panel.getByRole('button')).toHaveCount(1);await expect(panel.locator('input,select,textarea,form')).toHaveCount(0);
 await expect(panel.locator('.application-checks-timing')).toContainText('60s after each round');await expect(panel.locator('.application-checks-timing')).toContainText('85s');
 mark('retained-http-scope');const disclosure=panel.locator('details');await disclosure.locator('summary').click();await expect(disclosure).toHaveAttribute('open','');
 await expect(disclosure.getByRole('link',{name:'Startup-file guide (GitHub)',exact:true})).toHaveAttribute('rel','noopener noreferrer');
 await expect(disclosure).toContainText('2xx is an HTTP status, not proof of health. Certificate data is from the same check. Reload starts no check.');
 await applicationRowLayout({page,panel,expect,fixture,mobile:false});
 await panel.scrollIntoViewIfNeeded();await shot(page,'synthetic-http-test-application-checks-desktop-en',applicationFixtureDisclosure);
 await page.setViewportSize({width:390,height:844});await panel.scrollIntoViewIfNeeded();
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth&&document.body.scrollWidth<=innerWidth)).toBe(true);
 await applicationRowLayout({page,panel,expect,fixture,mobile:true});
 await row(fixture.items[0].id).scrollIntoViewIfNeeded();
 await expect(disclosure).toHaveAttribute('open','');await shot(page,'synthetic-http-test-application-checks-mobile-en',applicationFixtureDisclosure);
 await page.setViewportSize({width:1440,height:1000});
 // Original sample age is 65s; the four-row contract permits 85s. Re-reading
 // this same retained DTO cannot reset its clock watermark or sample time.
 mark('original-staleness');const beforePoll=reads;await page.clock.runFor(21000);expect(reads).toBeGreaterThan(beforePoll);
 await expect(panel.locator('.application-unknown')).toHaveCount(4);await expect(panel.locator('.application-expiry')).toHaveCount(0);
 await expect(panel.locator('.application-ok,.application-tls-valid,.application-tls-expiring,.application-tls-expired')).toHaveCount(0);
 for(const item of fixture.items){await expect(row(item.id).locator('td').nth(0).locator('.application-cell-value')).toHaveText('Unknown · stale');await expect(row(item.id).locator('td').nth(1).locator('.application-cell-value')).toHaveText('Unknown');await expect(row(item.id).locator('td:last-child time')).toHaveAttribute('datetime',item.observedAt);}
 phase='unavailable';await reload.click();await expect(panel.getByRole('alert')).toHaveText('Application status unavailable. Reload to try again.');await expect(rows).toHaveCount(0);
 phase='retained';await reload.click();await expect(rows).toHaveCount(4);await expect(panel.locator('.application-unknown')).toHaveCount(4);await expect(panel.locator('.application-expiry')).toHaveCount(0);
 for(const item of fixture.items)await expect(row(item.id).locator('td:last-child time')).toHaveAttribute('datetime',item.observedAt);
 phase='access-lost';await reload.click();await expect(page.getByRole('heading',{name:'Sign in',exact:true})).toBeVisible();await expect(panel).toHaveCount(0);await expect(page.locator('.app-shell')).toHaveCount(0);
 const stopped=reads;await page.clock.runFor(30000);expect(reads).toBe(stopped);
 // Keep both new protocols inside this existing hosted case and login lifecycle.
 // Each fresh login receives only invented, production-validated retained DTOs.
 for(const [nextFixture,suffix] of [[applicationHTTPStatusFixture(),'v1-http-https'],[applicationMixedStatusFixture(),'v2-dns-tcp-https']]){
  mark('retained-'+suffix);activeFixture=nextFixture;phase='retained';await login(page);
  await expect(rows).toHaveCount(nextFixture.items.length);
  const mixed=nextFixture.schemaVersion.endsWith('.v2');
  await expect(panel).toContainText(mixed?'Checks from the manager: HTTP/TLS, DNS, TCP.':'HTTP/TLS checks from the manager.');
  for(const item of nextFixture.items){
   const current=row(item.id), values=current.locator('.application-cell-value');
   await expect(current.locator('td:last-child time')).toHaveAttribute('datetime',item.observedAt);await expect(current.locator('td:last-child time')).toHaveText('1m ago');
   await expect(values.nth(0)).toHaveText(item.kind==='dns'?'Resolved':item.kind==='tcp'?'Connected':'204 · 2xx');
   if(item.kind==='dns'||item.kind==='tcp'){
    await expect(current.getByRole('rowheader')).toContainText(item.kind.toUpperCase());
    await expect(values.nth(1).getByRole('img',{name:'Certificate is not part of this check',exact:true})).toHaveCount(1);
    await expect(values.nth(1).locator('.application-mobile-certificate')).toHaveText('Certificate is not part of this check');
    await expect(current.locator('.application-expiry,.application-tls-valid,.application-tls-expiring,.application-tls-expired')).toHaveCount(0);await expect(current.locator('time')).toHaveCount(1);
   }else if(item.targetScheme==='http'){
    await expect(current.getByRole('rowheader')).toContainText('HTTP · plaintext');await expect(values.nth(1)).toHaveText('No TLS');await expect(current.locator('.application-expiry')).toHaveCount(0);
   }else{
    await expect(values.nth(1)).toContainText('Expiring soon');await expect(current.locator('.application-expiry')).toHaveAttribute('datetime',item.tls.expiresAt);
   }
  }
  await expect(panel.getByRole('button')).toHaveCount(1);await expect(panel.locator('input,select,textarea,form')).toHaveCount(0);
  mark('scope-'+suffix);const details=panel.locator('details');await details.locator('summary').click();await expect(details).toHaveAttribute('open','');
  await expect(details).toContainText('2xx is an HTTP status, not proof of health. Certificate data is from the same check. Reload starts no check.');
  if(mixed){
   await expect(details).toContainText(conciseCopy.applicationDNS);
   await expect(details).toContainText('TCP connects to the IP, then closes. No data, TLS or proof of application health.');
  }
  const captureDisclosure=`${applicationFixtureDisclosure}; invented ${mixed?'v2 DNS/TCP/HTTPS':'v1 HTTP/HTTPS'} rows, original sample age, ${mixed?'DNS/TCP have no certificate evidence':'plaintext HTTP has no TLS'}`;
  await applicationRowLayout({page,panel,expect,fixture:nextFixture,mobile:false});await panel.scrollIntoViewIfNeeded();
  await shot(page,`synthetic-http-test-application-checks-${suffix}-desktop-en`,captureDisclosure);
  await page.setViewportSize({width:390,height:844});await applicationRowLayout({page,panel,expect,fixture:nextFixture,mobile:true});
  for(const item of nextFixture.items){
   const current=row(item.id);
   if(item.kind==='dns'||item.kind==='tcp'){await expect(current.locator('.application-certificate-mark')).toBeHidden();await expect(current.locator('.application-mobile-certificate')).toBeVisible();}
  }
  await row(nextFixture.items[0].id).scrollIntoViewIfNeeded();await shot(page,`synthetic-http-test-application-checks-${suffix}-mobile-en`,captureDisclosure);
  if(mixed){await row('fixture-expiring').scrollIntoViewIfNeeded();await shot(page,`synthetic-http-test-application-checks-${suffix}-https-mobile-en`,captureDisclosure);}
  await page.setViewportSize({width:1440,height:1000});
  const beforeReload=reads;await reload.click();await expect(reload).toBeEnabled();expect(reads).toBeGreaterThan(beforeReload);
  const staleAfterMs=(nextFixture.maxAgeSeconds-65+1)*1000;await page.clock.runFor(staleAfterMs);
  await expect(panel.locator('.application-unknown')).toHaveCount(nextFixture.items.length);await expect(panel.locator('.application-expiry')).toHaveCount(0);
  await expect(panel.locator('.application-ok,.application-tls-valid,.application-tls-expiring,.application-tls-expired')).toHaveCount(0);
  const assertRetainedStale=async()=>{
   for(const item of nextFixture.items){
    const current=row(item.id),values=current.locator('.application-cell-value');
    await expect(values.nth(0)).toHaveText('Unknown · stale');
    if(item.kind==='dns'||item.kind==='tcp')await expect(values.nth(1).getByRole('img',{name:'Certificate is not part of this check',exact:true})).toHaveCount(1);
    else await expect(values.nth(1)).toHaveText(item.targetScheme==='http'?'No TLS':'Unknown');
    await expect(current.locator('td:last-child time')).toHaveAttribute('datetime',item.observedAt);await expect(current.locator('td:last-child time')).toHaveText('1m ago');
   }
  };
  await assertRetainedStale();await reload.click();await expect(reload).toBeEnabled();await assertRetainedStale();
  phase='unavailable';await reload.click();await expect(panel.getByRole('alert')).toHaveText('Application status unavailable. Reload to try again.');await expect(rows).toHaveCount(0);
  phase='retained';await reload.click();await expect(rows).toHaveCount(nextFixture.items.length);await assertRetainedStale();
  phase='access-lost';await reload.click();await expect(page.getByRole('heading',{name:'Sign in',exact:true})).toBeVisible();await expect(panel).toHaveCount(0);await expect(page.locator('.app-shell')).toHaveCount(0);
  const stoppedAgain=reads;await page.clock.runFor(30000);expect(reads).toBe(stoppedAgain);
 }
 // Disabled status has setup guidance, never a target form or trigger.
 mark('disabled-en');activeFixture={...fixture,enabled:false,intervalSeconds:0,maxAgeSeconds:0,items:[]};phase='retained';await login(page);
 await expect(panel).toContainText('Disabled · no application checks running.');
 await expect(panel).toContainText('Configure up to 8 HTTP/HTTPS, DNS or TCP targets on the manager.');
 await expect(panel.locator('table,dl,input,select,textarea,form')).toHaveCount(0);
 const setup=panel.locator('details');await expect(setup).not.toHaveAttribute('open','');
 await setup.locator('summary').click();await expect(setup).toHaveAttribute('open','');
 await expect(setup).toContainText('private LAN and plaintext HTTP need separate approval.');
 const guide=setup.getByRole('link',{name:'Startup-file guide (GitHub)',exact:true});
 await expect(guide).toHaveAttribute('href','https://github.com/storminator89/Tracebolt/blob/bb76d6a6b7000b244b8075d5644562ad0da94c91/docs/application-checks.md');
 await expect(guide).toHaveAttribute('referrerpolicy','no-referrer');await expect(panel.getByRole('button')).toHaveCount(1);
 await setup.locator('summary').click();await expect(setup).not.toHaveAttribute('open','');
 await panel.scrollIntoViewIfNeeded();await shot(page,'synthetic-application-checks-disabled-desktop-en',applicationFixtureDisclosure);
 await page.setViewportSize({width:390,height:844});await setup.locator('summary').click();
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth&&document.body.scrollWidth<=innerWidth)).toBe(true);
 await panel.scrollIntoViewIfNeeded();await shot(page,'synthetic-application-checks-disabled-mobile-en',applicationFixtureDisclosure);
 await page.getByRole('combobox',{name:'Language',exact:true}).selectOption('de');
 mark('disabled-de');const germanPanel=page.getByRole('region',{name:'Anwendungsprüfungen',exact:true});
 await expect(germanPanel).toContainText('Deaktiviert · keine Anwendungsprüfungen aktiv.');
 await expect(germanPanel.locator('details')).toHaveAttribute('open','');
 await expect(germanPanel).toContainText(conciseCopy.applicationApprovalDE);
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth&&document.body.scrollWidth<=innerWidth)).toBe(true);
 await germanPanel.scrollIntoViewIfNeeded();await shot(page,'synthetic-application-checks-disabled-mobile-de',applicationFixtureDisclosure);
 expect(mutations).toEqual([]);expect(applicationRequests.length).toBe(reads);expect(applicationRequests.every(value=>value===`GET ${statusPath}`)).toBe(true);
}
