/** Invented retained DTOs only; no application target, probe or configuration. */
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

/** Uses the existing LAN runner's real login, context, screenshot and cleanup. */
export async function applicationChecksBrowserCase({pageAt,login,expect,base,shot}) {
 const page=await pageAt('/overview');await page.clock.install({time:new Date()});
 const fixture=applicationStatusFixture(), statusPath='/api/application-checks/status';
 let reads=0,phase='retained';const mutations=[],applicationRequests=[];
 page.on('request',request=>{
  const url=new URL(request.url()),method=request.method();
  if(url.origin!==base||!url.pathname.startsWith('/api/'))return;
  // Login is the single authorized fixture mutation. Record only method/path,
  // never credentials, cookies, headers or bodies in diagnostics or artifacts.
  if(!['GET','HEAD'].includes(method)&&!(url.pathname==='/api/auth/login'&&method==='POST'))mutations.push(`${method} ${url.pathname}`);
  if(url.pathname.startsWith('/api/application-checks'))applicationRequests.push(`${method} ${url.pathname}${url.search}`);
 });
 await page.route(`${base}/api/application-checks/**`,route=>{
  const request=route.request();reads++;
  expect(request.url()).toBe(`${base}${statusPath}`);expect(request.method()).toBe('GET');expect(request.postData()).toBe(null);
  if(phase!=='retained')return route.fulfill({status:phase==='unavailable'?503:401,contentType:'application/json',body:JSON.stringify({error:{code:phase==='unavailable'?'fixture_unavailable':'authentication_required',message:'Synthetic application-status fault injection'}})});
  return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(fixture)});
 });
 await expect(page.getByRole('heading',{name:'Sign in',exact:true})).toBeVisible();expect(reads).toBe(0);
 await login(page);
 const panel=page.getByRole('region',{name:'Application checks',exact:true}), rows=panel.locator('tbody tr');
 const row=id=>rows.filter({has:page.getByText(id,{exact:true})});
 const reload=panel.getByRole('button',{name:'Reload application status',exact:true});
 await expect(rows).toHaveCount(4);await expect(panel).toContainText('HTTP/TLS observations from the management server.');
 for(const name of ['Application','HTTP result','Leaf certificate','Observed'])await expect(panel.getByRole('columnheader',{name,exact:true})).toBeVisible();
 await expect(row('fixture-expiring').locator('td').nth(0)).toHaveText('204 · 2xx');
 await expect(row('fixture-expiring').locator('td').nth(1)).toContainText('Expiring soon');
 await expect(row('fixture-http-error').locator('td').nth(0)).toHaveText('503 · HTTP error');
 await expect(row('fixture-http-error').locator('td').nth(1)).toContainText('Expiry > 30 days');
 await expect(row('fixture-retained-expired').locator('td').nth(0)).toHaveText('204 · 2xx');
 await expect(row('fixture-retained-expired').locator('td').nth(1)).toContainText('Expired');
 await expect(row('fixture-retained-expired').locator('.application-expiry')).toHaveAttribute('datetime',fixture.items[2].tls.expiresAt);
 await expect(row('fixture-unverified').locator('td').nth(0)).toHaveText('TLS verification failed');
 await expect(row('fixture-unverified').locator('td').nth(1)).toHaveText('Unknown');
 await expect(row('fixture-unverified').locator('.application-expiry')).toHaveCount(0);
 for(const item of fixture.items){await expect(row(item.id).locator('td:last-child time')).toHaveAttribute('datetime',item.observedAt);await expect(row(item.id).locator('td:last-child time')).toHaveText('1m ago');}
 await expect(panel.getByRole('button')).toHaveCount(1);await expect(panel.locator('a,input,select,textarea,form')).toHaveCount(0);
 const disclosure=panel.locator('details');await disclosure.locator('summary').click();await expect(disclosure).toHaveAttribute('open','');
 await expect(disclosure).toContainText('2xx describes only the HTTP status. Certificate details come from that observation. Reload only reads retained results.');
 await panel.scrollIntoViewIfNeeded();await shot(page,'synthetic-http-test-application-checks-desktop-en',applicationFixtureDisclosure);
 await page.setViewportSize({width:390,height:844});await panel.scrollIntoViewIfNeeded();
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth&&document.body.scrollWidth<=innerWidth)).toBe(true);
 await expect(disclosure).toHaveAttribute('open','');await shot(page,'synthetic-http-test-application-checks-mobile-en',applicationFixtureDisclosure);
 await page.setViewportSize({width:1440,height:1000});
 // Original sample age is 65s; the four-row contract permits 85s. Re-reading
 // this same retained DTO cannot reset its clock watermark or sample time.
 const beforePoll=reads;await page.clock.runFor(21000);expect(reads).toBeGreaterThan(beforePoll);
 await expect(panel.locator('.application-unknown')).toHaveCount(4);await expect(panel.locator('.application-expiry')).toHaveCount(0);
 await expect(panel.locator('.application-ok,.application-tls-valid,.application-tls-expiring,.application-tls-expired')).toHaveCount(0);
 for(const item of fixture.items){await expect(row(item.id).locator('td').nth(0)).toHaveText('Unknown · stale');await expect(row(item.id).locator('td').nth(1)).toHaveText('Unknown');await expect(row(item.id).locator('td:last-child time')).toHaveAttribute('datetime',item.observedAt);}
 phase='unavailable';await reload.click();await expect(panel.getByRole('alert')).toHaveText('Application status unavailable. Reload to try again.');await expect(rows).toHaveCount(0);
 phase='retained';await reload.click();await expect(rows).toHaveCount(4);await expect(panel.locator('.application-unknown')).toHaveCount(4);await expect(panel.locator('.application-expiry')).toHaveCount(0);
 for(const item of fixture.items)await expect(row(item.id).locator('td:last-child time')).toHaveAttribute('datetime',item.observedAt);
 phase='access-lost';await reload.click();await expect(page.getByRole('heading',{name:'Sign in',exact:true})).toBeVisible();await expect(panel).toHaveCount(0);await expect(page.locator('.app-shell')).toHaveCount(0);
 const stopped=reads;await page.clock.runFor(30000);expect(reads).toBe(stopped);
 expect(mutations).toEqual([]);expect(applicationRequests.length).toBe(reads);expect(applicationRequests.every(value=>value===`GET ${statusPath}`)).toBe(true);
}
