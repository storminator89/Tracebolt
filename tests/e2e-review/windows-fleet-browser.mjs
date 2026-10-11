/** Production-handler Windows vectors at an intercepted browser transport seam.
 * Real loopback operator authentication; no Windows live-store/native acceptance. */
import fs from 'node:fs';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const require=createRequire(path.join(root,'web/package.json'));
const {build}=require('esbuild');
const bundled=await build({stdin:{contents:"export {validFleetIdentityView} from './fleet-identity-types'; export {windowsDevice} from './windows-inventory-fixture';",resolveDir:path.join(root,'web/src'),loader:'ts'},bundle:true,platform:'node',format:'esm',write:false,logLevel:'silent'});
const {validFleetIdentityView,windowsDevice}=await import('data:text/javascript;base64,'+Buffer.from(bundled.outputFiles[0].text).toString('base64'));
const vectors=JSON.parse(fs.readFileSync(path.join(root,'web/src/windows-fleet-identity-vectors.json'),'utf8'));
export const windowsFleetCaseName='Windows fleet hostname and dual-stack search with production-handler vectors and synthetic transport';
export const windowsFleetDisclosure='Real loopback HTTP-test operator login and compiled UI; intercepted invented Windows overview rows and exported production-handler fleet identity vectors. Two synthetic device bindings and response time are adapted; original source, receipt and expiry times are preserved. UI interoperability evidence, not live Windows manager/store acceptance. No native Windows read, local grant, installer, host or service action.';
export const windowsFleetDeviceIds=[vectors.fresh.items[0].deviceId,vectors.expired.items[0].deviceId];
export function windowsFleetFixture(mode='ready',elapsed=0){
 if(!['ready','expired'].includes(mode)||!Number.isFinite(elapsed)||elapsed<0||elapsed>90000)throw new Error('Invalid Windows fleet fixture selection');
 const serverNow=new Date(Date.parse(mode==='expired'?vectors.expired.serverNow:vectors.partial.serverNow)+elapsed).toISOString();
 const items=(mode==='expired'?[vectors.expired.items[0],vectors.expired.items[0]]:[vectors.fresh.items[0],vectors.partial.items[0]]).map((source,index)=>({...structuredClone(source),deviceId:windowsFleetDeviceIds[index],serverNow}));
 const view={schemaVersion:'tracebolt.fleet-identities.v2',serverNow,items:items.sort((a,b)=>a.deviceId.localeCompare(b.deviceId,'en'))};
 if(!validFleetIdentityView(view))throw new Error('Invalid production Windows fleet vector');return view;
}
export function windowsFleetOverview(overview){
 if(!overview||!Array.isArray(overview.devices))throw new Error('Invalid authenticated overview');
 const devices=windowsFleetDeviceIds.map(id=>{const device=windowsDevice();return{...device,id,name:id,status:'unknown',cpu:{...device.cpu,value:null,quality:'unknown'},memory:{...device.memory,value:null,quality:'unknown'},disk:{...device.disk,value:null,quality:'unknown'}};});
 return{...overview,devices};
}
// Fetch the exact real route first with the context's cookies. Never turn an
// authentication failure, busy response or redirect into synthetic success.
export async function windowsFleetProtectedRead({route,base,pathname,transform}){
 const request=route.request(),url=new URL(request.url());
 if(url.origin!==base||url.pathname!==pathname||url.search||request.method()!=='GET'||!['/api/overview','/api/fleet/identities'].includes(pathname))throw new Error('Unexpected Windows fleet fixture read');
 const response=await route.fetch({maxRedirects:0,timeout:5000});
 try{
  if(response.status()!==200)return await route.fulfill({response});
  const headers={...response.headers()};delete headers['content-length'];delete headers['content-encoding'];
  return await route.fulfill({response,headers,json:transform(await response.json())});
 }finally{await response.dispose();}
}
export async function windowsFleetBrowserCase({pageAt,expect,base,shot,mark}){
 const began=Date.now(),external=[];let mode='ready',fleetReads=0;
 const page=await pageAt('/devices',{prepare:async page=>{
  page.on('request',request=>{if(new URL(request.url()).origin!==base)external.push('external');});
  await page.route(base+'/api/overview',route=>windowsFleetProtectedRead({route,base,pathname:'/api/overview',transform:windowsFleetOverview}));
  await page.route(base+'/api/fleet/identities',route=>{fleetReads++;return windowsFleetProtectedRead({route,base,pathname:'/api/fleet/identities',transform:()=>windowsFleetFixture(mode,Date.now()-began)});});
 }});
 const rows=page.locator('.device-table tbody tr'),row=id=>rows.filter({has:page.locator('.fleet-identity-id',{hasText:id})}),fresh=row(windowsFleetDeviceIds[0]),partial=row(windowsFleetDeviceIds[1]);
 const hostname=vectors.fresh.items[0].latest.hostname.rows[0].value,ipv4='192.0.2.8',ipv6='2001:db8::8';
 for(const locale of ['en','de'])for(const width of [1440,390]){
  mark('Windows compact table and local dual-stack search');const de=locale==='de';await page.setViewportSize({width,height:width===390?844:1000});await page.getByLabel(/Language|Sprache/).selectOption(locale);
  await expect(rows).toHaveCount(2);await expect(fresh.locator('strong')).toHaveText(hostname);await expect(fresh).toContainText(ipv4);await expect(fresh.locator('details')).not.toHaveAttribute('open');await expect(fresh.locator('summary')).toHaveText(de?'+1 weitere IPs':'+1 more IPs');await expect(fresh.locator('img,a,script')).toHaveCount(0);
  await expect(partial).toContainText(de?'Hostname nicht verfügbar':'Hostname unavailable');await expect(partial).toContainText(de?'Nicht verfügbar':'Unavailable');await expect(partial).toContainText(de?'Teilweise erfasst':'Partially collected');await expect(partial).toContainText(ipv4);
  const search=page.getByRole('textbox',{name:de?'Geräte durchsuchen':'Search devices'}),before=fleetReads;
  for(const value of [hostname,ipv4,ipv6]){await search.fill(value);await expect(rows).toHaveCount(value===hostname?1:2);await expect(fresh).toBeVisible();}
  await search.fill('203.0.113.250');await expect(rows).toHaveCount(0);await search.fill('');await expect(rows).toHaveCount(2);expect(fleetReads).toBe(before);
  const platform=page.getByLabel(de?'Nach Betriebssystem filtern':'Filter by operating system');await platform.selectOption('linux');await expect(rows).toHaveCount(0);await platform.selectOption('windows');await expect(rows).toHaveCount(2);await platform.selectOption('all');
  await fresh.locator('summary').focus();await page.keyboard.press('Enter');await expect(fresh.getByText(ipv6,{exact:true})).toBeVisible();await expect(fresh).toContainText('Fixture Ethernet · IPV6 /64');await expect(fresh).toContainText(de?'Windows-LAN-Agent':'Windows LAN agent');await expect(fresh).toContainText(de?'Schnittstellenstatus unbekannt.':'Interface state unknown.');await expect(page).toHaveURL(base+'/#/devices');await fresh.locator('summary').focus();await page.keyboard.press('Space');await expect(fresh.locator('details')).not.toHaveAttribute('open');
  await rows.last().scrollIntoViewIfNeeded();await expect(fresh).toBeInViewport({ratio:1});await expect(partial).toBeInViewport({ratio:1});await shot(page,`synthetic-windows-fleet-${width}-${locale}`,windowsFleetDisclosure);
 }
 await page.getByLabel(/Language|Sprache/).selectOption('en');
 mark('Windows suspension clears display and search');await page.evaluate(()=>window.dispatchEvent(new Event('blur')));await expect(page.locator('.device-table')).not.toContainText(hostname);await expect(page.locator('.device-table')).not.toContainText(ipv4);const search=page.getByRole('textbox',{name:'Search devices'});await search.fill(ipv6);await expect(rows).toHaveCount(0);await search.fill('');await page.evaluate(()=>window.dispatchEvent(new Event('focus')));await expect(fresh.locator('strong')).toHaveText(hostname);await expect(partial).toContainText(ipv4);
 mark('Windows exported expiry clears display and search');mode='expired';await page.getByRole('button',{name:'Refresh hostnames and IP addresses',exact:true}).click();await expect(fresh).toContainText('Expired');await expect(partial).toContainText('Expired');await expect(page.locator('.device-table')).not.toContainText(hostname);await expect(page.locator('.device-table')).not.toContainText(ipv4);for(const value of [hostname,ipv4,ipv6]){await search.fill(value);await expect(rows).toHaveCount(0);}await search.fill('');
 // New document resets the synthetic clock after the explicit expiry vector.
 // The real operator cookie/session remains unchanged, then is actually revoked.
 mark('Windows real session revocation clears intercepted values');mode='ready';await page.reload();await expect(fresh.locator('strong')).toHaveText(hostname);
 const session=await page.request.get(base+'/api/auth/session',{maxRedirects:0,timeout:5000});expect(session.status()).toBe(200);const auth=await session.json();await session.dispose();
 const logout=await page.request.post(base+'/api/auth/logout',{headers:{Origin:base,'X-CSRF-Token':auth.csrfToken},data:{},maxRedirects:0,timeout:5000});expect(logout.ok()).toBe(true);await logout.dispose();
 const denied=await page.request.get(base+'/api/fleet/identities',{maxRedirects:0,timeout:5000});expect(denied.status()).toBe(401);await denied.dispose();await page.getByRole('button',{name:'Refresh hostnames and IP addresses',exact:true}).click();await expect(page.getByRole('heading',{name:'Sign in',exact:true})).toBeVisible();await expect(page.locator('.fleet-identity-name')).toHaveCount(0);
 expect(await page.evaluate(values=>values.some(value=>JSON.stringify({...localStorage,...sessionStorage}).includes(value)),[hostname,ipv4,ipv6])).toBe(false);expect(external).toEqual([]);
 return{screens:4,transport:'intercepted production-handler vectors',liveStoreAcceptance:false,nativeAcceptance:false};
}
