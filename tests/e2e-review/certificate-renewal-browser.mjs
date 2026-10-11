/** Inert synthetic metadata case. The ordinary hosted runner owns browser/login. */
export const certificateRenewalCaseName='Automatic certificate renewal metadata remains explicit and bounded';
export const certificateRenewalDisclosure='Production operator UI and real loopback fixture login; invented renewable certificate metadata only. No certificate issuance, renewal request, host grant, native agent or live TLS acceptance.';
export function certificateRenewalFixture(status,now='2026-10-11T12:00:00Z'){
 if(!['healthy','blocked','expired'].includes(status)||!Number.isFinite(Date.parse(now)))throw new Error('Invalid certificate fixture');
 const expiresAt=new Date(Date.parse(now)+(status==='expired'?-1000:72*3600000)).toISOString();
 return {source:'guided-enrollment',checkedAt:now,expiresAt,renewal:{status,enabled:status!=='blocked',identityGeneration:'identity_'+'a'.repeat(32),credentialGeneration:2,currentNotAfter:expiresAt,authorityExpiresAt:new Date(Date.parse(now)+30*86400000).toISOString()}};
}
export function requireCertificateRenewalEvidence(rows,sourceSha){
 const selected=rows.filter(row=>row.test===certificateRenewalCaseName);
 if(!/^[a-f0-9]{40}$/.test(sourceSha??'')||selected.length!==12)throw new Error('Certificate renewal evidence missing');
 for(const status of ['healthy','blocked','expired'])for(const locale of ['en','de'])for(const width of [1440,390]){
  const match=selected.filter(row=>row.file===`synthetic-certificate-renewal-${status}-${width}-${locale}.png`);
  if(match.length!==1)throw new Error('Certificate renewal variant missing');const row=match[0];
  if(row.sourceSha!==sourceSha||row.fixtureDisclosure!==certificateRenewalDisclosure||row.publicSafe!==true||row.fullPage!==false||row.locale!==locale||row.viewport?.width!==width||row.viewport?.height!==(width===390?844:1000))throw new Error('Certificate renewal evidence mismatch');
 }
}
export async function certificateRenewalBrowserCase({pageAt,expect,base,login,shot}){
 const page=await pageAt('/devices');await login(page);
 const id='agent_00000000000000000000000000000001';
 const response=await page.request.get(`${base}/api/devices/${id}`,{timeout:5000,maxRedirects:0});
 expect(response.status()).toBe(200);const device=await response.json();await response.dispose();
 let status='healthy',ended=false;const now=new Date().toISOString();
 await page.route(`${base}/api/devices/${id}`,route=>{
  expect(route.request().method()).toBe('GET');expect(route.request().postData()).toBe(null);
  return route.fulfill({status:ended?401:200,contentType:'application/json',body:JSON.stringify(ended?{error:{code:'authentication_required',message:'Synthetic session ended'}}:{...device,agentCertificate:certificateRenewalFixture(status,now)})});
 });
 await page.getByRole('button',{name:'Open details: Fixture workstation',exact:true}).click();
 await page.getByRole('tab',{name:'Details',exact:true}).click();const panel=page.locator('.agent-certificate');
 for(const locale of ['en','de'])for(const width of [1440,390]){
  await page.getByLabel(/Language|Sprache/).selectOption(locale);await page.setViewportSize({width,height:width===390?844:1000});
  for(status of ['healthy','blocked','expired']){
   await page.getByRole('button',{name:locale==='de'?'Gerätedaten aktualisieren':'Refresh device metadata',exact:true}).click();
   const text=locale==='de'?{healthy:'Automatische Erneuerung: Aktiv',blocked:'Automatische Erneuerung: Erneuerung blockiert',expired:'Automatische Erneuerung: Abgelaufen'}:{healthy:'Automatic renewal: Enabled',blocked:'Automatic renewal: Renewal blocked',expired:'Automatic renewal: Expired'};
   await expect(panel).toContainText(text[status]);await expect(panel.locator('details')).not.toHaveAttribute('open');
   await expect(panel.locator('button,a')).toHaveCount(0);await panel.scrollIntoViewIfNeeded();
   expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth&&document.body.scrollWidth<=innerWidth)).toBe(true);
   await shot(page,`synthetic-certificate-renewal-${status}-${width}-${locale}`,certificateRenewalDisclosure);
  }
 }
 await panel.locator('summary').click();await expect(panel.locator('details')).toHaveAttribute('open','');await expect(panel).toContainText('Zertifikatsgeneration');
 ended=true;await page.getByRole('button',{name:'Gerätedaten aktualisieren',exact:true}).click();await expect(panel).toHaveCount(0);
}
