/** Invented adapter rows in the existing Network panel and browser/session.
 * No clock advance, request, grant, native read or separate browser case. */
export async function exerciseWindowsAdapterContext({page,expect,locale,width,shot,disclosure}){
 const panel=page.locator('.windows-inventory [role="tabpanel"]'),adapters=panel.locator('.windows-adapter-context'),table=adapters.locator('.windows-adapter-table');
 const row=name=>table.getByRole('row').filter({has:page.getByText(name,{exact:true})});
 const labels=locale==='de'?['Adapter','Verbindungszustand','Linkrate (TX)','Linkrate (RX)','DNS & Gateways']:['Adapter','Link state','TX link speed','RX link speed','DNS & gateways'];
 const ethernet=row('Fixture Ethernet'),wifi=row('Fixture Wi-Fi'),tunnel=row('Fixture tunnel');
 await expect(table.locator('tbody tr')).toHaveCount(3);
 for(const label of labels){
  if(width===1440)await expect(table.getByRole('columnheader',{name:label,exact:true})).toBeVisible();
  else {
   const cell=ethernet.locator(`td[data-label="${label}"]`);await expect(cell).toBeVisible();
   const before=await cell.evaluate(el=>{const style=getComputedStyle(el,'::before');return {content:style.content,display:style.display,visibility:style.visibility};});
   expect(before.content).toBe(JSON.stringify(label));expect(before.display).not.toBe('none');expect(before.visibility).toBe('visible');
  }
 }
 await expect(ethernet.locator(`td[data-label="${labels[1]}"]`)).toHaveText(locale==='de'?'Aktiv':'Up');
 await expect(wifi.locator(`td[data-label="${labels[1]}"]`)).toHaveText(locale==='de'?'Inaktiv':'Down');
 await expect(tunnel.locator(`td[data-label="${labels[1]}"]`)).toHaveText(locale==='de'?'Unbekannt':'Unknown');
 await expect(ethernet.locator(`td[data-label="${labels[2]}"]`)).toHaveText('1 Gbit/s');
 await expect(ethernet.locator(`td[data-label="${labels[3]}"]`)).toHaveText(locale==='de'?'2,5 Gbit/s':'2.5 Gbit/s');
 await expect(ethernet.locator('[title="1000000000 bit/s"]')).toBeVisible();await expect(ethernet.locator('[title="2500000000 bit/s"]')).toBeVisible();
 for(const [target,qualities] of [[wifi,['unknown','unavailable']],[tunnel,['unavailable','unknown']]])for(const [index,quality] of qualities.entries()){
  await expect(target.locator(`td[data-label="${labels[index+2]}"]`)).toHaveText(quality==='unknown'?(locale==='de'?'Unbekannt':'Unknown'):(locale==='de'?'Nicht verfügbar':'Unavailable'));
 }
 await expect(adapters.locator('details[open]')).toHaveCount(0);await expect(adapters.locator('.windows-adapter-addresses')).toHaveCount(3);
 await expect(ethernet.getByText('192.0.2.53',{exact:true})).toBeHidden();
 await ethernet.locator('.windows-adapter-addresses > summary').click();await expect(adapters.locator('details[open]')).toHaveCount(1);
 for(const address of ['192.0.2.53','2001:db8::53','192.0.2.1','fe80::1%4'])await expect(ethernet.getByText(address,{exact:true})).toBeVisible();
 await expect(ethernet.locator('dt')).toHaveText([locale==='de'?'DNS-Server':'DNS servers','Gateways',locale==='de'?'Schnittstellenindizes':'Interface indices']);
 await expect(table.getByRole('link')).toHaveCount(0);
 expect(await panel.evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);
 expect(await table.evaluate(el=>{const bounds=el.getBoundingClientRect(),panel=el.closest('[role="tabpanel"]').getBoundingClientRect();return bounds.left>=panel.left-1&&bounds.right<=panel.right+1&&el.scrollWidth<=el.clientWidth+1;})).toBe(true);
 await adapters.locator('.windows-inventory-section-header').evaluate(el=>el.scrollIntoView({block:'start',inline:'nearest',behavior:'instant'}));
 await expect(ethernet).toBeInViewport({ratio:1});
 await shot(page,`synthetic-windows-adapter-context-${width}-${locale}`,disclosure);
 await ethernet.locator('.windows-adapter-addresses > summary').click();await expect(adapters.locator('details[open]')).toHaveCount(0);
}

/** Pure completion check. Records exist only after the runner's screenshot
 * succeeds; source/viewport metadata does not establish pixel or native truth. */
export function requireWindowsAdapterContextEvidence(screenshots,sourceSha,testName){
 const fail=()=>{throw new Error('Windows adapter completion evidence missing or inconsistent');};
 if(!Array.isArray(screenshots)||!(sourceSha===null||typeof sourceSha==='string'&&/^[a-f0-9]{40}$/.test(sourceSha))||typeof testName!=='string'||!testName)fail();
 const captured=screenshots.filter(item=>typeof item?.file==='string'&&item.file.startsWith('synthetic-windows-adapter-context-'));
 if(captured.length!==4)fail();
 for(const locale of ['en','de'])for(const width of [1440,390]){
  const matches=captured.filter(item=>item.file===`synthetic-windows-adapter-context-${width}-${locale}.png`);if(matches.length!==1)fail();
  const item=matches[0];
  if(item.sourceSha!==sourceSha||item.test!==testName||item.locale!==locale||item.viewport?.width!==width||item.viewport?.height!==(width===390?844:1000)||item.publicSafe!==true||item.fullPage!==false||typeof item.fixtureDisclosure!=='string'||!item.fixtureDisclosure.trim())fail();
 }
 return {adapters:4};
}
