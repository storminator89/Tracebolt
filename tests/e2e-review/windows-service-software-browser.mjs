/** Invented bounded display rows and hosted assertions only. No host reads. */
export function addWindowsServiceSoftwareControlsFixture(view){
 const services=Array.from({length:61},(_,index)=>{const n=index+1;return {name:`synthetic-service-${String(n).padStart(3,'0')}`,displayName:n===60?'Literal [.*] Service':`Synthetic service label ${String(n).padStart(3,'0')}`,state:n===61?'start_pending':n%2?'running':'stopped',pid:n===1?2:n===2?10:n===10?1:n};});
 const software=Array.from({length:61},(_,index)=>{const n=index+1;return {name:`synthetic-software-${String(n).padStart(3,'0')}`,version:n===1?'2':n===2?'10':n===60?'literal[.*]':`v${String(n).padStart(3,'0')}`,publisher:n===1?'ZZZ Fixture Publisher':n===2?'AAA Fixture Publisher':`Fixture Publisher ${String(n).padStart(3,'0')}`,registryView:n%2?'64':'32'};});
 for(const [key,rows] of [['services',services],['software',software]])view.snapshot[key]={...view.snapshot[key],quality:'partial',countExact:false,complete:false,truncated:true,observedCount:200,rows};
 return view;
}

async function checkControls({page,expect,locale,width,kind}){
 const de=locale==='de',service=kind==='services',title=service?(de?'Dienste':'Services'):'Software';
 const workspace=page.locator('.windows-inventory'),panel=workspace.locator('[role="tabpanel"]');
 await page.getByRole('tab',{name:title,exact:true}).click();
 const table=panel.getByRole('table',{name:title,exact:true}),rows=table.locator('tbody tr');
 const filter=panel.getByRole('searchbox',{name:service?(de?'Erfasste Dienste filtern':'Filter captured services'):(de?'Erfasste Software filtern':'Filter captured software'),exact:true});
 const sort=panel.getByRole('combobox',{name:service?(de?'Erfasste Dienste sortieren':'Sort captured services'):(de?'Erfasste Software sortieren':'Sort captured software'),exact:true});
 const pagination=panel.locator('.windows-inventory-table-pagination'),next=pagination.getByRole('button',{name:de?'Nächste Seite':'Next page',exact:true}),previous=pagination.getByRole('button',{name:de?'Vorherige Seite':'Previous page',exact:true});
 const prefix=service?'synthetic-service-':'synthetic-software-';
 await expect(rows).toHaveCount(25);await expect(rows.first()).toContainText(prefix+'001');await expect(sort).toHaveValue('name-asc');
 await expect(panel).toContainText(de?'61 erfasst · mindestens 200 beobachtet':'61 captured · at least 200 observed');
 await expect(panel).toContainText(de?'Zeilen 1–25 von 61 Treffern · 61 erfasst':'Rows 1–25 of 61 matching · 61 captured');
 await expect(panel).toContainText(de?'Zeilen durch Erfassungs- oder Übertragungsgrenzen ausgelassen':'Rows omitted by collection or transfer limits');
 await expect(table.locator('thead th[aria-sort]')).toHaveCount(1);await expect(table.locator('thead th').first()).toHaveAttribute('aria-sort','ascending');
 await expect(filter).toBeVisible();await expect(sort).toBeVisible();await expect(table.locator('thead input, thead select, thead button')).toHaveCount(0);
 const labels=service?(de?['Name','Anzeigename','Zustand','PID']:['Name','Display name','State','PID']):(de?['Name','Version','Herausgeber','Registrierungsansicht']:['Name','Version','Publisher','Registry view']);
 for(const label of labels){
  if(width===1440)await expect(table.getByRole('columnheader',{name:label,exact:true})).toBeVisible();
  else {
   const cell=rows.first().locator(`td[data-label="${label}"]`);await expect(cell).toBeVisible();
   const before=await cell.evaluate(el=>{const style=getComputedStyle(el,'::before');return {content:style.content,display:style.display,visibility:style.visibility};});
   expect(before.content).toBe(JSON.stringify(label));expect(before.display).not.toBe('none');expect(before.visibility).toBe('visible');
  }
 }
 await expect(previous).toBeDisabled();await next.click();await expect(rows.first()).toContainText(prefix+'026');
 await next.focus();await page.keyboard.press('Enter');await expect(rows).toHaveCount(11);await expect(rows.first()).toContainText(prefix+'051');await expect(next).toBeDisabled();
 await expect(panel).toContainText(de?'Zeilen 51–61 von 61 Treffern · 61 erfasst':'Rows 51–61 of 61 matching · 61 captured');
 await previous.click();await expect(rows).toHaveCount(25);await expect(rows.first()).toContainText(prefix+'026');
 return {workspace,panel,table,rows,filter,sort,next,previous};
}

/** Called only by the existing hosted loopback runner, never a browser launcher. */
export async function exerciseWindowsServiceSoftwareControls({page,expect,locale,width,shot,disclosure}){
 const de=locale==='de';
 for(const kind of ['services','software']){
  const {workspace,panel,table,rows,filter,sort,next,previous}=await checkControls({page,expect,locale,width,kind});
  const service=kind==='services',prefix=service?'synthetic-service-':'synthetic-software-';
  const queries=service?['SYNTHETIC-SERVICE-061','label 061','61','START_PENDING',de?'WIRD GESTARTET':'STARTING']:['SYNTHETIC-SOFTWARE-061','V061','Publisher 061'];
  for(const query of queries){await filter.fill(query);await expect(rows).toHaveCount(1);await expect(rows.first()).toContainText(prefix+'061');await expect(previous).toBeDisabled();await expect(next).toBeDisabled();}
  await filter.fill('[.*]');await expect(rows).toHaveCount(1);await expect(rows.first()).toContainText(prefix+'060');
  if(!service){
   await filter.fill('32');await expect(rows).toHaveCount(25);await expect(panel).toContainText(de?'Zeilen 1–25 von 30 Treffern · 61 erfasst':'Rows 1–25 of 30 matching · 61 captured');
   await next.click();await expect(rows).toHaveCount(5);await expect(next).toBeDisabled();
   for(const cell of await rows.locator('td:last-child').allTextContents())expect(cell).toBe('32-bit');
  }
  await filter.fill('absent-fixture');await expect(table).toHaveCount(0);await expect(panel).toContainText(de?'Keine erfassten Zeilen entsprechen diesem Filter.':'No captured rows match this filter.');
  await expect(panel).toContainText(de?'Zeilen 0–0 von 0 Treffern · 61 erfasst':'Rows 0–0 of 0 matching · 61 captured');await expect(previous).toBeDisabled();await expect(next).toBeDisabled();
  await filter.fill('');await expect(rows).toHaveCount(25);await expect(previous).toBeDisabled();
  for(const [value,name] of [['name-desc','061'],['name-asc','001']]){await sort.selectOption(value);await expect(rows.first()).toContainText(prefix+name);await expect(table.locator('thead th').first()).toHaveAttribute('aria-sort',value.endsWith('-desc')?'descending':'ascending');}
  if(service){
   await sort.selectOption('pid-asc');await expect(rows.first()).toContainText(prefix+'010');await expect(rows.nth(1)).toContainText(prefix+'001');await expect(rows.nth(2)).toContainText(prefix+'003');
   await expect(table.locator('thead th').nth(3)).toHaveAttribute('aria-sort','ascending');
   await sort.selectOption('pid-desc');await expect(rows.first()).toContainText(prefix+'061');await expect(table.locator('thead th').nth(3)).toHaveAttribute('aria-sort','descending');
   for(const [direction,name] of [['asc',de?'002':'001'],['desc',de?'061':'002']]){await sort.selectOption('state-'+direction);await expect(rows.first()).toContainText(prefix+name);await expect(table.locator('thead th').nth(2)).toHaveAttribute('aria-sort',direction==='asc'?'ascending':'descending');}
  }else{
   await sort.selectOption('version-asc');await expect(rows.first()).toContainText(prefix+'002');await expect(rows.nth(1)).toContainText(prefix+'001');await expect(table.locator('thead th').nth(1)).toHaveAttribute('aria-sort','ascending');
   await sort.selectOption('version-desc');await expect(rows.first()).toContainText(prefix+'061');await expect(table.locator('thead th').nth(1)).toHaveAttribute('aria-sort','descending');
   await sort.selectOption('publisher-asc');await expect(rows.first()).toContainText(prefix+'002');await expect(table.locator('thead th').nth(2)).toHaveAttribute('aria-sort','ascending');
   await sort.selectOption('publisher-desc');await expect(rows.first()).toContainText(prefix+'001');await expect(table.locator('thead th').nth(2)).toHaveAttribute('aria-sort','descending');
  }
  await next.click();await expect(previous).toBeEnabled();await sort.selectOption('name-asc');await expect(previous).toBeDisabled();await expect(rows.first()).toContainText(prefix+'001');
  await expect(table.locator('thead th[aria-sort]')).toHaveCount(1);await expect(filter).toBeVisible();await expect(sort).toBeVisible();
  expect(await workspace.evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);
  await panel.locator('.windows-inventory-table-controls').scrollIntoViewIfNeeded();await shot(page,`synthetic-windows-${kind}-controls-${width}-${locale}`,disclosure);
  // Leaving and returning must clear even an all-field private filter.
  await filter.fill('[.*]');await page.getByRole('tab',{name:'Hostname',exact:true}).click();await page.getByRole('tab',{name:service?(de?'Dienste':'Services'):'Software',exact:true}).click();
  await expect(filter).toHaveValue('');await expect(sort).toHaveValue('name-asc');await expect(rows).toHaveCount(25);await expect(previous).toBeDisabled();
 }
 // The shared runner continues the independent process-metrics checks.
 await page.getByRole('tab',{name:de?'Prozesse':'Processes',exact:true}).click();
}
