/** Bounded, invented display data and hosted assertions only. No host reads. */
export function addWindowsProcessControlsFixture(view){
 const rows=Array.from({length:61},(_,index)=>({pid:index+1,parentPid:4,name:`synthetic-process-${String(index+1).padStart(3,'0')}.exe`,threads:3}));
 view.snapshot.processes={...view.snapshot.processes,quality:'partial',countExact:false,complete:false,truncated:true,observedCount:200,rows};
 view.processMetrics={...view.processMetrics,observedCount:61,truncated:false,rows:rows.map(({pid})=>({pid,cpuPercent:pid===61?null:pid===1?2:pid===2?10:pid===3?125.25:pid,cpuQuality:pid===61?'denied':'observed',memoryBytes:pid===61?null:pid===1?'9007199254740993':pid===2?'9007199254740992':pid===60?'18446744073709551615':String(pid*1024),memoryQuality:pid===61?'denied':'observed'}))};
 return view;
}
export async function exerciseWindowsProcessControls({page,expect,locale,width,shot,disclosure}){
 const de=locale==='de',workspace=page.locator('.windows-inventory'),table=workspace.locator('.windows-inventory-table'),rows=table.locator('tbody tr');
 const filter=page.getByRole('searchbox',{name:de?'Erfasste Prozesse nach Name oder PID filtern':'Filter captured processes by name or PID',exact:true});
 const sort=page.getByRole('combobox',{name:de?'Erfasste Prozesse sortieren':'Sort captured processes',exact:true});
 const next=page.getByRole('button',{name:de?'Nächste Seite':'Next page',exact:true}),previous=page.getByRole('button',{name:de?'Vorherige Seite':'Previous page',exact:true});
 await expect(rows).toHaveCount(25);await expect(rows.first()).toContainText('synthetic-process-001.exe');
 await expect(workspace).toContainText(de?'61 erfasst · mindestens 200 beobachtet':'61 captured · at least 200 observed');
 await expect(page.locator('.windows-process-metrics-note')).toContainText(de?'61 erfasst · 61 im begrenzten Umfang beobachtet':'61 captured · 61 observed within bounded scope');
 await expect(previous).toBeDisabled();await next.click();await expect(rows.first()).toContainText('synthetic-process-026.exe');
 await next.focus();await page.keyboard.press('Enter');await expect(rows).toHaveCount(11);await expect(rows.first()).toContainText('synthetic-process-051.exe');await expect(next).toBeDisabled();
 await expect(workspace).toContainText(de?'Zeilen 51–61 von 61 Treffern · 61 erfasst':'Rows 51–61 of 61 matching · 61 captured');
 for(const query of ['061','SYNTHETIC-PROCESS-061']){await filter.fill(query);await expect(rows).toHaveCount(1);await expect(rows.first()).toContainText('synthetic-process-061.exe');await expect(previous).toBeDisabled();}
 await filter.fill('absent-fixture');await expect(table).toHaveCount(0);await expect(workspace).toContainText(de?'Keine erfassten Prozesse entsprechen diesem Filter.':'No captured processes match this filter.');
 await filter.fill('');await expect(rows).toHaveCount(25);
 await sort.selectOption('cpu-desc');await expect(rows.first()).toContainText('synthetic-process-003.exe');
 await sort.selectOption('cpu-asc');await expect(rows.first()).toContainText('synthetic-process-001.exe');
 await sort.selectOption('ram-desc');await expect(rows.first()).toContainText('synthetic-process-060.exe');await expect(rows.nth(1)).toContainText('synthetic-process-001.exe');await expect(rows.nth(2)).toContainText('synthetic-process-002.exe');
 await next.click();await next.click();await expect(rows.last()).toContainText('synthetic-process-061.exe');await expect(rows.last()).toContainText(de?'Zugriff verweigert':'Access denied');
 await sort.selectOption('ram-asc');await expect(rows.first()).toContainText('synthetic-process-003.exe');await next.click();await next.click();await expect(rows.last()).toContainText('synthetic-process-061.exe');
 await sort.selectOption('cpu-desc');await expect(previous).toBeDisabled();await expect(filter).toBeVisible();await expect(sort).toBeVisible();
 expect(await workspace.evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);
 await page.locator('.windows-process-controls').scrollIntoViewIfNeeded();await shot(page,`synthetic-windows-process-controls-${width}-${locale}`,disclosure);
 await sort.selectOption('pid-asc');
}
