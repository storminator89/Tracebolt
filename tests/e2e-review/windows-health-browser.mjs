/** Called only by the existing hosted runner. Synthetic DTOs and GETs only. */
export const windowsHealthStageNames=['health-current','health-unverified','health-restored'];
export async function exerciseWindowsHealth({page,expect,locale,width,shot,disclosure,setPhase,mark,now}){
 const de=locale==='de',health=page.getByRole('region',{name:de?'Systemvolume-Beobachtung':'System-volume observation',exact:true});
 const contact=page.getByRole('region',{name:de?'Verlauf akzeptierter Meldungen':'Accepted-contact history',exact:true}),disk=health.getByRole('region',{name:de?'Systemvolume':'System volume',exact:true});
 const recent=de?'Aktuelle Meldung':'Recent report',current=de?'Aktuelle Messung':'Current reading',value=de?'61,0 %':'61.0 %';
 const metadata=page.getByRole('button',{name:de?'Gerätedaten aktualisieren':'Refresh device metadata',exact:true});
 const events=page.getByRole('region',{name:de?'Windows-Ereignisse':'Windows events',exact:true});
 const refreshEvents=events.getByRole('button',{name:de?'Aktualisieren':'Refresh events',exact:true});
 const refresh=async()=>{await metadata.click();await expect(metadata).toBeEnabled();await refreshEvents.click();await expect(refreshEvents).toBeEnabled();};
 const positive=async()=>{
  await expect(contact.getByText(recent,{exact:true})).toBeVisible();await expect(contact.locator('time')).toHaveCount(2);await expect(contact.locator('.windows-contact-times').first().locator('time').first()).toHaveAttribute('datetime',new Date(Date.parse(now())-1000).toISOString());
  await expect(disk.getByText(value,{exact:true})).toBeVisible();await expect(disk.getByText(current,{exact:true})).toBeVisible();await expect(disk.locator('time')).toHaveCount(1);await expect(disk.locator('time')).toHaveAttribute('datetime',new Date(Date.parse(now())-10000).toISOString());
  await expect(contact.getByText(de?'Vom Manager akzeptierte Windows-Meldungen. Die aktuelle Erreichbarkeit wird nicht geprüft.':'Manager-accepted Windows reports. Live reachability is not checked.',{exact:true})).toBeVisible();
  await expect(health.getByRole('status')).toHaveCount(0);
  expect(await health.evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);
 };
 mark('health-current');setPhase('health-current');await refresh();await positive();
 await health.scrollIntoViewIfNeeded();await shot(page,`synthetic-windows-health-current-${width}-${locale}`,disclosure);
 // A fresh inventory/event response cannot replace absent identity authority.
 mark('health-unverified');setPhase('health-unverified');await refresh();
 await expect(contact.getByText(de?'Unbekannt':'Unknown',{exact:true})).toBeVisible();await expect(disk.getByText('—',{exact:true})).toBeVisible();
 await expect(disk.getByText(de?'Unbekannt':'Unknown',{exact:true})).toBeVisible();await expect(health.locator('time')).toHaveCount(0);await expect(contact.locator('time')).toHaveCount(0);
 await expect(health.getByRole('status')).toHaveText(de?'Die aktuelle Gerätefreigabe konnte nicht bestätigt werden. Messungen sind ausgeblendet.':'Current device access could not be verified. Readings are hidden.');
 await expect(contact.getByRole('status')).toHaveText(de?'Die aktuelle Gerätefreigabe konnte nicht bestätigt werden. Der Meldungsverlauf ist ausgeblendet.':'Current device access could not be verified. Contact history is hidden.');
 await expect(contact.getByText(recent,{exact:true})).toHaveCount(0);await expect(disk.getByText(value,{exact:true})).toHaveCount(0);
 await expect(events.getByRole('status')).toHaveText(de?'Beobachtete Ereignisse':'Observed events');
 await health.scrollIntoViewIfNeeded();await shot(page,`synthetic-windows-health-unverified-${width}-${locale}`,disclosure);
 // Leave the following event screenshot with a checked positive summary too.
 mark('health-restored');setPhase('fresh');await refresh();await positive();
}
