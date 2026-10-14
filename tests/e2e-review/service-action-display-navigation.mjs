/** Pure harness navigation, separately exercised against the production DOM. */
export async function openServiceActionDisplay(page,base,deviceId,settleRoute,mark=()=>{}){
 await page.goto(`${base}/#/devices/${deviceId}`);
 await page.reload();
 mark('detail-route-readiness');await settleRoute();
 mark('inventory-tab');await page.getByRole('tab',{name:'Inventory',exact:true}).click();
 mark('services-tab');await page.getByRole('tab',{name:'Services',exact:true}).click();
}
