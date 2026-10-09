/** Pure DOM evidence for an accepted inventory projection. No network, clock,
 * lifecycle changes, retries or response-body inspection. evaluateAll-compatible. */
export function inventoryProjectionReady(panels,selector){
 if(panels.length!==1)return false;
 const panel=panels[0];
 if(!panel.isConnected||panel.getAttribute('aria-busy')!=='false'||panel.querySelector('[role=alert]'))return false;
 if(selector==='.complete-overview')return Boolean(panel.querySelector('.overview-progress')||panel.querySelector(':scope > p[role=status]'));
 if(selector==='.complete-packages'||selector==='.system-inventory')return Boolean(panel.querySelector('.complete-package-pagination')||panel.querySelector(':scope > .package-status')&&!panel.querySelector('.complete-package-search'));
 if(selector==='.software-overview')return Boolean(panel.querySelector(':scope > .package-status'));
 return false;
}
export function hasInventoryReadiness(selector){
 return ['.complete-overview','.complete-packages','.system-inventory','.software-overview'].includes(selector);
}
