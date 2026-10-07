/** Metadata-only navigation acceptance inside the existing LAN fixture case.
 * No response bodies, headers, storage, screenshots or additional browser. */
export function workspaceRequestMetadata(request,base){
 const url=new URL(request.url()),api=url.origin===base&&url.pathname.startsWith('/api/');
 return {
  documentNavigation:Number(request.isNavigationRequest()&&request.resourceType()==='document'),
  overviewReads:Number(api&&url.pathname==='/api/overview'),
  sessionReads:Number(api&&url.pathname==='/api/auth/session'),
  unexpectedMethodOrBody:Number(api&&(request.method()!=='GET'||request.postData()!==null)),
  externalRequests:Number(url.origin!==base),
 };
}

// The handle stays inside this document. Navigation destroys it; Back/Forward
// cache restoration is also caught by pagehide, even if the nodes survive.
export function installWorkspaceContinuity(){
 const originalDocument=document,timeOrigin=performance.timeOrigin;
 const selectors={shell:'.app-shell',sidebar:'.sidebar',topbar:'.topbar',main:'#main-content'};
 const anchors=Object.fromEntries(Object.entries(selectors).map(([key,selector])=>[key,document.querySelector(selector)]));
 if(Object.values(anchors).some(node=>!node))throw new Error('Workspace continuity anchors unavailable');
 const removedAnchors={shell:0,sidebar:0,topbar:0,main:0};let initialLoadingInsertions=0,pageHides=0;
 const mutations=records=>{
  for(const record of records){
   for(const removed of record.removedNodes)for(const [key,anchor] of Object.entries(anchors))if(removed===anchor||removed.contains(anchor))removedAnchors[key]++;
   for(const added of record.addedNodes)if(added.nodeType===1&&(added.matches('.initial-loading')||added.querySelector('.initial-loading')))initialLoadingInsertions++;
  }
 };
 const observer=new MutationObserver(mutations);observer.observe(document.documentElement,{childList:true,subtree:true});
 const pagehide=()=>{pageHides++;};window.addEventListener('pagehide',pagehide);
 return {
  read(){
   mutations(observer.takeRecords());
   return {sameDocument:document===originalDocument&&performance.timeOrigin===timeOrigin,identity:Object.fromEntries(Object.entries(anchors).map(([key,node])=>[key,node.isConnected&&node===document.querySelector(selectors[key])])),removedAnchors:{...removedAnchors},initialLoadingInsertions,pageHides};
  },
  stop(){observer.disconnect();window.removeEventListener('pagehide',pagehide);},
 };
}

/** Begins and ends on Devices after the existing case's authenticated load. */
export async function workspaceNavigationBrowserProbe({page,expect,base}){
 await expect(page.getByRole('heading',{name:'Devices',exact:true,level:1})).toBeVisible();
 await expect(page.locator('.initial-loading')).toHaveCount(0);
 const counts={documentNavigation:0,overviewReads:0,sessionReads:0,unexpectedMethodOrBody:0,externalRequests:0};
 const requested=request=>{for(const [key,value] of Object.entries(workspaceRequestMetadata(request,base)))counts[key]+=value;};
 const continuity=await page.evaluateHandle(installWorkspaceContinuity);page.on('request',requested);
 const routes={overview:'Overview',devices:'Devices',cases:'Investigations'};
 const sidebarButton=view=>page.locator('.sidebar nav').getByRole('button',{name:new RegExp('^'+routes[view]+'(?:\\s*\\d+)?$')});
 const assertRoute=async view=>{
  await expect(page).toHaveURL(`${base}/#/${view}`);
  await expect(page.getByRole('heading',{name:routes[view],exact:true,level:1})).toBeVisible();
  await expect(sidebarButton(view)).toHaveAttribute('aria-current','page');
  await expect(page.locator('.sidebar nav [aria-current="page"]')).toHaveCount(1);
  for(const selector of ['.app-shell','.sidebar','.topbar','#main-content'])await expect(page.locator(selector)).toBeVisible();
  // Drain rendering and passive effects, including request dispatch, without
  // raising the runner's assertion timeout or adding a fixed sleep.
  await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(()=>resolve()))));
  expect(await continuity.evaluate(probe=>probe.read())).toEqual({sameDocument:true,identity:{shell:true,sidebar:true,topbar:true,main:true},removedAnchors:{shell:0,sidebar:0,topbar:0,main:0},initialLoadingInsertions:0,pageHides:0});
  expect(counts).toEqual({documentNavigation:0,overviewReads:0,sessionReads:0,unexpectedMethodOrBody:0,externalRequests:0});
 };
 try{
  // The filter is WorkspaceApp state and must survive route changes as well.
  await page.getByLabel('Search devices',{exact:true}).fill('Fixture');
  for(const view of ['overview','cases','devices']){await sidebarButton(view).click();await assertRoute(view);}
  await expect(page.getByLabel('Search devices',{exact:true})).toHaveValue('Fixture');
  // Do not wait for page reads or headings between these real sidebar clicks.
  for(const view of ['overview','devices','cases','overview','devices','cases'])await sidebarButton(view).click();
  await assertRoute('cases');
  await page.goBack();await assertRoute('devices');
  await expect(page.getByLabel('Search devices',{exact:true})).toHaveValue('Fixture');
  await page.goBack();await assertRoute('overview');
  await page.goForward();await assertRoute('devices');
  await page.goForward();await assertRoute('cases');
  await sidebarButton('devices').click();await assertRoute('devices');
  await expect(page.getByLabel('Search devices',{exact:true})).toHaveValue('Fixture');
  await page.getByLabel('Search devices',{exact:true}).fill('');
 }finally{
  page.off('request',requested);
  try{await continuity.evaluate(probe=>probe.stop());}catch{/* A lost document already fails the probe. */}
  await continuity.dispose();
 }
}
