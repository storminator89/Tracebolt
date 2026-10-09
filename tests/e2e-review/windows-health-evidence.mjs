/** Completion metadata for the existing hosted Health screenshots. Pure check:
 * no browser, filesystem, native API, screenshot capture or DTO generation.
 * The live runner records each item only after page.screenshot succeeds. This
 * proves all promised outputs were emitted, not what their pixels establish.
 */
export function requireWindowsHealthEvidence(screenshots,sourceSha,testName){
 const fail=()=>{throw new Error('Windows Health completion evidence missing or inconsistent');};
 if(!Array.isArray(screenshots)||!(sourceSha===null||typeof sourceSha==='string'&&/^[a-f0-9]{40}$/.test(sourceSha))||typeof testName!=='string'||!testName)fail();
 const expected=[];
 for(const locale of ['en','de'])for(const width of [1440,390])for(const phase of ['current','unverified']){
  expected.push({file:`synthetic-windows-health-${phase}-${width}-${locale}.png`,locale,width,height:width===390?844:1000});
 }
 const health=screenshots.filter(item=>typeof item?.file==='string'&&item.file.startsWith('synthetic-windows-health-'));
 if(health.length!==expected.length)fail();
 for(const required of expected){
  const matches=health.filter(item=>item.file===required.file);
  if(matches.length!==1)fail();
  const item=matches[0];
  if(item.sourceSha!==sourceSha||item.test!==testName||item.locale!==required.locale||item.viewport?.width!==required.width||item.viewport?.height!==required.height||item.publicSafe!==true||item.fullPage!==false)fail();
 }
 return {positive:4,authorityLoss:4};
}
