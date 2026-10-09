/** Inert, dependency-injected browser helper. Only fixed stages and finite
 * primary/transport snapshots are reported, never raw response/error/UI data. */
const invocations=new Set(['single','first','second']);
const phases=new Set(['open dialog','arm primary reader','submit','await response','response status','await primary reader','primary reader complete','primary response binding','response schema','secret type','masked field','masked value']);
export function invitationCreationStage(invocation,phase){
 const call=invocations.has(invocation)?invocation:'single';
 const step=phases.has(phase)?phase:'unknown';
 return `create invitation ${call}: ${step}`;
}
export async function createBrowserInvitation(page,{base,mark,expect,secrets,invocation='single',transportDiagnostics,recordTransportFailure=()=>{},recordPrimaryFailure=()=>{}}){
 const step=phase=>mark(invitationCreationStage(invocation,phase));
 let capture,response;
 try{
  step('open dialog');
  await page.getByRole('button',{name:'Add device',exact:true}).click();
  step('arm primary reader');
  capture=await page.evaluate(()=>window.__traceboltEnrollmentBody.arm());
  // Register before the write. Observe the same POST and the application's
  // primary reader; no CDP body retrieval, clone, second read or mutation retry.
  const responsePending=page.waitForResponse(r=>r.url()===`${base}/api/enrollment/invitations`&&r.request().method()==='POST');
  step('submit');
  await page.getByRole('button',{name:'Create invitation',exact:true}).click();
  step('await response');response=await responsePending;
  step('response status');expect(response.status()).toBe(201);
  step('await primary reader');
  await expect.poll(()=>page.evaluate(id=>window.__traceboltEnrollmentBody.state(id),capture)).not.toMatch(/^(armed|waiting|reading)$/);
  step('primary reader complete');
  expect(await page.evaluate(id=>window.__traceboltEnrollmentBody.state(id),capture)).toBe('complete');
  // take() rejects any abort/invalidation observed through primary completion.
  // The masked-value checks below independently require application acceptance.
  const primary=await page.evaluate(id=>window.__traceboltEnrollmentBody.snapshot(id),capture);
  expect(primary.eof===true&&primary.signalAborted===false&&primary.requests===1).toBe(true);
  const consumed=await page.evaluate(id=>window.__traceboltEnrollmentBody.take(id),capture);
  step('primary response binding');expect(consumed!==null).toBe(true);expect(consumed.status).toBe(201);
  expect(consumed.requestBody===response.request().postData()).toBe(true);
  const created=consumed.body;
  step('response schema');expect(created?.schemaVersion==='tracebolt.enrollment-invitation.v2').toBe(true);
  step('secret type');expect(typeof created.invitationSecret).toBe('string');secrets.push(created.invitationSecret);
  step('masked field');const input=page.getByLabel('One-time invitation secret',{exact:true});
  await expect(input).toHaveAttribute('type','password');
  step('masked value');expect(await input.inputValue()===created.invitationSecret).toBe(true);
  return created;
 }catch(error){
  try{recordPrimaryFailure(await page.evaluate(id=>window.__traceboltEnrollmentBody.snapshot(id),capture));}catch{}
  try{recordTransportFailure(transportDiagnostics.capture('other',error,{response}));}catch{}
  throw error;
 }finally{
  // Includes failures before take and rejected UI validation. No secret-bearing
  // observer state survives into dismissal, authentication or screenshot tests.
  try{await page.evaluate(()=>window.__traceboltEnrollmentBody.clear());}catch{}
 }
}
