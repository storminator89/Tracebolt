/** Inert, dependency-injected browser helper. Diagnostics are fixed labels only;
 * never pass response bodies, errors, URLs, secret values or DOM contents to mark.
 */
const invocations=new Set(['single','first','second']);
const phases=new Set(['open dialog','submit','await response','response status','parse response','response schema','secret type','masked field']);
export function invitationCreationStage(invocation,phase){
 const call=invocations.has(invocation)?invocation:'single';
 const step=phases.has(phase)?phase:'unknown';
 return `create invitation ${call}: ${step}`;
}

export async function createBrowserInvitation(page,{base,mark,expect,secrets,invocation='single'}){
 const step=phase=>mark(invitationCreationStage(invocation,phase));
 step('open dialog');
 await page.getByRole('button',{name:'Add device',exact:true}).click();
 // Keep registration before the write. This helper never retries a mutation.
 const responsePending=page.waitForResponse(r=>r.url()===`${base}/api/enrollment/invitations`&&r.request().method()==='POST');
 step('submit');
 await page.getByRole('button',{name:'Create invitation',exact:true}).click();
 step('await response');
 const response=await responsePending;
 step('response status');
 expect(response.status()).toBe(201);
 step('parse response');
 const created=await response.json();
 step('response schema');
 expect(created?.schemaVersion==='tracebolt.enrollment-invitation.v2').toBe(true);
 step('secret type');
 expect(typeof created.invitationSecret).toBe('string');
 secrets.push(created.invitationSecret);
 step('masked field');
 await expect(page.getByLabel('One-time invitation secret',{exact:true})).toHaveAttribute('type','password');
 return created;
}
