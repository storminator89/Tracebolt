import { getProtectedRequestEpoch, mutateRaw, request } from './api';
import { hasLogoutIntent, validOperatorSession } from './auth';
import { sameSoftware } from './windows-software-jobs-types';
import { validManagedView } from './windows-managed-msi-types';
import { sameWorklistPackage, validWorklistPreview, validWorklistsView, validWorklistView, worklistAcknowledgements, worklistBindingDigest, worklistDispatchBody, worklistPath, type SaveWorklistBody, type WorklistBatch, type WorklistKind, type WorklistPreview, type WorklistRequest, type WorklistsView, type WorklistView } from './windows-managed-msi-worklist-types';

export type WorklistResourceState={data:WorklistsView|null;busy:boolean;running:boolean;preview:WorklistPreview|null;error:''|'invalid'|'unconfirmed'|'closeUnconfirmed'|'stopped';closeUnconfirmed:string;writeUnconfirmed:boolean};
type Options={actor:string;expires:string;allowed:(stage?:WorklistKind)=>boolean;onChange:(s:WorklistResourceState)=>void};
const same=(a:unknown,b:unknown)=>JSON.stringify(a)===JSON.stringify(b);
// Uncertainty only, never acknowledgements or authority; survives component remount.
const pendingCloses=new Map<string,{worklistId:string;batchId:string;expires:string}>();
const openBatch=(w:WorklistView)=>w.batches.find(b=>b.closedAt===0);
/** Memory contains foreground intent only. Reopening never dispatches or closes a saved batch. */
export class ManagedMSIWorklistResource {
 state:WorklistResourceState={data:null,busy:false,running:false,preview:null,error:'',closeUnconfirmed:'',writeUnconfirmed:false};
 private stopped=false;
 private disposed=false;
 private epoch=getProtectedRequestEpoch();
 private serverFloor=0;
 private anchor:{server:number;mono:number;wall:number}|null=null;
 private currentRun:{worklistId:string;batchId:string}|null=null;
 private deadline:ReturnType<typeof setTimeout>|undefined;
 constructor(private options:Options){const pending=pendingCloses.get(this.key());if(pending)this.state={...this.state,closeUnconfirmed:pending.batchId,writeUnconfirmed:true,error:'closeUnconfirmed'}}
 private syncClose(){const pending=pendingCloses.get(this.key());if(pending)this.emit({closeUnconfirmed:pending.batchId,writeUnconfirmed:true,error:'closeUnconfirmed'});else if(this.state.closeUnconfirmed)this.emit({closeUnconfirmed:'',writeUnconfirmed:false,error:''})}
 private key(){return `${this.options.actor}:${this.options.expires}`}
 private invalidate(){if(!this.state.data)return;this.emit({data:{...this.state.data,worklists:this.state.data.worklists.map(w=>({...w,rows:w.rows.map(row=>({deviceId:row.deviceId,available:false,state:'unavailable',...(row.historicalOutcome?{historicalOutcome:row.historicalOutcome}:{}),...(row.view?.result||row.historicalResult?{historicalResult:row.view?.result??row.historicalResult}: {})}))}))}})}
 private emit(patch:Partial<WorklistResourceState>){this.state={...this.state,...patch};if(!this.disposed)this.options.onChange(this.state)}
 private now(){const a=this.anchor;if(!a)return NaN;const elapsed=performance.now()-a.mono;if(elapsed<0||Math.abs(Date.now()-a.wall-elapsed)>1500)return NaN;return a.server+elapsed/1000}
 private active(stage?:WorklistKind){return !this.stopped&&!this.disposed&&this.options.allowed(stage)&&!hasLogoutIntent()&&!document.hidden&&this.epoch===getProtectedRequestEpoch()&&this.now()<Date.parse(this.options.expires)/1000}
 private async bounded<T>(task:(signal:AbortSignal)=>Promise<T>):Promise<T>{const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),15000);try{return await task(controller.signal)}finally{clearTimeout(timer)}}
 private async session(stage?:WorklistKind,closing=false){
  const value=await this.bounded(signal=>request<unknown>('/auth/session',{signal},16384));
  if(!validOperatorSession(value)||value.mode!=='lan'||!value.authenticated||value.loginMode!=='named'||value.actorId!==this.options.actor||value.expiresAt!==this.options.expires||value.insecureTestMode||Date.parse(value.expiresAt)<=Date.parse(value.serverNow)||!value.capabilities?.some(c=>c==='windows_managed_msi_deliver'||c==='windows_managed_msi_install')||stage&&!value.capabilities.includes(stage==='deliver'?'windows_managed_msi_deliver':'windows_managed_msi_install')||this.epoch!==getProtectedRequestEpoch()||hasLogoutIntent()||!closing&&!this.options.allowed(stage))throw Error('session');
  const server=Date.parse(value.serverNow)/1000;if(Math.floor(server)<this.serverFloor)throw Error('clock');this.serverFloor=Math.max(this.serverFloor,Math.floor(server));this.anchor={server:Math.max(server,Number.isFinite(this.now())?this.now():server),mono:performance.now(),wall:Date.now()};return value;
 }
 private accept(data:WorklistsView){
  if(data.serverNow<this.serverFloor)throw Error('clock');this.serverFloor=Math.max(this.serverFloor,data.serverNow);
  for(const old of this.state.data?.worklists??[]){const next=data.worklists.find(w=>w.id===old.id);if(!next)continue;
   if(next.revision<old.revision||next.createdAt!==old.createdAt||next.createdBy!==old.createdBy||next.name!==old.name||next.artifactId!==old.artifactId||next.artifactRetiredCount!==old.artifactRetiredCount||!sameSoftware(next.package,old.package)||next.nativeAcceptanceDigest!==old.nativeAcceptanceDigest||next.publisherStatus!==old.publisherStatus||next.publisherEvidenceDigest!==old.publisherEvidenceDigest||!same(next.group,old.group)||next.targets.length!==old.targets.length||next.targets.some((t,i)=>t.name!==old.targets[i].name||!same(t.binding,old.targets[i].binding)||old.targets[i].transferId!==''&&(t.transferId!==old.targets[i].transferId||t.jobSequence!==old.targets[i].jobSequence)))throw Error('changed');
  }
  this.anchor={server:Math.max(data.serverNow,Number.isFinite(this.now())?this.now():data.serverNow),mono:performance.now(),wall:Date.now()};
  const uncertain=this.state.closeUnconfirmed;const closed=uncertain&&data.worklists.some(w=>w.batches.some(b=>b.id===uncertain&&b.closedAt!==0));
  if(closed&&pendingCloses.get(this.key())?.batchId===uncertain)pendingCloses.delete(this.key());
  this.emit({data,...(closed?{closeUnconfirmed:'',writeUnconfirmed:false,error:'' as const}:{})});return data;
 }
 private async fetch(){const value=await this.bounded(signal=>request<unknown>(worklistPath,{signal},4*1024*1024));if(!validWorklistsView(value))throw Error('invalid');return this.accept(value)}
 private retirementIssued(w:WorklistView,batchId:string,index:number,q:WorklistRequest){const b=w.batches.find(b=>b.id===batchId),item=b?.items[index],view=w.rows.find(row=>row.deviceId===q.deviceId)?.view;return b?.kind==='retire'&&item?.state==='issued'&&same(item.request,q)&&item.jobSequence===q.jobSequence&&!!view&&sameWorklistPackage(view,w)&&view.bindingDigest===q.bindingDigest&&view.transferId===q.transferId&&view.jobSequence===q.jobSequence&&view.resultDigest===q.resultDigest&&['retirement_pending','retired','intervention_required'].includes(view.state)}
 private async post(path:string,body:unknown,guard:()=>boolean=()=>this.active()){return this.bounded(signal=>mutateRaw<unknown>(path,JSON.stringify(body),{},signal,2*1024*1024,guard))}
 private find(id:string){const w=this.state.data?.worklists.find(w=>w.id===id);if(!w||!this.state.data?.enabled)throw Error('unavailable');return w}
 private put(w:unknown,id?:string){if(!validWorklistView(w)||id&&w.id!==id||!this.state.data)throw Error('invalid');return this.accept({...this.state.data,serverNow:w.serverNow,worklists:[...this.state.data.worklists.filter(old=>old.id!==w.id),w]}).worklists.find(v=>v.id===w.id)!}
 async read(){if(this.state.busy||this.disposed)return;this.syncClose();this.stopped=false;this.emit({busy:true,preview:null,error:this.state.closeUnconfirmed?'closeUnconfirmed':''});try{await this.session();await this.fetch();if(!this.state.closeUnconfirmed)this.emit({writeUnconfirmed:false,error:''})}catch{this.invalidate();this.emit({error:this.state.closeUnconfirmed?'closeUnconfirmed':'invalid'})}finally{this.emit({busy:false})}}
 async save(body:SaveWorklistBody){if(this.state.busy||this.state.writeUnconfirmed||!this.active())return;this.emit({busy:true,error:'',preview:null});let sent=false;try{await this.session();if(!this.active())throw Error();sent=true;const response=await this.post(`${worklistPath}/save`,body);if(!validWorklistView(response)||response.name!==body.name||response.artifactId!==body.artifactId||response.artifactRetiredCount!==body.artifactRetiredCount||!same(response.group,body.group)||response.targets.length!==body.targets.length||!body.targets.every((t,i)=>response.targets[i].binding.deviceId===t.deviceId&&response.targets[i].name===t.name))throw Error('changed save');const hashes=await Promise.all(response.targets.map(t=>worklistBindingDigest(t.binding)));if(hashes.some((hash,i)=>hash!==body.targets[i].bindingDigest))throw Error('changed binding');await this.fetch();if(this.find(response.id).revision<response.revision)throw Error('unconfirmed save');if(!this.active())throw Error()}catch{this.emit({error:sent?'unconfirmed':'invalid',writeUnconfirmed:sent})}finally{this.emit({busy:false})}}
 async preview(id:string,stage:WorklistKind){if(this.state.busy||this.state.writeUnconfirmed||this.state.closeUnconfirmed||!this.active())return;this.emit({busy:true,preview:null,error:''});try{await this.session(stage);const data=await this.fetch(),w=data.worklists.find(w=>w.id===id);if(!this.active()||!w||w.archivedAt||openBatch(w))throw Error();const value=await this.post(`${worklistPath}/${id}/preview`,{revision:w.revision,kind:stage},()=>this.active(stage));if(!this.active()||!validWorklistPreview(value,w,stage)||value.items.some(q=>q.expiresAt<=this.now()))throw Error();this.emit({preview:value})}catch{this.invalidate();this.emit({error:'invalid'})}finally{this.emit({busy:false})}}
 dismiss(){this.emit({preview:null})}
 stop(){this.stopped=true;this.invalidate();this.emit({preview:null,...(this.state.running?{error:'stopped' as const}:{})})}
 dispose(){this.stop();this.disposed=true}
 private async closeRun(id:string,batchId:string){
  if(this.state.closeUnconfirmed)return false;
  await this.session(undefined,true);await this.fetch();const w=this.find(id),b=w.batches.find(b=>b.id===batchId);if(!b)throw Error('missing batch');if(b.closedAt)return true;
  for(const [key,pending] of pendingCloses)if(Date.parse(pending.expires)<=Date.now())pendingCloses.delete(key);
  if(!pendingCloses.has(this.key())&&pendingCloses.size>=128)throw Error('uncertainty capacity');
  let sent=false;const reservation={worklistId:id,batchId,expires:this.options.expires};
  try{this.put(await this.post(`${worklistPath}/${id}/close`,{revision:w.revision,batchId},()=>{if(this.epoch!==getProtectedRequestEpoch()||hasLogoutIntent()||pendingCloses.has(this.key()))return false;pendingCloses.set(this.key(),reservation);sent=true;return true}),id);const closed=this.find(id).batches.find(b=>b.id===batchId);if(!closed?.closedAt)throw Error('unconfirmed close');if(pendingCloses.get(this.key())===reservation)pendingCloses.delete(this.key());return true}
  catch{
   // HTTP 409 can also mean uncertain storage/commit. Every sent failure
   // stays read-only until the exact saved closure is observed.
   if(!sent){this.syncClose();if(!this.state.closeUnconfirmed)this.emit({error:'stopped'});return false}
   if(pendingCloses.get(this.key())===reservation)this.emit({closeUnconfirmed:batchId,writeUnconfirmed:true,error:'closeUnconfirmed'});else this.syncClose();return false;
  }
 }

 async close(id:string){this.syncClose();if(this.state.busy||this.state.closeUnconfirmed||this.state.writeUnconfirmed)return;const b=openBatch(this.find(id));if(!b)return;this.stop();this.emit({busy:true});try{const closed=await this.closeRun(id,b.id);if(closed)this.emit({error:''})}catch{this.emit({error:'unconfirmed',writeUnconfirmed:true})}finally{this.emit({busy:false})}}
 async archive(id:string){if(this.state.busy||this.state.writeUnconfirmed||this.state.closeUnconfirmed||!this.active())return;this.emit({busy:true,error:'',preview:null});let sent=false;try{await this.session();if(!this.active())throw Error();const w=this.find(id);if(w.archivedAt||openBatch(w))throw Error();sent=true;this.put(await this.post(`${worklistPath}/${id}/archive`,{revision:w.revision}),id);await this.fetch()}catch{this.emit({error:sent?'unconfirmed':'invalid',writeUnconfirmed:sent})}finally{this.emit({busy:false})}}
 async confirm(acknowledged:boolean){
  const preview=this.state.preview;if(!acknowledged||!preview||!preview.items.length||this.state.busy||this.state.writeUnconfirmed||!this.active())return;
  this.stopped=false;this.emit({busy:true,running:true,preview:null,error:''});let confirmed:WorklistBatch|undefined,attemptedConfirmation=false,unconfirmedRetirement:{index:number;request:WorklistRequest}|undefined;
  try{
   await this.session(preview.kind);if(!this.active()||preview.items.some(q=>q.expiresAt<=this.now()))throw Error();const w=this.find(preview.worklistId);if(w.revision!==preview.revision||openBatch(w))throw Error();
   attemptedConfirmation=true;const next=this.put(await this.post(`${worklistPath}/${w.id}/batches`,{revision:preview.revision,kind:preview.kind,items:preview.items,acknowledgements:worklistAcknowledgements(preview.kind)},()=>this.active(preview.kind)&&preview.items.every(q=>q.expiresAt>this.now())),w.id);
   confirmed=openBatch(next);if(!confirmed||confirmed.kind!==preview.kind||confirmed.actorId!==this.options.actor||confirmed.sessionExpiresAt!==Math.floor(Date.parse(this.options.expires)/1000)||!same(confirmed.items.map(i=>i.request),preview.items)||confirmed.items.some(i=>i.state!=='not_dispatched'))throw Error('confirmation');
   this.currentRun={worklistId:w.id,batchId:confirmed.id};this.deadline=setTimeout(()=>this.stop(),Math.max(0,(confirmed.expiresAt-this.now())*1000));
   for(let index=0;index<confirmed.items.length;index++){
    await this.session(preview.kind);if(!this.active()||this.now()>=confirmed.expiresAt||this.now()>=confirmed.items[index].request.expiresAt)throw Error('stopped');
    const item=confirmed.items[index],q=item.request;
    if(preview.kind==='retire')unconfirmedRetirement={index,request:q};
    const response=await this.bounded(signal=>mutateRaw<unknown>(`/devices/${q.deviceId}/windows-managed-msi/${q.operation}`,JSON.stringify(worklistDispatchBody(next,confirmed!,index)),{},signal,65536,()=>this.active(preview.kind)&&this.now()<confirmed!.expiresAt&&this.now()<q.expiresAt));
    if(!validManagedView(response,q.deviceId)||!sameWorklistPackage(response,next)||response.bindingDigest!==q.bindingDigest||response.transferId!==q.transferId||preview.kind!=='deliver'&&response.jobSequence!==q.jobSequence||preview.kind==='approve'&&response.readinessDigest!==q.readinessDigest||preview.kind==='retire'&&(response.resultDigest!==q.resultDigest||!['retirement_pending','retired','intervention_required'].includes(response.state)))throw Error('response');
    await this.fetch();const durable=this.find(w.id).batches.find(b=>b.id===confirmed!.id);if(!durable||durable.items[index].state!=='issued'||!same(durable.items[index].request,q)||preview.kind==='retire'&&!this.retirementIssued(this.find(w.id),confirmed.id,index,q))throw Error('unconfirmed');
    unconfirmedRetirement=undefined;
    if(!this.active())break;
   }
  }catch{this.stopped=true;this.emit({error:attemptedConfirmation?'unconfirmed':'invalid',writeUnconfirmed:attemptedConfirmation})}
  finally{
   if(this.deadline)clearTimeout(this.deadline);
   if(attemptedConfirmation){try{
    if(!this.currentRun){
     // Identical review/approval bodies can belong to a different tab. Without
     // this response's batch ID, only read; never adopt another open batch.
     await this.session(undefined,true);await this.fetch();this.emit({error:'unconfirmed',writeUnconfirmed:true});
    }else{
     if(unconfirmedRetirement){
      // A lost/malformed retirement response is reconciled only by exact GET
      // evidence. Never resend or close against another settled result.
      await this.session(undefined,true);await this.fetch();
      if(!this.retirementIssued(this.find(this.currentRun.worklistId),this.currentRun.batchId,unconfirmedRetirement.index,unconfirmedRetirement.request))throw Error('unconfirmed retirement');
     }
     await this.closeRun(this.currentRun.worklistId,this.currentRun.batchId);if(!this.state.closeUnconfirmed)this.emit({writeUnconfirmed:false,error:this.stopped?'stopped':''})}
   }catch{this.emit({error:'unconfirmed',writeUnconfirmed:true})}}
   this.currentRun=null;this.emit({busy:false,running:false});
  }
 }
}
