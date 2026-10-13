import { validMutationView, type MutationStatus } from './windows-mutation-status-types';
export type UpdateSelection = { updateId: string; revision: number };
export type UpdateReadiness = { purpose?: 'download'; downloadMetadataKnown?: boolean; downloadOrigins?: string; downloadMinBytes?: number; downloadMaxBytes?: number; downloadSource?: 'default'|'managed_server'|'windows_update'|'other'; downloadServiceId?: string; selection: UpdateSelection; capturedAt: number; software: string; installed: string; hidden: string; downloaded: string; eulaAccepted: string; canRequestUserInput: string; canRequireSource: string; requiresNetwork: string; bundledCount: number; installerBusy: string; rebootRequiredBefore: string; rebootBehavior: string; offlineVerified: string };
export type UpdatePreview = { id: string; actorId: string; binding: { managerId: string; deviceId: string; incarnationDigest: string; executorId: string; executorKeyId: string; grantId: string; keyId: string }; readiness: UpdateReadiness; createdAt: number; expiresAt: number; digest: string };
export type UpdateResult = { purpose?: 'download'; aggregateResultKnown?: boolean; aggregateHresultKnown?: boolean; updateResultKnown?: boolean; updateHresultKnown?: boolean; nativeReturned?: boolean; cleanupSucceeded?: boolean; aggregateOperationResult?: number; aggregateHresult?: number; downloadedAfter?: 'yes'|'no'|'unknown'; jobId: string; envelopeDigest: string; attempted: boolean; outcome: 'not_attempted'|'succeeded'|'failed'|'uncertain'; operationResult: number; hresult: number; rebootRequired: 'yes'|'no'|'unknown'; completedAt: number };
export type UpdateSchedule = { version: 'tracebolt.windows-selected-update-schedule.v1'; digest: string; approvedAt: number; startAt: number; endAt: number; permitIssuedAt: number; revoked: boolean };
export type UpdateRetirement = { state: 'available'|'pending'|'retired'|'blocked'; requestedAt?: number; claimedAt?: number; retiredAt?: number };
export type UpdateJobView = {downloadEnabled?:boolean;downloadAvailable?:boolean;reusableJobs?:true;grantExpiresAt?:number;retiredFloor?:string;backgroundExecutor?:true;backgroundScheduling?:true;executorAvailability?:'verified_recent'|'unknown';executorObservedAt?:number;coordinated?:true;mutation?:MutationStatus;mutationCapturedAt?:number; version: string; deviceId: string; serverNow: number; available: boolean; reason: string; schedulingAvailable?: boolean; schedulingRevoked?: boolean; job: { purpose?: 'download'; id: string; selection: UpdateSelection; state: string; reason: string; preview: UpdatePreview|null; result: UpdateResult|null; schedule?: UpdateSchedule; occurrence?: string; resultDigest?: string; retirement?: UpdateRetirement }|null };
const object=(v:unknown):v is Record<string,unknown>=>typeof v==='object'&&v!==null&&!Array.isArray(v);
const exact=(v:unknown,keys:string[]):v is Record<string,unknown>=>object(v)&&Object.keys(v).length===keys.length&&keys.every(k=>Object.hasOwn(v,k));
const optional=(v:unknown,keys:string[],allowed:string[]):v is Record<string,unknown>=>object(v)&&keys.every(k=>Object.hasOwn(v,k))&&Object.keys(v).every(k=>keys.includes(k)||allowed.includes(k));
const integer=(v:unknown,min=1,max=253402300799):v is number=>Number.isSafeInteger(v)&&Number(v)>=min&&Number(v)<=max;
export const updateID=(v:unknown,prefix:string):v is string=>typeof v==='string'&&new RegExp(`^${prefix}[0-9a-f]{32}$`).test(v);
const digest=(v:unknown):v is string=>typeof v==='string'&&/^sha256:[0-9a-f]{64}$/.test(v);
const sequence=(v:unknown):v is string=>typeof v==='string'&&/^[1-9][0-9]{0,19}$/.test(v)&&BigInt(v)<=18446744073709551615n;
const fact=(v:unknown)=>v==='yes'||v==='no'||v==='unknown';
export const validUpdateSelection=(v:unknown):v is UpdateSelection=>exact(v,['updateId','revision'])&&typeof v.updateId==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(v.updateId)&&v.updateId!=='00000000-0000-0000-0000-000000000000'&&integer(v.revision,0,2147483647);
export const sameUpdate=(a:UpdateSelection,b:UpdateSelection)=>a.updateId===b.updateId&&a.revision===b.revision;
export function validDownloadOrigins(v:unknown):v is string {
 if(typeof v!=='string'||!v||new TextEncoder().encode(v).length>2048)return false;
 const origins=v.split('\n');return origins.length<=8&&origins.every((origin,index)=>{
  if(origin.length>255||index>0&&origin<=origins[index-1]||!/^(https?):\/\/[^/?#\s%\\]+$/.test(origin))return false;
  try{const url=new URL(origin);return (url.protocol==='https:'||url.protocol==='http:')&&!url.username&&!url.password&&url.origin===origin;}catch{return false;}
 });
}
function validPreview(v:unknown,device:string,actor:string,id:string,s:UpdateSelection,now:number,purpose:unknown):v is UpdatePreview{
 if(!exact(v,['id','actorId','binding','readiness','createdAt','expiresAt','digest'])||v.id!==id||v.actorId!==actor||!digest(v.digest)||!integer(v.createdAt)||!integer(v.expiresAt)||v.createdAt>now||v.expiresAt<=now||v.expiresAt-v.createdAt>60)return false;
 const b=v.binding,r=v.readiness;
 if(!exact(b,['managerId','deviceId','incarnationDigest','executorId','executorKeyId','grantId','keyId'])||b.deviceId!==device||!updateID(b.managerId,'manager_')||!updateID(b.executorId,'executor_')||!updateID(b.grantId,'grant_')||!digest(b.incarnationDigest)||!digest(b.keyId)||!digest(b.executorKeyId)||b.executorKeyId===b.keyId)return false;
 if(!optional(r,['selection','capturedAt','software','installed','hidden','downloaded','eulaAccepted','canRequestUserInput','canRequireSource','requiresNetwork','bundledCount','installerBusy','rebootRequiredBefore','rebootBehavior','offlineVerified'],['purpose','downloadMetadataKnown','downloadOrigins','downloadMinBytes','downloadMaxBytes','downloadSource','downloadServiceId'])||r.purpose!==purpose||!validUpdateSelection(r.selection)||!sameUpdate(r.selection,s)||!integer(r.capturedAt)||r.capturedAt>v.createdAt||v.expiresAt>r.capturedAt+60)return false;
 if(purpose==='download')return ['software','eulaAccepted','offlineVerified'].every(k=>r[k]==='yes')&&['installed','hidden','downloaded'].every(k=>r[k]==='no')&&['canRequestUserInput','canRequireSource','requiresNetwork','installerBusy','rebootRequiredBefore'].every(k=>fact(r[k]))&&r.bundledCount===0&&['never','can','always','unknown'].includes(String(r.rebootBehavior))&&r.downloadMetadataKnown===true&&validDownloadOrigins(r.downloadOrigins)&&integer(r.downloadMinBytes??0,0,17179869184)&&integer(r.downloadMaxBytes??0,0,17179869184)&&Number(r.downloadMinBytes??0)<=Number(r.downloadMaxBytes??0)&&['default','managed_server','windows_update','other'].includes(String(r.downloadSource))&&(r.downloadSource==='other'?validUpdateSelection({updateId:r.downloadServiceId,revision:0}):!Object.hasOwn(r,'downloadServiceId'));
 if(['purpose','downloadMetadataKnown','downloadOrigins','downloadMinBytes','downloadMaxBytes','downloadSource','downloadServiceId'].some(k=>Object.hasOwn(r,k)))return false;
 return ['software','downloaded','eulaAccepted','offlineVerified'].every(k=>r[k]==='yes')&&['installed','hidden','canRequestUserInput','canRequireSource','requiresNetwork','installerBusy','rebootRequiredBefore'].every(k=>r[k]==='no')&&r.bundledCount===0&&['never','can','always'].includes(String(r.rebootBehavior));
}
function validResult(v:unknown,id:string,now:number,purpose:unknown):v is UpdateResult{
 if(!optional(v,['jobId','envelopeDigest','attempted','outcome','operationResult','hresult','rebootRequired','completedAt'],['purpose','aggregateResultKnown','aggregateHresultKnown','updateResultKnown','updateHresultKnown','nativeReturned','cleanupSucceeded','aggregateOperationResult','aggregateHresult','downloadedAfter'])||v.purpose!==purpose||v.jobId!==id||!digest(v.envelopeDigest)||typeof v.attempted!=='boolean'||!integer(v.operationResult,0,5)||!integer(v.hresult,-2147483648,2147483647)||!fact(v.rebootRequired)||!integer(v.completedAt)||v.completedAt>now)return false;
 if(purpose==='download'){
  const known=['aggregateResultKnown','aggregateHresultKnown','updateResultKnown','updateHresultKnown'];
  if(known.some(k=>Object.hasOwn(v,k)&&typeof v[k]!=='boolean')||!v.aggregateResultKnown&&(v.aggregateOperationResult??0)!==0||!v.aggregateHresultKnown&&(v.aggregateHresult??0)!==0||!v.updateResultKnown&&v.operationResult!==0||!v.updateHresultKnown&&v.hresult!==0||!v.nativeReturned&&known.some(k=>v[k]===true))return false;
  if(!v.nativeReturned&&v.downloadedAfter!=='unknown'||v.rebootRequired!=='unknown'||!fact(v.downloadedAfter)||!integer(v.aggregateOperationResult??0,0,5)||!integer(v.aggregateHresult??0,-2147483648,2147483647)||Object.hasOwn(v,'nativeReturned')&&typeof v.nativeReturned!=='boolean'||Object.hasOwn(v,'cleanupSucceeded')&&typeof v.cleanupSucceeded!=='boolean'||v.nativeReturned===true&&!v.attempted)return false;
  switch(v.outcome){case 'not_attempted':return !v.attempted&&!v.nativeReturned&&!v.cleanupSucceeded&&v.operationResult===0&&v.hresult===0&&(v.aggregateOperationResult??0)===0&&(v.aggregateHresult??0)===0&&v.downloadedAfter==='unknown';case 'succeeded':return known.every(k=>v[k]===true)&&v.attempted&&v.nativeReturned===true&&v.cleanupSucceeded===true&&v.operationResult===2&&v.hresult>=0&&v.aggregateOperationResult===2&&Number(v.aggregateHresult??0)>=0&&v.downloadedAfter==='yes';case 'failed':return v.attempted&&v.nativeReturned===true&&v.cleanupSucceeded===true&&[v.operationResult,v.aggregateOperationResult].some(code=>code===4||code===5);case 'uncertain':return v.attempted;default:return false;}
 }
 if(['purpose','aggregateResultKnown','aggregateHresultKnown','updateResultKnown','updateHresultKnown','nativeReturned','cleanupSucceeded','aggregateOperationResult','aggregateHresult','downloadedAfter'].some(k=>Object.hasOwn(v,k)))return false;
 switch(v.outcome){case 'not_attempted':return !v.attempted&&v.operationResult===0&&v.hresult===0&&v.rebootRequired==='unknown';case 'succeeded':return v.attempted&&v.operationResult===2&&v.hresult>=0&&v.rebootRequired!=='unknown';case 'failed':return v.attempted&&(v.operationResult===4||v.operationResult===5);case 'uncertain':return v.attempted;default:return false;}
}
const scheduleReasons=['schedule_waiting','schedule_canceled','schedule_authority_revoked','schedule_window_expired','schedule_readiness_expired','schedule_permit_expired','schedule_sequence_exhausted','schedule_readiness_changed'];
export function validUpdateSchedule(v:unknown,now:number):v is UpdateSchedule {
 if(!exact(v,['version','digest','approvedAt','startAt','endAt','permitIssuedAt','revoked'])||v.version!=='tracebolt.windows-selected-update-schedule.v1'||!digest(v.digest)||!integer(v.approvedAt)||v.approvedAt>now||!integer(v.startAt)||v.startAt<=v.approvedAt||v.startAt-v.approvedAt>86400||!integer(v.endAt)||v.endAt-v.startAt<60||v.endAt-v.startAt>3600||!integer(v.permitIssuedAt,0)||typeof v.revoked!=='boolean')return false;
 return v.permitIssuedAt===0||v.permitIssuedAt>=v.startAt&&v.permitIssuedAt<v.endAt&&v.permitIssuedAt<=now;
}
// Configuration alone is not evidence that the dedicated service is available.
function validBackgroundExecutor(v:Record<string,unknown>,now:number):boolean {
 if(!Object.hasOwn(v,'backgroundExecutor'))return !Object.hasOwn(v,'backgroundScheduling')&&!Object.hasOwn(v,'executorAvailability')&&!Object.hasOwn(v,'executorObservedAt');
 if(v.backgroundExecutor!==true||v.coordinated!==true||Object.hasOwn(v,'backgroundScheduling')&&v.backgroundScheduling!==true)return false;
 // Only the fresh combined consent may expose scheduling in a background view.
 if(v.backgroundScheduling!==true&&(v.schedulingAvailable===true||v.schedulingRevoked===true))return false;
 if(v.executorAvailability==='unknown')return !Object.hasOwn(v,'executorObservedAt');
 return v.executorAvailability==='verified_recent'&&integer(v.executorObservedAt)&&v.executorObservedAt<=now&&now-v.executorObservedAt<60&&v.executorObservedAt===v.mutationCapturedAt&&object(v.mutation)&&v.mutation.active===true;
}
const reasons=['ready','readiness_pending','readiness_unavailable','readiness_unknown','offline_unverified','selection_ineligible','not_downloaded','license_not_accepted','bundle_unsupported','interaction_or_source_required','installer_busy','restart_required_before','download_metadata_unknown','already_downloaded','download_size_exceeds_review_limit'];
// These fields are evidence from the separately consented reusable profile.
// Generic shared-owner idle status never creates retirement eligibility.
function validReusable(v:Record<string,unknown>):boolean {
 if(!Object.hasOwn(v,'reusableJobs'))return !Object.hasOwn(v,'grantExpiresAt')&&!Object.hasOwn(v,'retiredFloor');
 return v.reusableJobs===true&&integer(v.grantExpiresAt)&&(!Object.hasOwn(v,'retiredFloor')||sequence(v.retiredFloor));
}
function validRetirement(j:Record<string,unknown>,v:Record<string,unknown>,summary:boolean):boolean {
 const fields=['occurrence','resultDigest','retirement'];
 if(v.reusableJobs!==true)return fields.every(k=>!Object.hasOwn(j,k));
 const hasOccurrence=Object.hasOwn(j,'occurrence'),floor=BigInt(String(v.retiredFloor??'0'));
 if(hasOccurrence&&!sequence(j.occurrence)||!hasOccurrence&&(['approved','claimed','complete'].includes(String(j.state))||Object.hasOwn(j,'schedule')))return false;
 if(Object.hasOwn(j,'resultDigest')&&(summary||!digest(j.resultDigest)||j.result===null))return false;
 if(!summary&&hasOccurrence&&(v.available===true||v.downloadAvailable===true)&&(!object(j.retirement)||j.retirement.state!=='retired'))return false;
 if(!hasOccurrence)return !Object.hasOwn(j,'retirement')&&!Object.hasOwn(j,'resultDigest');
 if(!Object.hasOwn(j,'retirement'))return BigInt(String(j.occurrence))===floor+1n;
 const r=j.retirement;
 if(!optional(r,['state'],['requestedAt','claimedAt','retiredAt'])||!['available','pending','retired','blocked'].includes(String(r.state)))return false;
 for(const field of ['requestedAt','claimedAt','retiredAt'])if(Object.hasOwn(r,field)&&(!integer(r[field])||Number(r[field])>Number(v.serverNow)))return false;
 if(r.state==='retired'){
  if(BigInt(String(j.occurrence))>floor||!integer(r.retiredAt))return false;
 }else if(BigInt(String(j.occurrence))!==floor+1n||Object.hasOwn(r,'retiredAt'))return false;
 if(r.state==='available')return !Object.hasOwn(r,'requestedAt')&&!Object.hasOwn(r,'claimedAt')&&j.state==='complete'&&object(j.result)&&j.result.outcome==='succeeded'&&(summary||digest(j.resultDigest));
 if(r.state==='blocked')return (!Object.hasOwn(r,'requestedAt')||object(j.result)&&Number(r.requestedAt)>=Number(j.result.completedAt))&&(!Object.hasOwn(r,'claimedAt')||integer(r.requestedAt)&&Number(r.claimedAt)>=r.requestedAt);
 if(j.state!=='complete'||!object(j.result)||j.result.outcome!=='succeeded'||!summary&&!digest(j.resultDigest))return false;
 if(r.state==='pending'&&!integer(r.requestedAt))return false;
 if(Object.hasOwn(r,'requestedAt')&&Number(r.requestedAt)<Number(j.result.completedAt)||Object.hasOwn(r,'claimedAt')&&(!integer(r.requestedAt)||Number(r.claimedAt)<r.requestedAt))return false;
 return r.state!=='retired'||Number(r.retiredAt)>=Math.max(Number(j.result.completedAt),Number(r.requestedAt??0),Number(r.claimedAt??0));
}
export function validUpdateJobView(v:unknown,device:string,actor:string):v is UpdateJobView{return validView(v,device,actor,false);}
function validView(v:unknown,device:string,actor:string,summary:boolean):v is UpdateJobView{
 if(!optional(v,['version','deviceId','serverNow','available','reason','job'],['downloadEnabled','downloadAvailable','schedulingAvailable','schedulingRevoked','coordinated','mutation','mutationCapturedAt','backgroundExecutor','backgroundScheduling','executorAvailability','executorObservedAt','reusableJobs','grantExpiresAt','retiredFloor'])||v.version!=='tracebolt.windows-selected-update-job.v1'||v.deviceId!==device||!integer(v.serverNow)||typeof v.available!=='boolean'||!['ready','job_pending_or_intervention','capacity_exhausted','executor_not_configured','operator_capability_required','tls_required'].includes(String(v.reason))||v.available&&v.reason!=='ready')return false;
 if(Object.hasOwn(v,'downloadEnabled')&&v.downloadEnabled!==true||Object.hasOwn(v,'downloadAvailable')&&typeof v.downloadAvailable!=='boolean'||v.downloadAvailable===true&&v.downloadEnabled!==true||v.downloadEnabled===true&&(v.reusableJobs!==true||v.backgroundExecutor!==true||v.schedulingAvailable===true||v.backgroundScheduling===true))return false;
 if(!validReusable(v)||!validMutationView(v,v.serverNow as number)||!validBackgroundExecutor(v,v.serverNow as number))return false;
 if(Object.hasOwn(v,'schedulingAvailable')&&typeof v.schedulingAvailable!=='boolean'||Object.hasOwn(v,'schedulingRevoked')&&typeof v.schedulingRevoked!=='boolean'||v.schedulingRevoked===true&&v.schedulingAvailable===true)return false;
 if(v.job===null)return true;
 const j=v.job;if(v.backgroundExecutor===true&&v.backgroundScheduling!==true&&object(j)&&Object.hasOwn(j,'schedule'))return false;if(!optional(j,['id','selection','state','reason','preview','result'],['purpose','schedule','occurrence','resultDigest','retirement'])||!updateID(j.id,'update_')||!validUpdateSelection(j.selection)||!['requested','blocked','preview','approved','claimed','complete','expired','scheduled','schedule_canceled','schedule_blocked','schedule_expired'].includes(String(j.state))||![...reasons,...scheduleReasons].includes(String(j.reason)))return false;
 if(Object.hasOwn(j,'purpose')&&j.purpose!=='download'||j.purpose==='download'&&(!summary&&v.downloadEnabled!==true||Object.hasOwn(j,'schedule')))return false;
 if(Object.hasOwn(j,'schedule')&&(!validUpdateSchedule(j.schedule,v.serverNow)||j.preview!==null||j.state==='preview')||!Object.hasOwn(j,'schedule')&&(String(j.state).startsWith('schedule')||scheduleReasons.includes(String(j.reason))))return false;
 if(j.schedule){const schedule=j.schedule as UpdateSchedule;if(['blocked','expired','preview'].includes(String(j.state))||['scheduled','requested'].includes(String(j.state))&&schedule.permitIssuedAt!==0||['approved','claimed','complete'].includes(String(j.state))&&schedule.permitIssuedAt===0||j.state==='schedule_canceled'&&j.reason!=='schedule_canceled'||schedule.revoked&&(j.state!=='schedule_blocked'||j.reason!=='schedule_authority_revoked'))return false;}
 if(j.preview!==null&&(j.state!=='preview'||!validPreview(j.preview,device,actor,j.id,j.selection,v.serverNow,j.purpose)))return false;
 if(j.result!==null&&(j.state!=='complete'||!validResult(j.result,j.id,v.serverNow,j.purpose)))return false;
 return (j.state!=='complete'||j.result!==null)&&validRetirement(j,v,summary);
}

/** Saved summaries contain evidence only. They never carry a preview or permit. */
export type UpdateJobSummary = Omit<NonNullable<UpdateJobView['job']>, 'preview'|'resultDigest'> & { requestedAt: number; approvedAt: number; claimedAt: number };
export type UpdateJobHistory = { reusableJobs?:true; grantExpiresAt?:number; retiredFloor?:string; version: 'tracebolt.windows-selected-update-history.v1'; deviceId: string; serverNow: number; available: boolean; reason: string; remainingCapacity: number; jobs: UpdateJobSummary[] };
export function validUpdateJobHistory(v: unknown, device: string, actor: string): v is UpdateJobHistory {
 if (!optional(v, ['version','deviceId','serverNow','available','reason','remainingCapacity','jobs'],['reusableJobs','grantExpiresAt','retiredFloor']) || v.version !== 'tracebolt.windows-selected-update-history.v1' || !validReusable(v) || !integer(v.remainingCapacity,0,v.reusableJobs===true?1:32) || !Array.isArray(v.jobs) || v.jobs.length > (v.reusableJobs===true?9:33)) return false;
 const base = {version:'tracebolt.windows-selected-update-job.v1',deviceId:v.deviceId,serverNow:v.serverNow,available:v.available,reason:v.reason,job:null,...(v.reusableJobs===true?{reusableJobs:true,grantExpiresAt:v.grantExpiresAt,...(Object.hasOwn(v,'retiredFloor')?{retiredFloor:v.retiredFloor}:{})}:{})};
 if (!validUpdateJobView(base,device,actor)) return false;
 const ids = new Set<string>(),occurrences = new Set<string>();let retired=0,current=0;
 return v.jobs.every(j => {
  if (!optional(j,['id','selection','state','reason','result','requestedAt','approvedAt','claimedAt'],['purpose','schedule','occurrence','retirement']) || !integer(j.requestedAt) || !integer(j.approvedAt,0) || !integer(j.claimedAt,0) || j.requestedAt > base.serverNow || j.approvedAt > base.serverNow || j.claimedAt > base.serverNow || !Object.hasOwn(j,'schedule') && !(v.reusableJobs===true&&object(j.retirement)&&j.retirement.state==='retired') && j.approvedAt !== 0 && j.approvedAt < j.requestedAt || j.claimedAt !== 0 && (j.approvedAt === 0 || j.claimedAt < j.approvedAt)) return false;
  const job = {id:j.id,selection:j.selection,state:j.state,reason:j.reason,result:j.result,preview:null,...Object.fromEntries(['purpose','schedule','occurrence','retirement'].filter(k=>Object.hasOwn(j,k)).map(k=>[k,j[k]]))};
  if (!validView({...base,job},device,actor,true) || ids.has(job.id as string)) return false;
  if(v.reusableJobs===true){if(object(j.retirement)&&j.retirement.state==='retired')retired++;else current++;if(retired>8||current>1||typeof j.occurrence==='string'&&occurrences.has(j.occurrence))return false;if(typeof j.occurrence==='string')occurrences.add(j.occurrence);}
  if(Object.hasOwn(j,'schedule')&&(!validUpdateSchedule(j.schedule,base.serverNow as number)||j.approvedAt!==(j.schedule.permitIssuedAt===0?0:j.schedule.approvedAt)||j.claimedAt!==0&&j.claimedAt<j.schedule.permitIssuedAt))return false;
  ids.add(job.id as string); return true;
 });
}
