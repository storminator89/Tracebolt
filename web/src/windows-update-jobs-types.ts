export type UpdateSelection = { updateId: string; revision: number };
export type UpdateReadiness = { selection: UpdateSelection; capturedAt: number; software: string; installed: string; hidden: string; downloaded: string; eulaAccepted: string; canRequestUserInput: string; canRequireSource: string; requiresNetwork: string; bundledCount: number; installerBusy: string; rebootRequiredBefore: string; rebootBehavior: string; offlineVerified: string };
export type UpdatePreview = { id: string; actorId: string; binding: { managerId: string; deviceId: string; incarnationDigest: string; executorId: string; executorKeyId: string; grantId: string; keyId: string }; readiness: UpdateReadiness; createdAt: number; expiresAt: number; digest: string };
export type UpdateResult = { jobId: string; envelopeDigest: string; attempted: boolean; outcome: 'not_attempted'|'succeeded'|'failed'|'uncertain'; operationResult: number; hresult: number; rebootRequired: 'yes'|'no'|'unknown'; completedAt: number };
export type UpdateSchedule = { version: 'tracebolt.windows-selected-update-schedule.v1'; digest: string; approvedAt: number; startAt: number; endAt: number; permitIssuedAt: number; revoked: boolean };
export type UpdateJobView = { version: string; deviceId: string; serverNow: number; available: boolean; reason: string; schedulingAvailable?: boolean; schedulingRevoked?: boolean; job: { id: string; selection: UpdateSelection; state: string; reason: string; preview: UpdatePreview|null; result: UpdateResult|null; schedule?: UpdateSchedule }|null };
const object=(v:unknown):v is Record<string,unknown>=>typeof v==='object'&&v!==null&&!Array.isArray(v);
const exact=(v:unknown,keys:string[]):v is Record<string,unknown>=>object(v)&&Object.keys(v).length===keys.length&&keys.every(k=>Object.hasOwn(v,k));
const optional=(v:unknown,keys:string[],allowed:string[]):v is Record<string,unknown>=>object(v)&&keys.every(k=>Object.hasOwn(v,k))&&Object.keys(v).every(k=>keys.includes(k)||allowed.includes(k));
const integer=(v:unknown,min=1,max=253402300799):v is number=>Number.isSafeInteger(v)&&Number(v)>=min&&Number(v)<=max;
export const updateID=(v:unknown,prefix:string):v is string=>typeof v==='string'&&new RegExp(`^${prefix}[0-9a-f]{32}$`).test(v);
const digest=(v:unknown):v is string=>typeof v==='string'&&/^sha256:[0-9a-f]{64}$/.test(v);
const fact=(v:unknown)=>v==='yes'||v==='no'||v==='unknown';
export const validUpdateSelection=(v:unknown):v is UpdateSelection=>exact(v,['updateId','revision'])&&typeof v.updateId==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(v.updateId)&&v.updateId!=='00000000-0000-0000-0000-000000000000'&&integer(v.revision,0,2147483647);
export const sameUpdate=(a:UpdateSelection,b:UpdateSelection)=>a.updateId===b.updateId&&a.revision===b.revision;
function validPreview(v:unknown,device:string,actor:string,id:string,s:UpdateSelection,now:number):v is UpdatePreview{
 if(!exact(v,['id','actorId','binding','readiness','createdAt','expiresAt','digest'])||v.id!==id||v.actorId!==actor||!digest(v.digest)||!integer(v.createdAt)||!integer(v.expiresAt)||v.createdAt>now||v.expiresAt<=now||v.expiresAt-v.createdAt>60)return false;
 const b=v.binding,r=v.readiness;
 if(!exact(b,['managerId','deviceId','incarnationDigest','executorId','executorKeyId','grantId','keyId'])||b.deviceId!==device||!updateID(b.managerId,'manager_')||!updateID(b.executorId,'executor_')||!updateID(b.grantId,'grant_')||!digest(b.incarnationDigest)||!digest(b.keyId)||!digest(b.executorKeyId)||b.executorKeyId===b.keyId)return false;
 if(!exact(r,['selection','capturedAt','software','installed','hidden','downloaded','eulaAccepted','canRequestUserInput','canRequireSource','requiresNetwork','bundledCount','installerBusy','rebootRequiredBefore','rebootBehavior','offlineVerified'])||!validUpdateSelection(r.selection)||!sameUpdate(r.selection,s)||!integer(r.capturedAt)||r.capturedAt>v.createdAt||v.expiresAt>r.capturedAt+60)return false;
 return ['software','downloaded','eulaAccepted','offlineVerified'].every(k=>r[k]==='yes')&&['installed','hidden','canRequestUserInput','canRequireSource','requiresNetwork','installerBusy','rebootRequiredBefore'].every(k=>r[k]==='no')&&r.bundledCount===0&&['never','can','always'].includes(String(r.rebootBehavior));
}
function validResult(v:unknown,id:string,now:number):v is UpdateResult{
 if(!exact(v,['jobId','envelopeDigest','attempted','outcome','operationResult','hresult','rebootRequired','completedAt'])||v.jobId!==id||!digest(v.envelopeDigest)||typeof v.attempted!=='boolean'||!integer(v.operationResult,0,5)||!integer(v.hresult,-2147483648,2147483647)||!fact(v.rebootRequired)||!integer(v.completedAt)||v.completedAt>now)return false;
 switch(v.outcome){case 'not_attempted':return !v.attempted&&v.operationResult===0&&v.hresult===0&&v.rebootRequired==='unknown';case 'succeeded':return v.attempted&&v.operationResult===2&&v.hresult>=0&&v.rebootRequired!=='unknown';case 'failed':return v.attempted&&(v.operationResult===4||v.operationResult===5);case 'uncertain':return v.attempted;default:return false;}
}
const scheduleReasons=['schedule_waiting','schedule_canceled','schedule_authority_revoked','schedule_window_expired','schedule_readiness_expired','schedule_permit_expired','schedule_sequence_exhausted','schedule_readiness_changed'];
export function validUpdateSchedule(v:unknown,now:number):v is UpdateSchedule {
 if(!exact(v,['version','digest','approvedAt','startAt','endAt','permitIssuedAt','revoked'])||v.version!=='tracebolt.windows-selected-update-schedule.v1'||!digest(v.digest)||!integer(v.approvedAt)||v.approvedAt>now||!integer(v.startAt)||v.startAt<=v.approvedAt||v.startAt-v.approvedAt>86400||!integer(v.endAt)||v.endAt-v.startAt<60||v.endAt-v.startAt>3600||!integer(v.permitIssuedAt,0)||typeof v.revoked!=='boolean')return false;
 return v.permitIssuedAt===0||v.permitIssuedAt>=v.startAt&&v.permitIssuedAt<v.endAt&&v.permitIssuedAt<=now;
}
const reasons=['ready','readiness_pending','readiness_unavailable','readiness_unknown','offline_unverified','selection_ineligible','not_downloaded','license_not_accepted','bundle_unsupported','interaction_or_source_required','installer_busy','restart_required_before'];
export function validUpdateJobView(v:unknown,device:string,actor:string):v is UpdateJobView{
 if(!optional(v,['version','deviceId','serverNow','available','reason','job'],['schedulingAvailable','schedulingRevoked'])||v.version!=='tracebolt.windows-selected-update-job.v1'||v.deviceId!==device||!integer(v.serverNow)||typeof v.available!=='boolean'||!['ready','job_pending_or_intervention','capacity_exhausted','executor_not_configured','operator_capability_required','tls_required'].includes(String(v.reason))||v.available&&v.reason!=='ready')return false;
 if(Object.hasOwn(v,'schedulingAvailable')&&typeof v.schedulingAvailable!=='boolean'||Object.hasOwn(v,'schedulingRevoked')&&typeof v.schedulingRevoked!=='boolean'||v.schedulingRevoked===true&&v.schedulingAvailable===true)return false;
 if(v.job===null)return true;
 const j=v.job;if(!optional(j,['id','selection','state','reason','preview','result'],['schedule'])||!updateID(j.id,'update_')||!validUpdateSelection(j.selection)||!['requested','blocked','preview','approved','claimed','complete','expired','scheduled','schedule_canceled','schedule_blocked','schedule_expired'].includes(String(j.state))||![...reasons,...scheduleReasons].includes(String(j.reason)))return false;
 if(Object.hasOwn(j,'schedule')&&(!validUpdateSchedule(j.schedule,v.serverNow)||j.preview!==null||j.state==='preview')||!Object.hasOwn(j,'schedule')&&(String(j.state).startsWith('schedule')||scheduleReasons.includes(String(j.reason))))return false;
 if(j.schedule){const schedule=j.schedule as UpdateSchedule;if(['blocked','expired','preview'].includes(String(j.state))||['scheduled','requested'].includes(String(j.state))&&schedule.permitIssuedAt!==0||['approved','claimed','complete'].includes(String(j.state))&&schedule.permitIssuedAt===0||j.state==='schedule_canceled'&&j.reason!=='schedule_canceled'||schedule.revoked&&(j.state!=='schedule_blocked'||j.reason!=='schedule_authority_revoked'))return false;}
 if(j.preview!==null&&(j.state!=='preview'||!validPreview(j.preview,device,actor,j.id,j.selection,v.serverNow)))return false;
 if(j.result!==null&&(j.state!=='complete'||!validResult(j.result,j.id,v.serverNow)))return false;
 return j.state!=='complete'||j.result!==null;
}

/** Saved summaries contain evidence only. They never carry a preview or permit. */
export type UpdateJobSummary = Omit<NonNullable<UpdateJobView['job']>, 'preview'> & { requestedAt: number; approvedAt: number; claimedAt: number };
export type UpdateJobHistory = { version: 'tracebolt.windows-selected-update-history.v1'; deviceId: string; serverNow: number; available: boolean; reason: string; remainingCapacity: number; jobs: UpdateJobSummary[] };
export function validUpdateJobHistory(v: unknown, device: string, actor: string): v is UpdateJobHistory {
 if (!exact(v, ['version','deviceId','serverNow','available','reason','remainingCapacity','jobs']) || v.version !== 'tracebolt.windows-selected-update-history.v1' || !integer(v.remainingCapacity,0,32) || !Array.isArray(v.jobs) || v.jobs.length > 33) return false;
 const base = {version:'tracebolt.windows-selected-update-job.v1',deviceId:v.deviceId,serverNow:v.serverNow,available:v.available,reason:v.reason,job:null};
 if (!validUpdateJobView(base,device,actor)) return false;
 const ids = new Set<string>();
 return v.jobs.every(j => {
  if (!optional(j,['id','selection','state','reason','result','requestedAt','approvedAt','claimedAt'],['schedule']) || !integer(j.requestedAt) || !integer(j.approvedAt,0) || !integer(j.claimedAt,0) || j.requestedAt > base.serverNow || j.approvedAt > base.serverNow || j.claimedAt > base.serverNow || !Object.hasOwn(j,'schedule') && j.approvedAt !== 0 && j.approvedAt < j.requestedAt || j.claimedAt !== 0 && (j.approvedAt === 0 || j.claimedAt < j.approvedAt)) return false;
  const job = {id:j.id,selection:j.selection,state:j.state,reason:j.reason,result:j.result,preview:null,...(Object.hasOwn(j,'schedule')?{schedule:j.schedule}:{})};
  if (!validUpdateJobView({...base,job},device,actor) || ids.has(job.id as string)) return false;
  if(Object.hasOwn(j,'schedule')&&(!validUpdateSchedule(j.schedule,base.serverNow as number)||j.approvedAt!==(j.schedule.permitIssuedAt===0?0:j.schedule.approvedAt)||j.claimedAt!==0&&j.claimedAt<j.schedule.permitIssuedAt))return false;
  ids.add(job.id as string); return true;
 });
}
