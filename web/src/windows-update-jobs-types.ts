export type UpdateSelection = { updateId: string; revision: number };
export type UpdateReadiness = { selection: UpdateSelection; capturedAt: number; software: string; installed: string; hidden: string; downloaded: string; eulaAccepted: string; canRequestUserInput: string; canRequireSource: string; requiresNetwork: string; bundledCount: number; installerBusy: string; rebootRequiredBefore: string; rebootBehavior: string; offlineVerified: string };
export type UpdatePreview = { id: string; actorId: string; binding: { managerId: string; deviceId: string; incarnationDigest: string; executorId: string; executorKeyId: string; grantId: string; keyId: string }; readiness: UpdateReadiness; createdAt: number; expiresAt: number; digest: string };
export type UpdateResult = { jobId: string; envelopeDigest: string; attempted: boolean; outcome: 'not_attempted'|'succeeded'|'failed'|'uncertain'; operationResult: number; hresult: number; rebootRequired: 'yes'|'no'|'unknown'; completedAt: number };
export type UpdateJobView = { version: string; deviceId: string; serverNow: number; available: boolean; reason: string; job: { id: string; selection: UpdateSelection; state: string; reason: string; preview: UpdatePreview|null; result: UpdateResult|null }|null };
const object=(v:unknown):v is Record<string,unknown>=>typeof v==='object'&&v!==null&&!Array.isArray(v);
const exact=(v:unknown,keys:string[]):v is Record<string,unknown>=>object(v)&&Object.keys(v).length===keys.length&&keys.every(k=>Object.hasOwn(v,k));
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
const reasons=['ready','readiness_pending','readiness_unavailable','readiness_unknown','offline_unverified','selection_ineligible','not_downloaded','license_not_accepted','bundle_unsupported','interaction_or_source_required','installer_busy','restart_required_before'];
export function validUpdateJobView(v:unknown,device:string,actor:string):v is UpdateJobView{
 if(!exact(v,['version','deviceId','serverNow','available','reason','job'])||v.version!=='tracebolt.windows-selected-update-job.v1'||v.deviceId!==device||!integer(v.serverNow)||typeof v.available!=='boolean'||!['ready','job_pending_or_intervention','capacity_exhausted','executor_not_configured','operator_capability_required','tls_required'].includes(String(v.reason))||v.available&&v.reason!=='ready')return false;
 if(v.job===null)return true;
 const j=v.job;if(!exact(j,['id','selection','state','reason','preview','result'])||!updateID(j.id,'update_')||!validUpdateSelection(j.selection)||!['requested','blocked','preview','approved','claimed','complete','expired'].includes(String(j.state))||!reasons.includes(String(j.reason)))return false;
 if(j.preview!==null&&(j.state!=='preview'||!validPreview(j.preview,device,actor,j.id,j.selection,v.serverNow)))return false;
 if(j.result!==null&&(j.state!=='complete'||!validResult(j.result,j.id,v.serverNow)))return false;
 return j.state!=='complete'||j.result!==null;
}
