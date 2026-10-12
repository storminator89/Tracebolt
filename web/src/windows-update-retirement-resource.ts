import { sameUpdate, updateID, type UpdateJobView } from './windows-update-jobs-types';

/** Nonsecret reconciliation references, never consent or reusable write authority. */
export type UpdateRetirementIntent = { jobId: string; occurrence: string; envelopeDigest: string; resultDigest: string; grantExpiresAt: number };
const storagePrefix='tracebolt.windows-update-retirement.v1:';
const digest=(v:unknown)=>typeof v==='string'&&/^sha256:[0-9a-f]{64}$/.test(v);
function validIntent(v:unknown):v is UpdateRetirementIntent {
 if(typeof v!=='object'||v===null||Array.isArray(v))return false;
 const x=v as Record<string,unknown>;
 return Object.keys(x).length===5&&updateID(x.jobId,'update_')&&typeof x.occurrence==='string'&&/^[1-9][0-9]{0,19}$/.test(x.occurrence)&&BigInt(x.occurrence)<=18446744073709551615n&&digest(x.envelopeDigest)&&digest(x.resultDigest)&&Number.isSafeInteger(x.grantExpiresAt)&&Number(x.grantExpiresAt)>0&&Number(x.grantExpiresAt)<=253402300799;
}
export function updateRetirementIntent(view:UpdateJobView):UpdateRetirementIntent|null {
 const j=view.job;
 if(view.reusableJobs!==true||!j?.occurrence||!j.resultDigest||!j.result||!view.grantExpiresAt)return null;
 const intent={jobId:j.id,occurrence:j.occurrence,envelopeDigest:j.result.envelopeDigest,resultDigest:j.resultDigest,grantExpiresAt:view.grantExpiresAt};
 return validIntent(intent)?intent:null;
}
export function matchesUpdateRetirement(view:UpdateJobView,intent:UpdateRetirementIntent):boolean {
 const actual=updateRetirementIntent(view);
 return !!actual&&Object.keys(intent).every(k=>actual[k as keyof UpdateRetirementIntent]===intent[k as keyof UpdateRetirementIntent]);
}
export function canReviewUpdateRetirement(view:UpdateJobView|null,now:number):boolean {
 const j=view?.job;
 return !!view&&!!j&&Number.isFinite(now)&&now>=view.serverNow&&now<view.grantExpiresAt!&&view.reusableJobs===true&&j.retirement?.state==='available'&&j.state==='complete'&&j.result?.attempted===true&&j.result.outcome==='succeeded'&&updateRetirementIntent(view)!==null;
}
export function sameUpdateRetirementReview(value:UpdateJobView,reviewed:UpdateJobView,now:number):boolean {
 const intent=updateRetirementIntent(reviewed);
 const sameResult=!!value.job?.result&&!!reviewed.job?.result&&Object.keys(reviewed.job.result).every(k=>value.job!.result![k as keyof NonNullable<typeof value.job.result>]===reviewed.job!.result![k as keyof NonNullable<typeof reviewed.job.result>]);
 return sameResult&&!!intent&&value.deviceId===reviewed.deviceId&&value.retiredFloor===reviewed.retiredFloor&&!!value.job&&!!reviewed.job&&sameUpdate(value.job.selection,reviewed.job.selection)&&matchesUpdateRetirement(value,intent)&&canReviewUpdateRetirement(value,now);
}
export function readUpdateRetirementIntent(key:string):{intent:UpdateRetirementIntent|null;blocked:boolean} {
 try{
  const raw=sessionStorage.getItem(storagePrefix+key);
  if(raw===null)return {intent:null,blocked:false};
  if(raw.length>1024)return {intent:null,blocked:true};
  const value:unknown=JSON.parse(raw);
  return validIntent(value)?{intent:value,blocked:false}:{intent:null,blocked:true};
 }catch{return {intent:null,blocked:true};}
}
export function saveUpdateRetirementIntent(key:string,intent:UpdateRetirementIntent):boolean {
 if(!validIntent(intent))return false;
 try{
  // Never evict an unresolved reference to make room for another session.
  if(sessionStorage.getItem(storagePrefix+key)===null){let count=0;for(let i=0;i<sessionStorage.length;i++)if(sessionStorage.key(i)?.startsWith(storagePrefix))count++;if(count>=512)return false;}
  const raw=JSON.stringify(intent);sessionStorage.setItem(storagePrefix+key,raw);
  return sessionStorage.getItem(storagePrefix+key)===raw;
 }catch{return false;}
}
export function clearUpdateRetirementIntent(key:string):boolean {
 try{sessionStorage.removeItem(storagePrefix+key);return sessionStorage.getItem(storagePrefix+key)===null;}catch{return false;}
}
