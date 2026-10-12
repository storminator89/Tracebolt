export type MutationStatus = {active:boolean;blocked:boolean;domain?:'managed_msi'|'cached_wua';jobId?:string;phase:'idle'|'reserved'|'dispatch_intent'|'completion_recorded'|'unavailable';recovery?:'intervention_required'|'exact_terminal_receipt';revision:string;retained:number};
export function validMutationStatus(value:unknown):value is MutationStatus {
 if(typeof value!=='object'||value===null||Array.isArray(value))return false;
 const v=value as Record<string,unknown>,required=['active','blocked','phase','revision','retained'],optional=['domain','jobId','recovery'];
 if(!required.every(k=>Object.hasOwn(v,k))||!Object.keys(v).every(k=>required.includes(k)||optional.includes(k))||typeof v.active!=='boolean'||typeof v.blocked!=='boolean'||!['idle','reserved','dispatch_intent','completion_recorded','unavailable'].includes(String(v.phase))||typeof v.revision!=='string'||!/^(0|[1-9][0-9]{0,19})$/.test(v.revision)||BigInt(v.revision)>18446744073709551615n||!Number.isSafeInteger(v.retained)||Number(v.retained)<0||Number(v.retained)>33)return false;
 if(v.phase==='unavailable')return !v.active&&v.blocked&&v.recovery==='intervention_required'&&!Object.hasOwn(v,'domain')&&!Object.hasOwn(v,'jobId');
 if(!v.active||v.revision==='0')return false;
 if(v.phase==='idle')return !v.blocked&&!Object.hasOwn(v,'domain')&&!Object.hasOwn(v,'jobId')&&!Object.hasOwn(v,'recovery');
 return v.blocked&&Number(v.retained)>0&&(v.domain==='managed_msi'||v.domain==='cached_wua')&&typeof v.jobId==='string'&&new RegExp(`^${v.domain==='managed_msi'?'transfer':'update'}_[0-9a-f]{32}$`).test(v.jobId)&&v.recovery===(v.phase==='completion_recorded'?'exact_terminal_receipt':'intervention_required');
}
export function validMutationView(v:Record<string,unknown>,now:number):boolean {
 if(Object.hasOwn(v,'coordinated')&&v.coordinated!==true)return false;
 const has=Object.hasOwn(v,'mutation'),at=Object.hasOwn(v,'mutationCapturedAt');
 return has===at&&(!has||v.coordinated===true&&validMutationStatus(v.mutation)&&Number.isSafeInteger(v.mutationCapturedAt)&&Number(v.mutationCapturedAt)>0&&Number(v.mutationCapturedAt)<=now);
}
// This precheck only avoids consuming an approval against a known busy/stale
// peer. The durable endpoint fence remains the sole native admission authority.
export function mutationApprovalReady(view:{coordinated?:boolean;mutation?:MutationStatus;mutationCapturedAt?:number}|null,now:number):boolean {
 if(!view?.coordinated)return true;
 const s=view.mutation,at=view.mutationCapturedAt;
 return !!s&&s.active&&!s.blocked&&s.phase==='idle'&&typeof at==='number'&&Number.isFinite(now)&&now>=at&&now-at<60;
}
