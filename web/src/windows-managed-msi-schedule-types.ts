import { managedDigest, type ManagedView } from './windows-managed-msi-types';

export type ManagedScheduleState='scheduled'|'readiness_issued'|'permit_issued'|'canceled'|'expired'|'blocked';
export type ManagedSchedule={version:'tracebolt.windows-managed-msi-schedule.v1';digest:string;requestDigest:string;actorId:string;approvedAt:number;startAt:number;endAt:number;readinessDigest:string;state:ManagedScheduleState;readinessIssuedAt:number;permitIssuedAt:number;outcomeAt:number;canCancel:boolean};
export type ManagedScheduleRequest={artifactId:string;artifactRetiredCount:string;bindingDigest:string;transferId:string;jobSequence:string;readinessDigest:string;startAt:number;endAt:number;packageReviewAccepted:boolean;termsAccepted:boolean;serviceRiskAccepted:boolean;synchronousActionsAccepted:boolean;scheduleAccepted:boolean};
const fields=['version','digest','requestDigest','actorId','approvedAt','startAt','endAt','readinessDigest','state','readinessIssuedAt','permitIssuedAt','outcomeAt','canCancel'];
const integer=(n:unknown,min=0):n is number=>Number.isSafeInteger(n)&&Number(n)>=min&&Number(n)<=253402300799;
export function validManagedSchedule(value:unknown,now:number):value is ManagedSchedule{
 if(typeof value!=='object'||value===null||Array.isArray(value))return false;
 const v=value as Record<string,unknown>;
 if(Object.keys(v).length!==fields.length||!fields.every(k=>Object.hasOwn(v,k))||v.version!=='tracebolt.windows-managed-msi-schedule.v1'||!managedDigest(v.digest)||!managedDigest(v.requestDigest)||!managedDigest(v.readinessDigest)||typeof v.actorId!=='string'||!/^operator_[0-9a-f]{32}$/.test(v.actorId)||!integer(v.approvedAt,1)||v.approvedAt>now||!integer(v.startAt,1)||v.startAt<=v.approvedAt||v.startAt-v.approvedAt>86400||!integer(v.endAt,1)||v.endAt-v.startAt<60||v.endAt-v.startAt>600||!['scheduled','readiness_issued','permit_issued','canceled','expired','blocked'].includes(String(v.state))||!integer(v.readinessIssuedAt)||!integer(v.permitIssuedAt)||!integer(v.outcomeAt)||typeof v.canCancel!=='boolean')return false;
 if(v.readinessIssuedAt!==0&&(v.readinessIssuedAt<v.startAt||v.readinessIssuedAt>=v.endAt||v.readinessIssuedAt>now)||v.permitIssuedAt!==0&&(v.readinessIssuedAt===0||v.permitIssuedAt<v.readinessIssuedAt||v.permitIssuedAt>=v.endAt||v.permitIssuedAt>now)||v.outcomeAt!==0&&(v.outcomeAt<v.approvedAt||v.outcomeAt>now))return false;
 if(v.state==='scheduled'&&(v.readinessIssuedAt!==0||v.permitIssuedAt!==0)||v.state==='readiness_issued'&&(v.readinessIssuedAt===0||v.permitIssuedAt!==0)||v.state==='permit_issued'&&v.permitIssuedAt===0||v.state==='canceled'&&(v.permitIssuedAt!==0||v.outcomeAt===0)||v.canCancel&&(!['scheduled','readiness_issued'].includes(String(v.state))||v.permitIssuedAt!==0))return false;
 return true;
}
function utcInput(value:string):number{
 if(!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(value))return NaN;
 const n=Date.parse(value+':00Z');return Number.isFinite(n)&&new Date(n).toISOString().slice(0,16)===value?n/1000:NaN;
}
export function managedScheduleWindow(start:string,end:string,view:ManagedView,now:number):{startAt:number;endAt:number}|null{
 const startAt=utcInput(start),endAt=utcInput(end);
 return view.reusable&&view.schedulingAvailable===true&&!view.schedule&&view.state==='ready'&&view.readiness!==null&&view.expiresAt>now&&Number.isFinite(now)&&startAt>now&&startAt-now<=86400&&startAt>=view.expiresAt&&endAt-startAt>=60&&endAt-startAt<=600&&endAt<=(view.grantExpiresAt??0)&&endAt<=(view.leafExpiresAt??0)?{startAt,endAt}:null;
}
// Field order is the versioned manager request digest contract. No local date-zone conversion.
export function managedScheduleRequest(view:ManagedView,window:{startAt:number;endAt:number}):ManagedScheduleRequest{return {artifactId:view.artifactId!,artifactRetiredCount:view.artifactRetiredCount!,bindingDigest:view.bindingDigest!,transferId:view.transferId,jobSequence:view.jobSequence!,readinessDigest:view.readinessDigest,startAt:window.startAt,endAt:window.endAt,packageReviewAccepted:true,termsAccepted:true,serviceRiskAccepted:true,synchronousActionsAccepted:true,scheduleAccepted:true}}
export async function managedScheduleRequestDigest(value:ManagedScheduleRequest):Promise<string>{
 const canonical={artifactId:value.artifactId,artifactRetiredCount:value.artifactRetiredCount,bindingDigest:value.bindingDigest,transferId:value.transferId,jobSequence:value.jobSequence,readinessDigest:value.readinessDigest,startAt:value.startAt,endAt:value.endAt,packageReviewAccepted:value.packageReviewAccepted,termsAccepted:value.termsAccepted,serviceRiskAccepted:value.serviceRiskAccepted,synchronousActionsAccepted:value.synchronousActionsAccepted,scheduleAccepted:value.scheduleAccepted};
 const bytes=new TextEncoder().encode('Tracebolt managed MSI schedule request v1\u0000'+JSON.stringify(canonical));
 return 'sha256:'+Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)),v=>v.toString(16).padStart(2,'0')).join('');
}
