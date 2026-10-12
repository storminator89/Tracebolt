export type SoftwareSelection = { sha256: string; size: number; productCode: string; packageCode: string; version: string; architecture: 'amd64'; name: string; termsReviewDigest: string; reviewReference: string };
export type SoftwareReadiness = { selection: SoftwareSelection; capturedAt: number; packageVerified: 'yes'; machineAbsent: 'yes'; installerBusy: 'no'; nativeAcceptance: 'yes'; packageReviewAccepted: 'yes'; maintenanceWindowEnd: number };
export type SoftwarePreview = { id: string; actorId: string; binding: { managerId: string; deviceId: string; incarnationDigest: string; executorId: string; executorKeyId: string; grantId: string; keyId: string }; readiness: SoftwareReadiness; createdAt: number; expiresAt: number; digest: string };
export type SoftwareResult = { jobId: string; envelopeDigest: string; attempted: boolean; outcome: 'not_attempted'|'succeeded'|'restart_required'|'unexpected_restart'|'busy'|'failed'|'uncertain'; returnCodeKnown: boolean; returnCode: number; registrationVerified: 'yes'|'no'|'unknown'; completedAt: number };
export type SoftwareJobView = { version: 'tracebolt.windows-prepared-msi-job.v1'; deviceId: string; serverNow: number; package: SoftwareSelection; available: boolean; reason: string; job: { id: string; selection: SoftwareSelection; state: string; reason: string; preview: SoftwarePreview|null; result: SoftwareResult|null }|null };
const exact=(v:unknown,keys:string[]):v is Record<string,unknown>=>typeof v==='object'&&v!==null&&!Array.isArray(v)&&Object.keys(v).length===keys.length&&keys.every(k=>Object.hasOwn(v,k));
const integer=(v:unknown,min=1,max=253402300799):v is number=>Number.isSafeInteger(v)&&Number(v)>=min&&Number(v)<=max;
export const softwareID=(v:unknown,prefix:string):v is string=>typeof v==='string'&&new RegExp(`^${prefix}[0-9a-f]{32}$`).test(v);
const digest=(v:unknown):v is string=>typeof v==='string'&&/^sha256:[0-9a-f]{64}$/.test(v);
const text=(v:unknown,max:number):v is string=>typeof v==='string'&&v.length>0&&new TextEncoder().encode(v).length<=max&&v.trim()===v&&!/[\x00-\x1f\x7f]/.test(v);
const guid=(v:unknown)=>typeof v==='string'&&/^\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}$/.test(v)&&v!=='{00000000-0000-0000-0000-000000000000}';
const keys=['sha256','size','productCode','packageCode','version','architecture','name','termsReviewDigest','reviewReference'];
export function validSoftwareSelection(v:unknown):v is SoftwareSelection {
 if(!exact(v,keys)||!digest(v.sha256)||!integer(v.size,512,128*1024*1024)||!guid(v.productCode)||!guid(v.packageCode)||v.architecture!=='amd64'||!text(v.name,120)||!digest(v.termsReviewDigest)||!text(v.reviewReference,160)||typeof v.version!=='string')return false;
 const parts=v.version.split('.');return parts.length===3&&parts.every((p,i)=>/^(0|[1-9][0-9]*)$/.test(p)&&Number(p)<=(i<2?255:65535));
}
export const sameSoftware=(a:SoftwareSelection,b:SoftwareSelection)=>keys.every(k=>a[k as keyof SoftwareSelection]===b[k as keyof SoftwareSelection]);
function validPreview(v:unknown,device:string,actor:string,id:string,s:SoftwareSelection,now:number):v is SoftwarePreview {
 if(!exact(v,['id','actorId','binding','readiness','createdAt','expiresAt','digest'])||v.id!==id||v.actorId!==actor||!digest(v.digest)||!integer(v.createdAt)||!integer(v.expiresAt)||v.createdAt>now||v.expiresAt<=now||v.expiresAt-v.createdAt>60)return false;
 const b=v.binding,r=v.readiness;
 if(!exact(b,['managerId','deviceId','incarnationDigest','executorId','executorKeyId','grantId','keyId'])||b.deviceId!==device||!softwareID(b.managerId,'manager_')||!softwareID(b.executorId,'executor_')||!softwareID(b.grantId,'grant_')||!digest(b.incarnationDigest)||!digest(b.keyId)||!digest(b.executorKeyId)||b.executorKeyId===b.keyId)return false;
 return exact(r,['selection','capturedAt','packageVerified','machineAbsent','installerBusy','nativeAcceptance','packageReviewAccepted','maintenanceWindowEnd'])&&validSoftwareSelection(r.selection)&&sameSoftware(r.selection,s)&&integer(r.capturedAt)&&r.capturedAt<=v.createdAt&&v.expiresAt<=r.capturedAt+60&&integer(r.maintenanceWindowEnd)&&v.expiresAt<=r.maintenanceWindowEnd&&r.packageVerified==='yes'&&r.machineAbsent==='yes'&&r.installerBusy==='no'&&r.nativeAcceptance==='yes'&&r.packageReviewAccepted==='yes';
}
function validResult(v:unknown,id:string,now:number):v is SoftwareResult {
 if(!exact(v,['jobId','envelopeDigest','attempted','outcome','returnCodeKnown','returnCode','registrationVerified','completedAt'])||v.jobId!==id||!digest(v.envelopeDigest)||typeof v.attempted!=='boolean'||typeof v.returnCodeKnown!=='boolean'||!integer(v.returnCode,0,4294967295)||!['yes','no','unknown'].includes(String(v.registrationVerified))||!integer(v.completedAt)||v.completedAt>now)return false;
 if(v.outcome==='not_attempted')return !v.attempted&&!v.returnCodeKnown&&v.returnCode===0&&v.registrationVerified==='unknown';
 if(!v.attempted||!v.returnCodeKnown&&(v.returnCode!==0||v.outcome!=='uncertain'))return false;
 switch(v.outcome){case 'succeeded':return v.returnCode===0&&v.registrationVerified==='yes';case 'restart_required':return v.returnCode===3010;case 'unexpected_restart':return v.returnCode===1641;case 'busy':return v.returnCode===1618;case 'failed':return ![0,3010,1641,1618].includes(v.returnCode);case 'uncertain':return true;default:return false;}
}
export function validSoftwareJobView(v:unknown,device:string,actor:string):v is SoftwareJobView {
 if(!exact(v,['version','deviceId','serverNow','package','available','reason','job'])||v.version!=='tracebolt.windows-prepared-msi-job.v1'||v.deviceId!==device||!integer(v.serverNow)||typeof v.available!=='boolean'||!['ready','job_pending_or_intervention','capacity_exhausted','executor_not_configured','operator_capability_required','tls_required'].includes(String(v.reason))||v.available&&v.reason!=='ready')return false;
 const selection=v.package;
 if(!validSoftwareSelection(selection))return !v.available&&v.job===null&&['executor_not_configured','operator_capability_required','tls_required'].includes(String(v.reason))&&exact(selection,keys)&&keys.every(k=>selection[k]===(k==='size'?0:''));
 if(v.job===null)return true;
 const j=v.job;if(!exact(j,['id','selection','state','reason','preview','result'])||!softwareID(j.id,'software_')||!validSoftwareSelection(j.selection)||!sameSoftware(j.selection,selection)||!['requested','blocked','preview','approved','claimed','complete','expired'].includes(String(j.state))||!['ready','readiness_pending','readiness_unavailable','readiness_unknown','package_changed','already_registered','package_review_required','installer_busy','maintenance_window_expired'].includes(String(j.reason)))return false;
 if(j.preview!==null&&(j.state!=='preview'||!validPreview(j.preview,device,actor,j.id,j.selection,v.serverNow)))return false;
 if(j.result!==null&&(j.state!=='complete'||!validResult(j.result,j.id,v.serverNow)))return false;
 return j.state!=='complete'||j.result!==null;
}
