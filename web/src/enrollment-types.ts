export const enrollmentStates = ['created','claimed_pending','approved','issuance_intent','issued','activated','expired','canceled','rejected','revoked'] as const;
export type EnrollmentState = typeof enrollmentStates[number];
export interface EnrollmentSnapshot {
  version: 'tracebolt.enrollment-state.v2';
  binding: {instanceID:string;origin:string;profile:'tls'|'http-test';collectionProfile:string;issuerFingerprint:string};
  invitationID:string; createRequestID:string; platform:string; revision:number; state:EnrollmentState;
  createdAt:number; deadlineAt:number; updatedAt:number;
  claim:{claimID:string;requestID:string;keyFingerprint:string;csrHash:string;claimHash:string;comparisonCode:string;at:number};
  approval:{requestID:string;deviceID:string;keyFingerprint:string;at:number};
  intent:{intentID:string;requestID:string;serialHex:string;templateVersion:string;deviceID:string;keyFingerprint:string;notBefore:number;notAfter:number;at:number};
  issuance:{requestID:string;certificateHash:string;at:number}; activation:{requestID:string;at:number}; termination:{requestID:string;from:string;at:number};
}
export type EnrollmentCollectionProfile = 'basic-readonly-v1' | 'managed-operations-v1' | 'managed-operations-v2';
export interface EnrollmentList {collectionProfile?:EnrollmentCollectionProfile;collectionPrivacy?:'metadata_labels_may_be_sensitive'|'package_source_metadata_may_be_sensitive';serverNow:string;schemaVersion:'tracebolt.enrollment-operator.v2';enabled:boolean;platforms:string[];recordLimit:number;items:EnrollmentSnapshot[]}
export interface EnrollmentBootstrap {
 schemaVersion:'tracebolt.enrollment-bootstrap.v2';managerInstanceId:string;profile:'tls'|'http-test';enrollmentOrigin:string;agentOrigin:string;collectionProfile:string;invitationId:string;serverCaPem:string;issuerRootPem:string;issuerPem:string;
}
export interface InvitationCreation {serverNow:string;schemaVersion:'tracebolt.enrollment-invitation.v2';snapshot:EnrollmentSnapshot;invitationSecret:string;bootstrap:EnrollmentBootstrap}
const object=(value:unknown):value is Record<string,unknown>=>Boolean(value)&&typeof value==='object'&&!Array.isArray(value);
const text=(v:unknown):v is string=>typeof v==='string'&&v.length<=32768;
const time=(v:unknown):v is number=>typeof v==='number'&&Number.isSafeInteger(v)&&v>=0&&v<=253402300799;
export function terminal(state:EnrollmentState):boolean{return ['expired','canceled','rejected','revoked'].includes(state);}
export function validSnapshot(value:unknown):value is EnrollmentSnapshot {
 if(!object(value)||value.version!=='tracebolt.enrollment-state.v2'||!text(value.invitationID)||!/^invite_[a-f0-9]{32}$/.test(value.invitationID)||!text(value.createRequestID)||!text(value.platform)||!Number.isSafeInteger(value.revision)||Number(value.revision)<1||!enrollmentStates.includes(value.state as EnrollmentState)||!time(value.createdAt)||!time(value.deadlineAt)||!time(value.updatedAt))return false;
 const b=value.binding,c=value.claim,a=value.approval,i=value.intent;
 if(!object(b)||!text(b.instanceID)||!text(b.origin)||!['tls','http-test'].includes(String(b.profile))||!text(b.collectionProfile)||!text(b.issuerFingerprint)||!object(c)||!text(c.claimID)||!text(c.keyFingerprint)||!text(c.comparisonCode)||!object(a)||!text(a.deviceID)||!object(i)||!text(i.deviceID)||!time(i.notAfter)||!object(value.issuance)||!object(value.activation)||!object(value.termination))return false;
 return true;
}
export function validEnrollmentList(value:unknown):value is EnrollmentList {
 return object(value)&&validCollectionConsent(value)&&value.schemaVersion==='tracebolt.enrollment-operator.v2'&&validServerTime(value.serverNow)&&typeof value.enabled==='boolean'&&Array.isArray(value.platforms)&&value.platforms.every(text)&&Number.isSafeInteger(value.recordLimit)&&Number(value.recordLimit)>0&&Number(value.recordLimit)<=25&&Array.isArray(value.items)&&value.items.length<=Number(value.recordLimit)&&value.items.every(validSnapshot)&&new Set(value.items.map(item=>item.invitationID)).size===value.items.length;
}
function validCollectionConsent(value:Record<string,unknown>):boolean {
 if(value.collectionProfile===undefined||value.collectionProfile==='basic-readonly-v1')return value.collectionPrivacy===undefined;
 return (value.collectionProfile==='managed-operations-v1'&&value.collectionPrivacy==='metadata_labels_may_be_sensitive')||(value.collectionProfile==='managed-operations-v2'&&value.collectionPrivacy==='package_source_metadata_may_be_sensitive');
}
export function enrollmentCollectionProfile(value:EnrollmentList):EnrollmentCollectionProfile {return value.collectionProfile??'basic-readonly-v1';}
export function comparisonValid(item:EnrollmentSnapshot):boolean{return /^[a-f0-9]{64}$/.test(item.claim.keyFingerprint)&&/^[a-f0-9]{32}$/.test(item.claim.comparisonCode);}
export function groupedHex(value:string,size=4):string{return value.match(new RegExp(`.{1,${size}}`,'g'))?.join(' ')||value;}
export function enrollmentDate(seconds:number):string{return seconds?new Date(seconds*1000).toISOString():'';}
export function requestID():string {const bytes=crypto.getRandomValues(new Uint8Array(16));return `request_${Array.from(bytes,n=>n.toString(16).padStart(2,'0')).join('')}`;}
export function terminationAction(state:EnrollmentState):'canceled'|'rejected'|'revoked'|null {if(state==='created')return 'canceled';if(state==='claimed_pending')return 'rejected';if(['approved','issuance_intent','issued','activated'].includes(state))return 'revoked';return null;}
const bootstrapKeys=['schemaVersion','managerInstanceId','profile','enrollmentOrigin','agentOrigin','collectionProfile','invitationId','serverCaPem','issuerRootPem','issuerPem'] as const;
/** Public fields only. Never serialize the invitation response or a spread of server data. */
export function publicBootstrap(value:unknown,item:EnrollmentSnapshot,secret:string):EnrollmentBootstrap|null {
 if(!object(value)||Object.keys(value).length!==bootstrapKeys.length||!bootstrapKeys.every(key=>text(value[key])))return null;
 if(value.schemaVersion!=='tracebolt.enrollment-bootstrap.v2'||value.invitationId!==item.invitationID||value.managerInstanceId!==item.binding.instanceID||value.profile!==item.binding.profile||value.collectionProfile!==item.binding.collectionProfile||value.enrollmentOrigin!==item.binding.origin)return null;
 try{for(const key of ['enrollmentOrigin','agentOrigin'] as const){const raw=value[key] as string;const url=new URL(raw);if(raw.length>512||(url.port!==''&&Number(url.port)<1)||raw!==url.origin||/[\\%\s]/.test(raw)||url.username||url.password||url.protocol!==(value.profile==='tls'?'https:':'http:')||(!url.hostname.startsWith('[')&&url.hostname.split('.').some(label=>!label||label.length>63||!/^([a-z0-9]|[a-z0-9][a-z0-9-]*[a-z0-9])$/.test(label))))return null;}if(new URL(value.enrollmentOrigin as string).origin!==window.location.origin)return null;}catch{return null;}
 if(!certificatePEM(value.issuerRootPem,1)||!certificatePEM(value.issuerPem,1)||(value.profile==='tls'?!certificatePEM(value.serverCaPem,8):value.serverCaPem!==''))return null;
 if(secret&&JSON.stringify(value).includes(secret))return null;
 return {schemaVersion:'tracebolt.enrollment-bootstrap.v2',managerInstanceId:value.managerInstanceId as string,profile:value.profile as EnrollmentBootstrap['profile'],enrollmentOrigin:value.enrollmentOrigin as string,agentOrigin:value.agentOrigin as string,collectionProfile:value.collectionProfile as string,invitationId:value.invitationId as string,serverCaPem:value.serverCaPem as string,issuerRootPem:value.issuerRootPem as string,issuerPem:value.issuerPem as string};
}

export function enrollmentDeadline(item:EnrollmentSnapshot):number {const phase=terminal(item.state)?item.termination.from:item.state;if(phase==='activated')return item.intent.notAfter;if(['issuance_intent','issued'].includes(phase)&&item.intent.notAfter>0)return Math.min(item.deadlineAt,item.intent.notAfter);return item.deadlineAt;}

export function validServerTime(value:unknown):value is string {return typeof value==='string'&&value.length<=40&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/.test(value)&&Number.isFinite(Date.parse(value))&&Date.parse(value)>0;}
export function deadlinePassed(item:EnrollmentSnapshot,now:number|null):boolean {return now!==null&&!terminal(item.state)&&enrollmentDeadline(item)>0&&now>=enrollmentDeadline(item)*1000;}
function certificatePEM(value:unknown,maxBlocks:number):boolean {
 if(typeof value!=='string'||!value.length||value.length>16384)return false;
 let rest=value.trim(),blocks=0;
 while(rest){const match=/^-----BEGIN CERTIFICATE-----[\r\n\t ]+([A-Za-z0-9+/=\r\n\t ]+?)[\r\n\t ]+-----END CERTIFICATE-----/.exec(rest);if(!match||++blocks>maxBlocks)return false;const encoded=match[1].replace(/\s/g,'');try{if(!encoded||btoa(atob(encoded))!==encoded)return false;}catch{return false;}rest=rest.slice(match[0].length).trim();}
 return blocks>0;
}
