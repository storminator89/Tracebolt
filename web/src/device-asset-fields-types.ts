export interface AssetFields { assetTag: string; location: string; warrantyEnd: string }
export interface DeviceAssetFieldsView { schemaVersion:'tracebolt.device-asset-fields.v1';deviceId:string;identityKey:string;binding:string;serverNow:string;validUntil:string;revision:number;canWrite:boolean;fields:AssetFields;changedAt:string|null;operations:{id:string;revision:number}[];limits:{operations:100;assetTagBytes:80;locationBytes:160} }
const exact=(v:unknown,keys:string[]):v is Record<string,unknown>=>!!v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===keys.sort().join();
export const assetBytes=(s:string)=>new TextEncoder().encode(s).length;
export function validCivilDate(s:string):boolean {
 if(s==='')return true;
 if(!/^\d{4}-\d{2}-\d{2}$/.test(s))return false;
 const [y,m,d]=s.split('-').map(Number), leap=y%4===0&&(y%100!==0||y%400===0);
 return y>=1&&m>=1&&m<=12&&d>=1&&d<=[31,leap?29:28,31,30,31,30,31,31,30,31,30,31][m-1];
}
// A civil date is not an instant. Never parse it through Date or local time zones.
export function civilDateLabel(s:string,locale:'en'|'de'):string {return locale==='de'?s.split('-').reverse().join('.'):s;}
export function validAssetFields(v:unknown):v is AssetFields {
 if(!exact(v,['assetTag','location','warrantyEnd']))return false;
 return (['assetTag','location'] as const).every(k=>typeof v[k]==='string'&&v[k].trim()===v[k]&&!/[\p{Cc}\p{Cf}\p{Cs}\uFFFD]/u.test(v[k])&&assetBytes(v[k])<=(k==='assetTag'?80:160))&&typeof v.warrantyEnd==='string'&&validCivilDate(v.warrantyEnd);
}
const utc=(v:unknown):v is string=>typeof v==='string'&&/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(v)&&validCivilDate(v.slice(0,10))&&Number.isFinite(Date.parse(v))&&new Date(Date.parse(v)).toISOString().slice(0,19)===v.slice(0,19);
export function validDeviceAssetFields(v:unknown,id:string):v is DeviceAssetFieldsView {
 if(!exact(v,['schemaVersion','deviceId','identityKey','binding','serverNow','validUntil','revision','canWrite','fields','changedAt','operations','limits'])||v.schemaVersion!=='tracebolt.device-asset-fields.v1'||v.deviceId!==id||typeof v.identityKey!=='string'||! /^[a-f0-9]{64}$/.test(v.identityKey)||typeof v.binding!=='string'||! /^[a-f0-9]{64}$/.test(v.binding)||!utc(v.serverNow)||!utc(v.validUntil)||Date.parse(v.validUntil)<=Date.parse(v.serverNow)||Date.parse(v.validUntil)-Date.parse(v.serverNow)>60000||!Number.isInteger(v.revision)||(v.revision as number)<0||(v.revision as number)>100||typeof v.canWrite!=='boolean'||!validAssetFields(v.fields)||!exact(v.limits,['operations','assetTagBytes','locationBytes'])||v.limits.operations!==100||v.limits.assetTagBytes!==80||v.limits.locationBytes!==160||!Array.isArray(v.operations)||v.operations.length!==v.revision)return false;
 if(v.revision===0?(v.changedAt!==null||Object.values(v.fields).some(Boolean)):(!utc(v.changedAt)||Date.parse(v.changedAt)>Date.parse(v.serverNow)))return false;
 return v.operations.every((o,i)=>exact(o,['id','revision'])&&typeof o.id==='string'&&/^assetop_[a-f0-9]{32}$/.test(o.id)&&Number.isInteger(o.revision)&&(o.revision as number)>=1&&(o.revision as number)<=(v.revision as number)&&Array.isArray(v.operations)&&!v.operations.slice(0,i).some(p=>p.id===o.id||p.revision===o.revision));
}
