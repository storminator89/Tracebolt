import { validManagedArtifact, type ManagedArtifactView } from './windows-managed-msi-types';

export const managedCataloguePath='/windows-managed-msi/catalogue';
export const managedCatalogueVersion='tracebolt.windows-managed-msi-catalogue.v1';
export type ManagedCatalogueView={version:typeof managedCatalogueVersion;enabled:boolean;serverNow:number;revision:string;maxEntries:4;maxRetainedPayloadBytes:134217728;reservedBytes:number;entries:ManagedArtifactView[]};
const sequence=(v:unknown):v is string=>typeof v==='string'&&/^(0|[1-9][0-9]{0,19})$/.test(v)&&BigInt(v)<=18446744073709551615n;
/** Catalogue occurrences are immutable identifiers, not singleton retirement history. */
export function validManagedCatalogue(value:unknown):value is ManagedCatalogueView{
 if(typeof value!=='object'||value===null||Array.isArray(value))return false;
 const v=value as Record<string,unknown>,fields=['version','enabled','serverNow','revision','maxEntries','maxRetainedPayloadBytes','reservedBytes','entries'];
 if(Object.keys(v).length!==fields.length||!fields.every(k=>Object.hasOwn(v,k))||v.version!==managedCatalogueVersion||typeof v.enabled!=='boolean'||!Number.isSafeInteger(v.serverNow)||Number(v.serverNow)<1||Number(v.serverNow)>253402300799||!sequence(v.revision)||v.maxEntries!==4||v.maxRetainedPayloadBytes!==134217728||!Number.isSafeInteger(v.reservedBytes)||Number(v.reservedBytes)<0||Number(v.reservedBytes)>134217728||!Array.isArray(v.entries)||v.entries.length>4)return false;
 if(!v.enabled)return v.entries.length===0&&v.reservedBytes===0;
 if(v.revision==='0'||!v.entries.every(entry=>validManagedArtifact(entry,true)&&entry.serverNow<=Number(v.serverNow)))return false;
 const entries=v.entries as ManagedArtifactView[];
 return new Set(entries.map(entry=>entry.retiredCount)).size===entries.length&&entries.reduce((bytes,entry)=>bytes+(entry.state==='retired'?0:entry.package!.size),0)===v.reservedBytes;
}
