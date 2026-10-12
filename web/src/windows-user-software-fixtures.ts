import vectors from './windows-user-software-go-fixture.json';
import { sha256Bytes } from './sha256';
import { compareUserSoftwareRows, userSoftwareGenerationId, userSoftwareManifestHash } from './windows-user-software-types';
import type { UserSoftwareComplete, UserSoftwarePage, UserSoftwareQuery, UserSoftwareRow } from './windows-user-software-types';
export const userSoftwareQuery:UserSoftwareQuery={accountContextId:'',source:'',search:'',sort:'name-asc',limit:100,cursor:''};
export function userSoftwareVector(name:string):UserSoftwarePage{return structuredClone(vectors.find(v=>v.name===name)!.page) as UserSoftwarePage;}
export const userSoftwareDevice=vectors[0].page.deviceId;
export function userSoftwareRows(count=205):UserSoftwareRow[]{return Array.from({length:count},(_,i)=>({registrationId:(i+1).toString(16).padStart(64,'0'),source:i%2===0?'hkcu':'msix',name:`Selected App ${String(i).padStart(4,'0')}`,nameQuality:'observed',version:'1.0',versionQuality:'observed',publisher:'Invented publisher',publisherQuality:'observed'}));}
export function userSoftwareComplete(rows=userSoftwareRows(),account='d'.repeat(64),sequence=1):UserSoftwareComplete{
 const complete=userSoftwareVector('completeFirst').complete!,m=complete.manifest;m.accountContextId=account;m.accountLabel=`Selected account ${account.slice(0,12)}`;m.sequence=sequence;m.generationId=userSoftwareGenerationId(m.deviceId,m.grantId,sequence);m.rowCount=rows.length;m.chunkCount=Math.max(1,Math.ceil(rows.length/128));const raw=JSON.stringify(rows);m.rowsBytes=new TextEncoder().encode(raw).byteLength;m.rowsSha256=sha256Bytes(new TextEncoder().encode(`tracebolt.windows-selected-user-software.rows.v1\0${raw}`));complete.manifestSha256=userSoftwareManifestHash(m);return complete;
}
export function userSoftwarePage(query=userSoftwareQuery,rows=userSoftwareRows(),complete=userSoftwareComplete(rows),offset=0):UserSoftwarePage{
 const p=userSoftwareVector('completeFirst'),m=complete.manifest,search=query.search.toLowerCase();const matching=rows.filter(r=>(query.source===''||r.source===query.source)&&[r.name??'',r.version??'',r.publisher??'',r.source].some(s=>s.toLowerCase().includes(search))).sort((a,b)=>compareUserSoftwareRows(a,b,query.sort));const selected=matching.slice(offset,offset+query.limit);
 return {...p,source:query.source,search:query.search,sort:query.sort,limit:query.limit,accountContextId:m.accountContextId,complete,latestAttempt:{accountContextId:m.accountContextId,accountLabel:m.accountLabel,captureNonce:m.captureNonce,sequence:m.sequence,attemptedAt:m.captureStartedAt,status:'complete',reason:''},offset,matchingCount:matching.length,rows:selected,nextCursor:offset+selected.length<matching.length?`cursor_${offset+selected.length}.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`:''};
}
