/** Closed source coordinates only. Importing never starts any external process. */
import contract from './windows-service-actions-diagnostics.json' with {type:'json'};
export const windowsActionFailureContract=Object.freeze({schemaVersion:contract.schemaVersion,cases:Object.freeze(Object.fromEntries(Object.entries(contract.cases).map(([name,steps])=>[name,Object.freeze(steps)])))});
export function createWindowsActionDiagnostic(sourceSha,invocation){
 let location={case:'runner',locale:null,width:null,step:'setup'},readStep=null;
 const valid=value=>value&&typeof value.case==='string'&&Object.hasOwn(contract.cases,value.case)&&typeof value.step==='string'&&contract.cases[value.case].includes(value.step)&&(value.case==='runner'?value.locale===null&&value.width===null:['en','de'].includes(value.locale)&&[1440,390].includes(value.width));
 const begin=(name,locale=null,width=null,step='fixture')=>{const next={case:name,locale,width,step};if(!valid(next))throw new Error('Invalid source diagnostic coordinate');location=next;readStep=null;};
 const set=step=>begin(location.case,location.locale,location.width,step);
 const track=getter=>{if(typeof getter!=='function')throw new Error('Invalid source diagnostic getter');readStep=getter;};
 const checkpoint=step=>{const prior={...location},getter=readStep;set(step);return()=>{location=prior;readStep=getter;};};
 const report=()=>{
  const value={...location,...(readStep?{step:readStep()}:{})};
  if(typeof sourceSha!=='string'||sourceSha.length!==40||! /^[a-f0-9]{40}$/.test(sourceSha)||typeof invocation!=='string'||invocation.length!==32||! /^[a-f0-9]{32}$/.test(invocation)||!valid(value))return null;
  return {schemaVersion:contract.schemaVersion,sourceSha,invocation,status:'FAIL',browserAcceptance:false,nativeAcceptance:false,...value};
 };
 return {begin,set,track,checkpoint,report};
}
