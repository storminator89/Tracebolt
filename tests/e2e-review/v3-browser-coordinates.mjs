import coordinates from './v3-browser-coordinates.json' with {type:'json'};
import {focusContrastStage} from './focus-contrast-browser.mjs';

// Source-owned numeric coordinates only. Never copy result prose, errors, DOM
// content, URLs, request values or measurements into the private sidecar.
export const v3Checkpoints = Object.freeze([
 ...coordinates.stages,
 ...coordinates.focus.targets.flatMap(target => coordinates.focus.sizes.flatMap(size =>
  coordinates.focus.locales.flatMap(locale => coordinates.focus.themes.flatMap(theme =>
   coordinates.focus.phases.map(phase => focusContrastStage(target,size,locale,theme,phase)))))),
]);
export function v3FailureCoordinates({sourceSha,results,setupFailure,runtimeErrorCount,stage}) {
 if(typeof sourceSha!=='string'||!/^[0-9a-f]{40}$/.test(sourceSha)||sourceSha.length!==40
  ||!Array.isArray(results)||results.length>coordinates.cases.length||typeof setupFailure!=='boolean'
  ||!Number.isSafeInteger(runtimeErrorCount)||runtimeErrorCount<0
  ||(!setupFailure&&results.length!==coordinates.cases.length))return null;
 const finalCheckpoint=v3Checkpoints.indexOf(stage);
 if(finalCheckpoint<0)return null;
 const failures=[];
 for(const [index,result] of results.entries()) {
  if(result?.name!==coordinates.cases[index]||!['PASS','FAIL'].includes(result.status))return null;
  if(result.status==='FAIL') {
   const checkpoint=v3Checkpoints.indexOf(result.stage);
   if(checkpoint<0||(checkpoint>=coordinates.stages.length&&index+1!==coordinates.focus.case))return null;
   failures.push({case:index+1,checkpoint});
  }
 }
 if(!failures.length&&!setupFailure&&!runtimeErrorCount)return null;
 return {schemaVersion:'tracebolt.v3-browser-failure.v1',sourceSha,failures,setupFailure,runtimeFailure:runtimeErrorCount>0,finalCheckpoint};
}
