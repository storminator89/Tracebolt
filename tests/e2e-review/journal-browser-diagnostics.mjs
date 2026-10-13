import coordinates from './journal-browser-coordinates.json' with {type:'json'};

// Only fixed numeric source coordinates leave this helper. Never include result
// prose, exception text, URLs, request bodies, DOM content or fixture values.
export function journalFailureCoordinates({sourceSha,results,setupFailure,runtimeErrorCount,stage}) {
 if(typeof sourceSha!=='string'||sourceSha.length!==40||!/^[0-9a-f]{40}$/.test(sourceSha)||!Array.isArray(results)||results.length>coordinates.cases.length||typeof setupFailure!=='boolean'||!Number.isSafeInteger(runtimeErrorCount)||runtimeErrorCount<0)return null;
 const finalStage=coordinates.stages.indexOf(stage);
 if(finalStage<0)return null;
 const failures=[];
 for(const [index,result] of results.entries()) {
  if(result?.name!==coordinates.cases[index]||!['PASS','FAIL'].includes(result.status))return null;
  if(result.status==='FAIL') {
   const checkpoint=coordinates.stages.indexOf(result.stage);
   if(checkpoint<0)return null;
   failures.push({case:index+1,checkpoint});
  }
 }
 if(!failures.length&&!setupFailure&&!runtimeErrorCount)return null;
 return {schemaVersion:'tracebolt.journal-browser-failure.v1',sourceSha,failures,setupFailure,runtimeFailure:runtimeErrorCount>0,finalCheckpoint:finalStage};
}
