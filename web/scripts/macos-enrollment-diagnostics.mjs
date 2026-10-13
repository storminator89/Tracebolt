/** Bounded diagnostic vocabulary. Never accept page text, URLs, exception text,
 * browser logs, request bodies, invitation values or arbitrary metadata. */
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
const manifest=JSON.parse(await readFile(new URL('./macos-enrollment-scenes.json',import.meta.url),'utf8'));
assert.deepEqual(manifest.scenes,['ready','unavailable','created','review']);
assert.deepEqual(manifest.viewports,['en','de'].flatMap(locale=>[1440,390].map(width=>({locale,width,height:width===390?844:1100}))));
const matrix=manifest.viewports.flatMap(view=>manifest.scenes.map(scene=>({scene,...view})));
export const captureStages=Object.freeze(['launch','compile','prepare-output','new-context','route','new-page','navigate','initial-status','select-macos','unavailable-state','open-history','open-review','review-consent','review-approval','wait-add','open-create','open-scope','create-ready','submit-create','secret-masked','interrupt-clear','refresh-restored','open-source-steps','source-instructions','fonts','no-overflow','secret-excluded','linux-command-excluded','screenshot','runtime-errors','route-boundary','creation-count','image-hash','close-context','manifest','close-browser','evidence']);
export function captureDiagnostic(stage,index=null){
 assert(captureStages.includes(stage),'Unknown capture diagnostic stage');
 assert(index===null||Number.isSafeInteger(index)&&index>=0&&index<matrix.length,'Invalid capture diagnostic index');
 const row=index===null?null:matrix[index];
 return {stage,scene:row?.scene??null,locale:row?.locale??null,width:row?.width??null};
}
