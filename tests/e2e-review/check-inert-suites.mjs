/** Read-only classification/wiring check. Never imports or executes a suite.
 * The workflow retains explicit reviewed Node arguments; discoveries only fail.
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const require=createRequire(path.join(root,'web/package.json'));
// Use the locked compiler as a parser, including comments and re-exports. No
// source text is evaluated, bundled, transpiled, imported or sent to a child.
const ts=require('typescript');
const prefix='tests/e2e-review/';
const suiteName=/^[a-z0-9][a-z0-9-]*\.test\.mjs$/;
const requireThat=(condition,message)=>{if(!condition)throw new Error(message);};
const exactKeys=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join(',')===[...keys].sort().join(',');

function suiteImports(name,source){
 const parsed=ts.createSourceFile(name,source,ts.ScriptTarget.Latest,true,ts.ScriptKind.JS);
 requireThat(parsed.parseDiagnostics.length===0,`Cannot parse classified suite: ${name}`);
 const imports=[];
 for(const node of parsed.statements){
  if(!(ts.isImportDeclaration(node)||ts.isExportDeclaration(node))||!node.moduleSpecifier)continue;
  const specifier=node.moduleSpecifier;
  if(!ts.isStringLiteral(specifier)||!specifier.text.endsWith('.test.mjs'))continue;
  requireThat(specifier.text.startsWith('./')&&suiteName.test(specifier.text.slice(2)),`Nonlocal suite import: ${name}`);
  imports.push(specifier.text.slice(2));
 }
 // Suite registration must remain statically inspectable. Dynamic imports of
 // helper/production modules are unchanged; dynamic suite imports are rejected.
 const visit=node=>{
  if(ts.isCallExpression(node)&&node.expression.kind===ts.SyntaxKind.ImportKeyword){
   requireThat(!node.arguments.some(argument=>argument.getText(parsed).includes('.test.mjs')),`Dynamic suite import: ${name}`);
  }
  ts.forEachChild(node,visit);
 };
 visit(parsed);
 return imports;
}

export function validateInertSuites(manifest,sources,workflow){
 requireThat(exactKeys(manifest,['schemaVersion','scope','entries','imported','excluded'])&&manifest.schemaVersion==='tracebolt.inert-node-suites.v1'&&typeof manifest.scope==='string'&&manifest.scope.length>0,'Invalid inert-suite manifest');
 for(const field of ['entries','imported','excluded'])requireThat(Array.isArray(manifest[field]),`Invalid classification: ${field}`);
 requireThat(manifest.entries.length>0,'No explicit suite entries');
 const excluded=manifest.excluded.map(item=>{
  requireThat(exactKeys(item,['file','reason'])&&typeof item.reason==='string'&&item.reason.trim().length>0,'Exclusion requires a reviewed reason');
  return item.file;
 });
 const all=[...manifest.entries,...manifest.imported,...excluded];
 requireThat(all.every(name=>typeof name==='string'&&suiteName.test(name)),'Only local inert test basenames may be classified');
 requireThat(new Set(all).size===all.length,'Duplicate suite classification');
 const discovered=Object.keys(sources).sort();
 requireThat(discovered.every(name=>suiteName.test(name)),'Invalid discovered suite name');
 const classified=new Set(all);
 for(const name of discovered)requireThat(classified.has(name),`Unclassified suite; review before execution: ${name}`);
 for(const name of all)requireThat(Object.hasOwn(sources,name),`Classified suite is missing: ${name}`);

 const entries=new Set(manifest.entries),omitted=new Set(excluded),visited=new Set();
 const visit=name=>{
  if(visited.has(name))return;
  visited.add(name);
  for(const dependency of suiteImports(name,sources[name])){
   requireThat(classified.has(dependency)&&Object.hasOwn(sources,dependency),`Unclassified imported suite: ${dependency}`);
   requireThat(!omitted.has(dependency),`Excluded suite is imported: ${dependency}`);
   requireThat(!entries.has(dependency),`Entry suite is also imported: ${dependency}`);
   visit(dependency);
  }
 };
 for(const name of manifest.entries)visit(name);
 for(const name of manifest.imported)requireThat(visited.has(name),`Imported suite is unreachable: ${name}`);

 // Read only explicit single-line Node test invocations. This does not generate
 // commands. Removing an entry from CI while retaining its classification fails.
 const invoked=[];
 for(const line of workflow.split(/\r?\n/)){
  const words=line.trim().split(/\s+/);
  if(words[0]!=='node'||words[1]!=='--test')continue;
  for(const word of words.slice(2)){
   if(!word.startsWith(prefix)||!word.endsWith('.test.mjs'))continue;
   const name=word.slice(prefix.length);
   requireThat(suiteName.test(name),'Nonlocal explicit suite invocation');
   invoked.push(name);
  }
 }
 requireThat(JSON.stringify(invoked)===JSON.stringify(manifest.entries),'Workflow inert-suite entries differ from reviewed manifest');
 return {entries:entries.size,imported:manifest.imported.length,excluded:excluded.length};
}

function selfTest(){
 const fixture=()=>({
  manifest:{schemaVersion:'tracebolt.inert-node-suites.v1',scope:'In-memory self-test only',entries:['a.test.mjs','contact.test.mjs'],imported:['child.test.mjs'],excluded:[{file:'held.test.mjs',reason:'Explicit fixture exclusion; must not run'}]},
  sources:{'a.test.mjs':"import './child.test.mjs';",'contact.test.mjs':"throw new Error('Never execute suite contents');",'child.test.mjs':"// import './held.test.mjs';\nexport {};",'held.test.mjs':"throw new Error('Never execute excluded contents');"},
  workflow:'node --test tests/e2e-review/a.test.mjs tests/e2e-review/contact.test.mjs',
 });
 const check=value=>validateInertSuites(value.manifest,value.sources,value.workflow);
 assert.deepEqual(check(fixture()),{entries:2,imported:1,excluded:1});
 const rejected=(change,reason)=>{const value=fixture();change(value);assert.throws(()=>check(value),reason);};
 rejected(value=>{value.workflow='node --test tests/e2e-review/a.test.mjs';},/entries differ/);
 rejected(value=>{value.manifest.entries.pop();},/Unclassified suite/);
 rejected(value=>{value.sources['new.test.mjs']="throw new Error('Must not execute discovery');";},/Unclassified suite/);
 rejected(value=>{value.sources['a.test.mjs']='// removed import';},/unreachable/);
 rejected(value=>{value.sources['a.test.mjs']="import './held.test.mjs';";},/Excluded suite is imported/);
 rejected(value=>{value.sources['a.test.mjs']="import './missing.test.mjs';";},/Unclassified imported suite/);
 rejected(value=>{value.sources['a.test.mjs']="import('./child.test.mjs');";},/Dynamic suite import/);
 rejected(value=>{value.manifest.imported.push('contact.test.mjs');},/Duplicate suite classification/);
 rejected(value=>{value.manifest.excluded[0].reason=' ';},/reviewed reason/);
 rejected(value=>{delete value.sources['contact.test.mjs'];},/Classified suite is missing/);
 rejected(value=>{value.workflow+=' tests/e2e-review/held.test.mjs';},/entries differ/);
 const reexport=fixture();reexport.sources['a.test.mjs']="export * from './child.test.mjs';";check(reexport);
 console.log('PASS: inert-suite checker positive, omission, import-closure and no-execution negative controls.');
}

function main(){
 const args=process.argv.slice(2);
 if(args.length===1&&args[0]==='--self-test'){selfTest();return;}
 requireThat(args.length===0,'Unsupported checker arguments');
 const directory=path.join(root,prefix);
 const sources=Object.fromEntries(fs.readdirSync(directory).filter(name=>name.endsWith('.test.mjs')).map(name=>[name,fs.readFileSync(path.join(directory,name),'utf8')]));
 const result=validateInertSuites(JSON.parse(fs.readFileSync(path.join(directory,'inert-suites.json'),'utf8')),sources,fs.readFileSync(path.join(root,'.github/workflows/validate.yml'),'utf8'));
 console.log(`PASS: ${result.entries} explicit inert Node entries, ${result.imported} imported suites, ${result.excluded} reviewed exclusions; no suite executed.`);
}

if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{main();}catch(error){console.error(`FAIL: ${error.message}`);process.exitCode=1;}
}
