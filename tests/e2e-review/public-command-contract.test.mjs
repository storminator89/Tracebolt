/** Text-only tests: compile/call pure UI serializers, never execute their output.
 * No browser, network request, source pin change, bootstrap or installer runs. */
import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import fs from 'node:fs';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
import {assertPublicCommand,parseSourceOwnedPin,readSourceOwnedPin} from './public-command-contract.mjs';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const require=createRequire(path.join(root,'web/package.json'));
const {build}=require('esbuild');
const compiled=await build({entryPoints:[path.join(root,'web/src/verified-download-command.ts')],bundle:true,platform:'node',format:'esm',write:false,logLevel:'silent'});
const production=await import('data:text/javascript;base64,'+Buffer.from(compiled.outputFiles[0].text).toString('base64'));
const managerOrigin='http://127.0.0.1:19894',invitationId='invite_'+'1'.repeat(32),bootstrapSHA256='b'.repeat(64);
const pin={version:'v0.0.0-inert-fixture',publicationCommit:'c'.repeat(40),bootstrapSHA256:'d'.repeat(64)};
const context={managerOrigin,invitationId,bootstrapSHA256,collectionProfile:'managed-operations-v2'};
const seconds=1791039600;
const snapshot={version:'tracebolt.enrollment-state.v2',binding:{instanceID:'manager_'+'2'.repeat(32),origin:managerOrigin,profile:'http-test',collectionProfile:'managed-operations-v2',issuerFingerprint:'a'.repeat(64)},invitationID:invitationId,createRequestID:'request_'+'3'.repeat(32),platform:'linux',revision:1,state:'created',createdAt:seconds,deadlineAt:seconds+600,updatedAt:seconds,claim:{claimID:'',requestID:'',keyFingerprint:'',csrHash:'',claimHash:'',comparisonCode:'',at:0},approval:{requestID:'',deviceID:'',keyFingerprint:'',at:0},intent:{intentID:'',requestID:'',serialHex:'',templateVersion:'',deviceID:'',keyFingerprint:'',notBefore:0,notAfter:0,at:0},issuance:{requestID:'',certificateHash:'',at:0},activation:{requestID:'',at:0},termination:{requestID:'',from:'',at:0}};
const certificate='-----BEGIN CERTIFICATE-----\nQUJDRA==\n-----END CERTIFICATE-----';
const bootstrap={schemaVersion:'tracebolt.enrollment-bootstrap.v2',managerInstanceId:snapshot.binding.instanceID,profile:'http-test',enrollmentOrigin:managerOrigin,agentOrigin:'http://127.0.0.1:19893',collectionProfile:'managed-operations-v2',invitationId,serverCaPem:'',issuerRootPem:certificate,issuerPem:certificate};
const originalWindow=globalThis.window;globalThis.window={location:{origin:managerOrigin}};
const completePin={...pin,version:'v0.1.0-rc.3'};
const completeSnapshot={...snapshot,binding:{...snapshot.binding,collectionProfile:'managed-operations-v3'}};
const completeBootstrap={...bootstrap,collectionProfile:'managed-operations-v3'};
const completeContext={...context,collectionProfile:'managed-operations-v3',agentOrigin:bootstrap.agentOrigin};
const complete=production.verifiedDownloadCommand(completePin,completeBootstrap,completeSnapshot,bootstrapSHA256);
const selectedComplete=production.selectEnrollmentCommand(completeBootstrap,completeSnapshot,bootstrapSHA256);
// Compile synthetic pin substitutions in memory only. No source/release pin is
// written, and no generated installation text is executed or fetched.
const selectorFixtures=[];
const selectorSource=fs.readFileSync(path.join(root,'web/src/verified-download-command.ts'),'utf8');
for(const selectedPin of [null,{...pin,version:'v0.1.0-rc.1'},{...pin,version:'v0.1.0-rc.2'},completePin,{...pin,version:'v0.1.0-rc.4'}]){
 const contents=selectorSource.replace(/^(export const OFFICIAL_LINUX_BOOTSTRAP_PIN: BootstrapPublicationPin \| null = ).*;$/m,(_line,prefix)=>prefix+JSON.stringify(selectedPin)+';');
 assert.notEqual(contents,selectorSource);
 const compiledFixture=await build({stdin:{contents,loader:'ts',resolveDir:path.join(root,'web/src')},bundle:true,platform:'node',format:'esm',write:false,logLevel:'silent'});
 const fixture=await import('data:text/javascript;base64,'+Buffer.from(compiledFixture.outputFiles[0].text).toString('base64'));
 selectorFixtures.push({pin:selectedPin,available:fixture.verifiedLinuxDownloadAvailable('managed-operations-v3'),complete:fixture.selectEnrollmentCommand(completeBootstrap,completeSnapshot,bootstrapSHA256),basic:fixture.selectEnrollmentCommand(bootstrap,snapshot,bootstrapSHA256)});
}


const manual=production.verifiedDownloadCommand(null,bootstrap,snapshot,bootstrapSHA256) ?? (await import('data:text/javascript;base64,'+Buffer.from((await build({entryPoints:[path.join(root,'web/src/enrollment-command.ts')],bundle:true,platform:'node',format:'esm',write:false,logLevel:'silent'})).outputFiles[0].text).toString('base64'))).preparedEnrollmentCommand(bootstrap,snapshot,bootstrapSHA256);
const verified=production.verifiedDownloadCommand(pin,bootstrap,snapshot,bootstrapSHA256);
const tlsOrigin='https://manager.example.test:9443';
const tlsSnapshot={...snapshot,binding:{...snapshot.binding,origin:tlsOrigin,profile:'tls'}};
const tlsBootstrap={...bootstrap,profile:'tls',enrollmentOrigin:tlsOrigin,agentOrigin:'https://agent.example.test:9444',serverCaPem:certificate};
globalThis.window={location:{origin:tlsOrigin}};
const verifiedTLS=production.verifiedDownloadCommand(pin,tlsBootstrap,tlsSnapshot,bootstrapSHA256);
if(originalWindow===undefined)delete globalThis.window;else globalThis.window=originalWindow;
const quote=value=>"'"+value.split("'").join("'\\''")+"'";
// Decode only the serializer's single shell-quoted argument as inert text.
// Neither this decoder nor /bin/sh -n evaluates the displayed command.
const wrapper='/usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C.UTF-8 LC_ALL=C.UTF-8 /bin/sh -c ';
function innerScript(command){
 assert.equal(typeof command,'string');assert.ok(command.startsWith(wrapper));
 const encoded=command.slice(wrapper.length);assert.ok(encoded.startsWith("'")&&encoded.endsWith("'"));
 const segments=encoded.slice(1,-1).split("'\\''");
 for(const segment of segments)assert.ok(!segment.includes("'"));
 const decoded=segments.join("'");assert.equal(quote(decoded),encoded);return decoded;
}
const declaration=value=>`export const OFFICIAL_LINUX_BOOTSTRAP_PIN: unknown = ${value};`;
const literal=`{version:'${pin.version}',publicationCommit:'${pin.publicationCommit}',bootstrapSHA256:'${pin.bootstrapSHA256}'}`;

test('reads the current source-owned literal without changing it',()=>{assert.deepEqual(readSourceOwnedPin(root),production.OFFICIAL_LINUX_BOOTSTRAP_PIN);});
test('accepts the exact reviewed manual and nested verified strings from production serializers',()=>{assert.equal(assertPublicCommand(manual,{pin:null,...context}),'prepared-local');assert.equal(assertPublicCommand(verified,{pin,...context}),'verified-download');});
test('TLS preserves the exact reviewed wrapper and public CA binding',()=>{
 const script=innerScript(verifiedTLS);
 const common=` --invitation-id ${quote(invitationId)} --bootstrap-sha256 ${quote(bootstrapSHA256)}`;
 const tlsArgs=` --manager-origin ${quote(tlsOrigin)}${common} --server-ca-base64 ${quote(Buffer.from(certificate,'utf8').toString('base64'))}`;
 const httpArgs=` --manager-origin ${quote(managerOrigin)}${common} --insecure-http-test`;
 assert.ok(script.endsWith(tlsArgs));assert.equal(script.split(tlsArgs).length,2);
 // Substitute only the independently checked public TLS tail, then apply the
 // unchanged byte-for-byte HTTP wrapper contract to every remaining character.
 const normalized=wrapper+quote(script.slice(0,-tlsArgs.length)+httpArgs);
 assert.equal(assertPublicCommand(normalized,{pin,...context}),'verified-download');
});
test('HTTP and TLS copied commands have no CR/LF and both shell layers parse without execution',()=>{
 for(const command of [verified,verifiedTLS,complete]){
  assert.equal(typeof command,'string');assert.doesNotMatch(command,/[\r\n]/);
  const script=innerScript(command);assert.doesNotMatch(script,/[\r\n]/);
  for(const text of [command,script]){
   const parsed=spawnSync('/bin/sh',['-n','-c',text],{encoding:'utf8',timeout:5000});
   assert.equal(parsed.error,undefined);assert.equal(parsed.signal,null);assert.equal(parsed.status,0,parsed.stderr);
  }
 }
 assert.doesNotMatch(manual,/[\r\n]/);
 for(const newline of ['\r','\n'])assert.throws(()=>assertPublicCommand(verified.replace('set -eu; ',`set -eu${newline}`),{pin,...context}),/PUBLIC_COMMAND_CONTRACT_MISMATCH/);
});
test('the source pin controls selection; command text cannot choose another branch',()=>{assert.throws(()=>assertPublicCommand(verified,{pin:null,...context}),/PUBLIC_COMMAND_CONTRACT_MISMATCH/);assert.throws(()=>assertPublicCommand(manual,{pin,...context}),/PUBLIC_COMMAND_CONTRACT_MISMATCH/);});
test('requires exact public origin, invitation and bootstrap checksum inside nested shell quoting',()=>{for(const contextChange of [{managerOrigin:'http://127.0.0.1:19893'},{invitationId:'invite_'+'2'.repeat(32)},{bootstrapSHA256:'e'.repeat(64)}])assert.throws(()=>assertPublicCommand(verified,{pin,...context,...contextChange}),/PUBLIC_COMMAND_CONTRACT_MISMATCH/);assert.throws(()=>assertPublicCommand(verified,{pin:{...pin,publicationCommit:'f'.repeat(40)},...context}),/PUBLIC_COMMAND_CONTRACT_MISMATCH/);});
test('rejects alternate URL, weak download, altered hash/order, command suffix and quote corruption',()=>{for(const bad of [verified.replace('raw.githubusercontent.com','example.invalid'),verified.replace(' --max-redirs 0',' --location'),verified.replace('curl -q','curl'),verified.replace('sha256sum --check --status','true'),verified.replace('exec python3 -I -B','exec python3'),verified.replace(quote(pin.bootstrapSHA256).split("'").join("'\\''"),'bogus'),verified+'; echo EXTRA',verified.slice(0,-1)])assert.throws(()=>assertPublicCommand(bad,{pin,...context}),/PUBLIC_COMMAND_CONTRACT_MISMATCH/);});
test('rejects appended local command and removed local artifact checks',()=>{assert.throws(()=>assertPublicCommand(manual+'; echo EXTRA',{pin:null,...context}),/PUBLIC_COMMAND_CONTRACT_MISMATCH/);assert.throws(()=>assertPublicCommand(manual.replace('sha256sum','echo'),{pin:null,...context}),/PUBLIC_COMMAND_CONTRACT_MISMATCH/);});
test('parses only null or an exported const with three plain string literal fields',()=>{assert.equal(parseSourceOwnedPin(declaration('null')),null);assert.deepEqual(parseSourceOwnedPin(declaration(literal)),pin);for(const bad of [declaration(`(()=>{globalThis.__qaPinExecuted=true;return ${literal}})()`),declaration(`{...${literal}}`),declaration(literal+' as const'),declaration(literal.replace('version:',"['version']:")),declaration(literal.replace("version:","version:'v0.0.0',version:")),declaration('null')+declaration('null'),declaration(literal).replace('const','let'),declaration(literal).replace('export ',''),declaration(literal.replace(pin.publicationCommit,pin.publicationCommit+'\\n'))])assert.throws(()=>parseSourceOwnedPin(bad),/PUBLIC_COMMAND_CONTRACT_MISMATCH/);assert.equal(globalThis.__qaPinExecuted,undefined);});

test('complete commands require an explicitly capable pin and never a base-only fallback',()=>{
 assert.equal(assertPublicCommand(complete,{pin:completePin,...completeContext}),'verified-download');
 const script=innerScript(complete);
 assert.ok(script.includes(` --read-admin --read-admin-agent-origin ${quote(bootstrap.agentOrigin)}`));assert.ok(!script.includes('--pending-service'));
 for(const unavailablePin of [null,pin,{...pin,version:'v0.1.0-rc.1'},{...pin,version:'v0.1.0-rc.2'},{...pin,version:'v0.1.0-rc.4'}]){
  assert.equal(assertPublicCommand(null,{pin:unavailablePin,...completeContext}),'unavailable');
  for(const command of [manual,verified,complete])assert.throws(()=>assertPublicCommand(command,{pin:unavailablePin,...completeContext}),/PUBLIC_COMMAND_CONTRACT_MISMATCH/);
 }
 assert.throws(()=>assertPublicCommand(null,{pin:completePin,...completeContext}),/PUBLIC_COMMAND_CONTRACT_MISMATCH/);
 assert.equal(assertPublicCommand(selectedComplete?.command??null,{pin:readSourceOwnedPin(root),...completeContext}),readSourceOwnedPin(root)?.version==='v0.1.0-rc.3'?'verified-download':'unavailable');
});
test('complete contract rejects missing or changed validated ingress and any weaker install mode',()=>{
 for(const agentOrigin of [undefined,'http://127.0.0.1:0','http://127.0.0.1:99999','http://127.0.0.1:19892','http://127.0.0.1:19893/','https://127.0.0.1:19893',"http://127.0.0.1:19893';echo untrusted"]){
  assert.throws(()=>assertPublicCommand(complete,{pin:completePin,...completeContext,agentOrigin}),/PUBLIC_COMMAND_CONTRACT_MISMATCH/);
 }
 for(const installMode of [' --pending-service',' --read-admin',' --read-admin --pending-service']){
  const script=innerScript(complete).replace(` --read-admin --read-admin-agent-origin ${quote(bootstrap.agentOrigin)}`,installMode);
  assert.throws(()=>assertPublicCommand(wrapper+quote(script),{pin:completePin,...completeContext}),/PUBLIC_COMMAND_CONTRACT_MISMATCH/);
 }
});

test('a literal-only capable pin activation selects complete read-admin while disabled pins never fall back',()=>{
 for(const fixture of selectorFixtures){
  const capable=fixture.pin?.version==='v0.1.0-rc.3';
  assert.equal(fixture.available,capable);
  assert.equal(assertPublicCommand(fixture.complete?.command??null,{pin:fixture.pin,...completeContext}),capable?'verified-download':'unavailable');
  assert.equal(fixture.complete?.kind??null,capable?'verified-download':null);
  assert.equal(assertPublicCommand(fixture.basic.command,{pin:fixture.pin,...context}),fixture.pin===null?'prepared-local':'verified-download');
 }
});
