/** Text-only tests: compile/call pure UI serializers, never execute their output.
 * No browser, network request, source pin change, bootstrap or installer runs. */
import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import {assertPublicCommand,parseSourceOwnedPin,readSourceOwnedPin} from './public-command-contract.mjs';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const require=createRequire(path.join(root,'web/package.json'));
const {build}=require('esbuild');
const compiled=await build({entryPoints:[path.join(root,'web/src/verified-download-command.ts')],bundle:true,platform:'node',format:'esm',write:false,logLevel:'silent'});
const production=await import('data:text/javascript;base64,'+Buffer.from(compiled.outputFiles[0].text).toString('base64'));
const managerOrigin='http://127.0.0.1:19894',invitationId='invite_'+'1'.repeat(32),bootstrapSHA256='b'.repeat(64);
const pin={version:'v0.0.0-inert-fixture',publicationCommit:'c'.repeat(40),bootstrapSHA256:'d'.repeat(64)};
const context={managerOrigin,invitationId,bootstrapSHA256};
const seconds=1791039600;
const snapshot={version:'tracebolt.enrollment-state.v2',binding:{instanceID:'manager_'+'2'.repeat(32),origin:managerOrigin,profile:'http-test',collectionProfile:'managed-operations-v3',issuerFingerprint:'a'.repeat(64)},invitationID:invitationId,createRequestID:'request_'+'3'.repeat(32),platform:'linux',revision:1,state:'created',createdAt:seconds,deadlineAt:seconds+600,updatedAt:seconds,claim:{claimID:'',requestID:'',keyFingerprint:'',csrHash:'',claimHash:'',comparisonCode:'',at:0},approval:{requestID:'',deviceID:'',keyFingerprint:'',at:0},intent:{intentID:'',requestID:'',serialHex:'',templateVersion:'',deviceID:'',keyFingerprint:'',notBefore:0,notAfter:0,at:0},issuance:{requestID:'',certificateHash:'',at:0},activation:{requestID:'',at:0},termination:{requestID:'',from:'',at:0}};
const certificate='-----BEGIN CERTIFICATE-----\nQUJDRA==\n-----END CERTIFICATE-----';
const bootstrap={schemaVersion:'tracebolt.enrollment-bootstrap.v2',managerInstanceId:snapshot.binding.instanceID,profile:'http-test',enrollmentOrigin:managerOrigin,agentOrigin:'http://127.0.0.1:19893',collectionProfile:'managed-operations-v3',invitationId,serverCaPem:'',issuerRootPem:certificate,issuerPem:certificate};
const originalWindow=globalThis.window;globalThis.window={location:{origin:managerOrigin}};
const manual=production.verifiedDownloadCommand(null,bootstrap,snapshot,bootstrapSHA256) ?? (await import('data:text/javascript;base64,'+Buffer.from((await build({entryPoints:[path.join(root,'web/src/enrollment-command.ts')],bundle:true,platform:'node',format:'esm',write:false,logLevel:'silent'})).outputFiles[0].text).toString('base64'))).preparedEnrollmentCommand(bootstrap,snapshot,bootstrapSHA256);
const verified=production.verifiedDownloadCommand(pin,bootstrap,snapshot,bootstrapSHA256);
if(originalWindow===undefined)delete globalThis.window;else globalThis.window=originalWindow;
const quote=value=>"'"+value.split("'").join("'\\''")+"'";
const declaration=value=>`export const OFFICIAL_LINUX_BOOTSTRAP_PIN: unknown = ${value};`;
const literal=`{version:'${pin.version}',publicationCommit:'${pin.publicationCommit}',bootstrapSHA256:'${pin.bootstrapSHA256}'}`;

test('reads the current source-owned literal without changing it',()=>{assert.deepEqual(readSourceOwnedPin(root),production.OFFICIAL_LINUX_BOOTSTRAP_PIN);});
test('accepts the exact reviewed manual and nested verified strings from production serializers',()=>{assert.equal(assertPublicCommand(manual,{pin:null,...context}),'prepared-local');assert.equal(assertPublicCommand(verified,{pin,...context}),'verified-download');});
test('the source pin controls selection; command text cannot choose another branch',()=>{assert.throws(()=>assertPublicCommand(verified,{pin:null,...context}),/PUBLIC_COMMAND_CONTRACT_MISMATCH/);assert.throws(()=>assertPublicCommand(manual,{pin,...context}),/PUBLIC_COMMAND_CONTRACT_MISMATCH/);});
test('requires exact public origin, invitation and bootstrap checksum inside nested shell quoting',()=>{for(const contextChange of [{managerOrigin:'http://127.0.0.1:19893'},{invitationId:'invite_'+'2'.repeat(32)},{bootstrapSHA256:'e'.repeat(64)}])assert.throws(()=>assertPublicCommand(verified,{pin,...context,...contextChange}),/PUBLIC_COMMAND_CONTRACT_MISMATCH/);assert.throws(()=>assertPublicCommand(verified,{pin:{...pin,publicationCommit:'f'.repeat(40)},...context}),/PUBLIC_COMMAND_CONTRACT_MISMATCH/);});
test('rejects alternate URL, weak download, altered hash/order, command suffix and quote corruption',()=>{for(const bad of [verified.replace('raw.githubusercontent.com','example.invalid'),verified.replace(' --max-redirs 0',' --location'),verified.replace('curl -q','curl'),verified.replace('sha256sum --check --status','true'),verified.replace('exec python3 -I -B','exec python3'),verified.replace(quote(pin.bootstrapSHA256).split("'").join("'\\''"),'bogus'),verified+'; echo EXTRA',verified.slice(0,-1)])assert.throws(()=>assertPublicCommand(bad,{pin,...context}),/PUBLIC_COMMAND_CONTRACT_MISMATCH/);});
test('rejects appended local command and removed local artifact checks',()=>{assert.throws(()=>assertPublicCommand(manual+'; echo EXTRA',{pin:null,...context}),/PUBLIC_COMMAND_CONTRACT_MISMATCH/);assert.throws(()=>assertPublicCommand(manual.replace('sha256sum','echo'),{pin:null,...context}),/PUBLIC_COMMAND_CONTRACT_MISMATCH/);});
test('parses only null or an exported const with three plain string literal fields',()=>{assert.equal(parseSourceOwnedPin(declaration('null')),null);assert.deepEqual(parseSourceOwnedPin(declaration(literal)),pin);for(const bad of [declaration(`(()=>{globalThis.__qaPinExecuted=true;return ${literal}})()`),declaration(`{...${literal}}`),declaration(literal+' as const'),declaration(literal.replace('version:',"['version']:")),declaration(literal.replace("version:","version:'v0.0.0',version:")),declaration('null')+declaration('null'),declaration(literal).replace('const','let'),declaration(literal).replace('export ',''),declaration(literal.replace(pin.publicationCommit,pin.publicationCommit+'\\n'))])assert.throws(()=>parseSourceOwnedPin(bad),/PUBLIC_COMMAND_CONTRACT_MISMATCH/);assert.equal(globalThis.__qaPinExecuted,undefined);});
