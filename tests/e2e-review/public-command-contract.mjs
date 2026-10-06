/** Independent exact text contract for the real-handler HTTP-test browser case.
 * No shell, download, installer, VM, displayed command or source initializer is
 * executed. A source-owned literal pin selects reviewed formats or complete unavailability.
 */
import fs from 'node:fs';
import path from 'node:path';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const require=createRequire(path.join(root,'web/package.json'));
const ts=require('typescript');
const reject=()=>{throw new Error('PUBLIC_COMMAND_CONTRACT_MISMATCH');};
function validPin(pin){return pin!==null&&typeof pin==='object'&&!Array.isArray(pin)&&Object.keys(pin).sort().join(',')==='bootstrapSHA256,publicationCommit,version'&&typeof pin.version==='string'&&pin.version.length<=64&&pin.version.trim()===pin.version&&/^v[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9]+(?:[.-][a-z0-9]+)*)?$/.test(pin.version)&&typeof pin.publicationCommit==='string'&&pin.publicationCommit.length===40&&/^[0-9a-f]{40}$/.test(pin.publicationCommit)&&typeof pin.bootstrapSHA256==='string'&&pin.bootstrapSHA256.length===64&&/^[0-9a-f]{64}$/.test(pin.bootstrapSHA256);}
/** Parse only an exported const initializer: null or three plain string fields.
 * Calls, imports, computed keys, spreads and casts never become trust inputs. */
export function parseSourceOwnedPin(source){
 const file=ts.createSourceFile('verified-download-command.ts',source,ts.ScriptTarget.Latest,true,ts.ScriptKind.TS);
 if(file.parseDiagnostics.length)reject();
 const declarations=[];
 for(const statement of file.statements)if(ts.isVariableStatement(statement))for(const declaration of statement.declarationList.declarations)if(ts.isIdentifier(declaration.name)&&declaration.name.text==='OFFICIAL_LINUX_BOOTSTRAP_PIN')declarations.push({statement,declaration});
 if(declarations.length!==1)reject();const {statement,declaration}=declarations[0];
 if(!(statement.declarationList.flags&ts.NodeFlags.Const)||!statement.modifiers?.some(m=>m.kind===ts.SyntaxKind.ExportKeyword))reject();
 const init=declaration.initializer;if(!init)reject();if(init.kind===ts.SyntaxKind.NullKeyword)return null;
 if(!ts.isObjectLiteralExpression(init))reject();const pin=Object.create(null);
 for(const field of init.properties){if(!ts.isPropertyAssignment(field)||!ts.isIdentifier(field.name)||!ts.isStringLiteral(field.initializer)||Object.hasOwn(pin,field.name.text))reject();pin[field.name.text]=field.initializer.text;}
 if(!validPin(pin))reject();return Object.freeze({...pin});
}
export function readSourceOwnedPin(repositoryRoot=root){return parseSourceOwnedPin(fs.readFileSync(path.join(repositoryRoot,'web/src/verified-download-command.ts'),'utf8'));}
const quote=value=>"'"+value.split("'").join("'\\''")+"'";
function loopbackHTTPOrigin(value){
 if(typeof value!=='string'||!/^http:\/\/127\.0\.0\.1:[0-9]{1,5}$/.test(value))return false;
 try{const url=new URL(value);return url.origin===value&&Number(url.port)>0;}catch{return false;}
}
function publicArguments({managerOrigin,invitationId,bootstrapSHA256}){
 if(!loopbackHTTPOrigin(managerOrigin)||typeof invitationId!=='string'||invitationId.length!==39||!/^invite_[0-9a-f]{32}$/.test(invitationId)||typeof bootstrapSHA256!=='string'||bootstrapSHA256.length!==64||!/^[0-9a-f]{64}$/.test(bootstrapSHA256))reject();
 return ` --manager-origin ${quote(managerOrigin)} --invitation-id ${quote(invitationId)} --bootstrap-sha256 ${quote(bootstrapSHA256)} --insecure-http-test`;
}
function manual(args){return '"$PWD/bin/agent-service" --action install --apply --pending-service'+
 ' --agent-binary "$PWD/bin/lan-agent" --agent-sha256 "$(sha256sum < "$PWD/bin/lan-agent" | cut -d \' \' -f 1)"'+
 ' --enroll-binary "$PWD/bin/enroll-agent" --enroll-sha256 "$(sha256sum < "$PWD/bin/enroll-agent" | cut -d \' \' -f 1)"'+
 ' --source-archive "$PWD/tracebolt-selected-source.tar" --source-sha256 "$(sha256sum < "$PWD/tracebolt-selected-source.tar" | cut -d \' \' -f 1)"'+args;}
function download(pin,args,installMode){
 const url=`https://raw.githubusercontent.com/storminator89/Tracebolt/${pin.publicationCommit}/deploy/release/published/${pin.version}.py`;
 // Exact independently held shell text: changes require this contract's review.
 const lines=[
  'set -eu',
  'umask 077',
  '[ "$(id -u)" -eq 0 ] || { printf "%s\\n" "Run deliberately as root after approving account, service and persistent identity creation. No automatic elevation." >&2; exit 1; }',
  '[ -t 0 ] || { printf "%s\\n" "A real local terminal is required for hidden invitation entry." >&2; exit 1; }',
  'missing=""',
  'for tool in curl sha256sum python3 mktemp rm rmdir; do command -v "$tool" >/dev/null || missing="$missing $tool"; done',
  '[ -z "$missing" ] || { printf "%s\\n" "Missing prerequisites:$missing. No tools were installed." "On supported Debian 13 or Ubuntu 24.04, after administrator approval, run manually as root:" "apt-get update && apt-get install -- curl python3 ca-certificates coreutils" "Then retry the same reviewed installation command." >&2; exit 1; }',
  'stage=$(mktemp -d /tmp/tracebolt-bootstrap.XXXXXXXXXX)',
  'trap \'status=$?; trap - 0; rm -f -- "$stage/bootstrap.py"; rmdir -- "$stage"; exit "$status"\' 0',
  'trap \'exit 129\' HUP',
  'trap \'exit 130\' INT',
  'trap \'exit 143\' TERM',
  `status=$(curl -q --fail --silent --show-error --proto '=https' --proto-redir '=https' --proxy '' --noproxy '*' --max-redirs 0 --connect-timeout 10 --max-time 60 --max-filesize 131072 --output "$stage/bootstrap.py" --write-out '%{http_code}' ${quote(url)})`,
  '[ "$status" = 200 ] || { printf "%s\\n" "Official bootstrap download did not return HTTP 200." >&2; exit 1; }',
  `printf '%s  %s\\n' ${quote(pin.bootstrapSHA256)} "$stage/bootstrap.py" | sha256sum --check --status || { printf "%s\\n" "Official bootstrap SHA-256 mismatch. Nothing was executed." >&2; exit 1; }`,
  'exec 3< "$stage/bootstrap.py"',
  'rm -f -- "$stage/bootstrap.py"',
  'rmdir -- "$stage"',
  'trap - 0 HUP INT TERM',
  `exec python3 -I -B /proc/self/fd/3 --action install --apply${installMode}${args}`,
 ];
 return '/usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C.UTF-8 LC_ALL=C.UTF-8 /bin/sh -c '+quote(lines.join('; '));
}
/** Only the source-owned pin selects the branch; a command cannot choose its own. */
export function assertPublicCommand(command,{pin,...context}){
 const args=publicArguments(context);if(pin!==null&&!validPin(pin))reject();
 if(!['basic-readonly-v1','managed-operations-v1','managed-operations-v2','managed-operations-v3'].includes(context.collectionProfile))reject();
 const complete=context.collectionProfile==='managed-operations-v3';
 let installMode=' --pending-service';
 if(complete){
  const {agentOrigin}=context;
  if(!loopbackHTTPOrigin(agentOrigin))reject();
  if(pin?.version!=='v0.1.0-rc.2'){if(command!==null)reject();return 'unavailable';}
  installMode=` --read-admin --read-admin-agent-origin ${quote(agentOrigin)}`;
 }
 const kind=pin===null?'prepared-local':'verified-download';
 if(typeof command!=='string'||command!==(pin===null?manual(args):download(pin,args,installMode)))reject();
 return kind;
}
