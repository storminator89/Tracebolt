/** Closed stage coverage only: no browser, transport, native read or raw failure. */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';
import {createRequire} from 'node:module';
import {windowsLogsStageNames,windowsLogsBrowserCase} from './windows-logs-browser.mjs';
const require=createRequire(new URL('../../web/package.json',import.meta.url)),ts=require('typescript');
const path=new URL('./windows-logs-browser.mjs',import.meta.url),text=fs.readFileSync(path,'utf8');
const source=ts.createSourceFile(path.pathname,text,ts.ScriptTarget.Latest,true,ts.ScriptKind.JS);
const printer=ts.createPrinter({removeComments:true});
const markName=statement=>{
 if(!statement||!ts.isExpressionStatement(statement)||!ts.isCallExpression(statement.expression))return null;
 const call=statement.expression;
 return ts.isIdentifier(call.expression)&&call.expression.text==='mark'&&call.arguments.length===1&&ts.isStringLiteral(call.arguments[0])?call.arguments[0].text:null;
};

test('Logs diagnostic stages form a finite source-only allowlist and retain the legacy logs stage',()=>{
 assert.equal(Object.isFrozen(windowsLogsStageNames),true);assert.equal(windowsLogsStageNames.length,50);assert.equal(new Set(windowsLogsStageNames).size,50);
 assert.ok(windowsLogsStageNames.every(name=>/^logs-[a-z-]{1,40}$/.test(name)));
 const runner=fs.readFileSync(new URL('./windows-inventory-browser.mjs',import.meta.url),'utf8');
 assert.match(runner,/'logs',\.\.\.windowsLogsStageNames,'legacy'/);assert.match(runner,/windowsLogsBrowserCase\(\{page,expect,base,mark,deviceId:/);
 assert.match(runner,/stages\.has\(stage\)\?stage:'setup'/);
 let marked=0;
 function visit(node){if(ts.isCallExpression(node)&&ts.isIdentifier(node.expression)&&node.expression.text==='mark'){assert.equal(node.arguments.length,1);assert.equal(ts.isStringLiteral(node.arguments[0]),true);assert.ok(windowsLogsStageNames.includes(node.arguments[0].text));marked++;}ts.forEachChild(node,visit);}
 visit(source);assert.equal(marked,50);
});

test('every awaited helper operation has its own immediately preceding finite stage',()=>{
 let count=0;
 function visit(node){
  if(ts.isFunctionDeclaration(node)&&['remountWindowsLogsDevice','windowsLogsBrowserCase'].includes(node.name?.text)){
   function inspect(part){if(ts.isAwaitExpression(part)){let statement=part;while(statement&&!ts.isStatement(statement))statement=statement.parent;assert.ok(statement&&ts.isBlock(statement.parent),'await must be in a labeled block');const siblings=statement.parent.statements,index=siblings.indexOf(statement),name=markName(siblings[index-1]);assert.ok(name&&windowsLogsStageNames.includes(name),'await must follow a closed mark');count++;}ts.forEachChild(part,inspect);}
   inspect(node.body);
  }
  ts.forEachChild(node,visit);
 }
 visit(source);assert.equal(count,49);
});

test('all 28 published hosted assertions remain byte-equivalent after canonical AST printing',()=>{
 const assertions=[];
 const isExpect=node=>{if(ts.isCallExpression(node)&&ts.isIdentifier(node.expression)&&node.expression.text==='expect')return true;if(ts.isPropertyAccessExpression(node))return isExpect(node.expression);if(ts.isCallExpression(node))return isExpect(node.expression);return false;};
 function visit(node){if(ts.isCallExpression(node)&&ts.isPropertyAccessExpression(node.expression)&&isExpect(node.expression.expression))assertions.push(printer.printNode(ts.EmitHint.Expression,node,source));ts.forEachChild(node,visit);}
 visit(source);assert.equal(assertions.length,28);
 // Captured from published 882b3e's exact helper. This guards against weakening
 // count/focus/layout/expiry assertions while adding only stage labels.
 assert.equal(crypto.createHash('sha256').update(JSON.stringify(assertions)).digest('hex'),'73fd442b15fd1e2f06567fc85d6b91dfb49bf2ae09849fde9da99f146aa26795');
 assert.doesNotMatch(text,/setDefaultTimeout|waitForTimeout|timeout\s*:|\.skip\(|error\.message|error\.stack|innerText|textContent|innerHTML|outerHTML/);
});

test('inert desktop/mobile walks reach only closed labels, including response, focus, filtering and expiry',async()=>{
 const seen=new Set(),noop=async()=>{},locator={};
 for(const name of ['getByRole','getByLabel','locator','first'])locator[name]=()=>locator;
 for(const name of ['click','focus','fill','selectOption','scrollIntoViewIfNeeded'])locator[name]=noop;
 locator.getAttribute=async()=>'synthetic-time';locator.evaluate=async fn=>fn.toString().includes('getComputedStyle')?{content:'"Record ID"',display:'block',visibility:'visible'}:true;
 const page={...locator,goto:noop,waitForResponse:async()=>({})};
 const expectation=new Proxy({}, {get(_target,key){return key==='not'?expectation:noop;}}),expect=()=>expectation;
 for(const width of [1440,390])await windowsLogsBrowserCase({page,expect,base:'https://fixture.invalid',deviceId:'fixture-id',locale:'en',width,shot:noop,disclosure:'invented',setPhase:()=>{},advance:noop,mark:name=>{assert.ok(windowsLogsStageNames.includes(name));seen.add(name);}});
 assert.deepEqual([...seen].sort(),[...windowsLogsStageNames].sort());
});
