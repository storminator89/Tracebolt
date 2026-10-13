import {createRequire} from 'node:module';
import {createHash} from 'node:crypto';
import coordinates from './journal-browser-coordinates.json' with {type:'json'};
import {journalFailureCoordinates} from './journal-browser-diagnostics.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {smokeNames,smokeMode,requireSmoke} from './pr-browser-smoke.mjs';
const pass=()=>smokeNames.map(name=>({name,status:'PASS'}));
test('full invocation is unchanged; only exact explicit smoke selects a subset',()=>{
 assert.equal(smokeMode([]),false);assert.equal(smokeMode(['--pr-smoke']),true);
 for(const args of [['--all'],['--pr-smoke','--all'],['--pr-smoke=true']])assert.throws(()=>smokeMode(args));
});
test('all six exact existing cases must pass once',()=>{
 assert.equal(smokeNames.length,6);requireSmoke(pass());
 for(const rows of [[],pass().slice(1),[...pass(),pass()[0]],pass().map((r,i)=>i? r:{...r,status:'SKIP'}),pass().map((r,i)=>i? r:{...r,name:'wrong'})])assert.throws(()=>requireSmoke(rows));
 const source=fs.readFileSync(new URL('./lan-browser.mjs',import.meta.url),'utf8');
 for(const name of smokeNames)assert.equal(source.split("await check('"+name+"'").length,2);
 assert.ok(source.includes("prSmoke?'pr-browser-smoke-results.json':'lan-browser-results.json'"));
 assert.ok(source.includes('requireSmoke(results)'));
});

// Content-free diagnostics for the PR runner’s existing journal flow.
const sourceSha='a'.repeat(40),marker='PRIVATE_MARKER_MUST_NOT_ESCAPE';
const result=(index,status='PASS')=>({name:coordinates.cases[index],status,stage:coordinates.stages[5],error:marker,body:marker});
const input=()=>({sourceSha,results:[result(0,'FAIL')],setupFailure:false,runtimeErrorCount:0,stage:coordinates.stages[8]});

test('closed coordinates exactly match the existing ordered cases and literal checkpoints',()=>{
 const source=fs.readFileSync(new URL('./journal-browser.mjs',import.meta.url),'utf8');
 assert.deepEqual(coordinates.cases,[...source.matchAll(/await check\('([^']+)'/g)].map(match=>match[1]));
 assert.deepEqual(coordinates.stages,[...new Set(['setup',...[...source.matchAll(/mark\('([^']+)'\)/g)].map(match=>match[1])])]);
 assert.equal(coordinates.cases.length,7);assert.ok(coordinates.stages.length<=128);
});
test('all 407 existing browser assertions remain byte-equivalent after canonical AST printing',()=>{
 const require=createRequire(new URL('../../web/package.json',import.meta.url)),ts=require('typescript');
 const source=ts.createSourceFile('journal-browser.mjs',fs.readFileSync(new URL('./journal-browser.mjs',import.meta.url),'utf8'),ts.ScriptTarget.Latest,true,ts.ScriptKind.JS),printer=ts.createPrinter({newLine:ts.NewLineKind.LineFeed}),assertions=[];
 const isExpect=node=>ts.isCallExpression(node)?isExpect(node.expression):ts.isPropertyAccessExpression(node)?isExpect(node.expression):ts.isIdentifier(node)&&node.text==='expect';
 function visit(node){if(ts.isCallExpression(node)&&ts.isPropertyAccessExpression(node.expression)&&isExpect(node.expression.expression))assertions.push(printer.printNode(ts.EmitHint.Expression,node,source));ts.forEachChild(node,visit);}
 visit(source);assert.equal(assertions.length,407);assert.equal(createHash('sha256').update(JSON.stringify(assertions)).digest('hex'),'4c026b4214c6b8099f69e35a8c65eb3a243b5fdf2aa6b79e3939a2e84e5a0189');
});
test('reports only source identity and numeric case/checkpoint coordinates',()=>{
 const report=journalFailureCoordinates(input());
 assert.deepEqual(report,{schemaVersion:'tracebolt.journal-browser-failure.v1',sourceSha,failures:[{case:1,checkpoint:5}],setupFailure:false,runtimeFailure:false,finalCheckpoint:8});
 assert.equal(JSON.stringify(report).includes(marker),false);
 const multi={...input(),results:[result(0),result(1,'FAIL'),result(2,'FAIL')]};
 assert.deepEqual(journalFailureCoordinates(multi).failures,[{case:2,checkpoint:5},{case:3,checkpoint:5}]);
});
test('setup/runtime-only failures are fixed booleans; success emits nothing',()=>{
 assert.equal(journalFailureCoordinates({...input(),results:[result(0)]}),null);
 const setup=journalFailureCoordinates({...input(),results:[],setupFailure:true});
 assert.equal(setup.setupFailure,true);assert.deepEqual(setup.failures,[]);
 const runtime=journalFailureCoordinates({...input(),results:[],runtimeErrorCount:2});
 assert.equal(runtime.runtimeFailure,true);assert.deepEqual(runtime.failures,[]);
});
test('unknown, tampered, out-of-order and unbounded source inputs emit nothing',()=>{
 for(const patch of [{sourceSha:marker},{sourceSha:'a'.repeat(40)+'\n'},{stage:marker},{setupFailure:marker},{runtimeErrorCount:-1},{runtimeErrorCount:Infinity},{runtimeErrorCount:1.1},{results:null},{results:Array(8).fill(result(0))},{results:[result(1,'FAIL')]},{results:[{...result(0,'FAIL'),stage:marker}]},{results:[{...result(0,'FAIL'),status:marker}]}])assert.equal(journalFailureCoordinates({...input(),...patch}),null);
});
