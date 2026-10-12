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
