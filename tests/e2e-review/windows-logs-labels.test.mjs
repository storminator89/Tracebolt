/** Real production markup plus the locked Playwright label engine in JSDOM.
 * No browser, network, native collection or host mutation is started. */
import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createRequire} from 'node:module';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const require=createRequire(path.join(root,'web/package.json'));
const {JSDOM}=require('jsdom'),{buildSync}=require('esbuild');
const playwrightRoot=path.dirname(require.resolve('playwright-core/package.json'));
const injected=require(path.join(playwrightRoot,'lib/generated/injectedScriptSource.js')).source;
const compiled=buildSync({stdin:{contents:"export {WindowsLogsPanel} from './windows-logs';export {windowsEventsView} from './windows-events-fixture';export {setLocale} from './i18n';export {createElement,act} from 'react';export {createRoot} from 'react-dom/client';",resolveDir:path.join(root,'web/src'),loader:'tsx'},bundle:true,platform:'node',format:'cjs',write:false,logLevel:'silent',loader:{'.css':'empty'}});
function domFor(markup){
 const dom=new JSDOM(markup,{runScripts:'outside-only',url:'https://fixture.invalid'});
 // Execute the installed source without constructing InjectedScript/browser.
 // This is its actual label selector engine and text matcher, not a lookalike.
 dom.window.eval('var module={exports:{}};'+injected+';window.labelEngine=InjectedScript.prototype._createInternalLabelEngine.call({_evaluator:{_cacheText:new Map(),_queryCSS:({scope})=>Array.from(scope.querySelectorAll("*"))}});');
 return dom;
}
async function rendered(locale,count=1){
 const dom=domFor('<div id="fixture-root"></div>');dom.window.process={env:{NODE_ENV:'test'}};dom.window.require=require;dom.window.IS_REACT_ACT_ENVIRONMENT=true;
 dom.window.eval('var module={exports:{}};var exports=module.exports;'+compiled.outputFiles[0].text+';window.fixtureComponent=module.exports;');
 const {WindowsLogsPanel,windowsEventsView,setLocale,createElement,createRoot,act}=dom.window.fixtureComponent;
 const element=()=>{const view=windowsEventsView();return createElement(WindowsLogsPanel,{resource:{view,events:view.events,snapshot:view.snapshot,status:'fresh',loading:false,error:null,eventsStale:false,refresh:()=>{}}});};
 setLocale(locale,false);const root=createRoot(dom.window.document.getElementById('fixture-root'));
 act(()=>root.render(count===1?element():createElement('div',null,...Array.from({length:count},element))));
 return {dom,async close(){act(()=>root.unmount());dom.window.close();}};
}
const exact=(dom,name)=>dom.window.labelEngine.queryAll(dom.window.document,JSON.stringify(name)+'s');

test('locked Playwright reproduces nested-option exact-label failure independently of Testing Library',()=>{
 const dom=domFor('<label>Channel<select><option value="">All channels</option><option>Application</option><option>System</option></select></label><label>Provider<input type="search"></label>');
 try{assert.equal(exact(dom,'Channel').length,0);assert.equal(exact(dom,'ChannelAll channelsApplicationSystem').length,1);assert.equal(exact(dom,'Provider').length,1);}finally{dom.window.close();}
});
for(const locale of ['en','de'])test(`production Logs selects resolve through unchanged exact Playwright labels (${locale})`,async()=>{
 const view=await rendered(locale),{dom}=view;
 try{
  for(const [label,value] of [[locale==='de'?'Kanal':'Channel','System'],[locale==='de'?'Stufe':'Level','2']]){
   const matches=exact(dom,label);assert.equal(matches.length,1,`exact ${label} must identify one control`);const select=matches[0];assert.equal(select.tagName,'SELECT');assert.equal(select.disabled,false);assert.ok([...select.options].some(option=>option.value===value));
   assert.equal(select.labels.length,1);assert.equal(select.labels[0].htmlFor,select.id);assert.equal(select.labels[0].contains(select),false);assert.equal(select.labels[0].textContent,label);
  }
 }finally{await view.close();}
});
test('multiple rendered Logs panels receive unique explicit control IDs',async()=>{
 const view=await rendered('en',2),{dom}=view;
 try{const ids=[...dom.window.document.querySelectorAll('.windows-logs-filter select')].map(select=>select.id);assert.equal(ids.length,4);assert.ok(ids.every(Boolean));assert.equal(new Set(ids).size,4);}finally{await view.close();}
});
