import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import fs from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

// Read only the cleanup/start function bodies. Never import the browser runner,
// launch a process, listen on a port, load Playwright or compile the Go fixture.
const source=fs.readFileSync(new URL('./endpoint-identity-browser.mjs',import.meta.url),'utf8');
const stopSource=source.slice(source.indexOf('async function stop(){'),source.indexOf('\nasync function control('));
const startSource=source.slice(source.indexOf('async function start(){'),source.indexOf('\nasync function pageAt('));
assert.ok(stopSource.startsWith('async function stop(){'));
assert.ok(startSource.startsWith('async function start(){'));

function fixture({exitAt='none',code=null,signal=null,killResult=true,race=false,eventOnly=false}={}){
 const child=new EventEmitter(),actions=[],timers=new Set(),delays=[];
 let pipeCloses=0,spawns=0,mkdirs=0,clock=0;
 child.pid=123;child.exitCode=code;child.signalCode=signal;child.killed=false;
 const exit=(exitCode,signalCode)=>{child.exitCode=exitCode;child.signalCode=signalCode;child.emit('exit',exitCode,signalCode);};
 const finish=(exitCode,signalCode)=>queueMicrotask(()=>exit(eventOnly?null:exitCode,eventOnly?null:signalCode));
 child.stdin={end(){actions.push({action:'EOF',at:clock});if(exitAt==='EOF')finish(0,null);}};
 child.kill=value=>{actions.push({action:value,at:clock});child.killed=killResult;if(exitAt===value)finish(null,value);return killResult;};
 if(race)child.once('newListener',name=>{assert.equal(name,'exit');exit(null,'SIGTERM');});
 const context=vm.createContext({
  server:child,pipe:{close(){pipeCloses++;}},waiting:{},fatal:false,cleanupFailed:false,
  setTimeout(fn,delay){
   assert.equal(delay,1500,'every stage keeps its original 1.5-second bound');
   delays.push(delay);const timer={active:true};timers.add(timer);
   timer.handle=setImmediate(()=>{if(timer.active){timer.active=false;timers.delete(timer);clock+=delay;fn();}});
   return timer;
  },
  clearTimeout(timer){if(timer){timer.active=false;clearImmediate(timer.handle);timers.delete(timer);}},
  fs:{async mkdtemp(){mkdirs++;throw Error('UNEXPECTED_FIXTURE_DIRECTORY');}},
  path:{join(){return 'inert-fixture-directory';}},temporary:'inert',
  spawn(){spawns++;throw Error('UNEXPECTED_FIXTURE_SPAWN');}
 });
 vm.runInContext(stopSource+'\n'+startSource+'\nthis.stop=stop;this.start=start;',context);
 return {child,context,actions,delays,exit,
  state:()=>({pipeCloses,spawns,mkdirs,clock,timers:timers.size,listeners:child.listenerCount('exit')})};
}
function clean(f){assert.equal(f.state().timers,0);assert.equal(f.state().listeners,0);assert.equal(f.context.waiting,null);}

for(const [exitAt,expectedActions,elapsed] of [
 ['EOF',['EOF'],0],
 ['SIGTERM',['EOF','SIGTERM'],1500],
 ['SIGKILL',['EOF','SIGTERM','SIGKILL'],3000]
])test(`endpoint cleanup observes ${exitAt} exit without false failure or extra signals`,async()=>{
 const f=fixture({exitAt});await f.context.stop();
 assert.equal(f.context.fatal,false);assert.equal(f.context.cleanupFailed,false);assert.equal(f.context.server,null);
 assert.deepEqual(f.actions.map(v=>v.action),expectedActions);assert.equal(f.state().clock,elapsed);clean(f);
 if(exitAt!=='EOF'){assert.equal(f.child.exitCode,null);assert.equal(f.child.signalCode,exitAt);}
 await f.context.stop();assert.deepEqual(f.actions.map(v=>v.action),expectedActions);clean(f);
});

for(const [code,signal] of [[0,null],[7,null],[null,'SIGTERM'],[null,'SIGKILL']])
 test(`endpoint cleanup skips an already observed exit (${code}, ${signal})`,async()=>{
  const f=fixture({code,signal});await f.context.stop();
  assert.equal(f.context.fatal,false);assert.equal(f.context.server,null);
  assert.deepEqual(f.actions,[]);assert.deepEqual(f.delays,[]);clean(f);
 });

test('endpoint cleanup rechecks exit after listener attachment and removes the missed-event listener',async()=>{
 const f=fixture({race:true});await f.context.stop();
 assert.equal(f.context.fatal,false);assert.equal(f.context.server,null);assert.equal(f.child.signalCode,'SIGTERM');
 assert.deepEqual(f.actions,[{action:'EOF',at:0}]);assert.deepEqual(f.delays,[1500]);assert.equal(f.state().clock,0);clean(f);
});

for(const killResult of [true,false])test(`unobserved exit remains fatal even when kill() returns ${killResult}`,async()=>{
 const f=fixture({killResult});await f.context.stop();
 assert.equal(f.context.fatal,true);assert.equal(f.context.cleanupFailed,true);assert.equal(f.context.server,f.child);
 assert.deepEqual(f.actions,[{action:'EOF',at:0},{action:'SIGTERM',at:1500},{action:'SIGKILL',at:3000}]);
 assert.deepEqual(f.delays,[1500,1500,1500]);assert.equal(f.state().clock,4500);clean(f);
 await assert.rejects(f.context.start(),{message:'FIXTURE_CLEANUP_UNRESOLVED'});
 assert.equal(f.state().spawns,0);assert.equal(f.state().mkdirs,0);
 await f.context.stop();assert.equal(f.actions.length,3);assert.equal(f.delays.length,3);
 assert.equal(f.context.server,f.child);assert.equal(f.context.fatal,true);clean(f);
 f.exit(null,'SIGKILL');await f.context.stop();
 assert.equal(f.context.server,null);assert.equal(f.context.cleanupFailed,false);assert.equal(f.context.fatal,true);clean(f);
});

test('an exit event without either exit field is not accepted as termination evidence',async()=>{
 const f=fixture({exitAt:'SIGTERM',eventOnly:true});await f.context.stop();
 assert.equal(f.context.fatal,true);assert.equal(f.context.server,f.child);
 assert.deepEqual(f.actions.map(v=>v.action),['EOF','SIGTERM','SIGKILL']);clean(f);
});

test('a child with no PID and no observed exit cannot be discarded or replaced',async()=>{
 const f=fixture();f.child.pid=undefined;await f.context.stop();
 assert.equal(f.context.fatal,true);assert.equal(f.context.server,f.child);assert.deepEqual(f.actions,[]);
 await assert.rejects(f.context.start(),{message:'FIXTURE_CLEANUP_UNRESOLVED'});
 assert.equal(f.state().spawns,0);assert.equal(f.state().mkdirs,0);clean(f);
});

test('a runner without a child closes control state without creating timers or signals',async()=>{
 const f=fixture();f.context.server=null;await f.context.stop();
 assert.equal(f.context.fatal,false);assert.equal(f.context.server,null);assert.equal(f.state().pipeCloses,1);
 assert.deepEqual(f.actions,[]);assert.deepEqual(f.delays,[]);clean(f);
});

test('successful cleanup lets the next start reach fixture creation',async()=>{
 const f=fixture({exitAt:'EOF'});await f.context.stop();
 assert.equal(f.context.server,null);assert.equal(f.context.fatal,false);
 await assert.rejects(f.context.start(),{message:'UNEXPECTED_FIXTURE_DIRECTORY'});
 assert.equal(f.state().mkdirs,1);assert.equal(f.state().spawns,0);clean(f);
});

test('bounded cleanup removes only its own exit listeners',async()=>{
 const f=fixture({exitAt:'SIGTERM'});let lifecycleExits=0;
 const lifecycle=()=>{lifecycleExits++;};f.child.on('exit',lifecycle);
 await f.context.stop();assert.equal(lifecycleExits,1);
 assert.deepEqual(f.child.listeners('exit'),[lifecycle]);assert.equal(f.state().timers,0);
 f.child.removeListener('exit',lifecycle);clean(f);
});
