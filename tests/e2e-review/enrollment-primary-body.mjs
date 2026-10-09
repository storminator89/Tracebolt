/** Synthetic enrollment only. Observe the application's one bounded reader;
 * never clone, prefetch, create a second reader, change bytes or replay a POST. */
export function installEnrollmentPrimaryBody({url}){
 const target=new URL(url);
 if(target.protocol!=='http:'||!['127.0.0.1','localhost'].includes(target.hostname)||target.pathname!=='/api/enrollment/invitations'||target.search||target.hash||target.username||target.password)throw new Error('Invalid synthetic enrollment observation scope');
 const originalFetch=globalThis.fetch,maximum=262144;
 let serial=0,current=null;
 const detach=entry=>{entry.signal?.removeEventListener('abort',entry.abort);};
 const discard=(entry,phase)=>{entry.phase=phase;entry.chunks=[];entry.body=null;entry.requestBody=null;detach(entry);};
 const clear=()=>{if(current)discard(current,'cleared');current=null;};
 const invalidate=()=>{if(current)discard(current,'invalidated');};
 const hidden=()=>{if(document.visibilityState==='hidden')invalidate();};
 const matches=(input,init)=>{
  const method=String(init?.method??(typeof input==='object'?input.method:undefined)??'GET').toUpperCase();
  return method==='POST'&&new URL(typeof input==='object'?input.url:String(input),globalThis.location.href).href===target.href;
 };
 const freeze=value=>{const queue=[value];while(queue.length){const item=queue.pop();if(item&&typeof item==='object'){queue.push(...Object.values(item));Object.freeze(item);}}return value;};
 async function observedFetch(input,init){
  const entry=current&&matches(input,init)?current:null;
  if(entry){
   entry.requests=Math.min(2,entry.requests+1);
   if(entry.requests!==1)discard(entry,'duplicate');
   else if(typeof init?.body!=='string'||new TextEncoder().encode(init.body).byteLength>2048)discard(entry,'invalid-request');
   else{
    entry.requestBody=init.body;entry.phase='waiting';entry.signal=init?.signal;
    entry.abort=()=>{entry.signalAborted=true;discard(entry,'aborted');};
    entry.signal?.addEventListener('abort',entry.abort,{once:true});
    if(entry.signal?.aborted)entry.abort();
   }
  }
  let response;
  try{response=await Reflect.apply(originalFetch,this,[input,init]);}
  catch(error){if(entry&&!['aborted','invalidated','cleared','duplicate'].includes(entry.phase))discard(entry,'failed');throw error;}
  if(!entry||entry.phase!=='waiting')return response;
  entry.status=response.status;
  const stream=response.body;
  if(!stream){discard(entry,'missing-body');return response;}
  entry.phase='reading';
  const getReader=stream.getReader.bind(stream),cancelStream=stream.cancel.bind(stream);
  stream.cancel=(...args)=>{discard(entry,'cancelled');return cancelStream(...args);};
  stream.getReader=(...args)=>{
   const reader=getReader(...args),read=reader.read.bind(reader),cancel=reader.cancel.bind(reader);
   reader.cancel=(...args)=>{discard(entry,'cancelled');return cancel(...args);};
   reader.read=async(...args)=>{
    let result;
    try{result=await read(...args);}catch(error){if(entry.phase==='reading')discard(entry,'failed');throw error;}
    if(entry.phase!=='reading')return result;
    try{
     if(!result.done){
      entry.bytes=Math.min(maximum+1,entry.bytes+result.value.byteLength);
      if(entry.bytes>maximum)discard(entry,'oversized');else entry.chunks.push(result.value.slice());
     }else{
      entry.eof=true;
      const bytes=new Uint8Array(entry.bytes);let offset=0;
      for(const chunk of entry.chunks){bytes.set(chunk,offset);offset+=chunk.byteLength;}
      entry.body=freeze(JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes)));
      entry.chunks=[];entry.phase='complete';
     }
    }catch{discard(entry,'invalid');}
    return result;
   };
   return reader;
  };
  return response;
 }
 const observer=Object.freeze({
  arm(){clear();current={id:++serial,phase:'armed',requests:0,status:0,bytes:0,eof:false,signalAborted:false,chunks:[],body:null,requestBody:null,signal:null,abort:null};return serial;},
  state(id){return current?.id===id?current.phase:'missing';},
  snapshot(id){const entry=current?.id===id?current:null;return entry?{phase:entry.phase,requests:entry.requests,status:entry.status,bytes:entry.bytes,eof:entry.eof,signalAborted:entry.signalAborted}:{phase:'missing'};},
  take(id){
   if(current?.id!==id||current.phase!=='complete'||current.requests!==1||current.signalAborted)return null;
   const entry=current,result={status:entry.status,requestBody:entry.requestBody,body:entry.body};clear();return Object.freeze(result);
  },
  clear,
 });
 Object.defineProperty(globalThis,'__traceboltEnrollmentBody',{configurable:true,value:observer});
 globalThis.fetch=observedFetch;
 window.addEventListener('pagehide',invalidate);window.addEventListener('hashchange',invalidate);window.addEventListener('tracebolt:authentication-required',invalidate);document.addEventListener('visibilitychange',hidden);
 return()=>{clear();if(globalThis.fetch===observedFetch)globalThis.fetch=originalFetch;delete globalThis.__traceboltEnrollmentBody;window.removeEventListener('pagehide',invalidate);window.removeEventListener('hashchange',invalidate);window.removeEventListener('tracebolt:authentication-required',invalidate);document.removeEventListener('visibilitychange',hidden);};
}
