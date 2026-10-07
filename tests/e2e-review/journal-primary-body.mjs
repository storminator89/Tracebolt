/** Test-only observation of the fixture's primary fetch consumer. Never imported
 * by the application. No response clone, second reader, body prefetch or CDP
 * body retrieval; the original Response, read results and errors are preserved. */
export function installJournalPrimaryBody({ url }) {
 const target=new URL(url);
 if(target.protocol!=='http:'||!['127.0.0.1','localhost'].includes(target.hostname)||!/^\/api\/devices\/agent_[a-f0-9]{32}\/journal\/query$/.test(target.pathname)||target.search||target.hash)throw new Error('Invalid synthetic journal observation scope');
 // One armed response, scoped to this fixture device. Inventory pages use the
 // production SYSTEM_PAGE_BYTES bound; journal pages retain their original cap.
 const scopes={journal:{url:target.href,maximum:65536},services:{url:target.href.replace(/\/journal\/query$/,'/inventory/system/query'),maximum:262144},overview:{url:target.href.replace(/\/journal\/query$/,'/inventory/overview/query'),maximum:262144,requestBound:true},actionPreview:{url:target.href.replace(/\/journal\/query$/,'/service-actions/preview'),maximum:32768,requestBound:true,measureBytes:true},actionApprove:{url:target.href.replace(/\/journal\/query$/,'/service-actions/approve'),maximum:32768,requestBound:true,measureBytes:true}};
 const originalFetch=globalThis.fetch;
 let serial=0,current=null;
 const discard=(entry,phase)=>{entry.phase=phase;entry.chunks=[];entry.body=null;entry.requestBody=null;};
 const matches=(input,init,entry)=>{
  const method=String(init?.method??(typeof input==='object'?input.method:undefined)??'GET').toUpperCase();
  return method==='POST'&&new URL(typeof input==='object'?input.url:String(input),globalThis.location.href).href===entry.scope.url;
 };
 const frozen=value=>{const queue=[value];while(queue.length){const item=queue.pop();if(item&&typeof item==='object'){for(const child of Object.values(item))queue.push(child);Object.freeze(item);}}return value;};
 async function observedFetch(input,init){
  const entry=current&&matches(input,init,current)?current:null;
  if(entry){entry.requests++;if(entry.requests!==1)discard(entry,'duplicate');else{
   entry.phase='waiting';
   // Observe the original bounded query string; never read/clone Request bodies.
   if(entry.scope.requestBound){if(typeof init?.body!=='string'||new TextEncoder().encode(init.body).byteLength>2048)discard(entry,'invalid-request');else entry.requestBody=init.body;}
  }}
  let response;
  try{response=await Reflect.apply(originalFetch,this,[input,init]);}
  catch(error){if(entry)discard(entry,'failed');throw error;}
  if(!entry||entry.phase!=='waiting')return response;
  entry.status=response.status;
  const stream=response.body;
  if(!stream){discard(entry,'missing');return response;}
  entry.phase='reading';
  const getReader=stream.getReader.bind(stream),cancelStream=stream.cancel.bind(stream);
  stream.cancel=(...args)=>{discard(entry,'cancelled');return cancelStream(...args);};
  stream.getReader=(...args)=>{
   const reader=getReader(...args),read=reader.read.bind(reader),cancel=reader.cancel.bind(reader);
   reader.cancel=(...values)=>{discard(entry,'cancelled');return cancel(...values);};
   reader.read=async(...values)=>{
    let result;
    try{result=await read(...values);}catch(error){discard(entry,'failed');throw error;}
    if(entry.phase!=='reading')return result;
    try{
     if(!result.done){
      entry.bytes+=result.value.byteLength;
      if(entry.bytes>entry.scope.maximum)discard(entry,'oversized');
      else entry.chunks.push(result.value.slice());
     }else{
      const bytes=new Uint8Array(entry.bytes);let offset=0;
      for(const chunk of entry.chunks){bytes.set(chunk,offset);offset+=chunk.byteLength;}
      entry.body=frozen(JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes)));
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
  arm(scope='journal'){if(!Object.hasOwn(scopes,scope))throw new Error('Invalid synthetic observation scope');if(current)discard(current,'superseded');current={id:++serial,scope:scopes[scope],phase:'armed',requests:0,status:0,bytes:0,chunks:[],body:null,requestBody:null};return serial;},
  state(id){return current?.id===id?current.phase:'missing';},
  take(id){if(current?.id!==id||current.phase!=='complete'||current.requests!==1)return null;const entry=current,body=entry.body,requestBody=entry.requestBody;entry.body=null;entry.requestBody=null;current=null;return Object.freeze({status:entry.status,body,...(entry.scope.requestBound?{requestBody}:{}),...(entry.scope.measureBytes?{bytes:entry.bytes}:{})});},
  clear(){if(current)discard(current,'cleared');current=null;},
 });
 Object.defineProperty(globalThis,'__traceboltJournalBody',{configurable:true,value:observer});
 globalThis.fetch=observedFetch;
 return()=>{observer.clear();if(globalThis.fetch===observedFetch)globalThis.fetch=originalFetch;delete globalThis.__traceboltJournalBody;};
}
