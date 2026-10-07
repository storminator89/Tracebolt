/** Passive, closed failure diagnostics. No response bytes, headers, URLs, DOM
 * content or raw errors leave this helper. It never retries or changes a request. */
const layoutKeys=['viewportWidth','viewportHeight','documentClientWidth','documentClientHeight','mainWidth','mainHeight'];
const bounded=value=>typeof value==='number'&&Number.isFinite(value)&&value>=0&&value<=100000?Math.round(value*1000)/1000:null;
export function sanitizeTransportLayout(value){
 if(!value||typeof value!=='object'||Array.isArray(value))return null;
 const result={};for(const key of layoutKeys){const number=bounded(value[key]);if(number!==null)result[key]=number;}
 return Object.keys(result).length?result:null;
}
export function classifyTransportError(error){
 const message=typeof error?.message==='string'?error.message:'';
 // Match only known browser-tool categories; the matched text is never emitted.
 if(/Protocol error \(Page\.captureScreenshot\): Unable to capture screenshot(?:\n|$)/.test(message))return 'capture-unavailable';
 if(/Protocol error \(Network\.getResponseBody\): No resource with given identifier found(?:\n|$)/.test(message))return 'body-resource-missing';
 if(/Protocol error \(Network\.getResponseBody\): No data found for resource with given identifier(?:\n|$)/.test(message))return 'body-data-missing';
 if(/Protocol error \(Network\.getResponseBody\): Request content was evicted from inspector cache(?:\n|$)/.test(message))return 'body-buffer-evicted';
 if(message.includes('Target page, context or browser has been closed'))return 'target-closed';
 if(message.includes('Target crashed')||message.includes('Page crashed'))return 'target-crashed';
 if(error?.name==='TimeoutError')return 'timeout';
 if(message.includes('Protocol error (Network.getResponseBody)'))return 'body-protocol-other';
 if(message.includes('Protocol error (Page.captureScreenshot)'))return 'capture-protocol-other';
 return 'other';
}
function requestFailure(request){
 const text=request?.failure()?.errorText;
 if(text===null||text===undefined)return 'none';
 const known=new Map([['net::ERR_ABORTED','aborted'],['net::ERR_CONNECTION_CLOSED','connection-closed'],['net::ERR_CONNECTION_RESET','connection-reset'],['net::ERR_CONNECTION_REFUSED','connection-refused'],['net::ERR_TIMED_OUT','timed-out'],['net::ERR_FAILED','failed']]);
 return known.get(text)??'other';
}
export function createBrowserTransportDiagnostics(page,browser){
 const context=page.context(),requests=new WeakMap();
 let pageClosed=false,pageCrashed=false,contextClosed=false,browserDisconnected=false;
 const listeners=[
  [page,'close',()=>{pageClosed=true;}],[page,'crash',()=>{pageCrashed=true;}],
  [context,'close',()=>{contextClosed=true;}],[browser,'disconnected',()=>{browserDisconnected=true;}],
  [page,'requestfinished',request=>requests.set(request,'finished')],
  [page,'requestfailed',request=>requests.set(request,'failed')],
 ];
 for(const [target,event,listener] of listeners)target.on(event,listener);
 return {
  // Synchronous: snapshot at the failure, before ordinary finally cleanup.
  capture(operation,error,{response,elapsedMs,layout}={}){
   const request=typeof response?.request==='function'?response.request():null;
   const viewport=page.viewportSize(),version=browser.version();
   return {
    operation:operation==='screenshot'?'screenshot':operation==='response-body'?'response-body':'other',
    category:classifyTransportError(error),
    pageClosed:pageClosed||page.isClosed(),pageCrashed,contextClosed,browserDisconnected,browserConnected:browser.isConnected(),
    requestState:request?(requests.get(request)??'unobserved'):operation==='screenshot'?'not-applicable':'not-page-response',
    requestFailure:request?requestFailure(request):'none',
    configuredViewport:viewport?{width:bounded(viewport.width),height:bounded(viewport.height)}:null,
    preCaptureLayout:sanitizeTransportLayout(layout),elapsedMs:bounded(elapsedMs),
    browserVersion:typeof version==='string'&&/^\d{1,4}(?:\.\d{1,6}){1,3}$/.test(version)?version:null,
   };
  },
  dispose(){for(const [target,event,listener] of listeners)target.off(event,listener);},
 };
}
export function reportTransportFailure(diagnostics,operation,error,details){
 // Reporting must never replace the original failure or turn it into a pass.
 try{console.log('Browser transport diagnostic: '+JSON.stringify(diagnostics.capture(operation,error,details)));}
 catch{/* Preserve the caller's original error even if diagnostics are unavailable. */}
}
