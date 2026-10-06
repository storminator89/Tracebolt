/** Closed, bounded failure diagnostics. Never serialize DOM text, URLs or errors. */
const stages=new Set([
 'initial','status-bootstrap','status-initial','status-retained-desktop','status-disabled-retained','status-failure-reads','status-held-read','status-navigation','status-suspension','status-access-loss','status-final-guards',
 'status-mobile-en-summary','status-mobile-en-details','status-mobile-de-summary','status-mobile-de-details',
 'setup-bootstrap','setup-initial','setup-cancel','setup-escape','setup-save','setup-test-consent','setup-test-send','setup-accepted-refresh','setup-uncertain-refresh','setup-idle-guard','setup-mobile-en','setup-mobile-de','setup-disable','setup-final-guards',
 'setup-collapsed-desktop-en','setup-form-desktop-en','setup-test-queued-desktop-en','setup-test-accepted-desktop-en','setup-test-uncertain-mobile-en','setup-test-uncertain-mobile-de','setup-form-mobile-en','setup-form-mobile-de','setup-test-uncertain-desktop-de','setup-disabled-mobile-de'
]);
const steps=new Set(['action','document-width','panel-width','visibility','scroll-stability','scroll-center','viewport-ratio','bounding-box','horizontal-bounds','element-width','capture','aggregate-refresh']);
const categories=new Set(['panel','heading','button','input','label','time','term','definition','summary','paragraph','readback','mode','other','none']);
const numericKeys=['viewportWidth','viewportHeight','documentClientWidth','documentScrollWidth','bodyScrollWidth','elementLeft','elementTop','elementWidth','elementHeight','elementClientWidth','elementClientHeight','elementScrollWidth','elementScrollHeight','mainLeft','mainTop','mainWidth','mainHeight','mainClientWidth','mainClientHeight','mainScrollWidth','mainScrollHeight','mainScrollLeft','mainScrollTop'];
const bounded=n=>typeof n==='number'&&Number.isFinite(n)&&Math.abs(n)<=100000?Math.round(n*1000)/1000:null;
export function sanitizeAlarmGeometry(value){
 if(!value||typeof value!=='object'||Array.isArray(value))return null;
 const out={};for(const key of numericKeys){const n=bounded(value[key]);if(n!==null)out[key]=n;}return Object.keys(out).length?out:null;
}
export function createAlarmBrowserDiagnostics(){
 let stage='initial',step='action',index=-1,selected=null,panel=null;
 return {
  reset(target){stage='initial';step='action';index=-1;selected=null;panel=target??null;},
  mark(value){stage=stages.has(value)?value:'initial';step='action';index=-1;selected=null;},
  track(target,ordinal){selected=target;index=Number.isSafeInteger(ordinal)&&ordinal>=0&&ordinal<=200?ordinal:-1;},
  step(value){step=steps.has(value)?value:'action';},
  async details(){
   let snapshot=null;
   try{snapshot=await(selected??panel)?.evaluate(node=>{
    const r=node.getBoundingClientRect(),main=node.closest('.main-content'),m=main?.getBoundingClientRect();
    const tag={H2:'heading',BUTTON:'button',INPUT:'input',LABEL:'label',TIME:'time',DT:'term',DD:'definition',SUMMARY:'summary',P:'paragraph'};
    const category=node.classList.contains('alarm-status')||node.classList.contains('alarm-settings')?'panel':node.classList.contains('alarm-settings-readback')?'readback':node.classList.contains('alarm-mode')?'mode':tag[node.tagName]??'other';
    return {category,geometry:{viewportWidth:innerWidth,viewportHeight:innerHeight,documentClientWidth:document.documentElement.clientWidth,documentScrollWidth:document.documentElement.scrollWidth,bodyScrollWidth:document.body.scrollWidth,elementLeft:r.left,elementTop:r.top,elementWidth:r.width,elementHeight:r.height,elementClientWidth:node.clientWidth,elementClientHeight:node.clientHeight,elementScrollWidth:node.scrollWidth,elementScrollHeight:node.scrollHeight,mainLeft:m?.left,mainTop:m?.top,mainWidth:m?.width,mainHeight:m?.height,mainClientWidth:main?.clientWidth,mainClientHeight:main?.clientHeight,mainScrollWidth:main?.scrollWidth,mainScrollHeight:main?.scrollHeight,mainScrollLeft:main?.scrollLeft,mainScrollTop:main?.scrollTop}};
   },undefined,{timeout:750});}catch{/* No raw failure or detached DOM diagnostic is retained. */}
   return {stage,step,elementCategory:categories.has(snapshot?.category)?snapshot.category:'none',elementIndex:index,geometry:sanitizeAlarmGeometry(snapshot?.geometry)};
  }
 };
}
