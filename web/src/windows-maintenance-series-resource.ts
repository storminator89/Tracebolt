import { useEffect, useRef, useState } from 'react';
import { AUTH_REQUIRED_EVENT, getProtectedRequestEpoch, request } from './api';
import { hasLogoutIntent, validOperatorSession } from './auth';
import { inventoryAge } from './complete-packages-types';
import { validWindowsCapacityTimestamp } from './windows-capacity-types';
import { acceptWindowsHealthClock, windowsHealthElapsed } from './windows-health-clock';
import { validWindowsMaintenanceWeeklyBounds } from './windows-maintenance-series-plan';
import { validWindowsMaintenanceSeriesView, validWindowsMaintenanceSeriesReview, validWindowsMaintenanceSeriesReceipt, windowsMaintenanceSeriesCanStart, windowsMaintenanceSeriesState, WINDOWS_MAINTENANCE_SERIES_BYTES } from './windows-maintenance-series-types';
import type { WindowsMaintenanceSeriesView, WindowsMaintenanceSeriesProposal, WindowsMaintenanceSeriesReview } from './windows-maintenance-series-types';

type Anchor = { mono: number; wall: number };
const capture = (): Anchor => ({ mono: performance.now(), wall: Date.now() });
const elapsed = (a:Anchor) => { const mono=performance.now()-a.mono,wall=Date.now()-a.wall; return Number.isFinite(mono)&&mono>=0&&Number.isFinite(wall)&&Math.abs(mono-wall)<=1500?mono:Infinity; };
type Snapshot = { key: string; epoch: number; started: Anchor; view: WindowsMaintenanceSeriesView };
// Retain only receipt-matching metadata, never token, dates, intent or device name.
type Pending = Pick<WindowsMaintenanceSeriesReview,'operationId'|'key'|'action'|'revision'|'occurrenceId'> & { count: number };
function hasPendingScope(view:WindowsMaintenanceSeriesView|null,key:string,pending:Map<string,Pending>,ownOperation?:string):boolean {
    const selected=view?.targets.find(t=>t.key===key);
    return [...pending.values()].some(p=>{if(p.operationId===ownOperation)return false;if(p.key===key)return true;const prior=view?.targets.find(t=>t.key===p.key);return !!selected&&!!prior&&selected.deviceId===prior.deviceId&&(selected.domain==='all'||prior.domain==='all'||selected.domain===prior.domain)});
}
type Commands = { refresh:()=>void; prepare:(proposal:WindowsMaintenanceSeriesProposal,action?:'create'|'cancel'|'end',occurrenceId?:number)=>Promise<void>; commit:()=>Promise<void>; dismiss:()=>void };
const noop:Commands={refresh:()=>{},prepare:async()=>{},commit:async()=>{},dismiss:()=>{}};
const root='/fleet/windows-maintenance-schedule/series';
export function useWindowsMaintenanceSeries(enabled:boolean,sessionKey:string|null,admin:boolean) {
    const [snapshot,setSnapshot]=useState<Snapshot|null>(null),[loading,setLoading]=useState(false),[writing,setWriting]=useState(false),[error,setError]=useState(false),[notice,setNotice]=useState<'committed'|'unconfirmed'|null>(null),[review,setReview]=useState<WindowsMaintenanceSeriesReview|null>(null),[generation,setGeneration]=useState(0),[privacyGeneration,setPrivacyGeneration]=useState(0),[,tick]=useState(0);
    const retained=useRef({session:sessionKey,epoch:getProtectedRequestEpoch(),pending:new Map<string,Pending>(),revisions:new Map<string,number>()});
    const key=JSON.stringify([enabled,sessionKey,admin]),clockKey=JSON.stringify(['windows-maintenance-series',sessionKey]);
    const live=useRef(key);live.current=key;const commands=useRef<Commands>(noop);
    useEffect(()=>{
        const epoch=getProtectedRequestEpoch();
        if(retained.current.session!==sessionKey||retained.current.epoch!==epoch){retained.current={session:sessionKey,epoch,pending:new Map(),revisions:new Map()};setNotice(null)}
        let alive=true,locked=false,suspended=document.visibilityState==='hidden',operation=0,busy=false;
        let accepted:Snapshot|null=null,reviewed:WindowsMaintenanceSeriesReview|null=null;
        const controllers=new Set<AbortController>();
        const abort=()=>{operation++;for(const c of controllers)c.abort();controllers.clear()};
        const dismiss=()=>{reviewed=null;setReview(null);setGeneration(n=>n+1)};
        const clear=(failure=false)=>{abort();accepted=null;busy=false;reviewed=null;if(alive){setSnapshot(null);setReview(null);setLoading(false);setWriting(false);setError(failure);if(failure)setPrivacyGeneration(n=>n+1);setGeneration(n=>n+1)}};
        const active=()=>alive&&enabled&&live.current===key&&!locked&&!suspended&&document.visibilityState!=='hidden'&&!hasLogoutIntent()&&epoch===getProtectedRequestEpoch()&&validWindowsCapacityTimestamp(sessionKey);
        const age=()=>accepted?windowsHealthElapsed(clockKey,epoch,accepted.view.serverNow,elapsed(accepted.started)):Infinity;
        const current=()=>active()&&accepted!==null&&age()<120000&&inventoryAge(sessionKey!,accepted.view.serverNow)>age()&&inventoryAge(accepted.view.authorityExpiresAt,accepted.view.serverNow)>age();
        const fetchValue=async(path:string,guard:()=>boolean,body?:unknown)=>{
            if(!guard())throw new Error('Inactive');
            const controller=new AbortController(),started=capture();controllers.add(controller);let timer=0;
            const valid=()=>guard()&&!controller.signal.aborted&&elapsed(started)<10000;
            const timeout=new Promise<never>((_,reject)=>{timer=window.setTimeout(()=>{controller.abort();reject(new Error('Timeout'))},10000)});
            try{return await Promise.race([(async()=>{
                let options:RequestInit={signal:controller.signal};
                if(body){const session=await request<unknown>('/auth/session',options,32768);if(!valid()||!admin||!validOperatorSession(session)||session.mode!=='lan'||!session.authenticated||session.loginMode!=='shared'||session.expiresAt!==sessionKey||typeof session.csrfToken!=='string'||!session.csrfToken||session.csrfToken.length>256||inventoryAge(sessionKey!,session.serverNow)<=elapsed(started))throw new Error('Inactive session');options={...options,method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':session.csrfToken},body:JSON.stringify(body)}}
                if(!valid())throw new Error('Inactive');const value=await request<unknown>(path,options,WINDOWS_MAINTENANCE_SERIES_BYTES);if(!valid())throw new Error('Inactive');return {value,started};
            })(),timeout])}finally{window.clearTimeout(timer);controllers.delete(controller)}
        };
        const reconcile=async(run:number)=>{
            for(const [id,pending] of retained.current.pending){
                if(!active()||run!==operation)return;
                try{const {value}=await fetchValue(`${root}/receipts/${id}`,()=>active()&&run===operation);
                    if(validWindowsMaintenanceSeriesReceipt(value,{...pending,occurrences:Array.from({length:pending.count},()=>({startsAt:'',endsAt:''}))})){retained.current.pending.delete(id);setNotice(retained.current.pending.size?'unconfirmed':'committed')}
                }catch{ /* Missing/unavailable receipts never prove non-commit. */ }
            }
        };
        const read=async()=>{
            if(!active()||busy)return;clear();const run=operation;busy=true;setLoading(true);
            try{const {value,started}=await fetchValue(root,()=>active()&&run===operation);
                if(!validWindowsMaintenanceSeriesView(value)||value.targets.some(t=>t.revision<(retained.current.revisions.get(t.key)??0))||!acceptWindowsHealthClock(clockKey,epoch,value.serverNow,elapsed(started)))throw new Error('Invalid series');
                const a=windowsHealthElapsed(clockKey,epoch,value.serverNow,elapsed(started));if(a>=120000||inventoryAge(sessionKey!,value.serverNow)<=a||inventoryAge(value.authorityExpiresAt,value.serverNow)<=a)throw new Error('Expired');
                if(retained.current.revisions.size+value.targets.filter(t=>!retained.current.revisions.has(t.key)).length>1024)throw new Error('Limit');
                for(const t of value.targets)retained.current.revisions.set(t.key,t.revision);
                accepted={key,epoch,started,view:value};setSnapshot(accepted);setError(false);await reconcile(run);
            }catch{if(alive&&run===operation&&live.current===key)clear(true)}finally{if(alive&&run===operation&&live.current===key){busy=false;setLoading(false)}}
        };
        const permitted=(proposal:WindowsMaintenanceSeriesProposal,action:'create'|'cancel'|'end',id:number,ownOperation?:string)=>{
            if(!admin||!current()||!accepted||hasPendingScope(accepted?.view??null,proposal.key,retained.current.pending,ownOperation))return false;
            const target=accepted.view.targets.find(t=>t.key===proposal.key);if(!target||target.revision!==proposal.revision||target.revision>=Number.MAX_SAFE_INTEGER)return false;
            if(action==='create')return windowsMaintenanceSeriesCanStart(accepted.view,target,age(),proposal.occurrences.length)&&validWindowsMaintenanceWeeklyBounds(proposal.occurrences,accepted.view.serverNow,age());
            const row=target.occurrences.find(w=>w.id===id);return !!row&&proposal.intent===row.intent&&proposal.occurrences.length===1&&proposal.occurrences[0].startsAt===row.startsAt&&proposal.occurrences[0].endsAt===row.endsAt&&windowsMaintenanceSeriesState(row,accepted.view.serverNow,age())===(action==='cancel'?'pending':'active');
        };
        const prepare=async(proposal:WindowsMaintenanceSeriesProposal,action:'create'|'cancel'|'end'='create',occurrenceId=0)=>{
            if(busy||!permitted(proposal,action,occurrenceId))return;dismiss();busy=true;setWriting(true);setError(false);const run=operation;
            try{const {value}=await fetchValue(action==='create'?`${root}/review`:`${root}/${action}/review`,()=>run===operation&&permitted(proposal,action,occurrenceId),action==='create'?proposal:{key:proposal.key,revision:proposal.revision,occurrenceId});
                if(!accepted||!validWindowsMaintenanceSeriesReview(value,proposal,accepted.view.serverNow,age(),action,occurrenceId))throw new Error('Invalid review');reviewed=value;setReview(value);
            }catch{if(alive&&run===operation&&live.current===key){dismiss();setError(true)}}finally{if(alive&&run===operation&&live.current===key){busy=false;setWriting(false)}}
        };
        const commit=async()=>{
            const r=reviewed;
            const valid=()=>!!r&&!!accepted&&permitted(r,r.action,r.occurrenceId)&&inventoryAge(r.expiresAt,accepted.view.serverNow)>age();
            if(busy||!r||!valid())return;
            busy=true;setWriting(true);setNotice(null);dismiss();const run=operation;
            // Reserve before dispatch. Even aborted/lost responses reconcile only by operation ID.
            const pending:Pending={operationId:r.operationId,key:r.key,action:r.action,revision:r.revision,occurrenceId:r.occurrenceId,count:r.occurrences.length};
            // Guard excludes our own pending entry only during this one already-reviewed request.
            const guard=()=>run===operation&&permitted(r,r.action,r.occurrenceId,r.operationId)&&accepted!==null&&inventoryAge(r.expiresAt,accepted.view.serverNow)>age();
            retained.current.pending.set(r.operationId,pending);setNotice('unconfirmed');
            try{const {value}=await fetchValue(`${root}/commit`,guard,{reviewToken:r.reviewToken,operationId:r.operationId,acknowledged:true});if(!validWindowsMaintenanceSeriesReceipt(value,r))throw new Error('Unconfirmed');retained.current.pending.delete(r.operationId);setNotice('committed');
            }catch{ /* Never replay. A later GET receipt is the only reconciliation. */ }
            finally{if(alive&&run===operation&&live.current===key){busy=false;setWriting(false);void read()}}
        };
        const lock=()=>{locked=true;retained.current.pending.clear();retained.current.revisions.clear();setNotice(null);clear(true)},suspend=()=>{suspended=true;clear(true)},restore=()=>{if(locked||document.visibilityState==='hidden')return;suspended=false;void read()},visibility=()=>document.visibilityState==='hidden'?suspend():restore(),navigation=()=>{locked=true;setPrivacyGeneration(n=>n+1);clear()};
        commands.current={refresh:()=>{void read()},prepare,commit,dismiss};clear();
        if(!enabled)return()=>{alive=false;abort();commands.current=noop};
        window.addEventListener(AUTH_REQUIRED_EVENT,lock);window.addEventListener('blur',suspend);window.addEventListener('focus',restore);window.addEventListener('pagehide',suspend);window.addEventListener('hashchange',navigation);window.addEventListener('popstate',navigation);document.addEventListener('visibilitychange',visibility);
        const timer=window.setInterval(()=>{if(epoch!==getProtectedRequestEpoch()||hasLogoutIntent()){if(!locked)lock()}else if(accepted&&!current())clear(true);else if(accepted){if(reviewed&&inventoryAge(reviewed.expiresAt,accepted.view.serverNow)<=age())dismiss();tick(n=>n+1)}},250);
        void read();return()=>{alive=false;abort();accepted=null;reviewed=null;commands.current=noop;window.clearInterval(timer);window.removeEventListener(AUTH_REQUIRED_EVENT,lock);window.removeEventListener('blur',suspend);window.removeEventListener('focus',restore);window.removeEventListener('pagehide',suspend);window.removeEventListener('hashchange',navigation);window.removeEventListener('popstate',navigation);document.removeEventListener('visibilitychange',visibility)};
    },[enabled,key,clockKey,sessionKey,admin]);
    const age=snapshot?windowsHealthElapsed(clockKey,snapshot.epoch,snapshot.view.serverNow,elapsed(snapshot.started)):Infinity;
    const available=enabled&&snapshot?.key===key&&snapshot.epoch===getProtectedRequestEpoch()&&!hasLogoutIntent()&&document.visibilityState!=='hidden'&&age<120000&&validWindowsCapacityTimestamp(sessionKey)&&inventoryAge(sessionKey,snapshot.view.serverNow)>age&&inventoryAge(snapshot.view.authorityExpiresAt,snapshot.view.serverNow)>age;
    return {view:available?snapshot.view:null,review:available?review:null,age,loading,writing,error,notice,generation,privacyGeneration,isUncertain:(key:string)=>hasPendingScope(available?snapshot.view:null,key,retained.current.pending),refresh:()=>commands.current.refresh(),prepare:(p:WindowsMaintenanceSeriesProposal,a?:'create'|'cancel'|'end',id?:number)=>commands.current.prepare(p,a,id),commit:()=>commands.current.commit(),dismiss:()=>commands.current.dismiss()};
}
