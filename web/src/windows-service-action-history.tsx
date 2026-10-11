import { useEffect, useRef, useState } from 'react';
import './windows-service-action-history.css';
import { getProtectedRequestEpoch, request } from './api';
import { hasLogoutIntent, validOperatorSession } from './auth';
import { useLocale } from './i18n';
import { fullDate } from './utils';
import { validWindowsActionHistory, validWindowsActionHistoryDetail } from './windows-service-action-history-types';
import type { WindowsActionHistory, WindowsActionHistoryDetail, WindowsActionHistorySummary } from './windows-service-action-history-types';
const copy={
 en:{title:'Saved action history',scope:'Up to 64 approvals for this service grant, newest first. Original timestamps; no automatic retries.',capacity:'All 64 retained approval slots are used. New actions are blocked; saved receipts remain available.',empty:'No saved approvals for this service grant.',read:'Read receipt',close:'Close receipt',approved:'Approved',claimed:'Claimed once',notClaimed:'No claim recorded',actor:'Approving operator',job:'Action ID',at:'Status read',noCompletion:'The broker result has no completion timestamp.',error:'History is unavailable or changed. Close and reopen to read it again.'},
 de:{title:'Gespeicherte Aktionshistorie',scope:'Bis zu 64 Freigaben für diese Dienstfreigabe, neueste zuerst. Ursprüngliche Zeitangaben; keine automatischen Wiederholungen.',capacity:'Alle 64 gespeicherten Freigabeplätze sind belegt. Neue Aktionen sind gesperrt; gespeicherte Belege bleiben verfügbar.',empty:'Keine gespeicherten Aktionen für diese Dienstfreigabe.',read:'Beleg lesen',close:'Beleg schließen',approved:'Freigegeben',claimed:'Einmal abgeholt',notClaimed:'Keine Abholung erfasst',actor:'Freigebender Operator',job:'Aktions-ID',at:'Status gelesen',noCompletion:'Das Broker-Ergebnis enthält keinen Abschlusszeitpunkt.',error:'Historie nicht verfügbar oder geändert. Zum erneuten Lesen schließen und wieder öffnen.'},
};
type Labels = Record<'pending'|'deadline'|'reported'|'start'|'stop'|'restart'|'attempt'|'yes'|'no'|'complete'|'approved'|'claimed'|'expired'|'needs_intervention'|'not-requested'|'intervention-required'|'running-observed'|'stopped-observed',string>;
export function WindowsServiceActionHistory({deviceId,actor,sessionKey,insecure,serverNow,labels:l}:{deviceId:string;actor:string;sessionKey:string;insecure:boolean;serverNow:string;labels:Labels}) {
 const [locale]=useLocale(),c=copy[locale], [open,setOpen]=useState(false),[history,setHistory]=useState<WindowsActionHistory|null>(null),[selected,setSelected]=useState<string|null>(null),[detail,setDetail]=useState<WindowsActionHistoryDetail|null>(null),[busy,setBusy]=useState(false),[error,setError]=useState(false);
 const alive=useRef(false),version=useRef(0),pending=useRef<AbortController|null>(null),lastTime=useRef(Date.parse(serverNow));
 useEffect(()=>{alive.current=true;return()=>{alive.current=false;version.current++;pending.current?.abort()}},[]);
 const cancel=()=>{version.current++;pending.current?.abort();pending.current=null;setBusy(false);setDetail(null);setSelected(null);setError(false)};
 const visible=()=>document.visibilityState!=='hidden';
 async function read(row?:WindowsActionHistorySummary) {
  if(!alive.current||hasLogoutIntent()||!visible())return;
  pending.current?.abort();const controller=new AbortController(),token=++version.current,epoch=getProtectedRequestEpoch();pending.current=controller;setBusy(true);setError(false);setDetail(null);setSelected(row?.identity.jobId??null);
  const timeout=window.setTimeout(()=>controller.abort(),10000);
  try {
   const session=await request<unknown>('/auth/session',{signal:controller.signal},16384);
   if(!validOperatorSession(session)||session.mode!=='lan'||!session.authenticated||session.loginMode!=='named'||session.actorId!==actor||!session.capabilities?.includes('windows_service_control')||session.expiresAt!==sessionKey||session.insecureTestMode!==insecure||Date.parse(session.expiresAt)<=Date.parse(session.serverNow))throw new Error('Session ended');
   if(controller.signal.aborted||token!==version.current||epoch!==getProtectedRequestEpoch()||hasLogoutIntent())return;
   const value=await request<unknown>(`/devices/${deviceId}/windows-service-actions/history${row?'/'+row.identity.jobId:''}`,{signal:controller.signal},row?16384:65536);
   if(!alive.current||controller.signal.aborted||token!==version.current||epoch!==getProtectedRequestEpoch()||hasLogoutIntent()||!visible())return;
   if(row) {
    if(!history||!validWindowsActionHistoryDetail(value,history,row,actor))throw new Error('Invalid receipt');
   } else if(!validWindowsActionHistory(value,deviceId))throw new Error('Invalid history');
   const checked=value as WindowsActionHistory|WindowsActionHistoryDetail,at=Date.parse(checked.serverNow);
   if(at<lastTime.current||at>=Date.parse(sessionKey))throw new Error('Expired or stale history');
   lastTime.current=at;
   if(row)setDetail(checked as WindowsActionHistoryDetail);else setHistory(checked as WindowsActionHistory);
  } catch {if(alive.current&&token===version.current){setError(true);setHistory(null);setDetail(null)}}
  finally {window.clearTimeout(timeout);if(alive.current&&token===version.current){setBusy(false);pending.current=null}}
 }
 const yes=(v:boolean)=>v?l.yes:l.no,j=detail?.job;
 return <div className="windows-service-action-history">
  <button className="button small" aria-expanded={open} onClick={()=>{cancel();setHistory(null);setOpen(!open);if(!open)void read()}}>{c.title}</button>
  {open&&<div className="windows-service-action-history-content">
   <p className="windows-inventory-exclusions">{c.scope}</p>
   {busy&&<p role="status">{l.pending}</p>}{error&&<p role="alert">{c.error}</p>}
   {history&&<><p className="windows-inventory-exclusions">{c.at}: <time dateTime={history.serverNow}>{fullDate(history.serverNow)}</time></p>{history.jobs.length===history.limit&&<p role="status">{c.capacity}</p>}{history.jobs.length===0?<p>{c.empty}</p>:<ol className="windows-service-action-history-list">{history.jobs.map(row=><li key={row.identity.jobId}>
    <p><strong>{l[row.outcome??row.state]}</strong> · {l[row.operation]} · <time dateTime={row.approvedAt}>{fullDate(row.approvedAt)}</time></p>
    <button className="button small" aria-expanded={selected===row.identity.jobId} onClick={()=>{if(selected===row.identity.jobId)cancel();else void read(row)}}>{selected===row.identity.jobId?c.close:c.read} #{row.identity.sequence}</button>
    {selected===row.identity.jobId&&j&&detail&&<div className="windows-service-action-history-receipt">
     <p><strong>{l[j.result?.outcome??j.state]}</strong> · {l[j.operation]}: {j.target}</p>
     <p>{l[j.state]}</p><p className="windows-inventory-exclusions">{l.reported}</p>
     <p>{c.approved}: <time dateTime={j.approvedAt}>{fullDate(j.approvedAt)}</time></p>
     <p>{detail.claimedAt?<>{c.claimed}: <time dateTime={detail.claimedAt}>{fullDate(detail.claimedAt)}</time></>:c.notClaimed}</p>
     <p>{l.deadline}: <time dateTime={j.startDeadline}>{fullDate(j.startDeadline)}</time></p>
     {j.result&&<><p>{l.stop}: {l.attempt} {yes(j.result.stopAttempted)} / {yes(j.result.stopRequested)} / {yes(j.result.stoppedObserved)}</p><p>{l.start}: {l.attempt} {yes(j.result.startAttempted)} / {yes(j.result.startRequested)} / {yes(j.result.runningObserved)}</p><p className="windows-inventory-exclusions">{c.noCompletion}</p></>}
     <p>{c.actor}: {j.actorId}</p><p>{c.job}: {j.identity.jobId}</p>
     <p>{c.at}: <time dateTime={detail.serverNow}>{fullDate(detail.serverNow)}</time></p>
    </div>}
   </li>)}</ol>}</>}
  </div>}
 </div>;
}
