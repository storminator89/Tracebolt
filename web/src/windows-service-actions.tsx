import { sameWindowsServiceReviewBinding, windowsServiceReviewCurrent, WINDOWS_SERVICE_REVIEW_HEADER } from './windows-service-incident-review-types';
import type { WindowsServiceIncidentReviewContext } from './windows-service-incident-review-types';
import { useCallback, useEffect, useRef, useState } from 'react';
import { APIError, AUTH_REQUIRED_EVENT, getProtectedRequestEpoch, mutateRaw, request } from './api';
import { hasLogoutIntent, useOperator, validOperatorSession } from './auth';
import { useLocale } from './i18n';
import { fullDate } from './utils';
import { WindowsServiceActionHistory } from './windows-service-action-history';
import { actionID, validWindowsActionView } from './windows-service-action-types';
import type { WindowsActionView, WindowsServiceOperation } from './windows-service-action-types';
const copy = {
 en: { title: 'Selected service control', interruption: 'Actions may interrupt the application.', scope: 'Control scope', receipt: 'Action receipt', intro: 'A separate local broker grant authorizes only this reviewed service. Inventory does not authorize control.', access: 'A named operator with Windows service control permission is required.', refresh: 'Read saved status', select: 'Select service', chooseOperation: 'Choose an operation', start: 'Start', stop: 'Stop', restart: 'Restart', preview: 'Review action', approve: 'Approve this action once', cancel: 'Dismiss preview', acknowledge: 'I approve this exact operation and its possible interruption.', uncertain: 'The response is unconfirmed. Read saved status before doing anything else. Do not create a replacement action.', error: 'Action unavailable or changed. Read saved status.', pending: 'Reading…', deadline: 'Original deadline', reported: 'Agent-reported outcome; application health is not established.', empty: 'No broker action grant is configured.', disabled: 'Control is currently unavailable.', complete: 'Completed broker observation', approved: 'Approved; awaiting one-time claim', claimed: 'Claimed; execution unconfirmed', expired: 'Expired before claim', needs_intervention: 'Intervention required; further actions blocked', 'not-requested': 'No native request confirmed', 'intervention-required': 'Outcome uncertain', 'running-observed': 'Running observed', 'stopped-observed': 'Stopped observed', attempt: 'Attempted / requested / observed', yes: 'yes', no: 'no' },
 de: { title: 'Ausgewählten Dienst steuern', interruption: 'Aktionen können die Anwendung unterbrechen.', scope: 'Steuerungsumfang', receipt: 'Aktionsbeleg', intro: 'Eine separate lokale Broker-Freigabe erlaubt nur diesen geprüften Dienst. Inventar erteilt keine Steuerungsberechtigung.', access: 'Ein benannter Operator mit Berechtigung zur Windows-Dienststeuerung ist erforderlich.', refresh: 'Gespeicherten Status lesen', select: 'Dienst auswählen', chooseOperation: 'Aktion auswählen', start: 'Starten', stop: 'Stoppen', restart: 'Neu starten', preview: 'Aktion prüfen', approve: 'Diese Aktion einmal freigeben', cancel: 'Vorschau schließen', acknowledge: 'Ich genehmige genau diese Aktion und ihre mögliche Unterbrechung.', uncertain: 'Die Antwort ist unbestätigt. Zuerst den gespeicherten Status lesen. Keine Ersatzaktion erstellen.', error: 'Aktion nicht verfügbar oder geändert. Gespeicherten Status lesen.', pending: 'Wird gelesen …', deadline: 'Ursprüngliche Frist', reported: 'Vom Agent gemeldetes Ergebnis; der Anwendungszustand ist damit nicht bestätigt.', empty: 'Keine Broker-Aktionsfreigabe eingerichtet.', disabled: 'Steuerung derzeit nicht verfügbar.', complete: 'Broker-Beobachtung abgeschlossen', approved: 'Freigegeben; einmalige Abholung ausstehend', claimed: 'Abgeholt; Ausführung unbestätigt', expired: 'Vor Abholung abgelaufen', needs_intervention: 'Eingriff erforderlich; weitere Aktionen gesperrt', 'not-requested': 'Keine native Anforderung bestätigt', 'intervention-required': 'Ergebnis ungewiss', 'running-observed': 'Laufender Zustand beobachtet', 'stopped-observed': 'Gestoppter Zustand beobachtet', attempt: 'Versucht / angefordert / beobachtet', yes: 'ja', no: 'nein' },
};
export function WindowsServiceActionsPanel({ deviceId, sessionKey, enabled = true, review }: { deviceId: string; sessionKey: string | null; enabled?: boolean; review?: WindowsServiceIncidentReviewContext }) {
 const operator = useOperator(), [locale] = useLocale();
 if (!operator || operator.mode !== 'lan' || !operator.authenticated || operator.loginMode !== 'named' || !operator.actorId || !operator.capabilities?.includes('windows_service_control') || !sessionKey || !enabled || review && (!windowsServiceReviewCurrent(review) || review.sessionKey !== sessionKey || review.view.incident.deviceId !== deviceId || review.view.control.status !== 'matched' || !review.view.control.binding || !review.view.control.bindingDigest)) return <p className="windows-inventory-exclusions">{copy[locale].access}</p>;
 return <Actions key={`${deviceId}:${sessionKey}:${operator.actorId}:${review?.view.control.bindingDigest ?? ''}:${review?.anchor.mono ?? ''}`} deviceId={deviceId} actor={operator.actorId} sessionKey={sessionKey} insecure={operator.insecureTestMode} review={review}/>;
}
function Actions({ deviceId, actor, sessionKey, insecure, review }: { deviceId: string; actor: string; sessionKey: string; insecure: boolean; review?: WindowsServiceIncidentReviewContext }) {
 const [locale] = useLocale(), c = copy[locale], [view,setView] = useState<WindowsActionView | null>(null), [selected,setSelected] = useState(false), [op,setOp] = useState<WindowsServiceOperation | ''>(review ? '' : 'start'), [ack,setAck] = useState(false), [error,setError] = useState<'error'|'uncertain'|null>(null), [busy,setBusy] = useState(false), [,tick] = useState(0);
 const alive=useRef(false), locked=useRef(false), version=useRef(0), pending=useRef<AbortController|null>(null), current=useRef<WindowsActionView|null>(null), allowedPreview=useRef<string|null>(null), anchor=useRef<{server:number;mono:number;wall:number}|null>(null);
 const clearPreview=useCallback(() => { allowedPreview.current=null;setAck(false);setSelected(false);if(review)setOp('');setView(v => v ? {...v,preview:null} : null); },[review]);
 const fresh=useCallback(() => {const a=anchor.current;if(!a)return false;const elapsed=performance.now()-a.mono;return elapsed>=0&&Math.abs(Date.now()-a.wall-elapsed)<2000&&Date.parse(sessionKey)>a.server+elapsed;},[sessionKey]);
 const run=useCallback(async(kind:'read'|'preview'|'approve', operation?: WindowsServiceOperation) => {
  if (!alive.current || locked.current || hasLogoutIntent() || document.visibilityState==='hidden' || !actionID(deviceId,'agent_') || review && !windowsServiceReviewCurrent(review)) return;
  const previous=current.current, p=previous?.preview;
  if(kind!=='read' && (!fresh() || !previous || kind==='preview'&&(!previous.available || !operation) || kind==='approve'&&(!p || allowedPreview.current!==p.id || !anchor.current || Date.parse(p.expiresAt)<=anchor.current.server+performance.now()-anchor.current.mono))) { clearPreview();setError('error');return; }
  locked.current=true;setBusy(true);setError(null);setAck(false);allowedPreview.current=null;const token=++version.current, controller=new AbortController();pending.current=controller;const epoch=getProtectedRequestEpoch();const timeout=window.setTimeout(()=>controller.abort(),10000);
  if(kind==='read'){setView(null);current.current=null;setSelected(false);if(review)setOp('')} else setView(v=>v?{...v,preview:null}:null);
  try {
   const session=await request<unknown>('/auth/session',{signal:controller.signal},16384);
   if(!validOperatorSession(session)||session.mode!=='lan'||!session.authenticated||session.loginMode!=='named'||session.actorId!==actor||!session.capabilities?.includes('windows_service_control')||session.expiresAt!==sessionKey||session.insecureTestMode!==insecure||Date.parse(session.expiresAt)<=Date.parse(session.serverNow))throw new APIError('Session ended',401);
   if(controller.signal.aborted||token!==version.current||epoch!==getProtectedRequestEpoch()||hasLogoutIntent())throw new DOMException('Aborted','AbortError');
   const path=`/devices/${deviceId}/windows-service-actions`, headers: Record<string,string> = review ? { [WINDOWS_SERVICE_REVIEW_HEADER]: review.view.control.bindingDigest! } : {}, body=kind==='preview'?{target:previous!.target,operation}:{previewId:p?.id,previewDigest:p?.digest};
   if(review&&!windowsServiceReviewCurrent(review))throw new Error('Review expired');
   const value=kind==='read'?await request<unknown>(path,{signal:controller.signal,headers},16384):await mutateRaw<unknown>(`${path}/${kind}`,JSON.stringify(body),kind==='preview'?headers:{},controller.signal,16384,()=>!review||windowsServiceReviewCurrent(review));
   if(!alive.current||controller.signal.aborted||token!==version.current||epoch!==getProtectedRequestEpoch()||hasLogoutIntent()||review&&!windowsServiceReviewCurrent(review))return;
   if(!validWindowsActionView(value,deviceId,actor)||review&&(Date.parse(value.serverNow)<Date.parse(review.view.serverNow)||Date.parse(value.serverNow)>=Date.parse(review.view.authorityExpiresAt)||value.target!==review.view.incident.serviceName||value.preview&&!sameWindowsServiceReviewBinding(value.preview.binding,review.view.control.binding!))||anchor.current&&Date.parse(value.serverNow)<anchor.current.server||kind==='preview'&&(!value.preview||value.preview.operation!==operation||value.preview.binding.target!==previous?.target)||kind==='approve'&&value.job?.identity.jobId!==p?.id)throw new Error('Invalid response');
   anchor.current={server:Date.parse(value.serverNow),mono:performance.now(),wall:Date.now()};
   // A status read never revives an old preview or repeats an uncertain approval.
   if(kind!=='preview')value.preview=null;else allowedPreview.current=value.preview!.id;
   current.current=value;setView(value);
  } catch {if(alive.current&&token===version.current){current.current=null;setView(null);setSelected(false);setError(kind==='approve'?'uncertain':'error')}} finally {window.clearTimeout(timeout);if(token===version.current){locked.current=false;pending.current=null;if(alive.current)setBusy(false)}}
 },[actor,clearPreview,deviceId,fresh,insecure,sessionKey,review]);
 useEffect(()=>{alive.current=true;void run('read');const lose=()=>{version.current++;pending.current?.abort();pending.current=null;locked.current=false;current.current=null;anchor.current=null;allowedPreview.current=null;setView(null);setSelected(false);setAck(false);setBusy(false);setError('error')};const timer=window.setInterval(()=>{if(review&&!windowsServiceReviewCurrent(review)||anchor.current&&!fresh()){lose();return}const p=current.current?.preview,a=anchor.current;if(p&&a&&Date.parse(p.expiresAt)<=a.server+performance.now()-a.mono)clearPreview();tick(n=>n+1)},500);window.addEventListener('pagehide',lose);window.addEventListener('popstate',lose);window.addEventListener('hashchange',lose);window.addEventListener(AUTH_REQUIRED_EVENT,lose);window.addEventListener('blur',lose);document.addEventListener('visibilitychange',lose);return()=>{alive.current=false;version.current++;pending.current?.abort();window.clearInterval(timer);window.removeEventListener('pagehide',lose);window.removeEventListener('popstate',lose);window.removeEventListener('hashchange',lose);window.removeEventListener(AUTH_REQUIRED_EVENT,lose);window.removeEventListener('blur',lose);document.removeEventListener('visibilitychange',lose)}},[clearPreview,fresh,run,review]);
 const p=view?.preview,j=view?.job,yes=(b:boolean)=>b?c.yes:c.no;
 return <section className="windows-full-services windows-service-actions">
  <header className="windows-inventory-section-header"><h3>{c.title}</h3><button className="button small" disabled={busy} onClick={()=>void run('read')}>{c.refresh}</button></header>
  {busy&&<p role="status">{c.pending}</p>}{error&&<p role="alert">{c[error]}</p>}
  {view&&!busy&&<>
   {j&&<div role="status" className="windows-service-action-outcome">
    <p><strong>{c[j.result?.outcome??j.state]}</strong></p>
    <p>{c[j.operation]}: {j.target}</p>
    {j.state==='needs_intervention'&&<p>{c.needs_intervention}</p>}
    <p className="windows-inventory-exclusions">{c.reported}</p>
    <details key={j.identity.jobId} className="windows-full-services-details windows-service-action-receipt">
     <summary>{c.receipt}</summary>
     {j.result&&j.state!=='needs_intervention'&&<p>{c[j.state]}</p>}
     <p>{c.deadline}: <time dateTime={j.startDeadline}>{fullDate(j.startDeadline)}</time></p>
     {j.result&&<>
      <p>{c.stop}: {c.attempt} {yes(j.result.stopAttempted)} / {yes(j.result.stopRequested)} / {yes(j.result.stoppedObserved)}</p>
      <p>{c.start}: {c.attempt} {yes(j.result.startAttempted)} / {yes(j.result.startRequested)} / {yes(j.result.runningObserved)}</p>
     </>}
    </details>
   </div>}
   {view.configured&&!review&&<WindowsServiceActionHistory deviceId={deviceId} actor={actor} sessionKey={sessionKey} insecure={insecure} serverNow={view.serverNow} labels={c}/>}
   {!view.configured?<p>{c.empty}</p>:!view.available&&!p&&!j&&<p>{c.disabled}</p>}
   {view.available&&!p&&<>
    <p className="windows-inventory-exclusions">{c.interruption}</p>
    <button className="button small" aria-pressed={selected} onClick={()=>{setSelected(!selected);setAck(false)}}>{c.select}: {view.target}</button>
    {selected&&<><label>{c.preview}<select value={op} onChange={e=>{setOp(e.target.value as WindowsServiceOperation);setAck(false)}}>{review&&<option value="" disabled>{c.chooseOperation}</option>}{(['start','stop','restart'] as const).map(x=><option key={x} value={x}>{c[x]}</option>)}</select></label><button className="button small" disabled={!op} onClick={()=>{if(op)void run('preview',op)}}>{c.preview}</button></>}
   </>}
   {p&&<div role="group" aria-label={c.preview} onKeyDown={event=>{if(event.key==='Escape')clearPreview()}}>
    <p><strong>{c[p.operation]}: {p.binding.target}</strong></p>
    <p className="windows-inventory-exclusions">{c.interruption}</p>
    <p>{c.deadline}: <time dateTime={p.expiresAt}>{fullDate(p.expiresAt)}</time></p>
    <label className="service-action-consent"><input type="checkbox" checked={ack} onChange={e=>setAck(e.target.checked)}/>{c.acknowledge}</label>
    <div className="service-action-buttons"><button className="button small" disabled={!ack} onClick={()=>{if(ack)void run('approve')}}>{c.approve}</button><button className="button small" onClick={clearPreview}>{c.cancel}</button></div>
   </div>}
  </>}
  <details className="windows-full-services-details"><summary>{c.scope}</summary><p className="windows-inventory-exclusions">{c.intro}</p></details>
 </section>;
}
