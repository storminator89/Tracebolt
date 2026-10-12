import { useEffect, useState } from 'react';
import { useLocale } from './i18n';
import { WindowsMutationStatus } from './windows-mutation-status';
import type { UpdateJobView } from './windows-update-jobs-types';

/** Recent signed evidence is never a claim that the service is running now. */
export function WindowsUpdateExecutorStatus({view}:{view:UpdateJobView}) {
 const [locale]=useLocale(),de=locale==='de';
 const [clock,setClock]=useState({elapsed:0,valid:true});
 useEffect(()=>{
  const mono=performance.now(),wall=Date.now();
  const update=()=>{const elapsed=performance.now()-mono;setClock({elapsed,valid:elapsed>=0&&Math.abs(Date.now()-wall-elapsed)<1500})};
  update();const timer=window.setInterval(update,500);return()=>window.clearInterval(timer);
 },[view.serverNow]);
 const now=clock.valid?view.serverNow+clock.elapsed/1000:NaN;
 const recent=view.executorAvailability==='verified_recent'&&typeof view.executorObservedAt==='number'&&now>=view.executorObservedAt&&now-view.executorObservedAt<60;
 return <>
  <p role="status" className="windows-update-executor-status">{view.backgroundScheduling?(de?'Update-Hintergrunddienst · Genehmigte UTC-Zeitfenster':'Background update service · Approved UTC windows'):(de?'Update-Hintergrunddienst · Nur manuelle Freigaben':'Background update service · Manual approvals only')}<br/>{recent?(de?'Zuletzt bestätigt · Verfügbarkeit nicht live geprüft':'Recent confirmation · Availability not checked live'):(de?'Verfügbarkeit unbekannt':'Availability unknown')}</p>
  <WindowsMutationStatus status={view.mutation} capturedAt={view.mutationCapturedAt} serverNow={Number.isFinite(now)?now:Number.MAX_SAFE_INTEGER}/>
 </>;
}
