import { journalAge, journalTime } from './journal-types';
import { actionID, validWindowsActionBinding, validWindowsActionView } from './windows-service-action-types';
import type { WindowsActionBinding, WindowsActionIdentity, WindowsActionJob, WindowsActionResult, WindowsServiceOperation } from './windows-service-action-types';
export interface WindowsActionHistorySummary { identity: WindowsActionIdentity; operation: WindowsServiceOperation; approvedAt: string; state: WindowsActionJob['state']; outcome: WindowsActionResult['outcome'] | null }
export interface WindowsActionHistory { schemaVersion: 'tracebolt.windows-service-action-history.v1'; deviceId: string; serverNow: string; binding: WindowsActionBinding; limit: 64; jobs: WindowsActionHistorySummary[] }
export interface WindowsActionHistoryDetail { schemaVersion: 'tracebolt.windows-service-action-history-detail.v1'; deviceId: string; serverNow: string; binding: WindowsActionBinding; job: WindowsActionJob; claimedAt: string | null }
const exact = (v: unknown, keys: string[]): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v,k));
const same = (a: object,b: object) => Object.keys(a).every(k => a[k as keyof typeof a] === b[k as keyof typeof b]);
export function validWindowsActionHistory(v: unknown,device: string): v is WindowsActionHistory {
 if (!exact(v,['schemaVersion','deviceId','serverNow','binding','limit','jobs']) || v.schemaVersion !== 'tracebolt.windows-service-action-history.v1' || v.deviceId !== device || !actionID(device,'agent_') || !journalTime(v.serverNow) || !validWindowsActionBinding(v.binding,device) || v.limit !== 64 || !Array.isArray(v.jobs) || v.jobs.length > 64) return false;
 const ids=new Set<string>();
 return v.jobs.every((j,index) => {
  if (!exact(j,['identity','operation','approvedAt','state','outcome']) || !exact(j.identity,['jobId','sequence','envelopeDigest']) || !actionID(j.identity.jobId,'action_') || j.identity.sequence !== String((v.jobs as unknown[]).length-index) || typeof j.identity.envelopeDigest !== 'string' || !/^sha256:[a-f0-9]{64}$/.test(j.identity.envelopeDigest) || ids.has(j.identity.jobId) || !['start','stop','restart'].includes(j.operation as string) || !journalTime(j.approvedAt) || journalAge(v.serverNow as string,j.approvedAt)<0 || !['approved','claimed','expired','complete','needs_intervention'].includes(j.state as string)) return false;
  ids.add(j.identity.jobId);
  if (index>0 && journalAge((v.jobs as WindowsActionHistorySummary[])[index-1].approvedAt,j.approvedAt)<0) return false;
  if (j.state==='needs_intervention') return j.outcome==='intervention-required';
  if (j.state==='complete') return j.outcome==='not-requested' || j.outcome==='running-observed' && j.operation!=='stop' || j.outcome==='stopped-observed' && j.operation==='stop';
  return j.outcome===null || j.state==='claimed' && j.outcome==='not-requested';
 });
}
export function validWindowsActionHistoryDetail(v: unknown,history: WindowsActionHistory,selected: WindowsActionHistorySummary,actor: string): v is WindowsActionHistoryDetail {
 if (!exact(v,['schemaVersion','deviceId','serverNow','binding','job','claimedAt']) || v.schemaVersion!=='tracebolt.windows-service-action-history-detail.v1' || v.deviceId!==history.deviceId || !journalTime(v.serverNow) || journalAge(v.serverNow,history.serverNow)<0 || !validWindowsActionBinding(v.binding,history.deviceId) || !same(v.binding,history.binding)) return false;
 const projected={schemaVersion:'tracebolt.windows-service-action-view.v1',deviceId:history.deviceId,serverNow:v.serverNow,configured:true,available:false,reason:'disabled',target:history.binding.target,preview:null,job:v.job};
 if (!validWindowsActionView(projected,history.deviceId,actor) || !projected.job) return false;
 const j=projected.job;
 if (!same(j.identity,selected.identity) || j.operation!==selected.operation || j.approvedAt!==selected.approvedAt || ['complete','needs_intervention'].includes(selected.state) && (j.state!==selected.state || j.result?.outcome!==selected.outcome)) return false;
 if (v.claimedAt===null) return ['approved','expired'].includes(j.state) && j.result===null;
 return journalTime(v.claimedAt) && journalAge(v.claimedAt,j.approvedAt)>=0 && journalAge(j.startDeadline,v.claimedAt)>0 && journalAge(v.serverNow,v.claimedAt)>=0 && ['claimed','complete','needs_intervention'].includes(j.state);
}
