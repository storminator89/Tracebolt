import { useLocale } from './i18n';

import type { MutationStatus } from './windows-mutation-status-types';

export function WindowsMutationStatus({status,capturedAt,serverNow}:{status?:MutationStatus;capturedAt?:number;serverNow:number}) {
 const [locale]=useLocale(),de=locale==='de';
 if(!status||!capturedAt)return <p className="windows-inventory-exclusions">{de?'Gemeinsamer Status wartet auf den Executor.':'Shared status awaits the executor.'}</p>;
 const stale=serverNow-capturedAt>=60,domain=status.domain==='managed_msi'?'MSI':de?'Windows-Update':'Windows Update';
 return <div className="windows-mutation-status"><p role="status">{stale?(de?'Gespeicherter gemeinsamer Status':'Saved shared status'):de?'Gemeinsamer Status':'Shared status'}: {status.blocked?(status.domain?<>{de?'Blockiert durch':'Blocked by'} {domain} · {status.jobId?.slice(-8)}</>:de?'Unbekannt, gesperrt':'Unknown, blocked'):de?'Kein Besitzer gespeichert':'No owner saved'}</p>{stale&&<p>{de?'Vor Freigabe Status aktualisieren.':'Refresh status before approval.'}</p>}{status.blocked&&<details><summary>{de?'Wiederherstellung prüfen':'Review recovery'}</summary><p className="windows-mutation-owner">{status.jobId}</p><p>{status.recovery==='exact_terminal_receipt'?(de?'Der exakte gespeicherte Abschlussnachweis kann die Freigabe abschließen.':'The exact saved completion receipt can finish release.'):(de?'Ursprüngliches Ergebnis bleibt erhalten. Bei ungewissem Abschluss ist eine lokale Prüfung erforderlich. Nicht wiederholen oder zurücksetzen.':'The original result is retained. Uncertain completion requires local review. Do not retry or reset.')}</p></details>}</div>;
}
