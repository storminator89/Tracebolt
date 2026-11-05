import { useEffect, useRef, useState } from 'react';
import { APIError, AUTH_REQUIRED_EVENT, getProtectedRequestEpoch, mutateRaw, request } from './api';
import { useLocale } from './i18n';
import { fullDate } from './utils';
import { noteBytes, validDeviceNotes } from './device-notes-types';
import type { DeviceNotesView, NoteOperation } from './device-notes-types';
import './device-notes.css';
interface Props { deviceId: string; sessionKey: string; identityKey: string; admin: boolean; enabled: boolean }
type Pending = { operationId: string; identityKey: string; validUntil: string };
function validPending(value: unknown, sessionKey: string): value is Pending {
 if(!value||typeof value!=='object'||Array.isArray(value))return false;
 const p=value as Partial<Pending>;
 return Object.keys(p).sort().join()==='identityKey,operationId,validUntil'&&typeof p.operationId==='string'&&/^noteop_[a-f0-9]{32}$/.test(p.operationId)&&typeof p.identityKey==='string'&&/^[a-f0-9]{64}$/.test(p.identityKey)&&typeof p.validUntil==='string'&&/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(p.validUntil)&&Number.isFinite(Date.parse(p.validUntil))&&new Date(Date.parse(p.validUntil)).toISOString().slice(0,19)===p.validUntil.slice(0,19)&&Date.parse(p.validUntil)>0&&Date.parse(p.validUntil)<=Date.parse(sessionKey);
}
const copy = {
 en: { archivedBadge:'Archived', allArchived:'All notes are archived.', title:'Notes', intro:'Manager-only handover notes, visible to readers of this manager. No passwords or secrets. No endpoint action or AI export.', rule:'Notes cannot be edited or deleted. Add a correction as a new note, then archive the old one.', author:'Shared administrator', read:'Your access is read-only.', add:'New note', save:'Save note', cancel:'Cancel', archive:'Archive', restore:'Restore', archived:'Show archived', activeCount:'active', archivedCount:'archived', reload:'Reload notes', check:'Check saved result', uncertain:'The saved result is uncertain. Writes stay blocked until a check confirms the saved result or confirms no receipt after request expiry. Checking does not send it again.', unavailable:'Notes are unavailable. Reload explicitly to read again.', storage:'Safe pending-operation storage is unavailable. Notes are read-only.', saved:'Saved operation confirmed.', expiredRequest:'No saved operation was found after its request expired. You can make a new change.', rejected:'The change was rejected. Review the note and reload if needed.', quota:'Notes / changes used', exhausted:'The retained note or change limit is reached. Archiving does not free note space.', limit:'25 notes including archived; 250 changes total. Archiving does not free space.', empty:'No notes yet.', created:'Created', changed:'Changed', loading:'Loading notes…' },
 de: { archivedBadge:'Archiviert', allArchived:'Alle Notizen sind archiviert.', title:'Notizen', intro:'Übergabenotizen nur im Manager, sichtbar für alle mit Lesezugriff auf diesen Manager. Keine Passwörter oder Geheimnisse. Keine Geräteaktion oder KI-Ausgabe.', rule:'Notizen können nicht bearbeitet oder gelöscht werden. Korrektur als neue Notiz hinzufügen, dann die alte archivieren.', author:'Gemeinsamer Administrator', read:'Dein Zugriff ist nur lesend.', add:'Neue Notiz', save:'Notiz speichern', cancel:'Abbrechen', archive:'Archivieren', restore:'Wiederherstellen', archived:'Archivierte anzeigen', activeCount:'aktiv', archivedCount:'archiviert', reload:'Notizen neu laden', check:'Gespeichertes Ergebnis prüfen', uncertain:'Das gespeicherte Ergebnis ist unklar. Änderungen bleiben gesperrt, bis eine Prüfung das gespeicherte Ergebnis oder das Fehlen eines Belegs nach Anfrageablauf bestätigt. Die Prüfung sendet ihn nicht erneut.', unavailable:'Notizen nicht verfügbar. Zum erneuten Lesen ausdrücklich neu laden.', storage:'Sichere Speicherung ausstehender Vorgänge nicht verfügbar. Notizen sind nur lesend.', saved:'Gespeicherter Vorgang bestätigt.', expiredRequest:'Nach Ablauf der Anfrage wurde kein gespeicherter Vorgang gefunden. Du kannst eine neue Änderung vornehmen.', rejected:'Änderung abgelehnt. Notiz prüfen und bei Bedarf neu laden.', quota:'Verwendete Notizen / Änderungen', exhausted:'Die Grenze für gespeicherte Notizen oder Änderungen ist erreicht. Archivieren schafft keinen freien Notizplatz.', limit:'25 Notizen einschließlich archivierter; insgesamt 250 Änderungen. Archivieren schafft keinen freien Platz.', empty:'Noch keine Notizen.', created:'Erstellt', changed:'Geändert', loading:'Notizen werden geladen …' },
};
// Only opaque operation metadata is retained. Drafts, note content and API bindings
// never enter browser storage. Storage failure disables writes, rather than losing
// an unresolved operation on navigation or refresh.
export function DeviceNotes(props: Props) {
 const {deviceId, sessionKey, identityKey, admin} = props;
 const [locale] = useLocale(), c = copy[locale];
 const scope = JSON.stringify([deviceId,sessionKey,identityKey,admin]);
 return <DeviceNotesScope key={scope} {...props} copy={c}/>;
}
function DeviceNotesScope({deviceId,sessionKey,admin,enabled,copy:c}: Props & {copy: typeof copy.en}) {
 const archiveToggle = useRef<HTMLInputElement>(null);
 const key = `tracebolt:device-notes:${JSON.stringify([sessionKey,deviceId])}`;
 const [view,setView] = useState<DeviceNotesView|null>(null), [draft,setDraft] = useState(''), [archived,setArchived] = useState(false), [busy,setBusy] = useState(false), [pending,setPending] = useState<Pending|null>(null), [storageOK,setStorageOK] = useState(false), [message,setMessage] = useState<keyof typeof copy.en|null>(null);
 const live = useRef(true), generation = useRef(0), locked = useRef(false), pendingRef = useRef<Pending|null>(null), viewRef = useRef<DeviceNotesView|null>(null), timer = useRef<ReturnType<typeof setTimeout>|undefined>(undefined), deadline = useRef(0), floor = useRef(0), serverFloor = useRef(0), originalIdentity = useRef<string|null>(null), controller = useRef<AbortController|null>(null), authLost = useRef(false);
 const clear = (preserveDraft=false) => { generation.current++; controller.current?.abort(); clearTimeout(timer.current); viewRef.current=null; setView(null); if(!preserveDraft||pendingRef.current||Date.now()>=Date.parse(sessionKey))setDraft(''); setBusy(false); locked.current=false; setMessage('unavailable'); };
 const available = () => live.current && enabled && document.visibilityState!=='hidden' && !authLost.current && Date.parse(sessionKey)>Date.now();
 const storePending = (p: Pending|null) => { try { if(p) sessionStorage.setItem(key,JSON.stringify(p)); else sessionStorage.removeItem(key); pendingRef.current=p;setPending(p);return true; } catch {setStorageOK(false);setMessage('storage');return false;} };
 const read = async (explicitCheck=false) => {
  if (!available() || locked.current) return;
  // A delayed provably-unsent request may have removed its fence after blur or
  // remount. Reconcile that minimal metadata before checking server receipts.
  try {if(pendingRef.current&&!sessionStorage.getItem(key)){pendingRef.current=null;setPending(null);}}catch{setStorageOK(false);}
  clear(true); const g=generation.current, epoch=getProtectedRequestEpoch(), start=performance.now(); locked.current=true;setBusy(true);setMessage(null);controller.current=new AbortController();
  try {
   const value=await request<unknown>(`/devices/${encodeURIComponent(deviceId)}/handover-notes`,{signal:controller.current.signal},512*1024);
   if (!available() || g!==generation.current || epoch!==getProtectedRequestEpoch()) return;
   if (!validDeviceNotes(value,deviceId)) throw Error('invalid');
   const lease=Math.min(Date.parse(value.validUntil)-Date.parse(value.serverNow)-(performance.now()-start),Date.parse(value.validUntil)-Date.now(),Date.parse(sessionKey)-Date.now());
   if(lease<=0) throw Error('expired');
   if(originalIdentity.current!==null&&originalIdentity.current!==value.identityKey){floor.current=0;serverFloor.current=0;setDraft('');}
   if(value.revision<floor.current||Date.parse(value.serverNow)<serverFloor.current)throw Error('rollback');
   originalIdentity.current=value.identityKey;serverFloor.current=Date.parse(value.serverNow);
   floor.current=value.revision;deadline.current=performance.now()+lease;viewRef.current=value;setView(value);
   const p=pendingRef.current;
   if(p && p.identityKey!==value.identityKey) { storePending(null); }
   else if(p && value.operations.some(o=>o.id===p.operationId)) { setDraft('');if(storePending(null)) setMessage('saved'); }
   // Backend serializes this read with writes and permanently rejects backward
   // authority-clock movement for this API signing-key lifetime. Only an
   // explicit check can therefore establish absence after the original expiry.
   // Strict > stays conservative when Go nanoseconds are truncated to JS ms.
   else if(p&&explicitCheck&&Date.parse(value.serverNow)>Date.parse(p.validUntil)){setDraft('');if(storePending(null))setMessage('expiredRequest');}
   timer.current=setTimeout(()=>clear(true),lease);
  } catch {if(live.current&&g===generation.current) setMessage('unavailable');}
  finally {if(live.current&&g===generation.current){locked.current=false;setBusy(false);}}
 };
 useEffect(()=>{
  live.current=true;
  try { const raw=sessionStorage.getItem(key); if(raw){const p=JSON.parse(raw);if(!validPending(p,sessionKey)) throw Error();pendingRef.current=p;setPending(p);} sessionStorage.setItem(`${key}:probe`,'1');sessionStorage.removeItem(`${key}:probe`);setStorageOK(true); } catch {setStorageOK(false);setMessage('storage');}
  if(enabled) void read();
  const revoke=()=>{authLost.current=true;clear();};const sessionTimer=setTimeout(revoke,Math.max(0,Date.parse(sessionKey)-Date.now()));const blur=()=>clear(); const hide=()=>{if(document.visibilityState==='hidden')clear();};
  window.addEventListener(AUTH_REQUIRED_EVENT,revoke);window.addEventListener('blur',blur);window.addEventListener('hashchange',blur);window.addEventListener('pagehide',blur);document.addEventListener('visibilitychange',hide);
  return ()=>{clearTimeout(sessionTimer);live.current=false;generation.current++;controller.current?.abort();clearTimeout(timer.current);window.removeEventListener(AUTH_REQUIRED_EVENT,revoke);window.removeEventListener('blur',blur);window.removeEventListener('hashchange',blur);window.removeEventListener('pagehide',blur);document.removeEventListener('visibilitychange',hide);};
 // A new scope remounts this component. Enable changes revoke existing content.
 // eslint-disable-next-line react-hooks/exhaustive-deps
 },[]);
 useEffect(()=>{if(!enabled)clear();},[enabled]);
 const write=async(action: NoteOperation['action'],noteId?:string)=>{
  const v=viewRef.current,text=action==='add'?draft.trim():'';
  if(!available()||locked.current||pendingRef.current||!storageOK||!admin||!v?.canWrite||performance.now()>=deadline.current||Date.now()>=Date.parse(v.validUntil)||v.revision>=250||action==='add'&&(!text||noteBytes(text)>2000||v.notes.length>=25))return;
  let suffix:string;try{suffix=Array.from(crypto.getRandomValues(new Uint8Array(16)),b=>b.toString(16).padStart(2,'0')).join('');}catch{setMessage('unavailable');return;}
  const p:NoteOperation={id:`noteop_${suffix}`,noteId:noteId??`note_${suffix}`,action,revision:v.revision+1};
  if(!storePending({operationId:p.id,identityKey:v.identityKey,validUntil:v.validUntil}))return;
  locked.current=true;setBusy(true);setMessage(null);const g=generation.current,epoch=getProtectedRequestEpoch();controller.current=new AbortController();
  let dispatched=false;
  try{
   await mutateRaw(`/devices/${encodeURIComponent(deviceId)}/handover-notes`,JSON.stringify({binding:v.binding,validUntil:v.validUntil,expectedRevision:v.revision,operationId:p.id,action,noteId:p.noteId,text}),{},controller.current.signal,512*1024,()=>{if(!available()||generation.current!==g||performance.now()>=deadline.current)return false;dispatched=true;return true;});
   if(!available()||generation.current!==g||epoch!==getProtectedRequestEpoch())return;
   setDraft('');locked.current=false;setBusy(false);await read();
  }catch(error){
   if(!dispatched){
    // CSRF/pre-send failure proves the note POST was never entered. Remove only
    // this operation, never a newer operation from a remounted scope.
    try {if(JSON.parse(sessionStorage.getItem(key)??'null')?.operationId===p.id)sessionStorage.removeItem(key);}catch { /* Keep the durable fence if storage fails. */ }
    if(live.current&&generation.current===g){storePending(null);setMessage('rejected');}
    return;
   }
   if(!live.current||generation.current!==g||epoch!==getProtectedRequestEpoch())return;
   if(error instanceof APIError&&(error.status===400||error.code==='device_notes_rejected')){storePending(null);setMessage('rejected'); if(error.status!==400&&error.status!==413&&error.status!==422){viewRef.current=null;setView(null);}}
   else {setDraft('');setMessage('uncertain');}
  }finally{if(live.current&&generation.current===g){locked.current=false;setBusy(false);}}
 };
 const writable=enabled&&admin&&storageOK&&view?.canWrite&&!busy&&!pending&&view.revision<250;
 return <section className="detail-section device-notes" aria-label={c.title}><h2>{c.title}</h2><p>{c.intro}</p><p>{c.rule}</p><p className="device-notes-limit">{c.limit}</p>
 {(!admin||view?.canWrite===false)&&<p>{c.read}</p>}{!storageOK&&<p role="status">{c.storage}</p>}{pending&&<p role="status">{c.uncertain}</p>}{message&&message!=='storage'&&message!=='uncertain'&&<p role="status">{c[message]}</p>}
 <button className="button small" disabled={busy||!enabled||authLost.current} onClick={()=>void read(true)}>{pending?c.check:c.reload}</button>{busy&&<p role="status">{c.loading}</p>}
 {!view&&admin&&draft&&<div><label htmlFor="device-pending-draft">{c.add}</label><textarea id="device-pending-draft" value={draft} disabled readOnly/><button type="button" className="button" onClick={()=>setDraft('')}>{c.cancel}</button></div>}{view&&<><p>{c.quota}: {view.notes.length} / 25 · {view.revision} / 250</p>{(view.notes.length>=25||view.revision>=250)&&<p role="status">{c.exhausted}</p>}<p>{view.notes.filter(n=>!n.archived).length} {c.activeCount} · {view.notes.filter(n=>n.archived).length} {c.archivedCount}</p><label><input ref={archiveToggle} type="checkbox" checked={archived} onChange={e=>setArchived(e.target.checked)}/>{c.archived}</label><ul className="device-notes-list">{[...view.notes].sort((a,b)=>Date.parse(b.createdAt)-Date.parse(a.createdAt)||(view.operations.find(o=>o.action==='add'&&o.noteId===b.id)?.revision??0)-(view.operations.find(o=>o.action==='add'&&o.noteId===a.id)?.revision??0)).filter(n=>archived||!n.archived).map(n=><li key={n.id}>{n.archived&&<span className="device-note-archived">{c.archivedBadge}</span>}<p className="device-note-text">{n.text}</p><p>{c.author} · {c.created}: <time dateTime={n.createdAt}>{fullDate(n.createdAt)}</time> · {c.changed}: <time dateTime={n.changedAt}>{fullDate(n.changedAt)}</time></p>{admin&&<button className="button small" disabled={!writable} onClick={()=>void write(n.archived?'restore':'archive',n.id)}>{n.archived?c.restore:c.archive}</button>}</li>)}</ul>{!view.notes.length&&<p>{c.empty}</p>}{!archived&&view.notes.length>0&&view.notes.every(n=>n.archived)&&<div className="device-notes-empty"><p>{c.allArchived}</p><button className="button small" type="button" onClick={e=>{const v=viewRef.current;if(!available()||!v||performance.now()>=deadline.current||Date.now()>=Date.parse(v.validUntil))return;setArchived(true);if(document.activeElement===e.currentTarget)archiveToggle.current?.focus({preventScroll:true});}}>{c.archived}</button></div>}{admin&&<form onSubmit={e=>{e.preventDefault();void write('add');}}><label htmlFor="device-new-note">{c.add}</label><textarea id="device-new-note" maxLength={2000} value={draft} disabled={!writable||view.notes.length>=25} onChange={e=>setDraft(e.target.value)} aria-describedby="device-note-bytes"/><p id="device-note-bytes">{noteBytes(draft.trim())} / 2000 UTF-8 bytes</p><button className="button" type="submit" disabled={!writable||!draft.trim()||noteBytes(draft.trim())>2000||view.notes.length>=25}>{c.save}</button><button className="button" type="button" disabled={busy||!draft} onClick={()=>setDraft('')}>{c.cancel}</button></form>}</>}
 </section>;
}
