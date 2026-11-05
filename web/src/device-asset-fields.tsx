import { useEffect, useRef, useState } from 'react';
import { APIError, AUTH_REQUIRED_EVENT, getProtectedRequestEpoch, mutateRaw, request } from './api';
import { useLocale } from './i18n';
import { assetBytes, civilDateLabel, validAssetFields, validDeviceAssetFields } from './device-asset-fields-types';
import type { AssetFields, DeviceAssetFieldsView } from './device-asset-fields-types';
import './device-asset-fields.css';
interface Props { deviceId: string; sessionKey: string; identityKey: string; admin: boolean; enabled: boolean }
type Pending = { operationId: string; identityKey: string; validUntil: string };
function validPending(value: unknown, sessionKey: string): value is Pending {
 if(!value||typeof value!=='object'||Array.isArray(value))return false;
 const p=value as Partial<Pending>;
 return Object.keys(p).sort().join()==='identityKey,operationId,validUntil'&&typeof p.operationId==='string'&&/^assetop_[a-f0-9]{32}$/.test(p.operationId)&&typeof p.identityKey==='string'&&/^[a-f0-9]{64}$/.test(p.identityKey)&&typeof p.validUntil==='string'&&/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(p.validUntil)&&Number.isFinite(Date.parse(p.validUntil))&&new Date(Date.parse(p.validUntil)).toISOString().slice(0,19)===p.validUntil.slice(0,19)&&Date.parse(p.validUntil)>0&&Date.parse(p.validUntil)<=Date.parse(sessionKey);
}
const emptyFields = (): AssetFields => ({assetTag:'',location:'',warrantyEnd:''});
const copy = {
 en: { title:'Asset details', intro:'Manually entered manager data. No passwords or secrets.', details:'Storage and limits', boundary:'Visible to readers of this manager. No automatic lookup, device action or AI export.', rule:'Clearing empties the current fields. Previous values remain in retained manager revisions; they are not deleted.', read:'Your access is read-only.', edit:'Edit', clear:'Clear fields', save:'Save', cancel:'Cancel', reload:'Reload asset details', check:'Check saved result', uncertain:'The saved result is uncertain. Changes stay blocked until a check confirms a receipt or no receipt after request expiry. Checking does not send the change again.', unavailable:'Asset details are unavailable. Reload explicitly to read again.', storage:'Safe pending-operation storage is unavailable. Asset details are read-only.', saved:'Saved operation confirmed.', expiredRequest:'No saved operation was found after its request expired. You can make a new change.', rejected:'The change was rejected. Review the fields and reload if needed.', quota:'Retained changes', exhausted:'The retained change limit is reached. Clearing fields does not free space.', limit:'100 changes per device identity. Text must have no surrounding whitespace or control characters.', assetTag:'Asset tag', location:'Location', warrantyEnd:'Warranty end (manual)', dateHelp:'YYYY-MM-DD or empty. This date does not verify warranty coverage.', invalid:'Use at most 80 / 160 UTF-8 bytes, no surrounding whitespace or control characters, and a real YYYY-MM-DD date.', unset:'Not set', loading:'Loading asset details…' },
 de: { title:'Inventardetails', intro:'Manuell eingegebene Manager-Daten. Keine Passwörter oder Geheimnisse.', details:'Speicherung und Grenzen', boundary:'Sichtbar für alle mit Lesezugriff auf diesen Manager. Keine automatische Abfrage, Geräteaktion oder KI-Ausgabe.', rule:'Leeren entfernt die aktuellen Feldwerte. Frühere Werte bleiben in gespeicherten Manager-Revisionen erhalten und werden nicht gelöscht.', read:'Dein Zugriff ist nur lesend.', edit:'Bearbeiten', clear:'Felder leeren', save:'Speichern', cancel:'Abbrechen', reload:'Asset-Daten neu laden', check:'Gespeichertes Ergebnis prüfen', uncertain:'Das gespeicherte Ergebnis ist unklar. Änderungen bleiben gesperrt, bis eine Prüfung einen Beleg oder dessen Fehlen nach Anfrageablauf bestätigt. Die Änderung wird nicht erneut gesendet.', unavailable:'Asset-Daten nicht verfügbar. Zum erneuten Lesen ausdrücklich neu laden.', storage:'Sichere Speicherung ausstehender Vorgänge nicht verfügbar. Asset-Daten sind nur lesend.', saved:'Gespeicherter Vorgang bestätigt.', expiredRequest:'Nach Ablauf der Anfrage wurde kein gespeicherter Vorgang gefunden. Du kannst eine neue Änderung vornehmen.', rejected:'Änderung abgelehnt. Felder prüfen und bei Bedarf neu laden.', quota:'Gespeicherte Änderungen', exhausted:'Die Grenze gespeicherter Änderungen ist erreicht. Felder leeren schafft keinen freien Platz.', limit:'100 Änderungen je Geräteidentität. Kein Leerraum am Textrand und keine Steuerzeichen.', assetTag:'Inventarnummer', location:'Standort', warrantyEnd:'Garantieende (manuell)', dateHelp:'JJJJ-MM-TT oder leer. Das Datum bestätigt keinen Garantieanspruch.', invalid:'Höchstens 80 / 160 UTF-8-Bytes, kein Leerraum am Rand oder Steuerzeichen und ein gültiges Datum JJJJ-MM-TT.', unset:'Nicht gesetzt', loading:'Asset-Daten werden geladen …' },
};
// Only opaque operation metadata is retained. Drafts, field values and API bindings
// never enter browser storage. Storage failure disables writes, rather than losing
// an unresolved operation on navigation or refresh.
export function DeviceAssetFields(props: Props) {
 const {deviceId, sessionKey, identityKey, admin} = props;
 const [locale] = useLocale(), c = copy[locale];
 const scope = JSON.stringify([deviceId,sessionKey,identityKey,admin]);
 return <DeviceAssetFieldsScope key={scope} {...props} copy={c} locale={locale}/>;
}
function DeviceAssetFieldsScope({deviceId,sessionKey,admin,enabled,copy:c,locale}: Props & {copy: typeof copy.en; locale:'en'|'de'}) {
 const key = `tracebolt:device-asset-fields:${JSON.stringify([sessionKey,deviceId])}`;
 const [view,setView] = useState<DeviceAssetFieldsView|null>(null), [draft,setDraft] = useState<AssetFields|null>(null), [busy,setBusy] = useState(false), [pending,setPending] = useState<Pending|null>(null), [storageOK,setStorageOK] = useState(false), [message,setMessage] = useState<keyof typeof copy.en|null>(null);
 const live = useRef(true), generation = useRef(0), locked = useRef(false), pendingRef = useRef<Pending|null>(null), viewRef = useRef<DeviceAssetFieldsView|null>(null), timer = useRef<ReturnType<typeof setTimeout>|undefined>(undefined), deadline = useRef(0), floor = useRef(0), serverFloor = useRef(0), originalIdentity = useRef<string|null>(null), controller = useRef<AbortController|null>(null), authLost = useRef(false);
 const clear = (preserveDraft=false) => { generation.current++; controller.current?.abort(); clearTimeout(timer.current); viewRef.current=null; setView(null); if(!preserveDraft||pendingRef.current||Date.now()>=Date.parse(sessionKey))setDraft(null); setBusy(false); locked.current=false; setMessage('unavailable'); };
 const available = () => live.current && enabled && document.visibilityState!=='hidden' && !authLost.current && Date.parse(sessionKey)>Date.now();
 const storePending = (p: Pending|null) => { try { if(p) sessionStorage.setItem(key,JSON.stringify(p)); else sessionStorage.removeItem(key); pendingRef.current=p;setPending(p);return true; } catch {setStorageOK(false);setMessage('storage');return false;} };
 const read = async (explicitCheck=false) => {
  if (!available() || locked.current) return;
  // A delayed provably-unsent request may have removed its fence after blur or
  // remount. Reconcile that minimal metadata before checking server receipts.
  try {if(pendingRef.current&&!sessionStorage.getItem(key)){pendingRef.current=null;setPending(null);}}catch{setStorageOK(false);}
  clear(true); const g=generation.current, epoch=getProtectedRequestEpoch(), start=performance.now(); locked.current=true;setBusy(true);setMessage(null);controller.current=new AbortController();
  try {
   const value=await request<unknown>(`/devices/${encodeURIComponent(deviceId)}/asset-fields`,{signal:controller.current.signal},32768);
   if (!available() || g!==generation.current || epoch!==getProtectedRequestEpoch()) return;
   if (!validDeviceAssetFields(value,deviceId)) throw Error('invalid');
   const lease=Math.min(Date.parse(value.validUntil)-Date.parse(value.serverNow)-(performance.now()-start),Date.parse(value.validUntil)-Date.now(),Date.parse(sessionKey)-Date.now());
   if(lease<=0) throw Error('expired');
   if(originalIdentity.current!==null&&originalIdentity.current!==value.identityKey){floor.current=0;serverFloor.current=0;setDraft(null);}
   if(value.revision<floor.current||Date.parse(value.serverNow)<serverFloor.current)throw Error('rollback');
   originalIdentity.current=value.identityKey;serverFloor.current=Date.parse(value.serverNow);
   floor.current=value.revision;deadline.current=performance.now()+lease;viewRef.current=value;setView(value);
   const p=pendingRef.current;
   if(p && p.identityKey!==value.identityKey) { storePending(null); }
   else if(p && value.operations.some(o=>o.id===p.operationId)) { setDraft(null);if(storePending(null)) setMessage('saved'); }
   // Backend serializes this read with writes and permanently rejects backward
   // authority-clock movement for this API signing-key lifetime. Only an
   // explicit check can therefore establish absence after the original expiry.
   // Strict > stays conservative when Go nanoseconds are truncated to JS ms.
   else if(p&&explicitCheck&&Date.parse(value.serverNow)>Date.parse(p.validUntil)){setDraft(null);if(storePending(null))setMessage('expiredRequest');}
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
 const write=async()=>{
  const v=viewRef.current;
  if(!available()||locked.current||pendingRef.current||!storageOK||!admin||!v?.canWrite||!draft||!validAssetFields(draft)||performance.now()>=deadline.current||Date.now()>=Date.parse(v.validUntil)||v.revision>=100)return;
  let suffix:string;try{suffix=Array.from(crypto.getRandomValues(new Uint8Array(16)),b=>b.toString(16).padStart(2,'0')).join('');}catch{setMessage('unavailable');return;}
  const p={id:`assetop_${suffix}`};
  if(!storePending({operationId:p.id,identityKey:v.identityKey,validUntil:v.validUntil}))return;
  locked.current=true;setBusy(true);setMessage(null);const g=generation.current,epoch=getProtectedRequestEpoch();controller.current=new AbortController();
  let dispatched=false;
  try{
   await mutateRaw(`/devices/${encodeURIComponent(deviceId)}/asset-fields`,JSON.stringify({binding:v.binding,validUntil:v.validUntil,expectedRevision:v.revision,operationId:p.id,fields:draft}),{},controller.current.signal,32768,()=>{if(!available()||generation.current!==g||performance.now()>=deadline.current||Date.now()>=Date.parse(v.validUntil))return false;dispatched=true;return true;});
   if(!available()||generation.current!==g||epoch!==getProtectedRequestEpoch())return;
   setDraft(null);locked.current=false;setBusy(false);await read();
  }catch(error){
   if(!dispatched){
    // CSRF/pre-send failure proves the asset-fields POST was never entered. Remove only
    // this operation, never a newer operation from a remounted scope.
    try {if(JSON.parse(sessionStorage.getItem(key)??'null')?.operationId===p.id)sessionStorage.removeItem(key);}catch { /* Keep the durable fence if storage fails. */ }
    if(live.current&&generation.current===g){storePending(null);setMessage('rejected');}
    return;
   }
   if(!live.current||generation.current!==g||epoch!==getProtectedRequestEpoch())return;
   if(error instanceof APIError&&(error.status===400||error.code==='device_asset_fields_rejected')){storePending(null);setMessage('rejected'); if(error.status!==400&&error.status!==413&&error.status!==422){viewRef.current=null;setView(null);}}
   else {setDraft(null);setMessage('uncertain');}
  }finally{if(live.current&&generation.current===g){locked.current=false;setBusy(false);}}
 };
 const writable=enabled&&admin&&storageOK&&view?.canWrite&&!busy&&!pending&&view.revision<100;
 const labels: (keyof AssetFields)[]=['assetTag','location','warrantyEnd'];
 return <section className="detail-section device-asset-fields" aria-label={c.title}><h2>{c.title}</h2><p>{c.intro}</p>
 {(!admin||view?.canWrite===false)&&<p>{c.read}</p>}{!storageOK&&<p role="status">{c.storage}</p>}{pending&&<p role="status">{c.uncertain}</p>}{message&&message!=='storage'&&message!=='uncertain'&&<p role="status">{c[message]}</p>}
 <button className="button small" disabled={busy||!enabled||authLost.current} onClick={()=>void read(true)}>{pending?c.check:c.reload}</button>{busy&&<p role="status">{c.loading}</p>}
 {view&&<><dl className="metadata-grid">{labels.map(field=><div key={field}><dt>{c[field]}</dt><dd>{view.fields[field] ? field==='warrantyEnd'?<time dateTime={view.fields[field]}>{civilDateLabel(view.fields[field],locale)}</time>:view.fields[field] : c.unset}</dd></div>)}</dl><p>{c.dateHelp}</p><details><summary>{c.details}</summary><p>{c.boundary}</p><p>{c.limit}</p><p>{c.rule}</p><p>{c.quota}: {view.revision} / 100</p></details>{view.revision>=100&&<p role="status">{c.exhausted}</p>}{admin&&!draft&&<button className="button" disabled={!writable} onClick={()=>setDraft({...view.fields})}>{c.edit}</button>}</>}
 {admin&&draft&&<form onSubmit={e=>{e.preventDefault();void write();}}>{labels.map(field=><label key={field} htmlFor={`asset-${field}`}>{c[field]}<input id={`asset-${field}`} type="text" value={draft[field]} disabled={!writable} onChange={e=>setDraft({...draft,[field]:e.target.value})} aria-describedby="asset-field-help"/>{field!=='warrantyEnd'&&<span>{assetBytes(draft[field])} / {field==='assetTag'?80:160} UTF-8 bytes</span>}</label>)}<p id="asset-field-help">{c.limit} {c.dateHelp}</p>{!validAssetFields(draft)&&<p role="alert">{c.invalid}</p>}<p>{c.rule}</p><div className="asset-field-actions"><button className="button" type="submit" disabled={!writable||!validAssetFields(draft)||JSON.stringify(draft)===JSON.stringify(view?.fields)}>{c.save}</button><button className="button" type="button" disabled={!writable} onClick={()=>setDraft(emptyFields())}>{c.clear}</button><button className="button" type="button" disabled={busy} onClick={()=>setDraft(null)}>{c.cancel}</button></div></form>}
 </section>;
}
