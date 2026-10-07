import { useEffect, useId, useRef, useState } from 'react';
import { ChevronDown, ChevronLeft, ChevronRight, RefreshCw, Search } from 'lucide-react';
import { Dialog } from './components';
import { useLocale } from './i18n';
import { JournalServicePicker } from './journal-service-picker';
import { journalBrowsingAllowed, journalServiceLabel } from './journal-sources';
import { validJournalQuery, validJournalSourceSearch, validJournalUnit, JOURNAL_WARNING } from './journal-types';
import type { JournalQuery } from './journal-types';
import type { JournalResource } from './journal-resource';

const copy = {
 en: {title:'Logs',choose:'Choose a service',all:'All retained',dates:'Date range',from:'From (UTC)',to:'To (UTC)',search:'Search retained messages',apply:'Search logs',severity:'Severity through',refresh:'Refresh status',older:'Older logs',continue:'Continue searching older logs',previous:'Previous',next:'Next',waiting:'Choose a service to read its available retained logs.',loading:'Reading the selected service…',blocked:'Retained browsing is unavailable until the endpoint reports its enabled local browsing grant. Refresh after it reports again.',paused:'Reading is paused. Refresh status to recheck access.',failure:'The read could not be confirmed. Refresh status before issuing a new query.',expired:'This page is expired or no longer available. Start a new query to read the source again.',empty:'No matching messages in this source page. Older entries may still contain matches.',exhausted:'No more currently accessible entries in this service and date range.',incomplete:'This source page is incomplete. The journal may have changed or hit a source limit.',lost:'The continuation entry is no longer retained. Start a new query; removed entries cannot be recovered.',sourcePage:'matches in this source page',limits:'Each source page scans up to 4,096 entries / 8 MiB in 4 seconds and retains up to 500 messages / 512 KiB. Continue for older entries. Source pages are read at least 2 seconds apart and expire after 15 minutes; previous pages are replaced.',privacy:'The installation grant covers local journal browsing. External AI export requires separate approval.',retention:'Only currently retained, accessible journal entries can be read. Rotation, vacuuming, access limits or clock changes can leave gaps; this is not an archive.',pending:'Waiting for the endpoint to read this page…',cancel:'Cancel / discard',invalid:'Use one exact service, valid past UTC dates and at most 200 UTF-8 bytes of literal search.',details:'Scope and limits',shown:'Showing',newQuery:'Read newest logs',unit:'Exact service unit',denied:'The endpoint denied this read under its current local grant.',helper:'The local journal helper is unavailable. No source content was read.',lostResult:'The one-time read result is no longer available. Cancel this request before starting a new query.'},
 de: {title:'Logs',choose:'Dienst auswählen',all:'Alle aufbewahrten Logs',dates:'Zeitraum',from:'Von (UTC)',to:'Bis (UTC)',search:'Aufbewahrte Nachrichten durchsuchen',apply:'Logs durchsuchen',severity:'Schweregrade bis',refresh:'Status aktualisieren',older:'Ältere Logs',continue:'Ältere Logs weiter durchsuchen',previous:'Zurück',next:'Weiter',waiting:'Dienst auswählen, um seine verfügbaren aufbewahrten Logs zu lesen.',loading:'Logs des ausgewählten Diensts werden gelesen…',blocked:'Die Suche ist erst verfügbar, wenn der Endpunkt seine aktive lokale Journal-Freigabe meldet. Nach der Meldung den Status aktualisieren.',paused:'Lesen pausiert. Zum erneuten Prüfen Status aktualisieren.',failure:'Das Lesen konnte nicht bestätigt werden. Vor einer neuen Anfrage Status aktualisieren.',expired:'Diese Seite ist abgelaufen oder nicht mehr verfügbar. Eine neue Suche liest die Quelle erneut.',empty:'Keine passenden Nachrichten auf dieser Quellseite. Ältere Einträge können weitere Treffer enthalten.',exhausted:'Keine weiteren aktuell zugänglichen Einträge für diesen Dienst und Zeitraum.',incomplete:'Diese Quellseite ist unvollständig. Das Journal hat sich möglicherweise geändert oder eine Quellgrenze erreicht.',lost:'Der Fortsetzungseintrag ist nicht mehr aufbewahrt. Neue Suche starten; entfernte Einträge lassen sich nicht wiederherstellen.',sourcePage:'Treffer auf dieser Quellseite',limits:'Pro Quellseite werden bis zu 4.096 Einträge / 8 MiB in 4 Sekunden geprüft und bis zu 500 Nachrichten / 512 KiB behalten. Für ältere Einträge weiterblättern. Quellseiten werden mit mindestens 2 Sekunden Abstand gelesen, laufen nach 15 Minuten ab und ersetzen vorherige Seiten.',privacy:'Die Installationsfreigabe umfasst lokales Journal-Lesen. Externe KI-Übertragung braucht eine eigene Freigabe.',retention:'Nur aktuell aufbewahrte und zugängliche Einträge sind lesbar. Rotation, Bereinigung, Zugriffsgrenzen oder Zeitänderungen können Lücken hinterlassen; dies ist kein Archiv.',pending:'Der Endpunkt muss diese Seite noch lesen…',cancel:'Abbrechen / verwerfen',invalid:'Einen exakten Dienst, gültige vergangene UTC-Zeiten und höchstens 200 UTF-8-Bytes für die wörtliche Suche verwenden.',details:'Freigabe und Grenzen',shown:'Anzeige',newQuery:'Neueste Logs lesen',unit:'Exakte Service-Unit',denied:'Der Endpunkt hat diesen Lesezugriff unter seiner aktuellen lokalen Freigabe abgelehnt.',helper:'Der lokale Journal-Helper ist nicht verfügbar. Es wurde kein Quellinhalt gelesen.',lostResult:'Das Ergebnis der einmaligen Anfrage ist nicht mehr verfügbar. Anfrage abbrechen, bevor eine neue Suche gestartet wird.'},
};
const inputTime=(s:string)=>s.slice(0,19);
const queryTime=(s:string)=>s.replace(/(\.\d{6})\d+Z$/,'$1Z');
const utc=(s:string)=>/^\d{4}-\d\d-\d\dT\d\d:\d\d(?::\d\d)?$/.test(s)?`${s.length===16?s+':00':s}Z`:'';

export function JournalBrowseContent({resource:r,sessionKey=null,initialUnit=''}:{resource:JournalResource;insecureTestMode:boolean;sessionKey?:string|null;initialUnit?:string}){
 const [locale]=useLocale(),c=copy[locale],id=useId();
 const [unit,setUnit]=useState(validJournalUnit(initialUnit)?initialUnit:''),[picker,setPicker]=useState(false),[all,setAll]=useState(true),[from,setFrom]=useState(''),[to,setTo]=useState(''),[search,setSearch]=useState(''),[priority,setPriority]=useState(7),[preparing,setPreparing]=useState(false),[cooling,setCooling]=useState(false);
 const initialAttempt=useRef(false),attempt=useRef(0),alive=useRef(true),timer=useRef<ReturnType<typeof setTimeout>|null>(null),trigger=useRef<HTMLButtonElement>(null);
 const view=r.view,page=r.page,request=view?.request,active=!!request&&['pending','claimed'].includes(request.state);
 const localProblem=view&&['denied','disabled','helper_unavailable','result_lost'].includes(view.localStatus)?view.localStatus:null;
 const ready=journalBrowsingAllowed(view,unit),held=r.busy||r.paused||r.uncertain||active||preparing||cooling||r.failure==='session';
 useEffect(()=>{alive.current=true;return()=>{alive.current=false;attempt.current++;if(timer.current)clearTimeout(timer.current)}},[]);
 useEffect(()=>{attempt.current++;setPreparing(false);setPicker(false)},[r.reset]);
 useEffect(()=>{if(view&&!to){setTo(inputTime(view.serverNow));setFrom(inputTime(new Date(Date.parse(view.serverNow)-86400000).toISOString()))}},[view,to]);
 const send=async(q:JournalQuery)=>{if(!alive.current)return;setCooling(true);if(timer.current)clearTimeout(timer.current);timer.current=setTimeout(()=>{if(alive.current)setCooling(false)},2000);await r.create(q,false,false)};
 const start=async(selected=unit)=>{
  if(held||!journalBrowsingAllowed(view,selected)||!validJournalSourceSearch(search))return;
  const token=++attempt.current;setPreparing(true);
  try{const now=await r.refreshWindow();if(!alive.current||token!==attempt.current||!now)return;
   const q:JournalQuery={unit:selected,start:all?'1970-01-01T00:00:00Z':utc(from),end:all?queryTime(now):utc(to),maxPriority:priority,browseMode:'retained-v1',...(search?{search}:{})};
   if(validJournalQuery(q,now))await send(q);
  }finally{if(alive.current&&token===attempt.current)setPreparing(false)}
 };
 // Only the explicit service navigation that mounted this panel initiates a
 // read. Focus, status refresh, cursor loss and reconnect never replay it.
 useEffect(()=>{if(initialAttempt.current||!validJournalUnit(initialUnit)||!view||r.busy)return;initialAttempt.current=true;const prior=view.request;if(prior?.description.query.unit===initialUnit&&(['pending','claimed'].includes(prior.state)||prior.state==='accepted'&&view.contentStatus==='available'))return;if(!held&&journalBrowsingAllowed(view,initialUnit))void start(initialUnit)},[view,r.busy,initialUnit]);
 const choose=(name:string)=>{setPicker(false);trigger.current?.focus();if(!validJournalUnit(name))return;setUnit(name);void start(name)};
 const q:JournalQuery={unit,start:all?'1970-01-01T00:00:00Z':utc(from),end:all?queryTime(view?.serverNow??''):utc(to),maxPriority:priority,browseMode:'retained-v1',...(search?{search}:{})};
 const valid=!!view&&validJournalQuery(q,view.serverNow);
 const older=()=>{if(!held&&page?.nextCursor&&request&&ready)void send({...request.description.query,cursor:page.nextCursor})};
 return <section className="journal-panel detail-section" aria-labelledby={id} aria-busy={r.busy||preparing}>
  <header className="journal-heading"><h2 id={id}>{c.title}</h2><button className="button small" disabled={r.busy||preparing||r.failure==='session'} onClick={r.refresh}><RefreshCw size={14}/>{c.refresh}</button></header>
  {r.failure&&<p role="alert" className="journal-warning">{c.failure}</p>}
  {r.paused&&<p role="status">{c.paused}</p>}
  {view&&unit&&!ready&&<p role="status" className="journal-warning">{c.blocked}</p>}
  <form className="journal-capture journal-retained" onSubmit={e=>{e.preventDefault();void start()}}>
   <fieldset disabled={!view||held}>
    <div className="journal-query-bar"><div className="journal-source-control"><button ref={trigger} type="button" className="journal-service-trigger" aria-haspopup="dialog" aria-expanded={picker} onClick={()=>setPicker(true)}><span><strong>{unit||c.choose}</strong><span className="journal-service-label">{journalServiceLabel(unit,locale)}</span></span><ChevronDown size={16}/></button></div>
    <label className="journal-browse-search">{c.search}<input value={search} onChange={e=>setSearch(e.target.value)} maxLength={200} autoComplete="off" spellCheck={false}/></label>
    <button className="button primary" disabled={!ready||!valid}><Search size={15}/>{c.apply}</button></div>
    <div className="journal-filters"><label><input type="checkbox" checked={all} onChange={e=>setAll(e.target.checked)}/>{c.all}</label>{!all&&<><label>{c.from}<input type="datetime-local" step="1" value={from} onChange={e=>setFrom(e.target.value)}/></label><label>{c.to}<input type="datetime-local" step="1" value={to} onChange={e=>setTo(e.target.value)}/></label></>}<label>{c.severity}<select value={priority} onChange={e=>setPriority(Number(e.target.value))}>{['0 Emergency','1 Alert','2 Critical','3 Error','4 Warning','5 Notice','6 Info','7 Debug'].map((n,i)=><option key={i} value={i}>{n}</option>)}</select></label></div>
    <details><summary>{c.unit}</summary><input aria-label={c.unit} value={unit} onChange={e=>setUnit(e.target.value)} maxLength={255} autoComplete="off" spellCheck={false}/></details>
   </fieldset>{view&&unit&&!valid&&<p role="alert" className="journal-warning">{c.invalid}</p>}
  </form>
  {!unit&&<p>{c.waiting}</p>}
  {localProblem&&<p role="alert" className="journal-warning">{localProblem==='helper_unavailable'?c.helper:localProblem==='result_lost'?c.lostResult:c.denied}</p>}
  {!localProblem&&(active||r.busy||preparing)&&<p role="status">{active?c.pending:c.loading}</p>}
  {request&&['pending','claimed','accepted'].includes(request.state)&&<button className="button small" disabled={r.busy||r.paused||r.uncertain} onClick={r.cancelRequest}>{c.cancel}</button>}
  {request&&!active&&!page&&['expired','accepted'].includes(request.state)&&!r.busy&&<p role="status">{c.expired}</p>}
  {page&&<div className="journal-results"><h3>{page.query.unit}</h3><p className="journal-muted"><time>{page.query.start}</time> → <time>{page.query.end}</time>{page.query.search&&` · “${page.query.search}”`}</p><div className="journal-count"><strong>{page.totalCapturedRows} {c.sourcePage}</strong><span>{c.shown} {page.rows.length?page.offset+1:0}–{page.offset+page.rows.length}</span></div>
   {page.reason==='cursor_unavailable'?<p role="alert" className="journal-warning">{c.lost}</p>:page.coverage==='failed'||page.coverage==='partial'&&(!page.nextCursor||page.reason!=='item_limit')?<p role="alert" className="journal-warning">{c.incomplete}</p>:!page.rows.length&&!page.exhausted?<p role="status">{c.empty}</p>:null}
   {page.rows.length>0&&<div className="journal-table-wrap"><table className="journal-table"><thead><tr><th>UTC</th><th>{c.severity}</th><th>{locale==='de'?'Nachricht':'Message'}</th></tr></thead><tbody>{page.rows.map((row,n)=><tr key={`${page.identity.id}:${page.offset+n}`}><td><time>{row.timestamp.replace('T',' ').replace(/Z$/,'')}</time></td><td>{row.priority}</td><td className="journal-message">{row.message}</td></tr>)}</tbody></table></div>}
   <nav className="journal-pagination" aria-label={locale==='de'?'Log-Seiten':'Log pages'}><button className="button small" disabled={held||!r.canPrevious} onClick={r.previous}><ChevronLeft size={14}/>{c.previous}</button>{page.nextOffset!==null?<button className="button small" disabled={held} onClick={r.next}>{c.next}<ChevronRight size={14}/></button>:page.nextCursor?<button className="button" disabled={held||!ready} onClick={older}>{page.totalCapturedRows===0?c.continue:c.older}<ChevronRight size={14}/></button>:null}</nav>
   {page.exhausted&&page.nextOffset===null&&<p role="status">{c.exhausted}</p>}
  </div>}
  <details className="journal-details"><summary>{c.details}</summary><p>{c.limits}</p><p>{c.retention}</p><p>{JOURNAL_WARNING}</p><p>{c.privacy}</p>{request&&<p>{locale==='de'?'Seite läuft ab':'Page expires'}: {request.description.expiresAt}</p>}</details>
  {picker&&view&&<Dialog title={c.choose} onClose={()=>setPicker(false)} className="journal-picker-modal"><JournalServicePicker deviceId={view.deviceId} sessionKey={sessionKey} journalView={view} selectedUnit={unit} browseOnSelect onSelect={choose} onClose={()=>setPicker(false)}/></Dialog>}
 </section>;
}
