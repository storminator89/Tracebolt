import type { EnrollmentAttention } from './enrollment-attention';
import { activatedEnrollmentDisplay, EnrollmentReport, enrollmentReportIdentity, matchingReportDevice } from './enrollment-report';
import type { Device } from './types';
import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
import { ArrowDownToLine, ArrowRight, Check, ChevronDown, Copy, Eye, EyeOff, Fingerprint, Info, KeyRound, LoaderCircle, Monitor, Plus, RefreshCw, ShieldCheck, Terminal, TriangleAlert, X } from 'lucide-react';
import { APIError, mutate, request } from './api';
import './enrollment-windows.css';
import { WindowsSetupInstructions, WindowsSetupPreparation } from './enrollment-windows-setup';
import { MacOSScope, MacOSSourceInstructions, macOSCopy, macInventoryCopy } from './enrollment-macos';
import { selectEnrollmentCommand, verifiedLinuxDownloadAvailable } from './verified-download-command';
import { Dialog } from './components';
import { TransportWarning, useOperator } from './auth';
import { fullDate } from './utils';
import { t, ui, useLocale } from './i18n';
import { comparisonValid, deadlinePassed, enrollmentDate, enrollmentDeadline, enrollmentCollectionProfile, groupedHex, publicBootstrap, requestID, terminal, terminationAction, validEnrollmentList, validServerTime, validSnapshot, validBootstrapSHA256 } from './enrollment-types';
import type { EnrollmentBootstrap, EnrollmentCollectionProfile, EnrollmentList, EnrollmentPlatform, EnrollmentSnapshot, EnrollmentState, InvitationCreation } from './enrollment-types';

// Claim timestamps are not required by the snapshot validator. Treat missing,
// zero and malformed values as unknown rather than formatting a guessed date.
function approvalTime(value:unknown):string|null {
 if(typeof value!=='number'||!Number.isSafeInteger(value)||value<=0||value>253402300799)return null;
 return new Date(value*1000).toISOString();
}
function ApprovalTime({label,value,unknown}:{label:string;value:unknown;unknown:string}) {
 const date=approvalTime(value);
 return <span>{label}: {date?<time dateTime={date}>{date.replace('T',' ').replace('.000Z',' UTC')}</time>:unknown}</span>;
}

// In-memory fence only: retain interrupted mutations across dialog close and SPA
// navigation. A full reload or process restart loses this fence; the manager's
// revision guard remains authoritative. Never persist keys or infer the outcome
// of an aborted POST. This is not a durable no-replay guarantee.
type ReviewMutation = { item: EnrollmentSnapshot; kind: 'approve' | 'terminate' };
type ReviewFence = { revision:number; fingerprint:string; comparison:string; kind:ReviewMutation['kind'] };
const reviewFences = new Map<string, ReviewFence>();
let reviewFenceOverflow = false;
const reviewFenceKey = (item:EnrollmentSnapshot) => JSON.stringify([item.binding.instanceID,item.binding.origin,item.binding.profile,item.binding.collectionProfile,item.binding.issuerFingerprint,item.invitationID]);
function fenceReview({item,kind}:ReviewMutation) {
 const key=reviewFenceKey(item);
 if(!reviewFences.has(key)&&reviewFences.size>=100){reviewFenceOverflow=true;return;}
 reviewFences.set(key,{revision:item.revision,fingerprint:item.claim.keyFingerprint,comparison:item.claim.comparisonCode,kind});
}
function reconcileReviewFences(items:EnrollmentSnapshot[]) {
 const resolved=new Set<string>();
 for(const item of items){const key=reviewFenceKey(item), fence=reviewFences.get(key);if(!fence||item.revision<=fence.revision||item.claim.keyFingerprint!==fence.fingerprint||item.claim.comparisonCode!==fence.comparison)continue;
  if(terminal(item.state)||(fence.kind==='approve'&&['approved','issuance_intent','issued','activated'].includes(item.state))){reviewFences.delete(key);resolved.add(key);}
 }
 return resolved;
}
const reviewIsFenced=(item:EnrollmentSnapshot)=>reviewFenceOverflow||reviewFences.has(reviewFenceKey(item));

// This copy is profile-specific: v1 consent must not silently acquire v2 scope.
const packageConsent = {
 en: {
  title: 'Operational and package-source inventory · Linux',
  scope: 'Disk, network, service, process, software and event metadata, plus the selected OS release identifiers ID, VERSION_ID and VERSION_CODENAME, binary and source package names and exact versions, architecture, source-mapping basis and install state. Names, mount paths and package metadata may reveal applications or personal or sensitive labels.',
  bounds: 'The package snapshot is limited to 128 rows and 16 KiB, including release fields and metadata, and may be partial. Visibility is limited to the agent-visible namespace and its permissions.',
  retention: 'The latest exact frame remains stored until replaced, including after revocation. Age-based hiding does not delete stored frame bytes. A new unknown package observation replaces earlier package facts.',
  exclusions: 'No account data, command lines, environment variables, raw log bodies, descriptions, maintainers or repository URLs are added. No APT execution, package installation or changes, or AI export.',
  fresh: 'Requires a fresh store and fresh enrollment. Existing profiles, enrollment identities and sequence ledgers are not silently migrated or reset.',
  acknowledge: 'I acknowledge this operational and package-source collection for the new device.',
 },
 de: {
  title: 'Betriebs- und Paketquelleninventar · Linux',
  scope: 'Datenträger-, Netzwerk-, Dienst-, Prozess-, Software- und Ereignis-Metadaten sowie die ausgewählten OS-Release-Kennungen ID, VERSION_ID und VERSION_CODENAME, Binär- und Quellpaketnamen mit exakten Versionen, Architektur, Grundlage der Quellpaketzuordnung und Installationszustand. Namen, Mount-Pfade und Paketmetadaten können Anwendungen oder persönliche oder sensible Bezeichnungen offenlegen.',
  bounds: 'Der Paket-Snapshot ist einschließlich Release-Feldern und Metadaten auf 128 Zeilen und 16 KiB begrenzt und kann unvollständig sein. Die Sichtbarkeit ist auf den für den Agent sichtbaren Namensraum und seine Berechtigungen begrenzt.',
  retention: 'Der letzte exakte Frame bleibt bis zu seiner Ersetzung gespeichert, auch nach einem Widerruf. Altersbedingtes Ausblenden löscht keine gespeicherten Frame-Bytes. Eine neue unbekannte Paketbeobachtung ersetzt frühere Paketdaten.',
  exclusions: 'Keine zusätzlichen Kontodaten, Befehlszeilen, Umgebungsvariablen, Rohprotokolle, Beschreibungen, Maintainer oder Repository-URLs. Keine APT-Ausführung, Paketinstallation oder Paketänderungen und kein KI-Export.',
  fresh: 'Erfordert einen neuen Datenspeicher und ein neues Enrollment. Bestehende Profile, Enrollment-Identitäten und Sequenz-Ledger werden nicht stillschweigend migriert oder zurückgesetzt.',
  acknowledge: 'Ich bestätige diese Betriebs- und Paketquellenerfassung für das neue Gerät.',
 },
} as const;

// Complete package/system collection is separately acknowledged, never inherited v2 consent.
const completePackageConsent = {
 en: {
  ...packageConsent.en,
  scope: packageConsent.en.scope + ' Also includes system-service runtime, failed state and enablement, plus local TCP/UDP sockets and connections with numeric local/remote endpoints and available PID/process-name attribution. These observations may reveal private network topology. Unknown attribution remains explicit; a local binding does not prove external reachability.',
  exclusions: packageConsent.en.exclusions + ' No network scan, DNS lookup or UID collection. Main PID is not collected for services. Null process names remain unknown.',
  title: 'Complete package, service and connection inventory · Linux',
  bounds: 'Collects all supported installed and incomplete dpkg rows in the agent-visible namespace as one validated generation, without the older 128-row export prefix. Bounded transfer, storage and source limits may reject a generation instead of reporting a partial prefix as complete. Snap, Flatpak and other software sources are not included. Service and socket sections are fully enumerated within rejection limits; a failed section is never a successful empty section. Rejection ceilings are not proven device capacity.',
  retention: 'A completed generation remains available for up to 24 hours from its original collection time. A pending, failed or expired newer attempt does not turn the previous generation into fresh data or a successful empty inventory. Metadata and durable bytes may remain until bounded cleanup.',
  fresh: 'New managed-operations-v3 store and explicit enrollment consent required. Existing profiles, identities and sequence ledgers stay unchanged.',
  acknowledge: 'I acknowledge operational metadata, complete supported dpkg packages, system services, and local connection metadata for this new device.',
 },
 de: {
  ...packageConsent.de,
  scope: packageConsent.de.scope + ' Zusätzlich Systemdienste mit Laufzeit-, Fehler- und Aktivierungszustand sowie lokale TCP-/UDP-Sockets und Verbindungen mit numerischen lokalen und entfernten Endpunkten und verfügbarer PID-/Prozessnamen-Zuordnung. Diese Beobachtungen können die private Netzwerktopologie offenlegen. Unbekannte Zuordnungen bleiben ausdrücklich unbekannt; eine lokale Bindung belegt keine Erreichbarkeit von außen.',
  exclusions: packageConsent.de.exclusions + ' Kein Netzwerkscan, keine DNS-Abfrage und keine UID-Erfassung. Für Dienste wird keine Haupt-PID erfasst. Fehlende Prozessnamen bleiben unbekannt.',
  title: 'Vollständiges Paket-, Dienst- und Verbindungsinventar · Linux',
  bounds: 'Erfasst alle unterstützten installierten und unvollständigen dpkg-Einträge im für den Agent sichtbaren Namensraum als eine validierte Generation, ohne die frühere Exportauswahl von 128 Zeilen. Begrenzte Übertragung, Speicherung und Quellen können eine Generation ablehnen, statt eine Teilauswahl als vollständig zu melden. Snap, Flatpak und andere Softwarequellen sind nicht enthalten. Dienst- und Socket-Abschnitte werden innerhalb von Ablehnungsgrenzen vollständig erfasst; ein fehlgeschlagener Abschnitt ist kein erfolgreich leerer Abschnitt. Ablehnungsgrenzen sind keine nachgewiesene Gerätekapazität.',
  retention: 'Eine abgeschlossene Generation ist bis zu 24 Stunden ab der ursprünglichen Erfassung verfügbar. Ein neuerer ausstehender, fehlgeschlagener oder abgelaufener Versuch macht die vorherige Generation weder aktuell noch zu einem erfolgreich leeren Inventar. Metadaten und gespeicherte Bytes können bis zur begrenzten Bereinigung erhalten bleiben.',
  fresh: 'Neuer managed-operations-v3-Datenspeicher und neue ausdrückliche Enrollment-Freigabe erforderlich. Bestehende Profile, Identitäten und Sequenz-Ledger bleiben unverändert.',
  acknowledge: 'Ich bestätige die Erfassung von Betriebsmetadaten, allen unterstützten dpkg-Paketen, Systemdiensten und lokalen Verbindungsmetadaten für dieses neue Gerät.',
 },
} as const;

const windowsConsent = {
 en: {
  title: 'Bounded Windows inventory',
  scope: 'Hostname, interface IP addresses, process names and IDs, service metadata, and installed software metadata may contain personal or sensitive information.',
  bounds: 'Each snapshot carries at most 1 hostname, 128 process rows, 128 service rows, 128 software rows and 64 interface-address rows within 48 KiB. Partial results and lower-bound counts are shown explicitly; these counts do not prove whole-device coverage.',
  exclusions: 'No command lines, environment variables, raw logs, credentials, remote commands, Windows Update or CVE analysis. No AI export. Visibility depends on the native source and the agent’s permissions.',
  acknowledge: 'I acknowledge this Windows inventory collection for the new device.',
  http: 'HTTP test: the invitation and approved hostname, network, process, service and software metadata travel without encryption and may be intercepted or altered. Use only in a deliberately isolated test environment.',
  acknowledgeHTTP: 'I explicitly accept unencrypted HTTP-test enrollment and Windows inventory transmission.',
  availability: 'Windows selected. Prepare Setup first, then create the invitation. Local installation, persistent identity and the 21 Read admin scopes require separate approval on the device.',
 },
 de: {
  title: 'Begrenztes Windows-Inventar',
  scope: 'Hostname, Schnittstellen-IP-Adressen, Prozessnamen und IDs, Dienstmetadaten und Metadaten installierter Software können persönliche oder sensible Angaben enthalten.',
  bounds: 'Jeder Snapshot enthält höchstens 1 Hostnamen, 128 Prozesszeilen, 128 Dienstzeilen, 128 Softwarezeilen und 64 Schnittstellenadresszeilen innerhalb von 48 KiB. Teilergebnisse und Zählungen als Untergrenze werden ausdrücklich angezeigt; diese Werte belegen keine vollständige Geräteabdeckung.',
  exclusions: 'Keine Befehlszeilen, Umgebungsvariablen, Rohprotokolle, Zugangsdaten, Fernbefehle, Windows-Update- oder CVE-Analyse. Kein KI-Export. Die Sichtbarkeit hängt von der nativen Quelle und den Agent-Berechtigungen ab.',
  acknowledge: 'Ich bestätige diese Windows-Inventarerfassung für das neue Gerät.',
  http: 'HTTP-Test: Die Einladung und freigegebene Hostnamen-, Netzwerk-, Prozess-, Dienst- und Softwaremetadaten werden unverschlüsselt übertragen und können abgefangen oder verändert werden. Nur in einer bewusst isolierten Testumgebung verwenden.',
  acknowledgeHTTP: 'Ich akzeptiere ausdrücklich das unverschlüsselte HTTP-Test-Enrollment und die Übertragung des Windows-Inventars.',
  availability: 'Windows ausgewählt. Erst Setup vorbereiten, dann die Einladung erstellen. Lokale Installation, dauerhafte Identität und die 21 Read-admin-Bereiche benötigen eine separate Zustimmung am Gerät.',
 },
} as const;

type EnrollmentClockAnchor={monotonic:number;wall:number};
const captureClock=():EnrollmentClockAnchor=>({monotonic:performance.now(),wall:Date.now()});
function clockElapsed(anchor:EnrollmentClockAnchor):number|null {
 const elapsed=performance.now()-anchor.monotonic,wallElapsed=Date.now()-anchor.wall;
 // Wall time can revoke confidence after suspension or a clock jump; it never grants freshness.
 return Number.isFinite(elapsed)&&elapsed>=0&&Number.isFinite(wallElapsed)&&Math.abs(wallElapsed-elapsed)<=1500?elapsed:null;
}

function stateLabel(state:EnrollmentState):string {
 const labels={created:t('Wartet auf Gerät'),claimed_pending:t('Freigabe prüfen'),approved:t('Schlüssel freigegeben'),issuance_intent:t('Identität wird ausgestellt'),issued:t('Identität ausgestellt'),activated:t('Identität aktiviert'),expired:t('Abgelaufen'),canceled:t('Abgebrochen'),rejected:t('Abgelehnt'),revoked:t('Widerrufen')};return labels[state];
}
// These are workflow steps, not online-health evidence. Enrollment never proves a live connection.
function EnrollmentProgress({state='created',available=true,platform}:{state?:EnrollmentState;available?:boolean;platform?:string}) {
 const [locale]=useLocale();
 const labels=platform==='darwin'?(locale==='de'?['Anmelden','Freigeben','Bericht prüfen']:['Enroll','Approve','Verify report']):locale==='de'?['Installieren','Freigeben','Daten prüfen']:['Install','Approve','Check data'];
 const current=!available||terminal(state)?null:state==='created'?0:state==='claimed_pending'?1:2;
 return <ol className="enrollment-progress" aria-label={locale==='de'?'Einrichtungsschritte':'Setup steps'}>{labels.map((label,index)=><li key={label} aria-current={index===current?'step':undefined}><span aria-hidden="true">{index+1}</span>{label}</li>)}</ol>;
}
function ConnectionNextStep({state,available=true}:{state:EnrollmentState;available?:boolean}) {
 const [locale]=useLocale();
 if(state==='created'||state==='claimed_pending'||terminal(state)||state==='activated'&&!available)return null;
 return <p className="enrollment-next-step">{state==='activated'
  ?locale==='de'?'Identität aktiviert. Öffne das Gerät und prüfe den letzten Bericht, um die Verbindung zu bestätigen.':'Identity activated. Open the device and check its latest report to verify the connection.'
  :locale==='de'?'Freigegeben. Das Gerät muss die Aktivierung noch abschließen; die Verbindung ist noch nicht bestätigt.':'Approved. The device still needs to finish activation; the connection is not yet confirmed.'}</p>;
}
function macOSTransportAvailable(insecureTest:boolean):boolean{return !insecureTest&&window.location.protocol==='https:';}
function actionFailure(error:unknown):string {return error instanceof APIError&&error.status===409?t('Der Eintrag wurde geändert. Status aktualisieren und erneut vergleichen.'):error instanceof APIError&&error.status===429?t('Enrollment ist ausgelastet. Status prüfen und später erneut versuchen.'):t('Aktion nicht bestätigt. Status aktualisieren, bevor du erneut entscheidest.');}
function EnrollmentStatus({item,now,device,available=false}:{item:EnrollmentSnapshot;now:number|null;device?:Device;available?:boolean}) {
 const [locale]=useLocale(),activated=item.state==='activated'?activatedEnrollmentDisplay(item,device,now,available):null;
 const expired=activated?activated==='expired':deadlinePassed(item,now);
 return <span className={`enrollment-status state-${expired?'expired':activated??item.state}`}><span className="status-dot"/>{expired?t('Frist abgelaufen'):activated==='unavailable'?t('Status unbekannt'):activated==='denied'?(locale==='de'?'Identität nicht zugelassen':'Identity not admitted'):stateLabel(item.state)}</span>;
}
function displayExpired(item:EnrollmentSnapshot,now:number|null,device:Device|undefined,available:boolean):boolean {return item.state==='activated'?activatedEnrollmentDisplay(item,device,now,available)==='expired':deadlinePassed(item,now);}
function displayAvailable(item:EnrollmentSnapshot,now:number|null,device:Device|undefined,available:boolean):boolean {return now!==null&&(item.state==='activated'?activatedEnrollmentDisplay(item,device,now,available)==='activated':!deadlinePassed(item,now));}


type EnrollmentSectionProps={onAttention?:(value:EnrollmentAttention|null)=>void;onChanged:()=>void|Promise<void>;onRefreshReports?:()=>void|Promise<void>;onDevice:(id:string)=>void;deviceIds:string[];devices?:Device[];reportsAvailable?:boolean};
export function EnrollmentSection(props:EnrollmentSectionProps) {
 const [platform,setPlatform]=useState<EnrollmentPlatform>('linux');
 const [macProfile,setMacProfile]=useState<'basic-readonly-v1'|'macos-read-inventory-v1'>('basic-readonly-v1');
 const session=useRef(new AbortController());
 const selectPlatform=(next:EnrollmentPlatform)=>{if((next!=='linux'&&next!=='windows'&&next!=='darwin')||next===platform)return;session.current.abort();session.current=new AbortController();setPlatform(next);};
 const selectMacProfile=(next:typeof macProfile)=>{if(!['basic-readonly-v1','macos-read-inventory-v1'].includes(next)||next===macProfile)return;session.current.abort();session.current=new AbortController();setMacProfile(next);};
 return <EnrollmentPlatformSection key={`${platform}:${macProfile}`} macProfile={macProfile} onSelectMacProfile={selectMacProfile} {...props} platform={platform} sessionSignal={session.current.signal} onSelectPlatform={selectPlatform}/>;
}
function EnrollmentPlatformSection({onAttention,onChanged,onRefreshReports,onDevice,deviceIds,devices,reportsAvailable=false,platform,sessionSignal,onSelectPlatform,macProfile,onSelectMacProfile}:EnrollmentSectionProps&{platform:EnrollmentPlatform;macProfile:'basic-readonly-v1'|'macos-read-inventory-v1';onSelectMacProfile:(profile:'basic-readonly-v1'|'macos-read-inventory-v1')=>void;sessionSignal:AbortSignal;onSelectPlatform:(platform:EnrollmentPlatform)=>void}) {
 const operator=useOperator();
 const [locale]=useLocale();
 const enrollmentPath=platform==='windows'?'/windows/enrollment':platform==='darwin'?(macProfile==='macos-read-inventory-v1'?'/macos-inventory/enrollment':'/macos/enrollment'):'/enrollment';
 // Session identity stays inside this source owner; only the display projection
 // is invalidated when a response belongs to a replaced operator session.
 const attentionSessionKey=useRef(''),attentionSourceSession=useRef<string|null>(null);
 attentionSessionKey.current=JSON.stringify([operator?.mode,operator?.actorId,operator?.expiresAt,operator?.insecureTestMode]);
 const [data,setData]=useState<EnrollmentList|null>(null),[error,setError]=useState(''),[notice,setNotice]=useState(''),[loading,setLoading]=useState(false),[expanded,setExpanded]=useState(false),[all,setAll]=useState(false);
 const noticeReviewKey=useRef<string|null>(null);
 const [missingCapability,setMissingCapability]=useState(false);
 const [dialog,setDialog]=useState<{kind:'create'}|{kind:'record';id:string}|null>(null);
 const [now,setNow]=useState<number|null>(null);
 const clock=useRef<(EnrollmentClockAnchor&{server:number})|null>(null),lastServerTime=useRef<number|null>(null);
 const configurationContext=useRef(new AbortController());
 const invalidateConfiguration=useCallback(()=>{
  // Abort synchronously so an older create cannot restore its secret before React unmounts it.
  clock.current=null;configurationContext.current.abort();setNow(null);setData(null);setDialog(null);
 },[]);
 const currentTime=useCallback(()=>{if(!clock.current)return null;const elapsed=clockElapsed(clock.current);return elapsed===null?null:clock.current.server+elapsed;},[]);
 const syncClock=useCallback((serverNow:string,startedAt:EnrollmentClockAnchor)=>{
  const elapsed=clockElapsed(startedAt);if(elapsed===null||(clock.current&&currentTime()===null)){invalidateConfiguration();throw new Error('uncertain enrollment clock');}
  // Compare authoritative values only: request latency must not turn equal server timestamps into regressions.
  const authoritative=Date.parse(serverNow),regressed=lastServerTime.current!==null&&authoritative<lastServerTime.current;
  if(regressed)invalidateConfiguration();
  lastServerTime.current=authoritative;clock.current={server:authoritative+elapsed,...captureClock()};setNow(currentTime());return !regressed;
 },[currentTime,invalidateConfiguration]);
 const reading=useRef<'enrollment'|'reports'|null>(null),reportRefreshRequested=useRef(false);
 const active=useRef(true),fetcher=useRef<AbortController|null>(null),lastState=useRef(''),lastConfiguration=useRef(''),changed=useRef(onChanged),reportRefresh=useRef(onRefreshReports);changed.current=onChanged;reportRefresh.current=onRefreshReports;
 const load=useCallback(async(refreshReports=false)=>{
  if(refreshReports)reportRefreshRequested.current=true;
  // Coalesce manual clicks and the follow-on report read. Periodic reads must
  // still replace a stalled enrollment request so newer consent can invalidate it.
  if(reading.current&&fetcher.current&&!fetcher.current.signal.aborted&&(refreshReports||reading.current==='reports'))return;
  reading.current='enrollment';
  fetcher.current?.abort();if(clock.current&&currentTime()===null)invalidateConfiguration();const controller=new AbortController();fetcher.current=controller;const startedAt=captureClock(),attentionReadSession=attentionSessionKey.current;setLoading(true);setError('');setMissingCapability(false);
  try{const next=await request<EnrollmentList>(enrollmentPath,{signal:controller.signal});if(!active.current||controller.signal.aborted||fetcher.current!==controller)return;if(!validEnrollmentList(next,platform,macProfile))throw new Error('invalid enrollment contract');
   const configuration=JSON.stringify([next.enabled,next.platforms,next.recordLimit,enrollmentCollectionProfile(next),next.collectionPrivacy??null]);if(lastConfiguration.current&&configuration!==lastConfiguration.current)invalidateConfiguration();lastConfiguration.current=configuration;
   const clockValid=syncClock(next.serverNow,startedAt);if(clockValid){const resolved=reconcileReviewFences(next.items);if(noticeReviewKey.current&&resolved.has(noticeReviewKey.current)){noticeReviewKey.current=null;setNotice('');}}if(configurationContext.current.signal.aborted)configurationContext.current=new AbortController();const signature=next.items.map(item=>`${item.invitationID}:${item.revision}`).join('|');const snapshotChanged=Boolean(lastState.current&&signature!==lastState.current),refreshReportEvidence=reportRefreshRequested.current;reportRefreshRequested.current=false;lastState.current=signature;attentionSourceSession.current=attentionReadSession;setData(next);reading.current='reports';if(snapshotChanged)await changed.current();else if(refreshReportEvidence)await reportRefresh.current?.();
  }catch(error){if(active.current&&!controller.signal.aborted&&fetcher.current===controller){invalidateConfiguration();if(platform==='darwin'&&error instanceof APIError&&error.status===404)setMissingCapability(true);else setError(t('Enrollment-Status nicht verfügbar. Es werden keine Ersatzdaten angezeigt.'));}}
  finally{if(fetcher.current===controller){reading.current=null;reportRefreshRequested.current=false;if(active.current&&!controller.signal.aborted)setLoading(false);}}
 },[syncClock,invalidateConfiguration,currentTime,enrollmentPath,platform,macProfile]);
 useEffect(()=>{active.current=true;void load();return()=>{active.current=false;fetcher.current?.abort();configurationContext.current.abort();};},[load]);
 useEffect(()=>{const invalidateSession=()=>{fetcher.current?.abort();invalidateConfiguration();};sessionSignal.addEventListener('abort',invalidateSession);if(sessionSignal.aborted)invalidateSession();return()=>sessionSignal.removeEventListener('abort',invalidateSession);},[sessionSignal,invalidateConfiguration]);
 useEffect(()=>{const close=()=>setDialog(null);window.addEventListener('hashchange',close);return()=>window.removeEventListener('hashchange',close);},[]);
 useEffect(()=>{const suspend=()=>{fetcher.current?.abort();clock.current=null;setNow(null);setLoading(false);};const resume=()=>{suspend();void load();};const visibility=()=>document.visibilityState==='hidden'?suspend():resume();const pageshow=(event:PageTransitionEvent)=>{if(event.persisted||clock.current===null)resume();};window.addEventListener('pagehide',suspend);window.addEventListener('pageshow',pageshow);document.addEventListener('visibilitychange',visibility);return()=>{window.removeEventListener('pagehide',suspend);window.removeEventListener('pageshow',pageshow);document.removeEventListener('visibilitychange',visibility);};},[load]);
 useEffect(()=>{if(!data?.enabled||!data.items.some(item=>!terminal(item.state)))return;const timer=window.setInterval(()=>{if(document.visibilityState==='visible')void load();},10000);return()=>window.clearInterval(timer);},[data,load]);
 useEffect(()=>{if(!data?.enabled)return;const tick=window.setInterval(()=>{const next=currentTime();if(next===null)invalidateConfiguration();else setNow(next);},1000);return()=>window.clearInterval(tick);},[data?.enabled,currentTime,invalidateConfiguration]);
 const reportUncertain=(creating:boolean)=>{if(creating)noticeReviewKey.current=null;setNotice(creating?t('Erstellung nicht bestätigt. Eine Einladung kann bereits bestehen. Status prüfen, diese Einladung bei Bedarf abbrechen und anschließend eine neue erstellen.'):t('Aktion nicht bestätigt. Status aktualisieren, bevor du erneut entscheidest.'));setExpanded(true);};
 const accept=(item:EnrollmentSnapshot,serverNow?:string,startedAt?:EnrollmentClockAnchor)=>{if(serverNow&&startedAt!==undefined&&!syncClock(serverNow,startedAt))throw new Error('regressed enrollment clock');noticeReviewKey.current=null;setNotice('');fetcher.current?.abort();setLoading(false);setData(previous=>{if(!previous)return previous;const existing=previous.items.find(value=>value.invitationID===item.invitationID);if(existing&&existing.revision>item.revision)return previous;return {...previous,items:[item,...previous.items.filter(value=>value.invitationID!==item.invitationID)]};});setExpanded(true);changed.current();};
 const platformItems=data?.items.filter(item=>item.platform===platform)||[];
 const selected=dialog?.kind==='record'?platformItems.find(item=>item.invitationID===dialog.id):undefined;
 const currentCreation=dialog?.kind==='create'?data?.items:undefined;
 const supported=Boolean(data?.enabled&&data.platforms.includes(platform)&&(platform!=='darwin'||enrollmentCollectionProfile(data)===macProfile&&macOSTransportAvailable(Boolean(operator?.insecureTestMode))));
 const collectionProfile=data?enrollmentCollectionProfile(data):null;
 const records=platformItems.filter(item=>all||!terminal(item.state));
 const pending=platformItems.filter(item=>item.state==='claimed_pending').length;
 const reportDevice=selected?matchingReportDevice(devices,selected.approval.deviceID):undefined;
 const reportEvidenceAvailable=reportsAvailable&&!loading&&!error&&operator?.mode==='lan'&&operator.authenticated===true;
 // Copy only scalar display state to the page index. The source owner retains
 // every snapshot, identity, clock, request and acknowledgement. In particular,
 // unknown/refreshing/unconfirmed states never export a stale pending count.
 const attentionProfile=collectionProfile??(platform==='darwin'?macProfile:null);
 const attentionSession=operator?.mode==='lan'&&operator.authenticated===true&&!operator.checkingAccess&&!sessionSignal.aborted&&(!operator.expiresAt||now===null||Number.isFinite(Date.parse(operator.expiresAt))&&now<Date.parse(operator.expiresAt));
 const attentionItems=platformItems.filter(item=>item.binding.collectionProfile===attentionProfile);
 const livePending=attentionItems.filter(item=>item.state==='claimed_pending'&&!deadlinePassed(item,now)).length;
 const attentionReplaced=attentionSourceSession.current!==null&&attentionSourceSession.current!==attentionSessionKey.current;
 const attentionState:EnrollmentAttention['state']=
  !attentionSession||attentionReplaced?'unknown':notice?'unconfirmed':loading?'checking':error?'unknown':
  missingCapability?'unavailable':now===null||configurationContext.current.signal.aborted?'unknown':
  !supported?'unavailable':livePending>0?'pending-review':attentionItems.some(item=>item.state==='claimed_pending')?'expired':pending>0?'retained-review':'manual';
 const attentionPending=attentionState==='pending-review'?livePending:null;
 const approvalRows=attentionState==='pending-review'?attentionItems.filter(item=>item.state==='claimed_pending'&&!deadlinePassed(item,now)):[];
 const expiredApprovals=attentionState==='pending-review'?attentionItems.filter(item=>item.state==='claimed_pending'&&deadlinePassed(item,now)).length:0;
 const attentionCallback=useRef(onAttention);attentionCallback.current=onAttention;
 useLayoutEffect(()=>()=>{attentionCallback.current?.(null);},[]);
 useLayoutEffect(()=>{attentionCallback.current?.({platform,profile:attentionProfile,state:attentionState,pendingCount:attentionPending});},[platform,attentionProfile,attentionState,attentionPending]);
 return <section className="panel enrollment-panel" tabIndex={-1} aria-label={t('Geräte hinzufügen')}>
  <label className="enrollment-platform-picker"><span>{locale==='de'?'Betriebssystem':'Operating system'}</span><select value={platform} onChange={event=>onSelectPlatform(event.target.value as EnrollmentPlatform)}><option value="linux">Linux</option><option value="windows">Windows</option><option value="darwin">macOS</option></select></label>
  {platform==='darwin'&&<label className="enrollment-platform-picker"><span>{locale==='de'?'macOS-Erfassungsumfang':'macOS collection scope'}</span><select value={macProfile} onChange={event=>onSelectMacProfile(event.target.value as typeof macProfile)}><option value="basic-readonly-v1">{locale==='de'?'Basis · nur lesend':'Basic · read-only'}</option><option value="macos-read-inventory-v1">{locale==='de'?'Inventar · neue explizite Zustimmung':'Inventory · fresh explicit approval'}</option></select></label>}
  <div className="enrollment-toolbar"><span className="enrollment-symbol"><Monitor size={19}/></span><div className="enrollment-heading"><h2>{t('Geräte hinzufügen')}{attentionPending!==null&&attentionPending>0&&<span className="count">{attentionPending}</span>}</h2><p>{error?t('Status unbekannt'):missingCapability?t('Enrollment ist auf diesem Manager nicht eingerichtet.'):!data?t('Status wird geprüft …'):supported?(platform==='darwin'?(locale==='de'?'macOS · Einzelne Einladung · Manuelle Freigabe':'macOS · Single invitation · Manual approval'):platform==='windows'?(locale==='de'?'Windows · Einzelne Einladung · Manuelle Freigabe':'Windows · Single invitation · Manual approval'):t('Linux · Einzelne Einladung · Manuelle Freigabe')):t('Enrollment ist auf diesem Manager nicht eingerichtet.')}</p></div><div className="enrollment-actions"><button className="icon-button" aria-label={t('Enrollment-Status aktualisieren')} title={t('Enrollment-Status aktualisieren')} onClick={()=>void load(true)} disabled={loading}><RefreshCw size={15} className={loading?'spin':''}/></button>{platformItems.length>0&&<button className="button" aria-expanded={expanded} onClick={()=>setExpanded(!expanded)}>{t('Einladungen')}<span>{platformItems.length}</span><ChevronDown size={14}/></button>}<button className="button primary" disabled={!supported||now===null||loading||Boolean(error)||data!.items.length>=data!.recordLimit} onClick={()=>setDialog({kind:'create'})}><Plus size={15}/>{t('Gerät hinzufügen')}</button></div></div>
  {platform==='windows'&&<section className="enrollment-approvals" aria-label={locale==='de'?'Gerätefreigaben · Windows':'Device approvals · Windows'}>
   <div className="enrollment-approvals-heading"><h3>{locale==='de'?'Gerätefreigaben':'Device approvals'}</h3><span>Windows</span></div>
   {attentionState==='pending-review'?<><p className="enrollment-approvals-note">{locale==='de'?'Diese Anfragen warten auf einen Schlüsselvergleich. Die Geräteidentität ist noch nicht bestätigt.':'These requests await key comparison. Device identity is not yet confirmed.'}</p>{approvalRows.map(item=><button className="enrollment-row" key={item.invitationID} aria-label={locale==='de'?`Gerätefreigabe ${item.invitationID} prüfen`:`Review device approval ${item.invitationID}`} aria-describedby={`approval-times-${item.invitationID}`} onClick={()=>setDialog({kind:'record',id:item.invitationID})}><Fingerprint size={16}/><span className="enrollment-row-name"><strong>{locale==='de'?'Schlüssel vergleichen':'Compare key'}</strong><code>{item.invitationID}</code><span className="enrollment-approval-times" id={`approval-times-${item.invitationID}`}><ApprovalTime label={locale==='de'?'Angefragt':'Requested'} value={item.claim.at} unknown={locale==='de'?'Unbekannt':'Unknown'}/>{' '}<ApprovalTime label={locale==='de'?'Anfrage gültig bis':'Request expires'} value={enrollmentDeadline(item)} unknown={locale==='de'?'Unbekannt':'Unknown'}/></span></span><EnrollmentStatus item={item} now={now}/><ArrowRight size={15}/></button>)}{expiredApprovals>0&&<p className="enrollment-approvals-note">{locale==='de'?`${expiredApprovals} weitere Anfrage(n) sind abgelaufen; im Einladungsverlauf prüfen.`:`${expiredApprovals} other request(s) expired; review them in invitation history.`}</p>}</>:<p className="enrollment-approvals-note" role="status">{attentionState==='checking'?(locale==='de'?'Freigaben werden geprüft …':'Checking approvals…'):attentionState==='expired'?(locale==='de'?'Ausstehende Anfragen sind abgelaufen; im Einladungsverlauf prüfen.':'Pending requests have expired; review them in invitation history.'):attentionState==='manual'?(locale==='de'?'Keine Gerätefreigaben ausstehend.':'No device approvals pending.'):(locale==='de'?'Gerätefreigaben können derzeit nicht bestätigt werden. Status aktualisieren.':'Device approvals cannot be confirmed right now. Refresh status.')}</p>}
  </section>}
  {platform==='darwin'&&<div className="enrollment-message" role="status"><Info size={15}/><span>{(missingCapability||data&&!supported)?(macProfile==='macos-read-inventory-v1'?macInventoryCopy[locale].unavailable:macOSCopy[locale].unavailable):(macProfile==='macos-read-inventory-v1'?macInventoryCopy[locale].availability:macOSCopy[locale].availability)} {macOSCopy[locale].release}</span></div>}
  {notice&&<div className="enrollment-message" role="status"><Info size={15}/><span>{ui(notice)}</span></div>}
  {error&&<div className="enrollment-message" role="alert"><TriangleAlert size={15}/><span>{ui(error)}</span></div>}
  {data&&data.items.length>=data.recordLimit&&<div className="enrollment-message" role="status"><Info size={15}/><span>{t('Limit erreicht: {0} gespeicherte Einträge, einschließlich abgebrochener und widerrufener Einladungen.',{0:data.recordLimit})}</span></div>}
  {expanded&&data&&<div className="enrollment-history"><div className="enrollment-history-head"><span>{t('{0} von {1} gespeicherten Einträgen',{0:data.items.length,1:data.recordLimit})}</span><label className="enrollment-toggle"><input type="checkbox" checked={all} onChange={event=>setAll(event.target.checked)}/>{t('Beendete anzeigen')}</label></div>{records.length?records.map(item=><button className="enrollment-row" key={item.invitationID} aria-label={t("Einladung {0} prüfen",{0:item.invitationID})} onClick={()=>setDialog({kind:'record',id:item.invitationID})}><Terminal size={16}/><span className="enrollment-row-name"><strong>{item.platform==='linux'?'Linux':item.platform==='windows'?'Windows':item.platform==='darwin'?'macOS':item.platform}</strong><code>{item.invitationID}</code></span><EnrollmentStatus item={item} now={now} device={matchingReportDevice(devices,item.approval.deviceID)} available={reportEvidenceAvailable}/><ArrowRight size={15}/></button>):<p className="enrollment-empty">{t('Keine laufenden Einladungen.')}</p>}<p className="enrollment-retention">{t('Beendete Einträge bleiben erhalten. Eine aktive Identität bestätigt keine laufende Erfassung.')}</p></div>}
  {dialog?.kind==='create'&&supported&&collectionProfile&&<CreateInvitation refreshing={loading} onCheckStatus={()=>load(true)} devices={devices} reportsAvailable={reportEvidenceAvailable} platform={platform} enrollmentPath={enrollmentPath} key={collectionProfile} collectionProfile={collectionProfile} configurationSignal={configurationContext.current.signal} now={now} currentTime={currentTime} onUncertain={()=>reportUncertain(true)} insecureTest={Boolean(operator?.insecureTestMode)} onClose={()=>setDialog(null)} onCreated={accept} onRefresh={load} currentItems={currentCreation||[]} onReview={id=>setDialog({kind:'record',id})}/>}
  {selected&&<ReviewEnrollment refreshing={loading} onCheckStatus={()=>load(true)} reportDevice={reportDevice} reportsAvailable={reportEvidenceAvailable} enrollmentPath={enrollmentPath} configurationSignal={configurationContext.current.signal} now={now} currentTime={currentTime} onUncertain={mutation=>{fenceReview(mutation);noticeReviewKey.current=reviewFenceKey(mutation.item);reportUncertain(false);}} blocked={reviewIsFenced(selected)} key={selected.invitationID} item={selected} onClose={()=>setDialog(null)} onUpdated={accept} onRefresh={load} onDevice={deviceIds.includes(selected.approval.deviceID)?()=>{setDialog(null);onDevice(selected.approval.deviceID);}:undefined}/>}
 </section>;
}

function CreateInvitation({refreshing,onCheckStatus,devices,reportsAvailable,platform,enrollmentPath,collectionProfile,configurationSignal,now,currentTime,onUncertain,insecureTest,onClose,onCreated,onRefresh,currentItems,onReview}:{refreshing:boolean;onCheckStatus:()=>Promise<void>;devices?:Device[];reportsAvailable:boolean;platform:EnrollmentPlatform;enrollmentPath:string;collectionProfile:EnrollmentCollectionProfile;configurationSignal:AbortSignal;now:number|null;currentTime:()=>number|null;onUncertain:()=>void;insecureTest:boolean;onClose:()=>void;onCreated:(item:EnrollmentSnapshot,serverNow:string,startedAt:EnrollmentClockAnchor)=>void;onRefresh:()=>Promise<void>;currentItems:EnrollmentSnapshot[];onReview:(id:string)=>void}) {
 const [created,setCreated]=useState<{snapshot:EnrollmentSnapshot;bootstrap:EnrollmentBootstrap;bootstrapSHA256?:string}|null>(null),[secret,setSecret]=useState(''),[revealed,setRevealed]=useState(false),[pending,setPending]=useState(false),[error,setError]=useState(''),[uncertain,setUncertain]=useState(false),[copied,setCopied]=useState(false),[commandCopied,setCommandCopied]=useState(false);
 const [locale]=useLocale();
 const windows=platform==='windows',macOS=platform==='darwin',windowsCopy=windowsConsent[locale],macInventory=collectionProfile==='macos-read-inventory-v1',macCopy=macOSCopy[locale];
 const latestInsecureTest=useRef(insecureTest);latestInsecureTest.current=insecureTest;
 const transportAvailable=()=>!macOS||macOSTransportAvailable(latestInsecureTest.current);
 const completeSource=collectionProfile==='managed-operations-v3',packageSource=collectionProfile==='managed-operations-v2'||completeSource,managed=windows||macInventory||collectionProfile==='managed-operations-v1'||packageSource;
 const consentCopy=completeSource?completePackageConsent[locale]:packageConsent[locale];
 const downloadAvailable=platform==='linux'&&verifiedLinuxDownloadAvailable(collectionProfile);
 const readAdminUnavailable=locale==='de'?'Der vollständige Read-Admin-Befehl ist erst nach Aktivierung eines geprüften kompatiblen Releases verfügbar.':'The complete read-admin command is unavailable until a verified compatible release is activated.';
 const shortConsent=locale==='de'?{
  scope:completeSource?'Betriebsmetadaten, alle unterstützten dpkg-Pakete, Systemdienste und lokale Verbindungen. Namen und Pfade können sensible Angaben enthalten; Verbindungsmetadaten können die private Netzwerktopologie offenlegen.':'Betriebsmetadaten, OS-Kennungen sowie Binär- und Quellpaketnamen mit exakten Versionen. Namen, Pfade und Paketmetadaten können persönliche oder sensible Angaben enthalten.',
  retention:completeSource?'Inventar ist bis zu 24 Stunden verfügbar; gespeicherte Bytes können bis zur Bereinigung bleiben. Kein KI-Export.':'Begrenzter, möglicherweise unvollständiger Snapshot. Gespeichert bis zur Ersetzung, auch nach Widerruf. Kein KI-Export.',
  details:'Erfassungsumfang, Speicherung und Grenzen',
 }:{
  scope:completeSource?'Operational metadata, all supported dpkg packages, system services and local connections. Names and paths may contain sensitive information; connection metadata may reveal private network topology.':'Operational metadata, OS identifiers, and binary and source package names with exact versions. Names, paths and package metadata may contain personal or sensitive information.',
  retention:completeSource?'Inventory is available for up to 24 hours; stored bytes may remain until cleanup. No AI export.':'Bounded snapshot that may be partial. Stored until replaced, including after revocation. No AI export.',
  details:'Collection, retention and limits',
 };
 const [collectionAcknowledged,setCollectionAcknowledged]=useState(false),[insecureHTTPAcknowledged,setInsecureHTTPAcknowledged]=useState(false);
 const alive=useRef(true),operation=useRef<AbortController|null>(null),downloads=useRef<Set<string>>(new Set()),secretInput=useRef<HTMLInputElement|null>(null);
 const bindSecretInput=useCallback((input:HTMLInputElement|null)=>{if(!input&&secretInput.current)secretInput.current.value='';secretInput.current=input;},[]);
 const selectedCommand=created&&platform==='linux'?selectEnrollmentCommand(created.bootstrap,created.snapshot,created.bootstrapSHA256):null;
 const publicCommand=selectedCommand?.command??null,downloadCommand=selectedCommand?.kind==='verified-download';
 const commandCopy=locale==='de'?{title:'Als root im vorbereiteten lokalen Checkout ausführen',note:'Alle drei nativen Programme in bin/ (einschließlich agent-service) und tracebolt-selected-source.tar müssen bereits aus unabhängig ausgewählten und geprüften Quellen oder einem vertrauenswürdigen Release vorliegen. Die lokal berechneten SHA-256-Werte binden die vorhandenen Bytes; sie bestätigen weder Herausgeber noch die Zuordnung von Quellcode und Programm.',prompt:'Der native Client fragt den Einladungsschlüssel verdeckt ab. Dieser öffentliche Befehl enthält keinen Einladungsschlüssel. Der ausstehende Dienst wartet im Hintergrund auf die Operator-Freigabe. Vor Freigabe und Aktivierung wird kein Inventar erfasst. Dieser Befehl belegt für sich keine erfolgreiche Dienst- oder Neustartprüfung.',copy:'Öffentlichen Installationsbefehl kopieren',copied:'Öffentlicher Befehl kopiert',error:'Der öffentliche Befehl konnte nicht kopiert werden.'}:{title:'Run as root from the prepared local checkout',note:'All three native binaries in bin/ (including agent-service) and tracebolt-selected-source.tar must already come from independently selected and reviewed sources or a trusted release. Locally computed SHA-256 values pin the existing bytes; they do not verify the publisher or the source-to-binary relationship.',prompt:'The native client asks for the invitation through its hidden prompt. This public command contains no invitation secret. The pending service waits for operator approval in the background. No inventory is collected before approval and activation. This command does not itself prove service or reboot acceptance.',copy:'Copy public installation command',copied:'Public command copied',error:'The public command could not be copied.'};
 const downloadCopy=locale==='de'?{title:'Geprüften Download als root im lokalen Terminal ausführen',summary:'Benötigt Debian 13 oder Ubuntu 24.04 auf Linux amd64 mit systemd/cgroup v2, Python 3, curl, sha256sum und die System-CA-Zertifikate. Keine automatische Rechteerhöhung oder Installation von Abhängigkeiten.',note:'Nur nach Zustimmung zur Konto-, Dienst- und dauerhaften Identitätserstellung ausführen. Der Befehl lädt das offizielle Bootstrap über HTTPS, prüft dessen fest eingebetteten SHA-256 vor Python und verifiziert danach die Release-Provenienz und Artefakte. Commit und Prüfsumme müssen aus einer unabhängig vertrauenswürdigen Quelle stammen. Ein manipuliertes HTTP-Test-Dashboard kann den gesamten Befehl und seine Prüfsumme ersetzen.'}:{title:'Run the verified download as root in a local terminal',summary:'Requires Debian 13 or Ubuntu 24.04 on Linux amd64 with systemd/cgroup v2, Python 3, curl, sha256sum and the system CA bundle. No automatic elevation or dependency installation.',note:'Run only after approving account, service and persistent identity creation. The command downloads the official bootstrap over HTTPS, checks its source-pinned SHA-256 before Python, then verifies release provenance and artifacts. Obtain the commit and checksum from an independently trusted source. A tampered HTTP-test dashboard can replace the whole command and its checksum.'};
 const readAdminCopy=locale==='de'?{
  scope:'Eine gemeinsame Read-Admin-Zustimmung in diesem Terminal umfasst das unterstützte vollständige Inventar, Hostname und Schnittstellenadressen, Systemdienst-Protokollinhalte und Socket-Besitzer-Metadaten. CAP_SYS_PTRACE gibt dem separaten Helper weitreichenden Zugriff auf Prozessspeicher; die Beschränkung auf Metadaten beruht auf dem Programmcode.',
  http:'HTTP-Test: Freigegebene Inventar- und Protokolldaten werden im Klartext übertragen und können abgefangen oder gefälscht werden. Protokolle können Zugangsdaten, Tokens und persönliche Angaben enthalten. Die gemeinsame Terminal-Zustimmung muss dieses HTTP-Risiko ausdrücklich bestätigen.',
  prompt:'Lass dieses Terminal bis zum Abschluss geöffnet: die gemeinsame Read-Admin-Zustimmung prüfen, den Einladungsschlüssel nur im verdeckten Prompt eingeben und hier Fingerabdruck sowie Vergleichswert prüfen und das Gerät freigeben. Vor Freigabe und Aktivierung wird kein Inventar erfasst. Installation und tatsächliche Erfassungsabdeckung müssen danach geprüft werden.',
 }:{
  scope:'One combined read-admin approval in this terminal covers full supported inventory, hostname and interface addresses, system-service journal content, and socket-owner metadata. CAP_SYS_PTRACE gives the separate helper broad process-memory authority; metadata-only behavior is code policy.',
  http:'HTTP test: approved inventory and journal content travel in plaintext and can be intercepted or impersonated. Logs may contain credentials, tokens and personal information. The combined terminal approval must explicitly acknowledge this HTTP risk.',
  prompt:'Keep this terminal open until completion: review the combined read-admin approval, enter the invitation only at the hidden prompt, then compare the fingerprint and comparison value here and approve the device. No inventory is collected before approval and activation. Check installation and actual collection coverage afterward.',
 };
 const record=created?(currentItems.find(item=>item.invitationID===created.snapshot.invitationID)||created.snapshot):null;
 const reportDevice=record?matchingReportDevice(devices,record.approval.deviceID):undefined;
 const clearSecret=useCallback(()=>{if(secretInput.current)secretInput.current.value='';setSecret('');setRevealed(false);setCopied(false);},[]);
 useEffect(()=>{alive.current=true;const clear=()=>{clearSecret();setCollectionAcknowledged(false);setInsecureHTTPAcknowledged(false);if(operation.current){operation.current.abort();setPending(false);setUncertain(true);onUncertain();setError(t('Erstellung nicht bestätigt. Eine Einladung kann bereits bestehen. Status prüfen, diese Einladung bei Bedarf abbrechen und anschließend eine neue erstellen.'));}};const hidden=()=>{if(document.visibilityState==='hidden')clear();};window.addEventListener('pagehide',clear);document.addEventListener('visibilitychange',hidden);configurationSignal.addEventListener('abort',clear);if(configurationSignal.aborted)clear();return()=>{alive.current=false;if(secretInput.current)secretInput.current.value='';operation.current?.abort();downloads.current.forEach(url=>URL.revokeObjectURL(url));window.removeEventListener('pagehide',clear);document.removeEventListener('visibilitychange',hidden);configurationSignal.removeEventListener('abort',clear);};},[clearSecret,configurationSignal]);
 useEffect(()=>{if(transportAvailable())return;clearSecret();setCollectionAcknowledged(false);setInsecureHTTPAcknowledged(false);if(operation.current){operation.current.abort();operation.current=null;setPending(false);setUncertain(true);onUncertain();}},[macOS,insecureTest,clearSecret]);
 useEffect(()=>{if(!record||!secret)return;if(record.state!=='created'||deadlinePassed(record,currentTime())){clearSecret();return;}const remaining=enrollmentDeadline(record)*1000-(currentTime()??Infinity);const timer=window.setTimeout(clearSecret,Math.max(0,Math.min(remaining,2147483647)));return()=>window.clearTimeout(timer);},[record?.state,record?.deadlineAt,now,secret,currentTime,clearSecret]);
 const create=async()=>{
  if(configurationSignal.aborted||operation.current||created||uncertain||(!transportAvailable()||macOS&&!['basic-readonly-v1','macos-read-inventory-v1'].includes(collectionProfile))||currentTime()===null||(managed&&!collectionAcknowledged)||(windows&&insecureTest&&!insecureHTTPAcknowledged))return;const controller=new AbortController();operation.current=controller;const startedAt=captureClock();setPending(true);setError('');
  try{const next=await mutate<InvitationCreation>(`${enrollmentPath}/invitations`,{requestId:requestID(),platform,...(managed?{collectionAcknowledged:true}:{}),...(windows?{insecureHTTPAcknowledged:insecureTest&&insecureHTTPAcknowledged}:{})},controller.signal);if(!alive.current||controller.signal.aborted||configurationSignal.aborted)return;
   if(!transportAvailable()||next?.schemaVersion!=='tracebolt.enrollment-invitation.v2'||!validServerTime(next.serverNow)||!validSnapshot(next.snapshot)||next.snapshot.state!=='created'||next.snapshot.platform!==platform||next.snapshot.binding.collectionProfile!==collectionProfile||(windows&&next.snapshot.binding.profile!==(insecureTest?'http-test':'tls'))||(macOS&&next.snapshot.binding.profile!=='tls')||!validBootstrapSHA256(next.bootstrapSHA256)||typeof next.invitationSecret!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(next.invitationSecret))throw new Error('invalid invitation response');
   const bootstrap=publicBootstrap(next.bootstrap,next.snapshot,next.invitationSecret);if(!bootstrap)throw new Error('invalid public bootstrap');
   onCreated(next.snapshot,next.serverNow,startedAt);setCreated({snapshot:next.snapshot,bootstrap,bootstrapSHA256:next.bootstrapSHA256});setSecret(next.invitationSecret);
  }catch{if(alive.current&&!controller.signal.aborted){clearSecret();setUncertain(true);onUncertain();setError(t('Erstellung nicht bestätigt. Eine Einladung kann bereits bestehen. Status prüfen, diese Einladung bei Bedarf abbrechen und anschließend eine neue erstellen.'));void onRefresh();}}
  finally{if(alive.current&&!controller.signal.aborted){setPending(false);operation.current=null;}}
 };
 const close=()=>{clearSecret();if(operation.current){onUncertain();operation.current.abort();void onRefresh();}onClose();};
 const copy=async()=>{if(configurationSignal.aborted||!secret||!record)return;if(currentTime()===null||deadlinePassed(record,currentTime())){clearSecret();return;}if(!navigator.clipboard?.writeText)return;try{await navigator.clipboard.writeText(secret);if(alive.current&&!configurationSignal.aborted)setCopied(true);}catch{if(alive.current)setError(t('Kopieren nicht möglich. Den Schlüssel nach dem Anzeigen manuell übertragen.'));}};
 const copyPublicCommand=async()=>{if(configurationSignal.aborted||!publicCommand||!record||record.state!=='created'||currentTime()===null||deadlinePassed(record,currentTime())||!navigator.clipboard?.writeText)return;try{await navigator.clipboard.writeText(publicCommand);if(alive.current&&!configurationSignal.aborted)setCommandCopied(true);}catch{if(alive.current)setError(commandCopy.error);}};
 const download=()=>{if(configurationSignal.aborted||!created)return;const url=URL.createObjectURL(new Blob([JSON.stringify(created.bootstrap,null,2)+'\n'],{type:'application/json'}));downloads.current.add(url);const anchor=document.createElement('a');anchor.href=url;anchor.download=`tracebolt-bootstrap-${created.snapshot.invitationID}.json`;anchor.click();window.setTimeout(()=>{URL.revokeObjectURL(url);downloads.current.delete(url);},1000);};
 return <Dialog title={t('Gerät hinzufügen')} onClose={close} className="enrollment-dialog">
  <h2>{created?t('Einladung bereit'):t('Gerät hinzufügen')}</h2>
  {insecureTest&&<TransportWarning/>}
  <EnrollmentProgress platform={platform} state={record?.state} available={!record?now!==null:displayAvailable(record,now,reportDevice,reportsAvailable)}/>
  {!created?<>
   <p className="enrollment-intro">{t('Freigabe nach Schlüsselvergleich am Gerät.')}</p>
   <p className="enrollment-intro">{macOS?macCopy.selected:windows?windowsCopy.availability:locale==='de'?'Linux ausgewählt. Schließe diesen Dialog, um das Betriebssystem zu wechseln.':'Linux selected. Close this dialog to switch operating systems.'}</p>
   {windows&&<WindowsSetupPreparation insecureTest={insecureTest}/>}
   {macOS&&!macInventory&&<MacOSScope/>}
   {managed&&<div className="enrollment-consent">
    {macInventory?<MacOSScope inventory/>:windows?<><h3>{windowsCopy.title}</h3><p>{windowsCopy.scope}</p><p>{windowsCopy.bounds}</p><p>{windowsCopy.exclusions}</p></>:packageSource?<>
     <p>{shortConsent.scope}</p><p>{shortConsent.retention}</p><p>{consentCopy.fresh}</p>
     <details className="enrollment-context enrollment-advanced"><summary>{shortConsent.details}<ChevronDown size={14}/></summary><p>{consentCopy.scope}</p><p>{consentCopy.bounds}</p><p>{consentCopy.retention}</p><p>{consentCopy.exclusions}</p></details>
    </>:<><h3>{t('Betriebsinventar · Linux')}</h3><p>{t('Datenträger, Netzwerk, Dienste, Prozesse, Software und Ereignis-Metadaten. Namen und Mount-Pfade können persönliche oder sensible Angaben enthalten.')}</p><p>{t('Keine Befehlszeilen, Umgebungsvariablen oder Rohprotokolle. Kein KI-Export. Sichtbarkeit hängt vom Namensraum und den Berechtigungen des Agents ab.')}</p></>}
    <label className="check-field"><input type="checkbox" checked={collectionAcknowledged} disabled={pending||uncertain} onChange={event=>setCollectionAcknowledged(event.target.checked)}/><span>{macInventory?macInventoryCopy[locale].acknowledge:windows?windowsCopy.acknowledge:packageSource?consentCopy.acknowledge:t('Ich bestätige diese zusätzliche Erfassung für das neue Gerät.')}</span></label>
   </div>}
   {windows&&insecureTest&&<div className="enrollment-consent enrollment-windows-http"><p>{windowsCopy.http}</p><label className="check-field"><input type="checkbox" checked={insecureHTTPAcknowledged} disabled={pending||uncertain} onChange={event=>setInsecureHTTPAcknowledged(event.target.checked)}/><span>{windowsCopy.acknowledgeHTTP}</span></label></div>}
   {!windows&&<div className="enrollment-message"><Info size={16}/><span>{macOS?macCopy.release:completeSource&&!downloadAvailable?readAdminUnavailable:downloadAvailable?(locale==='de'?'Nach Erstellung: öffentlicher, quellseitig festgelegter Download-Befehl. Vor Ausführung Voraussetzungen und Dienstberechtigungen prüfen.':'After creation: a public source-pinned download command. Review prerequisites and service permissions before running it.') : completeSource?(locale==='de'?'Öffentliche Bootstrap-Konfiguration; die geprüften nativen Programme müssen separat vorbereitet werden.':'Public bootstrap configuration; reviewed native binaries must be prepared separately.'):t('Öffentliche Bootstrap-Datei. In diesem Build ist kein Installer enthalten.')}</span></div>}
   {error&&<div className="enrollment-message error" role="alert"><TriangleAlert size={16}/><span>{ui(error)}</span></div>}
   <div className="confirm-actions"><button className="button" onClick={close}>{t('Schließen')}</button>{uncertain?<button className="button" onClick={()=>void onRefresh()}><RefreshCw size={15}/>{t('Status prüfen')}</button>:<button className="button primary" disabled={pending||now===null||(managed&&!collectionAcknowledged)||(windows&&insecureTest&&!insecureHTTPAcknowledged)} onClick={()=>void create()}>{pending?<LoaderCircle size={15} className="spin"/>:<Plus size={15}/>} {t('Einladung erstellen')}</button>}</div>
  </>:<>
   <div className="enrollment-created-meta"><EnrollmentStatus item={record!} now={now} device={reportDevice} available={reportsAvailable}/><span>{record?.state==='activated'?`${locale==='de'?'Ursprüngliches Zertifikat gültig bis':'Original certificate valid until'} ${fullDate(enrollmentDate(enrollmentDeadline(record)))}`:t('Gültig bis {0}',{0:fullDate(enrollmentDate(enrollmentDeadline(record!)))})}</span></div>
   {record?.state==='created'?<div className="enrollment-install">
    {!macOS&&created.bootstrap.renewalPolicy&&<p role="status">{windows?(locale==='de'?'Automatische Zertifikatserneuerung benötigt passende geprüfte Setup-/Manager-Artefakte und eine eigene ungeprüfte lokale Zustimmung. Der tatsächliche Zertifikatswechsel bleibt nativ ungeprüft.':'Automatic certificate renewal needs matching reviewed Setup/manager artifacts and its own unchecked local approval. Actual certificate cutover remains natively unverified.'):(locale==='de'?'Automatische Zertifikatserneuerung: passender aktueller Quellbuild erforderlich. Die dauerhafte Freigabe wird am Gerät separat bestätigt.':'Automatic certificate renewal requires a matching current source build. Approve ongoing renewal separately on the device.')}</p>}
    {macOS&&<MacOSSourceInstructions inventory={macInventory} renewable={created.bootstrap.renewalPolicy==='same-key-v1'}/>}
    {windows&&created.bootstrap.collectionProfile==='windows-inventory-v1'&&<WindowsSetupInstructions/>}
    {publicCommand?<div className="enrollment-public-command">
     <h3>{downloadCommand?downloadCopy.title:commandCopy.title}</h3>
     <p>{downloadCommand?downloadCopy.summary+(completeSource?(locale==='de'?' Read-Admin benötigt einen Kernel ab Version 6.5.':' Read-admin requires kernel 6.5 or newer.'):''):locale==='de'?'Benötigt bereits geprüfte lokale Programme und das Quellarchiv. Dieser Befehl lädt keine Programme herunter.':'Requires reviewed local binaries and the source archive already in place. This command does not download binaries.'}</p>
     {downloadCommand&&<p>{downloadCopy.note}</p>}
     {downloadCommand&&completeSource&&<><p>{readAdminCopy.scope}</p>{created.bootstrap.profile==='http-test'&&<p>{readAdminCopy.http}</p>}<p>{readAdminCopy.prompt}</p></>}
     {typeof navigator.clipboard?.writeText==='function'&&<button className="button primary" disabled={configurationSignal.aborted||record?.state!=='created'||now===null||Boolean(record&&deadlinePassed(record,now))} onClick={()=>void copyPublicCommand()}><Copy size={15}/>{commandCopied?commandCopy.copied:commandCopy.copy}</button>}
     <details className="enrollment-context enrollment-advanced" open={typeof navigator.clipboard?.writeText!=='function'}><summary>{locale==='de'?'Befehl und technische Voraussetzungen':'Command and technical prerequisites'}<ChevronDown size={14}/></summary>{!downloadCommand&&<p>{commandCopy.note}</p>}{!completeSource&&<p>{commandCopy.prompt}</p>}<pre><code>{publicCommand}</code></pre></details>
    </div>:<div>{completeSource&&!downloadAvailable&&<p role="status">{readAdminUnavailable}</p>}<h3>{t('Öffentliche Konfiguration übertragen')}</h3><p>{t('Die Datei enthält Ziel und öffentliche Vertrauensdaten, keinen Einladungsschlüssel.')}</p></div>}
    <button className="button" onClick={download}><ArrowDownToLine size={15}/>{t('Bootstrap-Datei herunterladen')}</button>
    <h3>{t('Einladung im verdeckten Client-Prompt eingeben')}</h3><p>{t('Nicht in URLs, Befehlsargumente oder Umgebungsvariablen einfügen.')}</p>
    {secret&&record?.state==='created'&&!deadlinePassed(record,now)?<><div className="enrollment-secret"><KeyRound size={16}/><input ref={bindSecretInput} type={revealed?'text':'password'} aria-label={t('Einmaliger Einladungsschlüssel')} value={secret} readOnly autoComplete="off" spellCheck={false}/><button className="icon-button" aria-label={revealed?t('Einladungsschlüssel verbergen'):t('Einladungsschlüssel anzeigen')} onClick={()=>{if(configurationSignal.aborted||!record||currentTime()===null||deadlinePassed(record,currentTime()))clearSecret();else setRevealed(!revealed);}}>{revealed?<EyeOff size={16}/>:<Eye size={16}/>}</button>{typeof navigator.clipboard?.writeText==='function'&&<button className="icon-button" aria-label={t('Einladungsschlüssel kopieren')} onClick={()=>void copy()}>{copied?<Check size={16}/>:<Copy size={16}/>}</button>}</div><small className="enrollment-secret-note">{copied?t('Kopiert. Zwischenablage nach Verwendung leeren.'):t('Nur jetzt verfügbar. Beim Schließen oder Verlassen der Ansicht wird der Schlüssel entfernt.')}</small></>:<div className="enrollment-message"><Info size={15}/><span>{t('Einladungsschlüssel nicht mehr verfügbar. Falls nicht übertragen: Einladung abbrechen und neu erstellen.')}</span></div>}
    <p className="enrollment-next-step">{locale==='de'?'Danach hier den Schlüssel vergleichen und das Gerät freigeben. Vor Freigabe und Aktivierung wird kein Inventar erfasst.':'Then return here to compare the key and approve the device. No inventory is collected before approval and activation.'}</p>
   </div>:<>
    {record?.state==='claimed_pending'&&<p className="enrollment-next-step">{locale==='de'?'Das Gerät wartet auf deine Freigabe. Vergleiche jetzt Fingerabdruck und Vergleichswert am Gerät.':'The device is waiting for your approval. Compare its fingerprint and comparison value now.'}</p>}
    {record&&<ConnectionNextStep state={record.state} available={displayAvailable(record,now,reportDevice,reportsAvailable)}/>}
    {record&&terminal(record.state)&&<p className="enrollment-next-step">{t('Dieser Eintrag ist beendet und bleibt zur Nachvollziehbarkeit erhalten.')}</p>}
   </>}
   <details className="enrollment-context"><summary>{t('Ziel & Profil')}<ChevronDown size={14}/></summary><dl><div><dt>{t('Manager')}</dt><dd>{created.bootstrap.enrollmentOrigin}</dd></div><div><dt>{t('Agent-Ziel')}</dt><dd>{created.bootstrap.agentOrigin}</dd></div><div><dt>{t('Erfassungsprofil')}</dt><dd>{created.bootstrap.collectionProfile}</dd></div><div><dt>{t('Einladung')}</dt><dd>{created.snapshot.invitationID}</dd></div></dl></details>
   {error&&<div className="enrollment-message error" role="alert"><TriangleAlert size={15}/><span>{ui(error)}</span></div>}
   <div className="confirm-actions"><button className="button" onClick={()=>void onCheckStatus()} disabled={refreshing}><RefreshCw size={15}/>{t('Status prüfen')}</button><button className="button primary" onClick={()=>{clearSecret();onReview(created.snapshot.invitationID);}}>{record?.state==='claimed_pending'?t('Schlüssel vergleichen'):t('Einladung ansehen')}<ArrowRight size={15}/></button></div>
  </>}
 </Dialog>;
}

function ReviewEnrollment({refreshing,onCheckStatus,reportDevice,reportsAvailable,enrollmentPath,configurationSignal,now,currentTime,onUncertain,blocked,item,onClose,onUpdated,onRefresh,onDevice}:{refreshing:boolean;onCheckStatus:()=>Promise<void>;reportDevice?:Device;reportsAvailable:boolean;enrollmentPath:string;configurationSignal:AbortSignal;now:number|null;currentTime:()=>number|null;onUncertain:(mutation:ReviewMutation)=>void;blocked:boolean;item:EnrollmentSnapshot;onClose:()=>void;onUpdated:(next:EnrollmentSnapshot)=>void;onRefresh:()=>Promise<void>;onDevice?:()=>void}) {
 const operator=useOperator(),[locale]=useLocale();
 const latestTransport=useRef({platform:item.platform,insecureTest:Boolean(operator?.insecureTestMode)});latestTransport.current={platform:item.platform,insecureTest:Boolean(operator?.insecureTestMode)};
 const transportAvailable=()=>latestTransport.current.platform!=='darwin'||macOSTransportAvailable(latestTransport.current.insecureTest);
 const transportBlocked=!transportAvailable();
 const [confirmedFor,setConfirmedFor]=useState<string|null>(null),[terminationFor,setTerminationFor]=useState<string|null>(null),[pending,setPending]=useState(false),[error,setError]=useState('');
 const alive=useRef(true),operation=useRef<AbortController|null>(null),operationDetails=useRef<ReviewMutation|null>(null);
 const recordUncertain=()=>{if(operationDetails.current){onUncertain(operationDetails.current);operationDetails.current=null;}};
 const interrupt=()=>{if(operation.current){recordUncertain();operation.current.abort();operation.current=null;}};
 useEffect(()=>{setCompared(false);setTerminating(false);setError('');},[item.revision,item.claim.keyFingerprint,item.claim.comparisonCode]);
 useEffect(()=>{if(now===null||deadlinePassed(item,now))setCompared(false);},[item,now]);
 useEffect(()=>{alive.current=true;const clear=()=>{setCompared(false);setTerminating(false);interrupt();setPending(false);};const hidden=()=>{if(document.visibilityState==='hidden')clear();};window.addEventListener('pagehide',clear);document.addEventListener('visibilitychange',hidden);configurationSignal.addEventListener('abort',clear);if(configurationSignal.aborted)clear();return()=>{alive.current=false;interrupt();window.removeEventListener('pagehide',clear);document.removeEventListener('visibilitychange',hidden);configurationSignal.removeEventListener('abort',clear);};},[configurationSignal]);
 useEffect(()=>{if(!transportBlocked)return;setCompared(false);setTerminating(false);if(operation.current){interrupt();setPending(false);}},[transportBlocked]);
 const action=terminationAction(item.state);
 const comparisonContext=`${item.invitationID}:${item.revision}:${item.claim.keyFingerprint}:${item.claim.comparisonCode}`;
 const compared=!transportBlocked&&confirmedFor===comparisonContext&&now!==null&&!deadlinePassed(item,now),terminating=!transportBlocked&&terminationFor===`${item.revision}:${action}`;
 function setCompared(value:boolean){setConfirmedFor(value&&transportAvailable()?comparisonContext:null);}
 function setTerminating(value:boolean){setTerminationFor(value&&transportAvailable()?`${item.revision}:${action}`:null);}
 const write=async(kind:'approve'|'terminate')=>{
  if(blocked||reviewIsFenced(item)||!transportAvailable()||configurationSignal.aborted||operation.current||(kind==='approve'&&(currentTime()===null||deadlinePassed(item,currentTime())||!compared||item.state!=='claimed_pending'||!comparisonValid(item)))||(kind==='terminate'&&(!action||!terminating)))return;
  const controller=new AbortController();operation.current=controller;const baseline=item;operationDetails.current={item:baseline,kind};setPending(true);setError('');
  try{const next=await mutate<EnrollmentSnapshot>(`${enrollmentPath}/${encodeURIComponent(baseline.invitationID)}/${kind}`,kind==='approve'?{requestId:requestID(),expectedRevision:baseline.revision,expectedKeyFingerprint:baseline.claim.keyFingerprint}:{requestId:requestID(),expectedRevision:baseline.revision,action},controller.signal);if(!alive.current||controller.signal.aborted||configurationSignal.aborted)return;
   if(!transportAvailable()){setCompared(false);setTerminating(false);recordUncertain();return;}
   if(!validSnapshot(next)||next.invitationID!==baseline.invitationID||next.revision<=baseline.revision||next.platform!==baseline.platform||(['instanceID','origin','profile','collectionProfile','issuerFingerprint'] as const).some(key=>next.binding[key]!==baseline.binding[key])||next.claim.keyFingerprint!==baseline.claim.keyFingerprint||next.claim.comparisonCode!==baseline.claim.comparisonCode||next.state!==(kind==='approve'?'approved':action))throw new Error('invalid committed enrollment snapshot');setCompared(false);setTerminating(false);onUpdated(next);
  }catch(err){if(alive.current&&!controller.signal.aborted){setCompared(false);setTerminating(false);setError(actionFailure(err));recordUncertain();void onRefresh();}}
  finally{if(alive.current&&!controller.signal.aborted){operation.current=null;operationDetails.current=null;setPending(false);}}
 };
 const close=()=>{if(operation.current){interrupt();void onRefresh();}onClose();};
 const reportAvailable=reportsAvailable&&!transportBlocked&&!error&&!pending&&!configurationSignal.aborted;
 const expiryVisible=displayExpired(item,now,reportDevice,reportAvailable);
 const currentExpiry=reportAvailable?enrollmentReportIdentity(item,reportDevice,now).currentExpiry:null;
 return <Dialog title={t('Einladung prüfen')} onClose={close} className="enrollment-dialog"><h2>{item.state==='claimed_pending'?t('Schlüssel vergleichen'):t('Einladung')}</h2>{item.binding.profile==='http-test'&&<TransportWarning/>}<EnrollmentProgress platform={item.platform} state={item.state} available={displayAvailable(item,now,reportDevice,reportAvailable)}/><ConnectionNextStep state={item.state} available={displayAvailable(item,now,reportDevice,reportAvailable)}/><EnrollmentReport item={item} device={reportDevice} now={now} available={reportAvailable}/><div className="enrollment-created-meta"><EnrollmentStatus item={item} now={now} device={reportDevice} available={reportAvailable}/><span>{item.platform==='linux'?'Linux':item.platform==='windows'?'Windows':item.platform==='darwin'?'macOS':item.platform}</span></div>{transportBlocked&&<div className="enrollment-message error" role="status"><Info size={16}/>{locale==='de'?'macOS-Enrollment-Änderungen erfordern HTTPS und eine sichere Operator-Sitzung.':'macOS enrollment changes require HTTPS and a secure operator session.'}</div>}{blocked&&<div className="enrollment-message error" role="status">{locale==='de'?'Die letzte Aktion ist nicht bestätigt. Status prüfen; solange der Ausgang ungeklärt ist, sind weitere Aktionen gesperrt.':'The last action is unconfirmed. Check status; further actions remain blocked while its outcome is unknown.'}</div>}{now===null&&<div className="enrollment-message" role="status"><Info size={16}/>{t('Serverzeit nicht bestätigt. Status aktualisieren.')}</div>}{expiryVisible&&<div className="enrollment-message error" role="status"><Info size={16}/>{t('Die Serverfrist ist abgelaufen. Keine Freigabe möglich; Status aktualisieren.')}</div>}{item.state==='claimed_pending'?<><p className="enrollment-intro">{t('Vollständigen Fingerabdruck und Vergleichswert direkt am Gerät prüfen. Diese Anzeige allein bestätigt keine Identität.')}</p><div className="enrollment-fingerprint"><span><Fingerprint size={16}/>{t('Öffentlicher Schlüssel · SHA-256')}</span><code>{groupedHex(item.claim.keyFingerprint)}</code></div><div className="enrollment-comparison"><span>{t('Kontextgebundener Vergleichswert')}</span><code>{groupedHex(item.claim.comparisonCode)}</code></div>{comparisonValid(item)?<label className="check-field enrollment-approval"><input type="checkbox" checked={compared} disabled={blocked||transportBlocked||pending||now===null||deadlinePassed(item,now)} onChange={event=>setCompared(event.target.checked)}/><span>{t('Ich habe den vollständigen Fingerabdruck und Vergleichswert am Gerät abgeglichen.')}</span></label>:<div className="enrollment-message error" role="alert"><TriangleAlert size={16}/>{t('Vergleichsdaten unvollständig. Keine Freigabe möglich.')}</div>}</>:<div className="enrollment-message"><Info size={16}/><span>{item.state==='created'?t('Der Schlüssel wurde nur bei Erstellung angezeigt. Ein Client muss diese Einladung zuerst beanspruchen.'):terminal(item.state)?t('Dieser Eintrag ist beendet und bleibt zur Nachvollziehbarkeit erhalten.'):t('Freigabe und Aktivierung bestätigen keine laufende Erfassung oder Gerätesicherheit.')}</span></div>}<details className="enrollment-context"><summary>{t('Ziel & Profil')}<ChevronDown size={14}/></summary><dl><div><dt>{t('Einladung')}</dt><dd>{item.invitationID} · {t('Revision {0}',{0:item.revision})}</dd></div><div><dt>{t('Manager')}</dt><dd>{item.binding.origin}</dd></div><div><dt>{t('Erfassungsprofil')}</dt><dd>{item.binding.collectionProfile}</dd></div><div><dt>{t('Erstellt')}</dt><dd>{fullDate(enrollmentDate(item.createdAt))}</dd></div><div><dt>{item.state==='activated'?(locale==='de'?'Ursprüngliches Zertifikat gültig bis':'Original certificate valid until'):t('Gültig bis')}</dt><dd>{fullDate(enrollmentDate(enrollmentDeadline(item)))}</dd></div>{item.state==='activated'&&currentExpiry&&<div><dt>{locale==='de'?'Aktuelles Zertifikat gültig bis':'Current certificate valid until'}</dt><dd>{fullDate(currentExpiry)}</dd></div>}{item.approval.deviceID&&<div><dt>{t('Gerätekennung')}</dt><dd>{item.approval.deviceID}</dd></div>}</dl></details>{error&&<div className="enrollment-message error" role="alert"><TriangleAlert size={16}/>{ui(error)}</div>}{terminating&&<div className="enrollment-terminate" role="group" aria-label={t('Beendigung bestätigen')}><strong>{action==='revoked'?t('Identität wirklich widerrufen?'):action==='rejected'?t('Gerät wirklich ablehnen?'):t('Einladung wirklich abbrechen?')}</strong><p>{t('Diese Entscheidung beendet den Eintrag. Er kann nicht erneut aktiviert werden.')}</p><div className="confirm-actions"><button className="button" disabled={pending} onClick={()=>setTerminating(false)}>{t('Zurück')}</button><button className="button danger-button" disabled={blocked||transportBlocked||pending} onClick={()=>void write('terminate')}>{pending?<LoaderCircle size={15} className="spin"/>:<X size={15}/>} {t('Beendigung bestätigen')}</button></div></div>}<div className="confirm-actions enrollment-review-actions">{action&&!terminating&&<button className="text-button danger-text" disabled={blocked||transportBlocked||pending} onClick={()=>setTerminating(true)}>{action==='revoked'?t('Identität widerrufen'):action==='rejected'?t('Ablehnen'):t('Einladung abbrechen')}</button>}<button className="button" onClick={()=>void onCheckStatus()} disabled={pending||refreshing}><RefreshCw size={15}/>{t('Status prüfen')}</button>{onDevice&&<button className="button" onClick={onDevice} disabled={pending}>{t('Gerät öffnen')}<ArrowRight size={15}/></button>}{item.state==='claimed_pending'&&!terminating&&<button className="button primary" disabled={blocked||transportBlocked||!compared||pending||!comparisonValid(item)||now===null||deadlinePassed(item,now)} onClick={()=>void write('approve')}>{pending?<LoaderCircle size={15} className="spin"/>:<ShieldCheck size={15}/>} {t('Gerät freigeben')}</button>}</div></Dialog>;
}
