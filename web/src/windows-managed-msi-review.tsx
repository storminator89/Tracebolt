import { useEffect, useRef, useState } from 'react';
import { useLocale } from './i18n';
import { validManagedReview, validReusableManagedReview, type ManagedReview, type ReusableManagedReview } from './windows-managed-msi-types';

export type MSIReview = ManagedReview | ReusableManagedReview;
// A WebCrypto digest cannot be canceled. Keep the bound across component remounts.
let hashInFlight = false;
export async function boundedSelectedFileDigest(file:File,maxBytes=128*1048576):Promise<string>{
 if(hashInFlight||!Number.isSafeInteger(file.size)||file.size<1||file.size>maxBytes)throw Error();
 hashInFlight=true;
 try{const bytes=await file.arrayBuffer();if(bytes.byteLength!==file.size)throw Error();const digest=await crypto.subtle.digest('SHA-256',bytes);return `sha256:${Array.from(new Uint8Array(digest),b=>b.toString(16).padStart(2,'0')).join('')}`}finally{hashInFlight=false}
}
const copy = {
 en: { file:'MSI file', name:'Package name', version:'MSI version', details:'Package identity & review evidence', expert:'Advanced: import review JSON', choose:'Choose…', architecture:'Reviewed package type', x64:'x64 machine MSI', product:'ProductCode', package:'PackageCode', terms:'Terms-review SHA-256', reference:'Review reference', native:'Native-acceptance SHA-256', publisher:'Publisher review', publisherDigest:'Publisher-evidence SHA-256', unsigned:'Unsigned', unverified:'Unverified', help:'Copy identity and evidence from the completed package review. This browser reads only the selected file’s size and hash; it does not inspect MSI metadata or verify a publisher or native acceptance.', format:'Use {UPPERCASE-GUID} package codes, a three-part MSI version (0–255.0–255.0–65535), and sha256: followed by 64 lowercase hex digits for evidence.', missing:'Still needed', advanced:'identity/evidence fields in details', invalid:'Check identity, version and evidence formats.', select:'Choose a .msi file between 512 bytes and 128 MiB.', hashing:'Reading selected file hash…', local:'File hash ready. Nothing has been uploaded.', imported:'Imported exact review. Select its exact MSI for upload.', stale:'The file changed. Enter the review for this file again.', importError:'Choose a valid review JSON file up to 4 KiB.', ready:'Review fields complete. Nothing approved or uploaded.', copy:'Copy full value', copied:'Copied', failed:'Copy unavailable; select the full value below.', full:'Full value', evidenceFile:'Or hash the completed review file (up to 2 MiB)', evidenceHelp:'Choose the existing, completed evidence record for this exact package. Hashing a file does not verify its contents or create proof of acceptance.', evidenceError:'Choose a non-empty evidence file up to 2 MiB, or enter its existing SHA-256.', wait:'A selected file is still being read. Choose again after it finishes.' },
 de: { file:'MSI-Datei', name:'Paketname', version:'MSI-Version', details:'Paketidentität & Prüfnachweise', expert:'Erweitert: Prüf-JSON importieren', choose:'Auswählen…', architecture:'Geprüfter Pakettyp', x64:'x64-Geräte-MSI', product:'ProductCode', package:'PackageCode', terms:'SHA-256 der Bedingungsprüfung', reference:'Prüfverweis', native:'SHA-256 der nativen Abnahme', publisher:'Herausgeberprüfung', publisherDigest:'SHA-256 des Herausgebernachweises', unsigned:'Unsigniert', unverified:'Nicht verifiziert', help:'Identität und Nachweise aus der abgeschlossenen Paketprüfung übernehmen. Der Browser liest nur Größe und Hash der gewählten Datei; er prüft weder MSI-Metadaten noch Herausgeber oder native Abnahme.', format:'Paketcodes als {GROSSBUCHSTABEN-GUID}, dreiteilige MSI-Version (0–255.0–255.0–65535) und Nachweise als sha256: mit 64 kleinen Hex-Zeichen eingeben.', missing:'Noch erforderlich', advanced:'Identitäts-/Nachweisfelder in Details', invalid:'Formate von Identität, Version und Nachweisen prüfen.', select:'Eine .msi-Datei zwischen 512 Byte und 128 MiB auswählen.', hashing:'Hash der gewählten Datei wird gelesen…', local:'Datei-Hash bereit. Noch nichts hochgeladen.', imported:'Exakte Prüfung importiert. Zum Hochladen die zugehörige MSI auswählen.', stale:'Datei geändert. Die Prüfung für diese Datei erneut eingeben.', importError:'Eine gültige Prüf-JSON-Datei bis 4 KiB auswählen.', ready:'Prüffelder vollständig. Noch nichts genehmigt oder hochgeladen.', copy:'Vollständigen Wert kopieren', copied:'Kopiert', failed:'Kopieren nicht verfügbar; vollständigen Wert unten markieren.', full:'Vollständiger Wert', evidenceFile:'Oder abgeschlossene Prüfdatei hashen (bis 2 MiB)', evidenceHelp:'Den vorhandenen, abgeschlossenen Nachweis für genau dieses Paket wählen. Ein Datei-Hash prüft weder den Inhalt noch erzeugt er einen Abnahmenachweis.', evidenceError:'Eine nicht leere Nachweisdatei bis 2 MiB wählen oder ihren vorhandenen SHA-256 eingeben.', wait:'Eine gewählte Datei wird noch gelesen. Danach erneut auswählen.' },
};
type Fields = {name:string;version:string;productCode:string;packageCode:string;architecture:string;termsReviewDigest:string;reviewReference:string;nativeAcceptanceDigest:string;publisherStatus:string;publisherEvidenceDigest:string};
const blank = ():Fields => ({name:'',version:'',productCode:'',packageCode:'',architecture:'',termsReviewDigest:'',reviewReference:'',nativeAcceptanceDigest:'',publisherStatus:'',publisherEvidenceDigest:''});
const fromReview = (review:MSIReview):Fields => ({...blank(),...review.package,nativeAcceptanceDigest:review.nativeAcceptanceDigest,...('publisherStatus' in review?{publisherStatus:review.publisherStatus,publisherEvidenceDigest:review.publisherEvidenceDigest}:{})});

/** Display abbreviation only: request bodies always retain the complete value. */
export function MSIReference({value}:{value:string}) {
 const [locale]=useLocale(),c=copy[locale],[status,setStatus]=useState('');
 return <details className="managed-msi-reference"><summary>{value.length>28?`${value.slice(0,16)}…${value.slice(-8)}`:value}</summary><span>{value}</span><button type="button" className="text-button" aria-label={c.copy} onClick={async()=>{try{await navigator.clipboard.writeText(value);setStatus(c.copied)}catch{setStatus(c.failed)}}}>{c.copy}</button>{status&&<small role="status">{status}</small>}</details>;
}

/** Builds the unchanged strict request. File selection never sends bytes or grants permission. */
export function ManagedMSIReviewForm({reusable,disabled=false,fileLabel,importLabel,onChange}:{reusable:boolean;disabled?:boolean;fileLabel?:string;importLabel:string;onChange:(file:File|null,review:MSIReview|null)=>void}) {
 const [locale]=useLocale(),c=copy[locale];
 const [fields,setFields]=useState(blank),[file,setFile]=useState<File|null>(null),[hash,setHash]=useState(''),[imported,setImported]=useState<MSIReview|null>(null),[busy,setBusy]=useState(false),[notice,setNotice]=useState('');
 const generation=useRef(0),live=useRef(true),callback=useRef(onChange),input=useRef<HTMLInputElement|null>(null);callback.current=onChange;
 const validate=reusable?validReusableManagedReview:validManagedReview;
 const value:unknown=imported??{package:{sha256:hash,size:file?.size??0,productCode:fields.productCode,packageCode:fields.packageCode,version:fields.version,architecture:fields.architecture,name:fields.name,termsReviewDigest:fields.termsReviewDigest,reviewReference:fields.reviewReference},nativeAcceptanceDigest:fields.nativeAcceptanceDigest,...(reusable?{publisherStatus:fields.publisherStatus,publisherEvidenceDigest:fields.publisherEvidenceDigest}:{})};
 const valid=validate(value),serialized=valid?JSON.stringify(value):'';
 useEffect(()=>{callback.current(file,serialized?JSON.parse(serialized) as MSIReview:null)},[file,serialized]);
 useEffect(()=>{live.current=true;return()=>{live.current=false;generation.current++}},[]);
 const invalidate=()=>{generation.current++;callback.current(null,null);setImported(null)};
 const change=(key:keyof Fields,text:string)=>{invalidate();setFields(previous=>({...previous,[key]:text}));setNotice('')};
 const chooseFile=async(next:File|undefined)=>{
  const expected=imported;
  invalidate();setHash('');setFile(null);setFields(blank());setNotice(file||imported?c.stale:'');
  if(hashInFlight){setNotice(c.wait);return}
  if(!next||!/\.msi$/i.test(next.name)||!Number.isSafeInteger(next.size)||next.size<512||next.size>128*1048576){setNotice(c.select);return}
  const token=generation.current;setBusy(true);
  try{const nextHash=await boundedSelectedFileDigest(next);if(live.current&&token===generation.current){setFile(next);setHash(nextHash);if(expected&&expected.package.sha256===nextHash&&expected.package.size===next.size){setFields(fromReview(expected));setImported(expected);setNotice('')}}}catch{if(live.current&&token===generation.current)setNotice(c.select)}finally{if(live.current)setBusy(false)}
 };
 const chooseEvidence=async(key:'termsReviewDigest'|'nativeAcceptanceDigest'|'publisherEvidenceDigest',next:File|undefined)=>{
  invalidate();setFields(previous=>({...previous,[key]:''}));setNotice('');
  if(hashInFlight){setNotice(c.wait);return}
  if(!next||!Number.isSafeInteger(next.size)||next.size<1||next.size>2*1048576){setNotice(c.evidenceError);return}
  const token=generation.current;setBusy(true);
  try{const digest=await boundedSelectedFileDigest(next,2*1048576);if(live.current&&token===generation.current)setFields(previous=>({...previous,[key]:digest}))}catch{if(live.current&&token===generation.current)setNotice(c.evidenceError)}finally{if(live.current)setBusy(false)}
 };
 const importReview=async(next:File|undefined)=>{
  const selected=file,selectedHash=hash;invalidate();setFields(blank());setNotice('');const token=generation.current;
  if(!next||next.size===0||next.size>4096){setNotice(c.importError);return}
  try{const raw=await next.text();if(new TextEncoder().encode(raw).length>4096)throw Error();const review:unknown=JSON.parse(raw);if(live.current&&token===generation.current){if(!validate(review))throw Error();if(selected&&(review.package.sha256!==selectedHash||review.package.size!==selected.size)){setFile(null);setHash('');if(input.current)input.current.value=''}setFields(fromReview(review));setImported(review)}}catch{if(live.current&&token===generation.current)setNotice(c.importError)}
 };
 const labels:Record<keyof Fields,string>={name:c.name,version:c.version,productCode:c.product,packageCode:c.package,architecture:c.architecture,termsReviewDigest:c.terms,reviewReference:c.reference,nativeAcceptanceDigest:c.native,publisherStatus:c.publisher,publisherEvidenceDigest:c.publisherDigest};
 const required=(Object.keys(labels) as Array<keyof Fields>).filter(key=>reusable||!['publisherStatus','publisherEvidenceDigest'].includes(key));
 const missing=required.filter(key=>!fields[key]),advancedMissing=missing.filter(key=>!['name','version'].includes(key));
 const evidence=(key:'termsReviewDigest'|'nativeAcceptanceDigest'|'publisherEvidenceDigest')=><div className="managed-msi-evidence-field">{text(key,71)}<label>{c.evidenceFile}<input type="file" aria-label={`${labels[key]}: ${c.evidenceFile}`} onChange={event=>void chooseEvidence(key,event.target.files?.[0])}/></label></div>;
 const text=(key:keyof Fields,max:number)=> <label key={key}>{labels[key]}<input type="text" value={fields[key]} maxLength={max} autoComplete="off" spellCheck={false} onChange={event=>change(key,event.target.value)}/></label>;
 return <div className="managed-msi-review-form"><fieldset disabled={disabled||busy}>
  <label className="managed-msi-review-file">{fileLabel??c.file}<input ref={input} type="file" accept=".msi" onChange={event=>void chooseFile(event.target.files?.[0])}/></label>
  <div className="managed-msi-review-basics">{text('name',120)}{text('version',15)}</div>
  <details className="managed-msi-review-advanced"><summary>{c.details}{advancedMissing.length>0?` · ${advancedMissing.length}`:''}</summary><p>{c.help}</p><p>{c.format}</p><p>{c.evidenceHelp}</p><div className="managed-msi-review-grid">
   {text('productCode',38)}{text('packageCode',38)}
   <label>{c.architecture}<select value={fields.architecture} onChange={event=>change('architecture',event.target.value)}><option value="">{c.choose}</option><option value="amd64">{c.x64}</option></select></label>
   {text('reviewReference',160)}{evidence('termsReviewDigest')}{evidence('nativeAcceptanceDigest')}
   {reusable&&<><label>{c.publisher}<select value={fields.publisherStatus} onChange={event=>change('publisherStatus',event.target.value)}><option value="">{c.choose}</option><option value="unsigned">{c.unsigned}</option><option value="unverified">{c.unverified}</option></select></label>{evidence('publisherEvidenceDigest')}</>}
  </div></details>
  <details><summary>{c.expert}</summary><label>{importLabel}<input type="file" accept=".json" onChange={event=>void importReview(event.target.files?.[0])}/></label></details>
 </fieldset>
 {busy?<p role="status">{c.hashing}</p>:file&&<p>{file.name} · {(file.size/1048576).toFixed(2)} MiB · {c.local}</p>}
 {hash&&<MSIReference value={hash}/>}
 {imported&&<p>{c.imported}</p>}{notice&&<p role="status">{notice}</p>}
 <p className="managed-msi-review-guidance">{valid?c.ready:`${c.missing}: ${[...(!file&&!imported?[c.file]:[]),...missing.filter(key=>['name','version'].includes(key)).map(key=>labels[key]),...(advancedMissing.length?[`${advancedMissing.length} ${c.advanced}`]:[])].join(', ')||c.invalid}`}</p>
 </div>;
}
