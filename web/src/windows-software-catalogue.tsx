import { useLocale } from './i18n';
import { sameSoftware } from './windows-software-jobs-types';
import { validManagedArtifact, type ManagedArtifactView, type ReusableManagedReview } from './windows-managed-msi-types';

export type SoftwareChoice=ReusableManagedReview&{artifactId:string};
export type SoftwareChoiceState='ready'|'upload'|'blocked';
/** Durable reviewed metadata only. The rolling ledger is neither payload custody nor permission. */
export function managedSoftwareChoices(view:ManagedArtifactView|null):SoftwareChoice[]{
 if(!view?.reusable||!validManagedArtifact(view))return [];
 const candidates:SoftwareChoice[]=[];
 if(view.package)candidates.push({artifactId:view.artifactId,package:view.package,nativeAcceptanceDigest:view.nativeAcceptanceDigest,publisherStatus:view.publisherStatus!,publisherEvidenceDigest:view.publisherEvidenceDigest!});
 for(const row of [...(view.recent??[])].reverse())candidates.push({artifactId:row.artifactId,package:row.package,nativeAcceptanceDigest:row.nativeAcceptanceDigest,publisherStatus:row.publisherStatus,publisherEvidenceDigest:row.publisherEvidenceDigest});
 return candidates.filter((row,index)=>!candidates.slice(0,index).some(old=>sameSoftwareChoice(old,row)));
}
export function sameSoftwareChoice(a:ReusableManagedReview,b:ReusableManagedReview):boolean{return sameSoftware(a.package,b.package)&&a.nativeAcceptanceDigest===b.nativeAcceptanceDigest&&a.publisherStatus===b.publisherStatus&&a.publisherEvidenceDigest===b.publisherEvidenceDigest}
export function softwareChoiceState(choice:SoftwareChoice,view:ManagedArtifactView|null,blocked=false):SoftwareChoiceState{
 if(blocked||!view?.reusable||!validManagedArtifact(view)||view.state==='intervention_required')return 'blocked';
 const exact=!!view.package&&view.artifactId===choice.artifactId&&sameSoftwareChoice(choice,{package:view.package,nativeAcceptanceDigest:view.nativeAcceptanceDigest,publisherStatus:view.publisherStatus!,publisherEvidenceDigest:view.publisherEvidenceDigest!});
 if(view.state==='uploaded'&&exact)return 'ready';
 if(view.state==='empty'||view.state==='retired'||view.state==='upload_incomplete'&&exact)return 'upload';
 return 'blocked';
}
export const softwareCatalogueCopy={
 en:{title:'Recent packages',ready:'Ready here',upload:'Upload required',blocked:'Blocked',use:'Use saved review',selected:'Review selected',notice:'Reviewed metadata only. One active payload, up to 128 MiB. Every device still needs its own delivery and installation approval.',bounds:'Current review and eight recent retired records. Repeated exact reviews appear once; older choices can leave this list as history advances.',missing:'Choose the exact MSI bytes below. Its saved review never replaces the file.',occupied:'Retire the current shared payload explicitly before switching packages. Unconfirmed work blocks replacement.',empty:'Package choices appear after a reviewed upload.',publisher:'Publisher review',unsigned:'Unsigned',unverified:'Unverified'},
 de:{title:'Letzte Pakete',ready:'Hier bereit',upload:'Upload erforderlich',blocked:'Blockiert',use:'Gespeicherte Prüfung verwenden',selected:'Prüfung ausgewählt',notice:'Nur geprüfte Metadaten. Ein aktiver Paketbestand, höchstens 128 MiB. Jedes Gerät braucht weiterhin eine eigene Verteilungs- und Installationsfreigabe.',bounds:'Aktuelle Prüfung und acht zuletzt stillgelegte Einträge. Gleiche Prüfungen erscheinen einmal; ältere Auswahlen können aus dieser Liste herausfallen.',missing:'Unten die exakten MSI-Bytes auswählen. Die gespeicherte Prüfung ersetzt die Datei nie.',occupied:'Vor einem Paketwechsel den aktuellen gemeinsamen Paketbestand ausdrücklich stilllegen. Unbestätigte Vorgänge blockieren den Wechsel.',empty:'Paketauswahlen erscheinen nach einem geprüften Upload.',publisher:'Herausgeberprüfung',unsigned:'Nicht signiert',unverified:'Nicht verifiziert'},
};
export function ManagedSoftwareCatalogue({view,blocked,selected,onSelect}:{view:ManagedArtifactView;blocked:boolean;selected:ReusableManagedReview|null;onSelect:(choice:SoftwareChoice)=>void}){
 const [locale]=useLocale(),c=softwareCatalogueCopy[locale],choices=managedSoftwareChoices(view);
 return <section className="managed-software-catalogue" aria-label={c.title}><h4>{c.title}</h4><p>{c.notice}</p>{choices.length?<ul>{choices.map((choice,index)=>{const state=softwareChoiceState(choice,view,blocked),chosen=!!selected&&sameSoftwareChoice(choice,selected);return <li key={index}><div><strong>{choice.package.name}</strong><span>{choice.package.version} · x64 · {(choice.package.size/1048576).toFixed(1)} MiB</span><small>{c.publisher}: {c[choice.publisherStatus]}</small></div><div className="managed-software-choice-action"><span className={`managed-software-choice-state ${state}`}>{c[state]}</span>{state==='upload'&&<button type="button" className="button small" aria-pressed={chosen} onClick={()=>onSelect(choice)}>{chosen?c.selected:c.use}</button>}</div></li>})}</ul>:<p>{c.empty}</p>}{selected&&<p>{c.missing}</p>}<details><summary>{locale==='de'?'Aufbewahrung & Paketwechsel':'Retention & switching'}</summary><p>{c.bounds}</p><p>{c.occupied}</p></details></section>;
}
