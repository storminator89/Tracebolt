import { t, ui, useLocale } from './i18n';
import { useEffect, useRef, useState } from 'react';
import { ArrowLeft, ArrowRight, Check, CheckCircle2, ChevronRight, Clock3, Database, FileText, HardDrive, Info, ListFilter, LoaderCircle, MemoryStick, MessageSquare, Monitor, Play, ShieldCheck, Terminal, TriangleAlert } from 'lucide-react';
import { mutate, request } from './api';
import { AIAnalysisPanel } from './ai';
import { DeviceInventoryWorkspace } from './device-inventory';
import { SoftwareOverview } from './software-overview';
import { JournalPanel } from './journal';
import { EndpointHostnameStatus, EndpointIdentityPanel } from './endpoint-identity';
import { useEndpointIdentity } from './endpoint-identity-resource';
import { SecurityCoveragePanel } from './security-coverage';
import { PackageObservationsPanel } from './package-observations';
import { useOperator } from './auth';
import { ActivityList, CaseStatus, EvidenceCard, Loading, MetricValue, OSIcon, SectionHead, Severity, Source, Status } from './components';
import type { Case, Device } from './types';
import { fullDate, relativeTime, noteBytes, platformLabels } from './utils';
export function DeviceDetail({ id, onClose, onCase }: {
    id: string;
    onClose: () => void;
    onCase: (id: string) => void;
}) {
    const operator = useOperator();
    const [locale] = useLocale();
    const [device, setDevice] = useState<Device | null>(null);
    const [error, setError] = useState('');
    const [tab, setTab] = useState('overview');
    const [inventorySource, setInventorySource] = useState<'processes' | 'preview' | 'packages'>('processes');
    const selectTab = (value: string) => { setInventorySource('processes'); setTab(value); };
    const openPackages = () => { setInventorySource('packages'); setTab('inventory'); };
    const [retry, setRetry] = useState(0);
    const pageRef = useRef<HTMLElement>(null), closeRef = useRef(onClose);
    closeRef.current = onClose;
    useEffect(() => {
        pageRef.current?.focus();
        const key = (event: KeyboardEvent) => {
            // Escape still returns to the list, but an open modal owns its own dismissal.
            if (event.key === 'Escape' && !event.defaultPrevented && !document.querySelector('[role="dialog"]')) {
                event.preventDefault(); closeRef.current();
            }
        };
        document.addEventListener('keydown', key);
        return () => document.removeEventListener('keydown', key);
    }, [id]);

    useEffect(() => {
        let active = true;
        const controller = new AbortController();
        setDevice(null);
        setError('');
        setTab('overview');
        setInventorySource('processes');
        request<Device>(`/devices/${encodeURIComponent(id)}`, { signal: controller.signal }).then(value => {
            if (active) {
                if (!value || value.id !== id) { setError(t('Der Manager hat keine gültigen JSON-Daten zurückgegeben.')); return; }
                setDevice(value);
            }
        }).catch(err => {
            if (active)
                setError(err.message);
        });
        return () => { active = false; controller.abort(); };
    }, [id, retry]);
    const inventoryAvailable = Boolean(device && device.id === id && !device.synthetic && device.source === 'lan' && (device.platform === 'linux' || device.platform === 'unknown'));
    const securityAvailable = inventoryAvailable && operator?.mode === 'lan' && operator.authenticated;
    const endpoint = useEndpointIdentity(id, securityAvailable, operator?.expiresAt ?? null);
    const reportedHostname = endpoint.snapshot?.reportedHostname.value;
    const securityTabLabel = locale === 'de' ? 'Sicherheitsabdeckung' : 'Security coverage';
    const tabs: {id:string;name:string;count?:number}[] = device ? [{ id: 'overview', name: t("\u00DCbersicht") }, ...(inventoryAvailable ? [{ id: 'inventory', name: t('Inventar') }] : []), ...(securityAvailable ? [{ id: 'security', name: securityTabLabel }, { id: 'logs', name: 'Logs' }] : []), { id: 'evidence', name: t("Belege"), count: device.evidence.length }, { id: 'capabilities', name: t("F\u00E4higkeiten"), count: device.capabilities.length }] : [];
    return <section ref={pageRef} tabIndex={-1} aria-label={device ? t("Ger\u00E4t {0}", { "0": device.name }) : t("Ger\u00E4tedetails")} className="device-page"><button className="back-link" onClick={onClose}><ArrowLeft size={15}/>{locale==='de'?'Zurück zu Geräten':'Back to devices'}</button>{error ? <div className="detail-error" role="alert"><TriangleAlert size={25}/><h2>{t("Ger\u00E4t nicht verf\u00FCgbar")}</h2><p>{ui(error)}</p><button className="button" onClick={() => setRetry(v => v + 1)}>{t("Erneut versuchen")}</button></div> : !device ? <Loading /> : <><header className="device-page-header"><div className="device-detail-heading"><OSIcon platform={device.platform}/><div><h1>{reportedHostname ?? device.name}</h1><EndpointHostnameStatus resource={endpoint}/><p>{device.os}</p>{device.source === 'lan' && !device.synthetic && <p className="device-stable-identity"><span>{locale === 'de' ? 'Stabile kryptografische Geräte-ID' : 'Stable cryptographic device ID'}</span><code>{device.id}</code></p>}</div></div><div className="detail-badges"><Status status={device.status} source={device.source} synthetic={device.synthetic}/><Source synthetic={device.synthetic} source={device.source}/><span className="detail-time"><Clock3 size={13}/>{relativeTime(device.lastSeen)}</span></div></header><div className={`provenance-notice ${device.synthetic ? '' : 'real'}`}><Database size={16}/><p>{device.synthetic ? t("Synthetisches Beispielger\u00E4t. Messwerte, Ereignisse und Belege dienen der Demonstration.") : device.source === "lan" ? t("Freigegebener LAN-Agent. Messwerte werden erst nach einer akzeptierten Übertragung angezeigt.") : t("Lokale {0}-Umgebung. Messwerte werden nur angezeigt, wenn ein Collector sie geliefert hat.", { "0": platformLabels[device.platform] })}</p></div><div className="drawer-tabs" role="tablist" aria-label={t("Ger\u00E4tedaten")}>{tabs.map(item => <button key={item.id} role="tab" tabIndex={tab === item.id ? 0 : -1} aria-selected={tab === item.id} aria-controls={`device-${item.id}`} id={`tab-${item.id}`} onClick={() => selectTab(item.id)} onKeyDown={event => { const index=tabs.findIndex(entry=>entry.id===item.id); const target=event.key==='ArrowRight'?(index+1)%tabs.length:event.key==='ArrowLeft'?(index+tabs.length-1)%tabs.length:event.key==='Home'?0:event.key==='End'?tabs.length-1:null; if(target!==null){event.preventDefault();selectTab(tabs[target].id);document.getElementById(`tab-${tabs[target].id}`)?.focus();} }}>{item.name}{item.count !== undefined && <span>{item.count}</span>}</button>)}</div><div className="drawer-content" role="tabpanel" id={`device-${tab}`} aria-labelledby={`tab-${tab}`}>
    {tab === 'overview' && <>{securityAvailable && <EndpointIdentityPanel resource={endpoint}/>}{securityAvailable && <SoftwareOverview deviceId={device.id} onOpenPackages={openPackages}/>}<div className="device-metrics">{[{ label: 'CPU', metric: device.cpu, icon: Terminal }, { label: t("Arbeitsspeicher"), metric: device.memory, icon: MemoryStick }, { label: t("Datentr\u00E4ger"), metric: device.disk, icon: HardDrive }].map(item => <div className="device-metric-card" key={item.label}><span className="device-metric-label"><item.icon size={14}/>{ui(item.label)}</span><MetricValue metric={item.metric}/><span className="metric-source">{item.metric.source}</span></div>)}</div><details className="detail-section device-technical"><summary>{locale==='de'?'Geräteprofil & technische Details':'Device profile & technical details'}<ChevronRight size={15}/></summary><dl className="metadata-grid"><div><dt>{t("Ger\u00E4tename")}</dt><dd className="mono">{device.name}</dd></div><div><dt>{t("Standort")}</dt><dd>{device.site}</dd></div><div><dt>{t("Gruppe")}</dt><dd>{device.group}</dd></div>{device.source !== 'lan' && <div><dt>{t("IP-Adresse")}</dt><dd className="mono">{device.ip || t("Nicht erfasst")}</dd></div>}<div><dt>{t("Laufzeit")}</dt><dd>{device.uptime || t("Nicht verf\u00FCgbar")}</dd></div><div><dt>{t("Collector-Version")}</dt><dd className="mono">{device.agentVersion || t("Nicht verf\u00FCgbar")}</dd></div><div className="metadata-wide"><dt>{t("Letzter Kontakt")}</dt><dd>{fullDate(device.lastSeen)}</dd></div></dl>{device.tags.length > 0 && <div className="device-tags">{device.tags.map(tag => <span key={tag}>{tag}</span>)}</div>}</details><section className="detail-section"><SectionHead title={t("Verkn\u00FCpfte Untersuchungen")} count={device.caseIds.length}/>{device.caseIds.length ? device.caseIds.map(caseId => <button className="linked-case" key={caseId} onClick={() => onCase(caseId)}><span><FileText size={16}/><strong>{caseId}</strong></span><span>{t("Untersuchen")}<ArrowRight size={15}/></span></button>) : <p className="quiet-empty"><CheckCircle2 size={16}/>{t("Keine Untersuchung zu diesem Ger\u00E4t.")}</p>}</section><div className="quality-explainer"><Info size={16}/><p><strong>{t("Datenqualit\u00E4t ist Teil der Diagnose.")}</strong>{" " + t("Veraltete, verweigerte oder fehlende Werte sind ausdr\u00FCcklich markiert. Fehlende Daten bedeuten keinen gesunden Zustand.")}</p></div></>}
    {tab === 'inventory' && inventoryAvailable && <DeviceInventoryWorkspace key={device.id} deviceId={device.id} initialSource={inventorySource}/> }
    {tab === 'logs' && securityAvailable && <JournalPanel key={device.id} deviceId={device.id} insecureTestMode={operator.insecureTestMode} sessionKey={operator.expiresAt}/> }
    {tab === 'security' && securityAvailable && <><SecurityCoveragePanel deviceId={device.id} sessionKey={operator.expiresAt ?? undefined}/><PackageObservationsPanel deviceId={device.id} sessionKey={operator.expiresAt ?? undefined}/></>}
    {tab === 'evidence' && <><div className="tab-intro"><h3>{t("Jede Beobachtung hat eine Quelle.")}</h3><p>{t("\u00D6ffne einen Beleg f\u00FCr Messwert, Zeitpunkt und Herkunft.")}</p></div><div className="evidence-list">{device.evidence.map((evidence, index) => <EvidenceCard key={evidence.id} evidence={evidence} index={index}/>)}</div>{!device.evidence.length && <p className="quiet-empty">{t("F\u00FCr dieses Ger\u00E4t sind keine Belege verf\u00FCgbar.")}</p>}</>}
    {tab === 'capabilities' && <><div className="tab-intro"><h3>{t("Unterst\u00FCtzung transparent gemacht.")}</h3><p>{t("F\u00E4higkeiten gelten nur f\u00FCr den angegebenen Collector und seine Berechtigungen.")}</p></div><div className="device-capabilities">{device.capabilities.map(capability => <div key={capability.id}><span className={`capability-icon ${capability.status}`}>{capability.status === 'supported' ? <Check size={16}/> : capability.status === 'limited' ? <Info size={16}/> : <span>—</span>}</span><div><strong>{capability.name}</strong><p>{capability.detail}</p></div><span className={`capability-state ${capability.status}`}>{{ supported: t("Unterst\u00FCtzt"), limited: t("Eingeschr\u00E4nkt"), unsupported: t("Nicht verf\u00FCgbar"), denied: t("Verweigert") }[capability.status]}</span></div>)}</div></>}
  </div><div className="drawer-footer"><ShieldCheck size={14}/><span>{t("Lesende Ger\u00E4teansicht \u00B7 keine Remote-Ausf\u00FChrung")}</span><code>{device.id}</code></div></>}</section>;
}
export function CaseDetail({ id, onBack, onDevice, onChanged, onSettings = () => { window.location.hash = "/settings"; } }: {
    id: string;
    onBack: () => void;
    onDevice: (id: string) => void;
    onChanged: () => void;
    onSettings?: () => void;
}) {
    const [item, setItem] = useState<Case | null>(null);
    const [error, setError] = useState('');
    const [retry, setRetry] = useState(0);
    const [note, setNote] = useState('');
    const [saving, setSaving] = useState(false);
    const [saveError, setSaveError] = useState('');
    const [saved, setSaved] = useState('');
    useEffect(() => {
        let active = true;
        setItem(null);
        setError('');
        setNote('');
        setSaved('');
        request<Case>(`/cases/${encodeURIComponent(id)}`).then(value => {
            if (active)
                setItem(value);
        }).catch(err => {
            if (active)
                setError(err.message);
        });
        return () => { active = false; };
    }, [id, retry]);
    const changeStatus = async (status: Case['status']) => {
        if (!item || saving)
            return;
        setSaving(true);
        setSaveError('');
        setSaved('');
        try {
            const next = await mutate<Case>(`/cases/${encodeURIComponent(item.id)}/status`, { status });
            setItem(next);
            setSaved(t("Status gespeichert."));
            onChanged();
        }
        catch (err) {
            setSaveError(err instanceof Error ? err.message : t("Status konnte nicht gespeichert werden."));
        }
        finally {
            setSaving(false);
        }
    };
    const saveNote = async (event: React.SubmitEvent<HTMLFormElement>) => {
        event.preventDefault();
        if (!item || !note.trim() || noteBytes(note.trim()) > 2000 || saving)
            return;
        setSaving(true);
        setSaveError('');
        setSaved('');
        try {
            const next = await mutate<Case>(`/cases/${encodeURIComponent(item.id)}/notes`, { text: note.trim() });
            setItem(next);
            setNote('');
            setSaved(t("Notiz lokal gespeichert."));
            onChanged();
        }
        catch (err) {
            setSaveError(err instanceof Error ? err.message : t("Notiz konnte nicht gespeichert werden."));
        }
        finally {
            setSaving(false);
        }
    };
    return <><button className="back-link" onClick={onBack}><ArrowLeft size={15}/>{t("Alle Untersuchungen")}</button>{error ? <div className="panel detail-error" role="alert"><TriangleAlert size={24}/><h2>{t("Untersuchung nicht verf\u00FCgbar")}</h2><p>{ui(error)}</p><button className="button" onClick={() => setRetry(v => v + 1)}>{t("Erneut versuchen")}</button></div> : !item ? <Loading label={t("Untersuchung wird geladen \u2026")}/> : <><div className="case-detail-header"><div><div className="case-heading-meta"><span className="eyebrow">{item.id}</span><span className="separator-dot">·</span><Source synthetic={item.synthetic}/><span className="separator-dot">·</span><span className="text-secondary">{relativeTime(item.createdAt)}</span></div><h1>{item.title}</h1><div className="case-heading-device"><button onClick={() => onDevice(item.deviceId)}><Monitor size={14}/>{item.deviceName}<ArrowRight size={13}/></button><Severity value={item.severity}/><CaseStatus status={item.status}/></div></div><div className="case-status-actions">{item.status === 'open' && <button className="button primary" disabled={saving} onClick={() => void changeStatus('investigating')}><Play size={14}/>{t("Untersuchung beginnen")}</button>}{item.status === 'investigating' && <button className="button" disabled={saving} onClick={() => void changeStatus('resolved')}><CheckCircle2 size={16}/>{t("Fall abschlie\u00DFen")}</button>}{item.status === 'resolved' && <button className="button" disabled={saving} onClick={() => void changeStatus('open')}>{t("Wieder \u00F6ffnen")}</button>}</div></div>{saveError && <div className="error-banner" role="alert"><TriangleAlert size={17}/><p>{ui(saveError)}</p></div>}{saved && <div className="success-banner" role="status"><Check size={15}/>{ui(saved)}</div>}
  <div className="case-detail-grid"><div className="case-content-column"><section className="panel finding-panel"><div className="finding-label"><span><ShieldCheck size={15}/>{t("REGELBASIERTER BEFUND")}</span><span className={`confidence ${item.confidence === 'limited' ? 'limited' : ''}`}>{item.confidence === 'evidence-backed' ? t("Durch Belege gest\u00FCtzt") : t("Eingeschr\u00E4nkte Datenlage")}</span></div><h2>{t("Was die Daten zeigen")}</h2><p className="finding-summary">{item.summary}</p><div className="finding-footer"><span><span className="dot teal"/>{t("Regel") + " "}<code>{item.ruleId}</code></span><span>{item.evidenceIds.length}{" " + t("verkn\u00FCpfte Belege")}</span></div></section><section className="panel evidence-panel"><SectionHead title={t("Belege")} count={item.evidence.length} action={<span className="section-hint">{t("Quelle \u00B7 Zeitpunkt \u00B7 Qualit\u00E4t")}</span>}/><div className="evidence-list">{item.evidence.map((evidence, index) => <EvidenceCard evidence={evidence} key={evidence.id} index={index}/>)}</div>{!item.evidence.length && <p className="panel-empty">{t("Keine Belege verf\u00FCgbar. Dieser Befund ist nicht best\u00E4tigt.")}</p>}<div className="panel-footnote"><Info size={14}/><span>{t("Belege \u00F6ffnen, um Beobachtung und Schlussfolgerung zu pr\u00FCfen.")}</span></div></section><AIAnalysisPanel item={item} onSettings={onSettings}/><section className="panel next-steps-panel"><SectionHead title={t("Der n\u00E4chste sinnvolle Schritt")} action={<span className="read-only-badge"><ShieldCheck size={13}/>{t("Nur lesend")}</span>}/><ol className="next-steps">{item.nextSteps.slice(0, 1).map((step, index) => <li key={`${index}-${step}`}><span>1</span><p>{step}</p></li>)}</ol>{item.nextSteps.length > 1 && <details className="additional-checks"><summary><ListFilter size={14}/>{t("Weitere Pr\u00FCfschritte")}<span>{item.nextSteps.length - 1}</span><ChevronRight size={14}/></summary><ol className="next-steps" start={2}>{item.nextSteps.slice(1).map((step, index) => <li key={`${index}-${step}`}><span>{index + 2}</span><p>{step}</p></li>)}</ol></details>}<div className="runbook-footer"><Terminal size={15}/><span>{t("Runbook:") + " "}<code>{item.runbookId}</code>{" " + t("\u00B7 Empfehlungen werden nicht ausgef\u00FChrt.")}</span></div></section><section className="panel notes-panel"><SectionHead title={t("Notizen")} count={item.notes.length} action={<MessageSquare size={17}/>}/>{item.notes.length > 0 && <div className="notes-list">{item.notes.map(entry => <div className="note" key={entry.id}><div className="note-avatar">LO</div><div><div className="note-author"><strong>{entry.author}</strong><time dateTime={entry.createdAt} title={fullDate(entry.createdAt)}>{relativeTime(entry.createdAt)}</time></div><p>{entry.text}</p></div></div>)}</div>}<form onSubmit={event => void saveNote(event)}><label htmlFor="case-note" className="sr-only">{t("Notiz zur Untersuchung")}</label><textarea id="case-note" maxLength={2000} rows={3} value={note} onChange={event => setNote(event.target.value)} placeholder={t("Beobachtung oder Entscheidung festhalten \u2026")}/><div className="note-form-footer"><span className={noteBytes(note) > 2000 ? "text-warning" : ""}>{t("Lokal gespeichert \u00B7") + " "}{noteBytes(note)}{t("/2000 UTF-8 Bytes")}</span><button type="submit" className="button primary" disabled={!note.trim() || noteBytes(note.trim()) > 2000 || saving}>{saving ? <LoaderCircle className="spin" size={14}/> : <PlusIcon />}{t("Notiz speichern")}</button></div></form></section></div>
  <aside className="case-side-column"><section className="panel case-context-panel"><SectionHead title={t("Kontext")}/><dl><div><dt>{t("Ger\u00E4t")}</dt><dd><button className="text-button" onClick={() => onDevice(item.deviceId)}>{item.deviceName}<ArrowRight size={13}/></button></dd></div><div><dt>{t("Kategorie")}</dt><dd>{{ storage: t("Datentr\u00E4ger"), service: t("Dienst"), network: t("Netzwerk") }[item.category]}</dd></div><div><dt>{t("Datenquelle")}</dt><dd><Source synthetic={item.synthetic}/></dd></div><div><dt>{t("Erstellt")}</dt><dd>{fullDate(item.createdAt)}</dd></div><div><dt>{t("Aktualisiert")}</dt><dd>{fullDate(item.updatedAt)}</dd></div></dl></section><section className="panel case-timeline"><SectionHead title={t("Verlauf")} count={item.timeline.length}/><ActivityList items={item.timeline}/></section></aside></div></>}</>;
}
function PlusIcon() { return <span aria-hidden="true" className="plus-symbol">+</span>; }
