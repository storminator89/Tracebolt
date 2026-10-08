import { WindowsHealthSummary } from './windows-health';
import { WindowsEventsPanel } from './windows-events';
import { WindowsLogsPanel } from './windows-logs';
import { t, ui, useLocale } from './i18n';
import { useEffect, useRef, useState } from 'react';
import { ArrowLeft, ArrowRight, Bug, Check, CheckCircle2, ChevronRight, Clock3, Database, FileText, HardDrive, Info, ListFilter, LoaderCircle, MemoryStick, MessageSquare, Monitor, Play, RefreshCw, ShieldCheck, Terminal, TriangleAlert } from 'lucide-react';
import { mutate, request } from './api';
import { useDeviceMetadata } from './device-metadata-resource';
import { AIAnalysisPanel } from './ai';
import { DeviceEssentials, DeviceObservationNotes } from './device-essentials';
import { DeviceInventoryWorkspace } from './device-inventory';
import { WindowsDeviceOverview, WindowsInventoryWorkspace, WindowsObservationNotes } from './windows-inventory';
import { useWindowsInventory } from './windows-inventory-resource';
import { DeviceCapabilities } from './device-capabilities';
import { DeviceTabs } from './device-tabs';
import { SoftwareOverview } from './software-overview';
import { AgentCertificatePanel } from './agent-certificate';
import { HealthPanel } from './health';
import { JournalPanel } from './journal';
import { validJournalUnit } from './journal-types';
import { EndpointHostnameStatus, EndpointIdentityPanel } from './endpoint-identity';
import { useEndpointIdentity } from './endpoint-identity-resource';
import { DeviceSecurityWorkspace } from './device-security';
import { LinuxCVEPanel } from './linux-cve';
import { useOperator } from './auth';
import { ActivityList, CaseStatus, EvidenceCard, Loading, MetricValue, OSIcon, SectionHead, Severity, Source, Status } from './components';
import type { Case } from './types';
import { fullDate, relativeTime, noteBytes, platformLabels } from './utils';
export function DeviceDetail({ id, onClose, onCase, initialTab, initialUnit }: {
    initialTab?: 'health' | 'details' | 'logs';
    initialUnit?: string;
    id: string;
    onClose: () => void;
    onCase: (id: string) => void;
}) {
    const operator = useOperator();
    const [locale] = useLocale();
    const scope = JSON.stringify([id, operator?.mode, operator?.authenticated, operator?.expiresAt]);
    const [tab, setTab] = useState(initialTab ?? 'overview');
    const { device, snapshot, refreshing, accessEnded, error, automaticState, refresh } = useDeviceMetadata(id, scope, operator?.mode === 'lan' && operator.authenticated);
    const [journalUnit, setJournalUnit] = useState(initialUnit && validJournalUnit(initialUnit) ? initialUnit : '');
    const [windowsInventoryTab, setWindowsInventoryTab] = useState<'storage'>();
    const [inventorySource, setInventorySource] = useState<'processes' | 'preview' | 'packages' | 'updates'>();
    const selectTab = (value: string) => {
        if (value === tab) return;
        setJournalUnit(''); setInventorySource(undefined); setWindowsInventoryTab(undefined); setTab(value);
    };
    const openServiceLogs = (unit: string) => {
        if (!validJournalUnit(unit)) return;
        setJournalUnit(unit); setTab('logs');
        document.getElementById('tab-logs')?.focus();
    };
    const openPackages = () => { setInventorySource('packages'); setTab('inventory'); };
    const openUpdates = () => { setInventorySource('updates'); setTab('inventory'); document.getElementById('tab-inventory')?.focus(); };
    const openDetails = () => { selectTab('details'); document.getElementById('tab-details')?.focus(); };
    const openWindowsStorage = () => { setWindowsInventoryTab('storage'); setTab('inventory'); document.getElementById('tab-inventory')?.focus(); };
    const openWindowsLogs = () => { selectTab('logs'); document.getElementById('tab-logs')?.focus(); };
    const openWarnings = () => { selectTab('health'); document.getElementById('tab-health')?.focus(); };
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

    useEffect(() => { setTab(initialTab ?? 'overview'); setInventorySource(undefined); setWindowsInventoryTab(undefined); setJournalUnit(initialUnit && validJournalUnit(initialUnit) ? initialUnit : ''); }, [id, scope, initialTab, initialUnit]);
    const inventoryAvailable = Boolean(device && device.id === id && !device.synthetic && device.source === 'lan' && (device.platform === 'linux' || device.platform === 'unknown'));
    const windowsAvailable = Boolean(device && device.id === id && !device.synthetic && device.source === 'lan' && device.platform === 'windows' && operator?.mode === 'lan' && operator.authenticated);
    const windowsInventory = useWindowsInventory(id, windowsAvailable, operator?.expiresAt ?? null);
    const healthAvailable = Boolean(device && !device.synthetic && device.source === 'lan' && device.platform === 'linux' && operator?.mode === 'lan' && operator.authenticated);
    const securityAvailable = inventoryAvailable && operator?.mode === 'lan' && operator.authenticated;
    useEffect(() => { if (device && (tab === 'health' && !healthAvailable && !windowsAvailable || tab === 'logs' && !securityAvailable && !windowsAvailable)) setTab('overview'); }, [device, tab, healthAvailable, securityAvailable, windowsAvailable]);
    const endpoint = useEndpointIdentity(id, securityAvailable, operator?.expiresAt ?? null);
    const reportedHostname = windowsAvailable ? windowsInventory.snapshot?.hostname.rows[0]?.value : endpoint.snapshot?.reportedHostname.value;
    const securityTabLabel = locale === 'de' ? 'Sicherheitsabdeckung' : 'Security coverage';
    const tabs: {id:string;name:string;short?:string;count?:number;icon:typeof Info}[] = device ? [
        { id: 'overview', name: t('Übersicht'), icon: Monitor },
        ...(inventoryAvailable || windowsAvailable ? [{ id: 'inventory', name: t('Inventar'), icon: Database }] : []),
        ...(securityAvailable ? [{ id: 'security', name: securityTabLabel, short: locale === 'de' ? 'Sicherheit' : 'Security', icon: ShieldCheck }, { id: 'cves', name: locale === 'de' ? 'CVE-Warnungen' : 'CVE warnings', short: 'CVE', icon: Bug }] : []),
        ...(securityAvailable || windowsAvailable ? [{ id: 'logs', name: 'Logs', icon: Terminal }] : []),
        ...(healthAvailable || windowsAvailable ? [{ id: 'health', name: windowsAvailable ? 'Health' : t('Health & Verlauf'), short: 'Health', icon: TriangleAlert }] : []),
        { id: 'details', name: t('Details'), icon: Info },
        { id: 'evidence', name: t('Belege'), count: device.evidence.length, icon: FileText },
        { id: 'capabilities', name: t('Fähigkeiten'), count: device.capabilities.length, icon: ListFilter },
    ] : [];

    return <section ref={pageRef} tabIndex={-1} aria-label={device ? t("Ger\u00E4t {0}", { "0": device.name }) : t("Ger\u00E4tedetails")} className="device-page"><button className="back-link" onClick={onClose}><ArrowLeft size={15}/>{locale==='de'?'Zurück zu Geräten':'Back to devices'}</button>{!device && error ? <div className="detail-error" role="alert"><TriangleAlert size={25}/><h2>{t("Ger\u00E4t nicht verf\u00FCgbar")}</h2><p>{ui(error)}</p><button className="button" disabled={refreshing || accessEnded} onClick={refresh}>{t("Erneut versuchen")}</button></div> : !device ? <Loading /> : <><header className="device-page-header"><div className="device-detail-heading"><OSIcon platform={device.platform}/><div><h1>{reportedHostname ?? device.name}</h1>{windowsAvailable ? windowsInventory.snapshot && <span className="detail-time">{windowsInventory.status === 'stale' ? locale === 'de' ? 'Veraltete Beobachtung' : 'Stale observation' : locale === 'de' ? 'Inventar erfasst' : 'Inventory observed'} · <time dateTime={windowsInventory.snapshot.collectedAt}>{fullDate(windowsInventory.snapshot.collectedAt)}</time></span> : <EndpointHostnameStatus resource={endpoint}/>}<p>{device.os}</p></div></div><div className="detail-badges"><Status status={device.status} source={device.source} synthetic={device.synthetic}/><Source synthetic={device.synthetic} source={device.source}/>{tab !== 'overview' && <span className="detail-time"><Clock3 size={13}/>{relativeTime(device.lastSeen)}</span>}</div></header><div className="device-metadata-refresh"><button type="button" className="button small" disabled={refreshing || accessEnded} onClick={refresh} aria-label={locale === 'de' ? 'Gerätedaten aktualisieren' : 'Refresh device metadata'} aria-describedby="device-metadata-status"><RefreshCw size={14} className={refreshing ? 'spin' : undefined}/>{locale === 'de' ? 'Aktualisieren' : 'Refresh'}</button><span className="device-auto-refresh" aria-label={automaticState === 'off' ? undefined : locale === 'de' ? 'Automatische Geräteprüfung' : 'Automatic device checks'} title={automaticState === 'backoff' ? (locale === 'de' ? 'Erneuter Versuch mit bis zu zwei Minuten Abstand.' : 'Retrying with up to two minutes between checks.') : (locale === 'de' ? 'Gerätestatus alle 15 Sekunden prüfen, solange diese Seite sichtbar ist. Inventaransichten zeigen ihre eigenen Erfassungszeiten.' : 'Check device status every 15 seconds while this page is visible. Inventory views show their own collection times.')}>{automaticState === 'active' ? '↻ 15 s' : automaticState === 'backoff' ? (locale === 'de' ? '↻ Wartet' : '↻ Waiting') : null}</span><p id="device-metadata-status" role="status">{refreshing ? (locale === 'de' ? 'Gerätedaten werden geprüft …' : 'Checking device metadata…') : (locale === 'de' ? 'Zuletzt erfolgreich geprüft: ' : 'Last successful check: ')}{!refreshing && snapshot && <time dateTime={snapshot.checkedAt}>{fullDate(snapshot.checkedAt)}</time>}</p></div>{error && <div className="error-banner" role="alert"><TriangleAlert size={17}/><p>{locale === 'de' ? 'Aktualisierung fehlgeschlagen. Angezeigte Gerätedaten bleiben unverändert. ' : 'Refresh failed. Displayed device metadata is unchanged. '}{ui(error)}</p></div>}<DeviceTabs tabs={tabs} selected={tab} onSelect={selectTab}/><div className="drawer-content" role="tabpanel" id={`device-${tab}`} aria-labelledby={`tab-${tab}`}>
    {tab === 'overview' && <>{device.platform === 'windows' ? <WindowsDeviceOverview device={device} resource={windowsInventory} sessionKey={operator?.expiresAt ?? null} onInventory={windowsAvailable ? () => { selectTab('inventory'); document.getElementById('tab-inventory')?.focus(); } : undefined} onDetails={openDetails}/> : <DeviceEssentials device={device} sessionKey={operator?.expiresAt ?? null} readReady={!endpoint.loading && endpoint.error !== 'session' && Boolean(endpoint.view || endpoint.error)} onWarnings={healthAvailable ? openWarnings : undefined} onUpdates={securityAvailable ? openUpdates : undefined} onDetails={openDetails}/>}<section className="detail-section">{healthAvailable ? <><SectionHead title={t("Untersuchungen")}/><div className="investigation-links"><button className="text-button" onClick={openWarnings}>{locale === 'de' ? 'Health & Verlauf dieses Geräts' : 'This device’s Health & history'}<ArrowRight size={14}/></button><a href="#/cases">{t("Alle Untersuchungen")}</a></div></> : <><SectionHead title={t("Verkn\u00FCpfte Untersuchungen")} count={device.caseIds.length}/>{device.caseIds.length ? device.caseIds.map(caseId => <button className="linked-case" key={caseId} onClick={() => onCase(caseId)}><span><FileText size={16}/><strong>{caseId}</strong></span><span>{t("Untersuchen")}<ArrowRight size={15}/></span></button>) : null}</>}</section></>}
    {tab === 'details' && <>{device.platform === 'windows' ? <WindowsObservationNotes/> : <DeviceObservationNotes/>}{device.source === 'lan' && !device.synthetic && <p className="device-stable-identity"><span>{locale === 'de' ? 'Stabile kryptografische Geräte-ID' : 'Stable cryptographic device ID'}</span><code>{device.id}</code></p>}<div className={`provenance-notice ${device.synthetic ? '' : 'real'}`}><Database size={16}/><p>{device.synthetic ? t("Demodaten ohne Geräteverbindung.") : device.source === "lan" ? t("Nur akzeptierte Agentenmeldungen.") : t("Nur vom {0}-Collector erfasste Daten.", { "0": platformLabels[device.platform] })}</p></div><div className="device-metrics">{[{ label: 'CPU', metric: device.cpu, icon: Terminal }, { label: t("Arbeitsspeicher"), metric: device.memory, icon: MemoryStick }, { label: t("Datentr\u00E4ger"), metric: device.disk, icon: HardDrive }].map(item => <div className="device-metric-card" key={item.label}><span className="device-metric-label"><item.icon size={14}/>{ui(item.label)}</span><MetricValue metric={item.metric}/><span className="metric-source">{item.metric.source}</span></div>)}</div><div className="device-overview-summary">{securityAvailable && <SoftwareOverview deviceId={device.id} onOpenPackages={openPackages}/>}{device.source === 'lan' && !device.synthetic && operator?.mode === 'lan' && operator.authenticated && <AgentCertificatePanel value={device.agentCertificate}/>}</div>{securityAvailable && <EndpointIdentityPanel resource={endpoint}/>}<details className="detail-section device-technical"><summary>{locale==='de'?'Geräteprofil & technische Details':'Device profile & technical details'}<ChevronRight size={15}/></summary><dl className="metadata-grid"><div><dt>{t("Ger\u00E4tename")}</dt><dd className="mono">{device.name}</dd></div><div><dt>{t("Standort")}</dt><dd>{device.site}</dd></div><div><dt>{t("Gruppe")}</dt><dd>{device.group}</dd></div>{device.source !== 'lan' && <div><dt>{t("IP-Adresse")}</dt><dd className="mono">{device.ip || t("Nicht erfasst")}</dd></div>}<div><dt>{t("Laufzeit")}</dt><dd>{device.uptime || t("Nicht verf\u00FCgbar")}</dd></div><div><dt>{t("Collector-Version")}</dt><dd className="mono">{device.agentVersion || t("Nicht verf\u00FCgbar")}</dd></div><div className="metadata-wide"><dt>{t("Letzter Kontakt")}</dt><dd>{fullDate(device.lastSeen)}</dd></div></dl>{device.tags.length > 0 && <div className="device-tags">{device.tags.map(tag => <span key={tag}>{tag}</span>)}</div>}</details><div className="quality-explainer"><Info size={16}/><p>{t("Fehlende Daten bedeuten nicht, dass das Gerät gesund ist.")}</p></div></>}
    {tab === 'health' && windowsAvailable && <><WindowsHealthSummary device={device} resource={windowsInventory} sessionKey={operator?.expiresAt ?? null} metadataReady={!error && !refreshing && !accessEnded} onOpenStorage={openWindowsStorage}/><WindowsEventsPanel resource={windowsInventory} onOpenLogs={openWindowsLogs}/></>}
    {tab === 'health' && healthAvailable && <HealthPanel key={device.id} deviceId={device.id} device={device} sessionKey={operator?.expiresAt} onOpenLogs={openServiceLogs}/> }
    {tab === 'inventory' && windowsAvailable && <WindowsInventoryWorkspace key={`${device.id}:${operator?.expiresAt ?? ''}`} resource={windowsInventory} initialTab={windowsInventoryTab}/> }
    {tab === 'inventory' && inventoryAvailable && <DeviceInventoryWorkspace key={device.id} deviceId={device.id} initialSource={inventorySource} onOpenLogs={securityAvailable ? openServiceLogs : undefined}/> }
    {tab === 'logs' && windowsAvailable && <WindowsLogsPanel key={`${device.id}:${operator?.expiresAt ?? ''}`} resource={windowsInventory}/> }
    {tab === 'logs' && securityAvailable && <JournalPanel key={device.id} deviceId={device.id} insecureTestMode={operator.insecureTestMode} sessionKey={operator.expiresAt} initialUnit={journalUnit}/> }
    {tab === 'cves' && securityAvailable && <LinuxCVEPanel deviceId={device.id} sessionKey={operator.expiresAt ?? undefined}/> }
    {tab === 'security' && securityAvailable && <DeviceSecurityWorkspace deviceId={device.id} sessionKey={operator.expiresAt ?? undefined} onOpenPackages={openPackages} onOpenUpdates={openUpdates}/>}
    {tab === 'evidence' && <><div className="evidence-list">{device.evidence.map((evidence, index) => <EvidenceCard key={evidence.id} evidence={evidence} index={index}/>)}</div>{!device.evidence.length && <p className="quiet-empty">{t("F\u00FCr dieses Ger\u00E4t sind keine Belege verf\u00FCgbar.")}</p>}</>}
    {tab === 'capabilities' && <DeviceCapabilities key={`${device.id}:${operator?.expiresAt ?? ''}`} device={device}/>}
  </div><div className="drawer-footer"><ShieldCheck size={14}/><span>{tab === 'details' ? t("Lesende Ger\u00E4teansicht \u00B7 keine Remote-Ausf\u00FChrung") : t("Nur lesend")}</span>{tab === 'details' && <code>{device.id}</code>}</div></>}</section>;
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
  <div className="case-detail-grid"><div className="case-content-column"><section className="panel finding-panel"><div className="finding-label"><h2><ShieldCheck size={15}/>{t("Regelbefund")}</h2><span className={`confidence ${item.confidence === 'limited' ? 'limited' : ''}`}>{item.confidence === 'evidence-backed' ? t("Durch Belege gest\u00FCtzt") : t("Eingeschr\u00E4nkte Datenlage")}</span></div><p className="finding-summary">{item.summary}</p><div className="finding-footer"><span><span className="dot teal"/>{t("Regel") + " "}<code>{item.ruleId}</code></span><span>{item.evidenceIds.length}{" " + t("verkn\u00FCpfte Belege")}</span></div></section><section className="panel evidence-panel"><SectionHead title={t("Belege")} count={item.evidence.length}/><div className="evidence-list">{item.evidence.map((evidence, index) => <EvidenceCard evidence={evidence} key={evidence.id} index={index}/>)}</div>{!item.evidence.length && <p className="panel-empty">{t("Keine Belege verf\u00FCgbar. Dieser Befund ist nicht best\u00E4tigt.")}</p>}</section><AIAnalysisPanel item={item} onSettings={onSettings}/><section className="panel next-steps-panel"><SectionHead title={t("Nächster Schritt")} action={<span className="read-only-badge"><ShieldCheck size={13}/>{t("Nur lesend")}</span>}/><ol className="next-steps">{item.nextSteps.slice(0, 1).map((step, index) => <li key={`${index}-${step}`}><span>1</span><p>{step}</p></li>)}</ol>{item.nextSteps.length > 1 && <details className="additional-checks"><summary><ListFilter size={14}/>{t("Weitere Pr\u00FCfschritte")}<span>{item.nextSteps.length - 1}</span><ChevronRight size={14}/></summary><ol className="next-steps" start={2}>{item.nextSteps.slice(1).map((step, index) => <li key={`${index}-${step}`}><span>{index + 2}</span><p>{step}</p></li>)}</ol></details>}<div className="runbook-footer"><Terminal size={15}/><span>{t("Runbook:") + " "}<code>{item.runbookId}</code>{" " + t("\u00B7 Empfehlungen werden nicht ausgef\u00FChrt.")}</span></div></section><section className="panel notes-panel"><SectionHead title={t("Notizen")} count={item.notes.length} action={<MessageSquare size={17}/>}/>{item.notes.length > 0 && <div className="notes-list">{item.notes.map(entry => <div className="note" key={entry.id}><div className="note-avatar">LO</div><div><div className="note-author"><strong>{entry.author}</strong><time dateTime={entry.createdAt} title={fullDate(entry.createdAt)}>{relativeTime(entry.createdAt)}</time></div><p>{entry.text}</p></div></div>)}</div>}<form onSubmit={event => void saveNote(event)}><label htmlFor="case-note" className="sr-only">{t("Notiz zur Untersuchung")}</label><textarea id="case-note" maxLength={2000} rows={3} value={note} onChange={event => setNote(event.target.value)} placeholder={t("Beobachtung oder Entscheidung …")}/><div className="note-form-footer"><span className={noteBytes(note) > 2000 ? "text-warning" : ""}>{t("Lokal gespeichert \u00B7") + " "}{noteBytes(note)}{t("/2000 UTF-8 Bytes")}</span><button type="submit" className="button primary" disabled={!note.trim() || noteBytes(note.trim()) > 2000 || saving}>{saving ? <LoaderCircle className="spin" size={14}/> : <PlusIcon />}{t("Notiz speichern")}</button></div></form></section></div>
  <aside className="case-side-column"><section className="panel case-context-panel"><SectionHead title={t("Kontext")}/><dl><div><dt>{t("Ger\u00E4t")}</dt><dd><button className="text-button" onClick={() => onDevice(item.deviceId)}>{item.deviceName}<ArrowRight size={13}/></button></dd></div><div><dt>{t("Kategorie")}</dt><dd>{{ storage: t("Datentr\u00E4ger"), service: t("Dienst"), network: t("Netzwerk") }[item.category]}</dd></div><div><dt>{t("Datenquelle")}</dt><dd><Source synthetic={item.synthetic}/></dd></div><div><dt>{t("Erstellt")}</dt><dd>{fullDate(item.createdAt)}</dd></div><div><dt>{t("Aktualisiert")}</dt><dd>{fullDate(item.updatedAt)}</dd></div></dl></section><section className="panel case-timeline"><SectionHead title={t("Verlauf")} count={item.timeline.length}/><ActivityList items={item.timeline}/></section></aside></div></>}</>;
}
function PlusIcon() { return <span aria-hidden="true" className="plus-symbol">+</span>; }
