import { useInvestigations } from './investigations-resource';
import { InvestigationsPage, InvestigationList, InvestigationNotice } from './investigations';
import type { InvestigationScope } from './investigations-types';
import { useFleetIdentity } from './fleet-identity-resource';
import type { FleetIdentityResource } from './fleet-identity-resource';
import { FleetIdentityNotice } from './fleet-identity';
import { t, ui, useLocale } from './i18n';
import { EnrollmentSection } from './enrollment';
import { ApplicationChecksPanel } from './application-checks';
import { AlarmStatusPanel } from './alarm-status';
import { AlarmSettingsPanel } from './alarm-settings';
import { ApplicationCheckSettingsPanel } from './application-check-settings';
import { applicationCheckSetupId } from './application-check-entry';
import { LanguageSelector } from './LanguageSelector';
import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
import { Activity, ArrowDownToLine, ArrowRight, Bookmark, Check, ChevronDown, ChevronRight, Command, Database, Filter, LayoutDashboard, ListFilter, Menu, Monitor, Moon, PanelLeftClose, RefreshCw, Search, Settings2, ShieldCheck, SlidersHorizontal, Sun, Terminal, TriangleAlert, X } from 'lucide-react';
import type { Activity as ActivityType, Capabilities, Case, Device, Overview, View } from './types';
import type { Filters } from './utils';
import { defaultFilters, filterDevices, fullDate, platformLabels, saveLocal, csvCell, decodeRouteId, savedFilters } from './utils';
import { request } from './api';
import { ActivityList, CaseList, CaseStatus, DeviceTable, Dialog, EmptyState, Loading, Logo, SectionHead, Source } from './components';
import { CaseDetail, DeviceDetail } from './details';
import { AIProviderSettings } from './ai';
import { ProactiveAISettingsPanel } from './proactive-ai';
import { OfflineCatalogPanel } from './security-coverage';
import { AuthBoundary, OperatorAccount, TransportWarning, useOperator } from './auth';
function useRoute() {
    const parse = () => { const [view, id, tab, unit] = window.location.hash.replace(/^#\/?/, '').split('/'); return { view: (['overview', 'devices', 'cases', 'settings'].includes(view) ? view : 'overview') as View, rawHash: window.location.hash, id: decodeRouteId(id), tab: ['health', 'details', 'logs'].includes(tab) ? tab as 'health' | 'details' | 'logs' : undefined, unit: decodeRouteId(unit) }; };
    const [route, setRoute] = useState(parse), committed = useRef(route), scroll = useRef(new Map<View, number>());
    useLayoutEffect(() => { committed.current = route; }, [route]);
    useEffect(() => {
        const change = () => {
            const main = document.getElementById('main-content');
            if (main && !committed.current.id) scroll.current.set(committed.current.view, main.scrollTop);
            setRoute(parse());
        };
        window.addEventListener('hashchange', change);
        return () => window.removeEventListener('hashchange', change);
    }, []);
    return { ...route, scrollTop: route.id ? 0 : scroll.current.get(route.view) ?? 0 };
}
const navigate = (view: View, id?: string) => { window.location.hash = `/${view}${id ? `/${encodeURIComponent(id)}` : ''}`; };
const nav = [{ id: 'overview', label: t("\u00DCbersicht"), icon: LayoutDashboard }, { id: 'devices', label: t("Ger\u00E4te"), icon: Monitor }, { id: 'cases', label: t("Untersuchungen"), icon: Activity }] as const;
export default function App() { useLocale(); return <AuthBoundary><WorkspaceApp /></AuthBoundary>; }
function WorkspaceApp() {
    const operator = useOperator()!;
    const route = useRoute();
    const previousRoute = useRef(route);
    const [data, setData] = useState<Overview | null>(null);
    const [fleetRevision, setFleetRevision] = useState(0);
    const [investigationScope, setInvestigationScope] = useState<InvestigationScope>('open');
    const [investigationOffset, setInvestigationOffset] = useState(0);
    const [caseScope, setCaseScope] = useState('active');
    const investigations = useInvestigations(operator.mode === 'lan' && operator.authenticated && (route.view === 'overview' || route.view === 'cases'), operator.expiresAt ?? null, String(fleetRevision), route.view === 'cases' ? investigationScope : 'open', route.view === 'cases' ? investigationOffset : 0, true);
    const showFleetIdentity = operator.mode === 'lan' && operator.authenticated && !!data && (route.view === 'overview' || route.view === 'settings' || route.view === 'devices' && !route.id);
    const fleetIdentity = useFleetIdentity(showFleetIdentity, operator.expiresAt ?? null, String(fleetRevision), true);
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(true);
    const { theme, setTheme } = operator;
    const [mobileNav, setMobileNav] = useState(false);
    const [shortcuts, setShortcuts] = useState(false);
    const [filters, setFilters] = useState<Filters>(defaultFilters);
    const [savedView, setSavedView] = useState<Filters | null>(() => savedFilters());
    const [savedNotice, setSavedNotice] = useState(false);
    const searchRef = useRef<HTMLInputElement>(null);
    const load = useCallback(async (refreshEvidence = true) => {
        setLoading(true);
        if (refreshEvidence) setFleetRevision(value => value + 1);
        setError('');
        try {
            const next = await request<Overview>('/overview');
            if (!Array.isArray(next.devices) || !Array.isArray(next.cases) || !next.stats)
                throw new Error(t("Die Antwort des Managers ist unvollst\u00E4ndig."));
            setData(next);
        }
        catch (err) {
            setError(err instanceof Error ? err.message : t("Daten konnten nicht geladen werden."));
        }
        finally {
            setLoading(false);
        }
    }, []);
    useEffect(() => { void load(false); }, [load]);
    useEffect(() => { setMobileNav(false); }, [route.view, route.id]);
    useLayoutEffect(() => { const main = document.getElementById("main-content"), previous = previousRoute.current; if(main) { main.scrollTop = route.scrollTop; if(previous.view === "devices" && previous.id && route.view === "devices" && !route.id) main.focus({preventScroll:true}); } previousRoute.current = route; }, [route.view, route.id]);
    useEffect(() => {
        const key = (event: KeyboardEvent) => {
            if (event.key !== 'Escape' && document.querySelector('[role="dialog"]'))
                return;
            const typing = event.target instanceof HTMLElement && ['INPUT', 'TEXTAREA', 'SELECT'].includes(event.target.tagName);
            if ((event.key === 'k' && (event.ctrlKey || event.metaKey)) || (event.key === '/' && !typing)) {
                event.preventDefault();
                navigate('devices');
                setTimeout(() => searchRef.current?.focus(), 80);
            }
            if (event.key === '?' && !typing) {
                event.preventDefault();
                setShortcuts(true);
            }
            if (event.key === 'Escape')
                setMobileNav(false);
        };
        window.addEventListener('keydown', key);
        return () => window.removeEventListener('keydown', key);
    }, []);
    const changeView = (view: View) => { navigate(view); setMobileNav(false); };
    const openInvestigations = () => { setCaseScope('active'); setInvestigationScope('open'); setInvestigationOffset(0); changeView('cases'); };
    const openDevice = (device: Device) => navigate('devices', device.id);
    const openCase = (item: Case) => navigate('cases', item.id);
    const goActivity = (item: ActivityType) => {
        if (item.caseId)
            navigate('cases', item.caseId);
        else if (item.deviceId)
            navigate('devices', item.deviceId);
    };
    const activeCases = data?.cases.filter(item => item.status !== 'resolved') || [];
    const openInvestigationCount = operator.mode === 'lan' ? investigations.counts?.open : activeCases.length;
    const title = route.view === 'settings' ? t("Einstellungen") : nav.find(item => item.id === route.view)?.label;
    const sourceCount = data?.devices.filter(device => ['sandbox','local'].includes(device.source)).length || 0;
    const lanCount = data?.devices.filter(device => device.source === 'lan').length || 0;
    const demoCount = data?.devices.filter(device => device.synthetic).length || 0;
    const filtered = data ? filterDevices(data.devices, filters, fleetIdentity.identities) : [];
    const activeFilters = [filters.platform, filters.status, filters.source].filter(v => v !== 'all').length + (filters.query ? 1 : 0);
    const patchFilters = (patch: Partial<Filters>) => setFilters(previous => ({ ...previous, ...patch }));
    const saveView = () => { saveLocal('local-rmm-saved-view', filters); setSavedView({ ...filters }); setSavedNotice(true); setTimeout(() => setSavedNotice(false), 2200); };
    const exportCSV = () => { const rows = [[t("Ger\u00E4t"), t("Betriebssystem"), t("Status"), t("Quelle"), 'CPU %', t("Speicher %"), t("Datentr\u00E4ger %"), t("Zuletzt gesehen")], ...filtered.map(d => [d.name, d.os, d.status, d.synthetic ? t("Synthetische Demo") : d.source === "lan" ? t("LAN-Agent") : t("Lokale Quelle"), d.cpu.value, d.memory.value, d.disk.value, d.lastSeen])]; const url = URL.createObjectURL(new Blob(['\uFEFF' + rows.map(row => row.map(csvCell).join(';')).join('\r\n')], { type: 'text/csv;charset=utf-8;' })); const a = document.createElement('a'); a.href = url; a.download = t('Dateiname CSV'); a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000); };
    return <div className="app-shell">
    <a className="skip-link" href="#main-content" onClick={event => { event.preventDefault(); document.getElementById("main-content")?.focus(); }}>{t("Zum Inhalt")}</a>
    {mobileNav && <button className="mobile-scrim" aria-label={t("Men\u00FC schlie\u00DFen")} onClick={() => setMobileNav(false)}/>}
    <aside className={`sidebar ${mobileNav ? 'is-open' : ''}`} aria-label={t("Hauptnavigation")}>
      <button className="brand" onClick={() => changeView('overview')}><Logo /><span>Tracebolt<span className="brand-tag">{t("WORKSPACE")}</span></span></button>
      <div className="workspace-label"><span className="workspace-avatar">L</span><span><strong>{operator.mode === "lan" ? t("LAN-Umgebung") : t("Lokale Umgebung")}</strong><small>{t("Entwicklungsprototyp")}</small></span><span className="local-dot"/></div>
      <div className="nav-label">{t("ARBEITSBEREICH")}</div>
      <nav>{nav.map(item => <button key={item.id} className={`nav-item ${route.view === item.id ? 'active' : ''}`} aria-current={route.view === item.id ? 'page' : undefined} onClick={() => changeView(item.id)}><item.icon size={18}/><span>{ui(item.label)}</span>{item.id === 'devices' && data && <span className="nav-number">{data.devices.length}</span>}{item.id === 'cases' && !!openInvestigationCount && <span className="nav-badge">{openInvestigationCount}</span>}</button>)}</nav>
      <div className="sidebar-bottom"><button className={`nav-item ${route.view === 'settings' ? 'active' : ''}`} onClick={() => changeView('settings')} aria-current={route.view === 'settings' ? 'page' : undefined}><Settings2 size={18}/><span>{t("Einstellungen")}</span></button><button className="sidebar-help" onClick={() => setShortcuts(true)}><Command size={15}/><span>{t("Tastenk\u00FCrzel")}</span><kbd>?</kbd></button><OperatorAccount /></div>
    </aside>
    <div className="main-shell">
      <header className="topbar"><div className="breadcrumb"><button className="icon-button mobile-menu" aria-label={t("Men\u00FC \u00F6ffnen")} aria-expanded={mobileNav} onClick={() => setMobileNav(!mobileNav)}><Menu size={20}/></button><PanelLeftClose size={17} className="desktop-sidebar-icon"/><span className="breadcrumb-root">{t("Arbeitsbereich")}</span><ChevronRight size={13}/><strong>{ui(title || "")}</strong>{route.view === 'cases' && route.id && <><ChevronRight size={13} className="breadcrumb-case-divider"/><span className="breadcrumb-id">{route.id}</span></>}</div><div className="topbar-actions"><LanguageSelector /><span className="environment-badge"><span /> {operator.mode === "lan" ? "LAN" : t("Lokal")}</span><span className="topbar-divider"/><button className="icon-button" onClick={() => setTheme(theme === 'light' ? 'dark' : 'light')} aria-label={theme === 'light' ? t("Dunkles Design aktivieren") : t("Helles Design aktivieren")} title={theme === 'light' ? t("Dunkles Design") : t("Helles Design")}>{theme === 'light' ? <Moon size={17}/> : <Sun size={17}/>}</button></div></header>
      {operator.insecureTestMode && <TransportWarning />}
      <main id="main-content" tabIndex={-1} className={`main-content ${route.view === 'cases' && route.id ? 'case-main' : route.view === 'devices' && route.id ? 'device-main' : ''}`}>
        <div className="demo-banner"><span className="demo-banner-label"><Database size={14}/>{" " + (operator.mode === "lan" ? t("LAN-PILOT") : t("DEMO + LOKAL"))}</span><span>{operator.mode === "lan" ? t("Kein Produktivbetrieb.") : t("Keine angebundene Produktivflotte.")}</span><button onClick={() => changeView('settings')} aria-label={t("\u00DCber Datenquellen und Grenzen")}><ChevronRight size={16}/></button></div>
        {error && <div className="error-banner" role="alert"><TriangleAlert size={20}/><div><strong>{data ? t("Aktualisierung fehlgeschlagen") : t("Keine Verbindung zum lokalen Manager")}</strong><p>{ui(error)} {data ? t("Die angezeigten Daten stammen aus dem letzten erfolgreichen Abruf.") : t("Es werden keine Ersatz-Demodaten eingeblendet.")}</p></div><button className="button small" onClick={() => void load()} disabled={loading}>{t("Erneut versuchen")}</button></div>}
        {route.view === 'devices' && route.id ? <DeviceDetail key={`${route.id}:${route.tab ?? ''}:${route.unit ?? ''}`} id={route.id} initialTab={route.tab} initialUnit={route.unit} onClose={() => navigate('devices')} onCase={id => navigate('cases', id)}/> : !data && loading ? <div className="initial-loading"><Loading /><div className="skeleton-row"><i /><i /><i /></div><div className="skeleton-panel"/></div> : !data ? <EmptyState title={t("Keine Daten verfügbar")} detail={t("Manager starten und erneut laden.")}/> : <>
        {route.view === 'overview' && <>
          <div className="page-heading"><div><h1>{t("\u00DCbersicht")}</h1></div><button className="button" onClick={() => changeView('devices')}>{t("Zum Ger\u00E4teinventar")}<ArrowRight size={15}/></button></div>
          <div className="summary-strip"><button onClick={() => { setFilters(defaultFilters); changeView('devices'); }}><span className="summary-label"><Monitor size={16}/>{" " + t("Ger\u00E4te gesamt")}</span><div><strong>{data.stats.totalDevices}</strong><span>{operator.mode === "lan" ? t("LAN-Agenten: {0}",{0:lanCount}) : <>{demoCount}{" " + t("Demo \u00B7") + " "}{sourceCount}{" " + t("lokal")}</>}</span></div></button><button onClick={() => { setFilters({ ...defaultFilters, status: 'healthy' }); changeView('devices'); }}><span className="summary-label"><span className="dot green"/>{" " + t("Unauff\u00E4llig")}</span><div><strong>{data.stats.healthyDevices}</strong><span>{t("beobachteter Zustand")}</span></div></button><button onClick={() => { setFilters({ ...defaultFilters, status: 'needs-attention' }); changeView('devices'); }}><span className="summary-label"><span className="dot amber"/>{" " + t("Aufmerksamkeit")}</span><div><strong>{data.stats.attentionDevices}</strong><span>{t("Warnung oder kritisch")}</span></div></button><button onClick={openInvestigations}><span className="summary-label"><Activity size={16}/>{" " + t("Offene Untersuchungen")}</span><div><strong>{operator.mode === 'lan' ? openInvestigationCount ?? '—' : data.stats.openCases}</strong><span>{operator.mode === 'lan' ? t("Health-Warnungen") : <>{data.stats.criticalCases}{" " + t("kritisch")}</>}</span></div></button></div>
          <div className="overview-grid"><section className="panel attention-panel"><SectionHead title={t("Offene F\u00E4lle")} count={openInvestigationCount} action={<button className="text-button" onClick={openInvestigations}>{t("Alle ansehen")}<ArrowRight size={14}/></button>}/>{operator.mode === "lan" ? <><InvestigationNotice resource={investigations}/>{investigations.view && (investigations.view.items.length ? <InvestigationList view={investigations.view} devices={data.devices} concise onAll={openInvestigations}/> : <EmptyState title={t("Keine offenen Untersuchungen")} detail={t("Keine offenen Health-Vorfälle. Der Gerätezustand kann trotzdem unbekannt sein.")}/>)}</> : activeCases.length ? <CaseList cases={activeCases.slice(0, 4)} onSelect={openCase} concise/> : <EmptyState title={t("Keine offenen Untersuchungen")} detail={t("Die verf\u00FCgbaren Regeln melden derzeit keinen offenen Fall.")}/>}</section><section className="panel activity-panel"><SectionHead title={t("Letzte \u00C4nderungen")} action={<span className="live-label"><span />{" " + t("Lokales Protokoll")}</span>}/>{data.activity.length ? <ActivityList items={data.activity.slice(0, 4)} onNavigate={goActivity}/> : <p className="panel-empty">{t("Noch keine \u00C4nderungen erfasst.")}</p>}</section></div>
          <ApplicationChecksPanel />
          <section className="panel fleet-panel"><SectionHead title={t("Ger\u00E4te im \u00DCberblick")} count={data.devices.length} action={<button className="text-button" onClick={() => changeView('devices')}>{t("Inventar \u00F6ffnen")}<ArrowRight size={14}/></button>}/>{showFleetIdentity && <FleetIdentityNotice resource={fleetIdentity}/>}<DeviceTable identities={fleetIdentity.identities} devices={filterDevices(data.devices, defaultFilters, fleetIdentity.identities).slice(0, 6)} onSelect={openDevice} overview/><div className="table-footer"><span><span className="dot teal"/> {Math.min(6, data.devices.length)}{" " + t("von") + " "}{data.devices.length}{" " + t("Ger\u00E4ten \u00B7 nach Aufmerksamkeit sortiert")}</span></div></section>
        </>}
        {route.view === 'devices' && <>
          <div className="page-heading"><div><h1>{t("Ger\u00E4te")}</h1></div><button className="button" onClick={exportCSV} disabled={!filtered.length}><ArrowDownToLine size={15}/>{t("CSV exportieren")}</button></div>
          {operator.mode === "lan" && <EnrollmentSection key={`enrollment-${operator.mode}-${operator.insecureTestMode}`} onChanged={load} onDevice={id=>navigate("devices",id)} deviceIds={data.devices.map(device=>device.id)}/>}
          <div className="inventory-tabs"><button className={!activeFilters ? 'selected' : ''} onClick={() => setFilters(defaultFilters)}>{t("Alle Ger\u00E4te")}<span>{data.devices.length}</span></button>{sourceCount > 0 && <button className={filters.source === 'local' ? 'selected' : ''} onClick={() => setFilters({ ...defaultFilters, source: 'local' })}><Terminal size={14}/>{t("Lokale Quellen")}<span>{sourceCount}</span></button>}{lanCount > 0 && <button className={filters.source === "lan" ? "selected" : ""} onClick={() => setFilters({...defaultFilters,source:"lan"})}><Monitor size={14}/>{t("LAN-Agenten")}<span>{lanCount}</span></button>}{demoCount > 0 && <button className={filters.source === 'synthetic' ? 'selected' : ''} onClick={() => setFilters({ ...defaultFilters, source: 'synthetic' })}><Database size={14}/>{t("Demo-Ger\u00E4te")}<span>{demoCount}</span></button>}{savedView && <button className="saved-tab" onClick={() => setFilters({ ...savedView })}><Bookmark size={14}/>{t("Gespeicherte Ansicht")}</button>}</div>
          <section className="panel inventory-panel"><div className="filter-toolbar"><label className="search-field"><Search size={17}/><input ref={searchRef} aria-label={t("Ger\u00E4te durchsuchen")} placeholder={t("Name, Standort oder IP suchen \u2026")} value={filters.query} onChange={event => patchFilters({ query: event.target.value })}/>{filters.query ? <button aria-label={t("Suche leeren")} onClick={() => patchFilters({ query: '' })}><X size={14}/></button> : <kbd>⌘ K</kbd>}</label><div className="select-wrap"><Monitor size={14}/><select aria-label={t("Nach Betriebssystem filtern")} value={filters.platform} onChange={e => patchFilters({ platform: e.target.value })}><option value="all">{t("Alle Systeme")}</option>{Object.entries(platformLabels).map(([value, label]) => <option value={value} key={value}>{label}</option>)}</select><ChevronDown size={12}/></div><div className="select-wrap"><Filter size={14}/><select aria-label={t("Nach Status filtern")} value={filters.status} onChange={e => patchFilters({ status: e.target.value })}><option value="all">{t("Alle Status")}</option><option value="healthy">{t("Unauff\u00E4llig")}</option><option value="needs-attention">{t("Aufmerksamkeit")}</option><option value="attention">{t("Pr\u00FCfen")}</option><option value="critical">{t("Kritisch")}</option><option value="stale">{t("Veraltet")}</option><option value="unknown">{t("Unbekannt")}</option></select><ChevronDown size={12}/></div><button className="button save-view" onClick={saveView}>{savedNotice ? <Check size={15}/> : <Bookmark size={15}/>}<span>{savedNotice ? t("Gespeichert") : t("Ansicht speichern")}</span></button></div><div className="inventory-meta"><span>{filtered.length}{" " + t("Ger\u00E4te")}{activeFilters > 0 && <> · {activeFilters}{" " + t("Filter")}<button className="inline-reset" onClick={() => setFilters(defaultFilters)}>{t("Zur\u00FCcksetzen")}<X size={12}/></button></>}</span><label className="sort-select"><ListFilter size={14}/><select aria-label={t("Ger\u00E4te sortieren")} value={filters.sort} onChange={event => patchFilters({ sort: event.target.value })}><option value="priority">{t("Aufmerksamkeit zuerst")}</option><option value="name">{t("Name A\u2013Z")}</option><option value="seen">{t("Zuletzt gesehen")}</option></select><ChevronDown size={12}/></label></div>{showFleetIdentity && <FleetIdentityNotice resource={fleetIdentity}/>} {filtered.length ? <DeviceTable identities={fleetIdentity.identities} devices={filtered} onSelect={openDevice}/> : <EmptyState title={t("Keine passenden Ger\u00E4te")} detail={t("Suche oder Filter anpassen.")} action={<button className="button" onClick={() => setFilters(defaultFilters)}>{t("Filter zur\u00FCcksetzen")}</button>}/>}<div className="table-footer"><span>{filtered.length}{" " + t("von") + " "}{data.devices.length}{" " + t("Ger\u00E4ten")}</span></div></section>
        </>}
        {route.view === 'cases' && (operator.mode === 'lan' ? <InvestigationsPage resource={investigations} devices={data.devices} scope={investigationScope} offset={investigationOffset} onScope={scope => { setInvestigationScope(scope); setInvestigationOffset(0); }} onPage={setInvestigationOffset}/> : route.id ? <CaseDetail key={route.id} id={route.id} onBack={() => navigate('cases')} onDevice={id => navigate('devices', id)} onChanged={() => void load()} onSettings={() => navigate('settings')}/> : <CasesPage cases={data.cases} onSelect={openCase} scope={caseScope} onScope={setCaseScope}/>)}
        {route.view === 'settings' && <SettingsPage theme={theme} onTheme={setTheme} fleetIdentity={fleetIdentity} investigationReadiness={investigations.readiness} applicationCheckEntry={route.id === applicationCheckSetupId}/>}
        <footer className="page-footer"><span><span className={`dot ${error ? 'amber' : 'teal'}`}/>{error ? t("Letzter erfolgreicher Abruf") : t("Manager verbunden")}<span className="footer-dot">·</span><time dateTime={data.generatedAt} title={fullDate(data.generatedAt)}>{fullDate(data.generatedAt)}</time></span><button onClick={() => void load()} disabled={loading}><RefreshCw size={13} className={loading ? 'spin' : ''}/>{loading ? t("Wird aktualisiert") : t("Aktualisieren")}</button></footer>
        </>}
      </main>
    </div>
    {shortcuts && <Dialog title={t("Tastenk\u00FCrzel")} onClose={() => setShortcuts(false)} className="shortcuts-modal"><h2>{t("Tastenk\u00FCrzel")}</h2><dl><div><dt>{t("Ger\u00E4te suchen")}</dt><dd><kbd>{t("\u2318 / Strg")}</kbd> <kbd>K</kbd> {t("oder")} <kbd>/</kbd></dd></div><div><dt>{t("Dialog schlie\u00DFen")}</dt><dd><kbd>Esc</kbd></dd></div><div><dt>{t("Diese \u00DCbersicht")}</dt><dd><kbd>?</kbd></dd></div><div><dt>{t("Elemente ansteuern")}</dt><dd><kbd>Tab</kbd></dd></div></dl></Dialog>}
  </div>;
}
function CasesPage({ cases, onSelect, scope, onScope }: {
    cases: Case[];
    scope: string;
    onScope: (scope: string) => void;
    onSelect: (item: Case) => void;
}) { const operator = useOperator(); const filtered = cases.filter(c => scope === 'all' || (scope === 'active' ? c.status !== 'resolved' : c.status === 'resolved')); return <><div className="page-heading"><div><h1>{t("Untersuchungen")}</h1></div><span className="rule-badge"><ShieldCheck size={15}/>{t("Deterministische Regeln")}</span></div><div className="inventory-tabs">{[{ id: 'active', label: t("Offene F\u00E4lle") }, { id: 'resolved', label: t("Abgeschlossen") }, { id: 'all', label: t("Alle F\u00E4lle") }].map(item => <button className={scope === item.id ? 'selected' : ''} key={item.id} onClick={() => onScope(item.id)}>{ui(item.label)}<span>{cases.filter(c => item.id === 'all' || (item.id === 'active' ? c.status !== 'resolved' : c.status === 'resolved')).length}</span></button>)}</div><section className="panel">{filtered.length ? <div className="full-case-list">{filtered.map(item => <div className="full-case-item" key={item.id}><CaseList cases={[item]} onSelect={onSelect}/><div className="full-case-bottom"><p>{item.summary}</p><CaseStatus status={item.status}/></div></div>)}</div> : <EmptyState title={t("Keine Untersuchungen")} detail={operator?.mode === "lan" ? t("Noch keine automatische Gerätebewertung. Fehlende Befunde bedeuten keinen gesunden Zustand.") : t("Keine Fälle in dieser Ansicht.")}/>}</section></>; }
function SettingsPage({ theme, onTheme, fleetIdentity, investigationReadiness, applicationCheckEntry }: {
    fleetIdentity: FleetIdentityResource;
    investigationReadiness: 'ready' | 'unavailable' | 'unknown';
    applicationCheckEntry: boolean;
    theme: 'light' | 'dark';
    onTheme: (theme: 'light' | 'dark') => void;
}) {
    const operator = useOperator(), [locale] = useLocale();
    const [data, setData] = useState<Capabilities | null>(null);
    const [error, setError] = useState('');
    const [retry, setRetry] = useState(0);
    useEffect(() => {
        let alive = true;
        setError('');
        request<Capabilities>('/capabilities').then(value => {
            if (alive)
                setData(value);
        }).catch(err => {
            if (alive)
                setError(err.message);
        });
        return () => { alive = false; };
    }, [retry]);
    return <><div className="page-heading"><div><h1>{t("Einstellungen")}</h1></div><span className="version-badge">v{data?.version || '0.1.0'}</span></div><AlarmStatusPanel /><AlarmSettingsPanel /><ApplicationCheckSettingsPanel initialAdd={applicationCheckEntry}/><AIProviderSettings /><ProactiveAISettingsPanel fleetIdentity={fleetIdentity}/>{operator?.mode === 'lan' && operator.authenticated && <OfflineCatalogPanel sessionKey={operator.expiresAt ?? undefined}/>}<div className="settings-grid"><section className="panel settings-panel"><SectionHead title={t("Lokale Laufzeit")} action={<Terminal size={18}/>}/><div className="setting-row"><span><strong>{t("Manager")}</strong><small>{t("API \u00FCber dieselbe Adresse")}</small></span><span className="mono">{window.location.host}</span></div><div className="setting-row"><span><strong>{t("Speicherung")}</strong><small>{t("Auf dem Rechner des Managers")}</small></span><span>{data?.persistence || t("Wird geladen \u2026")}</span></div><div className="setting-row"><span><strong>{t("Darstellung")}</strong><small>{t("Wird in diesem Browser gespeichert")}</small></span><div className="theme-buttons"><button aria-pressed={theme === 'light'} onClick={() => onTheme('light')}><Sun size={15}/>{t("Hell")}</button><button aria-pressed={theme === 'dark'} onClick={() => onTheme('dark')}><Moon size={15}/>{t("Dunkel")}</button></div></div></section><section className="panel settings-panel"><SectionHead title={t("Quellen & Herkunft")} action={<Database size={18}/>}/>{data?.syntheticFleet && <div className="source-description"><Source synthetic={true}/><p>{t("Synthetische Beispiele, keine echten Geräte.")}</p></div>}<div className="source-description"><Source synthetic={false} source={operator?.mode === "lan" ? "lan" : undefined}/><h3>{operator?.mode === "lan" ? t("Freigegebene Agenten") : t("Lokaler Collector")}</h3><p>{data?.realCollector || t("Die verf\u00FCgbaren Collector-Funktionen werden vom Manager geladen.")}</p></div></section><section className="panel settings-capabilities"><SectionHead title={t("Verf\u00FCgbare Funktionen")} action={<SlidersHorizontal size={18}/>}/>{error ? <div className="settings-error" role="alert"><p>{ui(error)}</p><button className="button" onClick={() => setRetry(v => v + 1)}>{t("Erneut versuchen")}</button></div> : !data ? <Loading /> : <><div className="capability-line"><span><strong>{t("Lokales Inventar & Belege")}</strong><small>{t("Lesende Erfassung im Umfang des jeweiligen Collectors")}</small></span><span className="availability available"><Check size={13}/>{t("Verf\u00FCgbar")}</span></div><div className="capability-line"><span><strong>{t("Regelbasierte Untersuchungen")}</strong><small>{operator?.mode === "lan" ? (locale === 'de' ? 'Health: Agentkontakt, Root-Dateisystem und ausgewählte Dienste.' : 'Health: agent contact, root filesystem and selected services.') : t("Feste Regeln, dokumentierte Quellen, lokale Notizen")}</small></span><span className={`availability ${operator?.mode !== "lan" || investigationReadiness === 'ready' ? "available" : ""}`}>{operator?.mode === "lan" ? investigationReadiness === 'ready' ? t("Verfügbar") : investigationReadiness === 'unavailable' ? t("Nicht verfügbar") : (locale === 'de' ? 'Status unbekannt' : 'Status unknown') : <><Check size={13}/>{t("Demo")}</>}</span></div>{data.manualDeviceApproval && <div className="capability-line"><span><strong>{t("Manuelle Agentenfreigabe")}</strong><small>{t("Identität wird vom Manager geprüft")}</small></span><span className="availability available"><Check size={13}/>{t("Verfügbar")}</span></div>}{[{ name: t("Automatisches Agenten-Enrollment"), value: data.remoteEnrollment, detail: t("Kein Remote-Rollout oder produktives Enrollment") }, { name: t("Shell oder Ma\u00DFnahmen ausf\u00FChren"), value: data.shellExecution, detail: t("Diagnoseschritte werden ausschlie\u00DFlich beschrieben") }].map(item => <div className="capability-line" key={item.name}><span><strong>{item.name}</strong><small>{item.detail}</small></span><span className={`availability ${item.value ? 'available' : ''}`}>{item.value ? <Check size={13}/> : <span className="unavailable-symbol">—</span>}{item.value ? t("Verf\u00FCgbar") : t("Nicht verf\u00FCgbar")}</span></div>)}</>}</section></div>{data && <div className="scope-note settings-limitations"><TriangleAlert size={19}/><div><strong>{operator?.mode === "lan" ? t("LAN-Pilot \u00B7 kein Produktivbetrieb") : t("Lokaler Prototyp \u00B7 kein Produktivbetrieb")}</strong><details className="settings-boundary-details"><summary>{t("Grenzen & Details")}<ChevronDown size={14}/></summary><ul>{data.limitations.map(item => <li key={item}>{item}</li>)}</ul></details></div></div>}</>;
}
