import { useEffect, useId, useState } from 'react';
import type { ReactNode } from 'react';
import { Activity, Boxes, Clock3, Database, HardDrive, Info, LoaderCircle, Network, RefreshCw, Search, ServerCog, ShieldQuestion, TriangleAlert } from 'lucide-react';
import { APIError, AUTH_REQUIRED_EVENT, request } from './api';
import { useOperator } from './auth';
import { useLocale } from './i18n';
import type { Locale } from './i18n';
import { effectiveOperationalStatus, operationalNow, OPERATIONAL_PROFILE, SECTION_LIMITS, SECTION_NAMES, validOperationalView } from './operational-types';
import type { OperationalEvent, OperationalNetwork, OperationalProcess, OperationalQuality, OperationalReason, OperationalSectionName, OperationalSections, OperationalService, OperationalSoftware, OperationalStatus, OperationalView, OperationalVolume } from './operational-types';
import './operational.css';

export interface OperationalInventoryPanelProps { deviceId: string; sessionKey?: string | number }
const copy = {
    en: {
        title: 'Operational inventory', subtitle: 'Read-only observations reported by the Linux agent', refresh: 'Refresh observations', loading: 'Loading operational inventory…',
        loadError: 'Operational inventory could not be loaded. Try again.', invalid: 'The manager returned an unsupported or invalid inventory response.', timeout: 'The manager did not respond in time. Try again.', missing: 'This device is no longer available.', session: 'Your session has ended. Sign in again to view inventory.',
        source: 'Source', profile: 'Collection profile', collected: 'Collected', received: 'Received', age: 'Observation age', seconds: 's',
        privacy: 'This opt-in profile includes source names and mount paths, which can contain personal or secret-like labels. These observations stay outside AI evidence. No commands are run from this panel and raw logs are excluded.',
        healthyNote: '“Collected” describes data availability, not device health or security.',
        scopeNote: 'Scope: the agent-visible OS namespace. Service sandboxing can limit mount, process and journal coverage.',
        notConfigured: 'This device is not enrolled for the Linux operational profile. No operational inventory has been collected.', awaiting: 'The operational profile is selected. Waiting for its first accepted observation.', revoked: 'This device’s identity is revoked. Any retained observations are historical.', unavailable: 'Current operational observations are unavailable.',
        fresh: 'Within collection window', stale: 'Stale observation', not_configured: 'Not configured', revokedLabel: 'Revoked', awaitingLabel: 'Awaiting observations', unavailableLabel: 'Unavailable',
        volumes: 'Volumes', network: 'Network', services: 'Services', processes: 'Processes', software: 'Software', events: 'Events',
        available: 'Collected', partial: 'Partial coverage', unknown: 'Unknown', denied: 'Access denied', retained: 'Retained / stale',
        sectionTime: 'Observed', latest: 'Latest attempt', reason: 'Reason', cap: 'Record cap', complete: 'Complete coverage', incomplete: 'Incomplete coverage', truncated: 'Truncated sample', exact: 'Exact discovered count', lowerBound: 'At least', discovered: 'discovered', shown: 'records received', matches: 'matches in this received sample',
        filter: 'Filter received records', filterHint: 'Filtering only the bounded records shown here.', empty: 'No eligible records were observed in this collection.', noMatches: 'No received records match this filter.', noData: 'No current records are available.', retainedNote: 'Showing the last successful observation. It does not describe the current state.',
        none: 'No collection error', source_missing: 'Source missing', permission_denied: 'Permission denied', not_supported: 'Not supported', timeoutReason: 'Collection timed out', invalid_source: 'Invalid source data', read_failed: 'Source read failed', item_limit: 'Record limit reached', byte_limit: 'Size limit reached', remote_filesystem_skipped: 'Remote filesystem not measured', tool_unavailable: 'Required tool unavailable', not_implemented: 'No assessment adapter is implemented',
        updates: 'Available updates', vulnerabilities: 'Vulnerabilities / CVEs', assessment: 'Unknown · Not assessed', assessmentNote: 'Installed package versions alone do not establish update availability or vulnerability status.',
        mount: 'Mount point', filesystem: 'Filesystem', kind: 'Kind', capacity: 'Capacity', free: 'Available', used: 'Used', measurement: 'Measurement', interface: 'Interface', state: 'State', receivedBytes: 'Received bytes', sentBytes: 'Sent bytes', rxErrors: 'RX errors', txErrors: 'TX errors', ipv4: 'IPv4 count', ipv6: 'IPv6 count', name: 'Name', load: 'Load', active: 'Active state', substate: 'Substate', parent: 'Parent PID', rss: 'Resident memory', cpu: 'CPU time (s)', threads: 'Threads', version: 'Installed version', architecture: 'Architecture', manager: 'Manager', unit: 'Unit', priority: 'Priority', occurrences: 'Count', first: 'First seen', last: 'Last seen', messageId: 'Message ID', servicesNote: 'Loaded system service units only. Unloaded installed units and per-user services are outside this collection.', eventGroups: 'event groups received', sourceEvents: 'source events discovered', metadata: 'Metadata only · up to a 15-minute window. Message text is never included.', processNote: 'CPU time is cumulative, not current CPU utilization. Command lines, environments and user IDs are excluded.', networkNote: 'Interface counters and address counts only. IP and MAC addresses are excluded.', softwareNote: 'Installed packages only. The received sample cannot prove that a package is absent.',
        local: 'Local', remote: 'Remote', virtual: 'Virtual', up: 'Up', down: 'Down', loaded: 'Loaded', not_found: 'Not found', masked: 'Masked', activeState: 'Active', inactive: 'Inactive', failed: 'Failed', activating: 'Activating', deactivating: 'Deactivating', reloading: 'Reloading', running: 'Running', exited: 'Exited', dead: 'Dead', other: 'Other', sleeping: 'Sleeping', stopped: 'Stopped', zombie: 'Zombie', idle: 'Idle',
    },
    de: {
        title: 'Betriebsinventar', subtitle: 'Lesende Beobachtungen des Linux-Agenten', refresh: 'Beobachtungen aktualisieren', loading: 'Betriebsinventar wird geladen…',
        loadError: 'Das Betriebsinventar konnte nicht geladen werden. Erneut versuchen.', invalid: 'Der Manager hat ein nicht unterstütztes oder ungültiges Inventar geliefert.', timeout: 'Der Manager hat nicht rechtzeitig geantwortet. Erneut versuchen.', missing: 'Dieses Gerät ist nicht mehr verfügbar.', session: 'Die Sitzung ist beendet. Für das Inventar erneut anmelden.',
        source: 'Quelle', profile: 'Erfassungsprofil', collected: 'Erfasst', received: 'Empfangen', age: 'Alter der Beobachtung', seconds: 's',
        privacy: 'Dieses ausdrücklich gewählte Profil enthält Quellnamen und Einhängepfade, die persönliche oder geheimnisähnliche Angaben enthalten können. Diese Beobachtungen bleiben außerhalb der KI-Belege. Dieses Panel führt keine Befehle aus; Rohprotokolle sind ausgeschlossen.',
        healthyNote: '„Erfasst“ beschreibt die Datenverfügbarkeit, nicht den Gesundheits- oder Sicherheitszustand des Geräts.',
        scopeNote: 'Umfang: der für den Agenten sichtbare Betriebssystem-Namensraum. Die Dienst-Sandbox kann Einhängepunkte, Prozesse und Journalzugriff begrenzen.',
        notConfigured: 'Dieses Gerät ist nicht für das Linux-Betriebsprofil registriert. Es wurde kein Betriebsinventar erfasst.', awaiting: 'Das Betriebsprofil ist ausgewählt. Die erste akzeptierte Beobachtung steht noch aus.', revoked: 'Die Identität dieses Geräts wurde widerrufen. Aufbewahrte Beobachtungen sind historisch.', unavailable: 'Aktuelle Betriebsbeobachtungen sind nicht verfügbar.',
        fresh: 'Im Erfassungszeitfenster', stale: 'Veraltete Beobachtung', not_configured: 'Nicht eingerichtet', revokedLabel: 'Widerrufen', awaitingLabel: 'Beobachtungen ausstehend', unavailableLabel: 'Nicht verfügbar',
        volumes: 'Datenträger', network: 'Netzwerk', services: 'Dienste', processes: 'Prozesse', software: 'Software', events: 'Ereignisse',
        available: 'Erfasst', partial: 'Teilweise erfasst', unknown: 'Unbekannt', denied: 'Zugriff verweigert', retained: 'Aufbewahrt / veraltet',
        sectionTime: 'Beobachtet', latest: 'Letzter Versuch', reason: 'Grund', cap: 'Eintragslimit', complete: 'Vollständig erfasst', incomplete: 'Unvollständig erfasst', truncated: 'Begrenzte Stichprobe', exact: 'Exakte gefundene Anzahl', lowerBound: 'Mindestens', discovered: 'gefunden', shown: 'Einträge empfangen', matches: 'Treffer in dieser empfangenen Stichprobe',
        filter: 'Empfangene Einträge filtern', filterHint: 'Filtert nur die hier empfangenen, begrenzten Einträge.', empty: 'In dieser Erfassung wurden keine passenden Einträge beobachtet.', noMatches: 'Keine empfangenen Einträge entsprechen dem Filter.', noData: 'Keine aktuellen Einträge verfügbar.', retainedNote: 'Die letzte erfolgreiche Beobachtung wird angezeigt. Sie beschreibt nicht den aktuellen Zustand.',
        none: 'Kein Erfassungsfehler', source_missing: 'Quelle fehlt', permission_denied: 'Berechtigung verweigert', not_supported: 'Nicht unterstützt', timeoutReason: 'Erfassung hat das Zeitlimit erreicht', invalid_source: 'Ungültige Quelldaten', read_failed: 'Quelle konnte nicht gelesen werden', item_limit: 'Eintragslimit erreicht', byte_limit: 'Größenlimit erreicht', remote_filesystem_skipped: 'Entferntes Dateisystem nicht gemessen', tool_unavailable: 'Benötigtes Werkzeug nicht verfügbar', not_implemented: 'Kein Bewertungsadapter implementiert',
        updates: 'Verfügbare Updates', vulnerabilities: 'Schwachstellen / CVEs', assessment: 'Unbekannt · Nicht bewertet', assessmentNote: 'Installierte Paketversionen allein belegen weder verfügbare Updates noch den Schwachstellenstatus.',
        mount: 'Einhängepunkt', filesystem: 'Dateisystem', kind: 'Art', capacity: 'Kapazität', free: 'Verfügbar', used: 'Belegt', measurement: 'Messung', interface: 'Schnittstelle', state: 'Zustand', receivedBytes: 'Empfangene Bytes', sentBytes: 'Gesendete Bytes', rxErrors: 'RX-Fehler', txErrors: 'TX-Fehler', ipv4: 'IPv4-Anzahl', ipv6: 'IPv6-Anzahl', name: 'Name', load: 'Ladezustand', active: 'Aktivitätszustand', substate: 'Unterzustand', parent: 'Eltern-PID', rss: 'Residenter Speicher', cpu: 'CPU-Zeit (s)', threads: 'Threads', version: 'Installierte Version', architecture: 'Architektur', manager: 'Paketverwaltung', unit: 'Unit', priority: 'Priorität', occurrences: 'Anzahl', first: 'Erstmals gesehen', last: 'Zuletzt gesehen', messageId: 'Meldungs-ID', servicesNote: 'Nur geladene Systemdienst-Units. Nicht geladene installierte Units und benutzerspezifische Dienste sind nicht Teil dieser Erfassung.', eventGroups: 'Ereignisgruppen empfangen', sourceEvents: 'Quellereignisse gefunden', metadata: 'Nur Metadaten · maximal 15 Minuten. Meldungstexte sind nie enthalten.', processNote: 'Die CPU-Zeit ist kumulativ, keine aktuelle CPU-Auslastung. Befehlszeilen, Umgebungsvariablen und Nutzer-IDs sind ausgeschlossen.', networkNote: 'Nur Schnittstellenzähler und Adressanzahlen. IP- und MAC-Adressen sind ausgeschlossen.', softwareNote: 'Nur installierte Pakete. Die empfangene Stichprobe kann die Abwesenheit eines Pakets nicht belegen.',
        local: 'Lokal', remote: 'Entfernt', virtual: 'Virtuell', up: 'Aktiv', down: 'Inaktiv', loaded: 'Geladen', not_found: 'Nicht gefunden', masked: 'Maskiert', activeState: 'Aktiv', inactive: 'Inaktiv', failed: 'Fehlgeschlagen', activating: 'Wird aktiviert', deactivating: 'Wird deaktiviert', reloading: 'Wird neu geladen', running: 'Läuft', exited: 'Beendet', dead: 'Beendet', other: 'Sonstiges', sleeping: 'Wartend', stopped: 'Gestoppt', zombie: 'Zombie', idle: 'Leerlauf',
    },
};
type Copy = typeof copy.en;
function reasonLabel(reason: OperationalReason, labels: Copy): string { return reason === 'timeout' ? labels.timeoutReason : labels[reason]; }
function statusLabel(status: OperationalStatus, labels: Copy): string { return status === 'revoked' ? labels.revokedLabel : status === 'awaiting' ? labels.awaitingLabel : status === 'unavailable' ? labels.unavailableLabel : labels[status]; }
function enumLabel(value: string, labels: Copy): string { return value === 'active' ? labels.activeState : value in labels ? labels[value as keyof Copy] : value; }
function date(value: string, locale: Locale): string { return new Intl.DateTimeFormat(locale === 'de' ? 'de-DE' : 'en-GB', { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', timeZone: 'UTC' }).format(new Date(value)) + ' UTC'; }
function number(value: number | null, locale: Locale, labels: Copy): string { return value === null ? labels.unknown : new Intl.NumberFormat(locale, { maximumFractionDigits: 2 }).format(value); }
function bytes(value: number | null, locale: Locale, labels: Copy): string {
    if (value === null) return labels.unknown;
    const power = value === 0 ? 0 : Math.min(5, Math.floor(Math.log(value) / Math.log(1024)));
    return `${number(value / 1024 ** power, locale, labels)} ${['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'][power]}`;
}
const icons = { volumes: HardDrive, network: Network, services: ServerCog, processes: Activity, software: Boxes, events: Database };
type Section = OperationalSections[OperationalSectionName];
function currentSection(view: OperationalView, name: OperationalSectionName): { latest: Section | null; shown: Section | null; retained: boolean } {
    const latest = view.snapshot?.sections[name] ?? null;
    const unavailable = latest === null || latest.meta.quality === 'unknown' || latest.meta.quality === 'denied';
    const retained = unavailable && view.lastGood[name] !== null;
    return { latest, shown: retained ? view.lastGood[name] : latest, retained };
}
function qualityLabel(section: Section | null, retained: boolean, stale: boolean, labels: Copy): string {
    if (retained) return labels.retained;
    if (!section) return labels.unknown;
    if (section.meta.quality === 'denied') return labels.denied;
    if (section.meta.quality === 'unknown') return labels.unknown;
    if (section.meta.quality === 'stale' || stale) return labels.stale;
    return section.meta.complete ? labels.available : labels.partial;
}
function qualityTone(section: Section | null, retained: boolean, stale: boolean): string {
    return retained || stale || section?.meta.quality === 'stale' || section?.meta.truncated ? 'caution' : section?.meta.quality === 'denied' ? 'denied' : 'neutral';
}
function Measurement({ quality, reason, labels }: { quality: OperationalQuality; reason: OperationalReason; labels: Copy }) {
    return <span className={`operational-measurement ${quality === 'denied' ? 'denied' : ''}`}>{quality === 'healthy' ? labels.available : quality === 'denied' ? labels.denied : quality === 'stale' ? labels.stale : labels.unknown}{reason !== 'none' && <small>{reasonLabel(reason, labels)}</small>}</span>;
}
function InventoryTable({ name, section, filter, locale }: { name: OperationalSectionName; section: Section; filter: string; locale: Locale }) {
    const labels = copy[locale];
    const fmt = (value: number | null) => number(value, locale, labels);
    const size = (value: number | null) => bytes(value, locale, labels);
    let headings: string[];
    let rows: { key: string; search: string; values: ReactNode[]; failed?: boolean }[];
    switch (name) {
        case 'volumes':
            headings = [labels.mount, labels.filesystem, labels.kind, labels.capacity, labels.free, labels.used, labels.measurement];
            rows = (section.items as OperationalVolume[]).map((v, i) => ({ key: `${v.id}-${i}`, search: `${v.mountPoint} ${v.filesystem} ${enumLabel(v.kind, labels)}`, values: [v.mountPoint, v.filesystem, enumLabel(v.kind, labels), size(v.totalBytes), size(v.availableBytes), v.usedPercent === null ? labels.unknown : `${fmt(v.usedPercent)}%`, <Measurement quality={v.measurementQuality} reason={v.measurementReason} labels={labels}/>] })); break;
        case 'network':
            headings = [labels.interface, labels.state, 'MTU', labels.receivedBytes, labels.sentBytes, labels.rxErrors, labels.txErrors, labels.ipv4, labels.ipv6];
            rows = (section.items as OperationalNetwork[]).map((v, i) => ({ key: `${v.name}-${i}`, search: `${v.name} ${enumLabel(v.state, labels)}`, values: [v.name, enumLabel(v.state, labels), fmt(v.mtu), size(v.rxBytes), size(v.txBytes), fmt(v.rxErrors), fmt(v.txErrors), fmt(v.ipv4Count), fmt(v.ipv6Count)] })); break;
        case 'services':
            headings = [labels.name, labels.load, labels.active, labels.substate];
            rows = (section.items as OperationalService[]).map((v, i) => ({ key: `${v.name}-${i}`, search: `${v.name} ${enumLabel(v.loadState, labels)} ${enumLabel(v.activeState, labels)} ${enumLabel(v.subState, labels)}`, failed: v.activeState === 'failed', values: [v.name, enumLabel(v.loadState, labels), enumLabel(v.activeState, labels), enumLabel(v.subState, labels)] })); break;
        case 'processes':
            headings = ['PID', labels.name, labels.parent, labels.state, labels.rss, labels.cpu, labels.threads];
            rows = (section.items as OperationalProcess[]).map((v, i) => ({ key: `${v.pid}-${i}`, search: `${v.pid} ${v.name} ${enumLabel(v.state, labels)}`, values: [String(v.pid), v.name, v.parentPid === null ? labels.unknown : String(v.parentPid), enumLabel(v.state, labels), size(v.rssBytes), fmt(v.cpuTimeSeconds), fmt(v.threads)] })); break;
        case 'software':
            headings = [labels.name, labels.version, labels.architecture, labels.manager];
            rows = (section.items as OperationalSoftware[]).map((v, i) => ({ key: `${v.name}-${v.architecture}-${i}`, search: `${v.name} ${v.version} ${v.architecture} ${v.manager}`, values: [v.name, v.version, v.architecture, v.manager] })); break;
        case 'events':
            headings = [labels.source, labels.unit, labels.priority, labels.occurrences, labels.first, labels.last, labels.messageId];
            rows = (section.items as OperationalEvent[]).map((v, i) => ({ key: `${v.source}-${i}`, search: `${v.source} ${v.unit} ${v.priority} ${v.messageId}`, values: [v.source, v.unit || '—', String(v.priority), fmt(v.count), date(v.firstSeen, locale), date(v.lastSeen, locale), v.messageId || '—'] })); break;
    }
    const matching = rows.filter(row => row.search.toLocaleLowerCase(locale).includes(filter.trim().toLocaleLowerCase(locale)));
    const note = name === 'events' ? labels.metadata : name === 'services' ? labels.servicesNote : name === 'processes' ? labels.processNote : name === 'network' ? labels.networkNote : name === 'software' ? labels.softwareNote : null;
    return <><div className="operational-table-scroll" tabIndex={0} role="region" aria-label={labels[name]}><table className="operational-table"><caption className="sr-only">{labels[name]} · {labels.filterHint}</caption><thead><tr>{headings.map(heading => <th key={heading} scope="col">{heading}</th>)}</tr></thead><tbody>{matching.map(row => <tr key={row.key} className={row.failed ? 'operational-failed-row' : undefined}>{row.values.map((value, index) => <td key={index}>{value}</td>)}</tr>)}</tbody></table>{matching.length === 0 && <p className="operational-empty">{rows.length > 0 ? labels.noMatches : section.meta.complete ? labels.empty : labels.noData}</p>}</div>{filter.trim() && <p className="operational-filter-count" role="status">{fmt(matching.length)} {labels.matches}</p>}{note && <p className="operational-table-note"><Info size={13}/>{note}</p>}</>;
}
/** Must be rendered under the existing AuthBoundary. It performs only a protected GET. */
export function OperationalInventoryPanel({ deviceId, sessionKey }: OperationalInventoryPanelProps) {
    const operator = useOperator();
    const identity = JSON.stringify([deviceId, sessionKey ?? null, operator?.mode ?? null, operator?.authenticated ?? null, operator?.expiresAt ?? null]);
    return <OperationalInventorySession key={identity} deviceId={deviceId}/>;
}
function OperationalInventorySession({ deviceId }: { deviceId: string }) {
    const [locale] = useLocale();
    const labels = copy[locale];
    const headingId = useId();
    const filterId = useId();
    const [view, setView] = useState<OperationalView | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<'loadError' | 'invalid' | 'timeout' | 'missing' | 'session' | null>(null);
    const [retry, setRetry] = useState(0);
    const [selected, setSelected] = useState<OperationalSectionName>('volumes');
    const [filter, setFilter] = useState('');
    const [clock, setClock] = useState({ anchor: 0, elapsed: 0 });
    useEffect(() => {
        const controller = new AbortController();
        let active = true;
        let locked = false;
        let suspended = document.visibilityState === 'hidden';
        let restartQueued = false;
        let timeout: number | undefined;
        setView(null); setError(null); setLoading(true); setClock({ anchor: 0, elapsed: 0 });
        const clearObservation = () => { setView(null); setClock({ anchor: 0, elapsed: 0 }); };
        const lock = () => { locked = true; controller.abort(); window.clearTimeout(timeout); if (active) { clearObservation(); setFilter(''); setError('session'); setLoading(false); } };
        // Suspension invalidates even an unfinished request: its response can no
        // longer establish an anchor. Only a request begun after restoration may.
        const suspend = () => {
            suspended = true; controller.abort(); window.clearTimeout(timeout);
            if (active && !locked) { clearObservation(); setError(null); setLoading(true); }
        };
        const restore = () => {
            if (!active || locked || restartQueued || document.visibilityState === 'hidden') return;
            restartQueued = true; controller.abort(); window.clearTimeout(timeout);
            clearObservation(); setError(null); setLoading(true); setRetry(value => value + 1);
        };
        const visibility = () => { if (document.visibilityState === 'hidden') suspend(); else restore(); };
        const pageShow = (event: PageTransitionEvent) => { if (event.persisted) restore(); };
        window.addEventListener(AUTH_REQUIRED_EVENT, lock);
        window.addEventListener('focus', restore);
        window.addEventListener('blur', suspend);
        window.addEventListener('pagehide', suspend);
        window.addEventListener('pageshow', pageShow);
        document.addEventListener('visibilitychange', visibility);
        if (!suspended) timeout = window.setTimeout(() => { controller.abort(); if (active && !locked && !suspended) { clearObservation(); setError('timeout'); setLoading(false); } }, 10000);
        if (!suspended) void request<unknown>(`/devices/${encodeURIComponent(deviceId)}/operational`, { signal: controller.signal }).then(value => {
            if (!active || suspended || controller.signal.aborted) return;
            if (!validOperationalView(value, deviceId)) { setView(null); setError('invalid'); return; }
            setClock({ anchor: performance.now(), elapsed: 0 }); setView(value);
        }).catch(caught => {
            if (!active || suspended || controller.signal.aborted) return;
            setView(null);
            if (caught instanceof APIError && caught.status === 401) locked = true;
            setError(caught instanceof APIError && caught.status === 401 ? 'session' : caught instanceof APIError && caught.status === 404 ? 'missing' : 'loadError');
        }).finally(() => { window.clearTimeout(timeout); if (active && !controller.signal.aborted) setLoading(false); });
        return () => { active = false; controller.abort(); window.clearTimeout(timeout); window.removeEventListener(AUTH_REQUIRED_EVENT, lock); window.removeEventListener('focus', restore); window.removeEventListener('blur', suspend); window.removeEventListener('pagehide', suspend); window.removeEventListener('pageshow', pageShow); document.removeEventListener('visibilitychange', visibility); };
    }, [deviceId, retry]);
    useEffect(() => {
        if (!view) return;
        const timer = window.setInterval(() => setClock(previous => ({ ...previous, elapsed: Math.max(previous.elapsed, performance.now() - previous.anchor) })), 1000);
        return () => window.clearInterval(timer);
    }, [view]);
    const status = view ? effectiveOperationalStatus(view, clock.elapsed) : null;
    const now = view ? operationalNow(view, clock.elapsed) : 0;
    const chosen = view ? currentSection(view, selected) : null;
    const isStale = (section: Section | null) => status !== 'fresh' || Boolean(section && now - Date.parse(section.meta.observedAt) > (view?.maxAgeSeconds ?? 0) * 1000);
    const explanation = status === 'not_configured' ? labels.notConfigured : status === 'awaiting' ? labels.awaiting : status === 'revoked' ? labels.revoked : status === 'unavailable' ? labels.unavailable : null;
    return <section className="operational-panel" aria-labelledby={headingId} aria-busy={loading}>
        <header className="operational-heading"><div className="operational-heading-icon"><Database size={19}/></div><div><h2 id={headingId}>{labels.title}</h2><p>{labels.subtitle}</p></div><button type="button" className="button small" onClick={() => setRetry(value => value + 1)} disabled={loading || error === 'session'}><RefreshCw size={14}/>{labels.refresh}</button></header>
        {loading && <div className="operational-loading" role="status"><LoaderCircle className="spin" size={18}/>{labels.loading}</div>}
        {error && <div className="operational-notice error" role="alert"><TriangleAlert size={17}/><p>{labels[error]}</p></div>}
        {view && status && <>
            <div className="operational-provenance"><span className={`operational-quality ${status === 'fresh' ? 'neutral' : 'caution'}`}>{statusLabel(status, labels)}</span><span>{labels.source}: Linux agent</span><span>{labels.profile}: <code>{OPERATIONAL_PROFILE}</code></span></div>
            <p className="operational-table-note"><Info size={13}/>{labels.scopeNote}</p>
            {(view.snapshot || view.receivedAt) && <dl className="operational-timing">{view.snapshot && <div><dt>{labels.collected}</dt><dd><time dateTime={view.snapshot.collectedAt}>{date(view.snapshot.collectedAt, locale)}</time></dd></div>}{view.receivedAt && <div><dt>{labels.received}</dt><dd><time dateTime={view.receivedAt}>{date(view.receivedAt, locale)}</time></dd></div>}{view.snapshot && <div><dt>{labels.age}</dt><dd><Clock3 size={12}/>{now < Date.parse(view.snapshot.collectedAt) ? labels.unknown : `${number(Math.floor((now - Date.parse(view.snapshot.collectedAt)) / 1000), locale, labels)} ${labels.seconds}`}</dd></div>}</dl>}
            {explanation && <div className="operational-notice"><Info size={16}/><p>{explanation}</p></div>}
            <div className="operational-sections" aria-label={labels.title}>{SECTION_NAMES.map(name => {
                const { latest, shown, retained } = currentSection(view, name);
                const Icon = icons[name];
                const stale = isStale(shown);
                return <button type="button" key={name} className={selected === name ? 'selected' : undefined} aria-pressed={selected === name} aria-label={`${labels[name]} · ${qualityLabel(latest ?? shown, retained, stale, labels)}`} onClick={() => { setSelected(name); setFilter(''); }}><span className="operational-section-name"><Icon size={15}/>{labels[name]}</span><strong>{shown && (shown.meta.quality === 'healthy' || shown.meta.quality === 'stale') ? shown.items.length : '—'}</strong><span className={`operational-quality ${qualityTone(shown, retained, stale)}`}>{qualityLabel(latest ?? shown, retained, stale, labels)}</span></button>;
            })}</div>
            {chosen && <div className="operational-section-detail"><div className="operational-section-heading"><h3>{labels[selected]}</h3><span className={`operational-quality ${qualityTone(chosen.shown, chosen.retained, isStale(chosen.shown))}`}>{qualityLabel(chosen.latest ?? chosen.shown, chosen.retained, isStale(chosen.shown), labels)}</span></div>
                {chosen.latest && <p className="operational-attempt">{labels.latest}: <time dateTime={chosen.latest.meta.observedAt}>{date(chosen.latest.meta.observedAt, locale)}</time> · {reasonLabel(chosen.latest.meta.reason, labels)}</p>}
                {chosen.retained && <div className="operational-notice caution"><Clock3 size={16}/><p>{labels.retainedNote}</p></div>}
                {chosen.shown && <><dl className="operational-coverage"><div><dt>{labels.sectionTime}</dt><dd><time dateTime={chosen.shown.meta.observedAt}>{date(chosen.shown.meta.observedAt, locale)}</time></dd></div><div><dt>{chosen.shown.meta.countExact ? labels.exact : labels.lowerBound}</dt><dd>{number(chosen.shown.meta.observedCount, locale, labels)} {selected === 'events' ? labels.sourceEvents : labels.discovered}</dd></div><div><dt>{labels.cap}</dt><dd>{SECTION_LIMITS[selected]}</dd></div></dl><div className="operational-coverage-line"><span>{chosen.shown.items.length} {selected === 'events' ? labels.eventGroups : labels.shown}</span><span>{chosen.shown.meta.complete ? labels.complete : labels.incomplete}</span>{chosen.shown.meta.truncated && <strong>{labels.truncated}</strong>}{chosen.shown.meta.reason !== 'none' && <span>{reasonLabel(chosen.shown.meta.reason, labels)}</span>}</div></>}
                {chosen.shown && <><label className="operational-filter" htmlFor={filterId}><Search size={15}/><input id={filterId} type="search" maxLength={160} placeholder={labels.filter} aria-label={labels.filter} value={filter} onChange={event => setFilter(event.target.value)}/></label><InventoryTable name={selected} section={chosen.shown} filter={filter} locale={locale}/></>}
                {!chosen.shown && <p className="operational-empty">{labels.noData}</p>}
            </div>}
            <div className="operational-assessments">{(['updates', 'vulnerabilities'] as const).map(name => <div key={name}><ShieldQuestion size={18}/><div><h3>{labels[name]}</h3><strong>{labels.assessment}</strong><p>{labels.not_implemented}</p></div></div>)}</div><p className="operational-footnote">{labels.assessmentNote}</p>
        </>}
        <footer className="operational-footer"><Info size={14}/><div><p>{labels.healthyNote}</p><p>{labels.privacy}</p></div></footer>
    </section>;
}
