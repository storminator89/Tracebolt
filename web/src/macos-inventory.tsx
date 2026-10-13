import { useState } from 'react';
import { ChevronDown, Cpu, Database, Network, Package, RefreshCw, Terminal } from 'lucide-react';
import { useLocale } from './i18n';
import { fullDate } from './utils';
import { DeviceTabs } from './device-tabs';
import { useMacInventory } from './macos-inventory-resource';
import { isMacLookupSection, macInventoryMatchingCount, macInventorySections } from './macos-inventory-types';
import type { MacInventoryPage, MacInventorySection, MacInventorySource } from './macos-inventory-types';
import './macos-inventory.css';

const copy = {
 en: {
  title: 'Mac inventory', hardware: 'Hardware', receipts: 'Package receipts', processes: 'Processes', ipv4: 'IPv4 interfaces', ipv6: 'IPv6 interfaces',
  coverage: 'Source coverage', full: 'Full selected-source coverage', partial: 'Partial', unknown: 'Unknown', freshness: 'Freshness', fresh: 'Fresh', stale: 'Stale', expired: 'Expired', observed: 'Observed', denied: 'Access denied', unavailable: 'Unavailable',
  disabled: 'Inventory collection is disabled. Retained metadata does not grant access to private rows.', 'not-enabled': 'Expanded inventory is not enabled for this identity.',
  basic: 'This Mac has basic read-only scope. Hardware detail, receipt identifiers, process labels and interface metadata require a fresh, explicitly approved macOS inventory identity.',
  access: 'Private inventory access is unavailable. Sign in with a current operator session and recheck this device.',
  refresh: 'Refresh inventory', checking: 'Checking current authority…', previous: 'Previous page', next: 'Next page', empty: 'No receipt identifiers returned by this source.', noaddresses: 'No addresses returned',
  findReceipts: 'Find receipts', findProcesses: 'Find processes', apply: 'Apply', clear: 'Clear', matches: 'matches', noMatches: 'No matches in this captured source.', applied: 'Applied', allRows: 'All rows', draftPending: 'Draft not applied.', searchHelp: 'Literal text, ignoring case. Receipt ID, or process label / PID / PPID. Up to 256 printable ASCII characters.', searchInvalid: 'Use up to 256 printable ASCII characters.',
  captured: 'Captured', reason: 'Provider reason', scope: 'Source & collection limits', noData: 'No current inventory generation is available.', selected: 'Only the selected sources are covered. Source coverage and capture age are separate.',
  hardwareLimit: 'Fixed sysctl fields: model identifier, CPU counts and RAM capacity. Capacity is not utilization, pressure or machine identity.',
  receiptLimit: 'Installer receipt IDs on the root volume. Receipts may outlive removed files. This is not a complete installed-software inventory; App Store, portable apps and Homebrew need separate coverage.',
  processLimit: 'Caller-visible snapshot PIDs and parent PIDs, with short kernel accounting labels that can be truncated. No arguments, paths, owners, CPU/RAM metrics or process controls. PIDs are not joined across snapshots.',
  networkLimit: 'Passive local interface metadata. IPv4 and IPv6 are independent observations. Up/running flags are local OS state, not reachability. No DNS, probes, sockets, routes, traffic, MAC addresses or Wi-Fi names.',
  model: 'Model identifier', physical: 'Physical cores', logical: 'Logical processors', memory: 'RAM capacity', label: 'Short accounting label', interface: 'Interface', addresses: 'Local addresses', flags: 'OS flags', up: 'Up', down: 'Down', running: 'Running', notRunning: 'Not running', receipt: 'Receipt identifier',
  rows: 'source rows', rowsUnknown: 'Count unknown', private: 'Operator-only · read-only · no AI export', retention: 'Latest generation, up to 24 hours from capture. Refresh never renews its age.',
  error: { invalid: 'The manager returned an invalid inventory page. Private rows were cleared.', unavailable: 'Inventory could not be verified. Private rows were cleared.', session: 'Operator access ended. Sign in again.', expired: 'Inventory or current authority expired. Private rows were cleared.', changed: 'The inventory generation changed. Refresh to inspect the current generation.', timeout: 'Inventory read timed out. Private rows were cleared.', clock: 'Time could not be verified. Private rows were cleared.' },
  reasons: { macos_inventory_access_denied: 'Provider access denied', macos_inventory_unavailable: 'Provider unavailable', macos_inventory_unsupported_platform: 'Unsupported provider platform', macos_inventory_invalid_metadata: 'Malformed source output', macos_inventory_bounds: 'Source exceeded a safety bound', macos_inventory_budget_exhausted: 'Source time budget exhausted' },
 },
 de: {
  title: 'Mac-Inventar', hardware: 'Hardware', receipts: 'Paketbelege', processes: 'Prozesse', ipv4: 'IPv4-Schnittstellen', ipv6: 'IPv6-Schnittstellen',
  coverage: 'Quellenabdeckung', full: 'Alle ausgewählten Quellen erfasst', partial: 'Teilweise', unknown: 'Unbekannt', freshness: 'Aktualität', fresh: 'Aktuell', stale: 'Veraltet', expired: 'Abgelaufen', observed: 'Erfasst', denied: 'Zugriff verweigert', unavailable: 'Nicht verfügbar',
  disabled: 'Inventarerfassung ist deaktiviert. Gespeicherte Metadaten gewähren keinen Zugriff auf private Zeilen.', 'not-enabled': 'Erweitertes Inventar ist für diese Identität nicht aktiviert.',
  basic: 'Dieser Mac hat nur den Basis-Leseumfang. Hardwaredetails, Belegkennungen, Prozessbezeichnungen und Schnittstellenmetadaten brauchen eine neue, explizit freigegebene macOS-Inventaridentität.',
  access: 'Privater Inventarzugriff ist nicht verfügbar. Mit aktueller Operator-Sitzung anmelden und dieses Gerät erneut prüfen.',
  refresh: 'Inventar aktualisieren', checking: 'Aktuelle Berechtigung wird geprüft …', previous: 'Vorherige Seite', next: 'Nächste Seite', empty: 'Diese Quelle hat keine Belegkennungen geliefert.', noaddresses: 'Keine Adressen geliefert',
  findReceipts: 'Belege suchen', findProcesses: 'Prozesse suchen', apply: 'Anwenden', clear: 'Leeren', matches: 'Treffer', noMatches: 'Keine Treffer in dieser erfassten Quelle.', applied: 'Angewendet', allRows: 'Alle Zeilen', draftPending: 'Entwurf nicht angewendet.', searchHelp: 'Wörtlicher Text, ohne Groß-/Kleinschreibung. Belegkennung oder Prozessbezeichnung / PID / PPID. Bis zu 256 druckbare ASCII-Zeichen.', searchInvalid: 'Bis zu 256 druckbare ASCII-Zeichen verwenden.',
  captured: 'Erfasst', reason: 'Quellgrund', scope: 'Quelle & Erfassungsgrenzen', noData: 'Keine aktuelle Inventargeneration verfügbar.', selected: 'Nur die ausgewählten Quellen sind abgedeckt. Quellenabdeckung und Erfassungsalter bleiben getrennt.',
  hardwareLimit: 'Feste sysctl-Felder: Modellkennung, CPU-Anzahlen und RAM-Kapazität. Kapazität ist keine Auslastung, kein Speicherdruck und keine Geräteidentität.',
  receiptLimit: 'Installer-Belegkennungen auf dem Root-Volume. Belege können entfernte Dateien überdauern. Dies ist kein vollständiges Inventar installierter Software; App Store, portable Apps und Homebrew brauchen eigene Quellen.',
  processLimit: 'Sichtbare Snapshot-Prozess- und Eltern-IDs mit kurzen, möglicherweise gekürzten Kernel-Bezeichnungen. Keine Argumente, Pfade, Besitzer, CPU-/RAM-Metriken oder Prozesssteuerung. PIDs werden nicht über Snapshots verknüpft.',
  networkLimit: 'Passive lokale Schnittstellenmetadaten. IPv4 und IPv6 sind getrennte Beobachtungen. Up-/Running-Flags beschreiben lokalen OS-Zustand, keine Erreichbarkeit. Keine DNS-Abfragen, Probes, Sockets, Routen, Verkehrsdaten, MAC-Adressen oder WLAN-Namen.',
  model: 'Modellkennung', physical: 'Physische Kerne', logical: 'Logische Prozessoren', memory: 'RAM-Kapazität', label: 'Kurze Kernel-Bezeichnung', interface: 'Schnittstelle', addresses: 'Lokale Adressen', flags: 'OS-Flags', up: 'Up', down: 'Down', running: 'Running', notRunning: 'Nicht Running', receipt: 'Belegkennung',
  rows: 'Quellzeilen', rowsUnknown: 'Anzahl unbekannt', private: 'Nur Operatoren · nur lesend · kein KI-Export', retention: 'Neueste Generation, bis zu 24 Stunden ab Erfassung. Aktualisieren erneuert ihr Alter nicht.',
  error: { invalid: 'Der Manager lieferte eine ungültige Inventarseite. Private Zeilen wurden entfernt.', unavailable: 'Inventar konnte nicht verifiziert werden. Private Zeilen wurden entfernt.', session: 'Operatorzugriff beendet. Erneut anmelden.', expired: 'Inventar oder aktuelle Berechtigung abgelaufen. Private Zeilen wurden entfernt.', changed: 'Inventargeneration geändert. Aktualisieren, um die aktuelle Generation zu prüfen.', timeout: 'Zeitlimit beim Inventarlesen. Private Zeilen wurden entfernt.', clock: 'Zeit konnte nicht verifiziert werden. Private Zeilen wurden entfernt.' },
  reasons: { macos_inventory_access_denied: 'Quellzugriff verweigert', macos_inventory_unavailable: 'Quelle nicht verfügbar', macos_inventory_unsupported_platform: 'Quellplattform nicht unterstützt', macos_inventory_invalid_metadata: 'Ungültige Quelldaten', macos_inventory_bounds: 'Quelle überschritt eine Sicherheitsgrenze', macos_inventory_budget_exhausted: 'Zeitbudget der Quelle ausgeschöpft' },
 },
} as const;
type Copy = typeof copy.en | typeof copy.de;
function SourceStatus({ source, c }: { source: MacInventorySource; c: Copy }) {
 return <span className={`mac-source-status ${source.quality}`}>{c[source.quality]}{source.reason && <span className="mac-source-reason">{c.reasons[source.reason]}</span>}</span>;
}
function Rows({ page, section, c, locale }: { page: MacInventoryPage; section: MacInventorySection; c: Copy; locale: string }) {
 const source = page.sources![section];
 if (source.quality !== 'observed') return <p className="mac-inventory-empty">{c.rowsUnknown} · {c.reasons[source.reason as keyof Copy['reasons']]}</p>;
 if (section === 'hardware') { const h = page.hardware!; return <dl className="mac-hardware-grid">{[[c.model, h.modelIdentifier], [c.physical, h.physicalCPUs], [c.logical, h.logicalCPUs], [c.memory, `${new Intl.NumberFormat(locale, { maximumFractionDigits: 2 }).format(h.memoryCapacityBytes / 1073741824)} GiB`]].map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value}</dd></div>)}</dl>; }
 if (page.schemaVersion === 'tracebolt.macos-read-inventory-page.v2' && page.search !== '' && page.matchingCount === 0) return <p className="mac-inventory-empty">{c.noMatches}</p>;
 if (section === 'receipts') return page.receiptIds.length ? <table><thead><tr><th>{c.receipt}</th></tr></thead><tbody>{page.receiptIds.map(row => <tr key={row}><td className="mono">{row}</td></tr>)}</tbody></table> : <p className="mac-inventory-empty">{c.empty}</p>;
 if (section === 'processes') return <table><thead><tr><th>PID</th><th>PPID</th><th>{c.label}</th></tr></thead><tbody>{page.processes.map(row => <tr key={row.pid}><td>{row.pid}</td><td>{row.parentPid}</td><td className="mono">{row.nameQuality === 'observed' ? row.accountingName : <span className="mac-muted">{c.unavailable}</span>}</td></tr>)}</tbody></table>;
 return <table><thead><tr><th>{c.interface}</th><th>{c.addresses}</th><th>MTU</th><th>{c.flags}</th></tr></thead><tbody>{page.interfaces.map(row => <tr key={row.name}><td className="mono">{row.name}</td><td className="mono">{row.addresses.length ? row.addresses.map(address => <span className="mac-address" key={`${address.ip}/${address.prefixBits}`}>{address.ip}/{address.prefixBits}</span>) : <span className="mac-muted">{c.noaddresses}</span>}</td><td>{row.mtu}</td><td>{row.up ? c.up : c.down} · {row.running ? c.running : c.notRunning}</td></tr>)}</tbody></table>;
}
export function MacInventoryWorkspace({ deviceId, enabled, configured, sessionKey, identityKey }: { deviceId: string; enabled: boolean; configured: boolean; sessionKey: string | null; identityKey: string }) {
 const [locale] = useLocale(), c = copy[locale], [section, setSection] = useState<MacInventorySection>('hardware');
 const resource = useMacInventory(deviceId, enabled && configured, sessionKey, identityKey, section), { summary, page, loading, error } = resource;
 const icons = { hardware: Cpu, receipts: Package, processes: Terminal, ipv4: Network, ipv6: Network };
 const freshness = summary?.status === 'fresh' && summary.collectedAt && Date.parse(summary.serverNow) - Date.parse(summary.collectedAt) + resource.age >= 60000 ? 'stale' : summary?.status;
 const lookup = isMacLookupSection(section), count = page ? macInventoryMatchingCount(page) : 0;
 const limits = section === 'hardware' ? c.hardwareLimit : section === 'receipts' ? c.receiptLimit : section === 'processes' ? c.processLimit : c.networkLimit;
 return <section className="mac-inventory" aria-label={c.title}>
  <header className="mac-inventory-header"><div><h2><Database size={18}/>{c.title}</h2><p>{c.private}</p></div><button type="button" className="button small" disabled={!enabled || !configured || loading || error === 'session'} onClick={resource.refresh}><RefreshCw size={14} className={loading ? 'spin' : undefined}/>{c.refresh}</button></header>
  {!configured ? <p className="mac-inventory-empty">{c.basic}</p> : !enabled ? <p className="mac-inventory-empty">{c.access}</p> : <>
   <div className="mac-inventory-summary" aria-live="polite"><div><span>{c.coverage}</span><strong>{summary ? c[summary.sourceQuality] : c.unknown}</strong></div><div><span>{c.freshness}</span><strong>{freshness && ['fresh', 'stale', 'expired'].includes(freshness) ? c[freshness as 'fresh' | 'stale' | 'expired'] : c.unknown}</strong></div><div><span>{c.captured}</span><strong>{summary?.collectedAt ? <time dateTime={summary.collectedAt}>{fullDate(summary.collectedAt)}</time> : c.unknown}</strong></div></div>
   {error && <p role="alert" className="mac-inventory-empty">{c.error[error]}</p>}
   {loading && <p className="mac-read-status" role="status">{c.checking}</p>}
   {summary && summary.status !== 'fresh' && summary.status !== 'stale' && <p className="mac-inventory-empty">{summary.status === 'not-enabled' || summary.status === 'disabled' ? c[summary.status] : summary.status === 'expired' ? c.error.expired : c.noData}</p>}
   {summary?.sources && <div className="mac-source-strip" aria-label={c.coverage}>{macInventorySections.map(key => <div key={key}><strong>{c[key]}</strong><SourceStatus source={summary.sources![key]} c={c}/></div>)}</div>}
   <DeviceTabs tabs={macInventorySections.map(id => ({ id: `mac-${id}`, name: c[id], icon: icons[id] }))} selected={`mac-${section}`} onSelect={id => setSection(id.slice(4) as MacInventorySection)}/>
   <div role="tabpanel" id={`device-mac-${section}`} aria-labelledby={`tab-mac-${section}`} className="mac-inventory-panel">
    <div className="mac-table-heading"><h3>{c[section]}</h3><span data-testid="mac-lookup-count" aria-live="polite">{page && page.sources?.[section].quality === 'observed' && section !== 'hardware' ? `${lookup ? `${count} ${c.matches} · ` : ''}${page.total} ${c.rows}` : section === 'hardware' ? '' : c.rowsUnknown}</span></div>
    <p className="mac-scope-line">{limits}</p>
    {lookup && <form className="mac-lookup" data-testid="mac-lookup-controls" onSubmit={event => { event.preventDefault(); resource.applySearch(); }}>
     <label htmlFor={`mac-${section}-search`}>{section === 'receipts' ? c.findReceipts : c.findProcesses}</label>
     <div className="mac-lookup-inputs"><input id={`mac-${section}-search`} type="text" value={resource.draft} onChange={event => resource.setDraft(event.target.value)} maxLength={256} autoComplete="off" autoCapitalize="none" spellCheck={false} disabled={error === 'session'} aria-describedby={`mac-${section}-search-help`} aria-invalid={resource.searchInvalid}/><button type="submit" className="button small" disabled={error === 'session'}>{c.apply}</button><button type="button" className="button small" disabled={error === 'session' || !resource.draft && !resource.search} onClick={() => resource.applySearch('')}>{c.clear}</button></div>
     <p id={`mac-${section}-search-help`} className="mac-lookup-help">{resource.searchInvalid ? <span role="alert">{c.searchInvalid}</span> : c.searchHelp}</p>
     <p className="mac-lookup-applied">{c.applied}: <span>{resource.search || c.allRows}</span>{resource.draft !== resource.search && <span> · {c.draftPending}</span>}</p>
    </form>}
    <div className="mac-inventory-table" data-testid="mac-inventory-scroll">{page ? <Rows page={page} section={section} c={c} locale={locale}/> : !loading && !error ? <p className="mac-inventory-empty">{c.noData}</p> : null}</div>
    {page && section !== 'hardware' && page.sources?.[section].quality === 'observed' && count > 0 && <nav className="mac-pagination" aria-label={locale === 'de' ? 'Inventarseiten' : 'Inventory pages'}><button type="button" className="button small" disabled={loading || page.offset === 0} onClick={resource.previous}>{c.previous}</button><span>{page.offset + 1}–{page.offset + (section === 'receipts' ? page.receiptIds.length : section === 'processes' ? page.processes.length : page.interfaces.length)} / {count}</span><button type="button" className="button small" disabled={loading || page.nextOffset === null} onClick={resource.next}>{c.next}</button></nav>}
    <details className="mac-inventory-notes"><summary>{c.scope}<ChevronDown size={14}/></summary><p>{c.selected}</p><p>{c.retention}</p>{summary?.sources && <code>{summary.sources[section].source}</code>}</details>
   </div>
  </>}
 </section>;
}
