import { useId, useState } from 'react';
import { useOperator } from './auth';
import { useLocale } from './i18n';
import { fullDate } from './utils';
import { useWindowsFleetSoftware } from './windows-fleet-software-resource';
import { fleetSoftwareFresh } from './windows-fleet-software-types';
import type { FleetSoftwareItem } from './windows-fleet-software-types';
import './windows-fleet-software.css';

const copy = {
    en: {
        title: 'Find machine software', open: 'Find software across Windows devices', close: 'Close software lookup', search: 'Search reported software', name: 'Application name', version: 'Literal version', clear: 'Clear search', loading: 'Reading software reports…',
        scope: 'Authorized Windows devices · HKLM 32/64. Per-user, Store/MSIX and portable apps excluded.',
        literal: 'Name + version must match the same registration. Literal text; no upgrade comparison.',
        devices: 'Devices', of: 'of', matches: 'Reported matches', unknown: 'Registrations with unavailable queried fields', complete: 'Complete scoped enumeration', fresh: 'Fresh capture', stale: 'Stale capture',
        not_configured: 'Machine-software consent not configured', disabled: 'Collection disabled', awaiting: 'Waiting for first complete capture', unavailable: 'Software report unavailable', storeUnavailable: 'Fleet software lookup is not configured on this manager.', noDevices: 'No currently authorized Windows devices.', noMatch: 'No reported match. This does not prove the application is absent.',
        detail: 'View all matching registrations', nextDevices: 'Next devices', nextRows: 'Next matching registrations', back: 'Back to search', rows: 'Matching registrations', source: 'Scope and original capture', captured: 'Capture started', finished: 'Capture finished', received: 'Manager received', expiry: 'Capture expires', paging: 'Lookup expires', authority: 'Access expires', registrationCount: 'Enumerated registrations', identity: 'Original device identity', generation: 'Generation', view: 'Registry view', missing: 'Unavailable', empty: 'Empty value',
        pending: 'Latest capture pending', source_failed: 'Latest capture failed', expiredAttempt: 'Latest attempt expired', completeAttempt: 'Latest capture complete', retained: 'Showing the earlier complete capture with its original age.', attempted: 'Latest attempt',
        access_denied: 'Access denied', unsupported: 'Unsupported source', source_changed: 'Source changed', malformed_source: 'Invalid source', resource_limit: 'Capture limit reached', deadline: 'Capture timed out', canceled: 'Capture canceled', unavailableReason: 'Source unavailable',
        lifetime: 'All caller-visible machine Uninstall registrations in HKLM’s 32/64-bit views. Unregistered apps are also excluded. Literal, Unicode case-insensitive substring matching. Scoped, non-atomic enumeration; duplicate registrations remain separate. Unavailable fields are unknown, while an empty value was reported as empty. Reading does not collect software or grant consent. Results clear when you leave or focus is lost.',
        invalid: 'Invalid response. Start a new search.', timeout: 'Request timed out. Start a new search.', session: 'Your session has ended. Sign in again.', clock: 'Time reference changed. Start a new search.', busy: 'Manager busy. Try again shortly.', restart: 'Capture or access changed. Start a new search.', unauthorized: 'Access ended. Start a new search after access is restored.', expired: 'The original capture or lookup expired. Start a new search.', queryInvalid: 'Enter a name or version, with at most 256 UTF-8 bytes in each field.',
    },
    de: {
        title: 'Gerätesoftware finden', open: 'Software auf Windows-Geräten suchen', close: 'Softwaresuche schließen', search: 'Gemeldete Software suchen', name: 'Anwendungsname', version: 'Wörtliche Version', clear: 'Suche leeren', loading: 'Softwareberichte werden gelesen …',
        scope: 'Autorisierte Windows-Geräte · HKLM 32/64. Benutzerbezogene, Store-/MSIX- und portable Apps ausgeschlossen.',
        literal: 'Name + Version müssen dieselbe Registrierung treffen. Wörtlicher Text; kein Upgradevergleich.',
        devices: 'Geräte', of: 'von', matches: 'Gemeldete Treffer', unknown: 'Registrierungen mit nicht verfügbaren Suchfeldern', complete: 'Vollständige Erfassung im angegebenen Umfang', fresh: 'Frische Erfassung', stale: 'Veraltete Erfassung',
        not_configured: 'Gerätesoftware-Zustimmung nicht eingerichtet', disabled: 'Erfassung deaktiviert', awaiting: 'Warten auf erste vollständige Erfassung', unavailable: 'Softwarebericht nicht verfügbar', storeUnavailable: 'Die Flotten-Softwaresuche ist auf diesem Manager nicht eingerichtet.', noDevices: 'Keine aktuell autorisierten Windows-Geräte.', noMatch: 'Kein gemeldeter Treffer. Das belegt nicht, dass die Anwendung fehlt.',
        detail: 'Alle passenden Registrierungen ansehen', nextDevices: 'Nächste Geräte', nextRows: 'Nächste passende Registrierungen', back: 'Zurück zur Suche', rows: 'Passende Registrierungen', source: 'Umfang und ursprüngliche Erfassung', captured: 'Erfassung begonnen', finished: 'Erfassung beendet', received: 'Beim Manager empfangen', expiry: 'Erfassung läuft ab', paging: 'Suche läuft ab', authority: 'Zugriff läuft ab', registrationCount: 'Erfasste Registrierungen', identity: 'Ursprüngliche Geräteidentität', generation: 'Generation', view: 'Registry', missing: 'Nicht verfügbar', empty: 'Leerer Wert',
        pending: 'Neueste Erfassung ausstehend', source_failed: 'Neueste Erfassung fehlgeschlagen', expiredAttempt: 'Neuester Versuch abgelaufen', completeAttempt: 'Neueste Erfassung vollständig', retained: 'Die vorherige vollständige Erfassung wird mit ihrem ursprünglichen Alter angezeigt.', attempted: 'Neuester Versuch',
        access_denied: 'Zugriff verweigert', unsupported: 'Quelle nicht unterstützt', source_changed: 'Quelle geändert', malformed_source: 'Ungültige Quelle', resource_limit: 'Erfassungsgrenze erreicht', deadline: 'Zeitlimit erreicht', canceled: 'Erfassung abgebrochen', unavailableReason: 'Quelle nicht verfügbar',
        lifetime: 'Alle für den Dienst sichtbaren Uninstall-Geräteregistrierungen in HKLM 32/64. Unregistrierte Apps sind ebenfalls ausgeschlossen. Wörtliche Unicode-Teiltextsuche unabhängig von Groß- und Kleinschreibung. Begrenzter, nicht atomarer Umfang; doppelte Registrierungen bleiben getrennt. Nicht verfügbare Felder sind unbekannt, leere Werte wurden leer gemeldet. Lesen erfasst keine Software und erteilt keine Zustimmung. Ergebnisse werden beim Verlassen oder Fokusverlust gelöscht.',
        invalid: 'Ungültige Antwort. Neue Suche starten.', timeout: 'Zeitlimit überschritten. Neue Suche starten.', session: 'Die Sitzung ist beendet. Erneut anmelden.', clock: 'Zeitreferenz geändert. Neue Suche starten.', busy: 'Manager ausgelastet. Gleich erneut versuchen.', restart: 'Erfassung oder Zugriff geändert. Neue Suche starten.', unauthorized: 'Zugriff beendet. Nach Wiederherstellung erneut suchen.', expired: 'Die ursprüngliche Erfassung oder Suche ist abgelaufen. Neue Suche starten.', queryInvalid: 'Name oder Version eingeben, jeweils höchstens 256 UTF-8-Bytes.',
    },
};
export function WindowsFleetSoftwareLookup() {
    const operator = useOperator();
    if (!operator || operator.mode !== 'lan' || !operator.authenticated || !operator.expiresAt || operator.loginMode === 'named' && !operator.capabilities?.includes('read')) return null;
    return <Lookup key={`${operator.actorId ?? ''}:${operator.expiresAt}`} sessionKey={operator.expiresAt} actor={operator.actorId ?? ''}/>;
}
function Lookup({ sessionKey, actor }: { sessionKey: string; actor: string }) {
    const [locale] = useLocale(), c = copy[locale], [open, setOpen] = useState(false), id = useId();
    return <section className="windows-fleet-software" aria-label={c.title}>
        <div className="windows-fleet-software-heading"><strong>{c.title}</strong><button type="button" className="text-button" aria-expanded={open} aria-controls={`${id}-body`} onClick={() => setOpen(value => !value)}>{open ? c.close : c.open}</button></div>
        {open && <div id={`${id}-body`}><LookupBody sessionKey={sessionKey} actor={actor}/></div>}
    </section>;
}
function LookupBody({ sessionKey, actor }: { sessionKey: string; actor: string }) {
    const [locale] = useLocale(), c = copy[locale], id = useId(), resource = useWindowsFleetSoftware(true, sessionKey, actor), page = resource.page;
    const value = (field: string | null) => field === null ? <span className="windows-fleet-software-missing">{c.missing}</span> : field === '' ? <span className="windows-fleet-software-missing">{c.empty}</span> : field;
    const time = (label: string, date: string) => <div><dt>{label}</dt><dd><time dateTime={date}>{fullDate(date)}</time></dd></div>;
    const attempt = (item: FleetSoftwareItem) => {
        const a = item.latestAttempt;
        if (!a || item.complete && a.sequence === item.complete.manifest.sequence) return null;
        return <p className="windows-fleet-software-attempt">{c[a.status === 'expired' ? 'expiredAttempt' : a.status === 'complete' ? 'completeAttempt' : a.status]}{a.reason && <> · {c[a.reason === 'unavailable' ? 'unavailableReason' : a.reason]}</>}{item.complete && <> · {c.retained}</>}</p>;
    };
    return <div aria-busy={resource.loading}>
        <p className="windows-fleet-software-scope">{c.scope}</p>
        <form className="windows-fleet-software-controls" autoComplete="off" onSubmit={event => { event.preventDefault(); resource.submit(); }}>
            <label htmlFor={`${id}-name`}>{c.name}<input id={`${id}-name`} type="search" autoComplete="off" spellCheck={false} maxLength={256} value={resource.controls.name} onChange={event => resource.changeName(event.target.value)}/></label>
            <label htmlFor={`${id}-version`}>{c.version}<input id={`${id}-version`} type="search" autoComplete="off" spellCheck={false} maxLength={256} value={resource.controls.version} onChange={event => resource.changeVersion(event.target.value)}/></label>
            <button className="button small" type="submit" disabled={resource.loading || resource.error === 'session' || !resource.controls.name && !resource.controls.version}>{c.search}</button>
            <button className="text-button" type="button" onClick={resource.clear}>{c.clear}</button>
        </form>
        <p className="windows-fleet-software-help">{c.literal}</p>
        {resource.loading && <p role="status">{c.loading}</p>}
        {resource.error && <p role="alert">{c[resource.error]}</p>}
        {page && <>
            {page.status === 'not_configured' ? <p role="status">{c.storeUnavailable}</p> : <>
                <div className="windows-fleet-software-heading"><span>{page.mode === 'fleet' ? `${c.devices}: ${page.items.length ? page.offset + 1 : 0}–${page.offset + page.items.length} ${c.of} ${page.totalDevices}` : `${c.rows}: ${page.items[0].rows.length ? page.offset + 1 : 0}–${page.offset + page.items[0].rows.length} ${c.of} ${page.items[0].matchingCount}`}</span>{page.mode === 'device' && <button type="button" className="text-button" onClick={resource.back}>{c.back}</button>}</div>
                {!page.totalDevices && <p>{c.noDevices}</p>}
                <ul className="windows-fleet-software-results">{page.items.map(item => <li key={`${item.deviceId}:${item.identity}`}>
                    <div className="windows-fleet-software-heading"><strong className="windows-fleet-software-device">{item.deviceId}</strong><span>{item.status === 'ready' ? fleetSoftwareFresh(item, page.serverNow, resource.elapsed) ? c.fresh : c.stale : c[item.status]}</span></div>
                    {attempt(item)}
                    {item.complete && <>
                        <p>{c.matches}: {item.matchingCount} · {c.unknown}: {item.unknownCount}</p>
                        <p className="windows-fleet-software-help">{c.complete} · <time dateTime={item.complete.manifest.captureStartedAt}>{fullDate(item.complete.manifest.captureStartedAt)}</time></p>
                        {item.rows.length > 0 ? <div className="windows-fleet-software-table-wrap"><table><caption className="sr-only">{c.rows} · {item.deviceId}</caption><thead><tr><th scope="col">{c.name}</th><th scope="col">{c.version}</th><th scope="col">{c.view}</th></tr></thead><tbody>{item.rows.map(row => <tr key={row.registrationId}><td>{value(row.name)}</td><td>{value(row.version)}</td><td>HKLM {row.registryView}</td></tr>)}</tbody></table></div> : <p>{c.noMatch}</p>}
                        {page.mode === 'fleet' && <button type="button" className="text-button" aria-label={`${c.detail}: ${item.deviceId}`} onClick={() => resource.detail(item)}>{c.detail}</button>}
                    </>}
                    <details className="windows-fleet-software-source"><summary>{c.source}</summary><p>{c.lifetime}</p><dl>{time(c.authority, item.authorityUntil)}{page.cursorExpiresAt && time(c.paging, page.cursorExpiresAt)}<div><dt>{c.identity}</dt><dd>{item.identity}</dd></div>{item.complete && <>{time(c.captured, item.complete.manifest.captureStartedAt)}{time(c.finished, item.complete.manifest.captureFinishedAt)}{time(c.received, item.complete.receivedAt)}{time(c.expiry, item.complete.manifest.expiresAt)}<div><dt>{c.registrationCount}</dt><dd>{item.complete.manifest.rowCount}</dd></div><div><dt>{c.generation}</dt><dd>{item.complete.manifest.generationId}</dd></div></>}{item.latestAttempt && time(c.attempted, item.latestAttempt.attemptedAt)}</dl></details>
                </li>)}</ul>
                {page.nextCursor && <div className="windows-fleet-software-pagination"><button type="button" className="button small" onClick={resource.next}>{page.mode === 'fleet' ? c.nextDevices : c.nextRows}</button></div>}
            </>}
        </>}
    </div>;
}
