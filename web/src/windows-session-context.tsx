import { Users, Building2 } from 'lucide-react';
import { useLocale } from './i18n';
import { fullDate } from './utils';
import type { WindowsInventoryResource } from './windows-inventory-resource';
import type { WindowsSessionFieldQuality } from './windows-session-context-types';
import './windows-session-context.css';

const copy = {
    en: {
        title: 'Users / Sessions', sessions: 'Caller-visible sessions', captured: 'Captured', membership: 'Device membership', observed: 'Observed', partial: 'Partial', denied: 'Access denied', unavailable: 'Unavailable', unknown: 'Unknown', emptyLabel: 'No label',
        join: { unjoined: 'Unjoined', domain: 'Domain', workgroup: 'Workgroup', unknown: 'Unknown membership' },
        states: { active: 'Active', connected: 'Connected', 'connect-query': 'Connecting', shadow: 'Shadow', disconnected: 'Disconnected', idle: 'Idle', listen: 'Listening', reset: 'Reset', down: 'Down', init: 'Initializing', unknown: 'Unknown' },
        protocols: { console: 'Console', rdp: 'RDP', unknown: 'Unknown' },
        id: 'Session ID', user: 'User', domain: 'Domain', state: 'State', protocol: 'Protocol', shown: 'shown', omitted: 'omitted',
        noRows: 'No sessions observed within the caller-visible scope.', noRetained: 'No session rows were retained. See source coverage for collection limits.', missing: 'Session visibility is unavailable. An empty session list cannot be established.',
        absent: 'Session context is unavailable for this capture. Separate local approval is required.',
        stale: 'Stale observation; values describe the original capture.', expired: 'Session context expired after 24 hours.', ahead: 'Session context is hidden until its capture time can be verified.',
        details: 'Source & coverage', source: 'Session source', sessionSource: 'Local Windows session API (WTS)', joinSourceLabel: 'Membership source', joinSource: 'Local computer join information', count: 'Caller-visible count', retained: 'Retained rows', truncated: 'Omitted rows', limit: 'At most 32 session rows are retained. Counts cover caller-visible sessions only. Session state is an API label; activity and idle time are not monitored.',
        privacy: 'Caller-visible sessions, not all users or accounts. Names are personal metadata, visible only to operators and excluded from AI/provider export.',
        reasons: { windows_session_context_access_denied: 'Source access denied.', windows_session_context_unavailable: 'Source unavailable.', windows_session_context_unsupported_platform: 'Source unsupported.', windows_session_context_invalid_metadata: 'Some source metadata was invalid.', windows_session_context_bounds: 'Source collection limit reached.', windows_session_context_partial_result: 'Some fields were not available.', windows_session_context_budget_exhausted: 'Source collection time limit reached.' },
    },
    de: {
        title: 'Benutzer / Sitzungen', sessions: 'Sichtbare Sitzungen', captured: 'Erfasst', membership: 'Gerätezugehörigkeit', observed: 'Beobachtet', partial: 'Teilweise', denied: 'Zugriff verweigert', unavailable: 'Nicht verfügbar', unknown: 'Unbekannt', emptyLabel: 'Keine Angabe',
        join: { unjoined: 'Nicht beigetreten', domain: 'Domäne', workgroup: 'Arbeitsgruppe', unknown: 'Zugehörigkeit unbekannt' },
        states: { active: 'Aktiv', connected: 'Verbunden', 'connect-query': 'Verbindungsaufbau', shadow: 'Spiegelung', disconnected: 'Getrennt', idle: 'Leerlauf', listen: 'Wartend', reset: 'Zurückgesetzt', down: 'Inaktiv', init: 'Initialisierung', unknown: 'Unbekannt' },
        protocols: { console: 'Konsole', rdp: 'RDP', unknown: 'Unbekannt' },
        id: 'Sitzungs-ID', user: 'Benutzer', domain: 'Domäne', state: 'Zustand', protocol: 'Protokoll', shown: 'angezeigt', omitted: 'ausgelassen',
        noRows: 'Keine Sitzungen im sichtbaren Erfassungsumfang beobachtet.', noRetained: 'Keine Sitzungszeilen aufbewahrt. Erfassungsgrenzen stehen unter Quelle & Umfang.', missing: 'Sitzungsdaten sind nicht verfügbar. Eine leere Sitzungsliste ist damit nicht belegt.',
        absent: 'Für diese Erfassung sind keine Sitzungsdaten verfügbar. Eine separate lokale Zustimmung ist erforderlich.',
        stale: 'Veraltete Beobachtung; Werte gelten für die ursprüngliche Erfassung.', expired: 'Sitzungsdaten nach 24 Stunden abgelaufen.', ahead: 'Sitzungsdaten bleiben ausgeblendet, bis die Erfassungszeit geprüft werden kann.',
        details: 'Quelle & Umfang', source: 'Sitzungsquelle', sessionSource: 'Lokale Windows-Sitzungs-API (WTS)', joinSourceLabel: 'Quelle der Zugehörigkeit', joinSource: 'Lokale Beitrittsinformationen des Computers', count: 'Sichtbare Sitzungen', retained: 'Aufbewahrte Zeilen', truncated: 'Ausgelassene Zeilen', limit: 'Höchstens 32 Sitzungszeilen werden aufbewahrt. Zahlen gelten nur für Sitzungen, die mit den Dienstberechtigungen sichtbar sind. Der Zustand ist eine API-Angabe; Aktivität und Leerlaufzeit werden nicht überwacht.',
        privacy: 'Sichtbare Sitzungen, keine vollständige Benutzer- oder Kontenliste. Namen sind personenbezogene Metadaten, nur für Operatoren sichtbar und vom KI-/Provider-Export ausgeschlossen.',
        reasons: { windows_session_context_access_denied: 'Zugriff auf Quelle verweigert.', windows_session_context_unavailable: 'Quelle nicht verfügbar.', windows_session_context_unsupported_platform: 'Quelle nicht unterstützt.', windows_session_context_invalid_metadata: 'Einige Quellmetadaten waren ungültig.', windows_session_context_bounds: 'Erfassungsgrenze der Quelle erreicht.', windows_session_context_partial_result: 'Einige Felder waren nicht verfügbar.', windows_session_context_budget_exhausted: 'Zeitlimit der Quelle erreicht.' },
    },
};
export function WindowsSessionContextPanel({ resource }: { resource: WindowsInventoryResource }) {
    const [locale] = useLocale(), c = copy[locale], context = resource.sessionContext;
    if (!context) return <p role="status" className="windows-inventory-empty">{resource.sessionContextExpired ? c.expired : resource.sessionContextAhead ? c.ahead : c.absent}</p>;
    const { sessions, join } = context, binding = `${resource.view?.deviceId}:${context.grantId}:${context.generationId}:${context.collectedAt}`;
    const headers = [c.id, c.user, c.domain, c.state, c.protocol];
    const field = (value: string | null, quality: WindowsSessionFieldQuality) => quality === 'observed' ? value : quality === 'empty' ? c.emptyLabel : c[quality];
    return <section className="windows-session-context" aria-label={c.title}>
        <div className="windows-inventory-section-header"><h3>{c.title}</h3><span className="windows-inventory-times">{c.captured} <time dateTime={context.collectedAt}>{fullDate(context.collectedAt)}</time></span></div>
        {resource.sessionContextStale && <p role="status" className="windows-inventory-caution">{c.stale}</p>}
        <section className="windows-session-membership" aria-label={c.membership}>
            <h4><Building2 size={17} aria-hidden="true"/>{c.membership}</h4>
            <span className="windows-session-join-kind">{c.join[join.status]}</span>
            {join.status !== 'unjoined' && join.status !== 'unknown' && <bdi className="windows-session-join-name">{join.name ?? c.unknown}</bdi>}
            <span className="windows-session-quality">{c[join.quality]}</span>
        </section>
        <div className="windows-session-heading"><h4><Users size={17} aria-hidden="true"/>{c.sessions}</h4><span className="windows-session-quality">{c[sessions.quality]}</span></div>
        {sessions.observedCount !== null && <p className="windows-inventory-count">{sessions.retainedCount} {c.shown} · {sessions.observedCount} {c.observed.toLocaleLowerCase(locale)}{sessions.truncatedCount ? ` · ${sessions.truncatedCount} ${c.omitted}` : ''}</p>}
        {sessions.rows.length > 0 ? <div className="windows-inventory-table-wrap"><table className="windows-inventory-table windows-session-table"><caption className="sr-only">{c.sessions}</caption><thead><tr>{headers.map(header => <th key={header} scope="col">{header}</th>)}</tr></thead><tbody>{sessions.rows.map(row => <tr key={row.sessionId}>
            <td data-label={c.id}>{row.sessionId}</td><td data-label={c.user}><bdi>{field(row.userName, row.userQuality)}</bdi></td><td data-label={c.domain}><bdi>{field(row.domainName, row.domainQuality)}</bdi></td><td data-label={c.state}>{c.states[row.state]}</td><td data-label={c.protocol}>{c.protocols[row.protocol]}</td>
        </tr>)}</tbody></table></div> : <p role="status" className="windows-inventory-empty">{sessions.quality === 'observed' ? c.noRows : sessions.observedCount !== null ? c.noRetained : c.missing}</p>}
        <details className="windows-session-details" key={binding}><summary>{c.details}</summary>
            <dl><div><dt>{c.source}</dt><dd>{c.sessionSource}</dd></div><div><dt>{c.count}</dt><dd>{sessions.observedCount ?? c.unknown}</dd></div><div><dt>{c.retained}</dt><dd>{sessions.retainedCount}</dd></div><div><dt>{c.truncated}</dt><dd>{sessions.truncatedCount ?? c.unknown}</dd></div></dl>
            {sessions.reason && <p className="windows-inventory-caution">{c.reasons[sessions.reason]}</p>}
            <dl><div><dt>{c.joinSourceLabel}</dt><dd>{c.joinSource}</dd></div></dl>
            {join.reason && <p className="windows-inventory-caution">{c.reasons[join.reason]}</p>}
            <p>{c.limit}</p>
        </details>
        <p className="windows-session-note">{c.privacy}</p>
    </section>;
}
