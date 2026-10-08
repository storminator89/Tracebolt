import { useLocale } from './i18n';
import { fullDate } from './utils';
import type { WindowsInventoryResource } from './windows-inventory-resource';

export function WindowsEventsPanel({ resource, onOpenLogs }: { resource: WindowsInventoryResource; onOpenLogs?: () => void }) {
    const [locale] = useLocale(), de = locale === 'de';
    const events = resource.events;
    const state = resource.error ? (de ? 'Ereignisse nicht verfügbar. Health unbekannt.' : 'Events unavailable. Health unknown.') : resource.loading ? (de ? 'Ereignisse werden geladen …' : 'Loading events …') : resource.status === 'revoked' ? (de ? 'Gerätefreigabe beendet.' : 'Device access ended.') : !events ? (de ? 'Keine aktuelle Ereignisfreigabe gemeldet. Health unbekannt.' : 'No current event scope reported. Health unknown.') : resource.eventsStale ? (de ? 'Veraltete Ereignisstichprobe. Health unbekannt.' : 'Stale event sample. Health unknown.') : (de ? 'Beobachtete Ereignisse' : 'Observed events');
    const qualities = { observed: de ? 'Erfasst' : 'Observed', bounded: de ? 'Begrenzt' : 'Bounded', partial: de ? 'Unvollständig' : 'Partial', denied: de ? 'Zugriff verweigert' : 'Access denied', unavailable: de ? 'Nicht verfügbar' : 'Unavailable' };
    const level = (n: number) => [de ? 'Unbekannt' : 'Unknown', de ? 'Kritisch' : 'Critical', de ? 'Fehler' : 'Error', de ? 'Warnung' : 'Warning', de ? 'Information' : 'Information', de ? 'Ausführlich' : 'Verbose'][n] ?? (de ? 'Unbekannt' : 'Unknown');
    return <section className="windows-inventory" aria-label={de ? 'Windows-Ereignisse' : 'Windows events'}>
        <div className="windows-inventory-section-header"><h2>{de ? 'Windows-Ereignisse' : 'Windows events'}</h2><button className="button small" disabled={resource.loading || resource.error === 'session'} onClick={resource.refresh}>{de ? 'Aktualisieren' : 'Refresh events'}</button></div>
        <p role={resource.error ? 'alert' : 'status'}>{state}</p>
        {events && <><p>{de ? 'Erfasst' : 'Captured'}: <time dateTime={events.collectedAt}>{fullDate(events.collectedAt)}</time></p>{events.channels.map(channel => {
            const flagged = channel.rows.filter(e => e.level >= 1 && e.level <= 3).length;
            return <section key={channel.channel} aria-label={channel.channel}><div className="windows-inventory-section-header"><h3>{channel.channel}</h3><span>{qualities[channel.quality]}</span></div>
                {channel.quality === 'denied' || channel.quality === 'unavailable' ? <p>{de ? 'Keine auswertbare Beobachtung.' : 'No usable observation.'}</p> : <p>{channel.rows.length === 0 ? (de ? 'Keine Ereignisköpfe zurückgegeben. Health unbekannt.' : 'No event headers returned. Health unknown.') : de ? `${flagged} Fehler-/Warnköpfe in ${channel.rows.length} angezeigten Ereignissen.` : `${flagged} error/warning headers in ${channel.rows.length} displayed events.`}</p>}
                {channel.truncated && <p>{de ? 'Begrenzte Stichprobe; weitere Ereignisse fehlen.' : 'Bounded sample; more events are omitted.'}</p>}
                {channel.rows.length > 0 && <details><summary>{de ? 'Ereignisse ansehen' : 'View events'}</summary><div className="windows-inventory-table-wrap"><table className="windows-inventory-table"><thead><tr>{[de ? 'Zeit' : 'Time', de ? 'Stufe' : 'Level', 'Provider', 'ID'].map(h=><th key={h} scope="col">{h}</th>)}</tr></thead><tbody>{channel.rows.map(event=><tr key={event.recordId}><td data-label={de ? 'Zeit' : 'Time'}><time dateTime={event.timestamp}>{fullDate(event.timestamp)}</time></td><td data-label={de ? 'Stufe' : 'Level'}>{level(event.level)}</td><td data-label="Provider">{event.provider}</td><td data-label="ID">{event.eventId}</td></tr>)}</tbody></table></div></details>}
            </section>;
        })}</>}
        {onOpenLogs && <button type="button" className="text-button" onClick={onOpenLogs}>{de ? 'Ereignisköpfe in Logs öffnen' : 'Open event headers in Logs'}</button>}
        <details className="windows-inventory-scope"><summary>{de ? 'Umfang' : 'Scope'}</summary><p>{de ? 'Nur Application-/System-Ereignisköpfe. Keine Nachrichten oder Security-Logs, kein KI-Export. Die Stichprobe ist keine vollständige Health-Bewertung. Ereignisse können älter als die Erfassung sein. Eine separate lokale Freigabe ist erforderlich.' : 'Application/System event headers only. No messages, Security logs or AI export. A sample is not a complete health assessment. Events may be older than the capture time. Separate local approval is required.'}</p></details>
    </section>;
}
