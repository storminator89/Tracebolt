import { useLocale } from './i18n';
import { fullDate } from './utils';
import { IncidentTimeline, timelineCheckpointLabel, timelineCurrentLabel } from './incident-timeline';
import { comparisonCheckpoints, MAX_COMPARISON_EPISODES } from './incident-comparison-model';
import type { ComparisonEpisode } from './incident-comparison-model';

const copy = {
    en: {
        title: 'Compare incident episodes', selected: 'Selected episodes', choose: 'Select two to four visible episodes to compare their original checkpoints. Page, filter and session changes clear selection. Episodes are removed when their source disappears.',
        limit: 'Four episodes selected. Remove one before selecting another.', open: 'Open comparison', close: 'Close comparison', clear: 'Clear comparison', remove: 'Remove episode',
        chronology: 'Original checkpoints across selected episodes', boundary: 'This is a live comparison of loaded pages, not a shared incident or a pinned snapshot. Source clocks may differ. Time order and overlap do not establish correlation, uninterrupted failure or a common cause.',
        current: 'Current check, independent of the retained episode', readAt: 'Source page read at', unavailable: 'Not available', episode: 'Episode',
        openOutcome: 'Still open', recoveredOutcome: 'Check recovery or reports resumed', stoppedOutcome: 'Closed without confirmed recovery',
        'linux-health': 'Linux Health', 'windows-assessment': 'Windows assessment', 'windows-full-services': 'Windows complete service inventory',
    },
    de: {
        title: 'Vorfall-Episoden vergleichen', selected: 'Ausgewählte Episoden', choose: 'Zwei bis vier sichtbare Episoden auswählen, um ihre ursprünglichen Eckpunkte zu vergleichen. Seiten-, Filter- und Sitzungswechsel löschen die Auswahl. Bei Quellenverlust wird die betroffene Episode entfernt.',
        limit: 'Vier Episoden ausgewählt. Vor einer weiteren Auswahl eine entfernen.', open: 'Vergleich öffnen', close: 'Vergleich schließen', clear: 'Vergleich leeren', remove: 'Episode entfernen',
        chronology: 'Ursprüngliche Eckpunkte der ausgewählten Episoden', boundary: 'Dies ist ein aktueller Vergleich geladener Seiten, kein gemeinsamer Vorfall und keine fixierte Momentaufnahme. Quelluhren können abweichen. Zeitfolge und Überschneidungen belegen weder Zusammenhang noch durchgehenden Fehler oder gemeinsame Ursache.',
        current: 'Aktuelle Prüfung, unabhängig von der gespeicherten Episode', readAt: 'Quellseite abgerufen', unavailable: 'Nicht verfügbar', episode: 'Episode',
        openOutcome: 'Weiter offen', recoveredOutcome: 'Prüfung erholt oder Berichte fortgesetzt', stoppedOutcome: 'Ohne bestätigte Erholung geschlossen',
        'linux-health': 'Linux Health', 'windows-assessment': 'Windows-Bewertung', 'windows-full-services': 'Vollständiges Windows-Dienstinventar',
    },
};

/** Local presentation only. No fetch, export, persistence or mutation controls. */
export function IncidentComparison({ episodes, expanded, onExpanded, onClear, onRemove }: {
    episodes: ComparisonEpisode[]; expanded: boolean; onExpanded: (value: boolean) => void; onClear: () => void; onRemove: (identity: string) => void;
}) {
    const [locale] = useLocale(), c = copy[locale];
    const checkpoints = expanded && episodes.length >= 2 ? comparisonCheckpoints(episodes) : [];
    return <section className="panel incident-comparison" aria-label={c.title}>
        <header><h2>{c.title}</h2><span aria-live="polite">{c.selected}: {episodes.length}/{MAX_COMPARISON_EPISODES}</span></header>
        <p>{c.choose}</p>
        {episodes.length === MAX_COMPARISON_EPISODES && <p role="status">{c.limit}</p>}
        {episodes.length > 0 && <><ul className="incident-comparison-selection">{episodes.map((episode, index) => <li key={episode.identity}><span>{c.episode} {index + 1} · {c[episode.source]} · {episode.model.deviceId} · {episode.model.incidentId} · {episode.model.target} · {episode.model.sourceKey}</span><button type="button" className="text-button" onClick={() => onRemove(episode.identity)} aria-label={`${c.remove}: ${index + 1}`}>{c.remove}</button></li>)}</ul>
            <div className="incident-comparison-actions"><button type="button" className="button small" disabled={episodes.length < 2} aria-expanded={expanded && episodes.length >= 2} onClick={() => onExpanded(!expanded)}>{expanded && episodes.length >= 2 ? c.close : c.open}</button><button type="button" className="text-button" onClick={onClear}>{c.clear}</button></div></>}
        {expanded && episodes.length >= 2 && <div className="incident-comparison-content">
            <p>{c.boundary}</p>
            <div className="incident-comparison-cards">{episodes.map((episode, index) => <article key={episode.identity} aria-label={`${c.episode} ${index + 1}`}>
                <h3>{c.episode} {index + 1} · {c[episode.source]}</h3><p className="incident-comparison-identity">{episode.model.deviceId}<br/>{episode.model.incidentId}<br/>{episode.model.target}<br/>{episode.model.sourceKey}</p>
                <p><strong>{episode.model.lifecycle === 'open' ? c.openOutcome : episode.model.lifecycle === 'stopped' ? c.stoppedOutcome : c.recoveredOutcome}</strong></p>
                <p>{c.readAt}: {episode.readAt ? <time dateTime={episode.readAt}>{fullDate(episode.readAt)}<span className="incident-timeline-exact">{episode.readAt}</span></time> : c.unavailable}</p>
                <p>{c.current}: <strong>{timelineCurrentLabel(episode.model.current.state, locale)}</strong></p>
                <IncidentTimeline model={episode.model} platform={episode.platform}/>
            </article>)}</div>
            <section aria-label={c.chronology}><h3>{c.chronology}</h3><ol className="incident-comparison-checkpoints">{checkpoints.map((checkpoint, index) => <li key={`${checkpoint.identity}:${index}`}><span>{c.episode} {checkpoint.episodeIndex + 1} · {c[episodes[checkpoint.episodeIndex].source]}</span><strong>{timelineCheckpointLabel(checkpoint.kind, locale)}</strong><time dateTime={checkpoint.at}>{fullDate(checkpoint.at)}<span className="incident-timeline-exact">{checkpoint.at}</span></time></li>)}</ol></section>
        </div>}
    </section>;
}
