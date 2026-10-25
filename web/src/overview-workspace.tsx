import { ArrowRight } from 'lucide-react';
import { useLocale } from './i18n';
import { reportTimestamp } from './report-time';
import { fullDate } from './utils';
import './overview-workspace.css';

const copy = {
    en: {
        context: 'Data context', snapshot: 'Overview generated', unknown: 'Time unavailable',
        lan: 'LAN agent reports', local: 'Demo and local sources', demo: 'Synthetic examples only',
        boundary: 'Observation times belong to each source. Missing data is not an all-clear.',
        refreshing: 'Refreshing overview… Previous snapshot shown.',
        failed: 'Refresh unavailable. Previous snapshot shown.',
        linux: 'Linux Health incidents', windows: 'Windows incidents in Devices',
        localWork: 'Cases from the available rules',
    },
    de: {
        context: 'Datenkontext', snapshot: 'Übersicht erstellt', unknown: 'Zeit nicht verfügbar',
        lan: 'Meldungen der LAN-Agenten', local: 'Demo und lokale Quellen', demo: 'Nur synthetische Beispiele',
        boundary: 'Beobachtungszeiten gelten je Quelle. Fehlende Daten sind keine Entwarnung.',
        refreshing: 'Übersicht wird aktualisiert … Vorheriger Stand wird angezeigt.',
        failed: 'Aktualisierung nicht verfügbar. Vorheriger Stand wird angezeigt.',
        linux: 'Linux-Health-Vorfälle', windows: 'Windows-Vorfälle unter Geräte',
        localWork: 'Fälle aus den verfügbaren Regeln',
    },
} as const;

/** Presentation only. generatedAt describes this overview, never the age of
 * device, Health or application-check evidence. Each owner retains its clock. */
export function OverviewContext({ generatedAt, lan, demoOnly = false, loading, failed }: {
    generatedAt: string; lan: boolean; demoOnly?: boolean; loading: boolean; failed: boolean;
}) {
    const [locale] = useLocale(), c = copy[locale];
    return <section className="overview-context" aria-label={c.context}>
        <div className="overview-context-line"><strong>{lan ? c.lan : demoOnly ? c.demo : c.local}</strong><span>{c.snapshot}: {reportTimestamp(generatedAt) ? <time dateTime={generatedAt}>{fullDate(generatedAt)}</time> : c.unknown}</span></div>
        <p>{c.boundary}</p>
        {(loading || failed) && <p className="overview-context-notice" role="status">{loading ? c.refreshing : c.failed}</p>}
    </section>;
}

export function OverviewWorkScope({ lan, onDevices }: { lan: boolean; onDevices: () => void }) {
    const [locale] = useLocale(), c = copy[locale];
    return <div className="overview-work-scope"><p>{lan ? c.linux : c.localWork}</p>{lan && <button className="text-button" onClick={onDevices}>{c.windows}<ArrowRight size={14} aria-hidden="true"/></button>}</div>;
}
