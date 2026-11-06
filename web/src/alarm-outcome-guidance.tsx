import { useId } from 'react';
import { useLocale } from './i18n';
import type { AlarmStatus } from './alarm-status-types';

const copy = {
    en: {
        title: 'Review retained delivery outcomes',
        scope: 'These counts can include earlier destinations and synthetic tests. They do not identify an affected incident or prove a current destination problem.',
        previous: 'Previous snapshot. Refresh status before assessing current delivery.',
        dropped: 'Dropped: some events could not enter the full queue. Review incidents independently; these counts cannot identify the missed events.',
        uncertain: 'Uncertain: the provider may have accepted these events. Check the recipient independently before considering another send to avoid duplicates.',
        failed: 'Failed: these retained events ended without provider acceptance. An administrator can review destination settings; a synthetic test needs its own confirmation.',
        refresh: 'Refreshing only reads saved counts. It does not resend an event or clear these outcomes.',
    },
    de: {
        title: 'Gespeicherte Versandergebnisse prüfen',
        scope: 'Diese Zähler können frühere Ziele und synthetische Tests enthalten. Sie benennen keinen betroffenen Vorfall und belegen kein aktuelles Problem am Versandziel.',
        previous: 'Vorheriger Stand. Vor der Bewertung des aktuellen Versands den Status aktualisieren.',
        dropped: 'Verworfen: Einige Ereignisse konnten nicht in die volle Warteschlange aufgenommen werden. Vorfälle separat prüfen; diese Zähler benennen die fehlenden Ereignisse nicht.',
        uncertain: 'Ungewiss: Der Anbieter kann diese Ereignisse angenommen haben. Vor einem weiteren Versand den Empfang separat prüfen, um Duplikate zu vermeiden.',
        failed: 'Fehlgeschlagen: Diese gespeicherten Ereignisse endeten ohne Anbieterannahme. Ein Administrator kann die Zieleinstellungen prüfen; ein synthetischer Test erfordert eine eigene Bestätigung.',
        refresh: 'Aktualisieren liest nur gespeicherte Zähler. Es versendet kein Ereignis erneut und löscht diese Ergebnisse nicht.',
    },
};

/** Presentation only: aggregate history is not a current incident or retry plan. */
export function AlarmOutcomeGuidance({ view, previous }: { view: AlarmStatus; previous: boolean }) {
    const [locale] = useLocale(), labels = copy[locale], heading = useId();
    if (view.failed === 0 && view.uncertain === 0 && view.dropped === 0) return null;
    return <aside className="alarm-notice" aria-labelledby={heading}>
        <h3 id={heading}>{labels.title}</h3>
        {previous && <p><strong>{labels.previous}</strong></p>}
        <p>{labels.scope}</p>
        <ul>
            {view.dropped > 0 && <li>{labels.dropped}</li>}
            {view.uncertain > 0 && <li>{labels.uncertain}</li>}
            {view.failed > 0 && <li>{labels.failed}</li>}
        </ul>
        <p>{labels.refresh}</p>
    </aside>;
}
