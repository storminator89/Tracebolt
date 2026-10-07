import { useLocale } from './i18n';

export function InventoryLiveStatus({ state }: { state: 'active' | 'paused' | 'retrying' }) {
    const [locale] = useLocale(), de = locale === 'de';
    const title = de
        ? 'Die erste Seite wird alle 15 Sekunden geprüft. Neue Erfassungen folgen dem Agentenintervall. Blättern und eine noch nicht abgesendete Suche pausieren die Aktualisierung. Erfassungszeiten bleiben unverändert.'
        : 'The first page is checked every 15 seconds. New captures follow the agent interval. Paging and an unsubmitted search pause refresh. Collection times are unchanged.';
    return <p className="package-note" aria-label={de ? 'Inventaraktualisierung' : 'Inventory auto-refresh'} title={title}>{state === 'paused' ? (de ? '↻ Pausiert' : '↻ Paused') : state === 'retrying' ? (de ? '↻ Wiederholung ausstehend · letzter Datenstand unverändert' : '↻ Retrying · last snapshot unchanged') : (de ? '↻ Erste Seite · 15 s' : '↻ First page · 15 s')}</p>;
}
