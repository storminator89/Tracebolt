import { useId, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import type { SoftwareHistoryChange, SoftwareHistoryPage } from './windows-software-history-types';
import './windows-software-history-page-filter.css';

const kinds = ['all', 'registration_added', 'registration_removed', 'metadata_changed'] as const;
type Kind = typeof kinds[number];
const copy = {
    en: {
        label: 'Change type on this page', all: 'All change types', registration_added: 'Added registrations', registration_removed: 'Removed registrations', metadata_changed: 'Changed metadata',
        scope: 'Filters only the loaded page. Search totals and other pages are unchanged. Each new page starts with all change types.',
        reset: 'Show all change types', empty: 'No changes of this type on the loaded page. Other pages may contain matches.',
        count: (shown: number, total: number) => `${shown} of ${total} changes on this page shown`,
    },
    de: {
        label: 'Änderungsart auf dieser Seite', all: 'Alle Änderungsarten', registration_added: 'Hinzugefügte Registrierungen', registration_removed: 'Entfernte Registrierungen', metadata_changed: 'Geänderte Metadaten',
        scope: 'Filtert nur die geladene Seite. Suchtrefferzahl und andere Seiten bleiben unverändert. Jede neue Seite beginnt mit allen Änderungsarten.',
        reset: 'Alle Änderungsarten anzeigen', empty: 'Keine Änderungen dieser Art auf der geladenen Seite. Andere Seiten können Treffer enthalten.',
        count: (shown: number, total: number) => `${shown} von ${total} Änderungen auf dieser Seite angezeigt`,
    },
};
type Props = {
    page: Pick<SoftwareHistoryPage, 'deviceId' | 'grantId' | 'grantRevision' | 'historyDigest' | 'search' | 'offset' | 'rows'>;
    locale: 'en' | 'de';
    children: (rows: SoftwareHistoryChange[]) => ReactNode;
};

/** Presentation of the currently admitted page only. Never fetch, retain older
 * rows, change server counts/cursors, or reinterpret registration differences. */
export function WindowsSoftwareHistoryPageFilter({ page, ...props }: Props) {
    const key = JSON.stringify([page.deviceId, page.grantId, page.grantRevision, page.historyDigest, page.search, page.offset]);
    return <PageFilter key={key} rows={page.rows} {...props}/>;
}
function PageFilter({ rows, locale, children }: Omit<Props, 'page'> & { rows: SoftwareHistoryChange[] }) {
    const [kind, setKind] = useState<Kind>('all'), id = useId(), select = useRef<HTMLSelectElement>(null), c = copy[locale];
    const shown = kind === 'all' ? rows : rows.filter(row => row.kind === kind);
    return <>
        <div className="windows-history-page-filter">
            <label htmlFor={id}>{c.label}</label>
            <select ref={select} id={id} value={kind} aria-describedby={`${id}-scope`} onChange={event => { const value = event.target.value; if (kinds.some(item => item === value)) setKind(value as Kind); }}>
                {kinds.map(value => <option key={value} value={value}>{c[value]}</option>)}
            </select>
            {kind !== 'all' && <button type="button" className="button small" onClick={() => { setKind('all'); select.current?.focus(); }}>{c.reset}</button>}
            <p id={`${id}-scope`} className="windows-history-page-filter-scope">{c.scope}</p>
            <p className="windows-history-page-filter-count" role="status" aria-atomic="true">{c.count(shown.length, rows.length)}</p>
        </div>
        {shown.length ? children(shown) : <p className="windows-inventory-empty">{c.empty}</p>}
    </>;
}
