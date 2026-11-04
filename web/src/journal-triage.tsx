import { useId, useState } from 'react';
import { useLocale } from './i18n';
import { journalFold } from './journal-types';
import type { JournalPage } from './journal-types';
import { journalMessageGroups, journalPageRows, journalTriageBinding } from './journal-triage-model';
import type { JournalPageOrder } from './journal-triage-model';
import './journal-triage.css';

const copy = {
    en: { title: 'Review this page', scope: 'Only the loaded display page is summarized and filtered here. No additional logs are read.', severity: 'Page severity', all: 'All severities', view: 'Display', rows: 'Individual messages', groups: 'Group identical messages', order: 'Page order', source: 'Source order', oldest: 'Oldest first', newest: 'Newest first', shown: 'messages shown', of: 'of', page: 'loaded on this page', reset: 'Reset page view', time: 'Time (UTC)', level: 'Severity', message: 'Message', empty: 'No messages at this severity on the loaded page.', matches: 'displayed message groups', equality: 'Groups match exact displayed message, severity and service. Masking may make different original messages look identical; these are not event identities.', count: 'occurrences on this page', first: 'First on this page (UTC)', last: 'Last on this page (UTC)', occurrences: 'Show occurrences', row: 'Result row', levels: ['Emergency', 'Alert', 'Critical', 'Error', 'Warning', 'Notice', 'Info', 'Debug'] },
    de: { title: 'Diese Seite prüfen', scope: 'Hier wird nur die geladene Anzeigeseite zusammengefasst und gefiltert. Es werden keine weiteren Logs gelesen.', severity: 'Schweregrad auf dieser Seite', all: 'Alle Schweregrade', view: 'Anzeige', rows: 'Einzelne Nachrichten', groups: 'Identische Nachrichten gruppieren', order: 'Seitenreihenfolge', source: 'Quellreihenfolge', oldest: 'Älteste zuerst', newest: 'Neueste zuerst', shown: 'Nachrichten angezeigt', of: 'von', page: 'auf dieser Seite geladen', reset: 'Seitenansicht zurücksetzen', time: 'Zeit (UTC)', level: 'Schweregrad', message: 'Nachricht', empty: 'Keine Nachrichten dieses Schweregrads auf der geladenen Seite.', matches: 'Gruppen angezeigter Nachrichten', equality: 'Gruppen stimmen in angezeigter Nachricht, Schweregrad und Dienst exakt überein. Maskierung kann unterschiedliche Originalnachrichten gleich aussehen lassen; das sind keine Ereignisidentitäten.', count: 'Vorkommen auf dieser Seite', first: 'Erstes Vorkommen auf dieser Seite (UTC)', last: 'Letztes Vorkommen auf dieser Seite (UTC)', occurrences: 'Vorkommen anzeigen', row: 'Trefferzeile', levels: ['Notfall', 'Alarm', 'Kritisch', 'Fehler', 'Warnung', 'Hinweis', 'Info', 'Debug'] },
};

export function JournalHighlight({ text, search }: { text: string; search: string }) {
    if (!search) return <>{text}</>;
    const folded = journalFold(text), needle = journalFold(search), nodes = []; let at = 0, found = folded.indexOf(needle);
    while (found >= 0) { nodes.push(text.slice(at, found), <mark key={found}>{text.slice(found, found + needle.length)}</mark>); at = found + needle.length; found = folded.indexOf(needle, at); }
    nodes.push(text.slice(at)); return <>{nodes}</>;
}

function Timestamp({ value, zone = false }: { value: string; zone?: boolean }) {
    return <time dateTime={value}>{value.replace('T', ' ').replace(/Z$/, '')}{zone ? ' UTC' : ''}</time>;
}

// All content is derived from current props. The key resets controls and native
// disclosure state synchronously at every session/request/page boundary.
export function JournalPageTriage({ page, sessionKey = null }: { page: JournalPage; sessionKey?: string | null }) {
    return <JournalTriage key={journalTriageBinding(page, sessionKey)} page={page}/>;
}

function JournalTriage({ page }: { page: JournalPage }) {
    const [locale] = useLocale(), c = copy[locale], id = useId();
    const [priority, setPriority] = useState<number | null>(null), [order, setOrder] = useState<JournalPageOrder>('source'), [grouped, setGrouped] = useState(false);
    const counts = Array.from({ length: 8 }, (_, level) => page.rows.filter(row => row.priority === level).length);
    const rows = journalPageRows(page.rows, priority, order), groups = grouped ? journalMessageGroups(rows) : [];
    const search = page.search || page.query.search || '';
    const reset = () => { setPriority(null); setOrder('source'); setGrouped(false); };
    return <section className="journal-triage" aria-labelledby={`${id}-title`}>
        <header><h4 id={`${id}-title`}>{c.title}</h4><button type="button" className="button small" disabled={priority === null && order === 'source' && !grouped} onClick={reset}>{c.reset}</button></header>
        <p className="journal-muted" id={`${id}-scope`}>{c.scope}</p>
        <fieldset className="journal-triage-severities" aria-describedby={`${id}-scope`}><legend>{c.severity}</legend>
            <button type="button" className="button small" aria-pressed={priority === null} onClick={() => setPriority(null)}>{c.all} ({page.rows.length})</button>
            {counts.map((count, level) => <button key={level} type="button" className={`button small journal-priority-${level}`} disabled={count === 0} aria-pressed={priority === level} onClick={() => setPriority(level)}>{level} · {c.levels[level]} ({count})</button>)}
        </fieldset>
        <div className="journal-triage-controls"><label>{c.view}<select value={grouped ? 'groups' : 'rows'} onChange={event => setGrouped(event.target.value === 'groups')}><option value="rows">{c.rows}</option><option value="groups">{c.groups}</option></select></label><label>{c.order}<select value={order} onChange={event => setOrder(event.target.value as JournalPageOrder)}><option value="source">{c.source}</option><option value="oldest">{c.oldest}</option><option value="newest">{c.newest}</option></select></label></div>
        <p className="journal-triage-summary" role="status">{rows.length} {c.shown} {c.of} {page.rows.length} {c.page}{grouped && ` · ${groups.length} ${c.matches}`}</p>
        {grouped && <p className="journal-muted">{c.equality}</p>}
        {rows.length === 0 ? <p>{c.empty}</p> : grouped ? <ul className="journal-message-groups">{groups.map(group => <li key={group.key}>
            <div className="journal-message-group-heading"><strong>{group.rows.length} {c.count}</strong><span className={`journal-priority journal-priority-${group.first.row.priority}`}>{group.first.row.priority} · {c.levels[group.first.row.priority]}</span></div>
            <p className="journal-message"><JournalHighlight text={group.first.row.message} search={search}/></p>
            <dl><div><dt>{c.first}</dt><dd><Timestamp value={group.first.row.timestamp}/></dd></div><div><dt>{c.last}</dt><dd><Timestamp value={group.last.row.timestamp}/></dd></div></dl>
            <details><summary>{c.occurrences} ({group.rows.length})</summary><ol>{group.rows.map(value => <li key={value.index}><span>{c.row} {page.offset + value.index + 1}</span><Timestamp value={value.row.timestamp} zone/></li>)}</ol></details>
        </li>)}</ul> : <div className="journal-table-wrap"><table className="journal-table" role="table" aria-describedby={`${id}-scope`}><thead role="rowgroup"><tr role="row"><th role="columnheader" scope="col">{c.time}</th><th role="columnheader" scope="col">{c.level}</th><th role="columnheader" scope="col">{c.message}</th></tr></thead><tbody role="rowgroup">{rows.map(value => <tr role="row" key={value.index}><td role="cell"><Timestamp value={value.row.timestamp}/></td><td role="cell"><span className={`journal-priority journal-priority-${value.row.priority}`}>{value.row.priority} · {c.levels[value.row.priority]}</span></td><td role="cell" className="journal-message"><JournalHighlight text={value.row.message} search={search}/></td></tr>)}</tbody></table></div>}
    </section>;
}
