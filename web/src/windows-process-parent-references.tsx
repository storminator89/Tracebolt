import { useState } from 'react';
import { GitFork } from 'lucide-react';
import { FULL_PROCESSES_PAGE_ROWS } from './windows-full-processes-types';
import type { FullProcessesPage, FullProcessesRow } from './windows-full-processes-types';
import './windows-process-parent-references.css';

/** Equal captured values, never a claim of process ancestry or live identity. */
export function sharedParentReferences(rows: readonly FullProcessesRow[]) {
    const groups = new Map<number, FullProcessesRow[]>();
    for (const row of rows) {
        const group = groups.get(row.parentPid);
        if (group) group.push(row);
        else groups.set(row.parentPid, [row]);
    }
    return [...groups].filter(([, members]) => members.length > 1);
}

const copy = {
    en: {
        title: 'Shared parent PID references', page: 'Loaded page only',
        scope: 'Rows reporting the same parent PID on this page. Search and paging may split groups.',
        caution: 'Snapshot values, not a verified process tree. PIDs can be reused; a matching PID does not prove a live parent.',
        empty: 'No shared parent PID on this page.', parent: 'Reported parent PID', rows: 'Rows on page',
        pid: 'Snapshot PID', threads: 'Threads', unavailable: 'Name unavailable',
    },
    de: {
        title: 'Gemeinsame Eltern-PID-Verweise', page: 'Nur geladene Seite',
        scope: 'Zeilen mit gleicher gemeldeter Eltern-PID auf dieser Seite. Suche und Seitenwechsel können Gruppen aufteilen.',
        caution: 'Snapshot-Werte, kein bestätigter Prozessbaum. PIDs können erneut vergeben werden; eine passende PID belegt keinen laufenden Elternprozess.',
        empty: 'Keine gemeinsame Eltern-PID auf dieser Seite.', parent: 'Gemeldete Eltern-PID', rows: 'Zeilen auf Seite',
        pid: 'Snapshot-PID', threads: 'Threads', unavailable: 'Name nicht verfügbar',
    },
};

/** The existing complete-inventory owner admits and expires this one page.
 * No preview/metrics join, cross-page accumulation, request or retained rows. */
export function WindowsProcessParentReferences({ page, locale }: { page: FullProcessesPage; locale: 'en' | 'de' }) {
    if (page.status !== 'ready' || !page.complete || !page.rows.length || page.rows.length > FULL_PROCESSES_PAGE_ROWS) return null;
    const identity = JSON.stringify([page.deviceId, page.complete, page.authorityUntil, page.cursorExpiresAt, page.search, page.sort, page.limit, page.offset, page.rows]);
    return <ParentReferences key={identity} rows={page.rows} locale={locale}/>;
}

function ParentReferences({ rows, locale }: { rows: FullProcessesRow[]; locale: 'en' | 'de' }) {
    const [open, setOpen] = useState(false), c = copy[locale], groups = sharedParentReferences(rows);
    return <details className="windows-process-parent-references" onToggle={event => setOpen(event.currentTarget.open)}>
        <summary><GitFork size={16} aria-hidden="true" focusable="false"/> <strong>{c.title}</strong><span>{c.page}</span></summary>
        {open && <div className="windows-process-parent-content">
            <p>{c.scope}</p><p>{c.caution}</p>
            {!groups.length ? <p>{c.empty}</p> : <ul className="windows-process-parent-groups">{groups.map(([parentPid, members]) => <li key={parentPid}>
                <details className="windows-process-parent-group">
                    <summary><span>{c.parent}: <strong>{parentPid}</strong></span><span>{c.rows}: <strong>{members.length}</strong></span></summary>
                    <ul className="windows-process-parent-rows">{members.map(row => <li key={row.pid}>
                        <strong className="windows-process-parent-name">{row.name === null ? <span className="windows-full-processes-missing">{c.unavailable}</span> : row.name}</strong>
                        <dl><div><dt>{c.pid}</dt><dd>{row.pid}</dd></div><div><dt>{c.threads}</dt><dd>{row.threads}</dd></div></dl>
                    </li>)}</ul>
                </details>
            </li>)}</ul>}
        </div>}
    </details>;
}
