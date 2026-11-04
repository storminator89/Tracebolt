import type { JournalPage, JournalRow } from './journal-types';

export type JournalPageOrder = 'source' | 'oldest' | 'newest';
export interface JournalPageRow { row: JournalRow; index: number }
export interface JournalMessageGroup { key: string; rows: JournalPageRow[]; first: JournalPageRow; last: JournalPageRow }

// Accepted journal timestamps are UTC RFC3339 with up to nine fractional digits.
// Date.parse alone would discard the sub-millisecond ordering.
export function compareJournalTimestamp(a: string, b: string): number {
    const exact = (value: string) => value.slice(0, 19) + (value.includes('.') ? value.slice(20, -1) : '').padEnd(9, '0');
    const left = exact(a), right = exact(b);
    return left < right ? -1 : left > right ? 1 : 0;
}

export function journalPageRows(rows: JournalRow[], priority: number | null, order: JournalPageOrder): JournalPageRow[] {
    const result = rows.map((row, index) => ({ row, index })).filter(value => priority === null || value.row.priority === priority);
    if (order !== 'source') result.sort((a, b) => (order === 'newest' ? -1 : 1) * compareJournalTimestamp(a.row.timestamp, b.row.timestamp) || a.index - b.index);
    return result;
}

// Equality applies to the already-masked display projection only. It is neither
// source-event identity nor evidence about undisplayed/source journal rows.
export function journalMessageGroups(rows: JournalPageRow[]): JournalMessageGroup[] {
    const groups = new Map<string, JournalMessageGroup>();
    for (const value of rows) {
        const key = JSON.stringify([value.row.unit, value.row.priority, value.row.message]);
        const group = groups.get(key);
        if (!group) groups.set(key, { key, rows: [value], first: value, last: value });
        else {
            group.rows.push(value);
            if (compareJournalTimestamp(value.row.timestamp, group.first.row.timestamp) < 0) group.first = value;
            if (compareJournalTimestamp(value.row.timestamp, group.last.row.timestamp) > 0) group.last = value;
        }
    }
    return [...groups.values()];
}

export function journalTriageBinding(page: JournalPage, sessionKey: string | null): string {
    return JSON.stringify([sessionKey, page.deviceId, page.schemaVersion, page.identity.id, page.identity.sequence,
        page.identity.queryDigest, page.snapshotDigest, page.offset, page.search]);
}
