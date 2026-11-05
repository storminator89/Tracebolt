import type { WindowsPatchHistoryRow } from './windows-patch-context-types';

export const PATCH_HISTORY_PAGE_SIZE = 20;
export interface PatchHistoryFilters {
    query: string;
    result: 'all' | WindowsPatchHistoryRow['result'];
    operation: 'all' | WindowsPatchHistoryRow['operation'];
    from: string;
    through: string;
    order: 'newest' | 'oldest';
    page: number;
}
export const initialPatchHistoryFilters = (): PatchHistoryFilters => ({ query: '', result: 'all', operation: 'all', from: '', through: '', order: 'newest', page: 0 });

function validDay(day: string): boolean {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(day) || day < '1970-01-01') return false;
    const ms = Date.parse(`${day}T00:00:00Z`);
    return Number.isFinite(ms) && new Date(ms).toISOString().slice(0, 10) === day;
}

/** Filter only the already validated, bounded snapshot. No collection, joins,
 * deduplication, source-clock change or current installation claim. */
export function patchHistoryPage(rows: readonly WindowsPatchHistoryRow[], filters: PatchHistoryFilters) {
    const invalidDates = Boolean(filters.from && !validDay(filters.from) || filters.through && !validDay(filters.through) || filters.from && filters.through && filters.from > filters.through);
    const query = filters.query.trim().toLowerCase();
    const code = /^0x[0-9a-f]{8}$/.test(query) ? query.slice(2) : query;
    const matches = invalidDates ? [] : rows.filter(row => {
        const day = row.occurredAt.slice(0, 10);
        return (filters.result === 'all' || row.result === filters.result)
            && (filters.operation === 'all' || row.operation === filters.operation)
            && (!filters.from || day >= filters.from) && (!filters.through || day <= filters.through)
            && (!query || row.title.toLowerCase().includes(query) || row.updateId.includes(query) || row.hresult.includes(code));
    }).sort((a, b) => filters.order === 'oldest' ? b.index - a.index : a.index - b.index);
    // Source indexes retain WUA ordering, including equal-time duplicate events.
    const pages = Math.max(1, Math.ceil(matches.length / PATCH_HISTORY_PAGE_SIZE));
    const page = Math.max(0, Math.min(Number.isSafeInteger(filters.page) ? filters.page : 0, pages - 1));
    const start = page * PATCH_HISTORY_PAGE_SIZE;
    return { rows: matches.slice(start, start + PATCH_HISTORY_PAGE_SIZE), total: matches.length, page, pages, start, invalidDates };
}
