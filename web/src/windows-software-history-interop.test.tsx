import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import vectors from './windows-software-history-go-fixture.json';
import { WindowsSoftwareHistoryTable } from './windows-software-history';
import { sameSoftwareHistory, validSoftwareHistoryPage } from './windows-software-history-types';
import type { SoftwareHistoryPage, SoftwareHistoryQuery } from './windows-software-history-types';

describe('actual Go SQLite software history vectors', () => {
    it.each(vectors)('validates $name without changing its private paging or original observation timestamps', vector => {
        expect(validSoftwareHistoryPage(vector.page, vector.page.deviceId, vector.query as SoftwareHistoryQuery, vector.page.offset)).toBe(true);
    });
    it.each(['en', 'de'] as const)('renders exact observed before/after values from the Go page (%s)', locale => {
        const page = vectors.find(v => v.name === 'observedChanges')!.page as SoftwareHistoryPage;
        const html = renderToStaticMarkup(<WindowsSoftwareHistoryTable page={page} locale={locale}/>);
        expect((html.match(/<tr(?:>| )/g) ?? []).length).toBe(page.rows.length + 1);
        for (const row of page.rows) { expect(html).toContain(row.id); expect(html).toContain(row.beforeObservedAt); expect(html).toContain(row.afterObservedAt); }
        expect(html).not.toContain('<details open');
    });
    it('binds continuation summary counts to the same digest while allowing a separate latest attempt', () => {
        const first = vectors.find(v => v.name === 'firstPage')!.page as SoftwareHistoryPage, next = vectors.find(v => v.name === 'continuation')!.page as SoftwareHistoryPage;
        expect(first.nextCursor).toBe(vectors.find(v => v.name === 'continuation')!.query.cursor); expect(sameSoftwareHistory(first, next)).toBe(true);
        expect(sameSoftwareHistory(first, { ...next, omittedChanges: next.omittedChanges + 1 })).toBe(false);
    });
});
