import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import vectors from './windows-full-processes-store-fixture.json';
import { abortProtectedRequests } from './api';
import { useOperator } from './auth';
import { setLocale } from './i18n';
import { WindowsFullProcessesPanel, WindowsFullProcessesTable } from './windows-full-processes';
import { validFullProcessesPage } from './windows-full-processes-types';
import type { FullProcessesPage, FullProcessesQuery } from './windows-full-processes-types';
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
const find = (name: string) => vectors.find(value => value.name === name)!;
const reply = (value: unknown) => new Response(JSON.stringify(value));
const clocked = (page: typeof vectors[number]['page'], began: number) => ({ ...page, serverNow: new Date(Date.parse(page.serverNow) + Date.now() - began).toISOString() });
beforeEach(() => { vi.mocked(useOperator).mockReturnValue({ mode: 'lan', authenticated: true, expiresAt: 'fixture', insecureTestMode: false, logout: vi.fn(), theme: 'light', setTheme: vi.fn() }); });
afterEach(() => { cleanup(); abortProtectedRequests(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });
describe('actual Go SQLite process-page interoperability', () => {
    it.each(['en', 'de'] as const)('browses, returns and searches beyond the old 128-row preview (%s)', async locale => {
        setLocale(locale, false); const began = Date.now(), first = find('first2051'), next = find('second100'), later = find('search2049'), sent: FullProcessesQuery[] = [];
        vi.stubGlobal('fetch', vi.fn(async (path: string, options?: RequestInit) => {
            if (path === '/api/session') return reply({ csrfToken: 'fixture' });
            const query = JSON.parse(options!.body as string) as FullProcessesQuery; sent.push(query);
            expect(path).toBe(`/api/devices/${first.page.deviceId}/windows-full-processes/query`);
            const value = query.search ? later : query.cursor ? next : first; expect(query).toEqual(value.query); return reply(clocked(value.page, began));
        }));
        render(<WindowsFullProcessesPanel deviceId={first.page.deviceId} sessionKey="fixture"/>); await screen.findByText('InventedProcess00000'); expect(document.querySelectorAll('tbody tr')).toHaveLength(100);
        fireEvent.click(screen.getByRole('button', { name: locale === 'en' ? 'Next process page' : 'Nächste Prozessseite' })); await screen.findByText('InventedProcess00100'); expect(sent.at(-1)?.cursor).toBe(first.page.nextCursor);
        fireEvent.click(screen.getByRole('button', { name: locale === 'en' ? 'Previous process page' : 'Vorherige Prozessseite' })); await screen.findByText('InventedProcess00000');
        fireEvent.change(screen.getByRole('searchbox'), { target: { value: later.query.search } }); fireEvent.click(screen.getByRole('button', { name: locale === 'en' ? 'Apply' : 'Anwenden' })); await screen.findByText('InventedProcess02049'); await waitFor(() => expect(document.querySelectorAll('tbody tr')).toHaveLength(1));
        expect(document.querySelector('.windows-full-processes-details')).not.toHaveAttribute('open'); expect(sent.at(-1)?.cursor).toBe('');
    });
    it('renders PID zero and unavailable names without inventing measurements or parent relationships', () => {
        render(<WindowsFullProcessesTable page={find('duplicateNamesUnavailableZero').page as FullProcessesPage} locale="en"/>);
        expect(document.querySelector('tr[data-snapshot-pid="0"]')).toHaveTextContent('Unavailable'); expect(screen.getAllByRole('columnheader').map(value => value.textContent)).toEqual(['Name', 'Snapshot PID', 'Snapshot parent PID', 'Threads']);
    });
    it('validates and renders only the returned bounded page without client-side full sorting', () => {
        const vector = find('offset700'), page = structuredClone(vector.page) as FullProcessesPage, sort = vi.spyOn(page.rows, 'sort');
        expect(validFullProcessesPage(page, page.deviceId, vector.query as FullProcessesQuery, 700)).toBe(true);
        render(<WindowsFullProcessesTable page={page} locale="en"/>); expect(document.querySelectorAll('tbody tr')).toHaveLength(100); expect(screen.getByText('InventedProcess00700')).toBeVisible(); expect(screen.queryByText('InventedProcess00000')).toBeNull();
        for (let i = 0; i < 10; i++) expect((renderToStaticMarkup(<WindowsFullProcessesTable page={page} locale={i % 2 ? 'de' : 'en'}/>).match(/<tr(?:>| )/g) ?? []).length).toBe(101);
        expect(sort).not.toHaveBeenCalled();
    });
});
