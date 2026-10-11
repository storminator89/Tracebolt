import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { renderToStaticMarkup } from 'react-dom/server';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import interop from './windows-full-services-interop-fixtures.json';
import { abortProtectedRequests } from './api';
import { useOperator } from './auth';
import { setLocale } from './i18n';
import { WindowsFullServiceTable, WindowsFullServicesPanel } from './windows-full-services';
import { validFullServicesPage } from './windows-full-services-types';
import type { FullServicesPage, FullServicesQuery } from './windows-full-services-types';
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
const find = (name: string) => interop.find(v => v.name === name)!;
const reply = (body: unknown) => new Response(JSON.stringify(body));
// A real handler stamps its trusted current time on every response; keep the
// exported source/receipt/cursor times immutable while avoiding a replayed clock.
const clocked = (page: typeof interop[number]['page'], began: number) => ({ ...page, serverNow: new Date(Date.parse(page.serverNow) + Date.now() - began).toISOString() });
beforeEach(() => { setLocale('en', false); vi.mocked(useOperator).mockReturnValue({ mode: 'lan', authenticated: true, expiresAt: 'synthetic-session', insecureTestMode: false, logout: vi.fn(), theme: 'light', setTheme: vi.fn() }); });
afterEach(() => { cleanup(); abortProtectedRequests(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe('real SQLite-backed Go page to protected UI interoperability', () => {
    it.each(['en', 'de'] as const)('reads an actual 2051-row ledger and finds its later Unicode service in %s', async locale => {
        setLocale(locale, false); const began = Date.now(); const first = find('first2051'), later = find('unicode2049'), sent: FullServicesQuery[] = [];
        vi.stubGlobal('fetch', vi.fn(async (path: string, options?: RequestInit) => {
            if (path === '/api/session') return reply({ csrfToken: 'synthetic-csrf' });
            const query = JSON.parse(options!.body as string) as FullServicesQuery; sent.push(query);
            expect(path).toBe(`/api/devices/${first.page.deviceId}/windows-full-services/query`);
            const vector = query.search ? later : first; expect(query).toEqual(vector.query); return reply(clocked(vector.page, began));
        }));
        render(<WindowsFullServicesPanel deviceId={first.page.deviceId} sessionKey="fixture"/>); await screen.findByText('InventedService00000'); expect(document.querySelectorAll('tbody tr')).toHaveLength(100);
        expect(screen.getByText(locale === 'en' ? 'Captured rows' : 'Erfasste Zeilen').nextElementSibling).toHaveTextContent('2051');
        fireEvent.change(screen.getByRole('searchbox'), { target: { value: later.query.search } }); fireEvent.click(screen.getByRole('button', { name: locale === 'en' ? 'Apply search and sort' : 'Suche und Sortierung anwenden' }));
        await screen.findByText('InventedService02049'); expect(document.querySelectorAll('tbody tr')).toHaveLength(1); expect(sent).toHaveLength(2); expect(screen.getByText(locale === 'en' ? 'Matching rows in the whole generation' : 'Treffer in der gesamten Generation').nextElementSibling).toHaveTextContent('1');
    });
    it('follows the actual authenticated byte-short cursor from 77 to the final51 rows', async () => {
        const began = Date.now(); const first = find('byteShort'), next = find('byteShortContinuation'), sent: FullServicesQuery[] = [];
        vi.stubGlobal('fetch', vi.fn(async (path: string, options?: RequestInit) => {
            if (path === '/api/session') return reply({ csrfToken: 'synthetic-csrf' });
            const query = JSON.parse(options!.body as string) as FullServicesQuery; sent.push(query); const vector = query.cursor ? next : first; expect(query).toEqual(vector.query); return reply(clocked(vector.page, began));
        }));
        render(<WindowsFullServicesPanel deviceId={first.page.deviceId} sessionKey="fixture"/>); await screen.findByRole('table'); expect(document.querySelectorAll('tbody tr')).toHaveLength(77);
        fireEvent.click(screen.getByRole('button', { name: 'Next service page' })); await waitFor(() => expect(document.querySelectorAll('tbody tr')).toHaveLength(51)); expect(screen.getByRole('button', { name: 'Next service page' })).toBeDisabled(); expect(sent[1].cursor).toBe(first.page.nextCursor); expect(document.querySelector('img')).toBeNull();
    });
    it('renders validated actual offset700 without accumulating earlier rows or sorting at render', () => {
        const vector = find('offset700'), page = structuredClone(vector.page) as FullServicesPage;
        expect(validFullServicesPage(page, page.deviceId, vector.query as FullServicesQuery, 700)).toBe(true); const sort = vi.spyOn(page.rows, 'sort');
        const ui = render(<WindowsFullServiceTable page={page} locale="en"/>); expect(document.querySelectorAll('tbody tr')).toHaveLength(100); expect(screen.getByText('InventedService00700')).toBeVisible(); expect(screen.queryByText('InventedService00000')).toBeNull();
        ui.rerender(<WindowsFullServiceTable page={page} locale="de"/>); expect(screen.getByRole('columnheader', { name: 'Dienstname' })).toBeVisible(); expect(sort).not.toHaveBeenCalled();
    });
    it('bounds repeated validation/render work to one100-row page and records a fixture timing', () => {
        const vector = find('offset700'), page = vector.page as FullServicesPage, samples: number[] = [];
        for (let round = 0; round < 3; round++) {
            const started = performance.now();
            for (let i = 0; i < 20; i++) { expect(validFullServicesPage(page, page.deviceId, vector.query as FullServicesQuery, 700)).toBe(true); const html = renderToStaticMarkup(<WindowsFullServiceTable page={page} locale={i % 2 ? 'de' : 'en'}/>); expect((html.match(/<tr>/g) ?? []).length).toBe(101); }
            samples.push(performance.now() - started);
        }
        expect(Math.max(...samples)).toBeLessThan(5000);
        console.info(`Full-services fixture: 20 validations plus100-row SSR renders per round: ${samples.map(n => n.toFixed(1)).join(', ')} ms. Not a native browser benchmark.`);
    });
});
