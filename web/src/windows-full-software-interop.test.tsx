import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { renderToStaticMarkup } from 'react-dom/server';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import interop from './windows-full-software-store-fixture.json';
import { abortProtectedRequests } from './api';
import { useOperator } from './auth';
import { setLocale } from './i18n';
import { WindowsFullSoftwareTable, WindowsFullSoftwarePanel } from './windows-full-software';
import { validFullSoftwarePage } from './windows-full-software-types';
import type { FullSoftwarePage, FullSoftwareQuery } from './windows-full-software-types';
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
const find = (name: string) => interop.find(v => v.name === name)!;
const reply = (body: unknown) => new Response(JSON.stringify(body));
// Only trusted response time advances. Source, receipt and cursor ages stay exact.
const clocked = (page: typeof interop[number]['page'], began: number) => ({ ...page, serverNow: new Date(Date.parse(page.serverNow) + Date.now() - began).toISOString() });
beforeEach(() => { setLocale('en', false); vi.mocked(useOperator).mockReturnValue({ mode: 'lan', authenticated: true, expiresAt: 'synthetic-session', insecureTestMode: false, logout: vi.fn(), theme: 'light', setTheme: vi.fn() }); });
afterEach(() => { cleanup(); abortProtectedRequests(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe('actual SQLite software pages through protected UI', () => {
    it.each(['en', 'de'] as const)('searches beyond page700 in a 2051-registration generation (%s)', async locale => {
        setLocale(locale, false); const began = Date.now(), first = find('first2051'), later = find('unicode2049'), sent: FullSoftwareQuery[] = [];
        vi.stubGlobal('fetch', vi.fn(async (path: string, options?: RequestInit) => {
            if (path === '/api/session') return reply({ csrfToken: 'synthetic-csrf' });
            const query = JSON.parse(options!.body as string) as FullSoftwareQuery; sent.push(query);
            expect(path).toBe(`/api/devices/${first.page.deviceId}/windows-full-software/query`);
            const vector = query.search ? later : first; expect(query).toEqual(vector.query); return reply(clocked(vector.page, began));
        }));
        render(<WindowsFullSoftwarePanel deviceId={first.page.deviceId} sessionKey="fixture"/>); await screen.findByText('InventedSoftware00000'); expect(document.querySelectorAll('tbody tr')).toHaveLength(100);
        expect(screen.getByText(locale === 'en' ? 'Captured' : 'Erfasst').nextElementSibling).toHaveTextContent('2051');
        fireEvent.change(screen.getByRole('searchbox'), { target: { value: later.query.search } }); fireEvent.click(screen.getByRole('button', { name: locale === 'en' ? 'Apply' : 'Anwenden' }));
        await screen.findByText('InventedSoftware02049'); expect(document.querySelectorAll('tbody tr')).toHaveLength(1); expect(sent).toHaveLength(2); expect(screen.getByText(locale === 'en' ? 'Matching' : 'Treffer').nextElementSibling).toHaveTextContent('1');
        expect(document.querySelector('.windows-full-software-details')).not.toHaveAttribute('open');
        expect(screen.getByText(locale === 'en' ? /All caller-visible machine/ : /Alle für den Dienst/)).not.toBeVisible();
    });
    it('follows the exact byte-short cursor without pooling earlier rows', async () => {
        const began = Date.now(), first = find('byteShort'), next = find('byteShortContinuation'), sent: FullSoftwareQuery[] = [];
        vi.stubGlobal('fetch', vi.fn(async (path: string, options?: RequestInit) => {
            if (path === '/api/session') return reply({ csrfToken: 'synthetic-csrf' });
            const query = JSON.parse(options!.body as string) as FullSoftwareQuery; sent.push(query); const vector = query.cursor ? next : first; expect(query).toEqual(vector.query); return reply(clocked(vector.page, began));
        }));
        render(<WindowsFullSoftwarePanel deviceId={first.page.deviceId} sessionKey="fixture"/>); await screen.findByRole('table'); expect(document.querySelectorAll('tbody tr')).toHaveLength(26);
        fireEvent.click(screen.getByRole('button', { name: 'Next software page' })); await waitFor(() => expect(document.querySelector('tbody tr')).toHaveAttribute('data-registration-id', next.page.rows[0].registrationId));
        expect(document.querySelectorAll('tbody tr')).toHaveLength(26); expect(screen.getByRole('button', { name: 'Next software page' })).not.toBeDisabled(); expect(sent[1].cursor).toBe(first.page.nextCursor); expect(document.querySelector('img')).toBeNull();
    });
    it.each(['en', 'de'] as const)('retains duplicate registrations and distinguishes unavailable from observed empty (%s)', locale => {
        const page = find('duplicatesMissing').page as FullSoftwarePage;
        render(<WindowsFullSoftwareTable page={page} locale={locale}/>);
        expect(document.querySelectorAll('tbody tr')).toHaveLength(4);
        expect(new Set(Array.from(document.querySelectorAll('tbody tr')).map(row => row.getAttribute('data-registration-id'))).size).toBe(4);
        expect(screen.getAllByText(locale === 'en' ? 'Unavailable' : 'Nicht verfügbar')).toHaveLength(3);
        expect(screen.getAllByText(locale === 'en' ? 'Empty value' : 'Leerer Wert')).toHaveLength(3);
        expect(screen.getAllByText('HKLM 32').length).toBeGreaterThan(0); expect(screen.getAllByText('HKLM 64').length).toBeGreaterThan(0);
    });
    it('renders exact offset700 without client sorting and bounds repeated work to one100-row page', () => {
        const vector = find('offset700'), page = structuredClone(vector.page) as FullSoftwarePage, sort = vi.spyOn(page.rows, 'sort');
        expect(validFullSoftwarePage(page, page.deviceId, vector.query as FullSoftwareQuery, 700)).toBe(true);
        render(<WindowsFullSoftwareTable page={page} locale="en"/>); expect(document.querySelectorAll('tbody tr')).toHaveLength(100); expect(screen.getByText('InventedSoftware00700')).toBeVisible(); expect(screen.queryByText('InventedSoftware00000')).toBeNull();
        const started = performance.now();
        for (let i = 0; i < 20; i++) { expect(validFullSoftwarePage(page, page.deviceId, vector.query as FullSoftwareQuery, 700)).toBe(true); expect((renderToStaticMarkup(<WindowsFullSoftwareTable page={page} locale={i % 2 ? 'de' : 'en'}/>).match(/<tr(?:>| )/g) ?? []).length).toBe(101); }
        expect(performance.now() - started).toBeLessThan(5000); expect(sort).not.toHaveBeenCalled();
    });
});
