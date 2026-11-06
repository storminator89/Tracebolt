import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { useOperator } from './auth';
import { abortProtectedRequests, AUTH_REQUIRED_EVENT } from './api';
import { setLocale } from './i18n';
import { WindowsFullSoftwarePanel } from './windows-full-software';
import { softwareVersionGroups, WindowsSoftwareVersionGroups } from './windows-software-version-groups';
import { fullSoftwareComplete, fullSoftwareDevice, fullSoftwarePage, fullSoftwareQuery, replaceFullSoftwareGeneration } from './windows-full-software-fixtures';
import type { FullSoftwareQuery, FullSoftwareRow } from './windows-full-software-types';

vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
function row(n: number, changes: Partial<FullSoftwareRow> = {}): FullSoftwareRow {
    return { registrationId: n.toString(16).padStart(64, '0'), registryView: '64', name: 'Example', nameQuality: 'observed', publisher: 'Maker', publisherQuality: 'observed', version: '2.0', versionQuality: 'observed', ...changes };
}
const rows = () => [row(1), row(2, { registryView: '32' }), row(3, { version: '10.0' }), row(4, { version: '' }), row(5, { version: null, versionQuality: 'unavailable' }), row(6, { publisher: 'Other' })];
function page(input = rows(), query = fullSoftwareQuery, offset = 0) { const complete = fullSoftwareComplete(); replaceFullSoftwareGeneration(complete, input); return fullSoftwarePage(query, input, complete, offset); }
const ui = (value = page(), locale: 'en' | 'de' = 'en') => <WindowsSoftwareVersionGroups page={value} locale={locale}/>;
const summary = (locale: 'en' | 'de' = 'en') => screen.getByText(locale === 'en' ? 'Version groups' : 'Versionsgruppen').closest('summary')!;
async function expand(locale: 'en' | 'de' = 'en') { fireEvent.click(summary(locale)); await waitFor(() => expect(document.querySelector('.software-version-content')).not.toBeNull()); }
const response = (body: unknown) => new Response(JSON.stringify(body));
async function flush() { await act(async () => { for (let i = 0; i < 15; i++) await Promise.resolve(); }); }
beforeEach(() => {
    setLocale('en', false);
    vi.mocked(useOperator).mockReturnValue({ mode: 'lan', authenticated: true, expiresAt: 'session', insecureTestMode: false, logout: vi.fn(), theme: 'light', setTheme: vi.fn() });
});
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe('exact loaded-page version groups', () => {
    it('groups exact observed labels with stable source order, separate empty/unknown versions and no mutation', () => {
        const input = rows(), original = JSON.stringify(input), groups = softwareVersionGroups(input);
        expect(groups).toHaveLength(1); expect(groups[0].rows.map(r => r.registrationId)).toEqual(input.slice(0, 5).map(r => r.registrationId));
        expect(groups[0].versions.map(v => [v.value, v.rows.length])).toEqual([['2.0', 2], ['10.0', 1], ['', 1], [null, 1]]);
        expect(groups[0].versions[0].rows.map(r => r.registryView)).toEqual(['64', '32']); expect(JSON.stringify(input)).toBe(original);
    });
    it('never normalizes case, whitespace, Unicode, delimiters, missing labels or prototype-looking names', () => {
        const pairs = [['Example', 'Maker'], ['example', 'Maker'], ['Example ', 'Maker'], ['Example', 'maker'], ['é', 'Maker'], ['e\u0301', 'Maker'], ['a,b', 'c'], ['a', 'b,c'], ['__proto__', 'constructor']];
        const input = pairs.flatMap(([name, publisher], index) => [row(2 * index + 1, { name, publisher }), row(2 * index + 2, { name, publisher })]);
        input.push(row(100, { name: '' }), row(101, { name: '' }), row(102, { publisher: null, publisherQuality: 'unavailable' }), row(103, { publisher: null, publisherQuality: 'unavailable' }), row(104, { publisher: '' }), row(105, { name: null, nameQuality: 'unavailable' }));
        expect(softwareVersionGroups(input).map(g => [g.name, g.publisher, g.rows.length])).toEqual(pairs.map(p => [...p, 2]));
    });
    it.each(['en', 'de'] as const)('shows page scope, counts, original IDs/views and text equivalents for every bar (%s)', async locale => {
        const fetch = vi.fn(), writes = vi.spyOn(Storage.prototype, 'setItem'); vi.stubGlobal('fetch', fetch); render(ui(page(), locale));
        expect(document.querySelector('.software-version-content')).toBeNull(); await expand(locale);
        expect(document.querySelector('.software-version-counts')).toHaveTextContent('5 / 6');
        expect(document.querySelector('.software-version-heading')).toHaveTextContent(locale === 'en' ? 'Reported nonempty versions: 2' : 'Gemeldete nicht leere Versionen: 2');
        expect(document.querySelector('.software-version-content')).toHaveTextContent(locale === 'en' ? 'Matching labels do not prove' : 'Gleiche Angaben belegen weder');
        const variants = document.querySelectorAll('.software-version-variants > li'); expect(variants).toHaveLength(4);
        expect([...variants].map(v => v.querySelector('.software-version-variant')!.textContent)).toEqual(locale === 'en' ? ['2.0Registrations: 2', '10.0Registrations: 1', 'Empty reported versionRegistrations: 1', 'Version unavailableRegistrations: 1'] : ['2.0Registrierungen: 2', '10.0Registrierungen: 1', 'Leer gemeldete VersionRegistrierungen: 1', 'Version nicht verfügbarRegistrierungen: 1']);
        expect([...document.querySelectorAll('.software-version-bar > span')].map(v => (v as HTMLElement).style.width).sort()).toEqual(['20%', '20%', '20%', '40%']);
        expect(document.querySelectorAll('.software-version-bar[aria-hidden="true"]')).toHaveLength(4);
        const repeated = [...variants].find(v => v.textContent!.includes(row(1).registrationId))!;
        fireEvent.click(repeated.querySelector('summary')!); expect(repeated.querySelector('details')).toHaveAttribute('open');
        expect(within(repeated as HTMLElement).getByText(row(1).registrationId)).toBeVisible(); expect(repeated).toHaveTextContent('HKLM 32'); expect(repeated).toHaveTextContent('HKLM 64');
        expect(fetch).not.toHaveBeenCalled(); expect(writes).not.toHaveBeenCalled();
        summary(locale).focus(); fireEvent.click(summary(locale)); await waitFor(() => expect(document.querySelector('.software-version-content')).toBeNull()); expect(summary(locale)).toHaveFocus();
        await expand(locale); expect(document.querySelector('.software-version-variants details')).not.toHaveAttribute('open');
    });
    it('escapes names, publishers and versions and never creates links or executable content', async () => {
        render(ui(page([row(1, { name: '<img src=x onerror=bad()>', publisher: '<script>bad()</script>', version: '<svg onload=bad()>' }), row(2, { name: '<img src=x onerror=bad()>', publisher: '<script>bad()</script>', version: '<svg onload=bad()>' })]))); await expand();
        expect(screen.getByText('<img src=x onerror=bad()>')).toBeVisible(); expect(screen.getByText('<svg onload=bad()>')).toBeVisible();
        expect(document.querySelector('.software-version-groups img, .software-version-groups script, .software-version-groups a')).toBeNull();
    });
    it('explains no repeated group without claiming uniform or missing software', async () => {
        render(ui(page([row(1), row(2, { name: 'Other' })]))); await expand(); expect(screen.getByText(/No repeated nonempty name/)).toBeVisible(); expect(document.querySelector('.software-version-counts')).toBeNull();
    });
    it.each(['page', 'query', 'sort', 'generation', 'grant', 'device', 'rows'] as const)('closes disclosures on %s replacement', async change => {
        const first = page(), mounted = render(ui(first)); await expand(); const next = structuredClone(first);
        if (change === 'page') next.offset = 100;
        if (change === 'query') next.search = 'Example';
        if (change === 'sort') next.sort = 'version-desc';
        if (change === 'generation') next.complete!.manifest.generationId = 'replacement';
        if (change === 'grant') next.grantRevision!++;
        if (change === 'device') next.deviceId = 'replacement';
        if (change === 'rows') next.rows[0].version = 'replacement';
        mounted.rerender(ui(next)); expect(summary().closest('details')).not.toHaveAttribute('open'); expect(document.querySelector('.software-version-content')).toBeNull();
    });
    it('keeps opened evidence during locale change but omits empty or unavailable pages', async () => {
        const first = page(), mounted = render(ui(first)); await expand(); mounted.rerender(ui(first, 'de')); expect(summary('de').closest('details')).toHaveAttribute('open');
        mounted.rerender(ui({ ...first, status: 'disabled' })); expect(document.querySelector('.software-version-groups')).toBeNull(); mounted.rerender(ui({ ...first, rows: [] })); expect(document.querySelector('.software-version-groups')).toBeNull();
    });
});

function server(sourceRows = rows()) {
    const requests: FullSoftwareQuery[] = [];
    const fetch = vi.fn(async (url: string, options?: RequestInit) => {
        if (url === '/api/session') return response({ csrfToken: 'fixture-csrf' });
        const query = JSON.parse(options!.body as string) as FullSoftwareQuery; requests.push(query);
        return response(page(sourceRows, query, query.cursor ? 100 : 0));
    }); vi.stubGlobal('fetch', fetch); return { fetch, requests };
}
const panel = (sessionKey = 'a', enabled = true, deviceId = fullSoftwareDevice) => <WindowsFullSoftwarePanel deviceId={deviceId} sessionKey={sessionKey} enabled={enabled}/>;

describe('version-group private-reader integration', () => {
    it('does not change table order, search totals, paging or make reads when inspecting groups', async () => {
        const input = Array.from({ length: 102 }, (_, i) => row(i + 1, { version: i % 2 ? '2' : '10' })), api = server(input); render(panel()); await screen.findByRole('table');
        const original = screen.getByRole('table').textContent; await expand(); expect(screen.getByRole('table').textContent).toBe(original); expect(screen.getByText('1–100 of 102')).toBeVisible(); expect(api.requests).toHaveLength(1);
        fireEvent.click(screen.getByRole('button', { name: 'Next software page' })); await screen.findByText('101–102 of 102'); expect(summary().closest('details')).not.toHaveAttribute('open'); await expand(); expect(document.querySelector('.software-version-counts')).toHaveTextContent('2 / 2'); expect(api.requests).toHaveLength(2);
    });
    it.each(['blur', 'hidden', 'auth', 'disabled', 'session', 'device'] as const)('clears expanded private evidence on %s', async event => {
        const api = server(), mounted = render(panel()); await screen.findByRole('table'); await expand();
        act(() => {
            if (event === 'hidden') { vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden'); document.dispatchEvent(new Event('visibilitychange')); }
            else if (event === 'disabled') mounted.rerender(panel('a', false));
            else if (event === 'session') mounted.rerender(panel('b', false));
            else if (event === 'device') mounted.rerender(panel('a', false, 'replacement'));
            else window.dispatchEvent(new Event(event === 'auth' ? AUTH_REQUIRED_EVENT : event));
        });
        expect(document.querySelector('.software-version-groups')).toBeNull(); expect(document.body).not.toHaveTextContent(row(1).registrationId); expect(api.requests).toHaveLength(1);
    });
    it('clears at the original paging expiry without renewing it on inspection', async () => {
        vi.useFakeTimers(); const api = server(); api.fetch.mockImplementation(async (url: string, options?: RequestInit) => {
            if (url === '/api/session') return response({ csrfToken: 'fixture-csrf' });
            const value = page(rows(), JSON.parse(options!.body as string)); value.cursorExpiresAt = '2026-10-11T06:00:11Z'; return response(value);
        }); render(panel()); await flush(); fireEvent.click(summary()); await act(async () => { await vi.advanceTimersByTimeAsync(1); }); expect(document.querySelector('.software-version-content')).not.toBeNull();
        await act(async () => { await vi.advanceTimersByTimeAsync(1000); }); expect(document.querySelector('.software-version-groups')).toBeNull(); expect(screen.getByRole('alert')).toHaveTextContent('expired');
    });
    it('does not resurrect groups after a late page response following focus loss', async () => {
        const api = server(); render(panel()); await screen.findByRole('table'); await expand(); let resolve!: (response: Response) => void;
        api.fetch.mockImplementation(() => new Promise(done => { resolve = done; })); fireEvent.click(screen.getByRole('button', { name: 'Refresh software page' })); await flush();
        act(() => window.dispatchEvent(new Event('blur'))); await act(async () => resolve(response(page()))); expect(document.querySelector('.software-version-groups')).toBeNull(); expect(screen.queryByRole('table')).toBeNull();
    });
});
