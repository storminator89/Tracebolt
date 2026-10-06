import { act, cleanup, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, hasPendingAPIRequests, request } from './api';
import { useOperator } from './auth';
import { ApplicationChecksPanel } from './application-checks';
import { applicationNow, applicationRow, applicationView } from './application-checks-fixtures';
import { applicationDNSRow, applicationHTTPRow, applicationTCPRow, applicationViewV2 } from './application-checks-v2-fixtures';
import { setLocale } from './i18n';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), hasPendingAPIRequests: vi.fn(), request: vi.fn() }));
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
const operator = { mode: 'lan' as const, authenticated: true, expiresAt: '2026-10-06T14:00:00Z', insecureTestMode: false, logout: vi.fn(), theme: 'light' as const, setTheme: vi.fn() };
const rowFor = (id: string) => screen.getByText(id).closest('tr')!;
async function start() { render(<ApplicationChecksPanel/>); await act(async () => {}); }
beforeEach(() => {
    vi.useFakeTimers(); vi.setSystemTime(applicationNow); localStorage.clear(); sessionStorage.clear(); setLocale('en', false);
    vi.spyOn(document, 'hasFocus').mockReturnValue(true); vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('visible');
    vi.mocked(useOperator).mockReturnValue(operator); vi.mocked(hasPendingAPIRequests).mockReset().mockReturnValue(false); vi.mocked(request).mockReset();
});
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.restoreAllMocks(); });

describe('single responsive application table semantics', () => {
    it.each(['en', 'de'] as const)('preserves real headers, reading order and unique observation values in %s', async locale => {
        setLocale(locale, false);
        const longId = 'application_'.padEnd(48, 'x');
        vi.mocked(request).mockResolvedValue(applicationViewV2([
            applicationHTTPRow({ id: longId }), applicationDNSRow(),
            { ...applicationTCPRow(), state: 'network_error', reason: 'tcp_failed' },
        ]));
        await start();
        const table = screen.getByRole('table');
        expect(screen.getAllByRole('table')).toHaveLength(1);
        expect(within(table).getAllByRole('rowgroup')).toHaveLength(2);
        const columns = within(table).getAllByRole('columnheader');
        expect(columns.map(column => column.textContent)).toEqual(locale === 'en' ? ['Application', 'Result', 'Leaf certificate', 'Observed'] : ['Anwendung', 'Prüfergebnis', 'Blattzertifikat', 'Beobachtet']);
        for (const column of columns) expect(column).toHaveAttribute('scope', 'col');
        expect(table.querySelector('thead')).not.toHaveAttribute('aria-hidden');
        expect(table.querySelectorAll('tbody tr')).toHaveLength(3);

        for (const id of [longId, 'fixture-dns', 'fixture-tcp']) {
            const row = rowFor(id), header = within(row).getByRole('rowheader'), cells = within(row).getAllByRole('cell');
            expect(header).toHaveAttribute('scope', 'row');
            expect(header).toHaveAttribute('headers', columns[0].id);
            expect(Array.from(row.children).map(cell => cell.getAttribute('role'))).toEqual(['rowheader', 'cell', 'cell', 'cell']);
            expect(cells).toHaveLength(3);
            cells.forEach((cell, index) => {
                expect(cell).toHaveAttribute('headers', `${header.id} ${columns[index + 1].id}`);
                const label = cell.querySelector('.application-mobile-label');
                expect(label).toHaveTextContent(columns[index + 1].textContent!);
                expect(label).toHaveAttribute('aria-hidden', 'true');
                expect(cell.querySelectorAll('.application-cell-value')).toHaveLength(1);
            });
            expect(cells[2].querySelector('time')).toHaveAttribute('datetime', applicationNow);
            expect(cells[2]).toHaveAccessibleName(locale === 'en' ? '0s ago' : 'vor 0 s');
        }
        expect(rowFor(longId).querySelectorAll('.application-id')).toHaveLength(1);
        expect(rowFor(longId).querySelectorAll('.application-expiry')).toHaveLength(1);
        expect(rowFor(longId).querySelector('.application-expiry')).toHaveAttribute('datetime', '2026-10-10T12:00:00Z');
        expect(rowFor('fixture-tcp')).toHaveTextContent(locale === 'en' ? 'TCP connection failed' : 'TCP-Verbindung fehlgeschlagen');

        const noCertificate = locale === 'en' ? 'Certificate is not part of this check' : 'Zertifikat nicht Teil dieser Prüfung';
        for (const id of ['fixture-dns', 'fixture-tcp']) {
            const certificate = within(rowFor(id)).getByRole('img', { name: noCertificate });
            expect(certificate.querySelector('.application-certificate-mark')).toHaveTextContent('—');
            expect(certificate.querySelector('.application-mobile-certificate')).toHaveTextContent(noCertificate);
            expect(certificate.querySelector('.application-mobile-certificate')).toHaveAttribute('aria-hidden', 'true');
            expect(rowFor(id).querySelectorAll('time')).toHaveLength(1);
            expect(rowFor(id).querySelector('.application-expiry')).toBeNull();
        }
    });

    it('uses the v1 HTTP label and retains the original timestamp as the same row ages', async () => {
        vi.mocked(request).mockResolvedValue(applicationView([applicationRow()]));
        await start();
        const row = rowFor('fixture-app'), cells = within(row).getAllByRole('cell');
        expect(screen.getByRole('columnheader', { name: 'HTTP result' })).toHaveAttribute('id', 'application-checks-result');
        expect(cells[0].querySelector('.application-mobile-label')).toHaveTextContent('HTTP result');
        vi.mocked(hasPendingAPIRequests).mockReturnValue(true);
        await act(async () => { await vi.advanceTimersByTimeAsync(71000); });
        expect(rowFor('fixture-app')).toBe(row);
        expect(cells[0]).toHaveAccessibleName('Unknown · stale');
        expect(cells[1]).toHaveAccessibleName('Unknown');
        expect(cells[1].querySelector('.application-expiry')).toBeNull();
        expect(cells[2]).toHaveAccessibleName('1m ago');
        expect(cells[2].querySelector('time')).toHaveAttribute('datetime', applicationNow);
        expect(request).toHaveBeenCalledTimes(1);
    });

    it('keeps plaintext and unchecked states in the same mobile value cells', async () => {
        vi.mocked(request).mockResolvedValue(applicationViewV2([
            applicationHTTPRow({ id: 'fixture-plain', targetScheme: 'http', tls: { state: 'not_applicable', expiresAt: null } }),
            { kind: 'tcp', id: 'fixture-unchecked', state: 'unknown', reason: 'not_checked', observedAt: null },
        ]));
        await start();
        expect(within(rowFor('fixture-plain')).getByRole('rowheader')).toHaveAccessibleName(/fixture-plain\s*HTTP · plaintext/);
        expect(within(rowFor('fixture-plain')).getAllByRole('cell')[1]).toHaveAccessibleName('No TLS');
        const unchecked = within(rowFor('fixture-unchecked')).getAllByRole('cell');
        expect(unchecked[0]).toHaveAccessibleName('Not observed yet');
        expect(unchecked[2]).toHaveAccessibleName('—');
        expect(rowFor('fixture-unchecked').querySelector('time')).toBeNull();
    });
});

describe('responsive CSS source contract (not browser geometry)', () => {
    it('stacks narrow rows without a fixed table width or hidden semantic headers', async () => {
        // CSS imports are stubbed by this browser-focused Vitest configuration.
        const { readFileSync } = await vi.importActual<{ readFileSync(path: string, encoding: 'utf8'): string }>('node:fs');
        const style = document.createElement('style');
        style.textContent = readFileSync('src/application-checks.css', 'utf8');
        document.head.append(style);
        try {
            const rules = Array.from(style.sheet!.cssRules);
            const mobile = rules.find(rule => rule instanceof CSSMediaRule) as CSSMediaRule;
            expect(mobile.media.mediaText).toBe('(max-width:760px)');
            const matches = (rule: CSSRule, selector: string) => (rule as CSSStyleRule).selectorText?.replace(/,\s*/g, ',') === selector;
            const declarations = (selector: string) => (Array.from(mobile.cssRules).find(rule => matches(rule, selector)) as CSSStyleRule).style;
            expect(declarations('.application-checks-table').getPropertyValue('overflow-x')).toBe('visible');
            expect(declarations('.application-checks table,.application-checks tbody').getPropertyValue('display')).toBe('block');
            expect(declarations('.application-checks tbody tr').getPropertyValue('grid-template-columns')).toBe('minmax(0,1fr)');
            expect(declarations('.application-checks tbody td').getPropertyValue('grid-template-columns')).toBe('minmax(0,6.75rem) minmax(0,1fr)');
            expect(declarations('.application-checks tbody th,.application-checks tbody td').getPropertyValue('min-width')).toMatch(/^0(px)?$/);
            expect(declarations('.application-checks td:last-child').getPropertyValue('white-space')).toBe('normal');
            expect(declarations('.application-cell-value').getPropertyValue('overflow-wrap')).toBe('anywhere');
            expect(declarations('.application-checks thead').getPropertyValue('clip-path')).toBe('inset(50%)');
            expect(declarations('.application-checks thead').getPropertyValue('display')).not.toBe('none');
            expect(declarations('.application-certificate-mark').getPropertyValue('display')).toBe('none');
            expect(declarations('.application-mobile-certificate').getPropertyValue('display')).toBe('inline');
            expect(style.textContent).not.toContain('min-width:550px');
            const desktopLabels = rules.find(rule => matches(rule, '.application-mobile-label,.application-mobile-certificate')) as CSSStyleRule;
            expect(desktopLabels.style.getPropertyValue('display')).toBe('none');
        } finally { style.remove(); }
    });
});
