import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { mutateRaw, request } from './api';
import { CompletePackagesPanel } from './complete-packages';
import { completeDevice, completePage, completeRows, completeView } from './complete-packages-fixtures';
import { setLocale } from './i18n';
import { PackageObservationsPanel } from './package-observations';
import type { PackageView } from './package-observations-types';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutateRaw: vi.fn() }));
vi.mock('./auth', () => ({ useOperator: () => ({ mode: 'lan', authenticated: true, expiresAt: '2026-10-04T01:00:00Z' }) }));
const { readFileSync } = await vi.importActual<{ readFileSync(path: string, encoding: 'utf8'): string }>('node:fs');
const css = readFileSync('src/package-observations.css', 'utf8');
const rules = [...css.replace(/\/\*[\s\S]*?\*\//g, '').matchAll(/([^{}]+)\{([^{}]*)\}/g)];
const declarations = (selector: string) => {
    const matches = rules.filter(rule => rule[1].trim() === selector);
    expect(matches).toHaveLength(1);
    return Object.fromEntries(matches[0][2].split(';').filter(item => item.includes(':')).map(item => {
        const separator = item.indexOf(':'); return [item.slice(0, separator).trim(), item.slice(separator + 1).trim()];
    }));
};
let style: HTMLStyleElement;
let originalTheme: string | undefined;
beforeEach(() => {
    vi.mocked(request).mockReset(); vi.mocked(mutateRaw).mockReset();
    originalTheme = document.documentElement.dataset.theme;
    // Vitest stubs CSS imports. Apply the real shared stylesheet to the rendered
    // components; jsdom checks declarations/semantics, not native marker pixels.
    style = document.createElement('style'); style.textContent = css; document.head.append(style);
});
afterEach(() => {
    cleanup(); style.remove(); vi.restoreAllMocks();
    if (originalTheme === undefined) delete document.documentElement.dataset.theme;
    else document.documentElement.dataset.theme = originalTheme;
});

describe('package summary inset-ring clearance source contract', () => {
    it('reserves clearance before focus rather than shifting marker or wrapped text on entry', () => {
        const base = declarations('.package-row-details summary');
        expect(base.padding).toBe('6px');
        expect(base).toEqual({ cursor: 'pointer', 'border-radius': '3px', padding: '6px' });
        const summaryRules = rules.filter(rule => rule[1].includes('.package-row-details') && rule[1].includes('summary'));
        expect(summaryRules.map(rule => rule[1].trim())).toEqual(['.package-row-details summary', '.package-row-details summary:focus-visible']);
        // No marker suppression/replacement, display override, or state-only
        // padding: the native disclosure and all wrapped lines keep their inset.
        expect(summaryRules.map(rule => rule[2]).join('')).not.toMatch(/list-style|display\s*:|content\s*:|text-indent|transform|overflow\s*:/);
    });
    it('retains the complete 3 px opaque inset ring and the independent table ring', () => {
        for (const selector of ['.package-row-details summary:focus-visible', '.package-table-scroll:focus-visible']) {
            expect(declarations(selector)).toEqual({ outline: '3px solid var(--focus-ring)', 'outline-offset': '-3px' });
        }
    });
});

// Padding, native disclosure semantics and read counts do not vary by theme.
// Painted light/dark focus-ring evidence belongs to the existing browser gate.
for (const surface of ['legacy', 'complete'] as const) for (const locale of ['en', 'de'] as const) {
    it(`${surface}/${locale}: shares stable clearance with native disclosure semantics and unchanged reads`, async () => {
        setLocale(locale, false); document.documentElement.dataset.theme = 'light';
        const view = completeView(2), rows = completeRows(2);
        rows.forEach((row, index) => Object.assign(row, { sourcePackage: `qa-source-${'long-segment-'.repeat(8)}${index}`, sourceMapping: 'source-field' }));
        if (surface === 'complete') {
            vi.mocked(request).mockResolvedValue(view);
            vi.mocked(mutateRaw).mockImplementation(async (_path, raw) => completePage(view, rows, raw));
            render(<CompletePackagesPanel deviceId={completeDevice} inline/>);
        } else {
            const manifest = view.complete!.manifest;
            const legacy: PackageView = { schemaVersion: 'tracebolt.package-view.v1', deviceId: completeDevice, status: 'fresh', serverNow: view.serverNow, receivedAt: view.complete!.completedAt, sequence: 1, maxAgeSeconds: 120,
                snapshot: { schemaVersion: 'tracebolt.linux-packages.v1', scope: 'agent-visible-dpkg', generationId: manifest.generationId, collectedAt: manifest.collectedAt, durationMs: manifest.durationMs, release: manifest.release,
                    inventory: { quality: 'healthy', reason: 'none', complete: true, truncated: false, countExact: true, observedCount: 2, installedCount: 2, items: rows } } };
            vi.mocked(request).mockResolvedValue(legacy);
            render(<PackageObservationsPanel deviceId={completeDevice}/>);
            fireEvent.click(screen.getByRole('button', { name: locale === 'de' ? 'Release- und Quellpaket-Beobachtungen' : 'Release and source-package observations' }));
        }
        const table = await screen.findByRole('table'), region = table.closest('.package-table-scroll') as HTMLElement;
        region.scrollLeft = 83;
        const summaries = [...table.querySelectorAll('summary')]; expect(summaries).toHaveLength(2);
        const clearance = (summary: HTMLElement) => {
            const value = getComputedStyle(summary);
            expect([value.paddingTop, value.paddingRight, value.paddingBottom, value.paddingLeft]).toEqual(['6px', '6px', '6px', '6px']);
        };
        for (const [index, summary] of summaries.entries()) {
            const details = summary.parentElement!;
            expect(details.tagName).toBe('DETAILS'); expect(details).toHaveClass('package-row-details'); expect(details.firstElementChild).toBe(summary);
            expect(summary).not.toHaveAttribute('role'); expect(summary).not.toHaveAttribute('tabindex'); expect(summary).not.toHaveAttribute('aria-hidden');
            expect(summary.firstChild?.nodeType).toBe(Node.TEXT_NODE); expect(summary.firstChild?.textContent).toBe(rows[index].sourcePackage);
            expect(summary.children).toHaveLength(1); expect(summary.firstElementChild).toHaveClass('sr-only');
            expect(summary).toHaveTextContent(`${locale === 'de' ? 'Paketdetails' : 'Package details'}: ${rows[index].name} (${rows[index].architecture})`);
            const reveal = vi.fn(); Object.defineProperty(summary, 'scrollIntoView', { configurable: true, value: reveal });
            expect(details).not.toHaveAttribute('open'); clearance(summary);
            summary.focus(); expect(summary).toHaveFocus(); clearance(summary); expect(details).not.toHaveAttribute('open');
            expect(reveal).toHaveBeenCalledExactlyOnceWith({ block: 'nearest', inline: 'nearest', behavior: 'instant' });
            for (const key of [{ key: 'Tab' }, { key: 'Tab', shiftKey: true }, { key: 'Enter' }, { key: ' ' }]) {
                const event = new KeyboardEvent('keydown', { ...key, bubbles: true, cancelable: true });
                expect(summary.dispatchEvent(event)).toBe(true); expect(event.defaultPrevented).toBe(false);
            }
            fireEvent.click(summary); expect(details).toHaveAttribute('open'); clearance(summary);
            fireEvent.click(summary); expect(details).not.toHaveAttribute('open'); clearance(summary);
            summary.blur(); clearance(summary); expect(region.scrollLeft).toBe(83);
        }
        expect(request).toHaveBeenCalledTimes(1); expect(mutateRaw).toHaveBeenCalledTimes(surface === 'complete' ? 1 : 0);
    });
}
