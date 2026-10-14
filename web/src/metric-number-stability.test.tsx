import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import App from './App';
import { abortProtectedRequests, request } from './api';
import { MetricValue } from './components';
import { setLocale } from './i18n';
import { fullDate } from './utils';
import type { Device, Metric, Quality } from './types';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn() }));
const now = '2026-10-03T12:00:00Z';
const labels = { en: { healthy: 'Current', stale: 'Stale', unknown: 'Unavailable', denied: 'Access denied' }, de: { healthy: 'Aktuell', stale: 'Veraltet', unknown: 'Nicht verfügbar', denied: 'Zugriff verweigert' } };
const values = [0, 1, 8, 10, 99, 100, 0.4, 11.1, 88.8, 1234.5, null, NaN, Infinity, -Infinity];
const expected = {
 en: [['0', '1', '8', '10', '99', '100', '0', '11', '89', '1,235'], ['0', '1', '8', '10', '99', '100', '0.4', '11.1', '88.8', '1,234.5']],
 de: [['0', '1', '8', '10', '99', '100', '0', '11', '89', '1.235'], ['0', '1', '8', '10', '99', '100', '0,4', '11,1', '88,8', '1.234,5']],
};
beforeEach(() => { localStorage.clear(); sessionStorage.clear(); vi.mocked(request).mockReset(); window.history.replaceState({}, '', '/#/overview'); });
afterEach(() => { cleanup(); abortProtectedRequests(); vi.restoreAllMocks(); });

describe('numeric-only MetricValue contract (jsdom, not font/layout evidence)', () => {
 for (const locale of ['en', 'de'] as const) for (const compact of [false, true]) for (const precision of [0, 1] as const) for (const quality of ['healthy', 'stale', 'unknown', 'denied'] as Quality[]) {
  it(`${locale} compact=${compact} precision=${precision} quality=${quality} preserves every value and its original metadata`, () => {
   setLocale(locale, false);
   for (const [index, value] of values.entries()) {
    const metric: Metric = { value, unit: '%', quality, source: 'Synthetic original source', collectedAt: now };
    const { container, unmount } = render(<MetricValue metric={metric} compact={compact} precision={precision}/>);
    const root = container.querySelector('.metric')!, number = root.querySelector('.metric-value')!;
    const valid = value !== null && Number.isFinite(value);
    expect(root.getAttribute('title')).toBe(`${labels[locale][quality]} · Synthetic original source · ${fullDate(now)}`);
    // Numeric text is the anonymous text child. Only nonnumeric spans are reset.
    expect([...number.childNodes].filter(node => node.nodeType === Node.TEXT_NODE).map(node => node.textContent).join('')).toBe(valid ? expected[locale][precision][index] : '');
    expect([...number.children].every(child => child.tagName === 'SPAN')).toBe(true);
    expect(number.querySelector('.unavailable')?.textContent ?? null).toBe(valid ? null : '—');
    expect(number.querySelector('span:not([class])')?.textContent ?? null).toBe(valid ? '%' : null);
    const meter = root.querySelector<HTMLElement>('.meter-track > span');
    expect(Boolean(meter)).toBe(valid);
    if (valid) expect(meter!.style.width).toBe(`${Math.max(0, Math.min(100, value!))}%`);
    expect(number.querySelector('.metric-quality')?.textContent ?? null).toBe(compact ? null : labels[locale][quality]);
    expect(root.querySelector('.metric-note')?.textContent ?? null).toBe(compact && quality !== 'healthy' ? labels[locale][quality] : null);
    unmount();
   }
  });
 }
 it.each(['en', 'de'] as const)('keeps arbitrary units as a separate span in %s', locale => {
  setLocale(locale, false);
  const { container } = render(<MetricValue metric={{ value: 11.1, unit: 'MiB / s', quality: 'denied', source: 'fixture', collectedAt: now }} precision={1}/>);
  expect(container.querySelector('.metric-value > span:not([class])')).toHaveTextContent('MiB / s');
  expect(container.querySelector('.metric-quality')).toHaveTextContent(labels[locale].denied);
 });
 it('scopes the actual stylesheet to numeric primitives without alignment or font overrides', async () => {
  // Vitest disables CSS: parse the source rather than mislabel jsdom as rendered CSS.
  const { readFileSync } = await vi.importActual<{ readFileSync(path: string, encoding: 'utf8'): string }>('node:fs');
  const css = readFileSync('src/styles.css', 'utf8');
  const rules = [...css.matchAll(/([^{}]+)\{([^{}]*font-variant-numeric[^{}]*)\}/g)].map(match => ({ selector: match[1].replace(/\/\*[\s\S]*?\*\//g, '').trim().replace(/\s+/g, ' '), declarations: match[2].trim() }));
  expect(rules).toEqual([
   { selector: '.metric-value, .summary-strip strong', declarations: 'font-variant-numeric: tabular-nums;' },
   { selector: '.metric-value > span', declarations: 'font-variant-numeric: normal;' },
  ]);
 });

 it('keeps the rendered gate inside the existing source-bound synthetic gallery', async () => {
  const { readFileSync } = await vi.importActual<{ readFileSync(path: string, encoding: 'utf8'): string }>('node:fs');
  const gallery = readFileSync('../tests/e2e-review/concise-shell-gallery.mjs', 'utf8');
  const runner = readFileSync('../tests/e2e-review/run.mjs', 'utf8');
  expect(gallery).toContain("document.createRange(); range.selectNodeContents(number)");
  expect(gallery).toContain("fontVariantNumeric = 'normal'");
  expect(gallery).toContain("number.data = original");
  expect(gallery).toContain('sameTextNode && evidence.restoredMarkup && evidence.restoredStyle');
  const css = readFileSync('src/styles.css', 'utf8');
  for (const [selector, weight] of [['.summary-strip strong', '600'], ['.metric.compact .metric-value', '400'], ['.metric-value', '500']]) {
   const rules = [...css.matchAll(/([^{}]+)\{([^{}]*)\}/g)].filter(match => match[1].trim() === selector);
   expect(rules.some(match => match[2].includes(`font-weight:${weight}`))).toBe(true);
  }
  expect(gallery).toContain("const weights = { summary: '600', compact: '400', expanded: '500' }");
  expect(gallery).toContain("if (route === 'devices' && size === 'desktop')");
  expect(gallery).toContain("decimal: key === 'overview'");
  expect(gallery).not.toMatch(/chromium\.launch|newContext\(|waitForTimeout|setDefaultTimeout/);
  expect(runner).toContain("['diff', '--quiet', sourceSha, '--']");
  expect(runner).toContain("numericEvidence = { numericTypography, sourceTree, fontAssets");
 });
});

const metric: Metric = { value: 0, unit: '%', quality: 'healthy', source: 'Synthetic fixture', collectedAt: now };
const device: Device = { id: 'demo-numeric', name: 'Synthetic numeric fixture', platform: 'linux', os: 'Fixture Linux', site: '', group: '', ip: null, status: 'healthy', source: 'synthetic', synthetic: true, lastSeen: now, agentVersion: 'fixture', cpu: metric, memory: metric, disk: metric, uptime: '', tags: [], capabilities: [], evidence: [], trend: [], caseIds: [] };
function overview(count: number, lan = false, investigationsAvailable = true) {
 const session = { mode: lan ? 'lan' : 'development', transport: 'https', insecureTestMode: false, transportWarning: null, authenticationRequired: lan, authenticated: lan, csrfToken: 'synthetic-only', serverNow: now, expiresAt: lan ? '2099-01-01T00:00:00Z' : null, expiresInSeconds: lan ? 1800 : null };
 vi.mocked(request).mockImplementation(async path => {
  if (path === '/auth/session') return session;
  if (path === '/overview') return { generatedAt: now, stats: { totalDevices: count, healthyDevices: count, attentionDevices: count, openCases: count, criticalCases: 0 }, devices: [lan ? { ...device, id: `agent_${'a'.repeat(32)}`, synthetic: false, source: 'lan' } : device], cases: [], activity: [] };
  if (path.startsWith('/investigations?') && investigationsAvailable) return { schemaVersion: 'tracebolt.investigations.v1', serverNow: now, scope: 'open', offset: 0, total: 0, counts: { open: 0, recovered: 0, closed: 0, all: 0 }, devices: [], items: [] };
  throw new Error('Synthetic source unavailable');
 });
}
describe('summary counts retain their existing text and actions', () => {
 for (const locale of ['en', 'de'] as const) {
  it.each([0, 1, 8, 10, 99, 100, 111, 888, 1234])(`${locale} preserves raw count %s without introducing grouping`, async count => {
   setLocale(locale, false); overview(count); const { container } = render(<App/>);
   await waitFor(() => expect(container.querySelectorAll('.summary-strip strong')).toHaveLength(4));
   expect([...container.querySelectorAll('.summary-strip strong')].map(value => value.textContent)).toEqual(Array(4).fill(String(count)));
   expect([...container.querySelectorAll('.summary-strip button > div > span')].map(value => value.textContent)).toEqual(locale === 'en' ? ['1 Demo · 0 local', 'observed state', 'warning or critical', '0 critical'] : ['1 Demo · 0 lokal', 'beobachteter Zustand', 'Warnung oder kritisch', '0 kritisch']);
  });
  it.each([false, true])(`${locale} keeps unavailable investigation count distinct from valid zero: available=%s`, async available => {
   setLocale(locale, false); overview(1, true, available); const { container } = render(<App/>);
   await waitFor(() => expect(container.querySelectorAll('.summary-strip strong')).toHaveLength(4));
   if (available) await screen.findByText(locale === 'de' ? 'Keine offenen Untersuchungen' : 'No open investigations');
   else await waitFor(() => expect(container.querySelector('.investigation-failure')).toBeVisible());
   await waitFor(() => expect(container.querySelectorAll('.summary-strip strong')[3]).toHaveTextContent(available ? '0' : '—'));
  });
  it.each([0, 1, 2, 3])(`${locale} preserves summary shortcut %s`, async index => {
   setLocale(locale, false); overview(1); const { container } = render(<App/>);
   await waitFor(() => expect(container.querySelectorAll('.summary-strip button')).toHaveLength(4));
   const buttons = container.querySelectorAll('.summary-strip button');
   const names = locale === 'en' ? ['Total devices', 'Normal', 'Needs attention', 'Open investigations'] : ['Geräte gesamt', 'Unauffällig', 'Aufmerksamkeit', 'Offene Untersuchungen'];
   expect(buttons[index]).toHaveAccessibleName(expect.stringContaining(names[index]));
   fireEvent.click(buttons[index]);
   await waitFor(() => expect(window.location.hash).toBe(index === 3 ? '#/cases' : '#/devices'));
   if (index < 3) expect(screen.getByRole('combobox', { name: locale === 'de' ? 'Nach Status filtern' : 'Filter by status' })).toHaveValue(['all', 'healthy', 'needs-attention'][index]);
  });
 }
});
