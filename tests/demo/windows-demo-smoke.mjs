// Real loopback manager and compiled dashboard. Requires --demo-only; never
// substitutes fixtures for failed requests or connects to a real endpoint.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const require = createRequire(path.join(root, 'web/package.json'));
const { chromium, expect } = require('@playwright/test');
const base = new URL(process.env.TRACEBOLT_DEMO_URL || 'http://127.0.0.1:8787');
assert.ok(base.protocol === 'http:' && ['127.0.0.1', 'localhost'].includes(base.hostname) && !base.username && !base.password && base.pathname === '/' && !base.search && !base.hash, 'Only an explicit loopback demo origin is allowed');
const output = path.resolve(process.env.TRACEBOLT_DEMO_ARTIFACTS || path.join(root, 'artifacts/windows-demo-browser'));
await fs.mkdir(output, { recursive: true });
const executablePath = process.env.CHROMIUM_PATH || (process.platform === 'win32' ? 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe' : undefined);
const browser = await chromium.launch({ headless: true, ...(executablePath ? { executablePath } : {}) });
const report = { baseURL: base.origin, browser: browser.version(), nativePlatform: process.platform, syntheticOnly: true, mockedRequests: false, nativeEndpoint: false, cases: [], screenshots: [], sourceHashes: {} };
for (const file of ['cmd/manager/main.go', 'internal/api/demo.go', 'internal/api/api.go', 'internal/api/telemetry.go', 'internal/model/model.go', 'internal/store/store.go', 'internal/store/demo.go', 'web/src/App.tsx', 'web/src/types.ts', 'web/src/overview-workspace.tsx', 'web/package-lock.json', 'tests/demo/windows-demo-smoke.mjs']) report.sourceHashes[file] = createHash('sha256').update(await fs.readFile(path.join(root, file))).digest('hex');
try {
 const http = await browser.newContext();
 const read = async endpoint => { const response = await http.request.get(base.origin + endpoint, { maxRedirects: 0 }); assert.equal(response.status(), 200); return response.json(); };
 const capabilities = await read('/api/capabilities'), overview = await read('/api/overview');
 assert.equal(capabilities.mode, 'local-development'); assert.equal(capabilities.demoOnly, true); assert.equal(capabilities.managedPreview, false); assert.equal(capabilities.remoteEnrollment, false); assert.equal(capabilities.shellExecution, false); assert.equal(capabilities.aiConfigured, false);
 assert.equal(overview.demoOnly, true); assert.equal(overview.devices.length, 7); assert.ok(overview.devices.every(d => d.synthetic === true && d.source === 'synthetic')); assert.ok(overview.cases.every(c => c.synthetic === true));
 assert.equal((await http.request.get(base.origin + '/api/dev/telemetry/status')).status(), 404);
 assert.equal((await http.request.get(base.origin + '/api/devices/sandbox-local')).status(), 404);
 await http.close();
 for (const locale of ['en', 'de']) for (const width of [1440, 390]) for (const theme of ['light', 'dark']) {
  const de = locale === 'de', name = `${locale}-${width}-${theme}`, errors = [], unexpected = [];
  const context = await browser.newContext({ viewport: { width, height: width === 390 ? 844 : 1000 }, reducedMotion: 'reduce' });
  await context.addInitScript(({ locale, theme }) => { localStorage.setItem('tracebolt.locale', locale); localStorage.setItem('local-rmm-theme', JSON.stringify(theme)); }, { locale, theme });
  const page = await context.newPage(); page.on('pageerror', error => errors.push(error.message));
  await page.route('**/*', route => {
   if (new URL(route.request().url()).origin !== base.origin) { unexpected.push('External request blocked'); return route.abort(); }
   return route.continue();
  });
  const shot = async scene => {
   assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'No page overflow');
   const image = await page.screenshot({ animations: 'disabled' }), file = `${name}-${scene}.png`; await fs.writeFile(path.join(output, file), image);
   report.screenshots.push({ file, sha256: createHash('sha256').update(image).digest('hex') });
  };
  try {
   await page.goto(base.origin + '/#/overview'); await expect(page.getByRole('heading', { name: de ? 'Übersicht' : 'Overview', exact: true })).toBeVisible();
   await expect(page.locator('.overview-context')).toContainText(de ? 'Nur synthetische Beispiele' : 'Synthetic examples only');
   await expect(page.locator('.demo-banner')).toContainText(de ? 'Nur Beispieldaten, keine lokale Erfassung.' : 'Example data only; no local collection.'); await shot('overview');
   await page.goto(base.origin + '/#/devices'); await expect(page.locator('.device-table tbody tr')).toHaveCount(7); await expect(page.locator('.device-table tbody .source.real')).toHaveCount(0); await shot('inventory');
   const search = page.getByRole('textbox', { name: de ? 'Geräte durchsuchen' : 'Search devices' }); await search.fill('missing-synthetic-device');
   await expect(page.getByRole('heading', { name: de ? 'Keine passenden Geräte' : 'No matching devices', exact: true })).toBeVisible();
   await search.fill('BER-DC-01'); await expect(page.locator('.device-table tbody tr')).toHaveCount(1); await page.locator('.device-name-button').filter({ hasText: 'BER-DC-01' }).click();
   await expect(page.getByRole('region', { name: de ? 'Gerät BER-DC-01' : 'Device BER-DC-01', exact: true })).toBeVisible(); await shot('device');
   await page.goto(base.origin + '/#/cases/case-demo-win-01-service'); await expect(page.locator('.finding-panel h2')).toBeVisible();
   const note = `Synthetic demo browser check ${name}`; await page.locator('#case-note').fill(note); await page.locator('.notes-panel form').getByRole('button').click();
   await expect(page.locator('.notes-list')).toContainText(note); await page.reload(); await expect(page.locator('.notes-list')).toContainText(note); await shot('case');
   await page.goto(base.origin + '/#/settings'); await expect(page.getByText(de ? 'Demo-Inventar & Belege' : 'Demo inventory & evidence', { exact: true })).toBeVisible();
   await expect(page.getByText(de ? 'Lokaler Collector' : 'Local collector', { exact: true })).toHaveCount(0);
   await expect(page.getByText(de ? 'Reine Beispieldemo. Lokale Erfassung und Entwickler-Telemetrie sind deaktiviert.' : 'Synthetic demonstration only. Local collection and developer telemetry are disabled.', { exact: true })).toBeVisible(); await shot('settings');
   // Exercise actual UI controls as well as persisted initial preferences.
   await page.getByRole('combobox', { name: de ? 'Sprache' : 'Language', exact: true }).selectOption(de ? 'en' : 'de');
   await expect(page.locator('html')).toHaveAttribute('lang', de ? 'en' : 'de');
   const newDe = !de, themeName = theme === 'light' ? (newDe ? 'Dunkles Design aktivieren' : 'Switch to dark theme') : (newDe ? 'Helles Design aktivieren' : 'Switch to light theme');
   await page.getByRole('button', { name: themeName, exact: true }).click(); await expect(page.locator('html')).toHaveAttribute('data-theme', theme === 'light' ? 'dark' : 'light');
   assert.deepEqual(errors, []); assert.deepEqual(unexpected, []); report.cases.push({ name, status: 'PASS', scenarios: ['overview', 'seven-synthetic-devices', 'empty-search', 'device', 'note-save-and-reload', 'source-truth', 'language', 'theme'] }); console.log(`PASS ${name}`);
  } finally { await context.close(); }
 }
} finally { await browser.close(); await fs.writeFile(path.join(output, 'results.json'), JSON.stringify(report, null, 2)); }
console.log(JSON.stringify({ passed: report.cases.length, screenshots: report.screenshots.length }));
