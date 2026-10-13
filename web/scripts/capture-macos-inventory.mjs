/** Host-free synthetic Mac inventory capture. --check never launches a browser.
 * The compiled DeviceDetail, AuthBoundary and private request client are real;
 * every endpoint is intercepted. There are no host reads or external requests. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const root = fileURLToPath(new URL('../../', import.meta.url)), require = createRequire(new URL('../package.json', import.meta.url));
export const origin = 'https://macos-inventory.invalid';
export const disclosure = 'Synthetic Mac inventory metadata; actual compiled DeviceDetail, AuthBoundary, EnrollmentSection, MacOSSourceInstructions and bounded private request client. All requests intercepted. No native reads, host, real session, invitation, key, grant, install, service action, AI call or native acceptance.';
export const scenes = ['overview', 'hardware', 'receipts', 'processes', 'ipv4', 'ipv6', 'partial', 'basic', 'enrollment', 'instructions'];
export const captureMatrix = ['en', 'de'].flatMap(locale => [1440, 390].flatMap(width => scenes.map(scene => ({ locale, width, height: width === 390 ? 844 : 1100, scene, file: `macos-inventory-${scene}-${locale}-${width}.png` }))));
const hash = value => createHash('sha256').update(value).digest('hex');
async function bundle(contents, platform = 'browser') {
 const { build } = require('esbuild');
 return build({ stdin: { contents, resolveDir: path.join(root, 'web/src'), loader: 'tsx' }, absWorkingDir: root, outdir: 'web/.macos-inventory-memory-only', entryNames: 'app', bundle: true, platform, format: 'esm', jsx: 'automatic', define: { 'process.env.NODE_ENV': '"production"' }, loader: { '.woff': 'dataurl', '.woff2': 'dataurl', '.svg': 'dataurl', '.png': 'dataurl' }, write: false, metafile: true, minify: platform === 'browser', logLevel: 'silent' });
}
export async function compile() {
 const fixtures = await bundle("export * from './macos-inventory-fixture'; export {validMacInventoryPage} from './macos-inventory-types'; export {macOSFixtureList} from './enrollment-macos-fixture';", 'node');
 const data = await import(`data:text/javascript;base64,${Buffer.from(fixtures.outputFiles[0].contents).toString('base64')}`);
 const result = await bundle(`import React from 'react'; import {createRoot} from 'react-dom/client'; import './styles.css'; import {AuthBoundary} from './auth'; import {DeviceDetail} from './details'; import {EnrollmentSection} from './enrollment'; import {MacOSSourceInstructions} from './enrollment-macos'; import {setLocale} from './i18n'; setLocale(window.__MAC_INVENTORY_LOCALE__,false); createRoot(document.getElementById('root')).render(<main style={{maxWidth:1100,margin:'0 auto',padding:16}}><p role="note">SYNTHETIC · Mac inventory source UI · No endpoint actions</p><AuthBoundary>{window.__MAC_INVENTORY_SCENE__==='instructions'?<MacOSSourceInstructions renewable={false} inventory/>:window.__MAC_INVENTORY_SCENE__==='enrollment'?<EnrollmentSection onChanged={()=>{}} onDevice={()=>{}} deviceIds={[]}/>:<DeviceDetail id="${data.macInventoryDeviceId}" onClose={()=>{}} onCase={()=>{}}/>}</AuthBoundary></main>);`);
 const assets = new Map(result.outputFiles.map(file => [`/${path.basename(file.path)}`, { body: Buffer.from(file.contents), contentType: file.path.endsWith('.css') ? 'text/css' : 'text/javascript' }]));
 assets.set('/', { contentType: 'text/html', body: '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="icon" href="data:,"><link rel="stylesheet" href="/app.css"><title>Synthetic Mac inventory</title></head><body><div id="root"></div><script type="module" src="/app.js"></script></body></html>' });
 const files = [...new Set([...Object.keys(fixtures.metafile.inputs), ...Object.keys(result.metafile.inputs)].filter(file => file.startsWith('web/src/')).concat(['web/scripts/capture-macos-inventory.mjs', 'web/scripts/run-macos-inventory-ci.mjs', 'web/scripts/check-macos-inventory-evidence.mjs']))].sort();
 const sourceInputs = await Promise.all(files.map(async file => ({ file, sha256: hash(await readFile(path.join(root, file))) })));
 return { assets, data, sourceInputs, sourceDigest: hash(JSON.stringify(sourceInputs)) };
}
export function routeFixture(compiled, scene, state) {
 const data = compiled.data;
 return async route => {
  const req = route.request(), url = new URL(req.url()), method = req.method(), raw = req.postData();
  const block = kind => { state[kind]++; return route.abort('blockedbyclient'); };
  if (url.origin !== origin) return block('external'); if (url.search) return block('unexpected');
  const respond = body => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });
  if (method === 'GET' && raw === null) {
   if (url.pathname === '/api/auth/session') return respond({ mode: 'lan', transport: 'https', insecureTestMode: false, transportWarning: null, authenticationRequired: true, authenticated: true, csrfToken: 'synthetic-csrf', serverNow: data.macInventoryNow, expiresAt: '2026-10-13T10:30:00Z', expiresInSeconds: 1790 });
   if (url.pathname === '/api/session') return respond({ csrfToken: 'synthetic-csrf' });
   if (url.pathname === `/api/devices/${data.macInventoryDeviceId}`) return respond(data.macInventoryDevice(scene !== 'basic'));
   if (url.pathname === '/api/enrollment') return respond({ ...data.macOSFixtureList(), platforms: ['linux'] });
   if (url.pathname === '/api/macos/enrollment') return respond(data.macOSFixtureList());
   if (url.pathname === '/api/macos-inventory/enrollment') return respond({ ...data.macOSFixtureList(), collectionProfile: 'macos-read-inventory-v1', collectionPrivacy: 'macos_inventory_metadata_may_be_sensitive' });
   const asset = compiled.assets.get(url.pathname); if (asset) return route.fulfill({ status: 200, ...asset });
   return block('unexpected');
  }
  if (method === 'POST' && !['overview', 'basic', 'enrollment', 'instructions'].includes(scene) && url.pathname === `/api/devices/${data.macInventoryDeviceId}/macos-inventory/query`) {
   let q; try { q = JSON.parse(raw); } catch { return block('unexpected'); }
   if (Object.keys(q).sort().join(',') !== 'generationId,limit,offset,section' || req.headers()['x-csrf-token'] !== 'synthetic-csrf' || !['summary', 'hardware', 'receipts', 'processes', 'ipv4', 'ipv6'].includes(q.section) || q.limit !== 50 || q.offset !== 0 || q.generationId !== (q.section === 'summary' ? '' : data.macInventoryGeneration)) return block('unexpected');
   const page = data.macInventoryFixture(q);
   if (scene === 'partial') { page.sources.receipts = { ...page.sources.receipts, quality: 'denied', reason: 'macos_inventory_access_denied' }; page.sourceQuality = 'partial'; if (q.section === 'receipts') { page.receiptIds = []; page.total = 0; } }
   assert(data.validMacInventoryPage(page, data.macInventoryDeviceId, q)); state.privateReads++; return respond(page);
  }
  return block('writes');
 };
}
export async function check() {
 const compiled = await compile(), state = { external: 0, unexpected: 0, writes: 0, privateReads: 0 }, handler = routeFixture(compiled, 'hardware', state);
 let response;
 const fake = (method, url, raw = null) => ({ request: () => ({ method: () => method, url: () => url, postData: () => raw, headers: () => ({ 'x-csrf-token': 'synthetic-csrf' }) }), fulfill: value => { response = value; }, abort: () => {} });
 await handler(fake('POST', `${origin}/api/devices/${compiled.data.macInventoryDeviceId}/macos-inventory/query`, JSON.stringify(compiled.data.macInventoryQuery()))); assert.equal(JSON.parse(response.body).sourceQuality, 'full');
 await handler(fake('POST', `${origin}/api/macos-inventory/enrollment/invitations`, '{}')); await handler(fake('GET', 'https://real.invalid/'));
 assert.deepEqual(state, { external: 1, unexpected: 0, writes: 1, privateReads: 1 });
 const overviewState = { external: 0, unexpected: 0, writes: 0, privateReads: 0 };
 await routeFixture(compiled, 'overview', overviewState)(fake('POST', `${origin}/api/devices/${compiled.data.macInventoryDeviceId}/macos-inventory/query`, JSON.stringify(compiled.data.macInventoryQuery())));
 assert.deepEqual(overviewState, { external: 0, unexpected: 0, writes: 1, privateReads: 0 });
 // Geometry guard unit checks use plain objects only, never a browser or DOM.
 let centered = false;
 const fixtureTarget = box => ({ evaluate: fn => fn({ scrollIntoView: options => { centered = options.block === 'center' && options.inline === 'nearest'; } }), boundingBox: async () => box });
 const fixturePage = { viewportSize: () => ({ width: 390, height: 844 }) }, fixtureExpect = () => ({ toBeInViewport: async options => assert.equal(options.ratio, 0.95) });
 await frameTarget(fixturePage, fixtureExpect, fixtureTarget({ x: 20, y: 400, width: 180, height: 24 })); assert(centered);
 await assert.rejects(frameTarget(fixturePage, fixtureExpect, fixtureTarget({ x: 20, y: 850, width: 180, height: 24 })));
 await assert.rejects(frameTarget(fixturePage, fixtureExpect, fixtureTarget({ x: 350, y: 400, width: 180, height: 24 })));
 return { sourceDigest: compiled.sourceDigest, scenes: scenes.length, screenshots: captureMatrix.length, browserExecuted: false, nativeAcceptance: false, disclosure };
}
/** A positive DOM visibility result alone does not prove the selected evidence
 * appears inside the fixed screenshot crop, especially on narrow screens. */
async function frameTarget(page, expect, target) {
 await target.evaluate(element => element.scrollIntoView({ block: 'center', inline: 'nearest', behavior: 'instant' }));
 await expect(target).toBeInViewport({ ratio: 0.95 });
 const box = await target.boundingBox(), viewport = page.viewportSize();
 assert(box && viewport && box.width >= 16 && box.height >= 12);
 const visibleWidth = Math.max(0, Math.min(viewport.width, box.x + box.width) - Math.max(0, box.x));
 const visibleHeight = Math.max(0, Math.min(viewport.height, box.y + box.height) - Math.max(0, box.y));
 assert(visibleWidth >= box.width * 0.95 && visibleHeight >= box.height * 0.95, 'Selected synthetic evidence must be inside the screenshot crop.');
}
export async function capture({ browser, expect, output }) {
 const compiled = await compile(), captures = []; await mkdir(output, { recursive: true });
 for (const item of captureMatrix) {
  const { locale, width, height, scene, file } = item, de = locale === 'de', state = { external: 0, unexpected: 0, writes: 0, privateReads: 0 };
  const context = await browser.newContext({ viewport: { width, height }, reducedMotion: 'reduce', locale: de ? 'de-DE' : 'en-US', serviceWorkers: 'block' });
  try {
   await context.route('**/*', routeFixture(compiled, scene, state)); await context.addInitScript(({ locale, scene }) => { window.__MAC_INVENTORY_LOCALE__ = locale; window.__MAC_INVENTORY_SCENE__ = scene; }, { locale, scene });
   const page = await context.newPage(); let errors = 0, captureTarget = null; page.on('pageerror', () => errors++); await page.goto(origin + '/');
   if (scene === 'instructions') {
    await expect(page.getByRole('heading', { name: de ? 'Neues macOS-Leseinventar' : 'Fresh macOS read-only inventory', exact: true })).toBeVisible();
    await page.getByText(de ? 'Lokale Schritte & Voraussetzungen' : 'Local steps & prerequisites', { exact: true }).click();
    captureTarget = page.getByRole('listitem').filter({ hasText: '--macos-read-inventory' });
    await expect(captureTarget).toContainText('ALLOW MACOS INVENTORY');
    await expect(page.getByRole('listitem').filter({ hasText: '--foreground' })).toBeVisible();
   } else if (scene === 'enrollment') {
    await expect(page.getByRole('button', { name: de ? 'Gerät hinzufügen' : 'Add device', exact: true })).toBeEnabled();
    await page.getByRole('combobox', { name: de ? 'Betriebssystem' : 'Operating system', exact: true }).selectOption('darwin'); await page.getByRole('combobox', { name: de ? 'macOS-Erfassungsumfang' : 'macOS collection scope', exact: true }).selectOption('macos-read-inventory-v1');
    await expect(page.getByRole('button', { name: de ? 'Gerät hinzufügen' : 'Add device', exact: true })).toBeEnabled(); await page.getByRole('button', { name: de ? 'Gerät hinzufügen' : 'Add device', exact: true }).click();
    await expect(page.getByRole('dialog').getByRole('checkbox')).not.toBeChecked(); await expect(page.getByRole('dialog').getByRole('button', { name: de ? 'Einladung erstellen' : 'Create invitation', exact: true })).toBeDisabled();
   } else {
    await expect(page.getByRole('heading', { name: 'Synthetic Mac', exact: true })).toBeVisible();
    await expect(page.getByText(de ? 'Cache-Kandidaten' : 'cached candidates', { exact: true })).toHaveCount(0);
    if (scene === 'overview') {
     await expect(page.getByRole('tab', { name: de ? 'Übersicht' : 'Overview', exact: true })).toHaveAttribute('aria-selected', 'true');
     await expect(page.getByRole('heading', { name: de ? 'Letzte Meldung' : 'Last report', exact: true })).toBeVisible();
    } else {
     await page.getByRole('tab', { name: de ? 'Inventar' : 'Inventory', exact: true }).click();
     if (scene === 'basic') await expect(page.getByText(de ? /Dieser Mac hat nur den Basis-Leseumfang/ : /This Mac has basic read-only scope/)).toBeVisible();
     else {
     await expect(page.getByText('Mac14,12', { exact: true })).toBeVisible(); const selected = scene === 'partial' ? 'receipts' : scene;
     const labels = { hardware: de ? 'Hardware' : 'Hardware', receipts: de ? 'Paketbelege' : 'Package receipts', processes: de ? 'Prozesse' : 'Processes', ipv4: de ? 'IPv4-Schnittstellen' : 'IPv4 interfaces', ipv6: de ? 'IPv6-Schnittstellen' : 'IPv6 interfaces' };
     await page.getByRole('tab', { name: labels[selected], exact: true }).click(); await expect(page.getByRole('button', { name: de ? 'Inventar aktualisieren' : 'Refresh inventory', exact: true })).toBeEnabled();
     const targets = { hardware: 'Mac14,12', receipts: 'com.example.fixture.editor', processes: 'fixture-init', ipv4: '192.0.2.42/24', ipv6: '2001:db8::42/64' };
     if (scene === 'partial') { await expect(page.getByText(de ? 'Teilweise' : 'Partial', { exact: true })).toBeVisible(); await expect(page.getByText('0 source rows', { exact: true })).toHaveCount(0); captureTarget = page.getByTestId('mac-inventory-scroll').getByText(de ? 'Anzahl unbekannt · Quellzugriff verweigert' : 'Count unknown · Provider access denied', { exact: true }); }
     else captureTarget = page.getByText(targets[selected], { exact: true });
     await expect(captureTarget).toBeVisible();
     }
    }
   }
   await page.evaluate(() => document.fonts.ready); if (captureTarget) await frameTarget(page, expect, captureTarget); assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)); assert.equal(errors, 0); assert.equal(state.external + state.unexpected + state.writes, 0);
   await page.screenshot({ path: path.join(output, file), fullPage: false, animations: 'disabled' }); captures.push({ ...item, sha256: hash(await readFile(path.join(output, file))), sourceDigest: compiled.sourceDigest, publicSafe: true, synthetic: true, fullPage: false });
  } finally { await context.close(); }
 }
 return { sourceInputs: compiled.sourceInputs, sourceDigest: compiled.sourceDigest, captures, disclosure, browserExecuted: true, appMounted: false, nativeAcceptance: false, actualMutationRequests: 0, requestsToRealAPI: 0 };
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
 assert(process.argv.includes('--check'), 'Use --check locally; browser capture belongs to the separately approved hosted runner.'); console.log(JSON.stringify(await check()));
}
