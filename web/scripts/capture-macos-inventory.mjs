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
const lookupSections = ['receipts', 'processes'];
export const scenes = ['overview', 'hardware', 'receipts', 'processes', 'ipv4', 'ipv6', 'partial', 'basic', 'enrollment', 'instructions', 'receipts-search', 'processes-search', 'receipts-no-match', 'processes-paging'];
export const captureMatrix = ['en', 'de'].flatMap(locale => [1440, 390].flatMap(width => scenes.map(scene => ({ locale, width, height: width === 390 ? 844 : 1100, scene, file: `macos-inventory-${scene}-${locale}-${width}.png` }))));
const hash = value => createHash('sha256').update(value).digest('hex');
async function bundle(contents, platform = 'browser') {
 const { build } = require('esbuild');
 return build({ stdin: { contents, resolveDir: path.join(root, 'web/src'), loader: 'tsx' }, absWorkingDir: root, outdir: 'web/.macos-inventory-memory-only', entryNames: 'app', bundle: true, platform, format: 'esm', jsx: 'automatic', define: { 'process.env.NODE_ENV': '"production"' }, loader: { '.woff': 'dataurl', '.woff2': 'dataurl', '.svg': 'dataurl', '.png': 'dataurl' }, write: false, metafile: true, minify: platform === 'browser', logLevel: 'silent' });
}
export async function compile() {
 const fixtures = await bundle("export * from './macos-inventory-fixture'; export {validMacInventoryPage,macProcessMatches} from './macos-inventory-types'; export {macOSFixtureList} from './enrollment-macos-fixture';", 'node');
 const data = await import(`data:text/javascript;base64,${Buffer.from(fixtures.outputFiles[0].contents).toString('base64')}`);
 const result = await bundle(`import React from 'react'; import {createRoot} from 'react-dom/client'; import './styles.css'; import {AuthBoundary} from './auth'; import {DeviceDetail} from './details'; import {EnrollmentSection} from './enrollment'; import {MacOSSourceInstructions} from './enrollment-macos'; import {setLocale} from './i18n'; setLocale(window.__MAC_INVENTORY_LOCALE__,false); createRoot(document.getElementById('root')).render(<main style={{maxWidth:1100,margin:'0 auto',padding:16}}><p role="note">SYNTHETIC · Mac inventory source UI · No endpoint actions</p><AuthBoundary>{window.__MAC_INVENTORY_SCENE__==='instructions'?<MacOSSourceInstructions renewable={false} inventory/>:window.__MAC_INVENTORY_SCENE__==='enrollment'?<EnrollmentSection onChanged={()=>{}} onDevice={()=>{}} deviceIds={[]}/>:<DeviceDetail id="${data.macInventoryDeviceId}" onClose={()=>{}} onCase={()=>{}}/>}</AuthBoundary></main>);`);
 const assets = new Map(result.outputFiles.map(file => [`/${path.basename(file.path)}`, { body: Buffer.from(file.contents), contentType: file.path.endsWith('.css') ? 'text/css' : 'text/javascript' }]));
 assets.set('/', { contentType: 'text/html', body: '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="icon" href="data:,"><link rel="stylesheet" href="/app.css"><title>Synthetic Mac inventory</title></head><body><div id="root"></div><script type="module" src="/app.js"></script></body></html>' });
 const files = [...new Set([...Object.keys(fixtures.metafile.inputs), ...Object.keys(result.metafile.inputs)].filter(file => file.startsWith('web/src/')).concat(['web/scripts/capture-macos-inventory.mjs', 'web/scripts/run-macos-inventory-ci.mjs', 'web/scripts/check-macos-inventory-evidence.mjs']))].sort();
 const sourceInputs = await Promise.all(files.map(async file => ({ file, sha256: hash(await readFile(path.join(root, file))) })));
 return { assets, data, sourceInputs, sourceDigest: hash(JSON.stringify(sourceInputs)) };
}
const lookupSection = scene => lookupSections.find(section => scene.startsWith(`${section}-`));
const deniedSection = scene => scene === 'partial' ? 'receipts' : scene.endsWith('-denied') ? lookupSection(scene) : null;
const canonicalSearch = value => typeof value === 'string' && value.length <= 256 && !/[^\x20-\x7e]/.test(value) && value === value.replace(/^ +| +$/g, '').toLowerCase();
function holdLookup(section, search) {
 let release; const wait = new Promise(resolve => { release = resolve; });
 return { section, search, wait, release, started: false, finished: false };
}
function validFixtureQuery(q, data, scene) {
 if (q === null || typeof q !== 'object' || Array.isArray(q)) return false;
 const lookup = lookupSections.includes(q.section), keys = lookup ? 'generationId,limit,offset,schemaVersion,search,section' : 'generationId,limit,offset,section';
 if (Object.keys(q).sort().join(',') !== keys || !['summary', 'hardware', ...lookupSections, 'ipv4', 'ipv6'].includes(q.section) || q.limit !== 50 || !Number.isSafeInteger(q.offset) || Object.is(q.offset, -0) || q.offset < 0 || q.generationId !== (q.section === 'summary' ? '' : data.macInventoryGeneration)) return false;
 if (q.offset !== 0 && !(scene === `${q.section}-paging` && q.offset === 50)) return false;
 return !lookup || q.schemaVersion === 'tracebolt.macos-read-inventory-query.v2' && canonicalSearch(q.search);
}
/** Extra rows are synthetic fixtures for a real production paging interaction.
 * total is every source row; matchingCount alone bounds filtered pagination. */
function fixturePage(data, scene, q) {
 const page = data.macInventoryFixture(q), denied = deniedSection(scene);
 if (scene === `${q.section}-paging`) {
  const receipts = ['com.example.fixture.helper', 'com.example.fixture.other', ...Array.from({ length: 53 }, (_, i) => `com.example.fixture.paging-${String(i).padStart(3, '0')}`)].sort();
  const processes = [{ pid: 1, parentPid: 0, accountingName: 'fixture-init', nameQuality: 'observed' }, { pid: 42, parentPid: 1, accountingName: 'fixture-agent', nameQuality: 'observed' }, ...Array.from({ length: 53 }, (_, i) => ({ pid: 1000 + i, parentPid: 1, accountingName: `fixture-page-${String(i).padStart(2, '0')}`, nameQuality: 'observed' }))];
  const all = q.section === 'receipts' ? receipts : processes;
  const matching = all.filter(row => typeof row === 'string' ? row.toLowerCase().includes(q.search) : data.macProcessMatches(row, q.search)), end = Math.min(q.offset + q.limit, matching.length);
  page.total = all.length; page.matchingCount = matching.length; page.nextOffset = end < matching.length ? end : null;
  if (q.section === 'receipts') page.receiptIds = matching.slice(q.offset, end); else page.processes = matching.slice(q.offset, end);
 }
 if (denied) {
  page.sources[denied] = { ...page.sources[denied], quality: 'denied', reason: 'macos_inventory_access_denied' }; page.sourceQuality = 'partial';
  if (q.section === denied) { page.receiptIds = []; page.processes = []; page.total = 0; page.matchingCount = 0; page.nextOffset = null; }
 }
 return page;
}
export function routeFixture(compiled, scene, state) {
 const data = compiled.data;
 const serverNow = () => typeof state.clockStarted === 'number' ? new Date(Date.parse(data.macInventoryNow) + Math.floor(performance.now() - state.clockStarted)).toISOString() : data.macInventoryNow;
 return async route => {
  const req = route.request(), url = new URL(req.url()), method = req.method(), raw = req.postData();
  const block = kind => { state[kind]++; return route.abort('blockedbyclient'); };
  if (url.origin !== origin) return block('external'); if (url.search) return block('unexpected');
  const respond = body => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });
  if (method === 'GET' && raw === null) {
   if (url.pathname === '/api/auth/session') return respond({ mode: 'lan', transport: 'https', insecureTestMode: false, transportWarning: null, authenticationRequired: true, authenticated: true, csrfToken: 'synthetic-csrf', serverNow: serverNow(), expiresAt: '2026-10-13T10:30:00Z', expiresInSeconds: 1790 });
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
   if (!validFixtureQuery(q, data, scene) || req.headers()['x-csrf-token'] !== 'synthetic-csrf') return block('unexpected');
   const page = fixturePage(data, scene, q); page.serverNow = serverNow();
   assert(data.validMacInventoryPage(page, data.macInventoryDeviceId, q)); state.privateReads++; state.queries?.push({ ...q });
   const hold = state.hold;
   if (hold && !hold.started && q.section === hold.section && q.search === hold.search) { hold.started = true; await hold.wait; const result = await respond(page); hold.finished = true; return result; }
   return respond(page);
  }
  return block('writes');
 };
}
export async function check() {
 const compiled = await compile(), state = { external: 0, unexpected: 0, writes: 0, privateReads: 0 }, handler = routeFixture(compiled, 'hardware', state);
 let response;
 const fake = (method, url, raw = null, csrf = 'synthetic-csrf') => ({ request: () => ({ method: () => method, url: () => url, postData: () => raw, headers: () => ({ 'x-csrf-token': csrf }) }), fulfill: value => { response = value; }, abort: () => {} });
 await handler(fake('POST', `${origin}/api/devices/${compiled.data.macInventoryDeviceId}/macos-inventory/query`, JSON.stringify(compiled.data.macInventoryQuery()))); assert.equal(JSON.parse(response.body).sourceQuality, 'full');
 await handler(fake('POST', `${origin}/api/macos-inventory/enrollment/invitations`, '{}')); await handler(fake('GET', 'https://real.invalid/'));
 assert.deepEqual(state, { external: 1, unexpected: 0, writes: 1, privateReads: 1 });
 const overviewState = { external: 0, unexpected: 0, writes: 0, privateReads: 0 };
 await routeFixture(compiled, 'overview', overviewState)(fake('POST', `${origin}/api/devices/${compiled.data.macInventoryDeviceId}/macos-inventory/query`, JSON.stringify(compiled.data.macInventoryQuery())));
 assert.deepEqual(overviewState, { external: 0, unexpected: 0, writes: 1, privateReads: 0 });
 // Execute the intercepted v2 protocol directly. These checks do not launch a
 // browser, listen on a port, read native sources, or establish UI acceptance.
 const data = compiled.data, endpoint = `${origin}/api/devices/${data.macInventoryDeviceId}/macos-inventory/query`;
 const lookupState = { external: 0, unexpected: 0, writes: 0, privateReads: 0, queries: [] };
 const read = async (scene, q) => {
  response = null; await routeFixture(compiled, scene, lookupState)(fake('POST', endpoint, JSON.stringify(q))); assert(response);
  const page = JSON.parse(response.body); assert(data.validMacInventoryPage(page, data.macInventoryDeviceId, q)); return page;
 };
 for (const section of lookupSections) {
  const search = section === 'receipts' ? 'editor' : 'agent', rows = page => section === 'receipts' ? page.receiptIds : page.processes;
  const query = data.macInventoryLookupQuery(section, search), found = await read(`${section}-search`, query);
  assert.equal(found.schemaVersion, 'tracebolt.macos-read-inventory-page.v2'); assert.equal(found.search, search); assert.equal(found.matchingCount, 1); assert.equal(rows(found).length, 1); assert.equal(found.total, section === 'receipts' ? 3 : 2); assert.equal(found.nextOffset, null);
  const noMatchQuery = data.macInventoryLookupQuery(section, 'missing-fixture');
  const noMatch = await read(`${section}-no-match`, noMatchQuery), denied = await read(`${section}-denied`, noMatchQuery);
  assert.equal(noMatch.sources[section].quality, 'observed'); assert.equal(noMatch.sourceQuality, 'full'); assert.equal(noMatch.total, found.total); assert.equal(noMatch.matchingCount, 0); assert.equal(rows(noMatch).length, 0);
  assert.equal(denied.sources[section].quality, 'denied'); assert.equal(denied.sourceQuality, 'partial'); assert.equal(denied.total, 0); assert.equal(denied.matchingCount, 0); assert.equal(rows(denied).length, 0);
  const cleared = await read(`${section}-clear`, data.macInventoryLookupQuery(section)); assert.equal(cleared.search, ''); assert.equal(cleared.matchingCount, cleared.total); assert.equal(rows(cleared).length, cleared.total);
  const pagingSearch = section === 'receipts' ? 'paging' : 'fixture-page', first = await read(`${section}-paging`, data.macInventoryLookupQuery(section, pagingSearch)), second = await read(`${section}-paging`, data.macInventoryLookupQuery(section, pagingSearch, first.nextOffset));
  assert.equal(first.total, 55); assert.equal(first.matchingCount, 53); assert.equal(rows(first).length, 50); assert.equal(first.nextOffset, 50);
  assert.equal(second.total, 55); assert.equal(second.matchingCount, 53); assert.equal(rows(second).length, 3); assert.equal(second.offset, 50); assert.equal(second.nextOffset, null); assert.equal(second.search, first.search); assert.equal(second.generationId, first.generationId);
  assert.equal(rows(second)[0]?.accountingName ?? rows(second)[0], section === 'receipts' ? 'com.example.fixture.paging-050' : 'fixture-page-50');
  const all = await read(`${section}-paging`, data.macInventoryLookupQuery(section)); assert.equal(all.matchingCount, 55); assert.equal(all.total, 55);
  const summary = await read(`${section}-denied`, data.macInventoryQuery()); assert.equal(summary.schemaVersion, 'tracebolt.macos-read-inventory-page.v1'); assert.equal(summary.sources[section].quality, 'denied'); assert(!Object.hasOwn(summary, 'search')); assert(!Object.hasOwn(summary, 'matchingCount'));
 }
 assert.equal(lookupState.privateReads, 16); assert.equal(lookupState.external + lookupState.unexpected + lookupState.writes, 0);
 const valid = data.macInventoryLookupQuery(), invalid = [null, [], {}, data.macInventoryQuery('receipts'), { ...valid, schemaVersion: 'tracebolt.macos-read-inventory-query.v1' }, { ...valid, search: 'EDITOR' }, { ...valid, search: ' editor ' }, { ...valid, search: '\t' }, { ...valid, search: 'trailing\n' }, { ...valid, search: 'é' }, { ...valid, search: 'a'.repeat(257) }, { ...valid, extra: true }, { ...valid, limit: 100 }, { ...valid, offset: 50 }, { ...valid, offset: 1 }, { ...valid, generationId: `sample_${'b'.repeat(32)}` }, { ...valid, section: 'hardware' }];
 for (const q of invalid) { response = null; await routeFixture(compiled, 'receipts-search', lookupState)(fake('POST', endpoint, JSON.stringify(q))); assert.equal(response, null); }
 response = null; await routeFixture(compiled, 'receipts-search', lookupState)(fake('POST', endpoint, JSON.stringify(valid), 'wrong-csrf')); assert.equal(response, null);
 await routeFixture(compiled, 'receipts-search', lookupState)(fake('POST', `${endpoint}?search=editor`, JSON.stringify(valid)));
 assert.equal(lookupState.unexpected, invalid.length + 2); assert.equal(lookupState.privateReads, 16);
 assert(validFixtureQuery({ ...valid, search: 'a'.repeat(256) }, data, 'receipts-search'));
 assert(!validFixtureQuery({ ...valid, offset: -0 }, data, 'receipts-search'));
 const clockState = { external: 0, unexpected: 0, writes: 0, privateReads: 0, clockStarted: performance.now() - 2000 };
 await routeFixture(compiled, 'hardware', clockState)(fake('POST', endpoint, JSON.stringify(data.macInventoryQuery('hardware'))));
 const advanced = JSON.parse(response.body); assert(Date.parse(advanced.serverNow) - Date.parse(data.macInventoryNow) >= 2000); assert.equal(advanced.collectedAt, '2026-10-13T10:00:00Z'); assert.equal(advanced.expiresAt, '2026-10-14T10:00:00Z');
 const heldState = { external: 0, unexpected: 0, writes: 0, privateReads: 0, hold: holdLookup('receipts', 'editor') }, heldRoute = routeFixture(compiled, 'receipts-search', heldState);
 response = null; const pending = heldRoute(fake('POST', endpoint, JSON.stringify(data.macInventoryLookupQuery('receipts', 'editor')))); assert(heldState.hold.started); assert.equal(response, null);
 await heldRoute(fake('POST', endpoint, JSON.stringify(data.macInventoryLookupQuery('receipts')))); assert.equal(JSON.parse(response.body).matchingCount, 3);
 heldState.hold.release(); await pending; assert(heldState.hold.finished); assert.equal(JSON.parse(response.body).matchingCount, 1); assert.equal(heldState.privateReads, 2); assert.equal(heldState.external + heldState.unexpected + heldState.writes, 0);
 assert.equal(scenes.length, 14); assert.equal(captureMatrix.length, 56); assert.equal(new Set(captureMatrix.map(item => item.file)).size, captureMatrix.length);
 // Geometry guard unit checks use plain objects only, never a browser or DOM.
 let centered = false;
 const fixtureTarget = box => ({ evaluate: fn => fn({ scrollIntoView: options => { centered = options.block === 'center' && options.inline === 'nearest'; } }), boundingBox: async () => box });
 const fixturePage = { viewportSize: () => ({ width: 390, height: 844 }) }, fixtureExpect = () => ({ toBeInViewport: async options => assert.equal(options.ratio, 0.95) });
 await frameTarget(fixturePage, fixtureExpect, fixtureTarget({ x: 20, y: 400, width: 180, height: 24 })); assert(centered);
 await assert.rejects(frameTarget(fixturePage, fixtureExpect, fixtureTarget({ x: 20, y: 850, width: 180, height: 24 })));
 await assert.rejects(frameTarget(fixturePage, fixtureExpect, fixtureTarget({ x: 350, y: 400, width: 180, height: 24 })));
 const boxes = [{ x: 20, y: 900, width: 240, height: 24 }, { x: 20, y: 1200, width: 240, height: 40 }];
 const lookupFrame = { ...fixturePage, evaluate: async (_fn, delta) => { boxes.forEach(box => { box.y -= delta; }); } };
 await frameLookup(lookupFrame, fixtureExpect, boxes.map(fixtureTarget));
 await assert.rejects(frameLookup(lookupFrame, fixtureExpect, [fixtureTarget({ x: 20, y: 0, width: 240, height: 24 }), fixtureTarget({ x: 20, y: 1000, width: 240, height: 40 })]));
 return { sourceDigest: compiled.sourceDigest, scenes: scenes.length, screenshots: captureMatrix.length, browserExecuted: false, nativeAcceptance: false, disclosure };
}
/** A positive DOM visibility result alone does not prove the selected evidence
 * appears inside the fixed screenshot crop, especially on narrow screens. */
async function frameTarget(page, expect, target) {
 await target.evaluate(element => element.scrollIntoView({ block: 'center', inline: 'nearest', behavior: 'instant' }));
 await assertFramed(page, expect, target);
}
async function assertFramed(page, expect, target) {
 await expect(target).toBeInViewport({ ratio: 0.95 });
 const box = await target.boundingBox(), viewport = page.viewportSize();
 assert(box && viewport && box.width >= 16 && box.height >= 12);
 const visibleWidth = Math.max(0, Math.min(viewport.width, box.x + box.width) - Math.max(0, box.x));
 const visibleHeight = Math.max(0, Math.min(viewport.height, box.y + box.height) - Math.max(0, box.y));
 assert(visibleWidth >= box.width * 0.95 && visibleHeight >= box.height * 0.95, 'Selected synthetic evidence must be inside the screenshot crop.');
}
async function frameLookup(page, expect, targets) {
 // Keep the real input, count and result (including paging) in one fixed crop.
 // Only document scrolling is allowed; do not restyle or hide production UI.
 const boxes = await Promise.all(targets.map(target => target.boundingBox())), viewport = page.viewportSize();
 assert(viewport && boxes.length && boxes.every(Boolean));
 const top = Math.min(...boxes.map(box => box.y)), bottom = Math.max(...boxes.map(box => box.y + box.height));
 assert(bottom - top <= viewport.height - 16, 'Lookup evidence must fit the declared viewport without changing production layout.');
 await page.evaluate(delta => window.scrollBy({ top: delta, behavior: 'instant' }), (top + bottom - viewport.height) / 2);
 for (const target of targets) await assertFramed(page, expect, target);
}
async function exerciseLookup(page, expect, data, state, section, scene, de) {
 const input = page.getByLabel(section === 'receipts' ? de ? 'Belege suchen' : 'Find receipts' : de ? 'Prozesse suchen' : 'Find processes', { exact: true });
 const controls = page.getByTestId('mac-lookup-controls'), apply = controls.getByRole('button', { name: de ? 'Anwenden' : 'Apply', exact: true }), clear = controls.getByRole('button', { name: de ? 'Leeren' : 'Clear', exact: true });
 const table = page.getByTestId('mac-inventory-scroll'), count = page.getByTestId('mac-lookup-count');
 const noMatch = table.getByText(de ? 'Keine Treffer in dieser erfassten Quelle.' : 'No matches in this captured source.', { exact: true });
 const paging = scene === `${section}-paging`, total = paging ? 55 : section === 'receipts' ? 3 : 2;
 const countText = matching => de ? `${matching} Treffer · ${total} Quellzeilen` : `${matching} matches · ${total} source rows`;
 const query = async (search, offset = 0) => { await expect.poll(() => state.queries.at(-1)).toEqual(data.macInventoryLookupQuery(section, search, offset)); await expect(page.getByRole('button', { name: de ? 'Inventar aktualisieren' : 'Refresh inventory', exact: true })).toBeEnabled(); };
 const fillDraft = async value => { const before = state.privateReads; await input.fill(value); assert.equal(state.privateReads, before, 'Editing a draft must not send a private query.'); };
 const applySearch = async value => { await fillDraft(value); await apply.click(); await query(value.replace(/^ +| +$/g, '').toLowerCase()); };
 const clearSearch = async () => { await clear.click(); await query(''); await expect(input).toHaveValue(''); await expect(count).toHaveText(countText(total)); };
 await query(''); await expect(input).toBeVisible(); await expect(count).toHaveText(countText(total));
 // Observed zero matches must remain distinct from the denied-source scene.
 await applySearch(' MISSING-FIXTURE '); await expect(noMatch).toBeVisible(); await expect(count).toHaveText(countText(0));
 await expect(table.getByText(de ? 'Anzahl unbekannt · Quellzugriff verweigert' : 'Count unknown · Provider access denied', { exact: true })).toHaveCount(0);
 await clearSearch(); await expect(noMatch).toHaveCount(0);
 if (scene.endsWith('-no-match')) {
  await applySearch('missing-fixture'); await expect(noMatch).toBeVisible(); await expect(count).toHaveText(countText(0)); return [input, count, noMatch];
 }
 if (scene === 'receipts-search') {
  // Hold the actual bounded-client read, clear while it is pending, then release
  // its now-superseded response. The production cancellation guard owns this race.
  state.hold = holdLookup(section, 'editor'); await fillDraft('editor'); await apply.click(); await expect.poll(() => state.hold.started).toBe(true);
  await clearSearch(); state.hold.release(); await expect.poll(() => state.hold.finished).toBe(true);
  await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
  await expect(input).toHaveValue(''); await expect(count).toHaveText(countText(total)); await expect(table.getByText('com.example.fixture.helper', { exact: true })).toBeVisible();
 }
 const search = paging ? 'fixture-page' : section === 'receipts' ? 'editor' : 'agent';
 await applySearch(` ${search.toUpperCase()} `); await expect(count).toHaveText(countText(paging ? 53 : 1));
 if (!paging) {
  const target = table.getByText(section === 'receipts' ? 'com.example.fixture.editor' : 'fixture-agent', { exact: true });
  await expect(target).toBeVisible(); await fillDraft('unapplied-draft'); await expect(target).toBeVisible(); await fillDraft(search);
  return [input, count, target];
 }
 const next = page.getByRole('button', { name: de ? 'Nächste Seite' : 'Next page', exact: true }), previous = page.getByRole('button', { name: de ? 'Vorherige Seite' : 'Previous page', exact: true });
 const pagination = page.getByRole('navigation', { name: de ? 'Inventarseiten' : 'Inventory pages', exact: true });
 await fillDraft('fixture-agent'); await next.click(); await query(search, 50);
 await expect(pagination).toContainText('51–53 / 53'); await expect(previous).toBeEnabled(); await expect(next).toBeDisabled();
 // Clear a later page, reset both query fields and offset, then repeat the same
 // applied filter. Next/previous must use its 53 matches, never all 55 rows.
 await clearSearch(); await expect(pagination).toContainText('1–50 / 55'); await expect(previous).toBeDisabled();
 await applySearch(search); await next.click(); await query(search, 50); await previous.click(); await query(search); await next.click(); await query(search, 50);
 await expect(count).toHaveText(countText(53)); await expect(pagination).toContainText('51–53 / 53'); await expect(next).toBeDisabled();
 const target = table.getByText('fixture-page-50', { exact: true }); await expect(target).toBeVisible();
 return [input, count, target, pagination];
}
export async function capture({ browser, expect, output }) {
 const compiled = await compile(), captures = []; await mkdir(output, { recursive: true });
 for (const item of captureMatrix) {
  const { locale, width, height, scene, file } = item, de = locale === 'de', state = { external: 0, unexpected: 0, writes: 0, privateReads: 0, queries: [], clockStarted: performance.now() };
  const context = await browser.newContext({ viewport: { width, height }, reducedMotion: 'reduce', locale: de ? 'de-DE' : 'en-US', serviceWorkers: 'block' });
  try {
   await context.route('**/*', routeFixture(compiled, scene, state)); await context.addInitScript(({ locale, scene }) => { window.__MAC_INVENTORY_LOCALE__ = locale; window.__MAC_INVENTORY_SCENE__ = scene; }, { locale, scene });
   const page = await context.newPage(); let errors = 0, captureTarget = null, lookupTargets = null; page.on('pageerror', () => errors++); await page.goto(origin + '/');
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
     await expect(page.getByText('Mac14,12', { exact: true })).toBeVisible(); const selected = scene === 'partial' ? 'receipts' : lookupSection(scene) ?? scene;
     const labels = { hardware: de ? 'Hardware' : 'Hardware', receipts: de ? 'Paketbelege' : 'Package receipts', processes: de ? 'Prozesse' : 'Processes', ipv4: de ? 'IPv4-Schnittstellen' : 'IPv4 interfaces', ipv6: de ? 'IPv6-Schnittstellen' : 'IPv6 interfaces' };
     await page.getByRole('tab', { name: labels[selected], exact: true }).click(); await expect(page.getByRole('button', { name: de ? 'Inventar aktualisieren' : 'Refresh inventory', exact: true })).toBeEnabled();
     const targets = { hardware: 'Mac14,12', receipts: 'com.example.fixture.editor', processes: 'fixture-init', ipv4: '192.0.2.42/24', ipv6: '2001:db8::42/64' };
     if (lookupSection(scene)) lookupTargets = await exerciseLookup(page, expect, compiled.data, state, selected, scene, de);
     else if (scene === 'partial') { await expect(page.getByText(de ? 'Teilweise' : 'Partial', { exact: true })).toBeVisible(); await expect(page.getByText(de ? '0 Treffer · 0 Quellzeilen' : '0 matches · 0 source rows', { exact: true })).toHaveCount(0); captureTarget = page.getByTestId('mac-inventory-scroll').getByText(de ? 'Anzahl unbekannt · Quellzugriff verweigert' : 'Count unknown · Provider access denied', { exact: true }); }
     else captureTarget = page.getByText(targets[selected], { exact: true });
     if (captureTarget) await expect(captureTarget).toBeVisible();
     }
    }
   }
   await page.evaluate(() => document.fonts.ready); if (lookupTargets) await frameLookup(page, expect, lookupTargets); else if (captureTarget) await frameTarget(page, expect, captureTarget); assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)); assert.equal(errors, 0); assert.equal(state.external + state.unexpected + state.writes, 0);
   await page.screenshot({ path: path.join(output, file), fullPage: false, animations: 'disabled' }); captures.push({ ...item, sha256: hash(await readFile(path.join(output, file))), sourceDigest: compiled.sourceDigest, publicSafe: true, synthetic: true, fullPage: false });
  } finally { state.hold?.release(); await context.close(); }
 }
 return { sourceInputs: compiled.sourceInputs, sourceDigest: compiled.sourceDigest, captures, disclosure, browserExecuted: true, appMounted: false, nativeAcceptance: false, actualMutationRequests: 0, requestsToRealAPI: 0 };
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
 assert(process.argv.includes('--check'), 'Use --check locally; browser capture belongs to the separately approved hosted runner.'); console.log(JSON.stringify(await check()));
}
