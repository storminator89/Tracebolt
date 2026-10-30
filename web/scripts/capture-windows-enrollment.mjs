/** Hosted-only Windows created-stage captures. --check never launches a browser. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { mkdir, realpath, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { boundedRegular, captureMatrix, diagnostic, disclosure, origin, publicSafeFailures, requireHosted, scenes, validateDialogPNG, viewports } from './windows-enrollment-contract.mjs';
import { approvedBody, creation, csrf, invitation, listing, now, record, secret } from './windows-enrollment-fixtures.mjs';
import { createCaptureGuard } from './windows-enrollment-capture-guard.mjs';
import { runVisibilityControls } from './windows-enrollment-visibility-diagnostics.mjs';
export { captureMatrix, disclosure, origin, scenes, viewports };
const root = fileURLToPath(new URL('../../', import.meta.url)), require = createRequire(new URL('../package.json', import.meta.url));
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
export function compilerConfiguration(bytes) {
 const value = JSON.parse(bytes);
 assert(value && !Array.isArray(value) && !Object.hasOwn(value, 'extends') && value.compilerOptions && typeof value.compilerOptions === 'object');
 return value;
}
export const fontWeights = Object.freeze([400, 500, 600, 700]);
export async function compile() {
 const { build } = require('esbuild'), loaded = new Map(), dependencies = new Map();
 const dependencyRoot = await realpath(path.join(root, 'web/node_modules'));
 const fontRoot = path.join(dependencyRoot, '@fontsource/inter');
 const include = (map, file, bytes) => { const digest = hash(bytes); assert(!map.has(file) || map.get(file) === digest, 'Compiler input changed'); map.set(file, digest); };
 const readSource = async file => { const bytes = await boundedRegular(path.join(root, file), file === 'web/tsconfig.json' ? 65536 : 4 << 20); include(loaded, file, bytes); return bytes; };
 // Pass the exact bounded config explicitly. Inheritance is refused, so esbuild
 // cannot silently auto-discover an unrecorded parent or extended configuration.
 const configBytes = await readSource('web/tsconfig.json'), tsconfigRaw = compilerConfiguration(configBytes);
 const main = (await readSource('web/src/main.tsx')).toString('utf8');
 const fontImports = [...main.matchAll(/^import '(@fontsource\/inter\/latin-(?:400|500|600|700)\.css)';$/gm)].map(match => match[1]);
 assert.deepEqual(fontImports, fontWeights.map(weight => `@fontsource/inter/latin-${weight}.css`));
 const packageJSON = JSON.parse(await readSource('web/package.json')), lock = JSON.parse(await readSource('web/package-lock.json'));
 const fontPackage = await boundedRegular(path.join(fontRoot, 'package.json'), 1 << 20);
 assert.equal(JSON.parse(fontPackage).version, packageJSON.dependencies['@fontsource/inter']);
 assert.equal(lock.packages['node_modules/@fontsource/inter'].version, packageJSON.dependencies['@fontsource/inter']);
 include(dependencies, 'web/node_modules/@fontsource/inter/package.json', fontPackage);
 const plugin = { name: 'bounded-source-inputs', setup(build) {
  build.onLoad({ filter: /.*/, namespace: 'file' }, async args => {
   const file = path.resolve(args.path), inSource = file.startsWith(path.join(root, 'web/src') + path.sep), inDependencies = file.startsWith(dependencyRoot + path.sep);
   assert(inSource || inDependencies, 'Unexpected compiler input root');
   const bytes = await boundedRegular(file, 4 << 20);
   if (inSource) include(loaded, path.relative(root, file).split(path.sep).join('/'), bytes);
   if (file.startsWith(fontRoot + path.sep)) include(dependencies, 'web/node_modules/@fontsource/inter/' + path.relative(fontRoot, file).split(path.sep).join('/'), bytes);
   const loader = { '.ts': 'ts', '.tsx': 'tsx', '.js': 'js', '.mjs': 'js', '.cjs': 'js', '.json': 'json', '.css': 'css', '.woff': 'dataurl', '.woff2': 'dataurl', '.svg': 'dataurl', '.png': 'dataurl' }[path.extname(file)];
   assert(loader, 'Unsupported compiler input type'); return { contents: bytes, loader, resolveDir: path.dirname(file) };
  });
 } };
 const bundle = (contents, platform = 'browser') => build({ stdin: { contents, resolveDir: path.join(root, 'web/src'), loader: 'tsx' }, absWorkingDir: root, outdir: 'web/.windows-enrollment-memory-only', entryNames: 'app', bundle: true, platform, format: 'esm', jsx: 'automatic', tsconfigRaw, define: { 'process.env.NODE_ENV': '"production"', ...(platform === 'node' ? { 'window.location.origin': JSON.stringify(origin) } : {}) }, plugins: [plugin], write: false, metafile: true, minify: platform === 'browser', logLevel: 'silent' });
 const validators = await bundle("export { validEnrollmentList, validSnapshot, publicBootstrap } from './enrollment-types';", 'node');
 const data = await import(`data:text/javascript;base64,${Buffer.from(validators.outputFiles[0].contents).toString('base64')}`);
 const result = await bundle(`import React from 'react'; import {createRoot} from 'react-dom/client'; ${fontImports.map(file => `import '${file}';`).join(' ')} import './styles.css'; import {EnrollmentSection} from './enrollment'; import {setLocale} from './i18n'; setLocale(window.__WINDOWS_LOCALE__,false); createRoot(document.getElementById('root')).render(<main style={{maxWidth:1050,margin:'0 auto',padding:16}}><p role="note">SYNTHETIC · Windows setup instructions · No endpoint actions</p><EnrollmentSection onChanged={()=>{}} onDevice={()=>{}} deviceIds={[]}/></main>);`);
 const assets = new Map(result.outputFiles.map(file => [`/${path.basename(file.path)}`, { body: Buffer.from(file.contents), contentType: file.path.endsWith('.css') ? 'text/css' : 'text/javascript' }]));
 assert(assets.has('/app.js') && assets.has('/app.css'));
 assets.set('/', { contentType: 'text/html', body: '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="icon" href="data:,"><link rel="stylesheet" href="/app.css"><title>Synthetic Windows enrollment</title></head><body><div id="root"></div><script type="module" src="/app.js"></script></body></html>' });
 for (const file of ['web/scripts/capture-windows-enrollment.mjs', 'web/scripts/windows-enrollment-contract.mjs', 'web/scripts/windows-enrollment-fixtures.mjs', 'web/scripts/windows-enrollment-capture.node.mjs', 'web/scripts/run-windows-enrollment-ci.mjs', 'web/scripts/check-windows-enrollment-evidence.mjs', 'web/scripts/windows-enrollment-visibility-controls.mjs', 'web/scripts/windows-enrollment-visibility-diagnostics.mjs', 'web/scripts/windows-enrollment-capture-guard.mjs', 'web/scripts/windows-enrollment-capture-guard.node.mjs', '.github/workflows/pr-checks.yml']) await readSource(file);
 const rows = map => [...map].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([file, sha256]) => ({ file, sha256 }));
 const sourceInputs = rows(loaded), dependencyInputs = rows(dependencies);
 assert.deepEqual(dependencyInputs.map(row => row.file).sort(), ['web/node_modules/@fontsource/inter/package.json', ...fontWeights.flatMap(weight => [`web/node_modules/@fontsource/inter/latin-${weight}.css`, `web/node_modules/@fontsource/inter/files/inter-latin-${weight}-normal.woff`, `web/node_modules/@fontsource/inter/files/inter-latin-${weight}-normal.woff2`])].sort());
 return { assets, data, sourceInputs, dependencyInputs, sourceDigest: hash(JSON.stringify({ sourceInputs, dependencyInputs })) };
}
export const routeState = () => ({ external: 0, unexpected: 0, writes: 0, reads: 0, csrfReads: 0, syntheticCreates: 0 });
export function routeFixture(compiled, state) {
 const created = creation(origin); let items = [];
 return async route => {
  const request = route.request(), url = new URL(request.url()), method = request.method(), raw = request.postData(), headers = request.headers();
  const blocked = kind => { state[kind]++; return route.abort('blockedbyclient'); };
  if (url.origin !== origin) return blocked('external');
  if (url.search || url.hash || headers.authorization || headers.cookie) return blocked('unexpected');
  const respond = value => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(value) });
  if (method === 'GET' && raw === null) {
   if (url.pathname === '/api/session') { state.csrfReads++; return respond({ csrfToken: csrf }); }
   if (url.pathname === '/api/enrollment') return respond({ schemaVersion: 'tracebolt.enrollment-operator.v2', serverNow: now, enabled: true, platforms: ['linux'], recordLimit: 25, items: [] });
   if (url.pathname === '/api/windows/enrollment') { state.reads++; return respond(listing(items)); }
   const asset = compiled.assets.get(url.pathname); if (asset) return route.fulfill({ status: 200, ...asset });
   return blocked('unexpected');
  }
  if (method === 'POST' && url.pathname === '/api/windows/enrollment/invitations') {
   let body; try { body = JSON.parse(raw); } catch { return blocked('unexpected'); }
   if (!body || Array.isArray(body) || !/^request_[a-f0-9]{32}$/.test(body.requestId) || raw !== approvedBody(body.requestId) || headers['x-csrf-token'] !== csrf || headers['content-type'] !== 'application/json' || headers.origin !== origin || state.csrfReads !== 1 || items.length) return blocked('unexpected');
   state.syntheticCreates++; created.snapshot.createRequestID = body.requestId; items = [created.snapshot]; return respond(created);
  }
  return blocked('writes');
 };
}
export async function check() {
 const compiled = await compile(), created = creation(origin);
 assert(compiled.data.validEnrollmentList(listing(), 'windows')); assert(compiled.data.validSnapshot(record(origin)));
 assert.deepEqual(compiled.data.publicBootstrap(created.bootstrap, created.snapshot, secret), created.bootstrap);
 assert.equal(secret.length, 43); assert.equal(captureMatrix.length, 8);
 return { sourceDigest: compiled.sourceDigest, scenes: scenes.length, screenshots: captureMatrix.length, browserExecuted: false, nativeAcceptance: false, disclosure };
}
/** The captured production dialog must contain no secret or rendered raw fixture
 * identity/bootstrap value. Background fixture IDs are not private identities. */
export async function assertPublicSafe(page, dialog, expect, mark = () => {}) {
 mark('public-safe-elements');
 await expect(page.locator('.enrollment-secret, .enrollment-fingerprint, .enrollment-comparison')).toHaveCount(0);
 mark('public-safe-inspection');
 const failure = await dialog.evaluate((dialog, { secret, invitation }) => {
  const identifier = /(?:invite|manager|request|claim|agent)_[a-f0-9]{32}|(?:ab){32}|(?:12ab){8}/;
  // Range geometry can force layout inside a native closed disclosure without
  // enabling paint. Only identifier text with independent own-box evidence
  // and a native hidden result may be suppressed; secrets remain rejected.
  const walker = document.createTreeWalker(dialog, NodeFilter.SHOW_TEXT); let node;
  while ((node = walker.nextNode())) {
   if (node.textContent.includes(secret)) return 'public-safe-text';
   const parent = node.parentElement;
   if (!parent || parent.closest('script,style')) continue;
   const range = document.createRange(); range.selectNodeContents(node);
   if ([...range.getClientRects()].some(rect => rect.width > 0 && rect.height > 0) && identifier.test(node.textContent)) {
    let hiddenIdentifier = false;
    for (let ancestor = parent; ancestor; ancestor = ancestor.parentElement) {
     if (ancestor.matches('details:not([open])') && !ancestor.querySelector(':scope > summary')?.contains(parent)) {
      // A native false result alone is ambiguous for display:contents. Require
      // a finite positive box on this exact parent, then the native check, in
      // this synchronous inspection. No summary/open/fixture-specific bypass.
      try {
       const check = Element.prototype.checkVisibility;
       if (typeof check !== 'function') return 'public-safe-text-closed-details-native-unavailable';
       const box = Element.prototype.getClientRects;
       if (typeof box !== 'function') return 'public-safe-text-closed-details-native-error';
       const ownBox = [...box.call(parent)].some(rect => [rect.x, rect.y, rect.width, rect.height].every(Number.isFinite) && rect.width > 0 && rect.height > 0);
       const native = check.call(parent);
       if (ownBox && native === false) { hiddenIdentifier = true; break; }
       if (native === true) return 'public-safe-text-closed-details-native-true';
       if (native === false) return 'public-safe-text-closed-details-native-false';
      } catch {}
      return 'public-safe-text-closed-details-native-error';
     }
    }
    if (!hiddenIdentifier) return 'public-safe-text';
   }
  }
  if ([...document.querySelectorAll('input')].some(input => input.value.includes(secret) || identifier.test(input.value))) return 'public-safe-inputs';
  if (location.href.includes(secret) || location.href.includes(invitation)) return 'public-safe-location';
  if (JSON.stringify({ ...localStorage, ...sessionStorage }).includes(secret)) return 'public-safe-storage';
  return null;
 }, { secret, invitation });
 assert(failure === null || publicSafeFailures.includes(failure), 'Invalid public-safety diagnostic');
 if (failure !== null) mark(failure);
 assert(failure === null, 'Unsafe public capture surface');
}
/** Keep screenshot bytes in memory until the complete guarded pre/post
 * inspection succeeds. The guard never makes the DOM check/screenshot atomic. */
export async function capturePublicPNG(page, dialog, expect, mark = () => {}) {
 mark('capture-guard'); const guard = await dialog.evaluateHandle(createCaptureGuard);
 try {
  mark('public-safe'); await assertPublicSafe(page, dialog, expect, mark);
  mark('capture-guard-pre'); assert(await guard.evaluate(value => value.check()) === true, 'Unstable synthetic capture');
  // Default caret hiding and animation disabling mutate screenshot preparation.
  // Keep production state untouched; the guard rejects live animations instead.
  mark('screenshot'); const bytes = await dialog.screenshot({ animations: 'allow', caret: 'initial', timeout: 10000 });
  mark('public-safe-post'); await assertPublicSafe(page, dialog, expect, mark);
  mark('capture-guard-post'); assert(await guard.evaluate(value => value.check()) === true, 'Unstable synthetic capture');
  return bytes;
 } finally {
  try { await guard.evaluate(value => value.dispose()); } finally { await guard.dispose(); }
 }
}
export async function capture({ browser, expect, output, onStage = () => {} }) {
 requireHosted(); const mark = (stage, index = null) => onStage(diagnostic(stage, index));
 mark('compile'); const compiled = await compile(), captures = [];
 const visibilityControls = await runVisibilityControls({ browser, expect, assertPublicSafe, mark });
 mark('prepare-output'); await mkdir(output, { recursive: true });
 for (const [viewIndex, { locale, width, height }] of viewports.entries()) {
  const index = viewIndex * scenes.length, de = locale === 'de', state = routeState(); let runtimeErrors = 0, completed = false;
  mark('new-context', index); const context = await browser.newContext({ viewport: { width, height }, reducedMotion: 'reduce', locale: de ? 'de-DE' : 'en-US', serviceWorkers: 'block' });
  try {
   mark('route', index); await context.route('**/*', routeFixture(compiled, state)); await context.addInitScript(locale => { window.__WINDOWS_LOCALE__ = locale; }, locale);
   mark('new-page', index); const page = await context.newPage(); page.on('pageerror', () => { runtimeErrors++; });
   mark('navigate', index); await page.goto(origin + '/');
   mark('initial-status', index); const refresh = page.getByRole('button', { name: de ? 'Enrollment-Status aktualisieren' : 'Refresh enrollment status', exact: true }); await expect(refresh).toBeEnabled();
   mark('select-windows', index); await page.getByRole('combobox').selectOption('windows');
   const add = page.getByRole('button', { name: de ? 'Gerät hinzufügen' : 'Add device', exact: true }); await expect(add).toBeEnabled();
   mark('open-create', index); await add.click(); const dialog = page.getByRole('dialog', { name: de ? 'Gerät hinzufügen' : 'Add device', exact: true });
   mark('consent', index); const consent = dialog.getByRole('checkbox', { name: de ? 'Ich bestätige diese Windows-Inventarerfassung für das neue Gerät.' : 'I acknowledge this Windows inventory collection for the new device.', exact: true });
   const create = dialog.getByRole('button', { name: de ? 'Einladung erstellen' : 'Create invitation', exact: true });
   await expect(dialog.getByRole('checkbox')).toHaveCount(1); await expect(consent).not.toBeChecked(); await expect(create).toBeDisabled(); assert.equal(state.syntheticCreates, 0);
   await expect(dialog).toContainText('48 KiB'); await consent.check(); await expect(create).toBeEnabled();
   mark('submit-create', index); await create.click(); const input = dialog.getByLabel(de ? 'Einmaliger Einladungsschlüssel' : 'One-time invitation secret', { exact: true });
   mark('secret-masked', index); await expect(input).toHaveAttribute('type', 'password'); assert.equal(state.syntheticCreates, 1);
   mark('interrupt-clear', index); await page.evaluate(() => { window.dispatchEvent(new Event('pagehide')); window.dispatchEvent(new Event('pageshow')); }); await expect(input).toHaveCount(0);
   mark('refresh-restored', index); await expect(refresh).toBeEnabled(); await expect(dialog).toContainText('windows-inventory-v1');
   mark('instructions', index); const instructions = dialog.locator('.enrollment-windows-install'), heading = instructions.getByRole('heading'), paragraphs = instructions.locator('p'), release = paragraphs.last();
   await expect(instructions).toBeVisible(); await expect(paragraphs).toHaveCount(2);
   await expect(instructions).toContainText(de ? 'die zu diesem Manager und dem gewählten Profil passt' : 'matches this manager and the selected profile');
   await expect(instructions).toContainText(de ? 'Diese Dashboard-Bestätigung ersetzt nicht die lokale Bereichsfreigabe in Setup.' : 'This dashboard acknowledgement does not replace Setup’s local scope approval.');
   await expect(release).toContainText(de ? 'Die unsignierte Windows-preview.3' : 'Unsigned Windows preview.3 is published');
   await expect(release).toContainText(de ? 'Diese Seite bietet keinen verifizierten Installer-Download oder Download-Befehl.' : 'This page does not provide a verified installer download or command.');
   await expect(instructions).not.toContainText(de ? 'fünf lokalen Lesebereichen' : 'five local read scopes');
   await expect(dialog.locator('.enrollment-public-command')).toHaveCount(0); await expect(dialog.getByRole('link')).toHaveCount(0);
   mark('fonts', index);
   const loadedFonts = await page.evaluate(async weights => {
    await Promise.all(weights.map(weight => document.fonts.load(`${weight} 12px Inter`, 'Windows Geräte'))); await document.fonts.ready;
    const sample = document.querySelector('.enrollment-windows-install p');
    return sample && getComputedStyle(sample).fontFamily.split(',')[0].trim().replace(/["']/g, '') === 'Inter' && weights.every(weight => document.fonts.check(`${weight} 12px Inter`, 'Windows Geräte') && [...document.fonts].some(face => face.family.replace(/["']/g, '') === 'Inter' && face.weight === String(weight) && face.status === 'loaded'));
   }, fontWeights); assert(loadedFonts, 'Production Inter faces were not loaded');
   for (const [sceneIndex, scene] of scenes.entries()) {
    const matrixIndex = index + sceneIndex, row = captureMatrix[matrixIndex], target = scene === 'instructions' ? heading : release;
    mark('scroll', matrixIndex);
    // Scroll only the production dialog, not the document or a replacement UI.
    await target.evaluate(element => { const dialog = element.closest('[role="dialog"]'); if (!dialog) throw new Error('Missing dialog'); const top = element.getBoundingClientRect().top - dialog.getBoundingClientRect().top + dialog.scrollTop; dialog.scrollTo({ top: Math.max(0, top - 24), behavior: 'instant' }); });
    await expect(target).toBeInViewport({ ratio: 1 });
    mark('no-overflow', matrixIndex); assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
    const bytes = await capturePublicPNG(page, dialog, expect, stage => mark(stage, matrixIndex));
    mark('runtime-errors', matrixIndex); assert.equal(runtimeErrors, 0);
    mark('route-boundary', matrixIndex); assert.equal(state.external + state.unexpected + state.writes, 0); assert.equal(state.syntheticCreates, 1); assert.equal(state.csrfReads, 1);
    mark('image-hash', matrixIndex); const dimensions = validateDialogPNG(bytes, width, height);
    mark('persist-image', matrixIndex); await writeFile(path.join(output, row.file), bytes, { flag: 'wx' });
    captures.push({ ...row, synthetic: true, publicSafe: true, fullPage: false, captureScope: 'production-dialog', imageWidth: dimensions.width, imageHeight: dimensions.height, sha256: hash(bytes), sourceDigest: compiled.sourceDigest, syntheticCreates: 1, csrfReads: 1, productionFontsLoaded: true });
   }
   completed = true;
  } finally { if (completed) mark('close-context', index); await context.close(); }
 }
 return { sourceInputs: compiled.sourceInputs, dependencyInputs: compiled.dependencyInputs, sourceDigest: compiled.sourceDigest, captures, visibilityControls, disclosure, browserExecuted: true, appMounted: false, nativeAcceptance: false, actualMutationRequests: 0, requestsToRealAPI: 0 };
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
 assert(process.argv.includes('--check'), 'Use --check locally; captures require the hosted CI runner.');
 console.log(JSON.stringify(await check()));
}
