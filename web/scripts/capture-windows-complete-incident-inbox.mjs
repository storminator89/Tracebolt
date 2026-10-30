/** Synthetic source-only changed-view captures. --check bundles in memory only.
 * --capture requires hosted CI. All requests intercepted; no listener or host. */
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { contract, captureMatrix, captureCoordinate, disclosure, sceneManifestSHA256, assertHostedSource, validateManifest } from './windows-complete-incident-inbox-contract.mjs';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const require = createRequire(new URL('../package.json', import.meta.url));
export const origin = 'https://complete-incident-inbox.invalid';
export { disclosure };
export const scenes = contract.scenes;
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const hosted = () => assert(process.env.GITHUB_ACTIONS === 'true' && process.env.RUNNER_ENVIRONMENT === 'github-hosted', 'Hosted CI only; --check performs no browser work.');
async function bundle(contents, platform = 'node') {
    return require('esbuild').build({ stdin: { contents, resolveDir: path.join(root, 'web/src'), loader: 'tsx' }, absWorkingDir: root, outdir: 'web/.complete-inbox-memory-only', entryNames: 'app', bundle: true, platform, format: 'esm', jsx: 'automatic', define: { 'process.env.NODE_ENV': '"production"' }, loader: { '.woff': 'dataurl', '.woff2': 'dataurl', '.svg': 'dataurl', '.png': 'dataurl' }, write: false, metafile: true, minify: platform === 'browser', logLevel: 'silent' });
}
let modules, fixtureInputs = [];
async function fixtureModules() {
    if (!modules) {
        const result = await bundle("export * from './windows-complete-incident-inbox-fixture'; export * from './windows-complete-incident-inbox-types'; export { windowsCapacityDevice } from './windows-capacity-fixture';");
        fixtureInputs = Object.keys(result.metafile.inputs).filter(file => file.startsWith('web/src/'));
        modules = await import(`data:text/javascript;base64,${Buffer.from(result.outputFiles[0].contents).toString('base64')}`);
    }
    return modules;
}
export async function fixture(scene = 'active', now = new Date().toISOString()) {
    assert(scenes.includes(scene)); const m = await fixtureModules(), view = m.completeIncidentFixture(scene, now), device = m.windowsCapacityDevice();
    device.id = view.items[0].deviceId; device.name = 'SYNTHETIC · Complete service device';
    const session = { mode: 'lan', transport: 'https', insecureTestMode: false, transportWarning: null, authenticationRequired: true, authenticated: true, csrfToken: 'synthetic-only', serverNow: now, expiresAt: new Date(Date.parse(now) + 3600000).toISOString(), expiresInSeconds: 3600, loginMode: 'shared', actorId: null, capabilities: ['read'] };
    assert(m.validWindowsCompleteIncidentInboxView(view, 'active', 'all', 0));
    return { view, device, session, bootstrap: { device, session } };
}
export async function compile() {
    await fixtureModules();
    const result = await bundle(`import React from 'react'; import { createRoot } from 'react-dom/client'; import './styles.css'; import { WindowsIncidentInbox } from './windows-incident-inbox'; const data = window.__COMPLETE_INCIDENT_FIXTURE__; createRoot(document.getElementById('root')).render(<React.StrictMode><main style={{maxWidth:1080,margin:'0 auto',padding:16}}><p role="note">SYNTHETIC · Go source fixture · No endpoint actions</p><section className="panel"><WindowsIncidentInbox complete devices={[data.device]} sessionKey={data.session.expiresAt} admin/></section></main></React.StrictMode>);`, 'browser');
    const assets = new Map(result.outputFiles.map(file => [`/${path.basename(file.path)}`, { body: Buffer.from(file.contents), contentType: file.path.endsWith('.css') ? 'text/css' : 'text/javascript' }]));
    assert(assets.has('/app.js') && assets.has('/app.css'));
    assets.set('/', { contentType: 'text/html', body: '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="icon" href="data:,"><link rel="stylesheet" href="/app.css"><title>Synthetic complete-service inbox</title></head><body><div id="root"></div><script type="module" src="/app.js"></script></body></html>' });
    const files = [...new Set([...fixtureInputs, ...Object.keys(result.metafile.inputs).filter(file => file.startsWith('web/src/')), 'web/src/windows-complete-incident-go-fixture.json', 'web/scripts/capture-windows-complete-incident-inbox.mjs', 'web/scripts/windows-complete-incident-inbox-scenes.json', 'web/scripts/windows-complete-incident-inbox-contract.mjs', 'web/scripts/check-windows-complete-incident-inbox-evidence.mjs'])].sort();
    const sourceInputs = await Promise.all(files.map(async file => ({ file, sha256: hash(await readFile(path.join(root, file))) })));
    return { assets, sourceInputs, sourceDigest: hash(JSON.stringify(sourceInputs)) };
}
export function routeFixture(data, compiled, state) { return async route => {
    const req = route.request(), url = new URL(req.url()), method = req.method(), raw = req.postData();
    const blocked = kind => { state[kind]++; return route.abort('blockedbyclient'); };
    if (url.origin !== origin) return blocked('external');
    if (method !== 'GET' || raw !== null) return blocked('writes');
    const respond = body => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });
    if (url.pathname === '/api/fleet/windows-incidents/complete') {
        if (url.search !== '?scope=active&ack=all&offset=0&limit=25') return blocked('unexpected');
        state.reads++; return respond(data.view);
    }
    if (url.search) return blocked('unexpected');
    if (url.pathname === '/api/session') return respond({ csrfToken: data.session.csrfToken });
    if (url.pathname === '/api/auth/session') return respond(data.session);
    const asset = compiled.assets.get(url.pathname); return asset ? route.fulfill({ status: 200, ...asset }) : blocked('unexpected');
}; }
export async function capture({ browser, expect, output, sourceSha, checkpoint }) {
    hosted(); const sourceTree = await assertHostedSource(sourceSha); const compiled = await compile(), captures = []; await mkdir(output, { recursive: true });
    await assertHostedSource(sourceSha, compiled.sourceInputs);
    for (const { locale, width, height, scene, file } of captureMatrix) {
        const mark = phase => { try { const value = captureCoordinate(scene, locale, width, phase); if (value) checkpoint?.(value); } catch { /* Diagnostics cannot change acceptance. */ } };
        mark('fixture');
        const data = await fixture(scene), de = locale === 'de', state = { external: 0, writes: 0, unexpected: 0, reads: 0 }, errors = [];
        mark('context');
        const context = await browser.newContext({ viewport: { width, height }, reducedMotion: 'reduce', locale: de ? 'de-DE' : 'en-US', serviceWorkers: 'block' });
        let scenePassed = false;
        try {
            mark('route');
            await context.route('**/*', routeFixture(data, compiled, state));
            mark('init');
            await context.addInitScript(({ locale, bootstrap }) => { localStorage.setItem('tracebolt.locale', locale); window.__COMPLETE_INCIDENT_FIXTURE__ = bootstrap; }, { locale, bootstrap: data.bootstrap });
            mark('page');const page = await context.newPage(); page.on('pageerror', error => errors.push(error.message));
            mark('document');await page.goto(origin + '/');
            mark('open');
            await page.getByRole('button', { name: de ? 'Windows-Vorfälle' : 'Windows incidents', exact: true }).click();
            mark('service-row');
            await expect(page.locator('.windows-incident-service')).toHaveText(data.view.items[0].serviceName);
            mark('source-label');
            await expect(page.getByText(de ? 'Quelle: Vollständiges Dienstinventar' : 'Source: Complete service inventory', { exact: true })).toBeVisible();
            mark('review-controls');
            await expect(page.getByRole('button', { name: /Review service|Dienst prüfen/ })).toHaveCount(1);
            await expect(page.getByRole('button', { name: /Review service|Dienst prüfen/ })).toBeEnabled();
            // Keep the review closed: the route rejects any service-review or action read.
            mark('review-closed');
            await expect(page.locator('.windows-complete-service-incident-review')).toHaveCount(0);
            if (scene === 'unknown') {
                mark('source-status');
                await expect(page.getByText(de ? 'Quellstatus: Unbekannt' : 'Source status: Unknown', { exact: true })).toBeVisible();
                mark('evidence-open');
                await page.getByText(de ? 'Zeiten und Evidenz' : 'Times and evidence', { exact: true }).click();
                mark('source-unknown');
                await expect(page.getByText(de ? 'Keine qualifizierte aktuelle Quelle. Gespeicherte Historie bleibt sichtbar.' : 'No qualified current source. Retained history stays visible.', { exact: true })).toBeVisible();
                mark('provenance-open');
                await page.getByText(de ? 'Quelle bei Eröffnung' : 'Opening source', { exact: true }).click();
                mark('provenance-value');
                await expect(page.locator('.windows-incident-provenance[open]')).toContainText(data.view.items[0].openingSource.generationId);
                // Verify expandable original provenance, then capture readable status at normal scale.
                mark('evidence-close');
                await page.getByText(de ? 'Zeiten und Evidenz' : 'Times and evidence', { exact: true }).click();
                mark('badges');
                await expect(page.locator('.windows-incident-badges')).toHaveText(de ? 'AktivGesehen' : 'ActiveSeen');
                mark('ack-control');
                await expect(page.getByRole('button', { name: de ? /^Als gesehen markieren:/ : /^Mark seen:/ })).toHaveCount(0);
            } else {
                mark('source-status');
                await expect(page.getByText(de ? 'Quellstatus: Prüfen' : 'Source status: Needs attention', { exact: true })).toBeVisible();
                mark('ack-control');
                await expect(page.getByRole('button', { name: de ? /^Als gesehen markieren:/ : /^Mark seen:/ })).toBeEnabled();
                mark('badges');
                await expect(page.locator('.windows-incident-badges')).toHaveText(de ? 'AktivUngesehen' : 'ActiveNot seen');
            }
            mark('fonts');await page.evaluate(() => document.fonts.ready);
            mark('page-width');assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
            // The real controls and status must fit at their native text sizes. Never shrink a full page.
            const controls = page.locator('.windows-incident-toolbar');
            mark('toolbar-visible');
            await controls.scrollIntoViewIfNeeded();
            mark('toolbar-geometry');
            assert(await controls.evaluate(element => [...element.querySelectorAll('select,button')].every(control => { const rect = control.getBoundingClientRect(), style = getComputedStyle(control); return rect.width >= 60 && rect.height >= 24 && rect.left >= 0 && rect.right <= innerWidth + 1 && parseFloat(style.fontSize) >= 11 && control.scrollWidth <= control.clientWidth + 1; })));
            const row = page.locator('.windows-incident-row');
            mark('row-visible');
            await row.evaluate(element => element.scrollIntoView({ block: 'center', inline: 'nearest' }));
            mark('row-geometry');
            assert(await row.evaluate(element => [...element.querySelectorAll('.windows-incident-main, .windows-incident-meta > span, .windows-incident-meta > details > summary, .windows-incident-action button')].every(item => { const rect = item.getBoundingClientRect(), style = getComputedStyle(item); return rect.width > 0 && rect.height > 0 && rect.top >= 0 && rect.bottom <= innerHeight + 1 && rect.left >= 0 && rect.right <= innerWidth + 1 && parseFloat(style.fontSize) >= 10 && item.scrollWidth <= item.clientWidth + 1; })));
            mark('text-size');
            assert(await page.locator('.windows-incident-main p').evaluateAll(items => items.every(item => parseFloat(getComputedStyle(item).fontSize) >= 11)));
            mark('screenshot');
            await page.screenshot({ path: path.join(output, file), animations: 'disabled', fullPage: false });
            mark('runtime-guards');assert.deepEqual(errors, []);
            mark('route-guards');assert.equal(state.external + state.writes + state.unexpected, 0);
            mark('read-count');assert.equal(state.reads, 1);
            captures.push({ file, scene, locale, width, height, sourceSha, sourceTree, publicSafe: true, fullPage: false, synthetic: true, sha256: hash(await readFile(path.join(output, file))), sourceDigest: compiled.sourceDigest });
            scenePassed = true;
        } finally { if (scenePassed) mark('close'); await context.close(); }
    }
    try { checkpoint?.(null); } catch { /* Restore coarse setup/manifest coordinates only. */ }
    const manifest = { sourceSha, sourceTree, sceneManifestSHA256, appMounted: false, captures, sourceInputs: compiled.sourceInputs, sourceDigest: compiled.sourceDigest, disclosure, browserExecuted: true, nativeAcceptance: false, actualMutationRequests: 0 };
    assert.equal(await assertHostedSource(sourceSha, compiled.sourceInputs), sourceTree);
    await validateManifest(output, sourceSha, sourceTree, manifest); return manifest;
}
export async function check() {
    const compiled = await compile(), m = await fixtureModules();
    for (const scene of scenes) {
        const data = await fixture(scene, '2026-10-13T12:00:00Z'), state = { external: 0, writes: 0, unexpected: 0, reads: 0 }, route = routeFixture(data, compiled, state);
        let response; const fake = (method, target, body = null) => ({ request: () => ({ url: () => target.startsWith('https:') ? target : origin + target, method: () => method, postData: () => body }), fulfill: value => { response = value; }, abort: () => {} });
        await route(fake('GET', '/api/fleet/windows-incidents/complete?scope=active&ack=all&offset=0&limit=25')); assert(m.validWindowsCompleteIncidentInboxView(JSON.parse(response.body), 'active', 'all', 0));
        for (const target of ['/api/fleet/windows-incidents/complete/acknowledge', '/api/devices/fixture/windows-services/complete/policy', '/api/devices/fixture/windows-service-actions/preview']) await route(fake('POST', target, '{}'));
        await route(fake('GET', '/api/fleet/windows-incidents?scope=active'));
        // An unclicked review is not an allowed read in an inbox-only scene.
        await route(fake('GET', `/api/fleet/windows-incidents/complete/${data.view.items[0].key}/service-review`));
        await route(fake('GET', 'https://untrusted.invalid/'));
        assert.deepEqual(state, { external: 1, writes: 3, unexpected: 2, reads: 1 });
    }
    return { sourceDigest: compiled.sourceDigest, scenes, browserExecuted: false, nativeAcceptance: false, disclosure };
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    if (process.argv.includes('--check')) console.log(JSON.stringify(await check()));
    else if (process.argv.includes('--capture')) {
        hosted(); const { chromium, expect } = require('@playwright/test'), browser = await chromium.launch({ headless: true });
        try { const output = path.resolve(process.env.TRACEBOLT_CAPTURE_OUTPUT ?? path.join(root, 'artifacts/complete-incident-inbox')); const manifest = await capture({ browser, expect, output, sourceSha: process.env.TRACEBOLT_SOURCE_SHA }); await writeFile(path.join(output, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n'); } finally { await browser.close(); }
    } else throw new Error('Use --check, or --capture only in the gated hosted runner.');
}
