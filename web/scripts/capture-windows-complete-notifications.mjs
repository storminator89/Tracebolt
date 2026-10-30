/** Synthetic changed-view source. --check bundles/validates in memory only.
 * --capture is hosted-only. Every route is intercepted; no listener is created. */
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { root, sha256, disclosure, contract, captureMatrix, sceneManifestSHA256, assertHostedSource, validateManifest } from './windows-complete-notifications-contract.mjs';
const require = createRequire(new URL('../package.json', import.meta.url));
export const origin = 'https://complete-notifications.invalid';
export const scenes = contract.scenes;
export { disclosure };
const canonicalTime = value => new Date(value).toISOString().replace(/\.000Z$/, 'Z').replace(/(\.\d*?[1-9])0+Z$/, '$1Z');
async function bundle(contents, platform = 'node') {
    return require('esbuild').build({ stdin: { contents, resolveDir: path.join(root, 'web/src'), loader: 'tsx' }, absWorkingDir: root, outdir: 'web/.complete-notifications-memory-only', entryNames: 'app', bundle: true, platform, format: 'esm', jsx: 'automatic', define: { 'process.env.NODE_ENV': '"production"' }, loader: { '.woff': 'dataurl', '.woff2': 'dataurl', '.svg': 'dataurl', '.png': 'dataurl' }, write: false, metafile: true, minify: platform === 'browser', logLevel: 'silent' });
}
let modules, fixtureInputs = [];
async function fixtureModules() {
    if (!modules) {
        const result = await bundle("export { default as completeWire } from '../../tests/fixtures/windows-complete-notifications-view.json'; export * from './windows-complete-notifications-types'; export * from './windows-notifications-fixture'; export * from './windows-notifications-types'; export { windowsCapacityDevice } from './windows-capacity-fixture';");
        fixtureInputs = Object.keys(result.metafile.inputs).filter(file => file.startsWith('web/src/') || file.startsWith('tests/fixtures/'));
        modules = await import(`data:text/javascript;base64,${Buffer.from(result.outputFiles[0].contents).toString('base64')}`);
    }
    return modules;
}
export async function fixture(scene = 'review', now = new Date().toISOString()) {
    now = canonicalTime(now); assert(scenes.includes(scene)); const m = await fixtureModules(), view = structuredClone(m.completeWire);
    assert(m.validWindowsCompleteNotificationView(view));
    view.serverNow = now; view.authorityExpiresAt = canonicalTime(Date.parse(now) + 120000);
    view.targets = view.targets.map(target => ({ ...target, enabled: scene === 'unknown', effective: false, revision: scene === 'unknown' ? 1 : 0, changedAt: scene === 'unknown' ? now : null, maintenanceUntil: null, actionable: scene !== 'unknown' }));
    const preview = m.windowsNotificationView(); preview.serverNow = now; preview.authorityExpiresAt = view.authorityExpiresAt;
    const device = m.windowsCapacityDevice(); device.id = view.targets[0].deviceId; device.name = 'SYNTHETIC · Complete service device';
    const session = { mode: 'lan', transport: 'https', insecureTestMode: false, transportWarning: null, authenticationRequired: true, authenticated: true, csrfToken: 'synthetic-only', serverNow: now, expiresAt: new Date(Date.parse(now) + 3600000).toISOString(), expiresInSeconds: 3600, loginMode: scene === 'named' ? 'named' : 'shared', actorId: scene === 'named' ? `operator_${'6'.repeat(32)}` : null, capabilities: scene === 'named' ? ['read', 'alarm_admin'] : ['read'] };
    assert(m.validWindowsCompleteNotificationView(view)); assert(m.validWindowsNotificationView(preview));
    return { view, preview, device, session, scene, bootstrap: { device, session, admin: scene !== 'named' } };
}
export async function compile() {
    await fixtureModules();
    const result = await bundle(`import React from 'react'; import { createRoot } from 'react-dom/client'; import './styles.css'; import { WindowsNotifications } from './windows-notifications'; const data = window.__COMPLETE_NOTIFICATIONS_FIXTURE__; createRoot(document.getElementById('root')).render(<React.StrictMode><main style={{maxWidth:1080,margin:'0 auto',padding:16}}><p role="note">SYNTHETIC · Source-only fixture · No endpoint actions</p><section className="panel"><WindowsNotifications devices={[data.device]} sessionKey={data.session.expiresAt} admin={data.admin}/></section></main></React.StrictMode>);`, 'browser');
    const assets = new Map(result.outputFiles.map(file => [`/${path.basename(file.path)}`, { body: Buffer.from(file.contents), contentType: file.path.endsWith('.css') ? 'text/css' : 'text/javascript' }]));
    assert(assets.has('/app.js') && assets.has('/app.css'));
    assets.set('/', { contentType: 'text/html', body: '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="icon" href="data:,"><link rel="stylesheet" href="/app.css"><title>Synthetic complete notifications</title></head><body><div id="root"></div><script type="module" src="/app.js"></script></body></html>' });
    const files = [...new Set([...fixtureInputs, ...Object.keys(result.metafile.inputs).filter(file => file.startsWith('web/src/')), 'tests/fixtures/windows-complete-notifications-view.json', 'web/scripts/windows-complete-notifications-scenes.json', 'web/scripts/windows-complete-notifications-contract.mjs', 'web/scripts/capture-windows-complete-notifications.mjs'])].sort();
    const sourceInputs = await Promise.all(files.map(async file => ({ file, sha256: sha256(await readFile(path.join(root, file))) })));
    return { assets, sourceInputs, sourceDigest: sha256(JSON.stringify(sourceInputs)) };
}
export const routeState = () => ({ external: 0, writes: 0, unexpected: 0, reads: 0, previewReads: 0, interceptedPosts: 0 });
export function routeFixture(data, compiled, state) { return async route => {
    const req = route.request(), url = new URL(req.url()), method = req.method(), raw = req.postData();
    const blocked = kind => { state[kind]++; return route.abort('blockedbyclient'); };
    if (url.origin !== origin) return blocked('external');
    if (method === 'POST' && url.pathname === '/api/fleet/windows-notifications/complete/policy' && !url.search && data.scene === 'uncertain') {
        const target = data.view.targets[0];
        assert.equal(state.interceptedPosts, 0); assert.equal(req.headers()['x-csrf-token'], data.session.csrfToken); assert.match(req.headers()['content-type'] ?? '', /^application\/json(?:;|$)/);
        assert.deepEqual(JSON.parse(raw), { key: target.key, revision: target.revision, enabled: true, destinationBinding: data.view.destinationBinding, payloadAcknowledged: true });
        state.interceptedPosts++; return route.abort('failed');
    }
    if (method !== 'GET' || raw !== null) return blocked('writes');
    if (url.search) return blocked('unexpected');
    const respond = value => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(value) });
    if (url.pathname === '/api/fleet/windows-notifications/complete') { state.reads++; return respond(data.view); }
    if (url.pathname === '/api/fleet/windows-notifications') { state.previewReads++; return respond(data.preview); }
    if (url.pathname === '/api/auth/session') return respond(data.session);
    const asset = compiled.assets.get(url.pathname); return asset ? route.fulfill({ status: 200, ...asset }) : blocked('unexpected');
}; }
export async function capture({ browser, expect, output, sourceSha = process.env.TRACEBOLT_SOURCE_SHA ?? process.env.GITHUB_SHA }) {
    const sourceTree = await assertHostedSource(sourceSha); const compiled = await compile(); assert.equal(await assertHostedSource(sourceSha, compiled.sourceInputs), sourceTree);
    const captures = []; await mkdir(output, { recursive: true });
    for (const { locale, width, height, scene, file } of captureMatrix) {
        const data = await fixture(scene), de = locale === 'de', state = routeState(), errors = [];
        const context = await browser.newContext({ viewport: { width, height }, reducedMotion: 'reduce', locale: de ? 'de-DE' : 'en-US', serviceWorkers: 'block' });
        try {
            await context.route('**/*', routeFixture(data, compiled, state));
            await context.addInitScript(({ locale, bootstrap }) => { localStorage.setItem('tracebolt.locale', locale); window.__COMPLETE_NOTIFICATIONS_FIXTURE__ = bootstrap; }, { locale, bootstrap: data.bootstrap });
            const page = await context.newPage(); page.on('pageerror', error => errors.push(error.message)); await page.goto(origin + '/');
            const toggle = page.getByRole('button', { name: de ? 'Windows-Benachrichtigungen' : 'Windows notifications', exact: true });
            await expect(toggle).toHaveAttribute('aria-expanded', 'false'); assert.equal(state.reads + state.previewReads, 0); await toggle.click();
            await expect(page.getByRole('combobox', { name: de ? 'Gerät und Prüfung' : 'Device and check', exact: true })).toBeVisible();
            await page.getByRole('button', { name: de ? 'Vollständig' : 'Complete', exact: true }).click();
            await page.getByRole('combobox', { name: de ? 'Gerät und vollständige Prüfung' : 'Device and complete check', exact: true }).selectOption(data.view.targets[0].key);
            await expect(page.getByText(de ? 'Quelle: Vollständiges Dienstinventar' : 'Source: Complete service inventory', { exact: true })).toBeVisible();
            const enable = page.getByRole('button', { name: de ? 'Aktivierung prüfen' : 'Review enablement', exact: true });
            if (scene === 'unknown') {
                await expect(enable).toBeDisabled(); await expect(page.getByRole('button', { name: de ? 'Deaktivierung prüfen' : 'Review disablement', exact: true })).toBeEnabled();
                await expect(page.getByText(de ? /^Aktuelle Evidenz/ : /^Current complete-source evidence/)).toBeVisible(); await expect(page.getByRole('checkbox')).toHaveCount(0);
            } else if (scene === 'named') {
                await expect(enable).toHaveCount(0); await expect(page.getByText(de ? /^Nur der gemeinsame Administrator/ : /^Shared administrator required/)).toBeVisible(); await expect(page.getByRole('checkbox')).toHaveCount(0);
                await page.getByText(de ? 'Details' : 'Details', { exact: true }).click();
            } else {
                await enable.click(); const review = page.locator('.windows-maintenance-review');
                await expect(review.getByText(`${de ? 'Ziel' : 'Destination'}: ${data.view.destinationHost}`, { exact: true })).toBeVisible();
                await expect(review.locator('.windows-notifications-names li')).toHaveText(data.view.targets[0].services);
                const approval = page.getByRole('checkbox'), confirm = page.getByRole('button', { name: de ? 'Änderung bestätigen' : 'Confirm change', exact: true });
                await expect(approval).not.toBeChecked(); await expect(confirm).toBeDisabled();
                if (scene === 'review') {
                    await review.evaluate(element => element.scrollIntoView({ block: 'center' }));
                    await expect(review).toBeInViewport({ ratio: 1 }); await expect(approval).toBeInViewport({ ratio: 1 }); await expect(confirm).toBeInViewport({ ratio: 1 });
                    await expect(review.getByText(`${de ? 'Ziel' : 'Destination'}: ${data.view.destinationHost}`, { exact: true })).toBeInViewport({ ratio: 1 });
                    await expect(review.locator('.windows-notifications-names')).toBeInViewport({ ratio: 1 });
                }
                if (scene === 'uncertain') {
                    await approval.check(); await confirm.click(); await expect(page.getByText(de ? /^Änderung unbestätigt/ : /^Change unconfirmed/)).toBeVisible();
                    await expect(enable).toBeDisabled(); await page.getByRole('button', { name: de ? 'Aktualisieren' : 'Refresh', exact: true }).click(); await expect(enable).toBeDisabled();
                    await expect.poll(() => state.reads).toBe(3); assert.equal(state.interceptedPosts, 1);
                }
            }
            await page.evaluate(() => document.fonts.ready); assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
            assert(await page.locator('.windows-notifications').evaluate(element => element.scrollWidth <= element.clientWidth + 1));
            await page.screenshot({ path: path.join(output, file), animations: 'disabled', fullPage: false });
            assert.deepEqual(errors, []); assert.equal(state.external + state.writes + state.unexpected, 0); assert.equal(state.reads, scene === 'uncertain' ? 3 : 1); assert.equal(state.previewReads, 1); assert.equal(state.interceptedPosts, scene === 'uncertain' ? 1 : 0);
            captures.push({ file, scene, locale, width, height, synthetic: true, publicSafe: true, fullPage: false, sha256: sha256(await readFile(path.join(output, file))), sourceSha, sourceTree, sourceDigest: compiled.sourceDigest });
        } finally { await context.close(); }
    }
    const manifest = { sourceSha, sourceTree, captures, sourceInputs: compiled.sourceInputs, sourceDigest: compiled.sourceDigest, sceneManifestSHA256, disclosure, browserExecuted: true, appMounted: false, nativeAcceptance: false, actualMutationRequests: 0 };
    await validateManifest(output, sourceSha, sourceTree, manifest); return manifest;
}
export async function check() {
    const compiled = await compile(), m = await fixtureModules();
    for (const scene of scenes) {
        const data = await fixture(scene, '2026-10-13T12:00:00Z'), state = routeState(), route = routeFixture(data, compiled, state);
        let response; const fake = (method, target, body = null) => ({ request: () => ({ url: () => target.startsWith('https:') ? target : origin + target, method: () => method, postData: () => body, headers: () => ({ 'x-csrf-token': data.session.csrfToken, 'content-type': 'application/json' }) }), fulfill: value => { response = value; }, abort: () => {} });
        await route(fake('GET', '/api/fleet/windows-notifications/complete')); assert(m.validWindowsCompleteNotificationView(JSON.parse(response.body)));
        if (scene === 'uncertain') { const target = data.view.targets[0]; await route(fake('POST', '/api/fleet/windows-notifications/complete/policy', JSON.stringify({ key: target.key, revision: target.revision, enabled: true, destinationBinding: data.view.destinationBinding, payloadAcknowledged: true }))); }
        for (const target of ['/api/fleet/windows-notifications/policy', '/api/devices/fixture/windows-services/complete/policy', '/api/devices/fixture/windows-service-actions/preview']) await route(fake('POST', target, '{}'));
        await route(fake('GET', '/api/fleet/windows-notifications/complete?unexpected=1')); await route(fake('GET', 'https://untrusted.invalid/'));
        assert.deepEqual(state, { external: 1, writes: 3, unexpected: 1, reads: 1, previewReads: 0, interceptedPosts: scene === 'uncertain' ? 1 : 0 });
    }
    return { sourceDigest: compiled.sourceDigest, sceneManifestSHA256, scenes, browserExecuted: false, appMounted: false, nativeAcceptance: false, actualMutationRequests: 0, disclosure };
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    if (process.argv.includes('--check')) console.log(JSON.stringify(await check()));
    else if (process.argv.includes('--capture')) {
        await assertHostedSource(process.env.TRACEBOLT_SOURCE_SHA ?? process.env.GITHUB_SHA);
        const { chromium, expect } = require('@playwright/test'), browser = await chromium.launch({ headless: true });
        try { const output = path.resolve(process.env.TRACEBOLT_CAPTURE_OUTPUT ?? path.join(root, 'artifacts/review')); const manifest = await capture({ browser, expect, output }); await writeFile(path.join(output, 'windows-complete-notifications-manifest.json'), JSON.stringify(manifest, null, 2) + '\n'); } finally { await browser.close(); }
    } else throw new Error('Use --check, or --capture only in the gated hosted runner.');
}
