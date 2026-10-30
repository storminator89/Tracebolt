/** Source-only changed-view capture. --check only bundles/imports in memory and
 * invokes fake routes. --capture is hosted-CI-only, with every request intercepted.
 * Go review bytes feed the actual review, auth and action components; no copied UI. */
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { mkdir, readFile, realpath, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { root, sha256 as hash, disclosure, contract, assertionMatrix, captureMatrix, assertionEvidence, sceneManifestSHA256, dependencyPackagePath, dependencyBindings, assertHostedSource, validateManifest } from './windows-complete-service-review-contract.mjs';
const require = createRequire(new URL('../package.json', import.meta.url));
export const origin = 'https://complete-service-review.invalid';
export const scenes = [...new Set(assertionMatrix.map(row => row.scene))];
export { disclosure };
export const reviewHeader = 'x-tracebolt-windows-service-review';
async function bundle(contents, platform = 'node') {
    return require('esbuild').build({ stdin: { contents, resolveDir: path.join(root, 'web/src'), loader: 'tsx' }, absWorkingDir: root, outdir: 'web/.complete-service-review-memory-only', entryNames: 'app', bundle: true, platform, format: 'esm', jsx: 'automatic', define: { 'process.env.NODE_ENV': '"production"' }, loader: { '.woff': 'dataurl', '.woff2': 'dataurl', '.svg': 'dataurl', '.png': 'dataurl' }, write: false, metafile: true, minify: platform === 'browser', logLevel: 'silent' });
}
let modules, fixtureInputs = [];
export async function fixtureModules() {
    if (!modules) {
        const result = await bundle("export * from './windows-complete-service-review-fixture'; export * from './windows-complete-service-incident-review-types'; export { validWindowsActionView } from './windows-service-action-types';");
        fixtureInputs = Object.keys(result.metafile.inputs);
        modules = await import(`data:text/javascript;base64,${Buffer.from(result.outputFiles[0].contents).toString('base64')}`);
    }
    return modules;
}
export async function fixture(scene = 'matched', now = new Date().toISOString()) {
    assert(scenes.includes(scene));
    const m = await fixtureModules(), view = m.completeServiceReviewFixture(scene, now);
    const session = { mode: 'lan', transport: 'https', insecureTestMode: false, transportWarning: null, authenticationRequired: true, authenticated: true, csrfToken: 'synthetic-only', serverNow: now, expiresAt: new Date(Date.parse(now) + 3600000).toISOString(), expiresInSeconds: 3600, loginMode: 'named', actorId: `operator_${'7'.repeat(32)}`, capabilities: ['read', 'windows_service_control'] };
    const status = view.control.status === 'matched' ? { schemaVersion: 'tracebolt.windows-service-action-view.v1', deviceId: view.incident.deviceId, serverNow: now, configured: true, available: true, reason: 'ready', target: view.incident.serviceName, preview: null, job: null } : null;
    if (status) assert(m.validWindowsActionView(status, view.incident.deviceId, session.actorId));
    return { scene, view, session, status, bootstrap: { incidentKey: view.incident.key, deviceId: view.incident.deviceId, serviceName: view.incident.serviceName, sessionKey: session.expiresAt } };
}
// Preview data is separately labeled synthetic; the review and its binding remain
// the exact Go output, apart from the uniform display-clock translation above.
export function previewFixture(data, operation) {
    assert(data.status && ['start', 'stop', 'restart'].includes(operation));
    return { ...data.status, preview: { version: 'tracebolt.windows-service-action-preview.v1', id: `action_${'8'.repeat(32)}`, binding: data.view.control.binding, operation, actorId: data.session.actorId, sequence: '1', createdAt: data.view.serverNow, expiresAt: new Date(Date.parse(data.view.serverNow) + 60000).toISOString(), digest: `sha256:${'9'.repeat(64)}` } };
}
export async function compile() {
    await fixtureModules();
    const result = await bundle(`import React from 'react'; import { createRoot } from 'react-dom/client'; import './styles.css'; import './windows-incident-inbox.css'; import { AuthBoundary } from './auth'; import { WindowsCompleteServiceIncidentReview } from './windows-complete-service-incident-review'; const data = window.__COMPLETE_SERVICE_REVIEW_FIXTURE__; createRoot(document.getElementById('root')).render(<React.StrictMode><AuthBoundary><main style={{maxWidth:1080,margin:'0 auto',padding:16}}><p role="note">SYNTHETIC · Go source fixture · No endpoint actions</p><section className="panel"><div className="windows-incident-content"><WindowsCompleteServiceIncidentReview {...data} onClose={() => {}}/></div></section></main></AuthBoundary></React.StrictMode>);`, 'browser');
    const assets = new Map(result.outputFiles.map(file => [`/${path.basename(file.path)}`, { body: Buffer.from(file.contents), contentType: file.path.endsWith('.css') ? 'text/css' : 'text/javascript' }]));
    assert(assets.has('/app.js') && assets.has('/app.css'));
    assets.set('/', { contentType: 'text/html', body: '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="icon" href="data:,"><link rel="stylesheet" href="/app.css"><title>Synthetic complete-service review</title></head><body><div id="root"></div><script type="module" src="/app.js"></script></body></html>' });
    // Hash the complete transitive input closure, including CSS/assets and locked
    // third-party source. Normalize the shared node_modules symlink for portability.
    const moduleRoot = await realpath(path.join(root, 'web/node_modules'));
    const inputs = [...new Set([...fixtureInputs, ...Object.keys(result.metafile.inputs), 'web/package.json', 'web/package-lock.json', 'web/scripts/capture-windows-complete-service-review.mjs', 'web/scripts/windows-complete-service-review-contract.mjs', 'web/scripts/windows-complete-service-review-scenes.json'])].filter(file => file !== '<stdin>');
    const byName = new Map();
    for (const input of inputs) {
        const absolute = await realpath(path.resolve(root, input)), dependency = path.relative(moduleRoot, absolute), local = path.relative(root, absolute);
        const file = !dependency.startsWith('..') && !path.isAbsolute(dependency) ? `web/node_modules/${dependency}` : local;
        assert(!file.startsWith('..') && !path.isAbsolute(file), `Unexpected source outside the input closure: ${input}`);
        const sha256 = hash(await readFile(absolute));
        assert(!byName.has(file) || byName.get(file) === sha256, `Conflicting input: ${file}`); byName.set(file, sha256);
    }
    // Include each compiled dependency's identity metadata; bind it to both npm locks.
    for (const packagePath of new Set([...byName.keys()].map(dependencyPackagePath).filter(Boolean))) {
        const file = packagePath + '/package.json'; byName.set(file, hash(await readFile(path.join(root, file))));
    }
    const sourceInputs = [...byName].sort(([a], [b]) => a.localeCompare(b)).map(([file, sha256]) => ({ file, sha256 }));
    return { assets, sourceInputs, dependencyBindings: await dependencyBindings(sourceInputs), sourceDigest: hash(JSON.stringify(sourceInputs)) };
}
export const initialState = () => ({ external: 0, writes: 0, unexpected: 0, reviewReads: 0, actionReads: 0, previews: 0, manualPreview: null });
export function routeFixture(data, compiled, state) { return async route => {
    const req = route.request(), url = new URL(req.url()), method = req.method(), raw = req.postData(), headers = req.headers();
    const blocked = kind => { state[kind]++; return route.abort('blockedbyclient'); };
    if (url.origin !== origin) return blocked('external');
    if (url.search || url.hash) return blocked('unexpected');
    const respond = body => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });
    const actionPath = `/api/devices/${data.view.incident.deviceId}/windows-service-actions`;
    if (method === 'POST' && url.pathname === `${actionPath}/preview`) {
        // A capture step must independently arm one exact operation after an
        // explicit UI selection. No route ever accepts approval or other writes.
        const operation = state.manualPreview;
        if (!data.status || !operation || raw !== JSON.stringify({ target: data.status.target, operation }) || headers[reviewHeader] !== data.view.control.bindingDigest || headers['x-csrf-token'] !== data.session.csrfToken || headers['content-type'] !== 'application/json' || state.previews !== 0) return blocked('writes');
        state.manualPreview = null; state.previews++; return respond(previewFixture(data, operation));
    }
    if (method !== 'GET' || raw !== null) return blocked('writes');
    if (url.pathname === `/api/fleet/windows-incidents/complete/${data.view.incident.key}/service-review`) { state.reviewReads++; return respond(data.view); }
    if (url.pathname === actionPath) {
        if (!data.status || headers[reviewHeader] !== data.view.control.bindingDigest) return blocked('unexpected');
        state.actionReads++; return respond(data.status);
    }
    if (url.pathname === '/api/session') return respond({ csrfToken: data.session.csrfToken });
    if (url.pathname === '/api/auth/session') return respond(data.session);
    const asset = compiled.assets.get(url.pathname); return asset ? route.fulfill({ status: 200, ...asset }) : blocked('unexpected');
}; }
// Keep real source typography. Check every visible control for text clipping and
// ancestor clipping; fixed-viewport screenshots never shrink or restyle the UI.
export async function assertLayout(page, review, focus, expect) {
    await page.evaluate(() => document.fonts.ready);
    await focus.evaluate(element => element.scrollIntoView({ block: 'center' }));
    await expect(focus).toBeInViewport({ ratio: 1 });
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
    assert.equal(await page.evaluate(() => getComputedStyle(document.documentElement).fontSize), '13px');
    assert.equal(await review.evaluate(element => getComputedStyle(element).fontSize), '12px');
    assert(await review.evaluate(element => {
        if (element.scrollWidth > element.clientWidth + 1) return false;
        const visible = element => element.getClientRects().length && getComputedStyle(element).visibility !== 'hidden';
        return [...element.querySelectorAll('button,select,input,summary')].filter(visible).every(control => {
            const box = control.getBoundingClientRect(), style = getComputedStyle(control);
            if (parseFloat(style.fontSize) < 10 || box.left < -1 || box.right > innerWidth + 1 || control.scrollWidth > control.clientWidth + 1 || control.scrollHeight > control.clientHeight + 1) return false;
            for (let parent = control.parentElement; parent; parent = parent.parentElement) {
                const parentStyle = getComputedStyle(parent), outer = parent.getBoundingClientRect();
                if (['hidden', 'clip'].includes(parentStyle.overflowX) && (box.left < outer.left - 1 || box.right > outer.right + 1)) return false;
                if (['hidden', 'clip'].includes(parentStyle.overflowY) && (box.top < outer.top - 1 || box.bottom > outer.bottom + 1)) return false;
            }
            return true;
        });
    }), 'Normal-sized controls must not be clipped');
}
export async function capture({ browser, expect, output, sourceSha = process.env.TRACEBOLT_SOURCE_SHA ?? process.env.GITHUB_SHA }) {
    const sourceTree = await assertHostedSource(sourceSha), compiled = await compile();
    assert.equal(await assertHostedSource(sourceSha, compiled.sourceInputs, compiled.dependencyBindings), sourceTree);
    const captures = [], assertions = []; let interceptedPreviewRequests = 0; await mkdir(output, { recursive: true });
    for (const { locale, width, height } of contract.viewports) for (const scene of scenes) {
        const data = await fixture(scene), de = locale === 'de', state = initialState(), errors = [];
        const context = await browser.newContext({ viewport: { width, height }, reducedMotion: 'reduce', locale: de ? 'de-DE' : 'en-US', serviceWorkers: 'block' });
        try {
            await context.route('**/*', routeFixture(data, compiled, state));
            await context.addInitScript(({ locale, bootstrap }) => { localStorage.setItem('tracebolt.locale', locale); window.__COMPLETE_SERVICE_REVIEW_FIXTURE__ = bootstrap; }, { locale, bootstrap: data.bootstrap });
            const page = await context.newPage(); page.on('pageerror', error => errors.push(error.message)); await page.goto(origin + '/');
            const review = page.getByRole('region', { name: de ? 'Vorfallsdienst prüfen' : 'Review incident service', exact: true });
            const heading = review.getByRole('heading', { level: 3 }).first();
            await expect(heading).toContainText(data.view.incident.serviceName);
            await expect(review.getByText(de ? 'Vorfall aktiv' : 'Incident active', { exact: true })).toBeVisible();
            const evidence = review.locator('.windows-incident-provenance'); await expect(evidence).not.toHaveAttribute('open', '');
            if (scene === 'unknown') await expect(review.getByText(de ? 'Aktueller Zustand unbekannt. Fehlende Belege bedeuten nicht gestoppt.' : 'Current state unknown. Missing evidence does not mean stopped.', { exact: true })).toBeVisible();
            else await expect(review.getByText(data.view.observation.displayName, { exact: false })).toBeVisible();
            const select = review.getByRole('button', { name: de ? /^Dienst auswählen:/ : /^Select service:/ });
            if (data.status) {
                await expect(select).toHaveAttribute('aria-pressed', 'false');
                await expect(review.getByRole('combobox')).toHaveCount(0); await expect(review.getByRole('checkbox')).toHaveCount(0);
            } else {
                await expect(review.getByText(de ? 'Nur lesen: Dieser Dienstname liegt außerhalb der unterstützten Steuerungsziele.' : 'Read-only: this service name is outside the supported control targets.', { exact: true })).toBeVisible();
                await expect(review.locator('.windows-service-actions')).toHaveCount(0);
            }
            assert.equal(state.previews, 0);
            const save = async (phase, focus = review) => {
                await assertLayout(page, review, focus, expect);
                assert.deepEqual(errors, []); assert.equal(state.external + state.writes + state.unexpected, 0);
                const row = assertionMatrix.find(row => row.phase === phase && row.locale === locale && row.width === width); assert(row);
                const expected = assertionEvidence(row);
                assert.equal(state.reviewReads, expected.reviewReads); assert.equal(state.actionReads, expected.actionReads); assert.equal(state.previews, expected.interceptedPreviewRequests);
                assertions.push(expected);
                const capture = captureMatrix.find(row => row.phase === phase && row.locale === locale && row.width === width);
                if (capture) {
                    await page.screenshot({ path: path.join(output, capture.file), animations: 'disabled', fullPage: false });
                    captures.push({ ...capture, synthetic: true, publicSafe: true, fullPage: false, sha256: hash(await readFile(path.join(output, capture.file))), sourceSha, sourceTree, sourceDigest: compiled.sourceDigest });
                }
            };
            await save(scene === 'matched' ? 'matched-read' : scene);
            if (scene === 'matched') {
                await select.click(); await expect(select).toHaveAttribute('aria-pressed', 'true');
                const operation = review.getByRole('combobox'), preview = review.getByRole('button', { name: de ? 'Aktion prüfen' : 'Review action', exact: true });
                await expect(operation).toHaveValue(''); await expect(preview).toBeDisabled(); assert.equal(state.previews, 0);
                await save('matched-selected-blank', review.locator('.windows-service-actions'));
                await expect(operation).toBeInViewport({ ratio: 1 }); await expect(preview).toBeInViewport({ ratio: 1 });
                await operation.selectOption('stop'); assert.equal(state.previews, 0);
                state.manualPreview = 'stop'; await preview.click();
                const approval = review.getByRole('checkbox'), confirm = review.getByRole('button', { name: de ? 'Diese Aktion einmal freigeben' : 'Approve this action once', exact: true });
                await expect(approval).not.toBeChecked(); await expect(confirm).toBeDisabled(); assert.equal(state.previews, 1);
                await save('matched-preview-unchecked', review.getByRole('group', { name: de ? 'Aktion prüfen' : 'Review action', exact: true }));
                await expect(approval).toBeInViewport({ ratio: 1 }); await expect(confirm).toBeInViewport({ ratio: 1 });
            }
            assert.equal(state.reviewReads, 1); assert.equal(state.actionReads, data.status ? 1 : 0); interceptedPreviewRequests += state.previews;
        } finally { await context.close(); }
    }
    assert.deepEqual(assertions, assertionMatrix.map(assertionEvidence)); assert.equal(interceptedPreviewRequests, 4);
    const manifest = { sourceSha, sourceTree, captures, assertions, sourceInputs: compiled.sourceInputs, dependencyBindings: compiled.dependencyBindings, sourceDigest: compiled.sourceDigest, sceneManifestSHA256, disclosure, browserExecuted: true, appMounted: false, nativeAcceptance: false, interceptedPreviewRequests, approvalRequests: 0, outgoingNetworkRequests: 0 };
    await validateManifest(output, sourceSha, sourceTree, manifest);
    assert.equal(await assertHostedSource(sourceSha, compiled.sourceInputs, compiled.dependencyBindings), sourceTree);
    return manifest;
}
export async function check() {
    const compiled = await compile(), m = await fixtureModules();
    const originalWire = JSON.parse(await readFile(path.join(root, 'web/src/windows-complete-service-review-go-fixture.json'), 'utf8'));
    assert.deepEqual(Object.keys(originalWire).sort(), [...scenes].sort());
    for (const file of ['web/src/windows-complete-service-review-go-fixture.json', 'web/src/windows-complete-service-review-fixture.ts', 'web/src/windows-complete-service-incident-review.tsx', 'web/src/windows-service-actions.tsx', 'web/src/windows-service-incident-review-types.ts', 'web/src/api.ts', 'web/src/auth.tsx', 'web/src/styles.css', 'web/src/windows-incident-inbox.css', 'web/package-lock.json']) assert(compiled.sourceInputs.some(input => input.file === file), `Missing transitive source: ${file}`);
    assert(compiled.sourceInputs.some(input => input.file.startsWith('web/node_modules/react/')));
    for (const scene of scenes) {
        assert.deepEqual(m.completeServiceReviewFixture(scene), originalWire[scene], 'Unshifted review is the exact exported Go fixture');
        const data = await fixture(scene, '2026-10-13T12:00:00Z'), state = initialState(), route = routeFixture(data, compiled, state);
        let response;
        const fake = (method, target, body = null, headers = {}) => ({ request: () => ({ url: () => target.startsWith('https:') ? target : origin + target, method: () => method, postData: () => body, headers: () => headers }), fulfill: value => { response = value; }, abort: () => {} });
        await route(fake('GET', `/api/fleet/windows-incidents/complete/${data.view.incident.key}/service-review`));
        assert(m.validWindowsCompleteServiceIncidentReview(JSON.parse(response.body), data.view.incident.key, data.view.incident.deviceId, data.view.incident.serviceName));
        assert.equal(state.previews, 0);
        assert.equal(data.view.incident.serviceName, originalWire[scene].incident.serviceName);
        assert.deepEqual(data.view.control, originalWire[scene].control);
        assert.equal(Date.parse(data.view.authorityExpiresAt) - Date.parse(data.view.serverNow), Date.parse(originalWire[scene].authorityExpiresAt) - Date.parse(originalWire[scene].serverNow));
        assert.equal(data.view.observation === null, scene === 'unknown');
        const actionPath = `/api/devices/${data.view.incident.deviceId}/windows-service-actions`, headers = { [reviewHeader]: data.view.control.bindingDigest, 'x-csrf-token': data.session.csrfToken, 'content-type': 'application/json' };
        if (data.status) {
            await route(fake('GET', actionPath, null, headers)); assert(m.validWindowsActionView(JSON.parse(response.body), data.view.incident.deviceId, data.session.actorId));
            const body = JSON.stringify({ target: data.status.target, operation: 'stop' });
            await route(fake('POST', `${actionPath}/preview`, body, headers)); assert.equal(state.previews, 0); // Not manually armed.
            state.manualPreview = 'stop';
            const badPreviews = [
                [body, { ...headers, [reviewHeader]: 'sha256:' + '0'.repeat(64) }],
                [body, { ...headers, 'x-csrf-token': 'wrong' }],
                [body, { ...headers, 'content-type': 'text/plain' }],
                [JSON.stringify({ target: 'OtherService', operation: 'stop' }), headers],
                [JSON.stringify({ target: data.status.target, operation: 'start' }), headers],
                [JSON.stringify({ target: data.status.target, operation: 'stop', approve: true }), headers],
            ];
            for (const [badBody, badHeaders] of badPreviews) { await route(fake('POST', `${actionPath}/preview`, badBody, badHeaders)); assert.equal(state.previews, 0); }
            await route(fake('GET', actionPath)); assert.equal(state.actionReads, 1);
            await route(fake('POST', `${actionPath}/preview`, body, headers)); assert.equal(state.previews, 1); assert(m.validWindowsActionView(JSON.parse(response.body), data.view.incident.deviceId, data.session.actorId));
            await route(fake('POST', `${actionPath}/preview`, body, headers)); assert.equal(state.previews, 1); // Consume once.
        } else {
            await route(fake('GET', actionPath, null, headers)); assert.equal(state.actionReads, 0);
        }
        for (const target of [`${actionPath}/approve`, '/api/fleet/windows-incidents/complete/acknowledge', '/api/devices/fixture/windows-services/complete/policy']) await route(fake('POST', target, '{}'));
        await route(fake('GET', `/api/fleet/windows-incidents/${data.view.incident.key}/service-review`));
        await route(fake('GET', `/api/fleet/windows-incidents/complete/${data.view.incident.key}/service-review?extra=true`));
        await route(fake('GET', 'https://untrusted.invalid/'));
        assert.deepEqual(state, { external: 1, writes: data.status ? 11 : 3, unexpected: 3, reviewReads: 1, actionReads: data.status ? 1 : 0, previews: data.status ? 1 : 0, manualPreview: null });
    }
    return { sourceDigest: compiled.sourceDigest, sourceInputCount: compiled.sourceInputs.length, dependencyPackageCount: compiled.dependencyBindings.length, sceneManifestSHA256, scenes, capturePhases: contract.states, assertedViews: assertionMatrix.length, screenshots: captureMatrix.length, browserExecuted: false, appMounted: false, nativeAcceptance: false, disclosure };
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    if (process.argv.includes('--check')) console.log(JSON.stringify(await check()));
    else if (process.argv.includes('--capture')) {
        await assertHostedSource(process.env.TRACEBOLT_SOURCE_SHA ?? process.env.GITHUB_SHA); const { chromium, expect } = require('@playwright/test'), browser = await chromium.launch({ headless: true });
        try { const output = path.resolve(process.env.TRACEBOLT_CAPTURE_OUTPUT ?? path.join(root, 'artifacts/review')); const manifest = await capture({ browser, expect, output }); await writeFile(path.join(output, 'windows-complete-service-review-manifest.json'), JSON.stringify(manifest, null, 2) + '\n'); } finally { await browser.close(); }
    } else throw new Error('Use --check, or --capture only in the gated hosted runner.');
}
