/** Actual App, intercepted invented data. --check compiles and checks DTOs/routes
 * only. Browser execution is exclusively the separately gated hosted runner. */
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { mkdir, readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import path from 'node:path';
import { captureMatrix, root, sha256, disclosure } from './windows-fleet-software-contract.mjs';
const require = createRequire(new URL('../package.json', import.meta.url));
export const origin = 'https://windows-fleet-software.invalid';
export const queryPath = '/api/fleet/windows-software/query';
let modules;
async function fixtureModules() {
    if (!modules) {
        const { build } = require('esbuild');
        const result = await build({ stdin: { contents: "export * from './windows-fleet-software-fixtures'; export { validFleetSoftwarePage } from './windows-fleet-software-types'; export { fullSoftwareManifestHash } from './windows-full-software-types';", resolveDir: path.join(root, 'web/src'), loader: 'ts' }, bundle: true, platform: 'node', format: 'esm', write: false, logLevel: 'silent' });
        modules = await import(`data:text/javascript;base64,${Buffer.from(result.outputFiles[0].text).toString('base64')}`);
    }
    return modules;
}
export async function fixture(now = new Date().toISOString()) {
    const source = await fixtureModules(), delta = Date.parse(now) - Date.parse(source.fleetSoftwareNow);
    const shift = value => typeof value === 'string' && /^2026-10-1[12]T/.test(value) ? new Date(Date.parse(value) + delta).toISOString() : Array.isArray(value) ? value.map(shift) : value && typeof value === 'object' ? Object.fromEntries(Object.entries(value).map(([key, item]) => [key, shift(item)])) : value;
    const query = { name: 'Fixture [.*] Ä', version: '1.2.3+literal', cursor: '' };
    const prepare = input => {
        const page = shift(source.fleetSoftwarePage(input, 2));
        for (const item of page.items) if (item.complete) item.complete.manifestSha256 = source.fullSoftwareManifestHash(item.complete.manifest);
        return page;
    };
    const fleet = prepare(query);
    // Lack of consent is coverage truth, never an empty installed-software list.
    fleet.items[1] = { ...fleet.items[1], status: 'not_configured', complete: null, latestAttempt: null, matchingCount: 0, unknownCount: 0, rows: [], detailCursor: '' };
    const first = fleet.items[0], detailQuery = { ...query, cursor: first.detailCursor }, detail = prepare(detailQuery);
    const nextQuery = { ...query, cursor: detail.nextCursor }, next = prepare(nextQuery);
    assert(source.validFleetSoftwarePage(fleet, query, { mode: 'fleet', offset: 0 }));
    for (const [page, input, offset] of [[detail, detailQuery, 0], [next, nextQuery, 20]]) assert(source.validFleetSoftwarePage(page, input, { mode: 'device', offset, device: first, deadline: fleet.cursorExpiresAt, totalDevices: 2 }));
    assert.equal(first.matchingCount, 22); assert.equal(first.unknownCount, 4); assert.equal(detail.items[0].rows.length, 20); assert.equal(next.items[0].rows.length, 2);
    const metric = { value: null, unit: '%', quality: 'unknown', source: 'Synthetic fixture', collectedAt: '0001-01-01T00:00:00Z' };
    const devices = fleet.items.map((item, index) => ({ id: item.deviceId, name: `SYNTHETIC · Software fixture ${index + 1}`, platform: 'windows', os: 'Windows fixture', source: 'lan', synthetic: false, site: 'Fixture', group: 'Fixture', ip: null, status: 'unknown', lastSeen: now, agentVersion: 'fixture', cpu: metric, memory: metric, disk: metric, uptime: '', tags: [], capabilities: [], evidence: [], trend: [], caseIds: [] }));
    const session = { mode: 'lan', transport: 'https', insecureTestMode: false, transportWarning: null, authenticationRequired: true, authenticated: true, csrfToken: 'synthetic-only', serverNow: now, expiresAt: new Date(Date.parse(now) + 3600000).toISOString(), expiresInSeconds: 3600, loginMode: 'named', actorId: `operator_${'1'.repeat(32)}`, capabilities: ['read'] };
    const started = performance.now();
    const readNow = () => new Date(Date.parse(now) + Math.max(0, Math.floor(performance.now() - started))).toISOString();
    return { now, query, fleet, detailQuery, detail, nextQuery, next, devices, session, readNow };
}
export async function compile() {
    const { build } = require('esbuild');
    const result = await build({ absWorkingDir: root, entryPoints: ['web/src/main.tsx'], outdir: 'web/.fleet-software-memory-only', entryNames: 'app', bundle: true, platform: 'browser', format: 'esm', jsx: 'automatic', define: { 'process.env.NODE_ENV': '"production"' }, loader: { '.woff': 'dataurl', '.woff2': 'dataurl', '.svg': 'dataurl', '.png': 'dataurl' }, write: false, minify: true, metafile: true, logLevel: 'silent' });
    const assets = new Map(result.outputFiles.map(file => [`/${path.basename(file.path)}`, { body: Buffer.from(file.contents), contentType: file.path.endsWith('.css') ? 'text/css' : 'text/javascript' }]));
    assert(assets.has('/app.js') && assets.has('/app.css'));
    assets.set('/', { contentType: 'text/html', body: '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Synthetic fleet software lookup</title><link rel="icon" href="data:,"><link rel="stylesheet" href="/app.css"></head><body><div id="root"></div><script type="module" src="/app.js"></script></body></html>' });
    const names = [...new Set([...Object.keys(result.metafile.inputs).filter(file => file.startsWith('web/src/')), ...['windows-fleet-software-fixtures.ts', 'windows-full-software-fixtures.ts', 'windows-full-software-go-fixture.json'].map(file => `web/src/${file}`), ...['capture-windows-fleet-software.mjs', 'windows-fleet-software-contract.mjs', 'windows-fleet-software-scenes.json', 'run-windows-fleet-software-ci.mjs', 'check-windows-fleet-software-evidence.mjs'].map(file => `web/scripts/${file}`)])].sort();
    const sourceInputs = await Promise.all(names.map(async file => ({ file, sha256: sha256(await readFile(path.join(root, file))) })));
    return { assets, sourceInputs, sourceDigest: sha256(JSON.stringify(sourceInputs)) };
}
export function routeFixture(data, compiled, state) { return async route => {
    const req = route.request(), url = new URL(req.url()), method = req.method(), raw = req.postData();
    const blocked = kind => { state[kind]++; return route.abort('blockedbyclient'); };
    if (url.origin !== origin) return blocked('external');
    const reply = (value, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(value) });
    if (method === 'POST' && url.pathname === queryPath && !url.search) {
        const headers = req.headers();
        if (headers['content-type'] !== 'application/json' || headers['x-csrf-token'] !== data.session.csrfToken) return blocked('unexpected');
        for (const [input, output] of [[data.query, data.fleet], [data.detailQuery, data.detail], [data.nextQuery, data.next]]) {
            if (raw === JSON.stringify(input)) { state.queries++; return reply({ ...output, serverNow: data.readNow() }); }
        }
        return blocked('unexpected');
    }
    if (method !== 'GET' || raw !== null) return blocked('writes');
    if (url.search) return blocked('unexpected');
    if (url.pathname === '/api/auth/session') return reply(data.session);
    if (url.pathname === '/api/session') return reply({ csrfToken: data.session.csrfToken });
    if (url.pathname === '/api/overview') return reply({ product: 'Tracebolt', mode: 'lan', generatedAt: data.now, stats: { totalDevices: 2, healthyDevices: 0, attentionDevices: 0, unknownDevices: 2, openCases: 0, criticalCases: 0 }, devices: data.devices, cases: [], activity: [] });
    // Collapsed, unrelated fleet sections get no data or authority in this fixture.
    if (['/api/fleet/identities', '/api/fleet/groups', '/api/enrollment'].includes(url.pathname)) return reply({ error: { code: 'synthetic_unavailable' } }, 503);
    const asset = compiled.assets.get(url.pathname); return asset ? route.fulfill({ status: 200, ...asset }) : blocked('unexpected');
}; }
export async function capture({ browser, expect, output, onStage = () => {} }) {
    assert(process.env.GITHUB_ACTIONS === 'true' && process.env.RUNNER_ENVIRONMENT === 'github-hosted', 'Hosted CI only; use the inert --check locally.');
    onStage('compile', null);
    const compiled = await compile(), captures = []; await mkdir(output, { recursive: true });
    for (const [captureIndex, testCase] of captureMatrix.entries()) {
        const stage = name => onStage(name, captureIndex), { locale, width, height, scene } = testCase, de = locale === 'de';
        stage('fixture');
        const data = await fixture(), state = { external: 0, writes: 0, unexpected: 0, queries: 0 }, errors = [];
        stage('context');
        const context = await browser.newContext({ viewport: { width, height }, locale: de ? 'de-DE' : 'en-US', deviceScaleFactor: 1, reducedMotion: 'reduce', serviceWorkers: 'block' });
        try {
            await context.route('**/*', routeFixture(data, compiled, state)); await context.addInitScript(value => localStorage.setItem('tracebolt.locale', value), locale);
            const page = await context.newPage(); page.on('pageerror', error => errors.push(error.message));
            stage('navigate'); await page.goto(`${origin}/#/devices`);
            stage('open'); await page.getByRole('button', { name: de ? 'Software auf Windows-Geräten suchen' : 'Find software across Windows devices', exact: true }).click();
            const panel = page.getByRole('region', { name: de ? 'Gerätesoftware finden' : 'Find machine software', exact: true });
            await expect(panel).toContainText('HKLM'); assert.equal(state.queries, 0);
            stage('query'); await panel.getByRole('searchbox', { name: de ? 'Anwendungsname' : 'Application name', exact: true }).fill(data.query.name);
            await panel.getByRole('searchbox', { name: de ? 'Wörtliche Version' : 'Literal version', exact: true }).fill(data.query.version);
            const submit = panel.getByRole('button', { name: de ? 'Gemeldete Software suchen' : 'Search reported software', exact: true });
            await submit.focus(); await page.keyboard.press('Enter');
            stage('coverage'); await expect(panel).toContainText(de ? 'Gemeldete Treffer: 22' : 'Reported matches: 22');
            await expect(panel).toContainText(de ? 'Registrierungen mit nicht verfügbaren Suchfeldern: 4' : 'Registrations with unavailable queried fields: 4');
            await expect(panel).toContainText(de ? 'Gerätesoftware-Zustimmung nicht eingerichtet' : 'Machine-software consent not configured');
            let target = panel.locator('.windows-fleet-software-results');
            if (scene === 'exact-device-drill-down') {
                stage('detail'); const detail = panel.getByRole('button', { name: `${de ? 'Alle passenden Registrierungen ansehen' : 'View all matching registrations'}: ${data.fleet.items[0].deviceId}`, exact: true });
                await detail.focus(); await page.keyboard.press('Enter');
                await expect(panel).toContainText(de ? 'Passende Registrierungen: 1–20 von 22' : 'Matching registrations: 1–20 of 22');
                await expect(panel.locator('.windows-fleet-software-results > li')).toHaveCount(1);
                await expect(panel.locator('tbody tr')).toHaveCount(20);
                await expect(panel.locator('.windows-fleet-software-device')).toHaveText(data.fleet.items[0].deviceId);
                await expect(panel.locator('tbody tr').first()).toContainText('Fixture [.*] Ä 1');
                target = panel.locator('.windows-fleet-software-results > li');
            }
            stage('layout'); await page.evaluate(() => document.fonts.ready);
            await target.evaluate(element => element.scrollIntoView({ block: 'start', behavior: 'instant' }));
            assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
            assert.equal(await panel.evaluate(element => element.scrollWidth <= element.clientWidth + 1), true);
            stage('screenshot'); await page.screenshot({ path: path.join(output, testCase.file), animations: 'disabled', fullPage: false });
            if (scene === 'exact-device-drill-down') {
                stage('next'); await panel.getByRole('button', { name: de ? 'Nächste passende Registrierungen' : 'Next matching registrations', exact: true }).click();
                await expect(panel).toContainText(de ? 'Passende Registrierungen: 21–22 von 22' : 'Matching registrations: 21–22 of 22');
                await expect(panel.locator('tbody tr')).toHaveCount(2);
                await expect(panel.locator('.windows-fleet-software-device')).toHaveText(data.fleet.items[0].deviceId);
            }
            stage('final-guards');
            assert.deepEqual(state, { external: 0, writes: 0, unexpected: 0, queries: scene === 'exact-device-drill-down' ? 3 : 1 }); assert.deepEqual(errors, []);
            assert.equal(new URL(page.url()).hash, '#/devices');
            captures.push({ ...testCase, sourceDigest: compiled.sourceDigest, synthetic: true, disclosure });
        } finally { await context.close(); }
    }
    return { captures, sourceDigest: compiled.sourceDigest, sourceInputs: compiled.sourceInputs, browserExecuted: true, nativeAcceptance: false, disclosure };
}
export async function check() {
    const data = await fixture('2026-10-12T22:00:00.000Z'), compiled = await compile(), state = { external: 0, writes: 0, unexpected: 0, queries: 0 }, handler = routeFixture(data, compiled, state);
    const headers = { 'content-type': 'application/json', 'x-csrf-token': data.session.csrfToken };
    let reply; const fake = (method, pathname, body = null, requestHeaders = headers) => ({ request: () => ({ url: () => pathname.startsWith('https:') ? pathname : origin + pathname, method: () => method, postData: () => body, headers: () => requestHeaders }), fulfill: value => { reply = value; }, abort: () => {} });
    for (const [input, output] of [[data.query, data.fleet], [data.detailQuery, data.detail], [data.nextQuery, data.next]]) { await handler(fake('POST', queryPath, JSON.stringify(input))); const value = JSON.parse(reply.body); assert.deepEqual({ ...value, serverNow: output.serverNow }, output); assert(Date.parse(value.serverNow) >= Date.parse(data.now) && Date.parse(value.serverNow) < Date.parse(output.cursorExpiresAt)); }
    for (const pathname of ['/api/fleet/groups', '/api/fleet/windows-maintenance/start', '/api/fleet/windows-incidents/acknowledge', `/api/devices/${data.devices[0].id}/windows/managed-msi/prepare`]) await handler(fake('POST', pathname, '{}'));
    await handler(fake('POST', queryPath, JSON.stringify({ ...data.query, cursor: 'forged' })));
    for (const bad of [{}, { 'content-type': 'application/json' }, { ...headers, 'x-csrf-token': 'wrong' }, { ...headers, 'content-type': 'text/plain' }]) await handler(fake('POST', queryPath, JSON.stringify(data.query), bad));
    await handler(fake('GET', 'https://external.invalid/')); await handler(fake('GET', '/api/unlisted'));
    assert.deepEqual(state, { external: 1, writes: 4, unexpected: 6, queries: 3 });
    return { mode: 'source-only', browserExecuted: false, screenshotsCaptured: 0, nativeAcceptance: false, sourceDigest: compiled.sourceDigest, cases: captureMatrix, dtoAndRouteChecks: 'passed', disclosure };
}
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) { assert.deepEqual(process.argv.slice(2), ['--check']); console.log(JSON.stringify(await check(), null, 2)); }
