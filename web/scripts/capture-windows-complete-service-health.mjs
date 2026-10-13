/** Synthetic changed-view capture source. --check is inert: bundles/validates DTOs
 * only. --capture is strictly hosted-CI-only; no listener or real endpoint exists. */
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { contract, captureMatrix, disclosure } from './windows-complete-service-health-contract.mjs';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const require = createRequire(new URL('../package.json', import.meta.url));
export const origin = 'https://complete-service-health.invalid';
export { disclosure };
export const scenes = contract.scenes;
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
async function bundle(contents, platform = 'node') {
    const { build } = require('esbuild');
    return build({ stdin: { contents, resolveDir: path.join(root, 'web/src'), loader: 'tsx' }, absWorkingDir: root, outdir: 'web/.complete-health-memory-only', entryNames: 'app', bundle: true, platform, format: 'esm', jsx: 'automatic', define: { 'process.env.NODE_ENV': '"production"' }, loader: { '.woff': 'dataurl', '.woff2': 'dataurl', '.svg': 'dataurl', '.png': 'dataurl' }, write: false, metafile: true, minify: platform === 'browser', logLevel: 'silent' });
}
let modules, fixtureInputs = [];
async function fixtureModules() {
    if (!modules) {
        const compiled = await bundle("export * from './windows-service-health-complete-fixture'; export * from './windows-full-services-fixtures'; export * from './windows-service-health-complete-types'; export * from './windows-full-services-types'; export * from './fleet-group-service-checks-complete-fixture'; export * from './fleet-group-service-checks-complete-workflow'; export { windowsCapacityDevice } from './windows-capacity-fixture';");
        fixtureInputs = Object.keys(compiled.metafile.inputs).filter(file => file.startsWith('web/src/'));
        modules = await import(`data:text/javascript;base64,${Buffer.from(compiled.outputFiles[0].contents).toString('base64')}`);
    }
    return modules;
}
export async function fixture(now = new Date().toISOString()) {
    const m = await fixtureModules(), delta = Date.parse(now) - Date.parse(m.fullServicesNow);
    const shift = value => typeof value === 'string' && /^2026-10-1[12]T/.test(value) ? new Date(Date.parse(value) + delta).toISOString() : Array.isArray(value) ? value.map(shift) : value && typeof value === 'object' ? Object.fromEntries(Object.entries(value).map(([key, item]) => [key, shift(item)])) : value;
    const complete = shift(m.fullServicesComplete()); complete.manifestSha256 = m.fullServicesManifestHash(complete.manifest);
    const health = shift(m.completeHealthView()); health.inventory.source = m.completeServiceHealthSource(complete);
    const group = m.completeGroupServiceFixture(), choice = m.completeGroupServiceChoiceFixture();
    // Reuse the exact Go group envelope with the existing complete-generation DTO.
    // Original opaque member key/name stay unchanged; only synthetic clock/source
    // data are aligned for a real paged-picker-to-review round trip.
    for (const value of [group, choice]) { value.serverNow = now; value.authorityExpiresAt = new Date(Date.parse(now) + 120000).toISOString(); }
    assert.equal(choice.member.deviceId, health.deviceId); choice.member.inventory = structuredClone(health.inventory);
    assert(m.validWindowsServiceHealthCompleteView(health, health.deviceId));
    assert(m.validGroupCompleteServiceChecksView(group, group.groupId)); assert(m.validGroupCompleteServiceChoiceView(choice, group.groupId, choice.member.key));
    const device = m.windowsCapacityDevice(); device.id = health.deviceId; device.name = 'SYNTHETIC · Complete services'; device.agentCertificate.checkedAt = now; device.agentCertificate.expiresAt = health.certificateExpiresAt;
    const session = { mode: 'lan', transport: 'https', insecureTestMode: false, transportWarning: null, authenticationRequired: true, authenticated: true, csrfToken: 'synthetic-only', serverNow: now, expiresAt: new Date(Date.parse(now) + 3600000).toISOString(), expiresInSeconds: 3600, loginMode: 'shared', actorId: null, capabilities: ['read'] };
    const started = performance.now(), readNow = () => new Date(Date.parse(now) + Math.max(0, Math.floor(performance.now() - started))).toISOString();
    const page = (query, offset) => { const value = shift(m.fullServicesPage(query, m.fullServiceRows(), m.fullServicesComplete(), offset)); value.complete = structuredClone(complete); value.serverNow = readNow(); assert(m.validFullServicesPage(value, health.deviceId, query, offset)); return value; };
    const groups = { schemaVersion: 'tracebolt.fleet-groups.v1', serverNow: now, groups: [{ id: group.groupId, name: group.groupName, revision: group.groupRevision, memberIds: group.members.map(member => member.deviceId), unavailableMembers: group.unavailableMembers }], devices: group.members.map(member => ({ id: member.deviceId, name: member.name, platform: 'windows' })) };
    return { health, group, choice, groups, device, session, page, readNow, bootstrap: { device, session } };
}
export async function compile() {
    await fixtureModules();
    const code = `import React from 'react'; import { createRoot } from 'react-dom/client'; import './styles.css'; import { WindowsServiceHealthCompletePanel } from './windows-service-health-complete'; import { useWindowsServiceHealthComplete } from './windows-service-health-complete-resource'; import { FleetGroupsControls, useFleetGroups } from './fleet-groups'; const data = window.__COMPLETE_HEALTH_FIXTURE__; function Device() { const resource = useWindowsServiceHealthComplete(data.device.id, true, data.session.expiresAt, true, data.device.agentCertificate); return <WindowsServiceHealthCompletePanel device={data.device} resource={resource} sessionKey={data.session.expiresAt} metadataReady admin/>; } function Group() { const resource = useFleetGroups(true, data.session.expiresAt, true); return <FleetGroupsControls key={resource.generation} resource={resource}/>; } createRoot(document.getElementById('root')).render(<React.StrictMode><main style={{maxWidth:1050,margin:'0 auto',padding:16}}><p role="note">SYNTHETIC · Source-only fixture · No endpoint actions</p>{location.hash === '#group' ? <Group/> : <Device/>}</main></React.StrictMode>);`;
    const result = await bundle(code, 'browser');
    const assets = new Map(result.outputFiles.map(file => [`/${path.basename(file.path)}`, { body: Buffer.from(file.contents), contentType: file.path.endsWith('.css') ? 'text/css' : 'text/javascript' }]));
    assert(assets.has('/app.js') && assets.has('/app.css'));
    assets.set('/', { contentType: 'text/html', body: '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="icon" href="data:,"><link rel="stylesheet" href="/app.css"><title>Synthetic complete service checks</title></head><body><div id="root"></div><script type="module" src="/app.js"></script></body></html>' });
    const files = [...new Set([...fixtureInputs, ...Object.keys(result.metafile.inputs).filter(file => file.startsWith('web/src/')), 'web/src/windows-complete-service-health-go-fixture.json', 'web/src/windows-complete-group-service-go-fixture.json', 'web/src/windows-full-services-go-fixture.json', 'web/src/windows-service-health-complete-fixture.ts', 'web/src/windows-full-services-fixtures.ts', 'web/scripts/capture-windows-complete-service-health.mjs', 'web/scripts/windows-complete-service-health-scenes.json', 'web/scripts/windows-complete-service-health-contract.mjs', 'web/scripts/check-windows-complete-service-health-evidence.mjs'])].sort();
    const sourceInputs = await Promise.all(files.map(async file => ({ file, sha256: hash(await readFile(path.join(root, file))) })));
    return { assets, sourceInputs, sourceDigest: hash(JSON.stringify(sourceInputs)) };
}
export function routeFixture(data, compiled, state) { const cursors = new Map(); return async route => {
    const req = route.request(), url = new URL(req.url()), method = req.method(), raw = req.postData();
    const blocked = kind => { state[kind]++; return route.abort('blockedbyclient'); };
    if (url.origin !== origin) return blocked('external');
    const respond = body => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });
    if (url.search) return blocked('unexpected');
    if (method === 'POST' && url.pathname === `/api/devices/${data.health.deviceId}/windows-full-services/query`) {
        const headers = req.headers(); if (headers['content-type'] !== 'application/json' || headers['x-csrf-token'] !== data.session.csrfToken) return blocked('unexpected');
        let query; try { query = JSON.parse(raw); } catch { return blocked('unexpected'); }
        if (Object.keys(query).sort().join(',') !== 'cursor,limit,search,sort' || query.limit !== 100 || query.sort !== 'name-asc' || !['', 'FixtureService0150'].includes(query.search)) return blocked('unexpected');
        const position = query.cursor ? cursors.get(query.cursor) : { offset: 0, search: query.search };
        if (!position || position.search !== query.search) return blocked('unexpected');
        const value = data.page(query, position.offset); if (value.nextCursor) cursors.set(value.nextCursor, { offset: value.offset + value.rows.length, search: value.search }); state.queries++; return respond(value);
    }
    if (method !== 'GET' || raw !== null) return blocked('writes');
    if (url.pathname === '/api/session') return respond({ csrfToken: data.session.csrfToken });
    if (url.pathname === '/api/auth/session') return respond({ ...data.session, serverNow: data.readNow() });
    if (url.pathname === `/api/devices/${data.health.deviceId}/windows-services/complete`) return respond({ ...data.health, serverNow: data.readNow() });
    if (url.pathname === '/api/fleet/groups') return respond({ ...data.groups, serverNow: data.readNow() });
    if (url.pathname === `/api/fleet/groups/${data.group.groupId}/service-checks-complete`) return respond({ ...data.group, serverNow: data.readNow() });
    if (url.pathname === `/api/fleet/groups/${data.group.groupId}/service-checks-complete/${data.choice.member.key}`) return respond({ ...data.choice, serverNow: data.readNow() });
    const asset = compiled.assets.get(url.pathname); return asset ? route.fulfill({ status: 200, ...asset }) : blocked('unexpected');
}; }
export async function capture({ browser, expect, output }) {
    assert(process.env.GITHUB_ACTIONS === 'true' && process.env.RUNNER_ENVIRONMENT === 'github-hosted', 'Hosted CI only.');
    const compiled = await compile(), captures = []; await mkdir(output, { recursive: true });
    for (const { locale, width, height, scene, file } of captureMatrix) {
        const data = await fixture(), de = locale === 'de', state = { external: 0, writes: 0, unexpected: 0, queries: 0 }, errors = [];
        const context = await browser.newContext({ viewport: { width, height }, reducedMotion: 'reduce', locale: de ? 'de-DE' : 'en-US', serviceWorkers: 'block' });
        try {
            await context.route('**/*', routeFixture(data, compiled, state));
            await context.addInitScript(({ locale, bootstrap }) => { localStorage.setItem('tracebolt.locale', locale); window.__COMPLETE_HEALTH_FIXTURE__ = bootstrap; }, { locale, bootstrap: data.bootstrap });
            const page = await context.newPage(); page.on('pageerror', error => errors.push(error.message)); await page.goto(`${origin}/${scene === 'group-exact-review' ? '#group' : ''}`);
            if (scene === 'group-exact-review') {
                const groups = de ? 'Flottengruppen' : 'Fleet groups'; await page.getByRole('button', { name: groups, exact: true }).click(); await page.getByRole('combobox', { name: groups, exact: true }).selectOption(data.group.groupId);
                await page.getByRole('button', { name: de ? 'Vollständige Dienstprüfungen anwenden' : 'Apply complete service checks', exact: true }).click();
                await page.getByRole('checkbox', { name: `${data.choice.member.name} ${data.choice.member.deviceId}`, exact: true }).check(); await page.getByRole('button', { name: de ? 'Dienstoptionen der Auswahl laden' : 'Load selected service choices', exact: true }).click();
            } else {
                await page.getByText(de ? 'Richtlinie für ausgewählte Dienste & Grenzen' : 'Selected-service policy settings & limits', { exact: true }).click();
                await page.getByRole('button', { name: de ? 'Vollständige Generation prüfen' : 'Review complete generation', exact: true }).click();
            }
            await expect(page.locator('.windows-service-options li')).toHaveCount(100);
            await page.getByRole('button', { name: de ? 'Nächste Dienstseite' : 'Next service page', exact: true }).click(); await expect(page.locator('.windows-service-options code').first()).toHaveText('FixtureService0100');
            await page.locator('.windows-service-options label').filter({ has: page.locator('code', { hasText: /^FixtureService0150$/ }) }).locator('input').check();
            const enable = scene === 'group-exact-review' ? `${de ? 'Dienstprüfungen aktivieren' : 'Enable service checks'} · ${data.choice.member.name}` : de ? 'Richtlinie für ausgewählte Dienste aktivieren' : 'Enable selected-service policy';
            await page.getByRole('checkbox', { name: enable, exact: true }).check();
            if (scene === 'group-exact-review') { await page.getByRole('button', { name: de ? 'Exakte Dienstprüfungen prüfen' : 'Review exact service checks', exact: true }).click(); await expect(page.getByRole('table')).toContainText('FixtureService0150'); await expect(page.getByRole('checkbox', { name: de ? 'Diese exakten Dienstprüfungsrichtlinien einmal auf diese gewählten Mitglieder anwenden.' : 'Apply these exact service-check policies to these selected members once.', exact: true })).not.toBeChecked(); }
            else { await expect(page.getByRole('button', { name: de ? 'Richtlinie für ausgewählte Dienste speichern' : 'Save selected-service policy', exact: true })).toBeEnabled(); await page.locator('.windows-service-selections').scrollIntoViewIfNeeded(); }
            await page.evaluate(() => document.fonts.ready); assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
            await page.screenshot({ path: path.join(output, file), animations: 'disabled', fullPage: false });
            assert.deepEqual(errors, []); assert.equal(state.external + state.writes + state.unexpected, 0); assert.equal(state.queries, 2);
            captures.push({ file, scene, locale, width, height, synthetic: true, sha256: hash(await readFile(path.join(output, file))), sourceDigest: compiled.sourceDigest });
        } finally { await context.close(); }
    }
    return { captures, sourceInputs: compiled.sourceInputs, sourceDigest: compiled.sourceDigest, disclosure, browserExecuted: true, appMounted: false, nativeAcceptance: false, actualMutationRequests: 0 };
}
export async function check() {
    const data = await fixture('2026-10-13T12:00:00Z'), compiled = await compile(), state = { external: 0, writes: 0, unexpected: 0, queries: 0 }, handler = routeFixture(data, compiled, state);
    let response; const fake = (method, target, body = null) => ({ request: () => ({ url: () => target.startsWith('https:') ? target : origin + target, method: () => method, postData: () => body, headers: () => ({ 'content-type': 'application/json', 'x-csrf-token': data.session.csrfToken }) }), fulfill: value => { response = value; }, abort: () => {} });
    const first = { search: '', sort: 'name-asc', limit: 100, cursor: '' };
    await handler(fake('POST', `/api/devices/${data.health.deviceId}/windows-full-services/query`, JSON.stringify(first))); const page = JSON.parse(response.body); assert.equal(page.rows.length, 100);
    await handler(fake('POST', `/api/devices/${data.health.deviceId}/windows-full-services/query`, JSON.stringify({ ...first, cursor: page.nextCursor }))); assert.equal(JSON.parse(response.body).rows[50].name, 'FixtureService0150');
    await handler(fake('POST', `/api/devices/${data.health.deviceId}/windows-services/complete/policy`, '{}'));
    await handler(fake('GET', 'https://untrusted.invalid/')); assert.deepEqual(state, { external: 1, writes: 1, unexpected: 0, queries: 2 });
    assert(compiled.assets.size >= 3); return { sourceDigest: compiled.sourceDigest, browserExecuted: false, nativeAcceptance: false, disclosure };
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    if (process.argv.includes('--check')) console.log(JSON.stringify(await check()));
    else if (process.argv.includes('--capture')) {
        assert(process.env.GITHUB_ACTIONS === 'true' && process.env.RUNNER_ENVIRONMENT === 'github-hosted', 'Hosted CI only; --check performs no browser work.');
        const { chromium, expect } = require('@playwright/test'), browser = await chromium.launch({ headless: true });
        try { const output = path.resolve(process.env.TRACEBOLT_CAPTURE_OUTPUT ?? path.join(root, 'artifacts/complete-service-health')); const manifest = await capture({ browser, expect, output }); await writeFile(path.join(output, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n'); } finally { await browser.close(); }
    } else throw new Error('Use --check, or --capture only in the gated hosted runner.');
}
