/**
 * Inert synthetic Windows fleet MSI browser fixture and screenshot recipe.
 *
 * Source-only check (no listener, browser, screenshot, manager or endpoint):
 *   node web/scripts/capture-windows-fleet-msi-fixtures.mjs --check
 *
 * A separately permitted browser runner may import captureWindowsFleetMSIFixtures
 * and pass its existing Playwright `browser`, `expect`, and an output directory.
 * This module deliberately contains no browser-launch or server-start operation.
 * Do not use this recipe to bypass a denied browser or process launch.
 *
 * All HTTPS routes are fulfilled from compiled production assets or invented
 * read-only DTOs. Every non-GET and external request is blocked and counted.
 * The admitted-looking DTOs exercise UI guards only; they are not live devices,
 * grants, durable manager state, native acceptance, installation or release.
 */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const web = fileURLToPath(new URL('../', import.meta.url));
const root = path.dirname(web.replace(/\/$/, ''));
const require = createRequire(new URL('../package.json', import.meta.url));
export const windowsFleetMSIOrigin = 'https://windows-fleet-msi.invalid';
export const windowsFleetMSIDisclosure = 'Synthetic source fixture of compiled production UI and invented, fully intercepted HTTPS responses. No real login, live device, grant, package bytes, upload, delivery, manager write, native installer, update, service action or reboot. 3010 and registration truth remain independent. Source compilation is not browser execution or native acceptance.';
export const windowsFleetMSICases = Object.freeze(
  ['en', 'de'].flatMap(locale => [1440, 390].map(width => ({ locale, width, height: width === 390 ? 844 : 1100 }))),
);
const digest = byte => `sha256:${byte.repeat(64)}`;
const clone = value => structuredClone(value);
let contractsPromise;

async function contracts() {
  contractsPromise ??= (async () => {
    const { build } = require('esbuild');
    const result = await build({
      stdin: {
        contents: "export { validManagedArtifact, validManagedView } from './windows-managed-msi-types'; export { windowsHealthDevice } from './windows-health-fixture';",
        resolveDir: path.join(web, 'src'), loader: 'ts',
      },
      bundle: true, platform: 'node', format: 'esm', write: false, logLevel: 'silent',
    });
    return import(`data:text/javascript;base64,${Buffer.from(result.outputFiles[0].text).toString('base64')}`);
  })();
  return contractsPromise;
}

/** Build production main.tsx and its actual CSS, without mock component aliases. */
export async function compileWindowsFleetMSIAssets() {
  const { build } = require('esbuild');
  const result = await build({
    absWorkingDir: root, entryPoints: [path.join(web, 'src/main.tsx')],
    outdir: path.join(web, '.fleet-msi-fixture-memory-only'), entryNames: 'app',
    bundle: true, platform: 'browser', format: 'esm', jsx: 'automatic',
    define: { 'process.env.NODE_ENV': '"production"' },
    loader: { '.woff': 'dataurl', '.woff2': 'dataurl', '.svg': 'dataurl', '.png': 'dataurl' },
    write: false, minify: true, metafile: true, logLevel: 'silent',
  });
  const assets = new Map(result.outputFiles.map(file => [`/${path.basename(file.path)}`, {
    body: Buffer.from(file.contents),
    contentType: file.path.endsWith('.css') ? 'text/css; charset=utf-8' : 'text/javascript; charset=utf-8',
  }]));
  assert(assets.has('/app.js') && assets.has('/app.css'), 'Production JS and CSS must compile');
  const sourceFiles = Object.keys(result.metafile.inputs)
    .map(name => path.resolve(root, name)).filter(name => name.startsWith(path.join(web, 'src') + path.sep)).sort();
  assert(sourceFiles.some(name => name.endsWith('/windows-fleet-managed-msi.tsx')), 'Production App must include the fleet MSI component');
  const sourceInputs = await Promise.all(sourceFiles.map(async name => ({
    file: path.relative(root, name).split(path.sep).join('/'),
    sha256: createHash('sha256').update(await readFile(name)).digest('hex'),
  })));
  assets.set('/', {
    contentType: 'text/html; charset=utf-8',
    body: Buffer.from('<!doctype html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Synthetic Windows fleet MSI fixture</title><link rel="icon" href="data:,"><link rel="stylesheet" href="/app.css"></head><body><div id="root"></div><script type="module" src="/app.js"></script></body></html>'),
  });
  return {
    assets, sourceInputs,
    sourceDigest: createHash('sha256').update(JSON.stringify(sourceInputs)).digest('hex'),
    compiledBytes: result.outputFiles.reduce((sum, file) => sum + file.contents.length, 0),
  };
}

export async function createWindowsFleetMSIFixture(now = new Date(Math.floor(Date.now() / 1000) * 1000).toISOString()) {
  const { windowsHealthDevice, validManagedArtifact, validManagedView } = await contracts();
  const seconds = Date.parse(now) / 1000;
  assert(Number.isSafeInteger(seconds) && seconds > 0, 'Fixture needs an exact UTC second');
  const devices = ['a', 'b'].map((letter, index) => ({
    ...windowsHealthDevice(), id: `agent_${letter.repeat(32)}`,
    name: index === 0 ? 'SYNTHETIC · Berlin MSI target' : 'SYNTHETIC · Hamburg saved result',
    status: 'unknown', lastSeen: now,
    agentCertificate: { source: 'guided-enrollment', checkedAt: now, expiresAt: new Date((seconds + 86400) * 1000).toISOString() },
  }));
  const session = {
    mode: 'lan', transport: 'https', insecureTestMode: false, transportWarning: null,
    authenticationRequired: true, authenticated: true,
    csrfToken: 'PUBLIC_SYNTHETIC_FLEET_MSI_CSRF', serverNow: now,
    expiresAt: new Date((seconds + 3600) * 1000).toISOString(), expiresInSeconds: 3600,
    loginMode: 'named', actorId: `operator_${'c'.repeat(32)}`,
    capabilities: ['read', 'windows_managed_msi_deliver', 'windows_managed_msi_install'],
  };
  const selection = {
    sha256: digest('1'), size: 1048576,
    productCode: '{11111111-2222-3333-4444-555555555555}',
    packageCode: '{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}',
    version: '1.2.3', architecture: 'amd64', name: 'Synthetic reviewed machine package',
    termsReviewDigest: digest('2'), reviewReference: 'Invented source-only package review; no MSI bytes',
  };
  const artifact = {
    version: 'tracebolt.windows-managed-msi-artifact.v2', serverNow: seconds, state: 'uploaded',
    artifactId: digest('3'), package: selection, nativeAcceptanceDigest: digest('4'),
    uploadOffset: selection.size, uploadPendingDigest: '',
    targets: devices.map((device, index) => ({ deviceId: device.id, bindingDigest: digest(index === 0 ? '5' : '6') })),
  };
  const views = devices.map((device, index) => ({
    version: 'tracebolt.windows-managed-msi.v1', deviceId: device.id, serverNow: seconds,
    state: 'uploaded', artifactId: artifact.artifactId, bindingDigest: artifact.targets[index].bindingDigest,
    package: selection, nativeAcceptanceDigest: artifact.nativeAcceptanceDigest,
    transferId: '', readinessDigest: '', expiresAt: 0, readiness: null, result: null,
    uploadOffset: selection.size, uploadPendingDigest: '', canReview: false,
  }));
  Object.assign(views[1], {
    state: 'complete', transferId: `transfer_${'7'.repeat(32)}`,
    result: {
      returnCodeKnown: true, jobId: `software_${'7'.repeat(32)}`, envelopeDigest: digest('8'),
      attempted: true, outcome: 'restart_required', returnCode: 3010,
      registrationVerified: 'unknown', completedAt: seconds - 20,
    },
    coordinated: true, mutationCapturedAt: seconds - 1,
    mutation: {
      active: true, blocked: true, domain: 'cached_wua', jobId: `update_${'9'.repeat(32)}`,
      phase: 'dispatch_intent', recovery: 'intervention_required', revision: '7', retained: 1,
    },
  });
  assert(validManagedArtifact(artifact), 'Synthetic artifact must pass production validation');
  views.forEach((view, index) => assert(validManagedView(view, devices[index].id), 'Synthetic target must pass production validation'));
  const reads = { artifact: 0, devices: Object.fromEntries(devices.map(device => [device.id, 0])) };
  return {
    now, seconds, devices, session, artifact, views, reads,
    readArtifact() { reads.artifact++; return clone(artifact); },
    readDevice(id) {
      const index = devices.findIndex(device => device.id === id);
      if (index < 0) return null;
      reads.devices[id]++;
      return clone(views[index]);
    },
    // Changes only invented saved status; never a manager route or native action.
    showSavedIdleOwner() {
      views[1].mutation = { active: true, blocked: false, phase: 'idle', revision: '8', retained: 1 };
      assert(validManagedView(views[1], devices[1].id));
    },
  };
}

export function createWindowsFleetMSIRoute({ fixture, compiled, state }) {
  return async route => {
    const request = route.request(), url = new URL(request.url());
    const method = request.method(), raw = request.postData();
    const block = reason => { state.blocked.push(reason); return route.abort('blockedbyclient'); };
    if (url.origin !== windowsFleetMSIOrigin) { state.external.push('external'); return block('external-origin'); }
    if (method !== 'GET' || raw !== null) { state.writes.push({ method, path: url.pathname }); return block('unexpected-write'); }
    if (url.search) return block('unexpected-query');
    const reply = value => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(value) });
    if (url.pathname === '/api/auth/session') return reply(fixture.session);
    if (url.pathname === '/api/session') return reply({ csrfToken: fixture.session.csrfToken });
    if (url.pathname === '/api/overview') return reply({
      product: 'Tracebolt', mode: 'lan', generatedAt: fixture.now,
      stats: { totalDevices: 2, healthyDevices: 0, attentionDevices: 0, unknownDevices: 2, openCases: 0, criticalCases: 0 },
      devices: fixture.devices, cases: [], activity: [],
    });
    if (url.pathname === '/api/fleet/identities') return reply({ schemaVersion: 'tracebolt.fleet-identities.v2', serverNow: fixture.now, items: [] });
    if (url.pathname === '/api/fleet/groups') return reply({ schemaVersion: 'tracebolt.fleet-groups.v1', serverNow: fixture.now, groups: [], devices: fixture.devices.map(({ id, name, platform }) => ({ id, name, platform })) });
    if (url.pathname === '/api/windows-managed-msi/artifact') return reply(fixture.readArtifact());
    const managed = /^\/api\/devices\/(agent_[a-f0-9]{32})\/windows-managed-msi$/.exec(url.pathname);
    if (managed) { const value = fixture.readDevice(managed[1]); return value ? reply(value) : block('unknown-target'); }
    if (url.pathname.startsWith('/api/')) return route.fulfill({ status: 503, contentType: 'application/json', body: JSON.stringify({ error: { code: 'synthetic_unavailable' } }) });
    const asset = compiled.assets.get(url.pathname);
    if (!asset) return block('unknown-asset');
    return route.fulfill({ status: 200, ...asset });
  };
}

/** Source-only route/DTO assertions. No Playwright import, browser or network. */
export async function checkWindowsFleetMSIFixtures() {
  const fixture = await createWindowsFleetMSIFixture('2026-10-12T10:00:00.000Z');
  const { validManagedArtifact, validManagedView } = await contracts();
  assert.notEqual(fixture.devices[0].id, fixture.devices[1].id);
  assert.notEqual(fixture.artifact.targets[0].bindingDigest, fixture.artifact.targets[1].bindingDigest);
  assert.equal(validManagedArtifact({ ...fixture.artifact, targets: [fixture.artifact.targets[0], fixture.artifact.targets[0]] }), false);
  assert.equal(validManagedView(fixture.views[1], fixture.devices[0].id), false);
  assert.equal(validManagedView({ ...fixture.views[1], result: { ...fixture.views[1].result, outcome: 'succeeded' } }, fixture.devices[1].id), false);
  assert.equal(validManagedView({ ...fixture.views[0], artifactId: 'not-a-digest' }, fixture.devices[0].id), false);
  const originalResult = clone(fixture.views[1].result);
  fixture.showSavedIdleOwner();
  assert.deepEqual(fixture.views[1].result, originalResult);
  const state = { blocked: [], external: [], writes: [] };
  const route = createWindowsFleetMSIRoute({ fixture, compiled: { assets: new Map() }, state });
  async function request(url, method = 'GET', body = null) {
    let response;
    await route({ request: () => ({ url: () => url, method: () => method, postData: () => body }),
      fulfill: value => { response = value; }, abort: reason => { response = { aborted: reason }; } });
    return response;
  }
  const base = windowsFleetMSIOrigin;
  assert.equal((await request(`${base}/api/windows-managed-msi/artifact`)).status, 200);
  for (const device of fixture.devices) assert.equal((await request(`${base}/api/devices/${device.id}/windows-managed-msi`)).status, 200);
  assert.equal((await request(`${base}/api/devices/${fixture.devices[1].id}/windows-managed-msi/approve`, 'POST', '{}')).aborted, 'blockedbyclient');
  assert.equal((await request('https://example.invalid/api/overview')).aborted, 'blockedbyclient');
  assert.equal((await request(`${base}/api/devices/agent_${'d'.repeat(32)}/windows-managed-msi`)).aborted, 'blockedbyclient');
  assert.equal(state.writes.length, 1);
  assert.equal(state.external.length, 1);
  const compiled = await compileWindowsFleetMSIAssets();
  return {
    mode: 'source-only', compiled: true, sourceDigest: compiled.sourceDigest,
    compiledBytes: compiled.compiledBytes, productionSourceInputs: compiled.sourceInputs.length,
    dtoAndRouteChecks: 'passed', targetCount: fixture.devices.length,
    proposedCases: windowsFleetMSICases, browserExecuted: false, screenshotsCaptured: 0,
    nativeAcceptance: false, disclosure: windowsFleetMSIDisclosure,
  };
}

export async function exerciseWindowsFleetMSI({ page, expect, fixture, locale, width, shot }) {
  const de = locale === 'de', title = de ? 'Windows-MSI-Arbeitsliste' : 'Windows MSI worklist';
  await page.goto(`${windowsFleetMSIOrigin}/#/devices`);
  await expect(page.locator('html')).toHaveAttribute('lang', locale);
  const worklist = page.getByRole('region', { name: title, exact: true });
  await worklist.getByRole('button', { name: title, exact: true }).click();
  await expect(worklist).toContainText(fixture.artifact.package.name);
  const panel = worklist.locator('.managed-msi-panel:not(.managed-msi-artifact)');
  const capture = async (kind, focus = panel) => {
    await page.evaluate(() => document.fonts.ready);
    await focus.evaluate(element => element.scrollIntoView({ block: 'start', behavior: 'instant' }));
    expect(await worklist.evaluate(element => element.scrollWidth <= element.clientWidth + 1)).toBe(true);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
    await shot(page, `synthetic-windows-fleet-msi-${kind}-${width}-${locale}`);
  };
  await capture('uploaded-artifact', worklist.locator('.managed-msi-artifact'));
  const choices = worklist.getByRole('group', { name: de ? 'Geräte auswählen' : 'Select devices', exact: true });
  const freeze = worklist.getByRole('button', { name: de ? 'Geräteauswahl festhalten' : 'Freeze device selection', exact: true });
  await expect(choices.getByRole('checkbox')).toHaveCount(2);
  await expect(freeze).toBeDisabled();
  for (const device of fixture.devices) {
    const checkbox = choices.getByRole('checkbox', { name: new RegExp(device.name) });
    await expect(checkbox).not.toBeChecked();
    await checkbox.check();
  }
  await freeze.click();
  await expect(choices).toHaveCount(0);
  await expect(panel).toHaveCount(0);
  expect(Object.values(fixture.reads.devices)).toEqual([0, 0]);
  const open = device => worklist.getByRole('button', { name: `${de ? 'Gerät öffnen' : 'Open device'}: ${device.name}`, exact: true });
  await open(fixture.devices[0]).click();
  await expect(panel).toContainText(fixture.devices[0].id);
  const delivery = panel.getByRole('button', { name: de ? 'An dieses Gerät verteilen' : 'Deliver to this device', exact: true });
  await expect(panel.getByRole('checkbox')).toHaveCount(1);
  await expect(panel.getByRole('checkbox')).not.toBeChecked();
  await expect(delivery).toBeDisabled();
  expect(fixture.reads.devices[fixture.devices[1].id]).toBe(0);
  await capture('delivery-unchecked');
  await open(fixture.devices[1]).click();
  await expect(panel).toHaveCount(1);
  await expect(panel).toContainText(fixture.devices[1].id);
  await expect(panel).toContainText(de ? '3010: Neustart erforderlich' : '3010: Restart required');
  await expect(panel).toContainText(de ? 'Exakte Geräteregistrierung: Unbekannt' : 'Exact machine registration: Unknown');
  await expect(panel).not.toContainText(de ? 'Installiert; exakte Registrierung geprüft' : 'Installed; exact registration verified');
  await expect(panel.getByRole('checkbox')).toHaveCount(0);
  await expect(panel.locator('.windows-mutation-status')).toContainText(de ? 'Blockiert durch Windows-Update' : 'Blocked by Windows Update');
  await expect(panel.locator('.windows-mutation-status details')).not.toHaveAttribute('open');
  await capture('saved-3010-shared-owner');
  const savedResult = clone(fixture.views[1].result);
  fixture.showSavedIdleOwner();
  await panel.getByRole('button', { name: de ? 'Gespeicherten Status lesen' : 'Read saved status', exact: true }).click();
  await expect(panel.locator('.windows-mutation-status')).toContainText(de ? 'Kein Besitzer gespeichert' : 'No owner saved');
  await expect(panel).toContainText(de ? '3010: Neustart erforderlich' : '3010: Restart required');
  await expect(panel).toContainText(de ? 'Exakte Geräteregistrierung: Unbekannt' : 'Exact machine registration: Unknown');
  expect(fixture.views[1].result).toEqual(savedResult);
  await capture('saved-3010-owner-refreshed');
  await open(fixture.devices[0]).click();
  await expect(panel).toContainText(fixture.devices[0].id);
  await expect(panel.getByRole('checkbox')).not.toBeChecked();
  await expect(delivery).toBeDisabled();
  await expect(panel).not.toContainText('3010');
  await worklist.getByRole('button', { name: `${de ? 'Gerät schließen' : 'Close device'}: ${fixture.devices[0].name}`, exact: true }).click();
  await expect(panel).toHaveCount(0);
  return { targetCount: 2, noAutomaticNextDevice: true, deliveryUnchecked: true, saved3010Registration: 'unknown', sharedStatusPreservesResult: true };
}

/** The caller owns an already-authorized browser. This helper never launches one. */
export async function captureWindowsFleetMSIFixtures({ browser, expect, output }) {
  assert(browser && typeof browser.newContext === 'function' && typeof expect === 'function');
  assert(typeof output === 'string' && output.length > 0);
  const compiled = await compileWindowsFleetMSIAssets(), captures = [];
  await mkdir(output, { recursive: true });
  for (const testCase of windowsFleetMSICases) {
    const { locale, width, height } = testCase;
    const fixture = await createWindowsFleetMSIFixture();
    const state = { blocked: [], external: [], writes: [], pageErrors: [] };
    const context = await browser.newContext({ viewport: { width, height }, locale: locale === 'de' ? 'de-DE' : 'en-US', deviceScaleFactor: 1, reducedMotion: 'reduce', serviceWorkers: 'block' });
    try {
      await context.route('**/*', createWindowsFleetMSIRoute({ fixture, compiled, state }));
      await context.addInitScript(value => localStorage.setItem('tracebolt.locale', value), locale);
      const page = await context.newPage();
      page.on('pageerror', error => state.pageErrors.push(error.message));
      const pendingCaptures = [];
      const result = await exerciseWindowsFleetMSI({ page, expect, fixture, ...testCase, shot: async (target, name) => {
        const file = `${name}.png`;
        await target.screenshot({ path: path.join(output, file), animations: 'disabled', fullPage: false });
        pendingCaptures.push({ file, ...testCase, synthetic: true, sourceDigest: compiled.sourceDigest, disclosure: windowsFleetMSIDisclosure });
      } });
      expect(state).toEqual({ blocked: [], external: [], writes: [], pageErrors: [] });
      captures.push(...pendingCaptures.map(capture => ({ ...capture, assertions: result })));
    } finally {
      await context.close();
    }
  }
  const manifest = { browserExecuted: true, nativeAcceptance: false, capturedAt: new Date().toISOString(), sourceDigest: compiled.sourceDigest, sourceInputs: compiled.sourceInputs, disclosure: windowsFleetMSIDisclosure, captures };
  await writeFile(path.join(output, 'windows-fleet-msi-manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
  return manifest;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  assert.deepEqual(process.argv.slice(2), ['--check'], 'Only --check is supported here. Browser captures require a separately permitted existing browser and the exported recipe.');
  console.log(JSON.stringify(await checkWindowsFleetMSIFixtures(), null, 2));
}
