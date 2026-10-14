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
 * read-only DTOs. External requests and writes are blocked and counted. Only the
 * exact saved-worklist preview POST described by its synthetic fixture is admitted;
 * it reads invented data, is counted separately, and cannot confirm or dispatch.
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
        contents: "export { validManagedArtifact, validManagedView } from './windows-managed-msi-types'; export { windowsHealthDevice } from './windows-health-fixture'; export { validWorklistView, validWorklistsView, validWorklistPreview } from './windows-managed-msi-worklist-types';",
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
    .map(name => path.resolve(root, name)).filter(name => name.startsWith(path.join(web, 'src') + path.sep))
    .concat(['capture-windows-fleet-msi-fixtures.mjs', 'capture-windows-reusable-msi-fixtures.mjs',
      'capture-windows-scheduled-msi-fixtures.mjs', 'capture-windows-software-catalogue-fixtures.mjs',
      'capture-windows-msi-catalogue-fixtures.mjs', 'run-windows-fleet-msi-ci.mjs',
      'run-windows-msi-catalogue-ci.mjs', 'windows-msi-catalogue-scenes.json'].map(name => path.join(web, 'scripts', name))).sort();
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
      if (index < 0 || !views[index]) return null;
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

export const windowsSavedMSIScenes = Object.freeze(['compact-summary', 'expanded-evidence', 'delivery-unchecked', 'review-unchecked', 'approval-unchecked', 'retirement-unchecked', 'retired-outcomes']);
export const windowsSavedMSICaptureMatrix = Object.freeze(windowsSavedMSIScenes.flatMap(scene => windowsFleetMSICases.map(testCase => Object.freeze({
  scene, ...testCase, file: `synthetic-windows-saved-msi-${scene}-${testCase.width}-${testCase.locale}.png`,
}))));
export const windowsSavedMSIDisclosure = 'Synthetic saved reusable-v3 MSI worklists and compiled production UI. Preview POSTs read only fixed invented responses and are counted separately. Endpoint package-cleanup previews preserve exact result, transfer, job, occurrence and binding references; retired failures and restart-required results stay distinct. All confirmation, batch, delivery, review, approval, endpoint retirement, global artifact cleanup and other mutations are blocked. No real login, saved plan, device, grant, MSI bytes, installation, uninstallation, native acceptance or release.';
const savedStage = scene => ({ 'delivery-unchecked': 'deliver', 'review-unchecked': 'review', 'approval-unchecked': 'approve', 'retirement-unchecked': 'retire' })[scene];

/** Invented saved references, never a real durable manager journal or approval. */
export async function createWindowsSavedMSIFixture(scene, now) {
  assert(windowsSavedMSIScenes.includes(scene), 'Unknown saved MSI scene');
  const fixture = await createWindowsFleetMSIFixture(now);
  const { artifact, views, devices, seconds, session } = fixture;
  const stage = savedStage(scene);
  devices.push({ ...clone(devices[0]), id: `agent_${'d'.repeat(32)}`, name: 'SYNTHETIC · Munich unavailable target' });
  fixture.reads.devices[devices[2].id] = 0;
  const bindings = devices.map((device, index) => ({
    managerId: `manager_${'1'.repeat(32)}`, deviceId: device.id,
    incarnationDigest: digest(String(index + 5)), executorId: `executor_${String(index + 2).repeat(32)}`,
    executorKeyId: digest('8'), keyId: digest('9'),
    deliveryGrantId: `grant_${String(index + 3).repeat(32)}`, installGrantId: `grant_${String(index + 6).repeat(32)}`,
  }));
  const bindingDigests = bindings.map(binding => `sha256:${createHash('sha256').update(JSON.stringify(binding)).digest('hex')}`);
  Object.assign(artifact, {
    version: 'tracebolt.windows-managed-msi-artifact.v3', reusable: true,
    publisherStatus: 'unverified', publisherEvidenceDigest: digest('a'), retiredCount: '0',
    maxRetainedPayloadBytes: 128 * 1048576, canRetire: false, retirementBlocked: 'awaiting_device_retirement',
    targets: devices.map((device, index) => ({ deviceId: device.id, bindingDigest: bindingDigests[index] })),
  });
  const identity = { package: artifact.package, nativeAcceptanceDigest: artifact.nativeAcceptanceDigest, publisherStatus: artifact.publisherStatus, publisherEvidenceDigest: artifact.publisherEvidenceDigest };
  artifact.artifactId = `sha256:${createHash('sha256').update('Tracebolt reusable MSI artifact v3\0').update(JSON.stringify(identity)).digest('hex')}`;
  for (const [index, view] of views.entries()) {
    Object.assign(view, {
      reusable: true, artifactRetiredCount: artifact.retiredCount, artifactId: artifact.artifactId,
      bindingDigest: bindingDigests[index], coordinated: true, publisherStatus: artifact.publisherStatus,
      publisherEvidenceDigest: artifact.publisherEvidenceDigest, jobSequence: stage === 'deliver' ? '0' : '1', retiredFloor: '0',
      grantExpiresAt: seconds + 1800, canRetire: false, mutationCapturedAt: seconds,
      mutation: { active: true, blocked: false, phase: 'idle', revision: '8', retained: 0 },
      state: stage === 'deliver' ? 'uploaded' : stage === 'approve' ? 'ready' : 'imported',
      transferId: stage === 'deliver' ? '' : `transfer_${(index ? '7' : 'b').repeat(32)}`,
      readinessDigest: stage === 'approve' ? digest(index ? 'c' : 'b') : '',
      expiresAt: stage === 'approve' ? seconds + 55 : 0,
      readiness: stage === 'approve' ? {
        selection: clone(artifact.package), capturedAt: seconds,
        packageVerified: 'yes', machineAbsent: 'yes', installerBusy: 'no', nativeAcceptance: 'yes',
        packageReviewAccepted: 'yes', maintenanceWindowEnd: seconds + 300,
      } : null,
      result: null, canReview: stage === 'review' || !stage,
    });
    if (!stage && index === 1) Object.assign(view, {
      state: 'complete', canReview: false, resultDigest: digest('c'),
      result: { returnCodeKnown: true, jobId: `software_${'7'.repeat(32)}`, envelopeDigest: digest('8'), attempted: true,
        outcome: 'restart_required', returnCode: 3010, registrationVerified: 'unknown', completedAt: seconds - 20 },
    });
    if (stage === 'retire' || scene === 'retired-outcomes') {
      Object.assign(view, {
        state: scene === 'retired-outcomes' ? 'retired' : 'complete', canReview: false,
        canRetire: stage === 'retire', resultDigest: digest(index ? 'c' : 'd'),
        result: { returnCodeKnown: true, jobId: `software_${view.transferId.slice(9)}`, envelopeDigest: digest(index ? '8' : 'e'), attempted: true,
          outcome: index ? 'restart_required' : 'failed', returnCode: index ? 3010 : 1603,
          registrationVerified: index ? 'yes' : 'no', completedAt: seconds - 20 },
      });
    }
  }
  const targets = devices.map((device, index) => ({
    name: device.name, binding: bindings[index],
    transferId: index === 2 ? `transfer_${'d'.repeat(32)}` : views[index].transferId,
    jobSequence: index === 2 ? '1' : views[index].jobSequence,
  }));
  const worklist = {
    id: `worklist_${'e'.repeat(32)}`, revision: 3, serverNow: seconds, name: 'SYNTHETIC · Desktop package 1.2.3',
    createdBy: session.actorId, createdAt: seconds - 120, archivedAt: 0,
    artifactId: artifact.artifactId, artifactRetiredCount: artifact.retiredCount,
    package: clone(artifact.package), nativeAcceptanceDigest: artifact.nativeAcceptanceDigest,
    publisherStatus: artifact.publisherStatus, publisherEvidenceDigest: artifact.publisherEvidenceDigest,
    group: { id: `group_${'f'.repeat(32)}`, name: 'SYNTHETIC · Frozen pilot cohort', revision: 7 },
    targets, batches: [], rows: targets.map((target, index) => index === 2
      ? { deviceId: target.binding.deviceId, available: false, state: 'unavailable', historicalOutcome: 'succeeded' }
      : { deviceId: target.binding.deviceId, available: true, state: stage === 'deliver' ? 'not_dispatched' : views[index].state, view: views[index] }),
  };
  fixture.savedWorklist = worklist;
  fixture.reads.worklists = 0;
  fixture.reads.worklist = 0;
  fixture.readWorklists = () => { fixture.reads.worklists++; return { version: 'tracebolt.windows-managed-msi-worklists.v1', serverNow: seconds, enabled: true, worklists: [clone(worklist)] }; };
  fixture.readWorklist = () => { fixture.reads.worklist++; return clone(worklist); };
  if (stage) fixture.reviewedPreview = {
    path: `/api/windows-managed-msi/worklists/${worklist.id}/preview`,
    body: JSON.stringify({ revision: worklist.revision, kind: stage }),
    response: {
      worklistId: worklist.id, revision: worklist.revision, kind: stage,
      items: views.map((view, index) => ({
        deviceId: view.deviceId, operation: stage === 'review' ? 'review-coordinated' : stage,
        artifactId: artifact.artifactId, artifactRetiredCount: artifact.retiredCount, bindingDigest: bindingDigests[index],
        transferId: stage === 'deliver' ? `transfer_${(index ? '7' : 'b').repeat(32)}` : view.transferId,
        jobSequence: stage === 'deliver' ? '' : view.jobSequence,
        readinessDigest: stage === 'approve' ? view.readinessDigest : '',
        expiresAt: stage === 'approve' ? view.expiresAt : seconds + 60,
        ...(stage === 'retire' ? { resultDigest: view.resultDigest } : {}),
      })),
      excluded: [{ deviceId: devices[2].id, reason: 'unavailable' }],
    },
  };
  const validation = await contracts();
  assert(validation.validManagedArtifact(artifact), `Saved artifact ${scene}`);
  views.forEach(view => assert(validation.validManagedView(view, view.deviceId), `Saved device ${scene}`));
  assert(validation.validWorklistView(worklist), `Saved worklist ${scene}`);
  assert(validation.validWorklistsView({ version: 'tracebolt.windows-managed-msi-worklists.v1', serverNow: seconds, enabled: true, worklists: [worklist] }), `Saved worklist list ${scene}`);
  if (stage) assert(validation.validWorklistPreview(fixture.reviewedPreview.response, worklist, stage), `Saved preview ${scene}`);
  return fixture;
}

export function createWindowsFleetMSIRoute({ fixture, compiled, state }) {
  return async route => {
    const request = route.request(), url = new URL(request.url());
    const method = request.method(), raw = request.postData();
    const block = reason => { state.blocked.push(reason); return route.abort('blockedbyclient'); };
    if (url.origin !== windowsFleetMSIOrigin) { state.external.push('external'); return block('external-origin'); }
    const preview = fixture.reviewedPreview;
    if (method === 'POST' && preview && fixture.savedWorklist && preview.path === `/api/windows-managed-msi/worklists/${fixture.savedWorklist.id}/preview` && url.pathname === preview.path && !url.search && raw === preview.body) {
      assert(Array.isArray(state.previews), 'Synthetic preview reads must be counted independently');
      state.previews.push({ method, path: url.pathname, body: raw });
      return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(clone(preview.response)) });
    }
    if (method !== 'GET' || raw !== null) { state.writes.push({ method, path: url.pathname }); return block('unexpected-write'); }
    if (url.search) return block('unexpected-query');
    const reply = value => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(value) });
    if (url.pathname === '/api/auth/session') return reply(fixture.session);
    if (url.pathname === '/api/session') return reply({ csrfToken: fixture.session.csrfToken });
    if (url.pathname === '/api/overview') return reply({
      product: 'Tracebolt', mode: 'lan', generatedAt: fixture.now,
      stats: { totalDevices: fixture.devices.length, healthyDevices: 0, attentionDevices: 0, unknownDevices: fixture.devices.length, openCases: 0, criticalCases: 0 },
      devices: fixture.devices, cases: [], activity: [],
    });
    if (url.pathname === '/api/fleet/identities') return reply({ schemaVersion: 'tracebolt.fleet-identities.v2', serverNow: fixture.now, items: [] });
    if (url.pathname === '/api/fleet/groups') return reply({ schemaVersion: 'tracebolt.fleet-groups.v1', serverNow: fixture.now, groups: [], devices: fixture.devices.map(({ id, name, platform }) => ({ id, name, platform })) });
    if (url.pathname === '/api/windows-managed-msi/catalogue') return reply({ version: 'tracebolt.windows-managed-msi-catalogue.v1', enabled: false, serverNow: fixture.seconds, revision: '0', maxEntries: 4, maxRetainedPayloadBytes: 134217728, reservedBytes: 0, entries: [] });
    if (url.pathname === '/api/windows-managed-msi/artifact') return reply(fixture.readArtifact());
    if (url.pathname === '/api/windows-managed-msi/worklists') return reply(fixture.readWorklists ? fixture.readWorklists() : { version: 'tracebolt.windows-managed-msi-worklists.v1', serverNow: fixture.seconds, enabled: false, worklists: [] });
    if (fixture.savedWorklist && url.pathname === `/api/windows-managed-msi/worklists/${fixture.savedWorklist.id}`) return reply(fixture.readWorklist());
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
  const catalogue = await request(`${base}/api/windows-managed-msi/catalogue`);
  assert.equal(catalogue.status, 200);
  assert.deepEqual(JSON.parse(catalogue.body), { version: 'tracebolt.windows-managed-msi-catalogue.v1', enabled: false, serverNow: fixture.seconds, revision: '0', maxEntries: 4, maxRetainedPayloadBytes: 134217728, reservedBytes: 0, entries: [] });
  assert.equal((await request(`${base}/api/windows-managed-msi/artifact`)).status, 200);
  for (const device of fixture.devices) assert.equal((await request(`${base}/api/devices/${device.id}/windows-managed-msi`)).status, 200);
  assert.equal((await request(`${base}/api/devices/${fixture.devices[1].id}/windows-managed-msi/approve`, 'POST', '{}')).aborted, 'blockedbyclient');
  assert.equal((await request('https://example.invalid/api/overview')).aborted, 'blockedbyclient');
  assert.equal((await request(`${base}/api/devices/agent_${'d'.repeat(32)}/windows-managed-msi`)).aborted, 'blockedbyclient');
  assert.equal(state.writes.length, 1);
  assert.equal(state.external.length, 1);
  const savedWorklists = await checkWindowsSavedMSIFixtures();
  const compiled = await compileWindowsFleetMSIAssets();
  assert(compiled.sourceInputs.some(input => input.file === 'web/src/windows-managed-msi-worklists.tsx'), 'Source check must compile the production saved-worklist UI');
  return {
    mode: 'source-only', compiled: true, sourceDigest: compiled.sourceDigest,
    compiledBytes: compiled.compiledBytes, productionSourceInputs: compiled.sourceInputs.length,
    dtoAndRouteChecks: 'passed', targetCount: fixture.devices.length, savedWorklists,
    proposedCases: windowsFleetMSICases, browserExecuted: false, screenshotsCaptured: 0,
    nativeAcceptance: false, disclosure: windowsFleetMSIDisclosure,
  };
}

/** Inert preview exception checks. This does not execute browser interactions. */
export async function checkWindowsSavedMSIFixtures() {
  const validation = await contracts();
  assert.deepEqual(windowsSavedMSIScenes, ['compact-summary', 'expanded-evidence', 'delivery-unchecked', 'review-unchecked', 'approval-unchecked', 'retirement-unchecked', 'retired-outcomes']);
  assert.equal(windowsSavedMSICaptureMatrix.length, 28, 'Hosted saved-worklist matrix must include every new scene');
  assert.equal(new Set(windowsSavedMSICaptureMatrix.map(testCase => testCase.file)).size, 28);
  for (const scene of windowsSavedMSIScenes) for (const locale of ['en', 'de']) for (const width of [1440, 390]) {
    assert.deepEqual(windowsSavedMSICaptureMatrix.find(testCase => testCase.scene === scene && testCase.locale === locale && testCase.width === width), {
      scene, locale, width, height: width === 390 ? 844 : 1100, file: `synthetic-windows-saved-msi-${scene}-${width}-${locale}.png`,
    }, 'Hosted scenes require exact EN/DE desktop/mobile variants');
  }
  assert.equal(windowsSavedMSICaptureMatrix.filter(testCase => savedStage(testCase.scene)).length, 16);
  let allowedPreviewReads = 0, rejectedMutationRequests = 0;
  for (const scene of windowsSavedMSIScenes) {
    const fixture = await createWindowsSavedMSIFixture(scene, '2026-10-12T10:00:00.000Z');
    const worklist = fixture.savedWorklist, initialWorklist = clone(worklist);
    const state = { blocked: [], external: [], writes: [], previews: [] };
    const route = createWindowsFleetMSIRoute({ fixture, compiled: { assets: new Map() }, state });
    async function request(suffix, method = 'GET', body = null) {
      let response;
      await route({ request: () => ({ url: () => `${windowsFleetMSIOrigin}${suffix}`, method: () => method, postData: () => body }),
        fulfill: value => { response = value; }, abort: reason => { response = { aborted: reason }; } });
      return response;
    }
    const base = `/api/windows-managed-msi/worklists/${worklist.id}`;
    const listing = await request('/api/windows-managed-msi/worklists');
    assert.equal(listing.status, 200);
    assert(validation.validWorklistsView(JSON.parse(listing.body)));
    const saved = await request(base);
    assert.equal(saved.status, 200);
    assert.deepEqual(JSON.parse(saved.body), worklist);
    assert.equal(state.writes.length, 0);
    assert.equal(state.previews.length, 0, 'GETs must not start a stage');
    if (scene === 'retirement-unchecked' || scene === 'retired-outcomes') {
      assert.deepEqual(worklist.rows.slice(0, 2).map(row => [row.view.result.outcome, row.view.result.returnCode, row.view.result.registrationVerified]), [
        ['failed', 1603, 'no'], ['restart_required', 3010, 'yes'],
      ], 'Cleanup and retirement preserve each independent settled native outcome');
      assert.equal(fixture.artifact.state, 'uploaded', 'Endpoint retirement cannot imply global artifact cleanup');
      assert.equal(fixture.artifact.canRetire, false, 'The unavailable assignment still blocks global cleanup');
    }
    if (scene === 'retired-outcomes') {
      assert.equal(fixture.reviewedPreview, undefined, 'Reading retired results cannot preview another stage');
      for (const view of fixture.views) {
        assert.equal(view.state, 'retired');
        assert.equal(view.canRetire, false);
        assert.equal(view.jobSequence, '1');
        assert.equal(view.retiredFloor, '0', 'The current retired job is not compacted before the next explicit job');
        assert.equal(view.history, undefined, 'Current retired result remains in place; history advances with the next job');
      }
      const unverified = clone(fixture.views[1]);
      unverified.result.registrationVerified = 'unknown';
      assert.equal(validation.validManagedView(unverified, unverified.deviceId), false, 'Retired 3010 cannot invent verified registration');
    }
    const substituted = clone(worklist);
    substituted.rows[0].view.artifactRetiredCount = '1';
    assert.equal(validation.validWorklistView(substituted), false, 'Same-content occurrence substitution must be rejected');
    const stale = clone(worklist);
    stale.rows[2].view = clone(worklist.rows[0].view);
    assert.equal(validation.validWorklistView(stale), false, 'Unavailable rows must not regain a cached current view');
    if (fixture.reviewedPreview) {
      const expected = fixture.reviewedPreview;
      const response = await request(expected.path, 'POST', expected.body);
      assert.equal(response.status, 200);
      assert.deepEqual(JSON.parse(response.body), expected.response);
      assert.deepEqual(state.previews, [{ method: 'POST', path: expected.path, body: expected.body }]);
      allowedPreviewReads++;
      const wrongBodies = [
        '{}', JSON.stringify({ revision: worklist.revision + 1, kind: savedStage(scene) }),
        JSON.stringify({ revision: worklist.revision, kind: savedStage(scene), acknowledged: true }),
        JSON.stringify({ revision: worklist.revision, kind: savedStage(scene) === 'deliver' ? 'approve' : 'deliver' }),
        JSON.stringify({ kind: savedStage(scene), revision: worklist.revision }),
      ];
      for (const body of wrongBodies) {
        assert.equal((await request(expected.path, 'POST', body)).aborted, 'blockedbyclient');
        rejectedMutationRequests++;
      }
      for (const suffix of ['?unexpected=1', '/']) {
        assert.equal((await request(expected.path + suffix, 'POST', expected.body)).aborted, 'blockedbyclient');
        rejectedMutationRequests++;
      }
      const broader = clone(expected.response);
      broader.items.push({ ...clone(broader.items[0]), deviceId: fixture.devices[2].id });
      assert.equal(validation.validWorklistPreview(broader, worklist, savedStage(scene)), false, 'Preview cannot include an unavailable target');
      const changed = clone(expected.response);
      changed.items[0].bindingDigest = digest('0');
      assert.equal(validation.validWorklistPreview(changed, worklist, savedStage(scene)), false, 'Preview must match exact current binding');
      const stage = savedStage(scene);
      for (const item of expected.response.items) assert.equal(Object.hasOwn(item, 'resultDigest'), stage === 'retire', 'Only retirement requests carry resultDigest');
      if (stage === 'retire') {
        assert.equal(expected.response.kind, 'retire');
        assert.deepEqual(expected.response.excluded, [{ deviceId: fixture.devices[2].id, reason: 'unavailable' }]);
        for (const [index, item] of expected.response.items.entries()) {
          const view = fixture.views[index];
          assert.equal(item.operation, 'retire');
          assert.equal(item.resultDigest, view.resultDigest);
          assert.equal(item.transferId, worklist.targets[index].transferId);
          assert.equal(item.jobSequence, worklist.targets[index].jobSequence);
          assert.equal(item.artifactRetiredCount, worklist.artifactRetiredCount);
          assert.equal(item.bindingDigest, view.bindingDigest);
          assert.equal(item.readinessDigest, '');
          assert.equal(view.canRetire, true);
        }
        for (const [field, value] of Object.entries({ artifactId: digest('0'), artifactRetiredCount: '1', transferId: `transfer_${'0'.repeat(32)}`, jobSequence: '2', resultDigest: digest('0'), readinessDigest: digest('0'), operation: 'approve' })) {
          const substituted = clone(expected.response);
          substituted.items[0][field] = value;
          assert.equal(validation.validWorklistPreview(substituted, worklist, stage), false, `Cleanup preview cannot substitute ${field}`);
        }
        const missing = clone(expected.response);
        delete missing.items[0].resultDigest;
        assert.equal(validation.validWorklistPreview(missing, worklist, stage), false, 'Cleanup preview requires the exact settled result');
      } else {
        for (const resultDigest of ['', digest('d')]) {
          const extra = clone(expected.response);
          extra.items[0].resultDigest = resultDigest;
          assert.equal(validation.validWorklistPreview(extra, worklist, stage), false, 'Other stages reject even an empty retirement-only field');
        }
      }
    } else {
      assert.equal((await request(`${base}/preview`, 'POST', JSON.stringify({ revision: worklist.revision, kind: 'deliver' }))).aborted, 'blockedbyclient');
      rejectedMutationRequests++;
    }
    const writePaths = [
      '/api/windows-managed-msi/worklists/save', '/api/windows-managed-msi/artifact/retire', `${base}/batches`, `${base}/archive`, `${base}/close`,
      ...['deliver', 'review-coordinated', 'approve', 'retire'].map(operation => `/api/devices/${fixture.devices[0].id}/windows-managed-msi/${operation}`),
    ];
    const initialWrites = state.writes.length;
    for (const suffix of writePaths) assert.equal((await request(suffix, 'POST', '{}')).aborted, 'blockedbyclient');
    assert.equal(state.writes.length - initialWrites, writePaths.length);
    rejectedMutationRequests += writePaths.length;
    assert.equal(state.previews.length, fixture.reviewedPreview ? 1 : 0, 'Rejected writes cannot count as a preview');
    assert.deepEqual(worklist, initialWorklist, 'Preview reads must leave saved records and acknowledgements unchanged');
    assert.deepEqual(state.external, []);
  }
  return { scenes: windowsSavedMSIScenes, hostedCaptureMatrix: windowsSavedMSICaptureMatrix, dtoAndRouteChecks: 'passed', retirementOnlyResultPins: true,
    retiredNativeOutcomesPreserved: true, allowedPreviewReads, rejectedMutationRequests, actualMutations: 0, browserExecuted: false, screenshotsCaptured: 0 };
}

export async function exerciseWindowsFleetMSI({ page, expect, fixture, locale, width, shot, inventoryShot = async () => {}, onCase = () => {} }) {
  const de = locale === 'de', title = de ? 'Windows-MSI-Arbeitsliste' : 'Windows MSI worklist';
  await page.goto(`${windowsFleetMSIOrigin}/#/devices`);
  await expect(page.locator('html')).toHaveAttribute('lang', locale);
  // Four supplemental inventory views reuse this exact intercepted App. The
  // existing expanded MSI scenes and their original 16-image identity stay intact.
  const inventory = page.locator('.inventory-panel');
  const workspace = page.locator('.devices-workspace');
  const tools = workspace.locator('.devices-tools-section');
  await expect(inventory.locator('.device-table tbody tr')).toHaveCount(fixture.devices.length);
  // Inventory owns its rows; the six independent tools are its later sibling.
  expect(await workspace.evaluate(element => {
    const selectors = ['.filter-toolbar', '.fleet-groups', '.inventory-meta', '.fleet-identity-notice', '.device-table', '.table-footer', '.windows-incident-inbox', '.windows-fleet-software', '.windows-fleet-update-worklist:not(.windows-fleet-managed-msi)', '.windows-fleet-managed-msi', '.windows-maintenance', '.windows-notifications'];
    const nodes = selectors.map(selector => element.querySelector(selector));
    return nodes.every((node, index) => node && (!index || Boolean(nodes[index - 1].compareDocumentPosition(node) & Node.DOCUMENT_POSITION_FOLLOWING)));
  })).toBe(true);
  const toggles = tools.locator(':scope > section button[aria-expanded]');
  await expect(toggles).toHaveCount(6);
  for (const toggle of await toggles.all()) await expect(toggle).toHaveAttribute('aria-expanded', 'false');
  expect(fixture.reads.artifact).toBe(0);
  expect(Object.values(fixture.reads.devices)).toEqual([0, 0]);
  await page.evaluate(() => document.fonts.ready);
  await inventory.evaluate(element => element.scrollIntoView({ block: 'start', behavior: 'instant' }));
  expect(await inventory.evaluate(element => element.scrollWidth <= element.clientWidth + 1)).toBe(true);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
  await inventoryShot(page, `synthetic-fleet-inventory-default-${width}-${locale}`);
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
  onCase({ scene: 'delivery-unchecked', locale, width });
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
  onCase({ scene: 'saved-3010-shared-owner', locale, width });
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
  onCase({ scene: 'saved-3010-owner-refreshed', locale, width });
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

/** Hosted-browser exercise of saved metadata and initially unchecked stage reviews. */
export async function exerciseWindowsSavedMSI({ page, expect, fixture, scene, locale, width, state, shot }) {
  const de = locale === 'de', stage = savedStage(scene), worklist = fixture.savedWorklist;
  const labels = {
    fleet: de ? 'Windows-MSI-Arbeitsliste' : 'Windows MSI worklist',
    saved: de ? 'Gespeicherte MSI-Arbeitslisten' : 'Saved MSI worklists',
    read: de ? 'Arbeitslisten lesen' : 'Read worklists',
    evidence: de ? 'Gespeicherte Verweise' : 'Saved references',
    deliver: de ? 'An ausgewählte Geräte verteilen' : 'Deliver selected devices',
    review: de ? 'Installationen prüfen' : 'Review installations',
    approve: de ? 'Bereite Geräte genehmigen' : 'Approve ready devices',
    retire: de ? 'Paketbereinigung prüfen' : 'Review package cleanup',
    confirm: de ? 'Exakte Anfragen bestätigen' : 'Confirm exact requests',
    unavailable: de ? 'Aktuelle Nachweise nicht verfügbar' : 'Current evidence unavailable',
    history: de ? 'Nur historisches Ergebnis: Installiert; exakte Registrierung geprüft' : 'Historical result only: Installed; exact registration verified',
  };
  async function openSaved() {
    const fleet = page.getByRole('region', { name: labels.fleet, exact: true });
    await fleet.getByRole('button', { name: labels.fleet, exact: true }).click();
    const saved = fleet.getByRole('region', { name: labels.saved, exact: true });
    await expect(saved).toContainText(worklist.name);
    await expect(saved.getByRole('button', { name: labels.read, exact: true })).toBeEnabled();
    return saved;
  }
  await page.goto(`${windowsFleetMSIOrigin}/#/devices`);
  await expect(page.locator('html')).toHaveAttribute('lang', locale);
  const saved = await openSaved();
  const evidence = saved.locator('article > details').first();
  await expect(evidence.locator('summary')).toHaveText(labels.evidence);
  await expect(evidence).not.toHaveAttribute('open');
  await expect(saved).toContainText(worklist.package.name);
  await expect(saved).toContainText(worklist.package.version);
  const unavailableRow = saved.getByRole('row').filter({ hasText: fixture.devices[2].name });
  await expect(unavailableRow).toContainText(labels.unavailable);
  await expect(unavailableRow).toContainText(labels.history);
  await expect(unavailableRow.getByRole('button')).toBeDisabled();
  await expect(saved.locator('[role="row"]')).toHaveCount(4);
  expect(state.previews).toEqual([]);
  expect(state.writes).toEqual([]);
  let focus = saved, block = 'start';
  if (scene === 'expanded-evidence') {
    await evidence.locator('summary').click();
    await expect(evidence).toHaveAttribute('open', '');
    for (const text of [worklist.artifactId, worklist.package.sha256, worklist.package.termsReviewDigest,
      worklist.nativeAcceptanceDigest, worklist.publisherEvidenceDigest, worklist.group.name, worklist.group.id]) {
      await expect(evidence).toContainText(text);
    }
    focus = evidence;
  } else if (stage) {
    await saved.getByRole('button', { name: labels[stage], exact: true }).click();
    const confirmation = saved.getByRole('region', { name: labels[stage], exact: true });
    await expect(confirmation).toBeVisible();
    const packageReferences = confirmation.locator(':scope > details');
    await expect(packageReferences).toHaveCount(1);
    await expect(packageReferences.locator('summary')).toHaveText(de ? 'Paketverweise' : 'Package references');
    await expect(packageReferences).not.toHaveAttribute('open');
    await expect(packageReferences.locator('.managed-msi-confirm-evidence')).not.toBeVisible();
    // Retained evidence stays inspectable in the DOM while this compact
    // confirmation keeps its exact targets and unchecked consent visible.
    for (const reference of [worklist.package.sha256, worklist.package.productCode, worklist.package.packageCode,
      worklist.nativeAcceptanceDigest, worklist.publisherEvidenceDigest, worklist.package.termsReviewDigest, worklist.package.reviewReference]) {
      await expect(packageReferences).toContainText(reference);
    }
    await expect(confirmation.getByRole('checkbox')).toHaveCount(1);
    await expect(confirmation.getByRole('checkbox')).not.toBeChecked();
    await expect(confirmation.getByRole('button', { name: labels.confirm, exact: true })).toBeDisabled();
    const acknowledgement = stage === 'deliver'
      ? de ? 'Ich genehmige diese exakten Verteilungsanfragen.' : 'I approve these exact delivery requests.'
      : stage === 'approve'
        ? de ? 'Ich genehmige eine Installation genau dieses Pakets auf jedem aufgeführten Gerät.' : 'I approve one installation of this exact package on each listed device.'
        : stage === 'retire'
          ? de ? 'Ich genehmige das Entfernen des anwendungseigenen Pakets auf den Endgeräten nur für diese aufgeführten exakten Ergebnisse.' : 'I approve removal of the app-owned endpoint package for only these listed exact results.'
          : de ? /^Ich habe genau dieses Paket und seine nativen\/Herausgebernachweise geprüft/ : /^I reviewed this exact package and its native\/publisher evidence/;
    await expect(confirmation.getByRole('checkbox', { name: acknowledgement })).not.toBeChecked();
    const included = confirmation.locator('ol > li');
    await expect(included).toHaveCount(2);
    for (const [index, request] of fixture.reviewedPreview.response.items.entries()) {
      await expect(included.nth(index).locator('strong')).toHaveText(fixture.devices[index].name);
      await expect(included.nth(index).locator('strong')).toBeVisible();
      await expect(included.nth(index)).toContainText(request.deviceId);
      await expect(included.nth(index)).toContainText(request.bindingDigest);
      await expect(included.nth(index)).toContainText(request.transferId);
      if (stage === 'approve') await expect(included.nth(index)).toContainText(request.readinessDigest);
      if (stage === 'retire') {
        const result = fixture.views[index].result;
        await expect(included.nth(index)).toContainText(request.resultDigest);
        await expect(included.nth(index).getByText(`${request.transferId} · ${request.jobSequence}`, { exact: true })).toHaveCount(1);
        await expect(confirmation).toContainText(`${de ? 'Paketgeneration' : 'Payload generation'} ${request.artifactRetiredCount}`);
        await expect(included.nth(index)).toContainText(index
          ? de ? '3010: Neustart erforderlich' : '3010: Restart required'
          : de ? 'Installation fehlgeschlagen; Versuch verbraucht' : 'Installation failed; attempt consumed');
        await expect(included.nth(index)).toContainText(`${de ? 'Rückgabecode' : 'Return code'}: ${result.returnCode}`);
        await expect(included.nth(index).locator('p').filter({ hasText: `${de ? 'Rückgabecode' : 'Return code'}: ${result.returnCode}` })).toBeVisible();
        await expect(included.nth(index)).toContainText(index
          ? de ? 'Exakte Registrierung: Geprüft' : 'Exact registration: Verified'
          : de ? 'Exakte Registrierung: Nicht geprüft' : 'Exact registration: Not verified');
        await expect(included.nth(index).locator('.windows-mutation-status')).toContainText(de ? 'Gemeinsamer Status: Kein Besitzer gespeichert' : 'Shared status: No owner saved');
        await expect(included.nth(index).locator('.windows-mutation-status')).toBeVisible();
      }
      await expect(included.nth(index)).toContainText(new Date(request.expiresAt * 1000).toISOString());
    }
    await expect(included.filter({ hasText: fixture.devices[2].id })).toHaveCount(0);
    await expect(confirmation).toContainText(de ? 'Von dieser Bestätigung ausgeschlossen' : 'Excluded from this confirmation');
    await expect(confirmation).toContainText(fixture.devices[2].id);
    await expect(confirmation.locator('ul > li').filter({ hasText: fixture.devices[2].id })).toContainText(de ? 'Nicht verfügbar' : 'Unavailable');
    if (stage === 'review') {
      await expect(confirmation.locator('p').filter({ hasText: 'LocalSystem' })).toBeVisible();
      await expect(confirmation.locator('p').filter({ hasText: de ? 'Synchrone Aktionen müssen geprüft werden.' : 'Synchronous actions must be reviewed.' })).toBeVisible();
    }
    if (stage === 'retire') {
      await expect(confirmation).toContainText(de ? 'Installierte Anwendungen und gespeicherte Ergebnisse bleiben unverändert.' : 'Installed applications and retained outcomes remain unchanged.');
      await expect(confirmation).toContainText(de ? 'Die gemeinsame Manager-Paketbereinigung bleibt separat.' : 'Shared manager package cleanup is separate.');
      await expect(confirmation.getByRole('button', { name: labels.approve, exact: true })).toHaveCount(0);
      await expect(confirmation.getByRole('button', { name: de ? 'Gemeinsamen Paketbestand stilllegen' : 'Retire shared payload', exact: true })).toHaveCount(0);
    }
    expect(state.previews).toEqual([{ method: 'POST', path: fixture.reviewedPreview.path, body: fixture.reviewedPreview.body }]);
    focus = confirmation;
    // References stay collapsed. End alignment keeps the unchecked consent,
    // exact target list, exclusion and disabled control in the mobile shot.
    block = 'end';
  } else if (scene === 'retired-outcomes') {
    const counts = saved.locator('.managed-msi-counts');
    await expect(counts).toContainText(de ? 'Ausstehend: 0' : 'Pending: 0');
    await expect(counts).toContainText(de ? 'Erfasste Ergebnisse: 2' : 'Recorded results: 2');
    await expect(counts).toContainText(de ? 'Prüfen: 3' : 'Attention: 3');
    for (const [index, device] of fixture.devices.slice(0, 2).entries()) {
      const row = saved.getByRole('row').filter({ hasText: device.name });
      await expect(row).toContainText(de ? 'Stillgelegt; kein nächster Auftrag gestartet' : 'Retired; no next job started');
      await expect(row).toContainText(index
        ? de ? '3010: Neustart erforderlich' : '3010: Restart required'
        : de ? 'Installation fehlgeschlagen; Versuch verbraucht' : 'Installation failed; attempt consumed');
      await expect(row).toContainText(`${de ? 'Rückgabecode' : 'Return code'}: ${fixture.views[index].result.returnCode}`);
      await expect(row).toContainText(index
        ? de ? 'Exakte Registrierung: Geprüft' : 'Exact registration: Verified'
        : de ? 'Exakte Registrierung: Nicht geprüft' : 'Exact registration: Not verified');
      await expect(row).not.toContainText(de ? 'Installiert; exakte Registrierung geprüft' : 'Installed; exact registration verified');
    }
    focus = saved.locator('.managed-msi-saved-table');
    block = 'end';
  } else {
    const counts = saved.locator('.managed-msi-counts');
    await expect(counts).toContainText(de ? 'Ausstehend: 1' : 'Pending: 1');
    await expect(counts).toContainText(de ? 'Erfasste Ergebnisse: 1' : 'Recorded results: 1');
    await expect(counts).toContainText(de ? 'Prüfen: 2' : 'Attention: 2');
    await expect(saved).toContainText(de ? '3010: Neustart erforderlich' : '3010: Restart required');
  }
  await page.evaluate(() => document.fonts.ready);
  await focus.evaluate((element, position) => element.scrollIntoView({ block: position, behavior: 'instant' }), block);
  expect(await saved.evaluate(element => element.scrollWidth <= element.clientWidth + 1)).toBe(true);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
  await shot(page, `synthetic-windows-saved-msi-${scene}-${width}-${locale}`);
  expect(state.writes).toEqual([]);
  const previewReads = state.previews.length;
  const listReads = fixture.reads.worklists;
  // Reload discards the unconfirmed preview. Reopening restores the same saved
  // occurrence and frozen cohort, without POSTs or browser-stored authority.
  await page.reload();
  const reopened = await openSaved();
  expect(fixture.reads.worklists).toBeGreaterThan(listReads);
  await expect(reopened).toContainText(worklist.name);
  await expect(reopened.locator('.managed-msi-batch-confirmation')).toHaveCount(0);
  await expect(reopened.locator('article > details').first()).not.toHaveAttribute('open');
  await expect(reopened.getByRole('row').filter({ hasText: fixture.devices[2].name })).toContainText(labels.unavailable);
  expect(state.previews.length).toBe(previewReads);
  expect(state.writes).toEqual([]);
  expect(Object.values(fixture.reads.devices)).toEqual([0, 0, 0]);
  return { targetCount: 3, availableTargetCount: 2, historicalOutcomeIsNotCurrent: true,
    confirmationUnchecked: !!stage, reopenedWithGETOnly: true, previewReads, actualMutationRequests: 0,
    retirementPreviewExact: stage === 'retire', retiredOutcomesPreserved: scene === 'retired-outcomes' };
}

/** Extra saved-worklist captures; the original 16 fleet captures stay unchanged. */
export async function captureWindowsSavedMSIFixtures({ browser, expect, output, onCase = () => {} }) {
  assert(browser && typeof browser.newContext === 'function' && typeof expect === 'function');
  assert(typeof output === 'string' && output.length > 0);
  const compiled = await compileWindowsFleetMSIAssets(), captures = [];
  assert(compiled.sourceInputs.some(input => input.file === 'web/src/windows-managed-msi-worklists.tsx'), 'Saved captures must use the actual production worklist UI');
  await mkdir(output, { recursive: true });
  for (const { scene, locale, width, height, file: expectedFile } of windowsSavedMSICaptureMatrix) {
    const testCase = { locale, width, height };
    onCase({ scene, locale, width });
    const fixture = await createWindowsSavedMSIFixture(scene);
    const state = { blocked: [], external: [], writes: [], previews: [], pageErrors: [] };
    const context = await browser.newContext({ viewport: { width, height }, locale: locale === 'de' ? 'de-DE' : 'en-US', deviceScaleFactor: 1, reducedMotion: 'reduce', serviceWorkers: 'block' });
    try {
      await context.route('**/*', createWindowsFleetMSIRoute({ fixture, compiled, state }));
      await context.addInitScript(value => localStorage.setItem('tracebolt.locale', value), locale);
      const page = await context.newPage();
      page.on('pageerror', error => state.pageErrors.push(error.message));
      const pendingCaptures = [];
      const result = await exerciseWindowsSavedMSI({ page, expect, fixture, scene, state, ...testCase, shot: async (target, name) => {
        const file = `${name}.png`;
        assert.equal(file, expectedFile, 'Capture must match the checked hosted matrix');
        await target.screenshot({ path: path.join(output, file), animations: 'disabled', fullPage: false });
        pendingCaptures.push({ file, scene, ...testCase, synthetic: true, sourceDigest: compiled.sourceDigest, disclosure: windowsSavedMSIDisclosure });
      } });
      expect(state.blocked).toEqual([]);
      expect(state.external).toEqual([]);
      expect(state.writes).toEqual([]);
      expect(state.pageErrors).toEqual([]);
      expect(state.previews.length).toBe(savedStage(scene) ? 1 : 0);
      captures.push(...pendingCaptures.map(capture => ({ ...capture, assertions: result })));
    } finally {
      await context.close();
    }
  }
  const manifest = { browserExecuted: true, nativeAcceptance: false, capturedAt: new Date().toISOString(), sourceDigest: compiled.sourceDigest,
    sourceInputs: compiled.sourceInputs, disclosure: windowsSavedMSIDisclosure, captures };
  await writeFile(path.join(output, 'windows-saved-msi-manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
  return manifest;
}

/** The caller owns an already-authorized browser. This helper never launches one. */
export async function captureWindowsFleetMSIFixtures({ browser, expect, output, onCase = () => {} }) {
  assert(browser && typeof browser.newContext === 'function' && typeof expect === 'function');
  assert(typeof output === 'string' && output.length > 0);
  const compiled = await compileWindowsFleetMSIAssets(), captures = [], inventoryCaptures = [];
  await mkdir(output, { recursive: true });
  for (const testCase of windowsFleetMSICases) {
    const { locale, width, height } = testCase;
    onCase({ scene: 'uploaded-artifact', locale, width });
    const fixture = await createWindowsFleetMSIFixture();
    const state = { blocked: [], external: [], writes: [], pageErrors: [] };
    const context = await browser.newContext({ viewport: { width, height }, locale: locale === 'de' ? 'de-DE' : 'en-US', deviceScaleFactor: 1, reducedMotion: 'reduce', serviceWorkers: 'block' });
    try {
      await context.route('**/*', createWindowsFleetMSIRoute({ fixture, compiled, state }));
      await context.addInitScript(value => localStorage.setItem('tracebolt.locale', value), locale);
      const page = await context.newPage();
      page.on('pageerror', error => state.pageErrors.push(error.message));
      const pendingCaptures = [];
      const result = await exerciseWindowsFleetMSI({ page, expect, fixture, ...testCase, onCase, inventoryShot: async (target, name) => {
        const file = `${name}.png`;
        await target.screenshot({ path: path.join(output, file), animations: 'disabled', fullPage: false });
        inventoryCaptures.push({ file, ...testCase, synthetic: true, sourceDigest: compiled.sourceDigest, disclosure: windowsFleetMSIDisclosure, assertions: { tableBeforeTools: true, collapsedTools: 6, automaticMSIReads: 0, actualMutationRequests: 0 } });
      }, shot: async (target, name) => {
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
  const manifest = { browserExecuted: true, nativeAcceptance: false, capturedAt: new Date().toISOString(), sourceDigest: compiled.sourceDigest, sourceInputs: compiled.sourceInputs, disclosure: windowsFleetMSIDisclosure, captures, inventoryCaptures };
  await writeFile(path.join(output, 'windows-fleet-msi-manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
  return manifest;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  assert.deepEqual(process.argv.slice(2), ['--check'], 'Only --check is supported here. Browser captures require a separately permitted existing browser and the exported recipe.');
  console.log(JSON.stringify(await checkWindowsFleetMSIFixtures(), null, 2));
}
