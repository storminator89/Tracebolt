/** Hosted-only first-report UI recipe. --check compiles and checks invented DTOs
 * without a browser, listener, manager, native provider or credential creation.
 * A caller may pass its separately permitted existing Playwright browser. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { compileWindowsFleetMSIAssets, createWindowsFleetMSIFixture, createWindowsFleetMSIRoute, windowsFleetMSIOrigin as origin } from './capture-windows-fleet-msi-fixtures.mjs';

const web = fileURLToPath(new URL('../', import.meta.url)), root = path.dirname(web.replace(/\/$/, ''));
const require = createRequire(new URL('../package.json', import.meta.url));
export const firstReportScenes = Object.freeze(['activation-pending', 'waiting', 'renewed-waiting', 'denied', 'expired', 'invalid-time', 'macos-recorded']);
export const firstReportMatrix = Object.freeze(firstReportScenes.flatMap(scene => ['en', 'de'].flatMap(locale => [1440, 390].map(width => ({ scene, locale, width, height: width === 390 ? 844 : 1000, file: `synthetic-first-report-${scene}-${width}-${locale}.png` })))));
export const firstReportDisclosure = 'Invented enrollment/device DTOs rendered by the compiled production App through intercepted HTTPS routes. No real login, endpoint enrollment, persistent credential, invitation secret, native provider, manager mutation, installation or release. Recorded macOS inventory contact is independent of CPU/RAM availability; old timestamps never imply reachability. Browser source fixtures are not native acceptance.';
const clone = value => structuredClone(value);

export async function createFirstReportFixture(scene, now = new Date(Math.floor(Date.now() / 1000) * 1000).toISOString()) {
    assert(firstReportScenes.includes(scene));
    const fixture = await createWindowsFleetMSIFixture(now), seconds = fixture.seconds, mac = scene === 'macos-recorded';
    const metric = { value: null, unit: '%', quality: 'unknown', source: 'Synthetic uncollected metric', collectedAt: '0001-01-01T00:00:00Z' };
    const lastSeen = mac ? new Date((seconds - 1800) * 1000).toISOString() : scene === 'invalid-time' ? 'invalid-fixture-time' : '0001-01-01T00:00:00Z';
    const device = { ...fixture.devices[0], name: 'SYNTHETIC · Report fixture', platform: mac ? 'macos' : 'linux', os: mac ? 'macOS inventory fixture' : 'Linux enrollment fixture', lastSeen, cpu: metric, memory: metric, disk: metric, capabilities: [{ id: 'agent_identity', name: 'Enrolled agent identity', status: ['denied', 'expired'].includes(scene) ? 'denied' : scene === 'activation-pending' ? 'limited' : 'supported', detail: 'Invented identity metadata' }], evidence: [], trend: [], caseIds: [], tags: [] };
    device.agentCertificate.expiresAt = new Date((seconds + (scene === 'expired' ? -60 : 86400)) * 1000).toISOString();
    if (mac) device.capabilities.push({ id: 'macos_inventory', name: 'macOS inventory', status: 'scope', detail: 'Invented inventory-only contact, no CPU/RAM readings' });
    const item = {
        version: 'tracebolt.enrollment-state.v2', binding: { instanceID: `manager_${'2'.repeat(32)}`, origin, profile: 'tls', collectionProfile: mac ? 'macos-read-inventory-v1' : 'basic-readonly-v1', issuerFingerprint: 'a'.repeat(64) },
        invitationID: `invite_${'1'.repeat(32)}`, createRequestID: `request_${'3'.repeat(32)}`, platform: mac ? 'darwin' : 'linux', revision: 6, state: scene === 'activation-pending' ? 'approved' : 'activated', createdAt: seconds - 300, deadlineAt: seconds + 600, updatedAt: seconds,
        claim: { claimID: `claim_${'4'.repeat(32)}`, requestID: '', keyFingerprint: 'ab'.repeat(32), csrHash: '', claimHash: '', comparisonCode: '12ab'.repeat(8), at: seconds - 200 },
        approval: { requestID: '', deviceID: device.id, keyFingerprint: 'ab'.repeat(32), at: seconds - 100 },
        intent: { intentID: '', requestID: '', serialHex: '', templateVersion: '', deviceID: device.id, keyFingerprint: 'ab'.repeat(32), notBefore: seconds - 100, notAfter: seconds + (scene === 'expired' ? -60 : 86400), at: seconds - 100 },
        issuance: { requestID: '', certificateHash: 'b'.repeat(64), at: seconds - 90 }, activation: { requestID: '', at: seconds - 80 }, termination: { requestID: '', from: '', at: 0 },
    };
    // The stale inventory contact still follows this invented identity's activation.
    if (mac) {
        item.createdAt = seconds - 3600; item.claim.at = seconds - 3540; item.approval.at = seconds - 3480;
        item.intent.at = item.intent.notBefore = seconds - 3480; item.issuance.at = seconds - 3420; item.activation.at = seconds - 3360;
    }
    if (scene === 'renewed-waiting') {
        // The snapshot keeps the original anchor; only the activated leaf advances.
        item.intent.notAfter = seconds - 60;
        device.agentCertificate.renewal = { status: 'healthy', enabled: true, identityGeneration: `identity_${'8'.repeat(32)}`, credentialGeneration: 2, currentNotAfter: device.agentCertificate.expiresAt, authorityExpiresAt: new Date((seconds + 172800) * 1000).toISOString() };
    }
    fixture.devices = [device];
    fixture.session = { ...fixture.session, loginMode: 'shared', actorId: null, capabilities: ['read'] };
    fixture.enrollment = { schemaVersion: 'tracebolt.enrollment-operator.v2', serverNow: now, enabled: true, platforms: [item.platform], recordLimit: 25, items: [item], collectionProfile: item.binding.collectionProfile, ...(mac ? { collectionPrivacy: 'macos_inventory_metadata_may_be_sensitive' } : {}) };
    fixture.emptyEnrollment = { schemaVersion: 'tracebolt.enrollment-operator.v2', serverNow: now, enabled: false, platforms: ['linux'], recordLimit: 25, items: [] };
    fixture.enrollmentPath = mac ? '/api/macos-inventory/enrollment' : '/api/enrollment';
    return fixture;
}

export function createFirstReportRoute({ fixture, compiled, state }) {
    const fallback = createWindowsFleetMSIRoute({ fixture, compiled, state });
    return async route => {
        const request = route.request(), url = new URL(request.url());
        if (url.origin === origin && request.method() === 'GET' && request.postData() === null && !url.search && ['/api/enrollment', '/api/macos/enrollment', '/api/macos-inventory/enrollment'].includes(url.pathname)) {
            state.enrollmentReads++;
            if (state.failEnrollment && url.pathname === fixture.enrollmentPath) return route.fulfill({ status: 503, contentType: 'application/json', body: JSON.stringify({ error: { code: 'synthetic_unavailable' } }) });
            const value = url.pathname === fixture.enrollmentPath ? fixture.enrollment : url.pathname === '/api/macos/enrollment' ? { ...fixture.emptyEnrollment, platforms: ['darwin'] } : fixture.emptyEnrollment;
            return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(clone(value)) });
        }
        return fallback(route);
    };
}

export async function compileFirstReportAssets() {
    const compiled = await compileWindowsFleetMSIAssets();
    for (const file of ['web/scripts/capture-first-report-fixtures.mjs', 'web/scripts/run-first-report-ci.mjs', 'web/scripts/first-report-contract.mjs', 'web/scripts/check-first-report-evidence.mjs', 'web/package.json', 'web/package-lock.json', 'tests/security/pr_checks.py', '.github/workflows/pr-checks.yml']) compiled.sourceInputs.push({ file, sha256: createHash('sha256').update(await readFile(path.join(root, file))).digest('hex') });
    compiled.sourceInputs.sort((a, b) => a.file.localeCompare(b.file));
    compiled.sourceDigest = createHash('sha256').update(JSON.stringify(compiled.sourceInputs)).digest('hex');
    return compiled;
}

export async function checkFirstReportFixtures() {
    const { build } = require('esbuild');
    const result = await build({ stdin: { contents: "export { validEnrollmentList } from './enrollment-types'; export { noReportTimestamp, reportTimestamp } from './report-time'; export { enrollmentReportIdentity } from './enrollment-report';", resolveDir: path.join(web, 'src'), loader: 'ts' }, bundle: true, platform: 'node', format: 'esm', loader: { '.css': 'empty' }, write: false, logLevel: 'silent' });
    const guard = await import(`data:text/javascript;base64,${Buffer.from(result.outputFiles[0].text).toString('base64')}`);
    for (const scene of firstReportScenes) {
        const fixture = await createFirstReportFixture(scene, '2026-10-14T06:00:00.000Z');
        assert(guard.validEnrollmentList(fixture.enrollment, scene === 'macos-recorded' ? 'darwin' : 'linux', scene === 'macos-recorded' ? 'macos-read-inventory-v1' : 'basic-readonly-v1'));
        assert.equal(guard.reportTimestamp(fixture.devices[0].lastSeen), scene === 'macos-recorded');
        assert.equal(guard.noReportTimestamp(fixture.devices[0].lastSeen), !['invalid-time', 'macos-recorded'].includes(scene));
        assert.equal(fixture.devices[0].cpu.value, null); assert.equal(fixture.devices[0].memory.value, null);
        if (scene === 'macos-recorded') assert(Date.parse(fixture.devices[0].lastSeen) > fixture.enrollment.items[0].activation.at * 1000);
        if (scene === 'renewed-waiting') {
            const item = fixture.enrollment.items[0], device = fixture.devices[0];
            assert(item.intent.notAfter * 1000 < Date.parse(fixture.now));
            assert(guard.enrollmentReportIdentity(item, device, Date.parse(fixture.now)).admitted);
            const unverified = clone(device); delete unverified.agentCertificate.renewal;
            assert.equal(guard.enrollmentReportIdentity(item, unverified, Date.parse(fixture.now)).admitted, false);
        }
        const state = { blocked: [], external: [], writes: [], enrollmentReads: 0 }, route = createFirstReportRoute({ fixture, compiled: { assets: new Map() }, state });
        async function request(url, method = 'GET', body = null) { let response; await route({ request: () => ({ url: () => url, method: () => method, postData: () => body }), fulfill: value => { response = value; }, abort: reason => { response = { aborted: reason }; } }); return response; }
        assert.equal((await request(origin + fixture.enrollmentPath)).status, 200);
        assert.equal((await request(origin + fixture.enrollmentPath, 'POST', '{}')).aborted, 'blockedbyclient');
        assert.equal((await request('https://external.invalid/api/overview')).aborted, 'blockedbyclient');
        assert.equal(state.writes.length, 1); assert.equal(state.external.length, 1);
    }
    const compiled = await compileFirstReportAssets();
    assert(compiled.sourceInputs.some(input => input.file === 'web/src/enrollment-report.tsx'));
    return { browserExecuted: false, nativeAcceptance: false, compiled: true, sourceDigest: compiled.sourceDigest, dtoAndRouteChecks: 'passed', captureMatrix: firstReportMatrix, disclosure: firstReportDisclosure };
}

export async function captureFirstReportFixtures({ browser, expect, output, onCase = () => {} }) {
    assert(browser && typeof browser.newContext === 'function');
    const compiled = await compileFirstReportAssets(), captures = [];
    await mkdir(output, { recursive: true });
    for (const testCase of firstReportMatrix) {
        const { scene, locale, width, height, file } = testCase, de = locale === 'de'; onCase(testCase);
        const fixture = await createFirstReportFixture(scene), state = { blocked: [], external: [], writes: [], pageErrors: [], enrollmentReads: 0, failEnrollment: false };
        const context = await browser.newContext({ viewport: { width, height }, locale: de ? 'de-DE' : 'en-US', deviceScaleFactor: 1, reducedMotion: 'reduce', serviceWorkers: 'block' });
        try {
            await context.route('**/*', createFirstReportRoute({ fixture, compiled, state }));
            await context.addInitScript(value => localStorage.setItem('tracebolt.locale', value), locale);
            const page = await context.newPage(); page.on('pageerror', error => state.pageErrors.push(error.message));
            await page.goto(`${origin}/#/devices`);
            await expect(page.locator('.device-table tbody tr')).toHaveCount(1);
            if (scene === 'macos-recorded') {
                await expect(page.locator('.device-table time')).toHaveAttribute('datetime', fixture.devices[0].lastSeen);
                await page.getByRole('combobox', { name: de ? 'Betriebssystem' : 'Operating system', exact: true }).selectOption('darwin');
                await page.getByRole('combobox', { name: de ? 'macOS-Erfassungsumfang' : 'macOS collection scope', exact: true }).selectOption('macos-read-inventory-v1');
            } else await expect(page.locator('.device-table')).toContainText(scene === 'invalid-time' ? de ? 'Meldungsstatus nicht verfügbar' : 'Report status unavailable' : de ? 'Noch keine Meldung erfasst' : 'No report recorded yet');
            await page.getByRole('button', { name: de ? /^Einladungen/ : /^Invitations/ }).click();
            const row = page.getByRole('button', { name: de ? `Einladung ${fixture.enrollment.items[0].invitationID} prüfen` : `Review invitation ${fixture.enrollment.items[0].invitationID}`, exact: true });
            await row.focus(); await page.keyboard.press('Enter');
            const dialog = page.getByRole('dialog'), report = dialog.getByRole('status', { name: de ? 'Meldung' : 'Report', exact: true });
            const wanted = { 'activation-pending': de ? 'Aktivierung ausstehend' : 'Activation pending', waiting: de ? 'Warte auf erste Meldung' : 'Waiting for first report', 'renewed-waiting': de ? 'Warte auf erste Meldung' : 'Waiting for first report', denied: de ? 'Identität nicht zugelassen' : 'Identity not admitted', expired: de ? 'Identität abgelaufen' : 'Identity expired', 'invalid-time': de ? 'Meldungsstatus nicht verfügbar' : 'Report status unavailable', 'macos-recorded': de ? 'Letzte Meldung' : 'Last report' }[scene];
            await expect(report.getByText(wanted, { exact: true })).toBeVisible();
            if (!['waiting', 'renewed-waiting'].includes(scene)) await expect(report).not.toContainText(de ? 'Warte auf erste Meldung' : 'Waiting for first report');
            if (scene === 'macos-recorded') await expect(report.locator('time')).toHaveAttribute('datetime', fixture.devices[0].lastSeen);
            if (scene === 'renewed-waiting') {
                await expect(row.locator('.enrollment-status')).toHaveClass(/state-activated/);
                await expect(dialog.locator('.enrollment-status')).toHaveClass(/state-activated/);
                await expect(dialog.locator('[aria-current=step]')).toContainText(de ? 'Daten prüfen' : 'Check data');
                await expect(dialog.locator('.state-expired,.enrollment-message.error')).toHaveCount(0);
            }
            await expect(report.locator('details')).not.toHaveAttribute('open');
            await expect(dialog.locator('input[type=password],.enrollment-token,.enrollment-fingerprint')).toHaveCount(0);
            await expect(dialog).not.toContainText(fixture.session.csrfToken);
            expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
            expect(await dialog.evaluate(element => element.scrollWidth <= element.clientWidth + 1)).toBe(true);
            await page.evaluate(() => document.fonts.ready);
            await page.screenshot({ path: path.join(output, file), animations: 'disabled', fullPage: false });
            const bytes = await readFile(path.join(output, file)); assert(bytes.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10])));
            await page.keyboard.press('Escape'); await expect(dialog).toHaveCount(0); await expect(row).toBeFocused();
            if (scene === 'waiting') {
                await row.click(); state.failEnrollment = true;
                await page.getByRole('dialog').getByRole('button', { name: de ? 'Status prüfen' : 'Check status', exact: true }).click();
                await expect(page.getByRole('dialog')).toHaveCount(0); await expect(page.locator('.enrollment-panel [role=alert]')).toBeVisible();
                await expect(page.locator('.enrollment-panel')).not.toContainText(wanted);
                state.failEnrollment = false;
                await page.getByRole('button', { name: de ? 'Enrollment-Status aktualisieren' : 'Refresh enrollment status', exact: true }).click();
                await row.click();
                const refreshed = page.getByRole('dialog').getByRole('status', { name: de ? 'Meldung' : 'Report', exact: true });
                await expect(refreshed).toContainText(wanted);
                const unchangedRevision = fixture.enrollment.items[0].revision;
                fixture.devices[0].lastSeen = new Date((fixture.seconds - 30) * 1000).toISOString();
                await page.getByRole('dialog').getByRole('button', { name: de ? 'Status prüfen' : 'Check status', exact: true }).click();
                await expect(refreshed.locator('time')).toHaveAttribute('datetime', fixture.devices[0].lastSeen);
                await expect(refreshed).not.toContainText(wanted); expect(fixture.enrollment.items[0].revision).toBe(unchangedRevision);
            }
            expect(state.blocked).toEqual([]); expect(state.external).toEqual([]); expect(state.writes).toEqual([]); expect(state.pageErrors).toEqual([]);
            captures.push({ ...testCase, sha256: createHash('sha256').update(bytes).digest('hex'), sourceDigest: compiled.sourceDigest, synthetic: true, publicSafe: true, fullPage: false, disclosure: firstReportDisclosure, assertions: { exactState: true, originalTimestamp: scene === 'macos-recorded', absentMetricsDoNotImplyAbsentReport: scene === 'macos-recorded', focusRestored: true, renewedDisplayConsistent: scene === 'renewed-waiting', manualRefreshUnchangedRevision: scene === 'waiting', failureClearsWaiting: scene === 'waiting', actualMutationRequests: 0 } });
        } finally { await context.close(); }
    }
    const manifest = { browserExecuted: true, nativeAcceptance: false, sourceDigest: compiled.sourceDigest, sourceInputs: compiled.sourceInputs, disclosure: firstReportDisclosure, captures };
    await writeFile(path.join(output, 'first-report-manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
    return manifest;
}
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
    assert.deepEqual(process.argv.slice(2), ['--check'], 'Only inert --check is supported locally.');
    console.log(JSON.stringify(await checkFirstReportFixtures(), null, 2));
}
