/** Node-only byte, DTO and inert DOM contracts. These are not browser captures or pixel evidence. */
import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { deflateSync } from 'node:zlib';
import { compile } from './capture-windows-fleet-software.mjs';
import { captureMatrix, contract, disclosure, sceneManifestSHA256, sha256, validateEvidence } from './windows-fleet-software-contract.mjs';
function png(width, height) {
    const chunk = (name, bytes) => { const body = Buffer.concat([Buffer.from(name), bytes]); let crc = -1; for (const byte of body) { crc ^= byte; for (let n = 0; n < 8; n++) crc = crc >>> 1 ^ (crc & 1 ? 0xedb88320 : 0); } const result = Buffer.alloc(body.length + 8); result.writeUInt32BE(bytes.length); body.copy(result, 4); result.writeUInt32BE((crc ^ -1) >>> 0, body.length + 4); return result; };
    const header = Buffer.alloc(13); header.writeUInt32BE(width); header.writeUInt32BE(height, 4); header[8] = 8; header[9] = 2;
    return Buffer.concat([Buffer.from([137,80,78,71,13,10,26,10]), chunk('IHDR', header), chunk('IDAT', deflateSync(Buffer.alloc((width * 3 + 1) * height))), chunk('IEND', Buffer.alloc(0))]);
}
test('one shared scene contract enforces source, counts, PNGs and all trust flags', async () => {
    const output = await mkdtemp(path.join(os.tmpdir(), 'fleet-software-contract-')), sourceSha = 'a'.repeat(40), compiled = await compile();
    const report = { sourceSha, status: 'PASS', browserAcceptance: true, sceneManifestSHA256, scenes: contract.scenes.length, screenshots: captureMatrix.length, requestsToRealAPI: 0, actualMutationRequests: 0, nativeAcceptance: false, disclosure };
    const captures = [];
    try {
        for (const row of captureMatrix) { const bytes = png(row.width, row.height); await writeFile(path.join(output, row.file), bytes); captures.push({ ...row, sha256: sha256(bytes), sourceSha, sourceDigest: compiled.sourceDigest, synthetic: true, publicSafe: true, fullPage: false, disclosure }); }
        const manifest = { sourceSha, sourceDigest: compiled.sourceDigest, sourceInputs: compiled.sourceInputs, sceneManifestSHA256, captures, browserExecuted: true, nativeAcceptance: false, disclosure };
        const write = async (summary = report, value = manifest) => { await writeFile(path.join(output, 'windows-fleet-software-results.json'), JSON.stringify(summary)); await writeFile(path.join(output, 'windows-fleet-software-manifest.json'), JSON.stringify(value)); };
        await write(); await validateEvidence(output, sourceSha);
        const cli = spawnSync(process.execPath, [fileURLToPath(new URL('./check-windows-fleet-software-evidence.mjs', import.meta.url)), sourceSha, output], { encoding: 'utf8', timeout: 15000 });
        assert.equal(cli.status, 0, cli.stderr); assert.match(cli.stdout, /PASS: canonical Windows fleet software/);
        for (const [key, value] of [['sourceSha', 'b'.repeat(40)], ['sceneManifestSHA256', 'c'.repeat(64)], ['screenshots', 3], ['screenshots', true], ['browserAcceptance', false], ['actualMutationRequests', 1], ['requestsToRealAPI', 1], ['nativeAcceptance', true], ['disclosure', '']]) { await write({ ...report, [key]: value }); await assert.rejects(validateEvidence(output, sourceSha)); }
        for (const value of [{ ...manifest, captures: captures.slice(1) }, { ...manifest, captures: [captures[0], captures[0], ...captures.slice(2)] }, { ...manifest, browserExecuted: false }, { ...manifest, sourceInputs: [] }, { ...manifest, sourceInputs: compiled.sourceInputs.filter(row => !row.file.endsWith('/windows-fleet-software-resource.ts')), sourceDigest: sha256(JSON.stringify(compiled.sourceInputs.filter(row => !row.file.endsWith('/windows-fleet-software-resource.ts')))) }, { ...manifest, captures: [{ ...captures[0], file: '../private.png' }, ...captures.slice(1)] }, { ...manifest, captures: [{ ...captures[0], sha256: '0'.repeat(64) }, ...captures.slice(1)] }, { ...manifest, captures: [{ ...captures[0], fullPage: true }, ...captures.slice(1)] }]) { await write(report, value); await assert.rejects(validateEvidence(output, sourceSha)); }
    } finally { await rm(output, { recursive: true, force: true }); }
});
import { createRequire } from 'node:module';
import { check, fixture, routeFixture, origin } from './capture-windows-fleet-software.mjs';

test('inert source check requires CSRF/JSON and denies unrelated writes, forged queries and external routes', async () => {
    const result = await check();
    assert.equal(result.browserExecuted, false); assert.equal(result.screenshotsCaptured, 0);
    assert.equal(result.nativeAcceptance, false); assert.equal(result.cases.length, 8);
});

test('actual App renders literal coverage and exact-device paging in EN/DE without a browser', async () => {
    const require = createRequire(new URL('../package.json', import.meta.url));
    const { JSDOM } = require('jsdom'), { getByRole } = require('@testing-library/dom');
    const compiled = await compile();
    for (const locale of ['en', 'de']) {
        const de = locale === 'de', data = await fixture(), state = { external: 0, writes: 0, unexpected: 0, queries: 0 }, route = routeFixture(data, compiled, state);
        const dom = new JSDOM('<!doctype html><html><body><div id="root"></div></body></html>', { url: `${origin}/#/devices`, runScripts: 'outside-only', pretendToBeVisual: true });
        try {
            const window = dom.window, document = window.document;
            Object.assign(window, { TextEncoder, TextDecoder, structuredClone }); window.localStorage.setItem('tracebolt.locale', locale);
            window.fetch = async (input, options = {}) => {
                let response;
                await route({ request: () => ({ url: () => new URL(String(input), origin).href, method: () => options.method ?? 'GET', postData: () => options.body ?? null, headers: () => Object.fromEntries(new Headers(options.headers).entries()) }), fulfill: value => { response = new Response(value.body, { status: value.status, headers: { 'Content-Type': value.contentType } }); }, abort: () => { throw new Error('Inert fixture rejected request'); } });
                return response;
            };
            window.eval(compiled.assets.get('/app.js').body.toString());
            const eventually = async find => {
                for (let n = 0; n < 200; n++) { const value = find(); if (value) return value; await new Promise(resolve => setTimeout(resolve, 10)); }
                assert.fail('Production fixture did not render');
            };
            await eventually(() => document.querySelector('.windows-fleet-software'));
            getByRole(document.body, 'button', { name: de ? 'Software auf Windows-Geräten suchen' : 'Find software across Windows devices', exact: true }).click();
            const panel = await eventually(() => document.querySelector('.windows-fleet-software form'));
            assert.equal(state.queries, 0);
            for (const [name, value] of [[de ? 'Anwendungsname' : 'Application name', data.query.name], [de ? 'Wörtliche Version' : 'Literal version', data.query.version]]) {
                const input = getByRole(panel, 'searchbox', { name, exact: true });
                Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set.call(input, value);
                input.dispatchEvent(new window.Event('input', { bubbles: true }));
            }
            await new Promise(resolve => setTimeout(resolve, 0));
            panel.dispatchEvent(new window.Event('submit', { bubbles: true, cancelable: true }));
            await eventually(() => document.querySelectorAll('.windows-fleet-software-results > li').length === 2);
            const lookup = document.querySelector('.windows-fleet-software');
            assert.match(lookup.textContent, de ? /Gemeldete Treffer: 22/ : /Reported matches: 22/);
            assert.match(lookup.textContent, de ? /Registrierungen mit nicht verfügbaren Suchfeldern: 4/ : /Registrations with unavailable queried fields: 4/);
            assert.match(lookup.textContent, de ? /Gerätesoftware-Zustimmung nicht eingerichtet/ : /Machine-software consent not configured/);
            getByRole(lookup, 'button', { name: `${de ? 'Alle passenden Registrierungen ansehen' : 'View all matching registrations'}: ${data.fleet.items[0].deviceId}`, exact: true }).click();
            await eventually(() => lookup.querySelectorAll('tbody tr').length === 20);
            assert.equal(lookup.querySelectorAll('.windows-fleet-software-results > li').length, 1);
            assert.equal(lookup.querySelector('.windows-fleet-software-device').textContent, data.fleet.items[0].deviceId);
            getByRole(lookup, 'button', { name: de ? 'Nächste passende Registrierungen' : 'Next matching registrations', exact: true }).click();
            await eventually(() => lookup.querySelectorAll('tbody tr').length === 2);
            assert.match(lookup.textContent, de ? /Passende Registrierungen: 21–22 von 22/ : /Matching registrations: 21–22 of 22/);
            assert.equal(window.location.hash, '#/devices');
            assert.deepEqual(state, { external: 0, writes: 0, unexpected: 0, queries: 3 });
        } finally { dom.window.close(); }
    }
});

test('hosted runner refuses an ordinary local invocation before browser creation', () => {
    const cli = spawnSync(process.execPath, [fileURLToPath(new URL('./run-windows-fleet-software-ci.mjs', import.meta.url))], { encoding: 'utf8', timeout: 15000, env: { ...process.env, GITHUB_ACTIONS: 'false', RUNNER_ENVIRONMENT: '' } });
    assert.notEqual(cli.status, 0); assert.match(cli.stderr, /Hosted CI only/);
});
