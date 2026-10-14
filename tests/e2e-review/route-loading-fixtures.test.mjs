/** Inert contracts only: no Playwright launch, server or provider. */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createRequire } from 'node:module';
import test from 'node:test';
import vm from 'node:vm';
import { reloadDevelopmentCaseRoute, routeLoadingDevelopmentDiagnostic, routeLoadingDevelopmentStages } from './route-loading-browser.mjs';
const require = createRequire(new URL('../../web/package.json', import.meta.url));
const { JSDOM } = require('jsdom');

function inertPage({ fresh = true, origin = 'http://fixture.invalid' } = {}) {
    let document = new JSDOM('', { url: 'http://fixture.invalid/#/overview' });
    const oldWindow = document.window, calls = [];
    let hashchanges = 0, timeOrigin = 100;
    oldWindow.addEventListener('hashchange', () => hashchanges++);
    oldWindow.localStorage.setItem('tracebolt.locale', 'en');
    return {
        calls, oldWindow, hashchanges: () => hashchanges,
        page: {
            async evaluate(fn, ...args) {
                return vm.runInNewContext(`(${fn})(...args)`, { window: document.window, location: document.window.location, performance: { timeOrigin }, args });
            },
            async reload(options) {
                calls.push({ url: document.window.location.href, options });
                if (fresh) {
                    const hash = document.window.location.hash;
                    document = new JSDOM('', { url: origin + '/' + hash });
                    timeOrigin++;
                }
                // Same locale init script as pageAt: no opaque-origin exception.
                document.window.localStorage.setItem('tracebolt.locale', 'en');
            },
        },
        close() { oldWindow.close(); document.window.close(); },
    };
}

test('cold case navigation replaces history without hashchange, then reloads same-origin through bounded DOMContentLoaded', async () => {
    const fixture = inertPage();
    try {
        await reloadDevelopmentCaseRoute(fixture.page, 'case /?synthetic');
        await new Promise(resolve => setImmediate(resolve));
        assert.equal(fixture.hashchanges(), 0);
        assert.equal(fixture.oldWindow.localStorage.getItem('tracebolt.locale'), 'en');
        assert.deepEqual(fixture.calls, [{ url: 'http://fixture.invalid/#/cases/case%20%2F%3Fsynthetic', options: { waitUntil: 'domcontentloaded', timeout: 10000 } }]);
    } finally { fixture.close(); }
});

test('cold case navigation rejects unchanged document identity and changed origin', async () => {
    for (const options of [{ fresh: false }, { origin: 'http://different.invalid' }]) {
        const fixture = inertPage(options);
        try { await assert.rejects(reloadDevelopmentCaseRoute(fixture.page, 'case-synthetic'), /COLD_DOCUMENT_REQUIRED/); }
        finally { fixture.close(); }
    }
});

test('shell diagnostic contains only bounded coordinates and the initial checkpoint', () => {
    assert.ok(Object.isFrozen(routeLoadingDevelopmentStages));
    assert.equal(new Set(routeLoadingDevelopmentStages).size, routeLoadingDevelopmentStages.length);
    assert.deepEqual(routeLoadingDevelopmentDiagnostic('a'.repeat(40), 'NOT_RUN', false), {
        schema: 1, sourceSha: 'a'.repeat(40), status: 'NOT_RUN', stage: 'fixture', runtimeError: false,
    });
});

test('cold-case and pending-auth reloads never await load while holding a chunk', () => {
    const source = fs.readFileSync(new URL('./route-loading-browser.mjs', import.meta.url), 'utf8');
    assert.equal((source.match(/await page\.reload\(\{ waitUntil: 'domcontentloaded', timeout: 10000 \}\)/g) ?? []).length, 2);
    assert.equal(source.includes('about:blank'), false);
    assert.ok(source.indexOf('delayed = await delayModule(page, releases);', source.indexOf('export async function routeLoadingDevelopmentCase')) < source.indexOf('await reloadDevelopmentCaseRoute(page, caseItem.id)'));
});
