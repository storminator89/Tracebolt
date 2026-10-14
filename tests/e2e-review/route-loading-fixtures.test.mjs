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

// Inert production-React reproduction. The pinned Playwright clock is injected
// into jsdom exactly as its server-side Clock does; no browser/server is started.
// A native MessageChannel supplies the browser scheduler path absent in jsdom.
import { MessageChannel } from 'node:worker_threads';
import { pausedDetailCommitMs, settlePausedDetailRoute } from './paused-detail-route.mjs';
const { source: clockSource } = require(require.resolve('playwright-core/package.json').replace('package.json', 'lib/generated/clockSource.js'));
const pausedRouteBundle = require('esbuild').buildSync({
    stdin: { contents: `
        import {createElement as h, lazy, useLayoutEffect} from 'react';
        import {createRoot} from 'react-dom/client';
        import {DetailLoadingLifecycle, RouteDetailBoundary} from './src/route-details';
        import {setLocale} from './src/i18n';
        let resolve;
        const promise = new Promise(yes => { resolve = yes; });
        const root = createRoot(document.getElementById('root'));
        function Detail() {
            useLayoutEffect(() => { window.fixture.commits++; }, []);
            return h('section', {'data-fixture-ready': true}, 'Synthetic detail');
        }
        const LazyDetail = lazy(() => promise);
        const render = child => root.render(h(DetailLoadingLifecycle, null,
            h(RouteDetailBoundary, {onBack: () => {}, backLabel: 'Back'}, child)));
        window.fixture = {
            commits: 0, resolve: () => resolve({default: Detail}),
            open: () => render(h(LazyDetail)), ready: () => render(h(Detail)),
            locale: value => setLocale(value, false), dispose: () => root.unmount()
        };
    `, resolveDir: new URL('../../web/', import.meta.url).pathname, loader: 'tsx' },
    bundle: true, write: false, platform: 'browser', format: 'iife', jsx: 'automatic',
    loader: { '.css': 'empty' }, define: { 'process.env.NODE_ENV': '"production"' }, logLevel: 'silent',
}).outputFiles[0].text;
const realWait = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));
async function waitUntil(predicate) {
    const deadline = Date.now() + 1000;
    while (!predicate()) {
        assert.ok(Date.now() < deadline, 'Inert fixture condition did not settle');
        await realWait(1);
    }
}
async function pausedProductionRoute(locale = 'en', { replay = null, loadBeforeClock = false } = {}) {
    const dom = new JSDOM('<main id="root"></main>', { url: 'https://fixture.invalid/', pretendToBeVisual: true, runScripts: 'outside-only' });
    const window = dom.window, channels = [], advances = [];
    window.MessageChannel = class extends MessageChannel { constructor() { super(); channels.push(this); } };
    // jsdom exposes a getter; the real browser's clock replaces this property.
    Object.defineProperty(window, 'performance', { value: window.performance, writable: true, configurable: true });
    if (loadBeforeClock) window.eval(pausedRouteBundle);
    window.eval(`(() => { const module = {}; ${clockSource}; globalThis.__pwClock = (module.exports.inject())(globalThis); })();`);
    const clock = window.__pwClock.controller;
    const origin = Date.parse('2026-10-14T00:00:00Z');
    if (replay === null) {
        clock.install(origin); await clock.pauseAt(origin + 1000);
    } else {
        // Same command-log replay used by Playwright's document init scripts.
        clock.log('install', 0, origin); clock.log('pauseAt', 0, origin + 1000);
        for (const milliseconds of replay) clock.log('runFor', 0, milliseconds);
        clock.now();
    }
    if (!loadBeforeClock) window.eval(pausedRouteBundle);
    window.fixture.locale(locale);
    const readyElement = () => window.document.querySelector('[data-fixture-ready]');
    const loadingElement = () => [...window.document.querySelectorAll('.loading > span')].find(node => /^(Loading view …|Ansicht wird geladen …)$/.test(node.textContent));
    const locator = get => ({
        get, isVisible: async () => Boolean(get()),
        or(other) { return locator(() => get() || other.get()); }, first() { return this; },
    });
    const ready = locator(readyElement), fallback = locator(loadingElement);
    const page = {
        getByText(pattern) { assert.equal(pattern.source, '^(Loading view …|Ansicht wird geladen …)$'); return fallback; },
        clock: { async runFor(milliseconds) { advances.push(milliseconds); await clock.runFor(milliseconds); } },
    };
    const expectVisible = value => ({ toBeVisible: () => waitUntil(value.get) });
    return {
        window, clock, ready, fallback, page, expectVisible, advances, origin,
        async open() { window.fixture.open(); await waitUntil(loadingElement); },
        async close() { window.fixture.dispose(); clock.uninstall(); for (const channel of channels) { channel.port1.close(); channel.port2.close(); } window.close(); },
    };
}

test('production route boundary remains paused after lazy resolution and commits at the pinned 300 ms threshold', async () => {
    const fixture = await pausedProductionRoute();
    try {
        await fixture.open(); fixture.window.fixture.resolve();
        await waitUntil(() => fixture.clock.countTimers() === 1);
        const [timer] = fixture.clock._timers.values();
        assert.equal(timer.type, 'Timeout'); assert.equal(timer.delay, pausedDetailCommitMs);
        assert.equal(fixture.window.fixture.commits, 0);
        assert.equal(await fixture.ready.isVisible(), false);
        await fixture.clock.runFor(299);
        assert.equal(fixture.window.fixture.commits, 0);
        await fixture.clock.runFor(1);
        await waitUntil(() => fixture.window.fixture.commits === 1);
        assert.equal(fixture.window.Date.now(), fixture.origin + 1300);
        assert.equal(fixture.window.performance.now(), 1300);
    } finally { await fixture.close(); }
});

for (const resolvedBeforeSync of [true, false]) for (const locale of ['en', 'de']) {
    test(`bounded detail sync commits when import resolves ${resolvedBeforeSync ? 'before' : 'after'} the single tick (${locale})`, async () => {
        const fixture = await pausedProductionRoute(locale);
        try {
            await fixture.open();
            let laterDeadline = false;
            fixture.window.setTimeout(() => { laterDeadline = true; }, 1000);
            if (resolvedBeforeSync) fixture.window.fixture.resolve();
            const completed = settlePausedDetailRoute(fixture.page, fixture.expectVisible, fixture.ready);
            await waitUntil(() => fixture.advances.length === 1);
            if (!resolvedBeforeSync) fixture.window.fixture.resolve();
            await completed;
            assert.equal(fixture.window.fixture.commits, 1);
            assert.deepEqual(fixture.advances, [300]); assert.equal(laterDeadline, false);
            const pausedAt = fixture.window.performance.now();
            await realWait(5); assert.equal(fixture.window.performance.now(), pausedAt);
            assert.equal(fixture.window.Date.now(), fixture.origin + 1300);
        } finally { await fixture.close(); }
    });
}

test('ready detail route consumes no simulated time', async () => {
    const fixture = await pausedProductionRoute();
    try {
        fixture.window.fixture.ready(); await waitUntil(fixture.ready.get);
        await settlePausedDetailRoute(fixture.page, fixture.expectVisible, fixture.ready);
        assert.deepEqual(fixture.advances, []);
        assert.equal(fixture.window.Date.now(), fixture.origin + 1000);
    } finally { await fixture.close(); }
});

test('bounded detail synchronization preserves readiness failure and never retries clock advancement', async () => {
    const marker = new Error('Synthetic unchanged readiness failure'), calls = [];
    const fallback = { isVisible: async () => true }, ready = { or: value => { assert.equal(value, fallback); return { first: () => 'fallback' }; } };
    const page = { getByText: () => fallback, clock: { runFor: async ms => calls.push(ms) } };
    const expect = value => ({ toBeVisible: async () => { if (value === ready) throw marker; } });
    await assert.rejects(settlePausedDetailRoute(page, expect, ready), error => error === marker);
    assert.deepEqual(calls, [300]);
    calls.length = 0;
    await assert.rejects(settlePausedDetailRoute(page, () => ({ toBeVisible: async () => { throw marker; } }), ready), error => error === marker);
    assert.deepEqual(calls, []);
});


test('React loaded before clock installation uses its original timer for the first lazy navigation', async () => {
    const fixture = await pausedProductionRoute('en', { loadBeforeClock: true });
    try {
        await fixture.open(); fixture.window.fixture.resolve();
        await waitUntil(fixture.ready.get);
        assert.equal(fixture.window.fixture.commits, 1);
        assert.equal(fixture.window.Date.now(), fixture.origin + 1000);
        assert.equal(fixture.window.performance.now(), 1000);
    } finally { await fixture.close(); }
});

test('all seven cold Health documents replay bounded progress without resuming time or resetting deadlines', async () => {
    const health = fs.readFileSync(new URL('./health-dashboard-browser.mjs', import.meta.url), 'utf8');
    const phases = [...health.matchAll(/await change\('([^']+)'\)/g)].map(match => match[1]);
    assert.deepEqual(phases, ['clear', 'healthy-services', 'issue', 'clear', 'stale', 'awaiting', 'unavailable']);
    const history = [];
    for (const phase of phases) {
        const fixture = await pausedProductionRoute('en', { replay: history });
        try {
            const beforeWall = fixture.window.Date.now(), beforeMono = fixture.window.performance.now();
            assert.equal(beforeWall, fixture.origin + 1000 + history.reduce((sum, value) => sum + value, 0));
            await fixture.open(); fixture.window.fixture.resolve();
            let deadlineReached = false;
            fixture.window.setTimeout(() => { deadlineReached = true; }, 10000);
            await settlePausedDetailRoute(fixture.page, fixture.expectVisible, fixture.ready);
            assert.equal(fixture.window.Date.now() - beforeWall, 300);
            assert.equal(fixture.window.performance.now() - beforeMono, 300);
            assert.equal(deadlineReached, false); history.push(300);
            if (phase === 'issue') {
                // Existing three disclosure-focus steps remain exactly 32 ms.
                for (let frame = 0; frame < 3; frame++) { await fixture.clock.runFor(32); history.push(32); }
            }
        } finally { await fixture.close(); }
    }
    assert.equal(history.reduce((sum, value) => sum + value, 0), 2196);
    const helper = fs.readFileSync(new URL('./paused-detail-route.mjs', import.meta.url), 'utf8');
    assert.doesNotMatch(helper, /\.resume\(|\.fastForward\(|\.setFixedTime\(|\.setSystemTime\(|while\s*\(|timeout:/);
    const service = fs.readFileSync(new URL('./service-action-display-browser.mjs', import.meta.url), 'utf8');
    const packages = fs.readFileSync(new URL('./package-updates-browser.mjs', import.meta.url), 'utf8');
    assert.match(service, /clock\.pauseAt\(new Date\(Date\.parse\(actionNow\)\+100\)\)/);
    assert.match(packages, /clock\.pauseAt\(new Date\(start\+100\)\)/);
    assert.match(health, /await page\.reload\(\);mark\(`health-\$\{phase\}-detail-route-readiness`\);await settlePausedDetailRoute/);
});
