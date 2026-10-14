/** Focused route-code loading checks using only the existing disposable fixture.
 * Script requests are delayed/failed explicitly; API authority remains real.
 * Record counters and original synthetic screenshots, never cookies or bodies. */
const detailScript = '**/assets/details-*.js';
const fixtureID = 'agent_00000000000000000000000000000001';
const otherID = 'agent_22222222222222222222222222222222';
const disclosure = 'Existing loopback HTTP-test fixture with invented awaiting-device data; JavaScript chunk deliberately delayed or failed. No real telemetry, provider, native collection or trusted TLS acceptance.';
export const routeLoadingCaseNames = Object.freeze([
    'Deferred details stay absent on login and overview, and respect blurred route replacement',
    'Deferred details wait through pagehide and completed auth revalidation',
    'Deferred details cannot mount after logout or protected auth loss',
    'Rejected detail module is contained and deliberate reload retries without mutation replay',
]);
let failureStage = 'setup';
export const routeLoadingFailureStage = () => failureStage;
export const routeLoadingDevelopmentStages = Object.freeze([
    'fixture', 'overview-navigation', 'initial-deferral', 'interception-setup',
    'cold-navigation', 'module-interception', 'loading-fallback', 'module-transfer',
    'module-evaluation', 'final-render', 'final-counts', 'complete',
]);
let developmentStage = 'fixture';
export function routeLoadingDevelopmentDiagnostic(sourceSha, status, runtimeError) {
    return { schema: 1, sourceSha, status, stage: developmentStage, runtimeError };
}
export async function reloadDevelopmentCaseRoute(page, id) {
    // replaceState emits no hashchange: install the direct URL without starting
    // the old document's lazy route, then load a fresh same-origin document.
    const previous = await bounded(page.evaluate(id => {
        window.history.replaceState({}, '', `#/cases/${encodeURIComponent(id)}`);
        return { origin: location.origin, timeOrigin: performance.timeOrigin };
    }, id), 'COLD_DOCUMENT_DEADLINE');
    // Waiting for load could wait on the deliberately held dynamic script.
    await page.reload({ waitUntil: 'domcontentloaded', timeout: 10000 });
    const current = await bounded(page.evaluate(() => ({ origin: location.origin, timeOrigin: performance.timeOrigin })), 'COLD_DOCUMENT_DEADLINE');
    if (current.origin !== previous.origin || current.timeOrigin === previous.timeOrigin) throw new Error('COLD_DOCUMENT_REQUIRED');
}
export const routeLoadingDevelopmentCaseName = 'Direct synthetic case route loads the shared detail module only on demand';

async function bounded(promise, code) {
    let timer;
    try { return await Promise.race([promise, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(code)), 10000); })]); }
    finally { clearTimeout(timer); }
}
async function settle(page) { await bounded(page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))), 'ROUTE_RENDER_DEADLINE'); }
function monitor(page, base) {
    const counts = { details: 0, deviceReads: 0, otherReads: 0, mutations: 0 };
    page.on('request', request => {
        const url = new URL(request.url()); if (url.origin !== base) return;
        if (/^\/assets\/details-[\w-]+\.js$/.test(url.pathname)) counts.details++;
        if (url.pathname === `/api/devices/${fixtureID}`) counts.deviceReads++;
        if (url.pathname === `/api/devices/${otherID}`) counts.otherReads++;
        if (url.pathname.startsWith('/api/') && request.method() !== 'GET' && !url.pathname.startsWith('/api/auth/')) counts.mutations++;
    });
    return counts;
}
async function recordedDetails(page) {
    return page.evaluate(() => performance.getEntriesByType('resource').filter(row => /^\/assets\/details-[\w-]+\.js$/.test(new URL(row.name).pathname)).length);
}
async function delayModule(page, releases) {
    let release; const gate = new Promise(resolve => { release = resolve; });
    releases.add(release);
    let intercepted = false;
    await page.route(detailScript, async route => { intercepted = true; await gate; await route.continue(); });
    return { intercepted: () => intercepted, release };
}
async function releaseModule(page, delayed, onStage = () => {}) {
    onStage('module-transfer');
    const responsePromise = page.waitForResponse(response => /^\/assets\/details-[\w-]+\.js$/.test(new URL(response.url()).pathname), { timeout: 10000 });
    delayed.release(); const response = await responsePromise;
    if (await bounded(response.finished(), 'DETAIL_TRANSFER_DEADLINE')) throw new Error('DETAIL_TRANSFER_FAILED');
    // Join the exact same already-requested module URL. This awaits evaluation,
    // rather than mistaking response headers/two frames for completed loading.
    onStage('module-evaluation');
    await bounded(page.evaluate(async url => { await import(url); }, response.url()), 'DETAIL_EVALUATION_DEADLINE');
    await settle(page);
}
export async function runRouteLoadingChecks({ check, pageAt, login, expect, base, shot }) {
    const releases = new Set();
    const checked = (name, run, ttl) => check(name, async () => {
        failureStage = 'setup';
        try { await run(); } finally { for (const release of releases) release(); releases.clear(); }
    }, ttl);
    await checked(routeLoadingCaseNames[0], async () => {
        const page = await pageAt('/overview');
        await expect(page.getByRole('heading', { name: 'Sign in', exact: true })).toBeVisible();
        expect(await recordedDetails(page)).toBe(0);
        const counts = monitor(page, base), delayed = await delayModule(page, releases);
        await login(page); await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();
        expect(counts.details).toBe(0);
        await page.evaluate(id => { window.location.hash = `/devices/${id}`; }, fixtureID);
        await expect.poll(() => counts.details).toBe(1); await expect.poll(delayed.intercepted, { timeout: 10000 }).toBe(true); await expect(page.getByText('Loading view …', { exact: true })).toBeVisible();
        expect(counts.deviceReads).toBe(0); expect(counts.mutations).toBe(0);
        failureStage = 'loading-captures';
        await shot(page, 'synthetic-route-loading-desktop-en', disclosure);
        await page.setViewportSize({ width: 390, height: 844 });
        await page.getByLabel('Language', { exact: true }).selectOption('de');
        await shot(page, 'synthetic-route-loading-mobile-de', disclosure);
        expect(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth)).toBe(false);
        failureStage = 'blurred-route-replacement';
        await page.evaluate(id => { window.dispatchEvent(new Event('blur')); window.location.hash = `/devices/${id}`; }, otherID);
        await releaseModule(page, delayed);
        expect(counts.deviceReads).toBe(0); expect(counts.otherReads).toBe(0);
        await page.evaluate(() => { window.location.hash = '/overview'; }); await settle(page);
        await page.evaluate(id => { window.location.hash = `/devices/${id}`; }, fixtureID); await settle(page);
        expect(counts.deviceReads).toBe(0);
        await page.evaluate(() => window.dispatchEvent(new Event('focus')));
        await expect(page.getByRole('region', { name: 'Gerät Fixture workstation', exact: true })).toBeVisible();
        expect(counts.deviceReads).toBe(1); expect(counts.otherReads).toBe(0); expect(counts.details).toBe(1);
        await page.getByRole('button', { name: 'Zurück zu Geräten', exact: true }).click();
        await expect(page.getByLabel('Geräte durchsuchen', { exact: true })).toBeVisible();
        await expect(page.getByRole('main')).toBeFocused(); expect(counts.mutations).toBe(0);
    }, '10m');
    await checked(routeLoadingCaseNames[1], async () => {
        const page = await pageAt(`/devices/${fixtureID}`), counts = monitor(page, base), delayed = await delayModule(page, releases);
        await expect(page.getByRole('heading', { name: 'Sign in', exact: true })).toBeVisible(); expect(await recordedDetails(page)).toBe(0);
        await login(page); await expect.poll(() => counts.details).toBe(1); await expect.poll(delayed.intercepted, { timeout: 10000 }).toBe(true);
        failureStage = 'pending-pagehide';
        await page.evaluate(() => window.dispatchEvent(new Event('pagehide')));
        await releaseModule(page, delayed); expect(counts.deviceReads).toBe(0);
        let releaseSession; const sessionGate = new Promise(resolve => { releaseSession = resolve; }); releases.add(releaseSession);
        let sessionRequests = 0;
        await page.route('**/api/auth/session', async route => { sessionRequests++; await sessionGate; await route.continue(); });
        failureStage = 'auth-revalidation';
        await page.evaluate(() => window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true })));
        await expect.poll(() => sessionRequests).toBe(1); await page.evaluate(() => window.dispatchEvent(new Event('focus'))); await settle(page);
        expect(counts.deviceReads).toBe(0); await expect(page.locator('.auth-private-view')).toHaveAttribute('inert', '');
        releaseSession(); await expect(page.getByRole('region', { name: 'Device Fixture workstation', exact: true })).toBeVisible();
        expect(counts.deviceReads).toBe(1); expect(counts.details).toBe(1); expect(counts.mutations).toBe(0);
        await shot(page, 'synthetic-route-loaded-desktop-en', disclosure);
    }, '10m');
    await checked(routeLoadingCaseNames[2], async () => {
        const page = await pageAt(`/devices/${fixtureID}`), counts = monitor(page, base), delayed = await delayModule(page, releases);
        await login(page); await expect.poll(() => counts.details).toBe(1); await expect.poll(delayed.intercepted, { timeout: 10000 }).toBe(true);
        failureStage = 'pending-logout';
        await page.getByRole('button', { name: 'Sign out', exact: true }).click();
        await expect(page.getByRole('heading', { name: 'Sign in', exact: true })).toBeVisible();
        await releaseModule(page, delayed); expect(counts.deviceReads).toBe(0);
        await expect(page.locator('.app-shell')).toHaveCount(0); expect(counts.mutations).toBe(0);
        await login(page); await expect(page.getByRole('region', { name: 'Device Fixture workstation', exact: true })).toBeVisible();
        expect(counts.details).toBe(1); expect(counts.deviceReads).toBe(1);
        await page.unroute(detailScript); const nextDelayed = await delayModule(page, releases), priorReads = counts.deviceReads;
        let release401; const gate401 = new Promise(resolve => { release401 = resolve; }); releases.add(release401);
        let overviewHeld = false;
        await page.route('**/api/overview', async route => { overviewHeld = true; await gate401; await route.fulfill({ status: 401, contentType: 'application/json', body: JSON.stringify({ error: { code: 'authentication_required', message: 'Synthetic expired session' } }) }); });
        failureStage = 'pending-auth-loss'; await page.reload({ waitUntil: 'domcontentloaded', timeout: 10000 });
        await expect.poll(nextDelayed.intercepted, { timeout: 10000 }).toBe(true);
        await expect.poll(() => overviewHeld, { timeout: 10000 }).toBe(true); expect(counts.deviceReads).toBe(priorReads);
        release401(); await expect(page.getByRole('heading', { name: 'Sign in', exact: true })).toBeVisible();
        await releaseModule(page, nextDelayed); expect(counts.deviceReads).toBe(priorReads);
        await expect(page.locator('.app-shell')).toHaveCount(0); expect(counts.mutations).toBe(0);
    }, '10m');
    await checked(routeLoadingCaseNames[3], async () => {
        const page = await pageAt(`/devices/${fixtureID}`), counts = monitor(page, base);
        failureStage = 'module-failure';
        await page.route(detailScript, route => route.abort('failed'));
        await login(page); await expect(page.getByRole('alert')).toContainText('View could not be loaded');
        expect(counts.deviceReads).toBe(0); expect(counts.details).toBe(1); expect(counts.mutations).toBe(0);
        failureStage = 'failure-captures';
        await shot(page, 'synthetic-route-load-failure-desktop-en', disclosure);
        await page.setViewportSize({ width: 390, height: 844 }); await page.getByLabel('Language', { exact: true }).selectOption('de');
        await shot(page, 'synthetic-route-load-failure-mobile-de', disclosure);
        expect(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth)).toBe(false);
        await page.evaluate(() => { window.dispatchEvent(new Event('focus')); window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true })); });
        await expect(page.getByRole('button', { name: 'Seite neu laden', exact: true })).toBeVisible(); expect(counts.details).toBe(1);
        failureStage = 'deliberate-reload';
        await page.unroute(detailScript); await page.getByRole('button', { name: 'Seite neu laden', exact: true }).click();
        await expect(page.getByRole('region', { name: 'Gerät Fixture workstation', exact: true })).toBeVisible();
        expect(counts.details).toBe(2); expect(counts.deviceReads).toBe(1); expect(counts.mutations).toBe(0);
    }, '10m');
}
export async function routeLoadingDevelopmentCase({ pageAt, expect, base, caseItem }) {
    developmentStage = 'fixture';
    // Existing development manager supplies only the known synthetic case here.
    if (!caseItem.synthetic) throw new Error('Refusing a non-synthetic case');
    developmentStage = 'overview-navigation';
    const page = await pageAt('/overview', { width: 1440, height: 1000 }, { reviewLocale: 'en' });
    await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();
    developmentStage = 'initial-deferral';
    expect(await recordedDetails(page)).toBe(0);
    developmentStage = 'interception-setup';
    const releases = new Set(), counts = monitor(page, base), delayed = await delayModule(page, releases);
    try {
        developmentStage = 'cold-navigation';
        await reloadDevelopmentCaseRoute(page, caseItem.id);
        developmentStage = 'module-interception';
        await expect.poll(() => counts.details).toBe(1);
        await expect.poll(delayed.intercepted, { timeout: 10000 }).toBe(true);
        developmentStage = 'loading-fallback';
        await expect(page.getByText('Loading view …', { exact: true })).toBeVisible();
        await releaseModule(page, delayed, stage => { developmentStage = stage; });
        developmentStage = 'final-render';
        await expect(page.getByRole('heading', { name: caseItem.title, exact: true })).toBeVisible();
        developmentStage = 'final-counts';
        expect(counts.details).toBe(1); expect(counts.mutations).toBe(0);
        developmentStage = 'complete';
    } finally { for (const release of releases) release(); }
}
