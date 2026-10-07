/** Rendered production UI with invented status DTOs. No endpoint observation,
 * journal content, collection, grant, mutation or host operation is performed. */
import { systemDevice, systemNow, systemView } from '../../web/src/system-inventory-fixtures.ts';
export const capabilityFixtureDisclosure = 'Real loopback fixture login with intercepted synthetic capability status DTOs; rendered UI only, no host, journal content, capture, grant or data write.';
export const capabilityCaseName = 'Synthetic capability source states preserve denied, failed and stale reads without profile-only warnings';
let stage = 'setup';
export const capabilityFailureStage = () => stage;

export function capabilitySystemFixture(phase = 'collected', cycle = 0) {
 if (!['collected', 'denied', 'failed', 'stale', 'unsupported'].includes(phase)) throw new Error('Invalid capability fixture phase');
 if (!Number.isSafeInteger(cycle) || cycle < 0 || cycle > 1) throw new Error('Invalid capability fixture cycle');
 const view = systemView(), shift = value => new Date(Date.parse(value) + cycle * 300000).toISOString();
 view.serverNow = shift(view.serverNow); view.receivedAt = shift(view.receivedAt);
 view.latest.collectedAt = shift(view.latest.collectedAt);
 const generation = 'sample_' + (cycle ? 'b' : 'a').repeat(32);
 view.latest.generationId = generation; view.sequence = String(BigInt(view.sequence) + BigInt(cycle));
 for (const section of ['services', 'sockets']) {
  view.latest[section].generationId = generation; view.latest[section].observedAt = shift(view.latest[section].observedAt);
  view.lastComplete[section].sequence = view.sequence;
  view.lastComplete[section].meta.generationId = generation; view.lastComplete[section].meta.observedAt = shift(view.lastComplete[section].meta.observedAt);
 }
 if (phase === 'denied' || phase === 'failed' || phase === 'unsupported') {
  view.latest.services = { ...view.latest.services, coverage: 'failed', reason: phase === 'denied' ? 'permission_denied' : phase === 'failed' ? 'read_failed' : 'not_supported', observedCount: null, countExact: false };
 }
 if (phase === 'stale') {
  view.serverNow = shift('2026-10-04T00:02:10Z'); view.status = 'stale';
  view.lastComplete.services.status = 'stale'; view.lastComplete.sockets.status = 'stale';
 }
 return view;
}
export function capabilityDeviceFixture() {
 const metric = { value: null, unit: '%', quality: 'unknown', source: capabilityFixtureDisclosure, collectedAt: systemNow };
 return { id: systemDevice, name: 'Synthetic capability fixture', platform: 'linux', os: capabilityFixtureDisclosure, site: 'Fixture', group: 'Fixture', ip: null, status: 'unknown', source: 'lan', synthetic: false, lastSeen: systemNow, agentVersion: 'fixture', cpu: metric, memory: metric, disk: metric, uptime: '', tags: [], evidence: [], trend: [], caseIds: [], capabilities: [
  { id: 'systemd', name: 'Service inventory fixture', status: 'scope', detail: 'Selected profile is not collection success. The independent source report decides the displayed state.' },
  { id: 'socket_inventory', name: 'Connection inventory fixture', status: 'scope', detail: 'Connection enumeration does not establish owner attribution.' },
  { id: 'socket_owner_metadata', name: 'Owner source fixture', status: 'scope', detail: 'No privileged owner provenance is present in this fixture.' },
  { id: 'host_inventory', name: 'Attribution scope fixture', status: 'limited', detail: 'Static scope information, not a failed read.' },
  { id: 'remote_actions', name: 'Unsupported function fixture', status: 'unsupported', detail: 'Not part of this read profile.' },
 ] };
}

export async function capabilityBrowserCase({ pageAt, login, shot, expect, base }) {
  stage = 'setup'; const page = await pageAt('/devices/' + systemDevice);
  const noOverflow = async () => expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1 && document.body.scrollWidth <= innerWidth + 1)).toBe(true);
  let phase = 'collected', cycle = 0, statusReads = 0;
  const writes = [], contentReads = [], external = [], device = capabilityDeviceFixture();
  const prefix = '/api/devices/' + systemDevice;
  await page.route('**/*', async route => {
   const request = route.request(), url = new URL(request.url());
   if (url.origin !== base) { external.push('external'); return route.abort('blockedbyclient'); }
   if (url.pathname === '/api/auth/login' && request.method() === 'POST') return route.continue();
   if (request.method() !== 'GET' || request.postData() !== null) { writes.push('non-read'); return route.abort('blockedbyclient'); }
   if (url.pathname.includes('/journal') || url.pathname.endsWith('/query')) { contentReads.push('content-read'); return route.abort('blockedbyclient'); }
   const fulfill = value => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(value) });
   if (url.pathname === '/api/auth/session') return route.continue();
   if (url.pathname === '/api/overview') return fulfill({ product: 'Tracebolt synthetic fixture', mode: 'lan', generatedAt: systemNow, stats: { totalDevices: 1, healthyDevices: 0, attentionDevices: 0, unknownDevices: 1, openCases: 0, criticalCases: 0 }, devices: [device], cases: [], activity: [] });
   if (url.pathname === prefix) return fulfill(device);
   if (url.pathname === prefix + '/inventory/system') { statusReads++; return fulfill(capabilitySystemFixture(phase, cycle)); }
   if (url.pathname.startsWith('/api/')) return route.fulfill({ status: 503, contentType: 'application/json', body: JSON.stringify({ error: { code: 'synthetic_source_absent', message: 'Unrelated synthetic source unavailable.' } }) });
   return route.continue();
  });
  await expect(page.getByRole('heading', { name: 'Sign in', exact: true })).toBeVisible();
  expect(statusReads).toBe(0); await login(page);
  for (const locale of ['en', 'de']) {
  stage = locale + '-collected'; phase = 'collected'; cycle = locale === 'de' ? 1 : 0;
  await page.setViewportSize({ width: 1440, height: 1000 });
  if (locale === 'de') await page.getByLabel('Language', { exact: true }).selectOption('de');
  await expect(page.getByRole('heading', { name: 'Synthetic capability fixture', exact: true })).toBeVisible();
  await page.getByRole('tab', { name: locale === 'de' ? 'Fähigkeiten' : 'Capabilities', exact: true }).click();
  const row = id => page.locator(`[data-capability="${id}"]`), check = page.getByRole('button', { name: locale === 'de' ? 'Status prüfen' : 'Check status', exact: true });
  if (locale === 'de') { await expect(check).toBeEnabled(); await check.click(); }
  await expect(row('systemd')).toHaveAttribute('data-state', 'available');
  await expect(row('systemd')).toHaveClass(/observed/);
  await expect(row('systemd')).not.toHaveClass(/attention/);
  await expect(row('host_inventory')).toHaveAttribute('data-state', 'scope');
  await expect(row('host_inventory')).not.toHaveClass(/attention/);
  await expect(row('socket_owner_metadata')).toHaveAttribute('data-state', 'unknown');
  await expect(row('remote_actions')).toHaveAttribute('data-state', 'unsupported');
  await expect(page.locator('.capability-observations details[open]')).toHaveCount(0);
  await expect(page.getByText(device.capabilities[0].detail, { exact: true })).not.toBeVisible();
  await expect(page.locator('.device-tab-scroll')).toHaveCount(0);
  await noOverflow(); await page.locator('.capability-observations').scrollIntoViewIfNeeded(); await shot(page, `synthetic-capability-collected-desktop-${locale}`, capabilityFixtureDisclosure);
  for (const state of ['denied', 'failed', 'stale']) {
   stage = locale + '-' + state; phase = state; const before = statusReads; await check.click();
   await expect.poll(() => statusReads).toBeGreaterThan(before);
   await expect(row('systemd')).toHaveAttribute('data-state', state);
   await expect(row('systemd')).toHaveClass(/attention/);
   await expect(row('systemd').locator('.capability-state')).toBeVisible();
   await expect(check).toBeEnabled();
   if (locale === 'en') await shot(page, `synthetic-capability-${state}-desktop-en`, capabilityFixtureDisclosure);
  }
  await page.setViewportSize({ width: 390, height: 844 });
  await noOverflow();
  stage = locale + '-mobile-navigation';
  const activeTab = page.getByRole('tab', { name: locale === 'de' ? 'Fähigkeiten' : 'Capabilities', exact: true });
  const activeTabVisible = () => activeTab.evaluate(element => {
   const item = element.getBoundingClientRect(), strip = element.parentElement.getBoundingClientRect();
   return item.left >= strip.left - 1 && item.right <= strip.right + 1;
  });
  await expect.poll(activeTabVisible).toBe(true);
  const previousSections = page.getByRole('button', { name: locale === 'de' ? 'Vorherige Gerätebereiche anzeigen' : 'Show previous device sections', exact: true });
  const moreSections = page.getByRole('button', { name: locale === 'de' ? 'Weitere Gerätebereiche anzeigen' : 'Show more device sections', exact: true });
  await expect(previousSections).toBeEnabled(); await expect(moreSections).toBeDisabled();
  expect(await previousSections.evaluate(element => { const rect = element.getBoundingClientRect(); return rect.width >= 44 && rect.height >= 44; })).toBe(true);
  await previousSections.click(); await expect(moreSections).toBeEnabled();
  await expect(activeTab).toHaveAttribute('aria-selected', 'true');
  await expect(row('systemd')).toHaveAttribute('data-state', 'stale');
  await activeTab.evaluate(element => element.focus({ preventScroll: true }));
  await page.keyboard.press('End'); await expect(activeTab).toBeFocused();
  await expect.poll(activeTabVisible).toBe(true); await expect(moreSections).toBeDisabled();
  stage = locale + '-mobile-disclosure';
  const details = row('systemd').locator('details');
  await details.locator('summary').focus(); await page.keyboard.press('Enter');
  await expect(details).toHaveAttribute('open', '');
  await expect(page.getByText(device.capabilities[0].detail, { exact: true })).toBeVisible();
  await page.keyboard.press('Enter'); await expect(details).not.toHaveAttribute('open');
  await shot(page, `synthetic-capability-stale-mobile-${locale}`, capabilityFixtureDisclosure);
  }
  stage = 'read-only-guards'; expect(writes).toEqual([]); expect(contentReads).toEqual([]); expect(external).toEqual([]);
}
