/** Page-by-page rendered copy review. Overview rows are restricted to the
 * disposable manager's built-in synthetic fixtures before any public capture. */
export function conciseShellFixture(data) {
 const devices = data.devices.filter(item => item.synthetic === true && item.id.startsWith('demo-'));
 const deviceIds = new Set(devices.map(item => item.id));
 const cases = data.cases.filter(item => item.synthetic === true && item.id.startsWith('case-demo-') && deviceIds.has(item.deviceId));
 const caseIds = new Set(cases.map(item => item.id));
 return { product: 'Tracebolt synthetic gallery', mode: 'local-development', generatedAt: data.generatedAt, devices, cases,
  activity: data.activity.filter(item => (deviceIds.has(item.deviceId) || caseIds.has(item.caseId)) && (!item.deviceId || deviceIds.has(item.deviceId)) && (!item.caseId || caseIds.has(item.caseId))),
  stats: { totalDevices: devices.length, healthyDevices: devices.filter(item => item.status === 'healthy').length,
   attentionDevices: devices.filter(item => ['attention', 'critical'].includes(item.status)).length,
   unknownDevices: devices.filter(item => item.status === 'unknown').length,
   openCases: cases.filter(item => item.status !== 'resolved').length,
   criticalCases: cases.filter(item => item.status !== 'resolved' && item.severity === 'critical').length,
  },
 };
}
export function conciseShellTargets(data) {
 const fixture = conciseShellFixture(data);
 const device = fixture.devices.find(item => item.id === 'demo-win-01' && item.platform === 'windows');
 const statusDevice = fixture.devices.find(item => item.id === 'demo-linux-01' && item.platform === 'linux');
 const selectedCase = fixture.cases.find(item => item.deviceId === device?.id);
 if (!device || !statusDevice || !selectedCase) throw new Error('Required synthetic platform gallery fixtures are unavailable.');
 return { fixture, device, statusDevice, selectedCase };
}
export async function conciseShellGallery({ test, pageAt, loaded, shot, expect, data }) {
 const { fixture, device, statusDevice, selectedCase } = conciseShellTargets(data);
 for (const locale of ['en', 'de']) for (const [size, viewport] of [['desktop', { width: 1440, height: 1000 }], ['mobile', { width: 390, height: 844 }]]) {
  await test(`Concise shell every-page synthetic gallery ${size} ${locale}`, async () => {
   const page = await pageAt('/overview', viewport, { reviewLocale: locale });
   await page.route('**/api/overview', route => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(fixture) }));
   await page.reload(); await loaded(page);
   const capture = async (name, section) => {
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1 && document.body.scrollWidth <= innerWidth + 1)).toBe(true);
    await shot(page, `synthetic-concise-shell-${name}-${size}-${locale}`, section);
   };
   await expect(page.locator('.fleet-panel .device-table .source.real')).toHaveCount(0);
   await capture('overview');
   for (const route of ['devices', 'cases', 'settings']) {
    await page.goto(new URL(`#/${route}`, page.url()).href); await loaded(page);
    if (route === 'devices') await expect(page.locator('.device-table .source.real')).toHaveCount(0);
    await capture(route);
    if (route === 'settings') await capture('settings-runtime', '.settings-grid');
   }
   await page.goto(new URL(`#/devices/${device.id}`, page.url()).href);
   await expect(page.locator('.device-page h1')).toHaveText(device.name);
   for (const [key, name] of [['overview', locale === 'de' ? 'Übersicht' : 'Overview'], ['details', 'Details'], ['evidence', locale === 'de' ? 'Belege' : 'Evidence']]) {
    await page.getByRole('tab', { name, exact: true }).click();
    await capture(`device-${key}`);
   }
   if (locale === 'de') {
    // Windows has its own overview. Exercise the original three-card contract
    // on a separately whitelisted Linux demo, without dropping Windows views.
    await page.goto(new URL(`#/devices/${statusDevice.id}`, page.url()).href);
    await expect(page.locator('.device-page h1')).toHaveText(statusDevice.name);
    await page.getByRole('tab', { name: 'Übersicht', exact: true }).click();
    // Real layout assertion: the two unknown status values must remain intact
    // at 390px, while desktop typography and the three-card structure stay put.
    await page.evaluate(async () => { await document.fonts.ready; });
    await expect(page.locator('.device-essential-card')).toHaveCount(3);
    const unknown = page.locator('.device-essential-value').filter({ hasText: /^Unbekannt$/ });
    await expect(unknown).toHaveCount(2);
    const geometry = await unknown.evaluateAll(values => values.map(value => {
     const range = document.createRange(); range.selectNodeContents(value);
     const lines = [...range.getClientRects()], card = value.closest('.device-essential-card');
     const bounds = card.getBoundingClientRect(), style = getComputedStyle(card);
     return { text: value.textContent, lines: lines.length,
      contained: lines.every(line => line.left >= bounds.left + parseFloat(style.paddingLeft) - 1 && line.right <= bounds.right - parseFloat(style.paddingRight) + 1),
      fontSize: parseFloat(getComputedStyle(value).fontSize) };
    }));
    for (const value of geometry) {
     expect(value.text).toBe('Unbekannt'); expect(value.lines).toBe(1); expect(value.contained).toBe(true);
     if (size === 'desktop') expect(value.fontSize).toBe(22);
     else { expect(value.fontSize).toBeGreaterThanOrEqual(13); expect(value.fontSize).toBeLessThanOrEqual(16); }
    }
    await capture('linux-device-overview');
   }
   await page.goto(new URL(`#/cases/${selectedCase.id}`, page.url()).href);
   await expect(page.locator('.case-detail-header h1')).toHaveText(selectedCase.title);
   await capture('case'); await capture('case-steps', '.next-steps-panel');
   await page.keyboard.press('?');
   await expect(page.getByRole('dialog', { name: locale === 'de' ? 'Tastenkürzel' : 'Keyboard shortcuts', exact: true })).toBeVisible();
   await capture('shortcuts'); await page.keyboard.press('Escape');
  });
 }
}
