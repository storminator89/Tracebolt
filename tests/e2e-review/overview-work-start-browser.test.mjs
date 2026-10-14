import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { contrastRatio, overviewNoOpenWork, overviewWorkStartOrder, overviewWorkStartWidths } from './overview-work-start-browser.mjs';
const fixture = () => ({ generatedAt: '2026-10-04T12:00:00Z', devices: [{ id: 'demo-linux-01', synthetic: true, status: 'unknown', lastSeen: '2026-10-04T11:00:00Z' }], cases: [{ id: 'case-demo-one', synthetic: true, status: 'open' }], activity: [{ caseId: 'case-demo-one' }], stats: { totalDevices: 1, healthyDevices: 0, attentionDevices: 0, unknownDevices: 1, openCases: 1, criticalCases: 1 } });
test('no-open-work projection preserves exact device evidence and unknown counts', () => {
 const original = fixture(), output = overviewNoOpenWork(original);
 assert.equal(output.devices, original.devices); assert.equal(output.generatedAt, original.generatedAt);
 assert.deepEqual(output.stats, { ...original.stats, openCases: 0, criticalCases: 0 });
 assert.deepEqual(output.cases, []); assert.deepEqual(output.activity, []);
 assert.equal(original.cases.length, 1); assert.equal(original.stats.openCases, 1);
});
test('public capture refuses empty, private or incorrectly identified rows', () => {
 for (const change of [value => { value.devices = []; }, value => { value.devices[0].synthetic = false; }, value => { value.devices[0].id = 'real-device'; }, value => { value.cases[0].synthetic = false; }, value => { value.cases[0].id = 'real-case'; }]) {
  const value = fixture(); change(value); assert.throws(() => overviewNoOpenWork(value), /Synthetic populated overview required/);
 }
});
test('capture matrix names CSS viewport reflow without mislabelling zoom', () => {
 assert.deepEqual(overviewWorkStartWidths, [320, 375, 414, 720, 768]);
 assert.deepEqual(overviewWorkStartOrder, ['.overview-context', '.attention-panel', '.summary-strip', '.fleet-panel .device-table', '.activity-panel']);
 const source = readFileSync(new URL('./overview-work-start-browser.mjs', import.meta.url), 'utf8');
 assert.doesNotMatch(source, /deviceScaleFactor|pageScaleFactor|Emulation\.set|\.launch\(/);
 assert.match(source, /page\.setViewportSize/); assert.match(source, /overview-initial-loading/); assert.match(source, /overview-initial-fetch-error/); assert.match(source, /overview-retained-fetch-error/);
});
test('only the established synthetic gallery and existing first-start case call the helper', () => {
 const gallery = readFileSync(new URL('./concise-shell-gallery.mjs', import.meta.url), 'utf8');
 const enrollment = readFileSync(new URL('./enrollment-browser.mjs', import.meta.url), 'utf8');
 assert.match(gallery, /await capture\('overview'\);\s+await reviewOverviewWorkStart\(\{ page, expect, capture, locale, size, viewport, fixture \}\)/);
 assert.match(enrollment, /await assertOverviewWorkStart\(\{page,expect,empty:true\}\);\s+await shot\(page,`synthetic-first-device-empty-/);
 const source = readFileSync(new URL('./overview-work-start-browser.mjs', import.meta.url), 'utf8');
 assert.doesNotMatch(source, /request\.post|method:\s*['"]POST|fetch\(/);
 assert.match(source, /finally\s*\{/); assert.match(source, /unroute/);
});

test('new focus ring clears 3:1 against each authored adjacent surface in both themes', () => {
 for (const [ring, surfaces] of [['rgb(5, 117, 106)', ['rgb(255, 255, 255)', 'rgb(250, 252, 252)', 'rgb(234, 246, 242)']], ['rgb(119, 213, 191)', ['rgb(23, 36, 44)', 'rgb(27, 42, 50)', 'rgb(32, 58, 57)']]]) {
  for (const surface of surfaces) assert.ok(contrastRatio(ring, surface) >= 3);
 }
 assert.throws(() => contrastRatio('rgba(5, 117, 106, .5)', 'rgb(255, 255, 255)'), /opaque/);
});

test('new narrow-screen report and Windows destination reset inherited nowrap', () => {
 const css = readFileSync(new URL('../../web/src/overview-workspace.css', import.meta.url), 'utf8');
 for (const selector of ['.overview-work-scope .text-button', '.overview-workspace .overview-device-report']) {
  const escaped = selector.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const rule = new RegExp(escaped + '\\s*\\{([^}]*)\\}').exec(css);
  assert.ok(rule, 'Expected new overview rule: ' + selector);
  assert.match(rule[1], /white-space:\s*normal/);
 }
});
