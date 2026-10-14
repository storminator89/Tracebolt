import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { devicesWorkspaceCaptureMatrix, devicesWorkspaceOrder, devicesWorkspaceWidths } from './devices-workspace-browser.mjs';
const read = name => readFileSync(new URL(name, import.meta.url), 'utf8');
test('four bounded core captures show actual LAN Setup and Tools in representative locales, themes and sizes', () => {
 assert.equal(devicesWorkspaceCaptureMatrix.length, 4);
 assert.deepEqual(devicesWorkspaceCaptureMatrix.map(row => `${row.locale}/${row.size}/${row.theme}/${row.destination}`), ['en/desktop/light/setup', 'en/desktop/light/tools', 'de/mobile/dark/setup', 'de/mobile/dark/tools']);
 assert.deepEqual(devicesWorkspaceWidths, [320, 375, 414, 768]);
 assert.deepEqual(devicesWorkspaceOrder, ['.devices-workspace-index', '.devices-inventory-section', '.devices-setup-section', '.devices-tools-section']);
});
test('capture helper is read-only and identifies CSS reflow and text-resize without claiming native zoom', () => {
 const source = read('./devices-workspace-browser.mjs');
 assert.doesNotMatch(source, /\.launch\(|request\.post|fetch\(|method:\s*['"]POST|deviceScaleFactor|pageScaleFactor|Emulation\.set/);
 assert.match(source, /page\.setViewportSize/); assert.match(source, /text-resize-200-percent-320/); assert.match(source, /not native browser zoom/);
 assert.match(source, /getByRole\('dialog'\)\)\.toHaveCount\(0\)/); assert.match(source, /finally\s*\{/);
});
test('existing source-bound synthetic gallery and disposable enrollment cases call the focused helper', () => {
 const gallery = read('./concise-shell-gallery.mjs'), enrollment = read('./enrollment-browser.mjs');
 assert.match(gallery, /reviewDevicesWorkspace\(\{ page, expect, capture, locale, size, viewport \}\)/);
 assert.match(enrollment, /assertDevicesWorkspace\(\{page,expect,locale,tools:true\}\)/);
 for (const state of ['pending-review', 'unconfirmed']) assert.ok(enrollment.includes(`reviewSelectedSetupAttention({page,expect,shot,state:'${state}'})`));
 // Never relax the pre-existing public capture guard to obtain these images.
 for (const field of ['secret', 'comparison', 'fingerprint']) assert.ok(enrollment.includes(`page.locator('.enrollment-${field}')).toHaveCount(0)`));
});
test('page composition retains one instance of each module behind its original guard', () => {
 const app = read('../../web/src/App.tsx');
 const names = ['WindowsIncidentInbox', 'WindowsFleetSoftwareLookup', 'WindowsFleetUpdateWorklist', 'WindowsFleetManagedMSIWorklist', 'WindowsMaintenance', 'WindowsNotifications'];
 for (const name of names) assert.equal((app.match(new RegExp(`<${name} `, 'g')) ?? []).length, 1);
 assert.match(app, /tools=\{groupsEnabled && <>/); assert.match(app, /FleetGroupsControls key=\{fleetGroups.generation\} resource=\{fleetGroups\}/);
 const workspace = read('../../web/src/devices-workspace.tsx');
 assert.doesNotMatch(workspace, /navigate\(|history\.|location\.|dispatchEvent|aria-selected|role="tab|(?<!aria-)hidden=|inert=/);
 assert.match(workspace, /focus\(\{ preventScroll: true \}\)/); assert.match(workspace, /main\.scrollTop = Math\.max/);
});

test('destination captures follow real keyboard jumps and preserve the original page/control state', () => {
 const source = read('./devices-workspace-browser.mjs');
 const start = source.indexOf('export async function captureDevicesWorkspaceDestinations'), end = source.indexOf('export async function reviewSelectedSetupAttention', start);
 const captures = source.slice(start, end);
 assert.match(captures, /keyboard\.press\('Enter'\)/); assert.match(captures, /toBeFocused\(\)/); assert.match(captures, /toBeInViewport\(\)/);
 assert.doesNotMatch(captures, /scrollTop\s*=|addStyleTag|\.style\.|aria-expanded.*false|\.click\(.*toggle/);
 assert.match(captures, /await shot\(page, `synthetic-devices-\$\{item.destination\}/);
 const states = source.slice(end);
 assert.ok(states.indexOf('state}-destination') < states.indexOf('node.scrollTop = 0'));
 assert.match(read('./enrollment-browser.mjs'), /captureDevicesWorkspaceDestinations\(\{page,expect,shot,locale,mobile\}\)/);
});
