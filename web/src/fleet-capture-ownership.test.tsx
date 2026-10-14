import { act, cleanup, render } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import App from './App';
import { abortProtectedRequests } from './api';
import { setLocale } from './i18n';
import { windowsCapacityDevice, windowsCapacitySession } from './windows-capacity-fixture';
import { windowsNow } from './windows-inventory-fixture';

// Run the actual capture recipe's read-only inventory preamble against real App
// DOM. The adapter has no browser, navigation, click, network or screenshot API.
// jsdom geometry checks are inert; this tests ownership/order, never pixels.
const { readFileSync, existsSync } = await vi.importActual<{ readFileSync(path: string, encoding: 'utf8'): string; existsSync(path: string): boolean }>('node:fs');
const relative = 'scripts/capture-windows-fleet-msi-fixtures.mjs';
const source = readFileSync(existsSync(relative) ? relative : `web/${relative}`, 'utf8');
const start = source.indexOf('export async function exerciseWindowsFleetMSI(');
const body = source.indexOf('\n', start) + 1;
const end = source.indexOf('  const worklist = page.getByRole(', body);
if (start < 0 || body <= start || end <= body) throw new Error('Exact inventory preamble boundary missing');
const preamble = source.slice(body, end);
const run = new Function('return async function({page,expect,fixture,locale,width,inventoryShot,windowsFleetMSIOrigin}) {\n' + preamble + '\n}')() as (input: Record<string, unknown>) => Promise<void>;
const devices = [windowsCapacityDevice(), { ...windowsCapacityDevice(), id: `agent_${'2'.repeat(32)}`, name: 'Synthetic second device' }];
const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status });

class DOMLocator {
    constructor(readonly nodes: Element[]) {}
    locator(selector: string) { return new DOMLocator(this.nodes.flatMap(node => [...node.querySelectorAll(selector)])); }
    evaluate<T>(reader: (element: Element) => T): T { expect(this.nodes).toHaveLength(1); return reader(this.nodes[0]); }
    async all() { return this.nodes.map(node => new DOMLocator([node])); }
}
function captureExpect(value: unknown) {
    if (!(value instanceof DOMLocator)) return expect(value);
    return {
        toHaveCount(count: number) { expect(value.nodes).toHaveLength(count); },
        toHaveAttribute(name: string, expected: string) { expect(value.nodes).toHaveLength(1); expect(value.nodes[0]).toHaveAttribute(name, expected); },
    };
}
function recipe(root: ParentNode = document, reads = { artifact: 0, devices: { first: 0, second: 0 } }, locale = 'en') {
    const inventoryShot = vi.fn();
    const page = {
        goto: vi.fn(async (url: string) => { expect(url).toBe('https://windows-fleet-msi.invalid/#/devices'); }),
        locator: (selector: string) => new DOMLocator(root instanceof Element && root.matches(selector) ? [root] : [...root.querySelectorAll(selector)]),
        evaluate: <T,>(reader: () => T) => reader(),
    };
    return { inventoryShot, page, result: run({ page, expect: captureExpect, fixture: { devices, reads }, locale, width: 1440, inventoryShot, windowsFleetMSIOrigin: 'https://windows-fleet-msi.invalid' }) };
}
async function mounted(locale = 'en') {
    setLocale(locale as 'en' | 'de', false);
    const fetch = vi.fn(async (path: string, init?: RequestInit) => {
        if (init?.method && init.method !== 'GET') throw new Error('Capture ownership cannot mutate');
        if (path === '/api/auth/session') return json({ mode: 'lan', transport: 'https', insecureTestMode: false, transportWarning: null, authenticationRequired: true, authenticated: true, csrfToken: 'fixture-csrf', serverNow: windowsNow, expiresAt: windowsCapacitySession, expiresInSeconds: 3590, loginMode: 'named', actorId: `operator_${'6'.repeat(32)}`, capabilities: ['read', 'windows_managed_msi_deliver', 'windows_managed_msi_install'] });
        if (path === '/api/overview') return json({ generatedAt: windowsNow, stats: { totalDevices: devices.length, healthyDevices: 0, attentionDevices: 0, unknownDevices: devices.length, openCases: 0, criticalCases: 0 }, devices, cases: [], activity: [] });
        if (path === '/api/fleet/identities') return json({ schemaVersion: 'tracebolt.fleet-identities.v2', serverNow: windowsNow, items: [] });
        if (path === '/api/fleet/groups') return json({ schemaVersion: 'tracebolt.fleet-groups.v1', serverNow: windowsNow, groups: [], devices: devices.map(({ id, name, platform }) => ({ id, name, platform })) });
        return json({}, 503);
    });
    vi.stubGlobal('fetch', fetch); render(<App/>); await act(async () => {});
    expect(document.querySelectorAll('.inventory-panel .device-table tbody tr')).toHaveLength(2);
    return fetch;
}
beforeEach(() => {
    abortProtectedRequests(); localStorage.clear(); sessionStorage.clear(); vi.useFakeTimers(); vi.setSystemTime(windowsNow);
    window.history.replaceState({}, '', '/#/devices'); vi.spyOn(document, 'hasFocus').mockReturnValue(true);
    Object.defineProperty(document, 'fonts', { configurable: true, value: { ready: Promise.resolve() } });
    Object.defineProperty(HTMLElement.prototype, 'scrollIntoView', { configurable: true, value: vi.fn() });
});
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe('hosted fleet-MSI capture ownership', () => {
    it.each(['en', 'de'])('accepts the actual App and its six collapsed sibling tools (%s)', async locale => {
        const fetch = await mounted(locale), before = fetch.mock.calls.length;
        const probe = recipe(document, undefined, locale); await probe.result;
        expect(probe.inventoryShot).toHaveBeenCalledExactlyOnceWith(probe.page, `synthetic-fleet-inventory-default-1440-${locale}`);
        expect(fetch.mock.calls).toHaveLength(before);
        expect(fetch.mock.calls.some(([path]) => /windows-incidents|windows-software|windows-update|windows-managed-msi|windows-maintenance|windows-notifications/.test(path))).toBe(false);
        expect(fetch.mock.calls.some(([, init]) => init?.method && init.method !== 'GET')).toBe(false);
        // These are the exact stale assumptions that caused the hosted failure.
        const inventory = document.querySelector('.inventory-panel')!;
        expect(inventory.querySelector('.windows-incident-inbox')).toBeNull();
        expect(inventory.querySelectorAll(':scope > section button[aria-expanded]')).toHaveLength(0);
    });
    it('still rejects missing, duplicated, expanded, nested, misplaced or reordered modules and wrong inventory rows', async () => {
        await mounted();
        const changes: Array<[string, (root: Element) => void]> = [
            ['missing tool', root => root.querySelector('.windows-maintenance')!.remove()],
            ['duplicate tool', root => root.querySelector('.devices-tools-section')!.append(root.querySelector('.windows-maintenance')!.cloneNode(true))],
            ['expanded tool', root => root.querySelector('.devices-tools-section button[aria-expanded]')!.setAttribute('aria-expanded', 'true')],
            ['tools before inventory', root => { const tools = root.querySelector('.devices-tools-section')!; root.querySelector('.devices-workspace')!.prepend(tools); }],
            ['reordered tools', root => { const tools = root.querySelector('.devices-tools-section')!; tools.insertBefore(root.querySelector('.windows-maintenance')!, root.querySelector('.windows-incident-inbox')); }],
            ['tool in inventory', root => root.querySelector('.inventory-panel')!.append(root.querySelector('.windows-maintenance')!)],
            ['nested tool', root => { const tool = root.querySelector('.windows-maintenance')!, wrapper = document.createElement('div'); tool.before(wrapper); wrapper.append(tool); }],
            ['wrong inventory row count', root => root.querySelector('.inventory-panel tbody tr')!.remove()],
        ];
        for (const [name, change] of changes) {
            const root = document.documentElement.cloneNode(true) as Element; change(root); const probe = recipe(root);
            await expect(probe.result, name).rejects.toThrow(); expect(probe.inventoryShot, name).not.toHaveBeenCalled();
        }
    });
    it('still rejects any automatic artifact or endpoint MSI read before opening the tool', async () => {
        await mounted();
        for (const reads of [{ artifact: 1, devices: { first: 0, second: 0 } }, { artifact: 0, devices: { first: 1, second: 0 } }, { artifact: 0, devices: { first: 0, second: 1 } }]) {
            const probe = recipe(document, reads); await expect(probe.result).rejects.toThrow(); expect(probe.inventoryShot).not.toHaveBeenCalled();
        }
    });
});
