import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import App from './App';
import { abortProtectedRequests } from './api';
import { setLocale } from './i18n';
import type { Overview } from './types';
import { windowsCapacityDevice, windowsCapacitySession } from './windows-capacity-fixture';
import { windowsNow } from './windows-inventory-fixture';

// Synthetic responses, but real App/Auth/request/assignment and CSV production code.
// This is not a browser, endpoint, provider or deployed-manager acceptance test.
const customers = [
    { id: `customer_${'1'.repeat(32)}`, name: 'PRIVATE CUSTOMER ALPHA', revision: 1 },
    { id: `customer_${'2'.repeat(32)}`, name: 'PRIVATE CUSTOMER BETA', revision: 2 },
];
const devices = [
    { ...windowsCapacityDevice(), name: 'Allowed endpoint Alpha' },
    { ...windowsCapacityDevice(), id: `agent_${'3'.repeat(32)}`, name: 'Allowed endpoint Beta' },
];
const identities = ['ab'.repeat(32), 'cd'.repeat(32)];
const csrf = 'SYNTHETIC_PRIVATE_CSRF_CANARY';
const overview: Overview = { product: 'Tracebolt', mode: 'lan', generatedAt: windowsNow, devices, cases: [], activity: [], stats: { totalDevices: 2, healthyDevices: 0, attentionDevices: 0, unknownDevices: 2, openCases: 0, criticalCases: 0 } };
const session = { mode: 'lan', transport: 'https', insecureTestMode: false, transportWarning: null, authenticationRequired: true, authenticated: true, csrfToken: csrf, serverNow: windowsNow, expiresAt: windowsCapacitySession, expiresInSeconds: 3590, loginMode: 'shared', actorId: null, capabilities: ['read'] };
const labels = {
    en: { export: 'Export CSV', panel: 'Assign Windows devices to customers', device: 'Select a Windows identity', customer: 'Select a customer', assign: 'Assign reviewed identity', recorded: 'Recorded assignments' },
    de: { export: 'CSV exportieren', panel: 'Windows-Geräte Kunden zuordnen', device: 'Windows-Identität auswählen', customer: 'Kunden auswählen', assign: 'Geprüfte Identität zuordnen', recorded: 'Gespeicherte Zuordnungen' },
} as const;
const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status });
const flush = () => act(async () => {});

beforeEach(() => {
    abortProtectedRequests(); localStorage.clear(); sessionStorage.clear();
    // Leave FileReader's asynchronous I/O scheduler real while holding UI clocks.
    vi.useFakeTimers({ toFake: ['Date', 'performance', 'setTimeout', 'clearTimeout', 'setInterval', 'clearInterval'] }); vi.setSystemTime(windowsNow);
    window.history.replaceState({}, '', '/#/devices');
    vi.spyOn(document, 'hasFocus').mockReturnValue(true);
});
afterEach(() => {
    cleanup(); abortProtectedRequests(); vi.useRealTimers();
    vi.unstubAllGlobals(); vi.restoreAllMocks();
});

it.each(['en', 'de'] as const)('keeps actual CSV read/export scope unchanged by customer selection and acknowledged assignment (%s)', async locale => {
    const c = labels[locale];
    let assigned = false;
    const assignmentView = () => ({
        schemaVersion: 'tracebolt.customer-windows-assignments.v1', serverNow: windowsNow,
        validUntil: '2026-10-07T12:00:40Z', customers, unavailableAssignments: 0,
        devices: devices.map((d, index) => ({ deviceId: d.id, identity: identities[index], customerId: index === 1 ? customers[1].id : assigned ? customers[0].id : '' })),
    });
    const fetch = vi.fn(async (path: string, init?: RequestInit) => {
        const method = init?.method ?? 'GET';
        if (method === 'POST' && path === '/api/customer-windows-assignments') {
            expect(JSON.parse(String(init?.body))).toEqual({ customerId: customers[0].id, customerRevision: 1, deviceId: devices[0].id, identity: identities[0], acknowledged: true });
            expect(new Headers(init?.headers).get('X-CSRF-Token')).toBe(csrf);
            expect(assigned).toBe(false); assigned = true;
            return json(assignmentView());
        }
        expect(method).toBe('GET');
        if (path === '/api/auth/session') return json(session);
        if (path === '/api/session') return json({ csrfToken: csrf });
        if (path === '/api/overview') return json(overview);
        if (path === '/api/customers') return json({ schemaVersion: 'tracebolt.customers.v1', customers });
        if (path === '/api/customer-windows-assignments') return json(assignmentView());
        if (path === '/api/fleet/groups') return json({ schemaVersion: 'tracebolt.fleet-groups.v1', serverNow: windowsNow, groups: [], devices: devices.map(({ id, name }) => ({ id, name, platform: 'windows' })) });
        return json({}, 503);
    });
    vi.stubGlobal('fetch', fetch);
    const blobs: Blob[] = [];
    const createObjectURL = vi.fn((blob: Blob) => { blobs.push(blob); return 'blob:synthetic-customer-csv'; });
    vi.stubGlobal('URL', Object.assign(class extends URL {}, { createObjectURL, revokeObjectURL: vi.fn() }));
    const download = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
    setLocale(locale, false); render(<App/>); await flush();
    const panel = screen.getByRole('region', { name: c.panel });
    const recorded = () => within(panel).getByRole('list', { name: c.recorded });
    const rows = () => document.querySelectorAll('.inventory-panel tbody tr');
    expect(rows()).toHaveLength(2);

    async function exportCSV() {
        const before = fetch.mock.calls.length, downloads = download.mock.calls.length;
        fireEvent.click(screen.getByRole('button', { name: c.export }));
        await flush();
        expect(fetch).toHaveBeenCalledTimes(before);
        expect(download).toHaveBeenCalledTimes(downloads + 1);
        const blob = blobs.at(-1)!;
        expect(blob.type).toBe('text/csv;charset=utf-8;');
        const text = await new Promise<string>((resolve, reject) => {
            const reader = new FileReader(); reader.onload = () => resolve(String(reader.result));
            reader.onerror = () => reject(reader.error); reader.readAsText(blob);
        });
        expect(text.trim().split('\r\n')).toHaveLength(3);
        for (const d of devices) expect(text).toContain(d.name);
        for (const privateValue of [csrf, ...identities, ...customers.flatMap(customer => [customer.id, customer.name])]) expect(text).not.toContain(privateValue);
        return text;
    }
    const baseline = await exportCSV();
    const beforeSelection = fetch.mock.calls.length;
    fireEvent.change(within(panel).getByLabelText(c.device), { target: { value: devices[0].id } });
    for (const customer of [customers[1], customers[0]]) {
        fireEvent.change(within(panel).getByLabelText(c.customer), { target: { value: customer.id } });
        await flush();
        expect(within(recorded()).getAllByRole('listitem')).toHaveLength(2);
        expect(rows()).toHaveLength(2);
        expect(within(panel).getByRole('checkbox')).not.toBeChecked();
        expect(within(panel).getByRole('button', { name: c.assign })).toBeDisabled();
        expect(fetch).toHaveBeenCalledTimes(beforeSelection);
        expect(await exportCSV()).toBe(baseline);
    }
    const beforeAssignment = fetch.mock.calls.length;
    fireEvent.click(within(panel).getByRole('checkbox'));
    fireEvent.click(within(panel).getByRole('button', { name: c.assign }));
    await flush();
    expect(assigned).toBe(true);
    expect(fetch.mock.calls.slice(beforeAssignment).map(([path, init]) => [path, init?.method ?? 'GET'])).toEqual([
        ['/api/session', 'GET'], ['/api/customer-windows-assignments', 'POST'],
    ]);
    for (const customer of customers) expect(within(recorded()).getByText(customer.name)).toBeVisible();
    expect(rows()).toHaveLength(2);
    expect(await exportCSV()).toBe(baseline);
    expect(fetch.mock.calls.filter(([, init]) => init?.method && init.method !== 'GET')).toHaveLength(1);
    // CSV never performs a server export; assignment sends no collection/action/scope request.
    expect(fetch.mock.calls.some(([path]) => /export|grant|scope|actions|analy[sz]/i.test(path))).toBe(false);
    expect(fetch.mock.calls.every(([path]) => !path.includes('?') && !path.includes('customer_'))).toBe(true);
});
