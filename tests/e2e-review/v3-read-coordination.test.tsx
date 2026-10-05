/** Real React/request helpers plus the loopback Go v3 fixture. DOM integration,
 * not a Chromium, native collector, installer or endpoint acceptance claim. */
import { afterAll, afterEach, beforeAll, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '../../web/node_modules/@testing-library/react/dist/index.js';
import { spawn, execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { DeviceInventoryWorkspace } from '../../web/src/device-inventory';
import { abortProtectedRequests } from '../../web/src/api';
import { setLocale } from '../../web/src/i18n';

// Only the enclosing session context is supplied. Cookies, CSRF acquisition,
// status/page parsing, hooks and storage authorization use the real handlers.
vi.mock('../../web/src/auth', () => ({ useOperator: () => ({ mode: 'lan', authenticated: true, expiresAt: '2030-10-04T01:00:00Z' }) }));
const nativeFetch = globalThis.fetch;
const root = process.env.TRACEBOLT_V3_DOM_ROOT!;
const base = `http://127.0.0.1:${Number(process.env.V3_DOM_REVIEW_PORT || 19898)}`;
let directory: string, server: ReturnType<typeof spawn>, cookie = '';
let devices: Record<string, string>;
const events: { resource: string; status: number }[] = [];
const inFlight = new Set<Promise<Response>>();
beforeAll(async () => {
    directory = mkdtempSync(join(tmpdir(), 'tracebolt-v3-dom-'));
    const binary = join(directory, 'fixture');
    execFileSync(process.env.GO_BIN || 'go', ['build', '-buildvcs=false', '-o', binary, './tests/e2e-review/v3fixture'], { cwd: root, stdio: 'ignore' });
    server = spawn(binary, ['--listen', new URL(base).host, '--state', directory, '--web', join(root, 'web/dist')], { stdio: ['pipe', 'pipe', 'ignore'] });
    devices = await new Promise<Record<string, string>>((done, reject) => {
        const pipe = createInterface({ input: server.stdout! });
        const timeout = setTimeout(() => { pipe.close(); reject(new Error('FIXTURE_SETUP_TIMEOUT')); }, 15000);
        server.once('error', () => { clearTimeout(timeout); pipe.close(); reject(new Error('FIXTURE_START_FAILED')); });
        pipe.once('line', line => { clearTimeout(timeout); pipe.close(); const info = JSON.parse(line); expect(info.ok).toBe(true); done(info.devices); });
        server.stdin!.write('{"action":"info"}\n');
    });
    const login = await nativeFetch(base + '/api/auth/login', { method: 'POST', headers: { Origin: base, 'Content-Type': 'application/json' }, body: JSON.stringify({ password: 'TRACEBOLT_V3_BROWSER_FIXTURE_NOT_A_REAL_PASSWORD' }) });
    expect(login.status).toBe(200); cookie = login.headers.get('set-cookie')!.split(';')[0];
    // jsdom has no network cookie jar. Adapt only its origin/cookie transport;
    // retain production methods, bodies, cancellation and CSRF headers.
    vi.stubGlobal('fetch', async (path: string, options: RequestInit = {}) => {
        const pending = nativeFetch(base + path, { ...options, headers: { ...options.headers, Cookie: cookie, ...(options.method === 'POST' ? { Origin: base } : {}) } });
        inFlight.add(pending);
        try {
            const result = await pending;
            if (/inventory\/(packages|cached-updates|complete-updates)/.test(path)) events.push({ resource: path.split('/inventory/')[1], status: result.status });
            return result;
        } finally { inFlight.delete(pending); }
    });
}, 90000);
beforeEach(() => { setLocale('en', false); events.length = 0; });
afterEach(async () => { cleanup(); abortProtectedRequests(); await Promise.allSettled([...inFlight]); });
afterAll(async () => {
    vi.unstubAllGlobals(); cookie = '';
    try {
        if (server && server.exitCode === null) {
            const end = new Promise<void>(done => server.once('exit', () => done()));
            server.stdin!.end();
            const timer = setTimeout(() => server.kill('SIGKILL'), 1500);
            try { await end; } finally { clearTimeout(timer); }
        }
    } finally { if (directory) rmSync(directory, { recursive: true, force: true }); }
});

it.each(['alpha', 'beta', 'awaiting'])('reads only Packages for real %s without competing update reads', async label => {
    const { container } = render(<DeviceInventoryWorkspace deviceId={devices[label]} initialSource="packages"/>);
    await waitFor(() => expect(container.querySelector('.complete-packages')).toHaveAttribute('aria-busy', 'false'));
    expect(container.querySelector('[role=alert]')).toBeNull();
    if (label === 'alpha') expect(screen.getAllByRole('rowheader')).toHaveLength(100);
    if (label === 'beta') expect(screen.getByText('The completed generation contains zero installed or incomplete dpkg rows.')).toBeVisible();
    if (label === 'awaiting') {
        expect(screen.getByText('Awaiting a complete generation')).toBeVisible();
        expect(screen.queryByText(/completed generation contains zero/)).not.toBeInTheDocument();
    }
    expect(events).toEqual(label === 'awaiting' ? [{ resource: 'packages', status: 200 }] : [{ resource: 'packages', status: 200 }, { resource: 'packages/query', status: 200 }]);
});

it('changes the real update source without mounting both read paths', async () => {
    const { container } = render(<DeviceInventoryWorkspace deviceId={devices.beta} initialSource="packages"/>);
    await screen.findByText('The completed generation contains zero installed or incomplete dpkg rows.');
    events.length = 0;
    fireEvent.click(screen.getByRole('tab', { name: 'Updates' }));
    await screen.findByText('Awaiting a complete update generation');
    expect(events).toEqual([{ resource: 'complete-updates', status: 200 }]);
    const choice = screen.getByLabelText('Update view'); choice.focus();
    fireEvent.change(choice, { target: { value: 'preview' } });
    await screen.findByText('No accepted cached-update report');
    expect(choice).toHaveFocus(); expect(container.querySelector('.complete-packages')).toBeNull();
    expect(events).toEqual([{ resource: 'complete-updates', status: 200 }, { resource: 'cached-updates', status: 200 }]);
    fireEvent.change(choice, { target: { value: 'complete' } });
    await screen.findByText('Awaiting a complete update generation');
    expect(container.querySelector('.cached-updates')).toBeNull();
    expect(events).toEqual([{ resource: 'complete-updates', status: 200 }, { resource: 'cached-updates', status: 200 }, { resource: 'complete-updates', status: 200 }]);
    expect(container.querySelector('[role=alert]')).toBeNull();
});
