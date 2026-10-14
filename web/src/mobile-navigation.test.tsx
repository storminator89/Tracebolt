import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import App from './App';
import { abortProtectedRequests } from './api';
import { setLocale } from './i18n';
import type { Device, Overview } from './types';

const now = '2026-10-14T00:00:00Z';
const metric = { value: null, unit: '%', quality: 'unknown' as const, source: 'Keyboard fixture', collectedAt: now };
const device: Device = { id: 'demo-keyboard', name: 'Keyboard fixture', platform: 'linux', os: 'Synthetic Linux', site: '', group: '', ip: null, status: 'unknown', source: 'synthetic', synthetic: true, lastSeen: now, agentVersion: 'fixture', cpu: metric, memory: metric, disk: metric, uptime: '', tags: [], capabilities: [], evidence: [], trend: [], caseIds: [] };
const overview: Overview = { product: 'Tracebolt fixture', mode: 'local-development', generatedAt: now, stats: { totalDevices: 1, healthyDevices: 0, attentionDevices: 0, unknownDevices: 1, openCases: 0, criticalCases: 0 }, devices: [device], cases: [], activity: [] };
const session = { mode: 'development', transport: 'https', insecureTestMode: false, transportWarning: null, authenticationRequired: false, authenticated: false, csrfToken: null, serverNow: now, expiresAt: null, expiresInSeconds: null };
const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status });
let width: number;
let media: EventTarget & { matches: boolean; media: string };
let fetch: ReturnType<typeof vi.fn>;

beforeEach(() => {
    localStorage.clear(); sessionStorage.clear(); setLocale('en', false);
    window.history.replaceState({}, '', '/#/devices');
    width = 390;
    media = Object.assign(new EventTarget(), { matches: true, media: '(max-width: 760px)' });
    vi.stubGlobal('matchMedia', vi.fn((query: string) => { expect(query).toBe(media.media); return media; }));
    fetch = vi.fn(async (url: string, init?: RequestInit) => {
        if (init?.method && init.method !== 'GET') throw new Error('Navigation must not mutate the API');
        if (url === '/api/auth/session') return json(session);
        if (url === '/api/overview') return json(overview);
        if (url === `/api/devices/${device.id}`) return json(device);
        return json({}, 503);
    });
    vi.stubGlobal('fetch', fetch);
});
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });
function resize(next: number) {
    act(() => {
        const previous = width <= 760; width = next; media.matches = width <= 760;
        if (previous !== media.matches) media.dispatchEvent(new Event('change'));
    });
}
async function openApp() { render(<App/>); return screen.findByRole('textbox', { name: 'Search devices' }); }
const sidebar = () => document.querySelector<HTMLElement>('.sidebar')!;
const trigger = () => screen.getByRole('button', { name: 'Open navigation' });
async function openDrawer() {
    trigger().focus(); await userEvent.keyboard('{Enter}');
    return screen.getByRole('dialog', { name: 'Main navigation' });
}
function expectClosed() {
    expect(sidebar()).toHaveAttribute('inert');
    expect(sidebar()).toHaveAttribute('aria-hidden', 'true');
    expect(sidebar()).not.toHaveAttribute('aria-modal');
    expect(document.querySelector('.main-shell')).not.toHaveAttribute('inert');
    expect(document.querySelector('.skip-link')).not.toHaveAttribute('inert');
    expect(trigger()).toHaveAttribute('aria-expanded', 'false');
    expect(trigger()).toHaveFocus();
}

it('hides the closed mobile navigation from the accessibility tree and isolates the open drawer', async () => {
    const search = await openApp(), frame = document.querySelector('.main-shell');
    // jsdom does not implement native inert Tab traversal. Hosted Chromium
    // checks the actual closed-drawer Tab sequence and computed visibility.
    expect(sidebar()).toHaveAttribute('inert'); expect(sidebar()).toHaveAttribute('aria-hidden', 'true');
    expect(screen.queryByRole('complementary', { name: 'Main navigation' })).not.toBeInTheDocument();
    expect(trigger()).toHaveAttribute('aria-controls', sidebar().id);
    const drawer = await openDrawer();
    expect(drawer).not.toHaveAttribute('inert'); expect(drawer).not.toHaveAttribute('aria-hidden');
    expect(drawer).toHaveAttribute('aria-modal', 'true');
    expect(within(drawer).getByRole('button', { name: 'Devices1' })).toHaveFocus();
    expect(frame).toHaveAttribute('inert'); expect(document.querySelector('.skip-link')).toHaveAttribute('inert');
    const first = drawer.querySelector<HTMLElement>('.mobile-nav-close')!;
    const last = within(drawer).getByRole('button', { name: /Keyboard shortcuts/ });
    first.focus(); await userEvent.tab({ shift: true }); expect(last).toHaveFocus();
    await userEvent.tab(); expect(first).toHaveFocus();
    await userEvent.keyboard('{Escape}'); expectClosed();
    expect(document.querySelector('.main-shell')).toBe(frame); expect(screen.getByLabelText('Search devices')).toBe(search);
    expect(fetch.mock.calls.filter(([path]) => path === '/api/overview')).toHaveLength(1);
    expect(fetch.mock.calls.filter(([path]) => path === '/api/auth/session')).toHaveLength(1);
});

it.each(['close', 'backdrop', 'current route', 'new route', 'hash change'] as const)('dismisses via %s and restores the menu trigger', async dismissal => {
    const search = await openApp(); fireEvent.change(search, { target: { value: 'retained filter' } });
    const drawer = await openDrawer();
    if (dismissal === 'close') fireEvent.click(drawer.querySelector('.mobile-nav-close')!);
    if (dismissal === 'backdrop') fireEvent.click(document.querySelector('.mobile-scrim')!);
    if (dismissal === 'current route') fireEvent.click(within(drawer).getByRole('button', { name: 'Devices1' }));
    if (dismissal === 'new route') fireEvent.click(within(drawer).getByRole('button', { name: 'Investigations' }));
    if (dismissal === 'hash change') act(() => { window.history.replaceState({}, '', '/#/devices/'); window.dispatchEvent(new HashChangeEvent('hashchange')); });
    await waitFor(expectClosed);
    if (dismissal !== 'new route') { expect(screen.getByLabelText('Search devices')).toBe(search); expect(search).toHaveValue('retained filter'); }
});

it('hands Help its own focus and returns to a usable closed-drawer trigger', async () => {
    await openApp(); const drawer = await openDrawer();
    within(drawer).getByRole('button', { name: /Keyboard shortcuts/ }).focus(); await userEvent.keyboard('{Enter}');
    const help = screen.getByRole('dialog', { name: 'Keyboard shortcuts' });
    expect(help).toHaveFocus(); expect(sidebar()).toHaveAttribute('inert');
    await userEvent.keyboard('{Escape}'); expect(screen.queryByRole('dialog')).not.toBeInTheDocument(); expectClosed();
});

it.each([390, 761])('returns Help focus to visible navigation after resizing from %ipx', async initialWidth => {
    resize(initialWidth); const search = await openApp();
    if (initialWidth <= 760) await openDrawer();
    const helpButton = within(sidebar()).getByRole('button', { name: /Keyboard shortcuts/ });
    helpButton.focus(); await userEvent.keyboard('{Enter}');
    const help = screen.getByRole('dialog', { name: 'Keyboard shortcuts' }); expect(help).toHaveFocus();
    resize(initialWidth <= 760 ? 761 : 760); expect(help).toHaveFocus();
    await userEvent.keyboard('{Escape}'); expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    if (initialWidth <= 760) expect(within(sidebar()).getByRole('button', { name: 'Devices1' })).toHaveFocus();
    else expectClosed();
    expect(screen.getByLabelText('Search devices')).toBe(search);
});

it('keeps a device page and its selected tab mounted when drawer Escape is consumed', async () => {
    window.history.replaceState({}, '', `/#/devices/${device.id}`); render(<App/>);
    const detail = await screen.findByRole('region', { name: 'Device Keyboard fixture' });
    const detailsTab = within(detail).getByRole('tab', { name: 'Details' }); fireEvent.click(detailsTab);
    await openDrawer(); await userEvent.keyboard('{Escape}'); expectClosed();
    expect(window.location.hash).toBe(`#/devices/${device.id}`); expect(detail).toBeInTheDocument();
    expect(within(detail).getByRole('tab', { name: 'Details' })).toBe(detailsTab); expect(detailsTab).toHaveAttribute('aria-selected', 'true');
    expect(fetch.mock.calls.filter(([path]) => path === `/api/devices/${device.id}`)).toHaveLength(1);
});

it('handles the exact 760/761 breakpoint, clears latent open state and keeps desktop navigation usable', async () => {
    resize(761); const search = await openApp(), nav = sidebar();
    expect(nav).not.toHaveAttribute('inert'); expect(nav).not.toHaveAttribute('aria-hidden');
    expect(nav).not.toHaveAttribute('role');
    const selected = within(nav).getByRole('button', { name: 'Devices1' }); selected.focus();
    resize(760); expectClosed();
    await openDrawer(); resize(761);
    expect(nav).not.toHaveAttribute('inert'); expect(nav).not.toHaveAttribute('aria-hidden'); expect(nav).not.toHaveClass('is-open');
    expect(selected).toHaveFocus(); expect(document.querySelector('.main-shell')).not.toHaveAttribute('inert');
    resize(760); expectClosed(); await openDrawer();
    nav.querySelector<HTMLElement>('.mobile-nav-close')!.focus(); resize(761); expect(selected).toHaveFocus();
    resize(760); expectClosed(); resize(761); expect(selected).toHaveFocus();
    expect(sidebar()).toBe(nav); expect(screen.getByLabelText('Search devices')).toBe(search);
    expect(fetch.mock.calls.filter(([path]) => path === '/api/auth/session')).toHaveLength(1);
    expect(fetch.mock.calls.filter(([path]) => path === '/api/overview')).toHaveLength(1);
    fireEvent.click(within(nav).getByRole('button', { name: 'Investigations' }));
    await screen.findByRole('heading', { name: 'Investigations', level: 1 }); expect(nav).not.toHaveAttribute('inert');
});

it.each([390, 761])('recovers navigation focus if responsive CSS has already blurred the %ipx opener', async initialWidth => {
    resize(initialWidth); await openApp();
    const origin = initialWidth <= 760 ? trigger() : within(sidebar()).getByRole('button', { name: 'Devices1' });
    origin.focus(); origin.blur(); expect(document.body).toHaveFocus();
    resize(initialWidth <= 760 ? 761 : 760);
    if (initialWidth <= 760) expect(within(sidebar()).getByRole('button', { name: 'Devices1' })).toHaveFocus();
    else expectClosed();
});

it.each(['en', 'de'] as const)('names the compact Save view control and saved confirmation in %s', async locale => {
    setLocale(locale, false); render(<App/>);
    const name = locale === 'en' ? 'Save view' : 'Ansicht speichern', saved = locale === 'en' ? 'Saved' : 'Gespeichert';
    const button = await screen.findByRole('button', { name });
    expect(button).toHaveAttribute('aria-label', name);
    vi.useFakeTimers(); fireEvent.click(button);
    expect(button).toHaveAccessibleName(saved); expect(button).toHaveAttribute('aria-label', saved);
    act(() => vi.advanceTimersByTime(2200)); expect(button).toHaveAccessibleName(name);
    expect(fetch.mock.calls.every(([, init]) => !init?.method || init.method === 'GET')).toBe(true);
});
