import { Children, createElement, isValidElement } from 'react';
import type { ReactElement, ReactNode } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { DeviceMonitoringNavigation } from './device-monitoring-navigation';
import { DeviceDetail } from './details';
import type { Device } from './types';

const state = vi.hoisted(() => ({
    locale: 'en' as 'en' | 'de',
    device: null as Device | null,
    operator: { mode: 'lan', authenticated: true, expiresAt: '2026-10-07T21:00:00Z' },
    accessEnded: false,
}));
vi.mock('./i18n', async original => ({ ...await original<typeof import('./i18n')>(), useLocale: () => [state.locale, vi.fn()] as const }));
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: () => state.operator }));
vi.mock('./device-metadata-resource', () => ({ useDeviceMetadata: () => ({ device: state.device, snapshot: null, metadataElapsed: 0, refreshing: false, accessEnded: state.accessEnded, error: '', automaticState: 'off', refresh: vi.fn() }) }));
vi.mock('./endpoint-identity-resource', () => ({ useEndpointIdentity: () => ({ snapshot: null, view: null, error: null, loading: true }) }));
vi.mock('./windows-inventory-resource', () => ({ useWindowsInventory: () => ({ snapshot: null, view: null, error: null, loading: true }) }));
vi.mock('./device-essentials', () => ({ DeviceEssentials: () => null, DeviceObservationNotes: () => null }));
vi.mock('./windows-inventory', () => ({ WindowsDeviceOverview: () => null, WindowsInventoryWorkspace: () => null, WindowsObservationNotes: () => null }));
vi.mock('./endpoint-identity', () => ({ EndpointHostnameStatus: () => null, EndpointIdentityPanel: () => null }));

const id = 'agent_monitor_fixture';
function device(patch: Partial<Device> = {}): Device {
    const metric = { value: null, unit: '%', quality: 'unknown' as const, source: '', collectedAt: '2026-10-07T20:00:00Z' };
    return { id, name: 'Fixture device', platform: 'linux', os: 'Linux fixture', site: '', group: '', ip: null, status: 'unknown', source: 'lan', synthetic: false, lastSeen: metric.collectedAt, agentVersion: '', cpu: metric, memory: metric, disk: metric, uptime: '', tags: [], capabilities: [], evidence: [], trend: [], caseIds: [], ...patch };
}
function draw(onOpenProcesses?: () => void) {
    const onOpenHealth = vi.fn();
    const html = renderToStaticMarkup(createElement(DeviceMonitoringNavigation, { onOpenHealth, onOpenProcesses }));
    expect(onOpenHealth).not.toHaveBeenCalled();
    return html;
}
function page(patch: Partial<Device> = {}) {
    state.device = device(patch);
    return renderToStaticMarkup(createElement(DeviceDetail, { id, onClose: vi.fn(), onCase: vi.fn() }));
}
function buttons(node: ReactNode): ReactElement<{ onClick: () => void; type: string; children: ReactNode }>[] {
    return Children.toArray(node).flatMap(child => {
        if (!isValidElement<{ children?: ReactNode }>(child)) return [];
        return child.type === 'button' ? [child as ReactElement<{ onClick: () => void; type: string; children: ReactNode }>] : buttons(child.props.children);
    });
}

beforeEach(() => {
    state.locale = 'en'; state.device = device(); state.accessEnded = false;
    state.operator = { mode: 'lan', authenticated: true, expiresAt: '2026-10-07T21:00:00Z' };
    vi.stubGlobal('fetch', vi.fn(() => { throw new Error('Navigation must not send requests.'); }));
});
afterEach(() => { expect(fetch).not.toHaveBeenCalled(); vi.unstubAllGlobals(); });

describe('data-free device monitoring navigation', () => {
    it('offers the two existing Linux destinations without status guesses', () => {
        const html = draw(vi.fn());
        expect(html).toContain('aria-label="Monitoring"');
        expect(html).toContain('aria-label="Open Health"');
        expect(html).toContain('aria-label="Open Processes"');
        expect(html).toContain('Complete process snapshots and optional exact-name watches.');
        expect(html).toContain('Opening a view does not enable monitoring.');
        expect(html.match(/<button /g)).toHaveLength(2);
        expect(html).not.toMatch(/aria-busy|aria-live|data-status|healthy|0 open|0 unknown|enabled<|disabled</i);
    });
    it('does not offer Linux process watches without that destination', () => {
        const html = draw();
        expect(html.match(/<button /g)).toHaveLength(1);
        expect(html).toContain('Health &amp; history');
        expect(html).not.toContain('Processes');
    });
    it('renders German actions and the same status limitation', () => {
        state.locale = 'de'; const html = draw(vi.fn());
        expect(html).toContain('aria-label="Überwachung"');
        expect(html).toContain('aria-label="Health öffnen"');
        expect(html).toContain('aria-label="Prozesse öffnen"');
        expect(html).toContain('Das Öffnen aktiviert keine Überwachung.');
    });
    it('only delegates the explicitly selected navigation callback', () => {
        const health = vi.fn(), processes = vi.fn();
        const actions = buttons(DeviceMonitoringNavigation({ onOpenHealth: health, onOpenProcesses: processes }));
        expect(actions).toHaveLength(2);
        for (const action of actions) expect(action.props.type).toBe('button');
        expect(actions[0].props.onClick).toBe(health); expect(actions[1].props.onClick).toBe(processes);
        actions[0].props.onClick(); expect(health).toHaveBeenCalledTimes(1); expect(processes).not.toHaveBeenCalled();
        actions[1].props.onClick(); expect(health).toHaveBeenCalledTimes(1); expect(processes).toHaveBeenCalledTimes(1);
    });
    it('does not call navigation callbacks while rendering or rerendering', () => {
        const processes = vi.fn();
        for (let index = 0; index < 3; index++) draw(processes);
        expect(processes).not.toHaveBeenCalled();
    });
});

describe('device overview integration, server render only', () => {
    it('offers Health and Processes only for the existing authenticated Linux surface', () => {
        const html = page(); expect(html).toContain('aria-label="Monitoring"'); expect(html).toContain('aria-label="Open Processes"');
    });
    it('offers Health without Linux process navigation on Windows', () => {
        const html = page({ platform: 'windows' });
        expect(html).toContain('aria-label="Monitoring"'); expect(html).toContain('aria-label="Open Health"'); expect(html).not.toContain('aria-label="Open Processes"');
    });
    it.each(['macos', 'unknown'] as const)('does not invent monitoring support for %s', platform => {
        expect(page({ platform })).not.toContain('device-monitoring-navigation');
    });
    it.each([{ synthetic: true }, { source: 'local' }, { source: 'sandbox' }, { id: 'agent_other_fixture' }] as Partial<Device>[])('does not offer monitoring outside this LAN device context: %j', patch => {
        expect(page(patch)).not.toContain('device-monitoring-navigation');
    });
    it('removes shortcuts when authentication or metadata access ends', () => {
        state.operator.authenticated = false; expect(page()).not.toContain('device-monitoring-navigation');
        state.operator.authenticated = true; state.accessEnded = true; expect(page()).not.toContain('device-monitoring-navigation');
    });
    it('does not show shortcuts in the unauthenticated local manager mode', () => {
        state.operator.mode = 'local'; expect(page()).not.toContain('device-monitoring-navigation');
    });
});
