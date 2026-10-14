import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import App from './App';
import { abortProtectedRequests } from './api';
import { setLocale } from './i18n';
import { journalNow as now, journalSession } from './journal-fixtures';
import { applicationViewV2 } from './application-checks-v2-fixtures';
import type { InvestigationScope, InvestigationsView } from './investigations-types';
import type { Case, Device, Overview } from './types';
import { OverviewContext } from './overview-workspace';

const json = (data: unknown, status = 200) => new Response(JSON.stringify(data), { status });
const metric = { value: null, unit: '%', quality: 'unknown' as const, source: 'fixture', collectedAt: now };
const device: Device = { id: `agent_${'a'.repeat(32)}`, name: 'Synthetic overview device', platform: 'linux', os: 'Linux fixture', site: '', group: '', ip: null, status: 'unknown', source: 'lan', synthetic: false, lastSeen: '2026-10-04T11:55:00Z', agentVersion: '', cpu: metric, memory: metric, disk: metric, uptime: '', tags: [], capabilities: [], evidence: [], trend: [], caseIds: [] };
const example: Case = { id: 'case-demo-overview', title: 'Synthetic work item', deviceId: device.id, deviceName: device.name, severity: 'warning', status: 'open', category: 'service', summary: 'Synthetic rule output', ruleId: 'fixture', confidence: 'limited', createdAt: now, updatedAt: now, evidenceIds: [], evidence: [], runbookId: 'fixture', nextSteps: [], timeline: [], notes: [], synthetic: true };
const overview = (devices = [device], cases: Case[] = []): Overview => ({ product: 'Tracebolt', mode: 'lan', generatedAt: now, stats: { totalDevices: devices.length, healthyDevices: 0, attentionDevices: 0, unknownDevices: devices.length, openCases: cases.length, criticalCases: 0 }, devices, cases, activity: [] });
function health(open: boolean): InvestigationsView {
    return { schemaVersion: 'tracebolt.investigations.v1', serverNow: now, scope: 'open', offset: 0, total: open ? 1 : 0, counts: { open: open ? 1 : 0, recovered: 0, closed: 0, all: open ? 1 : 0 }, devices: [{ schemaVersion: 'tracebolt.health-view.v1', deviceId: device.id, serverNow: now, evaluatedAt: now, status: 'attention', maintenanceUntil: null, monitoredServices: ['fixture.service'], checks: [{ key: 'offline:contact', kind: 'offline', target: 'agent', state: 'ok', observedAt: now, value: null }, { key: 'filesystem:root', kind: 'filesystem', target: '/', state: 'unknown', observedAt: null, value: null }, { key: 'service:fixture.service', kind: 'service', target: 'fixture.service', state: open ? 'open' : 'unknown', observedAt: open ? now : null, value: null }], incidents: [] }], items: open ? [{ deviceId: device.id, incident: { id: 'health_0000000000000001', key: 'service:fixture.service', kind: 'service', target: 'fixture.service', openedAt: now, lastObservedAt: now, resolvedAt: null, acknowledgedAt: null } }] : [] };
}
function server({ lan = true, empty = false, open = false, failedWork = false }: { lan?: boolean; empty?: boolean; open?: boolean; failedWork?: boolean } = {}) {
    let readOverview = async () => json(overview(empty ? [] : [lan ? device : { ...device, source: 'synthetic', synthetic: true }], !lan && open ? [example] : []));
    const fetch = vi.fn(async (path: string, init?: RequestInit) => {
        if (init?.method && init.method !== 'GET') throw new Error('Overview navigation must be read-only');
        if (path === '/api/auth/session') return json(lan ? { ...journalSession, loginMode: 'shared', actorId: null, capabilities: ['read'] } : { ...journalSession, mode: 'development', authenticationRequired: false, authenticated: false, expiresAt: null, expiresInSeconds: null });
        if (path === '/api/overview') return readOverview();
        if (path.startsWith('/api/investigations?')) {
            if (failedWork) return json({}, 503);
            const value = health(open), scope = new URL(path, 'https://localhost').searchParams.get('scope') as InvestigationScope;
            return json({ ...value, scope });
        }
        if (path === '/api/application-checks/status') return json(applicationViewV2());
        return json({}, 503);
    });
    vi.stubGlobal('fetch', fetch);
    return { fetch, setOverview: (next: typeof readOverview) => { readOverview = next; } };
}
const order = (...selectors: string[]) => {
    const nodes = selectors.map(selector => { const node = document.querySelector(selector); expect(node, selector).not.toBeNull(); return node!; });
    for (let index = 1; index < nodes.length; index++) expect(nodes[index - 1].compareDocumentPosition(nodes[index]) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
};
const readOnly = (fetch: ReturnType<typeof server>['fetch']) => expect(fetch.mock.calls.every(([, init]) => !init?.method || init.method === 'GET')).toBe(true);
beforeEach(() => { localStorage.clear(); sessionStorage.clear(); setLocale('en', false); window.history.replaceState({}, '', '/#/overview'); vi.spyOn(document, 'hasFocus').mockReturnValue(true); });
afterEach(() => { cleanup(); abortProtectedRequests(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

it.each(['en', 'de'] as const)('puts source context and actual open work before compact fleet numbers (%s)', async locale => {
    setLocale(locale, false); const { fetch } = server({ open: true }); render(<App/>);
    await screen.findByText(locale === 'de' ? 'fixture.service: Dienst inaktiv' : 'fixture.service: service inactive');
    order('.overview-context', '.attention-panel', '.summary-strip', '.fleet-panel .device-table', '.application-checks', '.activity-panel');
    const context = screen.getByRole('region', { name: locale === 'de' ? 'Datenkontext' : 'Data context' });
    expect(context.querySelector('time')).toHaveAttribute('datetime', now);
    expect(context).toHaveTextContent(locale === 'de' ? 'Beobachtungszeiten gelten je Quelle' : 'Observation times belong to each source');
    expect(screen.getByText(locale === 'de' ? 'Linux-Health-Vorfälle' : 'Linux Health incidents')).toBeVisible();
    expect(screen.getByRole('button', { name: locale === 'de' ? 'Windows-Vorfälle unter Geräte' : 'Windows incidents in Devices' })).toBeVisible();
    const report = document.querySelector('.overview-device-report')!;
    expect(report.querySelector('time')).toHaveAttribute('datetime', device.lastSeen);
    expect(report).toHaveTextContent(locale === 'de' ? 'LAN-Agent' : 'LAN agent');
    expect(fetch.mock.calls.filter(([path]) => path === '/api/overview')).toHaveLength(1);
    expect(fetch.mock.calls.some(([path]) => path.includes('windows/incidents'))).toBe(false); readOnly(fetch);
});
it.each(['en', 'de'] as const)('keeps a populated fleet with no open incidents distinct from first setup (%s)', async locale => {
    setLocale(locale, false); const { fetch } = server(); render(<App/>);
    await screen.findByRole('heading', { name: locale === 'de' ? 'Keine offenen Untersuchungen' : 'No open investigations' });
    expect(document.querySelector('.attention-panel')).toHaveTextContent(locale === 'de' ? 'Der Gerätezustand kann trotzdem unbekannt sein.' : 'Device health may still be unknown.');
    expect(document.querySelectorAll('.fleet-panel tbody tr')).toHaveLength(1);
    expect(document.querySelector('.first-device-panel')).toBeNull(); readOnly(fetch);
});
it('keeps pending work source distinct from a zero count or an all-clear', async () => {
    const s = server(), original = s.fetch.getMockImplementation()!;
    let release!: (value: Response) => void;
    s.fetch.mockImplementation((path: string, init?: RequestInit) => path.startsWith('/api/investigations?') ? new Promise(resolve => { release = resolve; }) : original(path, init));
    render(<App/>); await screen.findByText('Reading investigations…');
    const attention = screen.getByRole('region', { name: 'Open cases' });
    expect(within(attention).queryByRole('heading', { name: 'No open investigations' })).not.toBeInTheDocument();
    expect(within(document.querySelector('.summary-strip')!).getByRole('button', { name: /Open investigations/ })).toHaveTextContent('—');
    await act(async () => { release(json(health(false))); });
    await within(attention).findByRole('heading', { name: 'No open investigations' }); readOnly(s.fetch);
});
it('keeps unknown work counts and failures separate from an empty work list', async () => {
    const { fetch } = server({ failedWork: true }); render(<App/>);
    const attention = await screen.findByRole('region', { name: 'Open cases' });
    await within(attention).findByRole('alert');
    expect(attention).toHaveTextContent('Investigations unavailable. Reliable case counts are unavailable.');
    expect(within(attention).queryByRole('heading', { name: 'No open investigations' })).not.toBeInTheDocument();
    expect(within(document.querySelector('.summary-strip')!).getByRole('button', { name: /Open investigations/ })).toHaveTextContent('—');
    expect(document.querySelector('.first-device-panel')).toBeNull(); readOnly(fetch);
});
it('keeps independently active checks visible on a true first start without an empty device table', async () => {
    const { fetch } = server({ empty: true }); render(<App/>);
    await screen.findByRole('heading', { name: 'No devices yet' });
    await screen.findByText('fixture-dns', {}, { timeout: 4000 });
    order('.overview-context', '.first-device-panel', '.attention-panel', '.application-checks', '.activity-panel');
    expect(document.querySelector('.summary-strip,.fleet-panel,.overview-table')).toBeNull();
    expect(screen.getByRole('button', { name: 'Review device setup' })).toBeEnabled();
    expect(fetch.mock.calls.some(([path]) => path === '/api/enrollment')).toBe(false); readOnly(fetch);
});
it('retains original report times during refresh and failure instead of relabelling them as fresh', async () => {
    const s = server(); render(<App/>); await screen.findByRole('region', { name: 'Data context' });
    let release!: (value: Response) => void; s.setOverview(() => new Promise(resolve => { release = resolve; }));
    fireEvent.click(screen.getByRole('button', { name: 'Refresh' }));
    expect(await screen.findByText('Refreshing overview… Previous snapshot shown.')).toBeVisible();
    expect(document.querySelector('.overview-device-report time')).toHaveAttribute('datetime', device.lastSeen);
    await act(async () => { release(json({}, 503)); });
    expect(await screen.findByText('Refresh unavailable. Previous snapshot shown.')).toBeVisible();
    expect(screen.getByRole('region', { name: 'Data context' }).querySelector('time')).toHaveAttribute('datetime', now);
    expect(document.querySelector('.overview-device-report time')).toHaveAttribute('datetime', device.lastSeen); readOnly(s.fetch);
});
it('preserves zero-report and unavailable report distinctions in narrow-screen metadata', async () => {
    const s = server(); s.setOverview(async () => json(overview([{ ...device, lastSeen: '0001-01-01T00:00:00Z' }]))); render(<App/>);
    await screen.findByRole('region', { name: 'Data context' });
    expect(document.querySelector('.overview-device-report')).toHaveTextContent('No report recorded yet');
    s.setOverview(async () => json({}, 503)); fireEvent.click(screen.getByRole('button', { name: 'Refresh' }));
    await screen.findByText('Refresh unavailable. Previous snapshot shown.');
    expect(document.querySelector('.overview-device-report')).toHaveTextContent('Report status unavailable');
    expect(document.querySelector('.overview-device-report time')).toBeNull(); readOnly(s.fetch);
});
it('preserves existing KPI filters and keyboard navigation without writes', async () => {
    const { fetch } = server({ lan: false, open: true }), user = userEvent.setup(); render(<App/>);
    await screen.findByText(example.title); const attention = screen.getByRole('button', { name: /Needs attention 0/ });
    attention.focus(); await user.keyboard('{Enter}'); await screen.findByRole('textbox', { name: 'Search devices' });
    expect(screen.getByRole('combobox', { name: 'Filter by status' })).toHaveValue('needs-attention');
    expect(window.location.hash).toBe('#/devices'); readOnly(fetch);
});
it('opens the existing investigation route with retained open scope from the first work section', async () => {
    const { fetch } = server({ open: true }), user = userEvent.setup(); render(<App/>);
    await screen.findByText('fixture.service: service inactive');
    const all = within(screen.getByRole('region', { name: 'Open cases' })).getByRole('button', { name: 'View all' });
    all.focus(); await user.keyboard('{Enter}'); await screen.findByRole('heading', { name: 'Investigations', level: 1 });
    expect(window.location.hash).toBe('#/cases');
    expect(fetch.mock.calls.filter(([path]) => path.startsWith('/api/investigations?'))).toHaveLength(1); readOnly(fetch);
});
it.each(['', 'not a date', '0001-01-01T00:00:00Z', '2026-02-30T12:00:00Z'])('does not present invalid overview time as observed evidence (%s)', generatedAt => {
    render(<OverviewContext generatedAt={generatedAt} lan loading={false} failed={false}/>);
    expect(screen.getByText(/Time unavailable/)).toBeVisible(); expect(document.querySelector('time')).toBeNull();
});
