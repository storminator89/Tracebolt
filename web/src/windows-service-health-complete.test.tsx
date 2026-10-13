import { useState } from 'react';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests } from './api';
import { setLocale } from './i18n';
import { windowsCapacityDevice } from './windows-capacity-fixture';
import { fullServiceRows, fullServicesComplete, fullServicesDevice, fullServicesNow, fullServicesPage } from './windows-full-services-fixtures';
import { fullServicesManifestHash } from './windows-full-services-types';
import type { FullServicesQuery } from './windows-full-services-types';
import { completeHealthSession, completeHealthView } from './windows-service-health-complete-fixture';
import { WindowsServiceHealthCompletePanel } from './windows-service-health-complete';
import { WindowsServiceHealthCompletePicker } from './windows-service-health-complete-picker';
import type { CompleteServiceSelectionEvidence } from './windows-service-health-complete-picker';
import { useWindowsServiceHealthComplete } from './windows-service-health-complete-resource';
import { windowsServiceHealthCompleteCopy } from './windows-service-health-complete-copy';
import wire from './windows-complete-service-health-go-fixture.json';
const reply = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status });
const flush = () => act(async () => { for (let i = 0; i < 16; i++) await Promise.resolve(); });
function server() {
    const state = { view: completeHealthView(), rows: fullServiceRows(), complete: fullServicesComplete(), queries: [] as FullServicesQuery[], writes: [] as any[], uncertain: false, restart: false, latestPending: false, csrf: null as (() => Promise<Response>) | null };
    const fetch = vi.fn(async (path: string, init?: RequestInit) => {
        if (path === '/api/session') return state.csrf ? state.csrf() : reply({ csrfToken: 'synthetic-only' });
        if (path.endsWith('/windows-full-services/query')) {
            const query = JSON.parse(String(init?.body)) as FullServicesQuery; state.queries.push(query);
            if (state.restart && query.cursor) return reply({ error: { code: 'windows_full_services_restart_required' } }, 409);
            const page = fullServicesPage(query, state.rows, state.complete, query.cursor ? Number(query.cursor.split('.')[0].split('_')[1]) : 0);
            if (state.latestPending) page.latestAttempt = { sequence: page.complete!.manifest.sequence + 1, attemptedAt: page.serverNow, status: 'pending', reason: '' };
            return reply(page);
        }
        if (path.endsWith('/windows-services/complete/policy')) {
            const body = JSON.parse(String(init?.body)); state.writes.push(body);
            state.view = completeHealthView({ enabled: body.enabled, services: body.services, revision: body.expectedRevision + 1, ...(body.source ? { source: { kind: body.source.kind, grantId: body.source.grantId, grantRevision: body.source.grantRevision } } : state.view.policy.source ? { source: state.view.policy.source } : {}) });
            if (state.uncertain) throw new Error('PRIVATE-WRITE-ERROR');
            return reply(state.view);
        }
        if (path.endsWith('/windows-services/complete')) return reply(state.view);
        return reply({}, 404);
    });
    vi.stubGlobal('fetch', fetch); return { state, fetch };
}
function Harness({ session = completeHealthSession }: { session?: string }) {
    const device = windowsCapacityDevice(); device.id = fullServicesDevice; device.agentCertificate!.checkedAt = fullServicesNow; device.agentCertificate!.expiresAt = completeHealthView().certificateExpiresAt;
    const resource = useWindowsServiceHealthComplete(device.id, true, session, true, device.agentCertificate);
    return <WindowsServiceHealthCompletePanel device={device} resource={resource} sessionKey={session} metadataReady admin/>;
}
const settings = () => fireEvent.click(screen.getByText('Selected-service policy settings & limits'));
const review = async () => { fireEvent.click(screen.getByRole('button', { name: 'Review complete generation' })); await flush(); };
const next = async () => { fireEvent.click(screen.getByRole('button', { name: 'Next service page' })); await flush(); };
const pick = (name: string) => { const label = [...document.querySelectorAll('.windows-service-options label')].find(row => row.querySelector('code')?.textContent === name); expect(label).toBeDefined(); fireEvent.click(label!.querySelector('input')!); };
const save = () => fireEvent.click(screen.getByRole('button', { name: 'Save selected-service policy' }));
beforeEach(() => { abortProtectedRequests(); vi.useFakeTimers(); vi.setSystemTime(fullServicesNow); setLocale('en', false); });
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });
describe('complete-generation policy workflow', () => {
    it.each(['en', 'de'] as const)('renders exact Go source health in %s without querying the chooser', async locale => {
        const value = structuredClone(wire.attention), device = windowsCapacityDevice(); device.id = value.deviceId; device.agentCertificate!.checkedAt = value.serverNow; device.agentCertificate!.expiresAt = value.certificateExpiresAt;
        vi.setSystemTime(value.serverNow); setLocale(locale, false); const fetch = vi.fn(async () => reply(value)); vi.stubGlobal('fetch', fetch);
        function GoPanel() { const resource = useWindowsServiceHealthComplete(device.id, true, value.certificateExpiresAt, true, device.agentCertificate); return <WindowsServiceHealthCompletePanel device={device} resource={resource} sessionKey={value.certificateExpiresAt} metadataReady admin/>; }
        render(<GoPanel/>); await flush(); expect(screen.getByText(windowsServiceHealthCompleteCopy[locale].attention, { selector: '.windows-capacity-assessment strong' })).toBeVisible(); expect(screen.getByText(value.incidents[0].id)).toBeVisible(); expect(fetch).toHaveBeenCalledOnce();
    });
    it('requires deliberate complete review and can select beyond the 128-row preview', async () => {
        const s = server(); render(<Harness/>); await flush(); settings(); expect(s.state.queries).toHaveLength(0); await review(); expect(document.querySelectorAll('.windows-service-options li')).toHaveLength(100);
        await next(); pick('FixtureService0150'); fireEvent.click(screen.getByRole('checkbox', { name: 'Enable selected-service policy' })); expect(screen.getByRole('button', { name: 'Save selected-service policy' })).toBeEnabled(); save(); await flush();
        expect(s.state.writes).toHaveLength(1); expect(s.state.writes[0]).toEqual({ enabled: true, services: ['FixtureService0150'], expectedRevision: 0, source: completeHealthView().inventory!.source }); expect(screen.getByText('Current saved policy confirmed.')).toBeVisible();
    });
    it('preserves exact dirty names across passive same-revision policy refresh', async () => {
        server(); render(<Harness/>); await flush(); settings(); await review(); await next(); pick('FixtureService0150'); fireEvent.click(screen.getByRole('checkbox', { name: 'Enable selected-service policy' })); fireEvent.click(screen.getByRole('button', { name: 'Refresh selected-service policy' })); await flush(); expect(screen.getByRole('button', { name: 'Remove service: FixtureService0150' })).toBeVisible(); expect(screen.getByRole('button', { name: 'Save selected-service policy' })).toBeEnabled();
    });
    it('permits disabling and removing retained names without any fresh source', async () => {
        const s = server(); s.state.view = completeHealthView({ enabled: true, services: ['FixtureService0150'], revision: 1, source: { kind: 'windows_full_services', grantId: s.state.complete.manifest.grantId, grantRevision: 1 } }); s.state.view.inventory = null;
        render(<Harness/>); await flush(); settings(); fireEvent.click(screen.getByRole('checkbox', { name: 'Enable selected-service policy' })); fireEvent.click(screen.getByRole('button', { name: 'Remove service: FixtureService0150' })); save(); await flush(); expect(s.state.writes[0]).toEqual({ enabled: false, services: [], expectedRevision: 1, source: null }); expect(s.state.queries).toHaveLength(0);
    });
    it('requires explicit renewal before rebinding retained names to a changed local grant', async () => {
        const s = server(); s.state.view = completeHealthView({ enabled: true, services: ['FixtureService0150'], revision: 1, source: { kind: 'windows_full_services', grantId: 'a'.repeat(32), grantRevision: 1 } });
        render(<Harness/>); await flush(); settings(); await review(); await next();
        expect(screen.getByRole('button', { name: 'Save selected-service policy' })).toBeDisabled();
        fireEvent.click(screen.getByRole('checkbox', { name: 'Review these exact selections for this local grant' }));
        expect(screen.getByRole('button', { name: 'Save selected-service policy' })).toBeEnabled(); save(); await flush(); expect(s.state.writes).toHaveLength(1); expect(s.state.writes[0].source).toEqual(completeHealthView().inventory!.source); expect(s.state.writes[0].services).toEqual(['FixtureService0150']);
    });
    it('clears explicit renewal when the reviewed generation is restarted', async () => {
        const s = server(); s.state.view = completeHealthView({ enabled: true, services: ['FixtureService0150'], revision: 1, source: { kind: 'windows_full_services', grantId: 'a'.repeat(32), grantRevision: 1 } });
        render(<Harness/>); await flush(); settings(); await review(); await next(); fireEvent.click(screen.getByRole('checkbox', { name: 'Review these exact selections for this local grant' }));
        fireEvent.click(screen.getByRole('button', { name: 'Review latest generation' })); await flush(); expect(screen.getByRole('checkbox', { name: 'Review these exact selections for this local grant' })).not.toBeChecked(); expect(screen.getByRole('button', { name: 'Save selected-service policy' })).toBeDisabled(); expect(s.state.writes).toHaveLength(0);
    });
    it('never upgrades an uncertain write to confirmed success from matching GET alone', async () => {
        const s = server(); s.state.uncertain = true; render(<Harness/>); await flush(); settings(); await review(); pick('FixtureService0001'); fireEvent.click(screen.getByRole('checkbox', { name: 'Enable selected-service policy' })); save(); await flush();
        expect(s.state.writes).toHaveLength(1); expect(screen.getByText(/write was not confirmed/)).toBeVisible(); expect(screen.queryByText('Current saved policy confirmed.')).toBeNull(); fireEvent.click(screen.getByRole('button', { name: 'Refresh selected-service policy' })); await flush(); expect(s.state.writes).toHaveLength(1); expect(document.body).not.toHaveTextContent('PRIVATE-WRITE-ERROR');
    });
    it('rejects an expired source after delayed CSRF without sending policy POST', async () => {
        const s = server(); render(<Harness/>); await flush(); settings(); await review(); pick('FixtureService0001'); fireEvent.click(screen.getByRole('checkbox', { name: 'Enable selected-service policy' }));
        s.state.csrf = async () => { const mono = performance.now(); vi.spyOn(performance, 'now').mockReturnValue(mono + 301000); vi.setSystemTime(Date.parse(fullServicesNow) + 301000); return reply({ csrfToken: 'synthetic-only' }); }; save(); await flush(); expect(s.state.writes).toHaveLength(0);
    });
    it.each(['blur', 'hashchange', 'pagehide'])('clears private drafts and rows on %s', async event => {
        server(); render(<Harness/>); await flush(); settings(); await review(); pick('FixtureService0001'); act(() => window.dispatchEvent(new Event(event))); await flush(); expect(screen.queryByRole('button', { name: 'Remove service: FixtureService0001' })).toBeNull(); expect(document.querySelectorAll('.windows-service-options li')).toHaveLength(0);
    });
    it('displays v1 incompatibility without falling back or posting', async () => { const s = server(); (s.state.view as unknown as { schemaVersion: string }).schemaVersion = 'tracebolt.windows-service-view.v1'; render(<Harness/>); await flush(); expect(screen.getByText(/previously used bounded-preview policy is not converted automatically/)).toBeVisible(); expect(s.state.writes).toEqual([]); expect(s.state.queries).toEqual([]); });
});

describe('bounded reusable complete picker', () => {
    function Picker({ onEvidence = () => {} }: { onEvidence?: (evidence: CompleteServiceSelectionEvidence | null) => void }) { const [selected, setSelected] = useState<string[]>([]); return <WindowsServiceHealthCompletePicker deviceId={fullServicesDevice} sessionKey={completeHealthSession} enabled disabled={false} selected={selected} onChange={setSelected} onEvidence={onEvidence} c={windowsServiceHealthCompleteCopy.en}/>; }
    it('keeps at most eight selected names across same-generation pages and searches the full source', async () => {
        const s = server(), evidence = vi.fn(); render(<Picker onEvidence={evidence}/>); await flush(); pick('FixtureService0001'); await next(); pick('FixtureService0150'); expect(evidence.mock.lastCall![0].names).toEqual(['FixtureService0001', 'FixtureService0150']);
        fireEvent.change(screen.getByRole('searchbox'), { target: { value: 'FixtureService0616' } }); expect(document.querySelectorAll('.windows-service-options li')).toHaveLength(0); fireEvent.click(screen.getByRole('button', { name: 'Search generation' })); await flush(); pick('FixtureService0616'); expect(evidence.mock.lastCall![0].names).toEqual(['FixtureService0001', 'FixtureService0150', 'FixtureService0616']); expect(s.state.queries.at(-1)?.search).toBe('FixtureService0616'); expect(s.state.queries.every(q => q.limit === 100)).toBe(true);
    });
    it('withholds retained complete pages while a newer generation is incomplete', async () => {
        const s = server(); s.state.latestPending = true; const evidence = vi.fn(); render(<Picker onEvidence={evidence}/>); await flush(); expect(evidence.mock.lastCall![0]).toBeNull(); expect(document.querySelectorAll('.windows-service-options li')).toHaveLength(0); expect(screen.getByText('No fresh complete generation is available for selection.')).toBeVisible();
    });
    it('caps all pages together at eight selected identities', async () => {
        server(); const evidence = vi.fn(); render(<Picker onEvidence={evidence}/>); await flush();
        for (let i = 0; i < 8; i++) pick(`FixtureService${String(i).padStart(4, '0')}`);
        await next(); const ninth = [...document.querySelectorAll('.windows-service-options label')].find(row => row.querySelector('code')?.textContent === 'FixtureService0150')!.querySelector('input')!; expect(ninth).toBeDisabled(); fireEvent.click(ninth); expect(evidence.mock.lastCall![0].names).toHaveLength(8);
    });
    it('withholds selection once the original capture reaches five minutes even though retention lasts 24h', async () => {
        const s = server(); const captured = new Date(Date.parse(fullServicesNow) - 299500).toISOString();
        s.state.complete.manifest.captureStartedAt = captured; s.state.complete.manifest.captureFinishedAt = captured; s.state.complete.manifest.expiresAt = new Date(Date.parse(captured) + 86400000).toISOString(); s.state.complete.receivedAt = captured;
        s.state.complete.manifestSha256 = fullServicesManifestHash(s.state.complete.manifest);
        const evidence = vi.fn(); render(<Picker onEvidence={evidence}/>); await flush(); pick('FixtureService0001'); await act(async () => vi.advanceTimersByTimeAsync(1000)); expect(evidence.mock.lastCall![0]).toBeNull(); expect(screen.getByText(/too old for a new policy selection/)).toBeVisible(); expect(document.querySelectorAll('.windows-service-options li')).toHaveLength(0);
    });
    it('clears reviewed evidence on a generation restart instead of joining rows', async () => {
        const s = server(), evidence = vi.fn(); render(<Picker onEvidence={evidence}/>); await flush(); pick('FixtureService0001'); s.state.restart = true; await next(); expect(evidence.mock.lastCall![0]).toBeNull(); expect(screen.getByText(/Generation or access changed/)).toBeVisible(); expect(document.querySelectorAll('.windows-service-options li')).toHaveLength(0); expect(screen.getByRole('button', { name: 'Remove service: FixtureService0001' })).toBeVisible();
    });
});
