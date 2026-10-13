import { StrictMode } from 'react';
import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, AUTH_REQUIRED_EVENT, request } from './api';
import { FleetGroupsControls, useFleetGroups } from './fleet-groups';
import { setLocale } from './i18n';
import { completeGroupServiceChoiceFixture, completeGroupServiceFixture } from './fleet-group-service-checks-complete-fixture';
import type { GroupCompleteServiceChecksView, GroupCompleteServiceChoiceView } from './fleet-group-service-checks-complete-workflow';
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn() }));
// Paging and its actual Go page DTOs are covered by the complete picker tests.
// Here the picker emits one deliberate exact-row selection through its public seam.
vi.mock('./windows-service-health-complete-picker', () => ({ WindowsServiceHealthCompletePicker: (props: import('react').ComponentProps<typeof import('./windows-service-health-complete-picker').WindowsServiceHealthCompletePicker>) => <div><button onClick={() => { const configured = completeGroupServiceChoiceFixture(true), source = choice.member.inventory?.source; props.onChange(configured.member.policy.services); props.onEvidence(source ? { source, names: configured.member.policy.services } : null); }}>Choose exported complete row</button>{props.selected.map(name => <button key={name} onClick={() => { props.onChange(props.selected.filter(n => n !== name)); props.onEvidence(null); }}>{`Remove service: ${name}`}</button>)}</div> }));
let view: GroupCompleteServiceChecksView, choice: GroupCompleteServiceChoiceView, configured: GroupCompleteServiceChoiceView;
let session: Record<string, unknown>;
const flush = () => act(async () => {});
const posts = () => vi.mocked(request).mock.calls.filter(([, options]) => options?.method === 'POST');
function Harness({ admin = true }: { admin?: boolean } = {}) { const resource = useFleetGroups(true, session.expiresAt as string, admin); return <FleetGroupsControls key={resource.generation} resource={resource}/>; }
const labels = (de = false) => de ? { groups: 'Flottengruppen', open: 'Vollständige Dienstprüfungen anwenden', load: 'Dienstoptionen der Auswahl laden', review: 'Exakte Dienstprüfungen prüfen', enable: 'Dienstprüfungen aktivieren', apply: 'Geprüfte Dienstprüfungen anwenden', consent: 'Diese exakten Dienstprüfungsrichtlinien einmal auf diese gewählten Mitglieder anwenden.' } : { groups: 'Fleet groups', open: 'Apply complete service checks', load: 'Load selected service choices', review: 'Review exact service checks', enable: 'Enable service checks', apply: 'Apply reviewed service checks', consent: 'Apply these exact service-check policies to these selected members once.' };
async function open(de = false) { const c = labels(de); fireEvent.click(screen.getByRole('button', { name: c.groups })); await flush(); fireEvent.change(screen.getByRole('combobox', { name: c.groups }), { target: { value: view.groupId } }); fireEvent.click(screen.getByRole('button', { name: c.open })); await flush(); }
async function choose(de = false) { const c = labels(de); await open(de); fireEvent.click(screen.getByRole('checkbox', { name: `${choice.member.name} ${choice.member.deviceId}` })); fireEvent.click(screen.getByRole('button', { name: c.load })); await flush(); }
async function review(de = false) { const c = labels(de); await choose(de); fireEvent.click(screen.getByRole('button', { name: 'Choose exported complete row' })); fireEvent.click(screen.getByRole('checkbox', { name: `${c.enable} · ${choice.member.name}` })); fireEvent.click(screen.getByRole('button', { name: c.review })); await flush(); }
async function apply(de = false) { const c = labels(de); fireEvent.click(screen.getByRole('checkbox', { name: c.consent })); fireEvent.click(screen.getByRole('button', { name: c.apply })); await flush(); }
beforeEach(() => {
    abortProtectedRequests(); vi.useFakeTimers(); setLocale('en', false); vi.mocked(request).mockReset(); view = completeGroupServiceFixture(); choice = completeGroupServiceChoiceFixture(); configured = completeGroupServiceChoiceFixture(true); vi.setSystemTime(view.serverNow);
    const expiresAt = new Date(Date.parse(view.serverNow) + 3600000).toISOString();
    session = { mode: 'lan', transport: 'https', insecureTestMode: false, transportWarning: null, authenticationRequired: true, authenticated: true, csrfToken: 'fixture-csrf', serverNow: view.serverNow, expiresAt, expiresInSeconds: 3600, loginMode: 'shared', actorId: null, capabilities: ['read'] };
    vi.mocked(request).mockImplementation(async (path, options) => {
        if (path === '/auth/session') return structuredClone(session);
        if (path === '/fleet/groups') return { schemaVersion: 'tracebolt.fleet-groups.v1', serverNow: view.serverNow, groups: [{ id: view.groupId, name: view.groupName, revision: view.groupRevision, memberIds: view.members.map(m => m.deviceId), unavailableMembers: view.unavailableMembers }], devices: view.members.map(m => ({ id: m.deviceId, name: m.name, platform: 'windows' })) };
        if (path === `/fleet/groups/${view.groupId}/service-checks-complete`) return structuredClone(view);
        if (path === `/fleet/groups/${view.groupId}/service-checks-complete/${choice.member.key}`) {
            if (options?.method === 'POST') { const body = JSON.parse(options.body as string); choice.member.policy = { enabled: body.enabled, services: body.services, revision: body.expectedRevision + 1, ...(body.source ? { source: { kind: body.source.kind, grantId: body.source.grantId, grantRevision: body.source.grantRevision } } : choice.member.policy.source ? { source: choice.member.policy.source } : {}) }; choice.member.inventory = body.source ? structuredClone(configured.member.inventory) : null; }
            return structuredClone(choice);
        }
        throw new Error(`Unexpected route: ${path}`);
    });
});
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.restoreAllMocks(); });
describe('complete-generation group selection and authority', () => {
    it.each([false, true])('keeps exact member, enable and final consent unchecked in DE=%s', async de => {
        setLocale(de ? 'de' : 'en', false); render(<Harness/>); await open(de); const c = labels(de);
        expect(screen.getAllByRole('checkbox').every(box => !(box as HTMLInputElement).checked)).toBe(true); expect(screen.getByRole('button', { name: c.load })).toBeDisabled();
        expect(screen.getByRole('dialog')).toHaveTextContent(de ? 'Vorschau-Richtlinien sind inkompatibel' : 'bounded-preview policies are incompatible');
        fireEvent.click(screen.getByRole('checkbox', { name: `${choice.member.name} ${choice.member.deviceId}` })); fireEvent.click(screen.getByRole('button', { name: c.load })); await flush();
        const enable = screen.getByRole('checkbox', { name: `${c.enable} · ${choice.member.name}` }); expect(enable).not.toBeChecked(); fireEvent.click(screen.getByRole('button', { name: 'Choose exported complete row' })); fireEvent.click(enable);
        fireEvent.click(screen.getByRole('button', { name: c.review })); await flush(); expect(posts()).toHaveLength(0); expect(screen.getByRole('checkbox', { name: c.consent })).not.toBeChecked(); expect(screen.getByRole('button', { name: c.apply })).toBeDisabled();
        expect(screen.getByRole('table')).toHaveTextContent(configured.member.policy.services[0]); expect(screen.getByRole('table')).toHaveTextContent(choice.member.inventory!.source.generationId);
        const source = structuredClone(choice.member.inventory!.source); await apply(de); expect(posts()).toHaveLength(1);
        expect(JSON.parse(posts()[0][1]!.body as string)).toEqual({ groupRevision: view.groupRevision, expectedRevision: 0, enabled: true, services: configured.member.policy.services, source, consent: true });
        expect((posts()[0][1]!.headers as Record<string, string>)['X-CSRF-Token']).toBe('fixture-csrf'); expect(screen.queryByRole('button', { name: c.apply })).toBeNull();
    });
    it('requires an initially unchecked explicit renewal to bind retained enabled names to a changed grant', async () => {
        view.members.find(m => m.key === choice.member.key)!.policy = structuredClone(configured.member.policy);
        choice.member.policy = structuredClone(configured.member.policy);
        choice.member.inventory!.source.grantRevision++;
        configured.member.inventory!.source.grantRevision++;
        render(<Harness/>); await choose(); fireEvent.click(screen.getByRole('button', { name: 'Choose exported complete row' }));
        const renewal = screen.getByRole('checkbox', { name: `Review these exact selections for this local grant · ${choice.member.name}` });
        expect(renewal).not.toBeChecked(); expect(renewal).toBeDisabled();
        fireEvent.click(screen.getByRole('checkbox', { name: `${labels().enable} · ${choice.member.name}` }));
        expect(renewal).not.toBeChecked(); expect(renewal).toBeEnabled(); fireEvent.click(renewal);
        fireEvent.click(screen.getByRole('button', { name: labels().review })); await flush(); await apply();
        const body = JSON.parse(posts()[0][1]!.body as string); expect(body.source.grantRevision).toBe(2); expect(body.expectedRevision).toBe(1); expect(body.services).toEqual(configured.member.policy.services);
        expect(choice.member.policy.source?.grantRevision).toBe(2);
    });
    it('clears explicit renewal on disable and preserves source:null', async () => {
        view.members.find(m => m.key === choice.member.key)!.policy = structuredClone(configured.member.policy);
        choice.member.policy = structuredClone(configured.member.policy);
        choice.member.inventory!.source.grantRevision++;
        render(<Harness/>); await choose(); fireEvent.click(screen.getByRole('button', { name: 'Choose exported complete row' }));
        const enable = screen.getByRole('checkbox', { name: `${labels().enable} · ${choice.member.name}` });
        fireEvent.click(enable); const renewal = screen.getByRole('checkbox', { name: `Review these exact selections for this local grant · ${choice.member.name}` }); fireEvent.click(renewal); expect(renewal).toBeChecked();
        fireEvent.click(enable); expect(renewal).not.toBeChecked(); expect(renewal).toBeDisabled();
        fireEvent.click(screen.getByRole('button', { name: labels().review })); await flush(); await apply();
        const body = JSON.parse(posts()[0][1]!.body as string); expect(body.enabled).toBe(false); expect(body.source).toBeNull(); expect(choice.member.policy.source?.grantRevision).toBe(1);
    });
    it('keeps both workflows available but requires a selected group and administrator', async () => {
        render(<Harness admin={false}/>); fireEvent.click(screen.getByRole('button', { name: labels().groups })); await flush(); fireEvent.change(screen.getByRole('combobox'), { target: { value: view.groupId } }); expect(screen.queryByRole('button', { name: labels().open })).toBeNull(); expect(posts()).toHaveLength(0);
    });
    it('survives StrictMode and does not read unselected member choices', async () => { render(<StrictMode><Harness/></StrictMode>); await choose(); expect(screen.getByRole('button', { name: 'Choose exported complete row' })).toBeVisible(); expect(vi.mocked(request).mock.calls.filter(([path]) => path.includes('/service-checks-complete/'))).toHaveLength(1); expect(posts()).toHaveLength(0); });
    it('sends source:null for retained-name removal/disable without inventory', async () => {
        view.members.find(m => m.key === choice.member.key)!.policy = structuredClone(configured.member.policy); choice.member.policy = structuredClone(configured.member.policy); choice.member.inventory = null;
        render(<Harness/>); await choose(); fireEvent.click(screen.getByRole('button', { name: `Remove service: ${configured.member.policy.services[0]}` })); fireEvent.click(screen.getByRole('button', { name: labels().review })); await flush(); await apply(); expect(JSON.parse(posts()[0][1]!.body as string).source).toBeNull(); expect(JSON.parse(posts()[0][1]!.body as string).enabled).toBe(false);
    });
    it.each(['blur', 'hashchange', 'pagehide', AUTH_REQUIRED_EVENT])('clears private review without any POST on %s', async event => { render(<Harness/>); await review(); act(() => window.dispatchEvent(new Event(event))); await flush(); expect(screen.queryByRole('dialog')).toBeNull(); expect(posts()).toHaveLength(0); });
    it('keeps the original list authority deadline when choice responses are later', async () => { view.authorityExpiresAt = new Date(Date.parse(view.serverNow) + 1000).toISOString(); render(<Harness/>); await choose(); await act(async () => vi.advanceTimersByTimeAsync(1100)); expect(screen.queryByRole('dialog')).toBeNull(); expect(posts()).toHaveLength(0); });
    it('rechecks the live shared administrator after waiting for CSRF', async () => {
        render(<Harness/>); await review(); const original = vi.mocked(request).getMockImplementation()!; let release!: (value: unknown) => void;
        vi.mocked(request).mockImplementation(async (path, options, cap) => path === '/auth/session' ? new Promise(resolve => { release = resolve; }) : original(path, options, cap));
        await apply(); act(() => { session = { ...session, loginMode: 'named', actorId: 'operator' }; }); await act(async () => release(structuredClone(session))); expect(posts()).toHaveLength(0); expect(screen.getByText('Unconfirmed · write may have happened')).toBeVisible();
    });
    it('rechecks original capture freshness after CSRF without refreshing it', async () => {
        const capturedAt = new Date(Date.parse(view.serverNow) - 299000).toISOString();
        const source = choice.member.inventory!.source;
        Object.assign(source, { capturedAt, captureFinishedAt: capturedAt, receivedAt: capturedAt, expiresAt: new Date(Date.parse(capturedAt) + 86400000).toISOString() });
        Object.assign(choice.member.inventory!, { collectedAt: capturedAt, receivedAt: capturedAt });
        configured.member.inventory = { ...structuredClone(choice.member.inventory!), services: configured.member.inventory!.services };
        render(<Harness/>); await review(); let release!: (value: unknown) => void; const original = vi.mocked(request).getMockImplementation()!;
        vi.mocked(request).mockImplementation(async (path, options, cap) => path === '/auth/session' ? new Promise(resolve => { release = resolve; }) : original(path, options, cap));
        await apply(); await act(async () => vi.advanceTimersByTimeAsync(1500)); await act(async () => release(structuredClone(session))); expect(posts()).toHaveLength(0); expect(screen.getByText('Unconfirmed · write may have happened')).toBeVisible();
    });
    it('never restores a canceled review when delayed read or write data arrives', async () => {
        render(<Harness/>); await review(); let release!: (value: unknown) => void; const original = vi.mocked(request).getMockImplementation()!;
        vi.mocked(request).mockImplementation(async (path, options, cap) => options?.method === 'POST' ? new Promise(resolve => { release = resolve; }) : original(path, options, cap)); await apply(); fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Cancel' })); await act(async () => release(structuredClone(configured))); expect(screen.queryByRole('dialog')).toBeNull(); expect(posts()).toHaveLength(1);
    });
});
