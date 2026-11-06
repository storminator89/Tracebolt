import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { AUTH_REQUIRED_EVENT, mutateRaw, request } from './api';
import { actionAccess, actionActor, actionDevice, actionDigest, actionNow, actionPreview, actionSession, actionView } from './service-action-fixtures';
import { useServiceActions } from './service-action-resource';
import type { ServiceActionAccess } from './service-action-api';
import { ServiceActionPanel } from './service-actions';
import { setLocale } from './i18n';
import { serviceActionBlocksNew, validServiceActionView, type ServiceActionJob, type ServiceActionPreview } from './service-action-types';
import { sequenceBinding, sequencePreviewMatches, sequenceStepsMatch } from './service-action-sequence-model';
import { actionV2Preview, actionV2View } from './service-action-v2-fixtures';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutateRaw: vi.fn() }));
let job: ServiceActionJob | null, preview: ServiceActionPreview | null, next: number, alter: (value: ServiceActionPreview) => void;
const status = () => ({ ...actionView(), job, available: !serviceActionBlocksNew(job), reason: job?.state === 'needs_intervention' ? 'needs_intervention' as const : serviceActionBlocksNew(job) ? 'action_in_progress' as const : 'ready' as const });
function Harness({ device = actionDevice, authorized = true, access = actionAccess }: { device?: string; authorized?: boolean; access?: ServiceActionAccess }) {
    const workflow = useServiceActions(device, authorized ? access : null);
    return <><button onClick={() => workflow.select('other.service')} disabled={!workflow.canSelect('other.service')}>Manual other service</button><ServiceActionPanel workflow={workflow} authorized={authorized}/></>;
}
const flush = () => act(async () => {});
const previews = () => vi.mocked(mutateRaw).mock.calls.filter(([path]) => path.endsWith('/preview'));
const approvals = () => vi.mocked(mutateRaw).mock.calls.filter(([path]) => path.endsWith('/approve'));
async function open(locale: 'en' | 'de' = 'en') {
    setLocale(locale, false); const ui = render(<Harness/>); await flush();
    fireEvent.click(screen.getByText(locale === 'en' ? 'Guided service sequence' : 'Geführte Dienstfolge', { selector: 'summary' })); return ui;
}
function add(unit: string, de = false) {
    fireEvent.change(screen.getByRole('combobox', { name: de ? 'Dienst für die Folge' : 'Service for sequence' }), { target: { value: unit } });
    fireEvent.click(screen.getByRole('button', { name: de ? 'Schritt hinzufügen' : 'Add step' }));
}
async function save(de = false) { fireEvent.click(screen.getByRole('button', { name: de ? 'Folge prüfen und vormerken' : 'Check and save sequence' })); await flush(); }
async function review(de = false) { fireEvent.click(screen.getByRole('button', { name: de ? 'Diesen Schritt prüfen' : 'Review this step' })); await flush(); }
async function approve(de = false) {
    const region = screen.getByRole('region', { name: de ? 'Dienstaktion prüfen' : 'Review service action' });
    const button = within(region).getByRole('button', { name: de ? 'Try-Restart freigeben' : 'Approve try-restart' });
    expect(button).toBeDisabled(); expect(within(region).getByRole('checkbox')).not.toBeChecked();
    fireEvent.click(within(region).getByRole('checkbox')); fireEvent.click(button); fireEvent.click(button); await flush();
}
async function complete(de = false) {
    job = { ...job!, state: 'operation_completed', result: { phase: 'operation_completed', outcome: 'completed', observedState: 'unknown' } };
    fireEvent.click(screen.getByRole('button', { name: de ? 'Aktionsstatus prüfen' : 'Check action status' })); await flush();
}
beforeEach(() => {
    vi.useFakeTimers(); vi.setSystemTime(actionNow); setLocale('en', false); job = null; preview = null; next = 0; alter = () => {};
    vi.mocked(request).mockReset().mockImplementation(async path => {
        if (path === '/auth/session') return structuredClone(actionSession) as never;
        if (path.endsWith('/service-actions')) return structuredClone(status()) as never;
        throw Error(`Unexpected read ${path}`);
    });
    vi.mocked(mutateRaw).mockReset().mockImplementation(async (path, body) => {
        const data = JSON.parse(body);
        if (path.endsWith('/preview')) {
            preview = { ...actionPreview(data.unit), id: `action_${(++next).toString(16).padStart(32, '0')}`, sequence: String(next) }; alter(preview);
            const value = { ...status(), preview }; expect(validServiceActionView(value, actionDevice, actionActor, false)).toBe(true); return structuredClone(value) as never;
        }
        if (path.endsWith('/approve')) {
            expect(data).toEqual({ previewId: preview!.id, previewDigest: preview!.digest });
            job = { id: preview!.id, unit: preview!.plan.unit, actorId: actionActor, approvedAt: actionNow, startDeadline: preview!.expiresAt, state: 'approved', envelopeDigest: actionDigest, result: null };
            return structuredClone(status()) as never;
        }
        throw Error(`Unexpected mutation ${path}`);
    });
});
afterEach(() => { act(() => window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT))); cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); });

it.each(['en', 'de'] as const)('runs two individually reviewed steps, then reuses selection with fresh consent in %s', async locale => {
    const de = locale === 'de'; await open(locale); add('fixture.service', de); add('other.service', de);
    const before = vi.mocked(request).mock.calls.length, storage = vi.spyOn(Storage.prototype, 'setItem');
    expect(mutateRaw).not.toHaveBeenCalled(); await save(de);
    expect(previews()).toHaveLength(1); expect(approvals()).toHaveLength(0); expect(screen.queryByRole('checkbox')).toBeNull();
    expect(storage).not.toHaveBeenCalled(); expect(request).toHaveBeenCalledTimes(before + 1);
    await review(de); expect(previews()).toHaveLength(2); await approve(de); expect(approvals()).toHaveLength(1);
    expect(screen.queryByRole('button', { name: de ? 'Nächsten Schritt prüfen' : 'Review next step' })).toBeNull();
    await complete(de); expect(previews()).toHaveLength(2);
    expect(screen.getByText(de ? /Genau dieser Befehl wurde abgeschlossen/ : /This exact command completed/)).toBeVisible();
    const nextButton = screen.getByRole('button', { name: de ? 'Nächsten Schritt prüfen' : 'Review next step' }); fireEvent.click(nextButton); fireEvent.click(nextButton); await flush();
    expect(previews()).toHaveLength(3); expect(JSON.parse(previews()[2][1])).toEqual({ unit: 'other.service' }); await approve(de); expect(approvals()).toHaveLength(2);
    await complete(de); expect(previews()).toHaveLength(3);
    fireEvent.click(screen.getByRole('button', { name: de ? 'Neuen geprüften Durchlauf starten' : 'Start a new reviewed run' })); await flush();
    expect(previews()).toHaveLength(4); expect(JSON.parse(previews()[3][1])).toEqual({ unit: 'fixture.service' });
    expect(screen.getByRole('checkbox')).not.toBeChecked(); expect(approvals()).toHaveLength(2);
});

it('edits ordering without I/O, rejects duplicate or over-eight selections and retains original source data', async () => {
    const services = Array.from({ length: 9 }, (_, i) => ({ unit: `fixture${i}.service`, unitPolicyDigest: actionDigest }));
    vi.mocked(request).mockImplementation(async path => structuredClone(path === '/auth/session' ? actionSession : { ...status(), services }) as never);
    await open(); const before = vi.mocked(request).mock.calls.length;
    for (let i = 0; i < 8; i++) add(`fixture${i}.service`);
    expect(screen.queryByRole('option', { name: 'fixture0.service' })).toBeNull();
    fireEvent.change(screen.getByRole('combobox'), { target: { value: 'fixture8.service' } }); expect(screen.getByRole('button', { name: 'Add step' })).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: 'Move step up: fixture1.service' }));
    expect(screen.getAllByRole('listitem')[0]).toHaveTextContent('fixture1.service');
    fireEvent.click(screen.getByRole('button', { name: 'Remove step: fixture7.service' })); expect(screen.getAllByRole('listitem')).toHaveLength(7);
    expect(request).toHaveBeenCalledTimes(before); expect(mutateRaw).not.toHaveBeenCalled(); expect(services[0].unit).toBe('fixture0.service');
});

it.each(['expired', 'not_started', 'needs_intervention', 'foreign'] as const)('stops on %s evidence without preparing the next step', async state => {
    await open(); add('fixture.service'); add('other.service'); await save(); await review(); await approve();
    job = { ...job!, ...(state === 'foreign' ? { id: `action_${'e'.repeat(32)}`, state: 'operation_completed', result: { phase: 'operation_completed', outcome: 'completed', observedState: 'active' } } : state === 'expired' ? { state, result: null } : state === 'not_started' ? { state, result: { phase: state, reason: 'inactive' } } : { state, result: { phase: state, outcome: 'unknown', observedState: 'unknown' } }) } as ServiceActionJob;
    fireEvent.click(screen.getByRole('button', { name: 'Check action status' })); await flush();
    expect(screen.getByText(/Sequence stopped/)).toBeVisible(); expect(screen.queryByRole('button', { name: 'Review next step' })).toBeNull(); expect(previews()).toHaveLength(2); expect(approvals()).toHaveLength(1);
});

it.each(['incarnationDigest', 'rootPolicyDigest', 'keyId'] as const)('refuses changed %s before showing approval', async field => {
    await open(); add('fixture.service'); await save(); alter = value => { value[field] = `sha256:${'e'.repeat(64)}`; }; await review();
    expect(screen.getByText(/Sequence stopped/)).toBeVisible(); expect(screen.queryByRole('checkbox')).toBeNull(); expect(approvals()).toHaveLength(0);
});

it('does not retry a lost approval, resume after close, or adopt an unrelated manual selection', async () => {
    await open(); add('fixture.service'); await save(); await review();
    fireEvent.click(screen.getByRole('button', { name: 'Close preview' })); expect(screen.getByText(/Sequence stopped/)).toBeVisible();
    fireEvent.click(screen.getByRole('button', { name: 'Discard sequence' })); add('fixture.service'); await save(); await review();
    fireEvent.click(screen.getByRole('button', { name: 'Manual other service' })); await flush();
    expect(screen.getByText(/separate manual selection detached/)).toBeVisible(); expect(screen.getByRole('region', { name: 'Review service action' })).toHaveTextContent('other.service');
    expect(screen.getByRole('checkbox')).not.toBeChecked(); expect(approvals()).toHaveLength(0);
    fireEvent.click(screen.getByRole('button', { name: 'Close preview' })); fireEvent.click(screen.getByRole('button', { name: 'Discard sequence' })); add('fixture.service'); await save(); await review();
    vi.mocked(mutateRaw).mockRejectedValueOnce(Error('lost approval')); await approve();
    expect(screen.getByText(/Sequence stopped/)).toBeVisible(); expect(screen.queryByRole('button', { name: 'Start a new reviewed run' })).toBeNull(); expect(approvals()).toHaveLength(1);
});

it('detaches a saved idle sequence before a separate manual review', async () => {
    await open(); add('fixture.service'); await save(); fireEvent.click(screen.getByRole('button', { name: 'Manual other service' })); await flush();
    expect(screen.getByText(/separate manual selection detached/)).toBeVisible(); expect(screen.getByRole('region', { name: 'Review service action' })).toHaveTextContent('other.service');
    expect(screen.queryByRole('button', { name: 'Review this step' })).toBeNull(); expect(approvals()).toHaveLength(0);
});

it('stops a saved sequence when its permitted unit policy changes', async () => {
    await open(); add('fixture.service'); await save();
    vi.mocked(request).mockImplementation(async path => structuredClone(path === '/auth/session' ? actionSession : { ...status(), services: [{ unit: 'fixture.service', unitPolicyDigest: `sha256:${'e'.repeat(64)}` }] }) as never);
    fireEvent.click(screen.getByRole('button', { name: 'Check action status' })); await flush();
    expect(screen.getByText(/Sequence stopped/)).toBeVisible(); expect(screen.queryByRole('button', { name: 'Review this step' })).toBeNull(); expect(previews()).toHaveLength(1); expect(approvals()).toHaveLength(0);
});

it.each(['blur', 'pagehide', 'hashchange', 'popstate', AUTH_REQUIRED_EVENT, 'visibilitychange', 'unmount'])('forgets the saved sequence and consent on %s', async event => {
    const ui = await open(); add('fixture.service'); await save(); await review(); fireEvent.click(screen.getByRole('checkbox'));
    if (event === 'unmount') ui.unmount(); else act(() => (event === 'visibilitychange' ? document : window).dispatchEvent(new Event(event)));
    expect(screen.queryByRole('checkbox')).toBeNull(); expect(screen.queryByRole('button', { name: 'Discard sequence' })).toBeNull(); expect(approvals()).toHaveLength(0);
});

it('drops late binding responses after navigation and never exposes them for approval', async () => {
    await open(); add('fixture.service'); let resolve!: (value: unknown) => void;
    vi.mocked(mutateRaw).mockImplementationOnce(() => new Promise<unknown>(r => { resolve = r; }) as never);
    fireEvent.click(screen.getByRole('button', { name: 'Check and save sequence' })); await flush(); act(() => window.dispatchEvent(new Event('pagehide')));
    await act(async () => resolve({ ...actionView(), preview: actionPreview() }));
    expect(screen.queryByRole('checkbox')).toBeNull(); expect(screen.queryByRole('button', { name: 'Review this step' })).toBeNull(); expect(approvals()).toHaveLength(0);
});

it.each(['device', 'actor', 'session', 'permission'] as const)('forgets the sequence on %s replacement', async changed => {
    const ui = await open(); add('fixture.service'); await save();
    ui.rerender(<Harness device={changed === 'device' ? `agent_${'e'.repeat(32)}` : actionDevice} authorized={changed !== 'permission'} access={{ ...actionAccess, actorId: changed === 'actor' ? `operator_${'e'.repeat(32)}` : actionActor, sessionKey: changed === 'session' ? '2026-10-05T14:00:00Z' : actionAccess.sessionKey }}/>); await flush();
    expect(screen.queryByRole('button', { name: 'Review this step' })).toBeNull(); expect(screen.queryByRole('button', { name: 'Discard sequence' })).toBeNull(); expect(approvals()).toHaveLength(0);
});

it('clears saved sequence at original session expiry without requesting another step', async () => {
    const expiry = '2026-10-05T12:00:01Z';
    vi.mocked(request).mockImplementation(async path => structuredClone(path === '/auth/session' ? { ...actionSession, expiresAt: expiry, expiresInSeconds: 1 } : status()) as never);
    render(<Harness access={{ ...actionAccess, sessionKey: expiry }}/>); await flush(); fireEvent.click(screen.getByText('Guided service sequence', { selector: 'summary' }));
    add('fixture.service'); await save(); expect(screen.getByRole('button', { name: 'Review this step' })).toBeEnabled();
    act(() => vi.advanceTimersByTime(1000)); expect(screen.queryByRole('button', { name: 'Review this step' })).toBeNull(); expect(previews()).toHaveLength(1); expect(approvals()).toHaveLength(0);
});

it('forgets the sequence after clock rollback and does not auto-resume after focus returns', async () => {
    await open(); add('fixture.service'); await save(); vi.setSystemTime(Date.now() - 2000); act(() => vi.advanceTimersByTime(500));
    expect(screen.queryByRole('button', { name: 'Review this step' })).toBeNull(); act(() => window.dispatchEvent(new Event('focus'))); await flush();
    expect(screen.queryByRole('button', { name: 'Review this step' })).toBeNull(); expect(previews()).toHaveLength(1); expect(approvals()).toHaveLength(0);
});

it('includes first-response latency in the original session deadline', async () => {
    const expiry = '2026-10-05T12:00:10Z'; let resolve!: (value: unknown) => void;
    vi.mocked(request).mockImplementation(async path => path === '/auth/session' ? { ...actionSession, expiresAt: expiry, expiresInSeconds: 10 } as never : await new Promise<unknown>(r => { resolve = r; }) as never);
    render(<Harness access={{ ...actionAccess, sessionKey: expiry }}/>); await flush(); act(() => vi.advanceTimersByTime(5000)); await act(async () => resolve(status()));
    fireEvent.click(screen.getByText('Guided service sequence', { selector: 'summary' })); add('fixture.service');
    expect(screen.getByRole('button', { name: 'Check and save sequence' })).toBeEnabled();
    act(() => vi.advanceTimersByTime(5000)); expect(screen.queryByRole('button', { name: 'Discard sequence' })).toBeNull(); expect(mutateRaw).not.toHaveBeenCalled();
});

it.each([true, false])('never extends the original session deadline after a delayed status reply (advancing=%s)', async advancing => {
    const expiry = '2026-10-05T12:00:10Z';
    vi.mocked(request).mockImplementation(async path => structuredClone(path === '/auth/session' ? { ...actionSession, expiresAt: expiry, expiresInSeconds: 10 } : status()) as never);
    render(<Harness access={{ ...actionAccess, sessionKey: expiry }}/>); await flush(); fireEvent.click(screen.getByText('Guided service sequence', { selector: 'summary' })); add('fixture.service'); await save();
    act(() => vi.advanceTimersByTime(1000)); let resolve!: (value: unknown) => void;
    const serverNow = advancing ? '2026-10-05T12:00:01Z' : actionNow;
    vi.mocked(request).mockImplementation(async path => path === '/auth/session' ? { ...actionSession, serverNow, expiresAt: expiry, expiresInSeconds: advancing ? 9 : 10 } as never : await new Promise<unknown>(r => { resolve = r; }) as never);
    fireEvent.click(screen.getByRole('button', { name: 'Check action status' })); await flush(); act(() => vi.advanceTimersByTime(3000)); await act(async () => resolve({ ...status(), serverNow }));
    expect(screen.getByRole('button', { name: 'Review this step' })).toBeEnabled();
    act(() => vi.advanceTimersByTime(6000)); expect(screen.queryByRole('button', { name: 'Review this step' })).toBeNull(); expect(previews()).toHaveLength(1); expect(approvals()).toHaveLength(0);
});

it('allows only a newly built sequence after a genuinely replaced valid session', async () => {
    const ui = await open(); add('fixture.service'); await save(); const expiry = '2026-10-05T14:00:00Z';
    vi.mocked(request).mockImplementation(async path => structuredClone(path === '/auth/session' ? { ...actionSession, expiresAt: expiry, expiresInSeconds: 7200 } : status()) as never);
    ui.rerender(<Harness access={{ ...actionAccess, sessionKey: expiry }}/>); await flush();
    expect(screen.queryByRole('button', { name: 'Review this step' })).toBeNull(); expect(screen.getByRole('combobox')).toBeEnabled();
    add('other.service'); await save(); expect(screen.getByRole('button', { name: 'Review this step' })).toBeEnabled(); expect(previews()).toHaveLength(2); expect(approvals()).toHaveLength(0);
});

it('does not hide a clock rollback by immediately accepting a newer status response', async () => {
    await open(); add('fixture.service'); await save(); vi.setSystemTime(Date.now() - 2000);
    vi.mocked(request).mockImplementation(async path => structuredClone(path === '/auth/session' ? { ...actionSession, serverNow: '2026-10-05T12:00:01Z' } : { ...status(), serverNow: '2026-10-05T12:00:01Z' }) as never);
    fireEvent.click(screen.getByRole('button', { name: 'Check action status' })); await flush(); act(() => vi.advanceTimersByTime(500));
    expect(screen.queryByRole('button', { name: 'Review this step' })).toBeNull(); expect(screen.getByRole('combobox')).toBeDisabled(); expect(previews()).toHaveLength(1); expect(approvals()).toHaveLength(0);
});

it('uses exact v1/v2 bindings and impact policies without mutating evidence', () => {
    const original = actionV2View(), p = original.preview!, before = JSON.stringify(original), binding = sequenceBinding(p), row = original.services[0];
    expect(sequenceStepsMatch([row], original)).toBe(true); expect(sequencePreviewMatches(p, row, binding)).toBe(true);
    expect(sequenceStepsMatch([row, row], original)).toBe(false); expect(sequenceStepsMatch(Array(9).fill(row), original)).toBe(false);
    expect(sequencePreviewMatches({ ...p, transportProfile: 'disposable-http-test' }, row, binding)).toBe(false);
    expect(sequencePreviewMatches(p, { ...row, affectedServices: [row.unit] }, binding)).toBe(false);
    expect(sequencePreviewMatches(actionPreview(), row, binding)).toBe(false); expect(JSON.stringify(original)).toBe(before);
});

it.each([false, true])('uses the existing v2 impact review and rejects changed impact=%s', async changed => {
    let impact = ['dependent.service', 'fixture.service'];
    const current = () => ({ ...actionV2View(impact), preview: null, job, available: status().available, reason: status().reason });
    vi.mocked(request).mockImplementation(async path => structuredClone(path === '/auth/session' ? actionSession : current()) as never);
    vi.mocked(mutateRaw).mockImplementation(async (path, body) => {
        if (path.endsWith('/preview')) {
            expect(JSON.parse(body)).toEqual({ unit: 'fixture.service' });
            preview = { ...actionV2Preview(impact), id: `action_${(++next).toString(16).padStart(32, '0')}`, sequence: String(next) };
            return structuredClone({ ...current(), preview }) as never;
        }
        expect(path.endsWith('/approve')).toBe(true); expect(JSON.parse(body)).toEqual({ previewId: preview!.id, previewDigest: preview!.digest });
        job = { id: preview!.id, unit: 'fixture.service', actorId: actionActor, approvedAt: actionNow, startDeadline: preview!.expiresAt, state: 'approved', envelopeDigest: actionDigest, result: null };
        return structuredClone(current()) as never;
    });
    await open(); add('fixture.service'); await save(); if (changed) impact = ['another.service', 'dependent.service', 'fixture.service']; await review();
    if (changed) { expect(screen.getByText(/Sequence stopped/)).toBeVisible(); expect(screen.queryByRole('checkbox')).toBeNull(); expect(approvals()).toHaveLength(0); }
    else {
        expect(screen.getByRole('region', { name: 'Review service action' })).toHaveTextContent('not a sandbox');
        expect(screen.getByRole('region', { name: 'Services that may be interrupted' })).toHaveTextContent('dependent.service');
        await approve(); await complete(); expect(screen.getByRole('button', { name: 'Start a new reviewed run' })).toBeEnabled(); expect(approvals()).toHaveLength(1);
    }
});
