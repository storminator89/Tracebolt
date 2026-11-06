import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AUTH_REQUIRED_EVENT, mutateRaw, request } from './api';
import { useOperator, type OperatorCapability } from './auth';
import { setLocale } from './i18n';
import { WindowsUpdateJobs } from './windows-update-jobs';
import { WindowsUpdateNextSteps } from './windows-update-next-steps';
import type { UpdateJobView } from './windows-update-jobs-types';
import type { WindowsInventoryResource } from './windows-inventory-resource';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutateRaw: vi.fn() }));
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
const now = '2026-10-11T10:00:00Z', seconds = Date.parse(now) / 1000;
const device = `agent_${'1'.repeat(32)}`, id = `update_${'2'.repeat(32)}`, other = `update_${'9'.repeat(32)}`, digest = `sha256:${'3'.repeat(64)}`;
const selection = { updateId: '11111111-2222-3333-4444-555555555555', revision: 3 };
const job = (): NonNullable<UpdateJobView['job']> => ({ id, selection, state: 'blocked', reason: 'not_downloaded', preview: null, result: null });
const view = (): UpdateJobView => ({ version: 'tracebolt.windows-selected-update-job.v1', deviceId: device, serverNow: seconds, available: false, reason: 'job_pending_or_intervention', job: job() });
const resource = { view: { deviceId: device }, updates: { rows: [{ ...selection, title: 'Cached fixture update' }] } } as unknown as WindowsInventoryResource;
let session: { mode: 'lan'; transport: 'https'; insecureTestMode: false; transportWarning: null; authenticationRequired: true; authenticated: true; csrfToken: string; serverNow: string; expiresAt: string; expiresInSeconds: number; loginMode: 'named'; actorId: string; capabilities: OperatorCapability[] };
const flush = () => act(async () => {});
const openGuide = () => { fireEvent.click(screen.getByText('Next steps for this job', { selector: 'summary' })); return screen.getByRole('group', { name: 'Next steps for this job' }); };
beforeEach(() => {
    vi.useFakeTimers(); vi.setSystemTime(now); setLocale('en', false);
    session = { mode: 'lan', transport: 'https', insecureTestMode: false, transportWarning: null, authenticationRequired: true, authenticated: true, csrfToken: 'csrf', serverNow: now, expiresAt: '2026-10-11T11:00:00Z', expiresInSeconds: 3600, loginMode: 'named', actorId: `operator_${crypto.randomUUID().replaceAll('-', '')}`, capabilities: ['read', 'windows_update_install'] };
    vi.mocked(useOperator).mockReturnValue({ ...session, theme: 'light', logout: vi.fn(), setTheme: vi.fn() } as ReturnType<typeof useOperator>);
    vi.mocked(request).mockReset().mockImplementation(async path => structuredClone(path === '/auth/session' ? session : view()) as never);
    vi.mocked(mutateRaw).mockReset();
});
afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); });

describe('saved update next-step guidance', () => {
    it.each(['en', 'de'] as const)('stays collapsed, localized and read-only in %s', locale => {
        setLocale(locale, false); const onRead = vi.fn(); const { container } = render(<WindowsUpdateNextSteps job={job()} unresolvedAction={false} disabled={false} onRead={onRead} />);
        const summary = screen.getByText(locale === 'en' ? 'Next steps for this job' : 'Nächste Schritte für diesen Auftrag', { selector: 'summary' });
        expect(summary.closest('details')).not.toHaveAttribute('open'); expect(onRead).not.toHaveBeenCalled();
        fireEvent.click(summary); expect(screen.getByText(new RegExp(selection.updateId))).toBeVisible();
        expect(screen.getByText(locale === 'en' ? /Installation content was not already/ : /Installationsinhalte waren nicht bereits/)).toBeVisible();
        expect(container.querySelectorAll('svg[aria-hidden="true"]')).toHaveLength(2);
        fireEvent.click(screen.getByRole('button')); expect(onRead).toHaveBeenCalledTimes(1);
        expect(request).not.toHaveBeenCalled(); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it.each([
        ['readiness_unavailable', 'No usable readiness response'], ['readiness_unknown', 'Unknown does not mean ready'],
        ['offline_unverified', 'cannot switch to an online scan'], ['selection_ineligible', 'do not substitute another revision'],
        ['not_downloaded', 'Download needs its own grant'], ['license_not_accepted', 'cannot accept it'],
        ['bundle_unsupported', 'Bundled updates are not supported'], ['interaction_or_source_required', 'Do not bypass'],
        ['installer_busy', 'not a live status'], ['restart_required_before', 'Coordinate any restart separately'],
        ['download_metadata_unknown', 'Do not approve an unknown download'], ['already_downloaded', 'does not establish installation readiness'],
        ['download_size_exceeds_review_limit', 'cannot increase that limit'],
    ])('explains the saved %s reason without granting a workaround', (reason, expected) => {
        render(<WindowsUpdateNextSteps job={{ ...job(), reason }} unresolvedAction={false} disabled={false} onRead={vi.fn()} />); expect(openGuide()).toHaveTextContent(expected);
        expect(mutateRaw).not.toHaveBeenCalled();
    });
    it.each([
        ['requested', 'exact readiness response'], ['preview', 'not approval'], ['approved', 'Waiting does not prove execution'],
        ['claimed', 'Waiting does not prove execution'], ['expired', 'cannot extend it'], ['schedule_canceled', 'no automatic reschedule'],
        ['schedule_blocked', 'no automatic reschedule'], ['schedule_expired', 'no automatic reschedule'], ['unexpected', 'No action is inferred'],
    ])('uses state-specific guidance for %s', (state, expected) => {
        render(<WindowsUpdateNextSteps job={{ ...job(), state }} unresolvedAction={false} disabled={false} onRead={vi.fn()} />); expect(openGuide()).toHaveTextContent(expected);
        expect(screen.queryByText('Saved readiness reason:', { exact: false })).toBeNull();
    });
    it.each([
        ['failed', 'separately reviewed intervention'], ['uncertain', 'not a failed or safely repeatable attempt'],
        ['not_attempted', 'does not authorize another attempt'], ['succeeded', 'not current installation'],
    ] as const)('preserves the saved %s outcome without decoding result codes', (outcome, expected) => {
        const value = { ...job(), state: 'complete', result: { jobId: id, envelopeDigest: digest, attempted: true, outcome, operationResult: 0, hresult: 0, rebootRequired: 'unknown' as const, completedAt: seconds } };
        render(<WindowsUpdateNextSteps job={value} unresolvedAction={false} disabled={false} onRead={vi.fn()} />); expect(openGuide()).toHaveTextContent(expected);
    });
    it('never turns successful download into installation approval', () => {
        const value = { ...job(), state: 'complete', purpose: 'download' as const, result: { jobId: id, envelopeDigest: digest, attempted: true, outcome: 'succeeded' as const, operationResult: 2, hresult: 0, rebootRequired: 'unknown' as const, completedAt: seconds } };
        render(<WindowsUpdateNextSteps job={value} unresolvedAction={false} disabled={false} onRead={vi.fn()} />); expect(openGuide()).toHaveTextContent('Download success is not installation approval');
    });
    it.each([['available', 'separate reviewed step'], ['pending', 'Do not replace'], ['retired', 'no next job has been started'], ['blocked', 'Do not reset state']] as const)('keeps %s retirement separate', (state, expected) => {
        render(<WindowsUpdateNextSteps job={{ ...job(), retirement: { state } }} unresolvedAction={false} disabled={false} onRead={vi.fn()} />); expect(openGuide()).toHaveTextContent(expected);
    });
    it('shows fixed-window guidance without inferring a guaranteed start', () => {
        const schedule = { version: 'tracebolt.windows-selected-update-schedule.v1' as const, digest, approvedAt: seconds, startAt: seconds + 60, endAt: seconds + 120, permitIssuedAt: 0, revoked: false };
        render(<WindowsUpdateNextSteps job={{ ...job(), state: 'scheduled', schedule }} unresolvedAction={false} disabled={false} onRead={vi.fn()} />); expect(openGuide()).toHaveTextContent('not a guaranteed execution time');
    });
    it('gives tracked uncertainty precedence and offers no competing exact-job read', () => {
        render(<WindowsUpdateNextSteps job={job()} unresolvedAction disabled={false} onRead={vi.fn()} />); expect(openGuide()).toHaveTextContent('Use “Read saved status” above'); expect(screen.queryByRole('button')).toBeNull();
    });
    it('disables repeated reads when busy', () => {
        const onRead = vi.fn(); render(<WindowsUpdateNextSteps job={job()} unresolvedAction={false} disabled onRead={onRead} />); openGuide(); fireEvent.click(screen.getByRole('button')); expect(onRead).not.toHaveBeenCalled();
    });
});

describe('existing exact-job and privacy lifecycle', () => {
    it('reads the displayed exact job once, hides old guidance during refresh and never writes', async () => {
        render(<WindowsUpdateJobs resource={resource} />); await flush(); const group = openGuide(); const control = within(group).getByRole('button', { name: 'Read this job again' });
        const reads = vi.mocked(request).mock.calls.length; fireEvent.click(control); fireEvent.click(control); expect(screen.queryByText('Next steps for this job')).toBeNull(); await flush();
        expect(request).toHaveBeenCalledTimes(reads + 2); expect(request).toHaveBeenLastCalledWith(`/devices/${device}/windows-update-jobs?jobId=${id}`, expect.anything(), 16384);
        expect(screen.getByText('Next steps for this job').closest('details')).not.toHaveAttribute('open'); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it.each(['blur', 'pagehide', 'popstate', 'hashchange', AUTH_REQUIRED_EVENT])('clears guidance on %s', async event => {
        render(<WindowsUpdateJobs resource={resource} />); await flush(); openGuide(); act(() => window.dispatchEvent(new Event(event))); expect(screen.queryByText('Next steps for this job')).toBeNull(); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('clears guidance on hidden state and session expiry', async () => {
        render(<WindowsUpdateJobs resource={resource} />); await flush(); openGuide(); act(() => document.dispatchEvent(new Event('visibilitychange'))); expect(screen.queryByText('Next steps for this job')).toBeNull();
        fireEvent.click(screen.getByRole('button', { name: 'Read saved status' })); await flush(); expect(screen.getByText('Next steps for this job')).toBeInTheDocument();
        await act(async () => { vi.advanceTimersByTime(3_600_001); }); expect(screen.queryByText('Next steps for this job')).toBeNull();
    });
    it('rejects a changed exact ID instead of showing another job’s guidance', async () => {
        render(<WindowsUpdateJobs resource={resource} />); await flush(); openGuide(); vi.mocked(request).mockImplementation(async path => structuredClone(path === '/auth/session' ? session : { ...view(), job: { ...job(), id: other } }) as never);
        fireEvent.click(screen.getByRole('button', { name: 'Read this job again' })); await flush(); expect(screen.queryByText('Next steps for this job')).toBeNull(); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('cannot restore guidance from a late response after interruption', async () => {
        render(<WindowsUpdateJobs resource={resource} />); await flush(); openGuide(); let finish!: (value: unknown) => void;
        vi.mocked(request).mockImplementation(async path => path === '/auth/session' ? structuredClone(session) as never : new Promise(resolve => { finish = resolve; }));
        fireEvent.click(screen.getByRole('button', { name: 'Read this job again' })); await flush(); act(() => window.dispatchEvent(new Event('pagehide'))); await act(async () => finish(view()));
        expect(screen.queryByText('Next steps for this job')).toBeNull(); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('keeps uncertain action A authoritative while inspecting saved job B', async () => {
        vi.mocked(request).mockImplementation(async path => structuredClone(path === '/auth/session' ? session : { ...view(), available: true, reason: 'ready', job: null }) as never);
        const ui = render(<WindowsUpdateJobs resource={resource} />); await flush();
        vi.mocked(mutateRaw).mockRejectedValueOnce(new Error('Lost request A'));
        fireEvent.change(screen.getByRole('combobox'), { target: { value: `${selection.updateId}:3` } }); fireEvent.click(screen.getByRole('button', { name: 'Check readiness' })); await flush();
        const a = JSON.parse(vi.mocked(mutateRaw).mock.calls[0][1]).requestId;
        const b = { ...job(), id: other, state: 'approved', reason: 'ready' };
        const { preview: _preview, ...summary } = b;
        const history = { version: 'tracebolt.windows-selected-update-history.v1', deviceId: device, serverNow: seconds, available: false, reason: 'job_pending_or_intervention', remainingCapacity: 31, jobs: [{ ...summary, requestedAt: seconds, approvedAt: seconds, claimedAt: 0 }] };
        vi.mocked(request).mockImplementation(async path => structuredClone(path === '/auth/session' ? session : path.endsWith('?history=1') ? history : { ...view(), job: { ...b, id: path.endsWith(other) ? other : a } }) as never);
        fireEvent.click(screen.getByText('Saved update jobs', { selector: 'summary' })); fireEvent.click(screen.getByRole('button', { name: 'Read saved jobs' })); await flush();
        fireEvent.click(screen.getByRole('button', { name: `Open saved job · ${other}` })); await flush();
        expect(openGuide()).toHaveTextContent('Use “Read saved status” above'); expect(screen.queryByRole('button', { name: 'Read this job again' })).toBeNull();
        ui.unmount(); render(<WindowsUpdateJobs resource={resource} />); await flush();
        expect(request).toHaveBeenLastCalledWith(`/devices/${device}/windows-update-jobs?jobId=${a}`, expect.anything(), 16384); expect(mutateRaw).toHaveBeenCalledTimes(1);
    });
    it.each(['account', 'capability'] as const)('cannot read more evidence after %s authority changes', async change => {
        render(<WindowsUpdateJobs resource={resource} />); await flush(); openGuide();
        session = change === 'account' ? { ...session, actorId: `operator_${'7'.repeat(32)}` } : { ...session, capabilities: ['read'] };
        const reads = vi.mocked(request).mock.calls.length; fireEvent.click(screen.getByRole('button', { name: 'Read this job again' })); await flush();
        expect(request).toHaveBeenCalledTimes(reads + 1); expect(screen.queryByText('Next steps for this job')).toBeNull(); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('does not persist guidance or expansion', async () => {
        const save = vi.spyOn(Storage.prototype, 'setItem'); render(<WindowsUpdateJobs resource={resource} />); await flush();
        openGuide(); fireEvent.click(screen.getByText('Next steps for this job', { selector: 'summary' })); expect(save).not.toHaveBeenCalled(); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('hides the extra read on retirement-storage failure without blocking original reconciliation', async () => {
        const original = Storage.prototype.getItem;
        vi.spyOn(Storage.prototype, 'getItem').mockImplementation(function (this: Storage, key: string) {
            if (key.startsWith('tracebolt.windows-update-retirement.v1:')) throw new Error('Storage unavailable');
            return original.call(this, key);
        });
        vi.mocked(request).mockImplementation(async path => structuredClone(path === '/auth/session' ? session : { ...view(), reusableJobs: true, grantExpiresAt: seconds + 1800 }) as never);
        render(<WindowsUpdateJobs resource={resource} />); await flush();
        expect(openGuide()).toHaveTextContent('Use “Read saved status” above'); expect(screen.queryByRole('button', { name: 'Read this job again' })).toBeNull();
        fireEvent.click(screen.getByRole('button', { name: 'Read saved status' })); await flush();
        expect(request).toHaveBeenLastCalledWith(`/devices/${device}/windows-update-jobs?jobId=${id}`, expect.anything(), 16384); expect(mutateRaw).not.toHaveBeenCalled();
    });
});
