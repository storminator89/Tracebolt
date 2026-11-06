import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AUTH_REQUIRED_EVENT, mutateRaw, request } from './api';
import { useOperator, type OperatorSession } from './auth';
import { setLocale } from './i18n';
import { useWindowsInventory } from './windows-inventory-resource';
import { WindowsFleetUpdateHistory } from './windows-fleet-update-history';
import { WindowsFleetUpdateWorklist } from './windows-fleet-update-worklist';
import { validUpdateJobHistory, type UpdateJobHistory, type UpdateJobSummary } from './windows-update-jobs-types';
import type { Device } from './types';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutateRaw: vi.fn() }));
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
vi.mock('./windows-inventory-resource', () => ({ useWindowsInventory: vi.fn() }));
const now = '2026-11-06T10:00:00Z', expiry = '2026-11-06T11:00:00Z', seconds = Date.parse(now) / 1000;
const ids = [1, 2, 3].map(n => `agent_${String(n).repeat(32)}`), devices = ids.slice(0, 2).map((id, i) => ({ id, name: `Office ${i + 1}` }));
const selection = { updateId: '11111111-2222-3333-4444-555555555555', revision: 3 }, digest = `sha256:${'4'.repeat(64)}`;
let session: OperatorSession;
const job = (n = 1): UpdateJobSummary => {
    const id = `update_${n.toString(16).padStart(32, '0')}`;
    return { id, selection, state: 'complete', reason: 'ready', result: { jobId: id, envelopeDigest: digest, attempted: true, outcome: 'failed', operationResult: 4, hresult: -1, rebootRequired: 'unknown', completedAt: seconds - 10 }, requestedAt: seconds - 40, approvedAt: seconds - 30, claimedAt: seconds - 20 };
};
const history = (id = ids[0], count = 1): UpdateJobHistory => ({ version: 'tracebolt.windows-selected-update-history.v1', deviceId: id, serverNow: seconds, available: false, reason: 'job_pending_or_intervention', remainingCapacity: 20, jobs: Array.from({ length: count }, (_, i) => job(i + 1)) });
const flush = () => act(async () => {});
const labels = (locale: 'en' | 'de') => locale === 'de' ? { title: 'Gespeicherte Flotten-Updateaufträge', read: 'Gespeicherte Aufträge dieser Geräte lesen', clear: 'Auftragsübersicht leeren' } : { title: 'Saved fleet update jobs', read: 'Read saved jobs for these devices', clear: 'Clear saved-job overview' };
const open = async (locale: 'en' | 'de' = 'en') => { const c = labels(locale); fireEvent.click(screen.getByRole('button', { name: c.title })); fireEvent.click(screen.getByRole('button', { name: c.read })); await flush(); };
beforeEach(() => {
    vi.useFakeTimers(); vi.setSystemTime(now); setLocale('en', false);
    session = { mode: 'lan', transport: 'https', insecureTestMode: false, transportWarning: null, authenticationRequired: true, authenticated: true, csrfToken: 'fixture', serverNow: now, expiresAt: expiry, expiresInSeconds: 3600, loginMode: 'named', actorId: `operator_${crypto.randomUUID().replaceAll('-', '')}`, capabilities: ['read', 'windows_update_install'] };
    vi.mocked(useOperator).mockReturnValue({ ...session, theme: 'light', logout: vi.fn(), setTheme: vi.fn() });
    vi.mocked(useWindowsInventory).mockReturnValue({ loading: false, updates: { rows: [{ ...selection, title: 'Exact cached update' }] } } as never);
    vi.mocked(request).mockReset().mockImplementation(async path => structuredClone(path === '/auth/session' ? session : history(path.split('/')[2])) as never);
    vi.mocked(mutateRaw).mockReset();
});
afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); });

describe('saved fleet update history overview', () => {
    it.each(['en', 'de'] as const)('reads only on demand and keeps evidence compact in %s', async locale => {
        setLocale(locale, false); const c = labels(locale), de = locale === 'de', storage = vi.spyOn(Storage.prototype, 'setItem');
        expect(validUpdateJobHistory(history(), ids[0], session.actorId!)).toBe(true);
        const { container } = render(<WindowsFleetUpdateHistory devices={devices} availableIds={ids}/>);
        expect(request).not.toHaveBeenCalled(); expect(screen.queryByRole('button', { name: c.read })).toBeNull();
        fireEvent.click(screen.getByRole('button', { name: c.title })); expect(request).not.toHaveBeenCalled();
        fireEvent.click(screen.getByRole('button', { name: c.read })); await flush(); expect(request).toHaveBeenCalledTimes(3);
        expect(screen.getByRole('status')).toHaveTextContent(de ? '2/2 Geräteverläufe gelesen · 2 gespeicherte Aufträge' : '2/2 device histories read · 2 saved jobs');
        const summary = screen.getByText('Office 1', { selector: 'strong' }).closest('summary')!, details = summary.closest('details')!;
        expect(details).not.toHaveAttribute('open'); expect(summary).toHaveTextContent(de ? '1 fehlgeschlagenes Ergebnis' : '1 failed result');
        fireEvent.click(summary); expect(within(details).getByText(de ? 'Installation · Fehlgeschlagenes Ergebnis' : 'Installation · Failed result')).toBeVisible();
        expect(within(details).getByText(ids[0])).toBeVisible(); expect(within(details).getByText(`${selection.updateId} · ${de ? 'Revision' : 'Revision'} 3`)).toBeVisible();
        const evidence = within(details).getByText(de ? 'Auftragsdetails' : 'Job details', { selector: 'summary' }); fireEvent.click(evidence);
        expect(within(details).getByText(job().id)).toBeVisible();
        expect(details.querySelector('time')).toHaveAttribute('datetime', '2026-11-06T10:00:00.000Z');
        expect(within(details).getByText('2026-11-06 09:59:50 UTC')).toBeVisible();
        for (const icon of container.querySelectorAll('svg')) expect(icon).toHaveAttribute('aria-hidden', 'true');
        fireEvent.click(screen.getByRole('button', { name: c.clear })); expect(screen.queryByText(job().id)).toBeNull();
        expect(request).toHaveBeenCalledTimes(3); expect(mutateRaw).not.toHaveBeenCalled(); expect(storage).not.toHaveBeenCalled();
    });

    it('pages ten jobs in original order without additional reads or merging equal updates', async () => {
        const value = history(ids[0], 12); value.jobs.reverse(); expect(validUpdateJobHistory(value, ids[0], session.actorId!)).toBe(true);
        vi.mocked(request).mockImplementation(async path => structuredClone(path === '/auth/session' ? session : value) as never);
        render(<WindowsFleetUpdateHistory devices={[devices[0]]} availableIds={ids}/>); await open();
        fireEvent.click(screen.getByText('Office 1', { selector: 'strong' }).closest('summary')!);
        const list = document.querySelector('.windows-fleet-history-jobs')!;
        expect(list.children).toHaveLength(10); expect(list.firstElementChild).toHaveTextContent(job(12).id);
        fireEvent.click(screen.getByRole('button', { name: 'Next jobs' })); expect(list.children).toHaveLength(2); expect(list.firstElementChild).toHaveTextContent(job(2).id);
        expect(screen.getByText('Page 2 of 2')).toBeVisible(); fireEvent.click(screen.getByRole('button', { name: 'Previous jobs' }));
        expect(list.firstElementChild).toHaveTextContent(job(12).id); expect(request).toHaveBeenCalledTimes(2); expect(mutateRaw).not.toHaveBeenCalled();
    });

    it('distinguishes saved result uncertainty from claims and retains exact scheduled windows', async () => {
        const value = history(ids[0], 4);
        value.jobs[0].result!.outcome = 'uncertain'; value.jobs[0].result!.operationResult = 0; value.jobs[0].result!.hresult = 0;
        value.jobs[1] = { ...value.jobs[1], purpose: 'download', state: 'claimed', result: null };
        value.jobs[2] = { ...value.jobs[2], state: 'scheduled', reason: 'schedule_waiting', result: null, approvedAt: 0, claimedAt: 0, schedule: { version: 'tracebolt.windows-selected-update-schedule.v1', digest, approvedAt: seconds - 30, startAt: seconds + 60, endAt: seconds + 120, permitIssuedAt: 0, revoked: false } };
        value.jobs[3].result = { ...value.jobs[3].result!, outcome: 'succeeded', operationResult: 2, hresult: 0, rebootRequired: 'yes' };
        expect(validUpdateJobHistory(value, ids[0], session.actorId!)).toBe(true);
        vi.mocked(request).mockImplementation(async path => structuredClone(path === '/auth/session' ? session : value) as never);
        render(<WindowsFleetUpdateHistory devices={[devices[0]]} availableIds={ids}/>); await open();
        const summary = screen.getByText('Office 1', { selector: 'strong' }).closest('summary')!; expect(summary).toHaveTextContent('1 uncertain result'); expect(summary).not.toHaveTextContent('failed results'); fireEvent.click(summary);
        expect(screen.getByText('Download · Claimed; outcome unconfirmed')).toBeVisible(); expect(screen.getByText('Installation · Scheduled')).toBeVisible();
        expect(screen.getByText('Installation · WUA reported success')).toBeVisible(); expect(screen.getByText('Restart reported as required')).toBeVisible();
        const scheduled = screen.getByText('Installation · Scheduled').closest('li')!; fireEvent.click(within(scheduled).getByText('Job details', { selector: 'summary' }));
        expect(within(scheduled).getByText('2026-11-06 10:01:00 UTC')).toBeVisible(); expect(within(scheduled).getByText('2026-11-06 10:02:00 UTC')).toBeVisible();
        expect(screen.queryByRole('checkbox')).toBeNull(); expect(mutateRaw).not.toHaveBeenCalled();
    });

    it('never turns unavailable devices into empty histories and never reads removed devices', async () => {
        vi.mocked(request).mockImplementation(async path => structuredClone(path === '/auth/session' ? session : history(path.split('/')[2], 0)) as never);
        const ui = render(<WindowsFleetUpdateHistory devices={devices} availableIds={[ids[0]]}/>); await open();
        expect(request).toHaveBeenCalledTimes(2); expect(screen.getByText('Saved jobs unavailable')).toBeVisible();
        fireEvent.click(screen.getByText('Office 1', { selector: 'strong' }).closest('summary')!); expect(screen.getByText('No saved jobs returned.')).toBeVisible();
        ui.rerender(<WindowsFleetUpdateHistory devices={devices} availableIds={[]}/>);
        expect(screen.queryByText('No saved jobs returned.')).toBeNull(); expect(screen.getByRole('button', { name: labels('en').read })).toBeDisabled();
    });

    it.each(['close', 'blur', 'pagehide', 'popstate', 'hashchange', AUTH_REQUIRED_EVENT, 'expiry'])('discards the loaded overview on %s', async event => {
        render(<WindowsFleetUpdateHistory devices={devices} availableIds={ids}/>); await open();
        if (event === 'close') fireEvent.click(screen.getByRole('button', { name: labels('en').title }));
        else if (event === 'expiry') act(() => vi.advanceTimersByTime(300000));
        else act(() => window.dispatchEvent(new Event(event)));
        expect(screen.queryByText(job().id)).toBeNull(); expect(screen.queryByText('Office 1')).toBeNull(); expect(request).toHaveBeenCalledTimes(3);
        if (event === 'close') { fireEvent.click(screen.getByRole('button', { name: labels('en').title })); expect(screen.queryByText(job().id)).toBeNull(); expect(request).toHaveBeenCalledTimes(3); }
    });

    it('clears results on capability loss and never grants access from read-only metadata', async () => {
        const ui = render(<WindowsFleetUpdateHistory devices={devices} availableIds={ids}/>); await open();
        vi.mocked(useOperator).mockReturnValue({ ...vi.mocked(useOperator)()!, capabilities: ['read'] }); ui.rerender(<WindowsFleetUpdateHistory devices={devices} availableIds={ids}/>);
        expect(screen.queryByText(job().id)).toBeNull(); expect(screen.getByRole('button', { name: labels('en').read })).toBeDisabled(); expect(request).toHaveBeenCalledTimes(3);
    });

    it('renders hostile device text literally and keeps duplicate names as distinct identities', async () => {
        const duplicates = devices.map(device => ({ ...device, name: '<img onerror=alert(1)>' }));
        const { container } = render(<WindowsFleetUpdateHistory devices={duplicates} availableIds={ids}/>); await open();
        const names = screen.getAllByText('<img onerror=alert(1)>', { selector: 'strong' }); expect(names).toHaveLength(2); expect(container.querySelector('img')).toBeNull();
        names.forEach((name, index) => { fireEvent.click(name.closest('summary')!); expect(within(name.closest('details')!).getByText(ids[index])).toBeVisible(); });
    });
});

it('integrates without auto reads and cannot reconcile or replace an uncertain per-device write', async () => {
    const base = (id: string) => ({ version: 'tracebolt.windows-selected-update-job.v1', deviceId: id, serverNow: seconds, available: true, reason: 'ready', job: null });
    vi.mocked(request).mockImplementation(async path => structuredClone(path === '/auth/session' ? session : path.endsWith('?history=1') ? history(path.split('/')[2]) : base(path.split('/')[2])) as never);
    const fleet = devices.map(device => ({ ...device, platform: 'windows', source: 'lan', synthetic: false } as Device));
    render(<WindowsFleetUpdateWorklist devices={fleet}/>); fireEvent.click(screen.getByRole('button', { name: 'Windows update worklist' }));
    fireEvent.click(screen.getByRole('checkbox', { name: /Office 1/ })); fireEvent.click(screen.getByRole('checkbox', { name: /Office 2/ })); fireEvent.click(screen.getByRole('button', { name: 'Freeze device selection' }));
    expect(request).not.toHaveBeenCalled(); fireEvent.click(screen.getByRole('button', { name: 'Open device: Office 1' })); await flush();
    fireEvent.change(screen.getByRole('combobox'), { target: { value: `${selection.updateId}:3` } }); vi.mocked(mutateRaw).mockRejectedValueOnce(new Error('Lost response'));
    fireEvent.click(screen.getByRole('button', { name: 'Check readiness' })); await flush();
    const uncertainId = JSON.parse(vi.mocked(mutateRaw).mock.calls[0][1]).requestId;
    expect(screen.getByText('Write unconfirmed; read saved status only')).toBeVisible(); await open();
    expect(screen.getByText('Write unconfirmed; read saved status only')).toBeVisible(); expect(mutateRaw).toHaveBeenCalledTimes(1);
    expect(vi.mocked(useWindowsInventory).mock.calls.some(([id]) => id === ids[1])).toBe(false);
    fireEvent.click(screen.getByRole('button', { name: 'Close device: Office 1' })); fireEvent.click(screen.getByRole('button', { name: 'Open device: Office 1' })); await flush();
    expect(request).toHaveBeenCalledWith(`/devices/${ids[0]}/windows-update-jobs?jobId=${uncertainId}`, expect.anything(), 16384);
    expect(mutateRaw).toHaveBeenCalledTimes(1); expect(screen.getByText('Write unconfirmed; read saved status only')).toBeVisible();
});

it('keeps the worklist close/reopen transport bound and offers explicit recovery without reusing late data', async () => {
    const late: Array<() => void> = [];
    const fleet = Array.from({ length: 8 }, (_, i) => ({ id: `agent_${(i + 1).toString(16).padStart(32, '0')}`, name: `Device ${i + 1}`, platform: 'windows', source: 'lan', synthetic: false } as Device));
    vi.mocked(request).mockImplementation(path => path === '/auth/session' ? Promise.resolve(session) as never : new Promise(resolve => late.push(() => resolve(history(path.split('/')[2])))) as never);
    render(<WindowsFleetUpdateWorklist devices={fleet}/>); fireEvent.click(screen.getByRole('button', { name: 'Windows update worklist' }));
    for (const device of fleet) fireEvent.click(screen.getByRole('checkbox', { name: new RegExp(device.name) }));
    fireEvent.click(screen.getByRole('button', { name: 'Freeze device selection' })); await open(); expect(request).toHaveBeenCalledTimes(5);
    fireEvent.click(screen.getByRole('button', { name: 'Windows update worklist' }));
    fireEvent.click(screen.getByRole('button', { name: 'Windows update worklist' }));
    fireEvent.click(screen.getByRole('button', { name: labels('en').title }));
    expect(screen.getByRole('button', { name: labels('en').read })).toBeDisabled();
    expect(screen.getByRole('status')).toHaveTextContent('reload the page; unsaved selections will be lost');
    await act(async () => vi.advanceTimersByTimeAsync(10000)); expect(request).toHaveBeenCalledTimes(5);
    await act(async () => late.forEach(resolve => resolve())); expect(request).toHaveBeenCalledTimes(5);
    expect(screen.getByRole('button', { name: labels('en').read })).toBeEnabled(); expect(screen.queryByText(job().id)).toBeNull();
    vi.mocked(request).mockImplementation(async path => (path === '/auth/session' ? session : { ...history(path.split('/')[2]), serverNow: seconds + 10 }) as never);
    fireEvent.click(screen.getByRole('button', { name: labels('en').read })); await flush();
    expect(screen.getByRole('status')).toHaveTextContent('8/8 device histories read'); expect(mutateRaw).not.toHaveBeenCalled();
});
