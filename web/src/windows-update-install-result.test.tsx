import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AUTH_REQUIRED_EVENT, mutateRaw, request } from './api';
import { useOperator, type OperatorCapability } from './auth';
import { setLocale } from './i18n';
import type { WindowsInventoryResource } from './windows-inventory-resource';
import { WindowsUpdateInstallResult } from './windows-update-install-result';
import { WindowsUpdateJobs } from './windows-update-jobs';
import { validUpdateJobView, type UpdateJobHistory, type UpdateJobView, type UpdateResult } from './windows-update-jobs-types';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutateRaw: vi.fn() }));
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
const now = '2026-10-11T10:00:00Z', seconds = Date.parse(now) / 1000;
const device = `agent_${'1'.repeat(32)}`, id = `update_${'2'.repeat(32)}`, otherId = `update_${'3'.repeat(32)}`;
const selection = { updateId: '11111111-2222-3333-4444-555555555555', revision: 3 };
const resource = { view: { deviceId: device }, updates: { rows: [] } } as unknown as WindowsInventoryResource;
const result = (changes: Partial<UpdateResult> = {}): UpdateResult => ({ jobId: id, envelopeDigest: `sha256:${'4'.repeat(64)}`, attempted: true, outcome: 'failed', operationResult: 4, hresult: -2145124329, rebootRequired: 'unknown', completedAt: seconds - 10, ...changes });
const jobView = (value = result()): UpdateJobView => ({ version: 'tracebolt.windows-selected-update-job.v1', deviceId: device, serverNow: seconds, available: false, reason: 'job_pending_or_intervention', job: { id: value.jobId, selection, state: 'complete', reason: 'ready', preview: null, result: value } });
let session: { mode: 'lan'; transport: 'https'; insecureTestMode: false; transportWarning: null; authenticationRequired: true; authenticated: true; csrfToken: string; serverNow: string; expiresAt: string; expiresInSeconds: number; loginMode: 'named'; actorId: string; capabilities: OperatorCapability[] };
const flush = () => act(async () => {});
const panel = () => screen.getByText('Installation evidence', { selector: 'summary' }).closest('details')!;
const field = (name: string, root: HTMLElement = panel()) => within(root).getByText(name, { selector: 'dt' }).nextElementSibling!;
beforeEach(() => {
    vi.useFakeTimers(); vi.setSystemTime(now); setLocale('en', false);
    session = { mode: 'lan', transport: 'https', insecureTestMode: false, transportWarning: null, authenticationRequired: true, authenticated: true, csrfToken: 'csrf', serverNow: now, expiresAt: '2026-10-11T11:00:00Z', expiresInSeconds: 3600, loginMode: 'named', actorId: `operator_${crypto.randomUUID().replaceAll('-', '')}`, capabilities: ['read', 'windows_update_install'] };
    vi.mocked(useOperator).mockReturnValue({ ...session, theme: 'light', logout: vi.fn(), setTheme: vi.fn() });
    vi.mocked(request).mockReset().mockImplementation(async path => structuredClone(path === '/auth/session' ? session : jobView()) as never);
    vi.mocked(mutateRaw).mockReset();
});
afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); });

describe('saved installation evidence', () => {
    it.each(['en', 'de'] as const)('keeps exact fields collapsed with accessible labels in %s', async locale => {
        vi.useRealTimers(); setLocale(locale, false); const de = locale === 'de';
        const source = result(), before = structuredClone(source), storage = vi.spyOn(Storage.prototype, 'setItem');
        render(<WindowsUpdateInstallResult result={source}/>);
        const summary = screen.getByText(de ? 'Installationsnachweis' : 'Installation evidence', { selector: 'summary' });
        const details = summary.closest('details')!;
        expect(details).not.toHaveAttribute('open');
        expect(summary.tagName).toBe('SUMMARY');
        fireEvent.click(summary);
        expect(field(de ? 'Versuch vermerkt' : 'Attempt recorded', details)).toHaveTextContent(de ? 'Ja' : 'Yes');
        expect(field(de ? 'Gespeicherter Ergebniscode' : 'Saved result code', details)).toHaveTextContent(/^4$/);
        expect(field(de ? 'Gespeicherter HRESULT' : 'Saved HRESULT', details)).toHaveTextContent('0x80240017 (-2145124329)');
        expect(field(de ? 'Neustart erforderlich' : 'Restart required', details)).toHaveTextContent(de ? 'Unbekannt' : 'Unknown');
        expect(details.querySelector('time')).toHaveAttribute('datetime', '2026-10-11T09:59:50.000Z');
        expect(details.querySelector('time')).toHaveTextContent('2026-10-11 09:59:50 UTC');
        expect(details.querySelectorAll('svg')).toHaveLength(3);
        for (const icon of details.querySelectorAll('svg')) expect(icon).toHaveAttribute('aria-hidden', 'true');
        fireEvent.click(summary); fireEvent.click(summary);
        expect(source).toEqual(before); expect(request).not.toHaveBeenCalled(); expect(mutateRaw).not.toHaveBeenCalled(); expect(storage).not.toHaveBeenCalled();
        expect(within(details).queryByRole('button')).toBeNull(); expect(within(details).queryByRole('link')).toBeNull();
    });

    it.each([[-2147483648, '0x80000000'], [-1, '0xffffffff'], [0, '0x00000000'], [1, '0x00000001'], [2147483647, '0x7fffffff']] as const)('preserves signed HRESULT %i and its complete hex bits', (hresult, hex) => {
        render(<WindowsUpdateInstallResult result={result({ hresult })}/>);
        expect(field('Saved HRESULT')).toHaveTextContent(`${hex} (${hresult})`);
    });

    it.each([0, 1, 2, 3, 4, 5])('does not infer an outcome from stored operation code %i', operationResult => {
        const source = result({ outcome: 'uncertain', operationResult, hresult: 0 });
        expect(validUpdateJobView(jobView(source), device, session.actorId)).toBe(true);
        render(<WindowsUpdateInstallResult result={source}/>);
        expect(field('Saved result code')).toHaveTextContent(new RegExp(`^${operationResult}$`));
        expect(screen.getByText(/Codes alone do not establish success/)).toBeInTheDocument();
        expect(screen.queryByText(/WUA reported success|Installation failed/)).toBeNull();
    });

    it.each(['yes', 'no', 'unknown'] as const)('retains the exact %s reboot fact', rebootRequired => {
        render(<WindowsUpdateInstallResult result={result({ rebootRequired })}/>);
        expect(field('Restart required')).toHaveTextContent({ yes: 'Yes', no: 'No', unknown: 'Unknown' }[rebootRequired]);
    });

    it.each(['en', 'de'] as const)('does not turn not-attempted zero fields into success in %s', locale => {
        setLocale(locale, false); const de = locale === 'de', source = result({ attempted: false, outcome: 'not_attempted', operationResult: 0, hresult: 0 });
        expect(validUpdateJobView(jobView(source), device, session.actorId)).toBe(true);
        render(<WindowsUpdateInstallResult result={source}/>);
        const details = screen.getByText(de ? 'Installationsnachweis' : 'Installation evidence').closest('details')!;
        expect(field(de ? 'Versuch vermerkt' : 'Attempt recorded', details)).toHaveTextContent(de ? 'Nein' : 'No');
        expect(within(details).getByText(de ? /Nullcodes melden keinen Erfolg/ : /Stored zero codes do not report success/)).toBeInTheDocument();
    });

    it('never presents download fields as installation evidence', () => {
        const { container } = render(<WindowsUpdateInstallResult result={result({ purpose: 'download' })}/>);
        expect(container).toBeEmptyDOMElement();
    });
});

describe('installation evidence in the existing authorized job session', () => {
    it.each(['en', 'de'] as const)('preserves the visible uncertainty and coverage limits in %s', async locale => {
        setLocale(locale, false); const de = locale === 'de', source = result({ outcome: 'uncertain', operationResult: 0, hresult: 0 });
        vi.mocked(request).mockImplementation(async path => structuredClone(path === '/auth/session' ? session : jobView(source)) as never);
        render(<WindowsUpdateJobs resource={resource}/>); await flush();
        const summary = screen.getByText(de ? 'Installationsnachweis' : 'Installation evidence', { selector: 'summary' });
        expect(summary.closest('details')).not.toHaveAttribute('open');
        expect(screen.getByText(de ? /Die Antwort ist unbestätigt/ : /The response is unconfirmed/)).toBeVisible();
        expect(screen.getByText(de ? /keine vollständige Patch-Abdeckung/ : /does not establish whole-device patch coverage/)).toBeVisible();
        const reads = vi.mocked(request).mock.calls.length;
        fireEvent.click(summary); expect(summary.closest('details')).toHaveAttribute('open');
        expect(request).toHaveBeenCalledTimes(reads); expect(mutateRaw).not.toHaveBeenCalled();
        expect(screen.queryByRole('checkbox')).toBeNull();
    });

    it('opens evidence for the exact saved job and closes the old disclosure', async () => {
        const other = jobView(result({ jobId: otherId, hresult: -1 }));
        const summary = { ...other.job!, requestedAt: seconds - 40, approvedAt: seconds - 30, claimedAt: seconds - 20 };
        delete (summary as Partial<typeof summary>).preview;
        const history: UpdateJobHistory = { version: 'tracebolt.windows-selected-update-history.v1', deviceId: device, serverNow: seconds, available: false, reason: 'job_pending_or_intervention', remainingCapacity: 30, jobs: [summary] };
        vi.mocked(request).mockImplementation(async path => structuredClone(path === '/auth/session' ? session : path.endsWith('?history=1') ? history : path.endsWith(`?jobId=${otherId}`) ? other : jobView()) as never);
        render(<WindowsUpdateJobs resource={resource}/>); await flush();
        fireEvent.click(screen.getByText('Installation evidence', { selector: 'summary' }));
        fireEvent.click(screen.getByText('Saved update jobs', { selector: 'summary' }));
        fireEvent.click(screen.getByRole('button', { name: 'Read saved jobs' })); await flush();
        fireEvent.click(screen.getByRole('button', { name: `Open saved job · ${otherId}` })); await flush();
        expect(vi.mocked(request).mock.calls.at(-1)?.[0]).toBe(`/devices/${device}/windows-update-jobs?jobId=${otherId}`);
        expect(panel()).not.toHaveAttribute('open'); expect(field('Saved HRESULT')).toHaveTextContent('0xffffffff (-1)');
        expect(mutateRaw).not.toHaveBeenCalled();
    });

    it.each(['blur', 'pagehide', 'popstate', 'hashchange', AUTH_REQUIRED_EVENT, 'visibilitychange', 'expiry'])('clears the result on %s without extra I/O', async event => {
        render(<WindowsUpdateJobs resource={resource}/>); await flush(); expect(panel()).toBeInTheDocument();
        const reads = vi.mocked(request).mock.calls.length;
        if (event === 'expiry') await act(async () => { await vi.advanceTimersByTimeAsync(3600000); });
        else act(() => (event === 'visibilitychange' ? document : window).dispatchEvent(new Event(event)));
        expect(screen.queryByText('Installation evidence', { selector: 'summary' })).toBeNull();
        expect(screen.queryByText('0x80240017 (-2145124329)')).toBeNull();
        expect(request).toHaveBeenCalledTimes(reads); expect(mutateRaw).not.toHaveBeenCalled();
    });

    it('withholds evidence during a reread and drops a late interrupted response', async () => {
        render(<WindowsUpdateJobs resource={resource}/>); await flush(); expect(panel()).toBeInTheDocument();
        let resolve!: (value: unknown) => void;
        vi.mocked(request).mockImplementation(async path => path === '/auth/session' ? session as never : new Promise(done => { resolve = done; }));
        fireEvent.click(screen.getByRole('button', { name: 'Read saved status' })); await flush();
        expect(screen.queryByText('Installation evidence')).toBeNull();
        act(() => window.dispatchEvent(new Event('blur')));
        await act(async () => resolve(jobView()));
        expect(screen.queryByText('Installation evidence')).toBeNull(); expect(mutateRaw).not.toHaveBeenCalled();
    });

    it('clears old evidence after an invalid replacement instead of keeping its codes', async () => {
        render(<WindowsUpdateJobs resource={resource}/>); await flush();
        vi.mocked(request).mockImplementation(async path => structuredClone(path === '/auth/session' ? session : jobView(result({ hresult: 2147483648 }))) as never);
        fireEvent.click(screen.getByRole('button', { name: 'Read saved status' })); await flush();
        expect(screen.queryByText('Installation evidence')).toBeNull(); expect(screen.getByRole('alert')).toHaveTextContent('unavailable or changed');
    });

    it('discards evidence on account replacement and capability loss', async () => {
        const ui = render(<WindowsUpdateJobs resource={resource}/>); await flush();
        vi.mocked(useOperator).mockReturnValue({ ...vi.mocked(useOperator)()!, actorId: `operator_${'9'.repeat(32)}` });
        ui.rerender(<WindowsUpdateJobs resource={resource}/>); await flush();
        expect(screen.queryByText('Installation evidence')).toBeNull();
        vi.mocked(useOperator).mockReturnValue({ ...vi.mocked(useOperator)()!, capabilities: ['read'] });
        ui.rerender(<WindowsUpdateJobs resource={resource}/>);
        expect(screen.getByText('Update installation is inactive.')).toBeInTheDocument(); expect(mutateRaw).not.toHaveBeenCalled();
    });
});
