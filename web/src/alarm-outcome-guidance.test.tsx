import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, APIError, AUTH_REQUIRED_EVENT, request } from './api';
import { useOperator } from './auth';
import { setLocale } from './i18n';
import { AlarmOutcomeGuidance } from './alarm-outcome-guidance';
import { AlarmStatusPanel } from './alarm-status';
import type { AlarmStatus } from './alarm-status-types';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn() }));
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
const empty = (): AlarmStatus => ({ schemaVersion: 'tracebolt.alarm-status.v1', enabled: true, queued: 0, inFlight: 0, providerAccepted: 0, failed: 0, uncertain: 0, suppressed: 0, dropped: 0 });
const populated = (): AlarmStatus => ({ ...empty(), failed: 2, uncertain: 3, dropped: 4 });
const operator = { mode: 'lan' as const, authenticated: true, expiresAt: '2026-11-06T08:00:00Z', insecureTestMode: false, logout: vi.fn(), theme: 'light' as const, setTheme: vi.fn() };
const flush = () => act(async () => {});
beforeEach(() => {
    localStorage.clear(); sessionStorage.clear(); setLocale('en', false);
    vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('visible');
    vi.mocked(useOperator).mockReturnValue(operator); vi.mocked(request).mockReset();
});
afterEach(() => { cleanup(); abortProtectedRequests(); vi.restoreAllMocks(); });

describe('retained alarm outcome guidance', () => {
    it.each(['en', 'de'] as const)('shows exactly the applicable retained outcomes in %s without actions', locale => {
        setLocale(locale, false);
        const mounted = render(<AlarmOutcomeGuidance view={empty()} previous={false}/>);
        for (let mask = 0; mask < 8; mask++) {
            mounted.rerender(<AlarmOutcomeGuidance view={{ ...empty(), dropped: mask & 1, uncertain: mask & 2, failed: mask & 4 }} previous={false}/>);
            const guidance = screen.queryByRole('complementary');
            if (!mask) { expect(guidance).toBeNull(); continue; }
            expect(guidance).toHaveAccessibleName(locale === 'en' ? 'Review retained delivery outcomes' : 'Gespeicherte Versandergebnisse prüfen');
            expect(within(guidance!).getAllByRole('listitem')).toHaveLength([1, 2, 4].filter(bit => mask & bit).length);
            expect(guidance).toHaveTextContent(locale === 'en' ? 'earlier destinations and synthetic tests' : 'frühere Ziele und synthetische Tests');
            expect(guidance!.querySelector('button,a,input')).toBeNull();
        }
        expect(request).not.toHaveBeenCalled();
    });
    it('does not turn ordinary pending, accepted or suppressed counts into a failure recommendation', () => {
        render(<AlarmOutcomeGuidance view={{ ...empty(), queued: 2, inFlight: 1, providerAccepted: 7, suppressed: 9 }} previous={false}/>);
        expect(screen.queryByRole('complementary')).toBeNull(); expect(request).not.toHaveBeenCalled();
    });
    it('explains all three outcomes independently without claiming delivery, replay or a current incident', () => {
        render(<AlarmOutcomeGuidance view={populated()} previous={false}/>);
        const guidance = screen.getByRole('complementary');
        expect(guidance).toHaveTextContent('cannot identify the missed events');
        expect(guidance).toHaveTextContent('Check the recipient independently');
        expect(guidance).toHaveTextContent('synthetic test needs its own confirmation');
        expect(guidance).toHaveTextContent('It does not resend an event or clear these outcomes');
        expect(guidance).toHaveTextContent('do not identify an affected incident or prove a current destination problem');
    });
    it.each(['en', 'de'] as const)('keeps disabled retained outcomes and explicitly labels a previous snapshot in %s', locale => {
        setLocale(locale, false);
        render(<AlarmOutcomeGuidance view={{ ...populated(), enabled: false }} previous/>);
        expect(screen.getByRole('complementary')).toHaveTextContent(locale === 'en' ? 'Previous snapshot. Refresh status' : 'Vorheriger Stand. Vor der Bewertung');
        expect(screen.getAllByRole('listitem')).toHaveLength(3);
    });
    it('marks retained guidance previous during a failed refresh, without adding requests or writes', async () => {
        vi.mocked(request).mockResolvedValueOnce(populated()); render(<AlarmStatusPanel/>); await flush();
        expect(screen.getByRole('complementary')).not.toHaveTextContent('Previous snapshot');
        vi.mocked(request).mockRejectedValueOnce(new APIError('private detail', 503));
        fireEvent.click(screen.getByRole('button', { name: 'Refresh alarm status' })); await flush();
        expect(screen.getByRole('complementary')).toHaveTextContent('Previous snapshot');
        expect(screen.getByRole('alert')).not.toHaveTextContent('private detail');
        expect(request).toHaveBeenCalledTimes(2);
        expect(vi.mocked(request).mock.calls.every(([path, options]) => path === '/alerts/status' && options?.method === undefined && options?.body === undefined)).toBe(true);
    });
    it.each(['session', 'navigation', 'suspension'] as const)('removes guidance on %s without preserving a second private snapshot', async kind => {
        vi.mocked(request).mockResolvedValue(populated()); render(<AlarmStatusPanel/>); await flush();
        expect(screen.getByRole('complementary')).toBeInTheDocument();
        act(() => window.dispatchEvent(new Event(kind === 'session' ? AUTH_REQUIRED_EVENT : kind === 'navigation' ? 'hashchange' : 'pagehide')));
        expect(screen.queryByRole('complementary')).toBeNull(); expect(request).toHaveBeenCalledTimes(1);
    });
    it('shows nothing after an initial read error or a fresh all-zero response', async () => {
        vi.mocked(request).mockRejectedValueOnce(new Error('private')); render(<AlarmStatusPanel/>); await flush();
        expect(screen.queryByRole('complementary')).toBeNull();
        vi.mocked(request).mockResolvedValueOnce(empty()); fireEvent.click(screen.getByRole('button', { name: 'Refresh alarm status' })); await flush();
        expect(screen.queryByRole('complementary')).toBeNull(); expect(request).toHaveBeenCalledTimes(2);
    });
    it('retains the authenticated read-only role boundary', async () => {
        vi.mocked(useOperator).mockReturnValue({ ...operator, loginMode: 'named', actorId: `operator_${'a'.repeat(32)}`, capabilities: ['read'] });
        vi.mocked(request).mockResolvedValue(populated()); render(<AlarmStatusPanel/>); await flush();
        expect(screen.getByRole('complementary')).toBeInTheDocument();
        expect(screen.getAllByRole('button')).toHaveLength(1); expect(request).toHaveBeenCalledTimes(1);
    });
});
