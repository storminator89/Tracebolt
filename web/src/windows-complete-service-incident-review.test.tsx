import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, AUTH_REQUIRED_EVENT, mutateRaw, request } from './api';
import { LOGOUT_INTENT_KEY, useOperator } from './auth';
import { setLocale } from './i18n';
import wire from './windows-complete-service-review-go-fixture.json';
import { WindowsCompleteServiceIncidentReview } from './windows-complete-service-incident-review';
import { validWindowsCompleteServiceIncidentReview } from './windows-complete-service-incident-review-types';
import type { WindowsCompleteServiceIncidentReviewView } from './windows-complete-service-incident-review-types';
import { validWindowsServiceIncidentReview, WINDOWS_SERVICE_REVIEW_HEADER } from './windows-service-incident-review-types';
import type { WindowsActionBinding, WindowsActionView } from './windows-service-action-types';
import { WindowsIncidentInbox } from './windows-incident-inbox';
import { completeIncidentFixture } from './windows-complete-incident-inbox-fixture';
import { windowsCapacityDevice } from './windows-capacity-fixture';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutateRaw: vi.fn() }));
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
const now = wire.matched.serverNow, expires = new Date(Date.parse(now) + 3600000).toISOString(), actor = `operator_${'2'.repeat(32)}`;
const session = { mode: 'lan', transport: 'https', insecureTestMode: false, transportWarning: null, authenticationRequired: true, authenticated: true, csrfToken: 'synthetic-csrf', serverNow: now, expiresAt: expires, expiresInSeconds: 3600, loginMode: 'named', actorId: actor, capabilities: ['read', 'windows_service_control'] };
let view: WindowsCompleteServiceIncidentReviewView;
const path = () => `/fleet/windows-incidents/complete/${view.incident.key}/service-review`;
const actionView = (): WindowsActionView => ({ schemaVersion: 'tracebolt.windows-service-action-view.v1', deviceId: view.incident.deviceId, serverNow: now, configured: true, available: true, reason: 'ready', target: view.incident.serviceName, preview: null, job: null });
const preview = () => ({ ...actionView(), preview: { version: 'tracebolt.windows-service-action-preview.v1', id: `action_${'5'.repeat(32)}`, binding: view.control.binding, operation: 'restart', actorId: actor, sequence: '1', createdAt: now, expiresAt: new Date(Date.parse(now) + 60000).toISOString(), digest: `sha256:${'a'.repeat(64)}` } });
const flush = () => act(async () => {});
const props = () => ({ incidentKey: view.incident.key, deviceId: view.incident.deviceId, serviceName: view.incident.serviceName, sessionKey: expires, onClose: vi.fn() });
async function choose() { fireEvent.click(screen.getByRole('button', { name: /^Select service:/ })); fireEvent.change(screen.getByRole('combobox'), { target: { value: 'restart' } }); fireEvent.click(screen.getByRole('button', { name: 'Review action' })); await flush(); }
beforeEach(() => {
    abortProtectedRequests(); vi.useFakeTimers(); vi.setSystemTime(now); setLocale('en', false);
    view = structuredClone(wire.matched) as WindowsCompleteServiceIncidentReviewView;
    vi.mocked(useOperator).mockReturnValue({ ...session, mode: 'lan', theme: 'light', loginMode: 'named', capabilities: ['read', 'windows_service_control'], logout: vi.fn(), setTheme: vi.fn() });
    vi.mocked(request).mockReset().mockImplementation(async p => structuredClone(p === '/auth/session' ? session : p === path() ? view : actionView()) as never);
    vi.mocked(mutateRaw).mockReset().mockImplementation(async () => structuredClone(preview()) as never);
});
afterEach(() => { cleanup(); abortProtectedRequests(); localStorage.removeItem(LOGOUT_INTENT_KEY); sessionStorage.removeItem(LOGOUT_INTENT_KEY); vi.useRealTimers(); vi.restoreAllMocks(); });

describe('closed complete-source incident review', () => {
    it('accepts actual Go DTOs and keeps every v1 decoder closed', () => {
        for (const value of Object.values(wire)) {
            expect(validWindowsCompleteServiceIncidentReview(value, value.incident.key, value.incident.deviceId, value.incident.serviceName)).toBe(true);
            expect(validWindowsServiceIncidentReview(value, value.incident.key, value.incident.deviceId, value.incident.serviceName)).toBe(false);
        }
        const valid = (value: unknown) => validWindowsCompleteServiceIncidentReview(value, view.incident.key, view.incident.deviceId, view.incident.serviceName);
        for (const changed of [
            { ...view, extra: true }, { ...view, schemaVersion: 'tracebolt.windows-service-incident-review.v1' },
            { ...view, incident: { ...view.incident, sourceKind: 'assessment_v1' } },
            { ...view, incident: { ...view.incident, key: 'b'.repeat(64) } },
            { ...view, observation: { ...view.observation, name: 'OtherService' } },
            { ...view, observation: { ...view.observation, source: { ...view.observation!.source, generationId: `sample_${'a'.repeat(32)}` } } },
            { ...view, observation: { ...view.observation, source: { ...view.observation!.source, receivedAt: '2026-10-13T11:00:00Z' } } },
            { ...view, observation: { ...view.observation, state: 'absent' } },
            { ...view, observation: { ...view.observation, source: { ...view.observation!.source, manifestSha256: 'e'.repeat(64) } } },
            { ...view, control: { ...view.control, binding: { ...view.control.binding, target: 'OtherService' } } },
            { ...view, control: { ...view.control, status: 'unsupported_target' } },
        ]) expect(valid(changed)).toBe(false);
    });
    it.each(['en', 'de'] as const)('shows compact original lifecycle and collapsed full provenance in %s', async locale => {
        setLocale(locale, false); render(<WindowsCompleteServiceIncidentReview {...props()}/>); await flush();
        const region = screen.getByRole('region', { name: locale === 'de' ? 'Vorfallsdienst prüfen' : 'Review incident service' });
        expect(within(region).getByText(locale === 'de' ? 'Gestoppt' : 'Stopped')).toBeVisible();
        expect(region.querySelector('time')).toHaveAttribute('datetime', view.incident.openedAt);
        expect(region.querySelector('details')).not.toHaveAttribute('open');
        expect(region.querySelector('details')).toHaveTextContent(view.observation!.source.generationId);
        expect(region.querySelector('details')).toHaveTextContent('2051');
        expect(mutateRaw).not.toHaveBeenCalled(); expect(within(region).queryByRole('combobox')).toBeNull(); expect(within(region).queryByRole('checkbox')).toBeNull();
        expect(vi.mocked(request).mock.calls.find(([p]) => p.endsWith('/windows-service-actions'))?.[1]?.headers).toEqual({ [WINDOWS_SERVICE_REVIEW_HEADER]: view.control.bindingDigest });
    });
    it('opens the complete row deliberately through its separate route', async () => {
        const inbox = completeIncidentFixture('active', now); inbox.items = [view.incident]; inbox.authorityExpiresAt = view.authorityExpiresAt;
        vi.mocked(request).mockImplementation(async p => structuredClone(p.includes('/complete?') ? inbox : p === path() ? view : p === '/auth/session' ? session : actionView()) as never);
        render(<WindowsIncidentInbox complete devices={[{ ...windowsCapacityDevice(), id: view.incident.deviceId }]} sessionKey={expires} admin={false}/>);
        fireEvent.click(screen.getByRole('button', { name: 'Windows incidents' })); await flush(); expect(vi.mocked(request).mock.calls.some(([p]) => p === path())).toBe(false);
        fireEvent.click(screen.getByRole('button', { name: /^Review service:/ })); await flush(); expect(vi.mocked(request).mock.calls.some(([p]) => p === path())).toBe(true);
        fireEvent.click(screen.getByRole('button', { name: 'Close service review' })); expect(screen.queryByRole('region', { name: 'Review incident service' })).toBeNull(); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('keeps a separate blank operation, immutable preview guard and unchecked approval', async () => {
        render(<WindowsCompleteServiceIncidentReview {...props()}/>); await flush();
        fireEvent.click(screen.getByRole('button', { name: /^Select service:/ })); expect(screen.getByRole('combobox')).toHaveValue(''); expect(screen.getByRole('button', { name: 'Review action' })).toBeDisabled();
        fireEvent.change(screen.getByRole('combobox'), { target: { value: 'restart' } }); fireEvent.click(screen.getByRole('button', { name: 'Review action' })); await flush();
        expect(vi.mocked(mutateRaw).mock.calls[0].slice(0, 3)).toEqual([`/devices/${view.incident.deviceId}/windows-service-actions/preview`, JSON.stringify({ target: view.incident.serviceName, operation: 'restart' }), { [WINDOWS_SERVICE_REVIEW_HEADER]: view.control.bindingDigest }]);
        expect(screen.getByRole('checkbox')).not.toBeChecked(); expect(screen.getByRole('button', { name: 'Approve this action once' })).toBeDisabled();
        const p = preview().preview;
        vi.mocked(mutateRaw).mockResolvedValueOnce({ ...actionView(), available: false, reason: 'job_pending', job: { identity: { jobId: p.id, sequence: p.sequence, envelopeDigest: p.digest }, target: view.incident.serviceName, operation: 'restart', actorId: actor, approvedAt: now, startDeadline: p.expiresAt, state: 'approved', result: null } });
        fireEvent.click(screen.getByRole('checkbox')); fireEvent.click(screen.getByRole('button', { name: 'Approve this action once' })); await flush();
        expect(mutateRaw).toHaveBeenCalledTimes(2); expect(vi.mocked(mutateRaw).mock.calls[1][2]).toEqual({});
    });
    it('rejects replacement-incarnation previews without offering approval', async () => {
        render(<WindowsCompleteServiceIncidentReview {...props()}/>); await flush();
        const p = preview(); p.preview.binding = { ...p.preview.binding as WindowsActionBinding, incarnationDigest: `sha256:${'b'.repeat(64)}` };
        vi.mocked(mutateRaw).mockResolvedValueOnce(p); await choose(); expect(screen.queryByRole('checkbox')).toBeNull(); expect(screen.getByRole('alert')).toBeVisible();
    });
    it.each(['en', 'de'] as const)('keeps unsupported native names readable and control blocked in %s', async locale => {
        view = structuredClone(wire.unsupported) as WindowsCompleteServiceIncidentReviewView; setLocale(locale, false);
        render(<WindowsCompleteServiceIncidentReview {...props()}/>); await flush();
        expect(screen.getByRole('status')).toHaveTextContent(locale === 'de' ? 'Nur lesen:' : 'Read-only:'); expect(screen.getByRole('heading')).toHaveTextContent(view.incident.serviceName);
        expect(vi.mocked(request).mock.calls.map(([p]) => p)).toEqual([path()]); expect(screen.queryByRole('button', { name: /^Select service:/ })).toBeNull(); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('retains the active episode as unknown without inventing stopped', async () => {
        view = structuredClone(wire.unknown) as WindowsCompleteServiceIncidentReviewView; render(<WindowsCompleteServiceIncidentReview {...props()}/>); await flush();
        expect(screen.getByText('Incident active')).toBeVisible(); expect(screen.getByText(/Current state unknown/)).toBeVisible(); expect(screen.queryByText('Stopped')).toBeNull(); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it.each(['blur', 'pagehide', 'hashchange', 'popstate', AUTH_REQUIRED_EVENT])('discards late results after %s', async event => {
        let finish!: (value: unknown) => void; vi.mocked(request).mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }) as never);
        render(<WindowsCompleteServiceIncidentReview {...props()}/>); act(() => window.dispatchEvent(new Event(event))); await act(async () => finish(view));
        expect(screen.queryByText('Stopped')).toBeNull(); expect(mutateRaw).not.toHaveBeenCalled(); expect(screen.getByRole('alert')).toBeVisible();
    });
    it('expires at the original broker deadline and cannot renew through status reads', async () => {
        render(<WindowsCompleteServiceIncidentReview {...props()}/>); await flush(); await act(async () => vi.advanceTimersByTime(30000));
        fireEvent.click(screen.getByRole('button', { name: 'Read saved status' })); await flush(); await act(async () => vi.advanceTimersByTime(30000));
        expect(screen.getByRole('alert')).toHaveTextContent('expired'); expect(screen.queryByRole('button', { name: /^Select service:/ })).toBeNull(); expect(mutateRaw).not.toHaveBeenCalled();
    });
});
