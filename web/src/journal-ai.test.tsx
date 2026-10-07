import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, APIError, AUTH_REQUIRED_EVENT, mutateRaw, request } from './api';
import { useOperator } from './auth';
import { setLocale } from './i18n';
import { JournalAISettingsPanel } from './journal-ai';
import { journalAIAllows, validJournalAISettings, validJournalAISource } from './journal-ai-types';
import type { JournalAISettings, JournalAISource } from './journal-ai-types';
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutateRaw: vi.fn() }));
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
const id = 'agent_00000000000000000000000000000001';
const operator = { mode: 'lan' as const, authenticated: true, loginMode: 'shared' as const, expiresAt: '2026-10-07T15:00:00Z', insecureTestMode: false, logout: vi.fn(), theme: 'light' as const, setTheme: vi.fn() };
const generation = { revision: '1', generation: 'a'.repeat(64), policyDigest: `sha256:${'b'.repeat(64)}` };
const settings = (): JournalAISettings => ({ schemaVersion: 'tracebolt.journal-ai-settings.v1', revision: 'scope-a', enabled: false, ready: false, configRevision: 'config-a', providerSaved: true, baseURL: 'http://127.0.0.1:11434/v1', model: 'fixture-model', targets: [], lookbackMinutes: 5, approvedAt: '0001-01-01T00:00:00Z', devices: [id], plaintext: false, maxTargets: 8, maxAnalysesPerHour: 2, maxRows: 10, maxMessageBytes: 1024, dataScope: 'service-journal-ai-v1', retention: 'original-capture-expiry-memory-only', blocked: false, cancellationPending: false });
const source = (): JournalAISource => ({ deviceId: id, serverNow: '2026-10-07T14:00:00Z', generation: { schemaVersion: 'tracebolt.journal-generation-view.v2', policyGeneration: generation, sequence: '1', observedAt: '2026-10-07T14:00:00Z', receivedAt: '2026-10-07T14:00:00Z', expiresAt: '2026-10-07T14:05:00Z', fresh: true, policyEnabled: true, serviceAuthorization: 'exact-units', allowedUnits: ['fixture.service'] } });
const flush = () => act(async () => {});
const button = (name: string) => screen.getByRole('button', { name });
const enable = () => button('Approve and enable service-log AI');
async function start(v = settings(), s: unknown = source()) { vi.mocked(request).mockImplementation(async path => path === '/ai/journal' ? v : s); render(<JournalAISettingsPanel/>); fireEvent.click(button('Service-log AI')); await flush(); }
async function prepare(v = settings()) { await start(v); fireEvent.click(button('Read local policy')); await flush(); fireEvent.change(screen.getByRole('textbox', { name: 'Service' }), { target: { value: 'fixture.service' } }); fireEvent.click(button('Add service')); }
beforeEach(() => { vi.useFakeTimers(); vi.setSystemTime('2026-10-07T14:00:00Z'); localStorage.clear(); sessionStorage.clear(); setLocale('en', false); vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('visible'); vi.mocked(useOperator).mockReturnValue(operator); vi.mocked(request).mockReset(); vi.mocked(mutateRaw).mockReset(); });
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.restoreAllMocks(); });
describe('service-log AI approval', () => {
    it('does no read while collapsed and never treats the local grant as export approval', async () => { render(<JournalAISettingsPanel/>); expect(request).not.toHaveBeenCalled(); expect(mutateRaw).not.toHaveBeenCalled(); });
    it('binds exact provider, target generation and window only after both unchecked approvals', async () => { await prepare(); const boxes = screen.getAllByRole('checkbox'); expect(boxes).toHaveLength(2); boxes.forEach(b => expect(b).not.toBeChecked()); expect(enable()).toBeDisabled(); fireEvent.click(boxes[0]); expect(enable()).toBeDisabled(); fireEvent.click(boxes[1]); expect(enable()).toBeEnabled(); vi.mocked(request).mockResolvedValue({ ...settings(), revision: 'scope-b', enabled: true, ready: true, approvedAt: source().serverNow, targets: [{ deviceId: id, unit: 'fixture.service', generation }] }); vi.mocked(mutateRaw).mockResolvedValue({ saved: true, revision: 'scope-b', enabled: true, cancellationPending: false }); fireEvent.click(enable()); await flush(); const call = vi.mocked(mutateRaw).mock.calls[0]; expect(call[0]).toBe('/ai/journal'); expect(JSON.parse(call[1])).toEqual({ dataScope: 'service-journal-ai-v1', expectedRevision: 'scope-a', configRevision: 'config-a', enabled: true, baseURL: settings().baseURL, model: 'fixture-model', targets: [{ deviceId: id, unit: 'fixture.service', generation }], lookbackMinutes: 5, acknowledgeCapture: true, acknowledgeExport: true, acknowledgePlaintext: false }); expect(mutateRaw).toHaveBeenCalledTimes(1); screen.getAllByRole('checkbox').forEach(b => expect(b).not.toBeChecked()); expect(screen.getByText(/Approval saved/)).toBeVisible(); });
    it('discloses local snapshot bounds separately from the smaller AI export', async () => { await prepare(); expect(screen.getByText(/Local capture: up to 500 rows \/ 512 KiB, at most 4 KiB\/message\. AI export: latest 10 rows, at most 1 KiB\/message/)).toBeVisible(); });
    it('requires the separate HTTP transport acknowledgement', async () => { await prepare({ ...settings(), plaintext: true }); const boxes = screen.getAllByRole('checkbox'); expect(boxes).toHaveLength(3); fireEvent.click(boxes[0]); fireEvent.click(boxes[1]); expect(enable()).toBeDisabled(); fireEvent.click(boxes[2]); expect(enable()).toBeEnabled(); });
    it('refuses a stale, disabled, wrong-generation or out-of-scope source', async () => { const s = source(); s.generation!.policyEnabled = false; await start(settings(), s); fireEvent.click(button('Read local policy')); await flush(); fireEvent.change(screen.getByRole('textbox', { name: 'Service' }), { target: { value: 'fixture.service' } }); expect(button('Add service')).toBeDisabled(); expect(enable()).toBeDisabled(); expect(mutateRaw).not.toHaveBeenCalled(); });
    it('explains changed local policy without silently rebinding the saved target', async () => { const v = { ...settings(), enabled: true, ready: false, approvedAt: source().serverNow, targets: [{ deviceId: id, unit: 'fixture.service', generation: { ...generation, revision: '2' } }] }; await start(v); expect(screen.getByText('Policy changed. Remove and add this service again.')).toBeVisible(); expect(enable()).toBeDisabled(); expect(mutateRaw).not.toHaveBeenCalled(); });
    it('allows disabling even when a saved source lookup fails', async () => { const v = { ...settings(), enabled: true, ready: false, approvedAt: source().serverNow, targets: [{ deviceId: id, unit: 'fixture.service', generation }] }; vi.mocked(request).mockImplementation(async path => { if (path === '/ai/journal') return v; throw new APIError('unavailable', 404); }); render(<JournalAISettingsPanel/>); fireEvent.click(button('Service-log AI')); await flush(); expect(button('Disable service-log AI')).toBeEnabled(); vi.mocked(request).mockResolvedValue({ ...settings(), cancellationPending: true }); vi.mocked(mutateRaw).mockResolvedValue({ saved: true, revision: 'scope-a', enabled: false, cancellationPending: true }); fireEvent.click(button('Disable service-log AI')); await flush(); expect(JSON.parse(vi.mocked(mutateRaw).mock.calls[0][1]).enabled).toBe(false); expect(screen.getByText(/Cancellation of earlier captures/)).toBeVisible(); });
    it.each(['blur', 'pagehide', 'hashchange', 'popstate', AUTH_REQUIRED_EVENT, 'tracebolt-ai-config-changed'])('clears reviewed consent on %s', async event => { await prepare(); screen.getAllByRole('checkbox').forEach(b => fireEvent.click(b)); act(() => window.dispatchEvent(new Event(event))); expect(screen.queryByRole('checkbox')).not.toBeInTheDocument(); expect(mutateRaw).not.toHaveBeenCalled(); });
    it('bounds review time and prevents replay after an ambiguous write', async () => { await prepare(); screen.getAllByRole('checkbox').forEach(b => fireEvent.click(b)); vi.mocked(mutateRaw).mockReturnValue(new Promise(() => {})); fireEvent.click(enable()); await act(async () => vi.advanceTimersByTimeAsync(10000)); expect(screen.getByRole('alert')).toHaveTextContent('may have taken effect'); expect(mutateRaw).toHaveBeenCalledTimes(1); await act(async () => vi.advanceTimersByTimeAsync(60000)); expect(mutateRaw).toHaveBeenCalledTimes(1); });
    it('clears acknowledgement when the selected window changes', async () => { await prepare(); screen.getAllByRole('checkbox').forEach(b => fireEvent.click(b)); fireEvent.change(screen.getByRole('combobox', { name: 'Minutes before incident' }), { target: { value: '15' } }); screen.getAllByRole('checkbox').forEach(b => expect(b).not.toBeChecked()); });
    it('clears consent when the source expires before the review timeout', async () => {
        const s = source(); s.serverNow = '2026-10-07T14:04:59Z';
        await start(settings(), s); fireEvent.click(button('Read local policy')); await flush();
        fireEvent.change(screen.getByRole('textbox', { name: 'Service' }), { target: { value: 'fixture.service' } }); fireEvent.click(button('Add service'));
        screen.getAllByRole('checkbox').forEach(b => fireEvent.click(b)); expect(enable()).toBeEnabled();
        await act(async () => vi.advanceTimersByTimeAsync(1000));
        expect(screen.queryByRole('checkbox')).not.toBeInTheDocument(); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('reports an uncertain write if the reviewed source expires while saving', async () => {
        const s = source(); s.serverNow = '2026-10-07T14:04:59Z';
        await start(settings(), s); fireEvent.click(button('Read local policy')); await flush();
        fireEvent.change(screen.getByRole('textbox', { name: 'Service' }), { target: { value: 'fixture.service' } }); fireEvent.click(button('Add service'));
        screen.getAllByRole('checkbox').forEach(b => fireEvent.click(b)); vi.mocked(mutateRaw).mockReturnValue(new Promise(() => {})); fireEvent.click(enable());
        await act(async () => vi.advanceTimersByTimeAsync(1000)); expect(screen.getByRole('alert')).toHaveTextContent('may have taken effect'); expect(mutateRaw).toHaveBeenCalledTimes(1);
    });
    it('does not renew provider review lifetime when a local policy is reread', async () => {
        await prepare(); await act(async () => vi.advanceTimersByTimeAsync(45000));
        fireEvent.click(button('Read local policy')); await flush(); screen.getAllByRole('checkbox').forEach(b => fireEvent.click(b));
        expect(enable()).toBeEnabled(); await act(async () => vi.advanceTimersByTimeAsync(15000));
        expect(screen.queryByRole('checkbox')).not.toBeInTheDocument(); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('rechecks source expiry at the click rather than relying on the previous render', async () => {
        const s = source(); s.serverNow = '2026-10-07T14:04:59Z';
        await start(settings(), s); fireEvent.click(button('Read local policy')); await flush();
        fireEvent.change(screen.getByRole('textbox', { name: 'Service' }), { target: { value: 'fixture.service' } }); fireEvent.click(button('Add service'));
        screen.getAllByRole('checkbox').forEach(b => fireEvent.click(b));
        vi.spyOn(performance, 'now').mockReturnValue(performance.now() + 1001); vi.setSystemTime(Date.now() + 1001);
        fireEvent.click(enable()); await flush(); expect(mutateRaw).not.toHaveBeenCalled(); expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();
    });
    it('does not allow approval while protected storage is blocked', async () => { await prepare({ ...settings(), blocked: true }); screen.getAllByRole('checkbox').forEach(b => expect(b).toBeDisabled()); expect(enable()).toBeDisabled(); });
    it('drops a settings reply held across close and reopening', async () => {
        let resolve!: (v: unknown) => void; vi.mocked(request).mockReturnValueOnce(new Promise(done => { resolve = done; }));
        render(<JournalAISettingsPanel/>); fireEvent.click(button('Service-log AI')); await flush(); fireEvent.click(button('Close'));
        vi.mocked(request).mockResolvedValue({ ...settings(), model: 'current-model' }); fireEvent.click(button('Service-log AI')); await flush();
        await act(async () => resolve({ ...settings(), model: 'old-model' })); expect(screen.getByText(/current-model/)).toBeVisible(); expect(screen.queryByText(/old-model/)).not.toBeInTheDocument();
    });
    it('keeps named accounts read-only', async () => { vi.mocked(useOperator).mockReturnValue({ ...operator, loginMode: 'named' }); await start(); expect(screen.queryByRole('checkbox')).not.toBeInTheDocument(); expect(screen.queryByRole('button', { name: /enable service/ })).not.toBeInTheDocument(); });
});
describe('strict service-log contracts', () => {
    it('requires independent new scope and bounded values', () => { expect(validJournalAISettings(settings())).toBe(true); for (const patch of [{ maxRows: 500 }, { lookbackMinutes: 60 }, { lookbackMinutes: '5' }, { dataScope: 'health-summary-v1' }, { retention: 'disk' }, { cancellationPending: undefined }, { enabled: true }, { baseURL: 'http://user:pass@localhost/' }, { devices: [id, id] }, { extra: true }]) expect(validJournalAISettings({ ...settings(), ...patch })).toBe(false); });
    it('requires fresh explicit v2 local service policy without converting it to approval', () => { expect(validJournalAISource(source(), id)).toBe(true); expect(journalAIAllows(source(), 'fixture.service')).toBe(true); expect(journalAIAllows(source(), 'other.service')).toBe(false); expect(journalAIAllows(source(), 'fixture.service', 60000)).toBe(false); expect(journalAIAllows({ ...source(), generation: { ...source().generation!, policyEnabled: false } }, 'fixture.service')).toBe(false); expect(validJournalAISource({ ...source(), extra: true }, id)).toBe(false); });
});
