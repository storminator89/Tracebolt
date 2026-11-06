import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, APIError, mutateRaw, request } from './api';
import { useOperator } from './auth';
import { setLocale } from './i18n';
import { JournalAISettingsPanel } from './journal-ai';
import type { JournalAISettings, JournalAISource } from './journal-ai-types';
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutateRaw: vi.fn() }));
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
const id = 'agent_00000000000000000000000000000001';
const operator = { mode: 'lan' as const, authenticated: true, loginMode: 'shared' as const, expiresAt: '2026-10-07T15:00:00Z', insecureTestMode: false, logout: vi.fn(), theme: 'light' as const, setTheme: vi.fn() };
const generation = { revision: '1', generation: 'a'.repeat(64), policyDigest: `sha256:${'b'.repeat(64)}` };
const settings = (): JournalAISettings => ({ schemaVersion: 'tracebolt.journal-ai-settings.v1', revision: 'scope-a', enabled: false, ready: false, configRevision: 'config-a', providerSaved: true, baseURL: 'http://127.0.0.1:11434/v1', model: 'fixture-model', targets: [], lookbackMinutes: 5, approvedAt: '0001-01-01T00:00:00Z', devices: [id], plaintext: false, maxTargets: 8, maxAnalysesPerHour: 2, maxRows: 10, maxMessageBytes: 1024, dataScope: 'service-journal-ai-v1', retention: 'original-capture-expiry-memory-only', blocked: false, cancellationPending: false });
const source = (): JournalAISource => ({ deviceId: id, serverNow: '2026-10-07T14:00:00Z', generation: { schemaVersion: 'tracebolt.journal-generation-view.v2', policyGeneration: generation, sequence: '1', observedAt: '2026-10-07T14:00:00Z', receivedAt: '2026-10-07T14:00:00Z', expiresAt: '2026-10-07T14:05:00Z', fresh: true, policyEnabled: true, serviceAuthorization: 'exact-units', allowedUnits: ['fixture.service'] } });

beforeEach(()=>{vi.useFakeTimers();vi.setSystemTime('2026-10-07T14:00:00Z');localStorage.clear();sessionStorage.clear();vi.spyOn(document,'visibilityState','get').mockReturnValue('visible');vi.mocked(useOperator).mockReturnValue(operator);vi.mocked(request).mockReset();vi.mocked(mutateRaw).mockReset();});
afterEach(()=>{cleanup();abortProtectedRequests();vi.useRealTimers();vi.restoreAllMocks();});
const texts={en:'This review expired or was interrupted. Read the saved approval again, then review your selection again.',de:'Diese Prüfung ist abgelaufen oder wurde unterbrochen. Gespeicherte Freigabe neu lesen und die Auswahl erneut prüfen.'};
async function open(locale:'en'|'de'){
 setLocale(locale,false);const saved={...settings(),enabled:true,ready:true,approvedAt:source().serverNow,targets:[{deviceId:id,unit:'fixture.service',generation}]};
 vi.mocked(request).mockImplementation(async path=>path==='/ai/journal'?saved:source());render(<JournalAISettingsPanel/>);fireEvent.click(screen.getByRole('button',{name:locale==='de'?'Dienstlog-KI':'Service-log AI'}));await act(async()=>{});return saved;
}
describe('service-log AI local review expiration copy',()=>{
 it.each([['en','expiry'],['de','expiry'],['en','blur'],['de','blur']] as const)('explains only the local review and requires explicit reread (%s, %s)',async(locale,reason)=>{
  const saved=await open(locale);screen.getAllByRole('checkbox').forEach(box=>fireEvent.click(box));const reads=vi.mocked(request).mock.calls.length;
  if(reason==='expiry')await act(async()=>vi.advanceTimersByTimeAsync(60000));else act(()=>window.dispatchEvent(new Event('blur')));
  expect(screen.getByRole('alert')).toHaveTextContent(texts[locale]);expect(screen.queryByRole('checkbox')).toBeNull();expect(screen.queryByText('fixture.service')).toBeNull();expect(mutateRaw).not.toHaveBeenCalled();expect(request).toHaveBeenCalledTimes(reads);expect(saved.enabled).toBe(true);
  act(()=>window.dispatchEvent(new Event('focus')));expect(request).toHaveBeenCalledTimes(reads);
  fireEvent.click(screen.getByRole('button',{name:locale==='de'?'Prüfung aktualisieren':'Refresh review'}));await act(async()=>{});
  expect(screen.queryByText(texts[locale])).toBeNull();expect(screen.getByText(locale==='de'?'Ein':'On')).toBeVisible();screen.getAllByRole('checkbox').forEach(box=>expect(box).not.toBeChecked());expect(mutateRaw).not.toHaveBeenCalled();
 });
 it.each([['en',409],['de',409],['en',503],['de',503]] as const)('retains distinct conflict and uncertain-write warnings (%s, %s)',async(locale,status)=>{
  await open(locale);screen.getAllByRole('checkbox').forEach(box=>fireEvent.click(box));vi.mocked(mutateRaw).mockRejectedValue(new APIError('fixture failure',status));fireEvent.click(screen.getByRole('button',{name:locale==='de'?'Dienstlog-KI freigeben und aktivieren':'Approve and enable service-log AI'}));await act(async()=>{});
  expect(screen.queryByText(texts[locale])).toBeNull();expect(screen.getByRole('alert')).toHaveTextContent(status===409?(locale==='de'?'Aktualisieren und erneut prüfen.':'Refresh and review again.'):(locale==='de'?'Die Änderung kann bereits wirksam sein.':'The change may have taken effect.'));expect(mutateRaw).toHaveBeenCalledTimes(1);
 });
});
