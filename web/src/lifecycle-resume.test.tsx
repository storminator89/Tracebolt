import { act, cleanup, renderHook } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, AUTH_REQUIRED_EVENT, mutateRaw, request } from './api';
import { useEndpointIdentity } from './endpoint-identity-resource';
import { useCachedUpdates } from './cached-updates-resource';
import { useCompletePackages } from './complete-packages-resource';
import { useCompleteOverview } from './complete-overview-resource';
import { useCompleteUpdates } from './complete-updates-resource';
import { useWindowsInventory } from './windows-inventory-resource';
import { useWindowsContact } from './windows-contact-resource';
import { useWindowsCapacity } from './windows-capacity-resource';
import { useWindowsServiceHealth } from './windows-service-health-resource';
import { useWindowsServiceHealthComplete } from './windows-service-health-complete-resource';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutateRaw: vi.fn() }));
const id = `agent_${'3'.repeat(32)}`, session = '2026-10-07T14:00:00Z';
const metadata = { checkedAt: '2026-10-07T12:00:00Z', expiresAt: '2026-11-07T12:00:00Z' };
const readers: [string, () => unknown][] = [
    ['Linux endpoint identity', () => useEndpointIdentity(id, true, session)],
    ['Linux cached updates', () => useCachedUpdates(id, true, session)],
    ['Linux complete packages', () => useCompletePackages(id)],
    ['Linux complete overview', () => useCompleteOverview(id, 'processes')],
    ['Linux complete updates', () => useCompleteUpdates(id)],
    ['Windows inventory', () => useWindowsInventory(id, true, session)],
    ['Windows contact', () => useWindowsContact(id, true, session)],
    ['Windows capacity', () => useWindowsCapacity(id, true, session, true, metadata)],
    ['Windows selected service health', () => useWindowsServiceHealth(id, true, session, true, metadata)],
    ['Windows complete service health', () => useWindowsServiceHealthComplete(id, true, session, true, metadata)],
];
const flush = () => act(async () => {});
const signal = (index: number) => vi.mocked(request).mock.calls[index][1]!.signal as AbortSignal;
function show() { const event = new Event('pageshow'); Object.defineProperty(event, 'persisted', { value: true }); window.dispatchEvent(event); }
beforeEach(() => {
    vi.useFakeTimers(); vi.setSystemTime(metadata.checkedAt); localStorage.clear(); sessionStorage.clear();
    vi.mocked(request).mockReset().mockImplementation(() => new Promise(() => {})); vi.mocked(mutateRaw).mockReset();
});
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.restoreAllMocks(); });

describe.each(readers)('%s lifecycle read admission', (_name, read) => {
    it('does not replace an active read for redundant focus/visible events', async () => {
        renderHook(read); await flush(); expect(request).toHaveBeenCalledTimes(1);
        const initial = signal(0);
        act(() => { window.dispatchEvent(new Event('focus')); document.dispatchEvent(new Event('visibilitychange')); });
        expect(request).toHaveBeenCalledTimes(1); expect(initial.aborted).toBe(false);
    });
    it('starts exactly one fresh read for a visibility, focus and pageshow restoration sequence', async () => {
        const visibility = vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('visible');
        renderHook(read); await flush();
        act(() => { visibility.mockReturnValue('hidden'); document.dispatchEvent(new Event('visibilitychange')); window.dispatchEvent(new Event('pagehide')); window.dispatchEvent(new Event('blur')); });
        expect(signal(0).aborted).toBe(true); expect(request).toHaveBeenCalledTimes(1);
        act(() => { visibility.mockReturnValue('visible'); document.dispatchEvent(new Event('visibilitychange')); });
        expect(request).toHaveBeenCalledTimes(2); const restored = signal(1);
        act(() => { window.dispatchEvent(new Event('focus')); show(); });
        expect(request).toHaveBeenCalledTimes(2); expect(restored.aborted).toBe(false);
        // A later, real suspension still cancels and admits a new read.
        act(() => window.dispatchEvent(new Event('blur'))); expect(restored.aborted).toBe(true);
        act(() => window.dispatchEvent(new Event('focus'))); expect(request).toHaveBeenCalledTimes(3);
        act(() => window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT))); expect(signal(2).aborted).toBe(true);
        act(() => { window.dispatchEvent(new Event('blur')); window.dispatchEvent(new Event('focus')); show(); });
        expect(request).toHaveBeenCalledTimes(3); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('keeps the original timeout through redundant restoration notifications', async () => {
        renderHook(read); await flush();
        await act(async () => { await vi.advanceTimersByTimeAsync(9000); });
        act(() => { window.dispatchEvent(new Event('focus')); document.dispatchEvent(new Event('visibilitychange')); show(); });
        await act(async () => { await vi.advanceTimersByTimeAsync(1000); });
        expect(request).toHaveBeenCalledTimes(1); expect(signal(0).aborted).toBe(true);
    });
});
