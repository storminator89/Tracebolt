import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, getProtectedRequestEpoch } from './api';
import { acceptWindowsCapacityClock, windowsCapacityElapsed } from './windows-capacity-clock';
import { windowsNow } from './windows-inventory-fixture';
beforeEach(() => { abortProtectedRequests(); vi.useFakeTimers(); vi.setSystemTime(windowsNow); });
afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks(); });
describe('Windows-capacity isolated timing watermarks', () => {
    it('retains request delay and elapsed floors through equal/slow replies across remount', () => { const e = getProtectedRequestEpoch(); expect(acceptWindowsCapacityClock('one', e, windowsNow, 250)).toBe(true); vi.advanceTimersByTime(1000); expect(acceptWindowsCapacityClock('one', e, windowsNow, 0)).toBe(true); vi.advanceTimersByTime(1000); expect(acceptWindowsCapacityClock('one', e, '2026-10-07T12:00:10.001Z', 0)).toBe(true); expect(windowsCapacityElapsed('one', e, '2026-10-07T12:00:10.001Z', 0)).toBe(2249); });
    it('rejects manager nanosecond regression and local clock divergence after unmount', () => { const e = getProtectedRequestEpoch(); expect(acceptWindowsCapacityClock('one', e, windowsNow, 0)).toBe(true); expect(acceptWindowsCapacityClock('one', e, '2026-10-07T12:00:09.999999999Z', 0)).toBe(false); vi.setSystemTime('2026-10-07T11:00:00Z'); expect(acceptWindowsCapacityClock('one', e, windowsNow, 0)).toBe(false); });
    it('never evicts a live device/session watermark and resets only with the authority epoch', () => { const e = getProtectedRequestEpoch(); for (let i = 0; i < 128; i++) expect(acceptWindowsCapacityClock(String(i), e, windowsNow, 0)).toBe(true); expect(acceptWindowsCapacityClock('overflow', e, windowsNow, 0)).toBe(false); abortProtectedRequests(); expect(windowsCapacityElapsed('0', e, windowsNow, 0)).toBe(Infinity); expect(acceptWindowsCapacityClock('overflow', getProtectedRequestEpoch(), windowsNow, 0)).toBe(true); });
});
