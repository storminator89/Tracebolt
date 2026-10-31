import { act, cleanup, renderHook } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { abortProtectedRequests, AUTH_REQUIRED_EVENT } from './api';
import { useWindowsEventHistory } from './windows-event-history-resource';
import { cancelEventHistory, createEventHistory, createHistoryMessages, queryEventHistory, readEventHistory } from './windows-event-history-api';
import { historyRecord, historyView } from './windows-event-history-fixture';
import { windowsDeviceId } from './windows-inventory-fixture';
import type { EventHistoryView } from './windows-event-history-types';
vi.mock('./windows-event-history-api', () => ({ cancelEventHistory: vi.fn(), createEventHistory: vi.fn(), createHistoryMessages: vi.fn(), queryEventHistory: vi.fn(), readEventHistory: vi.fn() }));
const now = '2026-10-07T12:00:00Z', expiry = '2026-10-07T13:00:00Z';
const search = historyRecord().description.query.search!;
const flush = () => act(async () => {});
const mount = (id = windowsDeviceId) => renderHook(() => useWindowsEventHistory(id, true, false, expiry));
function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(done => { resolve = done; }); return { resolve, promise }; }
beforeEach(() => {
 vi.useFakeTimers(); vi.setSystemTime(now); abortProtectedRequests();
 vi.mocked(readEventHistory).mockReset().mockImplementation(async id => ({ ...historyView(), deviceId: id }));
 vi.mocked(createEventHistory).mockReset().mockRejectedValue(new Error('lost'));
 vi.mocked(cancelEventHistory).mockReset().mockRejectedValue(new Error('lost cancellation'));
 vi.mocked(createHistoryMessages).mockReset(); vi.mocked(queryEventHistory).mockReset();
});
afterEach(() => { abortProtectedRequests(); window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT)); cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); });
it.each(['lost', 'pending'] as const)('preserves %s creation across navigation without private selection or query authority', async outcome => {
 const pending = deferred<EventHistoryView>(); if (outcome === 'pending') vi.mocked(createEventHistory).mockReturnValue(pending.promise);
 const first = mount(); await flush(); act(() => { void first.result.current.create(search, true, false); }); await flush(); first.unmount(); await flush();
 const next = mount(); await flush(); expect(next.result.current.uncertain).toBe(true); expect(next.result.current.requestOwned).toBe(false); expect(next.result.current.report).toBeNull();
 act(() => { void next.result.current.create(search, true, false); }); await flush(); expect(createEventHistory).toHaveBeenCalledTimes(1); expect(queryEventHistory).not.toHaveBeenCalled();
 if (outcome === 'pending') { await act(async () => pending.resolve({ ...historyView(), expectedFloor: '1' })); expect(next.result.current.uncertain).toBe(true); }
 vi.mocked(readEventHistory).mockResolvedValue({ ...historyView(), expectedFloor: '1' }); act(() => next.result.current.refresh()); await flush();
 expect(next.result.current.uncertain).toBe(false); expect(next.result.current.requestOwned).toBe(false); expect(next.result.current.report).toBeNull(); expect(queryEventHistory).not.toHaveBeenCalled();
});
it('retains failed cleanup cancellation until exact terminal identity or a newer floor', async () => {
 const base = historyView(), record = historyRecord(base), active: EventHistoryView = { ...base, request: record, expectedFloor: '1', contentStatus: 'pending' };
 vi.mocked(createEventHistory).mockResolvedValue(active);
 const first = mount(); await flush(); await act(async () => first.result.current.create(search, true, false)); first.unmount(); await flush(); expect(cancelEventHistory).toHaveBeenCalledTimes(1);
 vi.mocked(readEventHistory).mockResolvedValue(active); const next = mount(); await flush(); expect(next.result.current.uncertain).toBe(true); expect(next.result.current.requestOwned).toBe(false);
 const other = { ...record, description: { ...record.description, identity: { ...record.description.identity, id: 'winhistory_' + 'f'.repeat(32) } }, state: 'canceled' as const, canceledAt: now };
 vi.mocked(readEventHistory).mockResolvedValue({ ...active, request: other, contentStatus: 'canceled' }); act(() => next.result.current.refresh()); await flush(); expect(next.result.current.uncertain).toBe(true);
 vi.mocked(readEventHistory).mockResolvedValue({ ...active, request: { ...record, state: 'canceled', canceledAt: now }, contentStatus: 'canceled' }); act(() => next.result.current.refresh()); await flush(); expect(next.result.current.uncertain).toBe(false); expect(createEventHistory).toHaveBeenCalledTimes(1);
});
it('does not let stale cleanup replace a newer create fence', async () => {
 const oldRead = deferred<EventHistoryView>(); const first = mount(); await flush(); await act(async () => first.result.current.create(search, true, false));
 vi.mocked(readEventHistory).mockReturnValueOnce(oldRead.promise); first.unmount(); await flush();
 vi.mocked(readEventHistory).mockResolvedValue({ ...historyView(), expectedFloor: '1' }); const next = mount(); await flush(); expect(next.result.current.uncertain).toBe(false);
 await act(async () => next.result.current.create(search, true, false)); expect(next.result.current.uncertain).toBe(true); expect(createEventHistory).toHaveBeenCalledTimes(2);
 const oldRecord = historyRecord(); await act(async () => oldRead.resolve({ ...historyView(), expectedFloor: '1', request: oldRecord, contentStatus: 'pending' })); await flush();
 expect(cancelEventHistory).not.toHaveBeenCalled(); act(() => next.result.current.refresh()); await flush(); expect(next.result.current.uncertain).toBe(true);
});
it('does not let a stale cleanup cancellation delete a newer create fence', async () => {
 const base = historyView(), record = historyRecord(), active: EventHistoryView = { ...base, expectedFloor: '1', request: record, contentStatus: 'pending' };
 vi.mocked(createEventHistory).mockResolvedValueOnce(active); const first = mount(); await flush(); await act(async () => first.result.current.create(search, true, false));
 const oldCancel = deferred<EventHistoryView>(); vi.mocked(cancelEventHistory).mockReturnValueOnce(oldCancel.promise); first.unmount(); await flush();
 const terminal: EventHistoryView = { ...active, request: { ...record, state: 'canceled', canceledAt: now }, contentStatus: 'canceled' };
 vi.mocked(readEventHistory).mockResolvedValue(terminal); const next = mount(); await flush(); expect(next.result.current.uncertain).toBe(false);
 await act(async () => next.result.current.create(search, true, false)); expect(next.result.current.uncertain).toBe(true);
 await act(async () => oldCancel.resolve(terminal)); act(() => next.result.current.refresh()); await flush(); expect(next.result.current.uncertain).toBe(true); expect(createEventHistory).toHaveBeenCalledTimes(2);
});
it('clears old authentication epoch fences without an AUTH event or retained private data', async () => {
 const first = mount(); await flush(); await act(async () => first.result.current.create(search, true, false)); act(() => abortProtectedRequests()); first.unmount();
 const next = mount(); await flush(); expect(next.result.current.uncertain).toBe(false); expect(next.result.current.report).toBeNull(); expect(next.result.current.requestOwned).toBe(false); expect(cancelEventHistory).not.toHaveBeenCalled();
});
it('bounds navigation metadata without evicting unresolved requests', async () => {
 for (let index = 1; index <= 32; index++) { const ui = mount(`agent_${index.toString(16).padStart(32, '0')}`); await flush(); await act(async () => ui.result.current.create(search, true, false)); ui.unmount(); await flush(); }
 expect(createEventHistory).toHaveBeenCalledTimes(32);
 const excess = mount(`agent_${'f'.repeat(32)}`); await flush(); await act(async () => excess.result.current.create(search, true, false)); expect(excess.result.current.failure).toBe('unavailable'); expect(createEventHistory).toHaveBeenCalledTimes(32); excess.unmount();
 const oldest = mount(`agent_${'1'.padStart(32, '0')}`); await flush(); expect(oldest.result.current.uncertain).toBe(true);
});


it('does not let an old mounted cancellation overwrite a newer create fence', async () => {
 const base = historyView(), record = historyRecord(), active: EventHistoryView = { ...base, expectedFloor: '1', request: record, contentStatus: 'pending' };
 vi.mocked(createEventHistory).mockResolvedValueOnce(active); const old = mount(); await flush(); await act(async () => old.result.current.create(search, true, false));
 const terminal: EventHistoryView = { ...active, request: { ...record, state: 'canceled', canceledAt: now }, contentStatus: 'canceled' };
 vi.mocked(readEventHistory).mockResolvedValue(terminal); const newer = mount(); await flush(); await act(async () => newer.result.current.create(search, true, false));
 expect(newer.result.current.uncertain).toBe(true); act(() => old.result.current.cancel()); await flush(); expect(cancelEventHistory).not.toHaveBeenCalled();
 act(() => newer.result.current.refresh()); await flush(); expect(newer.result.current.uncertain).toBe(true); expect(createEventHistory).toHaveBeenCalledTimes(2);
});
it('does not clear a retained fence with a different session binding', async () => {
 const old = mount(); await flush(); await act(async () => old.result.current.create(search, true, false)); old.unmount(); await flush();
 vi.mocked(readEventHistory).mockResolvedValue({ ...historyView(), sessionBinding: 'f'.repeat(64), expectedFloor: '1' }); const wrong = mount(); await flush(); expect(wrong.result.current.failure).toBe('session'); wrong.unmount();
 vi.mocked(readEventHistory).mockResolvedValue(historyView()); const original = mount(); await flush(); expect(original.result.current.uncertain).toBe(true); expect(createEventHistory).toHaveBeenCalledTimes(1);
});
