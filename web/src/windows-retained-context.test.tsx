import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { AUTH_REQUIRED_EVENT, request } from './api';
import { setLocale } from './i18n';
import { useWindowsInventory } from './windows-inventory-resource';
import { WindowsContextPanel } from './windows-retained-context';
import { validWindowsInventoryView, type WindowsInventoryView } from './windows-inventory-types';
import { windowsDeviceId, windowsNow } from './windows-inventory-fixture';
import { windowsSessionContextView } from './windows-session-context-fixture';
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn() }));

function fixture(at = '2026-10-07T11:00:00Z'): WindowsInventoryView {
    const v = windowsSessionContextView(), old = structuredClone(v.sessionContext);
    old.collectedAt = at; old.generationId = `sample_${'b'.repeat(32)}`;
    v.sessionContext.sessions = { quality: 'unavailable', reason: 'windows_session_context_budget_exhausted', observedCount: null, retainedCount: 0, truncatedCount: null, rows: [] };
    v.sessionContext.join = { quality: 'unavailable', reason: 'windows_session_context_budget_exhausted', status: 'unknown', name: null };
    return { ...v, retainedContext: { sessionContext: old } };
}
function Harness() { return <WindowsContextPanel kind="sessionContext" resource={useWindowsInventory(windowsDeviceId, true, 'fixture')}/>; }
const flush = () => act(async () => {});
beforeEach(() => { setLocale('en'); vi.mocked(request).mockResolvedValue(fixture()); });
afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.useRealTimers(); });

it('accepts independently aged generations only under the current exact grant', () => {
    expect(validWindowsInventoryView(fixture(), windowsDeviceId)).toBe(true);
    for (const change of [
        (v: WindowsInventoryView) => { v.retainedContext!.sessionContext!.grantId = '4'.repeat(32); },
        (v: WindowsInventoryView) => { delete v.sessionContext; },
        (v: WindowsInventoryView) => { v.retainedContext!.sessionContext!.collectedAt = v.sessionContext!.collectedAt; },
        (v: WindowsInventoryView) => { v.retainedContext!.sessionContext!.collectedAt = '2026-10-06T12:00:10Z'; },
        (v: WindowsInventoryView) => { v.status = 'revoked'; v.snapshot = null; },
    ]) { const v = fixture(); change(v); expect(validWindowsInventoryView(v, windowsDeviceId)).toBe(false); }
});
it('keeps latest budget failure beside the labeled original useful capture', async () => {
    render(<Harness/>); await flush();
    expect(screen.getByText('Show previous capture')).toBeVisible();
    fireEvent.click(screen.getByText('Show previous capture'));
    expect(screen.getByText('fixture-alex')).toBeVisible();
    expect(screen.getByText(/keeps its original capture time/)).toBeVisible();
    expect(document.querySelector('time[datetime="2026-10-07T11:00:00Z"]')).not.toBeNull();
    expect(document.querySelector('time[datetime="2026-10-07T12:00:00Z"]')).not.toBeNull();
    expect(screen.getAllByText('Unavailable').length).toBeGreaterThan(0);
});
it('expires prior private data at its own 24-hour boundary while current remains', async () => {
    vi.useFakeTimers(); vi.setSystemTime(windowsNow); vi.mocked(request).mockResolvedValue(fixture('2026-10-06T12:00:11Z'));
    render(<Harness/>); await flush();
    expect(screen.getByText('Show previous capture')).toBeVisible();
    await act(async () => vi.advanceTimersByTimeAsync(1000));
    expect(screen.queryByText('Show previous capture')).toBeNull();
    expect(document.body).not.toHaveTextContent('fixture-alex');
    expect(document.querySelector('time[datetime="2026-10-07T12:00:00Z"]')).not.toBeNull();
});
it('clears even collapsed personal values when operator authority is lost', async () => {
    render(<Harness/>); await flush();
    expect(document.body).toHaveTextContent('fixture-alex');
    act(() => window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT)));
    expect(document.body).not.toHaveTextContent('fixture-alex');
    expect(screen.queryByText('Show previous capture')).toBeNull();
});
