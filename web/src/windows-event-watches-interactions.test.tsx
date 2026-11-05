// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import userEvent from '@testing-library/user-event';
import { setLocale } from './i18n';
import { EventWatchEditor, WindowsEventWatchPanel, eventWatchCopy } from './windows-event-watches';
import type { EventWatchesView } from './windows-event-watches-types';

const panelWrite = vi.hoisted(() => vi.fn());
vi.mock('./windows-event-watches-resource', () => ({
    useWindowsEventWatches: (open: boolean) => ({ view: open ? fixture() : null, busy: false, uncertain: false, refresh: vi.fn(), write: panelWrite }),
}));
afterEach(() => { cleanup(); panelWrite.mockReset(); });
function fixture(): EventWatchesView {
    return {
        schemaVersion: 'tracebolt.windows-event-watches.v1', deviceId: 'agent_' + 'a'.repeat(32), serverNow: '2026-11-04T20:00:00Z', validUntil: '2026-11-04T20:00:30Z', revision: 0, canManage: true,
        source: { token: 'eventsource_' + 'b'.repeat(32), available: true, collectedAt: '2026-11-04T19:59:55Z', receivedAt: '2026-11-04T19:59:56Z', reason: 'none', choices: Array.from({ length: 5 }, (_, i) => ({ channel: 'Application' as const, provider: `Provider ${i + 1}`, eventId: 1000 + i, level: 2 })) },
        policy: { enabled: false, selectors: [], enabledAt: null, retentionAcknowledged: false }, status: 'disabled', incidents: [], retentionDays: 7, maxSelectors: 4, maxIncidents: 100, lastRequest: null,
    };
}
describe('event watch selection and progressive disclosure', () => {
    it.each(['en', 'de'] as const)('makes the selection cap visible and preserves explicit consent in %s', locale => {
        const write = vi.fn(); render(<EventWatchEditor view={fixture()} disabled={false} locale={locale} write={write}/>);
        const boxes = screen.getAllByRole('checkbox');
        expect(boxes[5]).toBeDisabled();
        for (let i = 0; i < 4; i++) fireEvent.click(boxes[i]);
        expect(screen.getByText(eventWatchCopy[locale].limit)).toBeInTheDocument();
        expect(boxes[4]).toBeDisabled();
        const save = screen.getByRole('button', { name: eventWatchCopy[locale].enable });
        expect(save).toBeDisabled(); fireEvent.click(boxes[5]); expect(save).toBeEnabled();
        fireEvent.click(boxes[0]); expect(boxes[5]).not.toBeChecked(); expect(save).toBeDisabled(); expect(boxes[4]).toBeEnabled();
        fireEvent.click(boxes[4]); fireEvent.click(boxes[5]); fireEvent.click(save);
        expect(write).toHaveBeenCalledTimes(1);
        expect(write.mock.calls[0][0]).toMatchObject({ operation: 'policy', body: { enabled: true, retentionAcknowledged: true, expectedRevision: 0 } });
        expect(write.mock.calls[0][0].body.selectors.map((s: { provider: string }) => s.provider)).toEqual(['Provider 2', 'Provider 3', 'Provider 4', 'Provider 5']);
        expect(save).toBeDisabled(); expect(boxes[5]).not.toBeChecked();
    });
    it('shows localized UTC times while retaining original exact timestamps and closed timing details', () => {
        const view = fixture(); view.incidents.push({ id: 'wevent_' + 'd'.repeat(16), selector: view.source.choices[0], firstObservedAt: '2026-11-04T19:59:55Z', lastObservedAt: '2026-11-04T19:59:55Z', firstReceivedAt: '2026-11-04T19:59:56Z', lastReceivedAt: '2026-11-04T19:59:56Z', countLowerBound: 1, reviewedAt: null });
        const { container } = render(<EventWatchEditor view={view} disabled={false} locale="de" write={vi.fn()}/>);
        const time = container.querySelector('time')!;
        expect(time).toHaveAttribute('datetime', view.source.collectedAt); expect(time).toHaveAttribute('title', view.source.collectedAt); expect(time.textContent).toContain('UTC'); expect(time.textContent).not.toContain('T19:');
        const details = screen.getByText(eventWatchCopy.de.timing).closest('details'); expect(details).not.toHaveAttribute('open');
        expect(screen.getByText(eventWatchCopy.de.retention)).toBeInTheDocument();
        const observations = container.querySelector('.windows-event-watches-incidents');
        expect(observations).toHaveAttribute('role', 'list');
        expect(observations?.children).toHaveLength(1);
        expect(observations?.firstElementChild?.tagName).toBe('LI');
    });
    it.each(['en', 'de'] as const)('labels stored entries and keeps the disable consequence visible in %s', locale => {
        const view = fixture(), write = vi.fn();
        view.policy = { enabled: true, selectors: [view.source.choices[0]], enabledAt: view.serverNow, retentionAcknowledged: true }; view.status = 'baselining';
        render(<EventWatchEditor view={view} disabled={false} locale={locale} write={write}/>);
        expect(screen.getByRole('heading', { name: `${eventWatchCopy[locale].history} 0` })).toBeVisible();
        const notice = screen.getByText(eventWatchCopy[locale].disableHelp);
        expect(notice).toBeVisible(); expect(notice.closest('details')).toBeNull();
        const disable = screen.getByRole('button', { name: eventWatchCopy[locale].disable });
        expect(notice.parentElement).toContainElement(disable);
        fireEvent.click(disable);
        expect(write).toHaveBeenCalledTimes(1);
        expect(write.mock.calls[0][0]).toMatchObject({ operation: 'policy', body: { enabled: false, selectors: [], retentionAcknowledged: false } });
    });
    it('keeps uncertain or read-only views non-writable', () => {
        const write = vi.fn(), view = fixture();
        const { rerender } = render(<EventWatchEditor view={view} disabled locale="en" write={write}/>);
        for (const box of screen.getAllByRole('checkbox')) expect(box).toBeDisabled();
        rerender(<EventWatchEditor view={{ ...view, canManage: false }} disabled={false} locale="en" write={write}/>);
        expect(screen.queryByRole('checkbox')).toBeNull(); expect(write).not.toHaveBeenCalled();
    });
});

describe('event watch accordion keyboard flow (mocked resource)', () => {
    it('opens with Enter, closes with Space, and discards choices and consent on reopening', async () => {
        setLocale('en', false); const user = userEvent.setup();
        render(<WindowsEventWatchPanel deviceId={fixture().deviceId} scope="keyboard-fixture" sessionEnd={null}/>);
        const toggle = screen.getByRole('button', { name: eventWatchCopy.en.title });
        expect(toggle).toHaveAttribute('aria-expanded', 'false'); expect(screen.queryByRole('checkbox')).toBeNull();
        await user.tab(); expect(toggle).toHaveFocus(); await user.keyboard('{Enter}');
        expect(toggle).toHaveAttribute('aria-expanded', 'true');
        expect(document.getElementById(toggle.getAttribute('aria-controls')!)).toBeInTheDocument();
        await user.tab(); expect(screen.getByRole('button', { name: eventWatchCopy.en.refresh })).toHaveFocus();
        await user.tab(); const boxes = screen.getAllByRole('checkbox'); expect(boxes[0]).toHaveFocus(); await user.keyboard(' ');
        await user.click(boxes[5]); expect(boxes[5]).toBeChecked();
        expect(screen.getByRole('button', { name: eventWatchCopy.en.enable })).toBeEnabled();
        toggle.focus(); await user.keyboard(' '); expect(toggle).toHaveAttribute('aria-expanded', 'false'); expect(toggle).toHaveFocus();
        expect(screen.queryByRole('checkbox')).toBeNull();
        await user.keyboard('{Enter}');
        for (const box of screen.getAllByRole('checkbox')) expect(box).not.toBeChecked();
        expect(screen.getByRole('button', { name: eventWatchCopy.en.enable })).toBeDisabled(); expect(panelWrite).not.toHaveBeenCalled();
    });
});
