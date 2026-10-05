import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { JournalContent } from './journal';
import { journalNow, journalPage, journalView } from './journal-fixtures';
import type { JournalResource } from './journal-resource';
import { setLocale } from './i18n';
function resource(change: Partial<JournalResource> = {}): JournalResource {
    return { view: journalView('awaiting'), page: null, busy: false, paused: false, failure: null, uncertain: false, reset: 0, refresh: vi.fn(), create: vi.fn(async () => {}), cancelRequest: vi.fn(), search: vi.fn(), next: vi.fn(), previous: vi.fn(), canPrevious: false, ...change };
}
beforeEach(() => setLocale('en', false));
afterEach(cleanup);

describe('compact log workspace presentation', () => {
    it('leads with service selection and short presets, keeping technical inputs and consent out of the default surface', () => {
        const r = resource(); render(<JournalContent resource={r} insecureTestMode/>);
        expect(screen.getByRole('button', { name: 'Choose observed service' })).toBeVisible();
        expect(screen.getByRole('button', { name: '15 minutes ending at reference time' })).toHaveTextContent('15 min');
        expect(screen.getByRole('button', { name: 'Fetch logs' })).toBeDisabled();
        expect(screen.getByLabelText('Exact service unit')).not.toBeVisible(); expect(screen.getByLabelText('From (UTC)')).not.toBeVisible();
        expect(screen.queryByRole('checkbox')).not.toBeInTheDocument(); expect(screen.getByText('Permission not verified')).toBeVisible();
        expect(screen.getByText('Log sources', { selector: 'h3' })).not.toBeVisible();
        expect(r.create).not.toHaveBeenCalled(); expect(r.refresh).not.toHaveBeenCalled(); expect(r.cancelRequest).not.toHaveBeenCalled();
        fireEvent.click(screen.getByText('Advanced', { selector: 'summary' })); expect(screen.getByLabelText('Exact service unit')).toBeVisible();
        expect(screen.getByText(/Reference time \(UTC, last checked manager time\):/, { selector: '.journal-advanced p' })).toHaveTextContent(journalNow);
        fireEvent.click(screen.getByText('Permissions & sources', { selector: 'summary' })); expect(screen.getByText('Log sources', { selector: 'h3' })).toBeVisible();
    });
    it('announces one active loading status while retaining the prior snapshot status as context', () => {
        const r = resource({ view: journalView(), busy: true }); render(<JournalContent resource={r} insecureTestMode={false}/>);
        expect(screen.getAllByRole('status')).toHaveLength(1); expect(screen.getByRole('status')).toHaveTextContent('Reading journal status or captured content');
        expect(screen.getByText('Captured snapshot available')).toBeVisible(); expect(screen.getByRole('button', { name: 'Fetch logs' })).toBeDisabled(); expect(r.create).not.toHaveBeenCalled();
    });
    it('shows a reported all-service grant before selection without claiming a selected service or enabling capture', () => {
        const view = journalView('awaiting'); view.schemaVersion = 'tracebolt.journal-view.v2';
        view.generation = { schemaVersion: 'tracebolt.journal-generation-view.v2', policyGeneration: { revision: '1', generation: 'a'.repeat(64), policyDigest: `sha256:${'b'.repeat(64)}` }, sequence: '1', observedAt: journalNow, receivedAt: journalNow, expiresAt: '2026-10-04T12:05:00Z', fresh: true, policyEnabled: true, serviceAuthorization: 'all-system-services', allowedUnits: [] };
        const r = resource({ view }); render(<JournalContent resource={r} insecureTestMode={false}/>);
        expect(screen.getByText('All service units · reported grant')).toBeVisible(); expect(screen.queryByText('Outside reported grant')).not.toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Fetch logs' })).toBeDisabled(); expect(r.create).not.toHaveBeenCalled();
    });
    it('keeps a pending request identity/window visible when the editable draft targets another service', () => {
        const view = journalView('pending'), r = resource({ view }); render(<JournalContent resource={r} insecureTestMode={false} initialUnit="different.service"/>);
        const state = screen.getByRole('status'); expect(state).toHaveTextContent('Pending'); expect(state).toHaveTextContent('fixture.service');
        expect(state.querySelectorAll('time')[0]).toHaveAttribute('datetime', view.request!.description.query.start); expect(state.querySelectorAll('time')[1]).toHaveAttribute('datetime', view.request!.description.query.end);
        fireEvent.click(screen.getByRole('button', { name: '5 minutes ending at reference time' }));
        expect(state.querySelectorAll('time')[0]).toHaveAttribute('datetime', view.request!.description.query.start); expect(screen.getByRole('button', { name: 'Fetch logs' })).toBeDisabled();
        expect(r.create).not.toHaveBeenCalled(); expect(r.cancelRequest).not.toHaveBeenCalled();
    });
    it('keeps the retained capture window and severity visible independently of draft edits', () => {
        const view = journalView(), page = journalPage(), r = resource({ view, page }); render(<JournalContent resource={r} insecureTestMode={false} initialUnit="new.service"/>);
        const summary = document.querySelector('.journal-captured-window')!; expect(summary).toHaveTextContent('6 · Info');
        expect(summary.querySelectorAll('time')[0]).toHaveAttribute('datetime', view.request!.description.query.start);
        fireEvent.click(screen.getByRole('button', { name: '5 minutes ending at reference time' }));
        expect(summary.querySelectorAll('time')[0]).toHaveAttribute('datetime', view.request!.description.query.start); expect(screen.getByText('Synthetic fixture message')).toBeVisible();
        expect(r.create).not.toHaveBeenCalled(); expect(r.search).not.toHaveBeenCalled();
    });
    it('does not silently replace an explicitly cleared custom window with a default', () => {
        const r = resource(), mounted = render(<JournalContent resource={r} insecureTestMode={false} initialUnit="fixture.service"/>);
        fireEvent.click(screen.getByText('Advanced', { selector: 'summary' }));
        fireEvent.change(screen.getByLabelText('From (UTC)'), { target: { value: '' } }); fireEvent.change(screen.getByLabelText('To (UTC)'), { target: { value: '' } });
        expect(screen.getByLabelText('From (UTC)')).toHaveValue(''); expect(screen.getByLabelText('To (UTC)')).toHaveValue(''); expect(screen.getByRole('button', { name: 'Fetch logs' })).toBeDisabled();
        mounted.rerender(<JournalContent resource={{ ...r, view: { ...r.view!, serverNow: '2026-10-04T12:00:30Z' } }} insecureTestMode={false} initialUnit="fixture.service"/>);
        expect(screen.getByLabelText('From (UTC)')).toHaveValue(''); expect(screen.getByLabelText('To (UTC)')).toHaveValue(''); expect(r.create).not.toHaveBeenCalled();
    });
    it('shows exact custom milliseconds in request review while avoiding raw manager nanoseconds in the main reference', () => {
        const view = journalView('awaiting'); view.serverNow = '2026-10-04T12:00:00.123456789Z';
        const r = resource({ view }); render(<JournalContent resource={r} insecureTestMode={false} initialUnit="fixture.service"/>);
        expect(document.querySelector('.journal-preset-hint time')).not.toHaveTextContent('.123456789');
        fireEvent.click(screen.getByText('Advanced', { selector: 'summary' }));
        fireEvent.change(screen.getByLabelText('From (UTC)'), { target: { value: '2026-10-04T11:59:00.001' } });
        fireEvent.change(screen.getByLabelText('To (UTC)'), { target: { value: '2026-10-04T11:59:00.002' } });
        fireEvent.click(screen.getByRole('button', { name: 'Fetch logs' })); const dialog = screen.getByRole('dialog', { name: 'Review log request' });
        expect(within(dialog).getByText(/00\.001 UTC/)).toBeVisible(); expect(within(dialog).getByText(/00\.002 UTC/)).toBeVisible();
        expect(within(dialog).getByRole('checkbox')).not.toBeChecked(); expect(r.create).not.toHaveBeenCalled();
    });
});
