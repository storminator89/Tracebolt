import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { JournalContent } from './journal';
import { journalNow, journalPage, journalView } from './journal-fixtures';
import type { JournalResource } from './journal-resource';
import { setLocale } from './i18n';
function resource(change: Partial<JournalResource> = {}): JournalResource {
    return { view: journalView('awaiting'), page: null, busy: false, paused: false, failure: null, uncertain: false, reset: 0, refresh: vi.fn(), refreshWindow: vi.fn(async () => null), create: vi.fn(async () => {}), cancelRequest: vi.fn(), search: vi.fn(), next: vi.fn(), previous: vi.fn(), canPrevious: false, ...change };
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
        expect(screen.getByText(/Last checked manager time \(UTC\):/, { selector: '.journal-advanced p' })).toHaveTextContent(journalNow);
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

describe('fresh capture drafts and retained snapshot context', () => {
    it('shows the exact selected unit ahead of a shared human label', () => {
        render(<JournalContent resource={resource()} insecureTestMode={false} initialUnit="sshd.service"/>);
        expect(document.querySelector('.journal-source-choice strong')).toHaveTextContent('sshd.service');
        expect(document.querySelector('.journal-source-choice')).toHaveTextContent('SSH remote login');
        expect(screen.getByLabelText('Exact service unit')).toHaveValue('sshd.service');
    });
    it('keeps the draft end visible when a status read advances the reference clock', () => {
        const r = resource(), rendered = render(<JournalContent resource={r} insecureTestMode={false}/>);
        rendered.rerender(<JournalContent resource={{ ...r, view: { ...r.view!, serverNow: '2026-10-04T12:04:00Z' } }} insecureTestMode={false}/>);
        expect(document.querySelector('.journal-preset-hint')).toHaveTextContent('Draft ends');
        expect(document.querySelector('.journal-preset-hint time')).toHaveAttribute('datetime', journalNow);
        expect(r.refreshWindow).not.toHaveBeenCalled();
    });
    it('uses the immutable capture observation for age and shows empty-unit guidance only for a complete empty capture', () => {
        const r = resource({ view: { ...journalView(), serverNow: '2026-10-04T12:04:00Z' }, page: journalPage([]) });
        const rendered = render(<JournalContent resource={r} insecureTestMode={false} initialUnit="different.service"/>);
        const age = document.querySelector('.journal-snapshot-age')!;
        expect(age).toHaveTextContent('Age at last status check: 4 min');
        expect(age.querySelector('time')).toHaveAttribute('datetime', journalNow);
        expect(screen.getByText(/Alias targets are not reported here/)).not.toBeVisible();
        fireEvent.click(screen.getByText('Why is this empty?', { selector: 'summary' }));
        expect(screen.getByText(/Alias targets are not reported here/)).toBeVisible();
        rendered.rerender(<JournalContent resource={{ ...r, page: { ...r.page!, coverage: 'partial', reason: 'item_limit' } }} insecureTestMode={false}/>);
        expect(screen.queryByText(/Alias targets are not reported here/)).not.toBeInTheDocument();
        expect(r.create).not.toHaveBeenCalled(); expect(r.search).not.toHaveBeenCalled();
    });
});

it('keeps essential unchecked consent visible while collapsing limits and the full masking explanation', () => {
    const r = resource(); render(<JournalContent resource={r} insecureTestMode initialUnit="ssh.service"/>);
    fireEvent.click(screen.getByRole('button', { name: 'Fetch logs' }));
    const dialog = screen.getByRole('dialog', { name: 'Review log request' }), ui = within(dialog);
    expect(ui.getByText('Limits & privacy', { selector: 'summary' }).closest('details')).not.toHaveAttribute('open');
    expect(ui.getByText(/Masking is best effort and does not make log messages safe or anonymous/)).not.toBeVisible();
    expect(ui.getByRole('checkbox', { name: /credentials, personal data or other secrets, even after masking/ })).not.toBeChecked();
    expect(ui.getByRole('checkbox', { name: /HTTP test sends log content over an unencrypted connection/ })).not.toBeChecked();
    expect(ui.getByRole('button', { name: 'Capture logs' })).toBeDisabled();
    fireEvent.click(ui.getByText('Limits & privacy', { selector: 'summary' }));
    expect(ui.getByText(/Masking is best effort and does not make log messages safe or anonymous/)).toBeVisible();
    expect(r.create).not.toHaveBeenCalled(); expect(r.refreshWindow).not.toHaveBeenCalled();
});
