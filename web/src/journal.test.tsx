import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { JournalContent, JournalHighlight } from './journal';
import type { JournalResource } from './journal-resource';
import { journalPage, journalView } from './journal-fixtures';
import { setLocale } from './i18n';
function resource(change: Partial<JournalResource> = {}): JournalResource { return { view: journalView('awaiting'), page: null, busy: false, paused: false, failure: null, uncertain: false, reset: 0, refresh: vi.fn(), refreshWindow: vi.fn(async () => null), create: vi.fn(async () => undefined), cancelRequest: vi.fn(), search: vi.fn(), next: vi.fn(), previous: vi.fn(), canPrevious: false, ...change }; }
beforeEach(() => setLocale('en', false));
afterEach(cleanup);
describe('compact journal controls and truthful states', () => {
    it('offers separate unchecked content and HTTP plaintext acknowledgements', async () => {
        const r = resource(); render(<JournalContent resource={r} insecureTestMode/>); openAdvanced(); fireEvent.change(screen.getByLabelText('Exact service unit'), { target: { value: 'fixture.service' } });
        expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', { name: 'Fetch logs' })); expect(screen.getByRole('dialog', { name: 'Review log request' })).toBeVisible(); expect(r.create).not.toHaveBeenCalled();
        const boxes = screen.getAllByRole('checkbox'); expect(boxes).toHaveLength(2); expect(boxes[0]).not.toBeChecked(); expect(boxes[1]).not.toBeChecked();
        fireEvent.click(boxes[0]); expect(screen.getByRole('button', { name: 'Capture logs' })).toBeDisabled(); fireEvent.click(boxes[1]); expect(screen.getByRole('button', { name: 'Capture logs' })).toBeEnabled(); await act(async () => fireEvent.click(screen.getByRole('button', { name: 'Capture logs' })));
        expect(r.create).toHaveBeenCalledWith(expect.objectContaining({ unit: 'fixture.service', maxPriority: 6 }), true, true); expect(screen.queryByRole('dialog')).not.toBeInTheDocument(); expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', { name: 'Fetch logs' })); for (const box of screen.getAllByRole('checkbox')) expect(box).not.toBeChecked();
    });
    it('rejects wildcard, future, oversized-window and missing acknowledgement submissions', () => {
        const r = resource(); render(<JournalContent resource={r} insecureTestMode={false}/>); openAdvanced();
        for (const value of ['*.service', 'foo;id.service', 'fixture.socket']) { openAdvanced(); fireEvent.change(screen.getByLabelText('Exact service unit'), { target: { value } }); expect(screen.getByRole('button', { name: 'Fetch logs' })).toBeDisabled(); }
        openAdvanced(); fireEvent.change(screen.getByLabelText('Exact service unit'), { target: { value: 'fixture.service' } }); fireEvent.change(screen.getByLabelText('From (UTC)'), { target: { value: '2026-10-04T10:59:00' } }); expect(screen.getByRole('button', { name: 'Fetch logs' })).toBeDisabled();
        fireEvent.click(screen.getByRole('button', { name: '15 minutes ending at reference time' })); expect(screen.getByRole('button', { name: 'Fetch logs' })).toBeEnabled(); fireEvent.change(screen.getByLabelText('To (UTC)'), { target: { value: '2026-10-04T12:01:00' } }); expect(screen.getByRole('button', { name: 'Fetch logs' })).toBeDisabled(); expect(r.create).not.toHaveBeenCalled();
    });
    it.each(['Back', 'Close', 'Escape'] as const)('dismisses review with %s, resets both consents and never creates or cancels a capture', action => {
        const r = resource({ view: journalView(), page: journalPage(['Retained review fixture']) }); render(<JournalContent resource={r} insecureTestMode/>);
        expect(screen.getByText('Advanced', { selector: 'summary' }).closest('details')).not.toHaveAttribute('open');
        expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();
        openAdvanced(); fireEvent.change(screen.getByLabelText('Exact service unit'), { target: { value: 'review.service' } });
        fireEvent.change(screen.getByLabelText('From (UTC)'), { target: { value: '2026-10-04T11:42:12' } });
        fireEvent.change(screen.getByLabelText('To (UTC)'), { target: { value: '2026-10-04T11:58:34' } });
        fireEvent.change(screen.getByLabelText('Include severity through'), { target: { value: '3' } });
        const fetch = screen.getByRole('button', { name: 'Fetch logs' }); fetch.focus(); fireEvent.click(fetch);
        const dialog = screen.getByRole('dialog', { name: 'Review log request' });
        expect(dialog).toHaveTextContent('review.service'); const times = dialog.querySelectorAll('time'); expect(times).toHaveLength(2); expect(Date.parse(times[0].dateTime)).toBe(Date.parse('2026-10-04T11:42:12Z')); expect(Date.parse(times[1].dateTime)).toBe(Date.parse('2026-10-04T11:58:34Z')); expect(dialog).toHaveTextContent('3 · Error');
        const boxes = within(dialog).getAllByRole('checkbox'); expect(boxes).toHaveLength(2);
        for (const box of boxes) { expect(box).not.toBeChecked(); fireEvent.click(box); }
        expect(within(dialog).getByRole('button', { name: 'Capture logs' })).toBeEnabled(); expect(r.create).not.toHaveBeenCalled();
        if (action === 'Escape') fireEvent.keyDown(document.activeElement!, { key: 'Escape' });
        else fireEvent.click(within(dialog).getByRole('button', { name: action }));
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument(); expect(fetch).toHaveFocus(); expect(screen.getByText('Retained review fixture')).toBeVisible();
        expect(screen.getByLabelText('Exact service unit')).toHaveValue('review.service'); expect(r.create).not.toHaveBeenCalled(); expect(r.cancelRequest).not.toHaveBeenCalled();
        fireEvent.click(fetch); for (const box of screen.getAllByRole('checkbox')) expect(box).not.toBeChecked(); expect(screen.getByRole('button', { name: 'Capture logs' })).toBeDisabled();
    });
    it.each([['Exact service unit', 'changed.service'], ['From (UTC)', '2026-10-04T11:44'], ['To (UTC)', '2026-10-04T11:59'], ['Include severity through', '3']] as const)('invalidates reviewed consent when %s changes', (label, value) => {
        const r = resource(); render(<JournalContent resource={r} insecureTestMode initialUnit="review.service"/>); openAdvanced();
        fireEvent.click(screen.getByRole('button', { name: 'Fetch logs' })); for (const box of screen.getAllByRole('checkbox')) fireEvent.click(box);
        expect(screen.getByRole('button', { name: 'Capture logs' })).toBeEnabled();
        fireEvent.change(screen.getByLabelText(label), { target: { value } });
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument(); expect(r.create).not.toHaveBeenCalled(); expect(r.cancelRequest).not.toHaveBeenCalled();
        fireEvent.click(screen.getByRole('button', { name: 'Fetch logs' })); for (const box of screen.getAllByRole('checkbox')) expect(box).not.toBeChecked(); expect(screen.getByRole('button', { name: 'Capture logs' })).toBeDisabled();
    });
    it('does not reopen or repeat a reviewed creation while its result is still pending', async () => {
        let finish!: () => void; const r = resource({ create: vi.fn(() => new Promise<void>(resolve => { finish = resolve; })) });
        render(<JournalContent resource={r} insecureTestMode={false} initialUnit="fixture.service"/>);
        const fetch = screen.getByRole('button', { name: 'Fetch logs' }); fireEvent.click(fetch); fireEvent.click(screen.getByRole('checkbox'));
        const capture = screen.getByRole('button', { name: 'Capture logs' }); fireEvent.click(capture); fireEvent.click(capture); fireEvent.click(fetch); fireEvent.click(fetch);
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument(); expect(r.create).toHaveBeenCalledTimes(1); expect(r.cancelRequest).not.toHaveBeenCalled();
        await act(async () => finish()); fireEvent.click(fetch); expect(screen.getByRole('checkbox')).not.toBeChecked(); expect(screen.getByRole('button', { name: 'Capture logs' })).toBeDisabled(); expect(r.create).toHaveBeenCalledTimes(1);
    });
    it.each([['pending', 'Pending'], ['claimed', 'Claimed'], ['expired', 'Expired'], ['canceled', 'Canceled']] as const)('renders %s without fake empty success', (state, label) => {
        render(<JournalContent resource={resource({ view: journalView(state) })} insecureTestMode={false}/>); expect(screen.getByText(label)).toBeVisible(); expect(screen.queryByRole('table')).not.toBeInTheDocument(); expect(screen.queryByText('The complete capture contains no matching journal entries.')).not.toBeInTheDocument();
    });
    it.each([['disabled', 'Local journal access disabled'], ['denied', 'Local access denied'], ['helper_unavailable', 'Local journal helper unavailable'], ['result_lost', 'Content lost / unavailable']] as const)('renders local %s explicitly', (localStatus, label) => {
        const view = journalView('claimed'); view.localStatus = localStatus; render(<JournalContent resource={resource({ view })} insecureTestMode={false}/>); expect(screen.getByText(label)).toBeVisible(); expect(screen.queryByRole('table')).not.toBeInTheDocument();
    });
    it('distinguishes not configured, complete empty, no matches, partial empty and failed', () => {
        const view = journalView('awaiting'); view.configured = false; const result = render(<JournalContent resource={resource({ view })} insecureTestMode={false}/>); expect(screen.getByText('Not configured')).toBeVisible(); expect(screen.queryByRole('button', { name: 'Capture logs' })).not.toBeInTheDocument(); expect(screen.queryByRole('button', { name: 'Fetch logs' })).not.toBeInTheDocument();
        const page = journalPage([]); result.rerender(<JournalContent resource={resource({ view: journalView(), page })} insecureTestMode={false}/>); expect(screen.getByText('The complete capture contains no matching journal entries.')).toBeVisible();
        page.totalCapturedRows = 3; page.observedCount = 3; page.search = 'missing'; result.rerender(<JournalContent resource={resource({ view: journalView(), page: { ...page } })} insecureTestMode={false}/>); expect(screen.getByText('No literal matches in this captured snapshot.')).toBeVisible();
        page.totalCapturedRows = 0; page.observedCount = 0; page.coverage = 'partial'; page.reason = 'visibility_restricted'; page.countExact = false; result.rerender(<JournalContent resource={resource({ view: journalView(), page: { ...page } })} insecureTestMode={false}/>); expect(screen.getByText(/No rows were retained; coverage is partial/)).toBeVisible();
        page.coverage = 'failed'; page.reason = 'read_failed'; result.rerender(<JournalContent resource={resource({ view: journalView(), page: { ...page } })} insecureTestMode={false}/>); expect(screen.getByText('Collection failed', { selector: 'strong' })).toBeVisible(); expect(screen.queryByText('No literal matches in this captured snapshot.')).not.toBeInTheDocument();
    });
    it('renders markup, links, script-like strings and regex characters only as inert text', () => {
        const text = '<img src=x onerror=alert(1)> https://example.invalid [.*] NeEdLe';
        const result = render(<p><JournalHighlight text={text} search="[.*]"/></p>); expect(result.container.querySelector('img')).toBeNull(); expect(result.container.querySelector('a')).toBeNull(); expect(screen.getByText('[.*]', { selector: 'mark' })).toBeVisible(); expect(result.container.textContent).toBe(text);
        result.rerender(<p><JournalHighlight text={text} search="needle"/></p>); expect(screen.getByText('NeEdLe', { selector: 'mark' })).toBeVisible();
    });
    it('bounds search by UTF-8 bytes and clearly explains its scope', () => {
        const r = resource({ view: journalView(), page: journalPage() }); render(<JournalContent resource={r} insecureTestMode={false}/>); expect(screen.getByText(/Literal, case-insensitive search in this snapshot only/)).toBeVisible();
        fireEvent.change(screen.getByLabelText('Search captured messages'), { target: { value: '😀'.repeat(33) } }); expect(screen.getByRole('button', { name: 'Search capture' })).toBeDisabled(); expect(screen.getByRole('alert')).toHaveTextContent('128 UTF-8 bytes'); expect(r.search).not.toHaveBeenCalled();
    });
    it('keeps technical details collapsed and provides German labels', () => {
        setLocale('de', false); render(<JournalContent resource={resource()} insecureTestMode={false}/>); expect(screen.getByText('Grenzen & Datenschutz').closest('details')).not.toHaveAttribute('open'); expect(screen.getByText('Erweitert', { selector: 'summary' }).closest('details')).not.toHaveAttribute('open'); openAdvanced(); expect(screen.getByLabelText('Von (UTC)')).toBeVisible(); expect(screen.getByRole('button', { name: 'Logs abrufen' })).toBeDisabled();
    });
});

function openAdvanced() {
    const summary = screen.getByText(/^(Advanced|Erweitert)$/, { selector: 'summary' });
    if (!summary.closest('details')!.open) fireEvent.click(summary);
}
