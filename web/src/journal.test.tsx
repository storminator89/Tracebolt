import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { JournalContent, JournalHighlight } from './journal';
import type { JournalResource } from './journal-resource';
import { journalPage, journalView } from './journal-fixtures';
import { setLocale } from './i18n';
function resource(change: Partial<JournalResource> = {}): JournalResource { return { view: journalView('awaiting'), page: null, busy: false, failure: null, uncertain: false, reset: 0, refresh: vi.fn(), create: vi.fn(async () => undefined), cancelRequest: vi.fn(), search: vi.fn(), next: vi.fn(), previous: vi.fn(), canPrevious: false, ...change }; }
beforeEach(() => setLocale('en', false));
afterEach(cleanup);
describe('compact journal controls and truthful states', () => {
    it('offers separate unchecked content and HTTP plaintext acknowledgements', () => {
        const r = resource(); render(<JournalContent resource={r} insecureTestMode/>); fireEvent.change(screen.getByLabelText('Exact service unit'), { target: { value: 'fixture.service' } });
        const boxes = screen.getAllByRole('checkbox'); expect(boxes).toHaveLength(2); expect(boxes[0]).not.toBeChecked(); expect(boxes[1]).not.toBeChecked();
        fireEvent.click(boxes[0]); expect(screen.getByRole('button', { name: 'Capture logs' })).toBeDisabled(); fireEvent.click(boxes[1]); expect(screen.getByRole('button', { name: 'Capture logs' })).toBeEnabled(); fireEvent.click(screen.getByRole('button', { name: 'Capture logs' }));
        expect(r.create).toHaveBeenCalledWith(expect.objectContaining({ unit: 'fixture.service', maxPriority: 6 }), true, true); expect(boxes[0]).not.toBeChecked(); expect(boxes[1]).not.toBeChecked();
    });
    it('rejects wildcard, future, oversized-window and missing acknowledgement submissions', () => {
        const r = resource(); render(<JournalContent resource={r} insecureTestMode={false}/>); fireEvent.click(screen.getByRole('checkbox'));
        for (const value of ['*.service', 'foo;id.service', 'fixture.socket']) { fireEvent.change(screen.getByLabelText('Exact service unit'), { target: { value } }); expect(screen.getByRole('button', { name: 'Capture logs' })).toBeDisabled(); }
        fireEvent.change(screen.getByLabelText('Exact service unit'), { target: { value: 'fixture.service' } }); fireEvent.change(screen.getByLabelText('From (UTC)'), { target: { value: '2026-10-04T10:59:00' } }); expect(screen.getByRole('button', { name: 'Capture logs' })).toBeDisabled();
        fireEvent.click(screen.getByRole('button', { name: 'Last 15 minutes' })); expect(screen.getByRole('button', { name: 'Capture logs' })).toBeEnabled(); fireEvent.change(screen.getByLabelText('To (UTC)'), { target: { value: '2026-10-04T12:01:00' } }); expect(screen.getByRole('button', { name: 'Capture logs' })).toBeDisabled(); expect(r.create).not.toHaveBeenCalled();
    });
    it.each([['pending', 'Pending'], ['claimed', 'Claimed'], ['expired', 'Expired'], ['canceled', 'Canceled']] as const)('renders %s without fake empty success', (state, label) => {
        render(<JournalContent resource={resource({ view: journalView(state) })} insecureTestMode={false}/>); expect(screen.getByText(label)).toBeVisible(); expect(screen.queryByRole('table')).not.toBeInTheDocument(); expect(screen.queryByText('The complete capture contains no matching journal entries.')).not.toBeInTheDocument();
    });
    it.each([['disabled', 'Local journal access disabled'], ['denied', 'Local access denied'], ['helper_unavailable', 'Local journal helper unavailable'], ['result_lost', 'Content lost / unavailable']] as const)('renders local %s explicitly', (localStatus, label) => {
        const view = journalView('claimed'); view.localStatus = localStatus; render(<JournalContent resource={resource({ view })} insecureTestMode={false}/>); expect(screen.getByText(label)).toBeVisible(); expect(screen.queryByRole('table')).not.toBeInTheDocument();
    });
    it('distinguishes not configured, complete empty, no matches, partial empty and failed', () => {
        const view = journalView('awaiting'); view.configured = false; const result = render(<JournalContent resource={resource({ view })} insecureTestMode={false}/>); expect(screen.getByText('Not configured')).toBeVisible(); expect(screen.queryByRole('button', { name: 'Capture logs' })).not.toBeInTheDocument();
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
        const r = resource({ view: journalView(), page: journalPage() }); render(<JournalContent resource={r} insecureTestMode={false}/>); expect(screen.getByText(/Case-insensitive literal search across this captured snapshot only/)).toBeVisible();
        fireEvent.change(screen.getByLabelText('Literal text in captured messages'), { target: { value: '😀'.repeat(33) } }); expect(screen.getByRole('button', { name: 'Search capture' })).toBeDisabled(); expect(screen.getByRole('alert')).toHaveTextContent('128 UTF-8 bytes'); expect(r.search).not.toHaveBeenCalled();
    });
    it('keeps technical details collapsed and provides German labels', () => {
        setLocale('de', false); render(<JournalContent resource={resource()} insecureTestMode={false}/>); expect(screen.getByText('Erfassungsdetails & Grenzen').closest('details')).not.toHaveAttribute('open'); expect(screen.getByLabelText('Von (UTC)')).toBeVisible(); expect(screen.getByRole('button', { name: 'Logs erfassen' })).toBeDisabled();
    });
});
