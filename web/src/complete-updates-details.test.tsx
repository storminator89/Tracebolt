import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { mutateRaw, request } from './api';
import { CompleteUpdatesPanel } from './complete-updates';
import { updateDevice, updatePage, updateRows, updateView } from './complete-updates-fixtures';
import { setLocale } from './i18n';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutateRaw: vi.fn() }));
vi.mock('./auth', () => ({ useOperator: () => ({ mode: 'lan', authenticated: true, expiresAt: '2026-10-06T06:00:00Z' }) }));

function distinctAttempts(latest: 'pending' | 'failure' = 'pending') {
    const view = updateView(2), complete = view.complete!;
    // Retained, pending and failed sequences must remain distinct exact strings.
    complete.binding.sequence = '9223372036854775805';
    complete.manifest.collectedAt = '2026-10-04T16:00:00Z';
    complete.completedAt = '2026-10-04T16:00:05Z';
    complete.retainedUntil = '2026-10-05T16:00:00Z';
    complete.manifest.metadata.oldestIndexModifiedAt = '2026-10-01T16:00:00Z';
    complete.manifest.checkedCount--;
    complete.manifest.unknownCount = 1;
    complete.manifest.comparisonCoverage = 'partial';
    complete.manifest.comparisonReason = 'candidate_unknown';
    if (latest === 'pending') view.transfer = {
        binding: { sequence: '9223372036854775806', generationId: `sample_${'d'.repeat(32)}`, manifestHash: 'e'.repeat(64) },
        state: 'pending', declaredRows: 130, acceptedRows: 128, expectedChunks: 2, acceptedChunks: 1,
        collectedAt: '2026-10-04T22:00:00Z', startedAt: '2026-10-05T04:00:06Z', expiresAt: '2026-10-05T04:15:06Z',
    };
    else view.failure = {
        sequence: '9223372036854775807', generationId: `sample_${'f'.repeat(32)}`,
        attemptedAt: '2026-10-05T04:00:08Z', receivedAt: '2026-10-05T04:00:09Z', reason: 'source_missing',
    };
    return view;
}

let view = distinctAttempts();
beforeEach(() => {
    setLocale('en', false);
    view = distinctAttempts();
    vi.mocked(request).mockReset().mockImplementation(async () => view);
    vi.mocked(mutateRaw).mockReset().mockImplementation(async (_path, raw) => updatePage(view, updateRows(2), raw));
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.useRealTimers(); });

function disclosure(label: string) {
    return screen.getByText(label, { selector: 'summary' }).parentElement as HTMLDetailsElement;
}
function expectFact(section: HTMLElement, label: string, value: string) {
    const term = within(section).getByText(label, { selector: 'dt' });
    expect(term.nextElementSibling?.tagName).toBe('DD');
    expect(term.nextElementSibling?.textContent).toBe(value);
    expect(term.nextElementSibling).toBeVisible();
}
function toggle(details: HTMLDetailsElement) { fireEvent.click(within(details).getByText(/.+/, { selector: 'summary' })); }

describe('complete APT generation details', () => {
    describe.each([
        { locale: 'en', capture: 'Capture details', transfer: 'Transfer details', failure: 'Failure details', generation: 'Generation ID', sequence: 'Sequence', collected: 'Original capture time', attempted: 'Attempted at', age: 'Local metadata age at capture (hours)', latestTransfer: 'Latest transfer', latestFailure: 'Latest capture failed', available: 'Complete known-candidate generation available', pending: 'Transfer pending', reason: 'Source unavailable', stale: /metadata is stale/, partial: /lower bound/ },
        { locale: 'de', capture: 'Erfassungsdetails', transfer: 'Übertragungsdetails', failure: 'Fehlerdetails', generation: 'Generations-ID', sequence: 'Sequenz', collected: 'Ursprünglicher Erfassungszeitpunkt', attempted: 'Versuch am', age: 'Metadatenalter bei Erfassung (Stunden)', latestTransfer: 'Neueste Übertragung', latestFailure: 'Neueste Erfassung fehlgeschlagen', available: 'Vollständige Generation bekannter Kandidaten verfügbar', pending: 'Übertragung ausstehend', reason: 'Quelle nicht verfügbar', stale: /Metadaten sind veraltet/, partial: /Untergrenze/ },
    ] as const)('$locale details', labels => {
        it.each(['pending', 'failure'] as const)('distinguishes a newer %s from retained rows', async latest => {
            view = distinctAttempts(latest);
            setLocale(labels.locale, false);
            const original = JSON.stringify(view);
            render(<CompleteUpdatesPanel deviceId={updateDevice}/>);
            const table = await screen.findByRole('table');
            const capture = disclosure(labels.capture), latestDetails = disclosure(latest === 'pending' ? labels.transfer : labels.failure);
            const attempts = [view.complete!.binding, latest === 'pending' ? view.transfer!.binding : view.failure!];
            const sections = [capture, latestDetails];
            for (const [index, details] of sections.entries()) {
                expect(details).not.toHaveAttribute('open');
                expect(within(details).getByText(attempts[index].generationId)).not.toBeVisible();
                expect(within(details).getByText(attempts[index].sequence)).not.toBeVisible();
                for (const other of attempts.filter((_, otherIndex) => otherIndex !== index)) {
                    expect(within(details).queryByText(other.generationId)).not.toBeInTheDocument();
                    expect(within(details).queryByText(other.sequence)).not.toBeInTheDocument();
                }
            }
            if (latest === 'pending') {
                expect(latestDetails.closest('section')).toBe(screen.getByRole('region', { name: labels.latestTransfer }));
                expect(within(latestDetails).getByText(view.transfer!.collectedAt)).not.toBeVisible();
                expect(within(capture).queryByText(view.transfer!.collectedAt)).not.toBeInTheDocument();
                expect(within(latestDetails).queryByText(view.complete!.manifest.collectedAt)).not.toBeInTheDocument();
                expect(screen.getByText(labels.pending)).toBeVisible();
                expect(screen.getByText('128 / 130')).toBeVisible();
                expect(screen.queryByText(labels.failure, { selector: 'summary' })).not.toBeInTheDocument();
            } else {
                const failureSection = screen.getByRole('region', { name: labels.latestFailure });
                expect(latestDetails.closest('section')).toBe(failureSection);
                expectFact(failureSection, labels.attempted, view.failure!.attemptedAt);
                expect(within(latestDetails).queryByText(view.failure!.attemptedAt)).not.toBeInTheDocument();
                expect(screen.getByText(labels.reason)).toBeVisible();
                expect(screen.queryByText(labels.transfer, { selector: 'summary' })).not.toBeInTheDocument();
            }
            expect(screen.getByText(view.complete!.manifest.collectedAt)).toBeVisible();
            expect(screen.getByText(view.complete!.retainedUntil)).toBeVisible();
            expect(screen.getByText(labels.available)).toBeVisible();
            expect(screen.getByText(labels.stale)).toBeVisible();
            expect(screen.getByText(labels.partial)).toBeVisible();
            expect(within(table).getByText('fixture-update-000000')).toBeVisible();

            for (const [index, details] of sections.entries()) {
                const summary = details.querySelector('summary')!;
                summary.focus();
                toggle(details);
                expect(details).toHaveAttribute('open');
                expectFact(details, labels.generation, attempts[index].generationId);
                expectFact(details, labels.sequence, attempts[index].sequence);
                if (details === capture) expectFact(capture, labels.age, '72');
                if (details === latestDetails && latest === 'pending') expectFact(latestDetails, labels.collected, view.transfer!.collectedAt);
                toggle(details);
                expect(details).not.toHaveAttribute('open');
                expect(summary).toHaveFocus();
                expect(within(details).getByText(attempts[index].generationId)).not.toBeVisible();
                expect(within(details).getByText(attempts[index].sequence)).not.toBeVisible();
            }
            expect(screen.getByRole('table')).toBe(table);
            expect(screen.getByText(view.complete!.manifest.collectedAt)).toBeVisible();
            if (view.failure) expect(screen.getByText(view.failure.attemptedAt)).toBeVisible();
            expect(screen.getByText(labels.stale)).toBeVisible();
            expect(screen.getByText(labels.partial)).toBeVisible();
            expect(request).toHaveBeenCalledTimes(1);
            expect(mutateRaw).toHaveBeenCalledTimes(1);
            expect(JSON.parse(vi.mocked(mutateRaw).mock.calls[0][1]).generationId).toBe(view.complete!.binding.generationId);
            expect(JSON.stringify(view)).toBe(original);
        });
    });

    it.each(['staging lease', 'capture retention'] as const)('preserves exact transfer details as its %s expires', async deadline => {
        vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] });
        const mono = vi.spyOn(performance, 'now').mockReturnValue(1000), wall = vi.spyOn(Date, 'now').mockReturnValue(100000);
        let milliseconds = 896000;
        if (deadline === 'capture retention') {
            view.status = 'awaiting'; view.complete = null;
            view.transfer!.collectedAt = '2026-10-04T04:00:12Z';
            milliseconds = 2000;
        }
        const original = JSON.stringify(view);
        render(<CompleteUpdatesPanel deviceId={updateDevice}/>);
        await screen.findByText('Transfer pending');
        if (view.complete) await screen.findByRole('table');
        const transfer = disclosure('Transfer details');
        toggle(transfer);
        expectFact(transfer, 'Generation ID', view.transfer!.binding.generationId);
        expectFact(transfer, 'Sequence', view.transfer!.binding.sequence);
        expectFact(transfer, 'Original capture time', view.transfer!.collectedAt);
        mono.mockReturnValue(1000 + milliseconds - 1); wall.mockReturnValue(100000 + milliseconds - 1);
        act(() => vi.advanceTimersByTime(1000));
        expect(screen.getByText('Transfer pending')).toBeVisible();
        mono.mockReturnValue(1000 + milliseconds); wall.mockReturnValue(100000 + milliseconds);
        act(() => vi.advanceTimersByTime(1000));
        expect(screen.getByText('Transfer expired')).toBeVisible();
        expect(screen.queryByText('Transfer pending')).not.toBeInTheDocument();
        expect(transfer).toHaveAttribute('open');
        expectFact(transfer, 'Generation ID', view.transfer!.binding.generationId);
        expectFact(transfer, 'Sequence', view.transfer!.binding.sequence);
        expectFact(transfer, 'Original capture time', view.transfer!.collectedAt);
        expectFact(transfer, 'Accepted / expected chunks', '1 / 2');
        expect(screen.getByText('128 / 130')).toBeVisible();
        toggle(transfer);
        expect(screen.getByText('Transfer expired')).toBeVisible();
        expect(screen.getByText(view.transfer!.collectedAt)).not.toBeVisible();
        if (view.complete) {
            expect(screen.getByRole('table')).toBeVisible();
            expect(screen.getByText(view.complete.manifest.collectedAt)).toBeVisible();
        } else expect(screen.queryByRole('table')).not.toBeInTheDocument();
        expect(request).toHaveBeenCalledTimes(1);
        expect(mutateRaw).toHaveBeenCalledTimes(view.complete ? 1 : 0);
        expect(JSON.stringify(view)).toBe(original);
    });

    it('keeps historical identities inspectable without restoring expired rows', async () => {
        view = distinctAttempts('failure');
        view.status = 'unavailable';
        view.complete!.state = 'expired';
        view.serverNow = view.complete!.retainedUntil;
        render(<CompleteUpdatesPanel deviceId={updateDevice}/>);
        expect(await screen.findByText('This generation has expired. Its rows are no longer available.')).toBeVisible();
        expect(screen.getByText('Complete update inventory unavailable')).toBeVisible();
        expect(screen.getByText('Latest capture failed')).toBeVisible();
        expect(screen.getByText(/metadata is stale/)).toBeVisible();
        expect(screen.getByText(/lower bound/)).toBeVisible();
        expect(screen.getByText(view.complete!.manifest.collectedAt)).toBeVisible();
        expect(screen.getByText(view.failure!.attemptedAt)).toBeVisible();
        const sections = [disclosure('Capture details'), disclosure('Failure details')];
        const attempts = [view.complete!.binding, view.failure!];
        for (const [index, details] of sections.entries()) {
            expect(details).not.toHaveAttribute('open');
            toggle(details);
            expectFact(details, 'Generation ID', attempts[index].generationId);
            expectFact(details, 'Sequence', attempts[index].sequence);
        }
        expectFact(sections[0], 'Local metadata age at capture (hours)', '72');
        expect(screen.queryByRole('table')).not.toBeInTheDocument();
        expect(screen.queryByRole('searchbox')).not.toBeInTheDocument();
        expect(request).toHaveBeenCalledTimes(1);
        expect(mutateRaw).not.toHaveBeenCalled();
    });
});
