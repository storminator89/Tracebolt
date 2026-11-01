import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { CachedUpdatesPanel } from './cached-updates';
import { cachedUpdatesView, emptyCachedUpdatesView } from './cached-updates-fixtures';
import { validCachedUpdatesView } from './cached-updates-types';
import type { CachedUpdatesView } from './cached-updates-types';
import { setLocale } from './i18n';
const show = (view: CachedUpdatesView) => render(<CachedUpdatesPanel resource={{ view, snapshot: view.latest, loading: false, recovering: false, error: null, elapsed: 0, refresh: vi.fn() }}/>);
beforeEach(() => setLocale('en', false)); afterEach(cleanup);
describe('cached APT update panel', () => {
    it.each(['en', 'de'] as const)('keeps the cache-only patch-status boundary visible in every report state in %s', locale => {
        setLocale(locale, false);
        const summary = locale === 'de' ? 'Nur Cache-Kandidaten; keine CVE-Bewertung und kein bestätigter Patchstand.' : 'Cached candidates only; no CVE assessment or confirmed patch status.';
        for (const state of ['zero', 'stale', 'partial', 'unavailable', 'unsupported', 'missing', 'expired', 'revoked'] as const) {
            const view = cachedUpdatesView();
            if (state === 'zero') Object.assign(view.latest!, { candidateCount: 0, heldCount: 0, items: [] });
            if (state === 'stale') { view.status = 'stale'; view.serverNow = '2026-10-05T05:00:00Z'; }
            if (state === 'partial') Object.assign(view.latest!, { coverage: 'partial', reason: 'candidate_unknown', checkedCount: 2, unknownCount: 1 });
            if (state === 'unavailable' || state === 'unsupported') Object.assign(view.latest!, { coverage: 'unavailable', reason: state === 'unsupported' ? 'not_supported' : 'source_missing', installedCount: null, checkedCount: null, candidateCount: null, heldCount: null, unknownCount: null, items: [] });
            if (state === 'missing' || state === 'expired' || state === 'revoked') Object.assign(view, emptyCachedUpdatesView(), { status: state === 'missing' ? 'not_collected' : state });
            expect(validCachedUpdatesView(view, view.deviceId), state).toBe(true);
            const original = JSON.stringify(view), rendered = show(view), details = screen.getByText(locale === 'de' ? 'Umfang, Freigabe & Aufbewahrung' : 'Scope, consent & retention').closest('details')!;
            expect(details).not.toHaveAttribute('open');
            expect(screen.getByText(summary)).toBeVisible();
            if (view.latest) {
                expect(screen.getByText(locale === 'de' ? 'Für den Agent sichtbare dpkg-Pakete und vorhandener lokaler APT-Cache' : 'Agent-visible dpkg packages and existing local APT cache')).toBeVisible();
                expect(screen.getByText(view.latest.collectedAt)).toBeVisible();
                expect(screen.getByText(view.latest.metadata.oldestIndexModifiedAt!)).toBeVisible();
                // Failed and unsupported attempts must not acquire a successful
                // comparison claim merely by carrying a scope or capture time.
                const compared = locale === 'de' ? 'Debian-Paketversionsvergleich; keine Metadaten-Aktualisierung.' : 'Debian package-version comparison; no metadata refresh.';
                if (view.latest.coverage === 'unavailable') {
                    expect(screen.getByText(locale === 'de' ? 'Kein erfolgreicher Cache-Kandidatenvergleich.' : 'No successful cached-candidate comparison.')).toBeVisible();
                    expect(screen.queryByText(compared)).not.toBeInTheDocument();
                } else expect(screen.getByText(compared)).toBeVisible();
            } else {
                expect(screen.queryByText(locale === 'de' ? 'Vergleichsmethode' : 'Comparison method')).not.toBeInTheDocument();
                expect(screen.queryByText(locale === 'de' ? 'Ursprünglicher Erfassungszeitpunkt' : 'Original collection time')).not.toBeInTheDocument();
            }
            // Inspecting and dismissing the detailed scope must not be needed to
            // discover, or accidentally hide, the summary's evidence boundary.
            fireEvent.click(details.querySelector('summary')!);
            fireEvent.click(details.querySelector('summary')!);
            expect(details).not.toHaveAttribute('open');
            expect(screen.getByText(summary)).toBeVisible();
            expect(JSON.stringify(view)).toBe(original);
            rendered.unmount();
        }
    });
    it('shows native versions and holds without security or installation promises', () => {
        show(cachedUpdatesView()); expect(screen.getByText('curl')).toBeInTheDocument(); expect(screen.getByText('1:8.14.1-2+deb13u1')).toBeInTheDocument(); expect(screen.getByText('Held by dpkg')).toBeInTheDocument(); expect(screen.getByText(/Source freshness unknown/)).toBeInTheDocument(); expect(screen.getByText(/Zero candidates does not mean/)).toBeInTheDocument(); expect(screen.queryByRole('button', { name: /install|upgrade/i })).not.toBeInTheDocument();
    });
    it('uncollected data shows unknown counts and local consent requirement', () => { show(emptyCachedUpdatesView()); expect(screen.getByText('Update counts are unknown in this state.')).toBeInTheDocument(); expect(screen.queryByText('Newer candidates')).not.toBeInTheDocument(); expect(screen.getAllByText(/Off by default/).length).toBeGreaterThan(0); });
    it('shows stale metadata independently from a recent observation', () => { const v = cachedUpdatesView(); v.latest!.metadata = { ...v.latest!.metadata, freshness: 'stale', ageSeconds: 345600, oldestIndexModifiedAt: '2026-10-01T04:00:00Z' }; show(v); expect(screen.getByText('Recent observation')).toBeInTheDocument(); expect(screen.getByText(/indexes are stale/)).toBeInTheDocument(); });
    it('shows failed database separately from a successfully enumerated zero', () => { const v = cachedUpdatesView(); Object.assign(v.latest!, { coverage: 'unavailable', reason: 'source_missing', installedCount: null, checkedCount: null, candidateCount: null, heldCount: null, unknownCount: null, items: [] }); show(v); expect(screen.getByText(/Package database unavailable/)).toBeInTheDocument(); expect(screen.queryByText(/No newer candidates found/)).not.toBeInTheDocument(); });
    it('labels omitted preview rows and lower-bound comparison gaps', () => { const v = cachedUpdatesView(); Object.assign(v.latest!, { coverage: 'partial', reason: 'byte_limit', truncated: true, checkedCount: 2, unknownCount: 1, items: [v.latest!.items[0]] }); show(v); expect(screen.getByText(/Bounded preview/)).toBeInTheDocument(); expect(screen.getByText(/lower bound/)).toBeInTheDocument(); });
    it('renders German copy', () => { setLocale('de', false); show(cachedUpdatesView()); expect(screen.getByRole('heading', { name: 'Updates · APT-Vorschau' })).toBeInTheDocument(); expect(screen.getByText('Von dpkg zurückgehalten')).toBeInTheDocument(); });
});
