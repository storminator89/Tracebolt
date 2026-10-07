import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { CachedUpdatesPanel } from './cached-updates';
import { cachedUpdatesView, emptyCachedUpdatesView } from './cached-updates-fixtures';
import type { CachedUpdatesView } from './cached-updates-types';
import { setLocale } from './i18n';
const show = (view: CachedUpdatesView) => render(<CachedUpdatesPanel resource={{ view, snapshot: view.latest, loading: false, recovering: false, error: null, elapsed: 0, refresh: vi.fn() }}/>);
beforeEach(() => setLocale('en', false)); afterEach(cleanup);
describe('cached APT update panel', () => {
    it('shows native versions and holds without security or installation promises', () => {
        show(cachedUpdatesView()); expect(screen.getByText('curl')).toBeInTheDocument(); expect(screen.getByText('1:8.14.1-2+deb13u1')).toBeInTheDocument(); expect(screen.getByText('Held by dpkg')).toBeInTheDocument(); expect(screen.getByText(/Source freshness unknown/)).toBeInTheDocument(); expect(screen.getByText(/Zero candidates does not mean/)).toBeInTheDocument(); expect(screen.queryByRole('button', { name: /install|upgrade/i })).not.toBeInTheDocument();
    });
    it('uncollected data shows unknown counts and local consent requirement', () => { show(emptyCachedUpdatesView()); expect(screen.getByText('Update counts are unknown in this state.')).toBeInTheDocument(); expect(screen.queryByText('Newer candidates')).not.toBeInTheDocument(); expect(screen.getAllByText(/Off by default/).length).toBeGreaterThan(0); });
    it('shows stale metadata independently from a recent observation', () => { const v = cachedUpdatesView(); v.latest!.metadata = { ...v.latest!.metadata, freshness: 'stale', ageSeconds: 345600, oldestIndexModifiedAt: '2026-10-01T04:00:00Z' }; show(v); expect(screen.getByText('Recent observation')).toBeInTheDocument(); expect(screen.getByText(/indexes are stale/)).toBeInTheDocument(); });
    it('shows failed database separately from a successfully enumerated zero', () => { const v = cachedUpdatesView(); Object.assign(v.latest!, { coverage: 'unavailable', reason: 'source_missing', installedCount: null, checkedCount: null, candidateCount: null, heldCount: null, unknownCount: null, items: [] }); show(v); expect(screen.getByText(/Package database unavailable/)).toBeInTheDocument(); expect(screen.queryByText(/No newer candidates found/)).not.toBeInTheDocument(); });
    it('labels omitted preview rows and lower-bound comparison gaps', () => { const v = cachedUpdatesView(); Object.assign(v.latest!, { coverage: 'partial', reason: 'byte_limit', truncated: true, checkedCount: 2, unknownCount: 1, items: [v.latest!.items[0]] }); show(v); expect(screen.getByText(/Bounded preview/)).toBeInTheDocument(); expect(screen.getByText(/lower bound/)).toBeInTheDocument(); });
    it('renders German copy', () => { setLocale('de', false); show(cachedUpdatesView()); expect(screen.getByRole('heading', { name: 'Updates · APT-Vorschau' })).toBeInTheDocument(); expect(screen.getByText('Von dpkg zurückgehalten')).toBeInTheDocument(); });
});
