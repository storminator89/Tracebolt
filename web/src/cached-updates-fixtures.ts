import type { CachedUpdatesSnapshot, CachedUpdatesView } from './cached-updates-types';
// Synthetic test observations only; these never read or describe a real host.
export const cachedUpdatesDevice = `agent_${'7'.repeat(32)}`;
export function cachedUpdatesSnapshot(): CachedUpdatesSnapshot {
    return { schemaVersion: 'tracebolt.cached-apt-updates.v1', scope: 'agent-visible-dpkg-and-existing-apt-cache', generationId: `sample_${'a'.repeat(32)}`, collectedAt: '2026-10-05T04:00:00Z', durationMs: 12,
        release: { id: 'debian', versionId: '13', versionCodename: 'trixie' }, coverage: 'complete', reason: 'none', metadata: { freshness: 'unknown', oldestIndexModifiedAt: '2026-10-05T03:00:00Z', ageSeconds: 3600, ageBasis: 'oldest-local-package-index-mtime', refresh: 'not_attempted' },
        installedCount: 3, checkedCount: 3, candidateCount: 2, heldCount: 1, unknownCount: 0, truncated: false, items: [
            { name: 'curl', architecture: 'amd64', installedVersion: '1:8.14.1-2', candidateVersion: '1:8.14.1-2+deb13u1', state: 'candidate_only', installability: 'not_evaluated' },
            { name: 'fixture-held', architecture: 'amd64', installedVersion: '2.0~rc1-1', candidateVersion: '2.0-1', state: 'held', installability: 'not_evaluated' },
        ] };
}
export function cachedUpdatesView(): CachedUpdatesView { return { schemaVersion: 'tracebolt.cached-updates-view.v1', deviceId: cachedUpdatesDevice, status: 'fresh', serverNow: '2026-10-05T04:00:10Z', maxAgeSeconds: 120, sequence: '9', receivedAt: '2026-10-05T04:00:01Z', expiresAt: '2026-10-06T04:00:00Z', latest: cachedUpdatesSnapshot() }; }
export function emptyCachedUpdatesView(): CachedUpdatesView { return { ...cachedUpdatesView(), status: 'not_collected', sequence: null, receivedAt: null, expiresAt: null, latest: null }; }
