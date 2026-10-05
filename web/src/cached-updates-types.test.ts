import { describe, expect, it } from 'vitest';
import { cachedDebianCompare, cachedUpdatesAgeStatus, validCachedUpdatesSnapshot, validCachedUpdatesView } from './cached-updates-types';
import { cachedUpdatesDevice, cachedUpdatesSnapshot, cachedUpdatesView, emptyCachedUpdatesView } from './cached-updates-fixtures';
describe('cached APT update contract', () => {
    it('accepts scoped Debian/Ubuntu and empty unknown views', () => {
        expect(validCachedUpdatesView(cachedUpdatesView(), cachedUpdatesDevice)).toBe(true); expect(validCachedUpdatesView(emptyCachedUpdatesView(), cachedUpdatesDevice)).toBe(true);
        const s = cachedUpdatesSnapshot(); s.release = { id: 'ubuntu', versionId: '24.04', versionCodename: 'noble' }; expect(validCachedUpdatesSnapshot(s)).toBe(true);
    });
    it('does not convert unknown or stale metadata to fresh', () => {
        const s = cachedUpdatesSnapshot(); s.metadata = { ...s.metadata, oldestIndexModifiedAt: '2026-10-01T04:00:00Z', ageSeconds: 345600, freshness: 'stale' }; expect(validCachedUpdatesSnapshot(s)).toBe(true);
        expect(validCachedUpdatesSnapshot({ ...s, metadata: { ...s.metadata, freshness: 'fresh' } })).toBe(false);
        expect(validCachedUpdatesSnapshot({ ...s, metadata: { ...s.metadata, ageSeconds: 1 } })).toBe(false);
    });
    it('rejects unsupported release, false zero, overflow, missing and extra fields', () => {
        const s = cachedUpdatesSnapshot(); for (const bad of [{ ...s, candidateCount: 0 }, { ...s, checkedCount: 4294967295, unknownCount: 4 }, { ...s, coverage: 'unavailable' }, { ...s, release: { ...s.release, id: 'linuxmint' } }, { ...s, cveCount: 0 }, { ...s, items: null }, { ...s, items: [{ ...s.items[0], candidateVersion: '0.1' }] }]) expect(validCachedUpdatesSnapshot(bad)).toBe(false);
        expect(validCachedUpdatesView(cachedUpdatesView(), 'agent_other')).toBe(false);
    });
    it('keeps exact truncated counts while labeling missing candidates', () => {
        const s = cachedUpdatesSnapshot(); s.items = [s.items[0]]; s.truncated = true; s.coverage = 'partial'; s.reason = 'byte_limit'; expect(validCachedUpdatesSnapshot(s)).toBe(true);
        s.heldCount = 2; expect(validCachedUpdatesSnapshot(s)).toBe(false);
    });
    it('ages and expires original collection independently of a later receipt', () => {
        expect(cachedUpdatesAgeStatus(cachedUpdatesView(), 110000)).toBe('fresh'); expect(cachedUpdatesAgeStatus(cachedUpdatesView(), 110001)).toBe('stale'); expect(cachedUpdatesAgeStatus(cachedUpdatesView(), 86400000)).toBe('expired'); expect(cachedUpdatesAgeStatus(cachedUpdatesView(), Infinity)).toBe('unknown');
    });
    it.each([['1:10-1', '2:1-1', -1], ['2.0~rc1-1', '2.0-1', -1], ['1.0-1', '1.0-1+b1', -1], ['1.01', '1.1', 0], ['1.0', '1.0-0', 0], ['1.0+git', '1.0a', 1], ['1.0-2', '1.0-1', 1]])('mirrors bounded Debian ordering %s / %s', (a, b, n) => expect(cachedDebianCompare(a, b)).toBe(n));
    it('rejects injection and unsupported comparator epochs', () => { expect(cachedDebianCompare('1', '$(touch /tmp/x)')).toBeNull(); expect(cachedDebianCompare('2147483648:1', '2')).toBeNull(); });
});
