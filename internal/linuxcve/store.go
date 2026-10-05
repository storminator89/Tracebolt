package linuxcve

import (
	"localrmm/internal/linuxpackages"
	"time"
)

// Replace is separate from Parse so the caller can recheck its operator lease
// immediately before promotion. No caller-controlled trust or rules are accepted.
func (s *Store) Replace(snapshot *Snapshot, now time.Time) error {
	return s.ReplaceWith(snapshot, now, nil)
}

// ReplaceWith checks anti-rollback, persists through the caller callback, then
// publishes one atomic memory snapshot. A persistence failure retains last-good.
// The callback runs under the store lock and must not re-enter this store.
func (s *Store) ReplaceWith(snapshot *Snapshot, now time.Time, persist func() error) error {
	if snapshot == nil || !snapshot.valid || !validTime(now) || snapshot.metadata.ValidatedAt.After(now) || snapshot.metadata.FetchedAt.After(now) {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if prior := s.snapshots[snapshot.metadata.Target]; prior != nil {
		if snapshot.metadata.FetchedAt.Before(prior.metadata.FetchedAt) || snapshot.metadata.FetchedAt.Equal(prior.metadata.FetchedAt) && snapshot.metadata.SHA256 != prior.metadata.SHA256 {
			return ErrRollback
		}
	}
	if persist != nil {
		if err := persist(); err != nil {
			return err
		}
	}
	if s.snapshots == nil {
		s.snapshots = make(map[linuxpackages.ReleaseTarget]*Snapshot)
	}
	s.snapshots[snapshot.metadata.Target] = snapshot
	at := now.UTC()
	s.lastAttemptAt = &at
	s.outcome, s.failureReason = "success", ""
	return nil
}

func (s *Store) Snapshot(target linuxpackages.ReleaseTarget) *Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.snapshots[target]
}

func (s *Store) RecordFailure(now time.Time, reason string) {
	switch reason {
	case ErrInvalid.Error(), ErrLimit.Error(), ErrCanceled.Error(), ErrRollback.Error(), "import_failed", "operator_lease_expired", "sync_failed", "cache_load_failed", "cache_write_failed", "cache_commit_uncertain":
	default:
		reason = "import_failed"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if validTime(now) {
		at := now.UTC()
		s.lastAttemptAt = &at
	}
	s.outcome, s.failureReason = "failed", reason
}

func (s *Store) View(now time.Time) StoreView {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.viewLocked(now)
}

// SnapshotView captures an index and its display metadata under one read lock.
// An import racing a response cannot mix generations of feed metadata.
func (s *Store) SnapshotView(target linuxpackages.ReleaseTarget, now time.Time) (*Snapshot, StoreView) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.snapshots[target], s.viewLocked(now)
}

func (s *Store) viewLocked(now time.Time) StoreView {
	v := StoreView{Snapshots: []FeedMetadata{}, Outcome: s.outcome, FailureReason: s.failureReason}
	if v.Outcome == "" {
		v.Outcome = "never_attempted"
	}
	if s.lastAttemptAt != nil {
		at := *s.lastAttemptAt
		v.LastAttemptAt = &at
	}
	for _, target := range []linuxpackages.ReleaseTarget{linuxpackages.Debian13, linuxpackages.Ubuntu2404} {
		if snapshot := s.snapshots[target]; snapshot != nil {
			v.Snapshots = append(v.Snapshots, snapshot.Metadata(now))
		}
	}
	return v
}
