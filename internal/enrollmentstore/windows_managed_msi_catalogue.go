package enrollmentstore

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	msi "localrmm/internal/windowsmanagedmsi"
	"sort"
	"time"
)

func readWindowsMSIArtifactBody(ctx context.Context, c *sql.Conn) ([]byte, error) {
	var n int
	var raw []byte
	if c.QueryRowContext(ctx, `SELECT count(*) FROM enrollment_windows_msi_fleet_artifact`).Scan(&n) != nil || n != 1 || c.QueryRowContext(ctx, `SELECT body FROM enrollment_windows_msi_fleet_artifact WHERE id=1`).Scan(&raw) != nil {
		return nil, ErrStorage
	}
	return raw, nil
}
func readWindowsMSICatalogue(ctx context.Context, c *sql.Conn) (msi.CatalogueRecord, error) {
	raw, e := readWindowsMSIArtifactBody(ctx, c)
	if e != nil {
		return msi.CatalogueRecord{}, e
	}
	var h struct {
		Version string `json:"version"`
	}
	if json.Unmarshal(raw, &h) != nil {
		return msi.CatalogueRecord{}, ErrStorage
	}
	if h.Version != msi.CatalogueRecordVersion {
		return msi.CatalogueRecord{}, msi.ErrUnavailable
	}
	r, e := msi.DecodeCatalogueRecord(raw)
	if e != nil {
		return r, ErrStorage
	}
	return r, nil
}
func writeWindowsMSICatalogue(ctx context.Context, c *sql.Conn, r msi.CatalogueRecord) error {
	if r.Validate() != nil {
		return msi.ErrIntegrity
	}
	raw, e := json.Marshal(r)
	if e != nil || len(raw) > msi.MaxRecordBytes {
		return msi.ErrIntegrity
	}
	result, e := c.ExecContext(ctx, `UPDATE enrollment_windows_msi_fleet_artifact SET body=? WHERE id=1`, raw)
	if e != nil {
		return ErrStorage
	}
	if n, e := result.RowsAffected(); e != nil || n != 1 {
		return ErrStorage
	}
	return nil
}
func (s *Store) ReadWindowsMSICatalogue(ctx context.Context, key ed25519.PublicKey) (msi.CatalogueRecord, error) {
	var r msi.CatalogueRecord
	if s == nil || ctx == nil {
		return r, msi.ErrInvalid
	}
	e := s.transact(ctx, func(t *transaction) error {
		if e := s.checkWindowsManagedMSIKey(ctx, t, key); e != nil {
			return e
		}
		var e error
		r, e = readWindowsMSICatalogue(ctx, t.conn)
		if e != nil {
			return e
		}
		return msi.CheckFinal(ctx)
	})
	return r, e
}

// This path is called only by explicitly acknowledged fresh manager setup. It
// does not migrate any existing registry or change endpoint grant bytes.
func (s *Store) SetupWindowsMSICatalogueCreateOnly(ctx context.Context, key, executor ed25519.PublicKey, g msi.Grant, now time.Time, additional bool) error {
	if !g.Reusable() {
		return msi.ErrInvalid
	}
	return s.setupWindowsManagedMSICreateOnly(ctx, key, executor, g, now, additional, true, true)
}
func (s *Store) ReserveWindowsMSICatalogue(ctx context.Context, key ed25519.PublicKey, now time.Time, revision uint64, a msi.Artifact) (msi.CatalogueRecord, error) {
	var out msi.CatalogueRecord
	if s == nil || ctx == nil || !validStoreTime(now) || !msi.ValidSelection(a.Package) || !msi.ValidDigest(a.NativeAcceptanceDigest) || !msi.ValidPublisherEvidence(a.PublisherStatus, a.PublisherEvidenceDigest) {
		return out, msi.ErrInvalid
	}
	wrote := false
	e := s.transact(ctx, func(t *transaction) error {
		if e := s.checkWindowsManagedMSIKey(ctx, t, key); e != nil {
			return e
		}
		r, e := readWindowsMSICatalogue(ctx, t.conn)
		if e != nil {
			return e
		}
		at, e := windowsManagedMSINow(ctx, now)
		if e != nil || at.Before(now) || at.Unix() < r.ClockFloor {
			return msi.ErrExpired
		}
		if r.Revision != revision || r.Revision == ^uint64(0) || r.Sequence == ^uint64(0) {
			return msi.ErrConflict
		}
		if r.ReservedBytes()+a.Package.Size > msi.MaxRetainedPayloadBytes {
			return msi.ErrConsumed
		}
		journal, e := readWindowsMSIWorklists(ctx, t.conn)
		if e != nil || journal.Version != msi.CatalogueWorklistVersion {
			return ErrStorage
		}
		active := map[uint64]bool{}
		for _, w := range journal.Worklists {
			if w.ArchivedAt == 0 {
				active[w.ArtifactRetiredCount] = true
			}
		}
		used := map[uint32]bool{}
		for _, entry := range r.Entries {
			if !entry.Retired || active[entry.RetiredCount] {
				used[*entry.CatalogueSlot] = true
			}
		}
		var slot uint32
		for slot < msi.MaxCatalogueEntries && used[slot] {
			slot++
		}
		if slot == msi.MaxCatalogueEntries {
			return msi.ErrConsumed
		}
		kept := []msi.ArtifactRecord{}
		for _, entry := range r.Entries {
			if *entry.CatalogueSlot == slot {
				if !entry.Retired {
					return msi.ErrConflict
				}
				raw, _ := json.Marshal(entry)
				r.RetiredChain = msi.Digest(append([]byte("Tracebolt catalogue retired custody v1\x00"+r.RetiredChain+"\x00"), raw...))
			} else {
				kept = append(kept, entry)
			}
		}
		// Reserve the full declared size before creating or accepting any bytes.
		r.Sequence++
		r.Revision++
		r.ClockFloor = at.Unix()
		a = msi.Artifact{Package: a.Package, NativeAcceptanceDigest: a.NativeAcceptanceDigest, PublisherStatus: a.PublisherStatus, PublisherEvidenceDigest: a.PublisherEvidenceDigest}
		a.IntentAt = at.Unix()
		a.PrefixDigest = msi.Digest(nil)
		r.Entries = append(kept, msi.ArtifactRecord{Version: msi.CatalogueArtifactRecordVersion, RetiredCount: r.Sequence, CatalogueSlot: &slot, Artifact: &a, ClockFloor: at.Unix()})
		t.beforeCommit = append(t.beforeCommit, func() error {
			if e := msi.CheckFinal(ctx); e != nil {
				return e
			}
			fresh, e := windowsManagedMSINow(ctx, at)
			if e != nil || fresh.Before(at) {
				return msi.ErrExpired
			}
			r.ClockFloor = fresh.Unix()
			r.Entries[len(r.Entries)-1].ClockFloor = fresh.Unix()
			wrote = true
			if e = writeWindowsMSICatalogue(ctx, t.conn, r); e != nil {
				return e
			}
			if e = s.loadWindowsManagedMSIRecords(ctx, t); e != nil {
				return e
			}
			if e = msi.CheckFinal(ctx); e != nil {
				return e
			}
			out = r
			return nil
		})
		return nil
	})
	if e != nil && wrote {
		return msi.CatalogueRecord{}, msi.ErrUncertain
	}
	return out, e
}

// Exact entry admission and assignment evidence share the job transaction. A
// catalogue retirement intent wins against concurrent delivery, or delivery wins
// and records an unresolved assignment that blocks retirement.
func updateWindowsMSICatalogueAssignment(ctx context.Context, c *sql.Conn, before, after msi.Record) error {
	r, e := readWindowsMSICatalogue(ctx, c)
	if e != nil {
		return e
	}
	if after.Artifact == nil {
		return nil
	}
	a := r.Find(after.ArtifactRetiredCount)
	if a == nil {
		if after.TransferID == before.TransferID && len(after.RetiredReport) > 0 {
			return nil
		}
		return msi.ErrIntegrity
	}
	assignment := a.Assignment(after.Grant.Binding)
	if after.TransferID != before.TransferID {
		if assignment != nil || a.RetirementStarted || a.Retired || a.Artifact == nil || a.Artifact.CompletedAt == 0 || *a.Artifact != *after.Artifact || after.Jobs == nil {
			return msi.ErrConsumed
		}
		a.Assignments = append(a.Assignments, msi.CatalogueAssignment{Binding: after.Grant.Binding, TransferID: after.TransferID, JobSequence: after.Jobs.Sequence})
		sort.Slice(a.Assignments, func(i, j int) bool { return a.Assignments[i].Binding.DeviceID < a.Assignments[j].Binding.DeviceID })
		assignment = a.Assignment(after.Grant.Binding)
	}
	if assignment == nil || assignment.TransferID != after.TransferID || after.Jobs == nil || assignment.JobSequence != after.Jobs.Sequence {
		return msi.ErrIntegrity
	}
	changed := after.TransferID != before.TransferID
	if len(after.RetiredReport) > 0 && len(before.RetiredReport) == 0 {
		if assignment.RetirementDigest != "" {
			return msi.ErrIntegrity
		}
		assignment.RetirementDigest = msi.Digest(after.RetiredReport)
		assignment.ResultDigest = msi.Digest(after.ResultReport)
		changed = true
	}
	if !changed {
		return nil
	}
	if r.Revision == ^uint64(0) {
		return msi.ErrConsumed
	}
	r.Revision++
	a.ClockFloor = max(a.ClockFloor, after.ClockFloor)
	r.ClockFloor = max(r.ClockFloor, after.ClockFloor)
	return writeWindowsMSICatalogue(ctx, c, r)
}
func validateWindowsMSICatalogueRecords(r msi.CatalogueRecord, records map[string]msi.Record) error {
	for _, a := range r.Entries {
		for _, assignment := range a.Assignments {
			record, ok := records[assignment.Binding.DeviceID]
			if !ok || record.Grant.Binding != assignment.Binding || record.Jobs == nil || record.Jobs.Sequence < assignment.JobSequence {
				return ErrStorage
			}
			if record.Jobs.Sequence == assignment.JobSequence {
				if references, e := msi.ReferencesArtifactOccurrence(record, a); e != nil || !references {
					return ErrStorage
				}
			} else if assignment.RetirementDigest == "" {
				return ErrStorage
			}
		}
	}
	return nil
}
