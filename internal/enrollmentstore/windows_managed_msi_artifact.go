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

const windowsManagedMSIFleetSetupVersion = "tracebolt.windows-managed-msi-setup.v2"
const windowsManagedMSIFleetArtifactSchema = `CREATE TABLE enrollment_windows_msi_fleet_artifact(id INTEGER PRIMARY KEY CHECK(id=1),body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=262144)) STRICT`

func windowsManagedMSIFleetArtifactPresent(ctx context.Context, c *sql.Conn) (bool, error) {
	var n int
	if c.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE name='enrollment_windows_msi_fleet_artifact'`).Scan(&n) != nil || n > 1 {
		return false, ErrStorage
	}
	return n == 1, nil
}
func managedMSIBindingAlias(a, b msi.Binding) bool {
	return a.DeviceID == b.DeviceID || a.ExecutorID == b.ExecutorID || a.ExecutorKeyID == b.ExecutorKeyID || a.DeliveryGrantID == b.DeliveryGrantID || a.DeliveryGrantID == b.InstallGrantID || a.InstallGrantID == b.DeliveryGrantID || a.InstallGrantID == b.InstallGrantID
}

// This separate create-only version never adopts singleton v1 state.
func (s *Store) SetupWindowsManagedMSIFleetCreateOnly(ctx context.Context, key, executor ed25519.PublicKey, g msi.Grant, now time.Time, additional bool) error {
	return s.setupWindowsManagedMSICreateOnly(ctx, key, executor, g, now, additional, true)
}
func readWindowsManagedMSIArtifact(ctx context.Context, c *sql.Conn) (msi.ArtifactRecord, error) {
	var n int
	var raw []byte
	if c.QueryRowContext(ctx, `SELECT count(*) FROM enrollment_windows_msi_fleet_artifact`).Scan(&n) != nil || n != 1 || c.QueryRowContext(ctx, `SELECT body FROM enrollment_windows_msi_fleet_artifact WHERE id=1`).Scan(&raw) != nil {
		return msi.ArtifactRecord{}, ErrStorage
	}
	r, e := msi.DecodeArtifactRecord(raw)
	if e != nil {
		return msi.ArtifactRecord{}, ErrStorage
	}
	return r, nil
}
func (s *Store) ReadWindowsManagedMSIArtifact(ctx context.Context, key ed25519.PublicKey) (msi.ArtifactRecord, error) {
	var out msi.ArtifactRecord
	if s == nil || ctx == nil {
		return out, msi.ErrInvalid
	}
	e := s.transact(ctx, func(t *transaction) error {
		if e := s.checkWindowsManagedMSIKey(ctx, t, key); e != nil {
			return e
		}
		var e error
		out, e = readWindowsManagedMSIArtifact(ctx, t.conn)
		if e != nil {
			return e
		}
		return msi.CheckFinal(ctx)
	})
	return out, e
}
func (s *Store) WindowsManagedMSIFleetBindings(ctx context.Context, key ed25519.PublicKey) ([]msi.Binding, error) {
	var out []msi.Binding
	if s == nil || ctx == nil {
		return nil, msi.ErrInvalid
	}
	e := s.transact(ctx, func(t *transaction) error {
		if e := s.checkWindowsManagedMSIKey(ctx, t, key); e != nil {
			return e
		}
		for _, c := range t.credentials {
			if m := c.WindowsManagedMSISetup; m != nil {
				if m.Version != windowsManagedMSIFleetSetupVersion {
					return msi.ErrAuthority
				}
				out = append(out, m.Grant.Binding)
			}
		}
		return msi.CheckFinal(ctx)
	})
	sort.Slice(out, func(i, j int) bool { return out[i].DeviceID < out[j].DeviceID })
	return out, e
}

// Shared custody checks named operator/configuration after storage waits, never
// borrows a first endpoint's grant, leaf, expiry, or revocation authority.
func (s *Store) WindowsManagedMSIArtifactTransaction(ctx context.Context, key ed25519.PublicKey, now time.Time, fn func(*msi.ArtifactRecord, time.Time) error) (msi.ArtifactRecord, error) {
	var out msi.ArtifactRecord
	if s == nil || ctx == nil || fn == nil || !validStoreTime(now) {
		return out, msi.ErrInvalid
	}
	wrote := false
	e := s.transact(ctx, func(t *transaction) error {
		if e := s.checkWindowsManagedMSIKey(ctx, t, key); e != nil {
			return e
		}
		before, e := readWindowsManagedMSIArtifact(ctx, t.conn)
		if e != nil {
			return e
		}
		raw, _ := json.Marshal(before)
		after, e := msi.DecodeArtifactRecord(raw)
		if e != nil {
			return e
		}
		at, e := windowsManagedMSINow(ctx, now)
		if e != nil || at.Before(now) || at.Unix() < before.ClockFloor {
			return msi.ErrExpired
		}
		after.ClockFloor = at.Unix()
		if e = fn(&after, at); e != nil {
			return e
		}
		if after.Validate() != nil || after.Version != before.Version || after.ClockFloor != at.Unix() || msi.ArtifactTransition(before.Artifact, after.Artifact) != nil {
			return msi.ErrIntegrity
		}
		t.beforeCommit = append(t.beforeCommit, func() error {
			if e := msi.CheckFinal(ctx); e != nil {
				return e
			}
			fresh, e := windowsManagedMSINow(ctx, at)
			if e != nil || fresh.Before(at) {
				return msi.ErrExpired
			}
			after.ClockFloor = fresh.Unix()
			raw, e := json.Marshal(after)
			if e != nil || len(raw) > msi.MaxRecordBytes {
				return msi.ErrIntegrity
			}
			wrote = true
			if _, e = t.conn.ExecContext(ctx, `UPDATE enrollment_windows_msi_fleet_artifact SET body=? WHERE id=1`, raw); e != nil {
				return ErrStorage
			}
			if e = s.loadWindowsManagedMSIRecords(ctx, t); e != nil {
				return e
			}
			if e = msi.CheckFinal(ctx); e != nil {
				return e
			}
			last, e := windowsManagedMSINow(ctx, fresh)
			if e != nil || last.Before(fresh) {
				return msi.ErrExpired
			}
			out = after
			return nil
		})
		return nil
	})
	if e != nil {
		if wrote {
			return msi.ArtifactRecord{}, msi.ErrUncertain
		}
		return msi.ArtifactRecord{}, e
	}
	return out, nil
}
