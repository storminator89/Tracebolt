package enrollmentstore

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"localrmm/internal/inventoryledger"
	msi "localrmm/internal/windowsmanagedmsi"
	"time"
)

const windowsMSIWorklistsSchema = `CREATE TABLE enrollment_windows_msi_worklists(id INTEGER PRIMARY KEY CHECK(id=1),body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=2363392)) STRICT`

func windowsMSIWorklistsPresent(ctx context.Context, c *sql.Conn) (bool, error) {
	var n int
	if c.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE name='enrollment_windows_msi_worklists'`).Scan(&n) != nil || n > 1 {
		return false, ErrStorage
	}
	return n == 1, nil
}
func windowsMSIWorklistsObject() inventoryledger.SchemaObject {
	return inventoryledger.SchemaObject{Type: "table", Name: "enrollment_windows_msi_worklists", SQL: windowsMSIWorklistsSchema}
}
func readWindowsMSIWorklists(ctx context.Context, c *sql.Conn) (msi.WorklistJournal, error) {
	var n int
	var raw []byte
	if c.QueryRowContext(ctx, `SELECT count(*) FROM enrollment_windows_msi_worklists`).Scan(&n) != nil || n != 1 || c.QueryRowContext(ctx, `SELECT body FROM enrollment_windows_msi_worklists WHERE id=1`).Scan(&raw) != nil {
		return msi.WorklistJournal{}, ErrStorage
	}
	j, e := msi.DecodeWorklistJournal(raw)
	if e != nil {
		return j, ErrStorage
	}
	return j, nil
}
func (s *Store) loadWindowsMSIWorklists(ctx context.Context, t *transaction) error {
	present, e := windowsMSIWorklistsPresent(ctx, t.conn)
	if e != nil {
		return e
	}
	version := ""
	count := 0
	key, manager := "", ""
	for _, c := range t.credentials {
		if m := c.WindowsManagedMSISetup; m != nil {
			if count > 0 && version != m.WorklistsVersion {
				return ErrStorage
			}
			version = m.WorklistsVersion
			count++
			key = m.Grant.Binding.KeyID
			manager = m.Grant.Binding.ManagerID
		}
	}
	if present != (version == msi.WorklistVersion) || version != "" && version != msi.WorklistVersion {
		return ErrStorage
	}
	if !present {
		return nil
	}
	if count == 0 {
		return ErrStorage
	}
	j, e := readWindowsMSIWorklists(ctx, t.conn)
	if e != nil || j.KeyID != key || j.ManagerID != manager {
		return ErrStorage
	}
	return nil
}
func (s *Store) ReadWindowsMSIWorklists(ctx context.Context, key ed25519.PublicKey) (msi.WorklistJournal, error) {
	var out msi.WorklistJournal
	if s == nil || ctx == nil {
		return out, msi.ErrInvalid
	}
	e := s.transact(ctx, func(t *transaction) error {
		if e := s.checkWindowsManagedMSIKey(ctx, t, key); e != nil {
			return e
		}
		present, e := windowsMSIWorklistsPresent(ctx, t.conn)
		if e != nil {
			return e
		}
		if !present {
			return msi.ErrUnavailable
		}
		out, e = readWindowsMSIWorklists(ctx, t.conn)
		if e != nil {
			return e
		}
		return msi.CheckFinal(ctx)
	})
	if e != nil {
		return msi.WorklistJournal{}, e
	}
	return out, nil
}
func writeWindowsMSIWorklists(ctx context.Context, t *transaction, j msi.WorklistJournal) error {
	if j.Validate() != nil {
		return ErrStorage
	}
	raw, e := json.Marshal(j)
	if e != nil {
		return ErrStorage
	}
	result, e := t.conn.ExecContext(ctx, `UPDATE enrollment_windows_msi_worklists SET body=? WHERE id=1`, raw)
	if e != nil {
		return ErrStorage
	}
	n, e := result.RowsAffected()
	if e != nil || n != 1 {
		return ErrStorage
	}
	return nil
}

// One narrowly scoped metadata transaction. Original endpoint authority is sampled
// for the exact selected bindings before and after every blocking final check.
// GET never calls the write callback; missing used state is never reconstructed.
func (s *Store) WindowsMSIWorklistTransaction(ctx context.Context, key ed25519.PublicKey, now time.Time, bindings []msi.Binding, fn func(*msi.WorklistJournal, msi.ArtifactRecord, map[string]msi.Record, time.Time) error) (msi.WorklistJournal, error) {
	var out msi.WorklistJournal
	if s == nil || ctx == nil || fn == nil || !validStoreTime(now) || len(bindings) > msi.MaxDevices {
		return out, msi.ErrInvalid
	}
	wrote := false
	e := s.transact(ctx, func(t *transaction) error {
		if e := s.checkWindowsManagedMSIKey(ctx, t, key); e != nil {
			return e
		}
		present, e := windowsMSIWorklistsPresent(ctx, t.conn)
		if e != nil {
			return e
		}
		if !present {
			return msi.ErrUnavailable
		}
		before, e := readWindowsMSIWorklists(ctx, t.conn)
		if e != nil {
			return e
		}
		raw, _ := json.Marshal(before)
		j, e := msi.DecodeWorklistJournal(raw)
		if e != nil {
			return e
		}
		initial, e := windowsManagedMSINow(ctx, now)
		if e != nil || initial.Before(now) || initial.Unix() < before.ClockFloor {
			return msi.ErrExpired
		}
		a, e := readWindowsManagedMSIArtifact(ctx, t.conn)
		if e != nil || a.Version != msi.ReusableArtifactRecordVersion {
			return msi.ErrUnavailable
		}
		records := map[string]msi.Record{}
		rows, readErr := t.conn.QueryContext(ctx, `SELECT body FROM enrollment_windows_managed_msi_records`)
		if readErr != nil {
			return ErrStorage
		}
		for rows.Next() {
			var raw []byte
			if rows.Scan(&raw) != nil {
				rows.Close()
				return ErrStorage
			}
			record, err := msi.DecodeRecord(raw)
			if err != nil {
				rows.Close()
				return ErrStorage
			}
			records[record.Grant.Binding.DeviceID] = record
		}
		readErr = rows.Err()
		rows.Close()
		if readErr != nil {
			return ErrStorage
		}
		selected := map[string]bool{}
		currents := map[string]msi.Current{}
		invites := map[string]string{}
		for _, b := range bindings {
			if selected[b.DeviceID] {
				return msi.ErrInvalid
			}
			snap, e := systemDevice(t, b.DeviceID)
			if e != nil {
				return msi.ErrAuthority
			}
			var raw []byte
			if t.conn.QueryRowContext(ctx, `SELECT body FROM enrollment_windows_managed_msi_records WHERE invitation_id=?`, snap.InvitationID).Scan(&raw) != nil {
				return msi.ErrUnavailable
			}
			r, e := msi.DecodeRecord(raw)
			if e != nil {
				return ErrStorage
			}
			selected[b.DeviceID] = true
			if r.Grant.Binding != b || r.Grant.Version != msi.ReusableGrantVersion {
				return msi.ErrAuthority
			}
			c, e := s.windowsManagedMSICurrent(t, snap.InvitationID, b, r.Grant, initial)
			if e != nil {
				return e
			}
			records[b.DeviceID] = r
			currents[b.DeviceID] = c
			invites[b.DeviceID] = snap.InvitationID
		}
		if e = fn(&j, a, records, initial); e != nil {
			return e
		}
		if j.Revision >= msi.MaxWorklistRevision {
			return msi.ErrConsumed
		}
		j.Revision++
		j.ClockFloor = initial.Unix()
		if msi.WorklistJournalTransition(before, j, records) != nil {
			return msi.ErrIntegrity
		}
		t.beforeCommit = append(t.beforeCommit, func() error {
			if e := msi.CheckFinal(ctx); e != nil {
				return e
			}
			fresh, e := windowsManagedMSINow(ctx, initial)
			if e != nil || fresh.Before(initial) || fresh.Unix() < before.ClockFloor {
				return msi.ErrExpired
			}
			for _, b := range bindings {
				r := records[b.DeviceID]
				c, e := s.windowsManagedMSICurrent(t, invites[b.DeviceID], b, r.Grant, fresh)
				if e != nil {
					return e
				}
				if c != currents[b.DeviceID] {
					return msi.ErrAuthority
				}
			}
			// A newly confirmed batch cannot age past its original deadline while a
			// session/configuration guard blocks. Closing does not extend that deadline.
			for _, w := range j.Worklists {
				old := before.Find(w.ID)
				for _, b := range w.Batches {
					found := false
					if old != nil {
						for _, ob := range old.Batches {
							if ob.ID == b.ID {
								found = true
							}
						}
					}
					if !found && fresh.Unix() >= b.ExpiresAt {
						return msi.ErrExpired
					}
				}
			}
			j.ClockFloor = fresh.Unix()
			if s.checkPath() != nil {
				return ErrStorage
			}
			wrote = true
			if e = writeWindowsMSIWorklists(ctx, t, j); e != nil {
				return e
			}
			if e = s.loadWindowsMSIWorklists(ctx, t); e != nil {
				return e
			}
			out = j
			return ctx.Err()
		})
		return nil
	})
	if e != nil {
		if wrote || errors.Is(e, ErrStorage) {
			return msi.WorklistJournal{}, msi.ErrUncertain
		}
		return msi.WorklistJournal{}, e
	}
	return out, nil
}
