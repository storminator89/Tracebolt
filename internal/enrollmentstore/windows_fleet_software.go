package enrollmentstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/windowsfullsoftware"
	ledger "localrmm/internal/windowsfullsoftwareledger"
	"sort"
	"time"
)

type fleetSoftwareEntry struct {
	Snapshot     enrollmentstate.Snapshot
	Identity     string
	Leaf         string
	Until        time.Time
	Record       ledger.Record
	ManifestHash string
}

func fleetSoftwareHash(v any) string {
	raw, _ := json.Marshal(v)
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

func fleetSoftwareQueryHash(q windowsfullsoftware.FleetQuery) string {
	// Canonical exact filters are bound without repeating escaped private text in
	// every cursor. Valid maximum-length query bytes cannot inflate cursor size.
	return fleetSoftwareHash(struct{ Name, Version string }{q.Name, q.Version})
}

// Read all authority metadata under one enrollment transaction. No model.Device
// or other ID-only snapshot is joined, and no personal software table is read.
func (s *Store) fleetSoftwareRoster(ctx context.Context, t *transaction, now time.Time) ([]fleetSoftwareEntry, string, time.Time, error) {
	entries := []fleetSoftwareEntry{}
	snapshots := t.engine.Snapshots()
	if len(snapshots) > windowsfullsoftware.FleetDeviceLimit {
		return nil, "", time.Time{}, ErrStorage
	}
	deadline := now.Add(windowsfullsoftware.FleetCursorLifetime)
	seen := map[string]bool{}
	for _, snap := range snapshots {
		if e := ctx.Err(); e != nil {
			return nil, "", time.Time{}, e
		}
		device := snap.Approval.DeviceID
		if device != "" {
			if seen[device] {
				return nil, "", time.Time{}, ErrStorage
			}
			seen[device] = true
		}
		if snap.State != enrollmentstate.Activated || now.Unix() >= t.currentCredentialNotAfter(snap) {
			continue
		}
		if _, e := s.windowsFullSoftwareAuthority(t, snap.InvitationID, t.currentCertificateHash(snap), now); e != nil {
			return nil, "", time.Time{}, e
		}
		r, e := readWindowsFullSoftwareRecord(ctx, t, device)
		if e != nil {
			return nil, "", time.Time{}, e
		}
		entry := fleetSoftwareEntry{Snapshot: snap, Identity: fleetSoftwareHash(struct {
			Binding                    enrollmentstate.Binding
			Device, Invitation, Issued string
		}{snap.Binding, device, snap.InvitationID, snap.Issuance.CertificateHash}), Leaf: t.currentCertificateHash(snap), Until: time.Unix(t.currentCredentialNotAfter(snap), 0).UTC(), Record: r}
		if entry.Until.Before(deadline) {
			deadline = entry.Until
		}
		if r.Current != "" {
			g, e := ledger.LoadGeneration(ctx, t.conn, device, r.Current)
			if e != nil {
				return nil, "", time.Time{}, e
			}
			entry.ManifestHash = g.Hash
			if now.Before(g.Manifest.ExpiresAt) && g.Manifest.ExpiresAt.Before(deadline) {
				deadline = g.Manifest.ExpiresAt
			}
		}
		if r.Pending != "" {
			g, e := ledger.LoadGeneration(ctx, t.conn, device, r.Pending)
			if e != nil {
				return nil, "", time.Time{}, e
			}
			for _, until := range []time.Time{g.StartedAt.Add(ledger.StagingTTL), g.Manifest.ExpiresAt} {
				if now.Before(until) && until.Before(deadline) {
					deadline = until
				}
			}
		}
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Snapshot.Approval.DeviceID < entries[j].Snapshot.Approval.DeviceID
	})
	return entries, fleetSoftwareHash(entries), deadline, nil
}

func (s *Store) WindowsFleetSoftwarePage(ctx context.Context, q windowsfullsoftware.FleetQuery, now time.Time) (windowsfullsoftware.FleetPage, error) {
	zero := windowsfullsoftware.FleetPage{}
	release, e := s.windowsFullSoftwareAdmission(ctx)
	if e != nil {
		return zero, e
	}
	defer release()
	if windowsfullsoftware.ValidateFleetQuery(q) != nil || !validStoreTime(now) {
		return zero, windowsfullsoftware.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out := windowsfullsoftware.FleetPage{SchemaVersion: windowsfullsoftware.FleetPageVersion, Name: q.Name, Version: q.Version, Status: "ready", Mode: "fleet", Items: []windowsfullsoftware.FleetItem{}}
	e = s.transact(ctx, func(t *transaction) error {
		var e error
		now, e = overviewNow(ctx, now)
		if e != nil {
			return e
		}
		out.ServerNow = now
		session, e := fullSoftwareSession(ctx, now)
		if e != nil {
			return e
		}
		if session.id == "" {
			return enrollmentstate.ErrProof
		}
		out.SessionID = session.id
		present, e := windowsFullSoftwareSchemaPresent(ctx, t.conn, s.config.Binding.CollectionProfile)
		if e != nil {
			return e
		}
		if !present {
			if q.Cursor != "" {
				return windowsfullsoftware.ErrConflict
			}
			out.Status = "not_configured"
			t.beforeCommit = append(t.beforeCommit, func() error { return s.recheckFleetSoftwareTransaction(ctx, t, out, &now) })
			return nil
		}
		if e = ledger.Clock(ctx, t.conn, now); e != nil {
			return e
		}
		entries, digest, deadline, e := s.fleetSoftwareRoster(ctx, t, now)
		if e != nil {
			return e
		}
		if session.until.Before(deadline) {
			deadline = session.until.UTC()
		}
		out.TotalDevices = len(entries)
		out.RosterDigest = digest
		c := ledger.FleetCursor{Version: 1, Roster: digest, QueryDigest: fleetSoftwareQueryHash(q), Session: session.id, Mode: "fleet", ExpiresAt: deadline}
		if q.Cursor != "" {
			c, e = ledger.OpenFleetCursor(ctx, t.conn, q.Cursor)
			if e != nil {
				return e
			}
			if c.Roster != digest || c.QueryDigest != fleetSoftwareQueryHash(q) || c.Session != session.id || !now.Before(c.ExpiresAt) || c.ExpiresAt.After(deadline) {
				return windowsfullsoftware.ErrConflict
			}
		}
		out.Mode = c.Mode
		out.Offset = c.Offset
		out.CursorExpiresAt = &c.ExpiresAt
		start, end, limit, rowOffset := c.Offset, c.Offset+windowsfullsoftware.FleetPageDevices, windowsfullsoftware.FleetPreviewRows, 0
		if c.Mode == "device" {
			start = -1
			for i, entry := range entries {
				if entry.Snapshot.Approval.DeviceID == c.Device {
					start = i
					break
				}
			}
			if start < 0 {
				return windowsfullsoftware.ErrConflict
			}
			end = start + 1
			limit = windowsfullsoftware.FleetDetailRows
			rowOffset = c.Offset
		} else if start > len(entries) || start == len(entries) && start != 0 {
			return windowsfullsoftware.ErrConflict
		}
		if end > len(entries) {
			end = len(entries)
		}
		for i := start; i < end; i++ {
			entry := entries[i]
			id := entry.Snapshot.Approval.DeviceID
			p, e := ledger.Page(ctx, t.conn, id, entry.Record, windowsfullsoftware.Query{Sort: "name-asc", Limit: 1}, now, entry.Until, session.id, session.until)
			if e != nil {
				return e
			}
			item := windowsfullsoftware.FleetItem{DeviceID: id, Identity: entry.Identity, Status: p.Status, AuthorityUntil: entry.Until, Complete: p.Complete, LatestAttempt: p.LatestAttempt, Rows: []windowsfullsoftware.Row{}}
			if p.Status == "ready" {
				item.Rows, item.MatchingCount, item.UnknownCount, e = ledger.FleetMatches(ctx, t.conn, p, q, rowOffset, limit)
				if e != nil {
					return e
				}
				if c.Mode == "fleet" {
					detail := c
					detail.Mode = "device"
					detail.Device = id
					detail.Offset = 0
					item.DetailCursor, e = ledger.SealFleetCursor(ctx, t.conn, detail)
					if e != nil {
						return e
					}
				}
				if c.Mode == "device" && rowOffset+len(item.Rows) < item.MatchingCount {
					next := c
					next.Offset += len(item.Rows)
					out.NextCursor, e = ledger.SealFleetCursor(ctx, t.conn, next)
					if e != nil {
						return e
					}
				}
			} else if c.Mode == "device" {
				return windowsfullsoftware.ErrConflict
			}
			out.Items = append(out.Items, item)
		}
		if c.Mode == "fleet" && end < len(entries) {
			next := c
			next.Offset = end
			out.NextCursor, e = ledger.SealFleetCursor(ctx, t.conn, next)
			if e != nil {
				return e
			}
		}
		t.beforeCommit = append(t.beforeCommit, func() error { return s.recheckFleetSoftwareTransaction(ctx, t, out, &now) })
		return nil
	})
	if e != nil {
		return zero, fullSoftwareStorageError(e)
	}
	if e = s.recheckWindowsFleetSoftwarePage(ctx, out, &now); e != nil {
		return zero, e
	}
	out.ServerNow = now
	return out, nil
}

func (s *Store) recheckFleetSoftwareTransaction(ctx context.Context, t *transaction, p windowsfullsoftware.FleetPage, checked *time.Time) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	now, e := overviewNow(ctx, *checked)
	if e != nil {
		return e
	}
	*checked = now
	if now.Before(p.ServerNow) {
		return windowsfullsoftware.ErrInvalid
	}
	session, e := fullSoftwareSession(ctx, now)
	if e != nil {
		return e
	}
	if session.id == "" || session.id != p.SessionID {
		return enrollmentstate.ErrProof
	}
	present, e := windowsFullSoftwareSchemaPresent(ctx, t.conn, s.config.Binding.CollectionProfile)
	if e != nil {
		return e
	}
	if p.Status == "not_configured" {
		if present {
			return windowsfullsoftware.ErrConflict
		}
		return nil
	}
	if !present {
		return ErrStorage
	}
	if p.CursorExpiresAt == nil || !now.Before(*p.CursorExpiresAt) {
		return windowsfullsoftware.ErrConflict
	}
	_, digest, deadline, e := s.fleetSoftwareRoster(ctx, t, now)
	if e != nil {
		return e
	}
	if digest != p.RosterDigest || p.CursorExpiresAt.After(deadline) || p.CursorExpiresAt.After(session.until) {
		return windowsfullsoftware.ErrConflict
	}
	for _, item := range p.Items {
		if !now.Before(item.AuthorityUntil) || item.Complete != nil && !now.Before(item.Complete.Manifest.ExpiresAt) {
			return windowsfullsoftware.ErrConflict
		}
	}
	return nil
}

func (s *Store) recheckWindowsFleetSoftwarePage(ctx context.Context, p windowsfullsoftware.FleetPage, checked *time.Time) error {
	e := s.transact(ctx, func(t *transaction) error {
		validate := func() error { return s.recheckFleetSoftwareTransaction(ctx, t, p, checked) }
		if e := validate(); e != nil {
			return e
		}
		t.beforeCommit = append(t.beforeCommit, validate)
		return nil
	})
	if e != nil {
		return fullSoftwareStorageError(e)
	}
	return ctx.Err()
}

// The HTTP layer prepares its bounded bytes before this current-authority lease.
func (s *Store) RecheckWindowsFleetSoftwarePage(ctx context.Context, p windowsfullsoftware.FleetPage, now time.Time) error {
	release, e := s.windowsFullSoftwareAdmission(ctx)
	if e != nil {
		return e
	}
	defer release()
	if !validStoreTime(now) {
		return windowsfullsoftware.ErrInvalid
	}
	return s.recheckWindowsFleetSoftwarePage(ctx, p, &now)
}
