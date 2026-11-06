package enrollmentstore

import (
	"context"
	"encoding/json"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/windowsfullsoftware"
	ledger "localrmm/internal/windowsfullsoftwareledger"
	"sort"
	"time"
)

type fleetSoftwareHistoryEntry struct {
	Snapshot      enrollmentstate.Snapshot
	Identity      string
	Leaf          string
	Until         time.Time
	Record        ledger.Record
	HistoryDigest string
}

// The existing 25-device roster and 1 MiB / 1024-row per-device history ceiling
// bound this one transaction to 25 MiB of history validation. Only hashes and
// authority metadata survive each load. No native inventory is searched, no
// browser requests fan out, and no history/consent/record/key is created or saved.
func (s *Store) fleetSoftwareHistoryRoster(ctx context.Context, t *transaction, now time.Time) ([]fleetSoftwareHistoryEntry, string, time.Time, error) {
	entries := []fleetSoftwareHistoryEntry{}
	snapshots := t.engine.Snapshots()
	if len(snapshots) > windowsfullsoftware.FleetDeviceLimit {
		return nil, "", time.Time{}, ErrStorage
	}
	deadline := now.Add(windowsfullsoftware.FleetCursorLifetime)
	bound := func(at time.Time) {
		if at.Before(deadline) {
			deadline = at
		}
	}
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
		entry := fleetSoftwareHistoryEntry{Snapshot: snap, Identity: fleetSoftwareHash(struct {
			Binding                    enrollmentstate.Binding
			Device, Invitation, Issued string
		}{snap.Binding, device, snap.InvitationID, snap.Issuance.CertificateHash}), Leaf: t.currentCertificateHash(snap), Until: time.Unix(t.currentCredentialNotAfter(snap), 0).UTC(), Record: r}
		bound(entry.Until)
		if r.Consent.Enabled && r.Consent.HistoryScope == windowsfullsoftware.HistoryScope {
			h, e := ledger.LoadHistory(ctx, t.conn, device, r.Consent)
			if e != nil {
				return nil, "", time.Time{}, e
			}
			// Remove expired material from this projection only. The original
			// expiry and existing durable history remain untouched.
			ledger.PruneHistory(&h, now)
			entry.HistoryDigest = ledger.HistoryDigest(h)
			if h.Comparison != nil {
				if now.Before(h.Comparison.AfterObservedAt) {
					return nil, "", time.Time{}, windowsfullsoftware.ErrInvalid
				}
				bound(h.Comparison.ExpiresAt)
			}
			for _, row := range h.Changes {
				if now.Before(row.AfterObservedAt) {
					return nil, "", time.Time{}, windowsfullsoftware.ErrInvalid
				}
				bound(row.ExpiresAt)
			}
		}
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Snapshot.Approval.DeviceID < entries[j].Snapshot.Approval.DeviceID
	})
	return entries, fleetSoftwareHash(entries), deadline, nil
}

func fleetSoftwareHistoryQueryHash(q windowsfullsoftware.FleetQuery) string {
	return fleetSoftwareHash(struct{ View, Search string }{q.View, q.Name})
}

func (s *Store) WindowsFleetSoftwareHistoryPage(ctx context.Context, q windowsfullsoftware.FleetQuery, now time.Time) (windowsfullsoftware.FleetHistoryPage, error) {
	zero := windowsfullsoftware.FleetHistoryPage{}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	release, e := s.windowsFullSoftwareAdmission(ctx)
	if e != nil {
		return zero, e
	}
	defer release()
	if q.View != "history" || windowsfullsoftware.ValidateFleetQuery(q) != nil || !validStoreTime(now) {
		return zero, windowsfullsoftware.ErrInvalid
	}
	out := windowsfullsoftware.FleetHistoryPage{SchemaVersion: windowsfullsoftware.FleetHistoryPageVersion, Search: q.Name, Status: "ready", Mode: "fleet", Items: []windowsfullsoftware.FleetHistoryItem{}}
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
			t.beforeCommit = append(t.beforeCommit, func() error { return s.recheckFleetSoftwareHistoryTransaction(ctx, t, out, &now) })
			return nil
		}
		// The existing monotonic clock fence is the only data updated by this
		// read; no new durable records or history retention are introduced.
		if e = ledger.Clock(ctx, t.conn, now); e != nil {
			return e
		}
		entries, digest, deadline, e := s.fleetSoftwareHistoryRoster(ctx, t, now)
		if e != nil {
			return e
		}
		if session.until.Before(deadline) {
			deadline = session.until.UTC()
		}
		out.TotalDevices, out.RosterDigest = len(entries), digest
		c := ledger.FleetCursor{Version: 1, Roster: digest, QueryDigest: fleetSoftwareHistoryQueryHash(q), Session: session.id, Mode: "fleet", ExpiresAt: deadline}
		if q.Cursor != "" {
			c, e = ledger.OpenFleetHistoryCursor(ctx, t.conn, q.Cursor)
			if e != nil {
				return e
			}
			if c.Roster != digest || c.QueryDigest != fleetSoftwareHistoryQueryHash(q) || c.Session != session.id || !now.Before(c.ExpiresAt) || c.ExpiresAt.After(deadline) {
				return windowsfullsoftware.ErrConflict
			}
		}
		out.Mode, out.Offset, out.CursorExpiresAt = c.Mode, c.Offset, &c.ExpiresAt
		start, end, limit, rowOffset := c.Offset, c.Offset+windowsfullsoftware.FleetPageDevices, windowsfullsoftware.FleetPreviewRows, 0
		if c.Mode == "device" {
			start = -1
			for i, entry := range entries {
				if entry.Snapshot.Approval.DeviceID == c.Device {
					start = i
					break
				}
			}
			if start < 0 || c.Offset > windowsfullsoftware.MaxHistoryRows {
				return windowsfullsoftware.ErrConflict
			}
			end, limit, rowOffset = start+1, windowsfullsoftware.FleetDetailRows, c.Offset
		} else if start > len(entries) || start == len(entries) && start != 0 {
			return windowsfullsoftware.ErrConflict
		}
		if end > len(entries) {
			end = len(entries)
		}
		for i := start; i < end; i++ {
			entry := entries[i]
			id := entry.Snapshot.Approval.DeviceID
			h, e := ledger.QueryHistoryReadOnly(ctx, t.conn, id, entry.Record, windowsfullsoftware.Query{Search: q.Name, Sort: "observed-desc", Limit: limit}, now, entry.Until, session.id, session.until, rowOffset)
			if e != nil {
				return e
			}
			h.SchemaVersion = "tracebolt.windows-fleet-software-history-device.v1"
			// Only the containing fleet-history domain provides continuation tokens.
			if h.Status == "ready" {
				h.CursorExpiresAt = &c.ExpiresAt
			}
			item := windowsfullsoftware.FleetHistoryItem{DeviceID: id, Identity: entry.Identity, AuthorityUntil: entry.Until, History: h}
			if h.Status == "ready" {
				if h.HistoryDigest != entry.HistoryDigest || h.CursorExpiresAt == nil || h.CursorExpiresAt.Before(c.ExpiresAt) {
					return windowsfullsoftware.ErrConflict
				}
				if c.Mode == "fleet" {
					detail := c
					detail.Mode, detail.Device, detail.Offset = "device", id, 0
					item.DetailCursor, e = ledger.SealFleetHistoryCursor(ctx, t.conn, detail)
					if e != nil {
						return e
					}
				} else if rowOffset+len(h.Rows) < h.MatchingCount {
					next := c
					next.Offset += len(h.Rows)
					out.NextCursor, e = ledger.SealFleetHistoryCursor(ctx, t.conn, next)
					if e != nil {
						return e
					}
				}
			} else if c.Mode == "device" {
				return windowsfullsoftware.ErrConflict
			}
			out.Items = append(out.Items, item)
			raw, e := json.Marshal(out)
			if e != nil {
				return ErrStorage
			}
			if len(raw) > windowsfullsoftware.MaxPageBytes-8192 {
				if len(out.Items) == 1 || c.Mode != "fleet" {
					return windowsfullsoftware.ErrBudget
				}
				out.Items = out.Items[:len(out.Items)-1]
				break
			}
		}
		if c.Mode == "fleet" && start+len(out.Items) < len(entries) {
			next := c
			next.Offset = start + len(out.Items)
			out.NextCursor, e = ledger.SealFleetHistoryCursor(ctx, t.conn, next)
			if e != nil {
				return e
			}
		}
		t.beforeCommit = append(t.beforeCommit, func() error { return s.recheckFleetSoftwareHistoryTransaction(ctx, t, out, &now) })
		return nil
	})
	if e != nil {
		return zero, fullSoftwareStorageError(e)
	}
	if e = s.recheckWindowsFleetSoftwareHistoryPage(ctx, out, &now); e != nil {
		return zero, e
	}
	out.ServerNow = now
	return out, nil
}

func (s *Store) recheckFleetSoftwareHistoryTransaction(ctx context.Context, t *transaction, p windowsfullsoftware.FleetHistoryPage, checked *time.Time) error {
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
	_, digest, deadline, e := s.fleetSoftwareHistoryRoster(ctx, t, now)
	if e != nil {
		return e
	}
	if digest != p.RosterDigest || p.CursorExpiresAt.After(deadline) || p.CursorExpiresAt.After(session.until) {
		return windowsfullsoftware.ErrConflict
	}
	// Canonical history validation is bounded but can be nontrivial. Its start
	// time is not authority to release bytes after source/session expiry.
	fresh, e := overviewNow(ctx, now)
	if e != nil {
		return e
	}
	if fresh.Before(now) {
		return windowsfullsoftware.ErrInvalid
	}
	now, *checked = fresh, fresh
	if e = ctx.Err(); e != nil {
		return e
	}
	session, e = fullSoftwareSession(ctx, now)
	if e != nil {
		return e
	}
	if session.id != p.SessionID {
		return enrollmentstate.ErrProof
	}
	if !now.Before(*p.CursorExpiresAt) || p.CursorExpiresAt.After(session.until) {
		return windowsfullsoftware.ErrConflict
	}
	for _, item := range p.Items {
		if !now.Before(item.AuthorityUntil) {
			return windowsfullsoftware.ErrConflict
		}
		if e = ValidateWindowsSoftwareHistoryPageAt(item.History, now); e != nil {
			return e
		}
	}
	return nil
}
func (s *Store) recheckWindowsFleetSoftwareHistoryPage(ctx context.Context, p windowsfullsoftware.FleetHistoryPage, checked *time.Time) error {
	e := s.transact(ctx, func(t *transaction) error {
		validate := func() error { return s.recheckFleetSoftwareHistoryTransaction(ctx, t, p, checked) }
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
func (s *Store) RecheckWindowsFleetSoftwareHistoryPage(ctx context.Context, p windowsfullsoftware.FleetHistoryPage, now time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	release, e := s.windowsFullSoftwareAdmission(ctx)
	if e != nil {
		return e
	}
	defer release()
	if !validStoreTime(now) {
		return windowsfullsoftware.ErrInvalid
	}
	return s.recheckWindowsFleetSoftwareHistoryPage(ctx, p, &now)
}
