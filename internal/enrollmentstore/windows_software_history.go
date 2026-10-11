package enrollmentstore

import (
	"context"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/windowsfullsoftware"
	ledger "localrmm/internal/windowsfullsoftwareledger"
	"time"
)

func (s *Store) WindowsSoftwareHistoryPage(ctx context.Context, device string, q windowsfullsoftware.Query, now time.Time) (windowsfullsoftware.HistoryPage, error) {
	zero := windowsfullsoftware.HistoryPage{}
	release, e := s.windowsFullSoftwareAdmission(ctx)
	if e != nil {
		return zero, e
	}
	defer release()
	if windowsfullsoftware.ValidateHistoryQuery(q) != nil || !enrollmentcrypto.ValidID(device, "agent_") || !validStoreTime(now) {
		return zero, windowsfullsoftware.ErrInvalid
	}
	now = now.UTC()
	var out windowsfullsoftware.HistoryPage
	var authorityUntil time.Time
	var invitation, certificate, origin string
	var consent windowsfullsoftware.Consent

	e = s.transact(ctx, func(t *transaction) error {
		now, e = overviewNow(ctx, now)
		if e != nil {
			return e
		}
		session, e := fullSoftwareSession(ctx, now)
		if e != nil {
			return e
		}
		var snap enrollmentstate.Snapshot
		found := false
		for _, v := range t.engine.Snapshots() {
			if v.Approval.DeviceID == device {
				snap = v
				found = true
				break
			}
		}
		if !found {
			return enrollmentstate.ErrNotFound
		}
		snap, e = s.windowsFullSoftwareAuthority(t, snap.InvitationID, t.currentCertificateHash(snap), now)
		if e != nil {
			return e
		}
		until := time.Unix(t.currentCredentialNotAfter(snap), 0).UTC()
		authorityUntil = until
		invitation, certificate = snap.InvitationID, t.currentCertificateHash(snap)
		present, e := windowsFullSoftwareSchemaPresent(ctx, t.conn, s.config.Binding.CollectionProfile)
		if e != nil {
			return e
		}
		if !present {
			if q.Cursor != "" {
				return windowsfullsoftware.ErrConflict
			}
			out = windowsfullsoftware.HistoryPage{SchemaVersion: windowsfullsoftware.HistoryPageVersion, DeviceID: device, ServerNow: now, Status: "not_configured", Search: q.Search, Limit: q.Limit, Rows: []windowsfullsoftware.HistoryChange{}}
		} else {
			if e = ledger.Clock(ctx, t.conn, now); e != nil {
				return e
			}
			r, e := readWindowsFullSoftwareRecord(ctx, t, device)
			if e != nil {
				return e
			}
			consent, origin = r.Consent, r.IngressOrigin
			out, e = ledger.QueryHistory(ctx, t.conn, device, r, q, now, until, session.id, session.until)
			if e != nil {
				return e
			}
		}
		t.beforeCommit = append(t.beforeCommit, func() error {
			if e = ctx.Err(); e != nil {
				return e
			}
			fresh, e := overviewNow(ctx, now)
			if e != nil {
				return e
			}
			now = fresh
			if _, e = s.windowsFullSoftwareAuthority(t, snap.InvitationID, t.currentCertificateHash(snap), fresh); e != nil {
				return e
			}
			if _, e = fullSoftwareSession(ctx, fresh); e != nil {
				return e
			}
			return ValidateWindowsSoftwareHistoryPageAt(out, fresh)
		})
		return nil
	})
	if e != nil {
		return zero, fullSoftwareStorageError(e)
	}
	if e = ctx.Err(); e != nil {
		return zero, e
	}
	fresh, e := overviewNow(ctx, now)
	if e != nil {
		return zero, e
	}
	if !fresh.Before(authorityUntil) {
		return zero, enrollmentstate.ErrExpired
	}
	if _, e = fullSoftwareSession(ctx, fresh); e != nil {
		return zero, e
	}
	if e = ValidateWindowsSoftwareHistoryPageAt(out, fresh); e != nil {
		return zero, e
	}
	fresh, e = s.recheckWindowsFullSoftwareAt(ctx, invitation, certificate, consent, origin, "", fresh, func(at time.Time) error { return ValidateWindowsSoftwareHistoryPageAt(out, at) })
	if e != nil {
		return zero, e
	}
	if e = s.recheckWindowsSoftwareHistoryPage(ctx, out, fresh); e != nil {
		return zero, e
	}
	out.ServerNow = fresh
	return out, nil
}
func ValidateWindowsSoftwareHistoryPageAt(p windowsfullsoftware.HistoryPage, now time.Time) error {
	if !validStoreTime(now) || now.Before(p.ServerNow) {
		return windowsfullsoftware.ErrInvalid
	}
	if p.AuthorityUntil == nil {
		if p.Status != "not_configured" {
			return windowsfullsoftware.ErrInvalid
		}
		return nil
	}
	if !now.Before(*p.AuthorityUntil) {
		return enrollmentstate.ErrExpired
	}
	if p.CursorExpiresAt != nil && !now.Before(*p.CursorExpiresAt) {
		return windowsfullsoftware.ErrConflict
	}
	if p.Comparison != nil && !now.Before(p.Comparison.ExpiresAt) {
		return windowsfullsoftware.ErrConflict
	}
	for _, row := range p.Rows {
		if !now.Before(row.ExpiresAt) {
			return windowsfullsoftware.ErrConflict
		}
	}

	return nil
}
func (s *Store) RecheckWindowsSoftwareHistoryPage(ctx context.Context, p windowsfullsoftware.HistoryPage, now time.Time) error {
	release, e := s.windowsFullSoftwareAdmission(ctx)
	if e != nil {
		return e
	}
	defer release()
	return s.recheckWindowsSoftwareHistoryPage(ctx, p, now)
}
func (s *Store) recheckWindowsSoftwareHistoryPage(ctx context.Context, p windowsfullsoftware.HistoryPage, now time.Time) error {
	var e error
	if e = ValidateWindowsSoftwareHistoryPageAt(p, now); e != nil {
		return e
	}
	checked := now.UTC()
	return s.transact(ctx, func(t *transaction) error {
		validate := func() error {
			if e := ctx.Err(); e != nil {
				return e
			}
			next, e := overviewNow(ctx, checked)
			if e != nil {
				return e
			}
			checked = next
			if e = ValidateWindowsSoftwareHistoryPageAt(p, checked); e != nil {
				return e
			}
			var snap enrollmentstate.Snapshot
			found := false
			for _, v := range t.engine.Snapshots() {
				if v.Approval.DeviceID == p.DeviceID {
					snap = v
					found = true
					break
				}
			}
			if !found {
				return enrollmentstate.ErrNotFound
			}
			if _, e := s.windowsFullSoftwareAuthority(t, snap.InvitationID, t.currentCertificateHash(snap), checked); e != nil {
				return e
			}
			if _, e := fullSoftwareSession(ctx, checked); e != nil {
				return e
			}
			present, e := windowsFullSoftwareSchemaPresent(ctx, t.conn, s.config.Binding.CollectionProfile)
			if e != nil {
				return e
			}
			r := ledger.Record{}
			if present {
				r, e = readWindowsFullSoftwareRecord(ctx, t, p.DeviceID)
				if e != nil {
					return e
				}
			}
			if p.GrantID == nil || p.GrantRevision == nil {
				if r.Consent.HistoryScope != "" || p.Status != "not_configured" {
					return windowsfullsoftware.ErrConflict
				}
				return nil
			}
			if r.Consent.GrantID != *p.GrantID || r.Consent.Revision != *p.GrantRevision {
				return windowsfullsoftware.ErrConflict
			}
			if p.HistoryDigest != "" {
				if !r.Consent.Enabled || r.Consent.HistoryScope != windowsfullsoftware.HistoryScope {
					return windowsfullsoftware.ErrConflict
				}
				h, e := ledger.LoadHistory(ctx, t.conn, p.DeviceID, r.Consent)
				if e != nil {
					return e
				}
				if ledger.PruneHistory(&h, checked) || ledger.HistoryDigest(h) != p.HistoryDigest {
					return windowsfullsoftware.ErrConflict
				}
			}

			return nil
		}
		if e := validate(); e != nil {
			return e
		}
		t.beforeCommit = append(t.beforeCommit, validate)
		return nil
	})
}
