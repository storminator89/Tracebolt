package enrollmentstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/windowsusersoftware"
	ledger "localrmm/internal/windowsusersoftwareledger"
	"time"
)

func WithWindowsUserSoftwareClock(ctx context.Context, now func() time.Time) context.Context {
	return WithOverviewClock(ctx, now)
}

type windowsUserSoftwareSessionKey struct{}
type windowsUserSoftwareSession struct {
	id     string
	until  time.Time
	active func() bool
}

// Only the authenticated operator boundary installs this context; the identity
// and original session deadline never come from request JSON.
func WithWindowsUserSoftwareSession(ctx context.Context, id string, until time.Time, active func() bool) context.Context {
	return context.WithValue(ctx, windowsUserSoftwareSessionKey{}, windowsUserSoftwareSession{id, until, active})
}
func userSoftwareSession(ctx context.Context, now time.Time) (windowsUserSoftwareSession, error) {
	s, ok := ctx.Value(windowsUserSoftwareSessionKey{}).(windowsUserSoftwareSession)
	if !ok {
		return s, nil
	}
	if s.id == "" || s.active == nil || !s.active() || !now.Before(s.until) {
		return s, enrollmentstate.ErrProof
	}
	return s, nil
}
func (s *Store) windowsUserSoftwareAdmission(ctx context.Context) (func(), error) {
	if s == nil || s.storeState == nil || ctx == nil {
		return nil, enrollmentstate.ErrInvalid
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if s.config.Binding.CollectionProfile != enrollmentcrypto.CollectionProfileWindowsInventory {
		return nil, enrollmentstate.ErrProof
	}
	select {
	case s.inventoryCalls <- struct{}{}:
		return func() { <-s.inventoryCalls }, nil
	default:
		return nil, ErrInventoryBusy
	}
}
func (s *Store) windowsUserSoftwareAuthority(t *transaction, id, certificate string, now time.Time) (enrollmentstate.Snapshot, error) {
	snap, e := t.engine.Get(id)
	if e != nil {
		return snap, e
	}
	if snap.Binding.CollectionProfile != enrollmentcrypto.CollectionProfileWindowsInventory || snap.Platform != "windows" {
		return snap, enrollmentstate.ErrProof
	}
	if e = t.authorizeCurrentCredential(snap, certificate, now); e != nil {
		return snap, e
	}
	return snap, nil
}
func (s *Store) ApplyWindowsUserSoftware(ctx context.Context, id, certificate string, m windowsusersoftware.Message, raw []byte, now time.Time) (windowsusersoftware.Receipt, error) {
	zero := windowsusersoftware.Receipt{}
	release, e := s.windowsUserSoftwareAdmission(ctx)
	if e != nil {
		return zero, e
	}
	defer release()
	decoded, e := windowsusersoftware.DecodeMessage(raw)
	canonical, _ := json.Marshal(m)
	if e != nil || !bytes.Equal(canonical, raw) || !validStoreTime(now) {
		return zero, windowsusersoftware.ErrInvalid
	}
	origin, e := userSoftwareIngressOrigin(ctx, s.config.Binding.Profile)
	if e != nil {
		return zero, e
	}
	m = decoded
	raw = bytes.Clone(raw)
	now = now.UTC()
	var out windowsusersoftware.Receipt
	var authorityUntil, transferUntil time.Time
	e = s.transact(ctx, func(t *transaction) error {
		now, e = overviewNow(ctx, now)
		if e != nil {
			return e
		}
		present, e := windowsUserSoftwareSchemaPresent(ctx, t.conn, s.config.Binding.CollectionProfile)
		if e != nil {
			return e
		}
		if !present {
			return windowsusersoftware.ErrUnavailable
		}
		snap, e := s.windowsUserSoftwareAuthority(t, id, certificate, now)
		if e != nil {
			return e
		}
		authorityUntil = time.Unix(t.currentCredentialNotAfter(snap), 0).UTC()
		if m.DeviceID != snap.Approval.DeviceID || m.Consent.SenderBinding != windowsusersoftware.SenderBinding(snap.Binding.Profile, origin, snap.Issuance.CertificateHash, m.DeviceID) || m.Consent.ChangedAt.After(now) || m.Consent.ChangedAt.Unix() < snap.Activation.At {
			return enrollmentstate.ErrProof
		}
		if e = ledger.Clock(ctx, t.conn, now); e != nil {
			return e
		}
		r, e := readWindowsUserSoftwareRecord(ctx, t, m.DeviceID)
		if e != nil {
			return e
		}
		if r.Consent.Revision != 0 && r.IngressOrigin != origin {
			return enrollmentstate.ErrProof
		}
		r.IngressOrigin = origin
		if !r.LastAt.IsZero() && now.Before(r.LastAt) {
			return enrollmentstate.ErrInvalid
		}
		if m.Operation == "chunk" {
			previous, loadErr := ledger.LoadGeneration(ctx, t.conn, m.DeviceID, m.Manifest.GenerationID)
			if errors.Is(loadErr, ledger.ErrNotFound) {
				transferUntil = now.Add(ledger.StagingTTL)
			} else if loadErr == nil && previous.State == "staging" {
				transferUntil = previous.StartedAt.Add(ledger.StagingTTL)
			}
		}
		extra, e := windowsUserSoftwareOtherBytes(ctx, t)
		if e != nil {
			return e
		}
		out, e = ledger.Apply(ctx, t.conn, m, raw, &r, now, extra)
		if e != nil {
			return e
		}
		r.LastAt = now
		if e = ledger.SaveRecord(ctx, t.conn, m.DeviceID, id, snap.Issuance.CertificateHash, r); e != nil {
			return e
		}
		c := t.credentials[id]
		c.WindowsUserSoftwareInitialized = true
		t.credentials[id] = c
		t.beforeCommit = append(t.beforeCommit, func() error {
			if e = ctx.Err(); e != nil {
				return e
			}
			fresh, e := overviewNow(ctx, now)
			if e != nil {
				return e
			}
			now = fresh
			if _, e = s.windowsUserSoftwareAuthority(t, id, certificate, fresh); e != nil {
				return e
			}
			if !transferUntil.IsZero() && !fresh.Before(transferUntil) {
				return windowsusersoftware.ErrExpired
			}
			if m.Manifest != nil && !fresh.Before(m.Manifest.ExpiresAt) {
				return windowsusersoftware.ErrExpired
			}
			if m.Operation == "failure" && !fresh.Before(m.AttemptedAt.Add(windowsusersoftware.Retention)) {
				return windowsusersoftware.ErrExpired
			}
			return nil
		})
		return nil
	})
	if e != nil {
		return zero, userSoftwareStorageError(e)
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
	if !transferUntil.IsZero() && !fresh.Before(transferUntil) {
		return zero, windowsusersoftware.ErrExpired
	}
	if m.Manifest != nil && !fresh.Before(m.Manifest.ExpiresAt) {
		return zero, windowsusersoftware.ErrExpired
	}
	if m.Operation == "failure" && !fresh.Before(m.AttemptedAt.Add(windowsusersoftware.Retention)) {
		return zero, windowsusersoftware.ErrExpired
	}
	if _, e = s.recheckWindowsUserSoftwareAt(ctx, id, certificate, m.Consent, origin, "", fresh, func(at time.Time) error {
		if !transferUntil.IsZero() && !at.Before(transferUntil) {
			return windowsusersoftware.ErrExpired
		}
		if m.Manifest != nil && !at.Before(m.Manifest.ExpiresAt) {
			return windowsusersoftware.ErrExpired
		}
		if m.AttemptedAt != nil && !at.Before(m.AttemptedAt.Add(windowsusersoftware.Retention)) {
			return windowsusersoftware.ErrExpired
		}
		return nil
	}); e != nil {
		return zero, e
	}
	return out, nil
}
func (s *Store) WindowsUserSoftwarePage(ctx context.Context, device string, q windowsusersoftware.Query, now time.Time) (windowsusersoftware.Page, error) {
	zero := windowsusersoftware.Page{}
	release, e := s.windowsUserSoftwareAdmission(ctx)
	if e != nil {
		return zero, e
	}
	defer release()
	if windowsusersoftware.ValidateQuery(q) != nil || !enrollmentcrypto.ValidID(device, "agent_") || !validStoreTime(now) {
		return zero, windowsusersoftware.ErrInvalid
	}
	now = now.UTC()
	var out windowsusersoftware.Page
	var authorityUntil time.Time
	var invitation, certificate, origin string
	var consent windowsusersoftware.Consent
	var generation string
	e = s.transact(ctx, func(t *transaction) error {
		now, e = overviewNow(ctx, now)
		if e != nil {
			return e
		}
		session, e := userSoftwareSession(ctx, now)
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
		snap, e = s.windowsUserSoftwareAuthority(t, snap.InvitationID, t.currentCertificateHash(snap), now)
		if e != nil {
			return e
		}
		until := time.Unix(t.currentCredentialNotAfter(snap), 0).UTC()
		authorityUntil = until
		invitation, certificate = snap.InvitationID, t.currentCertificateHash(snap)
		present, e := windowsUserSoftwareSchemaPresent(ctx, t.conn, s.config.Binding.CollectionProfile)
		if e != nil {
			return e
		}
		if !present {
			if q.Cursor != "" {
				return windowsusersoftware.ErrConflict
			}
			out = windowsusersoftware.Page{SchemaVersion: windowsusersoftware.PageVersion, DeviceID: device, ServerNow: now, Status: "not_configured", Search: q.Search, Sort: q.Sort, Limit: q.Limit, Rows: []windowsusersoftware.Row{}}
		} else {
			if e = ledger.Clock(ctx, t.conn, now); e != nil {
				return e
			}
			r, e := readWindowsUserSoftwareRecord(ctx, t, device)
			if e != nil {
				return e
			}
			consent, origin = r.Consent, r.IngressOrigin
			out, e = ledger.Page(ctx, t.conn, device, r, q, now, until, session.id, session.until)
			if out.Complete != nil {
				generation = out.Complete.Manifest.GenerationID
			}
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
			if _, e = s.windowsUserSoftwareAuthority(t, snap.InvitationID, t.currentCertificateHash(snap), fresh); e != nil {
				return e
			}
			if _, e = userSoftwareSession(ctx, fresh); e != nil {
				return e
			}
			return ValidateWindowsUserSoftwarePageAt(out, fresh)
		})
		return nil
	})
	if e != nil {
		return zero, userSoftwareStorageError(e)
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
	if _, e = userSoftwareSession(ctx, fresh); e != nil {
		return zero, e
	}
	if e = ValidateWindowsUserSoftwarePageAt(out, fresh); e != nil {
		return zero, e
	}
	fresh, e = s.recheckWindowsUserSoftwareAt(ctx, invitation, certificate, consent, origin, generation, fresh, func(at time.Time) error { return ValidateWindowsUserSoftwarePageAt(out, at) })
	if e != nil {
		return zero, e
	}
	out.ServerNow = fresh
	return out, nil
}
func ValidateWindowsUserSoftwarePageAt(p windowsusersoftware.Page, now time.Time) error {
	if !validStoreTime(now) || now.Before(p.ServerNow) {
		return windowsusersoftware.ErrInvalid
	}
	if p.AuthorityUntil == nil {
		if p.Status != "not_configured" {
			return windowsusersoftware.ErrInvalid
		}
		return nil
	}
	if !now.Before(*p.AuthorityUntil) {
		return enrollmentstate.ErrExpired
	}
	if p.LatestAttempt != nil && !now.Before(p.LatestAttempt.AttemptedAt.Add(windowsusersoftware.Retention)) || p.Complete != nil && !now.Before(p.Complete.Manifest.ExpiresAt) || p.CursorExpiresAt != nil && !now.Before(*p.CursorExpiresAt) {
		return windowsusersoftware.ErrConflict
	}
	return nil
}
func userSoftwareStorageError(e error) error {
	if errors.Is(e, ledger.ErrStorage) {
		return ErrStorage
	}
	return e
}

// Maintenance never admits an agent request and never removes current data or
// independent floors. It is safe after identity revocation and disable.
func (s *Store) MaintainWindowsUserSoftware(ctx context.Context, now time.Time) error {
	release, e := s.windowsUserSoftwareAdmission(ctx)
	if e != nil {
		return e
	}
	defer release()
	if !validStoreTime(now) {
		return enrollmentstate.ErrInvalid
	}
	return s.transact(ctx, func(t *transaction) error {
		present, e := windowsUserSoftwareSchemaPresent(ctx, t.conn, s.config.Binding.CollectionProfile)
		if e != nil || !present {
			return e
		}
		if e = ledger.Clock(ctx, t.conn, now); e != nil {
			return e
		}
		for _, snap := range t.engine.Snapshots() {
			if !t.credentials[snap.InvitationID].WindowsUserSoftwareInitialized {
				continue
			}
			r, e := ledger.LoadRecord(ctx, t.conn, snap.Approval.DeviceID)
			if e != nil {
				return e
			}
			changed := false
			for _, pending := range []bool{false, true} {
				id := r.Current
				if pending {
					id = r.Pending
				}
				if id == "" {
					continue
				}
				g, e := ledger.LoadGeneration(ctx, t.conn, snap.Approval.DeviceID, id)
				if e != nil {
					return e
				}
				expired := !now.Before(g.Manifest.ExpiresAt) || snap.State != enrollmentstate.Activated || now.Unix() >= t.currentCredentialNotAfter(snap)
				if pending && !now.Before(g.StartedAt.Add(ledger.StagingTTL)) {
					expired = true
				}
				if expired {
					if e = ledger.MarkGarbage(ctx, t.conn, snap.Approval.DeviceID, id); e != nil {
						return e
					}
					if pending {
						r.Pending = ""
					} else {
						r.Current = ""
					}
					if r.Latest != nil && r.Latest.Sequence == g.Manifest.Sequence {
						copy := *r.Latest
						copy.Status = "expired"
						r.Latest = &copy
					}
					changed = true
				}
			}
			if r.Latest != nil && !now.Before(r.Latest.AttemptedAt.Add(windowsusersoftware.Retention)) {
				r.Latest = nil
				r.FailureRaw = nil
				r.FailureReceipt = nil
				changed = true
			}
			if changed {
				if e = ledger.SaveRecord(ctx, t.conn, snap.Approval.DeviceID, snap.InvitationID, snap.Issuance.CertificateHash, r); e != nil {
					return e
				}
			}
		}
		return ledger.CleanupStep(ctx, t.conn, now)
	})
}

// recheckWindowsUserSoftwareAt retains the outside-sample/current-authority
// interleaving, then samples again only AFTER connection/BEGIN/load admission and
// immediately before COMMIT. Each sample is paired with live authority and the
// same original deadline checks under that transaction. No action is replayed.
func (s *Store) recheckWindowsUserSoftwareAt(ctx context.Context, id, certificate string, consent windowsusersoftware.Consent, origin, generation string, floor time.Time, lifetime func(time.Time) error) (time.Time, error) {
	checked := floor.UTC()
	err := s.transact(ctx, func(t *transaction) error {
		validate := func() error {
			if e := ctx.Err(); e != nil {
				return e
			}
			next, e := overviewNow(ctx, checked)
			if e != nil {
				return e
			}
			checked = next
			snap, e := s.windowsUserSoftwareAuthority(t, id, certificate, checked)
			if e != nil {
				return e
			}
			if _, e = userSoftwareSession(ctx, checked); e != nil {
				return e
			}
			if lifetime != nil {
				if e = lifetime(checked); e != nil {
					return e
				}
			}
			present, e := windowsUserSoftwareSchemaPresent(ctx, t.conn, s.config.Binding.CollectionProfile)
			if e != nil {
				return e
			}
			if !present {
				if consent.Revision != 0 {
					return ErrStorage
				}
				return nil
			}
			r, e := readWindowsUserSoftwareRecord(ctx, t, snap.Approval.DeviceID)
			if e != nil {
				return e
			}
			if r.Consent != consent || r.IngressOrigin != origin {
				return windowsusersoftware.ErrConflict
			}
			if generation != "" && r.Current != generation {
				return windowsusersoftware.ErrConflict
			}
			return nil
		}
		if e := validate(); e != nil {
			return e
		}
		t.beforeCommit = append(t.beforeCommit, validate)
		return nil
	})
	if err != nil {
		return time.Time{}, userSoftwareStorageError(err)
	}
	if err = ctx.Err(); err != nil {
		return time.Time{}, err
	}
	return checked, nil
}

// RecheckWindowsUserSoftware is a read-only final receipt authority seam. The
// caller must install its configured ingress origin, then marshal the receipt
// before this check and preserve the returned checked time/original expiry.
func (s *Store) RecheckWindowsUserSoftware(ctx context.Context, id, certificate string, consent windowsusersoftware.Consent, now time.Time) (time.Time, error) {
	release, e := s.windowsUserSoftwareAdmission(ctx)
	if e != nil {
		return time.Time{}, e
	}
	defer release()
	origin, e := userSoftwareIngressOrigin(ctx, s.config.Binding.Profile)
	if e != nil {
		return time.Time{}, e
	}
	if windowsusersoftware.ValidateConsent(consent) != nil || !validStoreTime(now) {
		return time.Time{}, windowsusersoftware.ErrInvalid
	}
	checked, e := overviewNow(ctx, now.UTC())
	if e != nil {
		return time.Time{}, e
	}
	return s.recheckWindowsUserSoftwareAt(ctx, id, certificate, consent, origin, "", checked, nil)
}

// RecheckWindowsUserSoftwarePage is the final read-only operator disclosure
// guard, after response preparation and its final clock sample. It re-resolves
// current certificate, local grant and generation; it never refreshes the page.
func (s *Store) RecheckWindowsUserSoftwarePage(ctx context.Context, p windowsusersoftware.Page, now time.Time) error {
	release, e := s.windowsUserSoftwareAdmission(ctx)
	if e != nil {
		return e
	}
	defer release()
	if e = ValidateWindowsUserSoftwarePageAt(p, now); e != nil {
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
			if e = ValidateWindowsUserSoftwarePageAt(p, checked); e != nil {
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
			if _, e := s.windowsUserSoftwareAuthority(t, snap.InvitationID, t.currentCertificateHash(snap), checked); e != nil {
				return e
			}
			if _, e := userSoftwareSession(ctx, checked); e != nil {
				return e
			}
			present, e := windowsUserSoftwareSchemaPresent(ctx, t.conn, s.config.Binding.CollectionProfile)
			if e != nil {
				return e
			}
			r := ledger.Record{}
			if present {
				r, e = readWindowsUserSoftwareRecord(ctx, t, p.DeviceID)
				if e != nil {
					return e
				}
			}
			if p.GrantID == nil || p.GrantRevision == nil {
				if r.Consent.Revision != 0 || p.Status != "not_configured" {
					return windowsusersoftware.ErrConflict
				}
				return nil
			}
			if r.Consent.GrantID != *p.GrantID || r.Consent.Revision != *p.GrantRevision {
				return windowsusersoftware.ErrConflict
			}
			if p.Complete != nil {
				if !r.Consent.Enabled || r.Current != p.Complete.Manifest.GenerationID {
					return windowsusersoftware.ErrConflict
				}
				g, e := ledger.LoadGeneration(ctx, t.conn, p.DeviceID, r.Current)
				if e != nil {
					return e
				}
				if g.Hash != p.Complete.ManifestSHA256 {
					return windowsusersoftware.ErrConflict
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
