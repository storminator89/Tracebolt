package enrollmentstore

import (
	"context"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/windowsfullprocesses"
	ledger "localrmm/internal/windowsfullprocessesledger"
	"localrmm/internal/windowsmanaged"
	watch "localrmm/internal/windowsprocesswatch"
	"time"
)

// WithWindowsProcessWatchAuthority holds the existing enrollment transaction
// through the operator read/write. No host collection or source grant is made.
// The callback must not reenter enrollment storage. It must call guard following
// operator-store waits and just before committing or disclosing private data.
func (s *Store) WithWindowsProcessWatchAuthority(ctx context.Context, device string, names []string, clock func() time.Time, fn func(watch.Input, func(time.Time) error) error) error {
	if s == nil || s.storeState == nil || ctx == nil || clock == nil || fn == nil || !enrollmentcrypto.ValidID(device, "agent_") || s.config.Binding.CollectionProfile != windowsmanaged.CollectionProfile {
		return enrollmentstate.ErrInvalid
	}
	names, e := watch.Names(names)
	if e != nil {
		return e
	}
	release, e := s.windowsFullProcessesAdmission(ctx)
	if e != nil {
		return e
	}
	defer release()
	started := clock().UTC()
	if !validStoreTime(started) {
		return enrollmentstate.ErrInvalid
	}
	return s.transact(ctx, func(t *transaction) error {
		snap, e := systemDevice(t, device)
		if e != nil {
			return e
		}
		if snap.Platform != "windows" || snap.Binding != s.config.Binding {
			return enrollmentstate.ErrProof
		}
		leaf := t.currentCertificateHash(snap)
		if e = t.authorizeCurrentCredential(snap, leaf, clock().UTC()); e != nil {
			return e
		}
		in := watch.Input{DeviceID: device, InvitationID: snap.InvitationID, CertificateHash: snap.Issuance.CertificateHash, CurrentLeaf: leaf, AuthorityUntil: time.Unix(t.currentCredentialNotAfter(snap), 0).UTC()}
		present, e := windowsFullProcessesSchemaPresent(ctx, t.conn, s.config.Binding.CollectionProfile)
		if e != nil {
			return e
		}
		if present && len(names) > 0 {
			if e := ledger.Clock(ctx, t.conn, clock().UTC()); e != nil {
				return e
			}
			r, e := readWindowsFullProcessesRecord(ctx, t, device)
			if e != nil {
				return e
			}
			if r.Consent.Enabled && r.Current != "" && r.Pending == "" && r.Latest != nil && r.Latest.Status == "complete" {
				g, e := ledger.LoadGeneration(ctx, t.conn, device, r.Current)
				if e != nil {
					return e
				}
				m := g.Manifest
				if g.State != "current" || m.GrantID != r.Consent.GrantID || m.GrantRevision != r.Consent.Revision || g.NextRow != m.RowCount || g.NextChunk != m.ChunkCount || g.CompletedAt.IsZero() {
					return ErrStorage
				}
				p := windowsfullprocesses.Complete{Manifest: m, ManifestSHA256: g.Hash, ReceivedAt: g.CompletedAt}
				at := clock().UTC()
				if p.Manifest.CaptureStartedAt.After(at) || p.ReceivedAt.After(at) {
					return enrollmentstate.ErrProof
				}
				if r.Latest.Sequence == m.Sequence && watch.Fresh(&p, at) {
					in.Counts, in.UnavailableNames, e = ledger.Presence(ctx, t.conn, device, g, names)
					if e != nil {
						return e
					}
					in.Complete = &p
				}
			}
		}
		last := started
		guard := func(minimum time.Time) error {
			at := clock().UTC()
			if ctx.Err() != nil || !validStoreTime(at) || at.Before(last) || at.Before(minimum) || at.Sub(started) > 5*time.Second || !in.Authorized(at) || in.Complete != nil && !watch.Fresh(in.Complete, at) {
				return enrollmentstate.ErrProof
			}
			last = at
			if present && len(names) > 0 {
				if e := ledger.Clock(ctx, t.conn, at); e != nil {
					return e
				}
			}
			if e := t.authorizeCurrentCredential(snap, leaf, at); e != nil {
				return e
			}
			return nil
		}
		if e := guard(started); e != nil {
			return e
		}
		if e := fn(in, guard); e != nil {
			return e
		}
		t.beforeCommit = append(t.beforeCommit, func() error { return guard(last) })
		return guard(last)
	})
}
