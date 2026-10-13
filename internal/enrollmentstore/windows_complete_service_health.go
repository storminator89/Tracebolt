package enrollmentstore

import (
	"context"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	ledger "localrmm/internal/windowsfullservicesledger"
	"localrmm/internal/windowsmanaged"
	"localrmm/internal/windowsservicehealth"
	"time"
)

func readCompleteServiceHealth(ctx context.Context, t *transaction, device string, names []string, now time.Time) (*windowsservicehealth.CompleteSample, error) {
	r, e := readWindowsFullServicesRecord(ctx, t, device)
	if e != nil {
		return nil, e
	}
	if !r.Consent.Enabled || r.Current == "" || r.Pending != "" || r.Latest == nil || r.Latest.Status != "complete" {
		return nil, nil
	}
	g, e := ledger.LoadGeneration(ctx, t.conn, device, r.Current)
	if e != nil {
		return nil, e
	}
	m := g.Manifest
	if g.State != "current" || m.GrantID != r.Consent.GrantID || m.GrantRevision != r.Consent.Revision || g.NextRow != m.RowCount || g.NextChunk != m.ChunkCount || g.CompletedAt.IsZero() {
		return nil, ErrStorage
	}
	if r.Latest.Sequence != m.Sequence {
		return nil, nil
	}
	p := windowsservicehealth.Provenance{Kind: windowsservicehealth.CompleteSourceKind, GrantID: m.GrantID, GrantRevision: m.GrantRevision, GenerationID: m.GenerationID, ManifestSHA256: g.Hash, Sequence: m.Sequence, CapturedAt: m.CaptureStartedAt, CaptureFinishedAt: m.CaptureFinishedAt, ReceivedAt: g.CompletedAt, ExpiresAt: m.ExpiresAt, RowCount: m.RowCount}
	if !p.Fresh(now) {
		return nil, nil
	}
	rows, e := ledger.Selected(ctx, t.conn, device, g, names)
	if e != nil {
		return nil, e
	}
	return &windowsservicehealth.CompleteSample{Source: p, Rows: rows}, nil
}

// Freeze original identity, current leaf, consent and exact complete generation
// through the policy commit. The callback may enter only the operator store;
// its guard reuses this enrollment transaction after SQL waits and before commit.
func (s *Store) WithWindowsCompleteServiceAuthority(ctx context.Context, expected windowsservicehealth.Input, clock func() time.Time, fn func(func(time.Time) error) error) error {
	if s == nil || s.storeState == nil || ctx == nil || clock == nil || fn == nil || !expected.Authorized || !expected.Complete || !enrollmentcrypto.ValidHash(expected.CurrentLeaf) || s.config.Binding.CollectionProfile != windowsmanaged.CollectionProfile {
		return enrollmentstate.ErrProof
	}
	started := clock().UTC()
	if !validStoreTime(started) {
		return enrollmentstate.ErrInvalid
	}
	return s.transact(ctx, func(t *transaction) error {
		snap, e := systemDevice(t, expected.DeviceID)
		if e != nil {
			return e
		}
		last := started
		sourceChecked := false
		guard := func(minimum time.Time) error {
			at := clock().UTC()
			if ctx.Err() != nil || !validStoreTime(at) || at.Before(last) || at.Before(minimum) || at.Before(started) || at.Sub(started) > 5*time.Second || !at.Before(expected.AuthorityUntil) || snap.Platform != "windows" || snap.Binding != s.config.Binding || t.currentCertificateHash(snap) != expected.CurrentLeaf || snap.InvitationID != expected.InvitationID || snap.Issuance.CertificateHash != expected.CertificateHash || !time.Unix(t.currentCredentialNotAfter(snap), 0).UTC().Equal(expected.AuthorityUntil) {
				return enrollmentstate.ErrProof
			}
			last = at
			if e := t.authorizeCurrentCredential(snap, t.currentCertificateHash(snap), at); e != nil {
				return e
			}
			// Removal/disable may proceed without source. New/re-enabled selections
			// carry the reviewed immutable generation, never only a device/name claim.
			if expected.Selection != nil && !sourceChecked {
				present, e := windowsFullServicesSchemaPresent(ctx, t.conn, s.config.Binding.CollectionProfile)
				if e != nil {
					return e
				}
				if !present {
					return enrollmentstate.ErrProof
				}
				sample, e := readCompleteServiceHealth(ctx, t, expected.DeviceID, []string{}, at)
				if e != nil {
					return e
				}
				if sample == nil || sample.Source != *expected.Selection {
					return enrollmentstate.ErrProof
				}
				sourceChecked = true
			}
			// The locked transaction freezes source bytes/grant/current leaf.
			// Streaming integrity work may consume time; enforce actual time
			// after that work too, including every later post-wait guard.
			end := clock().UTC()
			if !validStoreTime(end) || end.Before(at) || end.Sub(started) > 5*time.Second || !end.Before(expected.AuthorityUntil) || expected.Selection != nil && !expected.Selection.Fresh(end) {
				return enrollmentstate.ErrProof
			}
			last = end
			return nil
		}
		if e := guard(started); e != nil {
			return e
		}
		return fn(guard)
	})
}
