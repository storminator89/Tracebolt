package windowsmanagedmsimanager

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"localrmm/internal/enrollmentcrypto"
	msi "localrmm/internal/windowsmanagedmsi"
	"sort"
	"sync"
	"time"
)

type ArtifactManager struct {
	mu              sync.Mutex
	store           msi.ArtifactStore
	key             ed25519.PublicKey
	spool           *Spool
	now             func() time.Time
	check           func() error
	deliveryAllowed func(string) bool
	failed          bool
}

func newArtifactManager(ctx context.Context, store msi.ArtifactStore, key ed25519.PublicKey, spool *Spool, clock func() time.Time, check func() error) (*ArtifactManager, error) {
	if store == nil || spool == nil || clock == nil || check == nil {
		return nil, msi.ErrInvalid
	}
	r, e := store.ReadWindowsManagedMSIArtifact(msi.WithFinalCheck(ctx, check), key)
	if e != nil {
		return nil, e
	}
	a := r.Artifact
	if r.RetirementStarted && !r.Retired {
		return nil, msi.ErrUncertain
	}
	if r.Retired {
		e = spool.validateRecord(false, false, 0)
	} else if a == nil {
		e = spool.validateRecord(false, false, 0)
	} else {
		e = spool.validateRecord(true, a.CompletedAt != 0, a.Package.Size)
	}
	if e != nil {
		return nil, e
	}
	return &ArtifactManager{store: store, key: bytes.Clone(key), spool: spool, now: clock, check: check}, nil
}
func (m *ArtifactManager) transaction(ctx context.Context, actor, kind string, fn func(*msi.ArtifactRecord, int64) error) (msi.ArtifactRecord, error) {
	if m.failed || ctx == nil {
		return msi.ArtifactRecord{}, msi.ErrUncertain
	}
	check := func() error {
		if e := m.check(); e != nil {
			return e
		}
		if !enrollmentcrypto.ValidID(actor, "operator_") || m.deliveryAllowed == nil || !m.deliveryAllowed(actor) {
			return msi.ErrAuthority
		}
		return nil
	}
	r, e := m.store.WindowsManagedMSIArtifactTransaction(msi.WithFinalCheck(ctx, check), m.key, m.now().UTC(), func(r *msi.ArtifactRecord, at time.Time) error {
		if e := check(); e != nil {
			return e
		}
		return fn(r, at.Unix())
	})
	if e == msi.ErrUncertain || e == msi.ErrIntegrity {
		m.failed = true
	}
	return r, e
}
func (m *ArtifactManager) read(ctx context.Context) (msi.ArtifactRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failed {
		return msi.ArtifactRecord{}, msi.ErrUncertain
	}
	r, e := m.store.ReadWindowsManagedMSIArtifact(msi.WithFinalCheck(ctx, m.check), m.key)
	if e == nil {
		e = msi.CheckFinal(ctx)
	}
	return r, e
}
func (m *ArtifactManager) ReserveUpload(ctx context.Context, actor string, selection msi.Selection, native string) error {

	return m.reserveUpload(ctx, actor, selection, native, "", "")
}
func (m *ArtifactManager) ReserveReusableUpload(ctx context.Context, actor string, selection msi.Selection, native, status, evidence string) error {
	if !msi.ValidPublisherEvidence(status, evidence) {
		return msi.ErrInvalid
	}
	return m.reserveUpload(ctx, actor, selection, native, status, evidence)
}
func (m *ArtifactManager) reserveUpload(ctx context.Context, actor string, selection msi.Selection, native, status, evidence string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !msi.ValidSelection(selection) || !msi.ValidDigest(native) {
		return msi.ErrInvalid
	}
	_, e := m.transaction(ctx, actor, "deliver", func(r *msi.ArtifactRecord, n int64) error {
		if (r.Version == msi.ReusableArtifactRecordVersion) != (status != "") {
			return msi.ErrAuthority
		}
		if r.Artifact != nil {
			next, e := msi.NextArtifact(*r)
			if e != nil {
				return e
			}
			*r = next
		}
		r.Artifact = &msi.Artifact{PublisherStatus: status, PublisherEvidenceDigest: evidence, Package: selection, NativeAcceptanceDigest: native, IntentAt: n, PrefixDigest: msi.Digest(nil)}
		return nil
	})
	return e
}

func (m *ArtifactManager) Upload(ctx context.Context, actor string, q UploadChunk) error {

	m.mu.Lock()
	defer m.mu.Unlock()
	if q.Index >= msi.MaxChunks || len(q.Data) == 0 || len(q.Data) > msi.MaxChunkBytes || !msi.ValidDigest(q.PackageDigest) || msi.Digest(q.Data) != q.Digest {
		return msi.ErrInvalid
	}
	var duplicate bool
	r, e := m.transaction(ctx, actor, "deliver", func(r *msi.ArtifactRecord, _ int64) error {
		a := r.Artifact
		if r.RetirementStarted || r.Retired || a == nil || a.CompletedAt != 0 || a.Package.SHA256 != q.PackageDigest {
			return msi.ErrConsumed
		}
		offset := int64(q.Index) * msi.MaxChunkBytes
		if offset < a.Offset && offset+int64(len(q.Data)) == a.Offset && q.Digest == a.LastChunkDigest {
			duplicate = true
			return nil
		}
		if offset != a.Offset || len(q.Data) != int(min(int64(msi.MaxChunkBytes), a.Package.Size-a.Offset)) {
			return msi.ErrConflict
		}
		if a.PendingDigest != "" && (a.PendingDigest != q.Digest || a.PendingIndex != q.Index || a.PendingSize != len(q.Data)) {
			return msi.ErrConflict
		}
		a.PendingDigest = q.Digest
		a.PendingIndex = q.Index
		a.PendingSize = len(q.Data)
		return nil
	})
	if e != nil || duplicate {
		return e
	}
	exact := *r.Artifact
	check := func() error {
		_, e := m.transaction(ctx, actor, "deliver", func(r *msi.ArtifactRecord, _ int64) error {
			if r.Artifact == nil || *r.Artifact != exact {
				return msi.ErrConflict
			}
			return nil
		})
		return e
	}
	var custody []func(string) error
	if exact.PublisherStatus != "" {
		custody = []func(string) error{func(identity string) error {
			_, e := m.transaction(ctx, actor, "deliver", func(r *msi.ArtifactRecord, _ int64) error {
				if r.Artifact == nil || *r.Artifact != exact || r.Artifact.CustodyDigest != "" {
					return msi.ErrConflict
				}
				r.Artifact.CustodyDigest = identity
				return nil
			})
			if e == nil {
				exact.CustodyDigest = identity
			}
			return e
		}}
	}
	prefix, e := m.spool.Append(ctx, exact, q.Data, check, custody...)
	if e != nil {
		return msi.ErrUncertain
	}
	_, e = m.transaction(ctx, actor, "deliver", func(r *msi.ArtifactRecord, _ int64) error {
		if r.Artifact == nil || *r.Artifact != exact {
			return msi.ErrConflict
		}
		a := r.Artifact
		a.Offset += int64(a.PendingSize)
		a.PrefixDigest = prefix
		a.LastChunkDigest = a.PendingDigest
		a.PendingIndex = 0
		a.PendingDigest = ""
		a.PendingSize = 0
		return nil
	})
	return e
}
func (m *ArtifactManager) CompleteUpload(ctx context.Context, actor string) error {

	m.mu.Lock()
	defer m.mu.Unlock()
	r, e := m.transaction(ctx, actor, "deliver", func(r *msi.ArtifactRecord, _ int64) error {
		a := r.Artifact
		if r.RetirementStarted || r.Retired || a == nil || a.CompletedAt != 0 || a.Offset != a.Package.Size || a.PrefixDigest != a.Package.SHA256 || a.PendingDigest != "" {
			return msi.ErrConflict
		}
		return nil
	})
	if e != nil {
		return e
	}
	exact := *r.Artifact
	check := func() error {
		_, e := m.transaction(ctx, actor, "deliver", func(r *msi.ArtifactRecord, _ int64) error {
			if r.Artifact == nil || *r.Artifact != exact {
				return msi.ErrConflict
			}
			return nil
		})
		return e
	}
	if _, e = m.spool.ReadChunk(ctx, exact.Package, 0, check, artifactCustody(exact)...); e != nil {
		return msi.ErrUncertain
	}
	_, e = m.transaction(ctx, actor, "deliver", func(r *msi.ArtifactRecord, n int64) error {
		if r.Artifact == nil || *r.Artifact != exact {
			return msi.ErrConflict
		}
		r.Artifact.CompletedAt = n
		return nil
	})
	return e
}

// RetireArtifact never reaches endpoints. It removes the current app-owned
// manager spool only after every assigned target durably acknowledged retirement.
// Unassigned devices contribute no permission and receive no package.
func (m *ArtifactManager) RetireArtifact(ctx context.Context, actor, artifactID string, ack bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !ack || !msi.ValidDigest(artifactID) {
		return msi.ErrInvalid
	}
	store, ok := m.store.(msi.TransactionStore)
	if !ok {
		return msi.ErrUnavailable
	}
	checkReferences := func(r msi.ArtifactRecord) (string, error) {
		if r.Version != msi.ReusableArtifactRecordVersion || r.Artifact == nil || r.RetirementStarted || r.Retired || msi.ArtifactIdentity(*r.Artifact) != artifactID {
			return "", msi.ErrConsumed
		}
		bindings, e := m.store.WindowsManagedMSIFleetBindings(ctx, m.key)
		if e != nil {
			return "", e
		}
		var evidence []string
		for _, b := range bindings {
			v, e := store.ReadRegisteredWindowsManagedMSI(msi.WithFinalCheck(ctx, m.check), b, m.key)
			if e != nil {
				return "", e
			}
			if v.Artifact == nil || msi.ArtifactIdentity(*v.Artifact) != artifactID {
				continue
			}
			if len(v.RetiredReport) == 0 {
				return "", msi.ErrUncertain
			}
			evidence = append(evidence, msi.BindingDigest(b)+":"+msi.Digest(v.RetiredReport))
		}
		sort.Strings(evidence)
		raw, _ := json.Marshal(evidence)
		return msi.Digest(raw), nil
	}
	r, e := m.store.ReadWindowsManagedMSIArtifact(msi.WithFinalCheck(ctx, m.check), m.key)
	if e != nil {
		return e
	}
	proof, e := checkReferences(r)
	if e != nil {
		return e
	}
	r, e = m.transaction(ctx, actor, "deliver", func(r *msi.ArtifactRecord, _ int64) error {
		if r.Artifact == nil || msi.ArtifactIdentity(*r.Artifact) != artifactID || r.RetirementStarted {
			return msi.ErrConflict
		}
		r.RetirementStarted = true
		r.RetirementEvidenceDigest = proof
		r.RetiredBy = actor
		return nil
	})
	if e != nil {
		return e
	}
	exact := r
	check := func() error {
		_, e := m.transaction(ctx, actor, "deliver", func(r *msi.ArtifactRecord, _ int64) error {
			if !sameJSON(*r, withArtifactClock(exact, r.ClockFloor)) {
				return msi.ErrConflict
			}
			return nil
		})
		return e
	}
	if e = m.spool.Retire(ctx, *r.Artifact, check); e != nil {
		m.failed = true
		return msi.ErrUncertain
	}
	_, e = m.transaction(ctx, actor, "deliver", func(r *msi.ArtifactRecord, _ int64) error {
		if !sameJSON(*r, withArtifactClock(exact, r.ClockFloor)) {
			return msi.ErrConflict
		}
		r.Retired = true
		return nil
	})
	return e
}
func withArtifactClock(r msi.ArtifactRecord, n int64) msi.ArtifactRecord { r.ClockFloor = n; return r }

func artifactCustody(a msi.Artifact) []string {
	if a.PublisherStatus != "" {
		return []string{a.CustodyDigest}
	}
	return nil
}
