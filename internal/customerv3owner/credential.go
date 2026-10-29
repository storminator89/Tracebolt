package customerv3owner

import (
	"bytes"
	"context"
	"encoding/json"
	"sync"
	"time"

	"localrmm/internal/customerbudget"
	"localrmm/internal/customerchallenge"
	"localrmm/internal/customerclaim"
	"localrmm/internal/customerissuance"
	"localrmm/internal/customerpending"
	"localrmm/internal/customerv3proof"
	"localrmm/internal/enrollmentcrypto"
)

// CredentialRequest contains public routing and one-use proof material. Neither
// nonce nor signature is written to the database or logged by this package.
type CredentialRequest struct {
	ClaimID, IntentID, IntentDigest, RequestID, Nonce string
	Signature                                         []byte
}

// WithCredential hands off only a public intent projection and exact stored
// certificate DER, after a fresh original-key credential-purpose proof. The
// shared manager-wide budget and original/profile/issuance leases are held
// throughout the synchronous callback. The callback must call its guard at the
// actual response edge before writing; a missing or failed guard is uncertain.
// Pre/post checks do not provide an HTTP
// response-commit boundary: a callback may already have disclosed bytes when
// it fails or authority expires. Such outcomes return ErrUncertain, without
// claiming non-delivery; a fresh challenge may request the same stored bytes.
// The callback must honor cancellation and return promptly; a blocking callback
// cannot be forcibly interrupted and can retain locks beyond the deadline.
// Callers must provide protected non-aliased storage, one shared pool/budget,
// real revocation/lifecycle authority, and a separately authenticated projection
// handoff to the client before it can construct its first possession proof.
// This is not an activation, consent, service-start, or telemetry grant.
func (s *Store) WithCredential(ctx context.Context, pending *customerpending.Store, pool *customerchallenge.Pool, budget *customerbudget.Budget, request CredentialRequest, issuerDER, rootDER []byte, clock func() time.Time, acquire customerpending.AcquireOriginalAuthority, acquireLive AcquireIssuanceAuthority, storageGuard StorageGuard, emit func(customerissuance.PublicIntent, []byte, func() error) error) (resultErr error) {
	handed := false
	defer func() {
		if recover() != nil {
			if handed {
				resultErr = ErrUncertain
			} else {
				resultErr = ErrInvalid
			}
		}
	}()
	if s == nil || s.db == nil || ctx == nil || pending == nil || pool == nil || budget == nil || !budget.Valid() || clock == nil || acquire == nil || acquireLive == nil || storageGuard == nil || emit == nil || !enrollmentcrypto.ValidID(request.ClaimID, "claim_") || !enrollmentcrypto.ValidID(request.IntentID, "intent_") || !enrollmentcrypto.ValidID(request.RequestID, "request_") || !enrollmentcrypto.ValidHash(request.IntentDigest) || len(request.Nonce) > 128 || len(request.Signature) != 64 || len(issuerDER) == 0 || len(issuerDER) > enrollmentcrypto.MaxCertificateBytes || len(rootDER) == 0 || len(rootDER) > enrollmentcrypto.MaxCertificateBytes {
		return ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, MaxTransactionDuration)
	defer cancel()
	issuerDER, rootDER, request.Signature = bytes.Clone(issuerDER), bytes.Clone(rootDER), bytes.Clone(request.Signature)
	started := clock().UTC()
	lastClock := started
	var clockMu sync.Mutex
	checkedClock := func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		now := clock().UTC()
		if now.Before(lastClock) || !now.Before(started.Add(customerpending.MaxReviewLease)) {
			return time.Time{}
		}
		lastClock = now
		return now
	}
	if started.Unix() <= 0 || started.Unix() > maxTimestamp || ctx.Err() != nil {
		return ErrInvalid
	}
	slot, e := budget.Acquire(ctx)
	if e != nil {
		return e
	}
	defer slot.Release()
	if e = storageGuard(ctx); e != nil {
		return e
	}
	challenge, e := pool.TakeCredentialV3(request.Nonce)
	if e != nil {
		return e
	}
	c, e := s.db.Conn(ctx)
	if e != nil {
		return ErrStorage
	}
	began, committed := false, false
	var original *customerpending.ReviewLease
	var live IssuanceAuthorityLease
	defer func() {
		if original != nil {
			original.Release()
		}
	}()
	defer func() {
		if live != nil {
			live.Release()
		}
	}()
	defer func() { closeTransaction(c, began, committed) }()
	if _, e = c.ExecContext(ctx, `BEGIN IMMEDIATE`); e != nil {
		return ErrStorage
	}
	began = true
	intents, last, e := load(ctx, c, s.managerID, s.managerDigest)
	if e != nil {
		return e
	}
	if started.Unix() < last {
		return ErrInvalid
	}
	var intent customerissuance.Intent
	found := false
	for _, v := range intents {
		if v.Approval.Candidate.Pending.ClaimID == request.ClaimID {
			intent = v
			found = true
			break
		}
	}
	if !found || intent.IntentID != request.IntentID {
		return ErrConflict
	}
	digest, e := customerissuance.Digest(intent)
	if e != nil || digest != request.IntentDigest {
		return ErrConflict
	}
	var count int
	if c.QueryRowContext(ctx, `SELECT cert_count FROM customer_v3_meta WHERE id=1`).Scan(&count) != nil {
		return ErrStorage
	}
	certs, e := loadCertificates(ctx, c, intents, count, last)
	if e != nil {
		return e
	}
	var cert CertificateRecord
	found = false
	for _, v := range certs {
		if v.ClaimID == request.ClaimID {
			cert = v
			found = true
			break
		}
	}
	if !found {
		return ErrConflict
	}
	p := intent.Approval.Candidate.Pending
	expected := customerpending.ReviewExpectation{ManagerID: p.ManagerID, CustomerID: p.CustomerID, InstallerProfileID: p.InstallerProfileID, ClaimID: p.ClaimID, ClaimHash: p.ClaimHash, KeyFingerprint: p.KeyFingerprint, ManagerDigest: intent.Approval.Candidate.ManagerDigest, CustomerRevision: intent.Approval.Candidate.CustomerRevision, DeadlineAt: p.DeadlineAt}
	original, e = pending.AcquireOriginal(ctx, expected, checkedClock, acquire)
	if e != nil {
		return e
	}
	snap, e := original.Snapshot()
	if e != nil {
		return e
	}
	want, e := json.Marshal(p)
	if e != nil {
		return ErrInvalid
	}
	got, e := json.Marshal(snap)
	if e != nil || !bytes.Equal(want, got) {
		return ErrConflict
	}
	copyIntent := intent
	copyIntent.Approval.Candidate.Pending.PublicKeyDER = bytes.Clone(p.PublicKeyDER)
	live, e = acquireLive(ctx, copyIntent, digest)
	if e != nil {
		return e
	}
	if live == nil {
		return ErrInvalid
	}
	projected, e := customerissuance.ProjectPublic(intent)
	if e != nil {
		return ErrInvalid
	}
	check := func(now time.Time) error {
		if ctx.Err() != nil || now.Before(started) || now.Unix() < last || !now.Before(started.Add(customerpending.MaxReviewLease)) {
			return ErrInvalid
		}
		proof, e := customerissuance.VerifyIssued(cert.DER, issuerDER, rootDER, intent, now)
		if e != nil || proof.IntentDigest() != digest || proof.CertificateHash() != cert.CertificateHash {
			return ErrInvalid
		}
		if e = customerv3proof.Verify(intent, proof, customerv3proof.Credential, challenge, request.RequestID, request.Signature, now); e != nil {
			return ErrInvalid
		}
		if e = original.Check(); e != nil {
			return e
		}
		if e = live.Check(); e != nil {
			return e
		}
		if e = storageGuard(ctx); e != nil {
			return e
		}
		edge := checkedClock()
		if edge.IsZero() || edge.Before(now) || !edge.Before(started.Add(customerpending.MaxReviewLease)) || ctx.Err() != nil || !customerissuance.Current(intent, edge) || !customerclaim.ValidChallengeContext(challenge, edge) {
			return ErrInvalid
		}
		return nil
	}
	if e = check(checkedClock()); e != nil {
		return e
	}
	var guardMu sync.Mutex
	active, called, failed := true, false, false
	defer func() { guardMu.Lock(); active = false; guardMu.Unlock() }()
	responseGuard := func() (result error) {
		guardMu.Lock()
		defer guardMu.Unlock()
		defer func() {
			if recover() != nil {
				failed = true
				result = ErrInvalid
			}
		}()
		if !active {
			return ErrInvalid
		}
		called = true
		if err := check(checkedClock()); err != nil {
			failed = true
			return err
		}
		return nil
	}
	handed = true
	if e = emit(projected, bytes.Clone(cert.DER), responseGuard); e != nil {
		return ErrUncertain
	}
	guardMu.Lock()
	active = false
	accepted := called && !failed
	guardMu.Unlock()
	if !accepted {
		return ErrUncertain
	}
	if e = check(checkedClock()); e != nil {
		return ErrUncertain
	}
	// Rollback of a read-only transaction occurs during deferred cleanup while
	// all identity/issuer leases and the budget are still held.
	return nil
}
