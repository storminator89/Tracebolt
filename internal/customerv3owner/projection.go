package customerv3owner

import (
	"bytes"
	"context"
	"sync"
	"time"

	"localrmm/internal/customerbudget"
	"localrmm/internal/customerchallenge"
	"localrmm/internal/customerclaim"
	"localrmm/internal/customerissuance"
	"localrmm/internal/customerpending"
	"localrmm/internal/enrollmentcrypto"
)

// WithPublicProjection verifies possession of the original pending key before
// handing off only the public projection of an already committed v3 intent.
// It acquires the manager's shared proof budget before consuming a status-only
// challenge, then holds the v3 -> pending -> profile -> operator locks and the
// current issuance/revocation lease through the synchronous callback. The
// caller must use the same budget and challenge pool for all proof paths.
//
// emit must be synchronous, bounded, honor ctx and never reenter locked
// stores. It must invoke guard immediately at its actual response edge; a
// missing/failed guard or a callback error/panic yields ErrUncertain after
// handoff. The callback must not retain or invoke guard after it returns. Neither
// a callback nor a nil error proves that bytes reached a client. This isolated
// candidate is not a registered HTTP handler; protected distinct stores,
// durable used markers, genuine lifecycle/revocation leases and an actual
// response-edge implementation remain required runtime gates. No operator
// session is needed after its recorded approval. The returned projection and
// its digest alone are not evidence of approval or activation.
func (s *Store) WithPublicProjection(ctx context.Context, pending *customerpending.Store, pool *customerchallenge.Pool, budget *customerbudget.Budget, nonce string, raw, issuerDER, rootDER []byte, clock func() time.Time, acquire customerpending.AcquireOriginalAuthority, acquireLive AcquireIssuanceAuthority, storageGuard StorageGuard, emit func(customerissuance.PublicIntent, func() error) error) (resultErr error) {
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
	if s == nil || s.db == nil || ctx == nil || pending == nil || pool == nil || !budget.Valid() || len(raw) == 0 || len(raw) > customerclaim.MaxBytes || len(issuerDER) == 0 || len(issuerDER) > enrollmentcrypto.MaxCertificateBytes || len(rootDER) == 0 || len(rootDER) > enrollmentcrypto.MaxCertificateBytes || clock == nil || acquire == nil || acquireLive == nil || storageGuard == nil || emit == nil {
		return ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, MaxTransactionDuration)
	defer cancel()
	raw, issuerDER, rootDER = bytes.Clone(raw), bytes.Clone(issuerDER), bytes.Clone(rootDER)
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
	slot, err := budget.Acquire(ctx)
	if err != nil {
		return err
	}
	defer slot.Release()
	if err = storageGuard(ctx); err != nil {
		return err
	}
	challenge, err := pool.TakeStatus(nonce)
	if err != nil {
		return err
	}
	c, err := s.db.Conn(ctx)
	if err != nil {
		return ErrStorage
	}
	began := false
	var status *customerpending.StatusLease
	var live IssuanceAuthorityLease
	defer func() {
		if status != nil {
			status.Release()
		}
	}()
	defer func() {
		if live != nil {
			live.Release()
		}
	}()
	defer func() { closeTransaction(c, began, false) }()
	if _, err = c.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return ErrStorage
	}
	began = true
	intents, last, err := load(ctx, c, s.managerID, s.managerDigest)
	if err != nil {
		return err
	}
	if started.Unix() < last {
		return ErrInvalid
	}
	var intent customerissuance.Intent
	found := false
	for _, item := range intents {
		if item.Approval.Candidate.Pending.ClaimID == challenge.ClaimID {
			intent, found = item, true
			break
		}
	}
	if !found {
		return ErrConflict
	}
	digest, err := customerissuance.Digest(intent)
	if err != nil {
		return ErrInvalid
	}
	p := intent.Approval.Candidate.Pending
	metadata := customerclaim.Metadata{ManagerID: p.ManagerID, CustomerID: p.CustomerID, InstallerProfileID: p.InstallerProfileID, Origin: p.Origin, AgentOrigin: p.AgentOrigin, IssuerFingerprint: p.IssuerFingerprint, ClaimID: p.ClaimID, RequestID: p.RequestID, KeyFingerprint: p.KeyFingerprint, CSRHash: p.CSRHash, ClaimHash: p.ClaimHash, ComparisonCode: p.ComparisonCode}
	status, err = pending.AcquireStatus(ctx, challenge, raw, checkedClock, func(ctx context.Context, m customerclaim.Metadata) (customerpending.AuthorityLease, error) {
		return acquire(ctx, m, intent.Approval.Candidate.ManagerDigest)
	})
	if err != nil {
		return err
	}
	snapshot, err := status.Snapshot()
	if err != nil || snapshot.DeadlineAt != p.DeadlineAt {
		return ErrConflict
	}
	copyIntent := intent
	copyIntent.Approval.Candidate.Pending.PublicKeyDER = bytes.Clone(p.PublicKeyDER)
	live, err = acquireLive(ctx, copyIntent, digest)
	if err != nil {
		return err
	}
	if live == nil {
		return ErrInvalid
	}
	guard := func() error {
		if ctx.Err() != nil || status.Check() != nil || live.Check() != nil || storageGuard(ctx) != nil {
			return ErrInvalid
		}
		now := checkedClock()
		if now.IsZero() || now.Unix() < last || customerissuance.ValidateIssuer(intent, issuerDER, rootDER, now) != nil {
			return ErrInvalid
		}
		if _, e := customerclaim.VerifyStatus(raw, challenge, metadata, p.PublicKeyDER, now); e != nil {
			return ErrInvalid
		}
		return nil
	}
	public, err := customerissuance.ProjectPublic(intent)
	if err != nil {
		return err
	}
	if err = guard(); err != nil {
		return err
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
		if err := guard(); err != nil {
			failed = true
			return err
		}
		return nil
	}
	handed = true
	if err = emit(public, responseGuard); err != nil {
		return ErrUncertain
	}
	guardMu.Lock()
	active = false
	accepted := called && !failed
	guardMu.Unlock()
	if !accepted {
		return ErrUncertain
	}
	if err = guard(); err != nil {
		return ErrUncertain
	}
	return nil
}
