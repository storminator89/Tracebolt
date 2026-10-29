package customerpending

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"sync"
	"time"

	"localrmm/internal/customerclaim"
	"localrmm/internal/enrollmentcrypto"
)

// MaxReviewLease limits the time an enclosing transaction may hold a reviewed
// pending identity. The original claim deadline remains independently binding.
const MaxReviewLease = 30 * time.Second

// ReviewExpectation is the exact original record an operator saw. ClaimHash
// binds the request ID, CSR hash and public key; it is not an approval.
type ReviewExpectation struct {
	ManagerID, CustomerID, InstallerProfileID string
	ClaimID, ClaimHash, KeyFingerprint        string
	ManagerDigest                             string
	CustomerRevision                          uint64
	DeadlineAt                                int64
}

// AcquireReviewAuthority must lock exactly the manager digest and customer
// revision that the operator reviewed. It must never substitute the latest
// revision. Admission's AcquireAuthority has deliberately different semantics.
type AcquireReviewAuthority func(context.Context, customerclaim.Metadata, string, uint64) (AuthorityLease, error)

// AcquireOriginalAuthority locks the original manager binding plus the current
// customer/profile/issuer authority after an already-committed v3 approval.
// Unlike an operator review, a rename after approval does not require the old
// catalog revision to remain current. This does not itself prove approval.
type AcquireOriginalAuthority func(context.Context, customerclaim.Metadata, string) (AuthorityLease, error)

// ReviewLease holds the pending write exclusion and the nested profile/operator
// authority until Release. It does not approve, issue, activate or mutate state.
// Caller must defer Release immediately, including on a panic, and retain it
// until the enclosing enrollment transaction has committed or rolled back.
// Production integration additionally requires protected, non-aliased DBs and
// a real session/issuer authority lease in enrollment→pending→profile→operator
// lock order. Its clock must be trusted and restart-safe.
type ReviewLease struct {
	mu        sync.Mutex
	conn      *sql.Conn
	ctx       context.Context
	clock     func() time.Time
	authority AuthorityLease
	expected  Record
	started   time.Time
	last      time.Time
}

func validExpectation(e ReviewExpectation) bool {
	return enrollmentcrypto.ValidID(e.ManagerID, "manager_") && enrollmentcrypto.ValidID(e.CustomerID, "customer_") && enrollmentcrypto.ValidID(e.InstallerProfileID, "profile_") && enrollmentcrypto.ValidID(e.ClaimID, "claim_") && enrollmentcrypto.ValidHash(e.ClaimHash) && enrollmentcrypto.ValidHash(e.KeyFingerprint) && enrollmentcrypto.ValidHash(e.ManagerDigest) && e.CustomerRevision > 0 && e.CustomerRevision <= 1<<53-1 && e.DeadlineAt > 0 && e.DeadlineAt <= maxTimestamp
}

func matchesReview(r Record, e ReviewExpectation) bool {
	return r.ManagerID == e.ManagerID && r.CustomerID == e.CustomerID && r.InstallerProfileID == e.InstallerProfileID && r.ClaimID == e.ClaimID && r.ClaimHash == e.ClaimHash && r.KeyFingerprint == e.KeyFingerprint && r.DeadlineAt == e.DeadlineAt
}

func reviewMetadata(r Record) customerclaim.Metadata {
	// The claim challenge was consumed on admission and is not review authority.
	return customerclaim.Metadata{ManagerID: r.ManagerID, CustomerID: r.CustomerID, InstallerProfileID: r.InstallerProfileID, Origin: r.Origin, AgentOrigin: r.AgentOrigin, IssuerFingerprint: r.IssuerFingerprint, ClaimID: r.ClaimID, RequestID: r.RequestID, KeyFingerprint: r.KeyFingerprint, CSRHash: r.CSRHash, ClaimHash: r.ClaimHash, ComparisonCode: r.ComparisonCode}
}

// AcquireReview reads and locks the exact pending record before acquiring the
// supplied authority lease. A successful result is a short-lived review guard,
// not approval. Call Check immediately before an outer commit and hold the
// returned lease through that commit or rollback; no callback may reenter this
// pending store. Unknown outer transaction outcomes require read reconciliation.
func (s *Store) AcquireReview(ctx context.Context, expected ReviewExpectation, clock func() time.Time, acquire AcquireReviewAuthority) (*ReviewLease, error) {
	if s == nil || s.db == nil || ctx == nil || clock == nil || acquire == nil || !validExpectation(expected) {
		return nil, ErrInvalid
	}
	return s.acquireOriginal(ctx, expected, clock, func(ctx context.Context, m customerclaim.Metadata) (AuthorityLease, error) {
		return acquire(ctx, m, expected.ManagerDigest, expected.CustomerRevision)
	})
}

// AcquireOriginal holds the original immutable pending binding and current
// authority for a continuation of an already committed v3 approval. The caller
// must first lock and verify that exact authoritative intent; this function is
// not an approval and does not authorize signing, delivery or observation. The
// recorded customer revision is historical: current customer existence and
// authority must be established by acquire without promoting or re-reviewing it.
func (s *Store) AcquireOriginal(ctx context.Context, expected ReviewExpectation, clock func() time.Time, acquire AcquireOriginalAuthority) (*ReviewLease, error) {
	if s == nil || s.db == nil || ctx == nil || clock == nil || acquire == nil || !validExpectation(expected) {
		return nil, ErrInvalid
	}
	return s.acquireOriginal(ctx, expected, clock, func(ctx context.Context, m customerclaim.Metadata) (AuthorityLease, error) {
		return acquire(ctx, m, expected.ManagerDigest)
	})
}

func (s *Store) acquireOriginal(ctx context.Context, expected ReviewExpectation, clock func() time.Time, acquire AcquireAuthority) (*ReviewLease, error) {
	started := clock().UTC()
	if started.Unix() <= 0 || started.Unix() > maxTimestamp || started.Unix() >= expected.DeadlineAt {
		return nil, ErrExpired
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return nil, ErrStorage
	}
	l := &ReviewLease{conn: conn, ctx: ctx, clock: clock, started: started, last: started}
	began, retained := false, false
	defer func() {
		if !retained {
			if began {
				l.Release()
			} else {
				discardConnection(conn)
			}
		}
	}()
	if _, err = conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return nil, ErrStorage
	}
	began = true
	records, last, err := load(ctx, conn)
	if err != nil {
		return nil, err
	}
	if started.Unix() < last {
		return nil, ErrInvalid
	}
	found := false
	for _, r := range records {
		if r.ClaimID == expected.ClaimID {
			if !matchesReview(r, expected) {
				return nil, ErrConflict
			}
			l.expected, found = r, true
			break
		}
	}
	if !found {
		return nil, ErrConflict
	}
	l.authority, err = acquire(ctx, reviewMetadata(l.expected))
	if err != nil {
		return nil, err
	}
	if l.authority == nil {
		return nil, ErrInvalid
	}
	if err = l.Check(); err != nil {
		return nil, err
	}
	retained = true
	return l, nil
}

func (l *ReviewLease) clockOK() error {
	at := l.clock().UTC()
	if at.Unix() <= 0 || at.Unix() > maxTimestamp || at.Before(l.started) || at.Before(l.last) || !at.Before(l.started.Add(MaxReviewLease)) || at.Unix() >= l.expected.DeadlineAt {
		return ErrExpired
	}
	l.last = at
	return nil
}

// Check revalidates the exact stored record, current authority, clock and
// context while locks remain held. A successful check is valid only for the
// immediately following guarded commit, not a persistent authorization token.
func (l *ReviewLease) Check() error {
	if l == nil {
		return ErrInvalid
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.checkLocked()
}

func (l *ReviewLease) checkLocked() error {
	if l.conn == nil || l.authority == nil || l.ctx == nil || l.clock == nil {
		return ErrInvalid
	}
	if err := l.ctx.Err(); err != nil {
		return err
	}
	if err := l.clockOK(); err != nil {
		return err
	}
	records, last, err := load(l.ctx, l.conn)
	if err != nil {
		return err
	}
	if l.last.Unix() < last {
		return ErrInvalid
	}
	found := false
	for _, r := range records {
		if r.ClaimID == l.expected.ClaimID {
			expected, _ := json.Marshal(l.expected)
			actual, _ := json.Marshal(r)
			if !bytes.Equal(actual, expected) {
				return ErrConflict
			}
			found = true
			break
		}
	}
	if !found {
		return ErrConflict
	}
	if err := l.authority.Check(); err != nil {
		return err
	}
	if err := l.ctx.Err(); err != nil {
		return err
	}
	return l.clockOK()
}

// Snapshot returns a deep copy only after a fresh authority/time check. The
// caller must recheck before commit; this value alone has no authority.
func (l *ReviewLease) Snapshot() (Record, error) {
	if l == nil {
		return Record{}, ErrInvalid
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.checkLocked(); err != nil {
		return Record{}, err
	}
	r := l.expected
	r.PublicKeyDER = bytes.Clone(r.PublicKeyDER)
	return r, nil
}

// Release rolls back the pending read lease before releasing nested authority.
// A failed rollback discards the connection; repeated releases are harmless.
func (l *ReviewLease) Release() {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	authority, conn := l.authority, l.conn
	l.authority, l.conn = nil, nil
	if authority != nil {
		defer authority.Release()
	}
	if conn != nil {
		releaseTransaction(conn, false)
	}
}
