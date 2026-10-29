package customerpending

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"sync"
	"time"

	"localrmm/internal/customerclaim"
)

// PendingStatus is a source-only view of the pending record, not the current
// enrollment lifecycle. It neither conveys approval nor permits issuance. Once
// approval or a terminal state exists, a retained pending record alone cannot
// establish current status; an outer enrollment authority is required.
type PendingStatus struct {
	SchemaVersion string `json:"schemaVersion"`
	State         string `json:"state"`
	DeadlineAt    int64  `json:"deadlineAt"`
}

// StatusLease protects the original pending claim and nested authority until
// Release. A caller must defer Release immediately, recheck at the response edge,
// and hold the lease through the synchronous response commitment. It must never
// be used as enrollment, approval, credential or telemetry authority.
type StatusLease struct {
	mu            sync.Mutex
	conn          *sql.Conn
	ctx           context.Context
	clock         func() time.Time
	authority     AuthorityLease
	record        Record
	proof         customerclaim.VerifiedStatus
	started, last time.Time
}

// AcquireStatus verifies a status proof against the exclusively stored key and
// metadata under the pending lock, then holds the profile/customer/issuer lease.
// The trusted coordinator MUST consume the exact status-purpose challenge from
// its bounded manager-owned pool first; accepting a caller-created context here
// would remove replay protection. The status challenge's original context must
// have been generated from trusted retained claim state. Protected files, alias
// checks and a real authority lease remain the integrating owner's responsibility.
// This method does not query an enrollment/approval/terminal state. Do not
// expose it until a live enrollment lease in enrollment→pending→profile→operator
// order verifies pending remains the current state through response commitment.
func (s *Store) AcquireStatus(ctx context.Context, challenge customerclaim.Context, raw []byte, clock func() time.Time, acquire AcquireAuthority) (*StatusLease, error) {
	if s == nil || s.db == nil || ctx == nil || clock == nil || acquire == nil || len(raw) == 0 || len(raw) > customerclaim.MaxBytes {
		return nil, ErrInvalid
	}
	started := clock().UTC()
	if ctx.Err() != nil || !customerclaim.ValidChallengeContext(challenge, started) {
		return nil, ErrExpired
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return nil, ErrStorage
	}
	l := &StatusLease{conn: conn, ctx: ctx, clock: clock, started: started, last: started}
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
	for _, record := range records {
		if record.ClaimID == challenge.ClaimID {
			l.record, found = record, true
			break
		}
	}
	if !found {
		return nil, ErrConflict
	}
	verifiedAt := clock().UTC()
	if verifiedAt.Before(started) || verifiedAt.Unix() >= l.record.DeadlineAt || !customerclaim.ValidChallengeContext(challenge, verifiedAt) {
		return nil, ErrExpired
	}
	// reviewMetadata reconstructs only public immutable fields from the stored
	// record; the old claim challenge is deliberately not carried forward.
	l.proof, err = customerclaim.VerifyStatus(raw, challenge, reviewMetadata(l.record), l.record.PublicKeyDER, verifiedAt)
	if err != nil {
		return nil, err
	}
	l.last = verifiedAt
	l.authority, err = acquire(ctx, l.proof.Metadata())
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

func (l *StatusLease) clockOK() error {
	now := l.clock().UTC()
	if now.Unix() <= 0 || now.Unix() > maxTimestamp || now.Before(l.started) || now.Before(l.last) ||
		!now.Before(l.started.Add(MaxReviewLease)) || now.Unix() >= l.record.DeadlineAt ||
		now.Unix() >= l.proof.ExpiresAt() || l.proof.ExpiresAt() > now.Unix()+int64(customerclaim.MaxChallengeLifetime/time.Second) {
		return ErrExpired
	}
	l.last = now
	return nil
}

// Check rereads and compares the complete canonical record and rechecks live
// authority, context and time. A successful check is not a persistent grant.
func (l *StatusLease) Check() error {
	if l == nil {
		return ErrInvalid
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.checkLocked()
}

func (l *StatusLease) checkLocked() error {
	if l.conn == nil || l.ctx == nil || l.clock == nil || l.authority == nil || !l.proof.Valid() {
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
	for _, record := range records {
		if record.ClaimID == l.record.ClaimID {
			actual, _ := json.Marshal(record)
			original, _ := json.Marshal(l.record)
			if !bytes.Equal(actual, original) || l.proof.Metadata() != reviewMetadata(record) {
				return ErrConflict
			}
			found = true
			break
		}
	}
	if !found {
		return ErrConflict
	}
	if err = l.authority.Check(); err != nil {
		return err
	}
	if err = l.ctx.Err(); err != nil {
		return err
	}
	return l.clockOK()
}

// Snapshot rechecks before returning the minimal pending view. Hold this lease
// and Check immediately before committing any response based on the view.
func (l *StatusLease) Snapshot() (PendingStatus, error) {
	if l == nil {
		return PendingStatus{}, ErrInvalid
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.checkLocked(); err != nil {
		return PendingStatus{}, err
	}
	return PendingStatus{SchemaVersion: "tracebolt.customer-pending-status.v1", State: "pending", DeadlineAt: l.record.DeadlineAt}, nil
}

// Release ends the pending transaction before nested authority; any uncertain
// rollback discards the connection. It is safe to call more than once.
func (l *StatusLease) Release() {
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
