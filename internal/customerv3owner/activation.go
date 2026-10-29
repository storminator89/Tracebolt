package customerv3owner

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"localrmm/internal/customerbudget"
	"localrmm/internal/customerchallenge"
	"localrmm/internal/customerclaim"
	"localrmm/internal/customerissuance"
	"localrmm/internal/customerpending"
	"localrmm/internal/customerschema"
	"localrmm/internal/customerv3proof"
	"localrmm/internal/enrollmentcrypto"
)

// ActivationRecord is an immutable v3 identity/leaf binding, not a local
// grant or a telemetry authorization. Neither nonce nor signature is retained.
type ActivationRecord struct {
	Version         string `json:"version"`
	ClaimID         string `json:"claimId"`
	IntentID        string `json:"intentId"`
	IntentDigest    string `json:"intentDigest"`
	CertificateHash string `json:"certificateHash"`
	DeviceID        string `json:"deviceId"`
	KeyFingerprint  string `json:"keyFingerprint"`
	RequestID       string `json:"requestId"`
	Purpose         string `json:"purpose"`
	ActivatedAt     int64  `json:"activatedAt"`
}

func loadActivations(ctx context.Context, c *sql.Conn, intents []customerissuance.Intent, certs []CertificateRecord, count int, last int64) ([]ActivationRecord, error) {
	byClaim := map[string]customerissuance.Intent{}
	byCert := map[string]CertificateRecord{}
	for _, i := range intents {
		byClaim[i.Approval.Candidate.Pending.ClaimID] = i
	}
	for _, cert := range certs {
		byCert[cert.ClaimID] = cert
	}
	rows, e := c.QueryContext(ctx, `SELECT claim_id,body FROM customer_v3_activations ORDER BY claim_id LIMIT 101`)
	if e != nil {
		return nil, ErrStorage
	}
	defer rows.Close()
	out := make([]ActivationRecord, 0, count)
	requests := map[string]bool{}
	for rows.Next() {
		var id string
		var raw []byte
		var a ActivationRecord
		if rows.Scan(&id, &raw) != nil || len(raw) > 4096 || json.Unmarshal(raw, &a) != nil {
			return nil, ErrStorage
		}
		i, ok := byClaim[id]
		cert, has := byCert[id]
		if !ok || !has {
			return nil, ErrStorage
		}
		digest, e := customerissuance.Digest(i)
		p := i.Approval.Candidate.Pending
		if e != nil || a.Version != "tracebolt.customer-v3-activation.v1" || a.ClaimID != id || a.IntentID != i.IntentID || a.IntentDigest != digest || a.IntentDigest != cert.IntentDigest || a.CertificateHash != cert.CertificateHash || a.DeviceID != i.Approval.Candidate.DeviceID || a.KeyFingerprint != p.KeyFingerprint || !enrollmentcrypto.ValidID(a.RequestID, "request_") || requests[a.RequestID] || a.Purpose != string(customerv3proof.Activation) || a.ActivatedAt < cert.RecordedAt || a.ActivatedAt < i.NotBefore || a.ActivatedAt >= i.NotAfter || a.ActivatedAt >= p.DeadlineAt || a.ActivatedAt > last {
			return nil, ErrStorage
		}
		canonical, e := json.Marshal(a)
		if e != nil || !bytes.Equal(canonical, raw) {
			return nil, ErrStorage
		}
		requests[a.RequestID] = true
		out = append(out, a)
	}
	if rows.Err() != nil || len(out) != count {
		return nil, ErrStorage
	}
	return out, nil
}

// ActivationRequest is public routing data; committed intent and certificate,
// not these fields, remain the authoritative identity and leaf. The nonce and
// proof signature are consumed but never persisted or logged.
type ActivationRequest struct {
	ClaimID, IntentID, IntentDigest, RequestID, Nonce string
	Signature                                         []byte
}

// Activate consumes an activation-purpose challenge after acquiring the shared
// manager-wide budget, then atomically retains one v3 activation under exact
// already-committed intent/leaf and proof of the original key. Runtime must
// share the SAME budget and challenge owner with all customer proof paths.
// Original/profile and live manager/issuer/revocation leases remain held across
// commit. Protected, non-aliased storage and external durable lifecycle fences
// are mandatory runtime gates; callbacks/this record alone prove none of them.
// Unknown commits require authorized read-only reconciliation, never retry.
func (s *Store) Activate(ctx context.Context, pending *customerpending.Store, pool *customerchallenge.Pool, budget *customerbudget.Budget, request ActivationRequest, issuerDER, rootDER []byte, clock func() time.Time, acquire customerpending.AcquireOriginalAuthority, acquireLive AcquireIssuanceAuthority, storageGuard StorageGuard) (result ActivationRecord, resultErr error) {
	attempted := false
	defer func() {
		if recover() != nil {
			result = ActivationRecord{}
			if attempted {
				resultErr = ErrUncertain
			} else {
				resultErr = ErrInvalid
			}
		}
	}()
	if s == nil || s.db == nil || ctx == nil || pending == nil || pool == nil || budget == nil || !budget.Valid() || clock == nil || acquire == nil || acquireLive == nil || storageGuard == nil || !enrollmentcrypto.ValidID(request.ClaimID, "claim_") || !enrollmentcrypto.ValidID(request.IntentID, "intent_") || !enrollmentcrypto.ValidID(request.RequestID, "request_") || !enrollmentcrypto.ValidHash(request.IntentDigest) || len(request.Nonce) > 128 || len(request.Signature) != 64 || len(issuerDER) == 0 || len(issuerDER) > enrollmentcrypto.MaxCertificateBytes || len(rootDER) == 0 || len(rootDER) > enrollmentcrypto.MaxCertificateBytes {
		return ActivationRecord{}, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, MaxTransactionDuration)
	defer cancel()
	issuerDER, rootDER, request.Signature = bytes.Clone(issuerDER), bytes.Clone(rootDER), bytes.Clone(request.Signature)
	started := clock().UTC()
	if started.Unix() <= 0 || started.Unix() > maxTimestamp || ctx.Err() != nil {
		return ActivationRecord{}, ErrInvalid
	}
	slot, e := budget.Acquire(ctx)
	if e != nil {
		return ActivationRecord{}, e
	}
	defer slot.Release()
	if e = storageGuard(ctx); e != nil {
		return ActivationRecord{}, e
	}
	challenge, e := pool.TakeActivationV3(request.Nonce)
	if e != nil {
		return ActivationRecord{}, e
	}
	c, e := s.db.Conn(ctx)
	if e != nil {
		return ActivationRecord{}, ErrStorage
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
		return ActivationRecord{}, ErrStorage
	}
	began = true
	intents, last, e := load(ctx, c, s.managerID, s.managerDigest)
	if e != nil {
		return ActivationRecord{}, e
	}
	if started.Unix() < last {
		return ActivationRecord{}, ErrInvalid
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
		return ActivationRecord{}, ErrConflict
	}
	digest, e := customerissuance.Digest(intent)
	if e != nil || digest != request.IntentDigest {
		return ActivationRecord{}, ErrConflict
	}
	var count int
	if c.QueryRowContext(ctx, `SELECT cert_count FROM customer_v3_meta WHERE id=1`).Scan(&count) != nil {
		return ActivationRecord{}, ErrStorage
	}
	certs, e := loadCertificates(ctx, c, intents, count, last)
	if e != nil {
		return ActivationRecord{}, e
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
		return ActivationRecord{}, ErrConflict
	}
	var existing int
	if c.QueryRowContext(ctx, `SELECT count(*) FROM customer_v3_activations WHERE claim_id=?`, request.ClaimID).Scan(&existing) != nil {
		return ActivationRecord{}, ErrStorage
	}
	if existing != 0 {
		return ActivationRecord{}, ErrConflict
	}
	p := intent.Approval.Candidate.Pending
	expected := customerpending.ReviewExpectation{ManagerID: p.ManagerID, CustomerID: p.CustomerID, InstallerProfileID: p.InstallerProfileID, ClaimID: p.ClaimID, ClaimHash: p.ClaimHash, KeyFingerprint: p.KeyFingerprint, ManagerDigest: intent.Approval.Candidate.ManagerDigest, CustomerRevision: intent.Approval.Candidate.CustomerRevision, DeadlineAt: p.DeadlineAt}
	original, e = pending.AcquireOriginal(ctx, expected, clock, acquire)
	if e != nil {
		return ActivationRecord{}, e
	}
	snap, e := original.Snapshot()
	if e != nil {
		return ActivationRecord{}, e
	}
	want, e := json.Marshal(p)
	if e != nil {
		return ActivationRecord{}, ErrInvalid
	}
	got, e := json.Marshal(snap)
	if e != nil || !bytes.Equal(want, got) {
		return ActivationRecord{}, ErrConflict
	}
	copyIntent := intent
	copyIntent.Approval.Candidate.Pending.PublicKeyDER = bytes.Clone(p.PublicKeyDER)
	live, e = acquireLive(ctx, copyIntent, digest)
	if e != nil {
		return ActivationRecord{}, e
	}
	if live == nil {
		return ActivationRecord{}, ErrInvalid
	}
	check := func(now time.Time) error {
		if ctx.Err() != nil || now.Before(started) || now.Unix() < last || !now.Before(started.Add(customerpending.MaxReviewLease)) {
			return ErrInvalid
		}
		if e := original.Check(); e != nil {
			return e
		}
		if e := live.Check(); e != nil {
			return e
		}
		if e := storageGuard(ctx); e != nil {
			return e
		}
		proof, e := customerissuance.VerifyIssued(cert.DER, issuerDER, rootDER, intent, now)
		if e != nil || proof.IntentDigest() != digest || proof.CertificateHash() != cert.CertificateHash {
			return ErrInvalid
		}
		if e = customerv3proof.Verify(intent, proof, customerv3proof.Activation, challenge, request.RequestID, request.Signature, now); e != nil {
			return ErrInvalid
		}
		return nil
	}
	now := clock().UTC()
	if e = check(now); e != nil {
		return ActivationRecord{}, e
	}
	if now.Unix() < cert.RecordedAt {
		return ActivationRecord{}, ErrInvalid
	}
	record := ActivationRecord{Version: "tracebolt.customer-v3-activation.v1", ClaimID: request.ClaimID, IntentID: intent.IntentID, IntentDigest: digest, CertificateHash: cert.CertificateHash, DeviceID: intent.Approval.Candidate.DeviceID, KeyFingerprint: p.KeyFingerprint, RequestID: request.RequestID, Purpose: string(customerv3proof.Activation), ActivatedAt: now.Unix()}
	// Check request uniqueness against the complete loaded activation set.
	var activationCount int
	if c.QueryRowContext(ctx, `SELECT activation_count FROM customer_v3_meta WHERE id=1`).Scan(&activationCount) != nil {
		return ActivationRecord{}, ErrStorage
	}
	existingRows, e := loadActivations(ctx, c, intents, certs, activationCount, last)
	if e != nil {
		return ActivationRecord{}, e
	}
	for _, v := range existingRows {
		if v.RequestID == request.RequestID {
			return ActivationRecord{}, ErrConflict
		}
	}
	raw, e := json.Marshal(record)
	if e != nil || len(raw) > 4096 {
		return ActivationRecord{}, ErrInvalid
	}
	if _, e = c.ExecContext(ctx, `INSERT INTO customer_v3_activations(claim_id,body) VALUES(?,?)`, request.ClaimID, raw); e != nil {
		return ActivationRecord{}, ErrStorage
	}
	end := clock().UTC()
	if end.Before(now) {
		return ActivationRecord{}, ErrInvalid
	}
	if e = check(end); e != nil {
		return ActivationRecord{}, e
	}
	if _, e = c.ExecContext(ctx, `UPDATE customer_v3_meta SET activation_count=activation_count+1,last_at=? WHERE id=1`, end.Unix()); e != nil || customerschema.ValidateVersion(ctx, c, schema(), schemaVersion) != nil {
		return ActivationRecord{}, ErrStorage
	}
	final := clock().UTC()
	if final.Before(end) {
		return ActivationRecord{}, ErrInvalid
	}
	if e = check(final); e != nil {
		return ActivationRecord{}, e
	}
	if final.Unix() != end.Unix() {
		if _, e = c.ExecContext(ctx, `UPDATE customer_v3_meta SET last_at=? WHERE id=1`, final.Unix()); e != nil {
			return ActivationRecord{}, ErrStorage
		}
	}
	// Repeat the guarded edge after verification and metadata writes; the
	// leases prevent revocation races and the clock must remain in bounds.
	if e = original.Check(); e != nil {
		return ActivationRecord{}, e
	}
	if e = live.Check(); e != nil {
		return ActivationRecord{}, e
	}
	if e = storageGuard(ctx); e != nil {
		return ActivationRecord{}, e
	}
	edge := clock().UTC()
	if edge.Before(final) || !edge.Before(started.Add(customerpending.MaxReviewLease)) || ctx.Err() != nil || !customerissuance.Current(intent, edge) || !customerclaim.ValidChallengeContext(challenge, edge) {
		return ActivationRecord{}, ErrInvalid
	}
	if edge.Unix() != final.Unix() {
		if _, e = c.ExecContext(ctx, `UPDATE customer_v3_meta SET last_at=? WHERE id=1`, edge.Unix()); e != nil {
			return ActivationRecord{}, ErrStorage
		}
	}
	attempted = true
	if _, e = c.ExecContext(ctx, `COMMIT`); e != nil {
		return ActivationRecord{}, ErrUncertain
	}
	committed = true
	after := clock().UTC()
	if after.Before(edge) || check(after) != nil {
		return ActivationRecord{}, ErrUncertain
	}
	finished := clock().UTC()
	if finished.Before(after) || !finished.Before(started.Add(customerpending.MaxReviewLease)) || ctx.Err() != nil || !customerissuance.Current(intent, finished) || !customerclaim.ValidChallengeContext(challenge, finished) {
		return ActivationRecord{}, ErrUncertain
	}
	return record, nil
}

// ActivationRecords provides an internal reconciliation read. Callers must
// enforce protected storage and operator authorization; this is not a public
// status or telemetry API and does not establish current revocation state.
func (s *Store) ActivationRecords(ctx context.Context) (result []ActivationRecord, resultErr error) {
	defer func() {
		if recover() != nil {
			result = nil
			resultErr = ErrStorage
		}
	}()
	if s == nil || s.db == nil || ctx == nil {
		return nil, ErrInvalid
	}
	c, e := s.db.Conn(ctx)
	if e != nil {
		return nil, ErrStorage
	}
	began, committed := false, false
	defer func() { closeTransaction(c, began, committed) }()
	if _, e = c.ExecContext(ctx, `BEGIN`); e != nil {
		return nil, ErrStorage
	}
	began = true
	intents, last, e := load(ctx, c, s.managerID, s.managerDigest)
	if e != nil {
		return nil, e
	}
	var certCount, activationCount int
	if c.QueryRowContext(ctx, `SELECT cert_count,activation_count FROM customer_v3_meta WHERE id=1`).Scan(&certCount, &activationCount) != nil {
		return nil, ErrStorage
	}
	certs, e := loadCertificates(ctx, c, intents, certCount, last)
	if e != nil {
		return nil, e
	}
	out, e := loadActivations(ctx, c, intents, certs, activationCount, last)
	if e != nil {
		return nil, e
	}
	if _, e = c.ExecContext(ctx, `COMMIT`); e != nil {
		return nil, ErrStorage
	}
	committed = true
	return out, nil
}
