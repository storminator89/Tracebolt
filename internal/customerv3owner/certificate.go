package customerv3owner

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	"localrmm/internal/customerissuance"
	"localrmm/internal/customerpending"
	"localrmm/internal/customerschema"
	"localrmm/internal/enrollmentcrypto"
)

// CertificateRequest identifies an already committed intent, not a CSR or
// arbitrary device. Digest is verified against the exact canonical stored row.
type CertificateRequest struct{ ClaimID, IntentID, IntentDigest string }

// IssuanceAuthorityLease protects the committed approval/intent against
// revocation, as well as the live manager and issuer. It does not depend on
// the operator's original browser session: that session was held through the
// prior approval COMMIT. A real runtime must implement and hold these guards.
type IssuanceAuthorityLease interface {
	Check() error
	Release()
}

// AcquireIssuanceAuthority must bind the exact stored immutable intent,
// including historical actor, and its digest to live revocation and issuer
// authority. This candidate store does not provide durable revocation itself.
type AcquireIssuanceAuthority func(context.Context, customerissuance.Intent, string) (IssuanceAuthorityLease, error)

// CommitCertificate atomically retains one already verified public DER leaf
// under the exact previously committed v3 intent. It never signs, delivers or
// activates a credential. The original pending binding is held with CURRENT
// customer/profile authority, so a customer rename after approval is not an
// implicit re-review or a changed identity. A retired/revoked profile, missing
// original binding, live issuance authority loss, expired original deadline or
// changed v3 state blocks the commit. The old reviewed customer revision stays
// immutable in the intent. Retrying an already retained certificate conflicts,
// even with identical bytes; unknown COMMIT outcomes require authorized reads.
// Protected non-aliased DBs, original used markers and genuine held leases are
// explicit runtime prerequisites; callbacks do not themselves prove them.
func (s *Store) CommitCertificate(ctx context.Context, pending *customerpending.Store, request CertificateRequest, proof customerissuance.VerifiedCertificate, issuerDER, rootDER []byte, clock func() time.Time, acquire customerpending.AcquireOriginalAuthority, acquireLive AcquireIssuanceAuthority, storageGuard StorageGuard) (result CertificateRecord, resultErr error) {
	commitAttempted := false
	defer func() {
		if recover() != nil {
			result = CertificateRecord{}
			if commitAttempted {
				resultErr = ErrUncertain
			} else {
				resultErr = ErrInvalid
			}
		}
	}()
	if s == nil || s.db == nil || ctx == nil || pending == nil || clock == nil || acquire == nil || acquireLive == nil || storageGuard == nil || !proof.Valid() || !enrollmentcrypto.ValidID(request.ClaimID, "claim_") || !enrollmentcrypto.ValidID(request.IntentID, "intent_") || !enrollmentcrypto.ValidHash(request.IntentDigest) || proof.IntentDigest() != request.IntentDigest || !enrollmentcrypto.ValidHash(proof.CertificateHash()) || len(issuerDER) == 0 || len(issuerDER) > enrollmentcrypto.MaxCertificateBytes || len(rootDER) == 0 || len(rootDER) > enrollmentcrypto.MaxCertificateBytes {
		return CertificateRecord{}, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, MaxTransactionDuration)
	defer cancel()
	issuerDER, rootDER, der := bytes.Clone(issuerDER), bytes.Clone(rootDER), proof.DER()
	if len(der) == 0 || len(der) > enrollmentcrypto.MaxCertificateBytes {
		return CertificateRecord{}, ErrInvalid
	}
	started := clock().UTC()
	if started.Unix() <= 0 || started.Unix() > maxTimestamp || ctx.Err() != nil {
		return CertificateRecord{}, ErrInvalid
	}
	if err := storageGuard(ctx); err != nil {
		return CertificateRecord{}, err
	}
	c, e := s.db.Conn(ctx)
	if e != nil {
		return CertificateRecord{}, ErrStorage
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
		return CertificateRecord{}, ErrStorage
	}
	began = true
	intents, last, e := load(ctx, c, s.managerID, s.managerDigest)
	if e != nil {
		return CertificateRecord{}, e
	}
	if started.Unix() < last {
		return CertificateRecord{}, ErrInvalid
	}
	var intent customerissuance.Intent
	found := false
	for _, candidate := range intents {
		if candidate.Approval.Candidate.Pending.ClaimID == request.ClaimID {
			intent = candidate
			found = true
			break
		}
	}
	if !found || intent.IntentID != request.IntentID {
		return CertificateRecord{}, ErrConflict
	}
	idigest, e := customerissuance.Digest(intent)
	if e != nil || idigest != request.IntentDigest {
		return CertificateRecord{}, ErrConflict
	}
	var existing int
	if c.QueryRowContext(ctx, `SELECT count(*) FROM customer_v3_certificates WHERE claim_id=?`, request.ClaimID).Scan(&existing) != nil {
		return CertificateRecord{}, ErrStorage
	}
	if existing != 0 {
		return CertificateRecord{}, ErrConflict
	}
	p := intent.Approval.Candidate.Pending
	expected := customerpending.ReviewExpectation{ManagerID: p.ManagerID, CustomerID: p.CustomerID, InstallerProfileID: p.InstallerProfileID, ClaimID: p.ClaimID, ClaimHash: p.ClaimHash, KeyFingerprint: p.KeyFingerprint, ManagerDigest: intent.Approval.Candidate.ManagerDigest, CustomerRevision: intent.Approval.Candidate.CustomerRevision, DeadlineAt: p.DeadlineAt}
	original, e = pending.AcquireOriginal(ctx, expected, clock, acquire)
	if e != nil {
		return CertificateRecord{}, e
	}
	currentPending, e := original.Snapshot()
	if e != nil {
		return CertificateRecord{}, e
	}
	wantPending, e := json.Marshal(p)
	if e != nil {
		return CertificateRecord{}, ErrInvalid
	}
	gotPending, e := json.Marshal(currentPending)
	if e != nil || !bytes.Equal(wantPending, gotPending) {
		return CertificateRecord{}, ErrConflict
	}
	leaseIntent := intent
	leaseIntent.Approval.Candidate.Pending.PublicKeyDER = bytes.Clone(intent.Approval.Candidate.Pending.PublicKeyDER)
	live, e = acquireLive(ctx, leaseIntent, idigest)
	if e != nil {
		return CertificateRecord{}, e
	}
	if live == nil {
		return CertificateRecord{}, ErrInvalid
	}
	if e = live.Check(); e != nil {
		return CertificateRecord{}, e
	}
	now := clock().UTC()
	if now.Before(started) || now.Unix() < last {
		return CertificateRecord{}, ErrInvalid
	}
	verified, e := customerissuance.VerifyIssued(der, issuerDER, rootDER, intent, now)
	if e != nil || verified.IntentDigest() != idigest || verified.CertificateHash() != proof.CertificateHash() {
		return CertificateRecord{}, ErrInvalid
	}
	record := CertificateRecord{Version: "tracebolt.customer-v3-certificate-record.v1", ClaimID: request.ClaimID, IntentID: request.IntentID, IntentDigest: idigest, CertificateHash: verified.CertificateHash(), DER: bytes.Clone(der), RecordedAt: now.Unix()}
	raw, e := json.Marshal(record)
	if e != nil || len(raw) > 16384 {
		return CertificateRecord{}, ErrInvalid
	}
	if _, e = c.ExecContext(ctx, `INSERT INTO customer_v3_certificates(claim_id,body) VALUES(?,?)`, request.ClaimID, raw); e != nil {
		return CertificateRecord{}, ErrStorage
	}
	if e = original.Check(); e != nil {
		return CertificateRecord{}, e
	}
	if e = live.Check(); e != nil {
		return CertificateRecord{}, e
	}
	if e = storageGuard(ctx); e != nil {
		return CertificateRecord{}, e
	}
	end := clock().UTC()
	if end.Before(now) || !end.Before(started.Add(customerpending.MaxReviewLease)) || ctx.Err() != nil {
		return CertificateRecord{}, ErrInvalid
	}
	verified, e = customerissuance.VerifyIssued(der, issuerDER, rootDER, intent, end)
	if e != nil || verified.IntentDigest() != idigest || verified.CertificateHash() != record.CertificateHash {
		return CertificateRecord{}, ErrInvalid
	}
	if _, e = c.ExecContext(ctx, `UPDATE customer_v3_meta SET cert_count=cert_count+1,last_at=? WHERE id=1`, end.Unix()); e != nil || customerschema.ValidateVersion(ctx, c, schema(), schemaVersion) != nil {
		return CertificateRecord{}, ErrStorage
	}
	if e = original.Check(); e != nil {
		return CertificateRecord{}, e
	}
	if e = live.Check(); e != nil {
		return CertificateRecord{}, e
	}
	if e = storageGuard(ctx); e != nil {
		return CertificateRecord{}, e
	}
	final := clock().UTC()
	if final.Before(end) || !final.Before(started.Add(customerpending.MaxReviewLease)) || ctx.Err() != nil {
		return CertificateRecord{}, ErrInvalid
	}
	verified, e = customerissuance.VerifyIssued(der, issuerDER, rootDER, intent, final)
	if e != nil || verified.IntentDigest() != idigest || verified.CertificateHash() != record.CertificateHash {
		return CertificateRecord{}, ErrInvalid
	}
	if final.Unix() != end.Unix() {
		if _, e = c.ExecContext(ctx, `UPDATE customer_v3_meta SET last_at=? WHERE id=1`, final.Unix()); e != nil {
			return CertificateRecord{}, ErrStorage
		}
	}
	commitAttempted = true
	if _, e = c.ExecContext(ctx, `COMMIT`); e != nil {
		return CertificateRecord{}, ErrUncertain
	}
	committed = true
	if ctx.Err() != nil {
		return CertificateRecord{}, ErrUncertain
	}
	if e = storageGuard(ctx); e != nil {
		return CertificateRecord{}, ErrUncertain
	}
	if e = live.Check(); e != nil {
		return CertificateRecord{}, ErrUncertain
	}
	if e = original.Check(); e != nil {
		return CertificateRecord{}, ErrUncertain
	}
	after := clock().UTC()
	if after.Before(final) || !after.Before(started.Add(customerpending.MaxReviewLease)) || ctx.Err() != nil {
		return CertificateRecord{}, ErrUncertain
	}
	verified, e = customerissuance.VerifyIssued(der, issuerDER, rootDER, intent, after)
	if e != nil || verified.IntentDigest() != idigest || verified.CertificateHash() != record.CertificateHash {
		return CertificateRecord{}, ErrUncertain
	}
	record.DER = bytes.Clone(record.DER)
	return record, nil
}

// CertificateRecords is an internal, untrusted reconciliation read only. The
// caller must independently enforce protected storage and operator session.
// It does not validate current issuer/revocation and is never a delivery API.
func (s *Store) CertificateRecords(ctx context.Context) (result []CertificateRecord, resultErr error) {
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
	var count int
	if e = c.QueryRowContext(ctx, `SELECT cert_count FROM customer_v3_meta WHERE id=1`).Scan(&count); e != nil {
		return nil, ErrStorage
	}
	out, e := loadCertificates(ctx, c, intents, count, last)
	if e != nil {
		return nil, e
	}
	if _, e = c.ExecContext(ctx, `COMMIT`); e != nil {
		return nil, ErrStorage
	}
	committed = true
	return out, nil
}
