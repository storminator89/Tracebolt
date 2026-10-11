package enrollmentstore

import (
	"bytes"
	"context"
	"encoding/base64"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
)

type renewalLeaf struct {
	Intent              enrollmentcrypto.Intent `json:"intent"`
	DER                 []byte                  `json:"der"`
	CertificateHash     string                  `json:"certificateHash"`
	Generation          uint64                  `json:"generation"`
	ActivatedAt         int64                   `json:"activatedAt"`
	RequestID           string                  `json:"requestId"`
	ActivationRequestID string                  `json:"activationRequestId,omitempty"`
}
type renewalCandidate struct {
	Leaf            renewalLeaf `json:"leaf"`
	PredecessorHash string      `json:"predecessorHash"`
	IntentRevision  uint64      `json:"intentRevision"`
	PreparedAt      int64       `json:"preparedAt"`
	IssuedAt        int64       `json:"issuedAt"`
}
type renewalRecord struct {
	IdentityGeneration string            `json:"identityGeneration"`
	Revision           uint64            `json:"revision"`
	Enabled            bool              `json:"enabled"`
	Current            renewalLeaf       `json:"current"`
	Candidate          *renewalCandidate `json:"candidate,omitempty"`
	UpdatedAt          int64             `json:"updatedAt"`
	DisableRequestID   string            `json:"disableRequestId,omitempty"`
}

// RenewalCredential and RenewalView are additive public metadata. The original
// enrollment intent/DER remain the immutable authority of every local grant.
type RenewalCredential struct {
	CertificateDER       string                  `json:"certificateDer"`
	Intent               enrollmentcrypto.Intent `json:"intent"`
	CertificateHash      string                  `json:"certificateHash"`
	CredentialGeneration uint64                  `json:"credentialGeneration"`
	RequestID            string                  `json:"requestId"`
}
type RenewalView struct {
	Status               string             `json:"status"`
	SchemaVersion        string             `json:"schemaVersion"`
	IdentityGeneration   string             `json:"identityGeneration"`
	CredentialGeneration uint64             `json:"credentialGeneration"`
	Revision             uint64             `json:"revision"`
	Enabled              bool               `json:"enabled"`
	Current              RenewalCredential  `json:"current"`
	Candidate            *RenewalCredential `json:"candidate,omitempty"`
}

func initialRenewal(cert enrollmentcrypto.VerifiedCertificate, now int64, revision uint64) *renewalRecord {
	generation, _ := enrollmentcrypto.RenewalIdentityGeneration(cert.Intent())
	return &renewalRecord{IdentityGeneration: generation, Revision: revision, Enabled: true, Current: renewalLeaf{Intent: cert.Intent(), DER: cert.DER(), CertificateHash: cert.CertificateHash(), Generation: 1, ActivatedAt: now, RequestID: cert.Intent().RequestID}, UpdatedAt: now}
}
func credentialAuthorityExpiry(s enrollmentstate.Snapshot, c credential) int64 {
	if c.Renewal != nil {
		return c.Renewal.Current.Intent.NotAfter
	}
	return s.Intent.NotAfter
}
func sameRenewalIdentity(a, b enrollmentcrypto.Intent) bool {
	a.RequestID = b.RequestID
	a.IntentID = b.IntentID
	a.SerialHex = b.SerialHex
	a.NotBefore = b.NotBefore
	a.NotAfter = b.NotAfter
	return a == b
}
func (s *Store) validRenewalRecord(snapshot enrollmentstate.Snapshot, anchor enrollmentcrypto.Intent, c credential) bool {
	r := c.Renewal
	if snapshot.Claim.RenewalPolicy == "" {
		return r == nil
	}
	if !s.config.AutomaticRenewal || snapshot.Claim.AgentOrigin != s.config.RenewalAgentOrigin || r == nil || snapshot.Binding.Profile != "tls" {
		return false
	}
	identity, e := enrollmentcrypto.RenewalIdentityGeneration(anchor)
	if e != nil || identity != r.IdentityGeneration || r.Revision < 1 || r.Revision > enrollmentstate.MaxRevision || r.UpdatedAt < snapshot.Issuance.At || r.UpdatedAt > enrollmentstate.MaxTimestamp || r.Current.Generation < 1 || r.Current.Generation > enrollmentstate.MaxRevision || r.Current.ActivatedAt < snapshot.Issuance.At || r.Current.ActivatedAt > r.UpdatedAt {
		return false
	}
	if !r.Enabled && !enrollmentcrypto.ValidID(r.DisableRequestID, "request_") || r.Enabled && r.DisableRequestID != "" {
		return false
	}
	validLeaf := func(l renewalLeaf, at int64) bool {
		if !sameRenewalIdentity(anchor, l.Intent) || (!enrollmentcrypto.ValidID(l.RequestID, "request_") || l.RequestID != l.Intent.RequestID) {
			return false
		}
		verified, err := enrollmentcrypto.VerifyIssued(l.DER, s.issuerDER, l.Intent, time.Unix(at, 0))
		return err == nil && verified.CertificateHash() == l.CertificateHash
	}
	if !validLeaf(r.Current, r.Current.ActivatedAt) {
		return false
	}
	if r.Current.Generation == 1 && (r.Current.Intent != anchor || !bytes.Equal(r.Current.DER, c.DER)) {
		return false
	}
	if r.Current.Generation > 1 && (r.Current.Intent.NotAfter-r.Current.Intent.NotBefore > enrollmentcrypto.RenewalLifetimeSeconds || r.Current.Intent.NotAfter <= anchor.NotAfter || !enrollmentcrypto.ValidID(r.Current.ActivationRequestID, "request_")) {
		return false
	}
	if p := r.Candidate; p != nil {
		if p.PredecessorHash != r.Current.CertificateHash || p.Leaf.Generation != r.Current.Generation+1 || p.IntentRevision < 2 || p.IntentRevision > r.Revision || p.PreparedAt < r.Current.ActivatedAt || p.PreparedAt > r.UpdatedAt || p.PreparedAt >= r.Current.Intent.NotAfter || p.Leaf.ActivatedAt != 0 || p.Leaf.ActivationRequestID != "" || p.Leaf.RequestID != p.Leaf.Intent.RequestID || !sameRenewalIdentity(anchor, p.Leaf.Intent) || enrollmentcrypto.ValidateIntent(p.Leaf.Intent) != nil || p.Leaf.Intent.NotAfter <= r.Current.Intent.NotAfter || p.Leaf.Intent.NotAfter-p.Leaf.Intent.NotBefore > enrollmentcrypto.RenewalLifetimeSeconds || !enrollmentcrypto.ValidID(p.Leaf.RequestID, "request_") {
			return false
		}
		if p.IssuedAt == 0 {
			if len(p.Leaf.DER) != 0 || p.Leaf.CertificateHash != "" {
				return false
			}
		} else if p.IssuedAt < p.PreparedAt || p.IssuedAt > r.UpdatedAt || !validLeaf(p.Leaf, p.IssuedAt) {
			return false
		}
	}
	return true
}
func (t *transaction) renewalState(id string, now time.Time) (enrollmentstate.Snapshot, credential, error) {
	snapshot, e := t.engine.Get(id)
	if e != nil {
		return snapshot, credential{}, e
	}
	c, ok := t.credentials[id]
	if !ok {
		return snapshot, c, ErrStorage
	}
	if (snapshot.State != enrollmentstate.Activated && snapshot.State != enrollmentstate.Revoked) || snapshot.Claim.RenewalPolicy != enrollmentcrypto.RenewalPolicySameKey || c.Renewal == nil {
		return snapshot, c, enrollmentstate.ErrState
	}
	if !validStoreTime(now) || now.Unix() < snapshot.UpdatedAt || now.Unix() < c.Renewal.UpdatedAt {
		return snapshot, c, enrollmentstate.ErrInvalid
	}
	return snapshot, c, nil
}
func leafValid(l renewalLeaf, now time.Time) bool {
	return len(l.DER) > 0 && now.Unix() >= l.Intent.NotBefore && now.Unix() < l.Intent.NotAfter
}
func (t *transaction) renewalProof(proof enrollmentcrypto.VerifiedRenewal, purpose string, now time.Time) (enrollmentstate.Snapshot, credential, error) {
	x := proof.Context()
	snapshot, c, e := t.renewalState(x.InvitationID, now)
	if e != nil {
		return snapshot, c, e
	}
	r := c.Renewal
	if snapshot.State != enrollmentstate.Activated && purpose != enrollmentcrypto.PurposeRenewalStatus {
		return snapshot, c, enrollmentstate.ErrState
	}
	if !proof.Valid() || x.Purpose != purpose || x.ExpiresAt <= now.Unix() || x.ExpiresAt > now.Unix()+60 || x.ManagerInstanceID != snapshot.Binding.InstanceID || x.Profile != snapshot.Binding.Profile || x.Origin != snapshot.Binding.Origin || x.AgentOrigin != snapshot.Claim.AgentOrigin || x.CollectionProfile != snapshot.Binding.CollectionProfile || x.ClaimID != snapshot.Claim.ClaimID || x.DeviceID != snapshot.Approval.DeviceID || x.KeyFingerprint != snapshot.Claim.KeyFingerprint || x.IdentityGeneration != r.IdentityGeneration || x.Revision != r.Revision {
		return snapshot, c, enrollmentstate.ErrProof
	}
	l := r.Current
	if x.CertificateHash != l.CertificateHash || x.CredentialGeneration != l.Generation {
		if r.Candidate == nil || x.CertificateHash != r.Candidate.Leaf.CertificateHash || x.CredentialGeneration != r.Candidate.Leaf.Generation || purpose == enrollmentcrypto.PurposeRenewalIssue {
			return snapshot, c, enrollmentstate.ErrProof
		}
		l = r.Candidate.Leaf
	}
	if purpose != enrollmentcrypto.PurposeRenewalStatus && !leafValid(l, now) {
		return snapshot, c, enrollmentstate.ErrExpired
	}
	return snapshot, c, nil
}

// RenewalContext selects only a current/candidate public leaf. Possession is
// established later by a separate proof and final write-transaction recheck.
func (s *Store) RenewalContext(ctx context.Context, id, claimID, certificateHash, purpose string, now func() time.Time) (enrollmentcrypto.RenewalContext, error) {
	var out enrollmentcrypto.RenewalContext
	if now == nil || !enrollmentcrypto.ValidRenewalPurpose(purpose) {
		return out, enrollmentstate.ErrInvalid
	}
	err := s.transact(ctx, func(t *transaction) error {
		snapshot, c, e := t.renewalState(id, now())
		if e != nil {
			return e
		}
		if claimID != snapshot.Claim.ClaimID {
			return enrollmentstate.ErrProof
		}
		if purpose != enrollmentcrypto.PurposeRenewalStatus && snapshot.State != enrollmentstate.Activated {
			return enrollmentstate.ErrState
		}
		r := c.Renewal
		l := r.Current
		if certificateHash != l.CertificateHash {
			if r.Candidate == nil || certificateHash != r.Candidate.Leaf.CertificateHash || purpose == enrollmentcrypto.PurposeRenewalIssue {
				return enrollmentstate.ErrProof
			}
			l = r.Candidate.Leaf
		}
		if purpose != enrollmentcrypto.PurposeRenewalStatus && !leafValid(l, now()) {
			return enrollmentstate.ErrExpired
		}
		out = enrollmentcrypto.RenewalContext{ChallengeContext: enrollmentcrypto.ChallengeContext{ManagerInstanceID: snapshot.Binding.InstanceID, Profile: snapshot.Binding.Profile, Origin: snapshot.Binding.Origin, AgentOrigin: snapshot.Claim.AgentOrigin, RenewalPolicy: snapshot.Claim.RenewalPolicy, CollectionProfile: snapshot.Binding.CollectionProfile, InvitationID: id, ClaimID: claimID}, IdentityGeneration: r.IdentityGeneration, CredentialGeneration: l.Generation, CertificateHash: l.CertificateHash, DeviceID: snapshot.Approval.DeviceID, KeyFingerprint: snapshot.Claim.KeyFingerprint, Revision: r.Revision, Purpose: purpose}
		return nil
	})
	return out, err
}
func renewalView(r *renewalRecord) RenewalView {
	view := RenewalView{SchemaVersion: enrollmentcrypto.RenewalVersion, IdentityGeneration: r.IdentityGeneration, CredentialGeneration: r.Current.Generation, Revision: r.Revision, Enabled: r.Enabled, Current: publicRenewalLeaf(r.Current)}
	if r.Candidate != nil {
		view.Status = "retrying"
	}
	if r.Candidate != nil && r.Candidate.IssuedAt != 0 {
		c := publicRenewalLeaf(r.Candidate.Leaf)
		view.Candidate = &c
	}
	return view
}
func (s *Store) ReadRenewal(ctx context.Context, proof enrollmentcrypto.VerifiedRenewal, now func() time.Time) (RenewalView, error) {
	var out RenewalView
	if now == nil {
		return out, enrollmentstate.ErrInvalid
	}
	e := s.transact(ctx, func(t *transaction) error {
		snapshot, c, e := t.renewalProof(proof, enrollmentcrypto.PurposeRenewalStatus, now())
		if e != nil {
			return e
		}
		out = renewalView(c.Renewal)
		if snapshot.State == enrollmentstate.Revoked {
			out.Status = "revoked"
		}
		t.beforeCommit = append(t.beforeCommit, func() error { _, _, e := t.renewalProof(proof, enrollmentcrypto.PurposeRenewalStatus, now()); return e })
		return nil
	})
	return out, e
}

// BeginRenewal commits fixed intent and idempotency key before signing. A retry
// returns the same intent only; it never manufactures a new serial or validity.
func (s *Store) BeginRenewal(ctx context.Context, proof enrollmentcrypto.VerifiedRenewal, intentID, serial string, notBefore, notAfter int64, now func() time.Time) (enrollmentcrypto.Intent, uint64, error) {
	var out enrollmentcrypto.Intent
	var revision uint64
	if now == nil {
		return out, 0, enrollmentstate.ErrInvalid
	}
	e := s.transact(ctx, func(t *transaction) error {
		snapshot, c, e := t.renewalProof(proof, enrollmentcrypto.PurposeRenewalIssue, now())
		if e != nil {
			return e
		}
		r := c.Renewal
		if !r.Enabled {
			return enrollmentstate.ErrState
		}
		if !leafValid(r.Current, now()) {
			return enrollmentstate.ErrExpired
		}
		if p := r.Candidate; p != nil {
			if p.Leaf.RequestID != proof.RequestID() {
				return enrollmentstate.ErrConflict
			}
			out = p.Leaf.Intent
			revision = r.Revision
			return nil
		}
		at := now().Unix()
		if r.Current.Intent.NotAfter-at > enrollmentcrypto.RenewalWindowSeconds {
			return enrollmentstate.ErrState
		}
		if r.Revision >= enrollmentstate.MaxRevision || r.Current.Generation >= enrollmentstate.MaxRevision {
			return enrollmentstate.ErrConflict
		}
		anchor, e := t.engine.TrustedRecordedIntent(snapshot.InvitationID)
		if e != nil {
			return e
		}
		intent := anchor
		intent.RequestID = proof.RequestID()
		intent.IntentID = intentID
		intent.SerialHex = serial
		intent.NotBefore = notBefore
		intent.NotAfter = notAfter
		if enrollmentcrypto.ValidateIntent(intent) != nil || notBefore > at || notBefore < at-30 || notAfter <= r.Current.Intent.NotAfter || notAfter-notBefore > enrollmentcrypto.RenewalLifetimeSeconds {
			return enrollmentstate.ErrInvalid
		}
		r.Revision++
		r.UpdatedAt = at
		r.Candidate = &renewalCandidate{Leaf: renewalLeaf{Intent: intent, Generation: r.Current.Generation + 1, RequestID: proof.RequestID()}, PredecessorHash: r.Current.CertificateHash, IntentRevision: r.Revision, PreparedAt: at}
		t.credentials[snapshot.InvitationID] = c
		out = intent
		revision = r.Revision
		t.beforeCommit = append(t.beforeCommit, func() error {
			n := now()
			if n.Unix() < at || n.Unix() >= proof.Context().ExpiresAt || !leafValid(r.Current, n) {
				return enrollmentstate.ErrExpired
			}
			return nil
		})
		return nil
	})
	return out, revision, e
}
func (s *Store) CommitRenewal(ctx context.Context, proof enrollmentcrypto.VerifiedRenewal, revision uint64, cert enrollmentcrypto.VerifiedCertificate, now func() time.Time) (RenewalView, error) {
	var out RenewalView
	if now == nil {
		return out, enrollmentstate.ErrInvalid
	}
	e := s.transact(ctx, func(t *transaction) error {
		snapshot, c, e := t.renewalState(proof.Context().InvitationID, now())
		if e != nil {
			return e
		}
		r := c.Renewal
		p := r.Candidate
		if snapshot.State != enrollmentstate.Activated || !proof.Valid() || proof.Context().Purpose != enrollmentcrypto.PurposeRenewalIssue || !r.Enabled || p == nil || r.Revision != revision || p.Leaf.RequestID != proof.RequestID() || p.PredecessorHash != proof.Context().CertificateHash || proof.Context().IdentityGeneration != r.IdentityGeneration || proof.Context().CredentialGeneration != r.Current.Generation || !cert.Valid() || cert.Intent() != p.Leaf.Intent {
			return enrollmentstate.ErrConflict
		}
		at := now().Unix()
		if at >= proof.Context().ExpiresAt || !leafValid(r.Current, now()) {
			return enrollmentstate.ErrExpired
		}
		if p.IssuedAt != 0 {
			if p.Leaf.CertificateHash != cert.CertificateHash() || !bytes.Equal(p.Leaf.DER, cert.DER()) {
				return enrollmentstate.ErrConflict
			}
		} else {
			if r.Revision >= enrollmentstate.MaxRevision {
				return enrollmentstate.ErrConflict
			}
			p.Leaf.DER = cert.DER()
			p.Leaf.CertificateHash = cert.CertificateHash()
			p.IssuedAt = at
			r.Revision++
			r.UpdatedAt = at
			t.credentials[snapshot.InvitationID] = c
		}
		out = renewalView(r)
		t.beforeCommit = append(t.beforeCommit, func() error {
			n := now()
			if n.Unix() < at || n.Unix() >= proof.Context().ExpiresAt || !leafValid(r.Current, n) || !leafValid(p.Leaf, n) {
				return enrollmentstate.ErrExpired
			}
			return nil
		})
		return nil
	})
	return out, e
}
func (s *Store) ActivateRenewal(ctx context.Context, proof enrollmentcrypto.VerifiedRenewal, now func() time.Time) (RenewalView, error) {
	var out RenewalView
	if now == nil {
		return out, enrollmentstate.ErrInvalid
	}
	e := s.transact(ctx, func(t *transaction) error {
		snapshot, c, e := t.renewalProof(proof, enrollmentcrypto.PurposeRenewalActivate, now())
		if e != nil {
			return e
		}
		r := c.Renewal
		p := r.Candidate
		// A lost successful response is reconciled by authenticating the new current
		// leaf. Retired predecessors cannot authorize any new operation.
		if p == nil {
			if r.Current.Generation > 1 && proof.Context().CertificateHash == r.Current.CertificateHash {
				out = renewalView(r)
				return nil
			}
			return enrollmentstate.ErrState
		}
		if !r.Enabled || p.IssuedAt == 0 || proof.Context().CertificateHash != p.Leaf.CertificateHash || r.Revision >= enrollmentstate.MaxRevision {
			return enrollmentstate.ErrState
		}
		at := now().Unix()
		if !leafValid(r.Current, now()) || !leafValid(p.Leaf, now()) {
			return enrollmentstate.ErrExpired
		}
		old := r.Current
		r.Current = p.Leaf
		r.Current.ActivatedAt = at
		r.Current.ActivationRequestID = proof.RequestID()
		r.Candidate = nil
		r.Revision++
		r.UpdatedAt = at
		t.credentials[snapshot.InvitationID] = c
		out = renewalView(r)
		t.beforeCommit = append(t.beforeCommit, func() error {
			n := now()
			if n.Unix() < at || n.Unix() >= proof.Context().ExpiresAt || !leafValid(old, n) || !leafValid(r.Current, n) {
				return enrollmentstate.ErrExpired
			}
			return nil
		})
		return nil
	})
	return out, e
}
func (s *Store) DisableRenewal(ctx context.Context, id, requestID string, revision uint64, now func() time.Time) (RenewalView, error) {
	var out RenewalView
	if now == nil || !enrollmentcrypto.ValidID(requestID, "request_") {
		return out, enrollmentstate.ErrInvalid
	}
	e := s.transact(ctx, func(t *transaction) error {
		_, c, e := t.renewalState(id, now())
		if e != nil {
			return e
		}
		r := c.Renewal
		if !r.Enabled && r.DisableRequestID == requestID {
			out = renewalView(r)
			return nil
		}
		if !r.Enabled || r.Revision != revision || r.Revision >= enrollmentstate.MaxRevision {
			return enrollmentstate.ErrConflict
		}
		r.Enabled = false
		r.DisableRequestID = requestID
		r.Revision++
		r.UpdatedAt = now().Unix()
		t.credentials[id] = c
		out = renewalView(r)
		return nil
	})
	return out, e
}

func publicRenewalLeaf(l renewalLeaf) RenewalCredential {
	return RenewalCredential{CertificateDER: base64.RawStdEncoding.EncodeToString(l.DER), Intent: l.Intent, CertificateHash: l.CertificateHash, CredentialGeneration: l.Generation, RequestID: l.RequestID}
}

// ExistingRenewal returns only an already committed, exact issuance retry.
// It does not retry or invoke a signer whose outcome may be uncertain.
func (s *Store) ExistingRenewal(ctx context.Context, proof enrollmentcrypto.VerifiedRenewal, now func() time.Time) (RenewalView, bool, error) {
	var out RenewalView
	found := false
	if now == nil {
		return out, false, enrollmentstate.ErrInvalid
	}
	e := s.transact(ctx, func(t *transaction) error {
		_, c, e := t.renewalProof(proof, enrollmentcrypto.PurposeRenewalIssue, now())
		if e != nil {
			return e
		}
		r := c.Renewal
		if !r.Enabled {
			return enrollmentstate.ErrState
		}
		if p := r.Candidate; p != nil {
			if p.Leaf.RequestID != proof.RequestID() {
				return enrollmentstate.ErrConflict
			}
			if p.IssuedAt != 0 {
				found = true
				out = renewalView(r)
			}
		}
		t.beforeCommit = append(t.beforeCommit, func() error { _, _, e := t.renewalProof(proof, enrollmentcrypto.PurposeRenewalIssue, now()); return e })
		return nil
	})
	return out, found, e
}

// OperatorRenewal is a privileged read of the separate renewal revision. It
// cannot authorize issuance or activation; it supplies CAS context for the
// operator's explicit disable-future-renewal command.
func (s *Store) OperatorRenewal(ctx context.Context, id string, now func() time.Time) (RenewalView, error) {
	var out RenewalView
	if now == nil || !enrollmentcrypto.ValidID(id, "invite_") {
		return out, enrollmentstate.ErrInvalid
	}
	e := s.transact(ctx, func(t *transaction) error {
		snapshot, e := t.engine.Get(id)
		if e != nil {
			return e
		}
		c, ok := t.credentials[id]
		if !ok || c.Renewal == nil {
			return enrollmentstate.ErrNotImplemented
		}
		at := now()
		if !validStoreTime(at) || at.Unix() < snapshot.UpdatedAt || at.Unix() < c.Renewal.UpdatedAt {
			return enrollmentstate.ErrInvalid
		}
		out = renewalView(c.Renewal)
		if snapshot.State == enrollmentstate.Revoked {
			out.Status = "revoked"
		} else if snapshot.State != enrollmentstate.Activated {
			out.Status = "blocked"
		}
		t.beforeCommit = append(t.beforeCommit, func() error {
			if now().Before(at) {
				return enrollmentstate.ErrInvalid
			}
			return nil
		})
		return nil
	})
	return out, e
}
