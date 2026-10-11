package enrollmentservice

import (
	"context"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
)

// RenewalEnvelope is distinct from enrollment snapshots and never changes the
// original issuance authority used by consent receipts and durable scope floors.
type RenewalEnvelope struct {
	enrollmentstore.RenewalView
	AuthorityExpiresAt int64     `json:"authorityExpiresAt"`
	ServerNow          time.Time `json:"serverNow"`
}
type RenewalChallenge struct {
	SchemaVersion string                          `json:"schemaVersion"`
	Context       enrollmentcrypto.RenewalContext `json:"context"`
	ServerNow     time.Time                       `json:"serverNow"`
}

func (s *Service) AutomaticRenewal() bool {
	return s != nil && s.serviceState != nil && s.store.Config().AutomaticRenewal
}
func (s *Service) RenewalAgentOrigin() string {
	if !s.AutomaticRenewal() {
		return ""
	}
	return s.store.Config().RenewalAgentOrigin
}
func (s *Service) RenewalChallenge(ctx context.Context, peer, id, claimID, certificateHash, purpose string) (RenewalChallenge, error) {
	if !s.AutomaticRenewal() || s.binding.Profile != "tls" {
		return RenewalChallenge{}, enrollmentstate.ErrNotImplemented
	}
	if !enrollmentcrypto.ValidRenewalPurpose(purpose) {
		return RenewalChallenge{}, ErrChallenge
	}
	// Apply the same bounded peer/global challenge admission before a store read.
	basic, e := s.Challenge(peer, id, claimID, purpose)
	if e != nil {
		return RenewalChallenge{}, e
	}
	c, e := s.store.RenewalContext(ctx, id, claimID, certificateHash, purpose, s.now)
	if e != nil {
		return RenewalChallenge{}, e
	}
	c.Challenge = basic.Context.Challenge
	c.ExpiresAt = basic.Context.ExpiresAt
	s.mu.Lock()
	entry, ok := s.challenges[c.Challenge]
	if ok {
		entry.renewal = &c
		s.challenges[c.Challenge] = entry
	}
	s.mu.Unlock()
	if !ok {
		return RenewalChallenge{}, ErrChallenge
	}
	return RenewalChallenge{SchemaVersion: "tracebolt.enrollment-renewal-challenge.v1", Context: c, ServerNow: s.now().UTC()}, nil
}
func (s *Service) renewalProof(ctx context.Context, nonce, purpose string, raw []byte) (enrollmentcrypto.VerifiedRenewal, error) {
	if !s.AutomaticRenewal() || s.binding.Profile != "tls" {
		return enrollmentcrypto.VerifiedRenewal{}, enrollmentstate.ErrNotImplemented
	}
	s.mu.Lock()
	entry, ok := s.challenges[nonce]
	delete(s.challenges, nonce)
	s.mu.Unlock()
	if !ok || entry.purpose != purpose || entry.renewal == nil || s.now().Unix() >= entry.renewal.ExpiresAt {
		return enrollmentcrypto.VerifiedRenewal{}, ErrChallenge
	}
	_, key, e := s.store.StatusContext(ctx, entry.renewal.InvitationID)
	if e != nil {
		return enrollmentcrypto.VerifiedRenewal{}, e
	}
	return enrollmentcrypto.VerifyRenewal(raw, key, *entry.renewal, s.now().UTC())
}
func (s *Service) renewalEnvelope(v enrollmentstore.RenewalView) RenewalEnvelope {
	now := s.now().UTC()
	status := "healthy"
	if v.Status == "revoked" {
		status = "revoked"
	} else if v.Current.Intent.NotAfter <= now.Unix() {
		status = "expired"
	} else if !v.Enabled || v.Status == "blocked" || v.Current.Intent.NotAfter >= s.issuerExpiry.Unix()-1 {
		status = "blocked"
	} else if v.Candidate != nil || v.Status == "retrying" {
		status = "retrying"
	} else if v.Current.Intent.NotAfter-now.Unix() <= enrollmentcrypto.RenewalWindowSeconds {
		status = "due"
	}
	v.Status = status
	return RenewalEnvelope{RenewalView: v, AuthorityExpiresAt: s.issuerExpiry.Unix(), ServerNow: now}
}
func (s *Service) RenewalStatus(ctx context.Context, nonce string, raw []byte) (RenewalEnvelope, error) {
	release, e := s.beginProof()
	if e != nil {
		return RenewalEnvelope{}, e
	}
	defer release()
	proof, e := s.renewalProof(ctx, nonce, enrollmentcrypto.PurposeRenewalStatus, raw)
	if e != nil {
		return RenewalEnvelope{}, e
	}
	v, e := s.store.ReadRenewal(ctx, proof, s.now)
	if e != nil {
		return RenewalEnvelope{}, e
	}
	return s.renewalEnvelope(v), nil
}
func (s *Service) Renew(ctx context.Context, nonce string, raw []byte) (RenewalEnvelope, error) {
	release, e := s.beginProof()
	if e != nil {
		return RenewalEnvelope{}, e
	}
	defer release()
	proof, e := s.renewalProof(ctx, nonce, enrollmentcrypto.PurposeRenewalIssue, raw)
	if e != nil {
		return RenewalEnvelope{}, e
	}
	select {
	case s.signing <- struct{}{}:
		defer func() { <-s.signing }()
	default:
		return RenewalEnvelope{}, ErrBusy
	}
	if v, ok, e := s.store.ExistingRenewal(ctx, proof, s.now); e != nil {
		return RenewalEnvelope{}, e
	} else if ok {
		return s.renewalEnvelope(v), nil
	}
	intentID, e := newID("intent_")
	if e != nil {
		return RenewalEnvelope{}, e
	}
	serial, e := newID("")
	if e != nil {
		return RenewalEnvelope{}, e
	}
	now := s.now().UTC()
	start := now
	end := start.Add(time.Duration(enrollmentcrypto.RenewalLifetimeSeconds) * time.Second)
	if !end.Before(s.issuerExpiry) {
		end = s.issuerExpiry.Add(-time.Second)
	}
	intent, revision, e := s.store.BeginRenewal(ctx, proof, intentID, serial, start.Unix(), end.Unix(), s.now)
	if e != nil {
		return RenewalEnvelope{}, e
	}
	cert, e := s.signer.Sign(ctx, intent, s.now().UTC())
	if e != nil {
		return RenewalEnvelope{}, e
	}
	v, e := s.store.CommitRenewal(ctx, proof, revision, cert, s.now)
	if e != nil {
		return RenewalEnvelope{}, e
	}
	return s.renewalEnvelope(v), nil
}
func (s *Service) ActivateRenewal(ctx context.Context, nonce string, raw []byte) (RenewalEnvelope, error) {
	release, e := s.beginProof()
	if e != nil {
		return RenewalEnvelope{}, e
	}
	defer release()
	proof, e := s.renewalProof(ctx, nonce, enrollmentcrypto.PurposeRenewalActivate, raw)
	if e != nil {
		return RenewalEnvelope{}, e
	}
	v, e := s.store.ActivateRenewal(ctx, proof, s.now)
	if e != nil {
		return RenewalEnvelope{}, e
	}
	return s.renewalEnvelope(v), nil
}
func (s *Service) DisableRenewal(ctx context.Context, id, requestID string, revision uint64) (RenewalEnvelope, error) {
	if !s.AutomaticRenewal() {
		return RenewalEnvelope{}, enrollmentstate.ErrNotImplemented
	}
	v, e := s.store.DisableRenewal(ctx, id, requestID, revision, s.now)
	if e != nil {
		return RenewalEnvelope{}, e
	}
	return s.renewalEnvelope(v), nil
}

func (s *Service) OperatorRenewal(ctx context.Context, id string) (RenewalEnvelope, error) {
	if !s.AutomaticRenewal() {
		return RenewalEnvelope{}, enrollmentstate.ErrNotImplemented
	}
	view, e := s.store.OperatorRenewal(ctx, id, s.now)
	if e != nil {
		return RenewalEnvelope{}, e
	}
	return s.renewalEnvelope(view), nil
}
