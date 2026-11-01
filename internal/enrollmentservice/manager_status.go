package enrollmentservice

import (
	"context"
	"crypto/x509"
	"localrmm/internal/managerstatus"
)

// ManagerStatus is a private aggregate of current durable read validity and
// existing bounded in-memory work; it creates no challenge or authority change.
func (s *Service) ManagerStatus(ctx context.Context) managerstatus.ProbeResult {
	if s == nil || s.serviceState == nil || s.store == nil {
		return managerstatus.ProbeResult{State: managerstatus.Unavailable}
	}
	out := s.store.ManagerStatus(ctx)
	s.mu.Lock()
	out.Work = &managerstatus.WorkMetrics{Used: len(s.signing) + len(s.proofs), Limit: cap(s.signing) + cap(s.proofs), Retained: len(s.challenges), RetainedLimit: MaxChallenges}
	s.mu.Unlock()
	return out
}

// IssuerStatus checks retained startup validity bounds using the same trusted
// service clock. It signs nothing and exposes no certificate/identity material.
func (s *Service) IssuerStatus(ctx context.Context) managerstatus.ProbeResult {
	if s == nil || s.serviceState == nil || ctx == nil {
		return managerstatus.ProbeResult{State: managerstatus.Invalid}
	}
	if err := ctx.Err(); err != nil {
		return managerstatus.ProbeResult{State: managerstatus.Classify(err)}
	}
	now := s.Now()
	if now.IsZero() || now.Before(s.issuerStart) {
		return managerstatus.ProbeResult{State: managerstatus.Invalid}
	}
	if !now.Before(s.issuerExpiry) {
		return managerstatus.ProbeResult{State: managerstatus.Expired}
	}
	root, err := x509.ParseCertificate(s.signer.RootDER())
	if err != nil || now.Before(root.NotBefore) {
		return managerstatus.ProbeResult{State: managerstatus.Invalid}
	}
	if !now.Before(root.NotAfter) {
		return managerstatus.ProbeResult{State: managerstatus.Expired}
	}
	return managerstatus.ProbeResult{State: managerstatus.OK}
}
